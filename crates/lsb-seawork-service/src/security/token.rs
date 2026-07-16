use std::ffi::c_void;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::ptr;

use anyhow::{bail, Context, Result};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Security::{
    DuplicateTokenEx, GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation,
    SecurityImpersonation, TokenElevation, TokenGroups, TokenImpersonation, TokenIntegrityLevel,
    TokenIsAppContainer, TokenSessionId, TokenStatistics, TokenUser, TOKEN_DUPLICATE,
    TOKEN_ELEVATION, TOKEN_GROUPS, TOKEN_IMPERSONATE, TOKEN_INFORMATION_CLASS,
    TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_STATISTICS, TOKEN_USER,
};
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows_sys::Win32::System::SystemServices::SE_GROUP_LOGON_ID;
use windows_sys::Win32::System::Threading::{
    GetCurrentThread, OpenProcess, OpenProcessToken, OpenThreadToken,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
};

use crate::session::ClientIdentityKey;

use super::access::authorize_interactive_client;
use super::client_image::{query_process_image, require_absolute_image};
use super::impersonation::ImpersonationGuard;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenSnapshot {
    pub user_sid: String,
    pub logon_sid: String,
    pub authentication_luid: u64,
    pub session_id: u32,
    pub integrity_rid: u32,
    pub is_app_container: bool,
    pub elevated: bool,
}

pub struct ClientIdentity {
    pub key: ClientIdentityKey,
    pub integrity_rid: u32,
    pub process_id: u32,
    pub elevated: bool,
    pub process_image: std::path::PathBuf,
    _process: OwnedHandle,
    _impersonation_token: OwnedHandle,
}

impl ClientIdentity {
    pub fn from_named_pipe(pipe: RawHandle) -> Result<Self> {
        let mut process_id = 0;
        if unsafe { GetNamedPipeClientProcessId(pipe as HANDLE, &mut process_id) } == 0
            || process_id == 0
        {
            bail!(
                "GetNamedPipeClientProcessId failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // This entire scope is synchronous: impersonation never crosses an await.
        let guard = ImpersonationGuard::for_named_pipe(pipe)?;
        let thread_token = open_thread_token()?;
        let pipe_snapshot = snapshot(&thread_token)?;
        authorize_interactive_client(&pipe_snapshot)?;
        let duplicated_token = duplicate_impersonation_token(&thread_token)?;
        guard.revert()?;

        let process_raw = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                process_id,
            )
        };
        if process_raw.is_null() {
            bail!("OpenProcess failed: {}", std::io::Error::last_os_error());
        }
        let process = owned(process_raw);
        let process_token = open_process_token(process_raw)?;
        let process_snapshot = snapshot(&process_token)?;
        if pipe_snapshot.user_sid != process_snapshot.user_sid
            || pipe_snapshot.logon_sid != process_snapshot.logon_sid
            || pipe_snapshot.authentication_luid != process_snapshot.authentication_luid
            || pipe_snapshot.session_id != process_snapshot.session_id
        {
            bail!("pipe and process token identities do not match");
        }

        let process_image = query_process_image(&process)?;
        require_absolute_image(&process_image)?;
        Ok(Self {
            key: ClientIdentityKey {
                user_sid: pipe_snapshot.user_sid,
                logon_sid: pipe_snapshot.logon_sid,
                authentication_luid: pipe_snapshot.authentication_luid,
                session_id: pipe_snapshot.session_id,
            },
            integrity_rid: pipe_snapshot.integrity_rid,
            process_id,
            elevated: pipe_snapshot.elevated,
            process_image,
            _process: process,
            _impersonation_token: duplicated_token,
        })
    }
}

fn open_thread_token() -> Result<OwnedHandle> {
    let mut token = ptr::null_mut();
    if unsafe {
        OpenThreadToken(
            GetCurrentThread(),
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
            0,
            &mut token,
        )
    } == 0
    {
        bail!(
            "OpenThreadToken failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(owned(token))
}

fn open_process_token(process: HANDLE) -> Result<OwnedHandle> {
    let mut token = ptr::null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        bail!(
            "OpenProcessToken failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(owned(token))
}

fn duplicate_impersonation_token(token: &OwnedHandle) -> Result<OwnedHandle> {
    let mut duplicate = ptr::null_mut();
    if unsafe {
        DuplicateTokenEx(
            raw(token),
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
            ptr::null(),
            SecurityImpersonation,
            TokenImpersonation,
            &mut duplicate,
        )
    } == 0
    {
        bail!(
            "DuplicateTokenEx failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(owned(duplicate))
}

fn snapshot(token: &OwnedHandle) -> Result<TokenSnapshot> {
    let token = raw(token);
    let user_sid = token_info(token, TokenUser, |bytes| {
        let user = unsafe { &*(bytes.as_ptr().cast::<TOKEN_USER>()) };
        sid_string(user.User.Sid)
    })??;
    let logon_sid = token_info(token, TokenGroups, |bytes| {
        let groups = unsafe { &*(bytes.as_ptr().cast::<TOKEN_GROUPS>()) };
        for index in 0..groups.GroupCount as usize {
            let group = unsafe { *groups.Groups.as_ptr().add(index) };
            if group.Attributes & SE_GROUP_LOGON_ID as u32 == SE_GROUP_LOGON_ID as u32 {
                return sid_string(group.Sid);
            }
        }
        bail!("token has no logon SID")
    })??;
    let session_id = token_value::<u32>(token, TokenSessionId)?;
    let statistics = token_value::<TOKEN_STATISTICS>(token, TokenStatistics)?;
    let authentication_luid = ((statistics.AuthenticationId.HighPart as u32 as u64) << 32)
        | statistics.AuthenticationId.LowPart as u64;
    let integrity_rid = token_info(token, TokenIntegrityLevel, |bytes| {
        let label = unsafe { &*(bytes.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()) };
        let count = unsafe { *GetSidSubAuthorityCount(label.Label.Sid) } as u32;
        if count == 0 {
            bail!("integrity SID has no subauthority");
        }
        Ok(unsafe { *GetSidSubAuthority(label.Label.Sid, count - 1) })
    })??;
    let is_app_container = token_value::<u32>(token, TokenIsAppContainer)? != 0;
    let elevated = token_value::<TOKEN_ELEVATION>(token, TokenElevation)?.TokenIsElevated != 0;
    Ok(TokenSnapshot {
        user_sid,
        logon_sid,
        authentication_luid,
        session_id,
        integrity_rid,
        is_app_container,
        elevated,
    })
}

fn token_value<T: Copy>(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Result<T> {
    token_info(token, class, |bytes| {
        if bytes.len() < std::mem::size_of::<T>() {
            bail!("token information buffer is truncated");
        }
        Ok(unsafe { *bytes.as_ptr().cast::<T>() })
    })?
}

fn token_info<T>(
    token: HANDLE,
    class: TOKEN_INFORMATION_CLASS,
    reader: impl FnOnce(&[u8]) -> T,
) -> Result<T> {
    let mut required = 0;
    unsafe { GetTokenInformation(token, class, ptr::null_mut(), 0, &mut required) };
    if required == 0 {
        bail!(
            "GetTokenInformation size query failed: {}",
            std::io::Error::last_os_error()
        );
    }
    let mut bytes = vec![0u8; required as usize];
    if unsafe {
        GetTokenInformation(
            token,
            class,
            bytes.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        bail!(
            "GetTokenInformation failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(reader(&bytes))
}

fn sid_string(sid: *mut c_void) -> Result<String> {
    use windows_sys::Win32::Foundation::{LocalFree, HLOCAL};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;

    let mut value = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut value) } == 0 {
        bail!(
            "ConvertSidToStringSidW failed: {}",
            std::io::Error::last_os_error()
        );
    }
    let len = (0..)
        .take_while(|index| unsafe { *value.add(*index) } != 0)
        .count();
    let result = String::from_utf16(unsafe { std::slice::from_raw_parts(value, len) })
        .context("SID string is invalid UTF-16")?;
    unsafe { LocalFree(value as HLOCAL) };
    Ok(result)
}

fn raw(handle: &OwnedHandle) -> HANDLE {
    handle.as_raw_handle() as HANDLE
}

fn owned(handle: HANDLE) -> OwnedHandle {
    unsafe { OwnedHandle::from_raw_handle(handle as _) }
}

#[cfg(test)]
mod tests {
    use windows_sys::Win32::System::SystemServices::SECURITY_MANDATORY_MEDIUM_RID;

    #[test]
    fn medium_integrity_constant_matches_policy() {
        assert_eq!(SECURITY_MANDATORY_MEDIUM_RID, 0x2000);
    }
}
