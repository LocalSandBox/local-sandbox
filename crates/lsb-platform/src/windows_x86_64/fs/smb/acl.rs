use std::path::PathBuf;

use super::types::{WindowsSmbAccess, WindowsSmbLifecycleError, WindowsSmbLifecyclePhase};
use super::user::WindowsSmbUserAccount;
use super::WindowsSmbPassword;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsSmbAclGrantRequest {
    pub path: PathBuf,
    pub account: WindowsSmbUserAccount,
    pub access: WindowsSmbAccess,
}

/// A recoverable ACL operation. `path` is the mount root; cleanup deliberately
/// sweeps it so grants remain removable after descendants are renamed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsSmbAclGrant {
    pub path: PathBuf,
    pub principal: String,
    pub sid: String,
    pub access: WindowsSmbAccess,
    pub original_dacl_control: Option<u16>,
}

pub trait WindowsSmbAclManager {
    fn prepare_grant(
        &mut self,
        request: &WindowsSmbAclGrantRequest,
    ) -> Result<WindowsSmbAclGrant, WindowsSmbLifecycleError> {
        Ok(WindowsSmbAclGrant {
            path: request.path.clone(),
            principal: request.account.principal.clone(),
            sid: request.account.sid.clone(),
            access: request.access,
            original_dacl_control: None,
        })
    }

    fn grant_access(
        &mut self,
        request: WindowsSmbAclGrantRequest,
    ) -> Result<WindowsSmbAclGrant, WindowsSmbLifecycleError>;

    fn revoke_access(&mut self, grant: &WindowsSmbAclGrant)
        -> Result<(), WindowsSmbLifecycleError>;

    fn verify_access(
        &mut self,
        _account: &WindowsSmbUserAccount,
        _password: &WindowsSmbPassword,
        _grants: &[WindowsSmbAclGrant],
    ) -> Result<(), WindowsSmbLifecycleError> {
        Ok(())
    }
}

#[cfg(windows)]
const MAX_ACL_TREE_ENTRIES: usize = 100_000;
#[cfg(windows)]
const MAX_WINDOWS_PATH_UNITS: usize = 32_767;

#[cfg(windows)]
#[derive(Default)]
pub struct NativeWindowsSmbAclManager;

#[cfg(windows)]
impl WindowsSmbAclManager for NativeWindowsSmbAclManager {
    fn prepare_grant(
        &mut self,
        request: &WindowsSmbAclGrantRequest,
    ) -> Result<WindowsSmbAclGrant, WindowsSmbLifecycleError> {
        enumerate_tree(&request.path, WindowsSmbLifecyclePhase::AclGrant)?;
        Ok(WindowsSmbAclGrant {
            path: request.path.clone(),
            principal: request.account.principal.clone(),
            sid: request.account.sid.clone(),
            access: request.access,
            original_dacl_control: Some(security_descriptor_control(&request.path)?),
        })
    }

    fn grant_access(
        &mut self,
        request: WindowsSmbAclGrantRequest,
    ) -> Result<WindowsSmbAclGrant, WindowsSmbLifecycleError> {
        let entries = enumerate_tree(&request.path, WindowsSmbLifecyclePhase::AclGrant)?;
        let original_dacl_control = security_descriptor_control(&request.path)?;
        for (path, is_dir) in &entries {
            apply_acl_change(
                path,
                &request.account.sid,
                request.access,
                windows_sys::Win32::Security::Authorization::GRANT_ACCESS,
                *is_dir,
                WindowsSmbLifecyclePhase::AclGrant,
            )?;
        }
        for (path, _) in &entries {
            verify_effective_access(path, &request.account.sid, request.access)?;
        }
        Ok(WindowsSmbAclGrant {
            path: request.path,
            principal: request.account.principal,
            sid: request.account.sid,
            access: request.access,
            original_dacl_control: Some(original_dacl_control),
        })
    }

    fn revoke_access(
        &mut self,
        grant: &WindowsSmbAclGrant,
    ) -> Result<(), WindowsSmbLifecycleError> {
        let entries = match enumerate_tree(&grant.path, WindowsSmbLifecyclePhase::AclRevoke) {
            Ok(entries) => entries,
            Err(_error) if !grant.path.exists() => return Ok(()),
            Err(error) => return Err(error),
        };
        for (path, is_dir) in entries.iter().rev() {
            apply_acl_change(
                path,
                &grant.sid,
                grant.access,
                windows_sys::Win32::Security::Authorization::REVOKE_ACCESS,
                *is_dir,
                WindowsSmbLifecyclePhase::AclRevoke,
            )?;
        }
        for (path, _) in &entries {
            if contains_explicit_sid(path, &grant.sid)? {
                return Err(WindowsSmbLifecycleError::operation_failed(
                    WindowsSmbLifecyclePhase::AclRevoke,
                    format!(
                        "explicit ACE for generated SID {} remains on '{}'",
                        grant.sid,
                        path.display()
                    ),
                ));
            }
        }
        if let Some(control) = grant.original_dacl_control {
            restore_security_descriptor_control(&grant.path, control)?;
        }
        Ok(())
    }

    fn verify_access(
        &mut self,
        account: &WindowsSmbUserAccount,
        password: &WindowsSmbPassword,
        grants: &[WindowsSmbAclGrant],
    ) -> Result<(), WindowsSmbLifecycleError> {
        verify_access_as_account(account, password, grants)
    }
}

#[cfg(windows)]
fn verify_access_as_account(
    account: &WindowsSmbUserAccount,
    password: &WindowsSmbPassword,
    grants: &[WindowsSmbAclGrant],
) -> Result<(), WindowsSmbLifecycleError> {
    use std::ptr;
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
    use windows_sys::Win32::Security::{
        ImpersonateLoggedOnUser, LogonUserW, RevertToSelf, LOGON32_LOGON_NETWORK,
        LOGON32_PROVIDER_DEFAULT,
    };

    let username = super::user::wide_null(account.name.as_str());
    let domain = super::user::wide_null(&account.domain);
    let mut password_w = super::user::wide_null(password.expose_secret());
    let mut token: HANDLE = ptr::null_mut();
    let logged_on = unsafe {
        LogonUserW(
            username.as_ptr(),
            domain.as_ptr(),
            password_w.as_ptr(),
            LOGON32_LOGON_NETWORK,
            LOGON32_PROVIDER_DEFAULT,
            &mut token,
        )
    };
    super::user::zero_wide(&mut password_w);
    if logged_on == 0 {
        let code = unsafe { GetLastError() };
        return Err(WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::AclGrant,
            format!("LogonUserW access verification failed with win32 error {code}"),
        ));
    }
    if unsafe { ImpersonateLoggedOnUser(token) } == 0 {
        let code = unsafe { GetLastError() };
        unsafe {
            CloseHandle(token);
        }
        return Err(WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::AclGrant,
            format!("ImpersonateLoggedOnUser failed with win32 error {code}"),
        ));
    }

    let result = (|| {
        for grant in grants {
            for (path, is_dir) in enumerate_tree(&grant.path, WindowsSmbLifecyclePhase::AclGrant)? {
                verify_path_open(&path, is_dir, grant.access)?;
            }
        }
        Ok(())
    })();
    let reverted = unsafe { RevertToSelf() };
    unsafe {
        CloseHandle(token);
    }
    if reverted == 0 {
        return Err(WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::AclGrant,
            "RevertToSelf failed after access verification",
        ));
    }
    result
}

#[cfg(windows)]
fn verify_path_open(
    path: &std::path::Path,
    is_dir: bool,
    access: WindowsSmbAccess,
) -> Result<(), WindowsSmbLifecycleError> {
    use windows_sys::Win32::Foundation::{
        CloseHandle, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, DELETE, FILE_DELETE_CHILD, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        OPEN_EXISTING,
    };

    let path_w = super::user::wide_null(&path.display().to_string());
    let desired = GENERIC_READ
        | GENERIC_EXECUTE
        | if access == WindowsSmbAccess::ReadWrite {
            GENERIC_WRITE | DELETE | if is_dir { FILE_DELETE_CHILD } else { 0 }
        } else {
            0
        };
    let handle = unsafe {
        CreateFileW(
            path_w.as_ptr(),
            desired,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT
                | if is_dir {
                    FILE_FLAG_BACKUP_SEMANTICS
                } else {
                    0
                },
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::AclGrant,
            format!(
                "generated SID lacks effective access on '{}': {}",
                path.display(),
                std::io::Error::last_os_error()
            ),
        ));
    }
    unsafe {
        CloseHandle(handle);
    }
    Ok(())
}

#[cfg(windows)]
fn security_descriptor_control(path: &std::path::Path) -> Result<u16, WindowsSmbLifecycleError> {
    use std::ptr;
    use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
    use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{GetSecurityDescriptorControl, DACL_SECURITY_INFORMATION};

    let mut path_w = super::user::wide_null(&path.display().to_string());
    let mut descriptor = ptr::null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            path_w.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::AclGrant,
            format!("failed to read DACL control with win32 error {status}"),
        ));
    }
    let mut control = 0;
    let mut revision = 0;
    let ok = unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) };
    unsafe {
        LocalFree(descriptor);
    }
    if ok == 0 {
        let code = unsafe { GetLastError() };
        return Err(WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::AclGrant,
            format!("GetSecurityDescriptorControl failed with win32 error {code}"),
        ));
    }
    Ok(control)
}

#[cfg(windows)]
fn restore_security_descriptor_control(
    path: &std::path::Path,
    original: u16,
) -> Result<(), WindowsSmbLifecycleError> {
    use std::ptr;
    use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
    use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        SetFileSecurityW, SetSecurityDescriptorControl, DACL_SECURITY_INFORMATION,
        SE_DACL_AUTO_INHERITED, SE_DACL_AUTO_INHERIT_REQ, SE_DACL_PROTECTED,
    };

    let mut path_w = super::user::wide_null(&path.display().to_string());
    let mut descriptor = ptr::null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            path_w.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::AclRevoke,
            format!("failed to read DACL control with win32 error {status}"),
        ));
    }
    let interest = SE_DACL_AUTO_INHERIT_REQ | SE_DACL_PROTECTED;
    let restored = (original & SE_DACL_PROTECTED)
        | if original & SE_DACL_AUTO_INHERITED != 0 {
            SE_DACL_AUTO_INHERIT_REQ
        } else {
            0
        };
    let ok = unsafe { SetSecurityDescriptorControl(descriptor, interest, restored) };
    if ok != 0 {
        let set_ok =
            unsafe { SetFileSecurityW(path_w.as_ptr(), DACL_SECURITY_INFORMATION, descriptor) };
        unsafe {
            LocalFree(descriptor);
        }
        if set_ok != 0 {
            let observed = security_descriptor_control(path)?;
            let observable = SE_DACL_AUTO_INHERITED | SE_DACL_PROTECTED;
            if observed & observable == original & observable {
                return Ok(());
            }
            return Err(WindowsSmbLifecycleError::operation_failed(
                WindowsSmbLifecyclePhase::AclRevoke,
                format!(
                    "restored DACL control differs for '{}': expected 0x{:04x}, observed 0x{:04x}",
                    path.display(),
                    original & observable,
                    observed & observable
                ),
            ));
        }
    } else {
        unsafe {
            LocalFree(descriptor);
        }
    }
    let code = unsafe { GetLastError() };
    Err(WindowsSmbLifecycleError::operation_failed(
        WindowsSmbLifecyclePhase::AclRevoke,
        format!("restoring DACL control failed with win32 error {code}"),
    ))
}

#[cfg(windows)]
fn enumerate_tree(
    root: &std::path::Path,
    phase: WindowsSmbLifecyclePhase,
) -> Result<Vec<(PathBuf, bool)>, WindowsSmbLifecycleError> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let mut result = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        if path.as_os_str().encode_wide().count() > MAX_WINDOWS_PATH_UNITS {
            return Err(WindowsSmbLifecycleError::operation_failed(
                phase,
                format!(
                    "SMB mount tree path exceeds the Windows path limit: '{}'",
                    path.display()
                ),
            ));
        }
        let metadata = std::fs::symlink_metadata(&path).map_err(|error| {
            WindowsSmbLifecycleError::operation_failed(
                phase,
                format!(
                    "failed to inspect SMB mount tree entry '{}': {error}",
                    path.display()
                ),
            )
        })?;
        if path != root && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(WindowsSmbLifecycleError::operation_failed(
                phase,
                format!(
                    "SMB mount tree contains an unsafe reparse-point descendant: '{}'",
                    path.display()
                ),
            ));
        }
        let is_dir = metadata.is_dir();
        result.push((path.clone(), is_dir));
        if result.len() > MAX_ACL_TREE_ENTRIES {
            return Err(WindowsSmbLifecycleError::operation_failed(
                phase,
                format!("SMB mount tree exceeds the {MAX_ACL_TREE_ENTRIES}-entry safety limit"),
            ));
        }
        if is_dir {
            let children = std::fs::read_dir(&path).map_err(|error| {
                WindowsSmbLifecycleError::operation_failed(
                    phase,
                    format!(
                        "failed to enumerate SMB mount directory '{}': {error}",
                        path.display()
                    ),
                )
            })?;
            for child in children {
                let child = child.map_err(|error| {
                    WindowsSmbLifecycleError::operation_failed(
                        phase,
                        format!(
                            "failed to enumerate SMB mount directory '{}': {error}",
                            path.display()
                        ),
                    )
                })?;
                pending.push(child.path());
            }
        }
    }
    Ok(result)
}

#[cfg(windows)]
fn apply_acl_change(
    path: &std::path::Path,
    sid_string: &str,
    access: WindowsSmbAccess,
    mode: windows_sys::Win32::Security::Authorization::ACCESS_MODE,
    is_dir: bool,
    phase: WindowsSmbLifecyclePhase,
) -> Result<(), WindowsSmbLifecycleError> {
    use std::ptr;
    use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSidToSidW, GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW,
        EXPLICIT_ACCESS_W, NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN,
        TRUSTEE_W,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, NO_INHERITANCE, SUB_CONTAINERS_AND_OBJECTS_INHERIT,
    };

    let mut path_w = super::user::wide_null(&path.display().to_string());
    let sid_w = super::user::wide_null(sid_string);
    let mut sid = ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(sid_w.as_ptr(), &mut sid) } == 0 {
        let code = unsafe { GetLastError() };
        return Err(WindowsSmbLifecycleError::operation_failed(
            phase,
            format!("ConvertStringSidToSidW failed with win32 error {code}"),
        ));
    }
    let mut old_dacl = ptr::null_mut();
    let mut security_descriptor = ptr::null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            path_w.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut old_dacl,
            ptr::null_mut(),
            &mut security_descriptor,
        )
    };
    if status != 0 {
        unsafe {
            LocalFree(sid.cast());
        }
        return Err(WindowsSmbLifecycleError::operation_failed(
            phase,
            format!(
                "GetNamedSecurityInfoW failed for '{}' with win32 error {status}",
                path.display()
            ),
        ));
    }

    let trustee = TRUSTEE_W {
        pMultipleTrustee: ptr::null_mut(),
        MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
        TrusteeForm: TRUSTEE_IS_SID,
        TrusteeType: TRUSTEE_IS_UNKNOWN,
        ptstrName: sid.cast(),
    };
    let mut entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: ntfs_access_mask(access),
        grfAccessMode: mode,
        grfInheritance: if is_dir {
            SUB_CONTAINERS_AND_OBJECTS_INHERIT
        } else {
            NO_INHERITANCE
        },
        Trustee: trustee,
    };
    let mut new_acl = ptr::null_mut();
    let status = unsafe { SetEntriesInAclW(1, &mut entry, old_dacl, &mut new_acl) };
    if status == 0 {
        let set_status = unsafe {
            SetNamedSecurityInfoW(
                path_w.as_mut_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                new_acl,
                ptr::null_mut(),
            )
        };
        unsafe {
            LocalFree(new_acl.cast());
            LocalFree(security_descriptor);
            LocalFree(sid.cast());
        }
        if set_status == 0 {
            return Ok(());
        }
        return Err(WindowsSmbLifecycleError::operation_failed(
            phase,
            format!(
                "SetNamedSecurityInfoW failed for '{}' with win32 error {set_status}",
                path.display()
            ),
        ));
    }
    unsafe {
        LocalFree(security_descriptor);
        LocalFree(sid.cast());
    }
    Err(WindowsSmbLifecycleError::operation_failed(
        phase,
        format!(
            "SetEntriesInAclW failed for '{}' with win32 error {status}",
            path.display()
        ),
    ))
}

#[cfg(windows)]
fn verify_effective_access(
    path: &std::path::Path,
    sid_string: &str,
    access: WindowsSmbAccess,
) -> Result<(), WindowsSmbLifecycleError> {
    let (allowed, denied) = explicit_rights(path, sid_string)?;
    let required = ntfs_access_mask(access);
    if allowed & required != required || denied & required != 0 {
        return Err(WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::AclGrant,
            format!(
                "generated SID {sid_string} lacks required effective access on '{}'",
                path.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn explicit_rights(
    path: &std::path::Path,
    sid_string: &str,
) -> Result<(u32, u32), WindowsSmbLifecycleError> {
    use std::ptr;
    use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSidToSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        EqualSid, GetAce, ACE_HEADER, DACL_SECURITY_INFORMATION, INHERITED_ACE,
    };
    use windows_sys::Win32::System::SystemServices::{
        ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE,
    };

    let mut path_w = super::user::wide_null(&path.display().to_string());
    let sid_w = super::user::wide_null(sid_string);
    let mut sid = ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(sid_w.as_ptr(), &mut sid) } == 0 {
        let code = unsafe { GetLastError() };
        return Err(WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::AclGrant,
            format!("ConvertStringSidToSidW failed with win32 error {code}"),
        ));
    }
    let mut dacl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            path_w.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        unsafe {
            LocalFree(sid.cast());
        }
        return Err(WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::AclGrant,
            format!(
                "GetNamedSecurityInfoW failed for '{}' with win32 error {status}",
                path.display()
            ),
        ));
    }
    let ace_count = if dacl.is_null() {
        0
    } else {
        unsafe { (*dacl).AceCount }
    };
    let mut allowed = 0;
    let mut denied = 0;
    for index in 0..ace_count {
        let mut raw = ptr::null_mut();
        if unsafe { GetAce(dacl, index as u32, &mut raw) } == 0 {
            continue;
        }
        let header = unsafe { &*(raw.cast::<ACE_HEADER>()) };
        if header.AceFlags & INHERITED_ACE as u8 != 0 {
            continue;
        }
        let ace_sid = unsafe { raw.cast::<u8>().add(8).cast() };
        if unsafe { EqualSid(sid, ace_sid) } == 0 {
            continue;
        }
        let mask = unsafe { *raw.cast::<u8>().add(4).cast::<u32>() };
        match header.AceType as u32 {
            ACCESS_ALLOWED_ACE_TYPE => allowed |= mask,
            ACCESS_DENIED_ACE_TYPE => denied |= mask,
            _ => {}
        }
    }
    unsafe {
        LocalFree(descriptor);
        LocalFree(sid.cast());
    }
    Ok((allowed, denied))
}

#[cfg(windows)]
fn contains_explicit_sid(
    path: &std::path::Path,
    sid_string: &str,
) -> Result<bool, WindowsSmbLifecycleError> {
    use std::ptr;
    use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSidToSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        EqualSid, GetAce, ACE_HEADER, DACL_SECURITY_INFORMATION, INHERITED_ACE,
    };
    use windows_sys::Win32::System::SystemServices::{
        ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE,
    };

    let mut path_w = super::user::wide_null(&path.display().to_string());
    let sid_w = super::user::wide_null(sid_string);
    let mut sid = ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(sid_w.as_ptr(), &mut sid) } == 0 {
        let code = unsafe { GetLastError() };
        return Err(WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::AclRevoke,
            format!("ConvertStringSidToSidW failed with win32 error {code}"),
        ));
    }
    let mut dacl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            path_w.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        unsafe {
            LocalFree(sid.cast());
        }
        return Err(WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::AclRevoke,
            format!(
                "GetNamedSecurityInfoW failed for '{}' with win32 error {status}",
                path.display()
            ),
        ));
    }
    let ace_count = if dacl.is_null() {
        0
    } else {
        unsafe { (*dacl).AceCount }
    };
    let mut found = false;
    for index in 0..ace_count {
        let mut raw = ptr::null_mut();
        if unsafe { GetAce(dacl, index as u32, &mut raw) } == 0 {
            continue;
        }
        let header = unsafe { &*(raw.cast::<ACE_HEADER>()) };
        if header.AceFlags & INHERITED_ACE as u8 != 0
            || !matches!(
                header.AceType as u32,
                ACCESS_ALLOWED_ACE_TYPE | ACCESS_DENIED_ACE_TYPE
            )
        {
            continue;
        }
        let ace_sid = unsafe { raw.cast::<u8>().add(8).cast() };
        if unsafe { EqualSid(sid, ace_sid) } != 0 {
            found = true;
            break;
        }
    }
    unsafe {
        LocalFree(descriptor);
        LocalFree(sid.cast());
    }
    Ok(found)
}

#[cfg(windows)]
fn ntfs_access_mask(access: WindowsSmbAccess) -> u32 {
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_DELETE_CHILD, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    };
    match access {
        WindowsSmbAccess::ReadOnly => FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
        WindowsSmbAccess::ReadWrite => {
            FILE_GENERIC_READ
                | FILE_GENERIC_EXECUTE
                | FILE_GENERIC_WRITE
                | FILE_DELETE_CHILD
                | DELETE
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use std::process::Command;

    use super::*;
    use crate::windows_x86_64::fs::smb::{
        generate_smb_user_name, NativeWindowsSmbPasswordGenerator, NativeWindowsSmbUserManager,
        WindowsSmbPasswordGenerator, WindowsSmbUserManager,
    };

    fn powershell(script: &str) -> String {
        let output = Command::new("pwsh.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .output()
            .expect("run PowerShell");
        assert!(
            output.status.success(),
            "PowerShell failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

    fn quoted(path: &std::path::Path) -> String {
        path.display().to_string().replace('\'', "''")
    }

    #[test]
    fn windows_smb_protected_acl() {
        let fixture = std::env::temp_dir().join(format!(
            "lsb-windows-smb-protected-acl-{}",
            std::process::id()
        ));
        let root = fixture.join("skills");
        let protected = root.join("mis-it-center");
        let skill = protected.join("SKILL.md");
        let _ = std::fs::remove_dir_all(&fixture);
        std::fs::create_dir_all(&fixture).expect("protected fixture parent");
        powershell(&format!(
            "$s=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;$a=New-Object Security.AccessControl.DirectorySecurity;$a.SetSecurityDescriptorSddlForm(('O:BAG:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{0})' -f $s));Set-Acl -LiteralPath '{}' -AclObject $a",
            quoted(&fixture)
        ));
        std::fs::create_dir_all(&protected).expect("protected test tree");
        std::fs::write(&skill, b"protected skill").expect("skill fixture");
        powershell(&format!(
            "$a=Get-Acl -LiteralPath '{}';$a.SetAccessRuleProtection($true,$true);Set-Acl -LiteralPath '{}' -AclObject $a",
            quoted(&protected),
            quoted(&protected)
        ));
        let before = [
            powershell(&format!("(Get-Acl -LiteralPath '{}').Sddl", quoted(&root))),
            powershell(&format!(
                "(Get-Acl -LiteralPath '{}').Sddl",
                quoted(&protected)
            )),
            powershell(&format!("(Get-Acl -LiteralPath '{}').Sddl", quoted(&skill))),
        ];

        let mut passwords = NativeWindowsSmbPasswordGenerator;
        let name = generate_smb_user_name(&mut passwords).expect("temporary user name");
        let password = passwords.generate_password().expect("temporary password");
        let mut users = NativeWindowsSmbUserManager;
        let account = users
            .create_user(&name, &password)
            .expect("create temporary SMB user");
        let mut acls = NativeWindowsSmbAclManager;
        let grant = acls
            .grant_access(WindowsSmbAclGrantRequest {
                path: root.clone(),
                account: account.clone(),
                access: WindowsSmbAccess::ReadOnly,
            })
            .expect("grant across protected boundary");
        acls.verify_access(&account, &password, std::slice::from_ref(&grant))
            .expect("generated account should enumerate and read the protected tree");
        acls.revoke_access(&grant).expect("revoke exact SID grants");
        users.delete_user(&account).expect("delete temporary user");

        let after = [
            powershell(&format!("(Get-Acl -LiteralPath '{}').Sddl", quoted(&root))),
            powershell(&format!(
                "(Get-Acl -LiteralPath '{}').Sddl",
                quoted(&protected)
            )),
            powershell(&format!("(Get-Acl -LiteralPath '{}').Sddl", quoted(&skill))),
        ];
        assert_eq!(after, before, "root, protected child, and file SDDL");
        let _ = std::fs::remove_dir_all(fixture);
    }
}
