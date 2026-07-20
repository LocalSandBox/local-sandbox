use std::os::windows::io::{AsRawHandle, OwnedHandle};

use windows_sys::Win32::Foundation::{LocalFree, GENERIC_ALL, GENERIC_WRITE, HANDLE};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetSecurityInfo, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    IsValidAcl, IsValidSid, ACE_HEADER, ACE_INHERITED_OBJECT_TYPE_PRESENT, ACE_OBJECT_TYPE_PRESENT,
    ACL, DACL_SECURITY_INFORMATION, INHERIT_ONLY_ACE, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_APPEND_DATA, FILE_DELETE_CHILD,
    FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA, WRITE_DAC, WRITE_OWNER,
};
use windows_sys::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_ALLOWED_COMPOUND_ACE_TYPE,
    ACCESS_ALLOWED_OBJECT_ACE_TYPE,
};

use crate::ClientError;

const TRUSTED_INSTALLER_SID: &str =
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
const WRITE_LIKE_ACCESS: u32 = GENERIC_ALL
    | GENERIC_WRITE
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER
    | FILE_ADD_FILE
    | FILE_ADD_SUBDIRECTORY
    | FILE_APPEND_DATA
    | FILE_DELETE_CHILD
    | FILE_WRITE_ATTRIBUTES
    | FILE_WRITE_DATA
    | FILE_WRITE_EA;

pub(crate) fn require_protected_package_object(handle: &OwnedHandle) -> Result<(), ClientError> {
    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            handle.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 || descriptor.is_null() {
        return Err(untrusted(format!(
            "query service package security failed with {status}"
        )));
    }
    let _descriptor = LocalSecurityDescriptor(descriptor);
    require_protected_descriptor(owner, dacl)
}

fn require_protected_descriptor(owner: PSID, dacl: *mut ACL) -> Result<(), ClientError> {
    if owner.is_null() || !is_protected_sid(owner)? {
        return Err(untrusted(
            "service package object owner is not a protected principal",
        ));
    }
    if dacl.is_null() {
        return Err(untrusted("service package object has a null DACL"));
    }
    if unsafe { IsValidAcl(dacl) } == 0 {
        return Err(untrusted("service package object has an invalid DACL"));
    }
    let ace_count = unsafe { (*dacl).AceCount as u32 };
    for index in 0..ace_count {
        let mut raw = std::ptr::null_mut();
        if unsafe { windows_sys::Win32::Security::GetAce(dacl, index, &mut raw) } == 0
            || raw.is_null()
        {
            return Err(untrusted("service package DACL contains an unreadable ACE"));
        }
        let header = unsafe { &*(raw as *const ACE_HEADER) };
        if header.AceSize < 8 {
            return Err(untrusted("service package DACL contains a short ACE"));
        }
        if header.AceFlags as u32 & INHERIT_ONLY_ACE != 0 {
            continue;
        }
        let mask = unsafe { std::ptr::read_unaligned((raw as *const u8).add(4).cast::<u32>()) };
        if mask & WRITE_LIKE_ACCESS == 0 {
            continue;
        }
        let sid = match header.AceType as u32 {
            ACCESS_ALLOWED_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_ACE_TYPE => ace_sid(raw, header, 8)?,
            ACCESS_ALLOWED_OBJECT_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE => {
                object_ace_sid(raw, header)?
            }
            ACCESS_ALLOWED_COMPOUND_ACE_TYPE => {
                return Err(untrusted(
                    "service package DACL contains a compound write grant",
                ));
            }
            _ => continue,
        };
        if !is_protected_sid(sid)? {
            return Err(untrusted(
                "service package object is writable by an untrusted principal",
            ));
        }
    }
    Ok(())
}

fn object_ace_sid(raw: *mut core::ffi::c_void, header: &ACE_HEADER) -> Result<PSID, ClientError> {
    if header.AceSize < 12 {
        return Err(untrusted(
            "service package DACL contains a short object ACE",
        ));
    }
    let flags = unsafe { std::ptr::read_unaligned((raw as *const u8).add(8).cast::<u32>()) };
    let mut offset = 12usize;
    if flags & ACE_OBJECT_TYPE_PRESENT != 0 {
        offset += 16;
    }
    if flags & ACE_INHERITED_OBJECT_TYPE_PRESENT != 0 {
        offset += 16;
    }
    ace_sid(raw, header, offset)
}

fn ace_sid(
    raw: *mut core::ffi::c_void,
    header: &ACE_HEADER,
    offset: usize,
) -> Result<PSID, ClientError> {
    let ace_size = header.AceSize as usize;
    if offset
        .checked_add(8)
        .is_none_or(|minimum| minimum > ace_size)
    {
        return Err(untrusted("service package DACL contains a short allow ACE"));
    }
    let sid_bytes = unsafe { (raw as *mut u8).add(offset) };
    let sub_authority_count = unsafe { *sid_bytes.add(1) as usize };
    let sid_size = 8usize
        .checked_add(
            sub_authority_count
                .checked_mul(4)
                .ok_or_else(|| untrusted("service package DACL contains an oversized SID"))?,
        )
        .ok_or_else(|| untrusted("service package DACL contains an oversized SID"))?;
    if offset
        .checked_add(sid_size)
        .is_none_or(|end| end > ace_size)
    {
        return Err(untrusted("service package DACL contains a truncated SID"));
    }
    let sid = sid_bytes.cast();
    if unsafe { IsValidSid(sid) } == 0 {
        return Err(untrusted("service package DACL contains an invalid SID"));
    }
    Ok(sid)
}

fn is_protected_sid(sid: PSID) -> Result<bool, ClientError> {
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err(untrusted(
            "service package descriptor contains an invalid SID",
        ));
    }
    let mut raw = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut raw) } == 0 || raw.is_null() {
        return Err(untrusted(format!(
            "convert service package SID: {}",
            std::io::Error::last_os_error()
        )));
    }
    let Some(length) = (0..184usize).find(|index| unsafe { *raw.add(*index) } == 0) else {
        unsafe { LocalFree(raw.cast()) };
        return Err(untrusted("converted service package SID is not bounded"));
    };
    let value = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(raw, length) });
    unsafe { LocalFree(raw.cast()) };
    Ok(matches!(
        value.as_str(),
        "S-1-5-18" | "S-1-5-32-544" | TRUSTED_INSTALLER_SID
    ))
}

struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}

fn untrusted(message: impl Into<String>) -> ClientError {
    ClientError::ServerNotTrusted(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{GetSecurityDescriptorDacl, GetSecurityDescriptorOwner};

    #[test]
    fn protected_descriptor_accepts_only_readable_users() {
        assert!(check_sddl("O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;BU)").is_ok());
    }

    #[test]
    fn protected_descriptor_rejects_user_write_grant() {
        assert!(check_sddl("O:SYD:P(A;;GA;;;SY)(A;;GW;;;BU)").is_err());
    }

    #[test]
    fn protected_descriptor_rejects_user_owner() {
        assert!(check_sddl("O:BUD:P(A;;GA;;;SY)(A;;GR;;;BU)").is_err());
    }

    #[test]
    fn allow_ace_rejects_sid_declared_beyond_ace() {
        let mut raw = [0u8; 16];
        raw[8] = 1;
        raw[9] = 2;
        let header = ACE_HEADER {
            AceType: ACCESS_ALLOWED_ACE_TYPE as u8,
            AceFlags: 0,
            AceSize: raw.len() as u16,
        };
        assert!(ace_sid(raw.as_mut_ptr().cast(), &header, 8).is_err());
    }

    fn check_sddl(value: &str) -> Result<(), ClientError> {
        let wide = std::ffi::OsStr::new(value)
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let mut descriptor = std::ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        } == 0
            || descriptor.is_null()
        {
            return Err(untrusted("construct test security descriptor"));
        }
        let _descriptor = LocalSecurityDescriptor(descriptor);
        let mut owner = std::ptr::null_mut();
        let mut dacl = std::ptr::null_mut();
        let mut present = 0;
        let mut owner_defaulted = 0;
        let mut dacl_defaulted = 0;
        if unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut owner_defaulted) } == 0
            || unsafe {
                GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut dacl_defaulted)
            } == 0
            || present == 0
        {
            return Err(untrusted("inspect test security descriptor"));
        }
        require_protected_descriptor(owner, dacl)
    }
}
