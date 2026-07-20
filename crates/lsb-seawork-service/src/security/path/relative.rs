use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use anyhow::{bail, Result};
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    NtCreateFile, FILE_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
    FILE_SYNCHRONOUS_IO_NONALERT,
};
use windows_sys::Win32::Foundation::{
    HANDLE, INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE, STATUS_NO_SUCH_FILE,
    STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

#[derive(Clone, Copy)]
pub(crate) enum RelativeKind {
    Any,
    Directory,
}

pub(crate) fn open_relative(
    parent: &OwnedHandle,
    name: &OsStr,
    access: u32,
    kind: RelativeKind,
) -> Result<(OwnedHandle, BY_HANDLE_FILE_INFORMATION)> {
    open_relative_if_exists(
        parent,
        name,
        access,
        kind,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
    )?
    .ok_or_else(|| anyhow::anyhow!("handle-relative mount entry is absent"))
}

pub(crate) fn open_relative_for_cleanup(
    parent: &OwnedHandle,
    name: &OsStr,
    access: u32,
    kind: RelativeKind,
) -> Result<Option<(OwnedHandle, BY_HANDLE_FILE_INFORMATION)>> {
    open_relative_if_exists(
        parent,
        name,
        access,
        kind,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    )
}

fn open_relative_if_exists(
    parent: &OwnedHandle,
    name: &OsStr,
    access: u32,
    kind: RelativeKind,
    share_mode: u32,
) -> Result<Option<(OwnedHandle, BY_HANDLE_FILE_INFORMATION)>> {
    let mut name = name.encode_wide().collect::<Vec<_>>();
    validate_component(&name)?;
    let byte_len = name
        .len()
        .checked_mul(2)
        .and_then(|length| u16::try_from(length).ok())
        .ok_or_else(|| anyhow::anyhow!("relative mount component exceeds NT string limits"))?;
    let object_name = UNICODE_STRING {
        Length: byte_len,
        MaximumLength: byte_len,
        Buffer: name.as_mut_ptr(),
    };
    let object_attributes = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle() as HANDLE,
        ObjectName: &object_name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut io_status = IO_STATUS_BLOCK::default();
    let mut raw = std::ptr::null_mut();
    let options = FILE_OPEN_REPARSE_POINT
        | FILE_SYNCHRONOUS_IO_NONALERT
        | match kind {
            RelativeKind::Any => 0,
            RelativeKind::Directory => FILE_DIRECTORY_FILE,
        };
    let status = unsafe {
        NtCreateFile(
            &mut raw,
            access,
            &object_attributes,
            &mut io_status,
            std::ptr::null(),
            0,
            share_mode,
            FILE_OPEN,
            options,
            std::ptr::null(),
            0,
        )
    };
    if matches!(
        status,
        STATUS_NO_SUCH_FILE | STATUS_OBJECT_NAME_NOT_FOUND | STATUS_OBJECT_PATH_NOT_FOUND
    ) {
        return Ok(None);
    }
    if status < 0 || raw.is_null() || raw == INVALID_HANDLE_VALUE {
        bail!("handle-relative mount open failed with NTSTATUS 0x{status:08x}");
    }
    let handle = unsafe { OwnedHandle::from_raw_handle(raw as _) };
    let mut info = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(raw, &mut info) } == 0 {
        bail!(
            "inspect handle-relative mount entry: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(Some((handle, info)))
}

fn validate_component(name: &[u16]) -> Result<()> {
    if name.is_empty()
        || name == ['.' as u16]
        || name == ['.' as u16, '.' as u16]
        || name.iter().any(|unit| matches!(*unit, 0 | 47 | 58 | 92))
    {
        bail!("invalid handle-relative mount component");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_components_are_single_non_dot_names() {
        for invalid in ["", ".", "..", "a\\b", "a/b", "a:b", "a\0b"] {
            assert!(validate_component(&invalid.encode_utf16().collect::<Vec<_>>()).is_err());
        }
        assert!(validate_component(&"workspace".encode_utf16().collect::<Vec<_>>()).is_ok());
    }
}
