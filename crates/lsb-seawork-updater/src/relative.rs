use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;

use anyhow::{bail, Result};
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    NtCreateFile, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE,
    FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
};
use windows_sys::Win32::Foundation::{
    HANDLE, INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE, STATUS_OBJECT_NAME_COLLISION,
    UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

#[derive(Clone, Copy)]
pub enum Kind {
    Any,
    Directory,
    File,
}

pub fn open_directory(path: &Path, access: u32) -> Result<OwnedHandle> {
    let wide = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        bail!(
            "open pinned update directory failed: {}",
            std::io::Error::last_os_error()
        );
    }
    let handle = unsafe { OwnedHandle::from_raw_handle(raw as _) };
    let info = information(&handle)?;
    require_kind(&info, Kind::Directory)?;
    Ok(handle)
}

pub fn open_relative(
    parent: &OwnedHandle,
    name: &OsStr,
    access: u32,
) -> Result<(OwnedHandle, BY_HANDLE_FILE_INFORMATION)> {
    create_or_open_relative(
        parent,
        name,
        access,
        Kind::Any,
        windows_sys::Wdk::Storage::FileSystem::FILE_OPEN,
    )?
    .ok_or_else(|| anyhow::anyhow!("handle-relative update source entry is absent"))
}

pub fn create_relative(
    parent: &OwnedHandle,
    name: &OsStr,
    access: u32,
    kind: Kind,
) -> Result<Option<(OwnedHandle, BY_HANDLE_FILE_INFORMATION)>> {
    create_or_open_relative(parent, name, access, kind, FILE_CREATE)
}

fn create_or_open_relative(
    parent: &OwnedHandle,
    name: &OsStr,
    access: u32,
    kind: Kind,
    disposition: u32,
) -> Result<Option<(OwnedHandle, BY_HANDLE_FILE_INFORMATION)>> {
    let mut name = name.encode_wide().collect::<Vec<_>>();
    validate_component(&name)?;
    let byte_len = name
        .len()
        .checked_mul(2)
        .and_then(|length| u16::try_from(length).ok())
        .ok_or_else(|| anyhow::anyhow!("relative update component exceeds NT string limits"))?;
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
            Kind::Any => 0,
            Kind::Directory => FILE_DIRECTORY_FILE,
            Kind::File => FILE_NON_DIRECTORY_FILE,
        };
    let status = unsafe {
        NtCreateFile(
            &mut raw,
            access,
            &object_attributes,
            &mut io_status,
            std::ptr::null(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            disposition,
            options,
            std::ptr::null(),
            0,
        )
    };
    if disposition == FILE_CREATE && status == STATUS_OBJECT_NAME_COLLISION {
        return Ok(None);
    }
    if status < 0 || raw.is_null() || raw == INVALID_HANDLE_VALUE {
        bail!("handle-relative update open failed with NTSTATUS 0x{status:08x}");
    }
    let handle = unsafe { OwnedHandle::from_raw_handle(raw as _) };
    let info = information(&handle)?;
    require_kind(&info, kind)?;
    Ok(Some((handle, info)))
}

fn information(handle: &OwnedHandle) -> Result<BY_HANDLE_FILE_INFORMATION> {
    let mut info = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(handle.as_raw_handle() as HANDLE, &mut info) } == 0 {
        bail!(
            "inspect handle-relative update entry failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(info)
}

fn require_kind(info: &BY_HANDLE_FILE_INFORMATION, kind: Kind) -> Result<()> {
    let directory = info.dwFileAttributes
        & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_DIRECTORY
        != 0;
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || matches!(kind, Kind::Directory) && !directory
        || matches!(kind, Kind::File) && directory
    {
        bail!("handle-relative update entry has an unsafe type or reparse attribute");
    }
    Ok(())
}

fn validate_component(name: &[u16]) -> Result<()> {
    if name.is_empty()
        || name == ['.' as u16]
        || name == ['.' as u16, '.' as u16]
        || name.iter().any(|unit| matches!(*unit, 0 | 47 | 58 | 92))
    {
        bail!("invalid handle-relative update component");
    }
    Ok(())
}
