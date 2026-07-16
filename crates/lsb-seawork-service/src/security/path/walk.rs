use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetDriveTypeW, GetFileInformationByHandle, GetFinalPathNameByHandleW,
    GetVolumeInformationW, GetVolumePathNameW, BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ADD_FILE,
    FILE_ADD_SUBDIRECTORY, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_ENCRYPTED,
    FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, FILE_ATTRIBUTE_RECALL_ON_OPEN,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_DELETE_CHILD, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES,
    FILE_READ_DATA, FILE_READ_EA, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES,
    FILE_WRITE_DATA, FILE_WRITE_EA, OPEN_EXISTING, READ_CONTROL, SYNCHRONIZE, VOLUME_NAME_DOS,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW;
use windows_sys::Win32::System::WindowsProgramming::DRIVE_FIXED;
use windows_sys::Win32::UI::Shell::{
    FOLDERID_Profile, FOLDERID_ProgramData, FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX86,
    FOLDERID_UserProfiles, SHGetKnownFolderPath,
};

use super::identity::{AuthorizedMountRoot, FileIdentity, MountAccess, WalkSummary};
use super::policy::{
    require_outside_protected_roots, validate_lexical, MountPolicy, MAX_MOUNT_BYTES,
    MAX_MOUNT_ENTRIES,
};

pub(super) fn authorize(
    token: &OwnedHandle,
    policy: &MountPolicy,
    path: PathBuf,
    access: MountAccess,
    owner_sid: String,
) -> Result<AuthorizedMountRoot> {
    validate_lexical(&path)?;
    let mut ancestor_pins = Vec::new();
    let mut ancestors = path.ancestors().skip(1).collect::<Vec<_>>();
    ancestors.reverse();
    for ancestor in ancestors {
        ancestor_pins.push(open_checked(ancestor, ancestor_access(), true)?.0);
    }

    let (root, root_info) = open_checked(&path, root_access(access), true)?;
    require_directory(&root_info, &path)?;
    reject_attributes(root_info.dwFileAttributes, &path)?;
    if root_info.nNumberOfLinks > 1 {
        bail!("mount root has multiple hard links");
    }
    let final_path = final_path(&root)?;
    let (protected, profiles, caller_profile) = protected_roots(token, policy)?;
    require_outside_protected_roots(
        &final_path,
        &protected,
        profiles.as_deref(),
        caller_profile.as_deref(),
    )?;
    require_supported_volume(&final_path)?;

    let identity = identity(&root_info, final_path.clone());
    let summary = inspect_tree(&path, &final_path, access)?;
    Ok(AuthorizedMountRoot::new(
        root,
        ancestor_pins,
        path,
        identity,
        owner_sid,
        access,
        summary,
    ))
}

fn inspect_tree(root: &Path, final_root: &Path, access: MountAccess) -> Result<WalkSummary> {
    let mut entries = 1u32;
    let mut file_bytes = 0u64;
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for child in std::fs::read_dir(&directory)
            .with_context(|| format!("enumerate authorized mount {}", directory.display()))?
        {
            let child = child?;
            entries = entries
                .checked_add(1)
                .context("mount entry count overflow")?;
            if entries > MAX_MOUNT_ENTRIES {
                bail!("mount tree exceeds {MAX_MOUNT_ENTRIES} entries");
            }
            let path = child.path();
            let (handle, info) = open_checked(
                &path,
                entry_access(access, child.file_type()?.is_dir()),
                true,
            )?;
            reject_attributes(info.dwFileAttributes, &path)?;
            let child_final = final_path(&handle)?;
            if !is_below(&child_final, final_root) {
                bail!("mount entry resolves outside the authorized root");
            }
            let is_directory = info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
            if is_directory {
                pending.push(path);
            } else {
                if info.nNumberOfLinks > 1 {
                    bail!("mount contains a regular file with multiple hard links");
                }
                let len = ((info.nFileSizeHigh as u64) << 32) | info.nFileSizeLow as u64;
                file_bytes = file_bytes
                    .checked_add(len)
                    .context("mount byte count overflow")?;
                if file_bytes > MAX_MOUNT_BYTES {
                    bail!("mount tree exceeds the 10 GiB data limit");
                }
            }
        }
    }
    Ok(WalkSummary {
        entries,
        file_bytes,
    })
}

pub(super) fn stage_snapshot(
    token: &OwnedHandle,
    _root_pin: OwnedHandle,
    source: &Path,
    final_root: &Path,
    destination: &Path,
) -> Result<crate::resource::mount_sync::TreeSnapshot> {
    if destination.exists() {
        std::fs::remove_dir_all(destination)?;
    }
    std::fs::create_dir_all(destination)?;
    if let Err(error) = copy_directory_under_token(token, source, final_root, destination) {
        let _ = std::fs::remove_dir_all(destination);
        return Err(error);
    }
    crate::resource::mount_sync::snapshot_tree(destination)
}

fn copy_directory_under_token(
    token: &OwnedHandle,
    source: &Path,
    final_root: &Path,
    destination: &Path,
) -> Result<()> {
    let guard = crate::security::impersonation::ImpersonationGuard::for_token(token)?;
    let names = std::fs::read_dir(source)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    guard.revert()?;

    for name in names {
        let source_child = source.join(&name);
        let destination_child = destination.join(&name);
        let guard = crate::security::impersonation::ImpersonationGuard::for_token(token)?;
        let (handle, info) = open_checked(
            &source_child,
            FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | READ_CONTROL | SYNCHRONIZE,
            true,
        )?;
        let child_final = final_path(&handle)?;
        if !is_below(&child_final, final_root) {
            bail!("staged mount entry resolves outside the authorized root");
        }
        let directory = info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        if !directory && info.nNumberOfLinks > 1 {
            bail!("staged mount contains a regular file with multiple hard links");
        }
        guard.revert()?;

        if directory {
            std::fs::create_dir(&destination_child)?;
            copy_directory_under_token(token, &source_child, final_root, &destination_child)?;
        } else {
            let mut input = std::fs::File::from(handle);
            let mut output = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&destination_child)?;
            std::io::copy(&mut input, &mut output)?;
            output.sync_all()?;
        }
    }
    Ok(())
}

fn open_checked(
    path: &Path,
    access: u32,
    directory: bool,
) -> Result<(OwnedHandle, BY_HANDLE_FILE_INFORMATION)> {
    let wide = wide(path.as_os_str());
    let flags = FILE_FLAG_OPEN_REPARSE_POINT
        | if directory {
            FILE_FLAG_BACKUP_SEMANTICS
        } else {
            0
        };
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            flags,
            std::ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        bail!(
            "client token cannot open {} with required mount rights: {}",
            path.display(),
            std::io::Error::last_os_error()
        );
    }
    let handle = unsafe { OwnedHandle::from_raw_handle(raw as _) };
    let mut info = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(raw, &mut info) } == 0 {
        bail!(
            "inspect mount handle {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        );
    }
    reject_attributes(info.dwFileAttributes, path)?;
    Ok((handle, info))
}

fn ancestor_access() -> u32 {
    FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE
}

fn root_access(access: MountAccess) -> u32 {
    let read =
        FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | FILE_READ_EA | READ_CONTROL | SYNCHRONIZE;
    match access {
        MountAccess::ReadOnly => read,
        MountAccess::ReadWrite => {
            read | FILE_ADD_FILE
                | FILE_ADD_SUBDIRECTORY
                | FILE_WRITE_ATTRIBUTES
                | FILE_WRITE_EA
                | FILE_DELETE_CHILD
        }
    }
}

fn entry_access(access: MountAccess, directory: bool) -> u32 {
    let read = FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | READ_CONTROL | SYNCHRONIZE;
    match access {
        MountAccess::ReadOnly => read,
        MountAccess::ReadWrite if directory => root_access(access) | DELETE,
        MountAccess::ReadWrite => {
            read | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | DELETE
        }
    }
}

fn require_directory(info: &BY_HANDLE_FILE_INFORMATION, path: &Path) -> Result<()> {
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        bail!("mount root is not a directory: {}", path.display());
    }
    Ok(())
}

fn reject_attributes(attributes: u32, path: &Path) -> Result<()> {
    let denied = FILE_ATTRIBUTE_REPARSE_POINT
        | FILE_ATTRIBUTE_ENCRYPTED
        | FILE_ATTRIBUTE_OFFLINE
        | FILE_ATTRIBUTE_RECALL_ON_OPEN
        | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;
    if attributes & denied != 0 {
        bail!(
            "mount entry has reparse, EFS, offline, or cloud-recall attributes: {}",
            path.display()
        );
    }
    Ok(())
}

fn final_path(handle: &OwnedHandle) -> Result<PathBuf> {
    let raw = handle.as_raw_handle() as HANDLE;
    let flags = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS;
    let required = unsafe { GetFinalPathNameByHandleW(raw, std::ptr::null_mut(), 0, flags) };
    if required == 0 {
        bail!(
            "query final mount path size: {}",
            std::io::Error::last_os_error()
        );
    }
    let mut buffer = vec![0u16; required as usize + 1];
    let length =
        unsafe { GetFinalPathNameByHandleW(raw, buffer.as_mut_ptr(), buffer.len() as u32, flags) };
    if length == 0 || length as usize >= buffer.len() {
        bail!(
            "query final mount path: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(PathBuf::from(OsString::from_wide(
        &buffer[..length as usize],
    )))
}

fn require_supported_volume(path: &Path) -> Result<()> {
    let input = wide(path.as_os_str());
    let mut volume = vec![0u16; 1024];
    if unsafe { GetVolumePathNameW(input.as_ptr(), volume.as_mut_ptr(), volume.len() as u32) } == 0
    {
        bail!("resolve mount volume: {}", std::io::Error::last_os_error());
    }
    if unsafe { GetDriveTypeW(volume.as_ptr()) } != DRIVE_FIXED {
        bail!("mount root must be on a local fixed drive");
    }
    let mut fs_name = vec![0u16; 64];
    if unsafe {
        GetVolumeInformationW(
            volume.as_ptr(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            fs_name.as_mut_ptr(),
            fs_name.len() as u32,
        )
    } == 0
    {
        bail!(
            "query mount filesystem: {}",
            std::io::Error::last_os_error()
        );
    }
    let len = fs_name
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(fs_name.len());
    let fs_name = String::from_utf16_lossy(&fs_name[..len]);
    if !fs_name.eq_ignore_ascii_case("NTFS") && !fs_name.eq_ignore_ascii_case("ReFS") {
        bail!("mount root filesystem must be NTFS or ReFS");
    }
    let volume_path = PathBuf::from(OsString::from_wide(
        &volume[..volume
            .iter()
            .position(|value| *value == 0)
            .unwrap_or(volume.len())],
    ));
    if normalize(path) == normalize(&volume_path) {
        bail!("volume roots are not eligible mount roots");
    }
    Ok(())
}

fn protected_roots(
    token: &OwnedHandle,
    policy: &MountPolicy,
) -> Result<(Vec<PathBuf>, Option<PathBuf>, Option<PathBuf>)> {
    let program_data = known_folder(&FOLDERID_ProgramData, std::ptr::null_mut())?;
    let program_files = known_folder(&FOLDERID_ProgramFiles, std::ptr::null_mut())?;
    let program_files_x86 = known_folder(&FOLDERID_ProgramFilesX86, std::ptr::null_mut())?;
    let profiles = known_folder(&FOLDERID_UserProfiles, std::ptr::null_mut())?;
    let caller_profile = known_folder(&FOLDERID_Profile, token.as_raw_handle() as HANDLE).ok();
    let windows = windows_directory()?;
    Ok((
        vec![
            program_data,
            program_files,
            program_files_x86,
            windows,
            policy.service_root().to_path_buf(),
        ],
        Some(profiles),
        caller_profile,
    ))
}

fn windows_directory() -> Result<PathBuf> {
    let mut buffer = vec![0u16; 32_768];
    let length = unsafe { GetWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    if length == 0 || length as usize >= buffer.len() {
        bail!(
            "GetWindowsDirectoryW failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(PathBuf::from(OsString::from_wide(
        &buffer[..length as usize],
    )))
}

fn known_folder(id: &windows_sys::core::GUID, token: HANDLE) -> Result<PathBuf> {
    let mut raw = std::ptr::null_mut();
    let result = unsafe { SHGetKnownFolderPath(id, 0, token, &mut raw) };
    if result < 0 {
        bail!("SHGetKnownFolderPath failed: HRESULT 0x{result:08x}");
    }
    let len = (0..)
        .take_while(|index| unsafe { *raw.add(*index) } != 0)
        .count();
    let path = PathBuf::from(OsString::from_wide(unsafe {
        std::slice::from_raw_parts(raw, len)
    }));
    unsafe { CoTaskMemFree(raw.cast()) };
    Ok(path)
}

fn identity(info: &BY_HANDLE_FILE_INFORMATION, final_path: PathBuf) -> FileIdentity {
    FileIdentity {
        volume_serial: info.dwVolumeSerialNumber,
        file_index: ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64,
        final_path,
    }
}

fn is_below(path: &Path, root: &Path) -> bool {
    let path = normalize(path);
    let root = normalize(root);
    path == root
        || path
            .strip_prefix(&root)
            .is_some_and(|suffix| suffix.starts_with('\\'))
}

fn normalize(path: &Path) -> String {
    path.as_os_str()
        .to_string_lossy()
        .trim_start_matches("\\\\?\\")
        .trim_end_matches('\\')
        .replace('/', "\\")
        .to_lowercase()
}

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}
