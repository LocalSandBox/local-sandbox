use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use lsb_service_proto::limits::{
    MAX_MOUNT_COMPONENTS, MAX_MOUNT_FILE_BYTES, MAX_MOUNT_WINDOWS_UTF16,
};
use windows_sys::Win32::Foundation::{LocalFree, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    AccessCheck, DACL_SECURITY_INFORMATION, GENERIC_MAPPING, GROUP_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PRIVILEGE_SET, PSECURITY_DESCRIPTOR,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetDriveTypeW, GetFileInformationByHandle, GetFinalPathNameByHandleW,
    GetVolumeInformationW, GetVolumePathNameW, BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ADD_FILE,
    FILE_ADD_SUBDIRECTORY, FILE_ALL_ACCESS, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_ENCRYPTED,
    FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, FILE_ATTRIBUTE_RECALL_ON_OPEN,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_DELETE_CHILD, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    FILE_LIST_DIRECTORY, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_READ_EA,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA,
    OPEN_EXISTING, READ_CONTROL, SYNCHRONIZE, VOLUME_NAME_DOS,
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
    validate_windows_path(&path)?;
    let mut ancestor_pins = Vec::new();
    let mut ancestors = path.ancestors().skip(1).collect::<Vec<_>>();
    ancestors.reverse();
    for ancestor in ancestors {
        let (pin, info) = if let Some(parent) = ancestor_pins.last() {
            let name = ancestor
                .file_name()
                .context("mount ancestor lacks a relative component")?;
            super::relative::open_relative(
                parent,
                name,
                ancestor_access(),
                super::relative::RelativeKind::Directory,
            )?
        } else {
            open_checked(ancestor, ancestor_access(), true)?
        };
        reject_attributes(info.dwFileAttributes, ancestor)?;
        require_access_check(token, &pin, ancestor_access(), ancestor)?;
        ancestor_pins.push(pin);
    }

    let root_parent = ancestor_pins
        .last()
        .context("mount root lacks a pinned parent")?;
    let root_name = path
        .file_name()
        .context("mount root lacks a relative component")?;
    let (root, root_info) = super::relative::open_relative(
        root_parent,
        root_name,
        root_access(access),
        super::relative::RelativeKind::Directory,
    )?;
    require_access_check(token, &root, root_access(access), &path)?;
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
    let summary = inspect_tree(
        token,
        root.try_clone()?,
        &path,
        &final_path,
        access,
        ancestor_pins.len() as u32 + 1,
    )?;
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

fn inspect_tree(
    token: &OwnedHandle,
    root_handle: OwnedHandle,
    root: &Path,
    final_root: &Path,
    access: MountAccess,
    mut access_checks: u32,
) -> Result<WalkSummary> {
    let mut entries = 1u32;
    let mut file_bytes = 0u64;
    let mut pending = vec![(root.to_path_buf(), root_handle)];
    while let Some((directory, directory_handle)) = pending.pop() {
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
            validate_windows_path(&path)?;
            let relative = path
                .strip_prefix(root)
                .context("authorized mount entry escaped its lexical root")?;
            crate::resource::mount_sync::validate_relative_path(relative)?;
            let name = child.file_name();
            let probe_access = entry_access(access, false);
            let (probe, probe_info) = super::relative::open_relative(
                &directory_handle,
                &name,
                probe_access,
                super::relative::RelativeKind::Any,
            )?;
            let is_directory = probe_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
            let desired_access = entry_access(access, is_directory);
            let (handle, info) = if desired_access == probe_access {
                (probe, probe_info)
            } else {
                let reopened = super::relative::open_relative(
                    &directory_handle,
                    &name,
                    desired_access,
                    super::relative::RelativeKind::Directory,
                )?;
                if file_version(&reopened.1) != file_version(&probe_info) {
                    bail!("mount entry changed identity while rights were authorized");
                }
                reopened
            };
            require_access_check(token, &handle, desired_access, &path)?;
            access_checks = access_checks
                .checked_add(1)
                .context("mount access-check count overflow")?;
            reject_attributes(info.dwFileAttributes, &path)?;
            let child_final = final_path(&handle)?;
            if !is_below(&child_final, final_root) {
                bail!("mount entry resolves outside the authorized root");
            }
            if is_directory {
                pending.push((path, handle));
            } else {
                if info.nNumberOfLinks > 1 {
                    bail!("mount contains a regular file with multiple hard links");
                }
                let len = ((info.nFileSizeHigh as u64) << 32) | info.nFileSizeLow as u64;
                if len > MAX_MOUNT_FILE_BYTES {
                    bail!("mount file exceeds the 4 GiB per-file limit");
                }
                file_bytes = file_bytes
                    .checked_add(len)
                    .context("mount byte count overflow")?;
                if file_bytes > MAX_MOUNT_BYTES {
                    bail!("mount tree exceeds the 20 GiB data limit");
                }
            }
        }
    }
    Ok(WalkSummary {
        entries,
        file_bytes,
        access_checks,
    })
}

fn require_access_check(
    token: &OwnedHandle,
    handle: &OwnedHandle,
    desired_access: u32,
    path: &Path,
) -> Result<()> {
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            handle.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 || descriptor.is_null() {
        bail!(
            "query mount DACL for {} failed with {status}",
            path.display()
        );
    }
    let descriptor = LocalSecurityDescriptor(descriptor);
    let mapping = GENERIC_MAPPING {
        GenericRead: FILE_GENERIC_READ,
        GenericWrite: FILE_GENERIC_WRITE,
        GenericExecute: FILE_GENERIC_EXECUTE,
        GenericAll: FILE_ALL_ACCESS,
    };
    let mut privileges = PRIVILEGE_SET::default();
    let mut privilege_bytes = std::mem::size_of::<PRIVILEGE_SET>() as u32;
    let mut granted_access = 0;
    let mut access_status = 0;
    if unsafe {
        AccessCheck(
            descriptor.0,
            token.as_raw_handle() as HANDLE,
            desired_access,
            &mapping,
            &mut privileges,
            &mut privilege_bytes,
            &mut granted_access,
            &mut access_status,
        )
    } == 0
    {
        bail!(
            "AccessCheck for {} failed: {}",
            path.display(),
            std::io::Error::last_os_error()
        );
    }
    if access_status == 0 || granted_access & desired_access != desired_access {
        bail!(
            "client token AccessCheck denied required mount rights for {}",
            path.display()
        );
    }
    Ok(())
}

struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

fn validate_windows_path(path: &Path) -> Result<()> {
    if path.components().count() > MAX_MOUNT_COMPONENTS {
        bail!("mount path exceeds the 256-component limit");
    }
    if path.as_os_str().encode_wide().count() > MAX_MOUNT_WINDOWS_UTF16 {
        bail!("mount path exceeds the 32,767-UTF-16-code-unit limit");
    }
    Ok(())
}

pub(super) fn stage_snapshot(
    token: &OwnedHandle,
    root_pin: OwnedHandle,
    source: &Path,
    final_root: &Path,
    destination: &Path,
) -> Result<crate::resource::mount_sync::TreeSnapshot> {
    if destination.exists() {
        std::fs::remove_dir_all(destination)?;
    }
    std::fs::create_dir_all(destination)?;
    let mut bounds = CopyBounds {
        entries: 1,
        file_bytes: 0,
    };
    if let Err(error) = copy_directory_under_token(
        token,
        &root_pin,
        source,
        final_root,
        destination,
        &mut bounds,
    ) {
        let _ = std::fs::remove_dir_all(destination);
        return Err(error);
    }
    crate::resource::mount_sync::snapshot_tree(destination)
}

fn copy_directory_under_token(
    token: &OwnedHandle,
    source_handle: &OwnedHandle,
    source: &Path,
    final_root: &Path,
    destination: &Path,
    bounds: &mut CopyBounds,
) -> Result<()> {
    let guard = crate::security::impersonation::ImpersonationGuard::for_token(token)?;
    let names = std::fs::read_dir(source)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    guard.revert()?;

    for name in names {
        bounds.entries = bounds
            .entries
            .checked_add(1)
            .context("staged mount entry count overflow")?;
        if bounds.entries > MAX_MOUNT_ENTRIES {
            bail!("staged mount exceeds {MAX_MOUNT_ENTRIES} entries during copy");
        }
        let source_child = source.join(&name);
        let destination_child = destination.join(&name);
        let guard = crate::security::impersonation::ImpersonationGuard::for_token(token)?;
        let desired_access =
            FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | READ_CONTROL | SYNCHRONIZE;
        let (handle, info) = super::relative::open_relative(
            source_handle,
            &name,
            desired_access,
            super::relative::RelativeKind::Any,
        )?;
        require_access_check(token, &handle, desired_access, &source_child)?;
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
            copy_directory_under_token(
                token,
                &handle,
                &source_child,
                final_root,
                &destination_child,
                bounds,
            )?;
        } else {
            let expected_len = ((info.nFileSizeHigh as u64) << 32) | info.nFileSizeLow as u64;
            if expected_len > MAX_MOUNT_FILE_BYTES {
                bail!("staged mount file exceeds the 4 GiB per-file limit during copy");
            }
            bounds.file_bytes = bounds
                .file_bytes
                .checked_add(expected_len)
                .context("staged mount byte count overflow")?;
            if bounds.file_bytes > MAX_MOUNT_BYTES {
                bail!("staged mount exceeds the 20 GiB data limit during copy");
            }
            let mut input = std::fs::File::from(handle);
            let mut output = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&destination_child)?;
            let copied = std::io::copy(
                &mut std::io::Read::take(&mut input, expected_len.saturating_add(1)),
                &mut output,
            )?;
            if copied != expected_len {
                bail!("staged mount file changed length while it was copied");
            }
            let mut final_info = unsafe { std::mem::zeroed() };
            if unsafe {
                GetFileInformationByHandle(input.as_raw_handle() as HANDLE, &mut final_info)
            } == 0
            {
                bail!(
                    "revalidate staged mount source {}: {}",
                    source_child.display(),
                    std::io::Error::last_os_error()
                );
            }
            if file_version(&final_info) != file_version(&info) {
                bail!("staged mount file changed identity or metadata while it was copied");
            }
            output.sync_all()?;
        }
    }
    Ok(())
}

struct CopyBounds {
    entries: u32,
    file_bytes: u64,
}

fn file_version(info: &BY_HANDLE_FILE_INFORMATION) -> (u32, u64, u64, u64) {
    (
        info.dwVolumeSerialNumber,
        ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64,
        ((info.nFileSizeHigh as u64) << 32) | info.nFileSizeLow as u64,
        ((info.ftLastWriteTime.dwHighDateTime as u64) << 32)
            | info.ftLastWriteTime.dwLowDateTime as u64,
    )
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
    let mut protected = vec![
        program_data,
        program_files,
        program_files_x86,
        windows,
        policy.service_root().to_path_buf(),
    ];
    extend_profile_roots(
        &mut protected,
        super::profiles::profile_list_roots()?,
        caller_profile.as_deref(),
    );
    Ok((protected, Some(profiles), caller_profile))
}

fn extend_profile_roots(
    protected: &mut Vec<PathBuf>,
    profiles: Vec<PathBuf>,
    caller_profile: Option<&Path>,
) {
    for profile in profiles {
        if caller_profile.is_some_and(|caller| normalize(&profile) == normalize(caller)) {
            continue;
        }
        if !protected
            .iter()
            .any(|existing| normalize(existing) == normalize(&profile))
        {
            protected.push(profile);
        }
    }
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

#[cfg(test)]
mod tests {
    use super::super::relative;
    use super::*;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Security::{
        DuplicateTokenEx, SecurityImpersonation, TokenImpersonation, TOKEN_DUPLICATE,
        TOKEN_IMPERSONATE, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    #[test]
    fn current_impersonation_token_passes_handle_dacl_access_check() {
        let root = unique_temp_path("access-check");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        let impersonation = current_impersonation_token();
        let desired = root_access(MountAccess::ReadOnly);
        let (directory, _) = open_checked(&root, desired, true).unwrap();
        require_access_check(&impersonation, &directory, desired, &root).unwrap();

        drop(directory);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn current_token_checks_and_stages_a_bounded_snapshot() {
        let source = unique_temp_path("stage-source");
        let destination = unique_temp_path("stage-destination");
        let _ = std::fs::remove_dir_all(&source);
        let _ = std::fs::remove_dir_all(&destination);
        std::fs::create_dir_all(source.join("nested")).unwrap();
        std::fs::write(source.join("root.txt"), b"root").unwrap();
        std::fs::write(source.join("nested").join("child.txt"), b"child").unwrap();

        let impersonation = current_impersonation_token();
        let desired = root_access(MountAccess::ReadOnly);
        let (root, root_info) = open_checked(&source, desired, true).unwrap();
        require_access_check(&impersonation, &root, desired, &source).unwrap();
        let final_root = final_path(&root).unwrap();
        let summary = inspect_tree(
            &impersonation,
            root.try_clone().unwrap(),
            &source,
            &final_root,
            MountAccess::ReadOnly,
            1,
        )
        .unwrap();
        require_directory(&root_info, &source).unwrap();
        assert_eq!(summary.entries, 4);
        assert_eq!(summary.file_bytes, 9);
        assert_eq!(summary.access_checks, summary.entries);

        let snapshot = stage_snapshot(
            &impersonation,
            root.try_clone().unwrap(),
            &source,
            &final_root,
            &destination,
        )
        .unwrap();
        assert_eq!(
            std::fs::read(destination.join("root.txt")).unwrap(),
            b"root"
        );
        assert_eq!(
            std::fs::read(destination.join("nested").join("child.txt")).unwrap(),
            b"child"
        );
        assert_eq!(snapshot.entries.len(), 3);

        drop(root);
        std::fs::remove_dir_all(source).unwrap();
        std::fs::remove_dir_all(destination).unwrap();
    }

    #[test]
    fn relocated_profile_roots_exclude_only_the_current_caller() {
        let mut protected = vec![PathBuf::from(r"C:\ProgramData")];
        extend_profile_roots(
            &mut protected,
            vec![
                PathBuf::from(r"D:\Profiles\alice"),
                PathBuf::from(r"D:\Profiles\bob"),
                PathBuf::from(r"c:\PROGRAMDATA"),
            ],
            Some(Path::new(r"d:\PROFILES\Alice")),
        );
        assert_eq!(
            protected,
            vec![
                PathBuf::from(r"C:\ProgramData"),
                PathBuf::from(r"D:\Profiles\bob")
            ]
        );
    }

    #[test]
    fn current_token_opens_mount_component_chain_relative_to_pins() {
        let root = unique_temp_path("relative-root");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let mut pins = Vec::new();
        let mut ancestors = root.ancestors().skip(1).collect::<Vec<_>>();
        ancestors.reverse();
        for ancestor in ancestors {
            let pin = if let Some(parent) = pins.last() {
                relative::open_relative(
                    parent,
                    ancestor.file_name().unwrap(),
                    ancestor_access(),
                    relative::RelativeKind::Directory,
                )
                .unwrap()
                .0
            } else {
                open_checked(ancestor, ancestor_access(), true).unwrap().0
            };
            pins.push(pin);
        }
        let relative = relative::open_relative(
            pins.last().unwrap(),
            root.file_name().unwrap(),
            root_access(MountAccess::ReadOnly),
            relative::RelativeKind::Directory,
        )
        .unwrap();
        let direct = open_checked(&root, root_access(MountAccess::ReadOnly), true).unwrap();
        assert_eq!(
            identity(&relative.1, final_path(&relative.0).unwrap()),
            identity(&direct.1, final_path(&direct.0).unwrap())
        );

        drop(relative);
        drop(direct);
        drop(pins);
        std::fs::remove_dir_all(root).unwrap();
    }

    fn current_impersonation_token() -> OwnedHandle {
        let mut primary = std::ptr::null_mut();
        assert_ne!(
            unsafe {
                OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_QUERY | TOKEN_DUPLICATE,
                    &mut primary,
                )
            },
            0
        );
        let primary = unsafe { OwnedHandle::from_raw_handle(primary as _) };
        let mut impersonation = std::ptr::null_mut();
        assert_ne!(
            unsafe {
                DuplicateTokenEx(
                    primary.as_raw_handle() as HANDLE,
                    TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
                    std::ptr::null(),
                    SecurityImpersonation,
                    TokenImpersonation,
                    &mut impersonation,
                )
            },
            0
        );
        unsafe { OwnedHandle::from_raw_handle(impersonation as _) }
    }

    fn unique_temp_path(label: &str) -> PathBuf {
        std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!(
                "lsbsw-{label}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ))
    }
}
