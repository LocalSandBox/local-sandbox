use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use lsb_service_proto::limits::{MAX_MOUNT_ENTRIES, MAX_MOUNT_FILE_BYTES, MAX_MOUNT_TREE_BYTES};
use windows_sys::Win32::Foundation::{ERROR_NO_MORE_FILES, HANDLE};
use windows_sys::Win32::Storage::FileSystem::{
    FileIdBothDirectoryInfo, FileIdBothDirectoryRestartInfo, GetFileInformationByHandle,
    GetFileInformationByHandleEx, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ID_BOTH_DIR_INFO, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_READ_EA,
    READ_CONTROL, SYNCHRONIZE,
};

use crate::resource::mount_sync::{validate_relative_path, EntryFingerprint, TreeSnapshot};

use super::relative::{open_relative, validate_relative_component, RelativeKind};

const WINDOWS_TO_UNIX_100NS: u64 = 116_444_736_000_000_000;
const DIRECTORY_BUFFER_BYTES: usize = 64 * 1024;

pub(super) fn host_tree(token: &OwnedHandle, root: OwnedHandle) -> Result<TreeSnapshot> {
    snapshot_pinned(root, Some(token))
}

pub(super) fn protected_tree(root: OwnedHandle) -> Result<TreeSnapshot> {
    snapshot_pinned(root, None)
}

fn snapshot_pinned(root: OwnedHandle, token: Option<&OwnedHandle>) -> Result<TreeSnapshot> {
    let root_info = handle_info(&root)?;
    require_safe_entry(&root_info, true)?;
    if let Some(token) = token {
        super::walk::require_access_check(
            token,
            &root,
            directory_access(),
            PathBuf::new().as_path(),
        )?;
    }

    let root_identity = file_identity(&root_info);
    let mut identities = BTreeSet::from([root_identity]);
    let mut snapshot = TreeSnapshot::default();
    let mut pending = vec![(PathBuf::new(), root)];
    let mut total_bytes = 0u64;

    while let Some((relative_directory, directory)) = pending.pop() {
        for name in enumerate_names(&directory)? {
            validate_relative_component(&name)?;
            let relative = relative_directory.join(&name);
            validate_relative_path(&relative)?;
            if snapshot.entries.len() >= MAX_MOUNT_ENTRIES {
                bail!("pinned mount snapshot exceeds entry limit");
            }

            let probe_access = file_access();
            let (probe, probe_info) =
                open_relative(&directory, &name, probe_access, RelativeKind::Any)?;
            let is_directory = probe_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
            let desired_access = if is_directory {
                directory_access()
            } else {
                probe_access
            };
            let (handle, info) = if desired_access == probe_access {
                (probe, probe_info)
            } else {
                let reopened =
                    open_relative(&directory, &name, desired_access, RelativeKind::Directory)?;
                if super::walk::file_version(&reopened.1) != super::walk::file_version(&probe_info)
                {
                    bail!("pinned mount entry changed identity while it was opened");
                }
                reopened
            };
            require_safe_entry(&info, is_directory)?;
            if let Some(token) = token {
                super::walk::require_access_check(token, &handle, desired_access, &relative)?;
            }
            if !identities.insert(file_identity(&info)) {
                bail!("pinned mount snapshot contains a repeated file identity");
            }

            let len = file_len(&info);
            let content_hash = if is_directory {
                pending.push((relative.clone(), handle));
                None
            } else {
                if len > MAX_MOUNT_FILE_BYTES {
                    bail!("pinned mount snapshot file exceeds per-file byte limit");
                }
                total_bytes = total_bytes
                    .checked_add(len)
                    .context("pinned mount snapshot byte overflow")?;
                if total_bytes > MAX_MOUNT_TREE_BYTES {
                    bail!("pinned mount snapshot exceeds byte limit");
                }
                Some(hash_open_file(handle, &info)?)
            };
            if snapshot
                .entries
                .insert(
                    relative,
                    EntryFingerprint {
                        directory: is_directory,
                        len,
                        modified_ns: modified_ns(&info)?,
                        content_hash,
                    },
                )
                .is_some()
            {
                bail!("pinned mount snapshot contains a duplicate path");
            }
        }
    }
    Ok(snapshot)
}

fn enumerate_names(directory: &OwnedHandle) -> Result<Vec<OsString>> {
    let words = DIRECTORY_BUFFER_BYTES / std::mem::size_of::<u64>();
    let mut buffer = vec![0u64; words];
    let mut names = Vec::new();
    let mut restart = true;
    loop {
        buffer.fill(0);
        let class = if restart {
            FileIdBothDirectoryRestartInfo
        } else {
            FileIdBothDirectoryInfo
        };
        restart = false;
        let ok = unsafe {
            GetFileInformationByHandleEx(
                directory.as_raw_handle() as HANDLE,
                class,
                buffer.as_mut_ptr().cast(),
                DIRECTORY_BUFFER_BYTES as u32,
            )
        };
        if ok == 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
                break;
            }
            return Err(error).context("enumerate pinned mount directory handle");
        }

        let bytes = unsafe {
            std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), DIRECTORY_BUFFER_BYTES)
        };
        let mut offset = 0usize;
        loop {
            let header_size = std::mem::offset_of!(FILE_ID_BOTH_DIR_INFO, FileName);
            if offset
                .checked_add(header_size)
                .is_none_or(|end| end > bytes.len())
            {
                bail!("directory enumeration returned a truncated record");
            }
            let record = unsafe {
                std::ptr::read_unaligned(bytes.as_ptr().add(offset).cast::<FILE_ID_BOTH_DIR_INFO>())
            };
            let name_bytes = record.FileNameLength as usize;
            if !name_bytes.is_multiple_of(2) {
                bail!("directory enumeration returned an invalid UTF-16 byte length");
            }
            let name_start = offset
                .checked_add(header_size)
                .context("directory enumeration record overflow")?;
            let name_end = name_start
                .checked_add(name_bytes)
                .context("directory enumeration name overflow")?;
            if name_end > bytes.len() {
                bail!("directory enumeration returned a truncated name");
            }
            let units = unsafe {
                std::slice::from_raw_parts(
                    bytes.as_ptr().add(name_start).cast::<u16>(),
                    name_bytes / 2,
                )
            };
            let name = OsString::from_wide(units);
            if name != OsStr::new(".") && name != OsStr::new("..") {
                if names.len() >= MAX_MOUNT_ENTRIES {
                    bail!("pinned mount directory exceeds entry limit");
                }
                names.push(name);
            }
            if record.NextEntryOffset == 0 {
                break;
            }
            let next = record.NextEntryOffset as usize;
            if next < header_size
                || offset
                    .checked_add(next)
                    .is_none_or(|end| end >= bytes.len())
            {
                bail!("directory enumeration returned an invalid next-record offset");
            }
            offset += next;
        }
    }
    Ok(names)
}

fn hash_open_file(handle: OwnedHandle, expected: &BY_HANDLE_FILE_INFORMATION) -> Result<[u8; 32]> {
    let expected_len = file_len(expected);
    let mut file = std::fs::File::from(handle);
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut actual_len = 0u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        actual_len = actual_len
            .checked_add(read as u64)
            .context("pinned mount snapshot byte overflow")?;
        if actual_len > expected_len || actual_len > MAX_MOUNT_FILE_BYTES {
            bail!("pinned mount file grew while it was snapshotted");
        }
        hasher.update(&buffer[..read]);
    }
    let final_info = handle_info_from_raw(file.as_raw_handle() as HANDLE)?;
    if actual_len != expected_len
        || super::walk::file_version(&final_info) != super::walk::file_version(expected)
    {
        bail!("pinned mount file changed while it was snapshotted");
    }
    Ok(*hasher.finalize().as_bytes())
}

fn require_safe_entry(info: &BY_HANDLE_FILE_INFORMATION, expected_directory: bool) -> Result<()> {
    super::walk::reject_attributes(info.dwFileAttributes, PathBuf::new().as_path())?;
    let is_directory = info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    if is_directory != expected_directory {
        bail!("pinned mount entry changed type while it was opened");
    }
    if info.nNumberOfLinks > 1 {
        bail!("pinned mount snapshot contains an entry with multiple hard links");
    }
    Ok(())
}

fn handle_info(handle: &OwnedHandle) -> Result<BY_HANDLE_FILE_INFORMATION> {
    handle_info_from_raw(handle.as_raw_handle() as HANDLE)
}

fn handle_info_from_raw(raw: HANDLE) -> Result<BY_HANDLE_FILE_INFORMATION> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(raw, &mut info) } == 0 {
        return Err(std::io::Error::last_os_error()).context("inspect pinned mount handle");
    }
    Ok(info)
}

fn file_identity(info: &BY_HANDLE_FILE_INFORMATION) -> (u32, u64) {
    (
        info.dwVolumeSerialNumber,
        ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64,
    )
}

fn file_len(info: &BY_HANDLE_FILE_INFORMATION) -> u64 {
    ((info.nFileSizeHigh as u64) << 32) | info.nFileSizeLow as u64
}

fn modified_ns(info: &BY_HANDLE_FILE_INFORMATION) -> Result<u128> {
    let ticks = ((info.ftLastWriteTime.dwHighDateTime as u64) << 32)
        | info.ftLastWriteTime.dwLowDateTime as u64;
    let unix_ticks = ticks
        .checked_sub(WINDOWS_TO_UNIX_100NS)
        .context("pinned mount entry modified time is before Unix epoch")?;
    Ok(unix_ticks as u128 * 100)
}

fn directory_access() -> u32 {
    FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | FILE_READ_EA | READ_CONTROL | SYNCHRONIZE
}

fn file_access() -> u32 {
    FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | READ_CONTROL | SYNCHRONIZE
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Security::{
        DuplicateTokenEx, SecurityImpersonation, TokenImpersonation, TOKEN_DUPLICATE,
        TOKEN_IMPERSONATE, TOKEN_QUERY,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    #[test]
    fn pinned_snapshots_are_fresh_and_match_under_the_caller_token() {
        let root = unique_path("fresh-snapshot");
        std::fs::create_dir_all(root.join("nested")).unwrap();
        std::fs::write(root.join("alpha.txt"), b"alpha").unwrap();
        std::fs::write(root.join("nested").join("beta.txt"), b"beta").unwrap();

        let root_handle = open_root(&root);
        let first = protected_tree(root_handle.try_clone().unwrap()).unwrap();
        assert_eq!(first.entries.len(), 3);
        assert_eq!(
            first.entries[&PathBuf::from("alpha.txt")].content_hash,
            Some(*blake3::hash(b"alpha").as_bytes())
        );

        std::fs::write(root.join("alpha.txt"), b"changed").unwrap();
        std::fs::remove_file(root.join("nested").join("beta.txt")).unwrap();
        std::fs::write(root.join("nested").join("gamma.txt"), b"gamma").unwrap();
        let second = protected_tree(root_handle.try_clone().unwrap()).unwrap();
        assert_ne!(first, second);
        assert!(second
            .entries
            .contains_key(&PathBuf::from("nested").join("gamma.txt")));
        assert!(!second
            .entries
            .contains_key(&PathBuf::from("nested").join("beta.txt")));

        let token = current_impersonation_token();
        let guard = crate::security::impersonation::ImpersonationGuard::for_token(&token).unwrap();
        let host = host_tree(&token, root_handle.try_clone().unwrap()).unwrap();
        guard.revert().unwrap();
        assert_eq!(host, second);

        drop(root_handle);
        std::fs::remove_dir_all(root).unwrap();
    }

    fn open_root(path: &std::path::Path) -> OwnedHandle {
        let wide = path
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                directory_access(),
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(raw, INVALID_HANDLE_VALUE);
        unsafe { OwnedHandle::from_raw_handle(raw as _) }
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

    fn unique_path(label: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
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
