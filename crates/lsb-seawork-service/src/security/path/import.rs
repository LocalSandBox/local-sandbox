use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::path::{Component, Path};

use anyhow::{bail, Context, Result};
use windows_sys::Wdk::Storage::FileSystem::{
    FileDispositionInformationEx, NtSetInformationFile, FILE_DISPOSITION_DELETE,
    FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE, FILE_DISPOSITION_INFORMATION_EX,
    FILE_DISPOSITION_POSIX_SEMANTICS,
};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Storage::FileSystem::{
    GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ADD_FILE,
    FILE_ADD_SUBDIRECTORY, FILE_ATTRIBUTE_DIRECTORY, FILE_DELETE_CHILD, FILE_LIST_DIRECTORY,
    FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_READ_EA, READ_CONTROL, SYNCHRONIZE,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

use crate::resource::mount_sync::EntryFingerprint;

use super::relative::{self, RelativeKind};

pub(super) fn apply_host_import(
    token: &OwnedHandle,
    host_root: &OwnedHandle,
    staging_root: &OwnedHandle,
    relative_path: &Path,
    desired: Option<&EntryFingerprint>,
) -> Result<()> {
    crate::resource::mount_sync::validate_relative_path(relative_path)?;
    let components = relative_components(relative_path)?;

    let guard = crate::security::impersonation::ImpersonationGuard::for_token(token)?;
    let source = open_host_entry(token, host_root, &components, desired)?;
    guard.revert().context("revert import source token")?;

    match (source, desired) {
        (None, None) => delete_target(staging_root, &components),
        (Some((_, info)), Some(expected)) if expected.directory => {
            require_source_matches(&info, expected)?;
            ensure_target_directory(staging_root, &components)
        }
        (Some((source, info)), Some(expected)) => {
            require_source_matches(&info, expected)?;
            publish_target_file(staging_root, &components, source, &info, expected)
        }
        (None, Some(_)) => bail!("authorized import source disappeared after observation"),
        (Some(_), None) => bail!("authorized import source reappeared after observation"),
    }
}

fn open_host_entry(
    token: &OwnedHandle,
    root: &OwnedHandle,
    components: &[OsString],
    desired: Option<&EntryFingerprint>,
) -> Result<Option<(OwnedHandle, BY_HANDLE_FILE_INFORMATION)>> {
    let (leaf, parents) = components
        .split_last()
        .context("host import path is empty")?;
    let mut parent = root.try_clone()?;
    for component in parents {
        let Some((child, info)) = relative::open_relative_optional(
            &parent,
            component,
            source_directory_access(),
            RelativeKind::Directory,
        )?
        else {
            return Ok(None);
        };
        super::export::require_safe_entry(&info, true)?;
        super::walk::require_access_check(
            token,
            &child,
            source_directory_access(),
            Path::new(component),
        )?;
        parent = child;
    }
    let access = match desired {
        Some(entry) if entry.directory => source_directory_access(),
        Some(_) => source_file_access(),
        None => FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
    };
    let Some((entry, info)) =
        relative::open_relative_optional(&parent, leaf, access, RelativeKind::Any)?
    else {
        return Ok(None);
    };
    let directory = info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    super::export::require_safe_entry(&info, directory)?;
    super::walk::require_access_check(token, &entry, access, Path::new(leaf))?;
    Ok(Some((entry, info)))
}

fn require_source_matches(
    info: &BY_HANDLE_FILE_INFORMATION,
    expected: &EntryFingerprint,
) -> Result<()> {
    let directory = info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    if directory != expected.directory || file_len(info) != expected.len {
        bail!("authorized import source changed type or length after observation");
    }
    if directory != expected.content_hash.is_none() {
        bail!("authorized import fingerprint has an invalid type/hash shape");
    }
    Ok(())
}

fn publish_target_file(
    root: &OwnedHandle,
    components: &[OsString],
    source: OwnedHandle,
    source_info: &BY_HANDLE_FILE_INFORMATION,
    expected: &EntryFingerprint,
) -> Result<()> {
    let (leaf, parents) = components
        .split_last()
        .context("stage import destination is empty")?;
    let parent = open_or_create_target_parents(root, parents)?;
    remove_directory_target_if_present(&parent, leaf)?;
    let mut output = super::export::create_temporary(&parent)?;
    let result = (|| {
        let mut source = std::fs::File::from(source);
        let expected_hash = expected
            .content_hash
            .context("file import fingerprint lacks a content hash")?;
        let mut hasher = blake3::Hasher::new();
        let mut buffer = [0u8; 64 * 1024];
        let mut copied = 0u64;
        loop {
            let read = source.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            copied = copied
                .checked_add(read as u64)
                .context("import byte count overflow")?;
            if copied > expected.len {
                bail!("authorized import source grew after observation");
            }
            hasher.update(&buffer[..read]);
            output.write_all(&buffer[..read])?;
        }
        let final_info = handle_info(&source)?;
        if copied != expected.len
            || *hasher.finalize().as_bytes() != expected_hash
            || super::walk::file_version(&final_info) != super::walk::file_version(source_info)
        {
            bail!("authorized import source changed while it was copied");
        }
        output.sync_all()?;
        super::export::rename_relative(&output, &parent, leaf, true)
    })();
    if result.is_err() {
        super::export::delete_on_close(&output);
    }
    result
}

fn ensure_target_directory(root: &OwnedHandle, components: &[OsString]) -> Result<()> {
    let (leaf, parents) = components
        .split_last()
        .context("stage import directory is empty")?;
    let parent = open_or_create_target_parents(root, parents)?;
    if let Some((existing, info)) =
        relative::open_relative_optional(&parent, leaf, target_entry_access(), RelativeKind::Any)?
    {
        let directory = info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        super::export::require_safe_entry(&info, directory)?;
        if directory {
            return Ok(());
        }
        mark_delete(&existing)?;
    }
    let created = relative::create_relative(
        &parent,
        leaf,
        target_directory_access(),
        RelativeKind::Directory,
    )?;
    let (directory, info) = match created {
        Some(value) => value,
        None => relative::open_relative(
            &parent,
            leaf,
            target_directory_access(),
            RelativeKind::Directory,
        )?,
    };
    super::export::require_safe_entry(&info, true)?;
    drop(directory);
    Ok(())
}

fn delete_target(root: &OwnedHandle, components: &[OsString]) -> Result<()> {
    let (leaf, parents) = components
        .split_last()
        .context("stage import deletion path is empty")?;
    let Some(parent) = open_target_parents(root, parents)? else {
        return Ok(());
    };
    let Some((entry, info)) =
        relative::open_relative_optional(&parent, leaf, target_entry_access(), RelativeKind::Any)?
    else {
        return Ok(());
    };
    let directory = info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    super::export::require_safe_entry(&info, directory)?;
    mark_delete(&entry)
}

fn remove_directory_target_if_present(parent: &OwnedHandle, leaf: &OsString) -> Result<()> {
    let Some((entry, info)) =
        relative::open_relative_optional(parent, leaf, target_entry_access(), RelativeKind::Any)?
    else {
        return Ok(());
    };
    let directory = info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    super::export::require_safe_entry(&info, directory)?;
    if directory {
        mark_delete(&entry)?;
    }
    Ok(())
}

fn open_or_create_target_parents(
    root: &OwnedHandle,
    components: &[OsString],
) -> Result<OwnedHandle> {
    let mut parent = root.try_clone()?;
    for component in components {
        let opened = relative::open_relative_optional(
            &parent,
            component,
            target_directory_access(),
            RelativeKind::Directory,
        )?;
        let (child, info) = match opened {
            Some(value) => value,
            None => match relative::create_relative(
                &parent,
                component,
                target_directory_access(),
                RelativeKind::Directory,
            )? {
                Some(value) => value,
                None => relative::open_relative(
                    &parent,
                    component,
                    target_directory_access(),
                    RelativeKind::Directory,
                )?,
            },
        };
        super::export::require_safe_entry(&info, true)?;
        parent = child;
    }
    Ok(parent)
}

fn open_target_parents(root: &OwnedHandle, components: &[OsString]) -> Result<Option<OwnedHandle>> {
    let mut parent = root.try_clone()?;
    for component in components {
        let Some((child, info)) = relative::open_relative_optional(
            &parent,
            component,
            target_directory_access(),
            RelativeKind::Directory,
        )?
        else {
            return Ok(None);
        };
        super::export::require_safe_entry(&info, true)?;
        parent = child;
    }
    Ok(Some(parent))
}

fn mark_delete(handle: &OwnedHandle) -> Result<()> {
    let disposition = FILE_DISPOSITION_INFORMATION_EX {
        Flags: FILE_DISPOSITION_DELETE
            | FILE_DISPOSITION_POSIX_SEMANTICS
            | FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE,
    };
    let mut io_status = IO_STATUS_BLOCK::default();
    let status = unsafe {
        NtSetInformationFile(
            handle.as_raw_handle() as HANDLE,
            &mut io_status,
            (&disposition as *const FILE_DISPOSITION_INFORMATION_EX).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFORMATION_EX>() as u32,
            FileDispositionInformationEx,
        )
    };
    if status < 0 {
        bail!("delete protected import target: NTSTATUS 0x{status:08x}");
    }
    Ok(())
}

fn relative_components(path: &Path) -> Result<Vec<OsString>> {
    let components = path
        .components()
        .map(|component| match component {
            Component::Normal(name) => Ok(name.to_os_string()),
            _ => bail!("import path must be a nonempty relative path"),
        })
        .collect::<Result<Vec<_>>>()?;
    if components.is_empty() {
        bail!("import path must be a nonempty relative path");
    }
    Ok(components)
}

fn handle_info(file: &std::fs::File) -> Result<BY_HANDLE_FILE_INFORMATION> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut info) } == 0 {
        return Err(std::io::Error::last_os_error()).context("revalidate import source handle");
    }
    Ok(info)
}

fn file_len(info: &BY_HANDLE_FILE_INFORMATION) -> u64 {
    ((info.nFileSizeHigh as u64) << 32) | info.nFileSizeLow as u64
}

fn source_directory_access() -> u32 {
    FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | FILE_READ_EA | READ_CONTROL | SYNCHRONIZE
}

fn source_file_access() -> u32 {
    FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | READ_CONTROL | SYNCHRONIZE
}

fn target_directory_access() -> u32 {
    FILE_LIST_DIRECTORY
        | FILE_ADD_FILE
        | FILE_ADD_SUBDIRECTORY
        | FILE_READ_ATTRIBUTES
        | FILE_DELETE_CHILD
        | DELETE
        | SYNCHRONIZE
}

fn target_entry_access() -> u32 {
    FILE_READ_DATA | FILE_READ_ATTRIBUTES | DELETE | SYNCHRONIZE
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
    fn imports_files_directories_type_changes_and_ordered_deletions_through_pins() {
        let root = unique_path("import");
        let host = root.join("host");
        let stage = root.join("stage");
        std::fs::create_dir_all(host.join("newdir")).unwrap();
        std::fs::create_dir_all(host.join("type-dir")).unwrap();
        std::fs::write(host.join("newdir").join("file.txt"), b"new file").unwrap();
        std::fs::write(host.join("replace.txt"), b"replacement").unwrap();
        std::fs::create_dir_all(stage.join("gone")).unwrap();
        std::fs::write(stage.join("gone").join("child.txt"), b"gone").unwrap();
        std::fs::write(stage.join("type-dir"), b"old type").unwrap();
        std::fs::write(stage.join("replace.txt"), b"old").unwrap();

        let host_root = open_root(&host, source_directory_access());
        let stage_root = open_root(&stage, target_directory_access());
        let token = current_impersonation_token();
        let directory = EntryFingerprint {
            directory: true,
            len: 0,
            modified_ns: 0,
            content_hash: None,
        };
        let file = |contents: &[u8]| EntryFingerprint {
            directory: false,
            len: contents.len() as u64,
            modified_ns: 0,
            content_hash: Some(*blake3::hash(contents).as_bytes()),
        };

        apply_host_import(
            &token,
            &host_root,
            &stage_root,
            Path::new("gone/child.txt"),
            None,
        )
        .unwrap();
        apply_host_import(&token, &host_root, &stage_root, Path::new("gone"), None).unwrap();
        apply_host_import(
            &token,
            &host_root,
            &stage_root,
            Path::new("newdir"),
            Some(&directory),
        )
        .unwrap();
        apply_host_import(
            &token,
            &host_root,
            &stage_root,
            Path::new("type-dir"),
            Some(&directory),
        )
        .unwrap();
        apply_host_import(
            &token,
            &host_root,
            &stage_root,
            Path::new("newdir/file.txt"),
            Some(&file(b"new file")),
        )
        .unwrap();
        apply_host_import(
            &token,
            &host_root,
            &stage_root,
            Path::new("replace.txt"),
            Some(&file(b"replacement")),
        )
        .unwrap();

        let host_snapshot =
            super::super::snapshot::protected_tree(host_root.try_clone().unwrap()).unwrap();
        let stage_snapshot =
            super::super::snapshot::protected_tree(stage_root.try_clone().unwrap()).unwrap();
        assert_eq!(normalized(host_snapshot), normalized(stage_snapshot));
        assert!(std::fs::read_dir(&stage).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".tmp")));

        drop(stage_root);
        drop(host_root);
        std::fs::remove_dir_all(root).unwrap();
    }

    fn normalized(
        mut snapshot: crate::resource::mount_sync::TreeSnapshot,
    ) -> crate::resource::mount_sync::TreeSnapshot {
        for entry in snapshot.entries.values_mut() {
            entry.modified_ns = 0;
        }
        snapshot
    }

    fn open_root(path: &Path, access: u32) -> OwnedHandle {
        let wide = path
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                access,
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

    fn unique_path(label: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
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
