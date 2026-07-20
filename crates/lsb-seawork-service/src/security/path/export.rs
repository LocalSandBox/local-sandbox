use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::path::{Component, Path};
use std::time::SystemTime;

use anyhow::{bail, Context, Result};
use windows_sys::Wdk::Storage::FileSystem::{
    FileDispositionInformation, FileRenameInformationEx, NtSetInformationFile,
    FILE_DISPOSITION_INFORMATION, FILE_RENAME_INFORMATION, FILE_RENAME_REPLACE_IF_EXISTS,
};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_ENCRYPTED, FILE_ATTRIBUTE_OFFLINE,
    FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, FILE_ATTRIBUTE_RECALL_ON_OPEN,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_DELETE_CHILD, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES,
    FILE_READ_DATA, FILE_WRITE_DATA, SYNCHRONIZE,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

use super::relative::{self, RelativeKind};

#[derive(Debug, Clone, Copy)]
pub struct ExportOptions {
    pub overwrite: bool,
    pub max_bytes: u64,
}

pub(super) fn open_protected_source(
    staging_root: &OwnedHandle,
    relative_source: &Path,
) -> Result<std::fs::File> {
    crate::resource::mount_sync::validate_relative_path(relative_source)?;
    let mut components = relative_components(relative_source)?;
    let leaf = components
        .pop()
        .ok_or_else(|| anyhow::anyhow!("protected export source is empty"))?;
    let mut parent = staging_root.try_clone()?;
    let parent_access = FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
    for component in components {
        let (child, info) =
            relative::open_relative(&parent, &component, parent_access, RelativeKind::Directory)?;
        require_safe_entry(&info, true)?;
        parent = child;
    }
    let source_access = FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
    let (source, info) =
        relative::open_relative(&parent, &leaf, source_access, RelativeKind::File)?;
    require_safe_entry(&info, false)?;
    Ok(source.into())
}

pub(super) fn export_open_file_under_client_token(
    protected_source: &mut std::fs::File,
    source_len: u64,
    source_modified: SystemTime,
    authorized_root: &OwnedHandle,
    relative_destination: &Path,
    options: ExportOptions,
) -> Result<u64> {
    if source_len > options.max_bytes {
        bail!("export source is not a bounded regular file");
    }
    crate::resource::mount_sync::validate_relative_path(relative_destination)?;
    let mut components = relative_components(relative_destination)?;
    let leaf = components
        .pop()
        .ok_or_else(|| anyhow::anyhow!("export destination is empty"))?;

    let parent = open_or_create_parents(authorized_root, components)?;
    let mut output = create_temporary(&parent)?;
    let result = (|| {
        let limit = source_len
            .checked_add(1)
            .context("export source length bound overflow")?;
        let copied = std::io::copy(
            &mut std::io::Read::take(&mut *protected_source, limit),
            &mut output,
        )?;
        let final_metadata = protected_source.metadata()?;
        if copied != source_len
            || final_metadata.len() != source_len
            || final_metadata.modified()? != source_modified
        {
            bail!("protected export source changed while it was copied");
        }
        output.sync_all()?;
        rename_relative(&output, &parent, &leaf, options.overwrite)?;
        Ok(copied)
    })();
    if result.is_err() {
        delete_on_close(&output);
    }
    result
}

fn relative_components(path: &Path) -> Result<Vec<OsString>> {
    path.components()
        .map(|component| match component {
            Component::Normal(name) => Ok(name.to_os_string()),
            _ => bail!("export destination must be a nonempty relative path"),
        })
        .collect()
}

fn open_or_create_parents(root: &OwnedHandle, components: Vec<OsString>) -> Result<OwnedHandle> {
    let mut parent = root.try_clone()?;
    let access = FILE_LIST_DIRECTORY
        | FILE_ADD_FILE
        | FILE_ADD_SUBDIRECTORY
        | FILE_READ_ATTRIBUTES
        | FILE_DELETE_CHILD
        | SYNCHRONIZE;
    for component in components {
        let opened =
            relative::open_relative_optional(&parent, &component, access, RelativeKind::Directory)?;
        let (child, info) = match opened {
            Some(value) => value,
            None => match relative::create_relative(
                &parent,
                &component,
                access,
                RelativeKind::Directory,
            )? {
                Some(value) => value,
                None => {
                    relative::open_relative(&parent, &component, access, RelativeKind::Directory)?
                }
            },
        };
        require_safe_entry(&info, true)?;
        parent = child;
    }
    Ok(parent)
}

fn create_temporary(parent: &OwnedHandle) -> Result<std::fs::File> {
    for _ in 0..8 {
        let mut random = [0u8; 8];
        getrandom::fill(&mut random)
            .map_err(|error| anyhow::anyhow!("OS random source failed: {error}"))?;
        let suffix = random
            .iter()
            .map(|value| format!("{value:02x}"))
            .collect::<String>();
        let name = OsString::from(format!(".lsbsw-export-{suffix}.tmp"));
        let access = FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | DELETE | SYNCHRONIZE;
        if let Some((handle, info)) =
            relative::create_relative(parent, &name, access, RelativeKind::File)?
        {
            let file = std::fs::File::from(handle);
            if let Err(error) = require_safe_entry(&info, false) {
                delete_on_close(&file);
                return Err(error);
            }
            return Ok(file);
        }
    }
    bail!("could not reserve a unique export temporary file")
}

fn require_safe_entry(info: &BY_HANDLE_FILE_INFORMATION, directory: bool) -> Result<()> {
    let denied = FILE_ATTRIBUTE_REPARSE_POINT
        | FILE_ATTRIBUTE_ENCRYPTED
        | FILE_ATTRIBUTE_OFFLINE
        | FILE_ATTRIBUTE_RECALL_ON_OPEN
        | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;
    if info.dwFileAttributes & denied != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
    {
        bail!("handle-relative export entry has an unsafe type or attributes");
    }
    Ok(())
}

fn rename_relative(
    source: &std::fs::File,
    parent: &OwnedHandle,
    destination_name: &OsStr,
    overwrite: bool,
) -> Result<()> {
    relative::validate_relative_component(destination_name)?;
    let name = destination_name.encode_wide().collect::<Vec<_>>();
    let name_bytes = name
        .len()
        .checked_mul(2)
        .and_then(|length| u32::try_from(length).ok())
        .ok_or_else(|| anyhow::anyhow!("export destination component exceeds NT limits"))?;
    let header = std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName);
    let total = header
        .checked_add(name_bytes as usize)
        .context("export rename buffer overflow")?;
    let mut storage = vec![0usize; total.div_ceil(std::mem::size_of::<usize>())];
    let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
    unsafe {
        (*info).Anonymous.Flags = if overwrite {
            FILE_RENAME_REPLACE_IF_EXISTS
        } else {
            0
        };
        (*info).RootDirectory = parent.as_raw_handle() as HANDLE;
        (*info).FileNameLength = name_bytes;
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            std::ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
            name.len(),
        );
    }
    let mut io_status = IO_STATUS_BLOCK::default();
    let status = unsafe {
        NtSetInformationFile(
            source.as_raw_handle() as HANDLE,
            &mut io_status,
            info.cast(),
            total as u32,
            FileRenameInformationEx,
        )
    };
    if status < 0 {
        bail!("handle-relative export commit failed with NTSTATUS 0x{status:08x}");
    }
    Ok(())
}

fn delete_on_close(file: &std::fs::File) {
    let disposition = FILE_DISPOSITION_INFORMATION { DeleteFile: true };
    let mut io_status = IO_STATUS_BLOCK::default();
    let _ = unsafe {
        NtSetInformationFile(
            file.as_raw_handle() as HANDLE,
            &mut io_status,
            std::ptr::addr_of!(disposition).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFORMATION>() as u32,
            FileDispositionInformation,
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING,
    };

    #[test]
    fn bounded_export_is_capability_relative_atomic_and_cleans_failed_temporary() {
        let root = unique_temp_path();
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("nested")).unwrap();
        let source_path = root.join("source");
        let destination = root.join("nested").join("destination");
        std::fs::write(&source_path, b"new-value").unwrap();
        std::fs::write(&destination, b"old-value").unwrap();
        let root_handle = open_root(&root);

        let mut source = open_protected_source(&root_handle, Path::new("source")).unwrap();
        let metadata = source.metadata().unwrap();
        assert_eq!(
            export_open_file_under_client_token(
                &mut source,
                metadata.len(),
                metadata.modified().unwrap(),
                &root_handle,
                Path::new(r"nested\destination"),
                ExportOptions {
                    overwrite: true,
                    max_bytes: 1024,
                },
            )
            .unwrap(),
            9
        );
        assert_eq!(std::fs::read(&destination).unwrap(), b"new-value");
        drop(source);

        let mut source = open_protected_source(&root_handle, Path::new("source")).unwrap();
        let metadata = source.metadata().unwrap();
        assert!(export_open_file_under_client_token(
            &mut source,
            metadata.len(),
            metadata.modified().unwrap(),
            &root_handle,
            Path::new(r"nested\destination"),
            ExportOptions {
                overwrite: false,
                max_bytes: 1024,
            },
        )
        .is_err());
        assert_eq!(std::fs::read(&destination).unwrap(), b"new-value");
        drop(source);

        let mut source = open_protected_source(&root_handle, Path::new("source")).unwrap();
        let metadata = source.metadata().unwrap();
        export_open_file_under_client_token(
            &mut source,
            metadata.len(),
            metadata.modified().unwrap(),
            &root_handle,
            Path::new(r"created\child\file"),
            ExportOptions {
                overwrite: false,
                max_bytes: 1024,
            },
        )
        .unwrap();
        assert_eq!(
            std::fs::read(root.join("created").join("child").join("file")).unwrap(),
            b"new-value"
        );
        drop(source);

        let mut source = open_protected_source(&root_handle, Path::new("source")).unwrap();
        let metadata = source.metadata().unwrap();
        assert!(export_open_file_under_client_token(
            &mut source,
            metadata.len() - 1,
            metadata.modified().unwrap(),
            &root_handle,
            Path::new("should-not-exist"),
            ExportOptions {
                overwrite: false,
                max_bytes: 1024,
            },
        )
        .is_err());
        assert!(!root.join("should-not-exist").exists());
        drop(source);

        for invalid_source in [
            Path::new(r"..\source"),
            Path::new(r"C:\source"),
            Path::new("source:stream"),
            Path::new(""),
        ] {
            assert!(open_protected_source(&root_handle, invalid_source).is_err());
        }

        for invalid in [
            Path::new(r"..\escape"),
            Path::new(r"C:\escape"),
            Path::new("stream:name"),
            Path::new(""),
        ] {
            let mut source = open_protected_source(&root_handle, Path::new("source")).unwrap();
            let metadata = source.metadata().unwrap();
            assert!(export_open_file_under_client_token(
                &mut source,
                metadata.len(),
                metadata.modified().unwrap(),
                &root_handle,
                invalid,
                ExportOptions {
                    overwrite: false,
                    max_bytes: 1024,
                },
            )
            .is_err());
        }
        assert!(!root.parent().unwrap().join("escape").exists());
        assert!(walk_files(&root).iter().all(|path| !path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with(".lsbsw-export-")));

        drop(root_handle);
        std::fs::remove_dir_all(root).unwrap();
    }

    fn open_root(path: &Path) -> OwnedHandle {
        let path = path
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let raw = unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE | DELETE | FILE_DELETE_CHILD,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(
            raw,
            INVALID_HANDLE_VALUE,
            "{}",
            std::io::Error::last_os_error()
        );
        unsafe { OwnedHandle::from_raw_handle(raw as _) }
    }

    fn walk_files(root: &Path) -> Vec<std::path::PathBuf> {
        let mut pending = vec![root.to_path_buf()];
        let mut files = Vec::new();
        while let Some(directory) = pending.pop() {
            for entry in std::fs::read_dir(directory).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    pending.push(path);
                } else {
                    files.push(path);
                }
            }
        }
        files
    }

    fn unique_temp_path() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("target")
            .join(format!(
                "lsbsw-export-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ))
    }
}
