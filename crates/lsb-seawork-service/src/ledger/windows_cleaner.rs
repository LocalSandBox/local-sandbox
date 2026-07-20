use std::ffi::OsString;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use windows_sys::Wdk::Storage::FileSystem::{
    FileDispositionInformationEx, FileIdBothDirectoryInformation, NtQueryDirectoryFile,
    NtSetInformationFile, FILE_DISPOSITION_DELETE, FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE,
    FILE_DISPOSITION_INFORMATION_EX, FILE_DISPOSITION_POSIX_SEMANTICS,
    FILE_ID_BOTH_DIR_INFORMATION,
};
use windows_sys::Win32::Foundation::{
    ERROR_INVALID_PARAMETER, HANDLE, INVALID_HANDLE_VALUE, STATUS_NO_MORE_FILES, WAIT_FAILED,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING, SYNCHRONIZE,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, TerminateProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_TERMINATE,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

use super::recovery::{ExternalResourceCleaner, RecoveryProof};
use super::schema::{LedgerDocument, ResourceRecord};

const PROCESS_EXIT_WAIT_MS: u32 = 5_000;
const MAX_STAGING_ENTRIES: usize = 100_000;
const MAX_STAGING_DEPTH: usize = 256;
const DIRECTORY_QUERY_BYTES: usize = 32 * 1024;

pub struct WindowsResourceCleaner {
    bundle_root: PathBuf,
    resources_root: PathBuf,
}

impl WindowsResourceCleaner {
    pub fn new(bundle_root: &Path, resources_root: &Path) -> Self {
        Self {
            bundle_root: bundle_root.to_path_buf(),
            resources_root: resources_root.to_path_buf(),
        }
    }

    fn remove_qemu(
        &self,
        pid: u32,
        creation_time: u64,
        image_relative_path: &str,
        committed: bool,
    ) -> Result<RecoveryProof> {
        // The service's kill-on-close Job owns every created child, and an uncommitted
        // child is suspended and cannot outlive the failed service process. There is no
        // caller-selected PID to inspect or mutate in an intent-only record.
        if !committed {
            return Ok(RecoveryProof::AlreadyAbsent);
        }

        let raw = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | SYNCHRONIZE,
                0,
                pid,
            )
        };
        if raw.is_null() {
            let error = std::io::Error::last_os_error();
            return if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) {
                Ok(RecoveryProof::AlreadyAbsent)
            } else {
                Ok(RecoveryProof::TemporarilyUnavailable)
            };
        }
        let process = unsafe { OwnedHandle::from_raw_handle(raw as _) };
        match process_exited(&process, 0) {
            Ok(true) => return Ok(RecoveryProof::AlreadyAbsent),
            Ok(false) => {}
            Err(_) => return Ok(RecoveryProof::TemporarilyUnavailable),
        }

        let actual_creation =
            match crate::windows::process::process_creation_time(process.as_raw_handle()) {
                Ok(value) => value,
                Err(_) => return Ok(absent_or_unavailable(&process)),
            };
        let actual_image = match crate::security::client_image::query_process_image(&process) {
            Ok(value) => value,
            Err(_) => return Ok(absent_or_unavailable(&process)),
        };
        let expected_image = self.bundle_root.join(image_relative_path);
        if actual_creation != creation_time
            || !crate::security::client_image::windows_path_eq(&actual_image, &expected_image)
        {
            return Ok(RecoveryProof::IdentityMismatch);
        }

        if unsafe { TerminateProcess(process.as_raw_handle() as HANDLE, 1) } == 0 {
            return Ok(absent_or_unavailable(&process));
        }
        match process_exited(&process, PROCESS_EXIT_WAIT_MS) {
            Ok(true) => Ok(RecoveryProof::Removed),
            Ok(false) | Err(_) => Ok(RecoveryProof::TemporarilyUnavailable),
        }
    }

    fn remove_staging_root(
        &self,
        ledger_id: &str,
        owner_directory_id: &str,
        relative_path: &str,
        expected_file_id: &str,
        committed: bool,
    ) -> Result<RecoveryProof> {
        let components = match staging_components(relative_path, ledger_id, owner_directory_id) {
            Ok(components) => components,
            Err(_) => return Ok(RecoveryProof::IdentityMismatch),
        };
        if !committed {
            return Ok(RecoveryProof::TemporarilyUnavailable);
        }
        let (mut current, root_info) = match open_absolute_directory(&self.resources_root) {
            Ok(value) => value,
            Err(_) => return Ok(RecoveryProof::TemporarilyUnavailable),
        };
        if is_reparse(&root_info) {
            return Ok(RecoveryProof::IdentityMismatch);
        }
        for component in components {
            let opened = match crate::security::path::relative::open_relative_for_cleanup(
                &current,
                &component,
                DELETE | FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                crate::security::path::relative::RelativeKind::Directory,
            ) {
                Ok(value) => value,
                Err(_) => return Ok(RecoveryProof::TemporarilyUnavailable),
            };
            let Some((next, info)) = opened else {
                return Ok(RecoveryProof::AlreadyAbsent);
            };
            if is_reparse(&info) {
                return Ok(RecoveryProof::IdentityMismatch);
            }
            current = next;
        }
        let actual_file_id = match file_id(&current) {
            Ok(value) => value,
            Err(_) => return Ok(RecoveryProof::TemporarilyUnavailable),
        };
        if actual_file_id != expected_file_id {
            return Ok(RecoveryProof::IdentityMismatch);
        }
        let mut deleted_entries = 0;
        match delete_tree_by_handle(&current, 0, &mut deleted_entries) {
            Ok(()) => Ok(RecoveryProof::Removed),
            Err(_) => Ok(RecoveryProof::TemporarilyUnavailable),
        }
    }
}

impl ExternalResourceCleaner for WindowsResourceCleaner {
    fn remove_if_exact(
        &mut self,
        ledger_id: &str,
        document: &LedgerDocument,
        resource: &ResourceRecord,
    ) -> Result<RecoveryProof> {
        match resource {
            ResourceRecord::QemuProcess {
                pid,
                creation_time,
                image_relative_path,
                committed,
                ..
            } => self.remove_qemu(*pid, *creation_time, image_relative_path, *committed),
            ResourceRecord::StagingRoot {
                relative_path,
                file_id,
                committed,
            } => {
                let owner_directory_id = match document.owner.protected_directory_id() {
                    Ok(value) => value,
                    Err(_) => return Ok(RecoveryProof::IdentityMismatch),
                };
                self.remove_staging_root(
                    ledger_id,
                    &owner_directory_id,
                    relative_path,
                    file_id,
                    *committed,
                )
            }
            _ => Ok(RecoveryProof::TemporarilyUnavailable),
        }
    }
}

fn staging_components(
    relative_path: &str,
    ledger_id: &str,
    owner_directory_id: &str,
) -> Result<Vec<OsString>> {
    let relative = Path::new(relative_path);
    if relative.is_absolute() {
        bail!("staging path must be relative");
    }
    let components = relative
        .components()
        .map(|component| match component {
            std::path::Component::Normal(value) => Ok(value.to_os_string()),
            _ => bail!("staging path contains a non-normal component"),
        })
        .collect::<Result<Vec<_>>>()?;
    if components.len() != 3
        || components[0] != owner_directory_id
        || components[1] != "instances"
        || components[2] != ledger_id
    {
        bail!("staging path is not bound to its ledger owner and sandbox");
    }
    Ok(components)
}

fn open_absolute_directory(path: &Path) -> Result<(OwnedHandle, BY_HANDLE_FILE_INFORMATION)> {
    let wide = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error().into());
    }
    let handle = unsafe { OwnedHandle::from_raw_handle(raw as _) };
    let info = handle_info(&handle)?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        bail!("protected resources root is not a directory");
    }
    Ok((handle, info))
}

fn handle_info(handle: &OwnedHandle) -> Result<BY_HANDLE_FILE_INFORMATION> {
    use windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandle;

    let mut info = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(handle.as_raw_handle() as _, &mut info) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(info)
}

fn file_id(handle: &OwnedHandle) -> Result<String> {
    let info = handle_info(handle)?;
    Ok(format!(
        "{:08x}:{:016x}",
        info.dwVolumeSerialNumber,
        ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64
    ))
}

fn is_reparse(info: &BY_HANDLE_FILE_INFORMATION) -> bool {
    info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

fn delete_tree_by_handle(
    directory: &OwnedHandle,
    depth: usize,
    deleted_entries: &mut usize,
) -> Result<()> {
    if depth >= MAX_STAGING_DEPTH {
        bail!("protected staging tree exceeds the cleanup depth bound");
    }
    let mut query_buffer = vec![0u64; DIRECTORY_QUERY_BYTES / std::mem::size_of::<u64>()];
    loop {
        let Some(name) = first_directory_entry(directory, &mut query_buffer)? else {
            break;
        };
        *deleted_entries = deleted_entries
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("protected staging cleanup count overflow"))?;
        if *deleted_entries > MAX_STAGING_ENTRIES {
            bail!("protected staging tree exceeds the cleanup entry bound");
        }
        let Some((child, info)) = crate::security::path::relative::open_relative_for_cleanup(
            directory,
            &name,
            DELETE | FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            crate::security::path::relative::RelativeKind::Any,
        )?
        else {
            continue;
        };
        if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 && !is_reparse(&info) {
            delete_tree_by_handle(&child, depth + 1, deleted_entries)?;
        } else {
            mark_delete(&child)?;
        }
    }
    mark_delete(directory)
}

fn first_directory_entry(directory: &OwnedHandle, buffer: &mut [u64]) -> Result<Option<OsString>> {
    let mut restart = true;
    loop {
        let mut io_status = IO_STATUS_BLOCK::default();
        let status = unsafe {
            NtQueryDirectoryFile(
                directory.as_raw_handle() as HANDLE,
                std::ptr::null_mut(),
                None,
                std::ptr::null(),
                &mut io_status,
                buffer.as_mut_ptr().cast(),
                DIRECTORY_QUERY_BYTES as u32,
                FileIdBothDirectoryInformation,
                true,
                std::ptr::null(),
                restart,
            )
        };
        if status == STATUS_NO_MORE_FILES {
            return Ok(None);
        }
        if status < 0 {
            bail!("enumerate protected staging handle: NTSTATUS 0x{status:08x}");
        }
        let header = std::mem::offset_of!(FILE_ID_BOTH_DIR_INFORMATION, FileName);
        if io_status.Information < header {
            bail!("protected staging enumeration returned a truncated entry");
        }
        let entry = unsafe { &*buffer.as_ptr().cast::<FILE_ID_BOTH_DIR_INFORMATION>() };
        let name_bytes = entry.FileNameLength as usize;
        if name_bytes == 0
            || !name_bytes.is_multiple_of(2)
            || header
                .checked_add(name_bytes)
                .is_none_or(|length| length > io_status.Information)
        {
            bail!("protected staging enumeration returned an invalid name");
        }
        let name = unsafe {
            std::slice::from_raw_parts(
                buffer.as_ptr().cast::<u8>().add(header).cast::<u16>(),
                name_bytes / 2,
            )
        };
        if name != ['.' as u16] && name != ['.' as u16, '.' as u16] {
            return Ok(Some(OsString::from_wide(name)));
        }
        restart = false;
    }
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
        bail!("delete protected staging handle: NTSTATUS 0x{status:08x}");
    }
    Ok(())
}

fn process_exited(process: &OwnedHandle, timeout_ms: u32) -> Result<bool> {
    match unsafe { WaitForSingleObject(process.as_raw_handle() as HANDLE, timeout_ms) } {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_TIMEOUT => Ok(false),
        WAIT_FAILED => Err(std::io::Error::last_os_error().into()),
        value => Err(anyhow::anyhow!(
            "WaitForSingleObject returned unexpected status {value}"
        )),
    }
}

fn absent_or_unavailable(process: &OwnedHandle) -> RecoveryProof {
    match process_exited(process, 0) {
        Ok(true) => RecoveryProof::AlreadyAbsent,
        Ok(false) | Err(_) => RecoveryProof::TemporarilyUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER_DIRECTORY: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const SANDBOX_ID: &str = "0123456789abcdef0123456789abcdef";
    const STAGING_RELATIVE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/instances/0123456789abcdef0123456789abcdef";

    #[test]
    fn uncommitted_qemu_intent_never_selects_a_process() {
        let cleaner = WindowsResourceCleaner::new(
            Path::new(r"C:\Program Files\SeaWork"),
            Path::new(r"C:\ProgramData\LocalSandbox\SeaWork\state\users"),
        );
        assert_eq!(
            cleaner
                .remove_qemu(0, 0, r"tools\qemu\qemu-system-x86_64.exe", false)
                .unwrap(),
            RecoveryProof::AlreadyAbsent
        );
    }

    #[test]
    fn exact_staging_tree_is_deleted_through_pinned_handles() {
        let root = std::env::temp_dir().join(format!("lsbsw-cleaner-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let staging = root
            .join(OWNER_DIRECTORY)
            .join("instances")
            .join(SANDBOX_ID);
        std::fs::create_dir_all(staging.join("nested")).unwrap();
        std::fs::write(staging.join("nested").join("rootfs.ext4"), b"rootfs").unwrap();
        let identity = crate::resource::mount::protected_identity(&staging).unwrap();
        let cleaner = WindowsResourceCleaner::new(Path::new(r"C:\bundle"), &root);

        assert_eq!(
            cleaner
                .remove_staging_root(
                    SANDBOX_ID,
                    OWNER_DIRECTORY,
                    STAGING_RELATIVE,
                    &identity,
                    true,
                )
                .unwrap(),
            RecoveryProof::Removed
        );
        assert!(!staging.exists());
        assert_eq!(
            cleaner
                .remove_staging_root(
                    SANDBOX_ID,
                    OWNER_DIRECTORY,
                    STAGING_RELATIVE,
                    &identity,
                    true,
                )
                .unwrap(),
            RecoveryProof::AlreadyAbsent
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn staging_identity_mismatch_preserves_the_tree() {
        let root =
            std::env::temp_dir().join(format!("lsbsw-cleaner-mismatch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let staging = root
            .join(OWNER_DIRECTORY)
            .join("instances")
            .join(SANDBOX_ID);
        std::fs::create_dir_all(&staging).unwrap();
        let cleaner = WindowsResourceCleaner::new(Path::new(r"C:\bundle"), &root);

        assert_eq!(
            cleaner
                .remove_staging_root(
                    SANDBOX_ID,
                    OWNER_DIRECTORY,
                    STAGING_RELATIVE,
                    "00000000:0000000000000000",
                    true,
                )
                .unwrap(),
            RecoveryProof::IdentityMismatch
        );
        assert!(staging.exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn staging_path_is_bound_to_ledger_owner_and_filename() {
        let root =
            std::env::temp_dir().join(format!("lsbsw-cleaner-binding-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let document = crate::ledger::schema::sample();
        let owner_directory = document.owner.protected_directory_id().unwrap();
        let relative_path = format!("{owner_directory}/instances/{SANDBOX_ID}");
        let staging = root.join(&relative_path);
        std::fs::create_dir_all(&staging).unwrap();
        let identity = crate::resource::mount::protected_identity(&staging).unwrap();
        let resource = ResourceRecord::StagingRoot {
            relative_path,
            file_id: identity,
            committed: true,
        };
        let mut cleaner = WindowsResourceCleaner::new(Path::new(r"C:\bundle"), &root);

        assert_eq!(
            cleaner
                .remove_if_exact("fedcba9876543210fedcba9876543210", &document, &resource,)
                .unwrap(),
            RecoveryProof::IdentityMismatch
        );
        assert!(staging.exists());
        assert_eq!(
            cleaner
                .remove_if_exact(SANDBOX_ID, &document, &resource)
                .unwrap(),
            RecoveryProof::Removed
        );
        assert!(!staging.exists());
        let _ = std::fs::remove_dir_all(root);
    }
}
