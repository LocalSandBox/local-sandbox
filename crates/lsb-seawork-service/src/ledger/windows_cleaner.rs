use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};

use anyhow::Result;
use windows_sys::Win32::Foundation::{
    ERROR_INVALID_PARAMETER, HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
use windows_sys::Win32::System::Threading::{
    OpenProcess, TerminateProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_TERMINATE,
};

use super::recovery::{ExternalResourceCleaner, RecoveryProof};
use super::schema::ResourceRecord;

const PROCESS_EXIT_WAIT_MS: u32 = 5_000;

pub struct WindowsResourceCleaner {
    bundle_root: PathBuf,
}

impl WindowsResourceCleaner {
    pub fn new(bundle_root: &Path) -> Self {
        Self {
            bundle_root: bundle_root.to_path_buf(),
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
}

impl ExternalResourceCleaner for WindowsResourceCleaner {
    fn remove_if_exact(
        &mut self,
        _ownership_id: &str,
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
            _ => Ok(RecoveryProof::TemporarilyUnavailable),
        }
    }
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

    #[test]
    fn uncommitted_qemu_intent_never_selects_a_process() {
        let cleaner = WindowsResourceCleaner::new(Path::new(r"C:\Program Files\SeaWork"));
        assert_eq!(
            cleaner
                .remove_qemu(0, 0, r"tools\qemu\qemu-system-x86_64.exe", false)
                .unwrap(),
            RecoveryProof::AlreadyAbsent
        );
    }
}
