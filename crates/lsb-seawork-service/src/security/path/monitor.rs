use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    NtCreateFile, FILE_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
};
use windows_sys::Win32::Foundation::{
    ERROR_IO_PENDING, ERROR_NOT_FOUND, ERROR_OPERATION_ABORTED, HANDLE, INVALID_HANDLE_VALUE,
    OBJ_CASE_INSENSITIVE, UNICODE_STRING, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{
    GetFileInformationByHandle, ReadDirectoryChangesW, BY_HANDLE_FILE_INFORMATION,
    FILE_LIST_DIRECTORY, FILE_NOTIFY_CHANGE_ATTRIBUTES, FILE_NOTIFY_CHANGE_DIR_NAME,
    FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SECURITY,
    FILE_NOTIFY_CHANGE_SIZE, FILE_NOTIFY_INFORMATION, FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
    FILE_SHARE_WRITE, SYNCHRONIZE,
};
use windows_sys::Win32::System::Threading::{CreateEventW, ResetEvent};
use windows_sys::Win32::System::IO::{
    CancelIoEx, GetOverlappedResultEx, IO_STATUS_BLOCK, OVERLAPPED,
};

use crate::resource::mount_sync::{ChangeBatch, ChangeQueue};

use super::identity::AuthorizedMountRoot;

const BUFFER_BYTES: usize = 64 * 1024;

pub struct HostChangeMonitor {
    changes: Arc<Mutex<ChangeQueue>>,
    failed: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl HostChangeMonitor {
    pub fn start(authorized: &AuthorizedMountRoot) -> Result<Self> {
        let identity = authorized.identity();
        start_pinned(
            authorized.raw_root_handle() as HANDLE,
            identity.volume_serial,
            identity.file_index,
        )
    }

    pub fn drain(&self) -> Result<ChangeBatch> {
        if self.failed.load(Ordering::Acquire) {
            bail!("authorized host change monitor failed");
        }
        let batch = self
            .changes
            .lock()
            .map_err(|_| anyhow::anyhow!("authorized host change queue poisoned"))
            .map(|mut queue| queue.drain())?;
        if self.failed.load(Ordering::Acquire) {
            bail!("authorized host change monitor failed");
        }
        Ok(batch)
    }
}

impl Drop for HostChangeMonitor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if self
            .thread
            .take()
            .is_some_and(|thread| thread.join().is_err())
        {
            std::process::abort();
        }
    }
}

fn start_pinned(raw_root: HANDLE, volume: u32, index: u64) -> Result<HostChangeMonitor> {
    let mut empty_name = UNICODE_STRING::default();
    let attributes = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: raw_root,
        ObjectName: &mut empty_name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: std::ptr::null_mut(),
        SecurityQualityOfService: std::ptr::null_mut(),
    };
    let mut io_status = IO_STATUS_BLOCK::default();
    let mut raw = std::ptr::null_mut();
    let status = unsafe {
        NtCreateFile(
            &mut raw,
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            &attributes,
            &mut io_status,
            std::ptr::null(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT,
            std::ptr::null(),
            0,
        )
    };
    if status < 0 || raw.is_null() || raw == INVALID_HANDLE_VALUE {
        bail!("reopen authorized mount monitor pin failed with NTSTATUS 0x{status:08x}");
    }
    let directory = unsafe { OwnedHandle::from_raw_handle(raw as _) };
    let info = handle_info(&directory)?;
    if info.dwVolumeSerialNumber != volume
        || (((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64) != index
    {
        bail!("authorized mount monitor reopened a different root identity");
    }
    let changes = Arc::new(Mutex::new(ChangeQueue::default()));
    let failed = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let thread_changes = changes.clone();
    let thread_failed = failed.clone();
    let thread_stop = stop.clone();
    let thread = std::thread::Builder::new()
        .name("lsbsw-host-mount-watch".to_string())
        .spawn(move || {
            if monitor_loop(directory, &thread_changes, &thread_stop).is_err() {
                thread_failed.store(true, Ordering::Release);
            }
        })
        .context("spawn authorized host change monitor")?;
    Ok(HostChangeMonitor {
        changes,
        failed,
        stop,
        thread: Some(thread),
    })
}

fn monitor_loop(
    directory: OwnedHandle,
    changes: &Mutex<ChangeQueue>,
    stop: &AtomicBool,
) -> Result<()> {
    let raw_event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
    if raw_event.is_null() {
        return Err(std::io::Error::last_os_error()).context("create host change event");
    }
    let event = unsafe { OwnedHandle::from_raw_handle(raw_event as _) };
    let mut buffer = vec![0u64; BUFFER_BYTES / std::mem::size_of::<u64>()];
    let filter = FILE_NOTIFY_CHANGE_FILE_NAME
        | FILE_NOTIFY_CHANGE_DIR_NAME
        | FILE_NOTIFY_CHANGE_ATTRIBUTES
        | FILE_NOTIFY_CHANGE_SIZE
        | FILE_NOTIFY_CHANGE_LAST_WRITE
        | FILE_NOTIFY_CHANGE_SECURITY;
    while !stop.load(Ordering::Acquire) {
        buffer.fill(0);
        if unsafe { ResetEvent(event.as_raw_handle() as HANDLE) } == 0 {
            return Err(std::io::Error::last_os_error()).context("reset host change event");
        }
        let mut overlapped = OVERLAPPED {
            hEvent: event.as_raw_handle() as HANDLE,
            ..OVERLAPPED::default()
        };
        let started = unsafe {
            ReadDirectoryChangesW(
                directory.as_raw_handle() as HANDLE,
                buffer.as_mut_ptr().cast(),
                BUFFER_BYTES as u32,
                1,
                filter,
                std::ptr::null_mut(),
                &mut overlapped,
                None,
            )
        };
        if started == 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
                return Err(error).context("start authorized host directory watch");
            }
        }
        let transferred = loop {
            let mut bytes = 0u32;
            if unsafe {
                GetOverlappedResultEx(
                    directory.as_raw_handle() as HANDLE,
                    &overlapped,
                    &mut bytes,
                    250,
                    0,
                )
            } != 0
            {
                break Some(bytes);
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(WAIT_TIMEOUT as i32) {
                if !stop.load(Ordering::Acquire) {
                    continue;
                }
                if unsafe { CancelIoEx(directory.as_raw_handle() as HANDLE, &overlapped) } == 0 {
                    let cancel = std::io::Error::last_os_error();
                    if cancel.raw_os_error() != Some(ERROR_NOT_FOUND as i32) {
                        return Err(cancel).context("cancel authorized host directory watch");
                    }
                }
                let mut cancelled_bytes = 0u32;
                if unsafe {
                    GetOverlappedResultEx(
                        directory.as_raw_handle() as HANDLE,
                        &overlapped,
                        &mut cancelled_bytes,
                        u32::MAX,
                        0,
                    )
                } == 0
                {
                    let completion = std::io::Error::last_os_error();
                    if completion.raw_os_error() != Some(ERROR_OPERATION_ABORTED as i32) {
                        return Err(completion)
                            .context("await cancelled authorized host directory watch");
                    }
                }
                break None;
            }
            return Err(error).context("complete authorized host directory watch");
        };
        let Some(transferred) = transferred else {
            break;
        };
        if transferred as usize > BUFFER_BYTES {
            bail!("host change byte count exceeds the notification buffer");
        }
        let mut queue = changes
            .lock()
            .map_err(|_| anyhow::anyhow!("authorized host change queue poisoned"))?;
        if transferred == 0 {
            queue.mark_full_rescan();
            continue;
        }
        let used = usize::try_from(transferred).context("host change byte count overflow")?;
        let bytes = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), used) };
        push_records(bytes, &mut queue)?;
    }
    Ok(())
}

fn push_records(bytes: &[u8], queue: &mut ChangeQueue) -> Result<()> {
    let header = std::mem::offset_of!(FILE_NOTIFY_INFORMATION, FileName);
    let mut offset = 0usize;
    loop {
        if offset
            .checked_add(header)
            .is_none_or(|end| end > bytes.len())
        {
            bail!("host change notification contains a truncated record");
        }
        let record = unsafe {
            std::ptr::read_unaligned(bytes.as_ptr().add(offset).cast::<FILE_NOTIFY_INFORMATION>())
        };
        let name_bytes = record.FileNameLength as usize;
        let start = offset
            .checked_add(header)
            .context("host change record overflow")?;
        let end = start
            .checked_add(name_bytes)
            .context("host change name overflow")?;
        if !name_bytes.is_multiple_of(2) || end > bytes.len() {
            bail!("host change notification contains an invalid name");
        }
        let units = unsafe {
            std::slice::from_raw_parts(bytes.as_ptr().add(start).cast::<u16>(), name_bytes / 2)
        };
        if queue
            .push(PathBuf::from(OsString::from_wide(units)))
            .is_err()
        {
            queue.mark_full_rescan();
        }
        if record.NextEntryOffset == 0 {
            return Ok(());
        }
        let next = record.NextEntryOffset as usize;
        if next < header
            || offset
                .checked_add(next)
                .is_none_or(|end| end >= bytes.len())
        {
            bail!("host change notification has an invalid next-record offset");
        }
        offset += next;
    }
}

fn handle_info(handle: &OwnedHandle) -> Result<BY_HANDLE_FILE_INFORMATION> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(handle.as_raw_handle() as HANDLE, &mut info) } == 0 {
        return Err(std::io::Error::last_os_error()).context("inspect host change monitor pin");
    }
    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::ffi::OsStrExt;
    use std::time::Duration;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, OPEN_EXISTING,
    };

    #[test]
    fn pinned_monitor_reports_recursive_changes_and_stops_cleanly() {
        let root = unique_path();
        std::fs::create_dir_all(root.join("nested")).unwrap();
        let handle = open_root(&root);
        let info = handle_info(&handle).unwrap();
        let monitor = start_pinned(
            handle.as_raw_handle() as HANDLE,
            info.dwVolumeSerialNumber,
            ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64,
        )
        .unwrap();
        std::fs::write(root.join("nested").join("changed.txt"), b"changed").unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        let mut observed = false;
        while std::time::Instant::now() < deadline {
            match monitor.drain().unwrap() {
                ChangeBatch::FullRescan => {
                    observed = true;
                    break;
                }
                ChangeBatch::Paths(paths)
                    if paths.iter().any(|path| path.ends_with("changed.txt")) =>
                {
                    observed = true;
                    break;
                }
                ChangeBatch::Paths(_) => std::thread::sleep(Duration::from_millis(25)),
            }
        }
        assert!(observed);
        drop(monitor);
        drop(handle);
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
                FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
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

    fn unique_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("target")
            .join(format!(
                "lsbsw-host-monitor-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ))
    }
}
