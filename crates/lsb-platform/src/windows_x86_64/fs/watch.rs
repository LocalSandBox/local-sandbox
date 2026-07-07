use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;

#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_IO_PENDING, ERROR_NOTIFY_ENUM_DIR, ERROR_OPERATION_ABORTED,
    HANDLE, INVALID_HANDLE_VALUE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadDirectoryChangesW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OVERLAPPED,
    FILE_LIST_DIRECTORY, FILE_NOTIFY_CHANGE_CREATION, FILE_NOTIFY_CHANGE_DIR_NAME,
    FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SIZE,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{CreateEventW, ResetEvent, WaitForSingleObject};
#[cfg(windows)]
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

const FILE_ACTION_ADDED_VALUE: u32 = 1;
const FILE_ACTION_REMOVED_VALUE: u32 = 2;
const FILE_ACTION_MODIFIED_VALUE: u32 = 3;
const FILE_ACTION_RENAMED_OLD_NAME_VALUE: u32 = 4;
const FILE_ACTION_RENAMED_NEW_NAME_VALUE: u32 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsHostWatchEventKind {
    Create,
    Modify,
    Delete,
    Rename,
}

impl WindowsHostWatchEventKind {
    pub fn as_watch_event(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Modify => "modify",
            Self::Delete => "delete",
            Self::Rename => "rename",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsHostWatchEvent {
    pub relative_path: String,
    pub kind: WindowsHostWatchEventKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WindowsHostWatchError {
    InvalidRoot,
    OpenFailed { code: u32 },
    EventCreateFailed { code: u32 },
    ThreadSpawnFailed { detail: String },
    ReadFailed { code: u32 },
    WaitFailed { code: u32 },
    Overflow,
    MalformedEventBuffer,
    UnsupportedHost,
}

impl fmt::Display for WindowsHostWatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRoot => {
                f.write_str("Windows direct SMB directory watch source is not a directory")
            }
            Self::OpenFailed { code } => write!(
                f,
                "Windows direct SMB directory watch failed to open source (os error {code})"
            ),
            Self::EventCreateFailed { code } => write!(
                f,
                "Windows direct SMB directory watch failed to create cancellation event (os error {code})"
            ),
            Self::ThreadSpawnFailed { detail } => write!(
                f,
                "Windows direct SMB directory watch failed to start worker thread: {detail}"
            ),
            Self::ReadFailed { code } => write!(
                f,
                "Windows direct SMB directory watch read failed (os error {code})"
            ),
            Self::WaitFailed { code } => write!(
                f,
                "Windows direct SMB directory watch wait failed (os error {code})"
            ),
            Self::Overflow => f.write_str(
                "Windows direct SMB directory watch overflowed; resync the watched tree",
            ),
            Self::MalformedEventBuffer => {
                f.write_str("Windows direct SMB directory watch returned a malformed event buffer")
            }
            Self::UnsupportedHost => {
                f.write_str("Windows direct SMB directory watch is only available on Windows hosts")
            }
        }
    }
}

impl std::error::Error for WindowsHostWatchError {}

#[derive(Debug, Clone)]
pub struct WindowsHostDirectoryWatchStop {
    stop: Arc<AtomicBool>,
}

impl WindowsHostDirectoryWatchStop {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Release);
    }

    pub fn stopped(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }
}

#[derive(Debug)]
pub struct WindowsHostDirectoryWatch {
    stop: WindowsHostDirectoryWatchStop,
    thread: Option<thread::JoinHandle<()>>,
}

impl WindowsHostDirectoryWatch {
    pub fn stop_handle(&self) -> WindowsHostDirectoryWatchStop {
        self.stop.clone()
    }
}

impl Drop for WindowsHostDirectoryWatch {
    fn drop(&mut self) {
        self.stop.stop();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn map_windows_directory_action_for_watch(action: u32) -> Option<WindowsHostWatchEventKind> {
    match action {
        FILE_ACTION_ADDED_VALUE => Some(WindowsHostWatchEventKind::Create),
        FILE_ACTION_REMOVED_VALUE => Some(WindowsHostWatchEventKind::Delete),
        FILE_ACTION_MODIFIED_VALUE => Some(WindowsHostWatchEventKind::Modify),
        FILE_ACTION_RENAMED_OLD_NAME_VALUE | FILE_ACTION_RENAMED_NEW_NAME_VALUE => {
            Some(WindowsHostWatchEventKind::Rename)
        }
        _ => None,
    }
}

pub fn join_guest_watch_event_path(guest_root: &str, relative_path: &str) -> String {
    let mut path = guest_root.trim_end_matches('/').to_string();
    if path.is_empty() {
        path.push('/');
    }

    for component in relative_path
        .split(['/', '\\'])
        .filter(|component| !component.is_empty())
    {
        if path != "/" {
            path.push('/');
        }
        path.push_str(component);
    }

    path
}

#[cfg(not(windows))]
pub fn start_windows_host_directory_watch(
    _root: PathBuf,
    _recursive: bool,
) -> Result<
    (
        WindowsHostDirectoryWatch,
        mpsc::Receiver<Result<WindowsHostWatchEvent, WindowsHostWatchError>>,
    ),
    WindowsHostWatchError,
> {
    Err(WindowsHostWatchError::UnsupportedHost)
}

#[cfg(windows)]
pub fn start_windows_host_directory_watch(
    root: PathBuf,
    recursive: bool,
) -> Result<
    (
        WindowsHostDirectoryWatch,
        mpsc::Receiver<Result<WindowsHostWatchEvent, WindowsHostWatchError>>,
    ),
    WindowsHostWatchError,
> {
    if !root.is_dir() {
        return Err(WindowsHostWatchError::InvalidRoot);
    }

    let directory = open_directory_handle(&root)?;
    let event = create_event_handle()?;
    let stop = WindowsHostDirectoryWatchStop {
        stop: Arc::new(AtomicBool::new(false)),
    };
    let thread_stop = stop.clone();
    let (events_tx, events_rx) = mpsc::channel();

    let thread = thread::Builder::new()
        .name("lsb-windows-smb-watch".to_string())
        .spawn(move || {
            watch_loop(directory, event, recursive, thread_stop, events_tx);
        })
        .map_err(|error| WindowsHostWatchError::ThreadSpawnFailed {
            detail: error.to_string(),
        })?;

    Ok((
        WindowsHostDirectoryWatch {
            stop,
            thread: Some(thread),
        },
        events_rx,
    ))
}

#[cfg(windows)]
fn watch_loop(
    directory: OwnedHandle,
    event: OwnedHandle,
    recursive: bool,
    stop: WindowsHostDirectoryWatchStop,
    events_tx: mpsc::Sender<Result<WindowsHostWatchEvent, WindowsHostWatchError>>,
) {
    const BUFFER_LEN: usize = 64 * 1024;
    const WAIT_MS: u32 = 200;
    let mut buffer = vec![0u8; BUFFER_LEN];

    while !stop.stopped() {
        // SAFETY: event is a valid manual-reset event handle owned by this worker.
        unsafe {
            ResetEvent(event.raw());
        }

        let mut overlapped = OVERLAPPED::default();
        overlapped.hEvent = event.raw();

        // SAFETY: directory is an overlapped directory handle, buffer is valid for
        // BUFFER_LEN bytes for the duration of the pending I/O, and overlapped
        // remains pinned on this stack until completion or cancellation.
        let read_started = unsafe {
            ReadDirectoryChangesW(
                directory.raw(),
                buffer.as_mut_ptr().cast(),
                BUFFER_LEN as u32,
                i32::from(recursive),
                FILE_NOTIFY_CHANGE_FILE_NAME
                    | FILE_NOTIFY_CHANGE_DIR_NAME
                    | FILE_NOTIFY_CHANGE_SIZE
                    | FILE_NOTIFY_CHANGE_LAST_WRITE
                    | FILE_NOTIFY_CHANGE_CREATION,
                std::ptr::null_mut(),
                &mut overlapped,
                None,
            )
        };

        if read_started == 0 {
            let code = last_error_code();
            if code != ERROR_IO_PENDING {
                let _ = events_tx.send(Err(read_error_for_code(code)));
                break;
            }
        }

        loop {
            if stop.stopped() {
                cancel_pending_read(directory.raw(), event.raw(), &overlapped);
                return;
            }

            // SAFETY: event is a valid event handle associated with the overlapped read.
            match unsafe { WaitForSingleObject(event.raw(), WAIT_MS) } {
                WAIT_OBJECT_0 => break,
                WAIT_TIMEOUT => continue,
                WAIT_FAILED => {
                    let _ = events_tx.send(Err(WindowsHostWatchError::WaitFailed {
                        code: last_error_code(),
                    }));
                    return;
                }
                _ => continue,
            }
        }

        let mut bytes_transferred = 0u32;
        // SAFETY: the overlapped operation has signaled completion on event.
        let completed =
            unsafe { GetOverlappedResult(directory.raw(), &overlapped, &mut bytes_transferred, 0) };
        if completed == 0 {
            let code = last_error_code();
            if stop.stopped() && code == ERROR_OPERATION_ABORTED {
                return;
            }
            let _ = events_tx.send(Err(read_error_for_code(code)));
            return;
        }

        if bytes_transferred == 0 {
            let _ = events_tx.send(Err(WindowsHostWatchError::Overflow));
            return;
        }

        match parse_notify_buffer(&buffer[..bytes_transferred as usize]) {
            Ok(events) => {
                for event in events {
                    if events_tx.send(Ok(event)).is_err() {
                        return;
                    }
                }
            }
            Err(error) => {
                let _ = events_tx.send(Err(error));
                return;
            }
        }
    }
}

#[cfg(windows)]
fn read_error_for_code(code: u32) -> WindowsHostWatchError {
    if code == ERROR_NOTIFY_ENUM_DIR {
        WindowsHostWatchError::Overflow
    } else {
        WindowsHostWatchError::ReadFailed { code }
    }
}

#[cfg(windows)]
fn parse_notify_buffer(buffer: &[u8]) -> Result<Vec<WindowsHostWatchEvent>, WindowsHostWatchError> {
    const HEADER_LEN: usize = 12;
    let mut offset = 0usize;
    let mut events = Vec::new();

    loop {
        if offset + HEADER_LEN > buffer.len() {
            return Err(WindowsHostWatchError::MalformedEventBuffer);
        }

        let next_entry_offset = read_u32_ne(buffer, offset)?;
        let action = read_u32_ne(buffer, offset + 4)?;
        let file_name_len = read_u32_ne(buffer, offset + 8)? as usize;
        let name_start = offset + HEADER_LEN;
        let name_end = name_start
            .checked_add(file_name_len)
            .ok_or(WindowsHostWatchError::MalformedEventBuffer)?;
        if name_end > buffer.len() || file_name_len % 2 != 0 {
            return Err(WindowsHostWatchError::MalformedEventBuffer);
        }

        if let Some(kind) = map_windows_directory_action_for_watch(action) {
            let mut units = Vec::with_capacity(file_name_len / 2);
            for chunk in buffer[name_start..name_end].chunks_exact(2) {
                units.push(u16::from_ne_bytes([chunk[0], chunk[1]]));
            }
            events.push(WindowsHostWatchEvent {
                relative_path: String::from_utf16_lossy(&units),
                kind,
            });
        }

        if next_entry_offset == 0 {
            return Ok(events);
        }

        let next = offset
            .checked_add(next_entry_offset as usize)
            .ok_or(WindowsHostWatchError::MalformedEventBuffer)?;
        if next <= offset || next > buffer.len() {
            return Err(WindowsHostWatchError::MalformedEventBuffer);
        }
        offset = next;
    }
}

#[cfg(windows)]
fn read_u32_ne(buffer: &[u8], offset: usize) -> Result<u32, WindowsHostWatchError> {
    let bytes = buffer
        .get(offset..offset + 4)
        .ok_or(WindowsHostWatchError::MalformedEventBuffer)?;
    Ok(u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[cfg(windows)]
fn cancel_pending_read(directory: HANDLE, event: HANDLE, overlapped: &OVERLAPPED) {
    // SAFETY: directory and overlapped identify the pending read owned by this worker.
    unsafe {
        CancelIoEx(directory, overlapped);
    }

    loop {
        // SAFETY: event is the completion event associated with this overlapped read.
        match unsafe { WaitForSingleObject(event, 200) } {
            WAIT_OBJECT_0 => break,
            WAIT_TIMEOUT => continue,
            WAIT_FAILED => return,
            _ => continue,
        }
    }

    let mut bytes_transferred = 0u32;
    // SAFETY: the read has completed or has been cancelled and signaled. This drains
    // the completion before the stack OVERLAPPED and buffer are dropped.
    unsafe {
        GetOverlappedResult(directory, overlapped, &mut bytes_transferred, 0);
    }
}

#[cfg(windows)]
fn open_directory_handle(path: &std::path::Path) -> Result<OwnedHandle, WindowsHostWatchError> {
    let wide = path_to_wide(path)?;
    // SAFETY: wide is NUL-terminated and all pointer arguments are either valid or null.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        Err(WindowsHostWatchError::OpenFailed {
            code: last_error_code(),
        })
    } else {
        Ok(OwnedHandle(handle))
    }
}

#[cfg(windows)]
fn create_event_handle() -> Result<OwnedHandle, WindowsHostWatchError> {
    // SAFETY: null security attributes/name create an unnamed manual-reset event.
    let handle = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
    if handle.is_null() {
        Err(WindowsHostWatchError::EventCreateFailed {
            code: last_error_code(),
        })
    } else {
        Ok(OwnedHandle(handle))
    }
}

#[cfg(windows)]
fn path_to_wide(path: &std::path::Path) -> Result<Vec<u16>, WindowsHostWatchError> {
    let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if wide.iter().any(|unit| *unit == 0) {
        return Err(WindowsHostWatchError::InvalidRoot);
    }
    wide.push(0);
    Ok(wide)
}

#[cfg(windows)]
fn last_error_code() -> u32 {
    // SAFETY: GetLastError has no preconditions.
    unsafe { GetLastError() }
}

#[cfg(windows)]
#[derive(Debug)]
struct OwnedHandle(HANDLE);

#[cfg(windows)]
unsafe impl Send for OwnedHandle {}

#[cfg(windows)]
impl OwnedHandle {
    fn raw(&self) -> HANDLE {
        self.0
    }
}

#[cfg(windows)]
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: self.0 is owned by this RAII wrapper and closed exactly once.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_smb_watch_maps_directory_actions_to_guest_event_names() {
        assert_eq!(
            map_windows_directory_action_for_watch(FILE_ACTION_ADDED_VALUE),
            Some(WindowsHostWatchEventKind::Create)
        );
        assert_eq!(
            map_windows_directory_action_for_watch(FILE_ACTION_MODIFIED_VALUE),
            Some(WindowsHostWatchEventKind::Modify)
        );
        assert_eq!(
            map_windows_directory_action_for_watch(FILE_ACTION_REMOVED_VALUE),
            Some(WindowsHostWatchEventKind::Delete)
        );
        assert_eq!(
            map_windows_directory_action_for_watch(FILE_ACTION_RENAMED_OLD_NAME_VALUE),
            Some(WindowsHostWatchEventKind::Rename)
        );
        assert_eq!(map_windows_directory_action_for_watch(999), None);
    }

    #[test]
    fn windows_smb_watch_maps_relative_events_back_to_guest_paths() {
        assert_eq!(
            join_guest_watch_event_path("/direct", r"nested\file.txt"),
            "/direct/nested/file.txt"
        );
        assert_eq!(
            join_guest_watch_event_path("/direct/sub", "renamed.txt"),
            "/direct/sub/renamed.txt"
        );
        assert_eq!(join_guest_watch_event_path("/", "top.txt"), "/top.txt");
        assert_eq!(join_guest_watch_event_path("/direct/", ""), "/direct");
    }
}
