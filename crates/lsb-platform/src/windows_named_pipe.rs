use std::cmp;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::ptr;
use std::sync::Arc;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_BROKEN_PIPE, ERROR_HANDLE_EOF, ERROR_IO_PENDING,
    ERROR_NOT_FOUND, HANDLE, WAIT_FAILED, WAIT_OBJECT_0,
};
use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile, FILE_FLAG_OVERLAPPED};
use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject, INFINITE};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

#[derive(Debug, Clone)]
pub(crate) struct WindowsNamedPipeStream {
    file: Arc<File>,
}

impl WindowsNamedPipeStream {
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(FILE_FLAG_OVERLAPPED)
            .open(path)?;
        Ok(Self {
            file: Arc::new(file),
        })
    }

    pub(crate) fn close(&self) -> io::Result<()> {
        self.cancel_pending_io()
    }

    pub(crate) fn reset(&self) -> io::Result<()> {
        self.cancel_pending_io()
    }

    fn raw_handle(&self) -> HANDLE {
        self.file.as_raw_handle() as HANDLE
    }

    fn cancel_pending_io(&self) -> io::Result<()> {
        // SAFETY: raw_handle returns a live handle owned by self.file. A null
        // OVERLAPPED pointer requests cancellation of all pending I/O for this
        // handle; errors are reported through GetLastError.
        let ok = unsafe { CancelIoEx(self.raw_handle(), ptr::null()) };
        if ok == 0 {
            let err = io::Error::last_os_error();
            if matches!(err.raw_os_error(), Some(code) if code == ERROR_NOT_FOUND as i32) {
                return Ok(());
            }
            return Err(err);
        }
        Ok(())
    }
}

impl Read for WindowsNamedPipeStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let len = cmp::min(buf.len(), u32::MAX as usize) as u32;
        let mut operation = OverlappedOperation::new()?;

        // SAFETY: buf is valid for len bytes for the duration of the
        // overlapped operation, and operation.overlapped owns a manual-reset
        // event that stays alive until completion.
        let started = unsafe {
            ReadFile(
                self.raw_handle(),
                buf.as_mut_ptr(),
                len,
                ptr::null_mut(),
                operation.overlapped_mut(),
            )
        };
        let bytes_read = if started == 0 {
            let error = last_error_code();
            if pipe_eof_error(error) {
                return Ok(0);
            }
            if error != ERROR_IO_PENDING {
                return Err(io::Error::from_raw_os_error(error as i32));
            }
            operation.wait(self.raw_handle())?
        } else {
            operation.result(self.raw_handle())?
        };

        Ok(bytes_read as usize)
    }
}

impl Write for WindowsNamedPipeStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let len = cmp::min(buf.len(), u32::MAX as usize) as u32;
        let mut operation = OverlappedOperation::new()?;

        // SAFETY: buf is valid for len bytes for the duration of the
        // overlapped operation, and operation.overlapped owns a manual-reset
        // event that stays alive until completion.
        let started = unsafe {
            WriteFile(
                self.raw_handle(),
                buf.as_ptr(),
                len,
                ptr::null_mut(),
                operation.overlapped_mut(),
            )
        };
        let bytes_written = if started == 0 {
            let error = last_error_code();
            if pipe_eof_error(error) {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "Windows named pipe peer closed",
                ));
            }
            if error != ERROR_IO_PENDING {
                return Err(io::Error::from_raw_os_error(error as i32));
            }
            operation.wait(self.raw_handle())?
        } else {
            operation.result(self.raw_handle())?
        };

        Ok(bytes_written as usize)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct OverlappedOperation {
    event: OwnedEvent,
    overlapped: OVERLAPPED,
}

impl OverlappedOperation {
    fn new() -> io::Result<Self> {
        let event = OwnedEvent::new()?;
        let mut overlapped = OVERLAPPED::default();
        overlapped.hEvent = event.raw();
        Ok(Self { event, overlapped })
    }

    fn overlapped_mut(&mut self) -> *mut OVERLAPPED {
        &mut self.overlapped
    }

    fn wait(&mut self, handle: HANDLE) -> io::Result<u32> {
        // SAFETY: event is an owned event handle associated with this
        // operation's OVERLAPPED.
        let wait = unsafe { WaitForSingleObject(self.event.raw(), INFINITE) };
        if wait != WAIT_OBJECT_0 {
            // SAFETY: handle and overlapped identify the pending operation we
            // are abandoning because the wait failed.
            unsafe {
                CancelIoEx(handle, &self.overlapped);
            }
            let err = if wait == WAIT_FAILED {
                io::Error::last_os_error()
            } else {
                io::Error::other(format!(
                    "Windows overlapped pipe wait returned unexpected status {wait}"
                ))
            };
            return Err(err);
        }
        self.result(handle)
    }

    fn result(&mut self, handle: HANDLE) -> io::Result<u32> {
        let mut transferred = 0u32;
        // SAFETY: the operation has either completed synchronously or the
        // event has been signaled. transferred points to valid output storage.
        let ok = unsafe { GetOverlappedResult(handle, &self.overlapped, &mut transferred, 0) };
        if ok == 0 {
            let error = last_error_code();
            if pipe_eof_error(error) {
                return Ok(0);
            }
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        Ok(transferred)
    }
}

struct OwnedEvent(HANDLE);

impl OwnedEvent {
    fn new() -> io::Result<Self> {
        // SAFETY: null security attributes/name create an unnamed manual-reset
        // event with initial state unsignaled.
        let handle = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
        if handle.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(handle))
        }
    }

    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedEvent {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: self.0 is owned by this RAII wrapper and closed once.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

fn pipe_eof_error(error: u32) -> bool {
    error == ERROR_BROKEN_PIPE || error == ERROR_HANDLE_EOF
}

fn last_error_code() -> u32 {
    // SAFETY: GetLastError has no preconditions.
    unsafe { GetLastError() }
}
