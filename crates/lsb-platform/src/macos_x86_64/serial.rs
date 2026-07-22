use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};

use objc2::rc::Retained;
use objc2::AnyThread;
use objc2_foundation::NSFileHandle;
use objc2_virtualization::{
    VZFileHandleSerialPortAttachment, VZSerialPortAttachment, VZSerialPortConfiguration,
    VZVirtioConsoleDeviceSerialPortConfiguration,
};

pub struct FileHandleSerialAttachment {
    inner: Retained<VZFileHandleSerialPortAttachment>,
}

impl FileHandleSerialAttachment {
    /// Creates an attachment from borrowed raw descriptors.
    ///
    /// Each descriptor is duplicated; the caller retains ownership of the originals.
    pub fn new(read_fd: RawFd, write_fd: RawFd) -> Self {
        unsafe {
            Self::try_new(
                BorrowedFd::borrow_raw(read_fd),
                BorrowedFd::borrow_raw(write_fd),
            )
        }
        .expect("failed to duplicate serial console file descriptors")
    }

    pub fn try_new(read_fd: BorrowedFd<'_>, write_fd: BorrowedFd<'_>) -> io::Result<Self> {
        let file_handle_for_reading = duplicate_file_handle(read_fd)?;
        let file_handle_for_writing = duplicate_file_handle(write_fd)?;

        unsafe {
            let attachment =
                VZFileHandleSerialPortAttachment::initWithFileHandleForReading_fileHandleForWriting(
                    VZFileHandleSerialPortAttachment::alloc(),
                    Some(&file_handle_for_reading),
                    Some(&file_handle_for_writing),
                );
            Ok(FileHandleSerialAttachment { inner: attachment })
        }
    }

    /// Creates a write-only attachment from a borrowed raw descriptor.
    ///
    /// The descriptor is duplicated; the caller retains ownership of the original.
    pub fn new_write_only(write_fd: RawFd) -> Self {
        unsafe { Self::try_new_write_only(BorrowedFd::borrow_raw(write_fd)) }
            .expect("failed to duplicate serial output file descriptor")
    }

    pub fn try_new_write_only(write_fd: BorrowedFd<'_>) -> io::Result<Self> {
        let file_handle_for_writing = duplicate_file_handle(write_fd)?;

        unsafe {
            let attachment =
                VZFileHandleSerialPortAttachment::initWithFileHandleForReading_fileHandleForWriting(
                    VZFileHandleSerialPortAttachment::alloc(),
                    None,
                    Some(&file_handle_for_writing),
                );
            Ok(FileHandleSerialAttachment { inner: attachment })
        }
    }

    #[cfg(test)]
    fn file_descriptor_for_reading(&self) -> i32 {
        unsafe {
            self.inner
                .fileHandleForReading()
                .expect("bidirectional serial attachment should have a read file handle")
                .fileDescriptor()
        }
    }

    #[cfg(test)]
    fn file_descriptor_for_writing(&self) -> i32 {
        unsafe {
            self.inner
                .fileHandleForWriting()
                .expect("write-only serial attachment should have a write file handle")
                .fileDescriptor()
        }
    }
}

fn duplicate_file_handle(fd: BorrowedFd<'_>) -> io::Result<Retained<NSFileHandle>> {
    let duplicated_fd = fd.try_clone_to_owned()?;
    let file_handle = NSFileHandle::initWithFileDescriptor_closeOnDealloc(
        NSFileHandle::alloc(),
        duplicated_fd.as_raw_fd(),
        true,
    );

    // Ownership transfers only after NSFileHandle has been initialized successfully.
    // VZFileHandleSerialPortAttachment retains the handle and closes this duplicate
    // when the attachment graph is released.
    std::mem::forget(duplicated_fd);
    Ok(file_handle)
}

pub struct VirtioConsoleSerialPort {
    inner: Retained<VZVirtioConsoleDeviceSerialPortConfiguration>,
}

impl VirtioConsoleSerialPort {
    pub fn new() -> Self {
        VirtioConsoleSerialPort {
            inner: unsafe { VZVirtioConsoleDeviceSerialPortConfiguration::new() },
        }
    }

    pub fn new_with_attachment(attachment: &FileHandleSerialAttachment) -> Self {
        let config = Self::new();
        config.set_attachment(attachment);
        config
    }

    pub fn set_attachment(&self, attachment: &FileHandleSerialAttachment) {
        unsafe {
            let id: Retained<VZSerialPortAttachment> =
                Retained::cast_unchecked(attachment.inner.clone());
            self.inner.setAttachment(Some(&id));
        }
    }

    pub(crate) fn as_serial_port_config(&self) -> Retained<VZSerialPortConfiguration> {
        unsafe { Retained::cast_unchecked(self.inner.clone()) }
    }
}

impl Default for VirtioConsoleSerialPort {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "../macos_serial_tests.rs"]
mod tests;
