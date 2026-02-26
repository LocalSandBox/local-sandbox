use std::os::fd::RawFd;

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
    pub fn new(read_fd: RawFd, write_fd: RawFd) -> Self {
        unsafe {
            let file_handle_for_reading =
                NSFileHandle::initWithFileDescriptor(NSFileHandle::alloc(), read_fd);
            let file_handle_for_writing =
                NSFileHandle::initWithFileDescriptor(NSFileHandle::alloc(), write_fd);

            let attachment =
                VZFileHandleSerialPortAttachment::initWithFileHandleForReading_fileHandleForWriting(
                    VZFileHandleSerialPortAttachment::alloc(),
                    Some(&file_handle_for_reading),
                    Some(&file_handle_for_writing),
                );
            FileHandleSerialAttachment { inner: attachment }
        }
    }

    /// Create a serial attachment with no read handle (stdin disconnected).
    /// Output goes to the given write fd. Useful for exec/shell mode where
    /// the host stdin must not be consumed by the serial console.
    pub fn new_write_only(write_fd: RawFd) -> Self {
        unsafe {
            let file_handle_for_writing =
                NSFileHandle::initWithFileDescriptor(NSFileHandle::alloc(), write_fd);

            let attachment =
                VZFileHandleSerialPortAttachment::initWithFileHandleForReading_fileHandleForWriting(
                    VZFileHandleSerialPortAttachment::alloc(),
                    None,
                    Some(&file_handle_for_writing),
                );
            FileHandleSerialAttachment { inner: attachment }
        }
    }
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
