use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

use objc2::rc::autoreleasepool;

use super::{FileHandleSerialAttachment, VirtioConsoleSerialPort};

static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(0);
static FD_TEST_LOCK: Mutex<()> = Mutex::new(());

struct TempFile {
    path: PathBuf,
    file: Option<File>,
}

impl TempFile {
    fn new(label: &str, contents: &[u8]) -> Self {
        let sequence = NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "lsb-platform-serial-{label}-{}-{sequence}",
            std::process::id()
        ));
        let mut file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .expect("create serial attachment test file");
        file.write_all(contents).expect("initialize test file");
        file.flush().expect("flush test file");

        Self {
            path,
            file: Some(file),
        }
    }

    fn file(&self) -> &File {
        self.file.as_ref().expect("test file should still be open")
    }

    fn close(&mut self) {
        drop(self.file.take());
    }

    fn contents(&self) -> Vec<u8> {
        std::fs::read(&self.path).expect("read serial attachment test file")
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn fd_is_open(fd: RawFd) -> bool {
    unsafe { libc::fcntl(fd, libc::F_GETFD) != -1 }
}

fn write_fd(fd: RawFd, bytes: &[u8]) {
    let written = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
    assert_eq!(written, bytes.len() as isize, "write to serial fd failed");
}

fn duplicate_at_least(fd: RawFd, minimum: RawFd) -> OwnedFd {
    let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, minimum) };
    assert!(
        duplicated >= 0,
        "failed to duplicate fd: {}",
        std::io::Error::last_os_error()
    );
    unsafe { OwnedFd::from_raw_fd(duplicated) }
}

fn lock_fd_tests() -> MutexGuard<'static, ()> {
    FD_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[test]
fn serial_configuration_keeps_an_independent_fd_after_source_file_is_dropped() {
    let _guard = lock_fd_tests();
    let serial_fd = autoreleasepool(|_| {
        let mut target = TempFile::new("source-lifetime", b"");
        let source_fd = target.file().as_raw_fd();
        let attachment = FileHandleSerialAttachment::try_new_write_only(target.file().as_fd())
            .expect("create write-only serial attachment");
        let serial_fd = attachment.file_descriptor_for_writing();
        let serial = VirtioConsoleSerialPort::new_with_attachment(&attachment);

        assert_ne!(
            serial_fd, source_fd,
            "serial attachment must duplicate the fd"
        );
        drop(attachment);
        target.close();

        assert!(
            fd_is_open(serial_fd),
            "retained serial fd should remain open"
        );
        write_fd(serial_fd, b"serial-output");
        assert_eq!(target.contents(), b"serial-output");

        drop(serial);
        serial_fd
    });
    assert!(
        !fd_is_open(serial_fd),
        "serial fd should close with the retained attachment graph"
    );
}

#[test]
fn reusing_the_source_fd_number_cannot_redirect_serial_output() {
    let _guard = lock_fd_tests();
    autoreleasepool(|_| {
        let target = TempFile::new("reuse-target", b"");
        let source = duplicate_at_least(target.file().as_raw_fd(), 64);
        let source_fd = source.as_raw_fd();
        let attachment = FileHandleSerialAttachment::try_new_write_only(source.as_fd())
            .expect("create write-only serial attachment");
        let serial_fd = attachment.file_descriptor_for_writing();
        let serial = VirtioConsoleSerialPort::new_with_attachment(&attachment);
        drop(attachment);
        drop(source);

        let sentinel = TempFile::new("reuse-sentinel", b"sentinel");
        let reused_source_fd = duplicate_at_least(sentinel.file().as_raw_fd(), source_fd);
        assert_eq!(
            reused_source_fd.as_raw_fd(),
            source_fd,
            "test must force reuse of the source fd number"
        );

        write_fd(serial_fd, b"guest-serial");
        assert_eq!(target.contents(), b"guest-serial");
        assert_eq!(sentinel.contents(), b"sentinel");

        drop(reused_source_fd);
        drop(serial);
    });
}

#[test]
fn dropping_attachment_closes_its_owned_duplicate() {
    let _guard = lock_fd_tests();
    let target = TempFile::new("attachment-drop", b"");
    let serial_fd = autoreleasepool(|_| {
        let attachment = FileHandleSerialAttachment::try_new_write_only(target.file().as_fd())
            .expect("create write-only serial attachment");
        let serial_fd = attachment.file_descriptor_for_writing();

        assert!(fd_is_open(serial_fd));
        drop(attachment);
        serial_fd
    });
    assert!(!fd_is_open(serial_fd), "owned serial fd should be closed");
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EBADF)
    );
}

#[test]
fn attachment_lifecycle_does_not_close_standard_streams() {
    let _guard = lock_fd_tests();
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    let standard_fds = [stdin.as_raw_fd(), stdout.as_raw_fd(), stderr.as_raw_fd()];
    assert!(standard_fds.into_iter().all(fd_is_open));

    autoreleasepool(|_| {
        let console = FileHandleSerialAttachment::try_new(stdin.as_fd(), stdout.as_fd())
            .expect("create console serial attachment");
        let verbose = FileHandleSerialAttachment::try_new_write_only(stderr.as_fd())
            .expect("create verbose serial attachment");

        assert!(!standard_fds.contains(&console.file_descriptor_for_reading()));
        assert!(!standard_fds.contains(&console.file_descriptor_for_writing()));
        assert!(!standard_fds.contains(&verbose.file_descriptor_for_writing()));

        drop(console);
        drop(verbose);
    });
    assert!(standard_fds.into_iter().all(fd_is_open));
}
