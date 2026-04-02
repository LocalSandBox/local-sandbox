use std::fs::{File, OpenOptions};
use std::os::unix::io::AsRawFd;

/// Flat-file backend using pread/pwrite for thread-safe positional I/O.
pub struct FlatFileBackend {
    file: File,
    path: String,
    size: u64,
}

impl FlatFileBackend {
    pub fn open(path: &str) -> anyhow::Result<Self> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        let size = file.metadata()?.len();
        Ok(Self {
            file,
            path: path.to_string(),
            size,
        })
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn read(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let fd = self.file.as_raw_fd();
        let n = unsafe {
            libc::pread(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                offset as libc::off_t,
            )
        };
        if n < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    pub fn write(&self, offset: u64, buf: &[u8]) -> std::io::Result<usize> {
        let fd = self.file.as_raw_fd();
        let n = unsafe {
            libc::pwrite(
                fd,
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
                offset as libc::off_t,
            )
        };
        if n < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    pub fn flush(&self) -> std::io::Result<()> {
        let fd = self.file.as_raw_fd();
        let ret = unsafe { libc::fsync(fd) };
        if ret < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}
