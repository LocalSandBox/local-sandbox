use std::fs::{File, OpenOptions};
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::fs::FileExt;

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
        #[cfg(unix)]
        {
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

        #[cfg(windows)]
        {
            self.file.seek_read(buf, offset)
        }

        #[cfg(not(any(unix, windows)))]
        {
            let _ = (offset, buf);
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "positional file reads are not implemented for this host",
            ))
        }
    }

    pub fn write(&self, offset: u64, buf: &[u8]) -> std::io::Result<usize> {
        #[cfg(unix)]
        {
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

        #[cfg(windows)]
        {
            self.file.seek_write(buf, offset)
        }

        #[cfg(not(any(unix, windows)))]
        {
            let _ = (offset, buf);
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "positional file writes are not implemented for this host",
            ))
        }
    }

    pub fn flush(&self) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            let fd = self.file.as_raw_fd();
            let ret = unsafe { libc::fsync(fd) };
            if ret < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        }

        #[cfg(windows)]
        {
            self.file.sync_all()
        }

        #[cfg(not(any(unix, windows)))]
        {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "file flush is not implemented for this host",
            ))
        }
    }
}
