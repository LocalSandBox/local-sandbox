use std::os::fd::RawFd;

/// Saved terminal state for later restoration.
pub struct TerminalState {
    fd: RawFd,
    termios: libc::termios,
}

impl TerminalState {
    /// Save the current terminal attributes and switch to raw mode.
    /// Returns `None` if the fd is not a terminal.
    pub fn enter_raw_mode(fd: RawFd) -> Option<Self> {
        unsafe {
            let mut saved: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(fd, &mut saved) != 0 {
                return None;
            }
            let mut raw = saved;
            libc::cfmakeraw(&mut raw);
            libc::tcsetattr(fd, libc::TCSANOW, &raw);
            Some(TerminalState { fd, termios: saved })
        }
    }

    /// Restore the saved terminal attributes.
    pub fn restore(&self) {
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.termios);
        }
    }
}

impl Drop for TerminalState {
    fn drop(&mut self) {
        self.restore();
    }
}

/// Get the terminal size (rows, cols) for the given fd.
/// Returns (24, 80) as fallback if the ioctl fails.
pub fn terminal_size(fd: RawFd) -> (u16, u16) {
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) == 0 {
            (ws.ws_row, ws.ws_col)
        } else {
            (24, 80)
        }
    }
}

/// Read bytes from a raw file descriptor.
/// Returns the number of bytes read, or 0 on EOF/error.
pub fn read_raw(fd: RawFd, buf: &mut [u8]) -> usize {
    unsafe {
        let n = libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len());
        if n > 0 { n as usize } else { 0 }
    }
}

// --- kqueue-based stdin relay ---

/// Events returned by `StdinRelay::wait()`.
pub enum StdinEvent {
    /// stdin has data available to read.
    Ready,
    /// Terminal was resized (SIGWINCH).
    Resize,
    /// Shutdown was signaled by the other thread.
    Shutdown,
}

/// Write-end of the shutdown pipe. Send to the other thread so it can
/// wake the kqueue when the session ends.
pub struct ShutdownSignal {
    pipe_write: RawFd,
}

// ShutdownSignal is just an i32 fd. it is safe to send across threads.
unsafe impl Send for ShutdownSignal {}

impl ShutdownSignal {
    /// Signal the `StdinRelay` to wake up and return `StdinEvent::Shutdown`.
    pub fn signal(&self) {
        unsafe {
            libc::write(self.pipe_write, [1u8].as_ptr() as *const libc::c_void, 1);
        }
    }
}

impl Drop for ShutdownSignal {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.pipe_write);
        }
    }
}

/// kqueue-based event multiplexer for stdin, SIGWINCH, and shutdown.
/// Blocks with zero CPU until an event occurs.
pub struct StdinRelay {
    kq: RawFd,
    pipe_read: RawFd,
    stdin_fd: RawFd,
}

impl StdinRelay {
    /// Create a new relay watching the given stdin fd.
    /// Returns the relay and a `ShutdownSignal` that should be moved
    /// to the thread that needs to trigger shutdown.
    pub fn new(stdin_fd: RawFd) -> Option<(StdinRelay, ShutdownSignal)> {
        unsafe {
            // Create shutdown pipe
            let mut fds = [0i32; 2];
            if libc::pipe(fds.as_mut_ptr()) != 0 {
                return None;
            }
            let pipe_read = fds[0];
            let pipe_write = fds[1];

            // Create kqueue
            let kq = libc::kqueue();
            if kq < 0 {
                libc::close(pipe_read);
                libc::close(pipe_write);
                return None;
            }

            // Register 3 events: stdin read, pipe read, SIGWINCH
            let changes = [
                libc::kevent {
                    ident: stdin_fd as libc::uintptr_t,
                    filter: libc::EVFILT_READ,
                    flags: libc::EV_ADD,
                    fflags: 0,
                    data: 0,
                    udata: std::ptr::null_mut(),
                },
                libc::kevent {
                    ident: pipe_read as libc::uintptr_t,
                    filter: libc::EVFILT_READ,
                    flags: libc::EV_ADD,
                    fflags: 0,
                    data: 0,
                    udata: std::ptr::null_mut(),
                },
                libc::kevent {
                    ident: libc::SIGWINCH as libc::uintptr_t,
                    filter: libc::EVFILT_SIGNAL,
                    flags: libc::EV_ADD,
                    fflags: 0,
                    data: 0,
                    udata: std::ptr::null_mut(),
                },
            ];

            // Register all events
            let ret = libc::kevent(
                kq,
                changes.as_ptr(),
                changes.len() as i32,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            );
            if ret < 0 {
                libc::close(kq);
                libc::close(pipe_read);
                libc::close(pipe_write);
                return None;
            }

            // Suppress default SIGWINCH action so kqueue receives it
            libc::signal(libc::SIGWINCH, libc::SIG_IGN);

            Some((
                StdinRelay {
                    kq,
                    pipe_read,
                    stdin_fd,
                },
                ShutdownSignal { pipe_write },
            ))
        }
    }

    /// Block until stdin is readable, a resize signal arrives, or shutdown
    /// is signaled. Returns immediately with zero CPU overhead.
    pub fn wait(&self) -> StdinEvent {
        unsafe {
            let mut event: libc::kevent = std::mem::zeroed();
            let ret = libc::kevent(
                self.kq,
                std::ptr::null(),
                0,
                &mut event,
                1,
                std::ptr::null(), // NULL timeout = block indefinitely
            );

            if ret < 1 {
                // Error or interrupted — treat as shutdown (fail-safe)
                return StdinEvent::Shutdown;
            }

            if event.filter == libc::EVFILT_SIGNAL
                && event.ident == libc::SIGWINCH as libc::uintptr_t
            {
                return StdinEvent::Resize;
            }

            if event.filter == libc::EVFILT_READ {
                if event.ident == self.stdin_fd as libc::uintptr_t {
                    return StdinEvent::Ready;
                }
                if event.ident == self.pipe_read as libc::uintptr_t {
                    return StdinEvent::Shutdown;
                }
            }

            // Unexpected event -> fail-safe to shutdown
            StdinEvent::Shutdown
        }
    }
}

impl Drop for StdinRelay {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.kq);
            libc::close(self.pipe_read);
            // Restore default SIGWINCH handling
            libc::signal(libc::SIGWINCH, libc::SIG_DFL);
        }
    }
}
