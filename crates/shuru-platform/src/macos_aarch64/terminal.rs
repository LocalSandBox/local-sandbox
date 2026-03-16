use std::os::fd::RawFd;

pub struct TerminalState {
    fd: RawFd,
    termios: libc::termios,
}

impl TerminalState {
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

pub fn read_raw(fd: RawFd, buf: &mut [u8]) -> usize {
    unsafe {
        let n = libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len());
        if n > 0 { n as usize } else { 0 }
    }
}

pub enum StdinEvent {
    Ready,
    Resize,
    Shutdown,
}

pub struct ShutdownSignal {
    pipe_write: RawFd,
}

unsafe impl Send for ShutdownSignal {}

impl ShutdownSignal {
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

pub struct StdinRelay {
    kq: RawFd,
    pipe_read: RawFd,
    stdin_fd: RawFd,
}

impl StdinRelay {
    pub fn new(stdin_fd: RawFd) -> Option<(StdinRelay, ShutdownSignal)> {
        unsafe {
            let mut fds = [0i32; 2];
            if libc::pipe(fds.as_mut_ptr()) != 0 {
                return None;
            }
            let pipe_read = fds[0];
            let pipe_write = fds[1];

            let kq = libc::kqueue();
            if kq < 0 {
                libc::close(pipe_read);
                libc::close(pipe_write);
                return None;
            }

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

    pub fn wait(&self) -> StdinEvent {
        unsafe {
            let mut event: libc::kevent = std::mem::zeroed();
            let ret = libc::kevent(
                self.kq,
                std::ptr::null(),
                0,
                &mut event,
                1,
                std::ptr::null(),
            );

            if ret < 1 {
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

            StdinEvent::Shutdown
        }
    }
}

impl Drop for StdinRelay {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.kq);
            libc::close(self.pipe_read);
            libc::signal(libc::SIGWINCH, libc::SIG_DFL);
        }
    }
}
