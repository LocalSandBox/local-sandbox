use std::io::{self, Read, Write};

pub(crate) type BoxedControlSession = Box<dyn ControlSession>;

pub(crate) trait ControlSession: Read + Write + Send + 'static {
    fn try_clone_session(&self) -> io::Result<BoxedControlSession>;

    #[allow(dead_code)]
    fn close_session(&mut self) -> io::Result<()>;

    #[allow(dead_code)]
    fn reset_session(&mut self) -> io::Result<()>;
}

impl ControlSession for lsb_platform::PlatformControlStream {
    fn try_clone_session(&self) -> io::Result<BoxedControlSession> {
        self.try_clone()
            .map(|session| Box::new(session) as BoxedControlSession)
    }

    fn close_session(&mut self) -> io::Result<()> {
        self.close()
    }

    fn reset_session(&mut self) -> io::Result<()> {
        self.reset()
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::mpsc::{self, Receiver, SyncSender};
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Clone)]
    pub(crate) struct MemorySession {
        rx: Arc<Mutex<Receiver<u8>>>,
        tx: SyncSender<u8>,
    }

    pub(crate) fn memory_session_pair() -> (MemorySession, MemorySession) {
        let (left_tx, right_rx) = mpsc::sync_channel(1024 * 1024);
        let (right_tx, left_rx) = mpsc::sync_channel(1024 * 1024);
        (
            MemorySession {
                rx: Arc::new(Mutex::new(left_rx)),
                tx: left_tx,
            },
            MemorySession {
                rx: Arc::new(Mutex::new(right_rx)),
                tx: right_tx,
            },
        )
    }

    impl Read for MemorySession {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }

            let rx = self
                .rx
                .lock()
                .map_err(|_| io::Error::other("memory session receiver lock poisoned"))?;
            match rx.recv() {
                Ok(byte) => {
                    buf[0] = byte;
                    let mut read = 1usize;
                    while read < buf.len() {
                        match rx.try_recv() {
                            Ok(byte) => {
                                buf[read] = byte;
                                read += 1;
                            }
                            Err(_) => break,
                        }
                    }
                    Ok(read)
                }
                Err(_) => Ok(0),
            }
        }
    }

    impl Write for MemorySession {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            for byte in buf {
                self.tx
                    .send(*byte)
                    .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "peer closed"))?;
            }
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl ControlSession for MemorySession {
        fn try_clone_session(&self) -> io::Result<BoxedControlSession> {
            Ok(Box::new(self.clone()))
        }

        fn close_session(&mut self) -> io::Result<()> {
            Ok(())
        }

        fn reset_session(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}
