use std::io::BufReader;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};
use tokio::sync::{mpsc, watch};

use crate::session::BoxedControlSession;

enum ProcessInput {
    Stdin(Vec<u8>),
    Kill,
}

/// Handle to a streaming process started in the VM.
pub struct ProcessHandle {
    input_tx: std::sync::mpsc::Sender<ProcessInput>,
    stdout_rx: Option<mpsc::UnboundedReceiver<Vec<u8>>>,
    stderr_rx: Option<mpsc::UnboundedReceiver<Vec<u8>>>,
    exited_rx: watch::Receiver<Option<i32>>,
}

impl ProcessHandle {
    pub fn write(&self, data: &[u8]) -> Result<()> {
        self.input_tx
            .send(ProcessInput::Stdin(data.to_vec()))
            .map_err(|_| anyhow::anyhow!("process is no longer writable"))
    }

    pub fn kill(&self) -> Result<()> {
        self.input_tx
            .send(ProcessInput::Kill)
            .map_err(|_| anyhow::anyhow!("process is no longer running"))
    }

    pub fn take_stdout(&mut self) -> Option<mpsc::UnboundedReceiver<Vec<u8>>> {
        self.stdout_rx.take()
    }

    pub fn take_stderr(&mut self) -> Option<mpsc::UnboundedReceiver<Vec<u8>>> {
        self.stderr_rx.take()
    }

    pub fn exit_watcher(&self) -> watch::Receiver<Option<i32>> {
        self.exited_rx.clone()
    }

    pub async fn exited(&self) -> Result<i32> {
        let mut rx = self.exited_rx.clone();
        if let Some(code) = *rx.borrow() {
            return Ok(code);
        }

        loop {
            if rx.changed().await.is_err() {
                bail!("process exit watcher closed unexpectedly");
            }

            if let Some(code) = *rx.borrow() {
                return Ok(code);
            }
        }
    }
}

pub(crate) fn spawn_process_threads(stream: BoxedControlSession) -> ProcessHandle {
    let (stdout_tx, stdout_rx) = mpsc::unbounded_channel();
    let (stderr_tx, stderr_rx) = mpsc::unbounded_channel();
    let (input_tx, input_rx) = std::sync::mpsc::channel();
    let (exited_tx, exited_rx) = watch::channel(None);
    let closed = Arc::new(AtomicBool::new(false));

    let _ = std::thread::Builder::new()
        .name("lsb-process".into())
        .spawn({
            let closed = closed.clone();
            move || {
                let mut reader = match stream.try_clone_session() {
                    Ok(value) => BufReader::new(value),
                    Err(_) => {
                        let _ = exited_tx.send(Some(1));
                        return;
                    }
                };
                let mut writer = stream;
                let closed_for_input = closed.clone();

                let input_thread = std::thread::spawn(move || {
                    while !closed_for_input.load(Ordering::SeqCst) {
                        match input_rx.recv_timeout(Duration::from_millis(100)) {
                            Ok(ProcessInput::Stdin(data)) => {
                                if lsb_proto::frame::write_frame(
                                    &mut writer,
                                    lsb_proto::frame::STDIN,
                                    &data,
                                )
                                .is_err()
                                {
                                    break;
                                }
                            }
                            Ok(ProcessInput::Kill) => {
                                let _ = lsb_proto::frame::write_frame(
                                    &mut writer,
                                    lsb_proto::frame::KILL,
                                    &[],
                                );
                                break;
                            }
                            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                        }
                    }
                });

                loop {
                    match lsb_proto::frame::read_frame(&mut reader) {
                        Ok(Some((lsb_proto::frame::STDOUT, data))) => {
                            let _ = stdout_tx.send(data);
                        }
                        Ok(Some((lsb_proto::frame::STDERR, data))) => {
                            let _ = stderr_tx.send(data);
                        }
                        Ok(Some((lsb_proto::frame::EXIT, data))) => {
                            let code = lsb_proto::frame::parse_exit_code(&data).unwrap_or(0);
                            let _ = exited_tx.send(Some(code));
                            break;
                        }
                        Ok(Some((lsb_proto::frame::ERROR, data))) => {
                            let _ = stderr_tx.send(data);
                            let _ = exited_tx.send(Some(1));
                            break;
                        }
                        _ => {
                            let _ = exited_tx.send(Some(1));
                            break;
                        }
                    }
                }

                closed.store(true, Ordering::SeqCst);
                let _ = input_thread.join();
            }
        });

    ProcessHandle {
        input_tx,
        stdout_rx: Some(stdout_rx),
        stderr_rx: Some(stderr_rx),
        exited_rx,
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;
    use crate::session::test_support::memory_session_pair;

    fn wait_for_exit(rx: watch::Receiver<Option<i32>>) -> i32 {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(code) = *rx.borrow() {
                return code;
            }
            assert!(
                Instant::now() < deadline,
                "process exit watcher did not receive an exit code"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn process_forwards_stdout_stderr_and_exit_frames() {
        let (host, mut guest) = memory_session_pair();
        let mut handle = spawn_process_threads(Box::new(host));

        lsb_proto::frame::write_frame(&mut guest, lsb_proto::frame::STDOUT, b"hello\n")
            .expect("stdout frame should write");
        lsb_proto::frame::write_frame(&mut guest, lsb_proto::frame::STDERR, b"warn\n")
            .expect("stderr frame should write");
        lsb_proto::frame::write_frame(
            &mut guest,
            lsb_proto::frame::EXIT,
            &lsb_proto::frame::exit_payload(17),
        )
        .expect("exit frame should write");

        let mut stdout = handle.take_stdout().expect("stdout receiver should exist");
        let mut stderr = handle.take_stderr().expect("stderr receiver should exist");

        assert_eq!(
            stdout.blocking_recv().expect("stdout chunk should arrive"),
            b"hello\n".to_vec()
        );
        assert_eq!(
            stderr.blocking_recv().expect("stderr chunk should arrive"),
            b"warn\n".to_vec()
        );
        assert_eq!(wait_for_exit(handle.exit_watcher()), 17);
    }
}
