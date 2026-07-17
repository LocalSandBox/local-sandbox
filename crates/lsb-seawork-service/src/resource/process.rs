use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use crossbeam_channel::{bounded, Receiver, RecvTimeoutError, SendTimeoutError, Sender};

use crate::session::ResourceHandle;

const OUTPUT_QUEUE_FRAMES: usize = 64;
const OUTPUT_STALL_TIMEOUT: Duration = Duration::from_secs(30);
const PROCESS_COMMANDS: usize = 1;
const MAX_OUTPUT_CHUNK: usize =
    lsb_service_proto::limits::MAX_STREAM_PAYLOAD - lsb_service_proto::limits::STREAM_SEQUENCE_LEN;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestProcessResource {
    pub id: ResourceHandle,
    pub sandbox_id: ResourceHandle,
    pub stdout_stream: ResourceHandle,
    pub stderr_stream: ResourceHandle,
}

impl GuestProcessResource {
    pub fn new(sandbox_id: ResourceHandle) -> anyhow::Result<Self> {
        Ok(Self {
            id: ResourceHandle::random()?,
            sandbox_id,
            stdout_stream: ResourceHandle::random()?,
            stderr_stream: ResourceHandle::random()?,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ManagedProcessOutput {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exited(i32),
}

#[derive(Debug, Clone, Copy)]
enum ProcessCommand {
    Kill,
}

#[derive(Clone)]
pub struct ManagedProcessController {
    commands: Sender<ProcessCommand>,
    output: Arc<Mutex<Receiver<ManagedProcessOutput>>>,
}

impl std::fmt::Debug for ManagedProcessController {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagedProcessController")
            .finish_non_exhaustive()
    }
}

pub struct ManagedProcess {
    controller: ManagedProcessController,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl std::fmt::Debug for ManagedProcess {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagedProcess")
            .finish_non_exhaustive()
    }
}

impl ManagedProcess {
    pub fn start<R, W>(mut reader: R, mut writer: W) -> Result<Self>
    where
        R: Read + Send + 'static,
        W: Write + Send + 'static,
    {
        let (commands, command_rx) = bounded(PROCESS_COMMANDS);
        let (output_tx, output) = bounded(OUTPUT_QUEUE_FRAMES);
        let closed = Arc::new(AtomicBool::new(false));
        let closed_for_thread = closed.clone();
        let commands_for_thread = commands.clone();
        let thread = std::thread::Builder::new()
            .name("lsbsw-guest-process".to_string())
            .spawn(move || {
                let closed_for_writer = closed_for_thread.clone();
                let writer_thread = std::thread::spawn(move || {
                    while !closed_for_writer.load(Ordering::Acquire) {
                        match command_rx.recv_timeout(Duration::from_millis(100)) {
                            Ok(ProcessCommand::Kill) => {
                                let _ = lsb_vm::frame::write_frame(
                                    &mut writer,
                                    lsb_vm::frame::KILL,
                                    &[],
                                );
                                break;
                            }
                            Err(RecvTimeoutError::Timeout) => continue,
                            Err(RecvTimeoutError::Disconnected) => break,
                        }
                    }
                });

                process_output_loop(&mut reader, &output_tx, &commands_for_thread);
                closed_for_thread.store(true, Ordering::Release);
                let _ = writer_thread.join();
            })
            .context("spawn bounded guest process pump")?;
        Ok(Self {
            controller: ManagedProcessController {
                commands,
                output: Arc::new(Mutex::new(output)),
            },
            thread: Some(thread),
        })
    }

    pub fn controller(&self) -> ManagedProcessController {
        self.controller.clone()
    }
}

impl ManagedProcessController {
    pub fn kill(&self) -> Result<()> {
        match self.commands.try_send(ProcessCommand::Kill) {
            Ok(()) | Err(crossbeam_channel::TrySendError::Full(_)) => Ok(()),
            Err(crossbeam_channel::TrySendError::Disconnected(_)) => Ok(()),
        }
    }

    pub fn output(&self, timeout: Duration) -> Result<Option<ManagedProcessOutput>> {
        let receiver = self
            .output
            .lock()
            .map_err(|_| anyhow::anyhow!("guest process output receiver poisoned"))?;
        match receiver.recv_timeout(timeout) {
            Ok(output) => Ok(Some(output)),
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => Ok(None),
        }
    }
}

impl Drop for ManagedProcess {
    fn drop(&mut self) {
        let _ = self.controller.kill();
        let finished = self
            .thread
            .as_ref()
            .is_some_and(|thread| thread.is_finished());
        if finished {
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }
}

fn process_output_loop(
    reader: &mut impl Read,
    output: &Sender<ManagedProcessOutput>,
    commands: &Sender<ProcessCommand>,
) {
    loop {
        let event = match lsb_vm::frame::read_frame(reader) {
            Ok(Some((lsb_vm::frame::STDOUT, bytes))) => {
                if !send_chunks(output, commands, bytes, false) {
                    return;
                }
                continue;
            }
            Ok(Some((lsb_vm::frame::STDERR, bytes))) => {
                if !send_chunks(output, commands, bytes, true) {
                    return;
                }
                continue;
            }
            Ok(Some((lsb_vm::frame::EXIT, bytes))) => {
                ManagedProcessOutput::Exited(lsb_vm::frame::parse_exit_code(&bytes).unwrap_or(1))
            }
            Ok(Some((lsb_vm::frame::ERROR, bytes))) => {
                if !send_chunks(output, commands, bytes, true) {
                    return;
                }
                ManagedProcessOutput::Exited(1)
            }
            _ => ManagedProcessOutput::Exited(1),
        };
        let _ = send_output(output, commands, event);
        return;
    }
}

fn send_chunks(
    output: &Sender<ManagedProcessOutput>,
    commands: &Sender<ProcessCommand>,
    bytes: Vec<u8>,
    stderr: bool,
) -> bool {
    for chunk in bytes.chunks(MAX_OUTPUT_CHUNK) {
        let event = if stderr {
            ManagedProcessOutput::Stderr(chunk.to_vec())
        } else {
            ManagedProcessOutput::Stdout(chunk.to_vec())
        };
        if !send_output(output, commands, event) {
            return false;
        }
    }
    true
}

fn send_output(
    output: &Sender<ManagedProcessOutput>,
    commands: &Sender<ProcessCommand>,
    event: ManagedProcessOutput,
) -> bool {
    match output.send_timeout(event, OUTPUT_STALL_TIMEOUT) {
        Ok(()) => true,
        Err(SendTimeoutError::Timeout(_)) => {
            let _ = commands.try_send(ProcessCommand::Kill);
            false
        }
        Err(SendTimeoutError::Disconnected(_)) => false,
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn output_is_split_to_service_stream_bounds() {
        let bytes = vec![b'x'; MAX_OUTPUT_CHUNK + 7];
        let mut guest = Cursor::new(Vec::new());
        lsb_vm::frame::write_frame(&mut guest, lsb_vm::frame::STDOUT, &bytes).unwrap();
        lsb_vm::frame::write_frame(
            &mut guest,
            lsb_vm::frame::EXIT,
            &lsb_vm::frame::exit_payload(9),
        )
        .unwrap();
        guest.set_position(0);

        let process = ManagedProcess::start(guest, Cursor::new(Vec::new())).unwrap();
        let output = process.controller();
        assert_eq!(
            output.output(Duration::from_secs(1)).unwrap(),
            Some(ManagedProcessOutput::Stdout(vec![b'x'; MAX_OUTPUT_CHUNK]))
        );
        assert_eq!(
            output.output(Duration::from_secs(1)).unwrap(),
            Some(ManagedProcessOutput::Stdout(vec![b'x'; 7]))
        );
        assert_eq!(
            output.output(Duration::from_secs(1)).unwrap(),
            Some(ManagedProcessOutput::Exited(9))
        );
    }
}
