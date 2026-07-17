use std::collections::HashMap;
#[cfg(test)]
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use crate::engine::ServiceEngineConfig;
use crate::resource::process::{ManagedProcess, ManagedProcessOutput};
use crate::resource::watch::ManagedWatch;
use crate::session::CancellationToken;

#[derive(Debug, Clone)]
pub struct ManagedVmSpec {
    pub instance_dir: PathBuf,
    pub rootfs_image: PathBuf,
    pub cpus: usize,
    pub memory_mib: u64,
}

enum Command {
    Stop(mpsc::SyncSender<Result<()>>),
    Exec(
        ManagedExecSpec,
        OperationContext,
        mpsc::SyncSender<Result<ManagedExecResult>>,
    ),
    Spawn(
        ManagedExecSpec,
        OperationContext,
        mpsc::SyncSender<Result<ManagedProcess>>,
    ),
    Watch {
        path: String,
        recursive: bool,
        operation: OperationContext,
        reply: mpsc::SyncSender<Result<ManagedWatch>>,
    },
    File(
        ManagedFileOp,
        OperationContext,
        mpsc::SyncSender<Result<ManagedFileResult>>,
    ),
}

#[derive(Clone)]
struct OperationContext {
    cancellation: CancellationToken,
    deadline: Instant,
}

impl OperationContext {
    fn new(cancellation: CancellationToken, timeout: Duration) -> Self {
        Self {
            cancellation,
            deadline: Instant::now() + timeout,
        }
    }

    fn check(&self) -> Result<()> {
        self.cancellation.check()?;
        if Instant::now() >= self.deadline {
            bail!("operation exceeded bounded deadline");
        }
        Ok(())
    }
}

const MAX_EXEC_OUTPUT: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ManagedExecSpec {
    pub argv: Vec<String>,
    pub env: HashMap<String, String>,
    pub cwd: Option<String>,
}

#[derive(Debug)]
pub struct ManagedExecResult {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: i32,
}

#[derive(Debug, Clone)]
pub enum ManagedFileOp {
    Mkdir {
        path: String,
        recursive: bool,
    },
    ReadDir {
        path: String,
    },
    Stat {
        path: String,
    },
    Remove {
        path: String,
        recursive: bool,
    },
    Rename {
        old_path: String,
        new_path: String,
    },
    Copy {
        src: String,
        dst: String,
        recursive: bool,
    },
    Chmod {
        path: String,
        mode: u32,
    },
    Exists {
        path: String,
    },
    ReadFile {
        path: String,
    },
    WriteFile {
        path: String,
        bytes: Vec<u8>,
    },
}

#[derive(Debug)]
pub enum ManagedFileResult {
    Empty,
    Directory(Vec<ManagedDirEntry>),
    Stat(ManagedFileStat),
    Exists(bool),
    Bytes(Vec<u8>),
}

#[derive(Debug)]
pub struct ManagedDirEntry {
    pub name: String,
    pub entry_type: String,
    pub size: u64,
}

#[derive(Debug)]
pub struct ManagedFileStat {
    pub size: u64,
    pub mode: u32,
    pub mtime: u64,
    pub is_dir: bool,
    pub is_file: bool,
    pub is_symlink: bool,
}

#[derive(Clone)]
pub struct ManagedVmController {
    commands: mpsc::SyncSender<Command>,
}

pub struct ManagedVm {
    commands: mpsc::SyncSender<Command>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl std::fmt::Debug for ManagedVm {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ManagedVm").finish_non_exhaustive()
    }
}

impl ManagedVm {
    pub fn start(
        engine: &ServiceEngineConfig,
        spec: ManagedVmSpec,
        session_cancellation: CancellationToken,
        startup_cancellation: CancellationToken,
    ) -> Result<Self> {
        validate_spec(engine, &spec)?;
        let engine = engine.clone();
        let (commands, receiver) = mpsc::sync_channel(8);
        let (ready, started) = mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name("lsbsw-managed-vm".to_string())
            .spawn(move || {
                run(
                    engine,
                    spec,
                    session_cancellation,
                    startup_cancellation,
                    receiver,
                    ready,
                )
            })
            .context("spawn managed VM thread")?;
        match started
            .recv()
            .context("managed VM thread lost startup reply")?
        {
            Ok(()) => Ok(Self {
                commands,
                thread: Some(thread),
            }),
            Err(error) => {
                let _ = thread.join();
                Err(error)
            }
        }
    }

    pub fn stop(mut self, timeout: Duration) -> Result<()> {
        let (reply, response) = mpsc::sync_channel(1);
        self.commands
            .send(Command::Stop(reply))
            .context("managed VM thread stopped before cleanup")?;
        let result = response
            .recv_timeout(timeout)
            .map_err(|_| anyhow::anyhow!("managed VM stop exceeded bounded deadline"))?;
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|_| anyhow::anyhow!("managed VM thread panicked"))?;
        }
        result
    }

    pub fn controller(&self) -> ManagedVmController {
        ManagedVmController {
            commands: self.commands.clone(),
        }
    }
}

impl ManagedVmController {
    pub fn exec(
        &self,
        spec: ManagedExecSpec,
        timeout: Duration,
        cancellation: CancellationToken,
    ) -> Result<ManagedExecResult> {
        let (reply, response) = mpsc::sync_channel(1);
        let operation = OperationContext::new(cancellation, timeout);
        self.commands
            .try_send(Command::Exec(spec, operation.clone(), reply))
            .map_err(|_| anyhow::anyhow!("managed VM command queue is unavailable"))?;
        wait_response(response, &operation, "exec")
    }

    pub fn file(
        &self,
        op: ManagedFileOp,
        timeout: Duration,
        cancellation: CancellationToken,
    ) -> Result<ManagedFileResult> {
        let (reply, response) = mpsc::sync_channel(1);
        let operation = OperationContext::new(cancellation, timeout);
        self.commands
            .try_send(Command::File(op, operation.clone(), reply))
            .map_err(|_| anyhow::anyhow!("managed VM command queue is unavailable"))?;
        wait_response(response, &operation, "file operation")
    }

    pub fn spawn(
        &self,
        spec: ManagedExecSpec,
        timeout: Duration,
        cancellation: CancellationToken,
    ) -> Result<ManagedProcess> {
        let (reply, response) = mpsc::sync_channel(1);
        let operation = OperationContext::new(cancellation, timeout);
        self.commands
            .try_send(Command::Spawn(spec, operation.clone(), reply))
            .map_err(|_| anyhow::anyhow!("managed VM command queue is unavailable"))?;
        wait_response(response, &operation, "spawn")
    }

    pub fn watch(
        &self,
        path: String,
        recursive: bool,
        timeout: Duration,
        cancellation: CancellationToken,
    ) -> Result<ManagedWatch> {
        let (reply, response) = mpsc::sync_channel(1);
        let operation = OperationContext::new(cancellation, timeout);
        self.commands
            .try_send(Command::Watch {
                path,
                recursive,
                operation: operation.clone(),
                reply,
            })
            .map_err(|_| anyhow::anyhow!("managed VM command queue is unavailable"))?;
        wait_response(response, &operation, "watch")
    }
}

fn wait_response<T>(
    response: mpsc::Receiver<Result<T>>,
    operation: &OperationContext,
    name: &str,
) -> Result<T> {
    loop {
        operation.check()?;
        let remaining = operation.deadline.saturating_duration_since(Instant::now());
        match response.recv_timeout(remaining.min(Duration::from_millis(25))) {
            Ok(result) => return result,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                bail!("managed VM {name} worker disconnected")
            }
        }
    }
}

impl Drop for ManagedVm {
    fn drop(&mut self) {
        let finished = self
            .thread
            .as_ref()
            .is_some_and(|thread| thread.is_finished());
        if !finished {
            return;
        }
        let Some(thread) = self.thread.take() else {
            return;
        };
        if thread.join().is_err() {
            std::process::abort();
        }
    }
}

fn run(
    engine: ServiceEngineConfig,
    spec: ManagedVmSpec,
    session_cancellation: CancellationToken,
    startup_cancellation: CancellationToken,
    commands: mpsc::Receiver<Command>,
    ready: mpsc::SyncSender<Result<()>>,
) {
    if session_cancellation.is_cancelled() || startup_cancellation.is_cancelled() {
        let _ = cleanup_instance(&engine, &spec);
        let _ = ready.send(Err(anyhow::anyhow!("operation cancelled")));
        return;
    }
    let result = build_and_start(&engine, &spec);
    let Ok(sandbox) = result else {
        let _ = cleanup_instance(&engine, &spec);
        let _ = ready.send(result.map(|_| ()));
        return;
    };
    if session_cancellation.is_cancelled() || startup_cancellation.is_cancelled() {
        let _ = sandbox.stop();
        let _ = cleanup_instance(&engine, &spec);
        let _ = ready.send(Err(anyhow::anyhow!("operation cancelled")));
        return;
    }
    if ready.send(Ok(())).is_err() {
        let _ = sandbox.stop();
        let _ = cleanup_instance(&engine, &spec);
        return;
    }
    loop {
        if session_cancellation.is_cancelled() {
            let _ = sandbox.stop();
            let _ = cleanup_instance(&engine, &spec);
            return;
        }
        match commands.recv_timeout(Duration::from_millis(100)) {
            Ok(Command::Stop(reply)) => {
                let result = sandbox
                    .stop()
                    .and_then(|()| cleanup_instance(&engine, &spec));
                let _ = reply.send(result);
                return;
            }
            Ok(Command::Exec(spec, operation, reply)) => {
                let result = operation
                    .check()
                    .and_then(|()| exec(&sandbox, spec, &operation));
                let _ = reply.send(result);
            }
            Ok(Command::Spawn(spec, operation, reply)) => {
                let result = operation
                    .check()
                    .and_then(|()| spawn(&sandbox, spec))
                    .and_then(|process| {
                        if let Err(error) = operation.check() {
                            let _ = process.controller().kill();
                            Err(error)
                        } else {
                            Ok(process)
                        }
                    });
                let _ = reply.send(result);
            }
            Ok(Command::Watch {
                path,
                recursive,
                operation,
                reply,
            }) => {
                let result = operation
                    .check()
                    .and_then(|()| watch(&sandbox, path, recursive))
                    .and_then(|watch| {
                        if let Err(error) = operation.check() {
                            watch.controller().stop();
                            Err(error)
                        } else {
                            Ok(watch)
                        }
                    });
                let _ = reply.send(result);
            }
            Ok(Command::File(op, operation, reply)) => {
                let result = operation
                    .check()
                    .and_then(|()| file_op(&sandbox, op, &operation))
                    .and_then(|result| operation.check().map(|()| result));
                let _ = reply.send(result);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let _ = sandbox.stop();
                let _ = cleanup_instance(&engine, &spec);
                return;
            }
        }
    }
}

fn spawn(sandbox: &lsb_vm::Sandbox, spec: ManagedExecSpec) -> Result<ManagedProcess> {
    start_process(sandbox, spec, false)
}

fn start_process(
    sandbox: &lsb_vm::Sandbox,
    spec: ManagedExecSpec,
    stdin_closed: bool,
) -> Result<ManagedProcess> {
    let writer = if stdin_closed {
        sandbox.open_exec_session_closed_stdin(&spec.argv, &spec.env, spec.cwd.as_deref())?
    } else {
        sandbox.open_exec_session(&spec.argv, &spec.env, spec.cwd.as_deref())?
    };
    let reader = writer.try_clone()?;
    ManagedProcess::start(reader, writer)
}

fn watch(sandbox: &lsb_vm::Sandbox, path: String, recursive: bool) -> Result<ManagedWatch> {
    let reader = sandbox.open_watch_session(&path, recursive)?;
    let cancel = Arc::new(Mutex::new(reader.try_clone()?));
    ManagedWatch::start(reader, path, move || {
        if let Ok(mut stream) = cancel.lock() {
            let _ = stream.close();
        }
    })
}

fn file_op(
    sandbox: &lsb_vm::Sandbox,
    op: ManagedFileOp,
    operation: &OperationContext,
) -> Result<ManagedFileResult> {
    match op {
        ManagedFileOp::Mkdir { path, recursive } => {
            sandbox.mkdir(&path, recursive)?;
            Ok(ManagedFileResult::Empty)
        }
        ManagedFileOp::ReadDir { path } => {
            let response = sandbox.read_dir(&path)?;
            Ok(ManagedFileResult::Directory(
                response
                    .entries
                    .into_iter()
                    .map(|entry| ManagedDirEntry {
                        name: entry.name,
                        entry_type: entry.entry_type,
                        size: entry.size,
                    })
                    .collect(),
            ))
        }
        ManagedFileOp::Stat { path } => {
            let stat = sandbox.stat(&path)?;
            Ok(ManagedFileResult::Stat(ManagedFileStat {
                size: stat.size,
                mode: stat.mode,
                mtime: stat.mtime,
                is_dir: stat.is_dir,
                is_file: stat.is_file,
                is_symlink: stat.is_symlink,
            }))
        }
        ManagedFileOp::Remove { path, recursive } => {
            sandbox.remove(&path, recursive)?;
            Ok(ManagedFileResult::Empty)
        }
        ManagedFileOp::Rename { old_path, new_path } => {
            sandbox.rename(&old_path, &new_path)?;
            Ok(ManagedFileResult::Empty)
        }
        ManagedFileOp::Copy {
            src,
            dst,
            recursive,
        } => {
            sandbox.copy(&src, &dst, recursive)?;
            Ok(ManagedFileResult::Empty)
        }
        ManagedFileOp::Chmod { path, mode } => {
            sandbox.chmod(&path, mode)?;
            Ok(ManagedFileResult::Empty)
        }
        ManagedFileOp::Exists { path } => match sandbox.stat(&path) {
            Ok(_) => Ok(ManagedFileResult::Exists(true)),
            Err(error) if error.to_string().contains("No such file or directory") => {
                Ok(ManagedFileResult::Exists(false))
            }
            Err(error) => Err(error),
        },
        ManagedFileOp::ReadFile { path } => {
            let stat = sandbox.stat(&path)?;
            if stat.size > lsb_service_proto::limits::MAX_FILE_TRANSFER_BYTES as u64 {
                bail!("file exceeds compiled transfer limit");
            }
            Ok(ManagedFileResult::Bytes(sandbox.read_file(&path)?))
        }
        ManagedFileOp::WriteFile { path, bytes } => {
            let temporary = temporary_guest_path(&path)?;
            sandbox.write_file(&temporary, &bytes)?;
            if let Err(error) = operation.check() {
                let _ = sandbox.remove(&temporary, false);
                return Err(error);
            }
            if let Err(error) = sandbox.rename(&temporary, &path) {
                let _ = sandbox.remove(&temporary, false);
                return Err(error);
            }
            Ok(ManagedFileResult::Empty)
        }
    }
}

fn temporary_guest_path(path: &str) -> Result<String> {
    let (parent, _) = path
        .rsplit_once('/')
        .filter(|(_, name)| !name.is_empty())
        .context("guest file path has no file name")?;
    let id = crate::session::ResourceHandle::random()?;
    let temporary = if parent.is_empty() {
        format!("/.lsbsw-{id}.tmp")
    } else {
        format!("{parent}/.lsbsw-{id}.tmp")
    };
    if temporary.len() > lsb_service_proto::limits::MAX_STRING_LEN {
        bail!("temporary guest file path exceeds protocol bound");
    }
    Ok(temporary)
}

fn exec(
    sandbox: &lsb_vm::Sandbox,
    spec: ManagedExecSpec,
    operation: &OperationContext,
) -> Result<ManagedExecResult> {
    let process = start_process(sandbox, spec, true)?;
    let controller = process.controller();
    let mut capture = ExecCapture::default();
    loop {
        if let Err(error) = operation.check() {
            let _ = controller.kill();
            return Err(error);
        }
        match controller.output(Duration::from_millis(25))? {
            Some(ManagedProcessOutput::Stdout(bytes)) => capture.append(bytes, false)?,
            Some(ManagedProcessOutput::Stderr(bytes)) => capture.append(bytes, true)?,
            Some(ManagedProcessOutput::Exited(exit_code)) => {
                return Ok(ManagedExecResult {
                    stdout: capture.stdout,
                    stderr: capture.stderr,
                    exit_code,
                });
            }
            None if controller.is_closed() => bail!("guest exec closed without exit status"),
            None => {}
        }
    }
}

#[derive(Default)]
struct ExecCapture {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    total: usize,
}

impl ExecCapture {
    fn append(&mut self, bytes: Vec<u8>, stderr: bool) -> Result<()> {
        let total = self
            .total
            .checked_add(bytes.len())
            .context("exec output limit exceeded")?;
        if total > MAX_EXEC_OUTPUT {
            bail!("exec output limit exceeded");
        }
        self.total = total;
        if stderr {
            self.stderr.extend(bytes);
        } else {
            self.stdout.extend(bytes);
        }
        Ok(())
    }
}

#[cfg(test)]
struct CaptureWriter {
    capture: Arc<Mutex<ExecCapture>>,
    stderr: bool,
}

#[cfg(test)]
impl CaptureWriter {
    fn new(capture: Arc<Mutex<ExecCapture>>, stderr: bool) -> Self {
        Self { capture, stderr }
    }
}

#[cfg(test)]
impl Write for CaptureWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let mut capture = self
            .capture
            .lock()
            .map_err(|_| std::io::Error::other("exec output capture poisoned"))?;
        let total = capture
            .total
            .checked_add(bytes.len())
            .ok_or_else(|| std::io::Error::other("exec output limit exceeded"))?;
        if total > MAX_EXEC_OUTPUT {
            return Err(std::io::Error::other("exec output limit exceeded"));
        }
        capture.total = total;
        if self.stderr {
            capture.stderr.extend_from_slice(bytes);
        } else {
            capture.stdout.extend_from_slice(bytes);
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn cleanup_instance(engine: &ServiceEngineConfig, spec: &ManagedVmSpec) -> Result<()> {
    engine.require_resource_path(&spec.instance_dir)?;
    if spec.instance_dir.exists() {
        std::fs::remove_dir_all(&spec.instance_dir).context("remove managed VM instance")?;
    }
    Ok(())
}

fn build_and_start(engine: &ServiceEngineConfig, spec: &ManagedVmSpec) -> Result<lsb_vm::Sandbox> {
    let sandbox = lsb_vm::Sandbox::builder()
        .data_dir(path_text(engine.resources_root())?)
        .service_qemu_executable(path_text(engine.qemu_executable())?)
        .kernel(path_text(engine.kernel_image())?)
        .initrd(path_text(engine.initrd_image())?)
        .rootfs(path_text(&spec.rootfs_image)?)
        .cpus(spec.cpus)
        .memory_mb(spec.memory_mib)
        .console(false)
        .build()?;
    sandbox.start()?;
    Ok(sandbox)
}

fn validate_spec(engine: &ServiceEngineConfig, spec: &ManagedVmSpec) -> Result<()> {
    engine.require_resource_path(&spec.instance_dir)?;
    engine.require_resource_path(&spec.rootfs_image)?;
    if spec.rootfs_image.parent() != Some(spec.instance_dir.as_path()) {
        bail!("managed rootfs must be directly below its protected instance directory");
    }
    if !(1..=16).contains(&spec.cpus) || !(256..=32 * 1024).contains(&spec.memory_mib) {
        bail!("managed VM resource request exceeds compiled bounds");
    }
    Ok(())
}

fn path_text(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_string)
        .context("managed VM path is not valid Unicode")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::ServicePaths;

    #[test]
    fn managed_vm_rejects_caller_paths_and_excess_resources_before_boot() {
        let root = std::env::temp_dir().join("lsbsw-vm-config");
        let paths = ServicePaths::for_test(root.clone());
        let bundle = PathBuf::from(r"C:\Program Files\SeaWork\LocalSandbox\versions\1");
        let engine = ServiceEngineConfig::from_verified_bundle(
            bundle.clone(),
            bundle.join("qemu-system-x86_64.exe"),
            bundle.join("Image"),
            bundle.join("initramfs.cpio.gz"),
            bundle.join("rootfs.ext4"),
            &paths,
        )
        .unwrap();
        let spec = ManagedVmSpec {
            instance_dir: PathBuf::from(r"C:\Users\caller\instance"),
            rootfs_image: PathBuf::from(r"C:\Users\caller\instance\rootfs.ext4"),
            cpus: 100,
            memory_mib: 64,
        };
        assert!(validate_spec(&engine, &spec).is_err());
    }

    #[test]
    fn exec_capture_enforces_one_combined_output_limit() {
        let capture = Arc::new(Mutex::new(ExecCapture {
            total: MAX_EXEC_OUTPUT,
            ..ExecCapture::default()
        }));
        let mut writer = CaptureWriter::new(capture, true);
        assert!(writer.write_all(&[1]).is_err());
    }

    #[test]
    fn write_file_temporary_path_is_a_random_sibling() {
        let first = temporary_guest_path("/workspace/output.txt").unwrap();
        let second = temporary_guest_path("/workspace/output.txt").unwrap();
        assert!(first.starts_with("/workspace/.lsbsw-"));
        assert!(first.ends_with(".tmp"));
        assert_ne!(first, second);

        let root = temporary_guest_path("/output.txt").unwrap();
        assert!(root.starts_with("/.lsbsw-"));
        assert!(temporary_guest_path("/").is_err());
    }

    #[test]
    fn cancelled_operation_context_fails_before_waiting() {
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let operation = OperationContext::new(cancellation, Duration::from_secs(1));
        let (_reply, response) = mpsc::sync_channel::<Result<()>>(1);
        assert!(wait_response(response, &operation, "test")
            .unwrap_err()
            .to_string()
            .contains("cancelled"));
    }
}
