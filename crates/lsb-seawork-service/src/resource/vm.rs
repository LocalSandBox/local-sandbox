use std::collections::HashMap;
#[cfg(test)]
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use crate::engine::ServiceEngineConfig;
use crate::ledger::schema::LifecycleState;
use crate::resource::process::{ManagedProcess, ManagedProcessOutput};
use crate::resource::transaction::ResourceTransaction;
use crate::resource::watch::ManagedWatch;
use crate::session::quota::SANDBOX_MEMORY_OVERHEAD_MIB;
use crate::session::{CancellationToken, ClientIdentityKey, ResourceHandle};
use crate::windows::job::{JobLimits, SandboxJob};

const MAX_QEMU_JOB_PROCESSES: u32 = 8;
const FORCED_JOB_STOP_GRACE: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
pub struct ManagedVmSpec {
    pub instance_dir: PathBuf,
    pub rootfs_image: PathBuf,
    pub cpus: usize,
    pub memory_mib: u64,
    pub proxy_config: Option<lsb_proxy::ProxyConfig>,
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
        if self.cancellation.is_committing() {
            return Ok(());
        }
        if Instant::now() >= self.deadline {
            self.cancellation.expire();
            self.cancellation.check()?;
        }
        Ok(())
    }

    fn begin_commit(&self) -> Result<()> {
        self.check()?;
        if self.cancellation.begin_commit() {
            Ok(())
        } else {
            self.cancellation.check()
        }
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
    containment: Arc<SandboxJob>,
}

impl std::fmt::Debug for ManagedVm {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ManagedVm").finish_non_exhaustive()
    }
}

impl ManagedVm {
    pub fn start(
        engine: &ServiceEngineConfig,
        sandbox_id: ResourceHandle,
        owner: &ClientIdentityKey,
        spec: ManagedVmSpec,
        session_cancellation: CancellationToken,
        startup_cancellation: CancellationToken,
    ) -> Result<Self> {
        validate_spec(engine, &spec)?;
        let image_relative_path = engine.qemu_image_relative_path()?;
        let mut containment = SandboxJob::create(job_limits(&spec)?)?;
        let mut transaction =
            ResourceTransaction::reserve(engine.ledger_root(), &sandbox_id.to_string(), owner)?;
        transaction.set_state(LifecycleState::Preparing)?;
        containment.attach_journal(
            transaction,
            image_relative_path,
            ResourceHandle::random()?.to_string(),
        )?;
        let containment = Arc::new(containment);
        let thread_containment = containment.clone();
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
                    thread_containment,
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
                containment,
            }),
            Err(error) => {
                let _ = thread.join();
                Err(error)
            }
        }
    }

    pub fn stop(mut self, timeout: Duration) -> Result<()> {
        let (reply, response) = mpsc::sync_channel(1);
        let graceful_deadline = Instant::now() + timeout;
        let mut forced_deadline = None;
        let mut pending = Command::Stop(reply);
        loop {
            match self.commands.try_send(pending) {
                Ok(()) => break,
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    bail!("managed VM thread stopped before cleanup")
                }
                Err(mpsc::TrySendError::Full(command)) => pending = command,
            }
            enforce_stop_deadline(
                &self.containment,
                graceful_deadline,
                &mut forced_deadline,
                "managed VM stop command queue remained blocked",
            );
            std::thread::sleep(Duration::from_millis(10));
        }

        let result = loop {
            match response.recv_timeout(Duration::from_millis(10)) {
                Ok(result) => break result,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    bail!("managed VM thread stopped before cleanup reply")
                }
                Err(mpsc::RecvTimeoutError::Timeout) => enforce_stop_deadline(
                    &self.containment,
                    graceful_deadline,
                    &mut forced_deadline,
                    "managed VM thread remained stuck after authoritative Job termination",
                ),
            }
        };

        if let Some(thread) = self.thread.take() {
            while !thread.is_finished() {
                enforce_stop_deadline(
                    &self.containment,
                    graceful_deadline,
                    &mut forced_deadline,
                    "managed VM thread did not exit after cleanup reply",
                );
                std::thread::sleep(Duration::from_millis(10));
            }
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

fn enforce_stop_deadline(
    containment: &SandboxJob,
    graceful_deadline: Instant,
    forced_deadline: &mut Option<Instant>,
    abort_reason: &'static str,
) {
    let now = Instant::now();
    match *forced_deadline {
        Some(deadline) if now >= deadline => {
            eprintln!("{abort_reason}");
            std::process::abort();
        }
        Some(_) => {}
        None if now >= graceful_deadline => {
            if let Err(error) = containment.terminate(1) {
                eprintln!("authoritative QEMU Job termination failed: {error}");
                std::process::abort();
            }
            *forced_deadline = Some(now + FORCED_JOB_STOP_GRACE);
        }
        None => {}
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
        wait_file_response(response, &operation)
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
        let wait = if operation.cancellation.is_committing() {
            Duration::from_millis(25)
        } else {
            operation
                .deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(25))
        };
        match response.recv_timeout(wait) {
            Ok(result) => return result,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                bail!("managed VM {name} worker disconnected")
            }
        }
    }
}

fn wait_file_response(
    response: mpsc::Receiver<Result<ManagedFileResult>>,
    operation: &OperationContext,
) -> Result<ManagedFileResult> {
    loop {
        let cancellation_pending = operation.check().is_err();
        let wait = if cancellation_pending || operation.cancellation.is_committing() {
            Duration::from_millis(25)
        } else {
            operation
                .deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(25))
        };
        match response.recv_timeout(wait) {
            Ok(result) => return result,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                bail!("managed VM file operation worker disconnected")
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
            let _ = self.containment.terminate(1);
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
    mut spec: ManagedVmSpec,
    session_cancellation: CancellationToken,
    startup_cancellation: CancellationToken,
    process_containment: Arc<SandboxJob>,
    commands: mpsc::Receiver<Command>,
    ready: mpsc::SyncSender<Result<()>>,
) {
    if session_cancellation.is_cancelled() || startup_cancellation.is_cancelled() {
        let _ = cleanup_instance(&engine, &spec);
        let _ = ready.send(Err(anyhow::anyhow!("operation cancelled")));
        return;
    }
    let result = build_and_start(&engine, &mut spec, process_containment.clone());
    let Ok((sandbox, proxy_handle)) = result else {
        let _ = cleanup_instance(&engine, &spec);
        let _ = ready.send(result.map(|_| ()));
        return;
    };
    let proxy_env = proxy_handle
        .as_ref()
        .map(|handle| handle.placeholders.clone())
        .unwrap_or_default();
    if let Err(error) = process_containment.set_transaction_state(LifecycleState::Running) {
        let _ = sandbox.stop();
        let _ = cleanup_instance(&engine, &spec);
        let _ = ready.send(Err(error));
        return;
    }
    if session_cancellation.is_cancelled() || startup_cancellation.is_cancelled() {
        let _ = stop_and_cleanup(&sandbox, &engine, &spec, &process_containment);
        let _ = ready.send(Err(anyhow::anyhow!("operation cancelled")));
        return;
    }
    if ready.send(Ok(())).is_err() {
        let _ = stop_and_cleanup(&sandbox, &engine, &spec, &process_containment);
        return;
    }
    loop {
        if session_cancellation.is_cancelled() {
            let _ = stop_and_cleanup(&sandbox, &engine, &spec, &process_containment);
            return;
        }
        match commands.recv_timeout(Duration::from_millis(100)) {
            Ok(Command::Stop(reply)) => {
                let result = stop_and_cleanup(&sandbox, &engine, &spec, &process_containment);
                let _ = reply.send(result);
                return;
            }
            Ok(Command::Exec(spec, operation, reply)) => {
                let spec = with_proxy_environment(spec, &proxy_env);
                let result = operation
                    .check()
                    .and_then(|()| exec(&sandbox, spec, &operation));
                let _ = reply.send(result);
            }
            Ok(Command::Spawn(spec, operation, reply)) => {
                let spec = with_proxy_environment(spec, &proxy_env);
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
                    .and_then(|result| {
                        if operation.cancellation.is_committing() {
                            Ok(result)
                        } else {
                            operation.check().map(|()| result)
                        }
                    });
                let _ = reply.send(result);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let _ = stop_and_cleanup(&sandbox, &engine, &spec, &process_containment);
                return;
            }
        }
    }
}

fn stop_and_cleanup(
    sandbox: &lsb_vm::Sandbox,
    engine: &ServiceEngineConfig,
    spec: &ManagedVmSpec,
    containment: &SandboxJob,
) -> Result<()> {
    sandbox.stop()?;
    cleanup_instance(engine, spec)?;
    containment.finish_transaction()
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
            operation.begin_commit()?;
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
            operation.begin_commit()?;
            sandbox.remove(&path, recursive)?;
            Ok(ManagedFileResult::Empty)
        }
        ManagedFileOp::Rename { old_path, new_path } => {
            operation.begin_commit()?;
            sandbox.rename(&old_path, &new_path)?;
            Ok(ManagedFileResult::Empty)
        }
        ManagedFileOp::Copy {
            src,
            dst,
            recursive,
        } => {
            operation.begin_commit()?;
            sandbox.copy(&src, &dst, recursive)?;
            Ok(ManagedFileResult::Empty)
        }
        ManagedFileOp::Chmod { path, mode } => {
            operation.begin_commit()?;
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
            if let Err(error) = sandbox.write_file(&temporary, &bytes) {
                let _ = sandbox.remove(&temporary, false);
                return Err(error);
            }
            if let Err(error) = operation.check() {
                let _ = sandbox.remove(&temporary, false);
                return Err(error);
            }
            if let Err(error) = operation.begin_commit() {
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

fn build_and_start(
    engine: &ServiceEngineConfig,
    spec: &mut ManagedVmSpec,
    process_containment: Arc<SandboxJob>,
) -> Result<(lsb_vm::Sandbox, Option<lsb_proxy::ProxyHandle>)> {
    let (network_attachment, proxy_handle) = match spec.proxy_config.take() {
        Some(config) => {
            let link = lsb_proxy::create_proxy_link()?;
            let attachment = match link.vm {
                lsb_proxy::VmNetworkAttachment::FileDescriptor(fd) => {
                    lsb_vm::PlatformNetworkAttachment::file_descriptor(fd)
                }
                lsb_proxy::VmNetworkAttachment::QemuStream { host, port } => {
                    lsb_vm::PlatformNetworkAttachment::qemu_stream(host, port)
                }
            };
            let handle = lsb_proxy::start_link(link.host, config)?;
            (Some(attachment), Some(handle))
        }
        None => (None, None),
    };
    let mut builder = lsb_vm::Sandbox::builder()
        .data_dir(path_text(engine.resources_root())?)
        .service_qemu_executable(path_text(engine.qemu_executable())?)
        .service_process_containment(process_containment)
        .kernel(path_text(engine.kernel_image())?)
        .initrd(path_text(engine.initrd_image())?)
        .rootfs(path_text(&spec.rootfs_image)?)
        .cpus(spec.cpus)
        .memory_mb(spec.memory_mib)
        .console(false);
    if let Some(attachment) = network_attachment {
        builder = builder.network_attachment(attachment);
    }
    let sandbox = builder.build()?;
    sandbox.start()?;
    if let Some(handle) = &proxy_handle {
        if handle.requires_guest_ca {
            if let Err(error) = install_proxy_ca(&sandbox, &handle.ca_cert_pem) {
                let _ = sandbox.stop();
                return Err(error);
            }
        }
    }
    Ok((sandbox, proxy_handle))
}

fn install_proxy_ca(sandbox: &lsb_vm::Sandbox, certificate: &[u8]) -> Result<()> {
    sandbox.write_file(
        "/usr/local/share/ca-certificates/lsb-proxy.crt",
        certificate,
    )?;
    let exit_code = sandbox.exec(
        &["update-ca-certificates", "--fresh"],
        &mut std::io::sink(),
        &mut std::io::sink(),
    )?;
    if exit_code != 0 {
        bail!("guest proxy CA installation failed");
    }
    Ok(())
}

fn with_proxy_environment(
    mut spec: ManagedExecSpec,
    proxy_env: &HashMap<String, String>,
) -> ManagedExecSpec {
    spec.env = crate::network_policy::merge_proxy_environment(proxy_env, spec.env);
    spec
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

fn job_limits(spec: &ManagedVmSpec) -> Result<JobLimits> {
    let memory_mib = spec
        .memory_mib
        .checked_add(u64::from(SANDBOX_MEMORY_OVERHEAD_MIB))
        .context("QEMU Job memory limit overflow")?;
    let memory_bytes = memory_mib
        .checked_mul(1024 * 1024)
        .and_then(|bytes| usize::try_from(bytes).ok())
        .context("QEMU Job memory limit does not fit this host")?;
    Ok(JobLimits {
        active_processes: MAX_QEMU_JOB_PROCESSES,
        memory_bytes,
    })
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
            proxy_config: None,
        };
        assert!(validate_spec(&engine, &spec).is_err());
    }

    #[test]
    fn managed_vm_job_limits_include_fixed_overhead_and_process_cap() {
        let spec = ManagedVmSpec {
            instance_dir: PathBuf::from(r"C:\ProgramData\LocalSandbox\instance"),
            rootfs_image: PathBuf::from(r"C:\ProgramData\LocalSandbox\instance\rootfs.ext4"),
            cpus: 2,
            memory_mib: 4096,
            proxy_config: None,
        };

        let limits = job_limits(&spec).expect("bounded request should produce Job limits");
        assert_eq!(limits.active_processes, 8);
        assert_eq!(limits.memory_bytes, 6144 * 1024 * 1024usize);
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

    #[test]
    fn cancelled_file_waiter_does_not_finish_before_worker_cleanup() {
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let operation = OperationContext::new(cancellation.clone(), Duration::from_secs(1));
        let (reply, response) = mpsc::sync_channel(1);
        let (finished, result) = mpsc::sync_channel(1);

        std::thread::spawn(move || {
            let outcome = wait_file_response(response, &operation);
            finished.send(outcome).unwrap();
        });

        assert!(matches!(
            result.recv_timeout(Duration::from_millis(25)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        reply.send(Err(cancellation.check().unwrap_err())).unwrap();
        assert!(result
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("cancelled"));
    }
}
