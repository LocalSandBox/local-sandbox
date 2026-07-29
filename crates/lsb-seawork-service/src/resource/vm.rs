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
use crate::resource::watch::ManagedWatch;
use crate::session::quota::SANDBOX_MEMORY_OVERHEAD_MIB;
use crate::session::{CancellationToken, ResourceHandle};
use crate::windows::job::{JobLimits, SandboxJob};

const MAX_QEMU_JOB_PROCESSES: u32 = 8;
const FORCED_JOB_STOP_GRACE: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
pub struct ManagedVmSpec {
    pub correlation_id: String,
    pub resource_id: String,
    pub instance_dir: PathBuf,
    pub rootfs_image: PathBuf,
    pub cpus: usize,
    pub memory_mib: u64,
    pub mounts: Vec<ManagedVmMountSpec>,
    pub proxy_config: Option<lsb_proxy::ProxyConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedVmMountSpec {
    pub host_path: String,
    pub guest_path: String,
    pub read_only: bool,
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
    telemetry: crate::telemetry::Telemetry,
    correlation_id: String,
    resource_id: String,
}

impl std::fmt::Debug for ManagedVm {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ManagedVm").finish_non_exhaustive()
    }
}

impl ManagedVm {
    pub fn start(
        engine: &ServiceEngineConfig,
        mut transaction: crate::resource::transaction::ResourceTransaction,
        spec: ManagedVmSpec,
        session_cancellation: CancellationToken,
        startup_cancellation: CancellationToken,
        telemetry: crate::telemetry::Telemetry,
        trace_parent: crate::telemetry::SpanParent,
    ) -> Result<Self> {
        let correlation_id = spec.correlation_id.clone();
        let resource_id = spec.resource_id.clone();
        let result = (|| {
            validate_spec(engine, &spec)?;
            let image_relative_path = engine.qemu_image_relative_path()?;
            let mut containment = SandboxJob::create(job_limits(&spec)?)?;
            containment.attach_qemu_telemetry(lsb_platform::PlatformQemuTelemetryContext {
                telemetry_root: engine.telemetry_root().to_path_buf(),
                run_id: telemetry.run_id(),
                correlation_id: spec.correlation_id.clone(),
                resource_id: spec.resource_id.clone(),
            });
            containment.attach_qemu_lifecycle(telemetry.clone(), trace_parent.clone());
            transaction.set_state(LifecycleState::Preparing)?;
            containment.attach_journal(
                transaction,
                image_relative_path,
                ResourceHandle::random()?.to_string(),
            )?;
            let containment = Arc::new(containment);
            let thread_containment = containment.clone();
            let engine = engine.clone();
            let managed_telemetry = telemetry.clone();
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
                        telemetry,
                        trace_parent,
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
                    telemetry: managed_telemetry,
                    correlation_id: correlation_id.clone(),
                    resource_id: resource_id.clone(),
                }),
                Err(error) => {
                    let _ = thread.join();
                    Err(error)
                }
            }
        })();
        result.with_context(|| {
            format!(
                "managed VM start failed (correlation_id={correlation_id}, resource_id={resource_id})"
            )
        })
    }

    pub fn stop(
        self,
        timeout: Duration,
        trace_parent: Option<crate::telemetry::SpanParent>,
    ) -> Result<()> {
        let context = format!(
            "managed VM stop failed (correlation_id={}, resource_id={})",
            self.correlation_id, self.resource_id
        );
        self.stop_inner(timeout, trace_parent).context(context)
    }

    fn stop_inner(
        mut self,
        timeout: Duration,
        trace_parent: Option<crate::telemetry::SpanParent>,
    ) -> Result<()> {
        if let Some(parent) = trace_parent {
            self.containment
                .attach_qemu_lifecycle(self.telemetry.clone(), parent);
        }
        let (reply, response) = mpsc::sync_channel(1);
        // A live shutdown-timeout snapshot may legitimately spend 30 seconds in
        // the dump helper. Keep the service watchdog outside that reviewed
        // deadline plus the 15-second termination margin.
        let graceful_deadline =
            Instant::now() + timeout.max(crate::ipc::connection::DEFAULT_STOP_DEADLINE);
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

#[allow(clippy::too_many_arguments)]
fn run(
    engine: ServiceEngineConfig,
    mut spec: ManagedVmSpec,
    session_cancellation: CancellationToken,
    startup_cancellation: CancellationToken,
    process_containment: Arc<SandboxJob>,
    commands: mpsc::Receiver<Command>,
    ready: mpsc::SyncSender<Result<()>>,
    telemetry: crate::telemetry::Telemetry,
    trace_parent: crate::telemetry::SpanParent,
) {
    telemetry.update_crash_context(
        "sandbox.boot",
        Some(&spec.resource_id),
        Some(&spec.instance_dir),
        false,
    );
    if session_cancellation.is_cancelled() || startup_cancellation.is_cancelled() {
        let _ = cleanup_instance(&engine, &spec);
        telemetry.update_crash_context("sandbox.cleaned_up", Some(&spec.resource_id), None, true);
        let _ = ready.send(Err(anyhow::anyhow!("operation cancelled")));
        return;
    }
    let result = build_and_start(
        &engine,
        &mut spec,
        process_containment.clone(),
        &trace_parent,
    );
    let Ok((sandbox, proxy_handle)) = result else {
        if let Err(error) = &result {
            capture_vm_failure(&telemetry, &engine, &spec, error, "boot");
        }
        let _ = cleanup_instance(&engine, &spec);
        telemetry.update_crash_context("sandbox.cleaned_up", Some(&spec.resource_id), None, true);
        let _ = ready.send(result.map(|_| ()));
        return;
    };
    let proxy_env = proxy_handle
        .as_ref()
        .map(|handle| handle.placeholders.clone())
        .unwrap_or_default();
    if let Err(error) = process_containment.check_notifications() {
        capture_vm_failure(&telemetry, &engine, &spec, &error, "boot");
        let _ = process_containment.terminate(1);
        let _ = sandbox.stop();
        let _ = cleanup_instance(&engine, &spec);
        let _ = ready.send(Err(error));
        return;
    }
    if let Err(error) = process_containment.set_transaction_state(LifecycleState::Running) {
        capture_vm_failure(&telemetry, &engine, &spec, &error, "boot");
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
        telemetry.update_crash_context("sandbox.cleaned_up", Some(&spec.resource_id), None, true);
        return;
    }
    telemetry.update_crash_context(
        "sandbox.ready",
        Some(&spec.resource_id),
        Some(&spec.instance_dir),
        true,
    );
    process_containment.clear_qemu_lifecycle();
    loop {
        if let Err(error) = process_containment.check_notifications() {
            eprintln!("authoritative QEMU Job monitor failed: {error}");
            telemetry.breadcrumb(
                crate::telemetry::Breadcrumb::lifecycle("qemu", "process exit")
                    .with_data("resource_id", spec.resource_id.clone()),
            );
            capture_vm_failure(&telemetry, &engine, &spec, &error, "runtime");
            let _ = process_containment.terminate(1);
            let _ = sandbox.stop();
            let _ = cleanup_instance(&engine, &spec);
            return;
        }
        if session_cancellation.is_cancelled() {
            let _ = stop_and_cleanup(&sandbox, &engine, &spec, &process_containment);
            return;
        }
        match commands.recv_timeout(Duration::from_millis(100)) {
            Ok(Command::Stop(reply)) => {
                telemetry.update_crash_context(
                    "sandbox.stopping",
                    Some(&spec.resource_id),
                    Some(&spec.instance_dir),
                    false,
                );
                let result = stop_and_cleanup(&sandbox, &engine, &spec, &process_containment);
                if result.is_ok() {
                    telemetry.update_crash_context(
                        "sandbox.cleaned_up",
                        Some(&spec.resource_id),
                        None,
                        true,
                    );
                } else if let Err(error) = &result {
                    capture_vm_failure(&telemetry, &engine, &spec, error, "stop");
                }
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

fn capture_vm_failure(
    telemetry: &crate::telemetry::Telemetry,
    engine: &ServiceEngineConfig,
    spec: &ManagedVmSpec,
    error: &anyhow::Error,
    phase: &'static str,
) {
    let Some(event_id) = telemetry.new_event_id() else {
        return;
    };
    let (operation, stable_error_code) = match phase {
        "stop" => ("sandbox.stop", "SANDBOX_STOP_FAILED"),
        "runtime" => ("sandbox.runtime", "QEMU_UNEXPECTED_EXIT"),
        _ => ("sandbox.start", "SANDBOX_BOOT_FAILED"),
    };
    let detailed_failure_kind = detailed_vm_failure_kind(
        &crate::telemetry::vm_diagnostics_dir(&spec.instance_dir),
        phase,
    );
    let metadata = crate::telemetry::IncidentMetadata {
        event_id: event_id.clone(),
        timestamp_utc: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "unknown".to_string()),
        stable_error_code: stable_error_code.to_string(),
        correlation_id: Some(spec.correlation_id.clone()),
        resource_id: Some(spec.resource_id.clone()),
        failure_phase: phase.to_string(),
        common_context: crate::telemetry::CommonContext::collect(
            option_env!("GITHUB_SHA").unwrap_or("unknown"),
            None,
            None,
        ),
    };
    let snapshot = crate::telemetry::collect_incident(
        &engine.telemetry_root().join("incidents"),
        &crate::telemetry::vm_diagnostics_dir(&spec.instance_dir),
        Some(engine.service_log()),
        &metadata,
        crate::telemetry::DiagnosticLimits::default(),
    );
    let snapshot = match snapshot {
        Ok(snapshot) => snapshot,
        Err(error) => {
            crate::telemetry::record_failure(crate::telemetry::TelemetryFailure::IncidentSnapshot);
            crate::telemetry::record_failure(crate::telemetry::TelemetryFailure::Archive);
            eprintln!("bounded QEMU incident snapshot/archive failed: {error}");
            engine.record_diagnostic_capture_failure();
            return;
        }
    };
    let mut event = crate::telemetry::FailureEvent::new(
        operation,
        stable_error_code,
        crate::telemetry::Level::Error,
        crate::telemetry::format_error_chain(error),
    )
    .with_detailed_failure_kind(detailed_failure_kind)
    .with_event_id(event_id)
    .with_correlation_id(&spec.correlation_id)
    .with_resource_id(&spec.resource_id)
    .with_phase(phase)
    .with_tag("qemu.failure_kind", detailed_failure_kind)
    .with_attachments(snapshot.attachments.clone());
    event.contexts.insert(
        "incident".to_string(),
        serde_json::json!({
            "event_id": snapshot.event_id,
            "total_bytes": snapshot.total_bytes,
        }),
    );
    let expects_live_diagnostics = matches!(
        detailed_failure_kind,
        "guest_ready_timeout" | "qemu_shutdown_timeout"
    );
    if !apply_qemu_diagnostic_context(&mut event, &snapshot.directory, expects_live_diagnostics)
        && expects_live_diagnostics
    {
        engine.record_diagnostic_capture_failure();
    }
    let captured = telemetry.capture_failure(event);
    if let Some(captured_event_id) = captured {
        let receipt_written = if expects_live_diagnostics {
            match crate::telemetry::write_sentry_receipt(
                engine.telemetry_root(),
                &snapshot.directory,
                &captured_event_id,
                sentry_project_identity().as_deref(),
            ) {
                Ok(()) => true,
                Err(error) => {
                    eprintln!("failed to write bounded QEMU Sentry receipt: {error}");
                    engine.record_diagnostic_capture_failure();
                    false
                }
            }
        } else {
            true
        };
        if receipt_written {
            if let Err(error) = snapshot.remove() {
                eprintln!("failed to remove accepted QEMU incident snapshot: {error}");
                engine.record_diagnostic_capture_failure();
            }
        } else if let Err(error) =
            snapshot.retain_bounded(crate::telemetry::RetentionPolicy::default())
        {
            eprintln!("failed to retain QEMU incident after receipt failure: {error}");
            engine.record_diagnostic_capture_failure();
        }
    } else if let Err(error) = snapshot.retain_bounded(crate::telemetry::RetentionPolicy::default())
    {
        eprintln!("failed to retain unaccepted QEMU incident snapshot: {error}");
        engine.record_diagnostic_capture_failure();
    } else if expects_live_diagnostics {
        engine.record_diagnostic_capture_failure();
    }
}

fn apply_qemu_diagnostic_context(
    event: &mut crate::telemetry::FailureEvent,
    incident_directory: &Path,
    expects_live_diagnostics: bool,
) -> bool {
    let hang = read_bounded_json(&incident_directory.join("qemu-hang.json"));
    let dump = read_bounded_json(&incident_directory.join("qemu-hang-dump.json"));
    let hyperv = read_bounded_json(&incident_directory.join("hyperv-events.json"));
    if let Some(hang) = &hang {
        event.contexts.insert("qemu".to_string(), hang.clone());
        for (tag, pointer) in [
            ("qemu.hang_signature", "/hang_signature"),
            ("qemu.qmp_responsive", "/qmp/responsive"),
        ] {
            if let Some(value) = hang.pointer(pointer) {
                event.tags.insert(tag.to_string(), scalar_tag(value));
            }
        }
        let serial = hang
            .pointer("/progress/serial_bytes")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|bytes| bytes > 0);
        let stderr = hang
            .pointer("/progress/stderr_bytes")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|bytes| bytes > 0);
        event
            .tags
            .insert("qemu.serial_observed".to_string(), serial.to_string());
        event
            .tags
            .insert("qemu.stderr_observed".to_string(), stderr.to_string());
    }
    let live_process_captured = hang
        .as_ref()
        .and_then(|value| value.get("process_snapshot_succeeded"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    if expects_live_diagnostics && !live_process_captured {
        crate::telemetry::record_failure(crate::telemetry::TelemetryFailure::LiveProcessSnapshot);
    }
    event
        .tags
        .insert("qemu.accelerator".to_string(), "whpx".to_string());
    let dump_captured = dump
        .as_ref()
        .and_then(|value| value.get("success"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    if expects_live_diagnostics && !dump_captured {
        crate::telemetry::record_failure(crate::telemetry::TelemetryFailure::Dump);
    }
    event
        .tags
        .insert("qemu.dump_captured".to_string(), dump_captured.to_string());
    let hyperv_errors = hyperv
        .as_ref()
        .and_then(|value| value.get("channels"))
        .and_then(serde_json::Value::as_array)
        .is_some_and(|channels| {
            channels.iter().any(|channel| {
                channel
                    .get("query_error")
                    .is_some_and(|value| !value.is_null())
            })
        });
    if expects_live_diagnostics && (hyperv.is_none() || hyperv_errors) {
        crate::telemetry::record_failure(crate::telemetry::TelemetryFailure::Hyperv);
    }
    let qmp_responsive = hang
        .as_ref()
        .and_then(|value| value.pointer("/qmp/responsive"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    if expects_live_diagnostics && !qmp_responsive {
        crate::telemetry::record_failure(crate::telemetry::TelemetryFailure::Qmp);
    }
    event.tags.insert(
        "qemu.hyperv_errors_present".to_string(),
        hyperv_errors.to_string(),
    );
    let archive = incident_directory.join("incident.zip");
    let archive_size = std::fs::metadata(&archive)
        .ok()
        .filter(|metadata| metadata.is_file())
        .map(|metadata| metadata.len());
    let archive_sha256 = bounded_file_sha256(&archive);
    let archive_captured = archive_size.is_some() && archive_sha256.is_some();
    let hyperv_captured = hyperv.is_some() && !hyperv_errors;
    let complete = dump_captured
        && live_process_captured
        && qmp_responsive
        && hyperv_captured
        && archive_captured;
    event.contexts.insert(
        "diagnostic".to_string(),
        serde_json::json!({
            "local_dump_available": dump_captured,
            "local_dump_relative_path": dump.as_ref().and_then(|value| value.get("relative_local_path")),
            "dump_size": dump.as_ref().and_then(|value| value.get("dump_byte_size")),
            "dump_sha256": dump.as_ref().and_then(|value| value.get("sha256")),
            "archive_size": archive_size,
            "archive_sha256": archive_sha256,
            "attachments_prepared": 2,
            "attachments_accepted": serde_json::Value::Null,
            "partial_capture": !complete,
            "collectors": {
                "live_process": live_process_captured,
                "qmp": qmp_responsive,
                "hyperv": hyperv_captured,
                "dump": dump_captured,
                "archive": archive_captured,
            },
            "telemetry_failure_counters": crate::telemetry::failure_counter_context(),
        }),
    );
    complete
}

fn read_bounded_json(path: &Path) -> Option<serde_json::Value> {
    let bytes = std::fs::read(path).ok()?;
    if bytes.len() > 256 * 1024 {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

fn bounded_file_sha256(path: &Path) -> Option<String> {
    use sha2::Digest;

    let metadata = std::fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > 10 * 1024 * 1024 {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    Some(format!("{:x}", sha2::Sha256::digest(bytes)))
}

fn scalar_tag(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(value) => value.chars().take(64).collect(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Number(value) => value.to_string(),
        _ => "unknown".to_string(),
    }
}

fn sentry_project_identity() -> Option<String> {
    let dsn = option_env!("LSB_SENTRY_DSN")?;
    let uri = dsn.parse::<http::Uri>().ok()?;
    let host = uri.host()?;
    let project = uri.path().trim_matches('/').rsplit('/').next()?;
    if project.is_empty() {
        return None;
    }
    Some(format!("{host}/{project}"))
}

fn detailed_vm_failure_kind(diagnostics_dir: &Path, phase: &str) -> &'static str {
    if let Some(kind) =
        read_bounded_json(&diagnostics_dir.join("qemu-hang.json")).and_then(|value| {
            value
                .get("failure_kind")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        })
    {
        if matches!(
            kind.as_str(),
            "guest_ready_timeout" | "qemu_shutdown_timeout"
        ) {
            return normalize_qemu_failure_kind(&kind);
        }
    }
    if let Ok(contents) = std::fs::read_to_string(diagnostics_dir.join("boot.status.json")) {
        if contents.len() <= 256 * 1024 {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&contents) {
                if let Some(kind) = value.get("error_kind").and_then(serde_json::Value::as_str) {
                    return normalize_qemu_failure_kind(kind);
                }
            }
        }
    }
    match phase {
        "stop" => "stop_failed",
        "runtime" => "guest_process_exited",
        _ => "preflight",
    }
}

fn normalize_qemu_failure_kind(kind: &str) -> &'static str {
    match kind {
        "asset_missing" => "asset_missing",
        "invalid_config" | "artifact_io" | "preflight" | "argv" => "preflight",
        "process_start" | "process_status" | "qmp_open" => "process_start",
        "control_open" => "control_open",
        "guest_boot_exited" | "guest_ready_process_exited" => "guest_process_exited",
        "guest_ready_timeout" => "guest_ready_timeout",
        "guest_ready_protocol" => "guest_ready_protocol",
        "guest_ready_transport" => "guest_ready_transport",
        "unsupported_windows_runtime_capability" => "unsupported_capability",
        "serial_output_missing" => "serial_output_missing",
        "qemu_shutdown_timeout" => "qemu_shutdown_timeout",
        "stop_failed" => "stop_failed",
        _ => "preflight",
    }
}

fn stop_and_cleanup(
    sandbox: &lsb_vm::Sandbox,
    engine: &ServiceEngineConfig,
    spec: &ManagedVmSpec,
    containment: &SandboxJob,
) -> Result<()> {
    sandbox.stop()?;
    let relative_path = spec
        .instance_dir
        .strip_prefix(engine.resources_root())
        .context("protected instance is not relative to resources root")?
        .display()
        .to_string();
    let file_id = crate::resource::mount::protected_identity(&spec.instance_dir)?;
    containment.require_staging_identity(&relative_path, &file_id)?;
    let cleanup_span = containment.start_lifecycle_span(
        "sandbox.instance_cleanup",
        "remove protected sandbox instance",
    );
    let cleanup_result = cleanup_instance(engine, spec);
    if let Some(span) = cleanup_span {
        span.finish(if cleanup_result.is_ok() {
            crate::telemetry::SpanStatus::Ok
        } else {
            crate::telemetry::SpanStatus::InternalError
        });
    }
    cleanup_result?;
    let ledger_span =
        containment.start_lifecycle_span("sandbox.ledger_finish", "finish sandbox resource ledger");
    let ledger_result = containment.finish_transaction();
    if let Some(span) = ledger_span {
        span.finish(if ledger_result.is_ok() {
            crate::telemetry::SpanStatus::Ok
        } else {
            crate::telemetry::SpanStatus::InternalError
        });
    }
    let _ = sandbox.record_resource_ledger_finished(ledger_result.is_ok());
    ledger_result
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
    trace_parent: &crate::telemetry::SpanParent,
) -> Result<(lsb_vm::Sandbox, Option<lsb_proxy::ProxyHandle>)> {
    let proxy_span = trace_parent.start_child(crate::telemetry::SpanDescription::child(
        "sandbox.proxy_start",
        "create protected sandbox proxy",
    ));
    let proxy_result: Result<(
        Option<lsb_vm::PlatformNetworkAttachment>,
        Option<lsb_proxy::ProxyHandle>,
    )> = (|| {
        Ok(match spec.proxy_config.take() {
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
        })
    })();
    proxy_span.finish(if proxy_result.is_ok() {
        crate::telemetry::SpanStatus::Ok
    } else {
        crate::telemetry::SpanStatus::InternalError
    });
    let (network_attachment, proxy_handle) = proxy_result?;
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
    for mount in &spec.mounts {
        builder = builder.mount(lsb_vm::MountConfig::Direct {
            host_path: mount.host_path.clone(),
            guest_path: mount.guest_path.clone(),
            flags: u64::from(mount.read_only),
        });
    }
    let sandbox = builder.build()?;
    let mount_span = trace_parent.start_child(crate::telemetry::SpanDescription::child(
        "sandbox.mount_initialize",
        "initialize sandbox mounts and boot VM",
    ));
    let start_result = sandbox.start();
    mount_span.finish(if start_result.is_ok() {
        crate::telemetry::SpanStatus::Ok
    } else {
        crate::telemetry::SpanStatus::InternalError
    });
    start_result?;
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
    use std::fs::File;

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
            correlation_id: "correlation".to_string(),
            resource_id: "sandbox".to_string(),
            instance_dir: PathBuf::from(r"C:\Users\caller\instance"),
            rootfs_image: PathBuf::from(r"C:\Users\caller\instance\rootfs.ext4"),
            cpus: 100,
            memory_mib: 64,
            mounts: Vec::new(),
            proxy_config: None,
        };
        assert!(validate_spec(&engine, &spec).is_err());
    }

    #[test]
    fn managed_vm_job_limits_include_fixed_overhead_and_process_cap() {
        let spec = ManagedVmSpec {
            correlation_id: "correlation".to_string(),
            resource_id: "sandbox".to_string(),
            instance_dir: PathBuf::from(r"C:\ProgramData\LocalSandbox\instance"),
            rootfs_image: PathBuf::from(r"C:\ProgramData\LocalSandbox\instance\rootfs.ext4"),
            cpus: 2,
            memory_mib: 4096,
            mounts: Vec::new(),
            proxy_config: None,
        };

        let limits = job_limits(&spec).expect("bounded request should produce Job limits");
        assert_eq!(limits.active_processes, 8);
        assert_eq!(limits.memory_bytes, 6144 * 1024 * 1024usize);
    }

    #[test]
    fn vm_incident_diagnostics_are_read_from_platform_artifact_directory() {
        let instance_dir = PathBuf::from(r"C:\ProgramData\LocalSandbox\instance");

        assert_eq!(
            crate::telemetry::vm_diagnostics_dir(&instance_dir),
            instance_dir.join("diagnostics")
        );
    }

    #[test]
    fn vm_incident_message_preserves_the_complete_error_chain() {
        let error = anyhow::anyhow!("guest-ready handshake timed out")
            .context("start Windows QEMU")
            .context("Failed to start VM");

        let message = crate::telemetry::format_error_chain(&error);

        assert!(message.contains("Failed to start VM"));
        assert!(message.contains("start Windows QEMU"));
        assert!(message.contains("guest-ready handshake timed out"));
    }

    #[test]
    fn unaccepted_vm_incident_is_retained_with_its_archive() {
        let root = std::env::temp_dir().join(format!(
            "lsbsw-rejected-vm-incident-{}-{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        let paths = ServicePaths::for_test(root.clone());
        let bundle = root.join("bundle");
        let engine = ServiceEngineConfig::from_verified_bundle(
            bundle.clone(),
            bundle.join("qemu-system-x86_64.exe"),
            bundle.join("Image"),
            bundle.join("initramfs.cpio.gz"),
            bundle.join("rootfs.ext4"),
            &paths,
        )
        .unwrap();
        let resource_id = "0123456789abcdef0123456789abcdef";
        let instance_dir = engine.resources_root().join(resource_id);
        let diagnostics = crate::telemetry::vm_diagnostics_dir(&instance_dir);
        std::fs::create_dir_all(&diagnostics).unwrap();
        std::fs::write(
            diagnostics.join("qemu-hang.json"),
            br#"{"schema_version":1,"failure_kind":"guest_ready_timeout"}"#,
        )
        .unwrap();
        let spec = ManagedVmSpec {
            correlation_id: "correlation-1".to_string(),
            resource_id: resource_id.to_string(),
            rootfs_image: instance_dir.join("rootfs.ext4"),
            instance_dir,
            cpus: 2,
            memory_mib: 2048,
            mounts: Vec::new(),
            proxy_config: None,
        };

        capture_vm_failure(
            &crate::telemetry::Telemetry::disabled(),
            &engine,
            &spec,
            &anyhow::anyhow!("guest-ready handshake timed out"),
            "start",
        );

        let incidents = std::fs::read_dir(engine.telemetry_root().join("incidents"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        assert_eq!(incidents.len(), 1);
        assert!(incidents[0].join("incident.json").is_file());
        assert!(incidents[0].join("incident.zip").is_file());
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(incidents[0].join("incident.json")).unwrap())
                .unwrap();
        assert_eq!(manifest["stable_error_code"], "SANDBOX_BOOT_FAILED");
        assert_eq!(manifest["correlation_id"], "correlation-1");
        assert_eq!(manifest["resource_id"], resource_id);

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn diagnostic_context_marks_collector_failures_as_partial_capture() {
        let root = std::env::temp_dir().join(format!(
            "lsbsw-partial-qemu-context-{}-{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::write(
            root.join("qemu-hang.json"),
            br#"{
                "process_snapshot_succeeded": true,
                "hang_signature": "alive_no_serial_no_stderr_no_ready",
                "progress": {"serial_bytes": 0, "stderr_bytes": 0},
                "qmp": {"responsive": false}
            }"#,
        )
        .unwrap();
        std::fs::write(
            root.join("qemu-hang-dump.json"),
            br#"{"success":true,"relative_local_path":"qemu-dumps/id/qemu-hang.dmp","dump_byte_size":1,"sha256":"00"}"#,
        )
        .unwrap();
        std::fs::write(
            root.join("hyperv-events.json"),
            br#"{"channels":[{"query_error":"access_denied"}]}"#,
        )
        .unwrap();
        std::fs::write(root.join("incident.zip"), b"bounded archive").unwrap();
        let mut event = crate::telemetry::FailureEvent::new(
            "sandbox.start",
            "SANDBOX_BOOT_FAILED",
            crate::telemetry::Level::Error,
            "test",
        );

        assert!(!apply_qemu_diagnostic_context(&mut event, &root, true));
        let diagnostic = event.contexts.get("diagnostic").unwrap();
        assert_eq!(diagnostic["partial_capture"], true);
        assert_eq!(diagnostic["collectors"]["live_process"], true);
        assert_eq!(diagnostic["collectors"]["dump"], true);
        assert_eq!(diagnostic["collectors"]["archive"], true);
        assert_eq!(diagnostic["collectors"]["qmp"], false);
        assert_eq!(diagnostic["collectors"]["hyperv"], false);
        assert_eq!(event.tags["qemu.qmp_responsive"], "false");
        assert_eq!(event.tags["qemu.hyperv_errors_present"], "true");

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn shutdown_hang_artifact_drives_stop_failure_kind() {
        let root = std::env::temp_dir().join(format!(
            "lsbsw-shutdown-kind-{}-{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::write(
            root.join("boot.status.json"),
            br#"{"state":"ready","error_kind":null}"#,
        )
        .unwrap();
        std::fs::write(
            root.join("qemu-hang.json"),
            br#"{"schema_version":1,"failure_kind":"qemu_shutdown_timeout"}"#,
        )
        .unwrap();

        assert_eq!(
            detailed_vm_failure_kind(&root, "stop"),
            "qemu_shutdown_timeout"
        );

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn qmp_open_failure_uses_process_start_grouping() {
        assert_eq!(normalize_qemu_failure_kind("qmp_open"), "process_start");
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

    #[cfg(feature = "qemu-hang-test-hooks")]
    #[test]
    #[ignore = "requires Windows 11 x86_64 with WHPX and provisioned QEMU/runtime assets"]
    fn windows_service_owned_qemu_hang_smoke() {
        let assets = PathBuf::from(
            std::env::var_os("LSB_WINDOWS_TEST_ASSETS_ROOT").expect("LSB_WINDOWS_TEST_ASSETS_ROOT"),
        );
        let service_root = PathBuf::from(
            std::env::var_os("LSB_QEMU_HANG_TEST_SERVICE_ROOT")
                .expect("LSB_QEMU_HANG_TEST_SERVICE_ROOT"),
        );
        let paths = ServicePaths::for_test(service_root);
        paths.prepare().unwrap();
        let engine = ServiceEngineConfig::from_verified_bundle(
            assets.clone(),
            assets.join("qemu/qemu-system-x86_64.exe"),
            assets.join("runtime/Image"),
            assets.join("runtime/initramfs.cpio.gz"),
            assets.join("runtime/rootfs.ext4"),
            &paths,
        )
        .unwrap();
        std::fs::write(
            engine.service_log(),
            b"{\"level\":\"info\",\"message\":\"qemu telemetry smoke\"}\n",
        )
        .unwrap();
        let identity =
            crate::session::ClientIdentityKey::for_test("S-1-5-21-qemu-smoke", "S-1-5-5-1-1", 1);
        let resource = ResourceHandle::random().unwrap();
        let instance_dir = engine.resources_root().join(resource.to_string());
        std::fs::create_dir(&instance_dir).unwrap();
        let rootfs_image = instance_dir.join("rootfs.ext4");
        std::fs::copy(engine.base_rootfs(), &rootfs_image).unwrap();
        let transaction = crate::resource::transaction::ResourceTransaction::reserve(
            engine.ledger_root(),
            &resource.to_string(),
            &identity,
        )
        .unwrap();
        let real_sentry = std::env::var_os("LSB_QEMU_HANG_TEST_REAL_SENTRY").is_some();
        let telemetry = if real_sentry {
            #[cfg(all(windows, feature = "sentry-telemetry"))]
            {
                let handler = PathBuf::from(
                    std::env::var_os("LSB_QEMU_HANG_TEST_CRASHPAD_HANDLER")
                        .expect("LSB_QEMU_HANG_TEST_CRASHPAD_HANDLER"),
                );
                crate::telemetry::Telemetry::initialize_native(
                    &engine.telemetry_root().join("sentry-acceptance-db"),
                    &handler,
                    &[],
                    &crate::telemetry::CommonContext::collect(
                        option_env!("GITHUB_SHA").unwrap_or("qemu-sentry-acceptance"),
                        None,
                        Some("qemu-sentry-acceptance".to_string()),
                    ),
                )
                .expect("initialize real Sentry telemetry")
            }
            #[cfg(not(all(windows, feature = "sentry-telemetry")))]
            panic!("real Sentry acceptance requires Windows and sentry-telemetry")
        } else {
            crate::telemetry::Telemetry::disabled()
        };
        let transaction_span = telemetry.start_span(
            crate::telemetry::SpanDescription::transaction("sandbox.start"),
        );
        let result = ManagedVm::start(
            &engine,
            transaction,
            ManagedVmSpec {
                correlation_id: "windows-service-qemu-hang-smoke".to_string(),
                resource_id: resource.to_string(),
                instance_dir,
                rootfs_image,
                cpus: 2,
                memory_mib: 2048,
                mounts: Vec::new(),
                proxy_config: None,
            },
            CancellationToken::default(),
            CancellationToken::default(),
            telemetry.clone(),
            transaction_span.parent(),
        );
        transaction_span.finish(crate::telemetry::SpanStatus::InternalError);
        let error = result.expect_err("test hook must force a service-owned QEMU timeout");
        let error_chain = format!("{error:#}");
        assert!(error_chain.contains("guest-ready"), "{error_chain}");
        assert!(
            error_chain.contains("correlation_id=windows-service-qemu-hang-smoke"),
            "{error_chain}"
        );
        assert!(
            error_chain.contains(&format!("resource_id={resource}")),
            "{error_chain}"
        );

        if real_sentry {
            telemetry.flush(Duration::from_secs(30));
            let diagnostics = crate::telemetry::vm_diagnostics_dir(
                &engine.resources_root().join(resource.to_string()),
            );
            let hang: serde_json::Value =
                serde_json::from_slice(&std::fs::read(diagnostics.join("qemu-hang.json")).unwrap())
                    .unwrap();
            let incident_id = hang["incident_id"].as_str().unwrap();
            let dump_directory = engine.telemetry_root().join("qemu-dumps").join(incident_id);
            let dump: serde_json::Value = serde_json::from_slice(
                &std::fs::read(dump_directory.join("qemu-hang-dump.json")).unwrap(),
            )
            .unwrap();
            let receipt: serde_json::Value = serde_json::from_slice(
                &std::fs::read(dump_directory.join("sentry-receipt.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(dump["sentry_event_id"], receipt["sentry_event_id"]);
            assert_eq!(dump["incident_id"], receipt["incident_id"]);
            assert_eq!(dump["success"], true);
            let result = serde_json::json!({
                "schema_version": 1,
                "incident_id": incident_id,
                "sentry_event_id": receipt["sentry_event_id"],
                "dump_relative_path": dump["relative_local_path"],
                "dump_size": dump["dump_byte_size"],
                "dump_sha256": dump["sha256"],
                "correlation_id": "windows-service-qemu-hang-smoke",
                "resource_id": resource.to_string(),
            });
            let result_path = PathBuf::from(
                std::env::var_os("LSB_QEMU_HANG_TEST_REAL_SENTRY_RESULT")
                    .expect("LSB_QEMU_HANG_TEST_REAL_SENTRY_RESULT"),
            );
            std::fs::write(&result_path, serde_json::to_vec_pretty(&result).unwrap()).unwrap();
            eprintln!("QEMU_SENTRY_ACCEPTANCE_RESULT {}", result_path.display());
            return;
        }

        let incident_root = engine.telemetry_root().join("incidents");
        let incidents = std::fs::read_dir(&incident_root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.is_dir())
            .collect::<Vec<_>>();
        assert_eq!(incidents.len(), 1);
        let incident = &incidents[0];
        let hang: serde_json::Value =
            serde_json::from_slice(&std::fs::read(incident.join("qemu-hang.json")).unwrap())
                .unwrap();
        let dump: serde_json::Value =
            serde_json::from_slice(&std::fs::read(incident.join("qemu-hang-dump.json")).unwrap())
                .unwrap();
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(incident.join("incident.json")).unwrap())
                .unwrap();
        let progress = std::fs::read_to_string(incident.join("qemu-progress.jsonl")).unwrap();
        let timeline = std::fs::read_to_string(incident.join("qemu-timeline.jsonl")).unwrap();
        assert_eq!(hang["failure_kind"], "guest_ready_timeout");
        assert_eq!(hang["process_snapshot_succeeded"], true);
        assert_eq!(hang["correlation_id"], "windows-service-qemu-hang-smoke");
        assert_eq!(hang["resource_id"], resource.to_string());
        assert_eq!(hang["job"]["active_pids"], serde_json::json!([]));
        assert_eq!(hang["job"]["active_process_zero_observed"], true);
        assert_eq!(hang["job"]["termination_requested"], false);
        assert_eq!(
            hang["job"]["termination_succeeded"],
            serde_json::Value::Null
        );
        assert_eq!(dump["incident_id"], hang["incident_id"]);
        assert_eq!(dump["correlation_id"], "windows-service-qemu-hang-smoke");
        assert_eq!(dump["resource_id"], resource.to_string());
        assert_eq!(
            manifest["correlation_id"],
            "windows-service-qemu-hang-smoke"
        );
        assert_eq!(manifest["resource_id"], resource.to_string());
        for line in progress.lines().chain(timeline.lines()) {
            let record: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(record["incident_id"], hang["incident_id"]);
            assert_eq!(record["correlation_id"], "windows-service-qemu-hang-smoke");
            assert_eq!(record["resource_id"], resource.to_string());
        }
        for name in ["boot.status.json", "preflight.json", "qemu.status.json"] {
            let evidence: serde_json::Value =
                serde_json::from_slice(&std::fs::read(incident.join(name)).unwrap()).unwrap();
            assert_eq!(evidence["incident_id"], hang["incident_id"], "{name}");
            assert_eq!(
                evidence["correlation_id"], "windows-service-qemu-hang-smoke",
                "{name}"
            );
            assert_eq!(evidence["resource_id"], resource.to_string(), "{name}");
        }
        let hyperv: serde_json::Value =
            serde_json::from_slice(&std::fs::read(incident.join("hyperv-events.json")).unwrap())
                .unwrap();
        assert_eq!(hyperv["incident_id"], hang["incident_id"]);
        assert_eq!(hyperv["correlation_id"], "windows-service-qemu-hang-smoke");
        assert_eq!(hyperv["resource_id"], resource.to_string());
        assert_eq!(hyperv["channels"].as_array().map(Vec::len), Some(3));
        let mut archive =
            zip::ZipArchive::new(File::open(incident.join("incident.zip")).unwrap()).unwrap();
        let archive_names = (0..archive.len())
            .map(|index| archive.by_index(index).unwrap().name().to_string())
            .collect::<Vec<_>>();
        assert_eq!(
            archive_names,
            [
                "incident.json",
                "machine.json",
                "qemu-hang.json",
                "qemu-progress.jsonl",
                "qemu-timeline.jsonl",
                "qemu-hang-dump.json",
                "hyperv-events.json",
                "boot.status.json",
                "preflight.json",
                "qemu.argv.redacted.txt",
                "qemu.status.json",
                "qemu.stderr.log",
                "qemu.stdout.log",
                "serial.log",
                "service.tail.jsonl",
            ]
        );
        assert!(archive.by_name("qemu-hang.json").is_ok());
        assert!(archive.by_name("hyperv-events.json").is_ok());
        assert!(archive.by_name("qemu-hang.dmp").is_err());
    }

    #[cfg(feature = "qemu-hang-test-hooks")]
    #[test]
    #[ignore = "requires Windows 11 x86_64 with WHPX and provisioned QEMU/runtime assets"]
    fn windows_service_owned_qemu_shutdown_hang_smoke() {
        let assets = PathBuf::from(
            std::env::var_os("LSB_WINDOWS_TEST_ASSETS_ROOT").expect("LSB_WINDOWS_TEST_ASSETS_ROOT"),
        );
        let service_root = PathBuf::from(
            std::env::var_os("LSB_QEMU_HANG_TEST_SERVICE_STOP_ROOT")
                .expect("LSB_QEMU_HANG_TEST_SERVICE_STOP_ROOT"),
        );
        let paths = ServicePaths::for_test(service_root);
        paths.prepare().unwrap();
        let engine = ServiceEngineConfig::from_verified_bundle(
            assets.clone(),
            assets.join("qemu/qemu-system-x86_64.exe"),
            assets.join("runtime/Image"),
            assets.join("runtime/initramfs.cpio.gz"),
            assets.join("runtime/rootfs.ext4"),
            &paths,
        )
        .unwrap();
        std::fs::write(
            engine.service_log(),
            b"{\"level\":\"info\",\"message\":\"qemu shutdown telemetry smoke\"}\n",
        )
        .unwrap();
        let identity = crate::session::ClientIdentityKey::for_test(
            "S-1-5-21-qemu-stop-smoke",
            "S-1-5-5-1-2",
            1,
        );
        let resource = ResourceHandle::random().unwrap();
        let instance_dir = engine.resources_root().join(resource.to_string());
        std::fs::create_dir(&instance_dir).unwrap();
        let rootfs_image = instance_dir.join("rootfs.ext4");
        std::fs::copy(engine.base_rootfs(), &rootfs_image).unwrap();
        let transaction = crate::resource::transaction::ResourceTransaction::reserve(
            engine.ledger_root(),
            &resource.to_string(),
            &identity,
        )
        .unwrap();
        let telemetry = crate::telemetry::Telemetry::disabled();
        let start_span = telemetry.start_span(crate::telemetry::SpanDescription::transaction(
            "sandbox.start",
        ));
        let vm = ManagedVm::start(
            &engine,
            transaction,
            ManagedVmSpec {
                correlation_id: "windows-service-qemu-stop-smoke".to_string(),
                resource_id: resource.to_string(),
                instance_dir,
                rootfs_image,
                cpus: 2,
                memory_mib: 2048,
                mounts: Vec::new(),
                proxy_config: None,
            },
            CancellationToken::default(),
            CancellationToken::default(),
            telemetry.clone(),
            start_span.parent(),
        )
        .expect("service-owned QEMU must reach guest ready before shutdown injection");
        start_span.finish(crate::telemetry::SpanStatus::Ok);
        let stop_span = telemetry.start_span(crate::telemetry::SpanDescription::transaction(
            "sandbox.stop",
        ));
        let error = vm
            .stop(Duration::from_secs(1), Some(stop_span.parent()))
            .expect_err("test hook must force a service-owned QEMU shutdown timeout");
        stop_span.finish(crate::telemetry::SpanStatus::InternalError);
        let error_chain = format!("{error:#}");
        assert!(error_chain.contains("did not exit"), "{error_chain}");
        assert!(
            error_chain.contains("correlation_id=windows-service-qemu-stop-smoke"),
            "{error_chain}"
        );
        assert!(
            error_chain.contains(&format!("resource_id={resource}")),
            "{error_chain}"
        );

        let incidents = std::fs::read_dir(engine.telemetry_root().join("incidents"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.is_dir())
            .collect::<Vec<_>>();
        assert_eq!(incidents.len(), 1);
        let incident = &incidents[0];
        let hang: serde_json::Value =
            serde_json::from_slice(&std::fs::read(incident.join("qemu-hang.json")).unwrap())
                .unwrap();
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(incident.join("incident.json")).unwrap())
                .unwrap();
        assert_eq!(hang["failure_kind"], "qemu_shutdown_timeout");
        assert_eq!(hang["job"]["active_pids"], serde_json::json!([]));
        assert_eq!(hang["job"]["active_process_zero_observed"], true);
        assert_eq!(hang["job"]["termination_requested"], false);
        assert_eq!(
            hang["job"]["termination_succeeded"],
            serde_json::Value::Null
        );
        assert_eq!(manifest["stable_error_code"], "SANDBOX_STOP_FAILED");
        assert_eq!(manifest["failure_phase"], "stop");
        assert_eq!(
            manifest["correlation_id"],
            "windows-service-qemu-stop-smoke"
        );
        assert_eq!(manifest["resource_id"], resource.to_string());
    }
}
