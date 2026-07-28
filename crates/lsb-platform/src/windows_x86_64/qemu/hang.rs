use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const TIMELINE_FILE: &str = "qemu-timeline.jsonl";
const PROGRESS_FILE: &str = "qemu-progress.jsonl";
const HANG_FILE: &str = "qemu-hang.json";
const MAX_TIMELINE_RECORD_BYTES: usize = 4 * 1024;
const MAX_PROGRESS_RECORD_BYTES: usize = 8 * 1024;
const SAMPLE_SCHEDULE: &[Duration] = &[
    Duration::from_secs(1),
    Duration::from_secs(5),
    Duration::from_secs(15),
    Duration::from_secs(30),
    Duration::from_secs(60),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct QemuDumpRetention {
    pub completed_incident_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct QemuHangTelemetryPolicy {
    pub dump_deadline: Duration,
    pub local_dump_retention: QemuDumpRetention,
}

impl Default for QemuHangTelemetryPolicy {
    fn default() -> Self {
        Self {
            dump_deadline: Duration::from_secs(30),
            local_dump_retention: QemuDumpRetention {
                completed_incident_count: 3,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum QemuTimelinePhase {
    PreflightStarted,
    PreflightCompleted,
    QemuSpawnRequested,
    QemuSpawnedSuspended,
    QemuJobAssigned,
    QemuPrimaryThreadResumed,
    QemuStartupObservationCompleted,
    ControlPipeOpenStarted,
    ControlPipeOpened,
    ForwardPipeOpenStarted,
    ForwardPipeOpened,
    GuestReadyWaitStarted,
    FirstSerialByte,
    FirstStdoutByte,
    FirstStderrByte,
    FirstControlByte,
    GuestReadyTimeout,
    QmpSnapshotStarted,
    QmpSnapshotCompleted,
    HypervSnapshotStarted,
    HypervSnapshotCompleted,
    DumpStarted,
    DumpHelperStarted,
    DumpHelperExited,
    DumpHelperTimedOut,
    DumpCompleted,
    QemuShutdownTimeout,
    TerminationRequested,
    TerminateJobReturned,
    QemuProcessExited,
    JobActiveProcessZero,
    ControlReaderExited,
    ForwardReaderExited,
    InstanceCleanupStarted,
    InstanceCleanupCompleted,
    LedgerTransactionFinished,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub(crate) struct QemuProcessSnapshot {
    pub pid: u32,
    pub creation_time: u64,
    pub cpu_user_100ns: u64,
    pub cpu_kernel_100ns: u64,
    pub working_set_bytes: u64,
    pub private_bytes: u64,
    pub virtual_bytes: u64,
    pub handle_count: u32,
    pub thread_count: u32,
    pub io_read_bytes: u64,
    pub io_write_bytes: u64,
    pub io_other_bytes: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub(crate) struct QemuProgressSnapshot {
    pub serial_bytes: u64,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub control_pipe_open: bool,
    pub guest_ready_bytes_received: u64,
}

#[derive(Debug, Serialize)]
struct QemuProgressRecord<'a> {
    schema_version: u32,
    incident_id: &'a str,
    sequence: u64,
    monotonic_elapsed_ms: u128,
    timestamp_utc: String,
    process: &'a QemuProcessSnapshot,
    progress: &'a QemuProgressSnapshot,
}

#[derive(Debug)]
pub(crate) struct QemuProgressWriter {
    incident_id: Arc<str>,
    path: PathBuf,
    file: File,
    started_at: Instant,
    sequence: u64,
    next_scheduled_sample: usize,
}

impl QemuProgressWriter {
    pub(crate) fn create(directory: &Path, incident_id: &str) -> io::Result<Self> {
        let path = directory.join(PROGRESS_FILE);
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)?;
        Ok(Self {
            incident_id: Arc::from(incident_id),
            path,
            file,
            started_at: Instant::now(),
            sequence: 0,
            next_scheduled_sample: 0,
        })
    }

    pub(crate) fn record_if_due<F>(
        &mut self,
        mut snapshot: F,
    ) -> io::Result<Option<(QemuProcessSnapshot, QemuProgressSnapshot)>>
    where
        F: FnMut() -> io::Result<(QemuProcessSnapshot, QemuProgressSnapshot)>,
    {
        let elapsed = self.started_at.elapsed();
        if self
            .next_scheduled_sample
            .checked_sub(SAMPLE_SCHEDULE.len())
            .is_some()
            || SAMPLE_SCHEDULE
                .get(self.next_scheduled_sample)
                .is_none_or(|scheduled| elapsed < *scheduled)
        {
            return Ok(None);
        }
        let snapshots = snapshot()?;
        self.write_record(elapsed, &snapshots.0, &snapshots.1)?;
        self.next_scheduled_sample += 1;
        Ok(Some(snapshots))
    }

    pub(crate) fn record_final(
        &mut self,
        process: &QemuProcessSnapshot,
        progress: &QemuProgressSnapshot,
    ) -> io::Result<()> {
        self.write_record(self.started_at.elapsed(), process, progress)
    }

    pub(crate) fn elapsed(&self) -> Duration {
        self.started_at.elapsed()
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    fn write_record(
        &mut self,
        elapsed: Duration,
        process: &QemuProcessSnapshot,
        progress: &QemuProgressSnapshot,
    ) -> io::Result<()> {
        let record = QemuProgressRecord {
            schema_version: 1,
            incident_id: &self.incident_id,
            sequence: self.sequence,
            monotonic_elapsed_ms: elapsed.as_millis(),
            timestamp_utc: utc_timestamp()?,
            process,
            progress,
        };
        let mut encoded = serde_json::to_vec(&record).map_err(io::Error::other)?;
        encoded.push(b'\n');
        if encoded.len() > MAX_PROGRESS_RECORD_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "QEMU progress record exceeds its fixed bound",
            ));
        }
        self.file.write_all(&encoded)?;
        self.file.flush()?;
        self.sequence = self.sequence.saturating_add(1);
        Ok(())
    }
}

#[derive(Debug, Serialize)]
struct QemuHangArtifact<'a> {
    schema_version: u32,
    incident_id: &'a str,
    failure_kind: &'a str,
    hang_signature: &'a str,
    elapsed_ms: u128,
    process: &'a QemuProcessSnapshot,
    progress: &'a QemuProgressSnapshot,
    qmp: &'a QemuQmpSnapshot,
    dump: &'a QemuDumpCaptureSummary,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub(crate) struct QemuQmpSnapshot {
    pub connected: bool,
    pub responsive: bool,
    pub queries: Vec<QemuQmpQuery>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct QemuQmpQuery {
    pub request_name: String,
    pub start_monotonic_ms: u128,
    pub end_monotonic_ms: u128,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub(crate) struct QemuDumpCaptureSummary {
    pub attempted: bool,
    pub completed: bool,
    pub manifest: Option<String>,
}

pub(crate) fn write_initial_hang_artifact(
    directory: &Path,
    incident_id: &str,
    failure_kind: &str,
    elapsed: Duration,
    process: &QemuProcessSnapshot,
    progress: &QemuProgressSnapshot,
    qmp: &QemuQmpSnapshot,
    dump: &QemuDumpCaptureSummary,
) -> io::Result<()> {
    let hang_signature = classify_hang_signature(process, progress);
    let artifact = QemuHangArtifact {
        schema_version: 1,
        incident_id,
        failure_kind,
        hang_signature,
        elapsed_ms: elapsed.as_millis(),
        process,
        progress,
        qmp,
        dump,
    };
    let mut encoded = serde_json::to_vec_pretty(&artifact).map_err(io::Error::other)?;
    encoded.push(b'\n');
    write_atomic(directory, HANG_FILE, &encoded)
}

const DUMP_FLAGS: &[&str] = &[
    "MiniDumpNormal",
    "MiniDumpWithThreadInfo",
    "MiniDumpWithHandleData",
    "MiniDumpWithUnloadedModules",
    "MiniDumpWithFullMemoryInfo",
    "MiniDumpWithProcessThreadData",
    "MiniDumpWithIndirectlyReferencedMemory",
];
const DUMP_TYPE_VALUE: i32 = 6500;

#[derive(Debug, Serialize)]
struct DumpManifest<'a> {
    schema_version: u32,
    incident_id: &'a str,
    sentry_event_id: Option<&'a str>,
    run_id: &'a Option<String>,
    correlation_id: &'a str,
    resource_id: &'a str,
    qemu_pid: u32,
    qemu_creation_time: u64,
    dump_started_utc: &'a str,
    dump_completed_utc: &'a str,
    elapsed_ms: u128,
    dump_type: &'static str,
    dump_type_value: i32,
    dump_flags: &'static [&'static str],
    dump_byte_size: Option<u64>,
    sha256: Option<&'a str>,
    success: bool,
    failure: Option<&'a str>,
    win32_error: Option<u32>,
    relative_local_path: &'a str,
    retention: DumpRetentionManifest,
}

#[derive(Debug, Clone, Copy, Serialize)]
struct DumpRetentionManifest {
    max_completed_incidents: usize,
    pruned_completed_incidents: usize,
    reconciliation_error: bool,
}

#[derive(Debug, serde::Deserialize)]
struct DumpHelperResult {
    schema_version: u32,
    success: bool,
    win32_error: Option<u32>,
}

pub(crate) fn capture_dump(
    process_handle: Option<isize>,
    process: &QemuProcessSnapshot,
    context: Option<&crate::PlatformQemuTelemetryContext>,
    incident_id: &str,
    artifact_directory: &Path,
    policy: QemuHangTelemetryPolicy,
    timeline: Option<&QemuTimeline>,
) -> QemuDumpCaptureSummary {
    let Some(context) = context else {
        return QemuDumpCaptureSummary {
            attempted: true,
            completed: false,
            manifest: None,
        };
    };
    let dump_root = context.telemetry_root.join("qemu-dumps");
    let retention = match reconcile_dump_retention(
        &dump_root,
        policy
            .local_dump_retention
            .completed_incident_count
            .saturating_sub(1),
    ) {
        Ok(pruned) => DumpRetentionManifest {
            max_completed_incidents: policy.local_dump_retention.completed_incident_count,
            pruned_completed_incidents: pruned,
            reconciliation_error: false,
        },
        Err(_) => DumpRetentionManifest {
            max_completed_incidents: policy.local_dump_retention.completed_incident_count,
            pruned_completed_incidents: 0,
            reconciliation_error: true,
        },
    };
    let incident_directory = dump_root.join(incident_id);
    let _ = fs::create_dir_all(&incident_directory);
    let dump_started_utc = utc_timestamp().unwrap_or_else(|_| "unknown".to_string());
    let started_at = Instant::now();
    if let Some(timeline) = timeline {
        let _ = timeline.record(QemuTimelinePhase::DumpStarted);
    }
    let outcome = write_dump_with_helper(
        process_handle,
        process.pid,
        &incident_directory,
        policy.dump_deadline,
        timeline,
    );
    let dump_completed_utc = utc_timestamp().unwrap_or_else(|_| "unknown".to_string());
    let elapsed = started_at.elapsed();
    let relative_path = format!("qemu-dumps/{incident_id}/qemu-hang.dmp");
    let manifest = DumpManifest {
        schema_version: 1,
        incident_id,
        sentry_event_id: None,
        run_id: &context.run_id,
        correlation_id: &context.correlation_id,
        resource_id: &context.resource_id,
        qemu_pid: process.pid,
        qemu_creation_time: process.creation_time,
        dump_started_utc: &dump_started_utc,
        dump_completed_utc: &dump_completed_utc,
        elapsed_ms: elapsed.as_millis(),
        dump_type: "diagnostic_qemu_hang",
        dump_type_value: DUMP_TYPE_VALUE,
        dump_flags: DUMP_FLAGS,
        dump_byte_size: outcome.byte_size,
        sha256: outcome.sha256.as_deref(),
        success: outcome.success,
        failure: outcome.failure.as_deref(),
        win32_error: outcome.win32_error,
        relative_local_path: &relative_path,
        retention,
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .map(|mut bytes| {
            bytes.push(b'\n');
            bytes
        })
        .unwrap_or_default();
    let manifest_name = "qemu-hang-dump.json";
    let local_manifest_written =
        write_atomic(&incident_directory, manifest_name, &manifest_bytes).is_ok();
    let diagnostic_manifest_written =
        write_atomic(artifact_directory, manifest_name, &manifest_bytes).is_ok();
    if let Some(timeline) = timeline {
        let _ = timeline.record_result(
            QemuTimelinePhase::DumpCompleted,
            Some(elapsed),
            Some(if outcome.success {
                "success"
            } else {
                "failure"
            }),
            outcome.failure.as_deref().map(|_| "dump"),
        );
    }
    QemuDumpCaptureSummary {
        attempted: true,
        completed: outcome.success,
        manifest: (local_manifest_written && diagnostic_manifest_written)
            .then(|| manifest_name.to_string()),
    }
}

struct DumpOutcome {
    success: bool,
    byte_size: Option<u64>,
    sha256: Option<String>,
    failure: Option<String>,
    win32_error: Option<u32>,
}

#[cfg(not(windows))]
fn write_dump_with_helper(
    _process_handle: Option<isize>,
    _pid: u32,
    _incident_directory: &Path,
    _deadline: Duration,
    _timeline: Option<&QemuTimeline>,
) -> DumpOutcome {
    DumpOutcome {
        success: false,
        byte_size: None,
        sha256: None,
        failure: Some("dump helper is available only on Windows".to_string()),
        win32_error: None,
    }
}

#[cfg(windows)]
fn write_dump_with_helper(
    process_handle: Option<isize>,
    _pid: u32,
    incident_directory: &Path,
    deadline: Duration,
    timeline: Option<&QemuTimeline>,
) -> DumpOutcome {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::process::{Command, Stdio};

    use windows_sys::Win32::Foundation::{DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE};
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    let failure = |message: String| DumpOutcome {
        success: false,
        byte_size: None,
        sha256: None,
        failure: Some(message),
        win32_error: None,
    };
    let Some(process_handle) = process_handle else {
        return failure("QEMU process handle was unavailable".to_string());
    };
    let helper_path = match std::env::current_exe().ok().and_then(|path| {
        path.parent()
            .map(|parent| parent.join("localsandbox-qemu-dump-helper.exe"))
    }) {
        Some(path) if path.is_file() => path,
        _ => return failure("packaged QEMU dump helper was unavailable".to_string()),
    };
    let pending_path = incident_directory.join("qemu-hang.dmp.pending");
    let final_path = incident_directory.join("qemu-hang.dmp");
    let output = match OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&pending_path)
    {
        Ok(file) => file,
        Err(error) => return failure(format!("create pending dump: {error}")),
    };
    let duplicate = |source: HANDLE| -> io::Result<OwnedHandle> {
        let mut target = std::ptr::null_mut();
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                source,
                GetCurrentProcess(),
                &mut target,
                0,
                1,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { OwnedHandle::from_raw_handle(target as _) })
    };
    let inherited_process = match duplicate(process_handle as HANDLE) {
        Ok(handle) => handle,
        Err(error) => return failure(format!("duplicate QEMU process handle: {error}")),
    };
    let inherited_output = match duplicate(output.as_raw_handle() as HANDLE) {
        Ok(handle) => handle,
        Err(error) => return failure(format!("duplicate dump output handle: {error}")),
    };
    let mut command = Command::new(helper_path);
    command
        .arg("--process-handle")
        .arg((inherited_process.as_raw_handle() as usize).to_string())
        .arg("--output-handle")
        .arg((inherited_output.as_raw_handle() as usize).to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    crate::windows_x86_64::apply_qemu_no_window_creation_flags(&mut command);
    let mut helper = match command.spawn() {
        Ok(child) => child,
        Err(error) => return failure(format!("start QEMU dump helper: {error}")),
    };
    drop(inherited_process);
    drop(inherited_output);
    if let Some(timeline) = timeline {
        let _ = timeline.record(QemuTimelinePhase::DumpHelperStarted);
    }
    let helper_deadline = Instant::now() + deadline;
    let status = loop {
        match helper.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < helper_deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(None) => {
                let _ = helper.kill();
                let _ = helper.wait();
                if let Some(timeline) = timeline {
                    let _ = timeline.record(QemuTimelinePhase::DumpHelperTimedOut);
                }
                let _ = fs::remove_file(&pending_path);
                return failure("QEMU dump helper exceeded its fixed deadline".to_string());
            }
            Err(error) => return failure(format!("poll QEMU dump helper: {error}")),
        }
    };
    if let Some(timeline) = timeline {
        let _ = timeline.record(QemuTimelinePhase::DumpHelperExited);
    }
    let mut result_bytes = Vec::new();
    if let Some(mut stdout) = helper.stdout.take() {
        let _ = stdout.by_ref().take(4096).read_to_end(&mut result_bytes);
    }
    let helper_result = serde_json::from_slice::<DumpHelperResult>(&result_bytes).ok();
    if status.is_none_or(|status| !status.success())
        || helper_result
            .as_ref()
            .is_none_or(|result| result.schema_version != 1 || !result.success)
    {
        let win32_error = helper_result.and_then(|result| result.win32_error);
        let _ = fs::remove_file(&pending_path);
        return DumpOutcome {
            win32_error,
            ..failure("QEMU dump helper reported failure".to_string())
        };
    }
    if let Err(error) = output.sync_all() {
        let _ = fs::remove_file(&pending_path);
        return failure(format!("flush QEMU dump: {error}"));
    }
    drop(output);
    let (byte_size, sha256) = match hash_file(&pending_path) {
        Ok(value) => value,
        Err(error) => {
            let _ = fs::remove_file(&pending_path);
            return failure(format!("hash QEMU dump: {error}"));
        }
    };
    if let Err(error) = fs::rename(&pending_path, &final_path) {
        let _ = fs::remove_file(&pending_path);
        return failure(format!("commit QEMU dump: {error}"));
    }
    DumpOutcome {
        success: true,
        byte_size: Some(byte_size),
        sha256: Some(sha256),
        failure: None,
        win32_error: None,
    }
}

fn hash_file(path: &Path) -> io::Result<(u64, String)> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let bytes = io::copy(&mut file, &mut hash)?;
    Ok((bytes, format!("{:x}", hash.finalize())))
}

fn reconcile_dump_retention(root: &Path, retain: usize) -> io::Result<usize> {
    fs::create_dir_all(root)?;
    let root_metadata = fs::symlink_metadata(root)?;
    if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
        return Err(io::Error::other(
            "QEMU dump root is not a regular directory",
        ));
    }
    let canonical_root = fs::canonicalize(root)?;
    let mut completed = Vec::new();
    for entry in fs::read_dir(root)?.take(128) {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.len() != 32 || !name.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            continue;
        }
        if !entry.path().join("qemu-hang-dump.json").is_file() {
            continue;
        }
        let canonical = fs::canonicalize(entry.path())?;
        if canonical.parent() != Some(canonical_root.as_path()) {
            continue;
        }
        completed.push((metadata.modified()?, canonical));
    }
    completed.sort_by_key(|(modified, _)| *modified);
    let remove_count = completed.len().saturating_sub(retain);
    for (_, path) in completed.into_iter().take(remove_count) {
        fs::remove_dir_all(path)?;
    }
    Ok(remove_count)
}

pub(crate) fn classify_hang_signature(
    process: &QemuProcessSnapshot,
    progress: &QemuProgressSnapshot,
) -> &'static str {
    if process.pid != 0
        && progress.control_pipe_open
        && progress.guest_ready_bytes_received == 0
        && progress.serial_bytes == 0
        && progress.stdout_bytes == 0
        && progress.stderr_bytes == 0
    {
        "alive_no_serial_no_stderr_no_ready"
    } else {
        "qemu_alive_guest_ready_timeout"
    }
}

#[derive(Debug, Serialize)]
struct TimelineRecord<'a> {
    schema_version: u32,
    incident_id: &'a str,
    sequence: u64,
    phase: QemuTimelinePhase,
    monotonic_elapsed_ms: u128,
    timestamp_utc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_ms: Option<u128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    outcome: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_category: Option<&'a str>,
}

#[derive(Debug)]
struct TimelineState {
    file: File,
    sequence: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct QemuTimeline {
    incident_id: Arc<str>,
    path: Arc<PathBuf>,
    started_at: Instant,
    state: Arc<Mutex<TimelineState>>,
}

impl QemuTimeline {
    pub(crate) fn create(directory: &Path) -> io::Result<Self> {
        fs::create_dir_all(directory)?;
        let path = directory.join(TIMELINE_FILE);
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)?;
        Ok(Self {
            incident_id: Arc::from(generate_incident_id()?),
            path: Arc::new(path),
            started_at: Instant::now(),
            state: Arc::new(Mutex::new(TimelineState { file, sequence: 0 })),
        })
    }

    pub(crate) fn incident_id(&self) -> &str {
        &self.incident_id
    }

    pub(crate) fn path(&self) -> &Path {
        self.path.as_path()
    }

    pub(crate) fn elapsed(&self) -> Duration {
        self.started_at.elapsed()
    }

    pub(crate) fn record(&self, phase: QemuTimelinePhase) -> io::Result<()> {
        self.record_result(phase, None, None, None)
    }

    pub(crate) fn record_result(
        &self,
        phase: QemuTimelinePhase,
        duration: Option<Duration>,
        outcome: Option<&str>,
        error_category: Option<&str>,
    ) -> io::Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("QEMU timeline lock poisoned"))?;
        let sequence = state.sequence;
        let record = TimelineRecord {
            schema_version: 1,
            incident_id: self.incident_id(),
            sequence,
            phase,
            monotonic_elapsed_ms: self.started_at.elapsed().as_millis(),
            timestamp_utc: utc_timestamp()?,
            duration_ms: duration.map(|value| value.as_millis()),
            outcome,
            error_category,
        };
        let mut encoded = serde_json::to_vec(&record).map_err(io::Error::other)?;
        encoded.push(b'\n');
        if encoded.len() > MAX_TIMELINE_RECORD_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "QEMU timeline record exceeds its fixed bound",
            ));
        }
        state.file.write_all(&encoded)?;
        state.file.flush()?;
        state.sequence = sequence.saturating_add(1);
        Ok(())
    }
}

fn utc_timestamp() -> io::Result<String> {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(io::Error::other)
}

fn write_atomic(directory: &Path, name: &str, contents: &[u8]) -> io::Result<()> {
    let destination = directory.join(name);
    let pending = directory.join(format!("{name}.pending"));
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&pending)?;
    file.write_all(contents)?;
    file.sync_all()?;
    drop(file);
    fs::rename(pending, destination)
}

fn generate_incident_id() -> io::Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|error| io::Error::other(format!("generate QEMU incident ID: {error}")))?;
    let mut value = String::with_capacity(32);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "lsb-qemu-timeline-{name}-{}",
            generate_incident_id().unwrap()
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn production_policy_is_fixed_and_enabled() {
        let policy = QemuHangTelemetryPolicy::default();
        assert_eq!(policy.dump_deadline, Duration::from_secs(30));
        assert_eq!(policy.local_dump_retention.completed_incident_count, 3);
    }

    #[test]
    fn timeline_records_stable_bounded_monotonic_jsonl() {
        let directory = temp_dir("schema");
        let timeline = QemuTimeline::create(&directory).unwrap();
        timeline
            .record(QemuTimelinePhase::PreflightStarted)
            .unwrap();
        timeline
            .record_result(
                QemuTimelinePhase::PreflightCompleted,
                Some(Duration::from_millis(12)),
                Some("success"),
                None,
            )
            .unwrap();

        let contents = fs::read_to_string(timeline.path()).unwrap();
        let lines = contents.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 2);
        assert!(lines
            .iter()
            .all(|line| line.len() < MAX_TIMELINE_RECORD_BYTES));
        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(first["schema_version"], 1);
        assert_eq!(first["incident_id"], timeline.incident_id());
        assert_eq!(first["sequence"], 0);
        assert_eq!(second["sequence"], 1);
        assert_eq!(first["phase"], "preflight_started");
        assert_eq!(second["phase"], "preflight_completed");
        assert!(
            second["monotonic_elapsed_ms"].as_u64().unwrap()
                >= first["monotonic_elapsed_ms"].as_u64().unwrap()
        );
        assert!(first["timestamp_utc"].as_str().unwrap().ends_with('Z'));
        assert_eq!(second["duration_ms"], 12);
        assert_eq!(second["outcome"], "success");
        assert!(!contents.contains('\r'));

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn timeline_create_starts_a_fresh_current_attempt_artifact() {
        let directory = temp_dir("fresh-attempt");
        let first = QemuTimeline::create(&directory).unwrap();
        first.record(QemuTimelinePhase::PreflightStarted).unwrap();
        drop(first);
        let second = QemuTimeline::create(&directory).unwrap();
        second
            .record(QemuTimelinePhase::QemuSpawnRequested)
            .unwrap();
        let contents = fs::read_to_string(second.path()).unwrap();
        assert!(!contents.contains("preflight_started"));
        assert!(contents.contains("qemu_spawn_requested"));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn observed_empty_output_signature_is_stable() {
        let process = QemuProcessSnapshot {
            pid: 2024,
            ..QemuProcessSnapshot::default()
        };
        let progress = QemuProgressSnapshot {
            control_pipe_open: true,
            ..QemuProgressSnapshot::default()
        };
        assert_eq!(
            classify_hang_signature(&process, &progress),
            "alive_no_serial_no_stderr_no_ready"
        );
        assert_eq!(
            classify_hang_signature(
                &process,
                &QemuProgressSnapshot {
                    stderr_bytes: 1,
                    ..progress
                }
            ),
            "qemu_alive_guest_ready_timeout"
        );
    }

    #[test]
    fn progress_final_sample_and_hang_artifact_share_incident_id() {
        let directory = temp_dir("progress");
        let process = QemuProcessSnapshot {
            pid: 42,
            cpu_user_100ns: 12,
            ..QemuProcessSnapshot::default()
        };
        let progress = QemuProgressSnapshot {
            control_pipe_open: true,
            ..QemuProgressSnapshot::default()
        };
        let mut writer = QemuProgressWriter::create(&directory, "incident-1").unwrap();
        writer.record_final(&process, &progress).unwrap();
        write_initial_hang_artifact(
            &directory,
            "incident-1",
            "guest_ready_timeout",
            Duration::from_millis(90_000),
            &process,
            &progress,
            &QemuQmpSnapshot::default(),
            &QemuDumpCaptureSummary::default(),
        )
        .unwrap();

        let progress_contents = fs::read_to_string(writer.path()).unwrap();
        let progress_json: serde_json::Value =
            serde_json::from_str(progress_contents.trim()).unwrap();
        let hang_json: serde_json::Value =
            serde_json::from_slice(&fs::read(directory.join(HANG_FILE)).unwrap()).unwrap();
        assert_eq!(progress_json["incident_id"], "incident-1");
        assert_eq!(hang_json["incident_id"], "incident-1");
        assert_eq!(hang_json["failure_kind"], "guest_ready_timeout");
        assert_eq!(
            hang_json["hang_signature"],
            "alive_no_serial_no_stderr_no_ready"
        );
        assert_eq!(hang_json["process"]["cpu_user_100ns"], 12);
        assert_eq!(hang_json["dump"]["attempted"], false);

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn retention_keeps_only_the_newest_completed_incidents() {
        let directory = temp_dir("retention");
        let root = directory.join("qemu-dumps");
        fs::create_dir_all(&root).unwrap();
        let ids = [
            "00000000000000000000000000000001",
            "00000000000000000000000000000002",
            "00000000000000000000000000000003",
            "00000000000000000000000000000004",
        ];
        for id in ids {
            let incident = root.join(id);
            fs::create_dir(&incident).unwrap();
            fs::write(incident.join("qemu-hang-dump.json"), b"{}\n").unwrap();
            std::thread::sleep(Duration::from_millis(20));
        }
        let pending = root.join("ffffffffffffffffffffffffffffffff");
        fs::create_dir(&pending).unwrap();
        fs::write(pending.join("qemu-hang.dmp.pending"), b"partial").unwrap();

        assert_eq!(reconcile_dump_retention(&root, 3).unwrap(), 1);
        assert!(!root.join(ids[0]).exists());
        assert!(ids[1..].iter().all(|id| root.join(id).is_dir()));
        assert!(pending.is_dir(), "active pending incidents must be ignored");

        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn retention_never_follows_reparse_like_symlinks_outside_root() {
        use std::os::unix::fs::symlink;

        let directory = temp_dir("retention-symlink");
        let root = directory.join("qemu-dumps");
        let outside = directory.join("outside");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("keep.txt"), b"keep").unwrap();
        symlink(&outside, root.join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")).unwrap();

        assert_eq!(reconcile_dump_retention(&root, 0).unwrap(), 0);
        assert_eq!(fs::read(outside.join("keep.txt")).unwrap(), b"keep");

        let linked_root = directory.join("linked-root");
        symlink(&root, &linked_root).unwrap();
        assert!(reconcile_dump_retention(&linked_root, 0).is_err());

        fs::remove_dir_all(directory).unwrap();
    }
}
