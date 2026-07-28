use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
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
    dump: QemuDumpPlaceholder,
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

#[derive(Debug, Serialize)]
struct QemuDumpPlaceholder {
    attempted: bool,
    completed: bool,
    manifest: Option<&'static str>,
}

pub(crate) fn write_initial_hang_artifact(
    directory: &Path,
    incident_id: &str,
    failure_kind: &str,
    elapsed: Duration,
    process: &QemuProcessSnapshot,
    progress: &QemuProgressSnapshot,
    qmp: &QemuQmpSnapshot,
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
        dump: QemuDumpPlaceholder {
            attempted: false,
            completed: false,
            manifest: None,
        },
    };
    let mut encoded = serde_json::to_vec_pretty(&artifact).map_err(io::Error::other)?;
    encoded.push(b'\n');
    write_atomic(directory, HANG_FILE, &encoded)
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
}
