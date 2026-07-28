use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const TIMELINE_FILE: &str = "qemu-timeline.jsonl";
const MAX_TIMELINE_RECORD_BYTES: usize = 4 * 1024;

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
            timestamp_utc: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .map_err(io::Error::other)?,
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
}
