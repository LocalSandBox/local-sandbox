use std::env;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;

pub(crate) const WINDOWS_MOUNT_METRICS_ENV: &str = "LSB_WINDOWS_MOUNT_METRICS_PATH";
const METRICS_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub(crate) enum DurationMetric {
    InitialPlan,
    GuestReady,
    Replan,
    SnapshotWalk,
    CacheLookup,
    CacheImageCreate,
    CacheDiskConfig,
    CacheDeviceDiscovery,
    CacheFormat,
    MuxSessionOpen,
    Transfer,
    Barrier,
    CacheValidate,
    OverlayMount,
    CachePublish,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
pub(crate) enum FailedPhase {
    Configuration,
    InitialPlan,
    VmCreate,
    GuestReady,
    Replan,
    Transfer,
    Barrier,
    CacheLookup,
    CachePrepare,
    CacheValidate,
    OverlayMount,
    VmStop,
    Finalization,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
pub(crate) enum ErrorCategory {
    InvalidConfiguration,
    UnsafeSource,
    SourceMutation,
    VmCreateFailed,
    VmStartFailed,
    TransportFailure,
    ProtocolFailure,
    GuestRejected,
    BarrierFailed,
    CacheInfrastructure,
    VmStopFailed,
    MetricsNotFinalized,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
pub(crate) enum CacheDecision {
    Disabled,
    HitSelected,
    BuildSelected,
    BusyBypass,
    UnsupportedBypass,
    InvalidCorruptBypass,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
pub(crate) enum TerminalOutcome {
    HitUsed,
    FallbackUsed,
    BuildPublished,
    BuildNotPublished,
    StartupFailed,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
pub(crate) enum FallbackReason {
    CacheDisabled,
    Busy,
    UnsupportedGuest,
    InvalidObject,
    CorruptObject,
    ImageCreateFailed,
    GuestRejected,
    BootRetry,
}

#[derive(Debug, Clone)]
pub(crate) struct MountSourceSummary {
    pub mount_id: String,
    pub file_count: u64,
    pub directory_count: u64,
    pub logical_bytes: u64,
    pub entries_visited: u64,
}

#[derive(Debug, Clone, Serialize)]
struct PerMountMetrics {
    mount_id: String,
    cache_decision: CacheDecision,
    terminal_outcome: Option<TerminalOutcome>,
    fallback_reason: Option<FallbackReason>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum MetricsStatus {
    Success,
    Failure,
}

#[derive(Debug, Clone, Serialize)]
struct MetricsRecord {
    schema_version: u32,
    status: Option<MetricsStatus>,
    failed_phase: Option<FailedPhase>,
    error_category: Option<ErrorCategory>,

    external_total_ms: Option<f64>,
    total_start_ms: f64,
    initial_plan_ms: f64,
    guest_ready_ms: f64,
    replan_ms: f64,
    snapshot_walk_ms: f64,
    cache_lookup_ms: f64,
    cache_image_create_ms: f64,
    cache_disk_config_ms: f64,
    cache_device_discovery_ms: f64,
    cache_format_ms: f64,
    mux_session_open_ms: f64,
    transfer_ms: f64,
    barrier_ms: f64,
    cache_validate_ms: f64,
    overlay_mount_ms: f64,
    cache_publish_ms: f64,
    mount_work_ms: f64,

    file_count: u64,
    directory_count: u64,
    logical_source_bytes: u64,
    snapshot_bytes_hashed: u64,
    transfer_verification_bytes_hashed: u64,
    guest_validation_bytes_hashed: u64,
    raw_image_bytes_hashed: u64,
    bytes_transferred: u64,
    chunk_count: u64,
    full_tree_walk_count: u64,
    entries_visited_per_walk: Vec<u64>,
    mux_file_sessions: u64,
    filesystem_requests: u64,
    filesystem_responses: u64,
    sync_all_calls: u64,
    global_sync_calls: u64,
    final_barriers: u64,

    cache_schema_version: Option<u32>,
    cache_key_version: Option<u32>,
    image_logical_size_bytes: u64,
    cache_object_count_before: u64,
    cache_object_count_after: u64,
    eviction_count: u64,
    lowerdir_tmpfs_bytes: u64,
    mounts: Vec<PerMountMetrics>,
}

impl Default for MetricsRecord {
    fn default() -> Self {
        Self {
            schema_version: METRICS_SCHEMA_VERSION,
            status: None,
            failed_phase: None,
            error_category: None,
            external_total_ms: None,
            total_start_ms: 0.0,
            initial_plan_ms: 0.0,
            guest_ready_ms: 0.0,
            replan_ms: 0.0,
            snapshot_walk_ms: 0.0,
            cache_lookup_ms: 0.0,
            cache_image_create_ms: 0.0,
            cache_disk_config_ms: 0.0,
            cache_device_discovery_ms: 0.0,
            cache_format_ms: 0.0,
            mux_session_open_ms: 0.0,
            transfer_ms: 0.0,
            barrier_ms: 0.0,
            cache_validate_ms: 0.0,
            overlay_mount_ms: 0.0,
            cache_publish_ms: 0.0,
            mount_work_ms: 0.0,
            file_count: 0,
            directory_count: 0,
            logical_source_bytes: 0,
            snapshot_bytes_hashed: 0,
            transfer_verification_bytes_hashed: 0,
            guest_validation_bytes_hashed: 0,
            raw_image_bytes_hashed: 0,
            bytes_transferred: 0,
            chunk_count: 0,
            full_tree_walk_count: 0,
            entries_visited_per_walk: Vec::new(),
            mux_file_sessions: 0,
            filesystem_requests: 0,
            filesystem_responses: 0,
            sync_all_calls: 0,
            global_sync_calls: 0,
            final_barriers: 0,
            cache_schema_version: None,
            cache_key_version: None,
            image_logical_size_bytes: 0,
            cache_object_count_before: 0,
            cache_object_count_after: 0,
            eviction_count: 0,
            lowerdir_tmpfs_bytes: 0,
            mounts: Vec::new(),
        }
    }
}

impl MetricsRecord {
    fn calculate_mount_work_ms(&mut self) {
        self.mount_work_ms = self.initial_plan_ms
            + self.replan_ms
            + self.snapshot_walk_ms
            + self.cache_lookup_ms
            + self.cache_image_create_ms
            + self.cache_disk_config_ms
            + self.cache_device_discovery_ms
            + self.cache_format_ms
            + self.mux_session_open_ms
            + self.transfer_ms
            + self.barrier_ms
            + self.cache_validate_ms
            + self.overlay_mount_ms;
    }
}

#[derive(Debug)]
struct MetricsState {
    record: MetricsRecord,
    current_phase: FailedPhase,
    current_error_category: ErrorCategory,
    start_instant: Option<Instant>,
    mount_init_active: bool,
}

#[derive(Debug)]
struct MetricsInner {
    path: PathBuf,
    state: Mutex<MetricsState>,
    finalized: AtomicBool,
}

impl Drop for MetricsInner {
    fn drop(&mut self) {
        if self.finalized.swap(true, Ordering::AcqRel) {
            return;
        }
        let snapshot = match self.state.get_mut() {
            Ok(state) => {
                state.record.status = Some(MetricsStatus::Failure);
                state.record.failed_phase = Some(state.current_phase);
                state.record.error_category = Some(ErrorCategory::MetricsNotFinalized);
                record_start_elapsed(state);
                state.record.calculate_mount_work_ms();
                state.record.clone()
            }
            Err(poisoned) => poisoned.into_inner().record.clone(),
        };
        write_metrics_file(&self.path, &snapshot);
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct WindowsMountMetrics {
    inner: Option<Arc<MetricsInner>>,
}

impl WindowsMountMetrics {
    pub(crate) fn from_env() -> Self {
        let Some(path) = env::var_os(WINDOWS_MOUNT_METRICS_ENV).filter(|value| !value.is_empty())
        else {
            return Self::default();
        };
        Self::from_path(PathBuf::from(path))
    }

    fn from_path(path: PathBuf) -> Self {
        Self {
            inner: Some(Arc::new(MetricsInner {
                path,
                state: Mutex::new(MetricsState {
                    record: MetricsRecord::default(),
                    current_phase: FailedPhase::Configuration,
                    current_error_category: ErrorCategory::InvalidConfiguration,
                    start_instant: None,
                    mount_init_active: false,
                }),
                finalized: AtomicBool::new(false),
            })),
        }
    }

    #[cfg(test)]
    fn for_test(path: PathBuf) -> Self {
        Self::from_path(path)
    }

    #[cfg(test)]
    fn enabled(&self) -> bool {
        self.inner.is_some()
    }

    pub(crate) fn set_failure_context(&self, phase: FailedPhase, category: ErrorCategory) {
        self.with_state(|state| {
            state.current_phase = phase;
            state.current_error_category = category;
        });
    }

    pub(crate) fn begin_start(&self) {
        self.with_state(|state| state.start_instant = Some(Instant::now()));
    }

    pub(crate) fn complete_start(&self) {
        self.with_state(|state| {
            record_start_elapsed(state);
            state.start_instant = None;
        });
    }

    pub(crate) fn add_duration(&self, metric: DurationMetric, duration: Duration) {
        self.add_duration_ms(metric, duration.as_secs_f64() * 1000.0);
    }

    pub(crate) fn add_duration_ms(&self, metric: DurationMetric, milliseconds: f64) {
        self.with_state(|state| match metric {
            DurationMetric::InitialPlan => state.record.initial_plan_ms += milliseconds,
            DurationMetric::GuestReady => state.record.guest_ready_ms += milliseconds,
            DurationMetric::Replan => state.record.replan_ms += milliseconds,
            DurationMetric::SnapshotWalk => state.record.snapshot_walk_ms += milliseconds,
            DurationMetric::CacheLookup => state.record.cache_lookup_ms += milliseconds,
            DurationMetric::CacheImageCreate => state.record.cache_image_create_ms += milliseconds,
            DurationMetric::CacheDiskConfig => state.record.cache_disk_config_ms += milliseconds,
            DurationMetric::CacheDeviceDiscovery => {
                state.record.cache_device_discovery_ms += milliseconds
            }
            DurationMetric::CacheFormat => state.record.cache_format_ms += milliseconds,
            DurationMetric::MuxSessionOpen => state.record.mux_session_open_ms += milliseconds,
            DurationMetric::Transfer => state.record.transfer_ms += milliseconds,
            DurationMetric::Barrier => state.record.barrier_ms += milliseconds,
            DurationMetric::CacheValidate => state.record.cache_validate_ms += milliseconds,
            DurationMetric::OverlayMount => state.record.overlay_mount_ms += milliseconds,
            DurationMetric::CachePublish => state.record.cache_publish_ms += milliseconds,
        });
    }

    pub(crate) fn duration_ms(&self, metric: DurationMetric) -> f64 {
        let Some(inner) = &self.inner else {
            return 0.0;
        };
        let Ok(state) = inner.state.lock() else {
            return 0.0;
        };
        match metric {
            DurationMetric::InitialPlan => state.record.initial_plan_ms,
            DurationMetric::GuestReady => state.record.guest_ready_ms,
            DurationMetric::Replan => state.record.replan_ms,
            DurationMetric::SnapshotWalk => state.record.snapshot_walk_ms,
            DurationMetric::CacheLookup => state.record.cache_lookup_ms,
            DurationMetric::CacheImageCreate => state.record.cache_image_create_ms,
            DurationMetric::CacheDiskConfig => state.record.cache_disk_config_ms,
            DurationMetric::CacheDeviceDiscovery => state.record.cache_device_discovery_ms,
            DurationMetric::CacheFormat => state.record.cache_format_ms,
            DurationMetric::MuxSessionOpen => state.record.mux_session_open_ms,
            DurationMetric::Transfer => state.record.transfer_ms,
            DurationMetric::Barrier => state.record.barrier_ms,
            DurationMetric::CacheValidate => state.record.cache_validate_ms,
            DurationMetric::OverlayMount => state.record.overlay_mount_ms,
            DurationMetric::CachePublish => state.record.cache_publish_ms,
        }
    }

    pub(crate) fn initialize_mounts(&self, summaries: Vec<MountSourceSummary>) {
        self.with_state(|state| {
            for summary in summaries {
                state.record.file_count =
                    state.record.file_count.saturating_add(summary.file_count);
                state.record.directory_count = state
                    .record
                    .directory_count
                    .saturating_add(summary.directory_count);
                state.record.logical_source_bytes = state
                    .record
                    .logical_source_bytes
                    .saturating_add(summary.logical_bytes);
                state.record.full_tree_walk_count =
                    state.record.full_tree_walk_count.saturating_add(1);
                state
                    .record
                    .entries_visited_per_walk
                    .push(summary.entries_visited);
                state.record.mounts.push(PerMountMetrics {
                    mount_id: summary.mount_id,
                    cache_decision: CacheDecision::Disabled,
                    terminal_outcome: None,
                    fallback_reason: Some(FallbackReason::CacheDisabled),
                });
            }
        });
    }

    pub(crate) fn record_tree_walk(&self, entries_visited: u64) {
        self.with_state(|state| {
            state.record.full_tree_walk_count = state.record.full_tree_walk_count.saturating_add(1);
            state.record.entries_visited_per_walk.push(entries_visited);
        });
    }

    pub(crate) fn begin_mount_init(&self) -> MountInitMetricsGuard {
        self.with_state(|state| state.mount_init_active = true);
        MountInitMetricsGuard {
            metrics: self.clone(),
        }
    }

    pub(crate) fn mount_init_active(&self) -> bool {
        self.inner
            .as_ref()
            .and_then(|inner| inner.state.lock().ok())
            .is_some_and(|state| state.mount_init_active)
    }

    pub(crate) fn record_mux_file_session(&self, open_duration: Duration, opened: bool) {
        self.add_duration(DurationMetric::MuxSessionOpen, open_duration);
        if opened {
            self.with_state(|state| {
                state.record.mux_file_sessions = state.record.mux_file_sessions.saturating_add(1)
            });
        }
    }

    pub(crate) fn record_filesystem_request(&self) {
        self.with_state(|state| {
            state.record.filesystem_requests = state.record.filesystem_requests.saturating_add(1)
        });
    }

    pub(crate) fn record_filesystem_response(&self) {
        self.with_state(|state| {
            state.record.filesystem_responses = state.record.filesystem_responses.saturating_add(1)
        });
    }

    pub(crate) fn record_file_write(&self, bytes: u64, deferred: bool) {
        self.with_state(|state| {
            state.record.bytes_transferred = state.record.bytes_transferred.saturating_add(bytes);
            state.record.chunk_count = state.record.chunk_count.saturating_add(1);
            if !deferred {
                state.record.sync_all_calls = state.record.sync_all_calls.saturating_add(1);
                state.record.global_sync_calls = state.record.global_sync_calls.saturating_add(1);
            }
        });
    }

    #[allow(dead_code)]
    pub(crate) fn record_final_barrier(&self) {
        self.with_state(|state| {
            state.record.final_barriers = state.record.final_barriers.saturating_add(1)
        });
    }

    pub(crate) fn mark_fallback_mounts_used(&self) {
        self.with_state(|state| {
            state.record.lowerdir_tmpfs_bytes = state.record.logical_source_bytes;
            for mount in &mut state.record.mounts {
                mount.terminal_outcome = Some(TerminalOutcome::FallbackUsed);
            }
        });
    }

    pub(crate) fn finish_success(&self) {
        self.finish(Some(MetricsStatus::Success), None, None);
    }

    pub(crate) fn finish_failure(&self, phase: FailedPhase, category: ErrorCategory) {
        self.with_state(|state| {
            for mount in &mut state.record.mounts {
                mount.terminal_outcome = Some(TerminalOutcome::StartupFailed);
            }
        });
        self.finish(Some(MetricsStatus::Failure), Some(phase), Some(category));
    }

    pub(crate) fn finish_current_failure(&self) {
        let Some(inner) = &self.inner else {
            return;
        };
        let (phase, category) = match inner.state.lock() {
            Ok(state) => (state.current_phase, state.current_error_category),
            Err(poisoned) => {
                let state = poisoned.into_inner();
                (state.current_phase, state.current_error_category)
            }
        };
        self.finish_failure(phase, category);
    }

    fn finish(
        &self,
        status: Option<MetricsStatus>,
        failed_phase: Option<FailedPhase>,
        error_category: Option<ErrorCategory>,
    ) {
        let Some(inner) = &self.inner else {
            return;
        };
        if inner.finalized.swap(true, Ordering::AcqRel) {
            return;
        }
        let snapshot = match inner.state.lock() {
            Ok(mut state) => {
                state.record.status = status;
                state.record.failed_phase = failed_phase;
                state.record.error_category = error_category;
                record_start_elapsed(&mut state);
                state.record.calculate_mount_work_ms();
                state.record.clone()
            }
            Err(poisoned) => poisoned.into_inner().record.clone(),
        };
        write_metrics_file(&inner.path, &snapshot);
    }

    fn with_state(&self, update: impl FnOnce(&mut MetricsState)) {
        let Some(inner) = &self.inner else {
            return;
        };
        if let Ok(mut state) = inner.state.lock() {
            update(&mut state);
        }
    }
}

pub(crate) struct MountInitMetricsGuard {
    metrics: WindowsMountMetrics,
}

impl Drop for MountInitMetricsGuard {
    fn drop(&mut self) {
        self.metrics
            .with_state(|state| state.mount_init_active = false);
    }
}

fn record_start_elapsed(state: &mut MetricsState) {
    if let Some(started) = state.start_instant {
        state.record.total_start_ms = started.elapsed().as_secs_f64() * 1000.0;
    }
}

fn write_metrics_file(path: &Path, record: &MetricsRecord) {
    if let Err(error) = try_write_metrics_file(path, record) {
        tracing::warn!(
            path = %path.display(),
            error = %error,
            "failed to write Windows mount metrics"
        );
    }
}

fn try_write_metrics_file(path: &Path, record: &MetricsRecord) -> std::io::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("mount-metrics.json");
    let temporary = path.with_file_name(format!(".{file_name}.{}.tmp", std::process::id()));
    let result = (|| {
        let mut writer = BufWriter::new(File::create(&temporary)?);
        serde_json::to_writer_pretty(&mut writer, record).map_err(std::io::Error::other)?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        if path.exists() {
            fs::remove_file(path)?;
        }
        fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn disabled_collector_has_no_side_effects() {
        let metrics = WindowsMountMetrics::default();
        assert!(!metrics.enabled());
        metrics.begin_start();
        metrics.finish_success();
    }

    #[test]
    fn successful_record_contains_required_durations_counters_and_states() {
        let root = temp_dir("success");
        let path = root.join("nested/metrics.json");
        let metrics = WindowsMountMetrics::for_test(path.clone());
        metrics.begin_start();
        metrics.add_duration(DurationMetric::InitialPlan, Duration::from_millis(2));
        metrics.add_duration(DurationMetric::GuestReady, Duration::from_millis(3));
        metrics.add_duration(DurationMetric::Transfer, Duration::from_millis(5));
        metrics.initialize_mounts(vec![MountSourceSummary {
            mount_id: "mount0".to_string(),
            file_count: 2,
            directory_count: 1,
            logical_bytes: 11,
            entries_visited: 3,
        }]);
        metrics.record_tree_walk(3);
        metrics.record_mux_file_session(Duration::from_millis(1), true);
        metrics.record_filesystem_request();
        metrics.record_filesystem_response();
        metrics.record_file_write(11, false);
        metrics.mark_fallback_mounts_used();
        metrics.finish_success();

        let value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("metrics output"))
                .expect("metrics json");
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["status"], "success");
        assert_eq!(value["file_count"], 2);
        assert_eq!(value["directory_count"], 1);
        assert_eq!(value["logical_source_bytes"], 11);
        assert_eq!(value["full_tree_walk_count"], 2);
        assert_eq!(value["entries_visited_per_walk"], serde_json::json!([3, 3]));
        assert_eq!(value["mux_file_sessions"], 1);
        assert_eq!(value["filesystem_requests"], 1);
        assert_eq!(value["filesystem_responses"], 1);
        assert_eq!(value["sync_all_calls"], 1);
        assert_eq!(value["global_sync_calls"], 1);
        assert_eq!(value["bytes_transferred"], 11);
        assert_eq!(value["lowerdir_tmpfs_bytes"], 11);
        assert_eq!(value["mounts"][0]["mount_id"], "mount0");
        assert_eq!(value["mounts"][0]["cache_decision"], "disabled");
        assert_eq!(value["mounts"][0]["terminal_outcome"], "fallback_used");
        assert_eq!(value["mounts"][0]["fallback_reason"], "cache_disabled");
        assert_eq!(value["mount_work_ms"], 8.0);
        assert_eq!(value["guest_ready_ms"], 3.0);
        assert!(value.get("host_path").is_none());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn failure_record_uses_sanitized_categories() {
        let root = temp_dir("failure");
        let path = root.join("metrics.json");
        let metrics = WindowsMountMetrics::for_test(path.clone());
        metrics.initialize_mounts(vec![MountSourceSummary {
            mount_id: "mount0".to_string(),
            file_count: 0,
            directory_count: 1,
            logical_bytes: 0,
            entries_visited: 1,
        }]);
        metrics.finish_failure(FailedPhase::Transfer, ErrorCategory::SourceMutation);

        let json = fs::read_to_string(&path).expect("metrics output");
        assert!(json.contains("\"failed_phase\": \"transfer\""));
        assert!(json.contains("\"error_category\": \"source_mutation\""));
        assert!(json.contains("\"terminal_outcome\": \"startup_failed\""));
        assert!(!json.contains("C:\\"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn deferred_import_metrics_record_one_barrier_and_no_per_file_syncs() {
        let root = temp_dir("deferred");
        let path = root.join("metrics.json");
        let metrics = WindowsMountMetrics::for_test(path.clone());
        metrics.record_file_write(5, true);
        metrics.record_file_write(7, true);
        metrics.record_final_barrier();
        metrics.finish_success();

        let value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("metrics output"))
                .expect("metrics json");
        assert_eq!(value["bytes_transferred"], 12);
        assert_eq!(value["chunk_count"], 2);
        assert_eq!(value["sync_all_calls"], 0);
        assert_eq!(value["global_sync_calls"], 0);
        assert_eq!(value["final_barriers"], 1);

        let _ = fs::remove_dir_all(root);
    }

    fn temp_dir(label: &str) -> PathBuf {
        let nonce = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = env::temp_dir().join(format!(
            "lsb-windows-mount-metrics-{label}-{}-{nonce}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        root
    }
}
