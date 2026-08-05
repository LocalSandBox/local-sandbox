mod context;
mod diagnostics;
#[cfg(all(windows, feature = "sentry-telemetry"))]
mod native;
mod run_marker;
mod update_trace;
#[cfg(windows)]
mod windows_events;

use std::collections::BTreeMap;
#[cfg(windows)]
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
#[cfg(windows)]
use std::sync::OnceLock;
use std::time::Duration;

pub use context::CommonContext;
#[cfg(any(test, all(windows, feature = "sentry-telemetry")))]
pub use context::COMPONENT;
#[cfg(all(windows, feature = "sentry-telemetry"))]
pub use context::SERVICE_NAME;
#[cfg(windows)]
pub(crate) use diagnostics::vm_diagnostics_dir;
#[cfg(windows)]
pub(crate) use diagnostics::write_sentry_receipt;
pub use diagnostics::{
    collect_incident, Attachment, DiagnosticLimits, IncidentMetadata, RetentionPolicy,
};
pub use run_marker::{PreviousRun, RunState};
#[cfg(windows)]
pub(crate) use windows_events::capture_hyperv_evidence;
#[cfg(windows)]
pub(crate) use windows_events::capture_termination_evidence;

pub const TRANSACTION_SERVICE_STARTUP: &str = "service.startup";
pub const TRANSACTION_SANDBOX_START: &str = "sandbox.start";
pub const TRANSACTION_SANDBOX_STOP: &str = "sandbox.stop";
pub const TRANSACTION_SERVICE_HEARTBEAT: &str = "service.heartbeat";
pub const TRANSACTION_SERVICE_UPDATE: &str = "service.update";

pub(crate) use update_trace::reconstruct_update;

#[cfg(windows)]
static EXIT_EVIDENCE_RUNTIME_ROOT: OnceLock<PathBuf> = OnceLock::new();

#[cfg(windows)]
pub fn install_exit_evidence(runtime_root: &Path) {
    if EXIT_EVIDENCE_RUNTIME_ROOT
        .set(runtime_root.to_path_buf())
        .is_err()
    {
        return;
    }
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic| {
        let location = panic
            .location()
            .map_or_else(|| "unknown".to_string(), ToString::to_string);
        let payload = panic
            .payload()
            .downcast_ref::<&str>()
            .map(|value| (*value).to_string())
            .or_else(|| panic.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "non-string panic payload".to_string());
        let thread = std::thread::current()
            .name()
            .unwrap_or("unnamed")
            .to_string();
        record_registered_exit(
            "panic",
            "RUST_PANIC",
            format!("panic on thread '{thread}' at {location}: {payload}"),
        );
        previous_hook(panic);
    }));
}

#[cfg(windows)]
pub fn record_returned_error(error: &anyhow::Error) {
    record_registered_exit(
        "returned_error",
        "SERVICE_MAIN_ERROR",
        format_error_chain(error),
    );
}

#[cfg(windows)]
pub fn abort_with_evidence(stable_reason: &'static str, summary: impl Into<String>) -> ! {
    record_registered_exit("explicit_abort", stable_reason, summary.into());
    std::process::abort()
}

#[cfg(windows)]
fn record_registered_exit(kind: &str, stable_reason: &str, summary: impl Into<String>) {
    let Some(runtime_root) = EXIT_EVIDENCE_RUNTIME_ROOT.get() else {
        return;
    };
    let _ = run_marker::record_current_exit(runtime_root, kind, stable_reason, summary);
}

#[derive(Debug, Clone, Copy)]
#[repr(usize)]
pub(crate) enum TelemetryFailure {
    Initialization,
    CrashpadUnavailable,
    NilEventUuid,
    Attachment,
    Flush,
    IncidentSnapshot,
    Archive,
    LiveProcessSnapshot,
    Qmp,
    Hyperv,
    Dump,
}

static TELEMETRY_FAILURES: [AtomicU64; 11] = [const { AtomicU64::new(0) }; 11];

pub(crate) fn record_failure(failure: TelemetryFailure) {
    TELEMETRY_FAILURES[failure as usize].fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn failure_counter_context() -> serde_json::Value {
    let values: [u64; 11] =
        std::array::from_fn(|index| TELEMETRY_FAILURES[index].load(Ordering::Relaxed));
    serde_json::json!({
        "initialization_failure": values[TelemetryFailure::Initialization as usize],
        "crashpad_unavailable": values[TelemetryFailure::CrashpadUnavailable as usize],
        "nil_event_uuid": values[TelemetryFailure::NilEventUuid as usize],
        "attachment_failure": values[TelemetryFailure::Attachment as usize],
        "flush_failure": values[TelemetryFailure::Flush as usize],
        "incident_snapshot_failure": values[TelemetryFailure::IncidentSnapshot as usize],
        "archive_failure": values[TelemetryFailure::Archive as usize],
        "live_process_snapshot_failure": values[TelemetryFailure::LiveProcessSnapshot as usize],
        "qmp_failure": values[TelemetryFailure::Qmp as usize],
        "hyperv_failure": values[TelemetryFailure::Hyperv as usize],
        "dump_failure": values[TelemetryFailure::Dump as usize],
    })
}

pub(crate) fn format_error_chain(error: &anyhow::Error) -> String {
    format!("{error:#}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    #[cfg(any(test, windows))]
    Warning,
    Error,
    #[cfg(all(windows, feature = "sentry-telemetry"))]
    Fatal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpanStatus {
    Ok,
    Cancelled,
    InvalidArgument,
    Unavailable,
    InternalError,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Breadcrumb {
    pub category: &'static str,
    pub message: &'static str,
    pub data: BTreeMap<String, String>,
}

impl Breadcrumb {
    pub fn lifecycle(category: &'static str, message: &'static str) -> Self {
        Self {
            category,
            message,
            data: BTreeMap::new(),
        }
    }

    pub fn with_data(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.data.insert(key.into(), bounded(value.into(), 256));
        self
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct FailureEvent {
    pub event_id: Option<String>,
    pub operation: &'static str,
    pub stable_error_code: &'static str,
    pub detailed_failure_kind: &'static str,
    pub level: Level,
    pub summary: String,
    pub retryable: bool,
    pub correlation_id: Option<String>,
    pub resource_id: Option<String>,
    pub phase: Option<&'static str>,
    pub tags: BTreeMap<String, String>,
    pub contexts: BTreeMap<String, serde_json::Value>,
    pub attachments: Vec<Attachment>,
}

impl FailureEvent {
    pub fn new(
        operation: &'static str,
        stable_error_code: &'static str,
        level: Level,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            event_id: None,
            operation,
            stable_error_code,
            detailed_failure_kind: "unknown",
            level,
            summary: bounded(summary.into(), 2_048),
            retryable: false,
            correlation_id: None,
            resource_id: None,
            phase: None,
            tags: BTreeMap::new(),
            contexts: BTreeMap::new(),
            attachments: Vec::new(),
        }
    }

    #[cfg(any(test, all(windows, feature = "sentry-telemetry")))]
    pub fn fingerprint(&self) -> [String; 4] {
        [
            COMPONENT.to_string(),
            self.operation.to_string(),
            self.stable_error_code.to_string(),
            self.detailed_failure_kind.to_string(),
        ]
    }

    pub fn with_detailed_failure_kind(mut self, kind: &'static str) -> Self {
        self.detailed_failure_kind = kind;
        self
    }

    pub fn with_event_id(mut self, event_id: impl Into<String>) -> Self {
        self.event_id = Some(event_id.into());
        self
    }

    pub fn with_correlation_id(mut self, correlation_id: impl Into<String>) -> Self {
        self.correlation_id = Some(bounded(correlation_id.into(), 128));
        self
    }

    pub fn with_resource_id(mut self, resource_id: impl Into<String>) -> Self {
        self.resource_id = Some(bounded(resource_id.into(), 128));
        self
    }

    pub fn with_phase(mut self, phase: &'static str) -> Self {
        self.phase = Some(phase);
        self
    }

    pub fn with_tag(mut self, key: &'static str, value: impl Into<String>) -> Self {
        self.tags
            .insert(key.to_string(), bounded(value.into(), 256));
        self
    }

    pub fn retryable(mut self, retryable: bool) -> Self {
        self.retryable = retryable;
        self
    }

    pub fn with_attachments(mut self, attachments: Vec<Attachment>) -> Self {
        self.attachments = attachments;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpanDescription {
    pub operation: &'static str,
    pub description: &'static str,
    pub data: BTreeMap<String, String>,
    pub sampled: Option<bool>,
    pub started_at_micros: Option<u64>,
}

impl SpanDescription {
    pub fn transaction(name: &'static str) -> Self {
        Self {
            operation: name,
            description: name,
            data: BTreeMap::new(),
            sampled: None,
            started_at_micros: None,
        }
    }

    pub fn child(operation: &'static str, description: &'static str) -> Self {
        Self {
            operation,
            description,
            data: BTreeMap::new(),
            sampled: None,
            started_at_micros: None,
        }
    }

    pub fn with_data(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.data.insert(key.into(), bounded(value.into(), 256));
        self
    }

    pub fn always_sampled(mut self) -> Self {
        self.sampled = Some(true);
        self
    }

    pub fn started_at(mut self, timestamp_micros: u64) -> Self {
        self.started_at_micros = Some(timestamp_micros);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceContext {
    pub trace_id: String,
    pub parent_span_id: Option<String>,
}

pub trait Adapter: Send + Sync {
    fn set_run_id(&self, _run_id: &str) -> Result<(), ()> {
        Ok(())
    }

    fn start_session(&self) -> Result<(), ()> {
        Ok(())
    }

    fn end_session(&self) -> Result<(), ()> {
        Ok(())
    }

    fn breadcrumb(&self, breadcrumb: Breadcrumb) -> Result<(), ()>;
    fn capture_failure(&self, event: FailureEvent) -> Result<Option<String>, ()>;
    fn capture_failure_for_span(
        &self,
        _span_id: u64,
        event: FailureEvent,
    ) -> Result<Option<String>, ()> {
        self.capture_failure(event)
    }
    fn start_span(
        &self,
        parent_id: Option<u64>,
        root_trace: Option<&TraceContext>,
        span: SpanDescription,
    ) -> Result<Option<u64>, ()>;
    fn finish_span(
        &self,
        span_id: u64,
        status: SpanStatus,
        timestamp_micros: Option<u64>,
    ) -> Result<Option<String>, ()>;
    fn set_span_data(&self, _span_id: u64, _key: &str, _value: &str) -> Result<(), ()> {
        Ok(())
    }
    fn flush(&self, timeout: Duration) -> Result<(), ()>;
}

#[derive(Clone)]
pub struct Telemetry {
    adapter: Arc<dyn Adapter>,
    run_state: Option<Arc<RunState>>,
}

impl Default for Telemetry {
    fn default() -> Self {
        Self::disabled()
    }
}

impl Telemetry {
    pub fn new(adapter: Arc<dyn Adapter>) -> Self {
        Self {
            adapter,
            run_state: None,
        }
    }

    pub fn disabled() -> Self {
        Self::new(Arc::new(NoopAdapter))
    }

    #[cfg(all(windows, feature = "sentry-telemetry"))]
    pub fn initialize_native(
        database_path: &std::path::Path,
        handler_path: &std::path::Path,
        crash_attachments: &[std::path::PathBuf],
        common_context: &CommonContext,
    ) -> anyhow::Result<Self> {
        native::NativeAdapter::initialize(
            database_path,
            handler_path,
            crash_attachments,
            common_context,
        )
        .map(|adapter| Self::new(Arc::new(adapter)))
    }

    pub fn with_run_state(mut self, run_state: Arc<RunState>) -> Self {
        if let Ok(run_id) = run_state.run_id() {
            let _ = self.adapter.set_run_id(&run_id);
        }
        self.run_state = Some(run_state);
        self
    }

    pub fn run_id(&self) -> Option<String> {
        self.run_state.as_ref()?.run_id().ok()
    }

    pub fn breadcrumb(&self, breadcrumb: Breadcrumb) {
        let _ = self.adapter.breadcrumb(breadcrumb);
    }

    pub fn capture_failure(&self, event: FailureEvent) -> Option<String> {
        self.adapter.capture_failure(event).ok().flatten()
    }

    pub fn start_span(&self, span: SpanDescription) -> SpanGuard {
        self.start_root_span(fresh_trace_context(), span)
    }

    pub fn continue_trace(&self, trace: TraceContext, span: SpanDescription) -> SpanGuard {
        if !valid_trace_context(&trace) {
            return SpanGuard {
                adapter: self.adapter.clone(),
                span_id: None,
                status: SpanStatus::InternalError,
            };
        }
        self.start_root_span(trace, span)
    }

    fn start_root_span(&self, trace: TraceContext, span: SpanDescription) -> SpanGuard {
        let span_id = valid_trace_context(&trace)
            .then(|| {
                self.adapter
                    .start_span(None, Some(&trace), span)
                    .ok()
                    .flatten()
            })
            .flatten();
        SpanGuard {
            adapter: self.adapter.clone(),
            span_id,
            status: SpanStatus::InternalError,
        }
    }

    pub fn start_session(&self) {
        let _ = self.adapter.start_session();
    }

    pub fn end_session(&self) {
        let _ = self.adapter.end_session();
    }

    pub fn flush(&self, timeout: Duration) {
        if self.adapter.flush(timeout).is_err() {
            record_failure(TelemetryFailure::Flush);
        }
    }

    pub fn new_event_id(&self) -> Option<String> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).ok()?;
        Some(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
    }

    pub fn update_crash_context(
        &self,
        phase: impl Into<String>,
        resource_id: Option<&str>,
        instance_path: Option<&std::path::Path>,
        boundary_completed: bool,
    ) {
        let Some(run_state) = &self.run_state else {
            return;
        };
        let _ = run_state.update(phase.into(), resource_id, instance_path, boundary_completed);
    }

    pub fn close_run(&self) -> bool {
        if let Some(run_state) = &self.run_state {
            return run_state.close().is_ok();
        }
        false
    }
}

pub struct SpanGuard {
    adapter: Arc<dyn Adapter>,
    span_id: Option<u64>,
    status: SpanStatus,
}

#[derive(Clone)]
pub(crate) struct SpanParent {
    adapter: Arc<dyn Adapter>,
    span_id: Option<u64>,
}

impl SpanParent {
    pub(crate) fn start_child(&self, span: SpanDescription) -> SpanGuard {
        let span_id = self.span_id.and_then(|parent_id| {
            self.adapter
                .start_span(Some(parent_id), None, span)
                .ok()
                .flatten()
        });
        SpanGuard {
            adapter: self.adapter.clone(),
            span_id,
            status: SpanStatus::InternalError,
        }
    }
}

impl SpanGuard {
    pub(crate) fn parent(&self) -> SpanParent {
        SpanParent {
            adapter: self.adapter.clone(),
            span_id: self.span_id,
        }
    }

    pub fn start_child(&self, span: SpanDescription) -> SpanGuard {
        let span_id = self
            .adapter
            .start_span(self.span_id, None, span)
            .ok()
            .flatten();
        SpanGuard {
            adapter: self.adapter.clone(),
            span_id,
            status: SpanStatus::InternalError,
        }
    }

    pub fn set_status(&mut self, status: SpanStatus) {
        self.status = status;
    }

    pub fn set_data(&self, key: &str, value: &str) {
        if let Some(span_id) = self.span_id {
            let _ = self.adapter.set_span_data(span_id, key, value);
        }
    }

    pub fn capture_failure(&self, event: FailureEvent) -> Option<String> {
        self.span_id
            .and_then(|span_id| self.adapter.capture_failure_for_span(span_id, event).ok())
            .flatten()
    }

    pub fn finish(mut self, status: SpanStatus) -> Option<String> {
        self.status = status;
        self.finish_once(None)
    }

    pub fn finish_at(mut self, status: SpanStatus, timestamp_micros: u64) -> Option<String> {
        self.status = status;
        self.finish_once(Some(timestamp_micros))
    }

    fn finish_once(&mut self, timestamp_micros: Option<u64>) -> Option<String> {
        if let Some(span_id) = self.span_id.take() {
            return self
                .adapter
                .finish_span(span_id, self.status, timestamp_micros)
                .ok()
                .flatten();
        }
        None
    }
}

impl Drop for SpanGuard {
    fn drop(&mut self) {
        let _ = self.finish_once(None);
    }
}

struct NoopAdapter;

impl Adapter for NoopAdapter {
    fn breadcrumb(&self, _breadcrumb: Breadcrumb) -> Result<(), ()> {
        Ok(())
    }

    fn capture_failure(&self, _event: FailureEvent) -> Result<Option<String>, ()> {
        Ok(None)
    }

    fn start_span(
        &self,
        _parent_id: Option<u64>,
        _root_trace: Option<&TraceContext>,
        _span: SpanDescription,
    ) -> Result<Option<u64>, ()> {
        Ok(None)
    }

    fn finish_span(
        &self,
        _span_id: u64,
        _status: SpanStatus,
        _timestamp_micros: Option<u64>,
    ) -> Result<Option<String>, ()> {
        Ok(None)
    }

    fn flush(&self, _timeout: Duration) -> Result<(), ()> {
        Ok(())
    }
}

fn fresh_trace_context() -> TraceContext {
    let mut bytes = [0u8; 16];
    if getrandom::fill(&mut bytes).is_err() {
        return TraceContext {
            trace_id: String::new(),
            parent_span_id: None,
        };
    }
    TraceContext {
        trace_id: bytes.iter().map(|byte| format!("{byte:02x}")).collect(),
        parent_span_id: None,
    }
}

fn valid_trace_context(trace: &TraceContext) -> bool {
    trace.trace_id.len() == 32
        && trace.trace_id.bytes().all(|byte| byte.is_ascii_hexdigit())
        && trace.parent_span_id.as_ref().is_none_or(|parent| {
            parent.len() == 16 && parent.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

fn bounded(mut value: String, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value;
    }
    let mut boundary = max_bytes;
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value.truncate(boundary);
    value
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct FakeState {
        run_ids: Vec<String>,
        sessions_started: usize,
        sessions_ended: usize,
        breadcrumbs: Vec<Breadcrumb>,
        events: Vec<FailureEvent>,
        spans: Vec<(u64, Option<u64>, String, SpanDescription)>,
        finished: Vec<(u64, SpanStatus, Option<u64>)>,
        span_data: Vec<(u64, String, String)>,
        flushes: Vec<Duration>,
        fail_calls: bool,
    }

    #[derive(Default)]
    struct FakeAdapter {
        state: Mutex<FakeState>,
    }

    impl Adapter for FakeAdapter {
        fn set_run_id(&self, run_id: &str) -> Result<(), ()> {
            self.state.lock().unwrap().run_ids.push(run_id.to_string());
            Ok(())
        }

        fn start_session(&self) -> Result<(), ()> {
            self.state.lock().unwrap().sessions_started += 1;
            Ok(())
        }

        fn end_session(&self) -> Result<(), ()> {
            self.state.lock().unwrap().sessions_ended += 1;
            Ok(())
        }

        fn breadcrumb(&self, breadcrumb: Breadcrumb) -> Result<(), ()> {
            let mut state = self.state.lock().unwrap();
            if state.fail_calls {
                return Err(());
            }
            state.breadcrumbs.push(breadcrumb);
            Ok(())
        }

        fn capture_failure(&self, event: FailureEvent) -> Result<Option<String>, ()> {
            let mut state = self.state.lock().unwrap();
            if state.fail_calls {
                return Err(());
            }
            let event_id = event
                .event_id
                .clone()
                .unwrap_or_else(|| "event-1".to_string());
            state.events.push(event);
            Ok(Some(event_id))
        }

        fn start_span(
            &self,
            parent_id: Option<u64>,
            root_trace: Option<&TraceContext>,
            span: SpanDescription,
        ) -> Result<Option<u64>, ()> {
            let mut state = self.state.lock().unwrap();
            if state.fail_calls {
                return Err(());
            }
            let id = state.spans.len() as u64 + 1;
            let trace_id = match parent_id {
                Some(parent_id) => state
                    .spans
                    .iter()
                    .find(|(id, ..)| *id == parent_id)
                    .map(|(_, _, trace_id, _)| trace_id.clone())
                    .ok_or(())?,
                None => root_trace.ok_or(())?.trace_id.clone(),
            };
            state.spans.push((id, parent_id, trace_id, span));
            Ok(Some(id))
        }

        fn finish_span(
            &self,
            span_id: u64,
            status: SpanStatus,
            timestamp_micros: Option<u64>,
        ) -> Result<Option<String>, ()> {
            let mut state = self.state.lock().unwrap();
            if state.fail_calls {
                return Err(());
            }
            state.finished.push((span_id, status, timestamp_micros));
            Ok(Some(format!("{span_id:032x}")))
        }

        fn set_span_data(&self, span_id: u64, key: &str, value: &str) -> Result<(), ()> {
            self.state.lock().unwrap().span_data.push((
                span_id,
                key.to_string(),
                value.to_string(),
            ));
            Ok(())
        }

        fn flush(&self, timeout: Duration) -> Result<(), ()> {
            let mut state = self.state.lock().unwrap();
            if state.fail_calls {
                return Err(());
            }
            state.flushes.push(timeout);
            Ok(())
        }
    }

    #[test]
    fn fake_records_facade_calls_and_span_finishes_once() {
        let adapter = Arc::new(FakeAdapter::default());
        let telemetry = Telemetry::new(adapter.clone());
        telemetry
            .breadcrumb(Breadcrumb::lifecycle("service", "running").with_data("run_id", "run-1"));
        let event_id = telemetry.capture_failure(
            FailureEvent::new(
                "sandbox.start",
                "SANDBOX_BOOT_FAILED",
                Level::Error,
                "guest did not become ready",
            )
            .with_correlation_id("correlation-1")
            .with_resource_id("sandbox-1"),
        );
        assert_eq!(event_id.as_deref(), Some("event-1"));

        telemetry
            .start_span(SpanDescription::transaction(TRANSACTION_SANDBOX_START))
            .finish(SpanStatus::Ok);
        telemetry.flush(Duration::from_millis(50));

        let state = adapter.state.lock().unwrap();
        assert_eq!(state.breadcrumbs.len(), 1);
        assert_eq!(state.events.len(), 1);
        assert_eq!(state.spans.len(), 1);
        assert_eq!(state.finished, vec![(1, SpanStatus::Ok, None)]);
        assert_eq!(state.flushes, vec![Duration::from_millis(50)]);
    }

    #[test]
    fn attaching_run_state_indexes_the_run_id() {
        let root = std::env::temp_dir().join(format!(
            "lsbs-telemetry-run-id-{}",
            crate::session::ResourceHandle::random().unwrap()
        ));
        let (run_state, _) = RunState::begin(&root, "2026-07-27T12:00:00Z").unwrap();
        let run_id = run_state.run_id().unwrap();
        let adapter = Arc::new(FakeAdapter::default());
        let _telemetry = Telemetry::new(adapter.clone()).with_run_state(Arc::new(run_state));
        assert_eq!(adapter.state.lock().unwrap().run_ids, vec![run_id]);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn child_span_records_its_parent() {
        let adapter = Arc::new(FakeAdapter::default());
        let telemetry = Telemetry::new(adapter.clone());
        let transaction =
            telemetry.start_span(SpanDescription::transaction(TRANSACTION_SERVICE_STARTUP));
        transaction
            .start_child(SpanDescription::child(
                "bundle.verify",
                "bundle verification",
            ))
            .finish(SpanStatus::Ok);
        transaction.finish(SpanStatus::Ok);

        let state = adapter.state.lock().unwrap();
        assert_eq!(state.spans[0].1, None);
        assert_eq!(state.spans[1].1, Some(1));
    }

    #[test]
    fn cloned_span_parent_preserves_cross_thread_parentage() {
        let adapter = Arc::new(FakeAdapter::default());
        let telemetry = Telemetry::new(adapter.clone());
        let transaction =
            telemetry.start_span(SpanDescription::transaction(TRANSACTION_SANDBOX_START));
        let parent = transaction.parent();
        std::thread::spawn(move || {
            parent
                .start_child(SpanDescription::child("qemu.preflight", "qemu.preflight"))
                .finish(SpanStatus::Ok);
        })
        .join()
        .unwrap();
        transaction.finish(SpanStatus::Ok);

        let state = adapter.state.lock().unwrap();
        assert_eq!(state.spans[1].1, Some(1));
        assert_eq!(state.spans[1].3.operation, "qemu.preflight");
        assert_eq!(
            state.finished,
            [(2, SpanStatus::Ok, None), (1, SpanStatus::Ok, None)]
        );
    }

    #[test]
    fn span_guard_finishes_on_early_return_and_unwind() {
        let adapter = Arc::new(FakeAdapter::default());
        let telemetry = Telemetry::new(adapter.clone());

        fn early_return(telemetry: &Telemetry) -> Result<(), &'static str> {
            let _span = telemetry.start_span(SpanDescription::child("preflight", "preflight"));
            Err("original error")
        }
        assert_eq!(early_return(&telemetry), Err("original error"));

        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe({
            let telemetry = telemetry.clone();
            move || {
                let _span =
                    telemetry.start_span(SpanDescription::child("qemu.spawn", "QEMU spawn"));
                panic!("fixture");
            }
        }));

        let state = adapter.state.lock().unwrap();
        assert_eq!(
            state.finished,
            vec![
                (1, SpanStatus::InternalError, None),
                (2, SpanStatus::InternalError, None)
            ]
        );
    }

    #[test]
    fn adapter_failures_are_fail_open() {
        let adapter = Arc::new(FakeAdapter::default());
        adapter.state.lock().unwrap().fail_calls = true;
        let telemetry = Telemetry::new(adapter);

        telemetry.breadcrumb(Breadcrumb::lifecycle("service", "start"));
        assert_eq!(
            telemetry.capture_failure(FailureEvent::new(
                "service.startup",
                "STARTUP_FAILED",
                Level::Error,
                "failure",
            )),
            None
        );
        telemetry
            .start_span(SpanDescription::transaction(TRANSACTION_SERVICE_STARTUP))
            .finish(SpanStatus::Unavailable);
        telemetry.flush(Duration::ZERO);
    }

    #[test]
    fn stable_fingerprint_excludes_high_cardinality_fields() {
        let first = FailureEvent::new(
            "sandbox.start",
            "SANDBOX_BOOT_FAILED",
            Level::Error,
            "first free-form error",
        )
        .with_correlation_id("correlation-1")
        .with_tag("run_id", "run-1")
        .with_resource_id("sandbox-1");
        let second = FailureEvent::new(
            "sandbox.start",
            "SANDBOX_BOOT_FAILED",
            Level::Error,
            "different free-form error",
        )
        .with_correlation_id("correlation-2")
        .with_resource_id("sandbox-2");

        assert_eq!(first.fingerprint(), second.fingerprint());
        let fingerprint = first.fingerprint();
        assert!(!fingerprint.iter().any(|part| part.contains("correlation-")));
        assert!(!fingerprint.iter().any(|part| part.contains("sandbox-1")));
        assert!(!fingerprint.iter().any(|part| part.contains("free-form")));
    }

    #[test]
    fn detailed_failure_kind_is_the_fourth_stable_fingerprint_part() {
        let event = FailureEvent::new(
            "sandbox.start",
            "SANDBOX_BOOT_FAILED",
            Level::Error,
            "timeout",
        )
        .with_detailed_failure_kind("guest_ready_timeout");

        assert_eq!(
            event.fingerprint(),
            [
                "local-sandbox-service".to_string(),
                "sandbox.start".to_string(),
                "SANDBOX_BOOT_FAILED".to_string(),
                "guest_ready_timeout".to_string(),
            ]
        );
    }

    #[test]
    fn incident_error_message_preserves_the_complete_error_chain() {
        let error = anyhow::anyhow!("guest-ready handshake timed out")
            .context("start Windows QEMU")
            .context("Failed to start VM");

        let message = format_error_chain(&error);

        assert!(message.contains("Failed to start VM"));
        assert!(message.contains("start Windows QEMU"));
        assert!(message.contains("guest-ready handshake timed out"));
    }

    #[test]
    fn disabled_adapter_accepts_every_operation() {
        let telemetry = Telemetry::disabled();
        telemetry.breadcrumb(Breadcrumb::lifecycle("service", "start"));
        assert_eq!(
            telemetry.capture_failure(FailureEvent::new(
                "service.startup",
                "STARTUP_FAILED",
                Level::Warning,
                "disabled",
            )),
            None
        );
        telemetry
            .start_span(SpanDescription::transaction(TRANSACTION_SERVICE_STARTUP))
            .finish(SpanStatus::Ok);
    }

    #[test]
    fn independent_roots_have_distinct_traces_and_children_inherit() {
        let adapter = Arc::new(FakeAdapter::default());
        let telemetry = Telemetry::new(adapter.clone());
        let first = telemetry.start_span(SpanDescription::transaction("first"));
        let child = first.start_child(SpanDescription::child("child", "child"));
        let second = telemetry.start_span(SpanDescription::transaction("second"));
        child.finish(SpanStatus::Ok);
        first.finish(SpanStatus::Ok);
        second.finish(SpanStatus::Ok);

        let state = adapter.state.lock().unwrap();
        assert_eq!(state.spans[0].2, state.spans[1].2);
        assert_ne!(state.spans[0].2, state.spans[2].2);
    }

    #[test]
    fn explicit_sessions_are_fail_open() {
        let adapter = Arc::new(FakeAdapter::default());
        let telemetry = Telemetry::new(adapter.clone());
        telemetry.start_session();
        telemetry.end_session();
        let state = adapter.state.lock().unwrap();
        assert_eq!(state.sessions_started, 1);
        assert_eq!(state.sessions_ended, 1);
    }

    #[test]
    fn span_data_can_be_attached_at_phase_completion() {
        let adapter = Arc::new(FakeAdapter::default());
        let telemetry = Telemetry::new(adapter.clone());
        let span = telemetry.start_span(SpanDescription::transaction("cleanup"));
        span.set_data("cleanup.result", "partial");
        span.finish(SpanStatus::InternalError);
        assert_eq!(
            adapter.state.lock().unwrap().span_data,
            [(1, "cleanup.result".to_string(), "partial".to_string())]
        );
    }

    #[test]
    fn successful_failed_interrupted_and_rolled_back_journals_replay_once() {
        use lsb_seawork_update::{
            HelperProtocol, TransactionEnvelope, TransactionPhase, UpdateActor, UpdateFailureCode,
            UpdateFailureStep, UpdateTransaction, UpdateTransition, UpdateTransitionOutcome,
        };
        use lsb_service_proto::{BundleIdentity, LedgerCompatibility, ProtocolRange};

        let identity = |version: &str, byte: char| BundleIdentity {
            version: version.to_string(),
            bundle_manifest_sha256: byte.to_string().repeat(64),
            archive_sha256: byte.to_string().repeat(64),
            protocol: ProtocolRange {
                major: 1,
                min_minor: 0,
                max_minor: 6,
            },
            ledger: LedgerCompatibility {
                reader_min_schema: 1,
                reader_max_schema: 1,
                writer_schema: 1,
            },
            service_configuration_revision: 2,
        };
        for (phase, outcome) in [
            (
                TransactionPhase::TargetCommitted,
                Some(UpdateTransitionOutcome::Succeeded),
            ),
            (
                TransactionPhase::Quarantined,
                Some(UpdateTransitionOutcome::Failed),
            ),
            (TransactionPhase::TargetCommitted, None),
            (
                TransactionPhase::RollbackComplete,
                Some(UpdateTransitionOutcome::Succeeded),
            ),
        ] {
            let failed = matches!(
                phase,
                TransactionPhase::Quarantined | TransactionPhase::RollbackComplete
            );
            let mut journal = TransactionEnvelope::new(UpdateTransaction {
                transaction_id: "1".repeat(32),
                update_id: "2".repeat(32),
                phase,
                created_utc: "2026-07-22T12:00:00Z".to_string(),
                old_bundle_identity: identity("0.5.0", 'a'),
                target_bundle_identity: identity("0.5.1", 'b'),
                old_image_path: r"C:\Program Files\SeaWork\old.exe".to_string(),
                target_image_path: r"C:\Program Files\SeaWork\new.exe".to_string(),
                old_event_message_path: r"C:\Program Files\SeaWork\old.exe".to_string(),
                target_event_message_path: r"C:\Program Files\SeaWork\new.exe".to_string(),
                staged_root: r"C:\ProgramData\SeaWork\staging\one".to_string(),
                final_version_root: r"C:\Program Files\SeaWork\versions\0.5.1".to_string(),
                helper_protocol: HelperProtocol { major: 1, minor: 1 },
                attempt_count: 1,
                last_error_category: None,
                last_failure_step: failed.then_some(UpdateFailureStep::TargetHealthAssertion),
                last_failure_code: failed.then_some(UpdateFailureCode::OperationFailed),
                timeline: vec![UpdateTransition {
                    phase: "update.target_health".to_string(),
                    actor: UpdateActor::Updater,
                    started_utc: "2026-07-22T12:01:00Z".to_string(),
                    completed_utc: outcome.map(|_| "2026-07-22T12:02:00Z".to_string()),
                    duration_ms: outcome.map(|_| 60_000),
                    outcome,
                    failure_code: (outcome == Some(UpdateTransitionOutcome::Failed))
                        .then(|| "UPDATE_OPERATION_FAILED".to_string()),
                    retryable: None,
                    retry_attempt: None,
                    started_event_id: None,
                    completed_event_id: None,
                }],
                reported_event_id: None,
            })
            .unwrap();
            let adapter = Arc::new(FakeAdapter::default());
            let telemetry = Telemetry::new(adapter.clone());
            let receipt = reconstruct_update(&telemetry, &journal).unwrap();
            assert_eq!(receipt.len(), 32);
            let state = adapter.state.lock().unwrap();
            assert_eq!(state.spans.len(), 2);
            assert!(state
                .spans
                .iter()
                .all(|(_, _, trace, _)| trace == &state.spans[0].2));
            let expected_start = update_trace::timestamp_micros("2026-07-22T12:01:00Z");
            let expected_end = update_trace::timestamp_micros(if outcome.is_some() {
                "2026-07-22T12:02:00Z"
            } else {
                "2026-07-22T12:01:00Z"
            });
            assert_eq!(state.spans[0].3.started_at_micros, expected_start);
            assert_eq!(state.finished.last().unwrap().2, expected_end);
            drop(state);
            journal.mark_reported(receipt).unwrap();
            assert_eq!(reconstruct_update(&telemetry, &journal), None);
        }
    }
}
