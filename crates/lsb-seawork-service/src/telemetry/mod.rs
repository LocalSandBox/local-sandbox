mod context;
mod diagnostics;
#[cfg(all(windows, feature = "sentry-telemetry"))]
mod native;
mod run_marker;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

#[cfg(all(windows, feature = "sentry-telemetry"))]
pub use context::SERVICE_NAME;
pub use context::{CommonContext, COMPONENT};
#[cfg(windows)]
pub(crate) use diagnostics::vm_diagnostics_dir;
pub use diagnostics::{
    collect_incident, Attachment, DiagnosticLimits, IncidentMetadata, RetentionPolicy,
};
pub use run_marker::{PreviousRun, RunState};

pub const TRANSACTION_SERVICE_STARTUP: &str = "service.startup";
pub const TRANSACTION_SANDBOX_START: &str = "sandbox.start";
pub const TRANSACTION_SANDBOX_STOP: &str = "sandbox.stop";

pub(crate) fn format_error_chain(error: &anyhow::Error) -> String {
    format!("{error:#}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Warning,
    Error,
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

    pub fn fingerprint(&self) -> [String; 3] {
        [
            COMPONENT.to_string(),
            self.operation.to_string(),
            self.stable_error_code.to_string(),
        ]
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
}

impl SpanDescription {
    pub fn transaction(name: &'static str) -> Self {
        Self {
            operation: name,
            description: name,
            data: BTreeMap::new(),
        }
    }

    pub fn child(operation: &'static str, description: &'static str) -> Self {
        Self {
            operation,
            description,
            data: BTreeMap::new(),
        }
    }

    pub fn with_data(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.data.insert(key.into(), bounded(value.into(), 256));
        self
    }
}

pub trait Adapter: Send + Sync {
    fn breadcrumb(&self, breadcrumb: Breadcrumb) -> Result<(), ()>;
    fn capture_failure(&self, event: FailureEvent) -> Result<Option<String>, ()>;
    fn start_span(&self, parent_id: Option<u64>, span: SpanDescription) -> Result<Option<u64>, ()>;
    fn finish_span(&self, span_id: u64, status: SpanStatus) -> Result<(), ()>;
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
        self.run_state = Some(run_state);
        self
    }

    pub fn breadcrumb(&self, breadcrumb: Breadcrumb) {
        let _ = self.adapter.breadcrumb(breadcrumb);
    }

    pub fn capture_failure(&self, event: FailureEvent) -> Option<String> {
        self.adapter.capture_failure(event).ok().flatten()
    }

    pub fn start_span(&self, span: SpanDescription) -> SpanGuard {
        let span_id = self.adapter.start_span(None, span).ok().flatten();
        SpanGuard {
            adapter: self.adapter.clone(),
            span_id,
            status: SpanStatus::InternalError,
        }
    }

    pub fn flush(&self, timeout: Duration) {
        let _ = self.adapter.flush(timeout);
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

    pub fn close_run(&self) {
        if let Some(run_state) = &self.run_state {
            let _ = run_state.close();
        }
    }
}

pub struct SpanGuard {
    adapter: Arc<dyn Adapter>,
    span_id: Option<u64>,
    status: SpanStatus,
}

impl SpanGuard {
    pub fn start_child(&self, span: SpanDescription) -> SpanGuard {
        let span_id = self.adapter.start_span(self.span_id, span).ok().flatten();
        SpanGuard {
            adapter: self.adapter.clone(),
            span_id,
            status: SpanStatus::InternalError,
        }
    }

    pub fn set_status(&mut self, status: SpanStatus) {
        self.status = status;
    }

    pub fn finish(mut self, status: SpanStatus) {
        self.status = status;
        self.finish_once();
    }

    fn finish_once(&mut self) {
        if let Some(span_id) = self.span_id.take() {
            let _ = self.adapter.finish_span(span_id, self.status);
        }
    }
}

impl Drop for SpanGuard {
    fn drop(&mut self) {
        self.finish_once();
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
        _span: SpanDescription,
    ) -> Result<Option<u64>, ()> {
        Ok(None)
    }

    fn finish_span(&self, _span_id: u64, _status: SpanStatus) -> Result<(), ()> {
        Ok(())
    }

    fn flush(&self, _timeout: Duration) -> Result<(), ()> {
        Ok(())
    }
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
        breadcrumbs: Vec<Breadcrumb>,
        events: Vec<FailureEvent>,
        spans: Vec<(u64, Option<u64>, SpanDescription)>,
        finished: Vec<(u64, SpanStatus)>,
        flushes: Vec<Duration>,
        fail_calls: bool,
    }

    #[derive(Default)]
    struct FakeAdapter {
        state: Mutex<FakeState>,
    }

    impl Adapter for FakeAdapter {
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
            span: SpanDescription,
        ) -> Result<Option<u64>, ()> {
            let mut state = self.state.lock().unwrap();
            if state.fail_calls {
                return Err(());
            }
            let id = state.spans.len() as u64 + 1;
            state.spans.push((id, parent_id, span));
            Ok(Some(id))
        }

        fn finish_span(&self, span_id: u64, status: SpanStatus) -> Result<(), ()> {
            let mut state = self.state.lock().unwrap();
            if state.fail_calls {
                return Err(());
            }
            state.finished.push((span_id, status));
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
        assert_eq!(state.finished, vec![(1, SpanStatus::Ok)]);
        assert_eq!(state.flushes, vec![Duration::from_millis(50)]);
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
                (1, SpanStatus::InternalError),
                (2, SpanStatus::InternalError)
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
}
