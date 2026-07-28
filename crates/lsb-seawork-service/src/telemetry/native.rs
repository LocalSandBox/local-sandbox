use std::collections::HashMap;
use std::ffi::{c_char, c_int, c_void, CString};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{bail, Context, Result};

use super::{
    Adapter, Breadcrumb, CommonContext, FailureEvent, Level, SpanDescription, SpanStatus,
    COMPONENT, SERVICE_NAME,
};

#[repr(C)]
#[derive(Clone, Copy)]
struct SentryValue {
    bits: u64,
}

#[repr(C)]
struct SentryUuid {
    bytes: [c_char; 16],
}

enum NativeSpan {
    Transaction(usize),
    Span(usize),
}

struct State {
    next_span_id: u64,
    spans: HashMap<u64, NativeSpan>,
}

pub struct NativeAdapter {
    state: Mutex<State>,
}

impl NativeAdapter {
    pub fn initialize(
        database_path: &Path,
        handler_path: &Path,
        crash_attachments: &[std::path::PathBuf],
        common_context: &CommonContext,
    ) -> Result<Self> {
        if !database_path.is_absolute() || !handler_path.is_absolute() || !handler_path.is_file() {
            bail!("Sentry database and Crashpad handler paths must be absolute");
        }
        let options = unsafe { sentry_options_new() };
        if options.is_null() {
            bail!("Sentry Native did not allocate options");
        }
        let dsn =
            CString::new(env!("LSB_SENTRY_DSN")).context("compiled Sentry DSN contains NUL")?;
        let release = CString::new(format!(
            "local-sandbox-service@{}",
            env!("CARGO_PKG_VERSION")
        ))
        .expect("release has no NUL");
        let environment = CString::new(env!("LSB_SENTRY_ENVIRONMENT"))
            .context("compiled Sentry environment contains NUL")?;
        let dist = CString::new("windows-x86_64").expect("static dist has no NUL");
        let database = wide(database_path);
        let handler = wide(handler_path);
        let sample_rate = env!("LSB_SENTRY_TRACES_SAMPLE_RATE")
            .parse::<f64>()
            .context("compiled Sentry trace sample rate is invalid")?;
        unsafe {
            sentry_options_set_dsn(options, dsn.as_ptr());
            sentry_options_set_release(options, release.as_ptr());
            sentry_options_set_environment(options, environment.as_ptr());
            sentry_options_set_dist(options, dist.as_ptr());
            sentry_options_set_database_pathw(options, database.as_ptr());
            sentry_options_set_handler_pathw(options, handler.as_ptr());
            for attachment in crash_attachments {
                let attachment = wide(attachment);
                sentry_options_add_attachmentw(options, attachment.as_ptr());
            }
            sentry_options_set_traces_sample_rate(options, sample_rate);
            sentry_options_set_shutdown_timeout(options, 2_000);
            if sentry_init(options) != 0 {
                bail!("Sentry Native initialization failed");
            }
        }
        let adapter = Self {
            state: Mutex::new(State {
                next_span_id: 1,
                spans: HashMap::new(),
            }),
        };
        adapter.set_common_context(common_context);
        Ok(adapter)
    }

    fn set_common_context(&self, common_context: &CommonContext) {
        unsafe {
            set_global_tag("component", COMPONENT);
            set_global_tag("service.name", SERVICE_NAME);
            set_global_tag("service.version", env!("CARGO_PKG_VERSION"));
            for (name, value) in common_context.as_contexts() {
                if let Ok(name) = CString::new(name) {
                    sentry_set_context(name.as_ptr(), json_value(&value));
                }
            }
        }
    }
}

impl Adapter for NativeAdapter {
    fn set_run_id(&self, run_id: &str) -> Result<(), ()> {
        if run_id.len() != 32 || !run_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(());
        }
        unsafe {
            set_global_tag("run_id", run_id);
            let context = sentry_value_new_object();
            set_string(&context, "run_id", run_id)?;
            let name = CString::new("service_run").expect("static string");
            sentry_set_context(name.as_ptr(), context);
        }
        Ok(())
    }

    fn breadcrumb(&self, breadcrumb: Breadcrumb) -> Result<(), ()> {
        let message = CString::new(breadcrumb.message).map_err(|_| ())?;
        let category = CString::new(breadcrumb.category).map_err(|_| ())?;
        unsafe {
            let value = sentry_value_new_breadcrumb(ptr::null(), message.as_ptr());
            set_value(&value, "category", string_value(&category))?;
            if !breadcrumb.data.is_empty() {
                let data = sentry_value_new_object();
                for (key, value) in breadcrumb.data {
                    set_string(&data, &key, &value)?;
                }
                set_value(&value, "data", data)?;
            }
            sentry_add_breadcrumb(value);
        }
        Ok(())
    }

    fn capture_failure(&self, event: FailureEvent) -> Result<Option<String>, ()> {
        let _guard = self.state.lock().map_err(|_| ())?;
        let summary = CString::new(event.summary.as_str()).map_err(|_| ())?;
        let logger = CString::new("local-sandbox-service").expect("static string");
        let value = unsafe {
            sentry_value_new_message_event(level(event.level), logger.as_ptr(), summary.as_ptr())
        };
        unsafe {
            if let Some(event_id) = &event.event_id {
                set_string(&value, "event_id", event_id)?;
            }
            let fingerprint = sentry_value_new_list();
            for part in event.fingerprint() {
                sentry_value_append(fingerprint, rust_string_value(&part)?);
            }
            set_value(&value, "fingerprint", fingerprint)?;

            let tags = sentry_value_new_object();
            set_string(&tags, "component", COMPONENT)?;
            set_string(&tags, "operation", event.operation)?;
            set_string(&tags, "error.code", event.stable_error_code)?;
            for (key, value) in &event.tags {
                set_string(&tags, key, value)?;
            }
            set_value(&value, "tags", tags)?;

            let contexts = sentry_value_new_object();
            for (key, context) in &event.contexts {
                set_value(&contexts, key, json_value(context))?;
            }
            let operation = sentry_value_new_object();
            set_string(&operation, "stable_error_code", event.stable_error_code)?;
            set_string(
                &operation,
                "detailed_failure_kind",
                event.detailed_failure_kind,
            )?;
            set_value(
                &operation,
                "retryable",
                sentry_value_new_bool(c_int::from(event.retryable)),
            )?;
            if let Some(correlation_id) = &event.correlation_id {
                set_string(&operation, "correlation_id", correlation_id)?;
            }
            if let Some(resource_id) = &event.resource_id {
                set_string(&operation, "resource_id", resource_id)?;
            }
            if let Some(phase) = event.phase {
                set_string(&operation, "phase", phase)?;
            }
            set_value(&contexts, "operation", operation)?;
            set_value(&value, "contexts", contexts)?;

            let mut native_attachments = Vec::new();
            for attachment in &event.attachments {
                let path = wide(&attachment.path);
                let native = sentry_attach_filew(path.as_ptr());
                if native.is_null() {
                    continue;
                }
                let filename = wide(Path::new(&attachment.filename));
                sentry_attachment_set_filenamew(native, filename.as_ptr());
                if let Ok(content_type) = CString::new(attachment.content_type) {
                    sentry_attachment_set_content_type(native, content_type.as_ptr());
                }
                native_attachments.push(native);
            }
            let uuid = sentry_capture_event(value);
            for attachment in native_attachments {
                sentry_remove_attachment(attachment);
            }
            Ok(uuid_string(&uuid))
        }
    }

    fn start_span(&self, parent_id: Option<u64>, span: SpanDescription) -> Result<Option<u64>, ()> {
        let mut state = self.state.lock().map_err(|_| ())?;
        let operation = CString::new(span.operation).map_err(|_| ())?;
        let description = CString::new(span.description).map_err(|_| ())?;
        let native = unsafe {
            match parent_id.and_then(|id| state.spans.get(&id)) {
                Some(NativeSpan::Transaction(parent)) => sentry_transaction_start_child(
                    *parent as *mut c_void,
                    operation.as_ptr(),
                    description.as_ptr(),
                ),
                Some(NativeSpan::Span(parent)) => sentry_span_start_child(
                    *parent as *mut c_void,
                    operation.as_ptr(),
                    description.as_ptr(),
                ),
                None if parent_id.is_some() => return Err(()),
                None => {
                    let context =
                        sentry_transaction_context_new(description.as_ptr(), operation.as_ptr());
                    let transaction = sentry_transaction_start(context, sentry_value_new_null());
                    transaction
                }
            }
        };
        if native.is_null() {
            return Ok(None);
        }
        unsafe {
            for (key, value) in &span.data {
                let key = CString::new(key.as_str()).map_err(|_| ())?;
                let value = rust_string_value(value)?;
                if parent_id.is_some() {
                    sentry_span_set_data(native, key.as_ptr(), value);
                } else {
                    sentry_transaction_set_data(native, key.as_ptr(), value);
                }
            }
        }
        let id = state.next_span_id;
        state.next_span_id = state.next_span_id.checked_add(1).ok_or(())?;
        let native = if parent_id.is_some() {
            NativeSpan::Span(native as usize)
        } else {
            NativeSpan::Transaction(native as usize)
        };
        state.spans.insert(id, native);
        Ok(Some(id))
    }

    fn finish_span(&self, span_id: u64, status: SpanStatus) -> Result<(), ()> {
        let mut state = self.state.lock().map_err(|_| ())?;
        let native = state.spans.remove(&span_id).ok_or(())?;
        unsafe {
            match native {
                NativeSpan::Transaction(transaction) => {
                    sentry_transaction_set_status(transaction as *mut c_void, span_status(status));
                    sentry_transaction_finish(transaction as *mut c_void);
                }
                NativeSpan::Span(span) => {
                    sentry_span_set_status(span as *mut c_void, span_status(status));
                    sentry_span_finish(span as *mut c_void);
                }
            }
        }
        Ok(())
    }

    fn flush(&self, timeout: Duration) -> Result<(), ()> {
        let timeout = timeout.as_millis().min(u128::from(u64::MAX)) as u64;
        if unsafe { sentry_flush(timeout) } == 0 {
            Ok(())
        } else {
            Err(())
        }
    }
}

impl Drop for NativeAdapter {
    fn drop(&mut self) {
        let _ = unsafe { sentry_close() };
    }
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

fn level(level: Level) -> c_int {
    match level {
        Level::Warning => 1,
        Level::Error => 2,
        Level::Fatal => 3,
    }
}

fn span_status(status: SpanStatus) -> c_int {
    match status {
        SpanStatus::Ok => 0,
        SpanStatus::Cancelled => 1,
        SpanStatus::InvalidArgument => 3,
        SpanStatus::InternalError => 13,
        SpanStatus::Unavailable => 14,
    }
}

unsafe fn set_global_tag(key: &str, value: &str) {
    if let (Ok(key), Ok(value)) = (CString::new(key), CString::new(value)) {
        unsafe { sentry_set_tag(key.as_ptr(), value.as_ptr()) };
    }
}

unsafe fn set_string(object: &SentryValue, key: &str, value: &str) -> Result<(), ()> {
    let value = rust_string_value(value)?;
    unsafe { set_value(object, key, value) }
}

unsafe fn set_value(object: &SentryValue, key: &str, value: SentryValue) -> Result<(), ()> {
    let key = CString::new(key).map_err(|_| ())?;
    if unsafe { sentry_value_set_by_key(*object, key.as_ptr(), value) } == 0 {
        Ok(())
    } else {
        unsafe { sentry_value_decref(value) };
        Err(())
    }
}

unsafe fn string_value(value: &CString) -> SentryValue {
    unsafe { sentry_value_new_string(value.as_ptr()) }
}

unsafe fn rust_string_value(value: &str) -> Result<SentryValue, ()> {
    let value = CString::new(value).map_err(|_| ())?;
    Ok(unsafe { string_value(&value) })
}

unsafe fn json_value(value: &serde_json::Value) -> SentryValue {
    match value {
        serde_json::Value::Null => unsafe { sentry_value_new_null() },
        serde_json::Value::Bool(value) => unsafe { sentry_value_new_bool(c_int::from(*value)) },
        serde_json::Value::Number(value) => unsafe {
            sentry_value_new_double(value.as_f64().unwrap_or_default())
        },
        serde_json::Value::String(value) => unsafe {
            rust_string_value(value).unwrap_or_else(|_| sentry_value_new_null())
        },
        serde_json::Value::Array(values) => unsafe {
            let list = sentry_value_new_list();
            for value in values {
                sentry_value_append(list, json_value(value));
            }
            list
        },
        serde_json::Value::Object(values) => unsafe {
            let object = sentry_value_new_object();
            for (key, value) in values {
                let _ = set_value(&object, key, json_value(value));
            }
            object
        },
    }
}

unsafe fn uuid_string(uuid: &SentryUuid) -> Option<String> {
    if uuid.bytes.iter().all(|byte| *byte == 0) {
        return None;
    }
    let mut output = [0 as c_char; 37];
    unsafe { sentry_uuid_as_string(uuid, output.as_mut_ptr()) };
    let bytes = output[..36]
        .iter()
        .map(|byte| *byte as u8)
        .collect::<Vec<_>>();
    String::from_utf8(bytes)
        .ok()
        .map(|value| value.replace('-', ""))
}

unsafe extern "C" {
    fn sentry_options_new() -> *mut c_void;
    fn sentry_options_set_dsn(options: *mut c_void, dsn: *const c_char);
    fn sentry_options_set_release(options: *mut c_void, release: *const c_char);
    fn sentry_options_set_environment(options: *mut c_void, environment: *const c_char);
    fn sentry_options_set_dist(options: *mut c_void, dist: *const c_char);
    fn sentry_options_set_database_pathw(options: *mut c_void, path: *const u16);
    fn sentry_options_set_handler_pathw(options: *mut c_void, path: *const u16);
    fn sentry_options_add_attachmentw(options: *mut c_void, path: *const u16);
    fn sentry_options_set_traces_sample_rate(options: *mut c_void, sample_rate: f64);
    fn sentry_options_set_shutdown_timeout(options: *mut c_void, timeout: u64);
    fn sentry_init(options: *mut c_void) -> c_int;
    fn sentry_flush(timeout: u64) -> c_int;
    fn sentry_close() -> c_int;
    fn sentry_set_tag(key: *const c_char, value: *const c_char);
    fn sentry_set_context(key: *const c_char, value: SentryValue);
    fn sentry_value_new_null() -> SentryValue;
    fn sentry_value_new_double(value: f64) -> SentryValue;
    fn sentry_value_new_bool(value: c_int) -> SentryValue;
    fn sentry_value_new_string(value: *const c_char) -> SentryValue;
    fn sentry_value_new_list() -> SentryValue;
    fn sentry_value_new_object() -> SentryValue;
    fn sentry_value_new_message_event(
        level: c_int,
        logger: *const c_char,
        text: *const c_char,
    ) -> SentryValue;
    fn sentry_value_new_breadcrumb(kind: *const c_char, message: *const c_char) -> SentryValue;
    fn sentry_value_set_by_key(value: SentryValue, key: *const c_char, child: SentryValue)
        -> c_int;
    fn sentry_value_append(value: SentryValue, child: SentryValue) -> c_int;
    fn sentry_value_decref(value: SentryValue);
    fn sentry_add_breadcrumb(value: SentryValue);
    fn sentry_capture_event(value: SentryValue) -> SentryUuid;
    fn sentry_uuid_as_string(uuid: *const SentryUuid, output: *mut c_char);
    fn sentry_attach_filew(path: *const u16) -> *mut c_void;
    fn sentry_attachment_set_filenamew(attachment: *mut c_void, filename: *const u16);
    fn sentry_attachment_set_content_type(attachment: *mut c_void, content_type: *const c_char);
    fn sentry_remove_attachment(attachment: *mut c_void);
    fn sentry_transaction_context_new(name: *const c_char, operation: *const c_char)
        -> *mut c_void;
    fn sentry_transaction_start(context: *mut c_void, sampling: SentryValue) -> *mut c_void;
    fn sentry_transaction_start_child(
        transaction: *mut c_void,
        operation: *const c_char,
        description: *const c_char,
    ) -> *mut c_void;
    fn sentry_span_start_child(
        span: *mut c_void,
        operation: *const c_char,
        description: *const c_char,
    ) -> *mut c_void;
    fn sentry_transaction_set_status(transaction: *mut c_void, status: c_int);
    fn sentry_transaction_set_data(
        transaction: *mut c_void,
        key: *const c_char,
        value: SentryValue,
    );
    fn sentry_span_set_status(span: *mut c_void, status: c_int);
    fn sentry_span_set_data(span: *mut c_void, key: *const c_char, value: SentryValue);
    fn sentry_transaction_finish(transaction: *mut c_void) -> SentryUuid;
    fn sentry_span_finish(span: *mut c_void);
}
