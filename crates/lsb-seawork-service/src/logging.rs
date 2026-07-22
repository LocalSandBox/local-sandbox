use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{bail, Context, Result};
use serde::Serialize;

const LOG_SCHEMA_VERSION: u32 = 1;
const MAX_LOG_FILES: usize = 10;
const MAX_LOG_SIZE: u64 = 10 * 1024 * 1024;
const MAX_RECORD_SIZE: usize = 8 * 1024;
const MAX_CODE_LEN: usize = 96;
const MAX_PHASE_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum EventId {
    ServiceStarted = 1,
    ServiceStopped = 2,
    LedgerQuarantined = 3,
    ServiceStartPending = 4,
    ServiceStopPending = 5,
    ServiceFatalExit = 6,
    BundleVerificationFailed = 7,
    ClientTrustFailed = 8,
    QuotaRejected = 9,
    ResourceCleanupFailed = 10,
    UpdateState = 11,
    RollbackState = 12,
    UninstallState = 13,
    RuntimeCapabilityUnavailable = 14,
    BundleVerified = 15,
    SessionsDrained = 16,
}

impl EventId {
    const ALL: [Self; 16] = [
        Self::ServiceStarted,
        Self::ServiceStopped,
        Self::LedgerQuarantined,
        Self::ServiceStartPending,
        Self::ServiceStopPending,
        Self::ServiceFatalExit,
        Self::BundleVerificationFailed,
        Self::ClientTrustFailed,
        Self::QuotaRejected,
        Self::ResourceCleanupFailed,
        Self::UpdateState,
        Self::RollbackState,
        Self::UninstallState,
        Self::RuntimeCapabilityUnavailable,
        Self::BundleVerified,
        Self::SessionsDrained,
    ];

    fn severity(self) -> Severity {
        match self {
            Self::ServiceFatalExit
            | Self::BundleVerificationFailed
            | Self::ClientTrustFailed
            | Self::ResourceCleanupFailed => Severity::Error,
            Self::LedgerQuarantined | Self::QuotaRejected | Self::RuntimeCapabilityUnavailable => {
                Severity::Warning
            }
            _ => Severity::Information,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Severity {
    Information,
    Warning,
    Error,
}

#[derive(Debug, Serialize)]
struct Event<'a> {
    schema_version: u32,
    event_id: u32,
    severity: Severity,
    timestamp_unix_ms: u64,
    service_version: &'static str,
    bundle_version: &'static str,
    protocol_major: u16,
    protocol_minor: u16,
    ledger_schema: u32,
    phase: &'a str,
    stable_code: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    correlation_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    identity_hash: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource_type: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    win32_code: Option<u32>,
}

#[derive(Debug, Clone, Copy)]
pub struct EventContext<'a> {
    pub correlation_id: Option<&'a str>,
    pub identity_hash: Option<&'a str>,
    pub resource_type: Option<&'a str>,
    pub resource_id: Option<&'a str>,
    pub duration_ms: Option<u64>,
    pub win32_code: Option<u32>,
}

impl EventContext<'_> {
    pub const EMPTY: Self = Self {
        correlation_id: None,
        identity_hash: None,
        resource_type: None,
        resource_id: None,
        duration_ms: None,
        win32_code: None,
    };

    fn validate(&self) -> Result<()> {
        validate_optional_hex(self.correlation_id, 32, "correlation id")?;
        validate_optional_hex(self.identity_hash, 64, "identity hash")?;
        validate_optional_hex(self.resource_id, 32, "resource id")?;
        if let Some(resource_type) = self.resource_type {
            validate_token(resource_type, MAX_PHASE_LEN, "resource type")?;
        }
        if self.resource_type.is_some() != self.resource_id.is_some() {
            bail!("resource type and opaque resource id must be recorded together");
        }
        Ok(())
    }
}

pub struct JsonLogger {
    path: PathBuf,
    limits: LogLimits,
    writer: Mutex<()>,
}

#[cfg(windows)]
pub struct ServiceLogger {
    json: JsonLogger,
    event_log: WindowsEventLog,
}

#[cfg(windows)]
impl ServiceLogger {
    pub fn new(log_dir: &Path) -> Result<Self> {
        Ok(Self {
            json: JsonLogger::new(log_dir)?,
            event_log: WindowsEventLog::register()?,
        })
    }

    pub fn write(&self, event_id: EventId, phase: &str, stable_code: &str) -> Result<()> {
        self.write_with_context(event_id, phase, stable_code, EventContext::EMPTY)
    }

    pub fn write_with_context(
        &self,
        event_id: EventId,
        phase: &str,
        stable_code: &str,
        context: EventContext<'_>,
    ) -> Result<()> {
        self.json
            .write_with_context(event_id, phase, stable_code, context)?;
        self.event_log.write(
            event_id,
            phase,
            stable_code,
            env!("CARGO_PKG_VERSION"),
            context.resource_id,
        )?;
        Ok(())
    }

    pub fn write_update(
        &self,
        phase: &str,
        stable_code: &str,
        target_version: Option<&str>,
        digest_prefix: Option<&str>,
    ) -> Result<()> {
        if target_version.is_some_and(|version| {
            version.is_empty()
                || version.len() > 128
                || !version
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        }) {
            bail!("update diagnostic version is invalid");
        }
        let context = EventContext {
            resource_type: digest_prefix.map(|_| "update_target"),
            resource_id: digest_prefix,
            ..EventContext::EMPTY
        };
        self.json
            .write_with_context(EventId::UpdateState, phase, stable_code, context)?;
        self.event_log.write(
            EventId::UpdateState,
            phase,
            stable_code,
            target_version.unwrap_or(env!("CARGO_PKG_VERSION")),
            digest_prefix,
        )?;
        Ok(())
    }
}

#[cfg(windows)]
struct WindowsEventLog {
    source: Vec<u16>,
}

#[cfg(windows)]
impl WindowsEventLog {
    fn register() -> Result<Self> {
        use std::os::windows::ffi::OsStrExt;

        let source = std::ffi::OsStr::new(crate::SERVICE_NAME)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let handle = unsafe {
            windows_sys::Win32::System::EventLog::RegisterEventSourceW(
                std::ptr::null(),
                source.as_ptr(),
            )
        };
        if handle.is_null() {
            bail!(
                "RegisterEventSourceW failed: {}",
                std::io::Error::last_os_error()
            );
        }
        unsafe {
            windows_sys::Win32::System::EventLog::DeregisterEventSource(handle);
        }
        Ok(Self { source })
    }

    fn write(
        &self,
        event_id: EventId,
        phase: &str,
        stable_code: &str,
        version: &str,
        digest_prefix: Option<&str>,
    ) -> Result<()> {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::System::EventLog::{
            ReportEventW, EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE, EVENTLOG_WARNING_TYPE,
        };

        let event_type = match event_id.severity() {
            Severity::Information => EVENTLOG_INFORMATION_TYPE,
            Severity::Warning => EVENTLOG_WARNING_TYPE,
            Severity::Error => EVENTLOG_ERROR_TYPE,
        };
        let insertions = [version, phase, stable_code, digest_prefix.unwrap_or("")].map(|value| {
            std::ffi::OsStr::new(value)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect::<Vec<_>>()
        });
        let insertion_pointers = insertions
            .iter()
            .map(|value| value.as_ptr())
            .collect::<Vec<_>>();
        let handle = unsafe {
            windows_sys::Win32::System::EventLog::RegisterEventSourceW(
                std::ptr::null(),
                self.source.as_ptr(),
            )
        };
        if handle.is_null() {
            bail!(
                "RegisterEventSourceW failed: {}",
                std::io::Error::last_os_error()
            );
        }
        let reported = unsafe {
            ReportEventW(
                handle,
                event_type,
                0,
                event_id as u32,
                std::ptr::null_mut(),
                u16::try_from(insertion_pointers.len()).unwrap_or(0),
                0,
                insertion_pointers.as_ptr(),
                std::ptr::null(),
            )
        };
        let report_error = (reported == 0).then(std::io::Error::last_os_error);
        unsafe {
            windows_sys::Win32::System::EventLog::DeregisterEventSource(handle);
        }
        if let Some(error) = report_error {
            bail!("ReportEventW failed: {error}");
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct LogLimits {
    files: usize,
    bytes_per_file: u64,
}

impl JsonLogger {
    pub fn new(log_dir: &Path) -> Result<Self> {
        Self::with_limits(
            log_dir,
            LogLimits {
                files: MAX_LOG_FILES,
                bytes_per_file: MAX_LOG_SIZE,
            },
        )
    }

    fn with_limits(log_dir: &Path, limits: LogLimits) -> Result<Self> {
        if limits.files == 0 || limits.bytes_per_file == 0 {
            bail!("diagnostic log limits must be nonzero");
        }
        std::fs::create_dir_all(log_dir)?;
        Ok(Self {
            path: log_dir.join("service.jsonl"),
            limits,
            writer: Mutex::new(()),
        })
    }

    #[cfg(test)]
    pub fn write(&self, event_id: EventId, phase: &str, stable_code: &str) -> Result<()> {
        self.write_with_context(event_id, phase, stable_code, EventContext::EMPTY)
    }

    pub fn write_with_context(
        &self,
        event_id: EventId,
        phase: &str,
        stable_code: &str,
        context: EventContext<'_>,
    ) -> Result<()> {
        debug_assert!(EventId::ALL.contains(&event_id));
        validate_token(phase, MAX_PHASE_LEN, "diagnostic phase")?;
        validate_stable_code(stable_code)?;
        context.validate()?;
        let timestamp_unix_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system clock is before Unix epoch")?
            .as_millis()
            .try_into()
            .context("diagnostic timestamp does not fit u64")?;
        let event = Event {
            schema_version: LOG_SCHEMA_VERSION,
            event_id: event_id as u32,
            severity: event_id.severity(),
            timestamp_unix_ms,
            service_version: env!("CARGO_PKG_VERSION"),
            bundle_version: env!("CARGO_PKG_VERSION"),
            protocol_major: lsb_service_proto::CURRENT.major,
            protocol_minor: lsb_service_proto::CURRENT.minor,
            ledger_schema: crate::LEDGER_SCHEMA_VERSION,
            phase,
            stable_code,
            correlation_id: context.correlation_id,
            identity_hash: context.identity_hash,
            resource_type: context.resource_type,
            resource_id: context.resource_id,
            duration_ms: context.duration_ms,
            win32_code: context.win32_code,
        };
        let mut encoded = serde_json::to_vec(&event)?;
        encoded.push(b'\n');
        if encoded.len() > MAX_RECORD_SIZE
            || u64::try_from(encoded.len()).unwrap_or(u64::MAX) > self.limits.bytes_per_file
        {
            bail!("diagnostic record exceeds its bounded size");
        }

        let _guard = self
            .writer
            .lock()
            .map_err(|_| anyhow::anyhow!("diagnostic writer lock poisoned"))?;
        self.reject_unsafe_active_file()?;
        let current_size = self.path.metadata().map(|value| value.len()).unwrap_or(0);
        if current_size.saturating_add(encoded.len() as u64) > self.limits.bytes_per_file {
            self.rotate()?;
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(&encoded)?;
        file.flush()?;
        Ok(())
    }

    fn reject_unsafe_active_file(&self) -> Result<()> {
        let metadata = match std::fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        if !metadata.file_type().is_file() {
            bail!("active diagnostic log is not a regular file");
        }
        Ok(())
    }

    fn rotate(&self) -> Result<()> {
        if self.limits.files == 1 {
            remove_regular_if_exists(&self.path)?;
            return Ok(());
        }
        let oldest = rotated_path(&self.path, self.limits.files - 1);
        remove_regular_if_exists(&oldest)?;
        for index in (1..self.limits.files - 1).rev() {
            let source = rotated_path(&self.path, index);
            let target = rotated_path(&self.path, index + 1);
            rename_regular_if_exists(&source, &target)?;
        }
        rename_regular_if_exists(&self.path, &rotated_path(&self.path, 1))?;
        Ok(())
    }
}

fn rotated_path(path: &Path, index: usize) -> PathBuf {
    path.with_extension(format!("jsonl.{index}"))
}

fn remove_regular_if_exists(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => std::fs::remove_file(path)?,
        Ok(_) => bail!("diagnostic rotation target is not a regular file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn rename_regular_if_exists(source: &Path, target: &Path) -> Result<()> {
    match std::fs::symlink_metadata(source) {
        Ok(metadata) if metadata.file_type().is_file() => std::fs::rename(source, target)?,
        Ok(_) => bail!("diagnostic rotation source is not a regular file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn validate_stable_code(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_CODE_LEN
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        bail!("stable diagnostic code is invalid");
    }
    Ok(())
}

fn validate_token(value: &str, max_len: usize, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > max_len
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-' | b'.')
        })
    {
        bail!("{label} is invalid");
    }
    Ok(())
}

fn validate_optional_hex(value: Option<&str>, len: usize, label: &str) -> Result<()> {
    if let Some(value) = value {
        if value.len() != len
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            bail!("{label} must be {len} lowercase hexadecimal characters");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Arc;

    fn root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("lsbsw-logging-{label}-{}", std::process::id()))
    }

    fn read_events(root: &Path) -> Vec<serde_json::Value> {
        let mut values = Vec::new();
        for index in (1..=9).rev() {
            let path = root.join(format!("service.jsonl.{index}"));
            if path.exists() {
                for line in std::fs::read_to_string(path).unwrap().lines() {
                    values.push(serde_json::from_str(line).unwrap());
                }
            }
        }
        let active = root.join("service.jsonl");
        if active.exists() {
            for line in std::fs::read_to_string(active).unwrap().lines() {
                values.push(serde_json::from_str(line).unwrap());
            }
        }
        values
    }

    #[test]
    fn event_ids_are_append_only_and_unique() {
        let ids = EventId::ALL.map(|event| event as u32);
        assert_eq!(ids, std::array::from_fn(|index| index as u32 + 1));
        assert_eq!(ids.iter().copied().collect::<HashSet<_>>().len(), ids.len());

        let message_ids = include_str!("../resources/LocalSandboxSeaWork.mc")
            .lines()
            .filter_map(|line| line.strip_prefix("MessageId=0x"))
            .map(|value| u32::from_str_radix(value, 16).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(message_ids, ids);
    }

    #[test]
    fn records_are_versioned_bounded_and_reject_payload_like_fields() {
        let root = root("schema");
        let _ = std::fs::remove_dir_all(&root);
        let logger = JsonLogger::new(&root).unwrap();
        logger
            .write_with_context(
                EventId::QuotaRejected,
                "admission.quota",
                "SANDBOX_QUOTA_EXCEEDED",
                EventContext {
                    correlation_id: Some("0123456789abcdef0123456789abcdef"),
                    identity_hash: Some(
                        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    ),
                    resource_type: Some("sandbox"),
                    resource_id: Some("fedcba9876543210fedcba9876543210"),
                    duration_ms: Some(17),
                    win32_code: Some(5),
                },
            )
            .unwrap();
        let events = read_events(&root);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["schema_version"], 1);
        assert_eq!(events[0]["event_id"], EventId::QuotaRejected as u32);
        assert_eq!(events[0]["severity"], "warning");
        assert_eq!(events[0]["service_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(
            events[0]["protocol_minor"],
            lsb_service_proto::CURRENT.minor
        );
        assert!(logger
            .write(
                EventId::ClientTrustFailed,
                "C:\\Users\\victim",
                "TRUST_FAILURE"
            )
            .is_err());
        assert!(logger
            .write(EventId::ClientTrustFailed, "trust", "TOKEN=secret")
            .is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn rotation_is_bounded_and_replaces_the_oldest_regular_file() {
        let root = root("rotation");
        let _ = std::fs::remove_dir_all(&root);
        let logger = JsonLogger::with_limits(
            &root,
            LogLimits {
                files: 3,
                bytes_per_file: 420,
            },
        )
        .unwrap();
        for _ in 0..12 {
            logger
                .write(EventId::ServiceStarted, "runtime", "RUNNING")
                .unwrap();
        }
        let files = std::fs::read_dir(&root).unwrap().collect::<Vec<_>>();
        assert!(files.len() <= 3);
        for file in files {
            let file = file.unwrap();
            assert!(file.metadata().unwrap().len() <= 420);
        }
        assert!(!root.join("service.jsonl.3").exists());
        assert!(!read_events(&root).is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn concurrent_writers_produce_complete_json_lines() {
        let root = root("concurrent");
        let _ = std::fs::remove_dir_all(&root);
        let logger = Arc::new(JsonLogger::new(&root).unwrap());
        let workers = (0..8)
            .map(|_| {
                let logger = Arc::clone(&logger);
                std::thread::spawn(move || {
                    for _ in 0..25 {
                        logger
                            .write(EventId::ServiceStarted, "runtime", "RUNNING")
                            .unwrap();
                    }
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(read_events(&root).len(), 200);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_non_file_active_log_fails_closed() {
        let root = root("non-file");
        let _ = std::fs::remove_dir_all(&root);
        let logger = JsonLogger::new(&root).unwrap();
        std::fs::create_dir(root.join("service.jsonl")).unwrap();
        assert!(logger
            .write(EventId::ServiceStarted, "runtime", "RUNNING")
            .is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn an_active_log_symlink_is_not_followed() {
        use std::os::unix::fs::symlink;

        let root = root("symlink");
        let _ = std::fs::remove_dir_all(&root);
        let logger = JsonLogger::new(&root).unwrap();
        let target = root.join("outside.txt");
        std::fs::write(&target, b"untouched").unwrap();
        symlink(&target, root.join("service.jsonl")).unwrap();
        assert!(logger
            .write(EventId::ServiceStarted, "runtime", "RUNNING")
            .is_err());
        assert_eq!(std::fs::read(target).unwrap(), b"untouched");
        let _ = std::fs::remove_dir_all(root);
    }
}
