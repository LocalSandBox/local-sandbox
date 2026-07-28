use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{bail, Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

use super::CommonContext;

const SMALL_FILES: &[&str] = &[
    "qemu-hang.json",
    "qemu-progress.jsonl",
    "qemu-timeline.jsonl",
    "qemu-hang-dump.json",
    "hyperv-events.json",
    "boot.status.json",
    "preflight.json",
    "qemu.argv.redacted.txt",
    "qemu.status.json",
];
const ROLLING_FILES: &[&str] = &["qemu.stderr.log", "qemu.stdout.log", "serial.log"];
const ARCHIVE_FILES: &[&str] = &[
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
];
const GENERATED_METADATA_RESERVE: u64 = 64 * 1024;
const INCIDENT_ARCHIVE_LIMIT: u64 = 10 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiagnosticLimits {
    pub small_file_bytes: u64,
    pub rolling_file_bytes: u64,
    pub service_log_bytes: u64,
    pub total_bytes: u64,
}

impl Default for DiagnosticLimits {
    fn default() -> Self {
        Self {
            small_file_bytes: 256 * 1024,
            rolling_file_bytes: 2 * 1024 * 1024,
            service_log_bytes: 2 * 1024 * 1024,
            total_bytes: 10 * 1024 * 1024,
        }
    }
}

impl DiagnosticLimits {
    fn validate(self) -> Result<Self> {
        if self.small_file_bytes == 0
            || self.rolling_file_bytes == 0
            || self.service_log_bytes == 0
            || self.total_bytes == 0
            || self.small_file_bytes > self.total_bytes
            || self.rolling_file_bytes > self.total_bytes
            || self.service_log_bytes > self.total_bytes
            || self.total_bytes <= GENERATED_METADATA_RESERVE
        {
            bail!("diagnostic limits must be non-zero and fit the total incident limit");
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    pub path: PathBuf,
    pub filename: String,
    pub content_type: &'static str,
}

#[derive(Debug, Clone)]
pub struct IncidentMetadata {
    pub event_id: String,
    pub timestamp_utc: String,
    pub stable_error_code: String,
    pub correlation_id: Option<String>,
    pub resource_id: Option<String>,
    pub failure_phase: String,
    pub common_context: CommonContext,
}

#[derive(Debug)]
pub struct IncidentSnapshot {
    pub event_id: String,
    pub directory: PathBuf,
    pub attachments: Vec<Attachment>,
    pub total_bytes: u64,
}

#[derive(Debug, Serialize)]
struct SentryReceipt<'a> {
    schema_version: u32,
    incident_id: &'a str,
    sentry_event_id: &'a str,
    dsn_project_identity: Option<&'a str>,
    submitted_utc: String,
}

pub(crate) fn vm_diagnostics_dir(instance_dir: &Path) -> PathBuf {
    instance_dir.join("diagnostics")
}

impl IncidentSnapshot {
    pub fn remove(self) -> Result<()> {
        fs::remove_dir_all(&self.directory).context("remove accepted telemetry incident snapshot")
    }

    pub fn retain_bounded(self, policy: RetentionPolicy) -> Result<()> {
        let root = self
            .directory
            .parent()
            .context("telemetry incident directory has no parent")?;
        prune_retained_incidents(root, policy)
    }
}

pub(crate) fn write_sentry_receipt(
    telemetry_root: &Path,
    incident_snapshot: &Path,
    sentry_event_id: &str,
    dsn_project_identity: Option<&str>,
) -> Result<()> {
    validate_event_id(sentry_event_id)?;
    let copied_manifest = incident_snapshot.join("qemu-hang-dump.json");
    let bytes = fs::read(&copied_manifest).context("read captured QEMU dump manifest")?;
    if bytes.len() > 256 * 1024 {
        bail!("captured QEMU dump manifest exceeds fixed bound");
    }
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&bytes).context("parse captured QEMU dump manifest")?;
    let incident_id = manifest
        .get("incident_id")
        .and_then(serde_json::Value::as_str)
        .context("QEMU dump manifest omitted incident ID")?
        .to_string();
    validate_event_id(&incident_id)?;
    let dump_root = telemetry_root.join("qemu-dumps");
    let dump_directory = dump_root.join(&incident_id);
    let metadata =
        fs::symlink_metadata(&dump_directory).context("inspect local QEMU dump directory")?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        bail!("local QEMU dump incident path is not a regular directory");
    }
    let canonical_root = dump_root
        .canonicalize()
        .context("canonicalize QEMU dump root")?;
    let canonical_incident = dump_directory
        .canonicalize()
        .context("canonicalize QEMU dump incident")?;
    if canonical_incident.parent() != Some(canonical_root.as_path()) {
        bail!("local QEMU dump incident escaped the validated root");
    }
    manifest["sentry_event_id"] = serde_json::Value::String(sentry_event_id.to_string());
    crate::ledger::atomic::write_value(&canonical_incident.join("qemu-hang-dump.json"), &manifest)
        .context("update local QEMU dump manifest with Sentry event ID")?;
    let receipt = SentryReceipt {
        schema_version: 1,
        incident_id: &incident_id,
        sentry_event_id,
        dsn_project_identity,
        submitted_utc: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "unknown".to_string()),
    };
    crate::ledger::atomic::write_value(&canonical_incident.join("sentry-receipt.json"), &receipt)
        .context("write local QEMU Sentry receipt")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionPolicy {
    pub max_count: usize,
    pub max_age: Duration,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            max_count: 20,
            max_age: Duration::from_secs(7 * 24 * 60 * 60),
        }
    }
}

#[derive(Debug, Serialize)]
struct IncidentManifest<'a> {
    schema_version: u32,
    event_id: &'a str,
    timestamp_utc: &'a str,
    stable_error_code: &'a str,
    correlation_id: &'a Option<String>,
    resource_id: &'a Option<String>,
    failure_phase: &'a str,
    total_bytes: u64,
    files: Vec<FileRecord>,
}

#[derive(Debug, Serialize)]
struct FileRecord {
    name: String,
    source_path: String,
    status: FileStatus,
    source_bytes: Option<u64>,
    captured_bytes: u64,
    sha256: Option<String>,
    truncated: bool,
    changed_during_capture: bool,
    inclusion_in_archive: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum FileStatus {
    Captured,
    Missing,
    Unavailable,
    TotalLimitReached,
}

pub fn collect_incident(
    incident_root: &Path,
    diagnostics_dir: &Path,
    service_log: Option<&Path>,
    metadata: &IncidentMetadata,
    limits: DiagnosticLimits,
) -> Result<IncidentSnapshot> {
    let limits = limits.validate()?;
    validate_event_id(&metadata.event_id)?;
    let directory = incident_root.join(&metadata.event_id);
    if directory.exists() {
        bail!("telemetry incident directory already exists");
    }
    fs::create_dir_all(&directory).context("create telemetry incident directory")?;

    let result = collect_into(&directory, diagnostics_dir, service_log, metadata, limits);
    if result.is_err() {
        let _ = fs::remove_dir_all(&directory);
    }
    result
}

fn collect_into(
    directory: &Path,
    diagnostics_dir: &Path,
    service_log: Option<&Path>,
    metadata: &IncidentMetadata,
    limits: DiagnosticLimits,
) -> Result<IncidentSnapshot> {
    let mut records = Vec::new();
    let mut total_bytes = 0u64;
    let source_total_limit = limits.total_bytes - GENERATED_METADATA_RESERVE;

    for name in SMALL_FILES {
        capture_file(
            &diagnostics_dir.join(name),
            name,
            false,
            limits.small_file_bytes,
            source_total_limit,
            directory,
            &mut total_bytes,
            &mut records,
        );
    }
    for name in ROLLING_FILES {
        capture_file(
            &diagnostics_dir.join(name),
            name,
            true,
            limits.rolling_file_bytes,
            source_total_limit,
            directory,
            &mut total_bytes,
            &mut records,
        );
    }
    if let Some(service_log) = service_log {
        capture_file(
            service_log,
            "service.tail.jsonl",
            true,
            limits.service_log_bytes,
            source_total_limit,
            directory,
            &mut total_bytes,
            &mut records,
        );
    }

    let machine = serde_json::to_vec_pretty(&metadata.common_context)
        .context("serialize telemetry machine context")?;
    write_bounded_generated(
        directory,
        "machine.json",
        &machine,
        limits.total_bytes,
        &mut total_bytes,
    )?;

    let manifest = IncidentManifest {
        schema_version: 2,
        event_id: &metadata.event_id,
        timestamp_utc: &metadata.timestamp_utc,
        stable_error_code: &metadata.stable_error_code,
        correlation_id: &metadata.correlation_id,
        resource_id: &metadata.resource_id,
        failure_phase: &metadata.failure_phase,
        total_bytes,
        files: records,
    };
    let manifest_bytes =
        serde_json::to_vec_pretty(&manifest).context("serialize telemetry incident manifest")?;
    write_atomic_bounded(
        directory,
        "incident.json",
        &manifest_bytes,
        limits.total_bytes,
        &mut total_bytes,
    )?;
    let archive_bytes = build_incident_archive(directory, INCIDENT_ARCHIVE_LIMIT)?;
    total_bytes = total_bytes.saturating_add(archive_bytes);
    let attachments = vec![
        Attachment {
            path: directory.join("incident.json"),
            filename: "incident.json".to_string(),
            content_type: "application/json",
        },
        Attachment {
            path: directory.join("incident.zip"),
            filename: "incident.zip".to_string(),
            content_type: "application/zip",
        },
    ];

    Ok(IncidentSnapshot {
        event_id: metadata.event_id.clone(),
        directory: directory.to_path_buf(),
        attachments,
        total_bytes,
    })
}

#[allow(clippy::too_many_arguments)]
fn capture_file(
    source: &Path,
    destination_name: &str,
    tail: bool,
    per_file_limit: u64,
    total_limit: u64,
    directory: &Path,
    total_bytes: &mut u64,
    records: &mut Vec<FileRecord>,
) {
    let source_path = source.display().to_string();
    let before = match fs::metadata(source) {
        Ok(metadata) if metadata.is_file() => metadata,
        Ok(_) => {
            records.push(unavailable_record(destination_name, source_path));
            return;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            records.push(FileRecord {
                name: destination_name.to_string(),
                source_path,
                status: FileStatus::Missing,
                source_bytes: None,
                captured_bytes: 0,
                sha256: None,
                truncated: false,
                changed_during_capture: false,
                inclusion_in_archive: false,
            });
            return;
        }
        Err(_) => {
            records.push(unavailable_record(destination_name, source_path));
            return;
        }
    };
    let available = total_limit.saturating_sub(*total_bytes);
    if available == 0 {
        records.push(FileRecord {
            name: destination_name.to_string(),
            source_path,
            status: FileStatus::TotalLimitReached,
            source_bytes: Some(before.len()),
            captured_bytes: 0,
            sha256: None,
            truncated: before.len() > 0,
            changed_during_capture: false,
            inclusion_in_archive: false,
        });
        return;
    }
    let capture_limit = per_file_limit.min(available);
    let destination = directory.join(destination_name);
    let captured = copy_bounded(source, &destination, tail, capture_limit);
    let (captured_bytes, hash) = match captured {
        Ok(value) => value,
        Err(_) => {
            let _ = fs::remove_file(&destination);
            records.push(unavailable_record(destination_name, source_path));
            return;
        }
    };
    let after = fs::metadata(source).ok();
    let changed = after.as_ref().is_none_or(|metadata| {
        metadata.len() != before.len() || metadata.modified().ok() != before.modified().ok()
    });
    *total_bytes = total_bytes.saturating_add(captured_bytes);
    records.push(FileRecord {
        name: destination_name.to_string(),
        source_path,
        status: FileStatus::Captured,
        source_bytes: Some(before.len()),
        captured_bytes,
        sha256: Some(hash),
        truncated: before.len() > captured_bytes,
        changed_during_capture: changed,
        inclusion_in_archive: true,
    });
}

fn copy_bounded(
    source: &Path,
    destination: &Path,
    tail: bool,
    limit: u64,
) -> Result<(u64, String)> {
    let mut input = File::open(source).context("open diagnostic source")?;
    let length = input.metadata().context("inspect diagnostic source")?.len();
    if tail && length > limit {
        input
            .seek(SeekFrom::Start(length - limit))
            .context("seek diagnostic tail")?;
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .context("create diagnostic snapshot file")?;
    let mut remaining = limit;
    let mut captured = 0u64;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    while remaining > 0 {
        let requested = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        let read = input
            .read(&mut buffer[..requested])
            .context("read diagnostic source")?;
        if read == 0 {
            break;
        }
        output
            .write_all(&buffer[..read])
            .context("write diagnostic snapshot")?;
        hasher.update(&buffer[..read]);
        let read = read as u64;
        captured += read;
        remaining -= read;
    }
    output
        .sync_all()
        .context("flush diagnostic snapshot file")?;
    Ok((captured, format!("{:x}", hasher.finalize())))
}

fn write_bounded_generated(
    directory: &Path,
    name: &str,
    bytes: &[u8],
    total_limit: u64,
    total_bytes: &mut u64,
) -> Result<()> {
    write_atomic_bounded(directory, name, bytes, total_limit, total_bytes)?;
    Ok(())
}

fn build_incident_archive(directory: &Path, limit: u64) -> Result<u64> {
    let pending = directory.join(".incident.zip.pending");
    let destination = directory.join("incident.zip");
    let output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pending)
        .context("create pending incident archive")?;
    let mut archive = ZipWriter::new(output);
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(0o600);
    for name in ARCHIVE_FILES {
        let path = directory.join(name);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).context("inspect incident archive input"),
        };
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            bail!("incident archive input is not a regular file");
        }
        archive
            .start_file(*name, options)
            .context("start incident archive entry")?;
        let mut input = File::open(&path).context("open incident archive input")?;
        std::io::copy(&mut input, &mut archive).context("write incident archive entry")?;
    }
    let output = archive.finish().context("finish incident archive")?;
    output.sync_all().context("flush incident archive")?;
    let length = output.metadata().context("inspect incident archive")?.len();
    drop(output);
    if length > limit {
        let _ = fs::remove_file(&pending);
        bail!("incident archive exceeds bounded attachment limit");
    }
    fs::rename(&pending, &destination).context("commit incident archive")?;
    Ok(length)
}

fn write_atomic_bounded(
    directory: &Path,
    name: &str,
    bytes: &[u8],
    total_limit: u64,
    total_bytes: &mut u64,
) -> Result<()> {
    let length = u64::try_from(bytes.len()).context("generated diagnostic file is too large")?;
    if total_bytes.saturating_add(length) > total_limit {
        bail!("generated diagnostic metadata exceeds total incident limit");
    }
    let pending = directory.join(format!(".{name}.pending"));
    let destination = directory.join(name);
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pending)
        .context("create pending diagnostic metadata")?;
    output
        .write_all(bytes)
        .context("write diagnostic metadata")?;
    output.sync_all().context("flush diagnostic metadata")?;
    fs::rename(&pending, &destination).context("commit diagnostic metadata")?;
    *total_bytes += length;
    Ok(())
}

fn unavailable_record(name: &str, source_path: String) -> FileRecord {
    FileRecord {
        name: name.to_string(),
        source_path,
        status: FileStatus::Unavailable,
        source_bytes: None,
        captured_bytes: 0,
        sha256: None,
        truncated: false,
        changed_during_capture: false,
        inclusion_in_archive: false,
    }
}

fn validate_event_id(event_id: &str) -> Result<()> {
    if event_id.len() != 32 || !event_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("telemetry event ID must be 32 hexadecimal characters");
    }
    Ok(())
}

fn prune_retained_incidents(root: &Path, policy: RetentionPolicy) -> Result<()> {
    if policy.max_count == 0 || policy.max_age.is_zero() {
        bail!("telemetry retention limits must be non-zero");
    }
    let now = SystemTime::now();
    let mut incidents = Vec::new();
    for entry in fs::read_dir(root).context("list retained telemetry incidents")? {
        let Ok(entry) = entry else {
            continue;
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if validate_event_id(name).is_err() {
            continue;
        }
        let Ok(metadata) = fs::symlink_metadata(entry.path()) else {
            continue;
        };
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            continue;
        }
        incidents.push((
            metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            entry.path(),
        ));
    }
    incidents.sort_by_key(|(modified, _)| *modified);
    let excess = incidents.len().saturating_sub(policy.max_count);
    for (index, (modified, path)) in incidents.into_iter().enumerate() {
        let expired = now
            .duration_since(modified)
            .is_ok_and(|age| age > policy.max_age);
        if index < excess || expired {
            let _ = fs::remove_dir_all(path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use zip::ZipArchive;

    use super::*;

    fn temporary_root(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "lsbs-telemetry-{label}-{}",
            crate::session::ResourceHandle::random().unwrap()
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn metadata() -> IncidentMetadata {
        IncidentMetadata {
            event_id: "0123456789abcdef0123456789abcdef".to_string(),
            timestamp_utc: "2026-07-25T00:00:00Z".to_string(),
            stable_error_code: "SANDBOX_BOOT_FAILED".to_string(),
            correlation_id: Some("correlation-1".to_string()),
            resource_id: Some("sandbox-1".to_string()),
            failure_phase: "boot".to_string(),
            common_context: CommonContext::collect("commit", Some("digest".to_string()), None),
        }
    }

    #[test]
    fn collects_allowlist_and_records_missing_files() {
        let root = temporary_root("allowlist");
        let instance = root.join("instance");
        fs::create_dir(&instance).unwrap();
        fs::write(instance.join("boot.status.json"), br#"{"ready":false}"#).unwrap();
        fs::write(instance.join("qemu-hang.dmp"), b"must stay local").unwrap();
        fs::write(instance.join("secret.txt"), b"must not be captured").unwrap();

        let snapshot = collect_incident(
            &root.join("incidents"),
            &instance,
            None,
            &metadata(),
            DiagnosticLimits::default(),
        )
        .unwrap();
        let manifest = fs::read_to_string(snapshot.directory.join("incident.json")).unwrap();
        assert!(manifest.contains("\"status\": \"missing\""));
        assert!(snapshot.directory.join("boot.status.json").is_file());
        assert!(!snapshot.directory.join("secret.txt").exists());
        assert!(!snapshot.directory.join("qemu-hang.dmp").exists());
        assert!(snapshot.directory.join("machine.json").is_file());
        assert_eq!(
            snapshot
                .attachments
                .iter()
                .map(|attachment| attachment.filename.as_str())
                .collect::<Vec<_>>(),
            ["incident.json", "incident.zip"]
        );
        let mut archive =
            ZipArchive::new(File::open(snapshot.directory.join("incident.zip")).unwrap()).unwrap();
        assert!(archive.by_name("incident.json").is_ok());
        assert!(archive.by_name("boot.status.json").is_ok());
        assert!(archive.by_name("qemu-hang.dmp").is_err());
        assert!(archive.by_name("secret.txt").is_err());
        assert!(manifest.contains("\"inclusion_in_archive\": true"));
        assert!(manifest.contains("\"inclusion_in_archive\": false"));
        snapshot.remove().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn resolves_vm_diagnostics_below_the_platform_artifact_directory() {
        let instance = PathBuf::from(r"C:\ProgramData\LocalSandbox\instance");

        assert_eq!(vm_diagnostics_dir(&instance), instance.join("diagnostics"));
    }

    #[test]
    fn tails_rolling_logs_and_preserves_non_utf8_bytes() {
        let root = temporary_root("tail");
        let instance = root.join("instance");
        fs::create_dir(&instance).unwrap();
        let bytes = [b'a', b'b', b'c', 0xff, b'd', b'e', b'f'];
        fs::write(instance.join("qemu.stderr.log"), bytes).unwrap();
        let limits = DiagnosticLimits {
            rolling_file_bytes: 4,
            ..DiagnosticLimits::default()
        };

        let snapshot = collect_incident(
            &root.join("incidents"),
            &instance,
            None,
            &metadata(),
            limits,
        )
        .unwrap();
        assert_eq!(
            fs::read(snapshot.directory.join("qemu.stderr.log")).unwrap(),
            [0xff, b'd', b'e', b'f']
        );
        let manifest = fs::read_to_string(snapshot.directory.join("incident.json")).unwrap();
        assert!(manifest.contains("\"truncated\": true"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn total_limit_stops_optional_files_without_exceeding_bound() {
        let root = temporary_root("total");
        let instance = root.join("instance");
        fs::create_dir(&instance).unwrap();
        fs::write(instance.join("boot.status.json"), vec![b'a'; 64 * 1024]).unwrap();
        fs::write(instance.join("preflight.json"), vec![b'b'; 64 * 1024]).unwrap();
        let limits = DiagnosticLimits {
            small_file_bytes: 64 * 1024,
            rolling_file_bytes: 64 * 1024,
            service_log_bytes: 64 * 1024,
            total_bytes: 128 * 1024,
        };

        let snapshot = collect_incident(
            &root.join("incidents"),
            &instance,
            None,
            &metadata(),
            limits,
        )
        .unwrap();
        assert!(snapshot.total_bytes <= limits.total_bytes);
        let manifest = fs::read_to_string(snapshot.directory.join("incident.json")).unwrap();
        assert!(manifest.contains("\"status\": \"total_limit_reached\""));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn invalid_limits_and_duplicate_event_ids_fail_without_overwrite() {
        let root = temporary_root("bounds");
        let instance = root.join("instance");
        fs::create_dir(&instance).unwrap();
        assert!(collect_incident(
            &root.join("incidents"),
            &instance,
            None,
            &metadata(),
            DiagnosticLimits {
                small_file_bytes: 0,
                ..DiagnosticLimits::default()
            },
        )
        .is_err());
        collect_incident(
            &root.join("incidents"),
            &instance,
            None,
            &metadata(),
            DiagnosticLimits::default(),
        )
        .unwrap();
        assert!(collect_incident(
            &root.join("incidents"),
            &instance,
            None,
            &metadata(),
            DiagnosticLimits::default(),
        )
        .is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejected_snapshots_are_retained_under_a_count_bound() {
        let root = temporary_root("retention");
        let instance = root.join("instance");
        fs::create_dir(&instance).unwrap();
        let incidents = root.join("incidents");
        for index in 0..3 {
            let mut metadata = metadata();
            metadata.event_id = format!("{index:032x}");
            collect_incident(
                &incidents,
                &instance,
                None,
                &metadata,
                DiagnosticLimits::default(),
            )
            .unwrap()
            .retain_bounded(RetentionPolicy {
                max_count: 2,
                max_age: Duration::from_secs(60),
            })
            .unwrap();
        }
        assert_eq!(fs::read_dir(&incidents).unwrap().count(), 2);
        fs::remove_dir_all(root).unwrap();
    }
}
