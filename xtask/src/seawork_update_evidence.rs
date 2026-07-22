use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Component, Path, PathBuf};

use anyhow::{bail, Context, Result};
use semver::Version;
use serde::Deserialize;
use sha2::{Digest, Sha256};

const SCHEMA_VERSION: u32 = 2;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_EVIDENCE_FILES: usize = 256;
const MAX_DURATION_MS: u64 = 24 * 60 * 60 * 1000;

const KNOWN_CASES: &[&str] = &[
    "update.stable_channel",
    "update.prerelease_channel",
    "update.indefinite_busy_wait",
    "update.idle_admission_race",
    "update.activation_success",
    "update.health_rollback",
    "update.untrusted_and_incompatible_rejection",
    "update.failed_target_suppression",
    "update.seawork_repair",
    "update.seawork_uninstall",
];

const REQUIRED_COMPLETE_CASES: &[&str] = &[
    "update.stable_channel",
    "update.indefinite_busy_wait",
    "update.activation_success",
    "update.health_rollback",
    "update.untrusted_and_incompatible_rejection",
];

const KNOWN_PHASES: &[&str] = &[
    "prepared",
    "helper_started",
    "final_path_verified",
    "old_service_stop_requested",
    "old_service_stopped",
    "image_path_changed",
    "target_start_requested",
    "target_health_pending",
    "rollback_requested",
    "target_stopped",
    "old_path_restored",
    "old_service_restarted",
];

const REQUIRED_COMPLETE_REBOOT_PHASE: &str = "image_path_changed";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    source_git_sha: String,
    release_id: u64,
    release_tag: String,
    generated_utc: String,
    service_archive: Artifact,
    helper_binary: Artifact,
    helper_protocol: HelperProtocol,
    helper_install: HelperInstallEvidence,
    timestamped_authenticode_verified: bool,
    publisher_sha256: String,
    previous_bundle: BundleIdentity,
    candidate_bundle: BundleIdentity,
    environment: Environment,
    cases: Vec<Check>,
    phase_coverage: Vec<PhaseCoverage>,
    files: Vec<EvidenceFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    name: String,
    sha256: String,
    size_bytes: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HelperProtocol {
    major: u16,
    minor: u16,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HelperInstallEvidence {
    valid: bool,
    service_name: String,
    helper_version: String,
    helper_protocol_major: u16,
    helper_protocol_minor: u16,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleIdentity {
    version: String,
    archive_sha256: String,
    manifest_sha256: String,
    protocol_major: u16,
    protocol_min_minor: u16,
    protocol_max_minor: u16,
    configuration_revision: u32,
    ledger_writer_schema: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Environment {
    os_build: String,
    architecture: String,
    runner_identity_sha256: String,
    policy_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Check {
    id: String,
    status: Status,
    duration_ms: u64,
    #[serde(default)]
    stable_code: Option<String>,
    evidence: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PhaseCoverage {
    phase: String,
    helper_crash: Status,
    reboot: Status,
    #[serde(default)]
    stable_code: Option<String>,
    evidence: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    Passed,
    Failed,
    Blocked,
    NotRun,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceFile {
    relative_path: String,
    sha256: String,
    size_bytes: u64,
    redacted: bool,
}

pub fn verify(args: &[String]) -> Result<()> {
    let mut manifest = None;
    let mut service_archive = None;
    let mut helper = None;
    let mut require_complete = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--manifest" => {
                index += 1;
                manifest = Some(PathBuf::from(
                    args.get(index).context("--manifest requires a path")?,
                ));
            }
            "--service-archive" => {
                index += 1;
                service_archive = Some(PathBuf::from(
                    args.get(index)
                        .context("--service-archive requires a path")?,
                ));
            }
            "--helper" => {
                index += 1;
                helper = Some(PathBuf::from(
                    args.get(index).context("--helper requires a path")?,
                ));
            }
            "--require-complete" => require_complete = true,
            other => bail!("unknown verify-seawork-update-evidence argument: {other}"),
        }
        index += 1;
    }
    let manifest = manifest.context("--manifest is required")?;
    validate_manifest(
        &manifest,
        require_complete,
        service_archive.as_deref(),
        helper.as_deref(),
    )?;
    println!(
        "verified SeaWork update evidence manifest {}",
        manifest.display()
    );
    Ok(())
}

fn validate_manifest(
    path: &Path,
    require_complete: bool,
    service_archive: Option<&Path>,
    helper: Option<&Path>,
) -> Result<()> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("read update evidence manifest metadata {}", path.display()))?;
    if !metadata.is_file() || metadata.len() > MAX_MANIFEST_BYTES {
        bail!("update evidence manifest is not a bounded regular file");
    }
    let manifest: Manifest = serde_json::from_slice(&std::fs::read(path)?)
        .context("parse SeaWork update evidence manifest")?;
    validate_shape(path, &manifest, require_complete)?;
    if let Some(path) = service_archive {
        validate_artifact(path, &manifest.service_archive)?;
    }
    if let Some(path) = helper {
        validate_artifact(path, &manifest.helper_binary)?;
    }
    Ok(())
}

fn validate_shape(path: &Path, manifest: &Manifest, require_complete: bool) -> Result<()> {
    if manifest.schema_version != SCHEMA_VERSION {
        bail!("unsupported SeaWork update evidence schema");
    }
    require_hex(&manifest.source_git_sha, 40, "source_git_sha")?;
    require_hex(&manifest.publisher_sha256, 64, "publisher_sha256")?;
    if manifest.release_id == 0
        || manifest.generated_utc.len() < 20
        || manifest.generated_utc.len() > 64
    {
        bail!("release or generated timestamp identity is invalid");
    }
    validate_bundle(&manifest.previous_bundle)?;
    validate_bundle(&manifest.candidate_bundle)?;
    let previous_version = Version::parse(&manifest.previous_bundle.version)?;
    let candidate_version = Version::parse(&manifest.candidate_bundle.version)?;
    if manifest.release_tag != format!("v{candidate_version}")
        || candidate_version <= previous_version
        || manifest.service_archive.name
            != format!("lsb-seawork-service-v{candidate_version}-windows-x86_64.zip")
        || manifest.helper_binary.name != "localsandbox-seawork-updater.exe"
        || manifest.service_archive.sha256 != manifest.candidate_bundle.archive_sha256
        || manifest.helper_protocol.major != 1
        || manifest.helper_protocol.minor < 1
        || !manifest.helper_install.valid
        || manifest.helper_install.error.is_some()
        || manifest.helper_install.service_name != "LocalSandboxSeaWorkUpdater"
        || !Version::parse(&manifest.helper_install.helper_version).is_ok_and(|version| {
            version.to_string() == manifest.helper_install.helper_version
                && version.build.is_empty()
        })
        || manifest.helper_install.helper_protocol_major != manifest.helper_protocol.major
        || manifest.helper_install.helper_protocol_minor != manifest.helper_protocol.minor
        || !manifest.timestamped_authenticode_verified
        || manifest.previous_bundle.protocol_major != manifest.candidate_bundle.protocol_major
        || manifest.previous_bundle.protocol_max_minor
            < manifest.candidate_bundle.protocol_min_minor
        || manifest.candidate_bundle.protocol_max_minor
            < manifest.previous_bundle.protocol_min_minor
        || manifest.previous_bundle.ledger_writer_schema
            != manifest.candidate_bundle.ledger_writer_schema
    {
        bail!("release artifacts and bundle identities are not one exact update tuple");
    }
    validate_artifact_shape(&manifest.service_archive)?;
    validate_artifact_shape(&manifest.helper_binary)?;
    validate_environment(&manifest.environment)?;
    validate_layout(path, manifest)?;

    let parent = path
        .parent()
        .context("update evidence manifest has no directory")?;
    let files = validate_files(parent, &manifest.files)?;
    validate_cases(&manifest.cases, &files, require_complete)?;
    validate_phases(&manifest.phase_coverage, &files, require_complete)
}

fn validate_bundle(bundle: &BundleIdentity) -> Result<()> {
    let version = Version::parse(&bundle.version)?;
    if version.to_string() != bundle.version
        || !version.build.is_empty()
        || bundle.protocol_major == 0
        || bundle.protocol_min_minor > bundle.protocol_max_minor
        || bundle.configuration_revision == 0
        || bundle.ledger_writer_schema == 0
    {
        bail!("bundle identity is invalid");
    }
    require_hex(&bundle.archive_sha256, 64, "bundle archive_sha256")?;
    require_hex(&bundle.manifest_sha256, 64, "bundle manifest_sha256")
}

fn validate_artifact_shape(artifact: &Artifact) -> Result<()> {
    require_safe_token(&artifact.name, 160, "artifact name")?;
    require_hex(&artifact.sha256, 64, "artifact sha256")?;
    if artifact.size_bytes == 0 {
        bail!("artifact size must be nonzero");
    }
    Ok(())
}

fn validate_artifact(path: &Path, artifact: &Artifact) -> Result<()> {
    let metadata = std::fs::metadata(path).context("read update artifact metadata")?;
    if !metadata.is_file()
        || metadata.len() != artifact.size_bytes
        || sha256_file(path)? != artifact.sha256
    {
        bail!("update artifact type, size, or digest differs from evidence");
    }
    Ok(())
}

fn validate_environment(environment: &Environment) -> Result<()> {
    require_safe_token(&environment.os_build, 128, "os_build")?;
    if environment.architecture != "x86_64" {
        bail!("update evidence architecture is not x86_64");
    }
    require_hex(
        &environment.runner_identity_sha256,
        64,
        "runner identity hash",
    )?;
    require_hex(&environment.policy_sha256, 64, "policy hash")
}

fn validate_layout(path: &Path, manifest: &Manifest) -> Result<()> {
    let helper_dir = path
        .parent()
        .and_then(Path::file_name)
        .and_then(|v| v.to_str());
    let service_dir = path
        .parent()
        .and_then(Path::parent)
        .and_then(Path::file_name)
        .and_then(|v| v.to_str());
    let git_dir = path
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .and_then(Path::file_name)
        .and_then(|v| v.to_str());
    if helper_dir != Some(&manifest.helper_binary.sha256)
        || service_dir != Some(&manifest.service_archive.sha256)
        || git_dir != Some(&manifest.source_git_sha)
    {
        bail!("update evidence layout does not match source/service/helper digests");
    }
    Ok(())
}

fn validate_files<'a>(
    parent: &Path,
    file_records: &'a [EvidenceFile],
) -> Result<BTreeMap<String, &'a EvidenceFile>> {
    if file_records.is_empty() || file_records.len() > MAX_EVIDENCE_FILES {
        bail!("update evidence file count is outside bounds");
    }
    let mut files = BTreeMap::new();
    for file in file_records {
        let relative = safe_relative(&file.relative_path)?;
        let folded = file.relative_path.to_ascii_lowercase();
        if files.insert(folded, file).is_some() || !file.redacted {
            bail!("update evidence file is duplicate, case-colliding, or not redacted");
        }
        require_hex(&file.sha256, 64, "evidence file sha256")?;
        let evidence_path = parent.join(relative);
        let metadata = std::fs::symlink_metadata(&evidence_path)?;
        if !metadata.file_type().is_file()
            || metadata.len() != file.size_bytes
            || sha256_file(&evidence_path)? != file.sha256
        {
            bail!("update evidence file type, size, or digest differs from manifest");
        }
    }
    Ok(files)
}

fn validate_cases(
    cases: &[Check],
    files: &BTreeMap<String, &EvidenceFile>,
    require_complete: bool,
) -> Result<()> {
    let known = KNOWN_CASES.iter().copied().collect::<BTreeSet<_>>();
    let required = REQUIRED_COMPLETE_CASES
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut observed = BTreeSet::new();
    for case in cases {
        if !known.contains(case.id.as_str()) || !observed.insert(case.id.as_str()) {
            bail!("unknown or duplicate update evidence case: {}", case.id);
        }
        if case.duration_ms > MAX_DURATION_MS {
            bail!("update evidence case exceeds the one-day duration bound");
        }
        validate_result(
            case.status,
            case.stable_code.as_deref(),
            &case.evidence,
            files,
        )?;
        if require_complete && required.contains(case.id.as_str()) && case.status != Status::Passed
        {
            bail!("required update evidence case did not pass: {}", case.id);
        }
    }
    if require_complete && !required.is_subset(&observed) {
        bail!("update evidence does not cover the minimum required case matrix");
    }
    Ok(())
}

fn validate_phases(
    phases: &[PhaseCoverage],
    files: &BTreeMap<String, &EvidenceFile>,
    require_complete: bool,
) -> Result<()> {
    let known = KNOWN_PHASES.iter().copied().collect::<BTreeSet<_>>();
    let mut observed = BTreeSet::new();
    for phase in phases {
        if !known.contains(phase.phase.as_str()) || !observed.insert(phase.phase.as_str()) {
            bail!(
                "unknown or duplicate update recovery phase: {}",
                phase.phase
            );
        }
        if (phase.helper_crash != Status::Passed || phase.reboot != Status::Passed)
            && phase.stable_code.as_deref().is_none_or(str::is_empty)
        {
            bail!("non-passing phase coverage lacks a stable_code");
        }
        if let Some(code) = phase.stable_code.as_deref() {
            require_safe_token(code, 64, "stable_code")?;
        }
        validate_evidence_refs(&phase.evidence, files)?;
        if require_complete
            && phase.phase == REQUIRED_COMPLETE_REBOOT_PHASE
            && phase.reboot != Status::Passed
        {
            bail!("required representative reboot recovery did not pass");
        }
    }
    if require_complete && !observed.contains(REQUIRED_COMPLETE_REBOOT_PHASE) {
        bail!("update evidence lacks representative reboot recovery coverage");
    }
    Ok(())
}

fn validate_result(
    status: Status,
    stable_code: Option<&str>,
    evidence: &[String],
    files: &BTreeMap<String, &EvidenceFile>,
) -> Result<()> {
    if status != Status::Passed && stable_code.is_none_or(str::is_empty) {
        bail!("non-passing update evidence result lacks a stable_code");
    }
    if let Some(code) = stable_code {
        require_safe_token(code, 64, "stable_code")?;
    }
    validate_evidence_refs(evidence, files)
}

fn validate_evidence_refs(
    evidence: &[String],
    files: &BTreeMap<String, &EvidenceFile>,
) -> Result<()> {
    if evidence.is_empty() {
        bail!("update evidence result has no evidence references");
    }
    for reference in evidence {
        safe_relative(reference)?;
        if !files.contains_key(&reference.to_ascii_lowercase()) {
            bail!("update result references an unlisted evidence file: {reference}");
        }
    }
    Ok(())
}

fn safe_relative(value: &str) -> Result<PathBuf> {
    if value.is_empty() || value.len() > 260 || value.contains('\\') {
        bail!("evidence path is not a bounded canonical relative path");
    }
    let path = PathBuf::from(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("unsafe evidence relative path: {value}");
    }
    Ok(path)
}

fn require_hex(value: &str, length: usize, name: &str) -> Result<()> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("{name} must be {length} lowercase hexadecimal characters");
    }
    Ok(())
}

fn require_safe_token(value: &str, max: usize, name: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > max
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+'))
    {
        bail!("{name} is not a bounded safe token");
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use serde_json::json;

    use super::*;

    static NEXT: AtomicU64 = AtomicU64::new(1);

    fn fixture() -> (PathBuf, PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "lsbsw-update-evidence-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let git = "1".repeat(40);
        let service_sha = "2".repeat(64);
        let helper_sha = "3".repeat(64);
        let dir = root.join(&git).join(&service_sha).join(&helper_sha);
        std::fs::create_dir_all(dir.join("evidence")).unwrap();
        let evidence = dir.join("evidence/results.redacted.json");
        std::fs::write(&evidence, b"{}\n").unwrap();
        let evidence_sha = sha256_file(&evidence).unwrap();
        let evidence_ref = "evidence/results.redacted.json";
        let cases = REQUIRED_COMPLETE_CASES
            .iter()
            .map(|id| json!({"id": id, "status": "passed", "duration_ms": 1, "evidence": [evidence_ref]}))
            .collect::<Vec<_>>();
        let phases = vec![
            json!({"phase": REQUIRED_COMPLETE_REBOOT_PHASE, "helper_crash": "not_run", "reboot": "passed", "stable_code": "helper-crash-not-required", "evidence": [evidence_ref]}),
        ];
        let manifest = json!({
            "schema_version": 2,
            "source_git_sha": git,
            "release_id": 7,
            "release_tag": "v0.5.1",
            "generated_utc": "2026-07-22T12:00:00Z",
            "service_archive": {"name": "lsb-seawork-service-v0.5.1-windows-x86_64.zip", "sha256": service_sha, "size_bytes": 7},
            "helper_binary": {"name": "localsandbox-seawork-updater.exe", "sha256": helper_sha, "size_bytes": 8},
            "helper_protocol": {"major": 1, "minor": 1},
            "helper_install": {
                "valid": true,
                "service_name": "LocalSandboxSeaWorkUpdater",
                "helper_version": "0.5.1",
                "helper_protocol_major": 1,
                "helper_protocol_minor": 1,
                "error": null
            },
            "timestamped_authenticode_verified": true,
            "publisher_sha256": "4".repeat(64),
            "previous_bundle": {"version": "0.5.0", "archive_sha256": "5".repeat(64), "manifest_sha256": "6".repeat(64), "protocol_major": 1, "protocol_min_minor": 1, "protocol_max_minor": 6, "configuration_revision": 2, "ledger_writer_schema": 1},
            "candidate_bundle": {"version": "0.5.1", "archive_sha256": service_sha, "manifest_sha256": "7".repeat(64), "protocol_major": 1, "protocol_min_minor": 1, "protocol_max_minor": 6, "configuration_revision": 2, "ledger_writer_schema": 1},
            "environment": {"os_build": "10.0.26100", "architecture": "x86_64", "runner_identity_sha256": "8".repeat(64), "policy_sha256": "9".repeat(64)},
            "cases": cases,
            "phase_coverage": phases,
            "files": [{"relative_path": evidence_ref, "sha256": evidence_sha, "size_bytes": 3, "redacted": true}]
        });
        let manifest_path = dir.join("manifest.json");
        std::fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        (root, manifest_path, evidence)
    }

    #[test]
    fn accepts_minimum_complete_digest_bound_update_matrix() {
        let (root, manifest, _) = fixture();
        validate_manifest(&manifest, true, None, None).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_evidence_tamper() {
        let (root, manifest, evidence) = fixture();
        std::fs::write(&evidence, b"tampered\n").unwrap();
        assert!(validate_manifest(&manifest, true, None, None).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_complete_matrix_missing_required_case() {
        let (root, manifest, _) = fixture();
        let mut document: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();
        document["cases"].as_array_mut().unwrap().pop();
        std::fs::write(&manifest, serde_json::to_vec_pretty(&document).unwrap()).unwrap();
        assert!(validate_manifest(&manifest, true, None, None).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_complete_matrix_without_representative_reboot() {
        let (root, manifest, _) = fixture();
        let mut document: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();
        document["phase_coverage"][0]["reboot"] = json!("not_run");
        std::fs::write(&manifest, serde_json::to_vec_pretty(&document).unwrap()).unwrap();
        assert!(validate_manifest(&manifest, true, None, None).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn accepts_nonpassing_optional_case_in_complete_matrix() {
        let (root, manifest, _) = fixture();
        let mut document: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();
        document["cases"].as_array_mut().unwrap().push(json!({
            "id": "update.seawork_uninstall",
            "status": "not_run",
            "duration_ms": 0,
            "stable_code": "optional-case-not-run",
            "evidence": ["evidence/results.redacted.json"]
        }));
        std::fs::write(&manifest, serde_json::to_vec_pretty(&document).unwrap()).unwrap();
        validate_manifest(&manifest, true, None, None).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
}
