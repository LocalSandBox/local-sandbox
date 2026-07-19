use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Component, Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const SCHEMA_VERSION: u32 = 1;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_EVIDENCE_FILES: usize = 256;
const MAX_CHECKS: usize = 128;

const FULL_CHECKS: &[&str] = &[
    "con01.job_containment",
    "ent01.managed_policy",
    "mnt01.admin_live",
    "mnt01.nonadmin_staged",
    "net01.managed_network",
    "net02.host_relay",
    "net02.ports_wfp",
    "obs01.event_log",
    "rel01.artifact_trust",
    "sec01.endpoint_auth",
    "sec02.reconciliation",
    "tst01.adversarial",
    "tst02.lifecycle",
    "win01.scm_lifecycle",
    "win01.service_identity_session0",
    "win01.standard_user_no_uac",
    "win01.two_users_two_logons",
    "win01.whpx_qemu_boot_exec_stop",
];

const WIN01_CHECKS: &[&str] = &[
    "con01.job_containment",
    "mnt01.admin_live",
    "mnt01.nonadmin_staged",
    "net01.managed_network",
    "net02.host_relay",
    "net02.ports_wfp",
    "obs01.event_log",
    "sec01.endpoint_auth",
    "sec02.reconciliation",
    "win01.scm_lifecycle",
    "win01.service_identity_session0",
    "win01.standard_user_no_uac",
    "win01.two_users_two_logons",
    "win01.whpx_qemu_boot_exec_stop",
];

const SECURITY_CHECKS: &[&str] = &[
    "con01.job_containment",
    "mnt01.admin_live",
    "mnt01.nonadmin_staged",
    "net02.host_relay",
    "net02.ports_wfp",
    "sec01.endpoint_auth",
    "sec02.reconciliation",
    "tst01.adversarial",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    git_sha: String,
    artifact_sha256: String,
    artifact_size_bytes: u64,
    profile: String,
    generated_utc: String,
    environment: Environment,
    checks: Vec<Check>,
    files: Vec<EvidenceFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Environment {
    os_build: String,
    architecture: String,
    service_version: String,
    bundle_version: String,
    qemu_version: String,
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
    let mut require_complete = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--manifest" => {
                index += 1;
                manifest = args.get(index).map(PathBuf::from);
            }
            "--require-complete" => require_complete = true,
            other => bail!("unknown verify-windows-evidence argument: {other}"),
        }
        index += 1;
    }
    let manifest = manifest.context("--manifest is required")?;
    validate_manifest(&manifest, require_complete)?;
    println!("verified Windows evidence manifest {}", manifest.display());
    Ok(())
}

fn validate_manifest(path: &Path, require_complete: bool) -> Result<()> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("read evidence manifest metadata {}", path.display()))?;
    if !metadata.is_file() || metadata.len() > MAX_MANIFEST_BYTES {
        bail!("evidence manifest is not a bounded regular file");
    }
    let bytes = std::fs::read(path).context("read evidence manifest")?;
    let manifest: Manifest = serde_json::from_slice(&bytes).context("parse evidence manifest")?;
    validate_shape(path, &manifest, require_complete)
}

fn validate_shape(path: &Path, manifest: &Manifest, require_complete: bool) -> Result<()> {
    if manifest.schema_version != SCHEMA_VERSION {
        bail!("unsupported Windows evidence schema");
    }
    require_hex(&manifest.git_sha, 40, "git_sha")?;
    require_hex(&manifest.artifact_sha256, 64, "artifact_sha256")?;
    if manifest.artifact_size_bytes == 0 {
        bail!("artifact_size_bytes must be nonzero");
    }
    let parent = path
        .parent()
        .context("manifest has no evidence directory")?;
    let artifact_dir = parent
        .file_name()
        .and_then(|value| value.to_str())
        .context("evidence artifact directory is invalid")?;
    let git_dir = parent
        .parent()
        .and_then(Path::file_name)
        .and_then(|value| value.to_str())
        .context("evidence git directory is invalid")?;
    if artifact_dir != manifest.artifact_sha256 || git_dir != manifest.git_sha {
        bail!("evidence layout does not match manifest git/artifact digests");
    }
    validate_environment(&manifest.environment)?;
    if manifest.generated_utc.len() < 20 || manifest.generated_utc.len() > 64 {
        bail!("generated_utc is not a bounded timestamp");
    }

    if manifest.files.is_empty() || manifest.files.len() > MAX_EVIDENCE_FILES {
        bail!("evidence file count is outside bounds");
    }
    let mut files = BTreeMap::new();
    for file in &manifest.files {
        let relative = safe_relative(&file.relative_path)?;
        let folded = file.relative_path.to_ascii_lowercase();
        if files.insert(folded, file).is_some() {
            bail!("duplicate or case-colliding evidence file");
        }
        if !file.redacted {
            bail!("evidence file is not declared redacted");
        }
        require_hex(&file.sha256, 64, "file sha256")?;
        let evidence_path = parent.join(relative);
        let metadata = std::fs::symlink_metadata(&evidence_path)
            .with_context(|| format!("inspect evidence file {}", evidence_path.display()))?;
        if !metadata.file_type().is_file() || metadata.len() != file.size_bytes {
            bail!("evidence file type/size mismatch: {}", file.relative_path);
        }
        if sha256_file(&evidence_path)? != file.sha256 {
            bail!("evidence file digest mismatch: {}", file.relative_path);
        }
    }

    if manifest.checks.is_empty() || manifest.checks.len() > MAX_CHECKS {
        bail!("evidence check count is outside bounds");
    }
    let required = profile_checks(&manifest.profile)?;
    let known = FULL_CHECKS.iter().copied().collect::<BTreeSet<_>>();
    let mut checks = BTreeMap::new();
    for check in &manifest.checks {
        if !known.contains(check.id.as_str()) || checks.insert(check.id.as_str(), check).is_some() {
            bail!("unknown or duplicate evidence check: {}", check.id);
        }
        if check.duration_ms > 24 * 60 * 60 * 1000 {
            bail!(
                "check duration exceeds the one-day evidence bound: {}",
                check.id
            );
        }
        if check.status != Status::Passed && check.stable_code.as_deref().is_none_or(str::is_empty)
        {
            bail!("non-passing check lacks a stable_code: {}", check.id);
        }
        if let Some(code) = &check.stable_code {
            require_safe_token(code, 64, "stable_code")?;
        }
        if check.evidence.is_empty() {
            bail!("check has no evidence references: {}", check.id);
        }
        for evidence in &check.evidence {
            safe_relative(evidence)?;
            if !files.contains_key(&evidence.to_ascii_lowercase()) {
                bail!("check references an unlisted evidence file: {evidence}");
            }
        }
    }
    for id in required {
        let check = checks.get(id).with_context(|| {
            format!(
                "profile {} is missing required check {id}",
                manifest.profile
            )
        })?;
        if require_complete && check.status != Status::Passed {
            bail!("required check did not pass: {id}");
        }
    }
    if require_complete && checks.values().any(|check| check.status != Status::Passed) {
        bail!("complete evidence contains a non-passing check");
    }
    Ok(())
}

fn validate_environment(environment: &Environment) -> Result<()> {
    for (name, value) in [
        ("os_build", &environment.os_build),
        ("architecture", &environment.architecture),
        ("service_version", &environment.service_version),
        ("bundle_version", &environment.bundle_version),
        ("qemu_version", &environment.qemu_version),
    ] {
        require_safe_token(value, 128, name)?;
    }
    if environment.architecture != "x86_64" {
        bail!("evidence architecture is not x86_64");
    }
    require_hex(
        &environment.runner_identity_sha256,
        64,
        "runner identity hash",
    )?;
    require_hex(&environment.policy_sha256, 64, "policy hash")
}

fn profile_checks(profile: &str) -> Result<&'static [&'static str]> {
    match profile {
        "win01" => Ok(WIN01_CHECKS),
        "security" => Ok(SECURITY_CHECKS),
        "full" => Ok(FULL_CHECKS),
        _ => bail!("unknown Windows evidence profile"),
    }
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

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    fn fixture(status: &str) -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "lsbsw-evidence-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        let git_sha = "a".repeat(40);
        let artifact_sha = "b".repeat(64);
        let directory = root.join(&git_sha).join(&artifact_sha);
        std::fs::create_dir_all(&directory).unwrap();
        let evidence_path = directory.join("results.json");
        std::fs::write(&evidence_path, b"{}\n").unwrap();
        let digest = sha256_file(&evidence_path).unwrap();
        let stable_code = if status == "passed" {
            serde_json::Value::Null
        } else {
            json!("EXTERNAL_VERIFICATION_PENDING")
        };
        let checks = SECURITY_CHECKS
            .iter()
            .map(|id| {
                json!({
                    "id": id,
                    "status": status,
                    "duration_ms": 1,
                    "stable_code": stable_code,
                    "evidence": ["results.json"]
                })
            })
            .collect::<Vec<_>>();
        let manifest = json!({
            "schema_version": 1,
            "git_sha": git_sha,
            "artifact_sha256": artifact_sha,
            "artifact_size_bytes": 1,
            "profile": "security",
            "generated_utc": "2026-07-20T00:00:00Z",
            "environment": {
                "os_build": "26100.1",
                "architecture": "x86_64",
                "service_version": "0.4.6",
                "bundle_version": "0.4.6",
                "qemu_version": "11.0.50",
                "runner_identity_sha256": "c".repeat(64),
                "policy_sha256": "d".repeat(64)
            },
            "checks": checks,
            "files": [{
                "relative_path": "results.json",
                "sha256": digest,
                "size_bytes": 3,
                "redacted": true
            }]
        });
        let manifest_path = directory.join("manifest.json");
        std::fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        (root, manifest_path)
    }

    #[test]
    fn accepts_digest_bound_redacted_security_evidence() {
        let (root, manifest) = fixture("passed");
        validate_manifest(&manifest, true).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn incomplete_profile_validates_shape_but_not_release_completeness() {
        let (root, manifest) = fixture("blocked");
        validate_manifest(&manifest, false).unwrap();
        assert!(validate_manifest(&manifest, true).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_evidence_tamper_after_manifest_creation() {
        let (root, manifest) = fixture("passed");
        std::fs::write(
            manifest.parent().unwrap().join("results.json"),
            b"tampered\n",
        )
        .unwrap();
        assert!(validate_manifest(&manifest, false).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
