use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_json::Value;

use crate::args::flag_value;

const PINNED_SEAWORK_COMMIT: &str = "0ae88c6d338ffb10d765296625ea38b3b3991f64";
const PINNED_LOCAL_SANDBOX_VERSION: &str = "0.4.6";
const TEST_RELEASE_SEAWORK_COMMIT: &str = "f9c6cd8ff339688a669451e36078d6cbbc91c1b2";
const TEST_RELEASE_LOCAL_SANDBOX_COMMIT: &str = "0470b57be237d181b04dbd558cec4eb2fddebd5c";
const TEST_RELEASE_CANDIDATE_VERSION: &str = "0.4.7-test.1";
const VALID_STATUSES: [&str; 3] = ["equivalent", "service-superset", "blocking"];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Contract {
    schema_version: u32,
    contract_id: String,
    baseline: Baseline,
    source_assertions: Vec<SourceAssertion>,
    start_fields: Vec<ParityEntry>,
    operations: Vec<ParityEntry>,
    mount_profiles: Vec<ParityEntry>,
    network_capabilities: Vec<ParityEntry>,
    lifecycle_behaviors: Vec<ParityEntry>,
    error_categories: Vec<ParityEntry>,
    limits: BTreeMap<String, Value>,
    golden_workloads: Vec<GoldenWorkload>,
    external_sign_off: Vec<ExternalSignOff>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Baseline {
    seawork_commit: String,
    local_sandbox_version: String,
    windows_target: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceAssertion {
    id: String,
    path: String,
    #[serde(default)]
    contains: Vec<String>,
    #[serde(default)]
    absent: Vec<String>,
    conclusion: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ParityEntry {
    id: String,
    reachable: bool,
    status: String,
    backlog: Option<String>,
    service_mapping: String,
    evidence: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GoldenWorkload {
    id: String,
    covers: Vec<String>,
    fixture: String,
    comparison: Vec<String>,
    status: String,
    backlog: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalSignOff {
    role: String,
    status: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TestReleaseContract {
    schema_version: u32,
    contract_id: String,
    baseline: TestReleaseBaseline,
    source_assertions: Vec<SourceAssertion>,
    operations: Vec<TestRequirement>,
    mount_profiles: Vec<TestMountRequirement>,
    network_capabilities: Vec<TestRequirement>,
    identities: TestReleaseIdentities,
    packaging: TestReleasePackaging,
    evidence: TestReleaseEvidence,
    unsupported_capabilities: Vec<UnsupportedCapability>,
    golden_workloads: Vec<TestGoldenWorkload>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TestReleaseBaseline {
    seawork_commit: String,
    local_sandbox_commit: String,
    candidate_version: String,
    windows_target: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TestRequirement {
    id: String,
    scope: String,
    evidence: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TestMountRequirement {
    id: String,
    scope: String,
    mount_type: String,
    guest_path: String,
    access: String,
    flags: u32,
    required_when: String,
    evidence: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TestReleaseIdentities {
    service_name: String,
    pipe_name: String,
    service_account: String,
    state_root: String,
    service_profile: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TestReleasePackaging {
    required_artifacts: Vec<String>,
    node_packages: Vec<String>,
    signing: TestReleaseSigning,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TestReleaseSigning {
    certificate: String,
    timestamp_required: bool,
    trusted_chain_required: bool,
    forbidden_flags: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TestReleaseEvidence {
    machine_readable_manifest: String,
    required_cases: Vec<String>,
    required_fields: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnsupportedCapability {
    id: String,
    test_scope: String,
    behavior: String,
    production_status_unchanged: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TestGoldenWorkload {
    id: String,
    covers: Vec<String>,
    fixture: String,
    comparison: Vec<String>,
    test_scope: String,
    production_status_unchanged: bool,
}

enum ContractDocument {
    Production(Box<Contract>),
    TestRelease(Box<TestReleaseContract>),
}

pub fn verify(args: &[String]) -> Result<()> {
    reject_unknown_flags(args)?;
    let contract_path = flag_value(args, "--contract")
        .map(PathBuf::from)
        .unwrap_or_else(default_contract_path);
    let contract = load_contract_document(&contract_path)?;
    let (contract_id, baseline_commit, source_assertions) = match &contract {
        ContractDocument::Production(contract) => {
            validate_contract(contract)?;
            validate_fixture_files(contract, &repository_root())?;
            (
                contract.contract_id.as_str(),
                contract.baseline.seawork_commit.as_str(),
                contract.source_assertions.as_slice(),
            )
        }
        ContractDocument::TestRelease(contract) => {
            validate_test_release_contract(contract)?;
            validate_test_release_fixture_files(contract, &repository_root())?;
            (
                contract.contract_id.as_str(),
                contract.baseline.seawork_commit.as_str(),
                contract.source_assertions.as_slice(),
            )
        }
    };

    if let Some(repository) = flag_value(args, "--seawork-repo") {
        verify_source_assertions(source_assertions, baseline_commit, Path::new(repository))?;
        println!(
            "verified {} and {} pinned SeaWork source assertions at {}",
            contract_id,
            source_assertions.len(),
            baseline_commit
        );
    } else {
        println!(
            "verified {} structure; pass --seawork-repo to re-check pinned source assertions",
            contract_id
        );
    }
    Ok(())
}

fn default_contract_path() -> PathBuf {
    repository_root()
        .join("contracts")
        .join("seawork-parity-v1.json")
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn reject_unknown_flags(args: &[String]) -> Result<()> {
    if !args.len().is_multiple_of(2) {
        bail!("all verify-seawork-parity flags require a value");
    }
    for pair in args.chunks_exact(2) {
        if !matches!(pair[0].as_str(), "--contract" | "--seawork-repo") {
            bail!("unknown verify-seawork-parity flag: {}", pair[0]);
        }
    }
    Ok(())
}

#[cfg(test)]
fn load_contract(path: &Path) -> Result<Contract> {
    let bytes = fs::read(path)
        .with_context(|| format!("failed to read parity contract {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse parity contract {}", path.display()))
}

fn load_contract_document(path: &Path) -> Result<ContractDocument> {
    let bytes = fs::read(path)
        .with_context(|| format!("failed to read parity contract {}", path.display()))?;
    let value: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse parity contract {}", path.display()))?;
    match value.get("contract_id").and_then(Value::as_str) {
        Some("seawork-production-parity-v1") => serde_json::from_value(value)
            .map(Box::new)
            .map(ContractDocument::Production)
            .with_context(|| format!("failed to parse parity contract {}", path.display())),
        Some("seawork-test-release-v1") => serde_json::from_value(value)
            .map(Box::new)
            .map(ContractDocument::TestRelease)
            .with_context(|| format!("failed to parse test-release contract {}", path.display())),
        _ => bail!("unsupported parity contract identity or schema version"),
    }
}

fn validate_contract(contract: &Contract) -> Result<()> {
    if contract.schema_version != 1 || contract.contract_id != "seawork-production-parity-v1" {
        bail!("unsupported parity contract identity or schema version");
    }
    if contract.baseline.seawork_commit != PINNED_SEAWORK_COMMIT
        || contract.baseline.local_sandbox_version != PINNED_LOCAL_SANDBOX_VERSION
        || contract.baseline.windows_target != "windows-11-x86_64"
    {
        bail!("parity baseline does not match the production decision record");
    }
    if contract.source_assertions.is_empty() {
        bail!("parity contract has no pinned-source assertions");
    }

    let mut ids = BTreeSet::new();
    for assertion in &contract.source_assertions {
        require_unique_id(&mut ids, &assertion.id)?;
        if assertion.path.is_empty()
            || (assertion.contains.is_empty() && assertion.absent.is_empty())
            || assertion.conclusion.is_empty()
        {
            bail!("source assertion {} is incomplete", assertion.id);
        }
    }

    let groups = [
        ("start_fields", &contract.start_fields),
        ("operations", &contract.operations),
        ("mount_profiles", &contract.mount_profiles),
        ("network_capabilities", &contract.network_capabilities),
        ("lifecycle_behaviors", &contract.lifecycle_behaviors),
        ("error_categories", &contract.error_categories),
    ];
    for (name, entries) in groups {
        if entries.is_empty() {
            bail!("parity group {name} is empty");
        }
        for entry in entries {
            require_unique_id(&mut ids, &entry.id)?;
            validate_status(&entry.id, &entry.status, entry.backlog.as_deref())?;
            if entry.service_mapping.is_empty() || entry.evidence.is_empty() {
                bail!("parity entry {} has no mapping or evidence", entry.id);
            }
            if !entry.reachable && entry.status != "service-superset" {
                bail!("unreachable entry {} must be a service-superset", entry.id);
            }
        }
    }

    validate_required_ids(&ids)?;
    validate_fixed_limits(&contract.limits)?;

    if contract.golden_workloads.is_empty() {
        bail!("parity contract has no golden workloads");
    }
    for workload in &contract.golden_workloads {
        require_unique_id(&mut ids, &workload.id)?;
        validate_status(&workload.id, &workload.status, workload.backlog.as_deref())?;
        if workload.covers.is_empty()
            || workload.fixture.is_empty()
            || workload.comparison.is_empty()
        {
            bail!("golden workload {} is incomplete", workload.id);
        }
    }

    let required_roles = [
        "seawork-product",
        "localsandbox",
        "windows-security",
        "installer",
    ];
    let roles: BTreeSet<&str> = contract
        .external_sign_off
        .iter()
        .map(|entry| entry.role.as_str())
        .collect();
    for role in required_roles {
        if !roles.contains(role) {
            bail!("missing required parity sign-off role: {role}");
        }
    }
    if contract
        .external_sign_off
        .iter()
        .any(|entry| entry.status != "external-verification-pending")
    {
        bail!("macOS parity contract must not claim external sign-off");
    }
    Ok(())
}

fn validate_test_release_contract(contract: &TestReleaseContract) -> Result<()> {
    if contract.schema_version != 1 || contract.contract_id != "seawork-test-release-v1" {
        bail!("unsupported test-release contract identity or schema version");
    }
    if contract.baseline.seawork_commit != TEST_RELEASE_SEAWORK_COMMIT
        || contract.baseline.local_sandbox_commit != TEST_RELEASE_LOCAL_SANDBOX_COMMIT
        || contract.baseline.candidate_version != TEST_RELEASE_CANDIDATE_VERSION
        || contract.baseline.windows_target != "windows-11-x86_64"
    {
        bail!("test-release baseline does not match the frozen sprint decision");
    }
    if contract.source_assertions.is_empty() {
        bail!("test-release contract has no pinned-source assertions");
    }

    let mut ids = BTreeSet::new();
    for assertion in &contract.source_assertions {
        require_unique_id(&mut ids, &assertion.id)?;
        if assertion.path.is_empty()
            || (assertion.contains.is_empty() && assertion.absent.is_empty())
            || assertion.conclusion.is_empty()
        {
            bail!("source assertion {} is incomplete", assertion.id);
        }
    }

    for requirement in contract
        .operations
        .iter()
        .chain(contract.network_capabilities.iter())
    {
        require_unique_id(&mut ids, &requirement.id)?;
        if requirement.scope != "required" || requirement.evidence.is_empty() {
            bail!(
                "in-scope test-release requirement {} must be required and have evidence",
                requirement.id
            );
        }
    }
    validate_test_release_required_ids(&ids)?;

    let required_mounts = [
        (
            "mount.workspace-ro",
            "/workspace",
            "read-only",
            1_u32,
            "always",
        ),
        (
            "mount.output-rw",
            "/workspace/output",
            "read-write",
            0,
            "workspace-present",
        ),
        (
            "mount.skills-ro",
            "caller-declared",
            "read-only",
            1,
            "active-agent",
        ),
        (
            "mount.uploaded-files-ro",
            "/uploaded_files",
            "read-only",
            1,
            "uploaded-files-present",
        ),
    ];
    if contract.mount_profiles.len() != required_mounts.len() {
        bail!("test-release contract must define exactly four direct mount profiles");
    }
    for (id, guest_path, access, flags, required_when) in required_mounts {
        let mount = contract
            .mount_profiles
            .iter()
            .find(|entry| entry.id == id)
            .with_context(|| format!("test-release contract is missing {id}"))?;
        require_unique_id(&mut ids, &mount.id)?;
        if mount.scope != "required"
            || mount.mount_type != "direct"
            || mount.guest_path != guest_path
            || mount.access != access
            || mount.flags != flags
            || mount.required_when != required_when
            || mount.evidence.is_empty()
        {
            bail!("test-release mount profile {id} does not match the frozen contract");
        }
    }

    let identities = &contract.identities;
    if identities.service_name != "LocalSandboxSeaWork"
        || identities.pipe_name != r"\\.\pipe\LocalSandbox.SeaWork.v1"
        || identities.service_account != "LocalSystem"
        || identities.state_root != r"%ProgramData%\LocalSandbox\SeaWork"
        || identities.service_profile != "production"
    {
        bail!("test-release production identities do not match the frozen contract");
    }

    let required_artifacts = [
        "service-zip",
        "symbols-zip",
        "SHA256SUMS",
        "bundle-manifest",
        "service-contract",
        "runtime-dependencies",
        "sbom-and-licenses",
        "seawork-test-release-manifest",
    ];
    require_exact_string_set(
        "test-release artifacts",
        &contract.packaging.required_artifacts,
        &required_artifacts,
    )?;
    require_exact_string_set(
        "test-release Node packages",
        &contract.packaging.node_packages,
        &[
            "@local-sandbox/lsb-nodejs",
            "@local-sandbox/lsb-nodejs-win32-x64-msvc",
        ],
    )?;
    let signing = &contract.packaging.signing;
    if signing.certificate != "SeaWork-CodeSign.pfx"
        || !signing.timestamp_required
        || !signing.trusted_chain_required
        || signing.forbidden_flags != ["-AllowUntrustedTestCertificate", "-SkipTimestamp"]
    {
        bail!("test-release signing requirements do not match the production path");
    }

    if contract.evidence.machine_readable_manifest != "seawork-test-release-manifest.json"
        || contract.evidence.required_cases.is_empty()
        || contract.evidence.required_fields.is_empty()
    {
        bail!("test-release evidence requirements are incomplete");
    }

    for capability in &contract.unsupported_capabilities {
        require_unique_id(&mut ids, &capability.id)?;
        if capability.test_scope != "out-of-scope"
            || capability.behavior.is_empty()
            || !capability.production_status_unchanged
        {
            bail!(
                "unsupported capability {} must remain explicitly out of test scope",
                capability.id
            );
        }
    }
    require_exact_string_set(
        "out-of-scope capabilities",
        &contract
            .unsupported_capabilities
            .iter()
            .map(|entry| entry.id.clone())
            .collect::<Vec<_>>(),
        &[
            "checkpoint",
            "ports",
            "network.expose-host",
            "mount.overlay",
            "host-connectivity",
            "exhaustive-lost-start-crash-recovery",
        ],
    )?;

    let required_workloads = [
        "golden.workspace-shell",
        "golden.skills-files",
        "golden.network-public-auth",
    ];
    let out_of_scope_workloads = ["golden.host-connectivity", "golden.start-loss-recovery"];
    for workload in &contract.golden_workloads {
        require_unique_id(&mut ids, &workload.id)?;
        if workload.covers.is_empty()
            || workload.fixture.is_empty()
            || workload.comparison.is_empty()
            || !workload.production_status_unchanged
        {
            bail!("test-release golden workload {} is incomplete", workload.id);
        }
        let expected_scope = if required_workloads.contains(&workload.id.as_str()) {
            "required"
        } else if out_of_scope_workloads.contains(&workload.id.as_str()) {
            "out-of-scope"
        } else {
            bail!("unexpected test-release golden workload {}", workload.id);
        };
        if workload.test_scope != expected_scope {
            bail!(
                "test-release golden workload {} has the wrong scope",
                workload.id
            );
        }
    }
    if contract.golden_workloads.len() != required_workloads.len() + out_of_scope_workloads.len() {
        bail!("test-release contract must classify all five production golden workloads");
    }
    Ok(())
}

fn validate_test_release_required_ids(ids: &BTreeSet<String>) -> Result<()> {
    let required = [
        "op.connect",
        "op.service-info",
        "op.health",
        "op.start",
        "op.stop",
        "op.exec",
        "op.spawn",
        "op.kill-process",
        "op.read-file",
        "op.write-file",
        "op.mkdir",
        "op.cancel-cleanup",
        "network.dns",
        "network.public-http",
        "network.public-https",
        "network.package-download",
        "network.scoped-secret",
        "network.private-link-local-denial",
    ];
    for id in required {
        if !ids.contains(id) {
            bail!("test-release contract is missing required entry {id}");
        }
    }
    Ok(())
}

fn require_exact_string_set(name: &str, actual: &[String], expected: &[&str]) -> Result<()> {
    let actual: BTreeSet<&str> = actual.iter().map(String::as_str).collect();
    let expected: BTreeSet<&str> = expected.iter().copied().collect();
    if actual != expected {
        bail!("{name} do not match the frozen test-release contract");
    }
    Ok(())
}

fn require_unique_id(ids: &mut BTreeSet<String>, id: &str) -> Result<()> {
    if id.is_empty() || !ids.insert(id.to_string()) {
        bail!("parity identifiers must be non-empty and unique: {id}");
    }
    Ok(())
}

fn validate_status(id: &str, status: &str, backlog: Option<&str>) -> Result<()> {
    if !VALID_STATUSES.contains(&status) {
        bail!("parity entry {id} has invalid status {status}");
    }
    if status == "blocking" && backlog.is_none() {
        bail!("blocking parity entry {id} has no backlog link");
    }
    if status != "blocking" && backlog.is_some() {
        bail!("non-blocking parity entry {id} must not claim a backlog blocker");
    }
    Ok(())
}

fn validate_required_ids(ids: &BTreeSet<String>) -> Result<()> {
    let required = [
        "start.instance-id",
        "start.from",
        "start.cpus",
        "start.memory-mib",
        "start.disk-size-mib",
        "start.data-dir",
        "start.ports",
        "start.mounts",
        "start.network",
        "op.start",
        "op.exec",
        "op.spawn",
        "op.read-file",
        "op.write-file",
        "op.mkdir",
        "op.kill-process",
        "op.stop",
        "mount.workspace-ro",
        "mount.output-rw",
        "mount.skills-ro",
        "mount.overlay",
        "network.default-public",
        "network.allow",
        "network.secrets",
        "network.https-interception",
        "network.request-headers",
        "network.expose-host",
        "network.ports",
        "lifecycle.at-most-once-start",
        "lifecycle.disconnect",
        "lifecycle.reboot-update-repair",
    ];
    for id in required {
        if !ids.contains(id) {
            bail!("parity contract is missing required entry {id}");
        }
    }
    Ok(())
}

fn validate_fixed_limits(limits: &BTreeMap<String, Value>) -> Result<()> {
    let expected = [
        ("connections_global", 32_u64),
        ("connections_per_user", 4),
        ("sandboxes_global", 8),
        ("sandboxes_per_user", 4),
        ("sandboxes_per_connection", 2),
        ("sandbox_cpus_min", 1),
        ("sandbox_cpus_max", 8),
        ("sandbox_memory_mib_min", 512),
        ("sandbox_memory_mib_max", 8192),
        ("sandbox_disk_mib_min", 1024),
        ("sandbox_disk_mib_max", 32768),
        ("processes_per_sandbox", 64),
        ("processes_per_user", 128),
        ("processes_global", 256),
        ("watches_per_sandbox", 64),
        ("watches_per_user", 128),
        ("watches_global", 512),
        ("watch_events_queued", 256),
        ("active_rpcs_per_connection", 16),
        ("active_rpcs_global", 64),
        ("control_payload_bytes", 262144),
        ("stream_frame_bytes", 65536),
        ("string_bytes", 32768),
        ("json_depth", 32),
        ("unary_output_bytes", 8388608),
        ("environment_bytes", 131072),
        ("file_transfer_bytes", 67108864),
        ("initial_credit_bytes", 262144),
        ("process_credit_bytes", 4194304),
        ("stalled_consumer_seconds", 30),
        ("boot_seconds", 120),
        ("unary_default_seconds", 30),
        ("server_max_seconds", 600),
        ("stop_seconds", 30),
        ("preshutdown_seconds", 60),
    ];
    for (name, expected_value) in expected {
        let actual = limits.get(name).and_then(Value::as_u64);
        if actual != Some(expected_value) {
            bail!("fixed limit {name} must be {expected_value}, got {actual:?}");
        }
    }
    Ok(())
}

fn validate_fixture_files(contract: &Contract, repository: &Path) -> Result<()> {
    for workload in &contract.golden_workloads {
        validate_fixture_file(repository, &workload.fixture, &workload.id)?;
    }
    Ok(())
}

fn validate_test_release_fixture_files(
    contract: &TestReleaseContract,
    repository: &Path,
) -> Result<()> {
    for workload in &contract.golden_workloads {
        validate_fixture_file(repository, &workload.fixture, &workload.id)?;
    }
    Ok(())
}

fn validate_fixture_file(repository: &Path, fixture: &str, workload_id: &str) -> Result<()> {
    let path = repository.join(fixture);
    let value: Value = serde_json::from_slice(
        &fs::read(&path)
            .with_context(|| format!("failed to read golden fixture {}", path.display()))?,
    )
    .with_context(|| format!("failed to parse golden fixture {}", path.display()))?;
    if value.get("schema_version").and_then(Value::as_u64) != Some(1)
        || value.get("workload_id").and_then(Value::as_str) != Some(workload_id)
    {
        bail!(
            "golden fixture {} has the wrong schema or workload id",
            path.display()
        );
    }
    if value
        .get("steps")
        .and_then(Value::as_array)
        .is_none_or(Vec::is_empty)
        || value
            .get("assertions")
            .and_then(Value::as_array)
            .is_none_or(Vec::is_empty)
    {
        bail!(
            "golden fixture {} has no steps or assertions",
            path.display()
        );
    }
    Ok(())
}

fn verify_source_assertions(
    assertions: &[SourceAssertion],
    baseline_commit: &str,
    repository: &Path,
) -> Result<()> {
    run_git(
        repository,
        &["cat-file", "-e", &format!("{baseline_commit}^{{commit}}")],
    )?;
    for assertion in assertions {
        let object = format!("{}:{}", baseline_commit, assertion.path);
        let source = run_git(repository, &["show", &object])?;
        for needle in &assertion.contains {
            if !source.contains(needle) {
                bail!(
                    "pinned-source assertion {} failed: {} no longer contains {:?}",
                    assertion.id,
                    assertion.path,
                    needle
                );
            }
        }
        for needle in &assertion.absent {
            if source.contains(needle) {
                bail!(
                    "pinned-source assertion {} failed: {} unexpectedly contains {:?}",
                    assertion.id,
                    assertion.path,
                    needle
                );
            }
        }
    }
    Ok(())
}

fn run_git(repository: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(args)
        .output()
        .with_context(|| format!("failed to execute git in {}", repository.display()))?;
    if !output.status.success() {
        bail!(
            "git {} failed in {}: {}",
            args.join(" "),
            repository.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    String::from_utf8(output.stdout).context("git output was not UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_contract_is_complete_and_uses_fixed_decisions() {
        let contract = load_contract(&default_contract_path()).expect("contract should parse");
        validate_contract(&contract).expect("contract should satisfy the parity schema");
        validate_fixture_files(&contract, &repository_root())
            .expect("golden fixtures should satisfy the fixture schema");
    }

    #[test]
    fn committed_test_release_contract_is_complete_and_uses_fixed_decisions() {
        let path = repository_root()
            .join("contracts")
            .join("seawork-test-release-v1.json");
        let ContractDocument::TestRelease(contract) =
            load_contract_document(&path).expect("test-release contract should parse")
        else {
            panic!("expected the test-release contract");
        };
        validate_test_release_contract(&contract)
            .expect("test-release contract should satisfy the frozen schema");
        validate_test_release_fixture_files(&contract, &repository_root())
            .expect("test-release fixtures should satisfy the fixture schema");
    }

    #[test]
    fn blocking_status_requires_a_backlog_link() {
        let error = validate_status("test", "blocking", None).expect_err("link is mandatory");
        assert!(error.to_string().contains("no backlog link"));
    }
}
