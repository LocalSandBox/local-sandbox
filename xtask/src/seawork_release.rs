use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Component, Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use lsb_platform::PlatformSpec;
use lsb_service_proto::{CURRENT, SUPPORTED};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::args::{flag_value, required_flag_value};
use crate::context::copy_file;

const BUNDLE_SCHEMA_VERSION: u32 = 1;
const SERVICE_CONTRACT_SCHEMA_VERSION: u32 = 1;
const SERVICE_CONFIGURATION_REVISION: u32 = 1;
const LEDGER_SCHEMA_VERSION: u32 = 1;
const MAX_BUNDLE_FILES: usize = 10_000;
const MAX_BUNDLE_BYTES: u64 = 16 * 1024 * 1024 * 1024;

#[derive(Debug, Serialize)]
struct BundleManifest {
    schema_version: u32,
    local_sandbox_version: String,
    service_version: String,
    client_version: String,
    protocol: ProtocolContract,
    ledger: LedgerContract,
    architecture: &'static str,
    target: &'static str,
    guest_asset_version: String,
    qemu: QemuContract,
    service_configuration_revision: u32,
    publisher: PublisherContract,
    files: Vec<BundleFile>,
}

#[derive(Debug, Serialize)]
struct ProtocolContract {
    major: u16,
    current_minor: u16,
    supported_min_minor: u16,
    supported_max_minor: u16,
}

#[derive(Debug, Serialize)]
struct LedgerContract {
    reader_min_schema: u32,
    reader_max_schema: u32,
    writer_schema: u32,
}

#[derive(Debug, Serialize)]
struct QemuContract {
    package_version: &'static str,
    qemu_version: &'static str,
    package_revision: &'static str,
    artifact_sha256: &'static str,
}

#[derive(Debug, Serialize)]
struct PublisherContract {
    subject: String,
    sha256_thumbprint: String,
}

#[derive(Debug, Serialize)]
struct BundleFile {
    path: String,
    size_bytes: u64,
    sha256: String,
}

#[derive(Debug, Serialize)]
struct ServiceContract {
    schema_version: u32,
    revision: u32,
    service: ServiceConfiguration,
    ipc: IpcConfiguration,
    filesystem: FilesystemConfiguration,
    health: HealthConfiguration,
    install_state_schema: u32,
}

#[derive(Debug, Serialize)]
struct ServiceConfiguration {
    name: &'static str,
    display_name: &'static str,
    description: &'static str,
    service_type: &'static str,
    account: &'static str,
    start: &'static str,
    delayed_auto_start: bool,
    binary_path_template: &'static str,
    dependencies: Vec<String>,
    service_sid_type: &'static str,
    service_object_sddl: &'static str,
    accepted_controls: Vec<&'static str>,
    preshutdown_timeout_ms: u32,
    failure_restart_delays_ms: Vec<u32>,
    failure_reset_period_seconds: u32,
    failure_actions_on_non_crash_failures: bool,
    event_source: &'static str,
}

#[derive(Debug, Serialize)]
struct IpcConfiguration {
    pipe_name: &'static str,
    pipe_sddl: &'static str,
    remote_clients_allowed: bool,
    protocol: ProtocolContract,
}

#[derive(Debug, Serialize)]
struct FilesystemConfiguration {
    version_root_template: &'static str,
    state_root: &'static str,
    program_files_sddl: &'static str,
    program_data_sddl: &'static str,
}

#[derive(Debug, Serialize)]
struct HealthConfiguration {
    required_checks: Vec<&'static str>,
    ports_available_only_with_wfp_evidence: bool,
}

pub fn stage_bundle(
    args: &[String],
    platform: &PlatformSpec,
    raw_version: &str,
    workspace_root: &Path,
    output_dir: &Path,
) -> Result<()> {
    if platform.id != "windows-x86_64" {
        bail!("the SeaWork service artifact supports only windows-x86_64");
    }
    let version = normalize_version(raw_version)?;
    let service_binary = input_file(args, "--service-binary", workspace_root)?;
    if service_binary.file_name().and_then(|name| name.to_str())
        != Some("localsandbox-seawork-service.exe")
    {
        bail!("--service-binary must name localsandbox-seawork-service.exe");
    }
    let runtime_dir = input_directory(args, "--runtime-dir", workspace_root)?;
    let qemu_dir = input_directory(args, "--qemu-dir", workspace_root)?;
    let sbom = input_file(args, "--sbom", workspace_root)?;
    let licenses = input_directory(args, "--licenses", workspace_root)?;
    let publisher_subject = required_flag_value(args, "--publisher-subject")?.trim();
    if publisher_subject.is_empty() || publisher_subject.len() > 512 {
        bail!("--publisher-subject must be between 1 and 512 characters");
    }
    let publisher_thumbprint =
        normalize_sha256_thumbprint(required_flag_value(args, "--publisher-thumbprint")?)?;

    for required in ["Image", "initramfs.cpio.gz", "rootfs.ext4"] {
        require_regular_file(&runtime_dir.join(required))
            .with_context(|| format!("runtime asset {required} is unavailable"))?;
    }
    for required in ["qemu-system-x86_64.exe", "qemu-img.exe"] {
        require_regular_file(&qemu_dir.join(required))
            .with_context(|| format!("managed QEMU file {required} is unavailable"))?;
    }

    let stage_dir = if let Some(path) = flag_value(args, "--stage-dir") {
        resolve_input(workspace_root, path)
    } else {
        output_dir.join(format!(
            "lsb-seawork-service-v{version}-windows-x86_64-stage"
        ))
    };
    if stage_dir.exists() {
        bail!(
            "refusing to overwrite existing stage {}",
            stage_dir.display()
        );
    }
    let bundle_root = stage_dir.join("LocalSandbox");
    fs::create_dir_all(&bundle_root)
        .with_context(|| format!("failed to create {}", bundle_root.display()))?;

    copy_file(
        &service_binary,
        &bundle_root.join("bin/localsandbox-seawork-service.exe"),
    )?;
    for asset in ["Image", "initramfs.cpio.gz", "rootfs.ext4"] {
        copy_file(
            &runtime_dir.join(asset),
            &bundle_root.join("runtime").join(asset),
        )?;
    }
    fs::write(bundle_root.join("runtime/VERSION"), format!("{version}\n"))?;
    copy_tree(&qemu_dir, &bundle_root.join("tools/qemu"))?;
    copy_file(&sbom, &bundle_root.join("manifests/sbom.spdx.json"))?;
    copy_tree(&licenses, &bundle_root.join("licenses"))?;

    let contract = service_contract();
    write_json(
        &bundle_root.join("manifests/service-contract.json"),
        &contract,
    )?;
    let files = inventory_bundle(&bundle_root)?;
    let qemu = lsb_platform::windows_x86_64::host_tools::managed_qemu_package_metadata();
    let manifest = BundleManifest {
        schema_version: BUNDLE_SCHEMA_VERSION,
        local_sandbox_version: version.clone(),
        service_version: version.clone(),
        client_version: version.clone(),
        protocol: protocol_contract(),
        ledger: LedgerContract {
            reader_min_schema: LEDGER_SCHEMA_VERSION,
            reader_max_schema: LEDGER_SCHEMA_VERSION,
            writer_schema: LEDGER_SCHEMA_VERSION,
        },
        architecture: "x86_64",
        target: "x86_64-pc-windows-msvc",
        guest_asset_version: version,
        qemu: QemuContract {
            package_version: qemu.package_version,
            qemu_version: qemu.qemu_version,
            package_revision: qemu.package_revision,
            artifact_sha256: qemu.artifact_sha256,
        },
        service_configuration_revision: SERVICE_CONFIGURATION_REVISION,
        publisher: PublisherContract {
            subject: publisher_subject.to_string(),
            sha256_thumbprint: publisher_thumbprint,
        },
        files,
    };
    write_json(&bundle_root.join("manifests/bundle.json"), &manifest)?;
    println!("staged SeaWork service bundle at {}", stage_dir.display());
    Ok(())
}

fn service_contract() -> ServiceContract {
    ServiceContract {
        schema_version: SERVICE_CONTRACT_SCHEMA_VERSION,
        revision: SERVICE_CONFIGURATION_REVISION,
        service: ServiceConfiguration {
            name: "LocalSandboxSeaWork",
            display_name: "LocalSandbox for SeaWork",
            description:
                "Runs LocalSandbox virtual machines for locally signed SeaWork desktop clients.",
            service_type: "SERVICE_WIN32_OWN_PROCESS",
            account: "LocalSystem",
            start: "automatic",
            delayed_auto_start: true,
            binary_path_template: "%ProgramFiles%\\SeaWork\\LocalSandbox\\versions\\<version>\\bin\\localsandbox-seawork-service.exe --service",
            dependencies: Vec::new(),
            service_sid_type: "SERVICE_SID_TYPE_UNRESTRICTED",
            service_object_sddl: "O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00000005;;;IU)",
            accepted_controls: vec!["STOP", "PRESHUTDOWN"],
            preshutdown_timeout_ms: 60_000,
            failure_restart_delays_ms: vec![5_000, 30_000, 120_000],
            failure_reset_period_seconds: 86_400,
            failure_actions_on_non_crash_failures: true,
            event_source: "LocalSandboxSeaWork",
        },
        ipc: IpcConfiguration {
            pipe_name: r"\\.\pipe\LocalSandbox.SeaWork.v1",
            pipe_sddl: "O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;IU)(A;;0x00000002;;;IU)S:(ML;;NW;;;ME)",
            remote_clients_allowed: false,
            protocol: protocol_contract(),
        },
        filesystem: FilesystemConfiguration {
            version_root_template: "%ProgramFiles%\\SeaWork\\LocalSandbox\\versions\\<version>",
            state_root: "%ProgramData%\\LocalSandbox\\SeaWork",
            program_files_sddl: "O:BAG:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;<SERVICE_SID>)(A;OICI;FRFX;;;BU)",
            program_data_sddl: "O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;<SERVICE_SID>)",
        },
        health: HealthConfiguration {
            required_checks: vec![
                "publisher",
                "bundle_version",
                "protocol_intersection",
                "ledger_schema",
                "protected_path_acls",
                "whpx",
                "guest_assets",
                "managed_qemu",
            ],
            ports_available_only_with_wfp_evidence: true,
        },
        install_state_schema: 1,
    }
}

fn protocol_contract() -> ProtocolContract {
    ProtocolContract {
        major: CURRENT.major,
        current_minor: CURRENT.minor,
        supported_min_minor: SUPPORTED.min_minor,
        supported_max_minor: SUPPORTED.max_minor,
    }
}

fn inventory_bundle(root: &Path) -> Result<Vec<BundleFile>> {
    let mut paths = Vec::new();
    collect_files(root, root, &mut paths)?;
    let mut normalized = BTreeMap::new();
    let mut total_bytes = 0u64;
    let mut files = Vec::new();
    for path in paths {
        let relative = path
            .strip_prefix(root)
            .context("bundle inventory escaped its root")?;
        let relative = archive_path(relative)?;
        if matches!(
            relative.as_str(),
            "manifests/bundle.json" | "manifests/LocalSandboxSeaWork.cat"
        ) {
            continue;
        }
        let folded = relative.to_ascii_lowercase();
        if let Some(existing) = normalized.insert(folded, relative.clone()) {
            bail!("case-insensitive bundle path collision: {existing} and {relative}");
        }
        let size_bytes = fs::metadata(&path)?.len();
        total_bytes = total_bytes
            .checked_add(size_bytes)
            .context("bundle expanded size overflow")?;
        if total_bytes > MAX_BUNDLE_BYTES {
            bail!("bundle exceeds maximum expanded size");
        }
        files.push(BundleFile {
            path: relative,
            size_bytes,
            sha256: sha256_file(&path)?,
        });
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    if files.is_empty() || files.len() > MAX_BUNDLE_FILES {
        bail!("bundle file count is outside the supported range");
    }
    Ok(files)
}

fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    let mut files = Vec::new();
    collect_files(source, source, &mut files)?;
    if files.is_empty() {
        bail!("input directory is empty: {}", source.display());
    }
    for path in files {
        let relative = path
            .strip_prefix(source)
            .context("source tree escaped its root")?;
        archive_path(relative)?;
        copy_file(&path, &destination.join(relative))?;
    }
    Ok(())
}

fn collect_files(root: &Path, directory: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    require_directory(directory)?;
    let mut entries = fs::read_dir(directory)
        .with_context(|| format!("failed to read {}", directory.display()))?
        .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        reject_reparse(&path, &metadata)?;
        if metadata.is_dir() {
            collect_files(root, &path, files)?;
        } else if metadata.is_file() {
            if files.len() >= MAX_BUNDLE_FILES {
                bail!("input tree exceeds maximum file count");
            }
            path.strip_prefix(root)
                .context("input path escaped its root")?;
            files.push(path);
        } else {
            bail!(
                "input tree contains a non-regular entry: {}",
                path.display()
            );
        }
    }
    Ok(())
}

fn archive_path(path: &Path) -> Result<String> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        bail!("bundle path must be non-empty and relative");
    }
    let mut segments = Vec::new();
    for component in path.components() {
        let Component::Normal(segment) = component else {
            bail!("bundle path contains traversal or a root prefix");
        };
        let segment = segment
            .to_str()
            .ok_or_else(|| anyhow!("bundle path is not UTF-8"))?;
        if segment.is_empty()
            || segment == "."
            || segment == ".."
            || segment.contains([':', '\\', '/', '\0'])
        {
            bail!("bundle path contains an unsafe segment");
        }
        segments.push(segment);
    }
    if segments.is_empty() {
        bail!("bundle path must contain a filename");
    }
    Ok(segments.join("/"))
}

fn input_file(args: &[String], flag: &str, workspace_root: &Path) -> Result<PathBuf> {
    let path = resolve_input(workspace_root, required_flag_value(args, flag)?);
    require_regular_file(&path).with_context(|| format!("invalid {flag}"))?;
    Ok(path)
}

fn input_directory(args: &[String], flag: &str, workspace_root: &Path) -> Result<PathBuf> {
    let path = resolve_input(workspace_root, required_flag_value(args, flag)?);
    require_directory(&path).with_context(|| format!("invalid {flag}"))?;
    Ok(path)
}

fn resolve_input(workspace_root: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        workspace_root.join(path)
    }
}

fn require_regular_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    reject_reparse(path, &metadata)?;
    if !metadata.is_file() {
        bail!("path is not a regular file: {}", path.display());
    }
    Ok(())
}

fn require_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    reject_reparse(path, &metadata)?;
    if !metadata.is_dir() {
        bail!("path is not a directory: {}", path.display());
    }
    Ok(())
}

fn reject_reparse(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    if metadata.file_type().is_symlink() || has_reparse_attribute(metadata) {
        bail!(
            "reparse entries are not allowed in bundle inputs: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(windows)]
fn has_reparse_attribute(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn has_reparse_attribute(_metadata: &fs::Metadata) -> bool {
    false
}

fn normalize_version(raw: &str) -> Result<String> {
    let version = raw.strip_prefix('v').unwrap_or(raw);
    if version.is_empty()
        || version.len() > 64
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
        || !version
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_digit())
    {
        bail!("release version is not a bounded SemVer-like value");
    }
    Ok(version.to_string())
}

fn normalize_sha256_thumbprint(raw: &str) -> Result<String> {
    let compact = raw
        .chars()
        .filter(|character| !character.is_ascii_whitespace() && *character != ':')
        .collect::<String>();
    if compact.len() != 64 || !compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("publisher thumbprint must be exactly 32 SHA-256 bytes");
    }
    Ok(compact.to_ascii_lowercase())
}

fn sha256_file(path: &Path) -> Result<String> {
    let file = File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 1024 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("JSON output has no parent: {}", path.display()))?;
    fs::create_dir_all(parent)?;
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    fs::write(path, bytes).with_context(|| format!("failed to write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_ID: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn archive_paths_reject_traversal_prefixes_ads_and_backslashes() {
        assert!(archive_path(Path::new("runtime/Image")).is_ok());
        for path in ["../escape", "/absolute", "C:payload", "file:ads"] {
            assert!(archive_path(Path::new(path)).is_err(), "accepted {path}");
        }
        #[cfg(windows)]
        assert_eq!(archive_path(Path::new("a\\b")).unwrap(), "a/b");
        #[cfg(not(windows))]
        assert!(archive_path(Path::new("a\\b")).is_err());
    }

    #[test]
    fn versions_and_publisher_thumbprints_are_canonical() {
        assert_eq!(normalize_version("v0.4.6").unwrap(), "0.4.6");
        assert!(normalize_version("../0.4.6").is_err());
        assert_eq!(
            normalize_sha256_thumbprint(
                "AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA"
            )
            .unwrap(),
            "a".repeat(64)
        );
    }

    #[test]
    fn staging_is_closed_deterministic_and_refuses_overwrite() {
        let root = test_root();
        let inputs = root.join("inputs");
        let runtime = inputs.join("runtime");
        let qemu = inputs.join("qemu");
        let licenses = inputs.join("licenses");
        fs::create_dir_all(&runtime).unwrap();
        fs::create_dir_all(&qemu).unwrap();
        fs::create_dir_all(&licenses).unwrap();
        for (path, bytes) in [
            (runtime.join("Image"), b"kernel".as_slice()),
            (runtime.join("initramfs.cpio.gz"), b"initrd".as_slice()),
            (runtime.join("rootfs.ext4"), b"rootfs".as_slice()),
            (qemu.join("qemu-system-x86_64.exe"), b"qemu".as_slice()),
            (qemu.join("qemu-img.exe"), b"qemu-img".as_slice()),
            (licenses.join("LICENSE"), b"license".as_slice()),
            (
                inputs.join("localsandbox-seawork-service.exe"),
                b"service".as_slice(),
            ),
            (inputs.join("sbom.spdx.json"), b"{}\n".as_slice()),
        ] {
            fs::write(path, bytes).unwrap();
        }
        let output = root.join("output");
        fs::create_dir_all(&output).unwrap();
        let args = vec![
            "--service-binary".into(),
            inputs
                .join("localsandbox-seawork-service.exe")
                .display()
                .to_string(),
            "--runtime-dir".into(),
            runtime.display().to_string(),
            "--qemu-dir".into(),
            qemu.display().to_string(),
            "--sbom".into(),
            inputs.join("sbom.spdx.json").display().to_string(),
            "--licenses".into(),
            licenses.display().to_string(),
            "--publisher-subject".into(),
            "CN=LocalSandbox Test".into(),
            "--publisher-thumbprint".into(),
            "ab".repeat(32),
        ];
        let platform = lsb_platform::platform_by_id("windows-x86_64").unwrap();
        stage_bundle(&args, platform, "v0.4.6", &root, &output).unwrap();
        let stage = output.join("lsb-seawork-service-v0.4.6-windows-x86_64-stage");
        let manifest = fs::read(stage.join("LocalSandbox/manifests/bundle.json")).unwrap();
        assert!(manifest.ends_with(b"\n"));
        let manifest: serde_json::Value = serde_json::from_slice(&manifest).unwrap();
        let files = manifest["files"].as_array().unwrap();
        assert!(files.iter().any(|file| file["path"] == "runtime/Image"));
        assert!(!files
            .iter()
            .any(|file| file["path"] == "manifests/bundle.json"));
        assert!(stage_bundle(&args, platform, "0.4.6", &root, &output).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    fn test_root() -> PathBuf {
        let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("lsb-seawork-release-{}-{id}", std::process::id()))
    }
}
