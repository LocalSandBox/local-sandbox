use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Seek, Write};
use std::path::{Component, Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use crc32fast::Hasher as Crc32;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use lsb_platform::PlatformSpec;
use lsb_service_proto::{CURRENT, SUPPORTED};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::args::{flag_value, required_flag_value};
use crate::context::copy_file;

const BUNDLE_SCHEMA_VERSION: u32 = 1;
const SERVICE_CONTRACT_SCHEMA_VERSION: u32 = 1;
const SERVICE_CONFIGURATION_REVISION: u32 = 2;
const UPDATER_PROTOCOL_MAJOR: u16 = 1;
const UPDATER_PROTOCOL_MIN: u16 = 1;
const UPDATER_PROTOCOL_MAX: u16 = 1;
const LEDGER_SCHEMA_VERSION: u32 = 1;
const MAX_BUNDLE_FILES: usize = 10_000;
const MAX_BUNDLE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_SERVICE_BINARY_BYTES: u64 = 256 * 1024 * 1024;
const MAX_UPDATER_BINARY_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ServiceProfile {
    Production,
    Development,
}

impl ServiceProfile {
    fn parse(args: &[String]) -> Result<Self> {
        match flag_value(args, "--service-profile").unwrap_or("production") {
            "production" => Ok(Self::Production),
            "development" => Ok(Self::Development),
            value => bail!("unsupported SeaWork service profile: {value}"),
        }
    }

    fn artifact_stem(self, version: &str) -> String {
        match self {
            Self::Production => format!("lsb-seawork-service-v{version}-windows-x86_64"),
            Self::Development => {
                format!("lsb-seawork-service-dev-v{version}-windows-x86_64")
            }
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BundleManifest {
    schema_version: u32,
    local_sandbox_version: String,
    service_version: String,
    client_version: String,
    protocol: ProtocolContract,
    ledger: LedgerContract,
    architecture: String,
    target: String,
    guest_asset_version: String,
    qemu: QemuContract,
    service_configuration_revision: u32,
    publisher: PublisherContract,
    files: Vec<BundleFile>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProtocolContract {
    major: u16,
    current_minor: u16,
    supported_min_minor: u16,
    supported_max_minor: u16,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LedgerContract {
    reader_min_schema: u32,
    reader_max_schema: u32,
    writer_schema: u32,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct QemuContract {
    package_version: String,
    qemu_version: String,
    package_revision: String,
    artifact_sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PublisherContract {
    subject: String,
    sha256_thumbprint: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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
    update: UpdateConfiguration,
    updater: UpdaterConfiguration,
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

#[derive(Debug, Serialize)]
struct UpdateConfiguration {
    enabled: bool,
    repository: &'static str,
    releases_api: &'static str,
    archive_name_template: &'static str,
    supported_channels: Vec<&'static str>,
    default_channel: &'static str,
    committed_state_path: String,
    status_path: String,
    failed_target_path: String,
    transaction_path: String,
    downloads_root: String,
    staging_root: String,
    history_root: String,
}

#[derive(Debug, Serialize)]
struct UpdaterConfiguration {
    name: &'static str,
    display_name: &'static str,
    binary_name: &'static str,
    binary_path_template: &'static str,
    binary_command_template: &'static str,
    artifact_name_template: &'static str,
    service_type: &'static str,
    account: &'static str,
    start: &'static str,
    service_sid_type: &'static str,
    service_object_sddl: &'static str,
    protocol: UpdaterProtocolContract,
    failure_restart_delays_ms: Vec<u32>,
    failure_reset_period_seconds: u32,
}

#[derive(Debug, Serialize)]
struct UpdaterProtocolContract {
    major: u16,
    min: u16,
    max: u16,
}

#[derive(Debug, Serialize)]
struct UpdaterArtifactManifest {
    schema_version: u32,
    version: String,
    target: &'static str,
    binary_name: &'static str,
    binary_sha256: String,
    publisher_subject: String,
    publisher_sha256_thumbprint: String,
    protocol: UpdaterProtocolContract,
    service_name: &'static str,
    command_template: &'static str,
}

pub fn package_bundle(
    args: &[String],
    platform: &PlatformSpec,
    version: &str,
    workspace_root: &Path,
    output_dir: &Path,
) -> Result<()> {
    match flag_value(args, "--mode").unwrap_or("stage") {
        "stage" => stage_bundle(args, platform, version, workspace_root, output_dir),
        "archive" => archive_bundle(args, platform, version, workspace_root, output_dir),
        mode => bail!("unsupported SeaWork service packaging mode: {mode}"),
    }
}

pub fn package_updater(
    args: &[String],
    platform: &PlatformSpec,
    raw_version: &str,
    workspace_root: &Path,
    output_dir: &Path,
) -> Result<()> {
    if platform.id != "windows-x86_64" {
        bail!("the SeaWork updater artifact supports only windows-x86_64");
    }
    let version = normalize_version(raw_version)?;
    let binary = input_file(args, "--updater-binary", workspace_root)?;
    if binary.file_name().and_then(|name| name.to_str()) != Some("localsandbox-seawork-updater.exe")
    {
        bail!("--updater-binary must name localsandbox-seawork-updater.exe");
    }
    let size = fs::metadata(&binary)?.len();
    if size == 0 || size > MAX_UPDATER_BINARY_BYTES {
        bail!("updater binary size is outside the supported range");
    }
    require_amd64_pe(&binary)?;
    let publisher_subject = required_flag_value(args, "--publisher-subject")?.trim();
    if publisher_subject.is_empty() || publisher_subject.len() > 512 {
        bail!("--publisher-subject must be between 1 and 512 characters");
    }
    let publisher_sha256_thumbprint =
        normalize_sha256_thumbprint(required_flag_value(args, "--publisher-thumbprint")?)?;

    let stem = format!("lsb-seawork-updater-v{version}-windows-x86_64");
    let archive_name = format!("{stem}.zip");
    let manifest_name = format!("{stem}-manifest.json");
    let archive = output_dir.join(&archive_name);
    let manifest_path = output_dir.join(&manifest_name);
    let sums_path = output_dir.join(format!("lsb-seawork-updater-v{version}-SHA256SUMS"));
    for output in [&archive, &manifest_path, &sums_path] {
        if output.exists() {
            bail!("refusing to overwrite {}", output.display());
        }
    }
    let manifest = UpdaterArtifactManifest {
        schema_version: 1,
        version,
        target: "x86_64-pc-windows-msvc",
        binary_name: "localsandbox-seawork-updater.exe",
        binary_sha256: sha256_file(&binary)?,
        publisher_subject: publisher_subject.to_string(),
        publisher_sha256_thumbprint,
        protocol: UpdaterProtocolContract {
            major: UPDATER_PROTOCOL_MAJOR,
            min: UPDATER_PROTOCOL_MIN,
            max: UPDATER_PROTOCOL_MAX,
        },
        service_name: "LocalSandboxSeaWorkUpdater",
        command_template:
            "\"%ProgramFiles%\\SeaWork\\LocalSandbox\\updater\\localsandbox-seawork-updater.exe\" --service",
    };
    write_json(&manifest_path, &manifest)?;
    write_deterministic_zip(
        &archive,
        vec![
            ZipInput {
                name: "localsandbox-seawork-updater.exe".to_string(),
                source: binary,
            },
            ZipInput {
                name: "manifests/updater.json".to_string(),
                source: manifest_path.clone(),
            },
        ],
    )?;
    fs::write(
        &sums_path,
        format!(
            "{}  {}\n{}  {}\n",
            sha256_file(&archive)?,
            archive_name,
            sha256_file(&manifest_path)?,
            manifest_name
        ),
    )?;
    println!("created {}", archive.display());
    println!("created {}", manifest_path.display());
    println!("created {}", sums_path.display());
    Ok(())
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
    let profile = ServiceProfile::parse(args)?;
    let version = normalize_version(raw_version)?;
    let service_binary = input_file(args, "--service-binary", workspace_root)?;
    if service_binary.file_name().and_then(|name| name.to_str())
        != Some("localsandbox-seawork-service.exe")
    {
        bail!("--service-binary must name localsandbox-seawork-service.exe");
    }
    require_service_profile_binary(&service_binary, profile)?;
    let runtime_dir = input_directory(args, "--runtime-dir", workspace_root)?;
    let qemu_dir = input_directory(args, "--qemu-dir", workspace_root)?;
    let sbom = input_file(args, "--sbom", workspace_root)?;
    let dependency_report = input_file(args, "--dependency-report", workspace_root)?;
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
        output_dir.join(format!("{}-stage", profile.artifact_stem(&version)))
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
    validate_json_file(&dependency_report, "runtime dependency report")?;
    copy_file(
        &dependency_report,
        &bundle_root.join("manifests/runtime-dependencies.json"),
    )?;
    copy_tree(&licenses, &bundle_root.join("licenses"))?;

    let contract = service_contract(profile);
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
        architecture: "x86_64".to_string(),
        target: "x86_64-pc-windows-msvc".to_string(),
        guest_asset_version: version,
        qemu: QemuContract {
            package_version: qemu.package_version.to_string(),
            qemu_version: qemu.qemu_version.to_string(),
            package_revision: qemu.package_revision.to_string(),
            artifact_sha256: qemu.artifact_sha256.to_string(),
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

fn archive_bundle(
    args: &[String],
    platform: &PlatformSpec,
    raw_version: &str,
    workspace_root: &Path,
    output_dir: &Path,
) -> Result<()> {
    if platform.id != "windows-x86_64" {
        bail!("the SeaWork service artifact supports only windows-x86_64");
    }
    let profile = ServiceProfile::parse(args)?;
    let version = normalize_version(raw_version)?;
    let stage_dir = input_directory(args, "--stage-dir", workspace_root)?;
    let catalog = input_file(args, "--catalog", workspace_root)?;
    let pdb = input_file(args, "--pdb", workspace_root)?;
    let source_map = input_file(args, "--source-map", workspace_root)?;
    if fs::metadata(&source_map)?.len() > 1024 * 1024 {
        bail!("source map exceeds the 1 MiB limit");
    }
    let bundle_root = require_closed_stage(&stage_dir)?;
    install_catalog(
        &catalog,
        &bundle_root.join("manifests/LocalSandboxSeaWork.cat"),
    )?;
    verify_staged_bundle(&bundle_root, &version, profile)?;
    serde_json::from_slice::<serde_json::Value>(&fs::read(&source_map)?)
        .context("source map must be valid JSON")?;

    let artifact_stem = profile.artifact_stem(&version);
    let archive_name = format!("{artifact_stem}.zip");
    let symbols_name = format!("{artifact_stem}-symbols.zip");
    let archive = output_dir.join(&archive_name);
    let symbols = output_dir.join(&symbols_name);
    let payload_entries = zip_entries(&stage_dir)?;
    write_deterministic_zip(&archive, payload_entries)?;
    write_deterministic_zip(
        &symbols,
        vec![
            ZipInput {
                name: "LocalSandbox/bin/localsandbox-seawork-service.pdb".to_string(),
                source: pdb,
            },
            ZipInput {
                name: "LocalSandbox/manifests/source-map.json".to_string(),
                source: source_map,
            },
        ],
    )?;
    let sums = format!(
        "{}  {}\n{}  {}\n",
        sha256_file(&archive)?,
        archive_name,
        sha256_file(&symbols)?,
        symbols_name
    );
    let sums_path = output_dir.join(format!("lsb-seawork-service-v{version}-SHA256SUMS"));
    if sums_path.exists() {
        bail!("refusing to overwrite {}", sums_path.display());
    }
    fs::write(&sums_path, sums)?;
    println!("created {}", archive.display());
    println!("created {}", symbols.display());
    println!("created {}", sums_path.display());
    Ok(())
}

fn require_closed_stage(stage_dir: &Path) -> Result<PathBuf> {
    let mut entries = fs::read_dir(stage_dir)?.collect::<std::io::Result<Vec<_>>>()?;
    if entries.len() != 1 || entries[0].file_name() != "LocalSandbox" {
        bail!("stage must contain exactly the LocalSandbox directory");
    }
    let bundle_root = entries.remove(0).path();
    require_directory(&bundle_root)?;
    Ok(bundle_root)
}

fn install_catalog(source: &Path, destination: &Path) -> Result<()> {
    let size = fs::metadata(source)?.len();
    if size == 0 || size > 16 * 1024 * 1024 {
        bail!("catalog size is outside the supported range");
    }
    if destination.exists() {
        require_regular_file(destination)?;
        if sha256_file(source)? != sha256_file(destination)? {
            bail!("stage already contains a different catalog");
        }
        return Ok(());
    }
    copy_file(source, destination)
}

fn verify_staged_bundle(
    bundle_root: &Path,
    expected_version: &str,
    profile: ServiceProfile,
) -> Result<()> {
    let manifest_path = bundle_root.join("manifests/bundle.json");
    let bytes = fs::read(&manifest_path)?;
    if bytes.is_empty() || bytes.len() > 1024 * 1024 {
        bail!("bundle manifest size is outside the supported range");
    }
    let manifest: BundleManifest = serde_json::from_slice(&bytes)?;
    if manifest.schema_version != BUNDLE_SCHEMA_VERSION
        || manifest.local_sandbox_version != expected_version
        || manifest.service_version != expected_version
        || manifest.client_version != expected_version
        || manifest.architecture != "x86_64"
        || manifest.target != "x86_64-pc-windows-msvc"
        || manifest.guest_asset_version != expected_version
        || manifest.service_configuration_revision != SERVICE_CONFIGURATION_REVISION
        || manifest.protocol.major != CURRENT.major
        || manifest.protocol.current_minor != CURRENT.minor
        || manifest.protocol.supported_min_minor != SUPPORTED.min_minor
        || manifest.protocol.supported_max_minor != SUPPORTED.max_minor
        || manifest.ledger.reader_min_schema != LEDGER_SCHEMA_VERSION
        || manifest.ledger.reader_max_schema != LEDGER_SCHEMA_VERSION
        || manifest.ledger.writer_schema != LEDGER_SCHEMA_VERSION
    {
        bail!("bundle manifest metadata does not match this release");
    }
    let qemu = lsb_platform::windows_x86_64::host_tools::managed_qemu_package_metadata();
    if manifest.qemu.package_version != qemu.package_version
        || manifest.qemu.qemu_version != qemu.qemu_version
        || manifest.qemu.package_revision != qemu.package_revision
        || !manifest
            .qemu
            .artifact_sha256
            .eq_ignore_ascii_case(qemu.artifact_sha256)
    {
        bail!("bundle managed QEMU metadata does not match this release");
    }
    normalize_sha256_thumbprint(&manifest.publisher.sha256_thumbprint)?;
    if manifest.publisher.subject.trim().is_empty() {
        bail!("bundle publisher subject is empty");
    }
    let actual_files = inventory_bundle(bundle_root)?;
    if actual_files != manifest.files {
        bail!("bundle payload differs from its closed manifest inventory");
    }
    let contract: serde_json::Value = serde_json::from_slice(&fs::read(
        bundle_root.join("manifests/service-contract.json"),
    )?)?;
    if contract != serde_json::to_value(service_contract(profile))? {
        bail!("service contract differs from the packager contract");
    }
    let runtime_version = fs::read_to_string(bundle_root.join("runtime/VERSION"))?;
    if runtime_version.trim() != expected_version {
        bail!("runtime VERSION does not match the bundle version");
    }
    let service_binary = bundle_root.join("bin/localsandbox-seawork-service.exe");
    require_amd64_pe(&service_binary)?;
    require_service_profile_binary(&service_binary, profile)?;
    require_regular_file(&bundle_root.join("manifests/LocalSandboxSeaWork.cat"))?;
    validate_json_file(
        &bundle_root.join("manifests/runtime-dependencies.json"),
        "runtime dependency report",
    )?;
    Ok(())
}

fn validate_json_file(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::metadata(path)?;
    if metadata.len() == 0 || metadata.len() > 1024 * 1024 {
        bail!("{label} size is outside the supported range");
    }
    serde_json::from_reader::<_, serde_json::Value>(File::open(path)?)
        .with_context(|| format!("{label} must be valid JSON"))?;
    Ok(())
}

fn require_amd64_pe(path: &Path) -> Result<()> {
    let mut file = File::open(path)?;
    let size = file.metadata()?.len();
    if size < 0x40 {
        bail!("service executable is not a PE image");
    }
    let mut dos = [0u8; 0x40];
    file.read_exact(&mut dos)?;
    if &dos[..2] != b"MZ" {
        bail!("service executable has no DOS header");
    }
    let offset = u32::from_le_bytes(dos[0x3c..0x40].try_into()?) as u64;
    if offset.checked_add(6).is_none_or(|end| end > size) {
        bail!("service executable PE header is out of bounds");
    }
    file.seek(std::io::SeekFrom::Start(offset))?;
    let mut header = [0u8; 6];
    file.read_exact(&mut header)?;
    if &header[..4] != b"PE\0\0" || u16::from_le_bytes([header[4], header[5]]) != 0x8664 {
        bail!("service executable is not an AMD64 PE image");
    }
    Ok(())
}

#[derive(Debug)]
struct ZipInput {
    name: String,
    source: PathBuf,
}

#[derive(Debug)]
struct ZipCentralEntry {
    name: String,
    crc32: u32,
    compressed_size: u32,
    uncompressed_size: u32,
    local_header_offset: u32,
}

fn zip_entries(root: &Path) -> Result<Vec<ZipInput>> {
    let mut paths = Vec::new();
    collect_files(root, root, &mut paths)?;
    let mut entries = Vec::new();
    let mut folded = BTreeMap::new();
    for source in paths {
        let name = archive_path(source.strip_prefix(root)?)?;
        if let Some(existing) = folded.insert(name.to_ascii_lowercase(), name.clone()) {
            bail!("case-insensitive ZIP path collision: {existing} and {name}");
        }
        entries.push(ZipInput { name, source });
    }
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(entries)
}

fn write_deterministic_zip(path: &Path, mut entries: Vec<ZipInput>) -> Result<()> {
    if path.exists() {
        bail!("refusing to overwrite {}", path.display());
    }
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    if entries.is_empty() || entries.len() > u16::MAX as usize {
        bail!("ZIP entry count is outside the supported range");
    }
    let temp = path.with_extension("zip.tmp");
    if temp.exists() {
        bail!("refusing to overwrite temporary archive {}", temp.display());
    }
    let result = write_zip_file(&temp, &entries);
    if let Err(error) = result {
        let _ = fs::remove_file(&temp);
        return Err(error);
    }
    fs::rename(&temp, path)?;
    Ok(())
}

fn write_zip_file(path: &Path, entries: &[ZipInput]) -> Result<()> {
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);
    let mut central = Vec::with_capacity(entries.len());
    for entry in entries {
        archive_path(Path::new(&entry.name))?;
        require_regular_file(&entry.source)?;
        let name = entry.name.as_bytes();
        let name_len = u16::try_from(name.len()).context("ZIP entry name is too long")?;
        let local_header_offset =
            u32::try_from(writer.stream_position()?).context("ZIP64 archives are not supported")?;
        write_u32(&mut writer, 0x0403_4b50)?;
        write_u16(&mut writer, 20)?;
        write_u16(&mut writer, 0x0808)?;
        write_u16(&mut writer, 8)?;
        write_u16(&mut writer, 0)?;
        write_u16(&mut writer, 33)?;
        write_u32(&mut writer, 0)?;
        write_u32(&mut writer, 0)?;
        write_u32(&mut writer, 0)?;
        write_u16(&mut writer, name_len)?;
        write_u16(&mut writer, 0)?;
        writer.write_all(name)?;
        let compressed_start = writer.stream_position()?;
        let mut input = BufReader::new(File::open(&entry.source)?);
        let mut crc = Crc32::new();
        let mut uncompressed_size = 0u64;
        {
            let mut encoder = DeflateEncoder::new(&mut writer, Compression::best());
            let mut buffer = vec![0u8; 64 * 1024];
            loop {
                let count = input.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                crc.update(&buffer[..count]);
                uncompressed_size = uncompressed_size
                    .checked_add(count as u64)
                    .context("ZIP entry size overflow")?;
                encoder.write_all(&buffer[..count])?;
            }
            encoder.finish()?;
        }
        let compressed_size = writer
            .stream_position()?
            .checked_sub(compressed_start)
            .context("ZIP compressed size underflow")?;
        let compressed_size =
            u32::try_from(compressed_size).context("ZIP64 archives are not supported")?;
        let uncompressed_size =
            u32::try_from(uncompressed_size).context("ZIP64 entries are not supported")?;
        let crc32 = crc.finalize();
        write_u32(&mut writer, 0x0807_4b50)?;
        write_u32(&mut writer, crc32)?;
        write_u32(&mut writer, compressed_size)?;
        write_u32(&mut writer, uncompressed_size)?;
        central.push(ZipCentralEntry {
            name: entry.name.clone(),
            crc32,
            compressed_size,
            uncompressed_size,
            local_header_offset,
        });
    }
    let central_offset =
        u32::try_from(writer.stream_position()?).context("ZIP64 archives are not supported")?;
    for entry in &central {
        let name = entry.name.as_bytes();
        write_u32(&mut writer, 0x0201_4b50)?;
        write_u16(&mut writer, 20)?;
        write_u16(&mut writer, 20)?;
        write_u16(&mut writer, 0x0808)?;
        write_u16(&mut writer, 8)?;
        write_u16(&mut writer, 0)?;
        write_u16(&mut writer, 33)?;
        write_u32(&mut writer, entry.crc32)?;
        write_u32(&mut writer, entry.compressed_size)?;
        write_u32(&mut writer, entry.uncompressed_size)?;
        write_u16(&mut writer, u16::try_from(name.len())?)?;
        write_u16(&mut writer, 0)?;
        write_u16(&mut writer, 0)?;
        write_u16(&mut writer, 0)?;
        write_u16(&mut writer, 0)?;
        write_u32(&mut writer, 0)?;
        write_u32(&mut writer, entry.local_header_offset)?;
        writer.write_all(name)?;
    }
    let central_size = u32::try_from(
        writer
            .stream_position()?
            .checked_sub(central_offset as u64)
            .context("ZIP central directory size underflow")?,
    )
    .context("ZIP64 archives are not supported")?;
    let count = u16::try_from(central.len())?;
    write_u32(&mut writer, 0x0605_4b50)?;
    write_u16(&mut writer, 0)?;
    write_u16(&mut writer, 0)?;
    write_u16(&mut writer, count)?;
    write_u16(&mut writer, count)?;
    write_u32(&mut writer, central_size)?;
    write_u32(&mut writer, central_offset)?;
    write_u16(&mut writer, 0)?;
    writer.flush()?;
    writer.get_ref().sync_all()?;
    Ok(())
}

fn write_u16(writer: &mut impl Write, value: u16) -> Result<()> {
    writer.write_all(&value.to_le_bytes())?;
    Ok(())
}

fn write_u32(writer: &mut impl Write, value: u32) -> Result<()> {
    writer.write_all(&value.to_le_bytes())?;
    Ok(())
}

fn service_contract(profile: ServiceProfile) -> ServiceContract {
    let (name, event_source, pipe_name, state_root, updater_name) = match profile {
        ServiceProfile::Production => (
            "LocalSandboxSeaWork",
            "LocalSandboxSeaWork",
            r"\\.\pipe\LocalSandbox.SeaWork.v1",
            "%ProgramData%\\LocalSandbox\\SeaWork",
            "LocalSandboxSeaWorkUpdater",
        ),
        ServiceProfile::Development => (
            "LocalSandboxSeaWorkDev",
            "LocalSandboxSeaWorkDev",
            r"\\.\pipe\LocalSandbox.SeaWork.Dev.v1",
            "%ProgramData%\\LocalSandbox\\SeaWorkDev",
            "LocalSandboxSeaWorkUpdaterDev",
        ),
    };
    ServiceContract {
        schema_version: SERVICE_CONTRACT_SCHEMA_VERSION,
        revision: SERVICE_CONFIGURATION_REVISION,
        service: ServiceConfiguration {
            name,
            display_name: "LocalSandbox for SeaWork",
            description:
                "Runs LocalSandbox virtual machines for locally signed SeaWork desktop clients.",
            service_type: "SERVICE_WIN32_OWN_PROCESS",
            account: "LocalSystem",
            start: "automatic",
            delayed_auto_start: true,
            binary_path_template: "\"%ProgramFiles%\\SeaWork\\LocalSandbox\\versions\\<version>\\bin\\localsandbox-seawork-service.exe\" --service",
            dependencies: Vec::new(),
            service_sid_type: "SERVICE_SID_TYPE_UNRESTRICTED",
            service_object_sddl: "O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00000005;;;IU)",
            accepted_controls: vec!["STOP", "PRESHUTDOWN"],
            preshutdown_timeout_ms: 60_000,
            failure_restart_delays_ms: vec![5_000, 30_000, 120_000],
            failure_reset_period_seconds: 86_400,
            failure_actions_on_non_crash_failures: true,
            event_source,
        },
        ipc: IpcConfiguration {
            pipe_name,
            pipe_sddl: "O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;IU)(A;;0x00000002;;;IU)S:(ML;;NW;;;ME)",
            remote_clients_allowed: false,
            protocol: protocol_contract(),
        },
        filesystem: FilesystemConfiguration {
            version_root_template: "%ProgramFiles%\\SeaWork\\LocalSandbox\\versions\\<version>",
            state_root,
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
        update: UpdateConfiguration {
            enabled: profile == ServiceProfile::Production,
            repository: "LocalSandBox/local-sandbox",
            releases_api:
                "https://api.github.com/repos/LocalSandBox/local-sandbox/releases",
            archive_name_template: "lsb-seawork-service-v<VERSION>-windows-x86_64.zip",
            supported_channels: vec!["stable", "prerelease"],
            default_channel: "stable",
            committed_state_path: format!("{state_root}\\updates\\committed.json"),
            status_path: format!("{state_root}\\updates\\status.json"),
            failed_target_path: format!("{state_root}\\updates\\failed-target.json"),
            transaction_path: format!(
                "{state_root}\\updates\\transactions\\current.json"
            ),
            downloads_root: format!("{state_root}\\updates\\downloads"),
            staging_root: format!("{state_root}\\updates\\staging"),
            history_root: format!("{state_root}\\updates\\history"),
        },
        updater: UpdaterConfiguration {
            name: updater_name,
            display_name: "LocalSandbox for SeaWork Updater",
            binary_name: "localsandbox-seawork-updater.exe",
            binary_path_template:
                "%ProgramFiles%\\SeaWork\\LocalSandbox\\updater\\localsandbox-seawork-updater.exe",
            binary_command_template:
                "\"%ProgramFiles%\\SeaWork\\LocalSandbox\\updater\\localsandbox-seawork-updater.exe\" --service",
            artifact_name_template:
                "lsb-seawork-updater-v<VERSION>-windows-x86_64.zip",
            service_type: "SERVICE_WIN32_OWN_PROCESS",
            account: "LocalSystem",
            start: "automatic",
            service_sid_type: "SERVICE_SID_TYPE_UNRESTRICTED",
            service_object_sddl:
                "O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00000005;;;IU)",
            protocol: UpdaterProtocolContract {
                major: UPDATER_PROTOCOL_MAJOR,
                min: UPDATER_PROTOCOL_MIN,
                max: UPDATER_PROTOCOL_MAX,
            },
            failure_restart_delays_ms: vec![5_000, 30_000, 120_000],
            failure_reset_period_seconds: 86_400,
        },
        install_state_schema: 1,
    }
}

fn require_service_profile_binary(path: &Path, profile: ServiceProfile) -> Result<()> {
    let size = fs::metadata(path)?.len();
    if size == 0 || size > MAX_SERVICE_BINARY_BYTES {
        bail!("service binary size is outside the supported range");
    }
    let bytes = fs::read(path)?;
    let contains = |needle: &[u8]| bytes.windows(needle.len()).any(|window| window == needle);
    let (required_name, required_pipe, forbidden_name, forbidden_pipe) = match profile {
        ServiceProfile::Production => (
            b"LocalSandboxSeaWork".as_slice(),
            br"\\.\pipe\LocalSandbox.SeaWork.v1".as_slice(),
            b"LocalSandboxSeaWorkDev".as_slice(),
            br"\\.\pipe\LocalSandbox.SeaWork.Dev.v1".as_slice(),
        ),
        ServiceProfile::Development => (
            b"LocalSandboxSeaWorkDev".as_slice(),
            br"\\.\pipe\LocalSandbox.SeaWork.Dev.v1".as_slice(),
            b"".as_slice(),
            br"\\.\pipe\LocalSandbox.SeaWork.v1".as_slice(),
        ),
    };
    if !contains(required_name)
        || !contains(required_pipe)
        || (!forbidden_name.is_empty() && contains(forbidden_name))
        || contains(forbidden_pipe)
    {
        bail!("service binary does not match the selected service profile");
    }
    Ok(())
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
    let mut buffer = vec![0u8; 64 * 1024];
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
    fn service_contract_quotes_the_exact_service_command() {
        assert_eq!(
            service_contract(ServiceProfile::Production)
                .service
                .binary_path_template,
            r#""%ProgramFiles%\SeaWork\LocalSandbox\versions\<version>\bin\localsandbox-seawork-service.exe" --service"#
        );
        let updater = service_contract(ServiceProfile::Production).updater;
        assert_eq!(updater.name, "LocalSandboxSeaWorkUpdater");
        assert_eq!(
            updater.binary_command_template,
            r#""%ProgramFiles%\SeaWork\LocalSandbox\updater\localsandbox-seawork-updater.exe" --service"#
        );
    }

    #[test]
    fn service_profiles_are_explicit_and_isolated() {
        assert_eq!(
            ServiceProfile::parse(&[]).unwrap(),
            ServiceProfile::Production
        );
        let development = vec!["--service-profile".into(), "development".into()];
        assert_eq!(
            ServiceProfile::parse(&development).unwrap(),
            ServiceProfile::Development
        );
        let invalid = vec!["--service-profile".into(), "preview".into()];
        assert!(ServiceProfile::parse(&invalid).is_err());

        let production =
            serde_json::to_value(service_contract(ServiceProfile::Production)).unwrap();
        let development =
            serde_json::to_value(service_contract(ServiceProfile::Development)).unwrap();
        assert_eq!(production["service"]["name"], "LocalSandboxSeaWork");
        assert_eq!(production["revision"], 2);
        assert_eq!(production["update"]["default_channel"], "stable");
        assert_eq!(
            production["update"]["repository"],
            "LocalSandBox/local-sandbox"
        );
        assert_eq!(production["updater"]["name"], "LocalSandboxSeaWorkUpdater");
        assert_eq!(development["service"]["name"], "LocalSandboxSeaWorkDev");
        assert_eq!(development["update"]["enabled"], false);
        assert_eq!(
            development["ipc"]["pipe_name"],
            r"\\.\pipe\LocalSandbox.SeaWork.Dev.v1"
        );
        assert_eq!(
            development["filesystem"]["state_root"],
            r"%ProgramData%\LocalSandbox\SeaWorkDev"
        );
        assert_eq!(
            production["filesystem"]["program_files_sddl"],
            development["filesystem"]["program_files_sddl"]
        );
        assert_eq!(
            production["filesystem"]["program_data_sddl"],
            development["filesystem"]["program_data_sddl"]
        );

        let root = test_root();
        fs::create_dir_all(&root).unwrap();
        let production_binary = root.join("production.exe");
        let development_binary = root.join("development.exe");
        fs::write(
            &production_binary,
            fake_amd64_pe(ServiceProfile::Production),
        )
        .unwrap();
        fs::write(
            &development_binary,
            fake_amd64_pe(ServiceProfile::Development),
        )
        .unwrap();
        assert!(
            require_service_profile_binary(&production_binary, ServiceProfile::Production).is_ok()
        );
        assert!(
            require_service_profile_binary(&development_binary, ServiceProfile::Development)
                .is_ok()
        );
        assert!(
            require_service_profile_binary(&production_binary, ServiceProfile::Development)
                .is_err()
        );
        assert!(
            require_service_profile_binary(&development_binary, ServiceProfile::Production)
                .is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn updater_artifact_is_digest_bound_and_deterministic() {
        let root = test_root();
        let inputs = root.join("inputs");
        let output = root.join("output");
        fs::create_dir_all(&inputs).unwrap();
        fs::create_dir_all(&output).unwrap();
        let binary = inputs.join("localsandbox-seawork-updater.exe");
        fs::write(&binary, fake_amd64_pe(ServiceProfile::Production)).unwrap();
        let args = vec![
            "--updater-binary".into(),
            binary.display().to_string(),
            "--publisher-subject".into(),
            "CN=LocalSandbox Test".into(),
            "--publisher-thumbprint".into(),
            "ab".repeat(32),
        ];
        let platform = lsb_platform::platform_by_id("windows-x86_64").unwrap();
        package_updater(&args, platform, "v0.5.0", &root, &output).unwrap();

        let stem = "lsb-seawork-updater-v0.5.0-windows-x86_64";
        let archive = output.join(format!("{stem}.zip"));
        let manifest_path = output.join(format!("{stem}-manifest.json"));
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        assert_eq!(manifest["version"], "0.5.0");
        assert_eq!(manifest["binary_sha256"], sha256_file(&binary).unwrap());
        assert_eq!(manifest["service_name"], "LocalSandboxSeaWorkUpdater");
        assert!(fs::read(&archive).unwrap().starts_with(b"PK\x03\x04"));
        assert!(package_updater(&args, platform, "0.5.0", &root, &output).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn staging_and_archives_are_closed_deterministic_and_tamper_evident() {
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
            (inputs.join("sbom.spdx.json"), b"{}\n".as_slice()),
            (
                inputs.join("runtime-dependencies.json"),
                b"{\"schema_version\":1}\n".as_slice(),
            ),
        ] {
            fs::write(path, bytes).unwrap();
        }
        fs::write(
            inputs.join("localsandbox-seawork-service.exe"),
            fake_amd64_pe(ServiceProfile::Production),
        )
        .unwrap();
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
            "--dependency-report".into(),
            inputs
                .join("runtime-dependencies.json")
                .display()
                .to_string(),
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

        fs::write(inputs.join("LocalSandboxSeaWork.cat"), b"signed catalog").unwrap();
        fs::write(inputs.join("localsandbox-seawork-service.pdb"), b"pdb").unwrap();
        fs::write(inputs.join("source-map.json"), b"{}\n").unwrap();
        let archive_args = vec![
            "--stage-dir".into(),
            stage.display().to_string(),
            "--catalog".into(),
            inputs.join("LocalSandboxSeaWork.cat").display().to_string(),
            "--pdb".into(),
            inputs
                .join("localsandbox-seawork-service.pdb")
                .display()
                .to_string(),
            "--source-map".into(),
            inputs.join("source-map.json").display().to_string(),
        ];
        archive_bundle(&archive_args, platform, "0.4.6", &root, &output).unwrap();
        let archive = output.join("lsb-seawork-service-v0.4.6-windows-x86_64.zip");
        let symbols = output.join("lsb-seawork-service-v0.4.6-windows-x86_64-symbols.zip");
        let first_archive = fs::read(&archive).unwrap();
        let first_symbols = fs::read(&symbols).unwrap();
        assert!(first_archive.starts_with(b"PK\x03\x04"));
        assert!(first_symbols.starts_with(b"PK\x03\x04"));
        let sums = output.join("lsb-seawork-service-v0.4.6-SHA256SUMS");
        assert!(fs::read_to_string(&sums)
            .unwrap()
            .contains("lsb-seawork-service-v0.4.6-windows-x86_64.zip"));
        fs::remove_file(&archive).unwrap();
        fs::remove_file(&symbols).unwrap();
        fs::remove_file(sums).unwrap();
        archive_bundle(&archive_args, platform, "0.4.6", &root, &output).unwrap();
        assert_eq!(fs::read(&archive).unwrap(), first_archive);
        assert_eq!(fs::read(&symbols).unwrap(), first_symbols);

        fs::write(stage.join("LocalSandbox/runtime/Image"), b"tampered").unwrap();
        assert!(verify_staged_bundle(
            &stage.join("LocalSandbox"),
            "0.4.6",
            ServiceProfile::Production
        )
        .is_err());
        fs::remove_dir_all(root).unwrap();
    }

    fn fake_amd64_pe(profile: ServiceProfile) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x80];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        bytes[0x40..0x44].copy_from_slice(b"PE\0\0");
        bytes[0x44..0x46].copy_from_slice(&0x8664u16.to_le_bytes());
        let identities: &[&[u8]] = match profile {
            ServiceProfile::Production => {
                &[b"LocalSandboxSeaWork", br"\\.\pipe\LocalSandbox.SeaWork.v1"]
            }
            ServiceProfile::Development => &[
                b"LocalSandboxSeaWorkDev",
                br"\\.\pipe\LocalSandbox.SeaWork.Dev.v1",
            ],
        };
        for identity in identities {
            bytes.extend_from_slice(identity);
            bytes.push(0);
        }
        bytes
    }

    fn test_root() -> PathBuf {
        let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("lsb-seawork-release-{}-{id}", std::process::id()))
    }
}
