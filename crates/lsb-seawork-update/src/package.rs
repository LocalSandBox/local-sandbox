use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{BufReader, Read, Seek};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use lsb_service_proto::{negotiate, BundleIdentity, LedgerCompatibility, ProtocolRange};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const BUNDLE_SCHEMA_VERSION: u32 = 1;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_BUNDLE_FILES: usize = 10_000;
const MAX_BUNDLE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_PATH_BYTES: usize = 512;
const MAX_DIRECTORY_DEPTH: usize = 32;

#[derive(Debug, Clone, Copy)]
pub struct PackagePolicy<'a> {
    pub expected_version: &'a str,
    pub supported_protocol: ProtocolRange,
    pub ledger_writer_schema: u32,
    pub service_configuration_revision: u32,
    pub service_name: &'a str,
    pub service_display_name: &'a str,
    pub service_account: &'a str,
    pub service_type: &'a str,
    pub pipe_name: &'a str,
    pub pipe_sddl: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublisherIdentity {
    pub subject: String,
    pub sha256_thumbprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageVerification {
    pub files_verified: usize,
    pub catalog_members: Vec<String>,
    pub version: String,
    pub bundle_manifest_sha256: String,
    pub protocol: ProtocolRange,
    pub ledger: LedgerCompatibility,
    pub service_configuration_revision: u32,
    pub publisher: PublisherIdentity,
}

impl PackageVerification {
    pub fn bundle_identity(&self, archive_sha256: &str) -> Result<BundleIdentity> {
        if !is_lower_sha256(archive_sha256) {
            bail!("archive digest is not canonical lowercase SHA-256");
        }
        let identity = BundleIdentity {
            version: self.version.clone(),
            bundle_manifest_sha256: self.bundle_manifest_sha256.clone(),
            archive_sha256: archive_sha256.to_string(),
            protocol: self.protocol,
            ledger: self.ledger.clone(),
            service_configuration_revision: self.service_configuration_revision,
        };
        identity
            .validate()
            .map_err(|_| anyhow::anyhow!("verified bundle identity is invalid"))?;
        Ok(identity)
    }
}

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtocolContract {
    major: u16,
    current_minor: u16,
    supported_min_minor: u16,
    supported_max_minor: u16,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LedgerContract {
    reader_min_schema: u32,
    reader_max_schema: u32,
    writer_schema: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct QemuContract {
    package_version: String,
    qemu_version: String,
    package_revision: String,
    artifact_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublisherContract {
    subject: String,
    sha256_thumbprint: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleFile {
    path: String,
    size_bytes: u64,
    sha256: String,
}

pub fn verify_bundle_root(root: &Path, policy: &PackagePolicy<'_>) -> Result<PackageVerification> {
    validate_policy(policy)?;
    require_directory(root)?;
    let manifest_path = root.join("manifests/bundle.json");
    let manifest_bytes = read_bounded_file(&manifest_path, MAX_MANIFEST_BYTES, "bundle manifest")?;
    let manifest_sha256 = sha256_bytes(&manifest_bytes);
    let manifest: BundleManifest = serde_json::from_slice(&manifest_bytes)?;
    let (protocol, ledger, publisher) = verify_metadata(&manifest, policy)?;

    if manifest.files.is_empty() || manifest.files.len() > MAX_BUNDLE_FILES {
        bail!("bundle file count is outside the supported range");
    }
    let mut expected_paths = BTreeSet::new();
    let mut folded_paths = BTreeMap::new();
    let mut total_bytes = 0u64;
    let mut previous = None;
    for entry in &manifest.files {
        validate_manifest_path(&entry.path)?;
        if matches!(
            entry.path.as_str(),
            "manifests/bundle.json" | "manifests/LocalSandboxSeaWork.cat"
        ) {
            bail!("bundle manifest contains a hash-cycle path");
        }
        if previous
            .as_ref()
            .is_some_and(|path: &&String| *path >= &entry.path)
        {
            bail!("bundle manifest file inventory is not strictly sorted");
        }
        previous = Some(&entry.path);
        if let Some(existing) = folded_paths.insert(entry.path.to_ascii_lowercase(), &entry.path) {
            bail!(
                "case-insensitive bundle path collision: {existing} and {}",
                entry.path
            );
        }
        if !is_lower_sha256(&entry.sha256) {
            bail!("bundle payload digest is not canonical lowercase SHA-256");
        }
        let path = bundle_path(root, &entry.path);
        require_regular_file(&path)?;
        let actual_size = fs::metadata(&path)?.len();
        if actual_size != entry.size_bytes || sha256_file(&path)? != entry.sha256 {
            bail!("bundle payload hash or size mismatch: {}", entry.path);
        }
        total_bytes = total_bytes
            .checked_add(actual_size)
            .context("bundle expanded size overflow")?;
        if total_bytes > MAX_BUNDLE_BYTES {
            bail!("bundle exceeds maximum expanded size");
        }
        expected_paths.insert(entry.path.clone());
    }

    require_mandatory_paths(&expected_paths)?;
    expected_paths.insert("manifests/bundle.json".to_string());
    expected_paths.insert("manifests/LocalSandboxSeaWork.cat".to_string());
    let mut actual_paths = BTreeSet::new();
    collect_relative_files(root, root, 0, &mut actual_paths)?;
    if actual_paths != expected_paths {
        bail!("bundle contains missing or unlisted payload files");
    }

    verify_service_contract(root, policy)?;
    verify_json_manifest(
        &root.join("manifests/runtime-dependencies.json"),
        "runtime dependency report",
    )?;
    let catalog = root.join("manifests/LocalSandboxSeaWork.cat");
    require_regular_file(&catalog)?;
    let catalog_size = fs::metadata(catalog)?.len();
    if catalog_size == 0 || catalog_size > 16 * 1024 * 1024 {
        bail!("catalog size is outside the supported range");
    }
    let runtime_version = fs::read_to_string(root.join("runtime/VERSION"))?;
    if runtime_version.trim() != policy.expected_version {
        bail!("runtime VERSION does not match the expected bundle version");
    }
    require_amd64_pe(&root.join("bin/localsandbox-seawork-service.exe"))?;
    let mut catalog_members = manifest
        .files
        .iter()
        .map(|entry| entry.path.clone())
        .collect::<Vec<_>>();
    catalog_members.push("manifests/bundle.json".to_string());
    catalog_members.sort();
    Ok(PackageVerification {
        files_verified: manifest.files.len(),
        catalog_members,
        version: manifest.service_version,
        bundle_manifest_sha256: manifest_sha256,
        protocol,
        ledger,
        service_configuration_revision: manifest.service_configuration_revision,
        publisher,
    })
}

fn validate_policy(policy: &PackagePolicy<'_>) -> Result<()> {
    let version = semver::Version::parse(policy.expected_version)?;
    if version.to_string() != policy.expected_version
        || !version.build.is_empty()
        || policy.supported_protocol.validate().is_err()
        || policy.ledger_writer_schema == 0
        || policy.service_configuration_revision == 0
    {
        bail!("compiled package policy is invalid");
    }
    for value in [
        policy.service_name,
        policy.service_display_name,
        policy.service_account,
        policy.service_type,
        policy.pipe_name,
        policy.pipe_sddl,
    ] {
        if value.is_empty() || value.len() > 1024 {
            bail!("compiled package policy string is invalid");
        }
    }
    Ok(())
}

fn verify_metadata(
    manifest: &BundleManifest,
    policy: &PackagePolicy<'_>,
) -> Result<(ProtocolRange, LedgerCompatibility, PublisherIdentity)> {
    let protocol = ProtocolRange {
        major: manifest.protocol.major,
        min_minor: manifest.protocol.supported_min_minor,
        max_minor: manifest.protocol.supported_max_minor,
    };
    let ledger = LedgerCompatibility {
        reader_min_schema: manifest.ledger.reader_min_schema,
        reader_max_schema: manifest.ledger.reader_max_schema,
        writer_schema: manifest.ledger.writer_schema,
    };
    if manifest.schema_version != BUNDLE_SCHEMA_VERSION
        || manifest.local_sandbox_version != policy.expected_version
        || manifest.service_version != policy.expected_version
        || manifest.client_version != policy.expected_version
        || manifest.guest_asset_version != policy.expected_version
        || manifest.architecture != "x86_64"
        || manifest.target != "x86_64-pc-windows-msvc"
        || manifest.service_configuration_revision != policy.service_configuration_revision
        || protocol.validate().is_err()
        || manifest.protocol.current_minor < protocol.min_minor
        || manifest.protocol.current_minor > protocol.max_minor
        || negotiate(protocol, policy.supported_protocol).is_err()
        || ledger.reader_min_schema == 0
        || ledger.reader_min_schema > ledger.reader_max_schema
        || ledger.writer_schema != policy.ledger_writer_schema
        || policy.ledger_writer_schema < ledger.reader_min_schema
        || policy.ledger_writer_schema > ledger.reader_max_schema
    {
        bail!("bundle metadata is incompatible with the compiled package policy");
    }
    for value in [
        &manifest.qemu.package_version,
        &manifest.qemu.qemu_version,
        &manifest.qemu.package_revision,
    ] {
        if value.trim().is_empty() || value.len() > 128 {
            bail!("bundle managed QEMU metadata is invalid");
        }
    }
    if !is_lower_sha256(&manifest.qemu.artifact_sha256) {
        bail!("bundle managed QEMU artifact digest is invalid");
    }
    if manifest.publisher.subject.trim().is_empty()
        || manifest.publisher.subject.len() > 512
        || !is_sha256(&manifest.publisher.sha256_thumbprint)
    {
        bail!("bundle publisher identity is invalid");
    }
    Ok((
        protocol,
        ledger,
        PublisherIdentity {
            subject: manifest.publisher.subject.clone(),
            sha256_thumbprint: manifest.publisher.sha256_thumbprint.to_ascii_lowercase(),
        },
    ))
}

fn require_mandatory_paths(paths: &BTreeSet<String>) -> Result<()> {
    for required in [
        "bin/localsandbox-seawork-service.exe",
        "runtime/Image",
        "runtime/VERSION",
        "runtime/initramfs.cpio.gz",
        "runtime/rootfs.ext4",
        "tools/qemu/qemu-system-x86_64.exe",
        "tools/qemu/qemu-img.exe",
        "manifests/service-contract.json",
        "manifests/sbom.spdx.json",
        "manifests/runtime-dependencies.json",
    ] {
        if !paths.contains(required) {
            bail!("bundle is missing mandatory payload {required}");
        }
    }
    if !paths.iter().any(|path| path.starts_with("licenses/")) {
        bail!("bundle has no license inventory");
    }
    Ok(())
}

fn verify_service_contract(root: &Path, policy: &PackagePolicy<'_>) -> Result<()> {
    let path = root.join("manifests/service-contract.json");
    let bytes = read_bounded_file(&path, MAX_MANIFEST_BYTES, "service contract")?;
    let contract: serde_json::Value = serde_json::from_slice(&bytes)?;
    for (pointer, expected) in [
        ("/service/name", policy.service_name),
        ("/service/display_name", policy.service_display_name),
        ("/service/account", policy.service_account),
        ("/service/service_type", policy.service_type),
        ("/ipc/pipe_name", policy.pipe_name),
        ("/ipc/pipe_sddl", policy.pipe_sddl),
    ] {
        if contract.pointer(pointer).and_then(|value| value.as_str()) != Some(expected) {
            bail!("service contract field {pointer} is incompatible");
        }
    }
    if contract
        .pointer("/schema_version")
        .and_then(|value| value.as_u64())
        != Some(1)
        || contract
            .pointer("/revision")
            .and_then(|value| value.as_u64())
            != Some(policy.service_configuration_revision as u64)
        || contract
            .pointer("/ipc/remote_clients_allowed")
            .and_then(|value| value.as_bool())
            != Some(false)
    {
        bail!("service contract schema or security policy is incompatible");
    }
    Ok(())
}

fn verify_json_manifest(path: &Path, label: &str) -> Result<()> {
    let bytes = read_bounded_file(path, MAX_MANIFEST_BYTES, label)?;
    serde_json::from_slice::<serde_json::Value>(&bytes)
        .with_context(|| format!("{label} must be valid JSON"))?;
    Ok(())
}

fn read_bounded_file(path: &Path, maximum: u64, label: &str) -> Result<Vec<u8>> {
    require_regular_file(path)?;
    let size = fs::metadata(path)?.len();
    if size == 0 || size > maximum {
        bail!("{label} size is outside the supported range");
    }
    fs::read(path).with_context(|| format!("read {label} {}", path.display()))
}

fn collect_relative_files(
    root: &Path,
    directory: &Path,
    depth: usize,
    files: &mut BTreeSet<String>,
) -> Result<()> {
    if depth > MAX_DIRECTORY_DEPTH {
        bail!("bundle directory nesting exceeds the supported limit");
    }
    require_directory(directory)?;
    let entries = fs::read_dir(directory)?.collect::<std::io::Result<Vec<_>>>()?;
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        reject_reparse(&metadata)?;
        if metadata.is_dir() {
            collect_relative_files(root, &path, depth + 1, files)?;
        } else if metadata.is_file() {
            if files.len() >= MAX_BUNDLE_FILES + 2 {
                bail!("bundle file count exceeds the supported limit");
            }
            let relative = path.strip_prefix(root)?;
            let relative = relative
                .components()
                .map(|component| {
                    component
                        .as_os_str()
                        .to_str()
                        .context("bundle path is not UTF-8")
                })
                .collect::<Result<Vec<_>>>()?
                .join("/");
            validate_manifest_path(&relative)?;
            if !files.insert(relative) {
                bail!("bundle contains a duplicate path");
            }
        } else {
            bail!("bundle contains a non-regular entry");
        }
    }
    Ok(())
}

fn validate_manifest_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.len() > MAX_PATH_BYTES
        || path.starts_with('/')
        || path.contains(['\\', ':', '\0'])
        || path
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        bail!("bundle manifest contains an unsafe relative path");
    }
    Ok(())
}

fn bundle_path(root: &Path, relative: &str) -> PathBuf {
    relative
        .split('/')
        .fold(root.to_path_buf(), |path, part| path.join(part))
}

fn require_regular_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    reject_reparse(&metadata)?;
    if !metadata.is_file() {
        bail!("bundle entry is not a regular file");
    }
    Ok(())
}

fn require_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    reject_reparse(&metadata)?;
    if !metadata.is_dir() {
        bail!("bundle entry is not a directory");
    }
    Ok(())
}

fn reject_reparse(metadata: &fs::Metadata) -> Result<()> {
    if metadata.file_type().is_symlink() || has_reparse_attribute(metadata) {
        bail!("bundle contains a reparse entry");
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

fn sha256_file(path: &Path) -> Result<String> {
    let mut reader = BufReader::new(File::open(path)?);
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

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_ID: AtomicU64 = AtomicU64::new(1);

    fn policy() -> PackagePolicy<'static> {
        PackagePolicy {
            expected_version: env!("CARGO_PKG_VERSION"),
            supported_protocol: ProtocolRange {
                major: 1,
                min_minor: 0,
                max_minor: 6,
            },
            ledger_writer_schema: 1,
            service_configuration_revision: 2,
            service_name: "LocalSandboxSeaWork",
            service_display_name: "LocalSandbox for SeaWork",
            service_account: "LocalSystem",
            service_type: "SERVICE_WIN32_OWN_PROCESS",
            pipe_name: r"\\.\pipe\LocalSandbox.SeaWork.v1",
            pipe_sddl: "O:SYG:SYD:P",
        }
    }

    #[test]
    fn verifies_closed_bundle_and_produces_exact_identity() {
        let root = test_root();
        write_fixture(&root);
        let report = verify_bundle_root(&root, &policy()).unwrap();
        assert_eq!(report.files_verified, 11);
        let identity = report.bundle_identity(&"c".repeat(64)).unwrap();
        assert_eq!(identity.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(identity.bundle_manifest_sha256.len(), 64);

        let image = root.join("runtime/Image");
        fs::write(&image, b"tampered").unwrap();
        assert!(verify_bundle_root(&root, &policy()).is_err());
        fs::write(&image, b"kernel").unwrap();
        assert!(verify_bundle_root(&root, &policy()).is_ok());
        fs::write(root.join("tools/qemu/unlisted.dll"), b"extra").unwrap();
        assert!(verify_bundle_root(&root, &policy()).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_incompatible_protocol_ledger_and_contract_policy() {
        let root = test_root();
        write_fixture(&root);
        let mut incompatible = policy();
        incompatible.supported_protocol.major = 2;
        assert!(verify_bundle_root(&root, &incompatible).is_err());
        let mut incompatible = policy();
        incompatible.ledger_writer_schema = 2;
        assert!(verify_bundle_root(&root, &incompatible).is_err());
        let mut incompatible = policy();
        incompatible.pipe_name = r"\\.\pipe\forged";
        assert!(verify_bundle_root(&root, &incompatible).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn manifest_paths_reject_archive_escape_forms() {
        assert!(validate_manifest_path("runtime/Image").is_ok());
        for path in ["../escape", "/absolute", "C:payload", "a\\b", "file:ads"] {
            assert!(validate_manifest_path(path).is_err(), "accepted {path}");
        }
    }

    fn write_fixture(root: &Path) {
        for (relative, bytes) in [
            ("bin/localsandbox-seawork-service.exe", fake_amd64_pe()),
            ("runtime/Image", b"kernel".to_vec()),
            (
                "runtime/VERSION",
                format!("{}\n", env!("CARGO_PKG_VERSION")).into_bytes(),
            ),
            ("runtime/initramfs.cpio.gz", b"initrd".to_vec()),
            ("runtime/rootfs.ext4", b"rootfs".to_vec()),
            ("tools/qemu/qemu-system-x86_64.exe", b"qemu".to_vec()),
            ("tools/qemu/qemu-img.exe", b"qemu-img".to_vec()),
            ("manifests/sbom.spdx.json", b"{}\n".to_vec()),
            (
                "manifests/runtime-dependencies.json",
                b"{\"schema_version\":1}\n".to_vec(),
            ),
            ("licenses/LICENSE", b"license".to_vec()),
        ] {
            let path = bundle_path(root, relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, bytes).unwrap();
        }
        let policy = policy();
        let contract = json!({
            "schema_version": 1,
            "revision": policy.service_configuration_revision,
            "service": {
                "name": policy.service_name,
                "display_name": policy.service_display_name,
                "account": policy.service_account,
                "service_type": policy.service_type
            },
            "ipc": {
                "pipe_name": policy.pipe_name,
                "pipe_sddl": policy.pipe_sddl,
                "remote_clients_allowed": false
            }
        });
        fs::write(
            root.join("manifests/service-contract.json"),
            serde_json::to_vec_pretty(&contract).unwrap(),
        )
        .unwrap();
        let mut files = Vec::new();
        let mut paths = BTreeSet::new();
        collect_relative_files(root, root, 0, &mut paths).unwrap();
        for relative in paths {
            let path = bundle_path(root, &relative);
            files.push(json!({
                "path": relative,
                "size_bytes": fs::metadata(&path).unwrap().len(),
                "sha256": sha256_file(&path).unwrap()
            }));
        }
        let version = env!("CARGO_PKG_VERSION");
        let manifest = json!({
            "schema_version": 1,
            "local_sandbox_version": version,
            "service_version": version,
            "client_version": version,
            "protocol": {
                "major": 1,
                "current_minor": 6,
                "supported_min_minor": 0,
                "supported_max_minor": 6
            },
            "ledger": {
                "reader_min_schema": 1,
                "reader_max_schema": 1,
                "writer_schema": 1
            },
            "architecture": "x86_64",
            "target": "x86_64-pc-windows-msvc",
            "guest_asset_version": version,
            "qemu": {
                "package_version": "qemu-11.0.50-lsb0.4.0",
                "qemu_version": "11.0.50",
                "package_revision": "lsb0.4.0",
                "artifact_sha256": "4".repeat(64)
            },
            "service_configuration_revision": 2,
            "publisher": {
                "subject": "CN=LocalSandbox Test",
                "sha256_thumbprint": "ab".repeat(32)
            },
            "files": files
        });
        fs::write(
            root.join("manifests/bundle.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        fs::write(
            root.join("manifests/LocalSandboxSeaWork.cat"),
            b"signed catalog",
        )
        .unwrap();
    }

    fn fake_amd64_pe() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x80];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        bytes[0x40..0x44].copy_from_slice(b"PE\0\0");
        bytes[0x44..0x46].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes
    }

    fn test_root() -> PathBuf {
        let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("lsb-package-verifier-{}-{id}", std::process::id()))
    }
}
