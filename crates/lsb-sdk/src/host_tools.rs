use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use flate2::read::GzDecoder;
use lsb_platform::windows_x86_64::apply_qemu_no_window_creation_flags;
use lsb_platform::windows_x86_64::host_tools::{
    managed_qemu_package_metadata, managed_qemu_paths, read_managed_qemu_current,
    read_managed_qemu_manifest, ManagedQemuCurrent, ManagedQemuManifest,
    ManagedQemuPackageMetadata, MANAGED_QEMU_CURRENT_SCHEMA_VERSION,
    MANAGED_QEMU_MANIFEST_SCHEMA_VERSION,
};
use sha2::{Digest, Sha256};
use tar::Archive;

use crate::progress::{
    NoopProgressReporter, ProgressReader, SandboxInitProgress, SandboxInitProgressPhase,
    SandboxInitProgressReporter,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostToolsInitResult {
    pub data_dir: String,
    pub supported: bool,
    pub package_version: Option<String>,
    pub installed: bool,
    pub validated: bool,
    pub qemu_system_x86_64: Option<String>,
    pub qemu_img: Option<String>,
    pub current_json: Option<String>,
}

impl HostToolsInitResult {
    fn unsupported(data_dir: String) -> Self {
        Self {
            data_dir,
            supported: false,
            package_version: None,
            installed: false,
            validated: false,
            qemu_system_x86_64: None,
            qemu_img: None,
            current_json: None,
        }
    }

    fn from_install(
        data_dir: &Path,
        install: ManagedQemuValidatedInstall,
        installed: bool,
    ) -> Self {
        Self {
            data_dir: data_dir.to_string_lossy().into_owned(),
            supported: true,
            package_version: Some(install.package_version),
            installed,
            validated: true,
            qemu_system_x86_64: Some(install.qemu_system_x86_64.display().to_string()),
            qemu_img: Some(install.qemu_img.display().to_string()),
            current_json: Some(install.current_json.display().to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManagedQemuValidatedInstall {
    package_version: String,
    qemu_system_x86_64: PathBuf,
    qemu_img: PathBuf,
    current_json: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManagedQemuInstallMetadata {
    platform: String,
    qemu_version: String,
    lsb_version: String,
    package_version: String,
    artifact_url: String,
    artifact_sha256: String,
    top_level_dir: String,
}

impl ManagedQemuInstallMetadata {
    fn current() -> Self {
        let metadata = managed_qemu_package_metadata();
        Self::from_platform_metadata(metadata)
    }

    fn from_platform_metadata(metadata: ManagedQemuPackageMetadata) -> Self {
        Self {
            platform: metadata.platform.to_string(),
            qemu_version: metadata.qemu_version.to_string(),
            lsb_version: metadata.lsb_version.to_string(),
            package_version: metadata.package_version.to_string(),
            artifact_url: metadata.artifact_url.to_string(),
            artifact_sha256: metadata.artifact_sha256.to_string(),
            top_level_dir: metadata.top_level_dir.to_string(),
        }
    }
}

trait ManagedQemuProbe {
    fn validate(&self, qemu_system_x86_64: &Path, qemu_img: &Path) -> Result<()>;
}

#[derive(Debug, Default, Clone, Copy)]
struct StdManagedQemuProbe;

impl ManagedQemuProbe for StdManagedQemuProbe {
    fn validate(&self, qemu_system_x86_64: &Path, qemu_img: &Path) -> Result<()> {
        run_required_probe(
            qemu_system_x86_64,
            &["--version"],
            "qemu-system-x86_64.exe --version",
        )?;
        run_required_probe(
            qemu_system_x86_64,
            &["--help"],
            "qemu-system-x86_64.exe --help",
        )?;
        let accel_output = run_required_probe(
            qemu_system_x86_64,
            &["-accel", "help"],
            "qemu-system-x86_64.exe -accel help",
        )?;
        if !contains_token(&accel_output, "whpx") {
            bail!("managed QEMU system emulator did not report WHPX in '-accel help' output");
        }

        run_required_probe(qemu_img, &["--version"], "qemu-img.exe --version")
            .or_else(|_| {
                run_required_probe(qemu_img, &["info", "--help"], "qemu-img.exe info --help")
            })
            .context("managed QEMU image utility probe failed")?;

        Ok(())
    }
}

pub fn init_host_tools(data_dir: Option<String>, force: bool) -> Result<HostToolsInitResult> {
    init_host_tools_with_progress(data_dir, force, &NoopProgressReporter)
}

pub(crate) fn init_host_tools_with_progress(
    data_dir: Option<String>,
    force: bool,
    reporter: &dyn SandboxInitProgressReporter,
) -> Result<HostToolsInitResult> {
    let data_dir = data_dir.unwrap_or_else(lsb_platform::default_data_dir);
    if !cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        return Ok(HostToolsInitResult::unsupported(data_dir));
    }

    init_windows_host_tools(Path::new(&data_dir), force, &StdManagedQemuProbe, reporter)
}

fn init_windows_host_tools(
    data_dir: &Path,
    force: bool,
    probe: &impl ManagedQemuProbe,
    reporter: &dyn SandboxInitProgressReporter,
) -> Result<HostToolsInitResult> {
    let metadata = ManagedQemuInstallMetadata::current();
    init_windows_host_tools_with_metadata_and_progress(data_dir, force, &metadata, probe, reporter)
}

#[cfg(test)]
fn init_windows_host_tools_with_metadata(
    data_dir: &Path,
    force: bool,
    metadata: &ManagedQemuInstallMetadata,
    probe: &impl ManagedQemuProbe,
) -> Result<HostToolsInitResult> {
    init_windows_host_tools_with_metadata_and_progress(
        data_dir,
        force,
        metadata,
        probe,
        &NoopProgressReporter,
    )
}

fn init_windows_host_tools_with_metadata_and_progress(
    data_dir: &Path,
    force: bool,
    metadata: &ManagedQemuInstallMetadata,
    probe: &impl ManagedQemuProbe,
    reporter: &dyn SandboxInitProgressReporter,
) -> Result<HostToolsInitResult> {
    if !force {
        if let Ok(install) = validate_existing_install(data_dir, &metadata, probe) {
            return Ok(HostToolsInitResult::from_install(data_dir, install, false));
        }
    }

    let paths = managed_qemu_paths(data_dir);
    fs::create_dir_all(&paths.qemu_dir).with_context(|| {
        format!(
            "failed to create managed QEMU directory '{}'",
            paths.qemu_dir.display()
        )
    })?;

    let archive_path = paths.qemu_dir.join(format!(
        ".download-{}-{}.tar.gz",
        std::process::id(),
        now_secs()?
    ));
    let download_result = (|| {
        download_artifact(&metadata, &archive_path, reporter)?;
        install_managed_qemu_archive_with_progress(
            data_dir,
            metadata,
            &archive_path,
            force,
            probe,
            reporter,
        )
    })();
    let _ = fs::remove_file(&archive_path);

    download_result
}

fn download_artifact(
    metadata: &ManagedQemuInstallMetadata,
    destination: &Path,
    reporter: &dyn SandboxInitProgressReporter,
) -> Result<()> {
    let response = ureq::get(&metadata.artifact_url).call().with_context(|| {
        format!(
            "failed to download managed QEMU artifact '{}'",
            metadata.artifact_url
        )
    })?;
    let total_bytes = response
        .headers()
        .get("content-length")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|total| *total > 0);
    let mut response = ProgressReader::new(
        response.into_body().into_reader(),
        SandboxInitProgressPhase::DownloadingHostTools,
        total_bytes,
        reporter,
    );
    let mut out = File::create(destination).with_context(|| {
        format!(
            "failed to create managed QEMU download staging file '{}'",
            destination.display()
        )
    })?;
    std::io::copy(&mut response, &mut out).with_context(|| {
        format!(
            "failed to write managed QEMU download staging file '{}'",
            destination.display()
        )
    })?;
    out.flush().with_context(|| {
        format!(
            "failed to flush managed QEMU download staging file '{}'",
            destination.display()
        )
    })?;
    Ok(())
}

#[cfg(test)]
fn install_managed_qemu_archive(
    data_dir: &Path,
    metadata: &ManagedQemuInstallMetadata,
    archive_path: &Path,
    _force: bool,
    probe: &impl ManagedQemuProbe,
) -> Result<HostToolsInitResult> {
    install_managed_qemu_archive_with_progress(
        data_dir,
        metadata,
        archive_path,
        _force,
        probe,
        &NoopProgressReporter,
    )
}

fn install_managed_qemu_archive_with_progress(
    data_dir: &Path,
    metadata: &ManagedQemuInstallMetadata,
    archive_path: &Path,
    _force: bool,
    probe: &impl ManagedQemuProbe,
    reporter: &dyn SandboxInitProgressReporter,
) -> Result<HostToolsInitResult> {
    reporter.report(SandboxInitProgress::phase(
        SandboxInitProgressPhase::VerifyingHostTools,
    ));
    let actual_sha = sha256_file(archive_path)?;
    if !actual_sha.eq_ignore_ascii_case(&metadata.artifact_sha256) {
        bail!(
            "managed QEMU artifact sha256 mismatch: expected {}, got {}",
            metadata.artifact_sha256,
            actual_sha
        );
    }

    let paths = managed_qemu_paths(data_dir);
    fs::create_dir_all(&paths.qemu_dir).with_context(|| {
        format!(
            "failed to create managed QEMU directory '{}'",
            paths.qemu_dir.display()
        )
    })?;

    let temp_root = paths.qemu_dir.join(format!(
        ".extract-{}-{}",
        metadata.package_version,
        now_secs()?
    ));
    let _ = fs::remove_dir_all(&temp_root);
    fs::create_dir_all(&temp_root).with_context(|| {
        format!(
            "failed to create managed QEMU extraction directory '{}'",
            temp_root.display()
        )
    })?;

    let install_result = (|| {
        reporter.report(SandboxInitProgress::phase(
            SandboxInitProgressPhase::ExtractingHostTools,
        ));
        extract_managed_qemu_archive(archive_path, &temp_root, &metadata.top_level_dir)?;
        let extracted_package = temp_root.join(&metadata.top_level_dir);
        reporter.report(SandboxInitProgress::phase(
            SandboxInitProgressPhase::ValidatingHostTools,
        ));
        let staged =
            validate_package_dir_contents(&extracted_package, metadata, &paths.current_json)?;
        let qemu_system_relative = staged
            .qemu_system_x86_64
            .strip_prefix(&extracted_package)
            .context("managed QEMU system emulator path is outside staged package")?
            .to_path_buf();
        let qemu_img_relative = staged
            .qemu_img
            .strip_prefix(&extracted_package)
            .context("managed QEMU image utility path is outside staged package")?
            .to_path_buf();

        if paths.package_dir.exists() {
            fs::remove_dir_all(&paths.package_dir).with_context(|| {
                format!(
                    "failed to replace existing managed QEMU package '{}'",
                    paths.package_dir.display()
                )
            })?;
        }
        fs::rename(&extracted_package, &paths.package_dir).with_context(|| {
            format!(
                "failed to install managed QEMU package '{}' to '{}'",
                extracted_package.display(),
                paths.package_dir.display()
            )
        })?;

        let qemu_system_x86_64 = paths.package_dir.join(qemu_system_relative);
        let qemu_img = paths.package_dir.join(qemu_img_relative);
        probe.validate(&qemu_system_x86_64, &qemu_img)?;

        let manifest_path = paths.package_dir.join("manifest.json");
        let current = ManagedQemuCurrent {
            schema_version: MANAGED_QEMU_CURRENT_SCHEMA_VERSION,
            package_version: metadata.package_version.clone(),
            artifact_url: metadata.artifact_url.clone(),
            artifact_sha256: metadata.artifact_sha256.clone(),
            installed_at_unix_secs: now_secs()?,
            qemu_system_x86_64,
            qemu_img,
            manifest: manifest_path,
        };
        write_current_json(&paths.current_json, &current)?;

        Ok(ManagedQemuValidatedInstall {
            package_version: staged.package_version,
            qemu_system_x86_64: current.qemu_system_x86_64,
            qemu_img: current.qemu_img,
            current_json: paths.current_json.clone(),
        })
    })();

    let _ = fs::remove_dir_all(&temp_root);

    install_result.map(|install| HostToolsInitResult::from_install(data_dir, install, true))
}

fn validate_existing_install(
    data_dir: &Path,
    metadata: &ManagedQemuInstallMetadata,
    probe: &impl ManagedQemuProbe,
) -> Result<ManagedQemuValidatedInstall> {
    let paths = managed_qemu_paths(data_dir);
    let current = read_managed_qemu_current(&paths.current_json)?;
    if current.schema_version != MANAGED_QEMU_CURRENT_SCHEMA_VERSION {
        bail!(
            "managed QEMU current schema version {} is unsupported",
            current.schema_version
        );
    }
    if current.package_version != metadata.package_version {
        bail!(
            "managed QEMU current package '{}' does not match expected '{}'",
            current.package_version,
            metadata.package_version
        );
    }
    if current.artifact_url != metadata.artifact_url {
        bail!("managed QEMU current artifact URL does not match this build");
    }
    if !current
        .artifact_sha256
        .eq_ignore_ascii_case(&metadata.artifact_sha256)
    {
        bail!("managed QEMU current artifact sha256 does not match this build");
    }

    let resolved = validate_package_dir(&paths.package_dir, metadata, &paths.current_json, probe)?;
    if resolved.qemu_system_x86_64 != current.qemu_system_x86_64 {
        bail!("managed QEMU current qemu-system path does not match manifest");
    }
    if resolved.qemu_img != current.qemu_img {
        bail!("managed QEMU current qemu-img path does not match manifest");
    }
    if !current.manifest.is_file() {
        bail!(
            "managed QEMU current manifest path is missing: '{}'",
            current.manifest.display()
        );
    }
    Ok(ManagedQemuValidatedInstall {
        package_version: resolved.package_version,
        qemu_system_x86_64: resolved.qemu_system_x86_64,
        qemu_img: resolved.qemu_img,
        current_json: paths.current_json,
    })
}

fn validate_package_dir(
    package_dir: &Path,
    metadata: &ManagedQemuInstallMetadata,
    current_json: &Path,
    probe: &impl ManagedQemuProbe,
) -> Result<ManagedQemuValidatedInstall> {
    let resolved = validate_package_dir_contents(package_dir, metadata, current_json)?;
    probe.validate(&resolved.qemu_system_x86_64, &resolved.qemu_img)?;
    Ok(resolved)
}

fn validate_package_dir_contents(
    package_dir: &Path,
    metadata: &ManagedQemuInstallMetadata,
    current_json: &Path,
) -> Result<ManagedQemuValidatedInstall> {
    let manifest_path = package_dir.join("manifest.json");
    let manifest = read_managed_qemu_manifest(&manifest_path)?;
    validate_manifest_metadata(&manifest, metadata)?;

    if manifest.files.is_empty() {
        bail!("managed QEMU manifest must list packaged files");
    }
    for entry in &manifest.files {
        let relative_path = validate_relative_path(&entry.path)?;
        let path = package_dir.join(relative_path);
        if !path.is_file() {
            bail!("managed QEMU manifest file '{}' is missing", entry.path);
        }
        let metadata = fs::metadata(&path)
            .with_context(|| format!("failed to stat managed QEMU file '{}'", path.display()))?;
        if metadata.len() != entry.size_bytes {
            bail!(
                "managed QEMU manifest file '{}' size mismatch: expected {}, got {}",
                entry.path,
                entry.size_bytes,
                metadata.len()
            );
        }
        let actual_sha = sha256_file(&path)?;
        if !actual_sha.eq_ignore_ascii_case(&entry.sha256) {
            bail!(
                "managed QEMU manifest file '{}' sha256 mismatch: expected {}, got {}",
                entry.path,
                entry.sha256,
                actual_sha
            );
        }
    }

    for required in [
        "manifest.json",
        "COPYING",
        "COPYING.LIB",
        "VERSION",
        "README.rst",
    ] {
        let path = package_dir.join(required);
        if !path.is_file() {
            bail!("managed QEMU package is missing required file '{required}'");
        }
    }

    let qemu_system_x86_64 =
        package_dir.join(validate_relative_path(&manifest.qemu_system_x86_64)?);
    let qemu_img = package_dir.join(validate_relative_path(&manifest.qemu_img)?);
    if !qemu_system_x86_64.is_file() {
        bail!(
            "managed QEMU system emulator from manifest is missing: '{}'",
            qemu_system_x86_64.display()
        );
    }
    if !qemu_img.is_file() {
        bail!(
            "managed QEMU image utility from manifest is missing: '{}'",
            qemu_img.display()
        );
    }

    Ok(ManagedQemuValidatedInstall {
        package_version: manifest.package_version,
        qemu_system_x86_64,
        qemu_img,
        current_json: current_json.to_path_buf(),
    })
}

fn validate_manifest_metadata(
    manifest: &ManagedQemuManifest,
    metadata: &ManagedQemuInstallMetadata,
) -> Result<()> {
    if manifest.schema_version != MANAGED_QEMU_MANIFEST_SCHEMA_VERSION {
        bail!(
            "managed QEMU manifest schema version {} is unsupported",
            manifest.schema_version
        );
    }
    if manifest.package_version != metadata.package_version {
        bail!(
            "managed QEMU manifest package '{}' does not match expected '{}'",
            manifest.package_version,
            metadata.package_version
        );
    }
    if manifest.qemu_version != metadata.qemu_version {
        bail!(
            "managed QEMU manifest QEMU version '{}' does not match expected '{}'",
            manifest.qemu_version,
            metadata.qemu_version
        );
    }
    if manifest.lsb_version != metadata.lsb_version {
        bail!(
            "managed QEMU manifest LSB version '{}' does not match expected '{}'",
            manifest.lsb_version,
            metadata.lsb_version
        );
    }
    if manifest.platform != metadata.platform {
        bail!(
            "managed QEMU manifest platform '{}' does not match expected '{}'",
            manifest.platform,
            metadata.platform
        );
    }
    Ok(())
}

fn extract_managed_qemu_archive(
    archive_path: &Path,
    destination_root: &Path,
    expected_top_level: &str,
) -> Result<()> {
    let archive_file = File::open(archive_path).with_context(|| {
        format!(
            "failed to open managed QEMU artifact '{}'",
            archive_path.display()
        )
    })?;
    let decoder = GzDecoder::new(archive_file);
    let mut archive = Archive::new(decoder);

    for entry in archive
        .entries()
        .context("failed to read managed QEMU archive")?
    {
        let mut entry = entry.context("failed to read managed QEMU archive entry")?;
        let raw_path = entry
            .path()
            .context("failed to read managed QEMU archive entry path")?;
        let raw_path = raw_path
            .to_str()
            .ok_or_else(|| anyhow!("managed QEMU archive entry path is not valid UTF-8"))?;
        let normalized = validate_relative_path(raw_path)?;
        let first = normalized
            .components()
            .next()
            .and_then(|component| component.as_os_str().to_str())
            .ok_or_else(|| anyhow!("managed QEMU archive entry path is empty"))?;
        if first != expected_top_level {
            bail!(
                "managed QEMU archive entry '{}' is outside expected top-level directory '{}'",
                raw_path,
                expected_top_level
            );
        }

        let destination = destination_root.join(&normalized);
        let entry_type = entry.header().entry_type();
        if entry_type.is_dir() {
            fs::create_dir_all(&destination).with_context(|| {
                format!(
                    "failed to create managed QEMU archive directory '{}'",
                    destination.display()
                )
            })?;
        } else if entry_type.is_file() {
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent).with_context(|| {
                    format!(
                        "failed to create managed QEMU archive parent directory '{}'",
                        parent.display()
                    )
                })?;
            }
            entry.unpack(&destination).with_context(|| {
                format!(
                    "failed to extract managed QEMU archive file '{}'",
                    destination.display()
                )
            })?;
        } else {
            bail!(
                "managed QEMU archive entry '{}' has unsupported type",
                raw_path
            );
        }
    }

    Ok(())
}

fn validate_relative_path(value: &str) -> Result<PathBuf> {
    if value.is_empty() {
        bail!("managed QEMU relative path is empty");
    }
    if value.contains('\0') {
        bail!("managed QEMU relative path contains a NUL byte");
    }
    if value.starts_with('/') || value.starts_with('\\') {
        bail!("managed QEMU relative path must not be absolute: '{value}'");
    }
    if value.contains(':') {
        bail!("managed QEMU relative path must not contain a Windows prefix or stream: '{value}'");
    }

    let normalized = value.replace('\\', "/");
    let trimmed = normalized.trim_end_matches('/');
    if trimmed.is_empty() {
        bail!("managed QEMU relative path is empty");
    }

    let mut path = PathBuf::new();
    for component in trimmed.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            bail!("managed QEMU relative path contains an unsafe component: '{value}'");
        }
        path.push(component);
    }
    Ok(path)
}

fn write_current_json(path: &Path, current: &ManagedQemuCurrent) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("managed QEMU current path has no parent"))?;
    fs::create_dir_all(parent).with_context(|| {
        format!(
            "failed to create managed QEMU current directory '{}'",
            parent.display()
        )
    })?;
    let tmp = path.with_extension(format!("json.tmp-{}", std::process::id()));
    let json = serde_json::to_string_pretty(current)
        .context("failed to serialize managed QEMU current metadata")?;
    fs::write(&tmp, format!("{json}\n")).with_context(|| {
        format!(
            "failed to write managed QEMU current staging file '{}'",
            tmp.display()
        )
    })?;
    fs::rename(&tmp, path).with_context(|| {
        format!(
            "failed to activate managed QEMU current file '{}'",
            path.display()
        )
    })?;
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)
        .with_context(|| format!("failed to open '{}' for sha256", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("failed to read '{}' for sha256", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn run_required_probe(program: &Path, args: &[&str], label: &'static str) -> Result<String> {
    let mut command = Command::new(program);
    command.args(args);
    apply_qemu_no_window_creation_flags(&mut command);
    let output = command.output().with_context(|| {
        format!(
            "failed to run managed QEMU probe {label} using '{}'",
            program.display()
        )
    })?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !output.status.success() {
        bail!(
            "managed QEMU probe {label} failed with {}: stdout: {}; stderr: {}",
            output.status,
            empty_as_placeholder(&stdout),
            empty_as_placeholder(&stderr)
        );
    }
    Ok(match (stdout.is_empty(), stderr.is_empty()) {
        (true, true) => String::new(),
        (false, true) => stdout,
        (true, false) => stderr,
        (false, false) => format!("{stdout}\n{stderr}"),
    })
}

fn contains_token(output: &str, token: &str) -> bool {
    output
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_' && ch != '-')
        .any(|candidate| candidate.eq_ignore_ascii_case(token))
}

fn empty_as_placeholder(value: &str) -> &str {
    if value.is_empty() {
        "<empty>"
    } else {
        value
    }
}

fn now_secs() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs())
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write as _};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use flate2::write::GzEncoder;
    use flate2::Compression;
    use tar::{Builder, Header};

    use super::*;

    static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

    #[derive(Debug, Default)]
    struct FakeProbe {
        calls: AtomicUsize,
        paths: Mutex<Vec<(PathBuf, PathBuf)>>,
    }

    impl ManagedQemuProbe for FakeProbe {
        fn validate(&self, qemu_system_x86_64: &Path, qemu_img: &Path) -> Result<()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if !qemu_system_x86_64.is_file() {
                bail!("missing fake qemu system path");
            }
            if !qemu_img.is_file() {
                bail!("missing fake qemu-img path");
            }
            self.paths
                .lock()
                .expect("fake probe paths lock")
                .push((qemu_system_x86_64.to_path_buf(), qemu_img.to_path_buf()));
            Ok(())
        }
    }

    fn temp_dir(label: &str) -> PathBuf {
        let id = TEMP_COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "lsb-managed-qemu-{label}-{}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create temp dir");
        path
    }

    fn test_metadata(archive_sha: String) -> ManagedQemuInstallMetadata {
        ManagedQemuInstallMetadata {
            platform: "windows-x86_64".to_string(),
            qemu_version: "11.0.50".to_string(),
            lsb_version: "0.4.0".to_string(),
            package_version: "qemu-11.0.50-lsb0.4.0".to_string(),
            artifact_url: "file://test-qemu.tar.gz".to_string(),
            artifact_sha256: archive_sha,
            top_level_dir: "qemu-11.0.50-lsb0.4.0".to_string(),
        }
    }

    fn write_archive(root: &Path, files: &[(&str, &[u8])]) -> PathBuf {
        let archive_path = root.join("qemu.tar.gz");
        let archive_file = File::create(&archive_path).expect("create archive");
        let encoder = GzEncoder::new(archive_file, Compression::default());
        let mut builder = Builder::new(encoder);
        for (path, contents) in files {
            let mut header = Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, path, Cursor::new(*contents))
                .expect("append archive file");
        }
        builder.finish().expect("finish archive");
        archive_path
    }

    fn write_raw_archive(root: &Path, path: &str, contents: &[u8]) -> PathBuf {
        let archive_path = root.join("qemu.tar.gz");
        let archive_file = File::create(&archive_path).expect("create archive");
        let mut encoder = GzEncoder::new(archive_file, Compression::default());
        let mut header = [0u8; 512];

        let path_bytes = path.as_bytes();
        assert!(path_bytes.len() <= 100);
        header[..path_bytes.len()].copy_from_slice(path_bytes);
        write_octal(&mut header[100..108], 0o755);
        write_octal(&mut header[108..116], 0);
        write_octal(&mut header[116..124], 0);
        write_octal(&mut header[124..136], contents.len() as u64);
        write_octal(&mut header[136..148], 0);
        header[148..156].fill(b' ');
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");

        let checksum = header.iter().map(|byte| u32::from(*byte)).sum::<u32>();
        write!(&mut header[148..156], "{checksum:06o}\0 ").expect("write checksum");

        encoder.write_all(&header).expect("write archive header");
        encoder.write_all(contents).expect("write archive file");
        let padding = (512 - (contents.len() % 512)) % 512;
        if padding > 0 {
            encoder
                .write_all(&vec![0u8; padding])
                .expect("write archive padding");
        }
        encoder
            .write_all(&[0u8; 1024])
            .expect("write archive terminator");
        encoder.finish().expect("finish archive");
        archive_path
    }

    fn write_octal(mut field: &mut [u8], value: u64) {
        write!(field, "{value:0width$o}\0", width = field.len() - 1).expect("write octal field");
    }

    fn sha256_bytes(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        format!("{:x}", hasher.finalize())
    }

    fn package_files() -> Vec<(String, Vec<u8>)> {
        let qemu_system = b"fake qemu system".to_vec();
        let qemu_img = b"fake qemu img".to_vec();
        let copying = b"copying".to_vec();
        let copying_lib = b"copying lib".to_vec();
        let version = b"11.0.50".to_vec();
        let readme = b"readme".to_vec();
        let manifest = format!(
            r#"{{
              "schema_version": 1,
              "package_version": "qemu-11.0.50-lsb0.4.0",
              "qemu_version": "11.0.50",
              "lsb_version": "0.4.0",
              "platform": "windows-x86_64",
              "qemu_system_x86_64": "qemu-system-x86_64.exe",
              "qemu_img": "qemu-img.exe",
              "files": [
                {{"path":"qemu-system-x86_64.exe","size_bytes":{},"sha256":"{}"}},
                {{"path":"qemu-img.exe","size_bytes":{},"sha256":"{}"}},
                {{"path":"COPYING","size_bytes":{},"sha256":"{}"}},
                {{"path":"COPYING.LIB","size_bytes":{},"sha256":"{}"}},
                {{"path":"VERSION","size_bytes":{},"sha256":"{}"}},
                {{"path":"README.rst","size_bytes":{},"sha256":"{}"}}
              ]
            }}"#,
            qemu_system.len(),
            sha256_bytes(&qemu_system),
            qemu_img.len(),
            sha256_bytes(&qemu_img),
            copying.len(),
            sha256_bytes(&copying),
            copying_lib.len(),
            sha256_bytes(&copying_lib),
            version.len(),
            sha256_bytes(&version),
            readme.len(),
            sha256_bytes(&readme),
        )
        .into_bytes();

        vec![
            (
                "qemu-11.0.50-lsb0.4.0/qemu-system-x86_64.exe".to_string(),
                qemu_system,
            ),
            ("qemu-11.0.50-lsb0.4.0/qemu-img.exe".to_string(), qemu_img),
            ("qemu-11.0.50-lsb0.4.0/COPYING".to_string(), copying),
            ("qemu-11.0.50-lsb0.4.0/COPYING.LIB".to_string(), copying_lib),
            ("qemu-11.0.50-lsb0.4.0/VERSION".to_string(), version),
            ("qemu-11.0.50-lsb0.4.0/README.rst".to_string(), readme),
            ("qemu-11.0.50-lsb0.4.0/manifest.json".to_string(), manifest),
        ]
    }

    fn write_valid_archive(root: &Path) -> (PathBuf, ManagedQemuInstallMetadata) {
        let files = package_files();
        let borrowed = files
            .iter()
            .map(|(path, bytes)| (path.as_str(), bytes.as_slice()))
            .collect::<Vec<_>>();
        let archive = write_archive(root, &borrowed);
        let sha = sha256_file(&archive).expect("hash archive");
        (archive, test_metadata(sha))
    }

    #[cfg(unix)]
    fn make_current_executable(path: &Path) {
        let mut permissions = fs::metadata(path).expect("stat").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).expect("chmod");
    }

    #[cfg(not(unix))]
    fn make_current_executable(_path: &Path) {}

    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    #[test]
    fn init_host_tools_is_noop_on_non_windows_hosts() {
        let result = init_host_tools(Some("custom-data".to_string()), false)
            .expect("host tools init should be a no-op");

        assert!(!result.supported);
        assert_eq!(result.data_dir, "custom-data");
        assert!(!result.installed);
    }

    #[test]
    fn safe_extraction_installs_manifest_driven_root_executables_and_current_json() {
        let root = temp_dir("install");
        let data_dir = root.join("data");
        let (archive, metadata) = write_valid_archive(&root);
        let probe = FakeProbe::default();

        let result = install_managed_qemu_archive(&data_dir, &metadata, &archive, false, &probe)
            .expect("install should succeed");

        assert!(result.supported);
        assert!(result.installed);
        assert_eq!(
            result.package_version.as_deref(),
            Some("qemu-11.0.50-lsb0.4.0")
        );
        let paths = managed_qemu_paths(&data_dir);
        let qemu_system = paths.package_dir.join("qemu-system-x86_64.exe");
        let qemu_img = paths.package_dir.join("qemu-img.exe");
        make_current_executable(&qemu_system);
        make_current_executable(&qemu_img);
        assert!(qemu_system.is_file());
        assert!(qemu_img.is_file());

        let current = lsb_platform::windows_x86_64::host_tools::read_managed_qemu_current(
            &paths.current_json,
        )
        .expect("read current json");
        assert_eq!(current.qemu_system_x86_64, qemu_system);
        assert_eq!(current.qemu_img, qemu_img);
        assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            probe
                .paths
                .lock()
                .expect("fake probe paths lock")
                .as_slice(),
            &[(qemu_system, qemu_img)]
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn managed_qemu_install_reports_verify_extract_validate_in_order() {
        let root = temp_dir("progress-order");
        let data_dir = root.join("data");
        let (archive, metadata) = write_valid_archive(&root);
        let probe = FakeProbe::default();
        let events = Mutex::new(Vec::new());
        let reporter = |event| events.lock().expect("progress events lock").push(event);

        install_managed_qemu_archive_with_progress(
            &data_dir, &metadata, &archive, false, &probe, &reporter,
        )
        .expect("install should succeed");

        let phases = events
            .into_inner()
            .expect("progress events")
            .into_iter()
            .map(|event| event.phase)
            .collect::<Vec<_>>();
        assert_eq!(
            phases,
            vec![
                SandboxInitProgressPhase::VerifyingHostTools,
                SandboxInitProgressPhase::ExtractingHostTools,
                SandboxInitProgressPhase::ValidatingHostTools,
            ]
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn existing_valid_install_is_idempotent_without_download_or_reinstall() {
        let root = temp_dir("idempotent");
        let data_dir = root.join("data");
        let (archive, metadata) = write_valid_archive(&root);
        let probe = FakeProbe::default();

        let first = install_managed_qemu_archive(&data_dir, &metadata, &archive, false, &probe)
            .expect("first install");
        assert!(first.installed);
        let current_before = fs::read_to_string(managed_qemu_paths(&data_dir).current_json)
            .expect("read current before");

        let second = init_windows_host_tools_with_metadata(&data_dir, false, &metadata, &probe)
            .expect("existing install should validate");
        let current_after = fs::read_to_string(managed_qemu_paths(&data_dir).current_json)
            .expect("read current after");

        assert!(!second.installed);
        assert_eq!(current_before, current_after);
        assert_eq!(probe.calls.load(Ordering::SeqCst), 2);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn existing_valid_install_emits_no_windows_install_phases() {
        let root = temp_dir("existing-progress");
        let data_dir = root.join("data");
        let (archive, metadata) = write_valid_archive(&root);
        let probe = FakeProbe::default();
        install_managed_qemu_archive(&data_dir, &metadata, &archive, false, &probe)
            .expect("initial install");
        let events = Mutex::new(Vec::new());
        let reporter = |event| events.lock().expect("progress events lock").push(event);

        let result = init_windows_host_tools_with_metadata_and_progress(
            &data_dir, false, &metadata, &probe, &reporter,
        )
        .expect("existing install should validate");

        assert!(!result.installed);
        assert!(events.into_inner().expect("progress events").is_empty());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn force_reinstall_rewrites_current_json() {
        let root = temp_dir("force");
        let data_dir = root.join("data");
        let (archive, metadata) = write_valid_archive(&root);
        let probe = FakeProbe::default();

        install_managed_qemu_archive(&data_dir, &metadata, &archive, false, &probe)
            .expect("first install");
        let paths = managed_qemu_paths(&data_dir);
        fs::write(paths.package_dir.join("stale.txt"), b"stale").expect("write stale file");

        let result = install_managed_qemu_archive(&data_dir, &metadata, &archive, true, &probe)
            .expect("force install");

        assert!(result.installed);
        assert!(!paths.package_dir.join("stale.txt").exists());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn hash_mismatch_rejects_artifact_before_extraction() {
        let root = temp_dir("hash-mismatch");
        let data_dir = root.join("data");
        let (archive, mut metadata) = write_valid_archive(&root);
        metadata.artifact_sha256 = "00".repeat(32);
        let probe = FakeProbe::default();

        let err = install_managed_qemu_archive(&data_dir, &metadata, &archive, false, &probe)
            .expect_err("hash mismatch should fail");

        assert!(err.to_string().contains("sha256 mismatch"));
        assert!(!managed_qemu_paths(&data_dir).package_dir.exists());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn missing_required_binary_is_rejected() {
        let root = temp_dir("missing-binary");
        let data_dir = root.join("data");
        let mut files = package_files();
        files.retain(|(path, _)| !path.ends_with("qemu-img.exe"));
        let borrowed = files
            .iter()
            .map(|(path, bytes)| (path.as_str(), bytes.as_slice()))
            .collect::<Vec<_>>();
        let archive = write_archive(&root, &borrowed);
        let metadata = test_metadata(sha256_file(&archive).expect("hash archive"));
        let probe = FakeProbe::default();

        let err = install_managed_qemu_archive(&data_dir, &metadata, &archive, false, &probe)
            .expect_err("missing qemu-img should fail");

        assert!(err.to_string().contains("qemu-img.exe"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn archive_traversal_entry_is_rejected() {
        let root = temp_dir("traversal");
        let data_dir = root.join("data");
        let archive = write_raw_archive(&root, r"qemu-11.0.50-lsb0.4.0\..\escape.txt", b"escape");
        let metadata = test_metadata(sha256_file(&archive).expect("hash archive"));
        let probe = FakeProbe::default();

        let err = install_managed_qemu_archive(&data_dir, &metadata, &archive, false, &probe)
            .expect_err("traversal should fail");

        assert!(err.to_string().contains("unsafe component"));
        assert!(!root.join("escape.txt").exists());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn validate_relative_path_rejects_windows_prefixes_and_absolute_paths() {
        for path in [
            "../qemu.exe",
            "qemu/../../qemu.exe",
            "/qemu.exe",
            r"C:\qemu\qemu.exe",
            r"\\server\share\qemu.exe",
            r"\\?\C:\qemu.exe",
            "qemu.exe:stream",
        ] {
            assert!(
                validate_relative_path(path).is_err(),
                "{path} should be rejected"
            );
        }

        assert_eq!(
            validate_relative_path(r"bin\qemu-img.exe").expect("valid relative path"),
            PathBuf::from("bin").join("qemu-img.exe")
        );
    }
}
