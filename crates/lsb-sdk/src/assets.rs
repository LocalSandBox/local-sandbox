use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use lsb_platform::{asset_paths, supported_runtime_platform, AssetPaths};
use tar::Archive;

use crate::fixes::{apply_sandbox_fixes, SandboxFixResult};
use crate::host_tools::{init_host_tools, HostToolsInitResult};

const GITHUB_REPO: &str = "LocalSandBox/local-sandbox";

/// Version of runtime assets expected by this SDK build.
pub const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Options for preparing sandbox runtime assets.
#[derive(Debug, Clone, Default)]
pub struct SandboxInitOptions {
    /// Runtime data directory containing kernel, rootfs, initramfs, checkpoints, and instances.
    /// Defaults to the platform runtime data directory.
    pub data_dir: Option<String>,
    /// Re-download assets even when the expected files and VERSION marker already exist.
    pub force: bool,
    /// Apply every automatic host configuration fix supported by this SDK build.
    pub fix: bool,
}

/// Result returned after checking or downloading sandbox runtime assets.
#[derive(Debug, Clone)]
pub struct SandboxInitResult {
    /// Runtime data directory that was checked or initialized.
    pub data_dir: String,
    /// Runtime asset version that is now expected in the data directory.
    pub version: String,
    /// True when this call downloaded and extracted assets.
    pub downloaded: bool,
    /// True when this call pinned the base rootfs for the first time.
    pub pinned: bool,
    /// Concrete runtime asset paths derived from `data_dir`.
    pub paths: AssetPaths,
    /// Host tool initialization status when this call initialized host tools.
    pub host_tools: Option<HostToolsInitResult>,
    /// Automatic host configuration fixes attempted by this call.
    pub fixes: Vec<SandboxFixResult>,
}

/// Check if the runtime assets exist and match this SDK version.
pub fn assets_ready(data_dir: &str) -> bool {
    assets_ready_for_version(data_dir, CURRENT_VERSION)
}

/// Ensure runtime assets for this SDK version exist in the configured data directory.
///
/// This is an explicit initialization step. `AsyncSandbox::boot` intentionally
/// still fails when assets are missing instead of downloading implicitly.
pub fn init_sandbox(options: SandboxInitOptions) -> Result<SandboxInitResult> {
    init_sandbox_version(options, CURRENT_VERSION)
}

/// Ensure runtime assets for a specific version exist in the configured data directory.
///
/// This is mainly used by the CLI upgrade flow, where the currently running
/// binary may need to download assets for the newly installed version.
pub fn init_sandbox_version(
    options: SandboxInitOptions,
    version: &str,
) -> Result<SandboxInitResult> {
    let data_dir = options
        .data_dir
        .unwrap_or_else(lsb_platform::default_data_dir);
    let force = options.force;
    let fixes = if options.fix {
        apply_sandbox_fixes()?
    } else {
        Vec::new()
    };
    let host_tools = init_host_tools(Some(data_dir.clone()), force)?;
    init_runtime_assets_for_data_dir(data_dir, version, force, Some(host_tools), fixes)
}

/// Ensure runtime assets for a specific version exist without initializing host tools.
///
/// This is intended for callers that already handled host-tool initialization
/// separately for status reporting. Normal users should call `init_sandbox` or
/// `init_sandbox_version`.
pub fn init_runtime_assets_version(
    options: SandboxInitOptions,
    version: &str,
) -> Result<SandboxInitResult> {
    let data_dir = options
        .data_dir
        .unwrap_or_else(lsb_platform::default_data_dir);
    let fixes = if options.fix {
        apply_sandbox_fixes()?
    } else {
        Vec::new()
    };
    init_runtime_assets_for_data_dir(data_dir, version, options.force, None, fixes)
}

fn init_runtime_assets_for_data_dir(
    data_dir: String,
    version: &str,
    force: bool,
    host_tools: Option<HostToolsInitResult>,
    fixes: Vec<SandboxFixResult>,
) -> Result<SandboxInitResult> {
    let paths = asset_paths(&data_dir);

    let version_record_path = format!("{}/cas/base-versions/{}.json", data_dir, version);
    let was_pinned = std::path::Path::new(&version_record_path).exists();

    if !force && assets_ready_for_version(&data_dir, version) {
        lsb_store::pin_base_version(&data_dir, &paths.rootfs, version, false)?;
        return Ok(SandboxInitResult {
            data_dir,
            version: version.to_string(),
            downloaded: false,
            pinned: !was_pinned,
            paths,
            host_tools,
            fixes,
        });
    }

    download_os_image_version(&data_dir, version)?;
    lsb_store::pin_base_version(&data_dir, &paths.rootfs, version, force)?;

    Ok(SandboxInitResult {
        data_dir,
        version: version.to_string(),
        downloaded: true,
        pinned: true,
        paths,
        host_tools,
        fixes,
    })
}

fn assets_ready_for_version(data_dir: &str, version: &str) -> bool {
    let paths = asset_paths(data_dir);

    if !Path::new(&paths.kernel).exists()
        || !Path::new(&paths.rootfs).exists()
        || !Path::new(&paths.initramfs).exists()
    {
        return false;
    }

    match fs::read_to_string(&paths.version_file) {
        Ok(value) => value.trim() == version,
        Err(_) => false,
    }
}

fn download_os_image_version(data_dir: &str, version: &str) -> Result<()> {
    let platform = supported_runtime_platform()?;
    let tag = platform.release_tag(version);
    let tarball_name = platform.os_image_tarball_name(version);
    let url = format!(
        "https://github.com/{}/releases/download/{}/{}",
        GITHUB_REPO, tag, tarball_name
    );

    fs::create_dir_all(data_dir)
        .with_context(|| format!("failed to create data directory: {}", data_dir))?;

    let response = ureq::get(&url)
        .call()
        .with_context(|| format!("download failed - is version {} released?", tag))?;

    let decoder = GzDecoder::new(response.into_body().into_reader());
    let mut archive = Archive::new(decoder);

    archive
        .unpack(data_dir)
        .context("failed to extract OS image")?;

    let paths = asset_paths(data_dir);
    fs::write(&paths.version_file, format!("{}\n", version))
        .context("failed to write VERSION file")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn temp_data_dir() -> PathBuf {
        let id = TEMP_COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!("lsb-sdk-assets-{}-{id}", std::process::id()))
    }

    fn write_ready_assets(data_dir: &Path, version: &str) {
        fs::create_dir_all(data_dir).expect("create data dir");
        fs::write(data_dir.join("Image"), b"kernel").expect("write kernel");
        fs::write(data_dir.join("rootfs.ext4"), b"rootfs").expect("write rootfs");
        fs::write(data_dir.join("initramfs.cpio.gz"), b"initramfs").expect("write initramfs");
        fs::write(data_dir.join("VERSION"), format!("{version}\n")).expect("write version");
    }

    #[test]
    fn assets_ready_is_false_when_required_files_are_missing() {
        let data_dir = temp_data_dir();
        let data_dir_str = data_dir.to_string_lossy();

        assert!(!assets_ready(&data_dir_str));
    }

    #[test]
    fn assets_ready_is_true_when_files_and_version_match() {
        let data_dir = temp_data_dir();
        write_ready_assets(&data_dir, CURRENT_VERSION);
        let data_dir_str = data_dir.to_string_lossy();

        assert!(assets_ready(&data_dir_str));

        let _ = fs::remove_dir_all(data_dir);
    }

    #[test]
    fn init_sandbox_skips_download_when_assets_are_ready() {
        let data_dir = temp_data_dir();
        write_ready_assets(&data_dir, CURRENT_VERSION);
        let data_dir_str = data_dir.to_string_lossy().into_owned();

        let result = init_runtime_assets_version(
            SandboxInitOptions {
                data_dir: Some(data_dir_str.clone()),
                force: false,
                fix: false,
            },
            CURRENT_VERSION,
        )
        .expect("runtime init should succeed without downloading");

        assert_eq!(result.data_dir, data_dir_str);
        assert_eq!(result.version, CURRENT_VERSION);
        assert!(!result.downloaded);
        assert_eq!(result.paths.kernel, format!("{}/Image", result.data_dir));
        assert!(result.host_tools.is_none());
        assert!(result.fixes.is_empty());

        let _ = fs::remove_dir_all(data_dir);
    }

    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    #[test]
    fn init_sandbox_includes_non_windows_host_tools_noop() {
        let data_dir = temp_data_dir();
        write_ready_assets(&data_dir, CURRENT_VERSION);
        let data_dir_str = data_dir.to_string_lossy().into_owned();

        let result = init_sandbox(SandboxInitOptions {
            data_dir: Some(data_dir_str.clone()),
            force: false,
            fix: true,
        })
        .expect("init should succeed without downloading");

        assert_eq!(result.data_dir, data_dir_str);
        assert_eq!(result.version, CURRENT_VERSION);
        assert!(!result.downloaded);
        assert_eq!(result.paths.kernel, format!("{}/Image", result.data_dir));
        assert!(result.host_tools.is_some());
        assert!(!result.host_tools.expect("host tools result").supported);
        assert!(result.fixes.is_empty());

        let _ = fs::remove_dir_all(data_dir);
    }
}
