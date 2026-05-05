use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use lsb_platform::{asset_paths, supported_runtime_platform, AssetPaths};
use tar::Archive;

const GITHUB_REPO: &str = "LocalSandBox/local-sandbox";

/// Version of runtime assets expected by this SDK build.
pub const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Options for preparing sandbox runtime assets.
#[derive(Debug, Clone, Default)]
pub struct SandboxInitOptions {
    /// Runtime data directory containing kernel, rootfs, initramfs, checkpoints, and instances.
    /// Defaults to `~/.local/share/lsb`.
    pub data_dir: Option<String>,
    /// Re-download assets even when the expected files and VERSION marker already exist.
    pub force: bool,
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
    /// Concrete runtime asset paths derived from `data_dir`.
    pub paths: AssetPaths,
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
    let paths = asset_paths(&data_dir);

    if !options.force && assets_ready_for_version(&data_dir, version) {
        return Ok(SandboxInitResult {
            data_dir,
            version: version.to_string(),
            downloaded: false,
            paths,
        });
    }

    download_os_image_version(&data_dir, version)?;

    Ok(SandboxInitResult {
        data_dir,
        version: version.to_string(),
        downloaded: true,
        paths,
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

        let result = init_sandbox(SandboxInitOptions {
            data_dir: Some(data_dir_str.clone()),
            force: false,
        })
        .expect("init should succeed without downloading");

        assert_eq!(result.data_dir, data_dir_str);
        assert_eq!(result.version, CURRENT_VERSION);
        assert!(!result.downloaded);
        assert_eq!(result.paths.kernel, format!("{}/Image", result.data_dir));

        let _ = fs::remove_dir_all(data_dir);
    }
}
