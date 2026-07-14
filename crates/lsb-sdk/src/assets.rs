use std::fs;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use lsb_platform::{asset_paths, supported_runtime_platform, AssetPaths};
use tar::Archive;

use crate::fixes::{apply_sandbox_fixes, SandboxFixResult};
use crate::host_tools::{init_host_tools_with_progress, HostToolsInitResult};
use crate::progress::{
    NoopProgressReporter, ProgressReader, SandboxInitProgress, SandboxInitProgressPhase,
    SandboxInitProgressReporter,
};

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
    init_sandbox_with_progress(options, &NoopProgressReporter)
}

/// Ensure runtime assets exist while reporting observational progress.
pub fn init_sandbox_with_progress(
    options: SandboxInitOptions,
    reporter: &dyn SandboxInitProgressReporter,
) -> Result<SandboxInitResult> {
    init_sandbox_version_with_progress(options, CURRENT_VERSION, reporter)
}

/// Ensure runtime assets for a specific version exist in the configured data directory.
///
/// This is mainly used by the CLI upgrade flow, where the currently running
/// binary may need to download assets for the newly installed version.
pub fn init_sandbox_version(
    options: SandboxInitOptions,
    version: &str,
) -> Result<SandboxInitResult> {
    init_sandbox_version_with_progress(options, version, &NoopProgressReporter)
}

/// Ensure runtime assets for a specific version exist while reporting progress.
pub fn init_sandbox_version_with_progress(
    options: SandboxInitOptions,
    version: &str,
    reporter: &dyn SandboxInitProgressReporter,
) -> Result<SandboxInitResult> {
    reporter.report(SandboxInitProgress::phase(
        SandboxInitProgressPhase::Checking,
    ));
    let data_dir = options
        .data_dir
        .unwrap_or_else(lsb_platform::default_data_dir);
    let force = options.force;
    let fixes = if options.fix {
        reporter.report(SandboxInitProgress::phase(
            SandboxInitProgressPhase::ApplyingFixes,
        ));
        apply_sandbox_fixes()?
    } else {
        Vec::new()
    };
    let host_tools = init_host_tools_with_progress(Some(data_dir.clone()), force, reporter)?;
    init_runtime_assets_for_data_dir(data_dir, version, force, Some(host_tools), fixes, reporter)
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
    init_runtime_assets_for_data_dir(
        data_dir,
        version,
        options.force,
        None,
        fixes,
        &NoopProgressReporter,
    )
}

fn init_runtime_assets_for_data_dir(
    data_dir: String,
    version: &str,
    force: bool,
    host_tools: Option<HostToolsInitResult>,
    fixes: Vec<SandboxFixResult>,
    reporter: &dyn SandboxInitProgressReporter,
) -> Result<SandboxInitResult> {
    init_runtime_assets_for_data_dir_with_downloader(
        data_dir,
        version,
        force,
        host_tools,
        fixes,
        reporter,
        download_os_image_version,
    )
}

fn init_runtime_assets_for_data_dir_with_downloader<F>(
    data_dir: String,
    version: &str,
    force: bool,
    host_tools: Option<HostToolsInitResult>,
    fixes: Vec<SandboxFixResult>,
    reporter: &dyn SandboxInitProgressReporter,
    downloader: F,
) -> Result<SandboxInitResult>
where
    F: FnOnce(&str, &str, &dyn SandboxInitProgressReporter) -> Result<()>,
{
    let paths = asset_paths(&data_dir);

    let version_record_path = format!("{}/cas/base-versions/{}.json", data_dir, version);
    let was_pinned = std::path::Path::new(&version_record_path).exists();

    if !force && assets_ready_for_version(&data_dir, version) {
        reporter.report(SandboxInitProgress::phase(
            SandboxInitProgressPhase::PinningRuntimeAssets,
        ));
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

    downloader(&data_dir, version, reporter)?;
    reporter.report(SandboxInitProgress::phase(
        SandboxInitProgressPhase::PinningRuntimeAssets,
    ));
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

fn download_os_image_version(
    data_dir: &str,
    version: &str,
    reporter: &dyn SandboxInitProgressReporter,
) -> Result<()> {
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

    let total_bytes = response
        .headers()
        .get("content-length")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|total| *total > 0);

    install_runtime_assets_from_reader(
        data_dir,
        version,
        response.into_body().into_reader(),
        total_bytes,
        reporter,
    )
}

fn install_runtime_assets_from_reader<R: Read>(
    data_dir: &str,
    version: &str,
    reader: R,
    total_bytes: Option<u64>,
    reporter: &dyn SandboxInitProgressReporter,
) -> Result<()> {
    let reader = ProgressReader::new(
        reader,
        SandboxInitProgressPhase::DownloadingAndExtractingRuntimeAssets,
        total_bytes,
        reporter,
    );
    let decoder = GzDecoder::new(reader);
    let mut archive = Archive::new(decoder);

    archive
        .unpack(data_dir)
        .context("failed to extract OS image")?;
    // Tar stops at its end markers, which can precede the gzip stream's EOF.
    // Drain the decoder so the compressed-byte reader can emit a true final
    // event and so the response body is consumed before VERSION is written.
    let mut decoder = archive.into_inner();
    std::io::copy(&mut decoder, &mut std::io::sink())
        .context("failed to finish reading OS image")?;
    let mut reader = decoder.into_inner();
    reader.finish();

    let paths = asset_paths(data_dir);
    fs::write(&paths.version_file, format!("{}\n", version))
        .context("failed to write VERSION file")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::io::Cursor;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use flate2::write::GzEncoder;
    use flate2::Compression;
    use tar::{Builder, Header};

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

    fn runtime_archive(files: &[(&str, &[u8])]) -> Vec<u8> {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = Builder::new(encoder);
        for (path, contents) in files {
            let mut header = Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, path, Cursor::new(*contents))
                .expect("append runtime archive entry");
        }
        builder
            .into_inner()
            .expect("finish tar archive")
            .finish()
            .expect("finish gzip archive")
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

    #[test]
    fn ready_runtime_reports_checking_and_pinning_without_download() {
        let data_dir = temp_data_dir();
        write_ready_assets(&data_dir, CURRENT_VERSION);
        let events = RefCell::new(Vec::new());
        let reporter = |event| events.borrow_mut().push(event);

        let result = init_sandbox_version_with_progress(
            SandboxInitOptions {
                data_dir: Some(data_dir.to_string_lossy().into_owned()),
                force: false,
                fix: false,
            },
            CURRENT_VERSION,
            &reporter,
        )
        .expect("ready runtime init");

        assert!(!result.downloaded);
        let phases = events
            .into_inner()
            .into_iter()
            .map(|event| event.phase)
            .collect::<Vec<_>>();
        assert_eq!(
            phases,
            vec![
                SandboxInitProgressPhase::Checking,
                SandboxInitProgressPhase::PinningRuntimeAssets,
            ]
        );
        assert!(!phases.contains(&SandboxInitProgressPhase::DownloadingAndExtractingRuntimeAssets));

        let _ = fs::remove_dir_all(data_dir);
    }

    #[test]
    fn reader_oriented_install_extracts_runtime_and_reports_compressed_bytes() {
        let data_dir = temp_data_dir();
        fs::create_dir_all(&data_dir).expect("create runtime data dir");
        let archive = runtime_archive(&[
            ("Image", b"kernel"),
            ("rootfs.ext4", b"rootfs"),
            ("initramfs.cpio.gz", b"initramfs"),
        ]);
        let archive_len = archive.len() as u64;
        let events = RefCell::new(Vec::new());
        let reporter = |event| events.borrow_mut().push(event);

        install_runtime_assets_from_reader(
            &data_dir.to_string_lossy(),
            "test-version",
            Cursor::new(archive),
            Some(archive_len),
            &reporter,
        )
        .expect("install runtime fixture");

        assert_eq!(fs::read(data_dir.join("Image")).unwrap(), b"kernel");
        assert_eq!(
            fs::read_to_string(data_dir.join("VERSION")).unwrap(),
            "test-version\n"
        );
        let events = events.into_inner();
        assert_eq!(events.first().unwrap().downloaded_bytes, Some(0));
        assert_eq!(events.last().unwrap().downloaded_bytes, Some(archive_len));
        assert!(events.iter().all(|event| {
            event.phase == SandboxInitProgressPhase::DownloadingAndExtractingRuntimeAssets
        }));

        let _ = fs::remove_dir_all(data_dir);
    }

    #[test]
    fn force_uses_instrumented_runtime_download_path_before_pinning() {
        let data_dir = temp_data_dir();
        write_ready_assets(&data_dir, CURRENT_VERSION);
        let archive = runtime_archive(&[
            ("Image", b"new-kernel"),
            ("rootfs.ext4", b"new-rootfs"),
            ("initramfs.cpio.gz", b"new-initramfs"),
        ]);
        let events = RefCell::new(Vec::new());
        let reporter = |event| events.borrow_mut().push(event);

        let result = init_runtime_assets_for_data_dir_with_downloader(
            data_dir.to_string_lossy().into_owned(),
            CURRENT_VERSION,
            true,
            None,
            Vec::new(),
            &reporter,
            |data_dir, version, reporter| {
                install_runtime_assets_from_reader(
                    data_dir,
                    version,
                    Cursor::new(&archive),
                    Some(archive.len() as u64),
                    reporter,
                )
            },
        )
        .expect("forced runtime init");

        assert!(result.downloaded);
        assert_eq!(
            fs::read(data_dir.join("rootfs.ext4")).unwrap(),
            b"new-rootfs"
        );
        let phases = events
            .into_inner()
            .into_iter()
            .map(|event| event.phase)
            .collect::<Vec<_>>();
        assert_eq!(
            phases.last(),
            Some(&SandboxInitProgressPhase::PinningRuntimeAssets)
        );
        assert!(phases.contains(&SandboxInitProgressPhase::DownloadingAndExtractingRuntimeAssets));

        let _ = fs::remove_dir_all(data_dir);
    }

    #[test]
    fn noop_progress_entrypoint_preserves_result_and_filesystem_state() {
        let first_dir = temp_data_dir();
        let second_dir = temp_data_dir();
        write_ready_assets(&first_dir, CURRENT_VERSION);
        write_ready_assets(&second_dir, CURRENT_VERSION);

        let first = init_sandbox(SandboxInitOptions {
            data_dir: Some(first_dir.to_string_lossy().into_owned()),
            force: false,
            fix: false,
        })
        .expect("compatibility entrypoint");
        let second = init_sandbox_with_progress(
            SandboxInitOptions {
                data_dir: Some(second_dir.to_string_lossy().into_owned()),
                force: false,
                fix: false,
            },
            &NoopProgressReporter,
        )
        .expect("progress entrypoint");

        assert_eq!(first.version, second.version);
        assert_eq!(first.downloaded, second.downloaded);
        assert_eq!(first.pinned, second.pinned);
        assert_eq!(first.fixes.len(), second.fixes.len());
        assert_eq!(
            first.host_tools.unwrap().supported,
            second.host_tools.unwrap().supported
        );
        for relative in [
            "Image",
            "rootfs.ext4",
            "initramfs.cpio.gz",
            "VERSION",
            &format!("cas/base-versions/{CURRENT_VERSION}.json"),
        ] {
            assert_eq!(
                first_dir.join(relative).exists(),
                second_dir.join(relative).exists()
            );
        }

        let _ = fs::remove_dir_all(first_dir);
        let _ = fs::remove_dir_all(second_dir);
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
