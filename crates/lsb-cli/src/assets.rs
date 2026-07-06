use std::fs;
use std::io::{self, Read, Write};

use anyhow::{bail, Context, Result};
use flate2::read::GzDecoder;
use lsb_platform::supported_runtime_platform;
use lsb_sdk::SandboxInitOptions;
use serde::Deserialize;
use tar::Archive;

const GITHUB_REPO: &str = "LocalSandBox/local-sandbox";
pub const CURRENT_VERSION: &str = lsb_sdk::CURRENT_VERSION;

/// Check if OS image assets exist and match the expected version.
pub fn assets_ready(data_dir: &str) -> bool {
    lsb_sdk::assets_ready(data_dir)
}

/// Download and extract OS image assets from GitHub Releases via the SDK.
pub fn download_os_image(data_dir: &str) -> Result<()> {
    init_os_image_version(data_dir, CURRENT_VERSION, true)
}

pub fn init_os_image_version(data_dir: &str, version: &str, force: bool) -> Result<()> {
    let platform = supported_runtime_platform()?;
    let tag = platform.release_tag(version);

    eprintln!("lsb: initializing OS image ({})...", tag);
    let result = lsb_sdk::init_sandbox_version(
        SandboxInitOptions {
            data_dir: Some(data_dir.to_string()),
            force,
        },
        version,
    )?;

    if result.downloaded {
        eprintln!("lsb: OS image downloaded ({})", version);
    } else {
        eprintln!("lsb: OS image already up to date ({})", version);
    }
    if result.pinned {
        eprintln!("lsb: base rootfs pinned ({})", version);
    }
    Ok(())
}

pub fn download_os_image_version(data_dir: &str, version: &str) -> Result<()> {
    init_os_image_version(data_dir, version, true)
}

#[derive(Deserialize)]
struct GithubRelease {
    tag_name: String,
}

/// Check for a newer release and upgrade the CLI binary + OS image.
pub fn upgrade(data_dir: &str) -> Result<()> {
    if let Ok(exe) = std::env::current_exe() {
        if exe.to_string_lossy().contains("/Cellar/") {
            bail!("This copy was installed via Homebrew. Please run `brew upgrade lsb` instead");
        }
    }

    if cfg!(windows) {
        bail!(
            "`lsb upgrade` cannot replace a running Windows executable yet. \
             Re-run the PowerShell installer instead: \
             irm https://raw.githubusercontent.com/LocalSandBox/local-sandbox/main/install.ps1 | iex"
        );
    }

    eprintln!("lsb: checking for updates...");

    let api_url = format!(
        "https://api.github.com/repos/{}/releases/latest",
        GITHUB_REPO
    );

    let response = ureq::get(&api_url)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "lsb")
        .call()
        .context("failed to check for updates")?;

    let release: GithubRelease = response
        .into_body()
        .read_json()
        .context("failed to parse release info")?;

    let latest = release
        .tag_name
        .strip_prefix('v')
        .unwrap_or(&release.tag_name);

    if latest == CURRENT_VERSION {
        eprintln!("lsb: already on latest version ({})", CURRENT_VERSION);
        return Ok(());
    }

    eprintln!("lsb: upgrading {} -> {}", CURRENT_VERSION, latest);

    // Update CLI binary
    let platform = supported_runtime_platform()?;
    let cli_tarball = platform.cli_tarball_name(latest);
    let cli_url = format!(
        "https://github.com/{}/releases/download/v{}/{}",
        GITHUB_REPO, latest, cli_tarball
    );

    let current_exe = std::env::current_exe().context("failed to determine current binary path")?;

    eprintln!("lsb: downloading CLI ({})...", latest);
    eprintln!("lsb: {}", cli_url);

    let response = ureq::get(&cli_url)
        .call()
        .with_context(|| format!("failed to download CLI v{}", latest))?;

    let total_bytes = response
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());

    let reader = ProgressReader::new(response.into_body().into_reader(), total_bytes);
    let decoder = GzDecoder::new(reader);
    let mut archive = Archive::new(decoder);
    let cli_binary_name = platform.cli_binary_name();

    // Extract to a temp file next to the current binary
    let tmp_path = current_exe.with_extension("new");
    for entry in archive.entries().context("failed to read CLI archive")? {
        let mut entry = entry.context("failed to read archive entry")?;
        if entry.path()?.to_str() == Some(cli_binary_name) {
            let mut out = fs::File::create(&tmp_path).context("failed to create temp binary")?;
            io::copy(&mut entry, &mut out)?;
            break;
        }
    }

    eprintln!();

    if !tmp_path.exists() {
        bail!("'{}' binary not found in CLI archive", cli_binary_name);
    }

    // Set executable permission
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o755))?;
    }

    // Atomic-ish replace: rename current -> .old, rename new -> current, remove .old
    let old_path = current_exe.with_extension("old");
    let _ = fs::remove_file(&old_path);
    fs::rename(&current_exe, &old_path)
        .context("failed to move current binary (try with sudo?)")?;
    if let Err(e) = fs::rename(&tmp_path, &current_exe) {
        // Rollback
        let _ = fs::rename(&old_path, &current_exe);
        return Err(e).context("failed to install new binary");
    }
    let _ = fs::remove_file(&old_path);

    eprintln!("lsb: CLI updated to {}", latest);

    // Update OS image
    download_os_image_version(data_dir, latest)?;

    eprintln!("lsb: upgrade complete ({})", latest);
    Ok(())
}

/// Wraps a reader to print download progress to stderr.
struct ProgressReader<R> {
    inner: R,
    bytes_read: u64,
    total_bytes: Option<u64>,
    last_printed_mb: u64,
}

impl<R> ProgressReader<R> {
    fn new(inner: R, total_bytes: Option<u64>) -> Self {
        Self {
            inner,
            bytes_read: 0,
            total_bytes,
            last_printed_mb: u64::MAX, // force first print
        }
    }
}

impl<R: Read> Read for ProgressReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.bytes_read += n as u64;

        let current_mb = self.bytes_read / (1024 * 1024);
        if current_mb != self.last_printed_mb {
            self.last_printed_mb = current_mb;
            let mut stderr = io::stderr().lock();
            if let Some(total) = self.total_bytes {
                let total_mb = total / (1024 * 1024);
                let _ = write!(stderr, "\rlsb: downloaded {} / {} MB", current_mb, total_mb);
            } else {
                let _ = write!(stderr, "\rlsb: downloaded {} MB", current_mb);
            }
            let _ = stderr.flush();
        }

        Ok(n)
    }
}
