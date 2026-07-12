use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use lsb_platform::default_data_dir;

pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask has a workspace root")
        .to_path_buf()
}

pub fn resolved_data_dir() -> PathBuf {
    PathBuf::from(
        env_value("LSB_DATA_DIR")
            .or_else(|| env_value("LSB_DEFAULT_DATA_DIR"))
            .unwrap_or_else(default_data_dir),
    )
}

pub fn env_value(key: &str) -> Option<String> {
    env::var(key).ok().filter(|value| !value.is_empty())
}

pub fn run_command(command: &mut Command, action: &str) -> Result<()> {
    let program = command.get_program().to_string_lossy().into_owned();
    let status = command
        .status()
        .with_context(|| format!("failed to {action} with {program}"))?;
    if !status.success() {
        bail!("{action} failed with {program}: {status}");
    }
    Ok(())
}

pub fn copy_file(from: &Path, to: &Path) -> Result<()> {
    let parent = to
        .parent()
        .ok_or_else(|| anyhow!("missing parent directory for {}", to.display()))?;
    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;
    fs::copy(from, to)
        .with_context(|| format!("failed to copy {} to {}", from.display(), to.display()))?;
    Ok(())
}

pub fn human_size(path: &Path) -> Result<String> {
    let bytes = fs::metadata(path)
        .with_context(|| format!("failed to read metadata for {}", path.display()))?
        .len();
    let units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit < units.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    Ok(if unit == 0 {
        format!("{bytes} {}", units[unit])
    } else {
        format!("{value:.1} {}", units[unit])
    })
}

pub fn make_jobs() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
}

pub fn is_macos() -> bool {
    env::consts::OS == "macos"
}

pub fn is_native_linux_arm64() -> bool {
    env::consts::OS == "linux" && env::consts::ARCH == "aarch64"
}

pub fn container_engine(message: &str) -> Result<String> {
    if let Some(engine) = env_value("LSB_CONTAINER_ENGINE") {
        if command_exists(&engine) {
            return Ok(engine);
        }
        bail!("LSB_CONTAINER_ENGINE points to unavailable command '{engine}'. {message}");
    }
    for engine in ["docker", "podman"] {
        if command_exists(engine) {
            return Ok(engine.to_string());
        }
    }
    bail!("{message}");
}

pub fn container_engine_available() -> bool {
    container_engine("a Docker-compatible container engine is required").is_ok()
}

pub fn ensure_linux_rootfs_prerequisites() -> Result<()> {
    let mut missing_packages = Vec::new();
    if !command_exists("mkfs.ext4") {
        missing_packages.push("e2fsprogs");
    }
    if !command_exists("debootstrap") {
        missing_packages.push("debootstrap");
    }
    if !command_exists("curl") {
        missing_packages.push("curl");
    }
    if !command_exists("xz") {
        missing_packages.push("xz-utils");
    }

    if !missing_packages.is_empty() {
        run_command(
            Command::new("sudo").arg("apt-get").arg("update"),
            "update apt package index",
        )?;
        let mut command = Command::new("sudo");
        command.arg("apt-get").arg("install").arg("-y");
        command.args(&missing_packages);
        run_command(&mut command, "install rootfs prerequisites")?;
    }

    Ok(())
}

pub fn create_mount_dir() -> Result<PathBuf> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_millis();
    let mount_dir = env::temp_dir().join(format!("lsb-rootfs-{}-{nonce}", process::id()));
    fs::create_dir_all(&mount_dir)
        .with_context(|| format!("failed to create {}", mount_dir.display()))?;
    Ok(mount_dir)
}

pub fn command_exists(command: &str) -> bool {
    let extensions = env::var("PATHEXT")
        .ok()
        .map(|value| {
            value
                .split(';')
                .filter(|extension| !extension.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    env::var_os("PATH").is_some_and(|paths| {
        env::split_paths(&paths).any(|path| {
            path.join(command).is_file()
                || extensions
                    .iter()
                    .any(|extension| path.join(format!("{command}{extension}")).is_file())
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_size_uses_binary_units() {
        let path = env::temp_dir().join(format!("xtask-human-size-{}", process::id()));
        fs::write(&path, vec![0; 1536]).expect("temp file should be writable");
        let size = human_size(&path).expect("size should be computed");
        fs::remove_file(&path).expect("temp file should be removable");

        assert_eq!(size, "1.5 KiB");
    }
}
