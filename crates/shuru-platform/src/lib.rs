#![cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64")),
    forbid(unsafe_code)
)]

use std::env;
use std::net::TcpStream;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use serde::Serialize;

pub mod linux_aarch64;
pub mod linux_x86_64;
pub mod macos_aarch64;
pub mod macos_x86_64;
pub mod windows_aarch64;
pub mod windows_x86_64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformStatus {
    Supported,
    Planned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PlatformSpec {
    pub id: &'static str,
    pub target_os: &'static str,
    pub target_arch: &'static str,
    pub host_target: &'static str,
    pub cli_artifact_suffix: &'static str,
    pub os_image_artifact_suffix: &'static str,
    pub guest_target: &'static str,
    pub docker_platform: &'static str,
    pub kernel_arch: &'static str,
    pub debootstrap_arch: &'static str,
    pub default_data_subdir: &'static str,
    pub codesign_entitlements: Option<&'static str>,
    pub status: PlatformStatus,
}

impl PlatformSpec {
    pub fn release_tag(&self, version: &str) -> String {
        if version.starts_with('v') {
            version.to_string()
        } else {
            format!("v{version}")
        }
    }

    pub fn release_version<'a>(&self, version: &'a str) -> &'a str {
        version.strip_prefix('v').unwrap_or(version)
    }

    pub fn cli_tarball_name(&self, version: &str) -> String {
        format!(
            "shuru-v{}-{}.tar.gz",
            self.release_version(version),
            self.cli_artifact_suffix
        )
    }

    pub fn os_image_tarball_name(&self, version: &str) -> String {
        format!(
            "shuru-os-{}-{}.tar.gz",
            self.release_tag(version),
            self.os_image_artifact_suffix
        )
    }
}

const KNOWN_PLATFORMS: &[PlatformSpec] = &[
    macos_aarch64::SPEC,
    macos_x86_64::SPEC,
    linux_x86_64::SPEC,
    linux_aarch64::SPEC,
    windows_x86_64::SPEC,
    windows_aarch64::SPEC,
];

pub fn known_platforms() -> &'static [PlatformSpec] {
    KNOWN_PLATFORMS
}

pub fn platform_by_id(id: &str) -> Option<&'static PlatformSpec> {
    KNOWN_PLATFORMS.iter().find(|platform| platform.id == id)
}

pub fn host_platform() -> Option<&'static PlatformSpec> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        return Some(&macos_aarch64::SPEC);
    }

    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        return Some(&macos_x86_64::SPEC);
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        return Some(&linux_x86_64::SPEC);
    }

    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        return Some(&linux_aarch64::SPEC);
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        return Some(&windows_x86_64::SPEC);
    }

    #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
    {
        return Some(&windows_aarch64::SPEC);
    }

    #[allow(unreachable_code)]
    None
}

pub fn supported_runtime_platform() -> Result<&'static PlatformSpec> {
    let platform = host_platform().ok_or_else(|| anyhow!("unsupported host target"))?;
    if platform.status == PlatformStatus::Supported {
        Ok(platform)
    } else {
        Err(anyhow!(
            "shuru runtime is not implemented for {} yet",
            platform.id
        ))
    }
}

pub fn default_data_dir() -> String {
    let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let subdir = host_platform()
        .map(|platform| platform.default_data_subdir)
        .unwrap_or(".local/share/shuru");
    format!("{home}/{subdir}")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AssetPaths {
    pub data_dir: String,
    pub version_file: String,
    pub kernel: String,
    pub rootfs: String,
    pub initramfs: String,
    pub checkpoints_dir: String,
    pub instances_dir: String,
}

pub fn asset_paths(data_dir: &str) -> AssetPaths {
    AssetPaths {
        data_dir: data_dir.to_string(),
        version_file: format!("{data_dir}/VERSION"),
        kernel: format!("{data_dir}/Image"),
        rootfs: format!("{data_dir}/rootfs.ext4"),
        initramfs: format!("{data_dir}/initramfs.cpio.gz"),
        checkpoints_dir: format!("{data_dir}/checkpoints"),
        instances_dir: format!("{data_dir}/instances"),
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use macos_aarch64::VmState;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use macos_aarch64::terminal;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug, Clone)]
pub struct PlatformSharedDir {
    pub host_path: String,
    pub tag: String,
    pub read_only: bool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug, Clone)]
pub struct PlatformVmConfig {
    pub kernel_path: String,
    pub rootfs_path: String,
    pub initrd_path: Option<String>,
    pub cpus: usize,
    pub memory_bytes: u64,
    pub console: bool,
    pub verbose: bool,
    pub network_fd: Option<i32>,
    pub shared_dirs: Vec<PlatformSharedDir>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub trait PlatformVm: Send + Sync {
    fn start(&self) -> Result<()>;
    fn stop(&self) -> Result<()>;
    fn state_channel(&self) -> crossbeam_channel::Receiver<VmState>;
    fn connect_to_vsock_port(&self, port: u32) -> Result<TcpStream>;
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub fn copy_file_cow(src: &str, dst: &str) -> Result<()> {
    macos_aarch64::copy_file_cow(src, dst)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub fn create_vm(config: PlatformVmConfig) -> Result<Arc<dyn PlatformVm>> {
    macos_aarch64::create_vm(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_naming_matches_existing_release_shape() {
        let spec = platform_by_id("macos-aarch64").expect("platform should exist");
        assert_eq!(spec.cli_tarball_name("0.5.2"), "shuru-v0.5.2-darwin-aarch64.tar.gz");
        assert_eq!(spec.cli_tarball_name("v0.5.2"), "shuru-v0.5.2-darwin-aarch64.tar.gz");
        assert_eq!(spec.os_image_tarball_name("0.5.2"), "shuru-os-v0.5.2-aarch64.tar.gz");
        assert_eq!(spec.os_image_tarball_name("v0.5.2"), "shuru-os-v0.5.2-aarch64.tar.gz");
    }

    #[test]
    fn asset_paths_are_derived_from_data_dir() {
        let paths = asset_paths("/tmp/shuru");
        assert_eq!(paths.kernel, "/tmp/shuru/Image");
        assert_eq!(paths.checkpoints_dir, "/tmp/shuru/checkpoints");
        assert_eq!(paths.instances_dir, "/tmp/shuru/instances");
    }
}
