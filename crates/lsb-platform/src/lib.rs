#![cfg_attr(
    not(any(target_os = "macos", target_os = "windows")),
    forbid(unsafe_code)
)]
#![cfg_attr(target_os = "windows", deny(unsafe_op_in_unsafe_fn))]

use std::env;
use std::fs::File;
use std::io::{self, Read, Write};
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
            "lsb-v{}-{}.tar.gz",
            self.release_version(version),
            self.cli_artifact_suffix
        )
    }

    pub fn os_image_tarball_name(&self, version: &str) -> String {
        format!(
            "lsb-os-{}-{}.tar.gz",
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
            "lsb runtime is not implemented for {} yet",
            platform.id
        ))
    }
}

pub fn default_data_dir() -> String {
    let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let subdir = host_platform()
        .map(|platform| platform.default_data_subdir)
        .unwrap_or(".local/share/lsb");
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

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub use macos_x86_64::VmState;

#[cfg(not(target_os = "macos"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmState {
    Stopped = 0,
    Running = 1,
    Paused = 2,
    Error = 3,
    Starting = 4,
    Pausing = 5,
    Resuming = 6,
    Stopping = 7,
    Unknown = -1,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use macos_aarch64::terminal;

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub use macos_x86_64::terminal;

#[derive(Debug, Clone)]
pub struct PlatformSharedDir {
    pub host_path: String,
    pub tag: String,
    pub read_only: bool,
}

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
    pub nbd_uri: Option<String>,
    pub shared_dirs: Vec<PlatformSharedDir>,
}

#[derive(Debug)]
pub struct PlatformControlStream {
    inner: PlatformControlStreamInner,
}

#[derive(Debug)]
enum PlatformControlStreamInner {
    Tcp(TcpStream),
    File(File),
}

impl PlatformControlStream {
    pub fn from_tcp_stream(stream: TcpStream) -> Self {
        Self {
            inner: PlatformControlStreamInner::Tcp(stream),
        }
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        match &self.inner {
            PlatformControlStreamInner::Tcp(stream) => stream
                .try_clone()
                .map(PlatformControlStream::from_tcp_stream),
            PlatformControlStreamInner::File(file) => file.try_clone().map(Self::from_file),
        }
    }

    pub fn set_nodelay_if_tcp(&self, enabled: bool) -> io::Result<()> {
        match &self.inner {
            PlatformControlStreamInner::Tcp(stream) => stream.set_nodelay(enabled),
            PlatformControlStreamInner::File(_) => Ok(()),
        }
    }

    pub(crate) fn from_file(file: File) -> Self {
        Self {
            inner: PlatformControlStreamInner::File(file),
        }
    }
}

impl Read for PlatformControlStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut self.inner {
            PlatformControlStreamInner::Tcp(stream) => stream.read(buf),
            PlatformControlStreamInner::File(file) => file.read(buf),
        }
    }
}

impl Write for PlatformControlStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match &mut self.inner {
            PlatformControlStreamInner::Tcp(stream) => stream.write(buf),
            PlatformControlStreamInner::File(file) => file.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.inner {
            PlatformControlStreamInner::Tcp(stream) => stream.flush(),
            PlatformControlStreamInner::File(file) => file.flush(),
        }
    }
}

pub trait PlatformVm: Send + Sync {
    fn start(&self) -> Result<()>;
    fn stop(&self) -> Result<()>;
    fn state_channel(&self) -> crossbeam_channel::Receiver<VmState>;
    fn guest_capabilities(&self) -> Vec<String> {
        Vec::new()
    }
    fn connect_control(&self) -> Result<PlatformControlStream>;
    fn connect_to_vsock_port(&self, port: u32) -> Result<TcpStream>;
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub fn copy_file_cow(src: &str, dst: &str) -> Result<()> {
    macos_aarch64::copy_file_cow(src, dst)
}

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub fn copy_file_cow(src: &str, dst: &str) -> Result<()> {
    macos_x86_64::copy_file_cow(src, dst)
}

#[cfg(not(target_os = "macos"))]
pub fn copy_file_cow(src: &str, dst: &str) -> Result<()> {
    std::fs::copy(src, dst).map(|_| ()).map_err(Into::into)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub fn create_vm(config: PlatformVmConfig) -> Result<Arc<dyn PlatformVm>> {
    macos_aarch64::create_vm(config)
}

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub fn create_vm(config: PlatformVmConfig) -> Result<Arc<dyn PlatformVm>> {
    macos_x86_64::create_vm(config)
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub fn create_vm(config: PlatformVmConfig) -> Result<Arc<dyn PlatformVm>> {
    windows_x86_64::create_vm(config)
}

#[cfg(not(any(
    target_os = "macos",
    all(target_os = "windows", target_arch = "x86_64")
)))]
pub fn create_vm(_config: PlatformVmConfig) -> Result<Arc<dyn PlatformVm>> {
    let platform = host_platform()
        .map(|platform| platform.id)
        .unwrap_or("unknown host target");
    Err(anyhow!(
        "LocalSandbox runtime is not implemented for {platform}; M01 only provides Windows x86_64 compile stubs"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macos_aarch64_artifact_naming_matches_existing_release_shape() {
        let spec = platform_by_id("macos-aarch64").expect("platform should exist");
        assert_eq!(
            spec.cli_tarball_name("0.5.2"),
            "lsb-v0.5.2-darwin-aarch64.tar.gz"
        );
        assert_eq!(
            spec.cli_tarball_name("v0.5.2"),
            "lsb-v0.5.2-darwin-aarch64.tar.gz"
        );
        assert_eq!(
            spec.os_image_tarball_name("0.5.2"),
            "lsb-os-v0.5.2-aarch64.tar.gz"
        );
        assert_eq!(
            spec.os_image_tarball_name("v0.5.2"),
            "lsb-os-v0.5.2-aarch64.tar.gz"
        );
    }

    #[test]
    fn macos_x86_64_artifact_naming_matches_existing_release_shape() {
        let spec = platform_by_id("macos-x86_64").expect("platform should exist");
        assert_eq!(spec.status, PlatformStatus::Supported);
        assert_eq!(spec.guest_target, "x86_64-unknown-linux-musl");
        assert_eq!(spec.kernel_arch, "x86");
        assert_eq!(
            spec.cli_tarball_name("0.5.2"),
            "lsb-v0.5.2-darwin-x86_64.tar.gz"
        );
        assert_eq!(
            spec.cli_tarball_name("v0.5.2"),
            "lsb-v0.5.2-darwin-x86_64.tar.gz"
        );
        assert_eq!(
            spec.os_image_tarball_name("0.5.2"),
            "lsb-os-v0.5.2-x86_64.tar.gz"
        );
        assert_eq!(
            spec.os_image_tarball_name("v0.5.2"),
            "lsb-os-v0.5.2-x86_64.tar.gz"
        );
    }

    #[test]
    fn windows_x86_64_is_registered_as_planned_m01_target() {
        let spec = platform_by_id("windows-x86_64").expect("platform should exist");
        assert_eq!(spec.status, PlatformStatus::Planned);
        assert_eq!(spec.target_os, "windows");
        assert_eq!(spec.target_arch, "x86_64");
        assert_eq!(spec.host_target, "x86_64-pc-windows-msvc");
        assert_eq!(spec.guest_target, "x86_64-unknown-linux-musl");
        assert_eq!(
            spec.cli_tarball_name("0.5.2"),
            "lsb-v0.5.2-windows-x86_64.tar.gz"
        );
    }

    #[test]
    fn x86_64_platforms_use_x86_64_guest_target() {
        for platform_id in ["macos-x86_64", "linux-x86_64", "windows-x86_64"] {
            let spec = platform_by_id(platform_id).expect("platform should exist");
            assert_eq!(spec.target_arch, "x86_64");
            assert_eq!(spec.guest_target, "x86_64-unknown-linux-musl");
            assert_eq!(spec.kernel_arch, "x86");
        }
    }

    #[test]
    fn asset_paths_are_derived_from_data_dir() {
        let paths = asset_paths("/tmp/lsb");
        assert_eq!(paths.kernel, "/tmp/lsb/Image");
        assert_eq!(paths.checkpoints_dir, "/tmp/lsb/checkpoints");
        assert_eq!(paths.instances_dir, "/tmp/lsb/instances");
    }
}
