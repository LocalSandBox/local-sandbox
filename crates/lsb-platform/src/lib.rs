#![cfg_attr(
    not(any(target_os = "macos", target_os = "windows")),
    forbid(unsafe_code)
)]
#![cfg_attr(target_os = "windows", deny(unsafe_op_in_unsafe_fn))]

use std::env;
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpStream};
use std::path::PathBuf;
use std::process::Child;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use serde::Serialize;

#[cfg(windows)]
mod windows_named_pipe;

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

    pub fn cli_binary_name(&self) -> &'static str {
        if self.target_os == "windows" {
            "lsb.exe"
        } else {
            "lsb"
        }
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
            "lsb runtime is not implemented for {}",
            platform.id
        ))
    }
}

pub fn default_data_dir() -> String {
    default_data_dir_with_env(host_platform(), |key| env::var(key).ok())
}

fn default_data_dir_with_env<F>(platform: Option<&PlatformSpec>, mut env_value: F) -> String
where
    F: FnMut(&str) -> Option<String>,
{
    if platform.is_some_and(|platform| platform.target_os == "windows") {
        if let Some(local_app_data) = env_nonempty(&mut env_value, "LOCALAPPDATA") {
            return join_data_path(&local_app_data, "lsb");
        }
        if let Some(user_profile) = env_nonempty(&mut env_value, "USERPROFILE") {
            return join_data_path(&user_profile, "AppData/Local/lsb");
        }
        if let Some(home) = env_nonempty(&mut env_value, "HOME") {
            return join_data_path(&home, "AppData/Local/lsb");
        }
    }

    let home = env_nonempty(&mut env_value, "HOME").unwrap_or_else(|| "/tmp".to_string());
    let subdir = platform
        .map(|platform| platform.default_data_subdir)
        .unwrap_or(".local/share/lsb");
    join_data_path(&home, subdir)
}

fn env_nonempty<F>(env_value: &mut F, key: &str) -> Option<String>
where
    F: FnMut(&str) -> Option<String>,
{
    env_value(key).filter(|value| !value.is_empty())
}

fn join_data_path(base: &str, subdir: &str) -> String {
    format!(
        "{}/{}",
        base.trim_end_matches(['/', '\\']),
        subdir.trim_start_matches(['/', '\\'])
    )
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

#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformDiskFormat {
    Raw,
    Qcow2,
}

#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformDataDisk {
    pub id: String,
    pub path: PathBuf,
    pub format: PlatformDiskFormat,
    pub read_only: bool,
    pub serial: String,
    pub virtual_size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformQemuStreamNetworkAttachment {
    pub host: Ipv4Addr,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlatformNetworkAttachment {
    FileDescriptor(i32),
    QemuStream(PlatformQemuStreamNetworkAttachment),
}

impl PlatformNetworkAttachment {
    pub fn file_descriptor(fd: i32) -> Self {
        Self::FileDescriptor(fd)
    }

    pub fn qemu_stream(host: Ipv4Addr, port: u16) -> Self {
        Self::QemuStream(PlatformQemuStreamNetworkAttachment { host, port })
    }
}

#[derive(Debug, Clone)]
pub struct PlatformVmConfig {
    pub data_dir: Option<String>,
    /// Verified service-owned QEMU executable. When set, Windows bypasses all
    /// environment, managed-tool, and PATH discovery.
    pub qemu_executable: Option<String>,
    /// Service-owned process containment used for QEMU and its descendants.
    /// Ordinary SDK callers leave this unset and receive platform-owned containment.
    #[doc(hidden)]
    pub process_containment: Option<Arc<dyn PlatformProcessContainment>>,
    pub kernel_path: String,
    pub rootfs_path: String,
    pub initrd_path: Option<String>,
    pub cpus: usize,
    pub memory_bytes: u64,
    pub console: bool,
    pub verbose: bool,
    pub network_fd: Option<i32>,
    pub network_attachment: Option<PlatformNetworkAttachment>,
    pub nbd_uri: Option<String>,
    pub shared_dirs: Vec<PlatformSharedDir>,
}

/// Opaque service-owned process containment boundary. The Windows QEMU backend
/// assigns the suspended child through this interface and never creates a second
/// Job when one is supplied.
#[doc(hidden)]
pub trait PlatformProcessContainment: std::fmt::Debug + Send + Sync {
    /// Persist any service-owned creation intent before the child process exists.
    fn prepare_process(&self) -> Result<()> {
        Ok(())
    }

    fn assign_process(&self, process: &Child) -> Result<()>;
    fn terminate(&self) -> Result<()>;
}

#[derive(Debug)]
pub struct PlatformControlStream {
    inner: PlatformControlStreamInner,
}

#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformControlSessionKind {
    Exec,
    Watch,
    File,
}

#[derive(Debug)]
enum PlatformControlStreamInner {
    Tcp(TcpStream),
    File(File),
    #[cfg(windows)]
    WindowsNamedPipe(windows_named_pipe::WindowsNamedPipeStream),
    WindowsMux(windows_x86_64::MuxSession),
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
            #[cfg(windows)]
            PlatformControlStreamInner::WindowsNamedPipe(stream) => {
                Ok(Self::from_windows_named_pipe(stream.clone()))
            }
            PlatformControlStreamInner::WindowsMux(session) => {
                Ok(Self::from_windows_mux_session(session.clone()))
            }
        }
    }

    pub fn set_nodelay_if_tcp(&self, enabled: bool) -> io::Result<()> {
        match &self.inner {
            PlatformControlStreamInner::Tcp(stream) => stream.set_nodelay(enabled),
            PlatformControlStreamInner::File(_) => Ok(()),
            #[cfg(windows)]
            PlatformControlStreamInner::WindowsNamedPipe(_) => Ok(()),
            PlatformControlStreamInner::WindowsMux(_) => Ok(()),
        }
    }

    #[doc(hidden)]
    pub fn close(&mut self) -> io::Result<()> {
        match &mut self.inner {
            PlatformControlStreamInner::Tcp(stream) => stream.shutdown(Shutdown::Both),
            PlatformControlStreamInner::File(file) => file.flush(),
            #[cfg(windows)]
            PlatformControlStreamInner::WindowsNamedPipe(stream) => stream.close(),
            PlatformControlStreamInner::WindowsMux(session) => session.close(),
        }
    }

    #[doc(hidden)]
    pub fn reset(&mut self) -> io::Result<()> {
        match &mut self.inner {
            PlatformControlStreamInner::Tcp(stream) => stream.shutdown(Shutdown::Both),
            PlatformControlStreamInner::File(file) => file.flush(),
            #[cfg(windows)]
            PlatformControlStreamInner::WindowsNamedPipe(stream) => stream.reset(),
            PlatformControlStreamInner::WindowsMux(session) => {
                session.reset("host reset control session")
            }
        }
    }

    pub(crate) fn from_file(file: File) -> Self {
        Self {
            inner: PlatformControlStreamInner::File(file),
        }
    }

    #[cfg(windows)]
    pub(crate) fn from_windows_named_pipe(
        stream: windows_named_pipe::WindowsNamedPipeStream,
    ) -> Self {
        Self {
            inner: PlatformControlStreamInner::WindowsNamedPipe(stream),
        }
    }

    pub(crate) fn from_windows_mux_session(session: windows_x86_64::MuxSession) -> Self {
        Self {
            inner: PlatformControlStreamInner::WindowsMux(session),
        }
    }
}

impl Read for PlatformControlStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut self.inner {
            PlatformControlStreamInner::Tcp(stream) => stream.read(buf),
            PlatformControlStreamInner::File(file) => file.read(buf),
            #[cfg(windows)]
            PlatformControlStreamInner::WindowsNamedPipe(stream) => stream.read(buf),
            PlatformControlStreamInner::WindowsMux(session) => session.read(buf),
        }
    }
}

impl Write for PlatformControlStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match &mut self.inner {
            PlatformControlStreamInner::Tcp(stream) => stream.write(buf),
            PlatformControlStreamInner::File(file) => file.write(buf),
            #[cfg(windows)]
            PlatformControlStreamInner::WindowsNamedPipe(stream) => stream.write(buf),
            PlatformControlStreamInner::WindowsMux(session) => session.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.inner {
            PlatformControlStreamInner::Tcp(stream) => stream.flush(),
            PlatformControlStreamInner::File(file) => file.flush(),
            #[cfg(windows)]
            PlatformControlStreamInner::WindowsNamedPipe(stream) => stream.flush(),
            PlatformControlStreamInner::WindowsMux(session) => session.flush(),
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
    #[doc(hidden)]
    fn configure_data_disks(&self, disks: Vec<PlatformDataDisk>) -> Result<()> {
        if disks.is_empty() {
            Ok(())
        } else {
            Err(anyhow!(
                "secondary data disks are not implemented for this platform backend"
            ))
        }
    }
    fn connect_control(&self) -> Result<PlatformControlStream>;
    #[doc(hidden)]
    fn open_control_session(
        &self,
        kind: PlatformControlSessionKind,
    ) -> Result<PlatformControlStream> {
        let _ = kind;
        Err(anyhow!(
            "multiplexed guest control sessions are not implemented for this platform backend"
        ))
    }
    fn connect_port_forward(&self) -> Result<PlatformControlStream> {
        Err(anyhow!(
            "host-to-guest port forwarding stream is not implemented for this platform backend"
        ))
    }
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
        "LocalSandbox runtime is not implemented for {platform}; supported hosts are macOS arm64/x64 and Windows x86_64"
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
        assert_eq!(spec.cli_binary_name(), "lsb");
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
        assert_eq!(spec.cli_binary_name(), "lsb");
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
    fn windows_x86_64_is_registered_as_supported_target() {
        let spec = platform_by_id("windows-x86_64").expect("platform should exist");
        assert_eq!(spec.status, PlatformStatus::Supported);
        assert_eq!(spec.target_os, "windows");
        assert_eq!(spec.target_arch, "x86_64");
        assert_eq!(spec.host_target, "x86_64-pc-windows-msvc");
        assert_eq!(spec.guest_target, "x86_64-unknown-linux-musl");
        assert_eq!(
            spec.cli_tarball_name("0.5.2"),
            "lsb-v0.5.2-windows-x86_64.tar.gz"
        );
        assert_eq!(
            spec.os_image_tarball_name("0.5.2"),
            "lsb-os-v0.5.2-windows-x86_64.tar.gz"
        );
        assert_eq!(
            spec.os_image_tarball_name("v0.5.2"),
            "lsb-os-v0.5.2-windows-x86_64.tar.gz"
        );
        assert_eq!(spec.cli_binary_name(), "lsb.exe");
    }

    #[test]
    fn windows_default_data_dir_prefers_localappdata() {
        let spec = platform_by_id("windows-x86_64");
        let path = default_data_dir_with_env(spec, |key| match key {
            "LOCALAPPDATA" => Some(r"C:\Users\me\AppData\Local".to_string()),
            "USERPROFILE" => Some(r"C:\Users\me".to_string()),
            "HOME" => Some("/home/me".to_string()),
            _ => None,
        });

        assert_eq!(path, r"C:\Users\me\AppData\Local/lsb");
    }

    #[test]
    fn windows_default_data_dir_falls_back_to_userprofile() {
        let spec = platform_by_id("windows-x86_64");
        let path = default_data_dir_with_env(spec, |key| match key {
            "USERPROFILE" => Some(r"C:\Users\me".to_string()),
            "HOME" => Some("/home/me".to_string()),
            _ => None,
        });

        assert_eq!(path, r"C:\Users\me/AppData/Local/lsb");
    }

    #[test]
    fn macos_default_data_dir_uses_home_subdir() {
        let spec = platform_by_id("macos-aarch64");
        let path = default_data_dir_with_env(spec, |key| match key {
            "HOME" => Some("/Users/me".to_string()),
            _ => None,
        });

        assert_eq!(path, "/Users/me/.local/share/lsb");
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
