mod sys;

mod bootloader;
mod configuration;
mod directory_sharing;
mod entropy;
mod error;
pub mod network;
mod memory;
mod serial;
mod socket;
mod storage;
pub mod terminal;
mod vm;

use crate::{PlatformSharedDir, PlatformSpec, PlatformStatus, PlatformVm, PlatformVmConfig};

pub use bootloader::LinuxBootLoader;
pub use configuration::VirtualMachineConfiguration;
pub use directory_sharing::{SharedDirectory, VirtioFileSystemDevice};
pub use entropy::VirtioEntropyDevice;
pub use error::{Result as VzResult, VzError};
pub use memory::VirtioMemoryBalloonDevice;
pub use network::{FileHandleNetworkAttachment, MACAddress, VirtioNetworkDevice};
pub use serial::{FileHandleSerialAttachment, VirtioConsoleSerialPort};
pub use socket::VirtioSocketDevice;
pub use storage::{
    DiskImageAttachment, DiskImageCachingMode, DiskImageSynchronizationMode, StorageDevice,
    VirtioBlockDevice,
};
pub use vm::{VirtualMachine, VmState};

pub const SPEC: PlatformSpec = PlatformSpec {
    id: "macos-aarch64",
    target_os: "macos",
    target_arch: "aarch64",
    host_target: "aarch64-apple-darwin",
    cli_artifact_suffix: "darwin-aarch64",
    os_image_artifact_suffix: "aarch64",
    guest_target: "aarch64-unknown-linux-musl",
    docker_platform: "linux/arm64/v8",
    kernel_arch: "arm64",
    debootstrap_arch: "arm64",
    default_data_subdir: ".local/share/shuru",
    codesign_entitlements: Some("shuru.entitlements"),
    status: PlatformStatus::Supported,
};

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use std::os::fd::AsRawFd;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use std::sync::Arc;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use anyhow::{bail, Context, Result};

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub fn copy_file_cow(src: &str, dst: &str) -> Result<()> {
    use std::ffi::CString;

    extern "C" {
        fn clonefile(src: *const libc::c_char, dst: *const libc::c_char, flags: u32)
            -> libc::c_int;
    }

    let c_src = CString::new(src).context("invalid source path")?;
    let c_dst = CString::new(dst).context("invalid destination path")?;
    let ret = unsafe { clonefile(c_src.as_ptr(), c_dst.as_ptr(), 0) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        bail!("clonefile({src} -> {dst}) failed: {err}");
    }

    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub fn create_vm(config: PlatformVmConfig) -> Result<Arc<dyn PlatformVm>> {
    if !VirtualMachine::supported() {
        bail!("Virtualization is not supported on this machine");
    }

    let boot_loader = LinuxBootLoader::new_with_kernel(&config.kernel_path);
    if let Some(ref initrd) = config.initrd_path {
        boot_loader.set_initrd(initrd);
    }

    let cmdline = if config.verbose {
        "console=hvc0 root=/dev/vda rw"
    } else {
        "console=hvc0 root=/dev/vda rw quiet"
    };
    boot_loader.set_command_line(cmdline);

    let vm_config =
        VirtualMachineConfiguration::new(&boot_loader, config.cpus, config.memory_bytes);

    let dev_null;
    let serial_attachment = if config.console {
        FileHandleSerialAttachment::new(
            std::io::stdin().as_raw_fd(),
            std::io::stdout().as_raw_fd(),
        )
    } else if config.verbose {
        FileHandleSerialAttachment::new_write_only(std::io::stderr().as_raw_fd())
    } else {
        dev_null = std::fs::File::open("/dev/null")?;
        FileHandleSerialAttachment::new_write_only(dev_null.as_raw_fd())
    };
    let serial = VirtioConsoleSerialPort::new_with_attachment(&serial_attachment);
    vm_config.set_serial_ports(&[serial]);

    let disk_attachment = DiskImageAttachment::new_with_options(
        &config.rootfs_path,
        false,
        DiskImageCachingMode::Cached,
        DiskImageSynchronizationMode::Fsync,
    )?;
    let block_device = VirtioBlockDevice::new(&disk_attachment);
    vm_config.set_storage_devices(&[&block_device]);

    if let Some(fd) = config.network_fd {
        let net_attachment = FileHandleNetworkAttachment::new(fd);
        let net_device = VirtioNetworkDevice::new_with_attachment(&net_attachment);
        net_device.set_mac_address(&MACAddress::random_local());
        vm_config.set_network_devices(&[net_device]);
    }

    let fs_devices: Vec<_> = config
        .shared_dirs
        .iter()
        .map(build_shared_dir_device)
        .collect();
    if !fs_devices.is_empty() {
        vm_config.set_directory_sharing_devices(&fs_devices);
    }

    vm_config.set_socket_devices(&[VirtioSocketDevice::new()]);
    vm_config.set_entropy_devices(&[VirtioEntropyDevice::new()]);
    vm_config.set_memory_balloon_devices(&[VirtioMemoryBalloonDevice::new()]);
    vm_config.validate()?;

    Ok(Arc::new(VirtualMachine::new(&vm_config)))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn build_shared_dir_device(shared_dir: &PlatformSharedDir) -> VirtioFileSystemDevice {
    let attachment = SharedDirectory::new(&shared_dir.host_path, shared_dir.read_only);
    VirtioFileSystemDevice::new(&shared_dir.tag, &attachment)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl PlatformVm for VirtualMachine {
    fn start(&self) -> Result<()> {
        VirtualMachine::start(self).map_err(Into::into)
    }

    fn stop(&self) -> Result<()> {
        VirtualMachine::stop(self).map_err(Into::into)
    }

    fn state_channel(&self) -> crossbeam_channel::Receiver<VmState> {
        VirtualMachine::state_channel(self)
    }

    fn connect_to_vsock_port(&self, port: u32) -> Result<std::net::TcpStream> {
        VirtualMachine::connect_to_vsock_port(self, port).map_err(Into::into)
    }
}
