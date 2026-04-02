#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod sys;

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod bootloader;
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod configuration;
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod directory_sharing;
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod entropy;
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod error;
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod memory;
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub mod network;
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod serial;
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod socket;
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod storage;
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub mod terminal;
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod vm;

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
use crate::{PlatformSharedDir, PlatformSpec, PlatformStatus, PlatformVm, PlatformVmConfig};

#[cfg(not(all(target_os = "macos", target_arch = "x86_64")))]
use crate::{PlatformSpec, PlatformStatus};

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub use bootloader::LinuxBootLoader;
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub use configuration::VirtualMachineConfiguration;
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub use directory_sharing::{SharedDirectory, VirtioFileSystemDevice};
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub use entropy::VirtioEntropyDevice;
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub use error::{Result as VzResult, VzError};
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub use memory::VirtioMemoryBalloonDevice;
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub use network::{FileHandleNetworkAttachment, MACAddress, VirtioNetworkDevice};
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub use serial::{FileHandleSerialAttachment, VirtioConsoleSerialPort};
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub use socket::VirtioSocketDevice;
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub use storage::{
    DiskImageAttachment, DiskImageCachingMode, DiskImageSynchronizationMode, NbdAttachment,
    StorageAttachment, StorageDevice, VirtioBlockDevice,
};
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub use vm::{VirtualMachine, VmState};

pub const SPEC: PlatformSpec = PlatformSpec {
    id: "macos-x86_64",
    target_os: "macos",
    target_arch: "x86_64",
    host_target: "x86_64-apple-darwin",
    cli_artifact_suffix: "darwin-x86_64",
    os_image_artifact_suffix: "x86_64",
    guest_target: "x86_64-unknown-linux-musl",
    docker_platform: "linux/amd64",
    kernel_arch: "x86",
    debootstrap_arch: "amd64",
    default_data_subdir: ".local/share/shuru",
    codesign_entitlements: Some("shuru.entitlements"),
    status: PlatformStatus::Supported,
};

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
use std::os::fd::AsRawFd;

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
use std::sync::Arc;

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
use anyhow::{bail, Context, Result};

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
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

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
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
        FileHandleSerialAttachment::new(std::io::stdin().as_raw_fd(), std::io::stdout().as_raw_fd())
    } else if config.verbose {
        FileHandleSerialAttachment::new_write_only(std::io::stderr().as_raw_fd())
    } else {
        dev_null = std::fs::File::open("/dev/null")?;
        FileHandleSerialAttachment::new_write_only(dev_null.as_raw_fd())
    };
    let serial = VirtioConsoleSerialPort::new_with_attachment(&serial_attachment);
    vm_config.set_serial_ports(&[serial]);

    let nbd_attachment;
    let disk_attachment;
    let block_device = if let Some(ref uri) = config.nbd_uri {
        nbd_attachment = NbdAttachment::new(uri, 30.0, false)?;
        VirtioBlockDevice::new(&nbd_attachment)
    } else {
        disk_attachment = DiskImageAttachment::new_with_options(
            &config.rootfs_path,
            false,
            DiskImageCachingMode::Cached,
            DiskImageSynchronizationMode::Fsync,
        )?;
        VirtioBlockDevice::new(&disk_attachment)
    };
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

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
fn build_shared_dir_device(shared_dir: &PlatformSharedDir) -> VirtioFileSystemDevice {
    let attachment = SharedDirectory::new(&shared_dir.host_path, shared_dir.read_only);
    VirtioFileSystemDevice::new(&shared_dir.tag, &attachment)
}

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
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
