use objc2::rc::{Id, Shared};

use crate::bootloader::LinuxBootLoader;
use crate::directory_sharing::VirtioFileSystemDevice;
use crate::entropy::VirtioEntropyDevice;
use crate::error::{Result, VzError};
use crate::memory::VirtioMemoryBalloonDevice;
use crate::network::VirtioNetworkDevice;
use crate::serial::VirtioConsoleSerialPort;
use crate::socket::VirtioSocketDevice;
use crate::storage::StorageDevice;
use crate::sys::foundation::NSArray;
use crate::sys::virtualization::VZVirtualMachineConfiguration;

pub struct VirtualMachineConfiguration {
    pub(crate) inner: Id<VZVirtualMachineConfiguration, Shared>,
}

impl VirtualMachineConfiguration {
    pub fn new(boot_loader: &LinuxBootLoader, cpus: usize, memory: u64) -> Self {
        let config = Self::default();
        config.set_boot_loader(boot_loader);
        config.set_cpu_count(cpus);
        config.set_memory_size(memory);
        config
    }

    pub fn set_cpu_count(&self, cpus: usize) {
        unsafe {
            self.inner.setCPUCount(cpus);
        }
    }

    pub fn set_memory_size(&self, memory: u64) {
        unsafe {
            self.inner.setMemorySize(memory);
        }
    }

    pub fn set_boot_loader(&self, boot_loader: &LinuxBootLoader) {
        unsafe {
            let bl = boot_loader.as_vz_boot_loader();
            self.inner.setBootLoader(Some(&bl));
        }
    }

    pub fn set_entropy_devices(&self, devices: &[VirtioEntropyDevice]) {
        let ids = devices.iter().map(|d| d.as_entropy_config()).collect();
        let array = NSArray::from_vec(ids);
        unsafe {
            self.inner.setEntropyDevices(&array);
        }
    }

    pub fn set_serial_ports(&self, ports: &[VirtioConsoleSerialPort]) {
        let ids = ports.iter().map(|s| s.as_serial_port_config()).collect();
        let array = NSArray::from_vec(ids);
        unsafe {
            self.inner.setSerialPorts(&array);
        }
    }

    pub fn set_memory_balloon_devices(&self, devices: &[VirtioMemoryBalloonDevice]) {
        let ids = devices
            .iter()
            .map(|d| d.as_memory_balloon_config())
            .collect();
        let array = NSArray::from_vec(ids);
        unsafe {
            self.inner.setMemoryBalloonDevices(&array);
        }
    }

    pub fn set_storage_devices(&self, devices: &[&dyn StorageDevice]) {
        let ids = devices.iter().map(|d| d.as_storage_config()).collect();
        let array = NSArray::from_vec(ids);
        unsafe {
            self.inner.setStorageDevices(&array);
        }
    }

    pub fn set_network_devices(&self, devices: &[VirtioNetworkDevice]) {
        let ids = devices.iter().map(|d| d.as_network_config()).collect();
        let array = NSArray::from_vec(ids);
        unsafe {
            self.inner.setNetworkDevices(&array);
        }
    }

    pub fn set_socket_devices(&self, devices: &[VirtioSocketDevice]) {
        let ids = devices.iter().map(|d| d.as_socket_config()).collect();
        let array = NSArray::from_vec(ids);
        unsafe {
            self.inner.setSocketDevices(&array);
        }
    }

    pub fn set_directory_sharing_devices(&self, devices: &[VirtioFileSystemDevice]) {
        let ids = devices
            .iter()
            .map(|d| d.as_directory_sharing_config())
            .collect();
        let array = NSArray::from_vec(ids);
        unsafe {
            self.inner.setDirectorySharingDevices(&array);
        }
    }

    pub fn validate(&self) -> Result<()> {
        unsafe {
            self.inner
                .validateWithError()
                .map_err(|e| VzError::from_ns_error(&e))?;
            Ok(())
        }
    }
}

impl Default for VirtualMachineConfiguration {
    fn default() -> Self {
        VirtualMachineConfiguration {
            inner: VZVirtualMachineConfiguration::new(),
        }
    }
}
