use std::os::unix::io::RawFd;

use objc2::rc::Retained;
use objc2::AnyThread;
use objc2_foundation::NSFileHandle;
use objc2_virtualization::{
    VZFileHandleNetworkDeviceAttachment, VZMACAddress, VZNetworkDeviceAttachment,
    VZNetworkDeviceConfiguration, VZVirtioNetworkDeviceConfiguration,
};

pub trait NetworkAttachment {
    fn as_vz_attachment(&self) -> Retained<VZNetworkDeviceAttachment>;
}

pub struct FileHandleNetworkAttachment {
    inner: Retained<VZFileHandleNetworkDeviceAttachment>,
}

impl FileHandleNetworkAttachment {
    pub fn new(fd: RawFd) -> Self {
        unsafe {
            let file_handle = NSFileHandle::initWithFileDescriptor_closeOnDealloc(
                NSFileHandle::alloc(),
                fd,
                true,
            );
            FileHandleNetworkAttachment {
                inner: VZFileHandleNetworkDeviceAttachment::initWithFileHandle(
                    VZFileHandleNetworkDeviceAttachment::alloc(),
                    &file_handle,
                ),
            }
        }
    }
}

impl NetworkAttachment for FileHandleNetworkAttachment {
    fn as_vz_attachment(&self) -> Retained<VZNetworkDeviceAttachment> {
        unsafe { Retained::cast_unchecked(self.inner.clone()) }
    }
}

pub struct MACAddress {
    inner: Retained<VZMACAddress>,
}

impl MACAddress {
    pub fn new() -> Self {
        MACAddress {
            inner: unsafe { VZMACAddress::init(VZMACAddress::alloc()) },
        }
    }

    pub fn random_local() -> Self {
        MACAddress {
            inner: unsafe { VZMACAddress::randomLocallyAdministeredAddress() },
        }
    }
}

impl Default for MACAddress {
    fn default() -> Self {
        Self::new()
    }
}

pub struct VirtioNetworkDevice {
    inner: Retained<VZVirtioNetworkDeviceConfiguration>,
}

impl VirtioNetworkDevice {
    pub fn new() -> Self {
        VirtioNetworkDevice {
            inner: unsafe {
                VZVirtioNetworkDeviceConfiguration::init(
                    VZVirtioNetworkDeviceConfiguration::alloc(),
                )
            },
        }
    }

    pub fn new_with_attachment(attachment: &impl NetworkAttachment) -> Self {
        let config = Self::new();
        config.set_attachment(attachment);
        config
    }

    pub fn set_attachment(&self, attachment: &impl NetworkAttachment) {
        unsafe {
            self.inner.setAttachment(Some(&attachment.as_vz_attachment()));
        }
    }

    pub fn set_mac_address(&self, address: &MACAddress) {
        unsafe {
            self.inner.setMACAddress(&address.inner);
        }
    }

    pub(crate) fn as_network_config(&self) -> Retained<VZNetworkDeviceConfiguration> {
        unsafe { Retained::cast_unchecked(self.inner.clone()) }
    }
}

impl Default for VirtioNetworkDevice {
    fn default() -> Self {
        Self::new()
    }
}
