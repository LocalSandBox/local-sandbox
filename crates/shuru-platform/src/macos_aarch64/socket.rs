use objc2::rc::Retained;
use objc2_virtualization::{VZSocketDeviceConfiguration, VZVirtioSocketDeviceConfiguration};

pub struct VirtioSocketDevice {
    inner: Retained<VZVirtioSocketDeviceConfiguration>,
}

impl VirtioSocketDevice {
    pub fn new() -> Self {
        VirtioSocketDevice {
            inner: unsafe { VZVirtioSocketDeviceConfiguration::new() },
        }
    }

    pub(crate) fn as_socket_config(&self) -> Retained<VZSocketDeviceConfiguration> {
        unsafe { Retained::cast_unchecked(self.inner.clone()) }
    }
}

impl Default for VirtioSocketDevice {
    fn default() -> Self {
        Self::new()
    }
}
