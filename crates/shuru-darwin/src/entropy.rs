use objc2::rc::Retained;
use objc2_virtualization::{VZEntropyDeviceConfiguration, VZVirtioEntropyDeviceConfiguration};

pub struct VirtioEntropyDevice {
    inner: Retained<VZVirtioEntropyDeviceConfiguration>,
}

impl VirtioEntropyDevice {
    pub fn new() -> Self {
        VirtioEntropyDevice {
            inner: unsafe { VZVirtioEntropyDeviceConfiguration::new() },
        }
    }

    pub(crate) fn as_entropy_config(&self) -> Retained<VZEntropyDeviceConfiguration> {
        unsafe { Retained::cast_unchecked(self.inner.clone()) }
    }
}

impl Default for VirtioEntropyDevice {
    fn default() -> Self {
        Self::new()
    }
}
