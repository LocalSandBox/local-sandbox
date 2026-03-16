use objc2::rc::Retained;
use objc2::AnyThread;
use objc2_virtualization::{
    VZMemoryBalloonDeviceConfiguration, VZVirtioTraditionalMemoryBalloonDeviceConfiguration,
};

pub struct VirtioMemoryBalloonDevice {
    inner: Retained<VZVirtioTraditionalMemoryBalloonDeviceConfiguration>,
}

impl VirtioMemoryBalloonDevice {
    pub fn new() -> Self {
        VirtioMemoryBalloonDevice {
            inner: unsafe {
                VZVirtioTraditionalMemoryBalloonDeviceConfiguration::init(
                    VZVirtioTraditionalMemoryBalloonDeviceConfiguration::alloc(),
                )
            },
        }
    }

    pub(crate) fn as_memory_balloon_config(
        &self,
    ) -> Retained<VZMemoryBalloonDeviceConfiguration> {
        unsafe { Retained::cast_unchecked(self.inner.clone()) }
    }
}

impl Default for VirtioMemoryBalloonDevice {
    fn default() -> Self {
        Self::new()
    }
}
