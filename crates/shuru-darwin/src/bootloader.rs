use objc2::rc::Retained;
use objc2::AnyThread;
use objc2_foundation::{NSString, NSURL};
use objc2_virtualization::{VZBootLoader, VZLinuxBootLoader};

pub struct LinuxBootLoader {
    inner: Retained<VZLinuxBootLoader>,
}

impl LinuxBootLoader {
    pub fn new(kernel_path: &str, initrd_path: &str, command_line: &str) -> Self {
        let boot_loader = Self::new_with_kernel(kernel_path);
        boot_loader.set_initrd(initrd_path);
        boot_loader.set_command_line(command_line);
        boot_loader
    }

    pub fn new_with_kernel(kernel_path: &str) -> Self {
        unsafe {
            let path = NSString::from_str(kernel_path);
            let kernel_url = NSURL::fileURLWithPath_isDirectory(&path, false);
            LinuxBootLoader {
                inner: VZLinuxBootLoader::initWithKernelURL(
                    VZLinuxBootLoader::alloc(),
                    &kernel_url,
                ),
            }
        }
    }

    pub fn set_initrd(&self, initrd_path: &str) {
        unsafe {
            let path = NSString::from_str(initrd_path);
            let initrd_url = NSURL::fileURLWithPath_isDirectory(&path, false);
            self.inner.setInitialRamdiskURL(Some(&initrd_url));
        }
    }

    pub fn set_command_line(&self, command_line: &str) {
        unsafe {
            let command_line = NSString::from_str(command_line);
            self.inner.setCommandLine(&command_line);
        }
    }

    pub(crate) fn as_vz_boot_loader(&self) -> Retained<VZBootLoader> {
        unsafe { Retained::cast_unchecked(self.inner.clone()) }
    }
}
