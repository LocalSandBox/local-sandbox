use objc2::rc::Retained;
use objc2::AnyThread;
use objc2_foundation::{NSString, NSURL};
use objc2_virtualization::{
    VZDirectoryShare, VZDirectorySharingDeviceConfiguration, VZSharedDirectory,
    VZSingleDirectoryShare, VZVirtioFileSystemDeviceConfiguration,
};

pub struct SharedDirectory {
    inner: Retained<VZSharedDirectory>,
}

impl SharedDirectory {
    pub fn new(path: &str, read_only: bool) -> Self {
        unsafe {
            let ns_path = NSString::from_str(path);
            let url = NSURL::fileURLWithPath_isDirectory(&ns_path, true);
            let inner =
                VZSharedDirectory::initWithURL_readOnly(VZSharedDirectory::alloc(), &url, read_only);
            SharedDirectory { inner }
        }
    }
}

pub struct VirtioFileSystemDevice {
    inner: Retained<VZVirtioFileSystemDeviceConfiguration>,
}

impl VirtioFileSystemDevice {
    pub fn new(tag: &str, directory: &SharedDirectory) -> Self {
        unsafe {
            let ns_tag = NSString::from_str(tag);
            let inner = VZVirtioFileSystemDeviceConfiguration::initWithTag(
                VZVirtioFileSystemDeviceConfiguration::alloc(),
                &ns_tag,
            );

            let single_share: Retained<VZDirectoryShare> = Retained::cast_unchecked(
                VZSingleDirectoryShare::initWithDirectory(
                    VZSingleDirectoryShare::alloc(),
                    &directory.inner,
                ),
            );
            inner.setShare(Some(&*single_share));

            VirtioFileSystemDevice { inner }
        }
    }

    pub(crate) fn as_directory_sharing_config(
        &self,
    ) -> Retained<VZDirectorySharingDeviceConfiguration> {
        unsafe { Retained::cast_unchecked(self.inner.clone()) }
    }
}
