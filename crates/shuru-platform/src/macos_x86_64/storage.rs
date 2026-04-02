use objc2::rc::Retained;
use objc2::AnyThread;
use objc2_foundation::{NSString, NSURL};
use objc2_virtualization::{
    VZDiskImageCachingMode, VZDiskImageStorageDeviceAttachment, VZDiskImageSynchronizationMode,
    VZDiskSynchronizationMode, VZNetworkBlockDeviceStorageDeviceAttachment,
    VZStorageDeviceAttachment, VZStorageDeviceConfiguration, VZVirtioBlockDeviceConfiguration,
};

use super::error::{Result, VzError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskImageCachingMode {
    Automatic,
    Cached,
    Uncached,
}

impl DiskImageCachingMode {
    fn to_vz(self) -> VZDiskImageCachingMode {
        match self {
            Self::Automatic => VZDiskImageCachingMode::Automatic,
            Self::Cached => VZDiskImageCachingMode::Cached,
            Self::Uncached => VZDiskImageCachingMode::Uncached,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskImageSynchronizationMode {
    Full,
    Fsync,
    None,
}

impl DiskImageSynchronizationMode {
    fn to_vz(self) -> VZDiskImageSynchronizationMode {
        match self {
            Self::Full => VZDiskImageSynchronizationMode::Full,
            Self::Fsync => VZDiskImageSynchronizationMode::Fsync,
            Self::None => VZDiskImageSynchronizationMode::None,
        }
    }
}

pub trait StorageDevice {
    fn as_storage_config(&self) -> Retained<VZStorageDeviceConfiguration>;
}

pub trait StorageAttachment {
    fn as_vz_attachment(&self) -> Retained<VZStorageDeviceAttachment>;
}

pub struct DiskImageAttachment {
    inner: Retained<VZDiskImageStorageDeviceAttachment>,
}

impl DiskImageAttachment {
    pub fn new(path: &str, read_only: bool) -> Result<Self> {
        unsafe {
            let ns_path = NSString::from_str(path);
            let url = NSURL::fileURLWithPath_isDirectory(&ns_path, false);
            let inner = VZDiskImageStorageDeviceAttachment::initWithURL_readOnly_error(
                VZDiskImageStorageDeviceAttachment::alloc(),
                &url,
                read_only,
            )
            .map_err(|e| VzError::from_ns_error(&e))?;
            Ok(DiskImageAttachment { inner })
        }
    }

    pub fn new_with_options(
        path: &str,
        read_only: bool,
        caching_mode: DiskImageCachingMode,
        synchronization_mode: DiskImageSynchronizationMode,
    ) -> Result<Self> {
        unsafe {
            let ns_path = NSString::from_str(path);
            let url = NSURL::fileURLWithPath_isDirectory(&ns_path, false);
            let inner = VZDiskImageStorageDeviceAttachment::initWithURL_readOnly_cachingMode_synchronizationMode_error(
                VZDiskImageStorageDeviceAttachment::alloc(),
                &url,
                read_only,
                caching_mode.to_vz(),
                synchronization_mode.to_vz(),
            )
            .map_err(|e| VzError::from_ns_error(&e))?;
            Ok(DiskImageAttachment { inner })
        }
    }
}

impl StorageAttachment for DiskImageAttachment {
    fn as_vz_attachment(&self) -> Retained<VZStorageDeviceAttachment> {
        unsafe { Retained::cast_unchecked(self.inner.clone()) }
    }
}

pub struct NbdAttachment {
    inner: Retained<VZNetworkBlockDeviceStorageDeviceAttachment>,
}

impl NbdAttachment {
    pub fn new(uri: &str, timeout_secs: f64, read_only: bool) -> Result<Self> {
        unsafe {
            let ns_uri = NSString::from_str(uri);
            let url = NSURL::URLWithString(&ns_uri)
                .ok_or_else(|| VzError::new(format!("invalid NBD URI: {}", uri)))?;
            let sync_mode = if read_only {
                VZDiskSynchronizationMode::None
            } else {
                VZDiskSynchronizationMode::Full
            };
            let inner = VZNetworkBlockDeviceStorageDeviceAttachment::initWithURL_timeout_forcedReadOnly_synchronizationMode_error(
                VZNetworkBlockDeviceStorageDeviceAttachment::alloc(),
                &url,
                timeout_secs,
                read_only,
                sync_mode,
            )
            .map_err(|e| VzError::from_ns_error(&e))?;
            Ok(Self { inner })
        }
    }
}

impl StorageAttachment for NbdAttachment {
    fn as_vz_attachment(&self) -> Retained<VZStorageDeviceAttachment> {
        unsafe { Retained::cast_unchecked(self.inner.clone()) }
    }
}

pub struct VirtioBlockDevice {
    inner: Retained<VZVirtioBlockDeviceConfiguration>,
}

impl VirtioBlockDevice {
    pub fn new(attachment: &dyn StorageAttachment) -> Self {
        unsafe {
            let attachment_id = attachment.as_vz_attachment();
            let inner = VZVirtioBlockDeviceConfiguration::initWithAttachment(
                VZVirtioBlockDeviceConfiguration::alloc(),
                &attachment_id,
            );
            VirtioBlockDevice { inner }
        }
    }

    pub fn validate_identifier(identifier: &str) -> Result<()> {
        unsafe {
            let id = NSString::from_str(identifier);
            VZVirtioBlockDeviceConfiguration::validateBlockDeviceIdentifier_error(&id)
                .map_err(|e| VzError::from_ns_error(&e))?;
            Ok(())
        }
    }

    pub fn set_identifier(&self, identifier: &str) {
        unsafe {
            let id = NSString::from_str(identifier);
            self.inner.setBlockDeviceIdentifier(&id);
        }
    }
}

impl StorageDevice for VirtioBlockDevice {
    fn as_storage_config(&self) -> Retained<VZStorageDeviceConfiguration> {
        unsafe { Retained::cast_unchecked(self.inner.clone()) }
    }
}
