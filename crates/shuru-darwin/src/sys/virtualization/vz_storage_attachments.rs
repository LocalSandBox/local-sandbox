#![allow(non_snake_case)]
use objc2::ffi::NSInteger;
use objc2::rc::{Allocated, Id, Shared};
use objc2::runtime::{NSObject, NSObjectProtocol};
use objc2::{extern_class, extern_methods, ClassType};

use crate::sys::foundation::*;

// region: VZDiskImageCachingMode
#[repr(isize)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VZDiskImageCachingMode {
    Automatic = 0,
    Cached = 1,
    Uncached = 2,
}
// endregion

// region: VZDiskImageSynchronizationMode
#[repr(isize)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VZDiskImageSynchronizationMode {
    Full = 1,
    Fsync = 2,
    None = 3,
}
// endregion

// region: VZStorageDeviceAttachment
extern_class!(
    #[derive(Debug, PartialEq, Eq, Hash)]
    pub struct VZStorageDeviceAttachment;

    unsafe impl ClassType for VZStorageDeviceAttachment {
        type Super = NSObject;
    }
);

unsafe impl NSObjectProtocol for VZStorageDeviceAttachment {}

extern_methods!(
    unsafe impl VZStorageDeviceAttachment {
        #[method_id(@__retain_semantics New new)]
        pub unsafe fn new() -> Id<Self, Shared>;

        #[method_id(@__retain_semantics Init init)]
        pub unsafe fn init(this: Option<Allocated<Self>>) -> Id<Self, Shared>;
    }
);
// endregion

// region: VZDiskImageStorageDeviceAttachment
extern_class!(
    #[derive(Debug, PartialEq, Eq, Hash)]
    pub(crate) struct VZDiskImageStorageDeviceAttachment;

    unsafe impl ClassType for VZDiskImageStorageDeviceAttachment {
        #[inherits(NSObject)]
        type Super = VZStorageDeviceAttachment;
    }
);

unsafe impl NSObjectProtocol for VZDiskImageStorageDeviceAttachment {}

extern_methods!(
    unsafe impl VZDiskImageStorageDeviceAttachment {
        #[method_id(@__retain_semantics Init initWithURL:readOnly:error:_)]
        pub unsafe fn initWithURL_readOnly_error(
            this: Option<Allocated<Self>>,
            url: &NSURL,
            read_only: bool,
        ) -> Result<Id<Self, Shared>, Id<NSError, Shared>>;

        #[method_id(@__retain_semantics Init initWithURL:readOnly:cachingMode:synchronizationMode:error:_)]
        pub unsafe fn initWithURL_readOnly_cachingMode_synchronizationMode_error(
            this: Option<Allocated<Self>>,
            url: &NSURL,
            read_only: bool,
            caching_mode: NSInteger,
            synchronization_mode: NSInteger,
        ) -> Result<Id<Self, Shared>, Id<NSError, Shared>>;

        #[method_id(@__retain_semantics Other URL)]
        pub unsafe fn URL(&self) -> Id<NSURL, Shared>;

        #[method(isReadOnly)]
        pub unsafe fn isReadOnly(&self) -> bool;

        #[method(cachingMode)]
        pub unsafe fn cachingMode(&self) -> NSInteger;

        #[method(synchronizationMode)]
        pub unsafe fn synchronizationMode(&self) -> NSInteger;
    }
);
// endregion
