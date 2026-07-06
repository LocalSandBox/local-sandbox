mod acl;
mod admin;
mod lifecycle;
mod password;
mod share;
mod types;
mod user;

#[cfg(windows)]
pub use acl::NativeWindowsSmbAclManager;
pub use acl::{WindowsSmbAclGrant, WindowsSmbAclGrantRequest, WindowsSmbAclManager};
#[cfg(windows)]
pub use admin::NativeWindowsSmbAdmin;
pub use admin::WindowsSmbAdmin;
#[cfg(windows)]
pub use lifecycle::recover_stale_windows_smb_cleanup_manifests;
pub use lifecycle::{
    read_windows_smb_cleanup_manifest, remove_windows_smb_cleanup_manifest,
    windows_smb_cleanup_manifest_path, write_windows_smb_cleanup_manifest,
    WindowsSmbActiveResources, WindowsSmbCleanupManifest, WindowsSmbLifecycleManager,
    WindowsSmbRecoveryReport, WINDOWS_SMB_CLEANUP_MANIFEST_FILE,
};
pub use password::{
    NativeWindowsSmbPasswordGenerator, WindowsSmbPassword, WindowsSmbPasswordGenerator,
};
#[cfg(windows)]
pub use share::NativeWindowsSmbShareManager;
pub use share::{
    WindowsSmbShare, WindowsSmbShareCreateRequest, WindowsSmbShareManager, WindowsSmbShareName,
};
pub use types::{
    generate_smb_share_name, generate_smb_user_name, validate_smb_share_name,
    validate_smb_user_name, WindowsSmbAccess, WindowsSmbCleanupFailure, WindowsSmbLifecycleConfig,
    WindowsSmbLifecycleError, WindowsSmbLifecyclePhase, WindowsSmbMount,
    WINDOWS_SMB_GATEWAY_SERVER, WINDOWS_SMB_UNC_SERVER,
};
#[cfg(windows)]
pub use user::NativeWindowsSmbUserManager;
pub use user::{WindowsSmbUserAccount, WindowsSmbUserManager, WindowsSmbUserName};
