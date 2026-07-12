mod copy;
#[cfg(windows)]
mod mount_cache;
mod mount_plan;
#[cfg(windows)]
mod mount_snapshot;
pub mod smb;
mod watch;

pub use copy::{
    join_guest_child, plan_copy_in, validate_copy_in_source_root, validate_copy_out_destination,
    validate_guest_absolute_path, validate_guest_path_component,
    validate_windows_host_path_lexical, CaseFoldSet, CopyInEntry, CopyInEntryKind, CopyInPlan,
    CopyInSourceRoot, CopyInSourceRootKind, CopyOutDestination, CopyPathError, CopyPathOperation,
    SymlinkPolicy, WindowsPathKind,
};
#[cfg(windows)]
pub use copy::{
    open_copy_in_directory_checked, open_copy_in_file_checked, open_copy_in_file_for_snapshot,
    CheckedCopyInDirectory, CheckedCopyInFile, CopyInFileIdentity,
};
#[cfg(windows)]
pub use mount_cache::{
    mount_cache_image_sizing, MountCacheImageFormat, MountCacheImageSizing,
    MountCacheMaintenanceReport, MountCacheManifest, WindowsMountCache, WindowsMountCacheBuild,
    WindowsMountCacheHit, WindowsMountCacheLimits, WindowsMountCacheSelection,
    WINDOWS_MOUNT_CACHE_DIR_ENV,
};
pub use mount_plan::{
    plan_windows_mounts, replan_windows_smb_mount, windows_mount_guest_source,
    WindowsMountDescriptor, WindowsMountMode, WindowsMountPlan, WindowsMountPlanError,
    WindowsMountSpec, WINDOWS_MOUNT_STAGING_ROOT,
};
#[cfg(windows)]
pub use mount_snapshot::{
    snapshot_windows_mount, WindowsMountSnapshot, WindowsMountSnapshotEntry,
    WindowsMountSnapshotEntryKind,
};
#[doc(hidden)]
pub use watch::{
    join_guest_watch_event_path, start_windows_host_directory_watch, WindowsHostDirectoryWatch,
    WindowsHostDirectoryWatchStop, WindowsHostWatchError, WindowsHostWatchEvent,
    WindowsHostWatchEventKind,
};
