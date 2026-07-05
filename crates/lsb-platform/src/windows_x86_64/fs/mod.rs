mod copy;
mod mount_plan;

pub use copy::{
    join_guest_child, plan_copy_in, validate_copy_out_destination, validate_guest_absolute_path,
    validate_guest_path_component, validate_windows_host_path_lexical, CaseFoldSet, CopyInEntry,
    CopyInEntryKind, CopyInPlan, CopyOutDestination, CopyPathError, CopyPathOperation,
    SymlinkPolicy, WindowsPathKind,
};
#[cfg(windows)]
pub use copy::{open_copy_in_file_checked, CopyInFileIdentity};
pub use mount_plan::{
    plan_windows_mounts, replan_windows_mount_import, windows_mount_guest_source,
    WindowsMountImport, WindowsMountMode, WindowsMountPlan, WindowsMountPlanError,
    WindowsMountSpec, WINDOWS_MOUNT_STAGING_ROOT,
};
