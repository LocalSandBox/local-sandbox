use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::path::PathBuf;

use lsb_proto::MountRequest;

use super::{
    join_guest_child, plan_copy_in, validate_guest_absolute_path, validate_guest_path_component,
    CopyInEntryKind, CopyInPlan, CopyPathError, CopyPathOperation,
};

pub const WINDOWS_MOUNT_STAGING_ROOT: &str = "/tmp/lsb/mounts";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WindowsMountMode {
    Overlay,
    Direct { flags: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsMountSpec {
    pub tag: String,
    pub host_path: PathBuf,
    pub guest_path: String,
    pub mode: WindowsMountMode,
}

impl WindowsMountSpec {
    pub fn overlay(
        tag: impl Into<String>,
        host_path: impl Into<PathBuf>,
        guest_path: impl Into<String>,
    ) -> Self {
        Self {
            tag: tag.into(),
            host_path: host_path.into(),
            guest_path: guest_path.into(),
            mode: WindowsMountMode::Overlay,
        }
    }

    pub fn direct(
        tag: impl Into<String>,
        host_path: impl Into<PathBuf>,
        guest_path: impl Into<String>,
        flags: u64,
    ) -> Self {
        Self {
            tag: tag.into(),
            host_path: host_path.into(),
            guest_path: guest_path.into(),
            mode: WindowsMountMode::Direct { flags },
        }
    }
}

#[derive(Debug, Clone)]
pub struct WindowsMountPlan {
    pub imports: Vec<WindowsMountImport>,
    pub mount_requests: Vec<MountRequest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsMountImport {
    pub tag: String,
    pub host_path: PathBuf,
    pub guest_source: String,
    pub guest_target: String,
    pub copy_plan: CopyInPlan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WindowsMountPlanError {
    InvalidPath(CopyPathError),
    SourceNotDirectory { tag: String, path: String },
    DuplicateTarget { target: String },
    ReservedTarget { target: String },
    UnsupportedDirectMount { target: String, flags: u64 },
}

impl fmt::Display for WindowsMountPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath(error) => write!(f, "Windows mount path validation failed: {error}"),
            Self::SourceNotDirectory { tag, path } => write!(
                f,
                "Windows mount '{tag}' source '{path}' is unsupported: mount sources must be directories"
            ),
            Self::DuplicateTarget { target } => write!(
                f,
                "Windows mount target '{target}' is configured more than once"
            ),
            Self::ReservedTarget { target } => write!(
                f,
                "Windows mount target '{target}' is reserved for LocalSandbox mount staging"
            ),
            Self::UnsupportedDirectMount { target, flags } => write!(
                f,
                "Windows mount target '{target}' uses direct mount flags {flags}; direct host mounts, including direct read-write host mounts, are unsupported in the Windows MVP. Use overlay/ro mounts for copy-import semantics."
            ),
        }
    }
}

impl Error for WindowsMountPlanError {}

impl From<CopyPathError> for WindowsMountPlanError {
    fn from(error: CopyPathError) -> Self {
        Self::InvalidPath(error)
    }
}

pub fn plan_windows_mounts(
    specs: &[WindowsMountSpec],
) -> Result<WindowsMountPlan, WindowsMountPlanError> {
    let mut imports = Vec::new();
    let mut mount_requests = Vec::new();
    let mut targets = HashSet::new();

    for spec in specs {
        validate_guest_path_component(
            &spec.tag,
            CopyPathOperation::CopyInGuestDestination,
            WINDOWS_MOUNT_STAGING_ROOT,
        )?;
        validate_guest_absolute_path(&spec.guest_path, CopyPathOperation::CopyInGuestDestination)?;
        reject_reserved_mount_target(&spec.guest_path)?;
        if !targets.insert(spec.guest_path.clone()) {
            return Err(WindowsMountPlanError::DuplicateTarget {
                target: spec.guest_path.clone(),
            });
        }

        match spec.mode {
            WindowsMountMode::Overlay => {
                let guest_source = windows_mount_guest_source(&spec.tag);
                let copy_plan = plan_copy_in(&spec.host_path, &guest_source)?;
                if !copy_plan_root_is_directory(&copy_plan) {
                    return Err(WindowsMountPlanError::SourceNotDirectory {
                        tag: spec.tag.clone(),
                        path: spec.host_path.display().to_string(),
                    });
                }

                imports.push(WindowsMountImport {
                    tag: spec.tag.clone(),
                    host_path: copy_plan.source_root.clone(),
                    guest_source: guest_source.clone(),
                    guest_target: spec.guest_path.clone(),
                    copy_plan,
                });
                mount_requests.push(MountRequest::Overlay {
                    source: guest_source,
                    target: spec.guest_path.clone(),
                });
            }
            WindowsMountMode::Direct { flags } => {
                return Err(WindowsMountPlanError::UnsupportedDirectMount {
                    target: spec.guest_path.clone(),
                    flags,
                });
            }
        }
    }

    Ok(WindowsMountPlan {
        imports,
        mount_requests,
    })
}

pub fn replan_windows_mount_import(
    import: &WindowsMountImport,
) -> Result<WindowsMountImport, WindowsMountPlanError> {
    let copy_plan = plan_copy_in(&import.host_path, &import.guest_source)?;
    if !copy_plan_root_is_directory(&copy_plan) {
        return Err(WindowsMountPlanError::SourceNotDirectory {
            tag: import.tag.clone(),
            path: import.host_path.display().to_string(),
        });
    }

    Ok(WindowsMountImport {
        tag: import.tag.clone(),
        host_path: copy_plan.source_root.clone(),
        guest_source: import.guest_source.clone(),
        guest_target: import.guest_target.clone(),
        copy_plan,
    })
}

pub fn windows_mount_guest_source(tag: &str) -> String {
    join_guest_child(&join_guest_child(WINDOWS_MOUNT_STAGING_ROOT, tag), "source")
}

fn copy_plan_root_is_directory(plan: &CopyInPlan) -> bool {
    plan.entries
        .iter()
        .find(|entry| entry.guest_path == plan.guest_root)
        .is_some_and(|entry| matches!(entry.kind, CopyInEntryKind::Directory))
}

fn reject_reserved_mount_target(target: &str) -> Result<(), WindowsMountPlanError> {
    if guest_path_contains_or_equals(target, WINDOWS_MOUNT_STAGING_ROOT)
        || guest_path_contains_or_equals(WINDOWS_MOUNT_STAGING_ROOT, target)
    {
        return Err(WindowsMountPlanError::ReservedTarget {
            target: target.to_string(),
        });
    }
    Ok(())
}

fn guest_path_contains_or_equals(path: &str, ancestor: &str) -> bool {
    path == ancestor
        || path
            .strip_prefix(ancestor)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn overlay_mount_plans_copy_import_and_guest_overlay_request() {
        let root = temp_dir("overlay");
        let source = root.join("src");
        fs::create_dir_all(source.join("nested")).expect("fixture dirs");
        write_fixture(&source.join("hello.txt"), b"hello");
        write_fixture(&source.join("nested/world.txt"), b"world");

        let plan =
            plan_windows_mounts(&[WindowsMountSpec::overlay("mount0", &source, "/workspace")])
                .expect("mount plan should build");

        assert_eq!(plan.imports.len(), 1);
        let import = &plan.imports[0];
        assert_eq!(import.tag, "mount0");
        assert_eq!(import.guest_source, "/tmp/lsb/mounts/mount0/source");
        assert_eq!(import.guest_target, "/workspace");
        assert_eq!(import.copy_plan.guest_root, import.guest_source);
        assert!(matches!(
            plan.mount_requests[0],
            MountRequest::Overlay { ref source, ref target }
                if source == "/tmp/lsb/mounts/mount0/source" && target == "/workspace"
        ));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn mount_plan_rejects_direct_mounts_on_windows() {
        let err = plan_windows_mounts(&[WindowsMountSpec::direct(
            "mount0",
            host_fixture_dir("direct"),
            "/workspace",
            0,
        )])
        .expect_err("direct mounts should fail");

        assert!(matches!(
            err,
            WindowsMountPlanError::UnsupportedDirectMount { flags: 0, .. }
        ));
        assert!(err.to_string().contains("direct read-write host mounts"));
    }

    #[test]
    fn mount_plan_rejects_file_sources() {
        let root = temp_dir("file-source");
        let source = root.join("input.txt");
        write_fixture(&source, b"not a directory");

        let err =
            plan_windows_mounts(&[WindowsMountSpec::overlay("mount0", &source, "/workspace")])
                .expect_err("file mount source should fail");

        assert!(matches!(
            err,
            WindowsMountPlanError::SourceNotDirectory { .. }
        ));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn mount_plan_reuses_copy_validation_for_unsafe_sources() {
        let err = plan_windows_mounts(&[WindowsMountSpec::overlay(
            "mount0",
            Path::new(r"\\server\share\project"),
            "/workspace",
        )])
        .expect_err("UNC source should fail");

        assert!(matches!(err, WindowsMountPlanError::InvalidPath(_)));
        assert!(err.to_string().contains("UNC paths"));
    }

    #[test]
    fn mount_plan_rejects_unsafe_or_reserved_guest_targets() {
        let source = host_fixture_dir("target");

        let traversal = plan_windows_mounts(&[WindowsMountSpec::overlay(
            "mount0",
            &source,
            "/workspace/../secret",
        )])
        .expect_err("target traversal should fail");
        assert!(matches!(traversal, WindowsMountPlanError::InvalidPath(_)));

        let reserved = plan_windows_mounts(&[WindowsMountSpec::overlay(
            "mount0",
            &source,
            "/tmp/lsb/mounts/mount0",
        )])
        .expect_err("reserved target should fail");
        assert!(matches!(
            reserved,
            WindowsMountPlanError::ReservedTarget { .. }
        ));

        let _ = fs::remove_dir_all(source.parent().unwrap());
    }

    #[test]
    fn mount_plan_rejects_targets_that_cover_staging_root() {
        let source = host_fixture_dir("target-ancestor");

        for target in ["/tmp", "/tmp/lsb", WINDOWS_MOUNT_STAGING_ROOT] {
            let err = plan_windows_mounts(&[WindowsMountSpec::overlay("mount0", &source, target)])
                .expect_err("staging root ancestors should be reserved");
            assert!(matches!(err, WindowsMountPlanError::ReservedTarget { .. }));
        }

        let _ = fs::remove_dir_all(source.parent().unwrap());
    }

    #[cfg(windows)]
    #[test]
    fn mount_plan_accepts_canonicalized_verbatim_windows_source() {
        let source = host_fixture_dir("canonical-verbatim");
        let canonical = source.canonicalize().expect("canonical source path");
        assert!(
            canonical.display().to_string().starts_with(r"\\?\"),
            "Windows canonicalize should use a verbatim path: {}",
            canonical.display()
        );

        let plan =
            plan_windows_mounts(&[WindowsMountSpec::overlay("mount0", canonical, "/workspace")])
                .expect("canonicalized Windows mount source should plan");

        assert_eq!(plan.imports.len(), 1);
        assert_eq!(plan.mount_requests.len(), 1);

        let _ = fs::remove_dir_all(source.parent().unwrap());
    }

    #[test]
    fn mount_plan_rejects_duplicate_targets() {
        let source = host_fixture_dir("duplicate");
        let err = plan_windows_mounts(&[
            WindowsMountSpec::overlay("mount0", &source, "/workspace"),
            WindowsMountSpec::overlay("mount1", &source, "/workspace"),
        ])
        .expect_err("duplicate targets should fail");

        assert!(matches!(err, WindowsMountPlanError::DuplicateTarget { .. }));

        let _ = fs::remove_dir_all(source.parent().unwrap());
    }

    #[test]
    fn replan_mount_import_rejects_entry_replaced_with_symlink_after_initial_plan() {
        let root = temp_dir("replan-symlink");
        let source = root.join("src");
        fs::create_dir_all(&source).expect("fixture source dir");
        write_fixture(&source.join("input.txt"), b"safe");

        let plan =
            plan_windows_mounts(&[WindowsMountSpec::overlay("mount0", &source, "/workspace")])
                .expect("initial mount plan should build");
        let import = &plan.imports[0];

        fs::remove_file(source.join("input.txt")).expect("remove planned file");
        write_fixture(&root.join("target.txt"), b"target");
        #[cfg(unix)]
        std::os::unix::fs::symlink(root.join("target.txt"), source.join("input.txt"))
            .expect("symlink fixture");
        #[cfg(windows)]
        {
            match std::os::windows::fs::symlink_file(
                root.join("target.txt"),
                source.join("input.txt"),
            ) {
                Ok(()) => {}
                Err(error) if error.raw_os_error() == Some(1314) => {
                    eprintln!(
                        "skipping Windows symlink replacement fixture because the runner lacks symlink privilege: {error}"
                    );
                    let _ = fs::remove_dir_all(root);
                    return;
                }
                Err(error) => panic!("symlink fixture: {error}"),
            }
        }

        let err = replan_windows_mount_import(import)
            .expect_err("replan should reject replaced symlink entry");

        assert!(matches!(err, WindowsMountPlanError::InvalidPath(_)));
        assert!(err.to_string().contains("symlinks"));

        let _ = fs::remove_dir_all(root);
    }

    fn host_fixture_dir(label: &str) -> PathBuf {
        let root = temp_dir(label);
        let source = root.join("src");
        fs::create_dir_all(&source).expect("fixture source dir");
        write_fixture(&source.join("hello.txt"), b"hello");
        source
    }

    fn write_fixture(path: &Path, content: &[u8]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("parent dir");
        }
        let mut file = fs::File::create(path).expect("fixture file");
        file.write_all(content).expect("fixture content");
    }

    fn temp_dir(label: &str) -> PathBuf {
        let nonce = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        #[cfg(windows)]
        let base = std::env::temp_dir();
        #[cfg(not(windows))]
        let base = PathBuf::from("/private/tmp");
        let root = base.join(format!(
            "lsb-windows-mount-plan-{label}-{}-{nonce}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        root
    }
}
