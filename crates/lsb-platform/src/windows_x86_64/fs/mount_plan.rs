use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::path::PathBuf;

use lsb_proto::MountRequest;

use super::smb::{WindowsSmbAccess, WindowsSmbMount};
use super::{
    join_guest_child, validate_copy_in_source_root, validate_guest_absolute_path,
    validate_guest_path_component, CopyInSourceRootKind, CopyPathError, CopyPathOperation,
};

pub const WINDOWS_MOUNT_STAGING_ROOT: &str = "/tmp/lsb/mounts";
const MS_RDONLY: u64 = 1;

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
    pub imports: Vec<WindowsMountDescriptor>,
    pub smb_directs: Vec<WindowsSmbMount>,
    pub mount_requests: Vec<MountRequest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsMountDescriptor {
    pub tag: String,
    pub host_root: PathBuf,
    pub guest_source: String,
    pub guest_target: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WindowsMountPlanError {
    InvalidPath(CopyPathError),
    SourceNotDirectory { tag: String, path: String },
    DuplicateTarget { target: String },
    ReservedTarget { target: String },
    UnsupportedDirectMountFlags { target: String, flags: u64 },
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
            Self::UnsupportedDirectMountFlags { target, flags } => write!(
                f,
                "Windows direct mount target '{target}' uses unsupported flags {flags}; Windows direct SMB mounts support only flags 0 or MS_RDONLY"
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
    let mut smb_directs = Vec::new();
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
                let source = validate_copy_in_source_root(&spec.host_path)?;
                if source.kind != CopyInSourceRootKind::Directory {
                    return Err(WindowsMountPlanError::SourceNotDirectory {
                        tag: spec.tag.clone(),
                        path: spec.host_path.display().to_string(),
                    });
                }

                imports.push(WindowsMountDescriptor {
                    tag: spec.tag.clone(),
                    host_root: source.path,
                    guest_source: guest_source.clone(),
                    guest_target: spec.guest_path.clone(),
                });
                mount_requests.push(MountRequest::Overlay {
                    source: guest_source,
                    target: spec.guest_path.clone(),
                });
            }
            WindowsMountMode::Direct { flags } => {
                let access = match flags {
                    0 => WindowsSmbAccess::ReadWrite,
                    MS_RDONLY => WindowsSmbAccess::ReadOnly,
                    _ => {
                        return Err(WindowsMountPlanError::UnsupportedDirectMountFlags {
                            target: spec.guest_path.clone(),
                            flags,
                        });
                    }
                };
                smb_directs.push(plan_direct_smb_mount(
                    &spec.tag,
                    &spec.host_path,
                    &spec.guest_path,
                    access,
                )?);
            }
        }
    }

    Ok(WindowsMountPlan {
        imports,
        smb_directs,
        mount_requests,
    })
}

pub fn replan_windows_smb_mount(
    mount: &WindowsSmbMount,
) -> Result<WindowsSmbMount, WindowsMountPlanError> {
    plan_direct_smb_mount("direct", &mount.source, &mount.target, mount.access)
}

pub fn windows_mount_guest_source(tag: &str) -> String {
    join_guest_child(&join_guest_child(WINDOWS_MOUNT_STAGING_ROOT, tag), "source")
}

fn plan_direct_smb_mount(
    tag: &str,
    host_path: &std::path::Path,
    guest_path: &str,
    access: WindowsSmbAccess,
) -> Result<WindowsSmbMount, WindowsMountPlanError> {
    let source = validate_copy_in_source_root(host_path)?;
    if source.kind != CopyInSourceRootKind::Directory {
        return Err(WindowsMountPlanError::SourceNotDirectory {
            tag: tag.to_string(),
            path: host_path.display().to_string(),
        });
    }

    Ok(WindowsSmbMount {
        source: source.path,
        target: guest_path.to_string(),
        access,
    })
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
        assert_eq!(import.host_root, source.canonicalize().unwrap());
        assert!(matches!(
            plan.mount_requests[0],
            MountRequest::Overlay { ref source, ref target }
                if source == "/tmp/lsb/mounts/mount0/source" && target == "/workspace"
        ));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn mount_plan_accepts_direct_read_write_as_smb_mount() {
        let source = host_fixture_dir("direct-rw");
        let plan =
            plan_windows_mounts(&[WindowsMountSpec::direct("mount0", &source, "/workspace", 0)])
                .expect("direct read-write mount should plan as SMB");

        assert!(plan.imports.is_empty());
        assert!(plan.mount_requests.is_empty());
        assert_eq!(plan.smb_directs.len(), 1);
        assert_eq!(plan.smb_directs[0].source, source.canonicalize().unwrap());
        assert_eq!(plan.smb_directs[0].target, "/workspace");
        assert_eq!(plan.smb_directs[0].access, WindowsSmbAccess::ReadWrite);

        let _ = fs::remove_dir_all(source.parent().unwrap());
    }

    #[test]
    fn mount_plan_accepts_direct_read_only_as_smb_mount() {
        let source = host_fixture_dir("direct-ro");
        let plan = plan_windows_mounts(&[WindowsMountSpec::direct(
            "mount0",
            &source,
            "/workspace",
            MS_RDONLY,
        )])
        .expect("direct read-only mount should plan as SMB");

        assert!(plan.imports.is_empty());
        assert!(plan.mount_requests.is_empty());
        assert_eq!(plan.smb_directs.len(), 1);
        assert_eq!(plan.smb_directs[0].access, WindowsSmbAccess::ReadOnly);

        let _ = fs::remove_dir_all(source.parent().unwrap());
    }

    #[test]
    fn mount_plan_rejects_unsupported_direct_mount_flags() {
        let source = host_fixture_dir("direct-flags");
        let err = plan_windows_mounts(&[WindowsMountSpec::direct(
            "mount0",
            &source,
            "/workspace",
            MS_RDONLY | 2,
        )])
        .expect_err("unsupported direct mount flags should fail");

        assert!(matches!(
            err,
            WindowsMountPlanError::UnsupportedDirectMountFlags { flags, .. }
                if flags == MS_RDONLY | 2
        ));
        assert!(err
            .to_string()
            .contains("support only flags 0 or MS_RDONLY"));

        let _ = fs::remove_dir_all(source.parent().unwrap());
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
    fn mount_plan_does_not_visit_overlay_descendants() {
        let root = temp_dir("root-only");
        let source = root.join("src");
        fs::create_dir_all(&source).expect("fixture source dir");
        write_fixture(&source.join("input.txt"), b"safe");

        let plan =
            plan_windows_mounts(&[WindowsMountSpec::overlay("mount0", &source, "/workspace")])
                .expect("root-only mount plan should build");

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

        assert_eq!(plan.imports.len(), 1);
        assert_eq!(plan.imports[0].host_root, source.canonicalize().unwrap());

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
