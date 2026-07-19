use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use anyhow::{bail, Context, Result};

use lsb_service_proto::limits::{
    MAX_MOUNT_COMPONENTS, MAX_MOUNT_ENTRIES, MAX_MOUNT_FILE_BYTES, MAX_MOUNT_QUEUED_CHANGES,
    MAX_MOUNT_TREE_BYTES, MAX_MOUNT_WINDOWS_UTF16,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryFingerprint {
    pub directory: bool,
    pub len: u64,
    pub modified_ns: u128,
    pub content_hash: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TreeSnapshot {
    pub entries: BTreeMap<PathBuf, EntryFingerprint>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountConflict {
    pub relative_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncDecision {
    Unchanged,
    ImportHost,
    ExportGuest,
    Converged,
    Conflict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeBatch {
    Paths(Vec<PathBuf>),
    FullRescan,
}

#[derive(Debug, Default)]
pub struct ChangeQueue {
    paths: BTreeSet<PathBuf>,
    full_rescan: bool,
}

impl ChangeQueue {
    pub fn push(&mut self, relative: PathBuf) -> Result<()> {
        validate_relative_path(&relative)?;
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            bail!("mount change must be a safe relative path");
        }
        if self.full_rescan || self.paths.contains(&relative) {
            return Ok(());
        }
        if self.paths.len() == MAX_MOUNT_QUEUED_CHANGES {
            self.paths.clear();
            self.full_rescan = true;
            return Ok(());
        }
        self.paths.insert(relative);
        Ok(())
    }

    pub fn drain(&mut self) -> ChangeBatch {
        if std::mem::take(&mut self.full_rescan) {
            self.paths.clear();
            ChangeBatch::FullRescan
        } else {
            ChangeBatch::Paths(std::mem::take(&mut self.paths).into_iter().collect())
        }
    }
}

impl std::fmt::Display for MountConflict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "MOUNT_CONFLICT on {} path(s)",
            self.relative_paths.len()
        )
    }
}

impl std::error::Error for MountConflict {}

pub fn snapshot_tree(root: &Path) -> Result<TreeSnapshot> {
    let root_metadata = std::fs::symlink_metadata(root)?;
    if root_metadata.file_type().is_symlink() || !root_metadata.file_type().is_dir() {
        bail!("staged mount root must be a regular directory");
    }
    let mut snapshot = TreeSnapshot::default();
    let mut pending = vec![(root.to_path_buf(), PathBuf::new())];
    let mut total_bytes = 0u64;
    while let Some((directory, relative_directory)) = pending.pop() {
        for entry in std::fs::read_dir(&directory)? {
            let entry = entry?;
            let metadata = std::fs::symlink_metadata(entry.path())?;
            let file_type = metadata.file_type();
            if file_type.is_symlink() || (!file_type.is_file() && !file_type.is_dir()) {
                bail!("staged mount contains an unsupported entry type");
            }
            let relative = relative_directory.join(entry.file_name());
            validate_relative_path(&relative)?;
            if snapshot.entries.len() >= MAX_MOUNT_ENTRIES {
                bail!("staged mount exceeds entry limit");
            }
            let modified = metadata.modified()?;
            let modified_ns = modified
                .duration_since(UNIX_EPOCH)
                .context("file modified time is before Unix epoch")?
                .as_nanos();
            let content_hash = if file_type.is_file() {
                if metadata.len() > MAX_MOUNT_FILE_BYTES {
                    bail!("staged mount file exceeds per-file byte limit");
                }
                total_bytes = total_bytes
                    .checked_add(metadata.len())
                    .context("staged byte overflow")?;
                if total_bytes > MAX_MOUNT_TREE_BYTES {
                    bail!("staged mount exceeds byte limit");
                }
                Some(hash_file(&entry.path(), metadata.len(), modified)?)
            } else {
                pending.push((entry.path(), relative.clone()));
                None
            };
            snapshot.entries.insert(
                relative,
                EntryFingerprint {
                    directory: file_type.is_dir(),
                    len: metadata.len(),
                    modified_ns,
                    content_hash,
                },
            );
        }
    }
    Ok(snapshot)
}

pub(crate) fn validate_relative_path(path: &Path) -> Result<()> {
    if path.components().count() > MAX_MOUNT_COMPONENTS {
        bail!("staged mount exceeds path component limit");
    }
    let value = path
        .to_str()
        .context("staged mount path is not valid Unicode")?;
    if value.encode_utf16().count() > MAX_MOUNT_WINDOWS_UTF16 {
        bail!("staged mount exceeds Windows extended-path limit");
    }
    Ok(())
}

pub fn detect_conflicts(
    baseline: &TreeSnapshot,
    host: &TreeSnapshot,
    guest: &TreeSnapshot,
) -> std::result::Result<(), MountConflict> {
    let paths = baseline
        .entries
        .keys()
        .chain(host.entries.keys())
        .chain(guest.entries.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let conflicts = paths
        .into_iter()
        .filter(|path| {
            classify_change(
                baseline.entries.get(path),
                host.entries.get(path),
                guest.entries.get(path),
            ) == SyncDecision::Conflict
        })
        .collect::<Vec<_>>();
    if conflicts.is_empty() {
        Ok(())
    } else {
        Err(MountConflict {
            relative_paths: conflicts,
        })
    }
}

pub fn plan_changes(
    baseline: &TreeSnapshot,
    host: &TreeSnapshot,
    guest: &TreeSnapshot,
) -> BTreeMap<PathBuf, SyncDecision> {
    baseline
        .entries
        .keys()
        .chain(host.entries.keys())
        .chain(guest.entries.keys())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter_map(|path| {
            let decision = classify_change(
                baseline.entries.get(&path),
                host.entries.get(&path),
                guest.entries.get(&path),
            );
            (decision != SyncDecision::Unchanged).then_some((path, decision))
        })
        .collect()
}

fn classify_change(
    baseline: Option<&EntryFingerprint>,
    host: Option<&EntryFingerprint>,
    guest: Option<&EntryFingerprint>,
) -> SyncDecision {
    let host_changed = !same_entry(host, baseline);
    let guest_changed = !same_entry(guest, baseline);
    match (host_changed, guest_changed) {
        (false, false) => SyncDecision::Unchanged,
        (true, false) => SyncDecision::ImportHost,
        (false, true) => SyncDecision::ExportGuest,
        (true, true) if same_entry(host, guest) => SyncDecision::Converged,
        (true, true) => SyncDecision::Conflict,
    }
}

pub fn conflict_artifact_path(relative: &Path, session_id: &str, sequence: u64) -> Result<PathBuf> {
    validate_relative_path(relative)?;
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        bail!("conflict path must be a safe relative path");
    }
    if session_id.len() != 32
        || !session_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("conflict session id must be 32 lowercase hexadecimal characters");
    }
    let name = relative
        .file_name()
        .and_then(|name| name.to_str())
        .context("conflict path must have a Unicode filename")?;
    let conflict_name = format!("{name}.lsb-conflict-{session_id}-{sequence}");
    if conflict_name.encode_utf16().count() > 255 {
        bail!("conflict artifact filename exceeds the filesystem component limit");
    }
    let artifact = relative.with_file_name(conflict_name);
    validate_relative_path(&artifact)?;
    Ok(artifact)
}

fn same_entry(left: Option<&EntryFingerprint>, right: Option<&EntryFingerprint>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => {
            left.directory == right.directory
                && left.len == right.len
                && (left.directory || left.content_hash == right.content_hash)
        }
        _ => false,
    }
}

#[allow(dead_code)]
pub(super) fn mirror_tree(source: &Path, destination: &Path) -> Result<TreeSnapshot> {
    if destination.exists() {
        std::fs::remove_dir_all(destination)?;
    }
    std::fs::create_dir_all(destination)?;
    copy_directory(source, destination)?;
    snapshot_tree(destination)
}

fn copy_directory(source: &Path, destination: &Path) -> Result<()> {
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let target = destination.join(entry.file_name());
        if file_type.is_dir() {
            std::fs::create_dir(&target)?;
            copy_directory(&entry.path(), &target)?;
        } else if file_type.is_file() {
            std::fs::copy(entry.path(), target)?;
        } else {
            bail!("cannot mirror reparse or special entry");
        }
    }
    Ok(())
}

fn hash_file(
    path: &Path,
    expected_len: u64,
    expected_modified: std::time::SystemTime,
) -> Result<[u8; 32]> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut actual_len = 0u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        actual_len = actual_len
            .checked_add(read as u64)
            .context("staged file byte overflow")?;
        if actual_len > MAX_MOUNT_FILE_BYTES {
            bail!("staged mount file grew beyond its per-file byte limit");
        }
        hasher.update(&buffer[..read]);
    }
    let final_metadata = file.metadata()?;
    if actual_len != expected_len
        || final_metadata.len() != expected_len
        || final_metadata.modified()? != expected_modified
    {
        bail!("staged mount file changed while it was being snapshotted");
    }
    Ok(*hasher.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fingerprint(value: u8) -> EntryFingerprint {
        EntryFingerprint {
            directory: false,
            len: 1,
            modified_ns: value as u128,
            content_hash: Some([value; 32]),
        }
    }

    #[test]
    fn one_sided_change_is_not_a_conflict() {
        let path = PathBuf::from("file");
        let baseline = TreeSnapshot {
            entries: [(path.clone(), fingerprint(1))].into(),
        };
        let host = TreeSnapshot {
            entries: [(path.clone(), fingerprint(2))].into(),
        };
        assert!(detect_conflicts(&baseline, &host, &baseline).is_ok());
    }

    #[test]
    fn divergent_two_sided_change_is_deterministic_conflict() {
        let path = PathBuf::from("file");
        let baseline = TreeSnapshot {
            entries: [(path.clone(), fingerprint(1))].into(),
        };
        let host = TreeSnapshot {
            entries: [(path.clone(), fingerprint(2))].into(),
        };
        let guest = TreeSnapshot {
            entries: [(path.clone(), fingerprint(3))].into(),
        };
        assert_eq!(
            detect_conflicts(&baseline, &host, &guest)
                .unwrap_err()
                .relative_paths,
            vec![path]
        );
    }

    #[test]
    fn planning_classifies_import_export_convergence_and_conflict() {
        let baseline = TreeSnapshot {
            entries: [
                (PathBuf::from("host"), fingerprint(1)),
                (PathBuf::from("guest"), fingerprint(1)),
                (PathBuf::from("same"), fingerprint(1)),
                (PathBuf::from("conflict"), fingerprint(1)),
            ]
            .into(),
        };
        let host = TreeSnapshot {
            entries: [
                (PathBuf::from("host"), fingerprint(2)),
                (PathBuf::from("guest"), fingerprint(1)),
                (PathBuf::from("same"), fingerprint(2)),
                (PathBuf::from("conflict"), fingerprint(2)),
            ]
            .into(),
        };
        let guest = TreeSnapshot {
            entries: [
                (PathBuf::from("host"), fingerprint(1)),
                (PathBuf::from("guest"), fingerprint(2)),
                (PathBuf::from("same"), fingerprint(2)),
                (PathBuf::from("conflict"), fingerprint(3)),
            ]
            .into(),
        };
        assert_eq!(
            plan_changes(&baseline, &host, &guest),
            [
                (PathBuf::from("conflict"), SyncDecision::Conflict),
                (PathBuf::from("guest"), SyncDecision::ExportGuest),
                (PathBuf::from("host"), SyncDecision::ImportHost),
                (PathBuf::from("same"), SyncDecision::Converged),
            ]
            .into()
        );
    }

    #[test]
    fn conflict_artifact_name_is_exact_and_bounded() {
        let session = "0123456789abcdef0123456789abcdef";
        assert_eq!(
            conflict_artifact_path(Path::new("output/report.txt"), session, 17).unwrap(),
            PathBuf::from(format!("output/report.txt.lsb-conflict-{session}-17"))
        );
        assert!(conflict_artifact_path(Path::new("../report.txt"), session, 1).is_err());
        assert!(conflict_artifact_path(Path::new("report.txt"), "UPPER", 1).is_err());
        assert!(conflict_artifact_path(Path::new(&"a".repeat(230)), session, 1).is_err());
    }

    #[test]
    fn snapshot_rejects_symlink_roots_entries_and_oversized_sparse_files() {
        let root = std::env::temp_dir().join(format!("lsbsw-mount-sync-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let oversized = root.join("oversized");
        std::fs::File::create(&oversized)
            .unwrap()
            .set_len(MAX_MOUNT_FILE_BYTES + 1)
            .unwrap();
        assert!(snapshot_tree(&root).is_err());
        std::fs::remove_file(oversized).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let target = root.join("target");
            std::fs::write(&target, b"data").unwrap();
            symlink(&target, root.join("link")).unwrap();
            assert!(snapshot_tree(&root).is_err());
            std::fs::remove_file(root.join("link")).unwrap();
            let root_link = root.with_extension("link");
            let _ = std::fs::remove_file(&root_link);
            symlink(&root, &root_link).unwrap();
            assert!(snapshot_tree(&root_link).is_err());
            std::fs::remove_file(root_link).unwrap();
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn path_limits_are_enforced_without_filesystem_dependent_setup() {
        let deep = (0..=MAX_MOUNT_COMPONENTS).fold(PathBuf::new(), |path, _| path.join("d"));
        assert!(validate_relative_path(&deep).is_err());
        assert!(
            validate_relative_path(Path::new(&"x".repeat(MAX_MOUNT_WINDOWS_UTF16 + 1))).is_err()
        );
    }

    #[test]
    fn change_queue_coalesces_and_overflow_becomes_one_bounded_rescan() {
        let mut queue = ChangeQueue::default();
        queue.push(PathBuf::from("same")).unwrap();
        queue.push(PathBuf::from("same")).unwrap();
        assert_eq!(
            queue.drain(),
            ChangeBatch::Paths(vec![PathBuf::from("same")])
        );

        for index in 0..=MAX_MOUNT_QUEUED_CHANGES {
            queue.push(PathBuf::from(format!("path-{index}"))).unwrap();
        }
        assert_eq!(queue.drain(), ChangeBatch::FullRescan);
        assert_eq!(queue.drain(), ChangeBatch::Paths(Vec::new()));
        assert!(queue.push(PathBuf::from("../unsafe")).is_err());
    }
}
