use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use anyhow::{bail, Context, Result};

use crate::security::path::{MAX_MOUNT_BYTES, MAX_MOUNT_ENTRIES};

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
    let mut snapshot = TreeSnapshot::default();
    let mut pending = vec![(root.to_path_buf(), PathBuf::new())];
    let mut total_bytes = 0u64;
    while let Some((directory, relative_directory)) = pending.pop() {
        for entry in std::fs::read_dir(&directory)? {
            let entry = entry?;
            let metadata = entry.metadata()?;
            let file_type = metadata.file_type();
            if file_type.is_symlink() || (!file_type.is_file() && !file_type.is_dir()) {
                bail!("staged mount contains an unsupported entry type");
            }
            let relative = relative_directory.join(entry.file_name());
            if snapshot.entries.len() >= MAX_MOUNT_ENTRIES as usize {
                bail!("staged mount exceeds entry limit");
            }
            let modified_ns = metadata
                .modified()?
                .duration_since(UNIX_EPOCH)
                .context("file modified time is before Unix epoch")?
                .as_nanos();
            let content_hash = if file_type.is_file() {
                total_bytes = total_bytes
                    .checked_add(metadata.len())
                    .context("staged byte overflow")?;
                if total_bytes > MAX_MOUNT_BYTES {
                    bail!("staged mount exceeds byte limit");
                }
                Some(hash_file(&entry.path())?)
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
            let baseline = baseline.entries.get(path);
            let host = host.entries.get(path);
            let guest = guest.entries.get(path);
            !same_entry(host, baseline) && !same_entry(guest, baseline) && !same_entry(host, guest)
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

fn hash_file(path: &Path) -> Result<[u8; 32]> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
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
}
