use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use lsb_proto::{
    MountSnapshotKey, MountSnapshotKeyEncoder, MOUNT_IMPORT_DIRECTORY_MODE, MOUNT_IMPORT_FILE_MODE,
};

use super::copy::{inspect_copy_in_path_kind, validate_copy_in_component};
use super::{
    join_guest_child, open_copy_in_directory_checked, open_copy_in_file_for_snapshot,
    validate_copy_in_source_root, CaseFoldSet, CopyInFileIdentity, CopyInSourceRootKind,
    CopyPathError, CopyPathOperation, WindowsMountDescriptor,
};

const SNAPSHOT_READ_BUFFER_SIZE: usize = 512 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsMountSnapshot {
    pub descriptor: WindowsMountDescriptor,
    pub entries: Vec<WindowsMountSnapshotEntry>,
    pub key: MountSnapshotKey,
    pub file_count: u64,
    pub directory_count: u64,
    pub logical_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsMountSnapshotEntry {
    pub host_path: PathBuf,
    pub relative_path: String,
    pub guest_path: String,
    pub kind: WindowsMountSnapshotEntryKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WindowsMountSnapshotEntryKind {
    Directory {
        mode: u32,
    },
    File {
        len: u64,
        identity: CopyInFileIdentity,
        digest: [u8; 32],
        mode: u32,
    },
}

pub fn snapshot_windows_mount(
    descriptor: &WindowsMountDescriptor,
) -> Result<WindowsMountSnapshot, CopyPathError> {
    let source = validate_copy_in_source_root(&descriptor.host_root)?;
    if source.kind != CopyInSourceRootKind::Directory {
        return Err(CopyPathError::new(
            CopyPathOperation::CopyInSource,
            descriptor.host_root.display().to_string(),
            "mount source is no longer a directory",
        ));
    }

    let mut descriptor = descriptor.clone();
    descriptor.host_root = source.path.clone();
    let mut state = SnapshotState {
        encoder: MountSnapshotKeyEncoder::new(),
        entries: vec![WindowsMountSnapshotEntry {
            host_path: source.path.clone(),
            relative_path: String::new(),
            guest_path: descriptor.guest_source.clone(),
            kind: WindowsMountSnapshotEntryKind::Directory {
                mode: MOUNT_IMPORT_DIRECTORY_MODE,
            },
        }],
        file_count: 0,
        directory_count: 1,
        logical_bytes: 0,
    };
    state
        .encoder
        .add_directory("")
        .map_err(|error| encoding_error(&source.path, error))?;
    snapshot_directory(&source.path, "", &descriptor.guest_source, &mut state)?;
    let key = state
        .encoder
        .finish()
        .map_err(|error| encoding_error(&source.path, error))?;

    Ok(WindowsMountSnapshot {
        descriptor,
        entries: state.entries,
        key,
        file_count: state.file_count,
        directory_count: state.directory_count,
        logical_bytes: state.logical_bytes,
    })
}

struct SnapshotState {
    encoder: MountSnapshotKeyEncoder,
    entries: Vec<WindowsMountSnapshotEntry>,
    file_count: u64,
    directory_count: u64,
    logical_bytes: u64,
}

fn snapshot_directory(
    host_directory: &Path,
    relative_directory: &str,
    guest_directory: &str,
    state: &mut SnapshotState,
) -> Result<(), CopyPathError> {
    let _pinned_directory = open_copy_in_directory_checked(host_directory)?;
    let mut children = Vec::new();
    let mut case_fold = CaseFoldSet::default();
    let directory = fs::read_dir(host_directory).map_err(|error| {
        CopyPathError::new(
            CopyPathOperation::CopyInSource,
            host_directory.display().to_string(),
            format!("failed to read directory: {error}"),
        )
    })?;

    for child in directory {
        let child = child.map_err(|error| {
            CopyPathError::new(
                CopyPathOperation::CopyInSource,
                host_directory.display().to_string(),
                format!("failed to read directory entry: {error}"),
            )
        })?;
        let name = child.file_name().into_string().map_err(|_| {
            CopyPathError::new(
                CopyPathOperation::CopyInSource,
                host_directory.display().to_string(),
                "directory entry name is not valid UTF-8",
            )
        })?;
        validate_copy_in_component(&name, host_directory, guest_directory)?;
        case_fold.insert(
            &name,
            CopyPathOperation::CopyInSource,
            &host_directory.display().to_string(),
        )?;
        children.push((name, child.path()));
    }
    children.sort_by(|left, right| left.0.cmp(&right.0));

    for (name, host_path) in children {
        let relative_path = if relative_directory.is_empty() {
            name.clone()
        } else {
            format!("{relative_directory}/{name}")
        };
        let guest_path = join_guest_child(guest_directory, &name);
        match inspect_copy_in_path_kind(&host_path)? {
            CopyInSourceRootKind::Directory => {
                state
                    .encoder
                    .add_directory(&relative_path)
                    .map_err(|error| encoding_error(&host_path, error))?;
                state.entries.push(WindowsMountSnapshotEntry {
                    host_path: host_path.clone(),
                    relative_path: relative_path.clone(),
                    guest_path: guest_path.clone(),
                    kind: WindowsMountSnapshotEntryKind::Directory {
                        mode: MOUNT_IMPORT_DIRECTORY_MODE,
                    },
                });
                state.directory_count = state.directory_count.saturating_add(1);
                snapshot_directory(&host_path, &relative_path, &guest_path, state)?;
            }
            CopyInSourceRootKind::File => {
                snapshot_file(&host_path, relative_path, guest_path, state)?;
            }
        }
    }
    Ok(())
}

fn snapshot_file(
    host_path: &Path,
    relative_path: String,
    guest_path: String,
    state: &mut SnapshotState,
) -> Result<(), CopyPathError> {
    let mut checked = open_copy_in_file_for_snapshot(host_path, None, None)?;
    let len = checked.len();
    let identity = checked.identity();
    state
        .encoder
        .begin_file(&relative_path, len)
        .map_err(|error| encoding_error(host_path, error))?;
    let mut digest = blake3::Hasher::new();
    let mut buffer = vec![0u8; SNAPSHOT_READ_BUFFER_SIZE];
    let mut bytes_read = 0u64;
    loop {
        let count = checked.file_mut().read(&mut buffer).map_err(|error| {
            CopyPathError::new(
                CopyPathOperation::CopyInSource,
                host_path.display().to_string(),
                format!("failed to read source while hashing snapshot: {error}"),
            )
        })?;
        if count == 0 {
            break;
        }
        bytes_read = bytes_read.saturating_add(count as u64);
        state
            .encoder
            .write_file_bytes(&buffer[..count])
            .map_err(|error| encoding_error(host_path, error))?;
        digest.update(&buffer[..count]);
    }
    state
        .encoder
        .finish_file()
        .map_err(|error| encoding_error(host_path, error))?;
    if bytes_read != len {
        return Err(CopyPathError::new(
            CopyPathOperation::CopyInSource,
            host_path.display().to_string(),
            format!(
                "source length changed while hashing snapshot: expected {len} bytes, read {bytes_read}"
            ),
        ));
    }
    checked.validate_unchanged(host_path)?;

    state.entries.push(WindowsMountSnapshotEntry {
        host_path: host_path.to_path_buf(),
        relative_path,
        guest_path,
        kind: WindowsMountSnapshotEntryKind::File {
            len,
            identity,
            digest: *digest.finalize().as_bytes(),
            mode: MOUNT_IMPORT_FILE_MODE,
        },
    });
    state.file_count = state.file_count.saturating_add(1);
    state.logical_bytes = state.logical_bytes.saturating_add(len);
    Ok(())
}

fn encoding_error(path: &Path, error: lsb_proto::MountSnapshotEncodingError) -> CopyPathError {
    CopyPathError::new(
        CopyPathOperation::CopyInSource,
        path.display().to_string(),
        format!("failed to encode deterministic mount snapshot: {error}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn snapshot_key_is_independent_of_host_root_and_guest_target() {
        let first_root = fixture("first");
        let second_root = fixture("second");
        let first = snapshot_windows_mount(&descriptor(&first_root, "/one")).unwrap();
        let second = snapshot_windows_mount(&descriptor(&second_root, "/two")).unwrap();

        assert_eq!(first.key, second.key);
        assert_eq!(first.file_count, 2);
        assert_eq!(first.directory_count, 3);
        assert_eq!(first.logical_bytes, 10);
        assert!(matches!(
            first.entries.first().map(|entry| &entry.kind),
            Some(WindowsMountSnapshotEntryKind::Directory { mode })
                if *mode == MOUNT_IMPORT_DIRECTORY_MODE
        ));

        let _ = fs::remove_dir_all(first_root.parent().unwrap());
        let _ = fs::remove_dir_all(second_root.parent().unwrap());
    }

    #[test]
    fn snapshot_key_detects_same_length_content_changes() {
        let root = fixture("mutation");
        let before = snapshot_windows_mount(&descriptor(&root, "/workspace")).unwrap();
        fs::write(root.join("hello.txt"), b"HELLO").unwrap();
        let after = snapshot_windows_mount(&descriptor(&root, "/workspace")).unwrap();

        assert_ne!(before.key, after.key);
        let _ = fs::remove_dir_all(root.parent().unwrap());
    }

    #[test]
    fn snapshot_preserves_empty_and_non_ascii_directories_in_parent_first_order() {
        let root = temp_dir("unicode").join("src");
        fs::create_dir_all(root.join("caf\u{00e9}/empty")).unwrap();
        fs::write(root.join("caf\u{00e9}/\u{6d4b}\u{8bd5}.txt"), b"data").unwrap();
        let snapshot = snapshot_windows_mount(&descriptor(&root, "/workspace")).unwrap();
        let paths = snapshot
            .entries
            .iter()
            .map(|entry| entry.relative_path.as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            paths,
            [
                "",
                "caf\u{00e9}",
                "caf\u{00e9}/empty",
                "caf\u{00e9}/\u{6d4b}\u{8bd5}.txt"
            ]
        );
        let _ = fs::remove_dir_all(root.parent().unwrap());
    }

    fn descriptor(root: &Path, target: &str) -> WindowsMountDescriptor {
        WindowsMountDescriptor {
            tag: "mount0".to_string(),
            host_root: root.to_path_buf(),
            guest_source: "/tmp/lsb/mounts/mount0/source".to_string(),
            guest_target: target.to_string(),
        }
    }

    fn fixture(label: &str) -> PathBuf {
        let root = temp_dir(label).join("src");
        fs::create_dir_all(root.join("nested/empty")).unwrap();
        write(&root.join("hello.txt"), b"hello");
        write(&root.join("nested/world.txt"), b"world");
        root
    }

    fn write(path: &Path, bytes: &[u8]) {
        let mut file = fs::File::create(path).unwrap();
        file.write_all(bytes).unwrap();
    }

    fn temp_dir(label: &str) -> PathBuf {
        let nonce = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "lsb-windows-mount-snapshot-{label}-{}-{nonce}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        root
    }
}
