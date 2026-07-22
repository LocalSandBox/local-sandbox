use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::de::DeserializeOwned;

const MAX_STATE_BYTES: u64 = 64 * 1024;
static WRITE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub fn load_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect protected update state {}", path.display()))?;
    reject_reparse(&metadata)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_STATE_BYTES {
        bail!("protected update state is not a bounded regular file");
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    BufReader::new(File::open(path)?)
        .take(MAX_STATE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() {
        bail!("protected update state changed while it was read");
    }
    serde_json::from_slice(&bytes)
        .with_context(|| format!("parse protected update state {}", path.display()))
}

pub fn create_json(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    let _guard = write_guard()?;
    let parent = trusted_parent(path)?;
    let bytes = serialize_bounded(value)?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .with_context(|| format!("reserve new protected update state {}", path.display()))?;
    if let Err(error) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error.into());
    }
    drop(file);
    sync_parent(parent)
}

pub fn write_json_atomic(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    let _guard = write_guard()?;
    let parent = trusted_parent(path)?;
    let bytes = serialize_bounded(value)?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        reject_reparse(&metadata)?;
        if !metadata.is_file() {
            bail!("protected update state destination is not a regular file");
        }
    }
    let stem = path
        .file_name()
        .and_then(|value| value.to_str())
        .context("protected update state filename is not UTF-8")?;
    let (temporary, mut file) = create_temporary(parent, stem)?;
    let result = (|| {
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        replace(&temporary, path)?;
        sync_parent(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

/// Moves a terminal transaction to a unique history path without replacement.
pub fn archive_file(source: &Path, destination: &Path) -> Result<()> {
    let _guard = write_guard()?;
    let source_parent = trusted_parent(source)?;
    let destination_parent = trusted_parent(destination)?;
    if source_parent != destination_parent {
        let source_metadata = fs::symlink_metadata(source_parent)?;
        let destination_metadata = fs::symlink_metadata(destination_parent)?;
        reject_reparse(&source_metadata)?;
        reject_reparse(&destination_metadata)?;
    }
    require_bounded_regular_file(source)?;
    if fs::symlink_metadata(destination).is_ok() {
        bail!("protected update history destination already exists");
    }
    move_without_replace(source, destination)?;
    sync_parent(source_parent)?;
    if source_parent != destination_parent {
        sync_parent(destination_parent)?;
    }
    Ok(())
}

pub fn remove_file_if_exists(path: &Path) -> Result<bool> {
    let _guard = write_guard()?;
    let parent = trusted_parent(path)?;
    match fs::remove_file(path) {
        Ok(()) => {
            sync_parent(parent)?;
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn serialize_bounded(value: &impl serde::Serialize) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec_pretty(value)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_STATE_BYTES {
        bail!("protected update state exceeds the compiled byte limit");
    }
    Ok(bytes)
}

fn write_guard() -> Result<std::sync::MutexGuard<'static, ()>> {
    WRITE_LOCK
        .lock()
        .map_err(|_| anyhow::anyhow!("protected update state writer lock poisoned"))
}

fn trusted_parent(path: &Path) -> Result<&Path> {
    if !path.is_absolute() {
        bail!("protected update state path must be absolute");
    }
    let parent = path
        .parent()
        .context("protected update state has no parent")?;
    let metadata = fs::symlink_metadata(parent)
        .with_context(|| format!("inspect protected update state parent {}", parent.display()))?;
    reject_reparse(&metadata)?;
    if !metadata.is_dir() {
        bail!("protected update state parent is not a directory");
    }
    Ok(parent)
}

fn require_bounded_regular_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    reject_reparse(&metadata)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_STATE_BYTES {
        bail!("protected update state is not a bounded regular file");
    }
    Ok(())
}

fn create_temporary(parent: &Path, stem: &str) -> Result<(PathBuf, File)> {
    for _ in 0..16 {
        let mut random = [0u8; 8];
        getrandom::fill(&mut random)
            .map_err(|error| anyhow::anyhow!("generate update-state temporary id: {error}"))?;
        let suffix = random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let temporary = parent.join(format!(".{stem}-{suffix}.tmp"));
        match OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
        {
            Ok(file) => return Ok((temporary, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    bail!("could not allocate a unique update-state temporary file")
}

fn reject_reparse(metadata: &fs::Metadata) -> Result<()> {
    if metadata.file_type().is_symlink() || has_reparse_attribute(metadata) {
        bail!("protected update state crosses a reparse point");
    }
    Ok(())
}

#[cfg(windows)]
fn has_reparse_attribute(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn has_reparse_attribute(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(windows)]
fn replace(temporary: &Path, destination: &Path) -> Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, ReplaceFileW, MOVEFILE_WRITE_THROUGH, REPLACEFILE_WRITE_THROUGH,
    };
    let source = wide(temporary);
    let target = wide(destination);
    let ok = if fs::symlink_metadata(destination).is_ok() {
        unsafe {
            ReplaceFileW(
                target.as_ptr(),
                source.as_ptr(),
                std::ptr::null(),
                REPLACEFILE_WRITE_THROUGH,
                std::ptr::null(),
                std::ptr::null(),
            )
        }
    } else {
        unsafe { MoveFileExW(source.as_ptr(), target.as_ptr(), MOVEFILE_WRITE_THROUGH) }
    };
    if ok == 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(not(windows))]
fn replace(temporary: &Path, destination: &Path) -> Result<()> {
    fs::rename(temporary, destination)?;
    Ok(())
}

#[cfg(windows)]
fn move_without_replace(source: &Path, destination: &Path) -> Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_WRITE_THROUGH};
    let ok = unsafe {
        MoveFileExW(
            wide(source).as_ptr(),
            wide(destination).as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(not(windows))]
fn move_without_replace(source: &Path, destination: &Path) -> Result<()> {
    fs::hard_link(source, destination)?;
    if let Err(error) = fs::remove_file(source) {
        let _ = fs::remove_file(destination);
        return Err(error.into());
    }
    Ok(())
}

#[cfg(windows)]
fn wide(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

#[cfg(windows)]
fn sync_parent(_parent: &Path) -> Result<()> {
    Ok(())
}

#[cfg(not(windows))]
fn sync_parent(parent: &Path) -> Result<()> {
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_ID: AtomicU64 = AtomicU64::new(1);

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Record {
        value: u64,
    }

    #[test]
    fn create_replace_load_and_remove_are_bounded_and_durable() {
        let root = test_root();
        fs::create_dir_all(&root).unwrap();
        let path = root.join("current.json");
        create_json(&path, &Record { value: 1 }).unwrap();
        assert!(create_json(&path, &Record { value: 2 }).is_err());
        write_json_atomic(&path, &Record { value: 2 }).unwrap();
        assert_eq!(load_json::<Record>(&path).unwrap(), Record { value: 2 });
        assert!(remove_file_if_exists(&path).unwrap());
        assert!(!remove_file_if_exists(&path).unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn terminal_state_moves_once_without_history_replacement() {
        let root = test_root();
        let transactions = root.join("transactions");
        let history = root.join("history");
        fs::create_dir_all(&transactions).unwrap();
        fs::create_dir_all(&history).unwrap();
        let current = transactions.join("current.json");
        let archived = history.join("1.json");
        create_json(&current, &Record { value: 1 }).unwrap();
        archive_file(&current, &archived).unwrap();
        assert!(!current.exists());
        assert_eq!(load_json::<Record>(&archived).unwrap(), Record { value: 1 });
        create_json(&current, &Record { value: 2 }).unwrap();
        assert!(archive_file(&current, &archived).is_err());
        assert_eq!(load_json::<Record>(&archived).unwrap(), Record { value: 1 });
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_symlink_state_and_oversized_documents() {
        let root = test_root();
        fs::create_dir_all(&root).unwrap();
        let oversized = root.join("oversized.json");
        fs::write(&oversized, vec![b'x'; MAX_STATE_BYTES as usize + 1]).unwrap();
        assert!(load_json::<Record>(&oversized).is_err());
        assert!(write_json_atomic(
            &root.join("large.json"),
            &vec![0u8; MAX_STATE_BYTES as usize]
        )
        .is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let target = root.join("target.json");
            fs::write(&target, b"{\"value\":1}").unwrap();
            let link = root.join("link.json");
            symlink(&target, &link).unwrap();
            assert!(load_json::<Record>(&link).is_err());
            assert!(write_json_atomic(&link, &Record { value: 2 }).is_err());
        }
        fs::remove_dir_all(root).unwrap();
    }

    fn test_root() -> PathBuf {
        let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("lsb-update-state-{}-{id}", std::process::id()))
    }
}
