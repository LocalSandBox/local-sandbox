use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};

use super::schema::LedgerDocument;

static WRITE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub fn write(path: &Path, document: &LedgerDocument) -> Result<()> {
    document.validate()?;
    write_value(path, document)
}

pub fn write_value(path: &Path, document: &impl serde::Serialize) -> Result<()> {
    let _write_guard = WRITE_LOCK
        .lock()
        .map_err(|_| anyhow::anyhow!("protected state writer lock poisoned"))?;
    let parent = path.parent().context("ledger path has no parent")?;
    std::fs::create_dir_all(parent)?;
    let id = path
        .file_stem()
        .and_then(|value| value.to_str())
        .context("ledger filename is not UTF-8")?;
    let bytes = serde_json::to_vec_pretty(document)?;
    let (temporary, mut file) = create_temporary(parent, id)?;
    let result = (|| {
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        replace(&temporary, path)
            .with_context(|| format!("atomically replace ledger {}", path.display()))?;
        sync_parent(parent)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn create_temporary(parent: &Path, id: &str) -> Result<(std::path::PathBuf, std::fs::File)> {
    for _ in 0..16 {
        let mut random = [0u8; 8];
        getrandom::fill(&mut random)
            .map_err(|error| anyhow::anyhow!("generate ledger temporary id: {error}"))?;
        let suffix = random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let temporary = parent.join(format!(".{id}-{suffix}.tmp"));
        match std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
        {
            Ok(file) => return Ok((temporary, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    anyhow::bail!("could not allocate a unique ledger temporary file")
}

#[cfg(windows)]
fn replace(temporary: &Path, destination: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, ReplaceFileW, MOVEFILE_WRITE_THROUGH, REPLACEFILE_WRITE_THROUGH,
    };

    let wide = |path: &Path| {
        path.as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>()
    };
    let source = wide(temporary);
    let target = wide(destination);
    let ok = if destination.exists() {
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
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(windows)]
fn sync_parent(_parent: &Path) -> Result<()> {
    Ok(())
}

#[cfg(not(windows))]
fn sync_parent(parent: &Path) -> Result<()> {
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(not(windows))]
fn replace(temporary: &Path, destination: &Path) -> Result<()> {
    std::fs::rename(temporary, destination)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomically_creates_and_replaces_document() {
        let root = std::env::temp_dir().join(format!("lsbsw-atomic-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let path = root
            .join("ledger")
            .join("0123456789abcdef0123456789abcdef.json");
        let mut document = crate::ledger::schema::sample();
        write(&path, &document).unwrap();
        document.updated_unix_ms = 2;
        write(&path, &document).unwrap();
        let stored: LedgerDocument =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(stored.updated_unix_ms, 2);
        assert_eq!(
            std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
            1
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn concurrent_writers_never_share_or_leave_a_temporary() {
        let root = std::env::temp_dir().join(format!("lsbsw-atomic-race-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let path = root
            .join("ledger")
            .join("0123456789abcdef0123456789abcdef.json");
        let threads = (0..8)
            .map(|value| {
                let path = path.clone();
                std::thread::spawn(move || write_value(&path, &value).unwrap())
            })
            .collect::<Vec<_>>();
        for thread in threads {
            thread.join().unwrap();
        }

        let stored: usize = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert!(stored < 8);
        assert_eq!(
            std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
            1
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn failed_replace_removes_its_unique_temporary() {
        let root = std::env::temp_dir().join(format!("lsbsw-atomic-fail-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let path = root.join("ledger").join("destination.json");
        std::fs::create_dir_all(&path).unwrap();

        assert!(write_value(&path, &1).is_err());
        assert_eq!(
            std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
            1
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
