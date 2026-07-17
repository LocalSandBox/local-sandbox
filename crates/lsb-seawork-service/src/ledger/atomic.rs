use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};

use super::schema::LedgerDocument;

pub fn write(path: &Path, document: &LedgerDocument) -> Result<()> {
    document.validate()?;
    write_value(path, document)
}

pub fn write_value(path: &Path, document: &impl serde::Serialize) -> Result<()> {
    let parent = path.parent().context("ledger path has no parent")?;
    std::fs::create_dir_all(parent)?;
    let id = path
        .file_stem()
        .and_then(|value| value.to_str())
        .context("ledger filename is not UTF-8")?;
    let temporary = parent.join(format!(".{id}.tmp"));
    let bytes = serde_json::to_vec_pretty(document)?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    replace(&temporary, path)
        .with_context(|| format!("atomically replace ledger {}", path.display()))
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
        assert!(!path
            .parent()
            .unwrap()
            .join(".0123456789abcdef0123456789abcdef.tmp")
            .exists());
        let _ = std::fs::remove_dir_all(root);
    }
}
