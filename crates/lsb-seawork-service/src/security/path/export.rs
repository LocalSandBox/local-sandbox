use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::time::SystemTime;

use anyhow::{bail, Context, Result};
use windows_sys::Win32::Storage::FileSystem::{
    MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
};

#[derive(Debug, Clone, Copy)]
pub struct ExportOptions {
    pub overwrite: bool,
    pub max_bytes: u64,
}

pub(super) fn export_open_file_under_client_token(
    protected_source: &mut std::fs::File,
    source_len: u64,
    source_modified: SystemTime,
    user_destination: &Path,
    options: ExportOptions,
) -> Result<u64> {
    if source_len > options.max_bytes {
        bail!("export source is not a bounded regular file");
    }
    let parent = user_destination
        .parent()
        .ok_or_else(|| anyhow::anyhow!("export destination has no parent"))?;
    std::fs::create_dir_all(parent)?;
    let (temporary, mut output) = create_temporary(parent)?;
    let result = (|| {
        let limit = source_len
            .checked_add(1)
            .context("export source length bound overflow")?;
        let copied = std::io::copy(
            &mut std::io::Read::take(&mut *protected_source, limit),
            &mut output,
        )?;
        let final_metadata = protected_source.metadata()?;
        if copied != source_len
            || final_metadata.len() != source_len
            || final_metadata.modified()? != source_modified
        {
            bail!("protected export source changed while it was copied");
        }
        output.sync_all()?;
        drop(output);
        if options.overwrite {
            replace_file(&temporary, user_destination)?;
        } else {
            std::fs::rename(&temporary, user_destination)?;
        }
        Ok(copied)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn replace_file(source: &Path, destination: &Path) -> Result<()> {
    let source = source
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn create_temporary(parent: &Path) -> Result<(std::path::PathBuf, std::fs::File)> {
    for _ in 0..8 {
        let mut random = [0u8; 8];
        getrandom::fill(&mut random)
            .map_err(|error| anyhow::anyhow!("OS random source failed: {error}"))?;
        let suffix = random
            .iter()
            .map(|value| format!("{value:02x}"))
            .collect::<String>();
        let path = parent.join(format!(".lsbsw-export-{suffix}.tmp"));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    bail!("could not reserve a unique export temporary file")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_export_replaces_atomically_and_cleans_failed_temporary() {
        let root = std::env::temp_dir().join(format!("lsbsw-export-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let source_path = root.join("source");
        let destination = root.join("destination");
        std::fs::write(&source_path, b"new-value").unwrap();
        std::fs::write(&destination, b"old-value").unwrap();
        let mut source = std::fs::File::open(&source_path).unwrap();
        let metadata = source.metadata().unwrap();

        assert_eq!(
            export_open_file_under_client_token(
                &mut source,
                metadata.len(),
                metadata.modified().unwrap(),
                &destination,
                ExportOptions {
                    overwrite: true,
                    max_bytes: 1024,
                },
            )
            .unwrap(),
            9
        );
        assert_eq!(std::fs::read(&destination).unwrap(), b"new-value");

        let mut source = std::fs::File::open(&source_path).unwrap();
        let metadata = source.metadata().unwrap();
        assert!(export_open_file_under_client_token(
            &mut source,
            metadata.len() - 1,
            metadata.modified().unwrap(),
            &root.join("should-not-exist"),
            ExportOptions {
                overwrite: false,
                max_bytes: 1024,
            },
        )
        .is_err());
        assert!(!root.join("should-not-exist").exists());
        assert!(std::fs::read_dir(&root).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".lsbsw-export-")));
        let _ = std::fs::remove_dir_all(root);
    }
}
