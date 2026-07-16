use std::path::Path;

use anyhow::{bail, Result};

#[derive(Debug, Clone, Copy)]
pub struct ExportOptions {
    pub overwrite: bool,
    pub max_bytes: u64,
}

pub(super) fn export_open_file_under_client_token(
    protected_source: &mut std::fs::File,
    source_len: u64,
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
    let copied = std::io::copy(protected_source, &mut output)?;
    output.sync_all()?;
    drop(output);
    if user_destination.exists() {
        if !options.overwrite {
            let _ = std::fs::remove_file(&temporary);
            bail!("export destination already exists");
        }
        std::fs::remove_file(user_destination)?;
    }
    std::fs::rename(&temporary, user_destination)?;
    Ok(copied)
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
