use std::path::Path;

use anyhow::{bail, Result};

#[derive(Debug, Clone, Copy)]
pub struct ExportOptions {
    pub overwrite: bool,
    pub max_bytes: u64,
}

pub fn export_file_under_client_token(
    protected_source: &Path,
    user_destination: &Path,
    options: ExportOptions,
) -> Result<u64> {
    let metadata = std::fs::metadata(protected_source)?;
    if !metadata.is_file() || metadata.len() > options.max_bytes {
        bail!("export source is not a bounded regular file");
    }
    let parent = user_destination
        .parent()
        .ok_or_else(|| anyhow::anyhow!("export destination has no parent"))?;
    std::fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".lsbsw-export-{}.tmp", std::process::id()));
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    let copied = std::io::copy(&mut std::fs::File::open(protected_source)?, &mut output)?;
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
