use anyhow::{bail, Result};

use lsb_vm::default_data_dir;

use crate::cli::VmArgs;
use crate::config::load_config;
use crate::vm::{self, PreparedStorageKind};

pub(crate) fn create(
    name: String,
    vm_args: &VmArgs,
    from: Option<&str>,
    command: Vec<String>,
) -> Result<i32> {
    let cfg = load_config(vm_args.config.as_deref())?;

    let command = if !command.is_empty() {
        command
    } else {
        vec!["/bin/sh".to_string()]
    };

    let data_dir = lsb_vm::default_data_dir();
    let checkpoints_dir = format!("{}/checkpoints", data_dir);
    lsb_vm::validate_checkpoint_name(&name).map_err(|e| anyhow::anyhow!(e))?;
    if checkpoint_exists(&checkpoints_dir, &name) {
        bail!("checkpoint '{}' already exists, delete it first", name);
    }

    let prepared = vm::prepare_vm(vm_args, &cfg, from)?;
    let result = vm::run_command_for_checkpoint(&prepared, &command)?;

    std::fs::create_dir_all(&prepared.checkpoints_dir)?;
    eprintln!("lsb: saving checkpoint '{}'...", name);
    if let Some(ref nbd_handle) = result.nbd_handle {
        let index_path = format!("{}/{}.idx", prepared.checkpoints_dir, name);
        nbd_handle.save_checkpoint(&index_path)?;
    } else if prepared.storage_kind == PreparedStorageKind::WindowsQcow2 {
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        {
            let source = prepared.windows_checkpoint_source.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "Windows checkpoint source metadata missing for active qcow2 disk '{}'",
                    prepared.work_rootfs
                )
            })?;
            let store = lsb_store::WindowsCheckpointStore::new(&prepared.data_dir);
            store.save_flat_checkpoint(
                &name,
                &prepared.work_rootfs,
                source,
                prepared.disk_size * 1024 * 1024,
                false,
            )?;
        }
        #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
        {
            unreachable!("Windows qcow2 storage kind is only produced on Windows x86_64");
        }
    } else {
        let checkpoint_path = format!("{}/{}.ext4", prepared.checkpoints_dir, name);
        vm::clone_file(&prepared.work_rootfs, &checkpoint_path)?;
    }
    eprintln!("lsb: checkpoint '{}' saved", name);

    drop(result.nbd_handle);
    let _ = std::fs::remove_dir_all(&prepared.instance_dir);
    Ok(result.exit_code)
}

pub(crate) fn list() -> Result<()> {
    let data_dir = default_data_dir();
    let checkpoints_dir = format!("{}/checkpoints", data_dir);

    let entries = match std::fs::read_dir(&checkpoints_dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("No checkpoints found.");
            return Ok(());
        }
        Err(e) => bail!("Failed to read checkpoints directory: {}", e),
    };

    let mut checkpoints: Vec<CheckpointListEntry> = Vec::new();
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str());
        let is_cas = ext == Some("idx");
        if !is_cas && ext != Some("ext4") {
            continue;
        }
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("?")
            .to_string();
        let meta = entry.metadata()?;
        let disk_usage = if is_cas {
            lsb_store::ChunkIndex::load(path.to_str().unwrap_or("")).map(|idx| {
                let non_zero = (0..idx.num_chunks())
                    .filter(|&i| idx.get_hash(i).map(|h| h != "ZERO").unwrap_or(false))
                    .count();
                (non_zero as u64) * 64 * 1024
            })?
        } else {
            checkpoint_disk_usage(&meta)
        };
        checkpoints.push(CheckpointListEntry {
            name,
            disk_usage,
            modified: meta.modified()?,
            kind: if is_cas {
                CheckpointKind::Cas
            } else {
                CheckpointKind::Ext4
            },
        });
    }

    let windows_store = lsb_store::WindowsCheckpointStore::new(&data_dir);
    for entry in windows_store.list_checkpoints()? {
        checkpoints.push(CheckpointListEntry {
            name: entry.name,
            disk_usage: entry.disk_bytes,
            modified: entry.modified,
            kind: CheckpointKind::WindowsQcow2,
        });
    }

    if checkpoints.is_empty() {
        eprintln!("No checkpoints found.");
        return Ok(());
    }

    checkpoints.sort_by_key(|entry| entry.modified);

    println!("{:<20} {:>10} {}", "NAME", "SIZE", "CREATED");
    for entry in &checkpoints {
        let size_str = match entry.kind {
            CheckpointKind::Cas => {
                if entry.disk_usage >= 1024 * 1024 {
                    format!("{} MB (cas)", entry.disk_usage / (1024 * 1024))
                } else {
                    format!("{} KB (cas)", entry.disk_usage / 1024)
                }
            }
            CheckpointKind::WindowsQcow2 => {
                if entry.disk_usage >= 1024 * 1024 * 1024 {
                    format!(
                        "{:.1} GB (win)",
                        entry.disk_usage as f64 / (1024.0 * 1024.0 * 1024.0)
                    )
                } else {
                    format!("{} MB (win)", entry.disk_usage / (1024 * 1024))
                }
            }
            CheckpointKind::Ext4 => {
                if entry.disk_usage >= 1024 * 1024 * 1024 {
                    format!(
                        "{:.1} GB",
                        entry.disk_usage as f64 / (1024.0 * 1024.0 * 1024.0)
                    )
                } else {
                    format!("{} MB", entry.disk_usage / (1024 * 1024))
                }
            }
        };
        let elapsed = entry
            .modified
            .elapsed()
            .unwrap_or(std::time::Duration::ZERO)
            .as_secs();
        let age = if elapsed < 60 {
            "just now".to_string()
        } else if elapsed < 3600 {
            format!("{}m ago", elapsed / 60)
        } else if elapsed < 86400 {
            format!("{}h ago", elapsed / 3600)
        } else {
            format!("{}d ago", elapsed / 86400)
        };
        println!("{:<20} {:>10} {}", entry.name, size_str, age);
    }

    Ok(())
}

#[derive(Debug, Clone)]
struct CheckpointListEntry {
    name: String,
    disk_usage: u64,
    modified: std::time::SystemTime,
    kind: CheckpointKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckpointKind {
    Cas,
    Ext4,
    WindowsQcow2,
}

pub(crate) fn delete(name: &str) -> Result<()> {
    let data_dir = default_data_dir();
    lsb_vm::validate_checkpoint_name(name).map_err(|e| anyhow::anyhow!(e))?;

    let windows_store = lsb_store::WindowsCheckpointStore::new(&data_dir);
    if windows_store.delete_checkpoint(name)? {
        eprintln!("lsb: checkpoint '{}' deleted", name);
        return Ok(());
    }

    let idx_path = format!("{}/checkpoints/{}.idx", data_dir, name);
    let ext4_path = format!("{}/checkpoints/{}.ext4", data_dir, name);

    if std::path::Path::new(&idx_path).exists() {
        std::fs::remove_file(&idx_path)?;
    } else if std::path::Path::new(&ext4_path).exists() {
        std::fs::remove_file(&ext4_path)?;
    } else {
        bail!("Checkpoint '{}' not found", name);
    }

    eprintln!("lsb: checkpoint '{}' deleted", name);
    Ok(())
}

fn checkpoint_exists(checkpoints_dir: &str, name: &str) -> bool {
    let store = lsb_store::WindowsCheckpointStore::new(
        std::path::Path::new(checkpoints_dir)
            .parent()
            .unwrap_or_else(|| std::path::Path::new(checkpoints_dir)),
    );
    std::path::Path::new(&format!("{}/{}.idx", checkpoints_dir, name)).exists()
        || std::path::Path::new(&format!("{}/{}.ext4", checkpoints_dir, name)).exists()
        || store.checkpoint_exists(name)
}

#[cfg(unix)]
fn checkpoint_disk_usage(meta: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;

    meta.blocks() * 512
}

#[cfg(not(unix))]
fn checkpoint_disk_usage(meta: &std::fs::Metadata) -> u64 {
    meta.len()
}
