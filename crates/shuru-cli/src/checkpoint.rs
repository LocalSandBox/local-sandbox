use std::os::unix::fs::MetadataExt;

use anyhow::{bail, Result};

use shuru_vm::default_data_dir;

use crate::cli::VmArgs;
use crate::config::load_config;
use crate::vm;

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

    let prepared = vm::prepare_vm(vm_args, &cfg, from)?;
    let exit_code = vm::run_command(&prepared, &command)?;

    // Save working copy as checkpoint
    let checkpoints_dir = format!("{}/checkpoints", prepared.data_dir);
    std::fs::create_dir_all(&checkpoints_dir)?;
    let checkpoint_path = format!("{}/{}.ext4", checkpoints_dir, name);
    eprintln!("shuru: saving checkpoint '{}'...", name);
    vm::clone_file(&prepared.work_rootfs, &checkpoint_path)?;
    eprintln!("shuru: checkpoint '{}' saved", name);

    let _ = std::fs::remove_dir_all(&prepared.instance_dir);
    Ok(exit_code)
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

    let mut checkpoints: Vec<(String, u64, std::time::SystemTime)> = Vec::new();
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("ext4") {
            let name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("?")
                .to_string();
            let meta = entry.metadata()?;
            let disk_usage = meta.blocks() * 512;
            checkpoints.push((name, disk_usage, meta.modified()?));
        }
    }

    if checkpoints.is_empty() {
        eprintln!("No checkpoints found.");
        return Ok(());
    }

    checkpoints.sort_by_key(|(_, _, t)| *t);

    println!("{:<20} {:>10} {}", "NAME", "SIZE", "CREATED");
    for (name, size, mtime) in &checkpoints {
        let size_str = if *size >= 1024 * 1024 * 1024 {
            format!("{:.1} GB", *size as f64 / (1024.0 * 1024.0 * 1024.0))
        } else {
            format!("{} MB", size / (1024 * 1024))
        };
        let elapsed = mtime
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
        println!("{:<20} {:>10} {}", name, size_str, age);
    }

    Ok(())
}

pub(crate) fn delete(name: &str) -> Result<()> {
    let data_dir = default_data_dir();
    let checkpoint_path = format!("{}/checkpoints/{}.ext4", data_dir, name);
    if !std::path::Path::new(&checkpoint_path).exists() {
        bail!("Checkpoint '{}' not found", name);
    }
    std::fs::remove_file(&checkpoint_path)?;
    eprintln!("shuru: checkpoint '{}' deleted", name);
    Ok(())
}
