mod assets;
mod checkpoint;
mod cli;
mod config;
mod vm;

use std::process;

use anyhow::Result;
use clap::Parser;

use shuru_vm::{default_data_dir, Sandbox, VmState};

use cli::{CheckpointCommands, Cli, Commands};
use config::load_config;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            vm,
            from,
            console,
            command,
        } => {
            let cfg = load_config(vm.config.as_deref())?;

            // Command resolution: CLI args > config > default /bin/sh
            let command = if !command.is_empty() {
                command
            } else if let Some(cfg_cmd) = cfg.command.clone() {
                cfg_cmd
            } else {
                vec!["/bin/sh".to_string()]
            };

            let prepared = vm::prepare_vm(&vm, &cfg, from.as_deref())?;

            let exit_code = if console {
                run_console(&prepared)?
            } else {
                vm::run_command(&prepared, &command)?
            };

            let _ = std::fs::remove_dir_all(&prepared.instance_dir);
            process::exit(exit_code);
        }
        Commands::Init { force } => {
            let data_dir = default_data_dir();
            if force {
                let _ = std::fs::remove_file(format!("{}/VERSION", data_dir));
            }
            if assets::assets_ready(&data_dir) {
                eprintln!(
                    "shuru: OS image already up to date ({})",
                    assets::CURRENT_VERSION
                );
            } else {
                assets::download_os_image(&data_dir)?;
            }
        }
        Commands::Upgrade => {
            let data_dir = default_data_dir();
            assets::upgrade(&data_dir)?;
        }
        Commands::Prune => {
            let data_dir = default_data_dir();
            let instances_dir = format!("{}/instances", data_dir);
            let entries = match std::fs::read_dir(&instances_dir) {
                Ok(entries) => entries,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    eprintln!("shuru: no orphaned instances found");
                    return Ok(());
                }
                Err(e) => return Err(e.into()),
            };

            let mut removed = 0u32;
            for entry in entries {
                let entry = entry?;
                let name = entry.file_name();
                let Some(pid) = name.to_str().and_then(|s| s.parse::<i32>().ok()) else {
                    continue;
                };
                // Check if the process is still running
                let alive = unsafe { libc::kill(pid, 0) } == 0;
                if !alive {
                    std::fs::remove_dir_all(entry.path())?;
                    removed += 1;
                }
            }

            if removed == 0 {
                eprintln!("shuru: no orphaned instances found");
            } else {
                eprintln!("shuru: removed {} orphaned instance(s)", removed);
            }
        }
        Commands::Checkpoint { action } => match action {
            CheckpointCommands::Create {
                name,
                vm,
                from,
                command,
            } => {
                let exit_code = checkpoint::create(name, &vm, from.as_deref(), command)?;
                process::exit(exit_code);
            }
            CheckpointCommands::List => checkpoint::list()?,
            CheckpointCommands::Delete { name } => checkpoint::delete(&name)?,
            CheckpointCommands::Push { name: _ } => {
                anyhow::bail!("checkpoint push is not yet implemented")
            }
            CheckpointCommands::Pull { name: _ } => {
                anyhow::bail!("checkpoint pull is not yet implemented")
            }
        },
    }

    Ok(())
}

/// Run the VM in raw serial console mode (for debugging).
fn run_console(prepared: &vm::PreparedVm) -> Result<i32> {
    eprintln!("shuru: kernel={}", prepared.kernel_path);
    eprintln!("shuru: rootfs={} (work copy)", prepared.work_rootfs);
    eprintln!(
        "shuru: booting VM ({}cpus, {}MB RAM, {}MB disk)...",
        prepared.cpus, prepared.memory, prepared.disk_size
    );

    let mut builder = Sandbox::builder()
        .kernel(&prepared.kernel_path)
        .rootfs(&prepared.work_rootfs)
        .cpus(prepared.cpus)
        .memory_mb(prepared.memory)
        .allow_net(prepared.allow_net);

    if let Some(initrd) = &prepared.initrd_path {
        eprintln!("shuru: using initramfs: {}", initrd);
        builder = builder.initrd(initrd);
    }

    for m in &prepared.mounts {
        eprintln!("shuru: mount {} -> {}", m.host_path, m.guest_path);
        builder = builder.mount(m.clone());
    }

    let sandbox = builder.build()?;
    eprintln!("shuru: VM created and validated successfully");

    let state_rx = sandbox.state_channel();

    eprintln!("shuru: starting VM...");
    sandbox.start()?;
    eprintln!("shuru: VM started");

    eprintln!("shuru: running in console mode (Ctrl+C to stop)");
    let mut exit_code = 0;
    loop {
        match state_rx.recv() {
            Ok(VmState::Stopped) => {
                eprintln!("shuru: VM stopped");
                break;
            }
            Ok(VmState::Error) => {
                eprintln!("shuru: VM encountered an error");
                exit_code = 1;
                break;
            }
            Ok(_) => continue,
            Err(_) => break,
        }
    }

    Ok(exit_code)
}
