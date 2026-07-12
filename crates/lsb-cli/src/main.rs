mod assets;
mod checkpoint;
mod cli;
mod config;
mod doctor;
mod stdio;
mod vm;

use std::process;

use anyhow::Result;
use clap::Parser;

use lsb_vm::{default_data_dir, VmState};

use cli::{CheckpointCommands, Cli, Commands, DoctorCommands};
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
            stdio,
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

            let result = if stdio {
                stdio::run_stdio(&prepared)
            } else if console {
                run_console(&prepared)
            } else {
                vm::run_command(&prepared, &command).map(|result| result.exit_code)
            };

            let _ = std::fs::remove_dir_all(&prepared.instance_dir);
            process::exit(result?);
        }
        Commands::Init {
            version,
            force,
            fix,
            host_tools_only,
        } => {
            let data_dir = default_data_dir();
            let version = version.as_deref().unwrap_or(assets::CURRENT_VERSION);
            assets::init_version(&data_dir, version, force, fix, host_tools_only)?;
        }
        Commands::Upgrade => {
            let data_dir = default_data_dir();
            assets::upgrade(&data_dir)?;
        }
        Commands::Prune { mount_cache } => {
            let data_dir = default_data_dir();
            if mount_cache {
                #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
                {
                    let cache =
                        lsb_platform::windows_x86_64::fs::WindowsMountCache::new(&data_dir)?;
                    let report = cache.prune_all()?;
                    eprintln!(
                        "lsb: removed {} mount-cache object(s) and {} staging item(s); skipped {} active key(s)",
                        report.removed_objects,
                        report.removed_staging_directories,
                        report.skipped_locked
                    );
                    return Ok(());
                }
                #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
                {
                    anyhow::bail!(
                        "persistent mount-cache pruning is only available on Windows x86_64"
                    );
                }
            }
            let instances_dir = format!("{}/instances", data_dir);
            let entries = match std::fs::read_dir(&instances_dir) {
                Ok(entries) => entries,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    eprintln!("lsb: no orphaned instances found");
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
                let alive = process_alive(pid)?;
                if !alive {
                    std::fs::remove_dir_all(entry.path())?;
                    removed += 1;
                }
            }

            if removed == 0 {
                eprintln!("lsb: no orphaned instances found");
            } else {
                eprintln!("lsb: removed {} orphaned instance(s)", removed);
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
        Commands::Doctor { action } => match action {
            DoctorCommands::WindowsSmbPolicy { fix, yes } => doctor::windows_smb_policy(fix, yes)?,
        },
    }

    Ok(())
}

#[cfg(unix)]
fn process_alive(pid: i32) -> Result<bool> {
    Ok(unsafe { libc::kill(pid, 0) } == 0)
}

#[cfg(not(unix))]
fn process_alive(_pid: i32) -> Result<bool> {
    anyhow::bail!(
        "orphaned instance pruning is not available on this host; remove stale instance metadata manually"
    )
}

/// Run the VM in raw serial console mode (for debugging).
fn run_console(prepared: &vm::PreparedVm) -> Result<i32> {
    eprintln!("lsb: kernel={}", prepared.kernel_path);
    eprintln!("lsb: rootfs={} (work copy)", prepared.work_rootfs);
    eprintln!(
        "lsb: booting VM ({}cpus, {}MB RAM, {}MB disk)...",
        prepared.cpus, prepared.memory, prepared.disk_size
    );

    let (network_attachment, _proxy_handle) =
        vm::start_optional_proxy_network(prepared.proxy_config.as_ref())?;

    let nbd_handle = vm::start_nbd(prepared)?;
    let nbd_uri = nbd_handle.as_ref().map(|handle| handle.uri());
    let sandbox = vm::build_sandbox(prepared, true, network_attachment, nbd_uri.as_deref())?;
    eprintln!("lsb: VM created and validated successfully");

    let state_rx = sandbox.state_channel();

    eprintln!("lsb: starting VM...");
    sandbox.start()?;
    eprintln!("lsb: VM started");

    eprintln!("lsb: running in console mode (Ctrl+C to stop)");
    let mut exit_code = 0;
    loop {
        match state_rx.recv() {
            Ok(VmState::Stopped) => {
                eprintln!("lsb: VM stopped");
                break;
            }
            Ok(VmState::Error) => {
                eprintln!("lsb: VM encountered an error");
                exit_code = 1;
                break;
            }
            Ok(_) => continue,
            Err(_) => break,
        }
    }

    Ok(exit_code)
}
