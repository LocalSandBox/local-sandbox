use std::collections::HashMap;
use std::ffi::CString;
use std::io::IsTerminal;

use anyhow::{bail, Context, Result};

extern "C" {
    fn clonefile(
        src: *const libc::c_char,
        dst: *const libc::c_char,
        flags: u32,
    ) -> libc::c_int;
}

pub(crate) fn clone_file(src: &str, dst: &str) -> Result<()> {
    let c_src = CString::new(src).context("invalid source path")?;
    let c_dst = CString::new(dst).context("invalid destination path")?;
    let ret = unsafe { clonefile(c_src.as_ptr(), c_dst.as_ptr(), 0) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        bail!("clonefile({} -> {}) failed: {}", src, dst, err);
    }
    Ok(())
}

use shuru_vm::{MountConfig, PortMapping, Sandbox};

use crate::assets;
use crate::cli::VmArgs;
use crate::config::ShuruConfig;

pub(crate) struct PreparedVm {
    pub data_dir: String,
    pub instance_dir: String,
    pub work_rootfs: String,
    pub kernel_path: String,
    pub initrd_path: Option<String>,
    pub cpus: usize,
    pub memory: u64,
    pub disk_size: u64,
    pub allow_net: bool,
    pub forwards: Vec<PortMapping>,
    pub mounts: Vec<MountConfig>,
}

pub(crate) fn prepare_vm(
    vm: &VmArgs,
    cfg: &ShuruConfig,
    from: Option<&str>,
) -> Result<PreparedVm> {
    let cpus = vm.cpus.or(cfg.cpus).unwrap_or(2);
    let memory = vm.memory.or(cfg.memory).unwrap_or(2048);
    let disk_size = vm.disk_size.or(cfg.disk_size).unwrap_or(4096);
    let allow_net = vm.allow_net || cfg.allow_net.unwrap_or(false);

    // Merge port forwards: CLI flags + config file
    let mut port_strs: Vec<&str> = vm.port.iter().map(|s| s.as_str()).collect();
    if let Some(ref cfg_ports) = cfg.ports {
        for p in cfg_ports {
            port_strs.push(p.as_str());
        }
    }
    let mut forwards = Vec::new();
    for s in &port_strs {
        let mapping = parse_port_mapping(s)
            .with_context(|| format!("invalid port mapping: '{}'", s))?;
        forwards.push(mapping);
    }

    // Merge mounts: CLI flags + config file
    let mut mount_strs: Vec<&str> = vm.mount.iter().map(|s| s.as_str()).collect();
    if let Some(ref cfg_mounts) = cfg.mounts {
        for m in cfg_mounts {
            mount_strs.push(m.as_str());
        }
    }
    let mut mounts = Vec::new();
    for s in &mount_strs {
        let mc = parse_mount_spec(s)
            .with_context(|| format!("invalid mount spec: '{}'", s))?;
        mounts.push(mc);
    }

    let data_dir = shuru_vm::default_data_dir();

    // Auto-download assets when using default paths
    if vm.kernel.is_none()
        && vm.rootfs.is_none()
        && vm.initrd.is_none()
        && !assets::assets_ready(&data_dir)
    {
        assets::download_os_image(&data_dir)?;
    }

    let kernel_path = vm
        .kernel
        .clone()
        .unwrap_or_else(|| format!("{}/Image", data_dir));
    let rootfs_path = vm
        .rootfs
        .clone()
        .unwrap_or_else(|| format!("{}/rootfs.ext4", data_dir));
    let initrd_path_str = vm
        .initrd
        .clone()
        .unwrap_or_else(|| format!("{}/initramfs.cpio.gz", data_dir));

    if !std::path::Path::new(&kernel_path).exists() {
        bail!(
            "Kernel not found at {}. Run `shuru init` to download.",
            kernel_path
        );
    }

    // Determine source for working copy: checkpoint or base rootfs
    let checkpoints_dir = format!("{}/checkpoints", data_dir);
    let source = match from {
        Some(name) => {
            let path = format!("{}/{}.ext4", checkpoints_dir, name);
            if !std::path::Path::new(&path).exists() {
                bail!("Checkpoint '{}' not found", name);
            }
            path
        }
        None => {
            if !std::path::Path::new(&rootfs_path).exists() {
                bail!(
                    "Rootfs not found at {}. Run `shuru init` to download.",
                    rootfs_path
                );
            }
            rootfs_path
        }
    };

    // Create per-instance working copy
    let instance_dir = format!("{}/instances/{}", data_dir, std::process::id());
    std::fs::create_dir_all(&instance_dir)?;
    let work_rootfs = format!("{}/rootfs.ext4", instance_dir);
    eprintln!("shuru: creating working copy...");
    clone_file(&source, &work_rootfs)?;

    // Extend to requested disk size
    let f = std::fs::OpenOptions::new()
        .write(true)
        .open(&work_rootfs)?;
    f.set_len(disk_size * 1024 * 1024)?;
    drop(f);

    let initrd_path = if std::path::Path::new(&initrd_path_str).exists() {
        Some(initrd_path_str)
    } else {
        eprintln!(
            "shuru: warning: initramfs not found at {}, booting without it",
            initrd_path_str
        );
        None
    };

    Ok(PreparedVm {
        data_dir,
        instance_dir,
        work_rootfs,
        kernel_path,
        initrd_path,
        cpus,
        memory,
        disk_size,
        allow_net,
        forwards,
        mounts,
    })
}

pub(crate) fn run_command(prepared: &PreparedVm, command: &[String]) -> Result<i32> {
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
        .allow_net(prepared.allow_net)
        .console(false);

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

    eprintln!("shuru: starting VM...");
    sandbox.start()?;
    eprintln!("shuru: VM started");
    eprintln!("shuru: waiting for guest to be ready...");

    let _fwd = if !prepared.forwards.is_empty() {
        Some(sandbox.start_port_forwarding(&prepared.forwards)?)
    } else {
        None
    };

    let exit_code = if std::io::stdin().is_terminal() {
        sandbox.shell(command, &HashMap::new())?
    } else {
        sandbox.exec(command, &mut std::io::stdout(), &mut std::io::stderr())?
    };

    let _ = sandbox.stop();
    Ok(exit_code)
}

fn parse_mount_spec(s: &str) -> Result<MountConfig> {
    let parts: Vec<&str> = s.splitn(2, ':').collect();
    if parts.len() < 2 {
        bail!("expected HOST:GUEST format (e.g. ./src:/workspace)");
    }

    let host_path = std::fs::canonicalize(parts[0])
        .with_context(|| format!("host path does not exist: '{}'", parts[0]))?
        .to_string_lossy()
        .to_string();

    let guest_path = parts[1].to_string();
    if !guest_path.starts_with('/') {
        bail!("guest path must be absolute (start with /): '{}'", guest_path);
    }

    Ok(MountConfig {
        host_path,
        guest_path,
    })
}

fn parse_port_mapping(s: &str) -> Result<PortMapping> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        bail!("expected HOST:GUEST format (e.g. 8080:80)");
    }
    let host_port: u16 = parts[0]
        .parse()
        .with_context(|| format!("invalid host port: '{}'", parts[0]))?;
    let guest_port: u16 = parts[1]
        .parse()
        .with_context(|| format!("invalid guest port: '{}'", parts[1]))?;
    Ok(PortMapping {
        host_port,
        guest_port,
    })
}
