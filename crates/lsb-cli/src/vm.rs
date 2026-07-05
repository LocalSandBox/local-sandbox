use std::collections::HashMap;
use std::io::IsTerminal;

use anyhow::{bail, Context, Result};

use lsb_platform::asset_paths;
use lsb_platform::PlatformNetworkAttachment;
use lsb_vm::{MountConfig, PortMapping, Sandbox};

use crate::assets;
use crate::cli::VmArgs;
use crate::config::LsbConfig;

const MS_RDONLY: u64 = 1;

pub(crate) struct PreparedVm {
    pub data_dir: String,
    pub checkpoints_dir: String,
    pub instance_dir: String,
    pub source_rootfs: String,
    pub work_rootfs: String,
    pub cas_index: Option<String>,
    pub kernel_path: String,
    pub initrd_path: Option<String>,
    pub cpus: usize,
    pub memory: u64,
    pub disk_size: u64,
    pub proxy_config: Option<lsb_proxy::config::ProxyConfig>,
    pub verbose: bool,
    pub forwards: Vec<PortMapping>,
    pub mounts: Vec<MountConfig>,
}

pub(crate) fn clone_file(src: &str, dst: &str) -> Result<()> {
    lsb_platform::copy_file_cow(src, dst)
}

pub(crate) fn prepare_vm(vm: &VmArgs, cfg: &LsbConfig, from: Option<&str>) -> Result<PreparedVm> {
    let cpus = vm.cpus.or(cfg.cpus).unwrap_or(2);
    let memory = vm.memory.or(cfg.memory).unwrap_or(2048);
    let disk_size = vm.disk_size.or(cfg.disk_size).unwrap_or(4096);
    let allow_net = vm.allow_net || cfg.allow_net.unwrap_or(false);
    let allow_host_writes = vm.allow_host_writes || cfg.allow_host_writes.unwrap_or(false);
    let verbose = vm.verbose;

    let proxy_config = if allow_net {
        let mut proxy = cfg.to_proxy_config();

        // Merge --secret flags: NAME=VALUE@host1,host2
        for s in &vm.secret {
            let (name, value, hosts) = parse_secret_flag(s).with_context(|| {
                format!(
                    "invalid --secret: '{}' (expected NAME=VALUE@host1,host2)",
                    s
                )
            })?;
            proxy
                .secrets
                .insert(name, lsb_proxy::config::SecretConfig { value, hosts });
        }

        // Merge --allow-domain flags
        for d in &vm.allow_host {
            proxy.network.allow.push(d.clone());
        }

        for s in &vm.expose_host {
            let mapping = crate::config::parse_expose_host(s)
                .with_context(|| format!("invalid --expose-host: '{}'", s))?;
            proxy.expose_host.push(mapping);
        }

        Some(proxy)
    } else {
        None
    };

    // Merge port forwards: CLI flags + config file
    let mut port_strs: Vec<&str> = vm.port.iter().map(|s| s.as_str()).collect();
    if let Some(ref cfg_ports) = cfg.ports {
        for p in cfg_ports {
            port_strs.push(p.as_str());
        }
    }
    let mut forwards = Vec::new();
    for s in &port_strs {
        let mapping =
            parse_port_mapping(s).with_context(|| format!("invalid port mapping: '{}'", s))?;
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
        let mc = parse_mount_spec(s).with_context(|| format!("invalid mount spec: '{}'", s))?;
        mounts.push(mc);
    }
    if !mounts.is_empty() {
        validate_mounts(&mounts, allow_host_writes)?;
    }

    let data_dir = lsb_vm::default_data_dir();
    let paths = asset_paths(&data_dir);
    if from.is_some() && vm.base_version.is_some() {
        bail!("--from and --base-version cannot be used together");
    }

    // Auto-download assets when using default paths
    if vm.kernel.is_none()
        && vm.rootfs.is_none()
        && vm.initrd.is_none()
        && !assets::assets_ready(&data_dir)
    {
        assets::download_os_image(&data_dir)?;
    }

    let kernel_path = vm.kernel.clone().unwrap_or_else(|| paths.kernel.clone());
    let rootfs_path = vm.rootfs.clone().unwrap_or_else(|| paths.rootfs.clone());
    let initrd_path_str = vm.initrd.clone().unwrap_or_else(|| paths.initramfs.clone());

    if !std::path::Path::new(&kernel_path).exists() {
        bail!(
            "Kernel not found at {}. Run `lsb init` to download.",
            kernel_path
        );
    }

    let storage = lsb_sdk::prepare_storage(lsb_sdk::StoragePrepareOptions {
        data_dir: &data_dir,
        checkpoints_dir: &paths.checkpoints_dir,
        rootfs_path: &rootfs_path,
        from,
        base_version: vm.base_version.as_deref(),
        custom_rootfs: vm.rootfs.is_some(),
        direct: std::env::var("LSB_STORAGE").unwrap_or_default() == "direct",
    })?;

    // Create per-instance working copy (clean any stale dir from PID reuse)
    let instance_dir = format!("{}/{}", paths.instances_dir, std::process::id());
    let _ = std::fs::remove_dir_all(&instance_dir);
    std::fs::create_dir_all(&instance_dir)?;
    let work_rootfs = format!("{instance_dir}/rootfs.ext4");
    if !storage.is_nbd() {
        if verbose {
            eprintln!("lsb: creating working copy...");
        }
        lsb_platform::copy_file_cow(&storage.direct_source_rootfs, &work_rootfs)?;
    } else {
        std::fs::File::create(&work_rootfs)?;
    }

    // Extend to requested disk size
    let f = std::fs::OpenOptions::new().write(true).open(&work_rootfs)?;
    let target = disk_size * 1024 * 1024;
    let current = if storage.is_nbd() {
        storage.logical_size
    } else {
        f.metadata()?.len()
    };
    if target < current {
        bail!(
            "--disk-size {}MB is smaller than the base image ({}MB)",
            disk_size,
            current / 1024 / 1024
        );
    }
    if !storage.is_nbd() && target > current {
        f.set_len(target)?;
    }
    drop(f);

    let initrd_path = if std::path::Path::new(&initrd_path_str).exists() {
        Some(initrd_path_str)
    } else {
        eprintln!(
            "lsb: warning: initramfs not found at {}, booting without it",
            initrd_path_str
        );
        None
    };

    Ok(PreparedVm {
        data_dir,
        checkpoints_dir: paths.checkpoints_dir,
        instance_dir,
        source_rootfs: storage.active_source_rootfs().to_string(),
        work_rootfs,
        cas_index: storage.cas_index().map(str::to_string),
        kernel_path,
        initrd_path,
        cpus,
        memory,
        disk_size,
        proxy_config,
        verbose,
        forwards,
        mounts,
    })
}

pub(crate) fn build_sandbox(
    prepared: &PreparedVm,
    console: bool,
    network_attachment: Option<PlatformNetworkAttachment>,
    nbd_uri: Option<&str>,
) -> Result<Sandbox> {
    let mut builder = Sandbox::builder()
        .kernel(&prepared.kernel_path)
        .rootfs(&prepared.work_rootfs)
        .cpus(prepared.cpus)
        .memory_mb(prepared.memory)
        .console(console)
        .verbose(prepared.verbose);

    if let Some(attachment) = network_attachment {
        builder = builder.network_attachment(attachment);
    }

    if let Some(uri) = nbd_uri {
        builder = builder.nbd_uri(uri);
    }

    if let Some(initrd) = &prepared.initrd_path {
        builder = builder.initrd(initrd);
    }

    for m in &prepared.mounts {
        builder = builder.mount(m.clone());
    }

    builder.build()
}

pub(crate) fn start_proxy_network(
    proxy_config: &lsb_proxy::config::ProxyConfig,
) -> Result<(PlatformNetworkAttachment, lsb_proxy::ProxyHandle)> {
    let link = lsb_proxy::create_proxy_link()?;
    let vm_attachment = platform_network_attachment(link.vm);
    let handle = lsb_proxy::start_link(link.host, proxy_config.clone())?;
    Ok((vm_attachment, handle))
}

fn platform_network_attachment(
    attachment: lsb_proxy::VmNetworkAttachment,
) -> PlatformNetworkAttachment {
    match attachment {
        lsb_proxy::VmNetworkAttachment::FileDescriptor(fd) => {
            PlatformNetworkAttachment::file_descriptor(fd)
        }
        lsb_proxy::VmNetworkAttachment::QemuStream { host, port } => {
            PlatformNetworkAttachment::qemu_stream(host, port)
        }
    }
}

pub(crate) struct RunResult {
    pub exit_code: i32,
    pub nbd_handle: Option<lsb_store::NbdHandle>,
}

pub(crate) fn start_nbd(prepared: &PreparedVm) -> Result<Option<lsb_store::NbdHandle>> {
    if std::env::var("LSB_STORAGE").unwrap_or_default() == "direct" {
        return Ok(None);
    }

    let socket_path = format!("{}/nbd.sock", prepared.instance_dir);
    let cas_dir = format!("{}/cas", prepared.data_dir);
    let index_path = prepared
        .cas_index
        .clone()
        .ok_or_else(|| anyhow::anyhow!("NBD storage requires a CAS index"))?;
    let target_size = prepared.disk_size * 1024 * 1024;

    Ok(Some(lsb_store::start_cas_nbd_server(
        &prepared.source_rootfs,
        &cas_dir,
        &index_path,
        &socket_path,
        target_size,
    )?))
}

pub(crate) fn run_command(prepared: &PreparedVm, command: &[String]) -> Result<RunResult> {
    run_command_inner(prepared, command, false)
}

pub(crate) fn run_command_for_checkpoint(
    prepared: &PreparedVm,
    command: &[String],
) -> Result<RunResult> {
    run_command_inner(prepared, command, true)
}

fn run_command_inner(
    prepared: &PreparedVm,
    command: &[String],
    sync_before_stop: bool,
) -> Result<RunResult> {
    if prepared.verbose {
        eprintln!("lsb: kernel={}", prepared.kernel_path);
        eprintln!("lsb: rootfs={} (work copy)", prepared.work_rootfs);
    }
    eprintln!(
        "lsb: booting VM ({}cpus, {}MB RAM, {}MB disk)...",
        prepared.cpus, prepared.memory, prepared.disk_size
    );

    // Set up proxy networking if --allow-net
    let (network_attachment, proxy_handle) = if let Some(ref proxy_config) = prepared.proxy_config {
        let (vm_attachment, handle) = start_proxy_network(proxy_config)?;

        if prepared.verbose {
            eprintln!("lsb: proxy started");
        }

        (Some(vm_attachment), Some(handle))
    } else {
        (None, None)
    };

    let nbd_handle = start_nbd(prepared)?;
    let nbd_uri = nbd_handle.as_ref().map(|handle| handle.uri());

    let sandbox = build_sandbox(prepared, false, network_attachment, nbd_uri.as_deref())?;
    if prepared.verbose {
        eprintln!("lsb: VM created and validated successfully");
    }

    sandbox.start()?;
    if prepared.verbose {
        eprintln!("lsb: VM started, waiting for guest...");
    }

    let _fwd = if !prepared.forwards.is_empty() {
        Some(sandbox.start_port_forwarding(&prepared.forwards)?)
    } else {
        None
    };

    // Inject CA cert and secret placeholders when MITM is needed
    let mut env = HashMap::new();
    if let Some(ref handle) = proxy_handle {
        if !handle.placeholders.is_empty() {
            sandbox.write_file(
                "/usr/local/share/ca-certificates/lsb-proxy.crt",
                &handle.ca_cert_pem,
            )?;
            sandbox.exec(
                &["update-ca-certificates", "--fresh"],
                &mut std::io::sink(),
                &mut std::io::sink(),
            )?;
            if prepared.verbose {
                eprintln!("lsb: proxy CA certificate injected");
            }
            for (name, placeholder) in &handle.placeholders {
                env.insert(name.clone(), placeholder.clone());
            }
        }
    }

    let exit_code = if std::io::stdin().is_terminal() {
        sandbox.shell(command, &env)?
    } else {
        sandbox.exec_with_env(
            command,
            &env,
            &mut std::io::stdout(),
            &mut std::io::stderr(),
        )?
    };

    if sync_before_stop {
        sandbox.exec(&["sync"], &mut std::io::sink(), &mut std::io::sink())?;
    }

    drop(proxy_handle);
    let _ = sandbox.stop();
    Ok(RunResult {
        exit_code,
        nbd_handle,
    })
}

fn parse_mount_spec(s: &str) -> Result<MountConfig> {
    let parts: Vec<&str> = s.splitn(3, ':').collect();
    if parts.len() < 2 {
        bail!("expected HOST:GUEST[:ro|rw] format (e.g. ./src:/workspace:rw)");
    }

    let host_path = std::fs::canonicalize(parts[0])
        .with_context(|| format!("host path does not exist: '{}'", parts[0]))?
        .to_string_lossy()
        .to_string();

    parse_mount_parts(&host_path, parts[1], parts.get(2).copied())
}

fn parse_mount_parts(host: &str, guest: &str, mode: Option<&str>) -> Result<MountConfig> {
    if !guest.starts_with('/') {
        bail!("guest path must be absolute (start with /): '{}'", guest);
    }

    match mode {
        None | Some("ro") => Ok(MountConfig::Overlay {
            host_path: host.to_string(),
            guest_path: guest.to_string(),
        }),
        Some("rw") => Ok(MountConfig::Direct {
            host_path: host.to_string(),
            guest_path: guest.to_string(),
            flags: 0,
        }),
        Some(other) => bail!("invalid mount mode '{}': expected 'ro' or 'rw'", other),
    }
}

fn validate_mounts(mounts: &[MountConfig], allow_host_writes: bool) -> Result<()> {
    let cwd = std::env::current_dir().context("failed to determine current working directory")?;
    let cwd =
        std::fs::canonicalize(&cwd).context("failed to canonicalize current working directory")?;
    validate_mounts_with_cwd(mounts, allow_host_writes, &cwd)
}

fn validate_mounts_with_cwd(
    mounts: &[MountConfig],
    allow_host_writes: bool,
    cwd: &std::path::Path,
) -> Result<()> {
    if cwd == std::path::Path::new("/") {
        bail!(
            "cannot use mounts when the current working directory is '/'. Change to a project directory first."
        );
    }

    for mount in mounts {
        let host_path = match mount {
            MountConfig::Overlay { host_path, .. } | MountConfig::Direct { host_path, .. } => {
                host_path
            }
        };
        let guest_path = match mount {
            MountConfig::Overlay { guest_path, .. } | MountConfig::Direct { guest_path, .. } => {
                guest_path
            }
        };
        let host = std::path::Path::new(host_path);

        if host == std::path::Path::new("/") {
            bail!("mounting '/' as a host path is not allowed. Mount a specific subdirectory instead.");
        }

        if !host.starts_with(cwd) {
            bail!(
                "mount host path '{}' is outside the current working directory '{}'. Only paths within CWD can be mounted.",
                host_path,
                cwd.display()
            );
        }

        let writes_to_host =
            matches!(mount, MountConfig::Direct { flags, .. } if flags & MS_RDONLY == 0);
        if writes_to_host && !allow_host_writes {
            bail!(
                "read-write mount '{}:{}:rw' requires --allow-host-writes flag (or \"allow_host_writes\": true in config).",
                host_path,
                guest_path
            );
        }
    }

    Ok(())
}

/// Parse `NAME=VALUE@host1,host2` into (name, value, hosts).
fn parse_secret_flag(s: &str) -> Result<(String, String, Vec<String>)> {
    let (name, rest) = s
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("missing '=' separator"))?;
    let (value, hosts_str) = rest
        .rsplit_once('@')
        .ok_or_else(|| anyhow::anyhow!("missing '@' separator for hosts"))?;
    let hosts: Vec<String> = hosts_str
        .split(',')
        .map(|h| h.trim())
        .filter(|h| !h.is_empty())
        .map(|h| h.to_string())
        .collect();
    if name.is_empty() || value.is_empty() || hosts.is_empty() {
        bail!("name, value, and hosts must all be non-empty");
    }
    Ok((name.to_string(), value.to_string(), hosts))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_defaults_to_overlay() {
        let mount =
            parse_mount_parts("/some/host", "/workspace", None).expect("mount should parse");
        assert!(matches!(mount, MountConfig::Overlay { .. }));
    }

    #[test]
    fn mount_rw_suffix_uses_direct_mount() {
        let mount =
            parse_mount_parts("/some/host", "/workspace", Some("rw")).expect("mount should parse");
        assert!(matches!(mount, MountConfig::Direct { flags: 0, .. }));
    }

    #[test]
    fn mount_rejects_bad_mode() {
        assert!(parse_mount_parts("/some/host", "/workspace", Some("xx")).is_err());
    }

    #[test]
    fn mount_rejects_relative_guest_path() {
        assert!(parse_mount_parts("/some/host", "workspace", None).is_err());
    }

    #[test]
    fn rw_mount_requires_allow_flag() {
        let cwd = std::env::current_dir().expect("cwd");
        let mounts = vec![MountConfig::Direct {
            host_path: cwd.to_string_lossy().to_string(),
            guest_path: "/workspace".to_string(),
            flags: 0,
        }];
        let err = validate_mounts_with_cwd(&mounts, false, &cwd).expect_err("rw mount should fail");
        assert!(err.to_string().contains("--allow-host-writes"));
    }

    #[test]
    fn parses_literal_secret_flag() {
        let (name, value, hosts) =
            parse_secret_flag("API_KEY=sk-test@api.openai.com").expect("flag should parse");

        assert_eq!(name, "API_KEY");
        assert_eq!(value, "sk-test");
        assert_eq!(hosts, vec!["api.openai.com"]);
    }

    #[test]
    fn parses_secret_flag_using_last_at_as_host_separator() {
        let (name, value, hosts) =
            parse_secret_flag("AUTH_TOKEN=tok@segment@api.openai.com,api.anthropic.com")
                .expect("flag should parse");

        assert_eq!(name, "AUTH_TOKEN");
        assert_eq!(value, "tok@segment");
        assert_eq!(hosts, vec!["api.openai.com", "api.anthropic.com"]);
    }

    #[test]
    fn rejects_secret_flag_without_hosts() {
        let err =
            parse_secret_flag("API_KEY=sk-test@").expect_err("flag without hosts should fail");

        assert!(err
            .to_string()
            .contains("name, value, and hosts must all be non-empty"));
    }
}
