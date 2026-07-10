#[cfg(lsb_nodejs_supported)]
use std::collections::HashMap;

#[cfg(lsb_nodejs_supported)]
use napi::bindgen_prelude::Either;

#[cfg(lsb_nodejs_supported)]
use crate::types::{
  DirEntry, ExecResult, ExposeHostConfig, MountConfig, PortMappingConfig, SandboxAssetPaths,
  SandboxFixResult, SandboxInitOptions, SandboxInitResult, SecretConfig, StartOptions, StatResult,
};

// Conversion layer between JS options and the Rust SDK. Keeping validation here
// lets the N-API classes stay as thin wrappers around lsb_sdk.
#[cfg(lsb_nodejs_supported)]
pub(crate) fn build_command_argv(
  command: Either<String, Vec<String>>,
  shell: Option<String>,
) -> Vec<String> {
  match command {
    Either::A(command) => vec![
      shell.unwrap_or_else(|| "sh".to_string()),
      "-c".to_string(),
      command,
    ],
    Either::B(argv) => argv,
  }
}

#[cfg(lsb_nodejs_supported)]
pub(crate) fn command_options(
  cwd: Option<String>,
  env: Option<HashMap<String, String>>,
) -> lsb_sdk::CommandOptions {
  lsb_sdk::CommandOptions {
    cwd,
    env: env.unwrap_or_default(),
  }
}

#[cfg(lsb_nodejs_supported)]
pub(crate) fn build_sandbox_config(opts: StartOptions) -> anyhow::Result<lsb_sdk::SandboxConfig> {
  let mut config = lsb_sdk::SandboxConfig::default();

  config.instance_id = opts.instanceId;
  config.from = opts.from;
  config.base_version = opts.baseVersion;
  config.data_dir = opts.dataDir;
  config.cpus = opts.cpus.unwrap_or(config.cpus as u32) as usize;
  config.memory_mb = u64::from(opts.memoryMb.unwrap_or(config.memory_mb as u32));
  config.disk_size_mb = u64::from(opts.diskSizeMb.unwrap_or(config.disk_size_mb as u32));

  if let Some(ports) = opts.ports {
    config.ports = ports
      .into_iter()
      .map(parse_port_mapping)
      .collect::<anyhow::Result<Vec<_>>>()?;
  }

  if let Some(mounts) = opts.mounts {
    config.mounts = mounts
      .into_iter()
      .map(parse_mount)
      .collect::<anyhow::Result<Vec<_>>>()?;
  }

  if let Some(network) = opts.network {
    config.allow_net = true;

    if let Some(allow) = network.allow {
      config.allowed_hosts = allow;
    }

    if let Some(expose_host) = network.exposeHost {
      config.expose_host = expose_host
        .into_iter()
        .map(parse_expose_host)
        .collect::<anyhow::Result<Vec<_>>>()?;
    }

    if let Some(secrets) = network.secrets {
      config.secrets = secrets
        .into_iter()
        .map(|(name, secret)| Ok((name, parse_secret(secret)?)))
        .collect::<anyhow::Result<HashMap<_, _>>>()?;
    }
  }

  Ok(config)
}

#[cfg(lsb_nodejs_supported)]
pub(crate) fn build_init_options(opts: SandboxInitOptions) -> lsb_sdk::SandboxInitOptions {
  lsb_sdk::SandboxInitOptions {
    data_dir: opts.dataDir,
    force: opts.force.unwrap_or(false),
    fix: opts.fix.unwrap_or(false),
  }
}

#[cfg(lsb_nodejs_supported)]
fn parse_mount(mount: MountConfig) -> anyhow::Result<lsb_sdk::MountConfig> {
  if !mount.guestPath.starts_with('/') {
    anyhow::bail!(
      "guest path must be absolute (start with /): '{}'",
      mount.guestPath
    );
  }

  let host_path = std::fs::canonicalize(&mount.hostPath)
    .map_err(|_| anyhow::anyhow!("host path does not exist: '{}'", mount.hostPath))?
    .to_string_lossy()
    .into_owned();

  // The public JS API names the mount behavior. The VM layer generates the
  // internal VirtioFS tag, so callers never provide or persist a tag directly.
  match mount.r#type.as_str() {
    "overlay" => {
      if mount.flags.is_some() {
        anyhow::bail!("overlay mounts do not accept flags");
      }

      Ok(lsb_sdk::MountConfig::Overlay {
        host_path,
        guest_path: mount.guestPath,
      })
    }
    "direct" => Ok(lsb_sdk::MountConfig::Direct {
      host_path,
      guest_path: mount.guestPath,
      flags: parse_mount_flags(mount.flags)?,
    }),
    other => anyhow::bail!(
      "invalid mount type '{}': expected 'overlay' or 'direct'",
      other
    ),
  }
}

#[cfg(lsb_nodejs_supported)]
fn parse_mount_flags(flags: Option<f64>) -> anyhow::Result<u64> {
  let flags = flags.ok_or_else(|| anyhow::anyhow!("direct mount flags are required"))?;
  const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

  if !flags.is_finite() || flags < 0.0 || flags.fract() != 0.0 || flags > MAX_SAFE_INTEGER {
    anyhow::bail!("direct mount flags must be a non-negative safe integer");
  }

  Ok(flags as u64)
}

#[cfg(lsb_nodejs_supported)]
fn parse_port_mapping(input: PortMappingConfig) -> anyhow::Result<lsb_sdk::PortMapping> {
  Ok(lsb_sdk::PortMapping {
    host_port: parse_u16_port(input.host, "host")?,
    guest_port: parse_u16_port(input.guest, "guest")?,
  })
}

#[cfg(lsb_nodejs_supported)]
fn parse_expose_host(input: ExposeHostConfig) -> anyhow::Result<lsb_sdk::ExposeHostMapping> {
  let host_port = parse_u16_port(input.host, "host")?;
  let guest_port = parse_u16_port(input.guest.unwrap_or(input.host), "guest")?;
  Ok(lsb_sdk::ExposeHostMapping {
    host_port,
    guest_port,
  })
}

#[cfg(lsb_nodejs_supported)]
fn parse_u16_port(port: u32, label: &str) -> anyhow::Result<u16> {
  u16::try_from(port).map_err(|_| anyhow::anyhow!("invalid {label} port: '{port}'"))
}

#[cfg(lsb_nodejs_supported)]
fn parse_secret(secret: SecretConfig) -> anyhow::Result<lsb_sdk::SecretConfig> {
  if secret.value.trim().is_empty() {
    anyhow::bail!("secret value must be non-empty");
  }

  if secret.hosts.is_empty() {
    anyhow::bail!("secret hosts must be non-empty");
  }

  Ok(lsb_sdk::SecretConfig {
    value: secret.value,
    hosts: secret.hosts,
  })
}

#[cfg(lsb_nodejs_supported)]
pub(crate) fn map_exec_result(result: lsb_sdk::ExecResult) -> ExecResult {
  ExecResult {
    stdout: result.stdout,
    stderr: result.stderr,
    exitCode: result.exit_code,
  }
}

#[cfg(lsb_nodejs_supported)]
pub(crate) fn map_dir_entry(entry: lsb_sdk::DirEntry) -> DirEntry {
  DirEntry {
    name: entry.name,
    r#type: entry.entry_type,
    size: entry.size as f64,
  }
}

#[cfg(lsb_nodejs_supported)]
pub(crate) fn map_stat_result(stat: lsb_sdk::StatResponse) -> StatResult {
  StatResult {
    size: stat.size as f64,
    mode: stat.mode,
    mtime: stat.mtime as f64,
    isDir: stat.is_dir,
    isFile: stat.is_file,
    isSymlink: stat.is_symlink,
  }
}

#[cfg(lsb_nodejs_supported)]
pub(crate) fn map_init_result(result: lsb_sdk::SandboxInitResult) -> SandboxInitResult {
  SandboxInitResult {
    dataDir: result.data_dir,
    version: result.version,
    downloaded: result.downloaded,
    fixes: result
      .fixes
      .into_iter()
      .map(|fix| SandboxFixResult {
        name: fix.name,
        changed: fix.changed,
      })
      .collect(),
    paths: SandboxAssetPaths {
      dataDir: result.paths.data_dir,
      versionFile: result.paths.version_file,
      kernel: result.paths.kernel,
      rootfs: result.paths.rootfs,
      initramfs: result.paths.initramfs,
      checkpointsDir: result.paths.checkpoints_dir,
      instancesDir: result.paths.instances_dir,
    },
  }
}
