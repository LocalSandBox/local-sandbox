use std::collections::HashMap;

use lsb_proto::PortMapping;
use lsb_proxy::config::{ExposeHostMapping, HttpsInterceptionConfig, SecretConfig};
use lsb_vm::MountConfig;

/// Configuration for booting a sandbox VM.
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Data directory containing kernel, rootfs, initramfs.
    /// Defaults to the platform runtime data directory.
    pub data_dir: Option<String>,
    /// Number of CPUs. Default: 2.
    pub cpus: usize,
    /// Memory in MB. Default: 2048.
    pub memory_mb: u64,
    /// Disk size in MB. Default: 4096.
    pub disk_size_mb: u64,
    /// Host -> guest directory mounts (overlay or direct VirtioFS).
    pub mounts: Vec<MountConfig>,
    /// Enable networking via proxy.
    pub allow_net: bool,
    /// Secrets for proxy injection.
    pub secrets: HashMap<String, SecretConfig>,
    /// Allowed domain patterns for network access.
    pub allowed_hosts: Vec<String>,
    /// Opt-in HTTPS request interception and request-header mutation.
    pub https_interception: HttpsInterceptionConfig,
    /// Port forwards (host -> guest).
    pub ports: Vec<PortMapping>,
    /// Host ports exposed to the guest via host.lsb.internal.
    pub expose_host: Vec<ExposeHostMapping>,
    /// Boot from a named checkpoint instead of base rootfs.
    pub from: Option<String>,
    /// Boot from a pinned base runtime asset version. Defaults to data_dir/VERSION.
    pub base_version: Option<String>,
    /// Optional stable instance id for the working rootfs directory.
    pub instance_id: Option<String>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            data_dir: None,
            cpus: 2,
            memory_mb: 2048,
            disk_size_mb: 4096,
            mounts: vec![],
            allow_net: false,
            secrets: HashMap::new(),
            allowed_hosts: vec![],
            https_interception: HttpsInterceptionConfig::default(),
            ports: vec![],
            expose_host: vec![],
            from: None,
            base_version: None,
            instance_id: None,
        }
    }
}

/// Result of executing a command in the VM.
#[derive(Debug)]
pub struct ExecResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

/// Per-command execution options.
#[derive(Debug, Clone, Default)]
pub struct CommandOptions {
    pub cwd: Option<String>,
    pub env: HashMap<String, String>,
}

/// A file change emitted by a guest watch stream.
#[derive(Debug, Clone)]
pub struct WatchEvent {
    pub path: String,
    pub event: String,
}
