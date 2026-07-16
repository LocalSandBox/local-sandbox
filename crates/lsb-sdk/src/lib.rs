mod assets;
mod fixes;
mod host_tools;
mod process;
mod progress;
mod runtime;
mod session;
mod shell;
mod storage;
mod types;
mod watch;

// Re-exports
pub use lsb_platform::AssetPaths;
pub use lsb_proto::{DirEntry, PortMapping, ReadDirResponse, StatResponse};
pub use lsb_proxy::config::{
    ExposeHostMapping, HostScope, HttpsInterceptionConfig, NetworkConfig, ProxyConfig,
    RequestHeaderRule, SecretConfig,
};
pub use lsb_vm::{default_data_dir, MountConfig};

pub use assets::{
    assets_ready, init_runtime_assets_version, init_sandbox, init_sandbox_version,
    init_sandbox_version_with_progress, init_sandbox_with_progress, SandboxInitOptions,
    SandboxInitResult, CURRENT_VERSION,
};
pub use fixes::{apply_sandbox_fixes, SandboxFixResult};
pub use host_tools::{init_host_tools, HostToolsInitResult};
pub use process::ProcessHandle;
pub use progress::{SandboxInitProgress, SandboxInitProgressPhase, SandboxInitProgressReporter};
pub use runtime::AsyncSandbox;
pub use shell::{ShellEvent, ShellHandle, ShellReader, ShellWriter};
pub use storage::{prepare_storage, NbdSource, PreparedStorage, StoragePrepareOptions};
pub use types::{CommandOptions, ExecResult, SandboxConfig, WatchEvent};
pub use watch::WatchHandle;
