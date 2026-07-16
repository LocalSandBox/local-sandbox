use std::collections::HashMap;

use napi::threadsafe_function::ThreadsafeFunction;
use napi::Status;
use napi_derive::napi;

// These structs define the JavaScript-facing data shapes. Field names stay in
// camelCase to match the generated TypeScript API and user input objects.
/// Secret value that is only exposed to requests for the listed hosts.
#[allow(non_snake_case)]
#[napi(object)]
pub struct SecretConfig {
  /// Secret payload or source value.
  pub value: String,
  /// Host allowlist for this secret.
  pub hosts: Vec<String>,
}

/// Optional destination scope for an intercepted request header.
#[allow(non_snake_case)]
#[napi(object)]
pub struct HostScopeConfig {
  /// Host patterns that may receive the header.
  pub allow: Option<Vec<String>>,
  /// Host patterns that must not receive the header. Deny takes precedence.
  pub deny: Option<Vec<String>>,
}

/// Request header set by the HTTPS interceptor.
#[allow(non_snake_case)]
#[napi(object)]
pub struct RequestHeaderConfig {
  pub name: String,
  pub value: String,
  pub hosts: Option<HostScopeConfig>,
}

/// Opt-in HTTPS request interception configuration.
#[allow(non_snake_case)]
#[napi(object)]
pub struct HttpsInterceptionConfig {
  pub enabled: bool,
  pub requestHeaders: Vec<RequestHeaderConfig>,
}

/// Host port made reachable from inside the guest via host.lsb.internal.
#[allow(non_snake_case)]
#[napi(object)]
pub struct ExposeHostConfig {
  /// Port on the host machine.
  pub host: u32,
  /// Port visible to the guest. Defaults to `host` when omitted.
  pub guest: Option<u32>,
}

/// Network policy for a sandbox.
#[allow(non_snake_case)]
#[napi(object)]
pub struct NetworkConfig {
  /// Outbound host patterns allowed by the proxy.
  pub allow: Option<Vec<String>>,
  /// Host ports exposed to the guest.
  pub exposeHost: Option<Vec<ExposeHostConfig>>,
  /// Secrets injected by the proxy for allowed hosts.
  pub secrets: Option<HashMap<String, SecretConfig>>,
  /// HTTPS request interception and header mutation.
  pub httpsInterception: Option<HttpsInterceptionConfig>,
}

/// Host-to-guest TCP port forwarding rule.
#[allow(non_snake_case)]
#[napi(object)]
pub struct PortMappingConfig {
  /// Host port to listen on.
  pub host: u32,
  /// Guest port to forward to.
  pub guest: u32,
}

/// Directory mount configuration.
#[allow(non_snake_case)]
#[napi(object)]
pub struct MountConfig {
  // napi-rs still deserializes this as String at runtime; the ts_type keeps the
  // generated declaration as a discriminated union for TypeScript callers.
  /// Mount behavior: `overlay` isolates writes, `direct` applies libc mount flags.
  #[napi(ts_type = "'overlay' | 'direct'")]
  pub r#type: String,
  /// Existing host directory to share with the VM.
  pub hostPath: String,
  /// Absolute guest path where the directory appears.
  pub guestPath: String,
  /// libc mount flags for direct mounts. Use `0` for read-write, `1` for MS_RDONLY.
  pub flags: Option<f64>,
}

/// Options used when booting a sandbox.
#[allow(non_snake_case)]
#[napi(object)]
pub struct StartOptions {
  /// Stable instance directory name.
  pub instanceId: Option<String>,
  /// Checkpoint name to resume from.
  pub from: Option<String>,
  /// Number of virtual CPUs.
  pub cpus: Option<u32>,
  /// Guest memory in MiB.
  pub memoryMb: Option<u32>,
  /// Writable root disk size in MiB.
  pub diskSizeMb: Option<u32>,
  /// Runtime data directory containing VM assets and instances.
  pub dataDir: Option<String>,
  /// Pinned base runtime asset version to boot from when `from` is not set.
  /// Defaults to the initialized VERSION in `dataDir`.
  pub baseVersion: Option<String>,
  /// Host-to-guest port forwards.
  pub ports: Option<Vec<PortMappingConfig>>,
  /// Directory mounts applied during boot.
  #[napi(
    ts_type = "Array<{ type: 'overlay'; hostPath: string; guestPath: string } | { type: 'direct'; hostPath: string; guestPath: string; flags: number }>"
  )]
  pub mounts: Option<Vec<MountConfig>>,
  /// Network proxy, host exposure, and secret policy.
  pub network: Option<NetworkConfig>,
}

/// Stages reported while sandbox runtime initialization runs.
#[napi(string_enum = "kebab-case")]
pub enum SandboxInitProgressPhase {
  Checking,
  ApplyingFixes,
  DownloadingHostTools,
  VerifyingHostTools,
  ExtractingHostTools,
  ValidatingHostTools,
  DownloadingAndExtractingRuntimeAssets,
  PinningRuntimeAssets,
}

/// Observational progress emitted while sandbox runtime initialization runs.
#[allow(non_snake_case)]
#[napi(object)]
pub struct SandboxInitProgress {
  /// Current initialization stage.
  pub phase: SandboxInitProgressPhase,
  /// Compressed response bytes consumed; present only during a download phase.
  pub downloadedBytes: Option<f64>,
  /// Positive Content-Length supplied by the server, when available.
  pub totalBytes: Option<f64>,
}

/// Options used when initializing sandbox runtime assets.
#[allow(non_snake_case)]
#[napi(object, object_to_js = false)]
pub struct SandboxInitOptions {
  /// Runtime data directory. Defaults to the platform runtime data directory.
  pub dataDir: Option<String>,
  /// Runtime asset version to initialize and pin as a base image. Defaults to this package version.
  pub version: Option<String>,
  /// Re-download assets even when the expected files and VERSION marker already exist.
  pub force: Option<bool>,
  /// Apply every automatic host configuration fix supported by this package.
  pub fix: Option<bool>,
  /// Receives non-blocking progress notifications on JavaScript's main thread.
  pub onProgress:
    Option<ThreadsafeFunction<SandboxInitProgress, (), SandboxInitProgress, Status, false>>,
}

/// Result of an automatic host configuration fix applied during initialization.
#[allow(non_snake_case)]
#[napi(object)]
pub struct SandboxFixResult {
  /// Stable name of the fix.
  pub name: String,
  /// True when the fix changed host configuration.
  pub changed: bool,
}

/// Runtime asset paths derived from a sandbox data directory.
#[allow(non_snake_case)]
#[napi(object)]
pub struct SandboxAssetPaths {
  /// Runtime data directory.
  pub dataDir: String,
  /// VERSION marker path.
  pub versionFile: String,
  /// Linux kernel image path.
  pub kernel: String,
  /// Writable root filesystem base image path.
  pub rootfs: String,
  /// Initramfs image path.
  pub initramfs: String,
  /// Checkpoint storage directory.
  pub checkpointsDir: String,
  /// Per-sandbox instance directory root.
  pub instancesDir: String,
}

/// Result returned after initializing or checking sandbox runtime assets.
#[allow(non_snake_case)]
#[napi(object)]
pub struct SandboxInitResult {
  /// Runtime data directory that was checked or initialized.
  pub dataDir: String,
  /// Runtime asset version now expected in the data directory.
  pub version: String,
  /// True when this call downloaded and extracted assets.
  pub downloaded: bool,
  /// Concrete runtime asset paths.
  pub paths: SandboxAssetPaths,
  /// Automatic host configuration fixes attempted by this call.
  pub fixes: Vec<SandboxFixResult>,
}

/// Per-command execution options.
#[allow(non_snake_case)]
#[napi(object)]
pub struct ExecOptions {
  /// Guest working directory.
  pub cwd: Option<String>,
  /// Additional environment variables.
  pub env: Option<HashMap<String, String>>,
  /// Shell used when the command is a string. Defaults to `sh`.
  pub shell: Option<String>,
}

/// Options for spawned processes.
#[allow(non_snake_case)]
#[napi(object)]
pub struct SpawnOptions {
  /// Guest working directory.
  pub cwd: Option<String>,
  /// Additional environment variables.
  pub env: Option<HashMap<String, String>>,
  /// Shell used when the command is a string. Defaults to `sh`.
  pub shell: Option<String>,
}

/// Options for file watching.
#[allow(non_snake_case)]
#[napi(object)]
pub struct WatchOptions {
  /// Watch subdirectories recursively. Defaults to true.
  pub recursive: Option<bool>,
}

/// Options for directory creation.
#[allow(non_snake_case)]
#[napi(object)]
pub struct MkdirOptions {
  /// Create parent directories as needed. Defaults to true.
  pub recursive: Option<bool>,
}

/// Options for removing files or directories.
#[allow(non_snake_case)]
#[napi(object)]
pub struct RemoveOptions {
  /// Remove directory trees recursively. Defaults to false.
  pub recursive: Option<bool>,
}

/// Options for copying files or directories.
#[allow(non_snake_case)]
#[napi(object)]
pub struct CopyOptions {
  /// Copy directory trees recursively. Defaults to false.
  pub recursive: Option<bool>,
}

/// Completed command result.
#[allow(non_snake_case)]
#[napi(object)]
pub struct ExecResult {
  /// Captured stdout as UTF-8 text.
  pub stdout: String,
  /// Captured stderr as UTF-8 text.
  pub stderr: String,
  /// Process exit code.
  pub exitCode: i32,
}

/// Directory entry returned by `readDir`.
#[napi(object)]
pub struct DirEntry {
  /// Entry basename.
  pub name: String,
  /// Entry type such as `file`, `dir`, or `symlink`.
  pub r#type: String,
  /// Entry size in bytes.
  pub size: f64,
}

/// File metadata returned by `stat`.
#[allow(non_snake_case)]
#[napi(object)]
pub struct StatResult {
  /// Size in bytes.
  pub size: f64,
  /// POSIX mode bits.
  pub mode: u32,
  /// Modified time as a Unix timestamp in milliseconds.
  pub mtime: f64,
  /// True when the path is a directory.
  pub isDir: bool,
  /// True when the path is a regular file.
  pub isFile: bool,
  /// True when the path is a symbolic link.
  pub isSymlink: bool,
}

/// File watcher event.
#[allow(non_snake_case)]
#[napi(object)]
pub struct FileChangeEvent {
  /// Changed guest path.
  pub path: String,
  /// Event kind reported by the guest watcher.
  pub event: String,
}

impl Default for StartOptions {
  fn default() -> Self {
    Self {
      instanceId: None,
      from: None,
      cpus: None,
      memoryMb: None,
      diskSizeMb: None,
      dataDir: None,
      baseVersion: None,
      ports: None,
      mounts: None,
      network: None,
    }
  }
}

impl Default for SandboxInitOptions {
  fn default() -> Self {
    Self {
      dataDir: None,
      version: None,
      force: None,
      fix: None,
      onProgress: None,
    }
  }
}

impl Default for ExecOptions {
  fn default() -> Self {
    Self {
      cwd: None,
      env: None,
      shell: None,
    }
  }
}

impl Default for SpawnOptions {
  fn default() -> Self {
    Self {
      cwd: None,
      env: None,
      shell: None,
    }
  }
}
