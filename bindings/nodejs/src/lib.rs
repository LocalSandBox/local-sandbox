#![deny(clippy::all)]
#![allow(non_snake_case)]

// Keep this crate root thin: N-API exports are implemented in focused modules
// and re-exported here so napi-rs still generates a single public JS surface.
mod config;
mod error;
mod process;
mod sandbox;
mod streams;
mod types;

use napi::Result;
use napi_derive::napi;

#[cfg(lsb_nodejs_supported)]
use crate::config::{build_init_options, map_init_result};
#[cfg(lsb_nodejs_supported)]
use crate::error::to_napi_error;
#[cfg(not(lsb_nodejs_supported))]
use crate::error::unsupported_platform_error;

pub use process::SpawnedProcess;
pub use sandbox::Sandbox;
pub use streams::{ByteStream, WatchStream};
pub use types::{
  CopyOptions, DirEntry, ExecOptions, ExecResult, ExposeHostConfig, FileChangeEvent, MkdirOptions,
  MountConfig, NetworkConfig, PortMappingConfig, RemoveOptions, SandboxAssetPaths,
  SandboxInitOptions, SandboxInitResult, SecretConfig, SpawnOptions, StartOptions, StatResult,
  WatchOptions,
};

/// Download or verify sandbox runtime assets such as kernel, rootfs, and initramfs.
///
/// Usage: `await initSandbox({ dataDir, force: false })`
#[napi]
pub async fn init_sandbox(opts: Option<SandboxInitOptions>) -> Result<SandboxInitResult> {
  #[cfg(lsb_nodejs_supported)]
  {
    let opts = opts.unwrap_or_default();
    let version = opts.version.clone();
    let options = build_init_options(opts);
    let result = tokio::task::spawn_blocking(move || match version {
      Some(version) => lsb_sdk::init_sandbox_version(options, &version),
      None => lsb_sdk::init_sandbox(options),
    })
    .await
    .map_err(|error| to_napi_error(anyhow::Error::new(error)))?
    .map_err(to_napi_error)?;
    return Ok(map_init_result(result));
  }

  #[cfg(not(lsb_nodejs_supported))]
  {
    let _ = opts;
    Err(unsupported_platform_error())
  }
}
