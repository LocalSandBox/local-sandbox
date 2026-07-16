use std::collections::{BTreeMap, HashMap};

use napi::bindgen_prelude::{Either, Result};
use napi_derive::napi;

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
use crate::error::unsupported_platform_error;
use crate::types::{CopyOptions, DirEntry, ExecResult, MkdirOptions, RemoveOptions, StatResult};

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use std::sync::Arc;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use tokio::sync::Mutex;

#[allow(non_snake_case)]
#[napi(object)]
pub struct SeaWorkStartOptions {
  pub cpus: Option<u32>,
  pub memoryMb: Option<u32>,
  pub diskSizeMb: Option<u32>,
}

#[allow(non_snake_case)]
#[napi(object)]
pub struct SeaWorkExecOptions {
  pub cwd: Option<String>,
  pub env: Option<HashMap<String, String>>,
}

#[allow(non_snake_case)]
#[napi(object)]
pub struct SeaWorkHealth {
  pub ready: bool,
  pub admissionsOpen: bool,
  pub stableCode: String,
  pub bundleReady: bool,
}

#[napi]
pub struct SeaWorkService {
  #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
  client: Arc<Mutex<lsb_service_client::ServiceClient>>,
}

#[napi]
impl SeaWorkService {
  #[napi(factory)]
  pub async fn connect() -> Result<Self> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
      let client = lsb_service_client::connect(lsb_service_client::ConnectOptions::default())
        .await
        .map_err(service_error)?;
      return Ok(Self {
        client: Arc::new(Mutex::new(client)),
      });
    }
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    Err(unsupported_platform_error())
  }

  #[napi]
  pub async fn health(&self) -> Result<SeaWorkHealth> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
      let health = self
        .client
        .lock()
        .await
        .health_check()
        .await
        .map_err(service_error)?;
      return Ok(SeaWorkHealth {
        ready: health.ready,
        admissionsOpen: health.admissions_open,
        stableCode: health.stable_code,
        bundleReady: matches!(health.bundle, lsb_service_proto::HealthState::Ready),
      });
    }
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    Err(unsupported_platform_error())
  }

  #[napi]
  pub async fn start(&self, opts: Option<SeaWorkStartOptions>) -> Result<SeaWorkSandbox> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
      let opts = opts.unwrap_or(SeaWorkStartOptions {
        cpus: None,
        memoryMb: None,
        diskSizeMb: None,
      });
      let start = lsb_service_client::StartSandboxOptions {
        cpus: u16::try_from(opts.cpus.unwrap_or(2))
          .map_err(|_| napi::Error::from_reason("cpus is out of range"))?,
        memory_mib: opts.memoryMb.unwrap_or(2048),
        disk_mib: opts.diskSizeMb.unwrap_or(4096),
        ..lsb_service_client::StartSandboxOptions::default()
      };
      let sandbox = self
        .client
        .lock()
        .await
        .start_sandbox(start)
        .await
        .map_err(service_error)?;
      return Ok(SeaWorkSandbox {
        client: self.client.clone(),
        sandbox: Arc::new(sandbox),
      });
    }
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    {
      let _ = opts;
      Err(unsupported_platform_error())
    }
  }

  #[napi]
  pub async fn close(&self) -> Result<()> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    return self
      .client
      .lock()
      .await
      .close_session()
      .await
      .map_err(service_error);
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    Err(unsupported_platform_error())
  }
}

#[napi]
pub struct SeaWorkSandbox {
  #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
  client: Arc<Mutex<lsb_service_client::ServiceClient>>,
  #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
  sandbox: Arc<lsb_service_client::RemoteSandbox>,
}

#[napi]
impl SeaWorkSandbox {
  #[napi(getter)]
  pub fn id(&self) -> Result<String> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    return Ok(self.sandbox.id().to_string());
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    Err(unsupported_platform_error())
  }

  #[napi]
  pub async fn exec(
    &self,
    command: Either<String, Vec<String>>,
    opts: Option<SeaWorkExecOptions>,
  ) -> Result<ExecResult> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
      let opts = opts.unwrap_or(SeaWorkExecOptions {
        cwd: None,
        env: None,
      });
      let command = match command {
        Either::A(shell) => lsb_service_client::RemoteCommand::Shell(shell),
        Either::B(argv) => lsb_service_client::RemoteCommand::Argv(argv),
      };
      let result = self
        .client
        .lock()
        .await
        .exec(
          &self.sandbox,
          command,
          lsb_service_client::ExecOptions {
            cwd: opts.cwd,
            env: opts
              .env
              .unwrap_or_default()
              .into_iter()
              .collect::<BTreeMap<_, _>>(),
          },
        )
        .await
        .map_err(service_error)?;
      return Ok(ExecResult {
        stdout: result.stdout,
        stderr: result.stderr,
        exitCode: result.exit_code,
      });
    }
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    {
      let _ = command;
      let _ = opts;
      Err(unsupported_platform_error())
    }
  }

  #[napi]
  pub async fn mkdir(&self, path: String, opts: Option<MkdirOptions>) -> Result<()> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    return self
      .client
      .lock()
      .await
      .mkdir(
        &self.sandbox,
        path,
        opts.and_then(|v| v.recursive).unwrap_or(true),
      )
      .await
      .map_err(service_error);
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    {
      let _ = path;
      let _ = opts;
      Err(unsupported_platform_error())
    }
  }

  #[napi]
  pub async fn read_dir(&self, path: String) -> Result<Vec<DirEntry>> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    return self
      .client
      .lock()
      .await
      .read_dir(&self.sandbox, path)
      .await
      .map_err(service_error)
      .map(|entries| {
        entries
          .into_iter()
          .map(|entry| DirEntry {
            name: entry.name,
            r#type: entry.entry_type,
            size: entry.size as f64,
          })
          .collect()
      });
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    {
      let _ = path;
      Err(unsupported_platform_error())
    }
  }

  #[napi]
  pub async fn stat(&self, path: String) -> Result<StatResult> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    return self
      .client
      .lock()
      .await
      .stat(&self.sandbox, path)
      .await
      .map_err(service_error)
      .map(|stat| StatResult {
        size: stat.size as f64,
        mode: stat.mode,
        mtime: stat.mtime as f64,
        isDir: stat.is_dir,
        isFile: stat.is_file,
        isSymlink: stat.is_symlink,
      });
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    {
      let _ = path;
      Err(unsupported_platform_error())
    }
  }

  #[napi]
  pub async fn remove(&self, path: String, opts: Option<RemoveOptions>) -> Result<()> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    return self
      .client
      .lock()
      .await
      .remove(
        &self.sandbox,
        path,
        opts.and_then(|v| v.recursive).unwrap_or(false),
      )
      .await
      .map_err(service_error);
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    {
      let _ = path;
      let _ = opts;
      Err(unsupported_platform_error())
    }
  }

  #[napi]
  pub async fn rename(&self, old_path: String, new_path: String) -> Result<()> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    return self
      .client
      .lock()
      .await
      .rename(&self.sandbox, old_path, new_path)
      .await
      .map_err(service_error);
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    {
      let _ = old_path;
      let _ = new_path;
      Err(unsupported_platform_error())
    }
  }

  #[napi]
  pub async fn copy(&self, src: String, dst: String, opts: Option<CopyOptions>) -> Result<()> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    return self
      .client
      .lock()
      .await
      .copy(
        &self.sandbox,
        src,
        dst,
        opts.and_then(|v| v.recursive).unwrap_or(false),
      )
      .await
      .map_err(service_error);
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    {
      let _ = src;
      let _ = dst;
      let _ = opts;
      Err(unsupported_platform_error())
    }
  }

  #[napi]
  pub async fn chmod(&self, path: String, mode: u32) -> Result<()> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    return self
      .client
      .lock()
      .await
      .chmod(&self.sandbox, path, mode)
      .await
      .map_err(service_error);
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    {
      let _ = path;
      let _ = mode;
      Err(unsupported_platform_error())
    }
  }

  #[napi]
  pub async fn exists(&self, path: String) -> Result<bool> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    return self
      .client
      .lock()
      .await
      .exists(&self.sandbox, path)
      .await
      .map_err(service_error);
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    {
      let _ = path;
      Err(unsupported_platform_error())
    }
  }

  #[napi]
  pub async fn stop(&self) -> Result<()> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    return self
      .client
      .lock()
      .await
      .stop_sandbox(&self.sandbox)
      .await
      .map_err(service_error);
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    Err(unsupported_platform_error())
  }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn service_error(error: lsb_service_client::ClientError) -> napi::Error {
  napi::Error::from_reason(error.to_string())
}
