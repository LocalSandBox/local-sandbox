use std::collections::HashMap;

use napi::bindgen_prelude::{Buffer, Either, Result, Uint8Array};
use napi_derive::napi;

use crate::types::{
  CopyOptions, DirEntry, ExecResult, FileChangeEvent, MkdirOptions, RemoveOptions, StatResult,
  WatchOptions,
};
#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
use napi::Status;

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use std::collections::BTreeMap;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use std::sync::Arc;

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
fn unsupported_platform_error() -> napi::Error {
  napi::Error::new(
    Status::GenericFailure,
    "SeaWork service is supported only on Windows 11 x86-64".to_string(),
  )
}
#[allow(non_snake_case)]
#[napi(object)]
pub struct SeaWorkServiceConnectOptions {
  pub connectTimeoutMs: Option<u32>,
}

#[allow(non_snake_case)]
#[napi(object)]
pub struct SeaWorkStartOptions {
  /// Correlation/cache hint only; never a service path or caller-selected resource.
  pub instanceId: Option<String>,
  /// Legacy checkpoint name. Non-empty values return CHECKPOINT_UNSUPPORTED.
  pub from: Option<String>,
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

#[allow(non_snake_case)]
#[napi(object)]
pub struct SeaWorkCapabilities {
  pub directMount: bool,
  pub directMountBackends: Vec<String>,
  pub watch: bool,
  pub ports: bool,
}

#[napi(object)]
pub struct SeaWorkNegotiatedProtocol {
  pub major: u32,
  pub minor: u32,
  pub features: Vec<String>,
}

#[allow(non_snake_case)]
#[napi(object)]
pub struct SeaWorkServiceInfo {
  pub serviceVersion: String,
  pub protocol: SeaWorkNegotiatedProtocol,
  pub bundleVersion: String,
  pub capabilities: SeaWorkCapabilities,
}

#[allow(non_snake_case)]
#[napi(object)]
pub struct SeaWorkServiceHealth {
  pub ready: bool,
  pub admissionsOpen: bool,
  pub stableCode: String,
  pub serviceInfo: SeaWorkServiceInfo,
}

#[allow(non_snake_case)]
#[napi(object)]
pub struct SeaWorkProtocolRange {
  pub major: u32,
  pub minMinor: u32,
  pub maxMinor: u32,
}

#[allow(non_snake_case)]
#[napi(object)]
pub struct SeaWorkUninstallPreparation {
  pub clean: bool,
  pub quarantineIds: Vec<String>,
}

#[napi]
pub struct SeaWorkService {
  #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
  client: Arc<lsb_service_client::ServiceClient>,
}

#[napi]
impl SeaWorkService {
  async fn connect_with_options(options: Option<SeaWorkServiceConnectOptions>) -> Result<Self> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
      let timeout_ms = options
        .and_then(|options| options.connectTimeoutMs)
        .unwrap_or(10_000);
      if !(1..=60_000).contains(&timeout_ms) {
        return Err(napi::Error::from_reason(
          "connectTimeoutMs must be between 1 and 60000",
        ));
      }
      let client = lsb_service_client::connect(lsb_service_client::ConnectOptions {
        timeout: std::time::Duration::from_millis(u64::from(timeout_ms)),
      })
      .await
      .map_err(service_error)?;
      Ok(Self {
        client: Arc::new(client),
      })
    }
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    {
      let _ = options;
      Err(unsupported_platform_error())
    }
  }

  #[napi(factory)]
  pub async fn connect() -> Result<Self> {
    Self::connect_with_options(None).await
  }

  #[napi]
  pub async fn get_service_info(&self) -> Result<SeaWorkServiceInfo> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
      let client = &self.client;
      let info = client.get_service_info().await.map_err(service_error)?;
      let protocol = client.negotiated_protocol();
      Ok(map_service_info(info, protocol))
    }
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    Err(unsupported_platform_error())
  }

  #[napi]
  pub async fn health_check(&self) -> Result<SeaWorkServiceHealth> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
      let client = &self.client;
      let health = client.health_check().await.map_err(service_error)?;
      let info = client.get_service_info().await.map_err(service_error)?;
      let protocol = client.negotiated_protocol();
      Ok(SeaWorkServiceHealth {
        ready: health.ready,
        admissionsOpen: health.admissions_open,
        stableCode: health.stable_code,
        serviceInfo: map_service_info(info, protocol),
      })
    }
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    Err(unsupported_platform_error())
  }

  #[napi]
  pub async fn health(&self) -> Result<SeaWorkHealth> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
      let health = self.client.health_check().await.map_err(service_error)?;
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
  pub async fn prepare_update(
    &self,
    target_bundle: String,
    target_protocol_range: SeaWorkProtocolRange,
  ) -> Result<String> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
      let range = lsb_service_proto::ProtocolRange {
        major: u16::try_from(target_protocol_range.major)
          .map_err(|_| napi::Error::from_reason("protocol major is out of range"))?,
        min_minor: u16::try_from(target_protocol_range.minMinor)
          .map_err(|_| napi::Error::from_reason("protocol minimum is out of range"))?,
        max_minor: u16::try_from(target_protocol_range.maxMinor)
          .map_err(|_| napi::Error::from_reason("protocol maximum is out of range"))?,
      };
      return self
        .client
        .prepare_update(target_bundle, range)
        .await
        .map_err(service_error);
    }
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    {
      let _ = target_bundle;
      let _ = target_protocol_range;
      Err(unsupported_platform_error())
    }
  }

  #[napi]
  pub async fn commit_update(&self, update_id: String) -> Result<()> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    return self
      .client
      .commit_update(update_id)
      .await
      .map_err(service_error);
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    {
      let _ = update_id;
      Err(unsupported_platform_error())
    }
  }

  #[napi]
  pub async fn abort_update(&self, update_id: String) -> Result<()> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    return self
      .client
      .abort_update(update_id)
      .await
      .map_err(service_error);
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    {
      let _ = update_id;
      Err(unsupported_platform_error())
    }
  }

  #[napi]
  pub async fn prepare_uninstall(&self) -> Result<SeaWorkUninstallPreparation> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
      let preparation = self
        .client
        .prepare_uninstall()
        .await
        .map_err(service_error)?;
      return Ok(SeaWorkUninstallPreparation {
        clean: preparation.clean,
        quarantineIds: preparation.quarantine_ids,
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
        instanceId: None,
        from: None,
        cpus: None,
        memoryMb: None,
        diskSizeMb: None,
      });
      let start = lsb_service_client::StartSandboxOptions {
        client_instance_id: opts.instanceId,
        from: opts.from,
        cpus: u16::try_from(opts.cpus.unwrap_or(2))
          .map_err(|_| napi::Error::from_reason("cpus is out of range"))?,
        memory_mib: opts.memoryMb.unwrap_or(2048),
        disk_mib: opts.diskSizeMb.unwrap_or(4096),
        ..lsb_service_client::StartSandboxOptions::default()
      };
      let sandbox = self
        .client
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
  pub async fn start_sandbox(&self, options: SeaWorkStartOptions) -> Result<SeaWorkSandbox> {
    self.start(Some(options)).await
  }

  #[napi]
  pub async fn close(&self) -> Result<()> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    return self.client.close_session().await.map_err(service_error);
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    Err(unsupported_platform_error())
  }
}

#[napi(js_name = "connectSeaWorkService")]
pub async fn connect_seawork_service(
  options: Option<SeaWorkServiceConnectOptions>,
) -> Result<SeaWorkService> {
  SeaWorkService::connect_with_options(options).await
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn map_service_info(
  info: lsb_service_proto::ServiceInfo,
  protocol: lsb_service_proto::ProtocolVersion,
) -> SeaWorkServiceInfo {
  SeaWorkServiceInfo {
    serviceVersion: info.service_version,
    protocol: SeaWorkNegotiatedProtocol {
      major: u32::from(protocol.major),
      minor: u32::from(protocol.minor),
      features: Vec::new(),
    },
    bundleVersion: info.bundle_version,
    capabilities: SeaWorkCapabilities {
      directMount: info.capabilities.direct_mount,
      directMountBackends: info.capabilities.direct_mount_backends,
      watch: info.capabilities.watch,
      ports: info.capabilities.ports,
    },
  }
}

#[napi]
pub struct SeaWorkSandbox {
  #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
  client: Arc<lsb_service_client::ServiceClient>,
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
  pub async fn begin_exec(
    &self,
    command: Either<String, Vec<String>>,
    opts: Option<SeaWorkExecOptions>,
  ) -> Result<SeaWorkExecOperation> {
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
      let operation = self
        .client
        .begin_exec(
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
      return Ok(SeaWorkExecOperation {
        operation: Arc::new(operation),
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
  pub async fn spawn(
    &self,
    command: Either<String, Vec<String>>,
    opts: Option<SeaWorkExecOptions>,
  ) -> Result<SeaWorkProcess> {
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
      let process = self
        .client
        .spawn(
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
      return Ok(SeaWorkProcess {
        process: Arc::new(process),
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
  pub async fn watch(&self, path: String, opts: Option<WatchOptions>) -> Result<SeaWorkWatch> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
      let watch = self
        .client
        .watch(
          &self.sandbox,
          path,
          opts.and_then(|value| value.recursive).unwrap_or(true),
        )
        .await
        .map_err(service_error)?;
      return Ok(SeaWorkWatch {
        watch: Arc::new(watch),
      });
    }
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    {
      let _ = path;
      let _ = opts;
      Err(unsupported_platform_error())
    }
  }

  #[napi]
  pub async fn mkdir(&self, path: String, opts: Option<MkdirOptions>) -> Result<()> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    return self
      .client
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
  pub async fn read_file(&self, path: String) -> Result<Buffer> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    return self
      .client
      .read_file(&self.sandbox, path)
      .await
      .map(Buffer::from)
      .map_err(service_error);
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    {
      let _ = path;
      Err(unsupported_platform_error())
    }
  }

  #[napi]
  pub async fn write_file(&self, path: String, content: Either<String, Uint8Array>) -> Result<()> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
      let bytes = match content {
        Either::A(text) => text.into_bytes(),
        Either::B(bytes) => bytes.to_vec(),
      };
      return self
        .client
        .write_file(&self.sandbox, path, &bytes)
        .await
        .map_err(service_error);
    }
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    {
      let _ = path;
      let _ = content;
      Err(unsupported_platform_error())
    }
  }

  #[napi]
  pub async fn stop(&self) -> Result<()> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    return self
      .client
      .stop_sandbox(&self.sandbox)
      .await
      .map_err(service_error);
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    Err(unsupported_platform_error())
  }
}

#[napi]
pub struct SeaWorkProcess {
  #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
  process: Arc<lsb_service_client::RemoteProcess>,
}

#[napi]
pub struct SeaWorkExecOperation {
  #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
  operation: Arc<lsb_service_client::RemoteExecOperation>,
}

#[napi]
impl SeaWorkExecOperation {
  #[napi(getter)]
  pub fn id(&self) -> Result<String> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    return Ok(self.operation.id().to_string());
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    Err(unsupported_platform_error())
  }

  #[napi]
  pub async fn cancel(&self) -> Result<()> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    return self.operation.cancel().await.map_err(service_error);
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    Err(unsupported_platform_error())
  }

  #[napi]
  pub async fn complete(&self) -> Result<ExecResult> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    return self
      .operation
      .complete()
      .await
      .map(|result| ExecResult {
        stdout: result.stdout,
        stderr: result.stderr,
        exitCode: result.exit_code,
      })
      .map_err(service_error);
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    Err(unsupported_platform_error())
  }
}

#[napi]
pub struct SeaWorkWatch {
  #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
  watch: Arc<lsb_service_client::RemoteWatch>,
}

#[napi]
impl SeaWorkWatch {
  #[napi(getter)]
  pub fn id(&self) -> Result<String> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    return Ok(self.watch.id().to_string());
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    Err(unsupported_platform_error())
  }

  #[napi]
  pub async fn next(&self) -> Result<Option<FileChangeEvent>> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    return self
      .watch
      .next()
      .await
      .map(|event| {
        event.map(|event| FileChangeEvent {
          path: event.path,
          event: match event.change {
            lsb_service_proto::WatchChange::Created => "create",
            lsb_service_proto::WatchChange::Modified => "modify",
            lsb_service_proto::WatchChange::Removed => "delete",
            lsb_service_proto::WatchChange::Renamed => "rename",
            lsb_service_proto::WatchChange::Overflow => "overflow",
          }
          .to_string(),
        })
      })
      .map_err(service_error);
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    Err(unsupported_platform_error())
  }

  #[napi]
  pub async fn stop(&self) -> Result<()> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    return self.watch.stop().await.map_err(service_error);
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    Err(unsupported_platform_error())
  }
}

#[napi]
impl SeaWorkProcess {
  #[napi(getter)]
  pub fn id(&self) -> Result<String> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    return Ok(self.process.id().to_string());
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    Err(unsupported_platform_error())
  }

  #[napi]
  pub async fn next_stdout(&self) -> Result<Option<Buffer>> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    return self
      .process
      .next_stdout()
      .await
      .map(|chunk| chunk.map(Buffer::from))
      .map_err(service_error);
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    Err(unsupported_platform_error())
  }

  #[napi]
  pub async fn next_stderr(&self) -> Result<Option<Buffer>> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    return self
      .process
      .next_stderr()
      .await
      .map(|chunk| chunk.map(Buffer::from))
      .map_err(service_error);
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    Err(unsupported_platform_error())
  }

  #[napi]
  pub async fn kill(&self) -> Result<()> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    return self.process.kill().await.map_err(service_error);
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    Err(unsupported_platform_error())
  }

  #[napi(getter)]
  pub async fn exited(&self) -> Result<i32> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    return self.process.exited().await.map_err(service_error);
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    Err(unsupported_platform_error())
  }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn service_error(error: lsb_service_client::ClientError) -> napi::Error {
  napi::Error::from_reason(error.to_string())
}
