use napi::bindgen_prelude::{Buffer, Either, Result, Uint8Array};
use napi_derive::napi;

#[cfg(lsb_nodejs_supported)]
use std::sync::Arc;

#[cfg(lsb_nodejs_supported)]
use crate::config::{
  build_command_argv, build_interception_policy, build_sandbox_config, command_options,
  map_dir_entry, map_exec_result, map_stat_result,
};
#[cfg(lsb_nodejs_supported)]
use crate::error::to_napi_error;
#[cfg(not(lsb_nodejs_supported))]
use crate::error::unsupported_platform_error;
use crate::process::SpawnedProcess;
use crate::streams::WatchStream;
use crate::types::{
  CopyOptions, DirEntry, ExecOptions, ExecResult, MkdirOptions, NetworkInterceptionUpdate,
  RemoveOptions, SpawnOptions, StartOptions, StatResult, WatchOptions,
};

// Public Sandbox class exposed to Node. Methods intentionally delegate to
// lsb_sdk and keep only JS type conversion/error mapping in this layer.
/// Running sandbox VM instance.
///
/// Usage: `const sandbox = await Sandbox.start(); await sandbox.stop()`
#[napi]
pub struct Sandbox {
  #[cfg(lsb_nodejs_supported)]
  inner: Arc<lsb_sdk::AsyncSandbox>,
}

#[napi]
impl Sandbox {
  /// Replace all live network secrets and HTTPS request-header rules.
  #[napi]
  pub async fn update_network_interception(&self, update: NetworkInterceptionUpdate) -> Result<()> {
    #[cfg(lsb_nodejs_supported)]
    {
      let policy = build_interception_policy(update).map_err(to_napi_error)?;
      return self
        .inner
        .update_network_interception(policy)
        .await
        .map_err(to_napi_error);
    }
    #[cfg(not(lsb_nodejs_supported))]
    {
      let _ = update;
      Err(unsupported_platform_error())
    }
  }

  /// Boot a new sandbox VM.
  ///
  /// Usage: `const sandbox = await Sandbox.start({ cpus: 2, mounts: [{ type: 'overlay', hostPath: '.', guestPath: '/workspace' }] })`
  #[napi(factory)]
  pub async fn start(opts: Option<StartOptions>) -> Result<Self> {
    #[cfg(lsb_nodejs_supported)]
    {
      let config = build_sandbox_config(opts.unwrap_or_default()).map_err(to_napi_error)?;
      let inner = lsb_sdk::AsyncSandbox::boot(config)
        .await
        .map_err(to_napi_error)?;
      return Ok(Self {
        inner: Arc::new(inner),
      });
    }

    #[cfg(not(lsb_nodejs_supported))]
    {
      let _ = opts;
      Err(unsupported_platform_error())
    }
  }

  /// Execute a command and wait for stdout, stderr, and exit code.
  ///
  /// Usage: `const result = await sandbox.exec('npm test', { cwd: '/workspace' })`
  #[napi]
  pub async fn exec(
    &self,
    command: Either<String, Vec<String>>,
    opts: Option<ExecOptions>,
  ) -> Result<ExecResult> {
    #[cfg(lsb_nodejs_supported)]
    {
      let opts = opts.unwrap_or_default();
      let argv = build_command_argv(command, opts.shell);
      let argv_refs = argv.iter().map(String::as_str).collect::<Vec<_>>();
      let result = self
        .inner
        .exec_with_options(&argv_refs, command_options(opts.cwd, opts.env))
        .await
        .map_err(to_napi_error)?;
      return Ok(map_exec_result(result));
    }

    #[cfg(not(lsb_nodejs_supported))]
    {
      let _ = command;
      let _ = opts;
      Err(unsupported_platform_error())
    }
  }

  /// Execute a shell command string with the SDK shell runner.
  ///
  /// Usage: `const result = await sandbox.execShell('echo $PWD && ls', { cwd: '/workspace' })`
  #[napi]
  pub async fn exec_shell(&self, command: String, opts: Option<ExecOptions>) -> Result<ExecResult> {
    #[cfg(lsb_nodejs_supported)]
    {
      let opts = opts.unwrap_or_default();
      let result = self
        .inner
        .exec_shell_with_options(&command, command_options(opts.cwd, opts.env))
        .await
        .map_err(to_napi_error)?;
      return Ok(map_exec_result(result));
    }

    #[cfg(not(lsb_nodejs_supported))]
    {
      let _ = command;
      let _ = opts;
      Err(unsupported_platform_error())
    }
  }

  /// Start a long-running process with streamable stdout and stderr.
  ///
  /// Usage: `const proc = await sandbox.spawn(['node', 'server.js'], { cwd: '/workspace' })`
  #[napi]
  pub async fn spawn(
    &self,
    command: Either<String, Vec<String>>,
    opts: Option<SpawnOptions>,
  ) -> Result<SpawnedProcess> {
    #[cfg(lsb_nodejs_supported)]
    {
      let opts = opts.unwrap_or_default();
      let argv = build_command_argv(command, opts.shell);
      let argv_refs = argv.iter().map(String::as_str).collect::<Vec<_>>();
      let process = self
        .inner
        .spawn(&argv_refs, command_options(opts.cwd, opts.env))
        .await
        .map_err(to_napi_error)?;

      return SpawnedProcess::from_process(process);
    }

    #[cfg(not(lsb_nodejs_supported))]
    {
      let _ = command;
      let _ = opts;
      Err(unsupported_platform_error())
    }
  }

  /// Watch a guest path for file changes.
  ///
  /// Usage: `for await (const event of await sandbox.watch('/workspace')) console.log(event.path, event.event)`
  #[napi]
  pub async fn watch(&self, path: String, opts: Option<WatchOptions>) -> Result<WatchStream> {
    #[cfg(lsb_nodejs_supported)]
    {
      let recursive = opts.and_then(|value| value.recursive).unwrap_or(true);
      let watch = self
        .inner
        .watch(&path, recursive)
        .await
        .map_err(to_napi_error)?;
      return Ok(WatchStream {
        handle: Arc::new(tokio::sync::Mutex::new(watch)),
      });
    }

    #[cfg(not(lsb_nodejs_supported))]
    {
      let _ = path;
      let _ = opts;
      Err(unsupported_platform_error())
    }
  }

  /// Read a guest file as a Buffer.
  ///
  /// Usage: `const content = await sandbox.readFile('/workspace/package.json')`
  #[napi]
  pub async fn read_file(&self, path: String) -> Result<Buffer> {
    #[cfg(lsb_nodejs_supported)]
    {
      let content = self.inner.read_file(&path).await.map_err(to_napi_error)?;
      return Ok(Buffer::from(content));
    }

    #[cfg(not(lsb_nodejs_supported))]
    {
      let _ = path;
      Err(unsupported_platform_error())
    }
  }

  /// Write a string or Uint8Array to a guest file.
  ///
  /// Usage: `await sandbox.writeFile('/tmp/input.txt', 'hello')`
  #[napi]
  pub async fn write_file(&self, path: String, content: Either<String, Uint8Array>) -> Result<()> {
    #[cfg(lsb_nodejs_supported)]
    {
      let content = match content {
        Either::A(text) => text.into_bytes(),
        Either::B(bytes) => bytes.to_vec(),
      };
      self
        .inner
        .write_file(&path, &content)
        .await
        .map_err(to_napi_error)?;
      return Ok(());
    }

    #[cfg(not(lsb_nodejs_supported))]
    {
      let _ = path;
      let _ = content;
      Err(unsupported_platform_error())
    }
  }

  /// Create a guest directory.
  ///
  /// Usage: `await sandbox.mkdir('/workspace/out', { recursive: true })`
  #[napi]
  pub async fn mkdir(&self, path: String, opts: Option<MkdirOptions>) -> Result<()> {
    #[cfg(lsb_nodejs_supported)]
    {
      self
        .inner
        .mkdir(
          &path,
          opts.and_then(|value| value.recursive).unwrap_or(true),
        )
        .await
        .map_err(to_napi_error)?;
      return Ok(());
    }

    #[cfg(not(lsb_nodejs_supported))]
    {
      let _ = path;
      let _ = opts;
      Err(unsupported_platform_error())
    }
  }

  /// List entries in a guest directory.
  ///
  /// Usage: `const entries = await sandbox.readDir('/workspace')`
  #[napi]
  pub async fn read_dir(&self, path: String) -> Result<Vec<DirEntry>> {
    #[cfg(lsb_nodejs_supported)]
    {
      let response = self.inner.read_dir(&path).await.map_err(to_napi_error)?;
      return Ok(response.entries.into_iter().map(map_dir_entry).collect());
    }

    #[cfg(not(lsb_nodejs_supported))]
    {
      let _ = path;
      Err(unsupported_platform_error())
    }
  }

  /// Return metadata for a guest path.
  ///
  /// Usage: `const stat = await sandbox.stat('/workspace/package.json')`
  #[napi]
  pub async fn stat(&self, path: String) -> Result<StatResult> {
    #[cfg(lsb_nodejs_supported)]
    {
      let stat = self.inner.stat(&path).await.map_err(to_napi_error)?;
      return Ok(map_stat_result(stat));
    }

    #[cfg(not(lsb_nodejs_supported))]
    {
      let _ = path;
      Err(unsupported_platform_error())
    }
  }

  /// Remove a guest file or directory.
  ///
  /// Usage: `await sandbox.remove('/workspace/out', { recursive: true })`
  #[napi]
  pub async fn remove(&self, path: String, opts: Option<RemoveOptions>) -> Result<()> {
    #[cfg(lsb_nodejs_supported)]
    {
      self
        .inner
        .remove(
          &path,
          opts.and_then(|value| value.recursive).unwrap_or(false),
        )
        .await
        .map_err(to_napi_error)?;
      return Ok(());
    }

    #[cfg(not(lsb_nodejs_supported))]
    {
      let _ = path;
      let _ = opts;
      Err(unsupported_platform_error())
    }
  }

  /// Rename or move a guest file or directory.
  ///
  /// Usage: `await sandbox.rename('/tmp/a.txt', '/tmp/b.txt')`
  #[napi]
  pub async fn rename(&self, old_path: String, new_path: String) -> Result<()> {
    #[cfg(lsb_nodejs_supported)]
    {
      self
        .inner
        .rename(&old_path, &new_path)
        .await
        .map_err(to_napi_error)?;
      return Ok(());
    }

    #[cfg(not(lsb_nodejs_supported))]
    {
      let _ = old_path;
      let _ = new_path;
      Err(unsupported_platform_error())
    }
  }

  /// Copy a guest file or directory.
  ///
  /// Usage: `await sandbox.copy('/workspace/src', '/workspace/src-copy', { recursive: true })`
  #[napi]
  pub async fn copy(&self, src: String, dst: String, opts: Option<CopyOptions>) -> Result<()> {
    #[cfg(lsb_nodejs_supported)]
    {
      self
        .inner
        .copy(
          &src,
          &dst,
          opts.and_then(|value| value.recursive).unwrap_or(false),
        )
        .await
        .map_err(to_napi_error)?;
      return Ok(());
    }

    #[cfg(not(lsb_nodejs_supported))]
    {
      let _ = src;
      let _ = dst;
      let _ = opts;
      Err(unsupported_platform_error())
    }
  }

  /// Change permission bits on a guest path.
  ///
  /// Usage: `await sandbox.chmod('/workspace/script.sh', 0o755)`
  #[napi]
  pub async fn chmod(&self, path: String, mode: u32) -> Result<()> {
    #[cfg(lsb_nodejs_supported)]
    {
      self.inner.chmod(&path, mode).await.map_err(to_napi_error)?;
      return Ok(());
    }

    #[cfg(not(lsb_nodejs_supported))]
    {
      let _ = path;
      let _ = mode;
      Err(unsupported_platform_error())
    }
  }

  /// Check whether a guest path exists.
  ///
  /// Usage: `if (await sandbox.exists('/workspace/package.json')) console.log('found')`
  #[napi]
  pub async fn exists(&self, path: String) -> Result<bool> {
    #[cfg(lsb_nodejs_supported)]
    {
      return self.inner.exists(&path).await.map_err(to_napi_error);
    }

    #[cfg(not(lsb_nodejs_supported))]
    {
      let _ = path;
      Err(unsupported_platform_error())
    }
  }

  /// Save a named VM checkpoint that can be used with `Sandbox.start({ from })`.
  ///
  /// Usage: `await sandbox.checkpoint('deps-installed')`
  #[napi]
  pub async fn checkpoint(&self, name: String) -> Result<()> {
    #[cfg(lsb_nodejs_supported)]
    {
      self.inner.checkpoint(&name).await.map_err(to_napi_error)?;
      return Ok(());
    }

    #[cfg(not(lsb_nodejs_supported))]
    {
      let _ = name;
      Err(unsupported_platform_error())
    }
  }

  /// Stop the sandbox VM and release runtime resources.
  ///
  /// Usage: `await sandbox.stop()`
  #[napi]
  pub async fn stop(&self) -> Result<()> {
    #[cfg(lsb_nodejs_supported)]
    {
      self.inner.stop().await.map_err(to_napi_error)?;
      return Ok(());
    }

    #[cfg(not(lsb_nodejs_supported))]
    {
      Err(unsupported_platform_error())
    }
  }

  /// Absolute host path for this sandbox instance directory.
  ///
  /// Usage: `console.log(sandbox.instanceDir)`
  #[napi(getter)]
  pub fn instance_dir(&self) -> Result<String> {
    #[cfg(lsb_nodejs_supported)]
    {
      return Ok(self.inner.instance_dir().to_string());
    }

    #[cfg(not(lsb_nodejs_supported))]
    {
      Err(unsupported_platform_error())
    }
  }
}
