#![deny(clippy::all)]
#![allow(non_snake_case)]

use std::collections::HashMap;

use napi::bindgen_prelude::{Buffer, Either, Function, Result, Uint8Array, Unknown};
use napi::{Error, Status};
use napi_derive::napi;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use anyhow::{bail, Context};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use napi::threadsafe_function::{
  ThreadsafeCallContext, ThreadsafeFunction, ThreadsafeFunctionCallMode,
};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use shuru_sdk::{
  DirEntry as NativeDirEntry, MountConfig, PortMapping, SandboxConfig,
  SecretConfig as NativeSecretConfig, StatResponse as NativeStatResponse,
};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use shuru_vm::PortForwardHandle;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use tokio::sync::{oneshot, watch};

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use std::io::BufReader;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use std::net::TcpStream;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use std::sync::{Arc, Mutex};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use std::time::Duration;

#[allow(non_snake_case)]
#[napi(object)]
pub struct SecretConfig {
  pub value: String,
  pub hosts: Vec<String>,
}

#[allow(non_snake_case)]
#[napi(object)]
pub struct NetworkConfig {
  pub allow: Option<Vec<String>>,
}

#[allow(non_snake_case)]
#[napi(object)]
pub struct StartOptions {
  pub from: Option<String>,
  pub cpus: Option<u32>,
  pub memory: Option<u32>,
  pub diskSize: Option<u32>,
  pub dataDir: Option<String>,
  pub allowNet: Option<bool>,
  pub allowedHosts: Option<Vec<String>>,
  pub ports: Option<Vec<String>>,
  pub mounts: Option<HashMap<String, String>>,
  pub secrets: Option<HashMap<String, SecretConfig>>,
  pub network: Option<NetworkConfig>,
}

#[allow(non_snake_case)]
#[napi(object)]
pub struct ExecOptions {
  pub shell: Option<String>,
}

#[allow(non_snake_case)]
#[napi(object)]
pub struct SpawnOptions {
  pub cwd: Option<String>,
  pub env: Option<HashMap<String, String>>,
  pub shell: Option<String>,
}

#[allow(non_snake_case)]
#[napi(object)]
pub struct WatchOptions {
  pub recursive: Option<bool>,
}

#[allow(non_snake_case)]
#[napi(object)]
pub struct MkdirOptions {
  pub recursive: Option<bool>,
}

#[allow(non_snake_case)]
#[napi(object)]
pub struct RemoveOptions {
  pub recursive: Option<bool>,
}

#[allow(non_snake_case)]
#[napi(object)]
pub struct CopyOptions {
  pub recursive: Option<bool>,
}

#[allow(non_snake_case)]
#[napi(object)]
pub struct ExecResult {
  pub stdout: String,
  pub stderr: String,
  pub exitCode: i32,
}

#[napi(object)]
pub struct DirEntry {
  pub name: String,
  pub r#type: String,
  pub size: f64,
}

#[allow(non_snake_case)]
#[napi(object)]
pub struct StatResult {
  pub size: f64,
  pub mode: u32,
  pub mtime: f64,
  pub isDir: bool,
  pub isFile: bool,
  pub isSymlink: bool,
}

#[allow(non_snake_case)]
#[napi(object)]
pub struct FileChangeEvent {
  pub path: String,
  pub event: String,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
type BufferThreadsafeFunction =
  ThreadsafeFunction<Vec<u8>, Unknown<'static>, Buffer, Status, false>;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
type ExitThreadsafeFunction = ThreadsafeFunction<i32, Unknown<'static>, i32, Status, false>;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
enum VmCommand {
  Exec {
    argv: Vec<String>,
    reply: oneshot::Sender<anyhow::Result<shuru_sdk::ExecResult>>,
  },
  ReadFile {
    path: String,
    reply: oneshot::Sender<anyhow::Result<Vec<u8>>>,
  },
  WriteFile {
    path: String,
    content: Vec<u8>,
    reply: oneshot::Sender<anyhow::Result<()>>,
  },
  ReadDir {
    path: String,
    reply: oneshot::Sender<anyhow::Result<shuru_proto::ReadDirResponse>>,
  },
  Stat {
    path: String,
    reply: oneshot::Sender<anyhow::Result<shuru_proto::StatResponse>>,
  },
  Mkdir {
    path: String,
    recursive: bool,
    reply: oneshot::Sender<anyhow::Result<()>>,
  },
  Remove {
    path: String,
    recursive: bool,
    reply: oneshot::Sender<anyhow::Result<()>>,
  },
  Rename {
    old_path: String,
    new_path: String,
    reply: oneshot::Sender<anyhow::Result<()>>,
  },
  Copy {
    src: String,
    dst: String,
    recursive: bool,
    reply: oneshot::Sender<anyhow::Result<()>>,
  },
  Chmod {
    path: String,
    mode: u32,
    reply: oneshot::Sender<anyhow::Result<()>>,
  },
  OpenExec {
    argv: Vec<String>,
    cwd: Option<String>,
    env: HashMap<String, String>,
    reply: oneshot::Sender<anyhow::Result<TcpStream>>,
  },
  OpenWatch {
    path: String,
    recursive: bool,
    reply: oneshot::Sender<anyhow::Result<TcpStream>>,
  },
  Checkpoint {
    name: String,
    reply: oneshot::Sender<anyhow::Result<()>>,
  },
  Stop {
    reply: oneshot::Sender<anyhow::Result<()>>,
  },
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct RuntimeSandbox {
  cmd_tx: std::sync::mpsc::Sender<VmCommand>,
  instance_dir: String,
  stopped: AtomicBool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl RuntimeSandbox {
  async fn boot(config: SandboxConfig) -> anyhow::Result<Self> {
    let (ready_tx, ready_rx) = oneshot::channel::<anyhow::Result<String>>();
    let (cmd_tx, cmd_rx) = std::sync::mpsc::channel();

    std::thread::Builder::new()
      .name("shuru-nodejs-vm".into())
      .spawn(move || match boot_vm(config) {
        Ok((sandbox, instance_dir, proxy_handle, fwd_handle)) => {
          if ready_tx.send(Ok(instance_dir.clone())).is_err() {
            return;
          }
          run_vm_loop(sandbox, &instance_dir, cmd_rx, proxy_handle, fwd_handle);
        }
        Err(error) => {
          let _ = ready_tx.send(Err(error));
        }
      })?;

    Ok(Self {
      cmd_tx,
      instance_dir: ready_rx.await??,
      stopped: AtomicBool::new(false),
    })
  }

  async fn exec(&self, argv: Vec<String>) -> anyhow::Result<shuru_sdk::ExecResult> {
    let (reply_tx, reply_rx) = oneshot::channel();
    self
      .cmd_tx
      .send(VmCommand::Exec {
        argv,
        reply: reply_tx,
      })
      .map_err(|_| anyhow::anyhow!("VM thread exited"))?;
    reply_rx.await?
  }

  async fn read_file(&self, path: String) -> anyhow::Result<Vec<u8>> {
    let (reply_tx, reply_rx) = oneshot::channel();
    self
      .cmd_tx
      .send(VmCommand::ReadFile {
        path,
        reply: reply_tx,
      })
      .map_err(|_| anyhow::anyhow!("VM thread exited"))?;
    reply_rx.await?
  }

  async fn write_file(&self, path: String, content: Vec<u8>) -> anyhow::Result<()> {
    let (reply_tx, reply_rx) = oneshot::channel();
    self
      .cmd_tx
      .send(VmCommand::WriteFile {
        path,
        content,
        reply: reply_tx,
      })
      .map_err(|_| anyhow::anyhow!("VM thread exited"))?;
    reply_rx.await?
  }

  async fn read_dir(&self, path: String) -> anyhow::Result<shuru_proto::ReadDirResponse> {
    let (reply_tx, reply_rx) = oneshot::channel();
    self
      .cmd_tx
      .send(VmCommand::ReadDir {
        path,
        reply: reply_tx,
      })
      .map_err(|_| anyhow::anyhow!("VM thread exited"))?;
    reply_rx.await?
  }

  async fn stat(&self, path: String) -> anyhow::Result<shuru_proto::StatResponse> {
    let (reply_tx, reply_rx) = oneshot::channel();
    self
      .cmd_tx
      .send(VmCommand::Stat {
        path,
        reply: reply_tx,
      })
      .map_err(|_| anyhow::anyhow!("VM thread exited"))?;
    reply_rx.await?
  }

  async fn mkdir(&self, path: String, recursive: bool) -> anyhow::Result<()> {
    let (reply_tx, reply_rx) = oneshot::channel();
    self
      .cmd_tx
      .send(VmCommand::Mkdir {
        path,
        recursive,
        reply: reply_tx,
      })
      .map_err(|_| anyhow::anyhow!("VM thread exited"))?;
    reply_rx.await?
  }

  async fn remove(&self, path: String, recursive: bool) -> anyhow::Result<()> {
    let (reply_tx, reply_rx) = oneshot::channel();
    self
      .cmd_tx
      .send(VmCommand::Remove {
        path,
        recursive,
        reply: reply_tx,
      })
      .map_err(|_| anyhow::anyhow!("VM thread exited"))?;
    reply_rx.await?
  }

  async fn rename(&self, old_path: String, new_path: String) -> anyhow::Result<()> {
    let (reply_tx, reply_rx) = oneshot::channel();
    self
      .cmd_tx
      .send(VmCommand::Rename {
        old_path,
        new_path,
        reply: reply_tx,
      })
      .map_err(|_| anyhow::anyhow!("VM thread exited"))?;
    reply_rx.await?
  }

  async fn copy(&self, src: String, dst: String, recursive: bool) -> anyhow::Result<()> {
    let (reply_tx, reply_rx) = oneshot::channel();
    self
      .cmd_tx
      .send(VmCommand::Copy {
        src,
        dst,
        recursive,
        reply: reply_tx,
      })
      .map_err(|_| anyhow::anyhow!("VM thread exited"))?;
    reply_rx.await?
  }

  async fn chmod(&self, path: String, mode: u32) -> anyhow::Result<()> {
    let (reply_tx, reply_rx) = oneshot::channel();
    self
      .cmd_tx
      .send(VmCommand::Chmod {
        path,
        mode,
        reply: reply_tx,
      })
      .map_err(|_| anyhow::anyhow!("VM thread exited"))?;
    reply_rx.await?
  }

  async fn open_exec(
    &self,
    argv: Vec<String>,
    cwd: Option<String>,
    env: HashMap<String, String>,
  ) -> anyhow::Result<TcpStream> {
    let (reply_tx, reply_rx) = oneshot::channel();
    self
      .cmd_tx
      .send(VmCommand::OpenExec {
        argv,
        cwd,
        env,
        reply: reply_tx,
      })
      .map_err(|_| anyhow::anyhow!("VM thread exited"))?;
    reply_rx.await?
  }

  async fn open_watch(&self, path: String, recursive: bool) -> anyhow::Result<TcpStream> {
    let (reply_tx, reply_rx) = oneshot::channel();
    self
      .cmd_tx
      .send(VmCommand::OpenWatch {
        path,
        recursive,
        reply: reply_tx,
      })
      .map_err(|_| anyhow::anyhow!("VM thread exited"))?;
    reply_rx.await?
  }

  async fn checkpoint(&self, name: String) -> anyhow::Result<()> {
    let (reply_tx, reply_rx) = oneshot::channel();
    self
      .cmd_tx
      .send(VmCommand::Checkpoint {
        name,
        reply: reply_tx,
      })
      .map_err(|_| anyhow::anyhow!("VM thread exited"))?;
    reply_rx.await?
  }

  async fn stop(&self) -> anyhow::Result<()> {
    if self.stopped.swap(true, Ordering::SeqCst) {
      return Ok(());
    }

    let (reply_tx, reply_rx) = oneshot::channel();
    let _ = self.cmd_tx.send(VmCommand::Stop { reply: reply_tx });
    reply_rx.await.unwrap_or(Ok(()))
  }

  fn instance_dir(&self) -> &str {
    &self.instance_dir
  }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for RuntimeSandbox {
  fn drop(&mut self) {
    if !self.stopped.swap(true, Ordering::SeqCst) {
      let (reply_tx, _) = oneshot::channel();
      let _ = self.cmd_tx.send(VmCommand::Stop { reply: reply_tx });
    }
    let _ = std::fs::remove_dir_all(&self.instance_dir);
  }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
enum ProcessInput {
  Stdin(Vec<u8>),
  Kill,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Default)]
struct ProcessEventState {
  stdout_listeners: Vec<BufferThreadsafeFunction>,
  stderr_listeners: Vec<BufferThreadsafeFunction>,
  exit_listeners: Vec<ExitThreadsafeFunction>,
  pending_stdout: Vec<Vec<u8>>,
  pending_stderr: Vec<Vec<u8>>,
  exit_code: Option<i32>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct SpawnedProcessState {
  pid: String,
  input_tx: std::sync::mpsc::Sender<ProcessInput>,
  events: Mutex<ProcessEventState>,
  exited_rx: watch::Receiver<Option<i32>>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl SpawnedProcessState {
  fn register_stdout_listener(
    &self,
    callback: Function<'static, Unknown<'static>, Unknown<'static>>,
  ) -> Result<()> {
    let tsfn = callback
      .build_threadsafe_function::<Vec<u8>>()
      .callee_handled::<false>()
      .build_callback(|ctx: ThreadsafeCallContext<Vec<u8>>| Ok(Buffer::from(ctx.value)))
      .map_err(to_napi_error)?;

    let mut state = self.events.lock().unwrap();
    let flush_pending = state.stdout_listeners.is_empty();
    let pending = if flush_pending {
      std::mem::take(&mut state.pending_stdout)
    } else {
      Vec::new()
    };
    state.stdout_listeners.push(tsfn);
    if flush_pending {
      let listener_idx = state.stdout_listeners.len() - 1;
      for chunk in pending {
        let _ =
          state.stdout_listeners[listener_idx].call(chunk, ThreadsafeFunctionCallMode::NonBlocking);
      }
    }
    Ok(())
  }

  fn register_stderr_listener(
    &self,
    callback: Function<'static, Unknown<'static>, Unknown<'static>>,
  ) -> Result<()> {
    let tsfn = callback
      .build_threadsafe_function::<Vec<u8>>()
      .callee_handled::<false>()
      .build_callback(|ctx: ThreadsafeCallContext<Vec<u8>>| Ok(Buffer::from(ctx.value)))
      .map_err(to_napi_error)?;

    let mut state = self.events.lock().unwrap();
    let flush_pending = state.stderr_listeners.is_empty();
    let pending = if flush_pending {
      std::mem::take(&mut state.pending_stderr)
    } else {
      Vec::new()
    };
    state.stderr_listeners.push(tsfn);
    if flush_pending {
      let listener_idx = state.stderr_listeners.len() - 1;
      for chunk in pending {
        let _ =
          state.stderr_listeners[listener_idx].call(chunk, ThreadsafeFunctionCallMode::NonBlocking);
      }
    }
    Ok(())
  }

  fn register_exit_listener(
    &self,
    callback: Function<'static, Unknown<'static>, Unknown<'static>>,
  ) -> Result<()> {
    let tsfn = callback
      .build_threadsafe_function::<i32>()
      .callee_handled::<false>()
      .build_callback(|ctx: ThreadsafeCallContext<i32>| Ok(ctx.value))
      .map_err(to_napi_error)?;

    let mut state = self.events.lock().unwrap();
    let exit_code = state.exit_code;
    state.exit_listeners.push(tsfn);
    if let (Some(code), Some(listener)) = (exit_code, state.exit_listeners.last()) {
      let _ = listener.call(code, ThreadsafeFunctionCallMode::NonBlocking);
    }
    Ok(())
  }

  fn emit_stdout(&self, chunk: Vec<u8>) {
    let mut state = self.events.lock().unwrap();
    if state.stdout_listeners.is_empty() {
      state.pending_stdout.push(chunk);
      return;
    }

    for listener in &state.stdout_listeners {
      let _ = listener.call(chunk.clone(), ThreadsafeFunctionCallMode::NonBlocking);
    }
  }

  fn emit_stderr(&self, chunk: Vec<u8>) {
    let mut state = self.events.lock().unwrap();
    if state.stderr_listeners.is_empty() {
      state.pending_stderr.push(chunk);
      return;
    }

    for listener in &state.stderr_listeners {
      let _ = listener.call(chunk.clone(), ThreadsafeFunctionCallMode::NonBlocking);
    }
  }

  fn emit_exit(&self, code: i32) {
    let mut state = self.events.lock().unwrap();
    if state.exit_code.is_none() {
      state.exit_code = Some(code);
      for listener in &state.exit_listeners {
        let _ = listener.call(code, ThreadsafeFunctionCallMode::NonBlocking);
      }
    }
  }
}

#[napi]
pub struct Sandbox {
  #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
  inner: Arc<RuntimeSandbox>,
}

#[napi]
pub struct SpawnedProcess {
  #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
  state: Arc<SpawnedProcessState>,
}

#[napi]
impl SpawnedProcess {
  #[napi]
  pub fn on(
    &self,
    event: String,
    callback: Function<'static, Unknown<'static>, Unknown<'static>>,
  ) -> Result<()> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
      match event.as_str() {
        "stdout" => self.state.register_stdout_listener(callback),
        "stderr" => self.state.register_stderr_listener(callback),
        "exit" => self.state.register_exit_listener(callback),
        _ => Err(Error::new(
          Status::InvalidArg,
          format!("unsupported process event: {event}"),
        )),
      }
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
      let _ = event;
      let _ = callback;
      Err(unsupported_platform_error())
    }
  }

  #[napi]
  pub fn write(&self, data: Either<String, Uint8Array>) -> Result<()> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
      let bytes = match data {
        Either::A(text) => text.into_bytes(),
        Either::B(buffer) => buffer.to_vec(),
      };
      self
        .state
        .input_tx
        .send(ProcessInput::Stdin(bytes))
        .map_err(|_| Error::new(Status::GenericFailure, "process is no longer writable"))
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
      let _ = data;
      Err(unsupported_platform_error())
    }
  }

  #[napi]
  pub async fn kill(&self) -> Result<()> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
      self
        .state
        .input_tx
        .send(ProcessInput::Kill)
        .map_err(|_| Error::new(Status::GenericFailure, "process is no longer running"))
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
      Err(unsupported_platform_error())
    }
  }

  #[napi(getter)]
  pub fn pid(&self) -> Result<String> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
      Ok(self.state.pid.clone())
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
      Err(unsupported_platform_error())
    }
  }

  #[napi(getter)]
  pub async fn exited(&self) -> Result<i32> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
      let mut rx = self.state.exited_rx.clone();
      if let Some(code) = *rx.borrow() {
        return Ok(code);
      }

      loop {
        if rx.changed().await.is_err() {
          return Err(Error::new(
            Status::GenericFailure,
            "process exit watcher closed unexpectedly",
          ));
        }

        if let Some(code) = *rx.borrow() {
          return Ok(code);
        }
      }
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
      Err(unsupported_platform_error())
    }
  }
}

#[napi]
impl Sandbox {
  #[napi(factory)]
  pub async fn start(opts: Option<StartOptions>) -> Result<Self> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
      let config = build_sandbox_config(opts.unwrap_or_default()).map_err(to_napi_error)?;
      let inner = RuntimeSandbox::boot(config).await.map_err(to_napi_error)?;
      return Ok(Self {
        inner: Arc::new(inner),
      });
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
      let _ = opts;
      Err(unsupported_platform_error())
    }
  }

  #[napi]
  pub async fn exec(
    &self,
    command: Either<String, Vec<String>>,
    opts: Option<ExecOptions>,
  ) -> Result<ExecResult> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
      let shell = opts
        .and_then(|options| options.shell)
        .unwrap_or_else(|| "sh".to_string());

      let argv = match command {
        Either::A(command) => vec![shell, "-c".to_string(), command],
        Either::B(argv) => argv,
      };

      let result = self.inner.exec(argv).await.map_err(to_napi_error)?;
      return Ok(map_exec_result(result));
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
      let _ = command;
      let _ = opts;
      Err(unsupported_platform_error())
    }
  }

  #[napi]
  pub async fn exec_shell(&self, command: String) -> Result<ExecResult> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
      let result = self
        .inner
        .exec(vec!["/bin/sh".to_string(), "-c".to_string(), command])
        .await
        .map_err(to_napi_error)?;
      return Ok(map_exec_result(result));
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
      let _ = command;
      Err(unsupported_platform_error())
    }
  }

  #[napi]
  pub async fn spawn(
    &self,
    command: Either<String, Vec<String>>,
    opts: Option<SpawnOptions>,
  ) -> Result<SpawnedProcess> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
      let opts = opts.unwrap_or(SpawnOptions {
        cwd: None,
        env: None,
        shell: None,
      });

      let shell = opts.shell.unwrap_or_else(|| "sh".to_string());
      let argv = match command {
        Either::A(command) => vec![shell, "-c".to_string(), command],
        Either::B(argv) => argv,
      };

      let stream = self
        .inner
        .open_exec(argv, opts.cwd, opts.env.unwrap_or_default())
        .await
        .map_err(to_napi_error)?;

      let pid = format!("p{}", PROCESS_ID_COUNTER.fetch_add(1, Ordering::SeqCst));
      let (input_tx, input_rx) = std::sync::mpsc::channel();
      let (exited_tx, exited_rx) = watch::channel(None);
      let closed = Arc::new(AtomicBool::new(false));

      let state = Arc::new(SpawnedProcessState {
        pid,
        input_tx,
        events: Mutex::new(ProcessEventState::default()),
        exited_rx,
      });

      spawn_process_threads(stream, state.clone(), input_rx, exited_tx, closed);

      return Ok(SpawnedProcess { state });
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
      let _ = command;
      let _ = opts;
      Err(unsupported_platform_error())
    }
  }

  #[napi]
  pub fn watch(
    &self,
    path: String,
    callback: Function<'static, FileChangeEvent, Unknown<'static>>,
    opts: Option<WatchOptions>,
  ) -> Result<()> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
      let tsfn = callback
        .build_threadsafe_function::<FileChangeEvent>()
        .callee_handled::<false>()
        .build_callback(|ctx: ThreadsafeCallContext<FileChangeEvent>| Ok(ctx.value))
        .map_err(to_napi_error)?;
      let recursive = opts.and_then(|value| value.recursive).unwrap_or(true);
      let stream = napi::bindgen_prelude::block_on(self.inner.open_watch(path, recursive))
        .map_err(to_napi_error)?;

      std::thread::Builder::new()
        .name("shuru-nodejs-watch".into())
        .spawn(move || {
          let mut reader = BufReader::new(stream);
          loop {
            match shuru_proto::frame::read_frame(&mut reader) {
              Ok(Some((shuru_proto::frame::WATCH_EVENT, payload))) => {
                if let Ok(event) = serde_json::from_slice::<shuru_proto::WatchEvent>(&payload) {
                  let _ = tsfn.call(
                    FileChangeEvent {
                      path: event.path,
                      event: event.event,
                    },
                    ThreadsafeFunctionCallMode::NonBlocking,
                  );
                }
              }
              _ => break,
            }
          }
        })
        .map_err(to_napi_error)?;

      Ok(())
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
      let _ = path;
      let _ = callback;
      let _ = opts;
      Err(unsupported_platform_error())
    }
  }

  #[napi]
  pub async fn read_file(&self, path: String) -> Result<Buffer> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
      let content = self.inner.read_file(path).await.map_err(to_napi_error)?;
      return Ok(Buffer::from(content));
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
      let _ = path;
      Err(unsupported_platform_error())
    }
  }

  #[napi]
  pub async fn write_file(&self, path: String, content: Either<String, Uint8Array>) -> Result<()> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
      let content = match content {
        Either::A(text) => text.into_bytes(),
        Either::B(bytes) => bytes.to_vec(),
      };
      self
        .inner
        .write_file(path, content)
        .await
        .map_err(to_napi_error)?;
      return Ok(());
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
      let _ = path;
      let _ = content;
      Err(unsupported_platform_error())
    }
  }

  #[napi]
  pub async fn mkdir(&self, path: String, opts: Option<MkdirOptions>) -> Result<()> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
      self
        .inner
        .mkdir(path, opts.and_then(|value| value.recursive).unwrap_or(true))
        .await
        .map_err(to_napi_error)?;
      return Ok(());
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
      let _ = path;
      let _ = opts;
      Err(unsupported_platform_error())
    }
  }

  #[napi]
  pub async fn read_dir(&self, path: String) -> Result<Vec<DirEntry>> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
      let response = self.inner.read_dir(path).await.map_err(to_napi_error)?;
      return Ok(response.entries.into_iter().map(map_dir_entry).collect());
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
      let _ = path;
      Err(unsupported_platform_error())
    }
  }

  #[napi]
  pub async fn stat(&self, path: String) -> Result<StatResult> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
      let stat = self.inner.stat(path).await.map_err(to_napi_error)?;
      return Ok(map_stat_result(stat));
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
      let _ = path;
      Err(unsupported_platform_error())
    }
  }

  #[napi]
  pub async fn remove(&self, path: String, opts: Option<RemoveOptions>) -> Result<()> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
      self
        .inner
        .remove(
          path,
          opts.and_then(|value| value.recursive).unwrap_or(false),
        )
        .await
        .map_err(to_napi_error)?;
      return Ok(());
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
      let _ = path;
      let _ = opts;
      Err(unsupported_platform_error())
    }
  }

  #[napi]
  pub async fn rename(&self, old_path: String, new_path: String) -> Result<()> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
      self
        .inner
        .rename(old_path, new_path)
        .await
        .map_err(to_napi_error)?;
      return Ok(());
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
      let _ = old_path;
      let _ = new_path;
      Err(unsupported_platform_error())
    }
  }

  #[napi]
  pub async fn copy(&self, src: String, dst: String, opts: Option<CopyOptions>) -> Result<()> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
      self
        .inner
        .copy(
          src,
          dst,
          opts.and_then(|value| value.recursive).unwrap_or(false),
        )
        .await
        .map_err(to_napi_error)?;
      return Ok(());
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
      let _ = src;
      let _ = dst;
      let _ = opts;
      Err(unsupported_platform_error())
    }
  }

  #[napi]
  pub async fn chmod(&self, path: String, mode: u32) -> Result<()> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
      self.inner.chmod(path, mode).await.map_err(to_napi_error)?;
      return Ok(());
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
      let _ = path;
      let _ = mode;
      Err(unsupported_platform_error())
    }
  }

  #[napi]
  pub async fn exists(&self, path: String) -> Result<bool> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
      return match self.inner.stat(path).await {
        Ok(_) => Ok(true),
        Err(error) if error.to_string().contains("No such file or directory") => Ok(false),
        Err(error) => Err(to_napi_error(error)),
      };
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
      let _ = path;
      Err(unsupported_platform_error())
    }
  }

  #[napi]
  pub async fn checkpoint(&self, name: String) -> Result<()> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
      self.inner.checkpoint(name).await.map_err(to_napi_error)?;
      return Ok(());
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
      let _ = name;
      Err(unsupported_platform_error())
    }
  }

  #[napi]
  pub async fn stop(&self) -> Result<()> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
      self.inner.stop().await.map_err(to_napi_error)?;
      return Ok(());
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
      Err(unsupported_platform_error())
    }
  }

  #[napi(getter)]
  pub fn instance_dir(&self) -> Result<String> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
      return Ok(self.inner.instance_dir().to_string());
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
      Err(unsupported_platform_error())
    }
  }
}

impl Default for StartOptions {
  fn default() -> Self {
    Self {
      from: None,
      cpus: None,
      memory: None,
      diskSize: None,
      dataDir: None,
      allowNet: None,
      allowedHosts: None,
      ports: None,
      mounts: None,
      secrets: None,
      network: None,
    }
  }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
static PROCESS_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
extern "C" {
  fn clonefile(src: *const libc::c_char, dst: *const libc::c_char, flags: u32) -> libc::c_int;
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn clone_file_cow(src: &str, dst: &str) -> anyhow::Result<()> {
  let c_src = std::ffi::CString::new(src).context("invalid source path")?;
  let c_dst = std::ffi::CString::new(dst).context("invalid destination path")?;
  let ret = unsafe { clonefile(c_src.as_ptr(), c_dst.as_ptr(), 0) };
  if ret != 0 {
    bail!(
      "clonefile({src} -> {dst}) failed: {}",
      std::io::Error::last_os_error()
    );
  }
  Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn boot_vm(
  config: SandboxConfig,
) -> anyhow::Result<(
  shuru_vm::Sandbox,
  String,
  Option<shuru_proxy::ProxyHandle>,
  Option<PortForwardHandle>,
)> {
  let data_dir = config.data_dir.unwrap_or_else(shuru_vm::default_data_dir);
  let kernel_path = format!("{data_dir}/Image");
  let rootfs_path = format!("{data_dir}/rootfs.ext4");
  let initrd_path = format!("{data_dir}/initramfs.cpio.gz");

  if !std::path::Path::new(&kernel_path).exists() {
    bail!("Kernel not found at {kernel_path}. Run `shuru init` to download.");
  }

  let source = match &config.from {
    Some(name) => {
      let checkpoint_path = format!("{data_dir}/checkpoints/{name}.ext4");
      if !std::path::Path::new(&checkpoint_path).exists() {
        bail!("Checkpoint '{name}' not found");
      }
      checkpoint_path
    }
    None => {
      if !std::path::Path::new(&rootfs_path).exists() {
        bail!("Rootfs not found at {rootfs_path}. Run `shuru init` to download.");
      }
      rootfs_path
    }
  };

  let instance_dir = format!("{data_dir}/instances/nodejs-{}", std::process::id());
  let _ = std::fs::remove_dir_all(&instance_dir);
  std::fs::create_dir_all(&instance_dir)?;

  let work_rootfs = format!("{instance_dir}/rootfs.ext4");
  clone_file_cow(&source, &work_rootfs)?;

  let file = std::fs::OpenOptions::new().write(true).open(&work_rootfs)?;
  let target_len = config.disk_size_mb * 1024 * 1024;
  let current_len = file.metadata()?.len();
  if target_len > current_len {
    file.set_len(target_len)?;
  }
  drop(file);

  let initrd_path = if std::path::Path::new(&initrd_path).exists() {
    Some(initrd_path)
  } else {
    None
  };

  let (vm_fd, proxy_handle) = if config.allow_net {
    let mut proxy_config = shuru_proxy::config::ProxyConfig::default();
    proxy_config.secrets = config.secrets;
    proxy_config.network.allow = config.allowed_hosts;

    let (vm_fd, host_fd) = shuru_proxy::create_socketpair()?;
    let handle = shuru_proxy::start(host_fd, proxy_config)?;
    (Some(vm_fd), Some(handle))
  } else {
    (None, None)
  };

  let mut builder = shuru_vm::Sandbox::builder()
    .kernel(&kernel_path)
    .rootfs(&work_rootfs)
    .cpus(config.cpus)
    .memory_mb(config.memory_mb)
    .console(false);

  if let Some(fd) = vm_fd {
    builder = builder.network_fd(fd);
  }
  if let Some(ref initrd) = initrd_path {
    builder = builder.initrd(initrd);
  }
  for mount in &config.mounts {
    builder = builder.mount(mount.clone());
  }

  let sandbox = builder.build()?;
  sandbox.start()?;

  let fwd_handle = if !config.ports.is_empty() {
    Some(sandbox.start_port_forwarding(&config.ports)?)
  } else {
    None
  };

  if let Some(ref handle) = proxy_handle {
    if !handle.placeholders.is_empty() {
      sandbox.write_file(
        "/usr/local/share/ca-certificates/shuru-proxy.crt",
        &handle.ca_cert_pem,
      )?;
      sandbox.exec(
        &["update-ca-certificates", "--fresh"],
        &mut std::io::sink(),
        &mut std::io::sink(),
      )?;
    }
  }

  Ok((sandbox, instance_dir, proxy_handle, fwd_handle))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn run_vm_loop(
  sandbox: shuru_vm::Sandbox,
  instance_dir: &str,
  cmd_rx: std::sync::mpsc::Receiver<VmCommand>,
  proxy_handle: Option<shuru_proxy::ProxyHandle>,
  _fwd_handle: Option<PortForwardHandle>,
) {
  let secret_env = proxy_handle
    .as_ref()
    .map(|handle| handle.placeholders.clone())
    .unwrap_or_default();
  let _proxy = proxy_handle;

  while let Ok(cmd) = cmd_rx.recv() {
    match cmd {
      VmCommand::Exec { argv, reply } => {
        let _ = reply.send(exec_command(&sandbox, &argv, &secret_env));
      }
      VmCommand::ReadFile { path, reply } => {
        let _ = reply.send(sandbox.read_file(&path));
      }
      VmCommand::WriteFile {
        path,
        content,
        reply,
      } => {
        let _ = reply.send(sandbox.write_file(&path, &content));
      }
      VmCommand::ReadDir { path, reply } => {
        let _ = reply.send(sandbox.read_dir(&path));
      }
      VmCommand::Stat { path, reply } => {
        let _ = reply.send(sandbox.stat(&path));
      }
      VmCommand::Mkdir {
        path,
        recursive,
        reply,
      } => {
        let _ = reply.send(sandbox.mkdir(&path, recursive));
      }
      VmCommand::Remove {
        path,
        recursive,
        reply,
      } => {
        let _ = reply.send(sandbox.remove(&path, recursive));
      }
      VmCommand::Rename {
        old_path,
        new_path,
        reply,
      } => {
        let _ = reply.send(sandbox.rename(&old_path, &new_path));
      }
      VmCommand::Copy {
        src,
        dst,
        recursive,
        reply,
      } => {
        let _ = reply.send(sandbox.copy(&src, &dst, recursive));
      }
      VmCommand::Chmod { path, mode, reply } => {
        let _ = reply.send(sandbox.chmod(&path, mode));
      }
      VmCommand::OpenExec {
        argv,
        cwd,
        env,
        reply,
      } => {
        let mut combined_env = secret_env.clone();
        combined_env.extend(env);
        let _ = reply.send(sandbox.open_exec(&argv, &combined_env, cwd.as_deref()));
      }
      VmCommand::OpenWatch {
        path,
        recursive,
        reply,
      } => {
        let _ = reply.send(sandbox.open_watch(&path, recursive));
      }
      VmCommand::Checkpoint { name, reply } => {
        let result = (|| -> anyhow::Result<()> {
          let checkpoints_dir = format!("{}/checkpoints", shuru_vm::default_data_dir());
          std::fs::create_dir_all(&checkpoints_dir)?;
          let checkpoint_path = format!("{checkpoints_dir}/{name}.ext4");
          if std::path::Path::new(&checkpoint_path).exists() {
            std::fs::remove_file(&checkpoint_path)?;
          }
          let work_rootfs = format!("{instance_dir}/rootfs.ext4");
          clone_file_cow(&work_rootfs, &checkpoint_path)?;
          Ok(())
        })();
        let _ = reply.send(result);
      }
      VmCommand::Stop { reply } => {
        let _ = reply.send(sandbox.stop());
        break;
      }
    }
  }

  let _ = sandbox.stop();
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn exec_command(
  sandbox: &shuru_vm::Sandbox,
  argv: &[String],
  env: &HashMap<String, String>,
) -> anyhow::Result<shuru_sdk::ExecResult> {
  let argv_refs: Vec<&str> = argv.iter().map(String::as_str).collect();
  let mut stdout = Vec::new();
  let mut stderr = Vec::new();
  let exit_code = sandbox.exec_with_env(&argv_refs, env, &mut stdout, &mut stderr)?;

  Ok(shuru_sdk::ExecResult {
    stdout: String::from_utf8_lossy(&stdout).to_string(),
    stderr: String::from_utf8_lossy(&stderr).to_string(),
    exit_code,
  })
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn spawn_process_threads(
  stream: TcpStream,
  state: Arc<SpawnedProcessState>,
  input_rx: std::sync::mpsc::Receiver<ProcessInput>,
  exited_tx: watch::Sender<Option<i32>>,
  closed: Arc<AtomicBool>,
) {
  let state_for_thread = state.clone();

  let _ = std::thread::Builder::new()
    .name(format!("shuru-nodejs-process-{}", state.pid))
    .spawn(move || {
      let mut reader = match stream.try_clone() {
        Ok(value) => BufReader::new(value),
        Err(_) => {
          let _ = exited_tx.send(Some(1));
          state_for_thread.emit_exit(1);
          return;
        }
      };
      let mut writer = stream;
      let closed_for_input = closed.clone();

      let input_thread = std::thread::spawn(move || {
        while !closed_for_input.load(Ordering::SeqCst) {
          match input_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(ProcessInput::Stdin(data)) => {
              if shuru_proto::frame::write_frame(&mut writer, shuru_proto::frame::STDIN, &data)
                .is_err()
              {
                break;
              }
            }
            Ok(ProcessInput::Kill) => {
              let _ = shuru_proto::frame::write_frame(&mut writer, shuru_proto::frame::KILL, &[]);
              break;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
          }
        }
      });

      loop {
        match shuru_proto::frame::read_frame(&mut reader) {
          Ok(Some((shuru_proto::frame::STDOUT, data))) => state_for_thread.emit_stdout(data),
          Ok(Some((shuru_proto::frame::STDERR, data))) => state_for_thread.emit_stderr(data),
          Ok(Some((shuru_proto::frame::EXIT, data))) => {
            let code = shuru_proto::frame::parse_exit_code(&data).unwrap_or(0);
            let _ = exited_tx.send(Some(code));
            state_for_thread.emit_exit(code);
            break;
          }
          Ok(Some((shuru_proto::frame::ERROR, data))) => {
            state_for_thread.emit_stderr(data);
            let _ = exited_tx.send(Some(1));
            state_for_thread.emit_exit(1);
            break;
          }
          _ => {
            let _ = exited_tx.send(Some(1));
            state_for_thread.emit_exit(1);
            break;
          }
        }
      }

      closed.store(true, Ordering::SeqCst);
      let _ = input_thread.join();
    });
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn build_sandbox_config(opts: StartOptions) -> anyhow::Result<SandboxConfig> {
  let mut config = SandboxConfig::default();

  config.from = opts.from;
  config.data_dir = opts.dataDir;
  config.cpus = opts.cpus.unwrap_or(config.cpus as u32) as usize;
  config.memory_mb = u64::from(opts.memory.unwrap_or(config.memory_mb as u32));
  config.disk_size_mb = u64::from(opts.diskSize.unwrap_or(config.disk_size_mb as u32));
  config.allow_net = opts.allowNet.unwrap_or(config.allow_net);

  if let Some(allowed_hosts) = opts.allowedHosts {
    config.allowed_hosts.extend(allowed_hosts);
  }

  if let Some(network) = opts.network {
    if let Some(allow) = network.allow {
      config.allowed_hosts.extend(allow);
    }
  }

  if let Some(ports) = opts.ports {
    config.ports = ports
      .into_iter()
      .map(|port| parse_port_mapping(&port))
      .collect::<anyhow::Result<Vec<_>>>()?;
  }

  if let Some(mounts) = opts.mounts {
    config.mounts = mounts
      .into_iter()
      .map(|(host_path, guest_path)| parse_mount(host_path, guest_path))
      .collect::<anyhow::Result<Vec<_>>>()?;
  }

  if let Some(secrets) = opts.secrets {
    config.secrets = secrets
      .into_iter()
      .map(|(name, secret)| Ok((name, parse_secret(secret)?)))
      .collect::<anyhow::Result<HashMap<_, _>>>()?;
  }

  Ok(config)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn parse_mount(host_path: String, guest_path: String) -> anyhow::Result<MountConfig> {
  if !guest_path.starts_with('/') {
    bail!("guest path must be absolute (start with /): '{guest_path}'");
  }

  let host_path = std::fs::canonicalize(&host_path)
    .with_context(|| format!("host path does not exist: '{host_path}'"))?
    .to_string_lossy()
    .into_owned();

  Ok(MountConfig {
    host_path,
    guest_path,
  })
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn parse_port_mapping(input: &str) -> anyhow::Result<PortMapping> {
  let parts = input.split(':').collect::<Vec<_>>();
  if parts.len() != 2 {
    bail!("expected HOST:GUEST format (e.g. 8080:80)");
  }

  let host_port = parts[0]
    .parse::<u16>()
    .with_context(|| format!("invalid host port: '{}'", parts[0]))?;
  let guest_port = parts[1]
    .parse::<u16>()
    .with_context(|| format!("invalid guest port: '{}'", parts[1]))?;

  Ok(PortMapping {
    host_port,
    guest_port,
  })
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn parse_secret(secret: SecretConfig) -> anyhow::Result<NativeSecretConfig> {
  if secret.value.trim().is_empty() {
    bail!("secret value must be non-empty");
  }

  if secret.hosts.is_empty() {
    bail!("secret hosts must be non-empty");
  }

  Ok(NativeSecretConfig {
    value: secret.value,
    hosts: secret.hosts,
  })
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn map_exec_result(result: shuru_sdk::ExecResult) -> ExecResult {
  ExecResult {
    stdout: result.stdout,
    stderr: result.stderr,
    exitCode: result.exit_code,
  }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn map_dir_entry(entry: NativeDirEntry) -> DirEntry {
  DirEntry {
    name: entry.name,
    r#type: entry.entry_type,
    size: entry.size as f64,
  }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn map_stat_result(stat: NativeStatResponse) -> StatResult {
  StatResult {
    size: stat.size as f64,
    mode: stat.mode,
    mtime: stat.mtime as f64,
    isDir: stat.is_dir,
    isFile: stat.is_file,
    isSymlink: stat.is_symlink,
  }
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn unsupported_platform_error() -> Error {
  Error::new(
    Status::GenericFailure,
    "Shuru native bindings currently support only macOS on Apple Silicon (aarch64). This package may install elsewhere, but Sandbox.start() is unsupported there.".to_string(),
  )
}

fn to_napi_error(error: impl std::fmt::Display) -> Error {
  Error::new(Status::GenericFailure, error.to_string())
}
