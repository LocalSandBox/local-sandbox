use std::collections::HashMap;
use std::io::BufReader;
use std::net::TcpStream;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use tokio::sync::{mpsc, oneshot};
use tracing::info;

// Re-exports
pub use shuru_proto::{DirEntry, ReadDirResponse, StatResponse};
pub use shuru_proxy::config::{NetworkConfig, ProxyConfig, SecretConfig};
pub use shuru_vm::{default_data_dir, MountConfig};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Configuration for booting a sandbox VM.
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Data directory containing kernel, rootfs, initramfs.
    /// Defaults to `~/.local/share/shuru`.
    pub data_dir: Option<String>,
    /// Number of CPUs. Default: 2.
    pub cpus: usize,
    /// Memory in MB. Default: 2048.
    pub memory_mb: u64,
    /// Disk size in MB. Default: 4096.
    pub disk_size_mb: u64,
    /// Host → guest directory mounts (VirtioFS).
    pub mounts: Vec<MountConfig>,
    /// Enable networking via proxy.
    pub allow_net: bool,
    /// Secrets for proxy injection.
    pub secrets: HashMap<String, SecretConfig>,
    /// Allowed domain patterns for network access.
    pub allowed_hosts: Vec<String>,
    /// Port forwards (host → guest).
    pub ports: Vec<shuru_proto::PortMapping>,
    /// Boot from a named checkpoint instead of base rootfs.
    pub from: Option<String>,
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
            ports: vec![],
            from: None,
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

/// Events from an interactive shell session.
#[derive(Debug)]
pub enum ShellEvent {
    /// Terminal output bytes (PTY stdout).
    Output(Vec<u8>),
    /// Process exited with code.
    Exit(i32),
    /// Error from guest.
    Error(String),
}

/// Writer half of a shell session. Cloneable — used to send input and resize.
#[derive(Clone)]
pub struct ShellWriter {
    writer: Arc<std::sync::Mutex<TcpStream>>,
}

impl ShellWriter {
    /// Send input bytes (keystrokes) to the shell.
    pub fn send_input(&self, data: &[u8]) -> Result<()> {
        use std::io::Write;
        let mut w = self.writer.lock().unwrap();
        shuru_proto::frame::write_frame(&mut *w, shuru_proto::frame::STDIN, data)?;
        w.flush()?;
        Ok(())
    }

    /// Send a terminal resize event.
    pub fn resize(&self, rows: u16, cols: u16) -> Result<()> {
        let mut w = self.writer.lock().unwrap();
        let payload = shuru_proto::frame::resize_payload(rows, cols);
        shuru_proto::frame::write_frame(&mut *w, shuru_proto::frame::RESIZE, &payload)?;
        Ok(())
    }
}

/// Reader half of a shell session. Receives output events asynchronously.
pub struct ShellReader {
    output_rx: mpsc::UnboundedReceiver<ShellEvent>,
}

impl ShellReader {
    /// Receive the next shell event. Returns `None` when the session ends.
    pub async fn recv(&mut self) -> Option<ShellEvent> {
        self.output_rx.recv().await
    }
}

/// Handle to an interactive shell session with PTY support.
pub struct ShellHandle {
    writer: ShellWriter,
    reader: ShellReader,
    _reader_thread: std::thread::JoinHandle<()>,
}

impl ShellHandle {
    /// Split into writer (cloneable, for input) and reader (for output).
    pub fn split(self) -> (ShellWriter, ShellReader) {
        // Leak the thread handle so it runs to completion
        std::mem::forget(self._reader_thread);
        (self.writer, self.reader)
    }
}

// ---------------------------------------------------------------------------
// Internal command protocol (async ↔ VM thread)
// ---------------------------------------------------------------------------

enum SandboxCmd {
    Exec {
        argv: Vec<String>,
        reply: oneshot::Sender<Result<ExecResult>>,
    },
    ReadFile {
        path: String,
        reply: oneshot::Sender<Result<Vec<u8>>>,
    },
    WriteFile {
        path: String,
        content: Vec<u8>,
        reply: oneshot::Sender<Result<()>>,
    },
    ReadDir {
        path: String,
        reply: oneshot::Sender<Result<ReadDirResponse>>,
    },
    OpenShell {
        rows: u16,
        cols: u16,
        reply: oneshot::Sender<Result<TcpStream>>,
    },
    Checkpoint {
        name: String,
        reply: oneshot::Sender<Result<()>>,
    },
    Stop {
        reply: oneshot::Sender<Result<()>>,
    },
}

// ---------------------------------------------------------------------------
// AsyncSandbox — the main public interface
// ---------------------------------------------------------------------------

/// Async wrapper around a Shuru VM sandbox.
///
/// All VM operations are dispatched to a dedicated OS thread that owns
/// the sandbox. This avoids Send/Sync constraints from the Apple
/// Virtualization framework's Objective-C objects.
pub struct AsyncSandbox {
    cmd_tx: std::sync::mpsc::Sender<SandboxCmd>,
    instance_dir: String,
}

impl AsyncSandbox {
    /// Boot a new sandbox VM with the given configuration.
    pub async fn boot(config: SandboxConfig) -> Result<Self> {
        let (ready_tx, ready_rx) = oneshot::channel::<Result<String>>();
        let (cmd_tx, cmd_rx) = std::sync::mpsc::channel();

        std::thread::Builder::new()
            .name("shuru-vm".into())
            .spawn(move || {
                match boot_vm(config) {
                    Ok((sandbox, instance_dir, proxy_handle, fwd_handle)) => {
                        if ready_tx.send(Ok(instance_dir.clone())).is_err() {
                            return;
                        }
                        run_vm_loop(sandbox, &instance_dir, cmd_rx, proxy_handle, fwd_handle);
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                    }
                }
            })?;

        let instance_dir = ready_rx.await??;

        Ok(Self {
            cmd_tx,
            instance_dir,
        })
    }

    /// Execute a command and wait for the result.
    pub async fn exec(&self, argv: &[&str]) -> Result<ExecResult> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(SandboxCmd::Exec {
                argv: argv.iter().map(|s| s.to_string()).collect(),
                reply: reply_tx,
            })
            .map_err(|_| anyhow::anyhow!("VM thread exited"))?;
        reply_rx.await?
    }

    /// Execute a shell command string via `/bin/sh -c`.
    pub async fn exec_shell(&self, command: &str) -> Result<ExecResult> {
        self.exec(&["/bin/sh", "-c", command]).await
    }

    /// Spawn an interactive shell with PTY support.
    /// Returns a `ShellHandle` that can be split into writer/reader halves.
    pub async fn open_shell(&self, rows: u16, cols: u16) -> Result<ShellHandle> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(SandboxCmd::OpenShell {
                rows,
                cols,
                reply: reply_tx,
            })
            .map_err(|_| anyhow::anyhow!("VM thread exited"))?;
        let stream = reply_rx.await??;

        // Split the stream for bidirectional I/O
        let writer_stream = stream.try_clone()?;
        let reader_stream = stream;

        let (event_tx, event_rx) = mpsc::unbounded_channel();

        let reader_thread = std::thread::Builder::new()
            .name("shuru-shell-reader".into())
            .spawn(move || {
                let mut reader = BufReader::new(reader_stream);
                loop {
                    match shuru_proto::frame::read_frame(&mut reader) {
                        Ok(Some((shuru_proto::frame::STDOUT, payload))) => {
                            if event_tx.send(ShellEvent::Output(payload)).is_err() {
                                break;
                            }
                        }
                        Ok(Some((shuru_proto::frame::EXIT, payload))) => {
                            let code =
                                shuru_proto::frame::parse_exit_code(&payload).unwrap_or(0);
                            let _ = event_tx.send(ShellEvent::Exit(code));
                            break;
                        }
                        Ok(Some((shuru_proto::frame::ERROR, payload))) => {
                            let msg = String::from_utf8_lossy(&payload).to_string();
                            let _ = event_tx.send(ShellEvent::Error(msg));
                            break;
                        }
                        Ok(Some(_)) => {} // skip unknown frame types
                        Ok(None) | Err(_) => break,
                    }
                }
            })?;

        Ok(ShellHandle {
            writer: ShellWriter {
                writer: Arc::new(std::sync::Mutex::new(writer_stream)),
            },
            reader: ShellReader { output_rx: event_rx },
            _reader_thread: reader_thread,
        })
    }

    /// Read a file from the VM. Returns raw bytes.
    pub async fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(SandboxCmd::ReadFile {
                path: path.to_string(),
                reply: reply_tx,
            })
            .map_err(|_| anyhow::anyhow!("VM thread exited"))?;
        reply_rx.await?
    }

    /// Write a file to the VM.
    pub async fn write_file(&self, path: &str, content: &[u8]) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(SandboxCmd::WriteFile {
                path: path.to_string(),
                content: content.to_vec(),
                reply: reply_tx,
            })
            .map_err(|_| anyhow::anyhow!("VM thread exited"))?;
        reply_rx.await?
    }

    /// List directory contents in the VM.
    pub async fn read_dir(&self, path: &str) -> Result<ReadDirResponse> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(SandboxCmd::ReadDir {
                path: path.to_string(),
                reply: reply_tx,
            })
            .map_err(|_| anyhow::anyhow!("VM thread exited"))?;
        reply_rx.await?
    }

    /// Save the current rootfs state as a named checkpoint (CoW clone).
    /// Future VMs can boot from this checkpoint via `SandboxConfig::from`.
    pub async fn checkpoint(&self, name: &str) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(SandboxCmd::Checkpoint {
                name: name.to_string(),
                reply: reply_tx,
            })
            .map_err(|_| anyhow::anyhow!("VM thread exited"))?;
        reply_rx.await?
    }

    /// Stop the VM and clean up resources.
    pub async fn stop(&self) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = self.cmd_tx.send(SandboxCmd::Stop { reply: reply_tx });
        reply_rx.await.unwrap_or(Ok(()))
    }

    /// Get the instance directory path (contains the working rootfs copy).
    pub fn instance_dir(&self) -> &str {
        &self.instance_dir
    }
}

impl Drop for AsyncSandbox {
    fn drop(&mut self) {
        // Signal the VM thread to stop
        let (reply_tx, _) = oneshot::channel();
        let _ = self.cmd_tx.send(SandboxCmd::Stop { reply: reply_tx });
        // Clean up instance directory
        let _ = std::fs::remove_dir_all(&self.instance_dir);
    }
}

// ---------------------------------------------------------------------------
// Internal: VM boot & command loop (runs on dedicated OS thread)
// ---------------------------------------------------------------------------

extern "C" {
    fn clonefile(src: *const libc::c_char, dst: *const libc::c_char, flags: u32) -> libc::c_int;
}

fn clone_file_cow(src: &str, dst: &str) -> Result<()> {
    let c_src = std::ffi::CString::new(src).context("invalid source path")?;
    let c_dst = std::ffi::CString::new(dst).context("invalid destination path")?;
    let ret = unsafe { clonefile(c_src.as_ptr(), c_dst.as_ptr(), 0) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        bail!("clonefile({} -> {}) failed: {}", src, dst, err);
    }
    Ok(())
}

fn boot_vm(
    config: SandboxConfig,
) -> Result<(
    shuru_vm::Sandbox,
    String, // instance_dir
    Option<shuru_proxy::ProxyHandle>,
    Option<shuru_vm::PortForwardHandle>,
)> {
    let data_dir = config
        .data_dir
        .unwrap_or_else(shuru_vm::default_data_dir);

    // Resolve asset paths
    let kernel_path = format!("{}/Image", data_dir);
    let rootfs_path = format!("{}/rootfs.ext4", data_dir);
    let initrd_path_str = format!("{}/initramfs.cpio.gz", data_dir);

    if !std::path::Path::new(&kernel_path).exists() {
        bail!(
            "Kernel not found at {}. Run `shuru init` to download.",
            kernel_path
        );
    }

    // Determine rootfs source (checkpoint or base)
    let source = match &config.from {
        Some(name) => {
            let path = format!("{}/checkpoints/{}.ext4", data_dir, name);
            if !std::path::Path::new(&path).exists() {
                bail!("Checkpoint '{}' not found", name);
            }
            path
        }
        None => {
            if !std::path::Path::new(&rootfs_path).exists() {
                bail!(
                    "Rootfs not found at {}. Run `shuru init` to download.",
                    rootfs_path
                );
            }
            rootfs_path
        }
    };

    // Create per-instance working copy (CoW via macOS clonefile)
    let instance_dir = format!(
        "{}/instances/sdk-{}",
        data_dir,
        std::process::id()
    );
    let _ = std::fs::remove_dir_all(&instance_dir);
    std::fs::create_dir_all(&instance_dir)?;
    let work_rootfs = format!("{}/rootfs.ext4", instance_dir);
    clone_file_cow(&source, &work_rootfs)?;

    // Extend disk to requested size
    let f = std::fs::OpenOptions::new()
        .write(true)
        .open(&work_rootfs)?;
    let target = config.disk_size_mb * 1024 * 1024;
    let current = f.metadata()?.len();
    if target > current {
        f.set_len(target)?;
    }
    drop(f);

    let initrd_path = if std::path::Path::new(&initrd_path_str).exists() {
        Some(initrd_path_str)
    } else {
        None
    };

    // Set up proxy networking if enabled
    let (vm_fd, proxy_handle) = if config.allow_net {
        let mut proxy_config = ProxyConfig::default();
        proxy_config.secrets = config.secrets;
        proxy_config.network.allow = config.allowed_hosts;

        let (vm_fd, host_fd) = shuru_proxy::create_socketpair()?;
        let handle = shuru_proxy::start(host_fd, proxy_config)?;
        (Some(vm_fd), Some(handle))
    } else {
        (None, None)
    };

    // Build the VM
    let mut builder = shuru_vm::Sandbox::builder()
        .kernel(&kernel_path)
        .rootfs(&work_rootfs)
        .cpus(config.cpus)
        .memory_mb(config.memory_mb)
        .console(false); // No serial console in SDK mode

    if let Some(fd) = vm_fd {
        builder = builder.network_fd(fd);
    }
    if let Some(ref initrd) = initrd_path {
        builder = builder.initrd(initrd);
    }
    for m in &config.mounts {
        builder = builder.mount(m.clone());
    }

    let sandbox = builder.build()?;

    info!(
        "booting VM ({}cpus, {}MB RAM, {}MB disk)",
        config.cpus, config.memory_mb, config.disk_size_mb
    );

    sandbox.start()?;

    // Start port forwarding
    let fwd_handle = if !config.ports.is_empty() {
        Some(sandbox.start_port_forwarding(&config.ports)?)
    } else {
        None
    };

    // Inject CA cert and secret placeholders when proxy is active
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

    info!("VM ready");

    Ok((sandbox, instance_dir, proxy_handle, fwd_handle))
}

fn run_vm_loop(
    sandbox: shuru_vm::Sandbox,
    instance_dir: &str,
    cmd_rx: std::sync::mpsc::Receiver<SandboxCmd>,
    proxy_handle: Option<shuru_proxy::ProxyHandle>,
    _fwd_handle: Option<shuru_vm::PortForwardHandle>,
) {
    // Secret placeholder env vars — passed to all commands
    let env: HashMap<String, String> = proxy_handle
        .as_ref()
        .map(|h| h.placeholders.clone())
        .unwrap_or_default();

    // Keep proxy_handle alive for the lifetime of the VM
    let _proxy = proxy_handle;

    while let Ok(cmd) = cmd_rx.recv() {
        match cmd {
            SandboxCmd::Exec { argv, reply } => {
                let result = exec_command(&sandbox, &argv, &env);
                let _ = reply.send(result);
            }
            SandboxCmd::ReadFile { path, reply } => {
                let _ = reply.send(sandbox.read_file(&path));
            }
            SandboxCmd::WriteFile { path, content, reply } => {
                let _ = reply.send(sandbox.write_file(&path, &content));
            }
            SandboxCmd::ReadDir { path, reply } => {
                let _ = reply.send(sandbox.read_dir(&path));
            }
            SandboxCmd::OpenShell { rows, cols, reply } => {
                let result = sandbox.open_shell(&["/bin/bash", "-l"], &env, rows, cols);
                let _ = reply.send(result);
            }
            SandboxCmd::Checkpoint { name, reply } => {
                let result = (|| -> Result<()> {
                    let data_dir = shuru_vm::default_data_dir();
                    let checkpoints_dir = format!("{}/checkpoints", data_dir);
                    std::fs::create_dir_all(&checkpoints_dir)?;
                    let checkpoint_path = format!("{}/{}.ext4", checkpoints_dir, name);
                    if std::path::Path::new(&checkpoint_path).exists() {
                        std::fs::remove_file(&checkpoint_path)?;
                    }
                    let work_rootfs = format!("{}/rootfs.ext4", instance_dir);
                    clone_file_cow(&work_rootfs, &checkpoint_path)?;
                    info!("checkpoint '{}' saved", name);
                    Ok(())
                })();
                let _ = reply.send(result);
            }
            SandboxCmd::Stop { reply } => {
                let _ = reply.send(sandbox.stop());
                break;
            }
        }
    }

    // Ensure cleanup
    let _ = sandbox.stop();
}

fn exec_command(
    sandbox: &shuru_vm::Sandbox,
    argv: &[String],
    env: &HashMap<String, String>,
) -> Result<ExecResult> {
    let mut stdout_buf = Vec::new();
    let mut stderr_buf = Vec::new();
    let argv_refs: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();

    let exit_code = sandbox.exec_with_env(&argv_refs, env, &mut stdout_buf, &mut stderr_buf)?;

    Ok(ExecResult {
        stdout: String::from_utf8_lossy(&stdout_buf).to_string(),
        stderr: String::from_utf8_lossy(&stderr_buf).to_string(),
        exit_code,
    })
}
