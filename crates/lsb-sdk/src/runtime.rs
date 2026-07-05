use std::collections::HashMap;
use std::io::BufReader;
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{bail, Result};
use lsb_platform::{asset_paths, PlatformNetworkAttachment};
use lsb_proxy::config::ProxyConfig;
use tokio::sync::{mpsc, oneshot};
use tracing::info;

use crate::process::{spawn_process_threads, ProcessHandle};
use crate::shell::{ShellEvent, ShellHandle, ShellReader, ShellWriter};
use crate::storage::{prepare_storage, StoragePrepareOptions};
use crate::types::{CommandOptions, ExecResult, SandboxConfig};
use crate::watch::{spawn_watch_thread, WatchHandle};
use crate::{ReadDirResponse, StatResponse};

static INSTANCE_COUNTER: AtomicU64 = AtomicU64::new(0);

enum SandboxCmd {
    Exec {
        argv: Vec<String>,
        cwd: Option<String>,
        env: HashMap<String, String>,
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
    Stat {
        path: String,
        reply: oneshot::Sender<Result<StatResponse>>,
    },
    Mkdir {
        path: String,
        recursive: bool,
        reply: oneshot::Sender<Result<()>>,
    },
    Remove {
        path: String,
        recursive: bool,
        reply: oneshot::Sender<Result<()>>,
    },
    Rename {
        old_path: String,
        new_path: String,
        reply: oneshot::Sender<Result<()>>,
    },
    Copy {
        src: String,
        dst: String,
        recursive: bool,
        reply: oneshot::Sender<Result<()>>,
    },
    Chmod {
        path: String,
        mode: u32,
        reply: oneshot::Sender<Result<()>>,
    },
    OpenExec {
        argv: Vec<String>,
        cwd: Option<String>,
        env: HashMap<String, String>,
        reply: oneshot::Sender<Result<TcpStream>>,
    },
    OpenWatch {
        path: String,
        recursive: bool,
        reply: oneshot::Sender<Result<TcpStream>>,
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

/// Async wrapper around a lsb VM sandbox.
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
            .name("lsb-vm".into())
            .spawn(move || match boot_vm(config) {
                Ok((
                    sandbox,
                    instance_dir,
                    checkpoints_dir,
                    proxy_handle,
                    fwd_handle,
                    nbd_handle,
                )) => {
                    if ready_tx.send(Ok(instance_dir.clone())).is_err() {
                        return;
                    }
                    run_vm_loop(
                        sandbox,
                        &instance_dir,
                        &checkpoints_dir,
                        cmd_rx,
                        proxy_handle,
                        fwd_handle,
                        nbd_handle,
                    );
                }
                Err(e) => {
                    let _ = ready_tx.send(Err(e));
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
        self.exec_with_options(argv, CommandOptions::default())
            .await
    }

    /// Execute a command with cwd and environment overrides.
    pub async fn exec_with_options(
        &self,
        argv: &[&str],
        options: CommandOptions,
    ) -> Result<ExecResult> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(SandboxCmd::Exec {
                argv: argv.iter().map(|s| s.to_string()).collect(),
                cwd: options.cwd,
                env: options.env,
                reply: reply_tx,
            })
            .map_err(|_| anyhow::anyhow!("VM thread exited"))?;
        reply_rx.await?
    }

    /// Execute a shell command string via `/bin/sh -c`.
    pub async fn exec_shell(&self, command: &str) -> Result<ExecResult> {
        self.exec(&["/bin/sh", "-c", command]).await
    }

    /// Execute a shell command string via `/bin/sh -c` with options.
    pub async fn exec_shell_with_options(
        &self,
        command: &str,
        options: CommandOptions,
    ) -> Result<ExecResult> {
        self.exec_with_options(&["/bin/sh", "-c", command], options)
            .await
    }

    /// Start a streaming process with separate stdout/stderr streams.
    pub async fn spawn(&self, argv: &[&str], options: CommandOptions) -> Result<ProcessHandle> {
        let stream = self.open_exec(argv, options).await?;
        Ok(spawn_process_threads(stream))
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

        let writer_stream = stream.try_clone()?;
        let reader_stream = stream;
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        let reader_thread = std::thread::Builder::new()
            .name("lsb-shell-reader".into())
            .spawn(move || {
                let mut reader = BufReader::new(reader_stream);
                loop {
                    match lsb_proto::frame::read_frame(&mut reader) {
                        Ok(Some((lsb_proto::frame::STDOUT, payload))) => {
                            if event_tx.send(ShellEvent::Output(payload)).is_err() {
                                break;
                            }
                        }
                        Ok(Some((lsb_proto::frame::EXIT, payload))) => {
                            let code = lsb_proto::frame::parse_exit_code(&payload).unwrap_or(0);
                            let _ = event_tx.send(ShellEvent::Exit(code));
                            break;
                        }
                        Ok(Some((lsb_proto::frame::ERROR, payload))) => {
                            let msg = String::from_utf8_lossy(&payload).to_string();
                            let _ = event_tx.send(ShellEvent::Error(msg));
                            break;
                        }
                        Ok(Some(_)) => {}
                        Ok(None) | Err(_) => break,
                    }
                }
            })?;

        Ok(ShellHandle {
            writer: ShellWriter {
                writer: Arc::new(std::sync::Mutex::new(writer_stream)),
            },
            reader: ShellReader {
                output_rx: event_rx,
            },
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

    /// Get file or directory metadata in the VM.
    pub async fn stat(&self, path: &str) -> Result<StatResponse> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(SandboxCmd::Stat {
                path: path.to_string(),
                reply: reply_tx,
            })
            .map_err(|_| anyhow::anyhow!("VM thread exited"))?;
        reply_rx.await?
    }

    pub async fn mkdir(&self, path: &str, recursive: bool) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(SandboxCmd::Mkdir {
                path: path.to_string(),
                recursive,
                reply: reply_tx,
            })
            .map_err(|_| anyhow::anyhow!("VM thread exited"))?;
        reply_rx.await?
    }

    pub async fn remove(&self, path: &str, recursive: bool) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(SandboxCmd::Remove {
                path: path.to_string(),
                recursive,
                reply: reply_tx,
            })
            .map_err(|_| anyhow::anyhow!("VM thread exited"))?;
        reply_rx.await?
    }

    pub async fn rename(&self, old_path: &str, new_path: &str) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(SandboxCmd::Rename {
                old_path: old_path.to_string(),
                new_path: new_path.to_string(),
                reply: reply_tx,
            })
            .map_err(|_| anyhow::anyhow!("VM thread exited"))?;
        reply_rx.await?
    }

    pub async fn copy(&self, src: &str, dst: &str, recursive: bool) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(SandboxCmd::Copy {
                src: src.to_string(),
                dst: dst.to_string(),
                recursive,
                reply: reply_tx,
            })
            .map_err(|_| anyhow::anyhow!("VM thread exited"))?;
        reply_rx.await?
    }

    pub async fn chmod(&self, path: &str, mode: u32) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(SandboxCmd::Chmod {
                path: path.to_string(),
                mode,
                reply: reply_tx,
            })
            .map_err(|_| anyhow::anyhow!("VM thread exited"))?;
        reply_rx.await?
    }

    pub async fn exists(&self, path: &str) -> Result<bool> {
        match self.stat(path).await {
            Ok(_) => Ok(true),
            Err(error) if error.to_string().contains("No such file or directory") => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Watch guest filesystem changes.
    pub async fn watch(&self, path: &str, recursive: bool) -> Result<WatchHandle> {
        let stream = self.open_watch(path, recursive).await?;
        Ok(spawn_watch_thread(stream))
    }

    async fn open_exec(&self, argv: &[&str], options: CommandOptions) -> Result<TcpStream> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(SandboxCmd::OpenExec {
                argv: argv.iter().map(|s| s.to_string()).collect(),
                cwd: options.cwd,
                env: options.env,
                reply: reply_tx,
            })
            .map_err(|_| anyhow::anyhow!("VM thread exited"))?;
        reply_rx.await?
    }

    async fn open_watch(&self, path: &str, recursive: bool) -> Result<TcpStream> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(SandboxCmd::OpenWatch {
                path: path.to_string(),
                recursive,
                reply: reply_tx,
            })
            .map_err(|_| anyhow::anyhow!("VM thread exited"))?;
        reply_rx.await?
    }

    /// Save the current rootfs state as a named checkpoint.
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
        let (reply_tx, _) = oneshot::channel();
        let _ = self.cmd_tx.send(SandboxCmd::Stop { reply: reply_tx });
        let _ = std::fs::remove_dir_all(&self.instance_dir);
    }
}

fn boot_vm(
    config: SandboxConfig,
) -> Result<(
    lsb_vm::Sandbox,
    String,
    String,
    Option<lsb_proxy::ProxyHandle>,
    Option<lsb_vm::PortForwardHandle>,
    Option<lsb_store::NbdHandle>,
)> {
    let data_dir = config.data_dir.unwrap_or_else(lsb_vm::default_data_dir);
    let paths = asset_paths(&data_dir);

    let kernel_path = paths.kernel.clone();
    let rootfs_path = paths.rootfs.clone();
    let initrd_path_str = paths.initramfs.clone();

    if !std::path::Path::new(&kernel_path).exists() {
        bail!(
            "Kernel not found at {}. Run `lsb init` to download.",
            kernel_path
        );
    }

    if config.from.is_some() && config.base_version.is_some() {
        bail!("SandboxConfig::from and SandboxConfig::base_version cannot be used together");
    }

    let storage = prepare_storage(StoragePrepareOptions {
        data_dir: &data_dir,
        checkpoints_dir: &paths.checkpoints_dir,
        rootfs_path: &rootfs_path,
        from: config.from.as_deref(),
        base_version: config.base_version.as_deref(),
        custom_rootfs: false,
        direct: std::env::var("LSB_STORAGE").unwrap_or_default() == "direct",
    })?;

    let instance_dir = match config.instance_id {
        Some(id) => {
            if id.is_empty()
                || id.contains('/')
                || id.contains('\\')
                || id.contains('\0')
                || id.contains("..")
            {
                bail!("invalid instance id: '{}'", id);
            }
            format!("{}/{}", paths.instances_dir, id)
        }
        None => {
            let counter = INSTANCE_COUNTER.fetch_add(1, Ordering::SeqCst);
            format!(
                "{}/sdk-{}-{}",
                paths.instances_dir,
                std::process::id(),
                counter
            )
        }
    };
    let _ = std::fs::remove_dir_all(&instance_dir);
    std::fs::create_dir_all(&instance_dir)?;
    let work_rootfs = format!("{instance_dir}/rootfs.ext4");
    if storage.nbd_source.is_none() {
        lsb_platform::copy_file_cow(&storage.direct_source_rootfs, &work_rootfs)?;
    } else {
        std::fs::File::create(&work_rootfs)?;
    }

    let f = std::fs::OpenOptions::new().write(true).open(&work_rootfs)?;
    let target = config.disk_size_mb * 1024 * 1024;
    let current = if storage.nbd_source.is_some() {
        storage.logical_size
    } else {
        f.metadata()?.len()
    };
    if target < current {
        bail!(
            "disk_size_mb {}MB is smaller than the base image ({}MB)",
            config.disk_size_mb,
            current / 1024 / 1024
        );
    }
    if storage.nbd_source.is_none() && target > current {
        f.set_len(target)?;
    }
    drop(f);

    let initrd_path = if std::path::Path::new(&initrd_path_str).exists() {
        Some(initrd_path_str)
    } else {
        None
    };

    let (network_attachment, proxy_handle) = if config.allow_net {
        let mut proxy_config = ProxyConfig::default();
        proxy_config.secrets = config.secrets;
        proxy_config.network.allow = config.allowed_hosts;
        proxy_config.expose_host = config.expose_host;

        let link = lsb_proxy::create_proxy_link()?;
        let vm_attachment = platform_network_attachment(link.vm);
        let handle = lsb_proxy::start_link(link.host, proxy_config)?;
        (Some(vm_attachment), Some(handle))
    } else {
        (None, None)
    };

    let nbd_handle = if let Some(ref nbd_source) = storage.nbd_source {
        let socket_path = format!("{instance_dir}/nbd.sock");
        Some(lsb_store::start_cas_nbd_server(
            &nbd_source.rootfs_path,
            &format!("{data_dir}/cas"),
            &nbd_source.index_path,
            &socket_path,
            target,
        )?)
    } else {
        None
    };
    let nbd_uri = nbd_handle.as_ref().map(|handle| handle.uri());

    let mut builder = lsb_vm::Sandbox::builder()
        .kernel(&kernel_path)
        .rootfs(&work_rootfs)
        .cpus(config.cpus)
        .memory_mb(config.memory_mb)
        .console(false);

    if let Some(attachment) = network_attachment {
        builder = builder.network_attachment(attachment);
    }
    if let Some(uri) = nbd_uri {
        builder = builder.nbd_uri(uri);
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

    let fwd_handle = if !config.ports.is_empty() {
        Some(sandbox.start_port_forwarding(&config.ports)?)
    } else {
        None
    };

    if let Some(ref handle) = proxy_handle {
        if !handle.placeholders.is_empty() {
            sandbox.write_file(
                "/usr/local/share/ca-certificates/lsb-proxy.crt",
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

    Ok((
        sandbox,
        instance_dir,
        paths.checkpoints_dir,
        proxy_handle,
        fwd_handle,
        nbd_handle,
    ))
}

fn platform_network_attachment(
    attachment: lsb_proxy::VmNetworkAttachment,
) -> PlatformNetworkAttachment {
    match attachment {
        lsb_proxy::VmNetworkAttachment::FileDescriptor(fd) => {
            PlatformNetworkAttachment::file_descriptor(fd)
        }
        lsb_proxy::VmNetworkAttachment::QemuStream { host, port } => {
            PlatformNetworkAttachment::qemu_stream(host, port)
        }
    }
}

fn run_vm_loop(
    sandbox: lsb_vm::Sandbox,
    instance_dir: &str,
    checkpoints_dir: &str,
    cmd_rx: std::sync::mpsc::Receiver<SandboxCmd>,
    proxy_handle: Option<lsb_proxy::ProxyHandle>,
    _fwd_handle: Option<lsb_vm::PortForwardHandle>,
    nbd_handle: Option<lsb_store::NbdHandle>,
) {
    let env: HashMap<String, String> = proxy_handle
        .as_ref()
        .map(|h| h.placeholders.clone())
        .unwrap_or_default();

    let _proxy = proxy_handle;

    while let Ok(cmd) = cmd_rx.recv() {
        match cmd {
            SandboxCmd::Exec {
                argv,
                cwd,
                env: command_env,
                reply,
            } => {
                let mut combined_env = env.clone();
                combined_env.extend(command_env);
                let result = exec_command(&sandbox, &argv, &combined_env, cwd.as_deref());
                let _ = reply.send(result);
            }
            SandboxCmd::ReadFile { path, reply } => {
                let _ = reply.send(sandbox.read_file(&path));
            }
            SandboxCmd::WriteFile {
                path,
                content,
                reply,
            } => {
                let _ = reply.send(sandbox.write_file(&path, &content));
            }
            SandboxCmd::ReadDir { path, reply } => {
                let _ = reply.send(sandbox.read_dir(&path));
            }
            SandboxCmd::Stat { path, reply } => {
                let _ = reply.send(sandbox.stat(&path));
            }
            SandboxCmd::Mkdir {
                path,
                recursive,
                reply,
            } => {
                let _ = reply.send(sandbox.mkdir(&path, recursive));
            }
            SandboxCmd::Remove {
                path,
                recursive,
                reply,
            } => {
                let _ = reply.send(sandbox.remove(&path, recursive));
            }
            SandboxCmd::Rename {
                old_path,
                new_path,
                reply,
            } => {
                let _ = reply.send(sandbox.rename(&old_path, &new_path));
            }
            SandboxCmd::Copy {
                src,
                dst,
                recursive,
                reply,
            } => {
                let _ = reply.send(sandbox.copy(&src, &dst, recursive));
            }
            SandboxCmd::Chmod { path, mode, reply } => {
                let _ = reply.send(sandbox.chmod(&path, mode));
            }
            SandboxCmd::OpenExec {
                argv,
                cwd,
                env: command_env,
                reply,
            } => {
                let mut combined_env = env.clone();
                combined_env.extend(command_env);
                let result = sandbox.open_exec(&argv, &combined_env, cwd.as_deref());
                let _ = reply.send(result);
            }
            SandboxCmd::OpenWatch {
                path,
                recursive,
                reply,
            } => {
                let _ = reply.send(sandbox.open_watch(&path, recursive));
            }
            SandboxCmd::OpenShell { rows, cols, reply } => {
                let result = sandbox.open_shell(&["/bin/bash", "-l"], &env, rows, cols);
                let _ = reply.send(result);
            }
            SandboxCmd::Checkpoint { name, reply } => {
                let result = (|| -> Result<()> {
                    lsb_vm::validate_checkpoint_name(&name).map_err(|e| anyhow::anyhow!(e))?;
                    std::fs::create_dir_all(checkpoints_dir)?;
                    sandbox.exec(&["sync"], &mut std::io::sink(), &mut std::io::sink())?;
                    if let Some(ref handle) = nbd_handle {
                        let checkpoint_path = format!("{}/{}.idx", checkpoints_dir, name);
                        handle.save_checkpoint(&checkpoint_path)?;
                    } else {
                        let checkpoint_path = format!("{}/{}.ext4", checkpoints_dir, name);
                        if std::path::Path::new(&checkpoint_path).exists() {
                            std::fs::remove_file(&checkpoint_path)?;
                        }
                        let work_rootfs = format!("{instance_dir}/rootfs.ext4");
                        lsb_platform::copy_file_cow(&work_rootfs, &checkpoint_path)?;
                    }
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

    let _ = sandbox.stop();
}

fn exec_command(
    sandbox: &lsb_vm::Sandbox,
    argv: &[String],
    env: &HashMap<String, String>,
    cwd: Option<&str>,
) -> Result<ExecResult> {
    let argv_refs: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit_code =
        sandbox.exec_with_env_and_cwd(&argv_refs, env, cwd, &mut stdout, &mut stderr)?;

    Ok(ExecResult {
        stdout: String::from_utf8_lossy(&stdout).to_string(),
        stderr: String::from_utf8_lossy(&stderr).to_string(),
        exit_code,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    #[ignore = "requires Windows 11 x86_64 with WHPX, QEMU, outbound network, and disposable LocalSandbox assets"]
    fn windows_qemu_network_policy_proxy_smoke() {
        #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
        {
            eprintln!("skipping Windows QEMU network policy/proxy smoke on non-Windows host");
        }

        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        {
            use std::collections::HashMap;
            use std::path::{Path, PathBuf};

            use lsb_proxy::config::SecretConfig;

            use crate::types::SandboxConfig;

            let _storage_guard = EnvVarGuard::set("LSB_STORAGE", "direct");
            let data_dir = prepare_smoke_data_dir();
            let secret_value = "m12-real-secret-never-in-guest".to_string();
            let mut secrets = HashMap::new();
            secrets.insert(
                "M12_SECRET".to_string(),
                SecretConfig {
                    value: secret_value.clone(),
                    hosts: vec!["example.com".to_string()],
                },
            );

            let config = SandboxConfig {
                data_dir: Some(data_dir.display().to_string()),
                allow_net: true,
                allowed_hosts: vec!["example.com".to_string()],
                secrets,
                instance_id: Some(format!("m12-network-policy-{}", std::process::id())),
                ..Default::default()
            };

            let (sandbox, instance_dir, _checkpoints, proxy_handle, _fwd, _nbd) =
                super::boot_vm(config).expect("Windows allow-net sandbox should boot");

            let result = (|| -> anyhow::Result<()> {
                let proxy_handle = proxy_handle
                    .as_ref()
                    .expect("allow-net should keep a proxy handle alive");
                let placeholder = proxy_handle
                    .placeholders
                    .get("M12_SECRET")
                    .expect("secret placeholder should be generated");
                assert_ne!(placeholder, &secret_value);
                assert!(
                    placeholder.starts_with("lsb_tok_"),
                    "placeholder should be a guest token, got {placeholder}"
                );

                sandbox.write_file(
                    "/usr/local/share/ca-certificates/lsb-proxy.crt",
                    &proxy_handle.ca_cert_pem,
                )?;
                sandbox.exec(
                    &["update-ca-certificates", "--fresh"],
                    &mut std::io::sink(),
                    &mut std::io::sink(),
                )?;

                let mut env = HashMap::new();
                env.insert("M12_SECRET".to_string(), placeholder.clone());
                let allowed = sandbox.exec_with_env(
                    &[
                        "/usr/bin/curl",
                        "-fsS",
                        "--max-time",
                        "15",
                        "http://example.com/",
                    ],
                    &env,
                    &mut std::io::sink(),
                    &mut std::io::sink(),
                )?;
                assert_eq!(allowed, 0, "allowed host should succeed");

                let mut secret_stdout = Vec::new();
                let mut secret_stderr = Vec::new();
                let secret_env = sandbox.exec_with_env(
                    &["/bin/sh", "-c", "printf '%s' \"$M12_SECRET\""],
                    &env,
                    &mut secret_stdout,
                    &mut secret_stderr,
                )?;
                assert_eq!(
                    secret_env,
                    0,
                    "guest env placeholder read failed: {}",
                    String::from_utf8_lossy(&secret_stderr)
                );
                let guest_secret = String::from_utf8(secret_stdout)?;
                assert_eq!(
                    guest_secret,
                    placeholder.as_str(),
                    "guest env should contain the placeholder token"
                );
                assert_ne!(
                    guest_secret, secret_value,
                    "guest env must not contain the host-side secret"
                );

                let blocked = sandbox.exec_with_env(
                    &[
                        "/usr/bin/curl",
                        "-fsS",
                        "--max-time",
                        "8",
                        "http://iana.org/",
                    ],
                    &env,
                    &mut std::io::sink(),
                    &mut std::io::sink(),
                )?;
                assert_ne!(blocked, 0, "blocked domain should fail");

                let direct_ip = sandbox.exec_with_env(
                    &[
                        "/usr/bin/curl",
                        "-fsS",
                        "--max-time",
                        "8",
                        "http://93.184.216.34/",
                    ],
                    &env,
                    &mut std::io::sink(),
                    &mut std::io::sink(),
                )?;
                assert_ne!(direct_ip, 0, "direct IP egress should fail");

                let forged_host = sandbox.exec_with_env(
                    &[
                        "/usr/bin/curl",
                        "-fsS",
                        "--max-time",
                        "8",
                        "-H",
                        "Host: example.com",
                        "http://1.1.1.1/",
                    ],
                    &env,
                    &mut std::io::sink(),
                    &mut std::io::sink(),
                )?;
                assert_ne!(
                    forged_host, 0,
                    "forged allowed Host header to arbitrary IP should fail"
                );

                let forged_sni = sandbox.exec_with_env(
                    &[
                        "/usr/bin/curl",
                        "-fsS",
                        "--max-time",
                        "8",
                        "--resolve",
                        "example.com:443:1.1.1.1",
                        "https://example.com/",
                    ],
                    &env,
                    &mut std::io::sink(),
                    &mut std::io::sink(),
                )?;
                assert_ne!(
                    forged_sni, 0,
                    "forged allowed SNI to arbitrary IP should fail"
                );

                let argv_path = Path::new(&instance_dir)
                    .join("diagnostics")
                    .join("qemu.argv.redacted.txt");
                let argv = std::fs::read_to_string(&argv_path)
                    .unwrap_or_else(|error| panic!("read {}: {error}", argv_path.display()));
                assert!(argv.contains("-netdev"));
                assert!(argv.contains("stream,id=lsbproxy0"));
                assert!(argv.contains("virtio-net-pci,netdev=lsbproxy0"));
                assert!(!argv.contains("-netdev user"));
                assert!(!argv.contains("hostfwd"));
                assert!(!argv.contains(&secret_value));
                assert!(!argv.contains(placeholder));

                assert_smoke_artifacts_do_not_contain(Path::new(&instance_dir), &secret_value)?;

                Ok(())
            })();

            let stop_result = sandbox.stop();
            let post_stop_artifact_scan =
                assert_smoke_artifacts_do_not_contain(Path::new(&instance_dir), &secret_value);
            let _ = std::fs::remove_dir_all(&data_dir);
            result.expect("Windows network policy/proxy smoke should pass");
            stop_result.expect("Windows network smoke QEMU should stop cleanly");
            post_stop_artifact_scan
                .expect("Windows network smoke artifacts should not contain sentinel secret");

            struct EnvVarGuard {
                name: &'static str,
                old_value: Option<std::ffi::OsString>,
            }

            impl EnvVarGuard {
                fn set(name: &'static str, value: &str) -> Self {
                    let old_value = std::env::var_os(name);
                    std::env::set_var(name, value);
                    Self { name, old_value }
                }
            }

            impl Drop for EnvVarGuard {
                fn drop(&mut self) {
                    if let Some(value) = self.old_value.take() {
                        std::env::set_var(self.name, value);
                    } else {
                        std::env::remove_var(self.name);
                    }
                }
            }

            fn prepare_smoke_data_dir() -> PathBuf {
                let kernel = required_env_path("LSB_WINDOWS_BOOT_KERNEL");
                let initrd = required_env_path("LSB_WINDOWS_BOOT_INITRD");
                let rootfs = required_env_path("LSB_WINDOWS_BOOT_ROOTFS");
                let root = std::env::temp_dir()
                    .join(format!("lsb-sdk-m12-network-{}", std::process::id()));
                let _ = std::fs::remove_dir_all(&root);
                std::fs::create_dir_all(root.join("instances")).expect("create instances dir");
                std::fs::create_dir_all(root.join("checkpoints")).expect("create checkpoints dir");
                std::fs::copy(kernel, root.join("Image")).expect("copy kernel asset");
                std::fs::copy(initrd, root.join("initramfs.cpio.gz")).expect("copy initrd asset");
                std::fs::copy(rootfs, root.join("rootfs.ext4")).expect("copy rootfs asset");
                root
            }

            fn required_env_path(name: &str) -> PathBuf {
                std::env::var_os(name)
                    .map(PathBuf::from)
                    .unwrap_or_else(|| panic!("{name} must point to a disposable boot asset path"))
            }

            fn assert_smoke_artifacts_do_not_contain(
                instance_dir: &Path,
                sentinel: &str,
            ) -> anyhow::Result<()> {
                let diagnostics = instance_dir.join("diagnostics");
                if !diagnostics.exists() {
                    return Ok(());
                }

                let mut pending = vec![diagnostics];
                while let Some(dir) = pending.pop() {
                    for entry in std::fs::read_dir(&dir)? {
                        let entry = entry?;
                        let path = entry.path();
                        let file_type = entry.file_type()?;
                        if file_type.is_dir() {
                            pending.push(path);
                            continue;
                        }
                        if !file_type.is_file() {
                            continue;
                        }

                        let contents = std::fs::read(&path)?;
                        let text = String::from_utf8_lossy(&contents);
                        anyhow::ensure!(
                            !text.contains(sentinel),
                            "sentinel secret found in diagnostic artifact {}",
                            path.display()
                        );
                    }
                }

                Ok(())
            }
        }
    }
}
