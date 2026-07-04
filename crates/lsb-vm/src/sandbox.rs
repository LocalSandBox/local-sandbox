use std::collections::HashMap;
#[cfg(target_os = "macos")]
use std::io::{BufReader, BufWriter};
use std::io::{Read, Write};
use std::net::TcpStream;
#[cfg(target_os = "macos")]
use std::net::{Shutdown, TcpListener};
#[cfg(target_os = "macos")]
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
#[cfg(target_os = "macos")]
use std::time::Duration;

use anyhow::{bail, Context, Result};
use crossbeam_channel::Receiver;
#[cfg(target_os = "macos")]
use lsb_platform::terminal;
use lsb_platform::PlatformControlStream;
use lsb_platform::{self, PlatformSharedDir, PlatformVm, PlatformVmConfig, VmState};

use lsb_proto::{
    frame, ChmodRequest, CopyRequest, ExecRequest, FsOkResponse, MkdirRequest, MountRequest,
    MountResponse, PortMapping, ReadDirRequest, ReadDirResponse, ReadFileRequest, RemoveRequest,
    RenameRequest, StatRequest, StatResponse, WatchRequest, WriteFileRequest, WriteFileResponse,
};
#[cfg(target_os = "macos")]
use lsb_proto::{ForwardRequest, ForwardResponse, VSOCK_PORT, VSOCK_PORT_FORWARD};

#[cfg(not(target_os = "macos"))]
#[derive(Debug)]
struct UnsupportedWindowsRuntime {
    capability: &'static str,
    milestone: &'static str,
}

#[cfg(not(target_os = "macos"))]
impl std::fmt::Display for UnsupportedWindowsRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Windows support is in progress: {} is not implemented yet ({}); current Windows runtime support includes VM startup through the M07 guest-ready handshake and non-interactive exec through M08",
            self.capability, self.milestone
        )
    }
}

#[cfg(not(target_os = "macos"))]
impl std::error::Error for UnsupportedWindowsRuntime {}

#[cfg(not(target_os = "macos"))]
fn unsupported_runtime(capability: &'static str, milestone: &'static str) -> anyhow::Error {
    UnsupportedWindowsRuntime {
        capability,
        milestone,
    }
    .into()
}

// --- Mount types ---

const MS_RDONLY: u64 = 1;

#[derive(Debug, Clone)]
pub enum MountConfig {
    Overlay {
        host_path: String,
        guest_path: String,
    },
    Direct {
        host_path: String,
        guest_path: String,
        flags: u64,
    },
}

// --- VmConfigBuilder ---

pub struct VmConfigBuilder {
    kernel: Option<String>,
    rootfs: Option<String>,
    initrd: Option<String>,
    cpus: usize,
    memory_mb: u64,
    console: bool,
    verbose: bool,
    network_fd: Option<i32>,
    nbd_uri: Option<String>,
    mounts: Vec<MountConfig>,
}

impl VmConfigBuilder {
    pub(crate) fn new() -> Self {
        VmConfigBuilder {
            kernel: None,
            rootfs: None,
            initrd: None,
            cpus: 2,
            memory_mb: 2048,
            console: true,
            verbose: false,
            network_fd: None,
            nbd_uri: None,
            mounts: Vec::new(),
        }
    }

    /// When false, serial console stdin is disconnected and stdout goes to
    /// stderr. This prevents the serial console from consuming host stdin
    /// in exec/shell mode.
    pub fn console(mut self, enabled: bool) -> Self {
        self.console = enabled;
        self
    }

    /// When true, serial console output (kernel dmesg, initramfs) is shown
    /// even in non-console mode. Default is false (quiet).
    pub fn verbose(mut self, enabled: bool) -> Self {
        self.verbose = enabled;
        self
    }

    pub fn kernel(mut self, path: impl Into<String>) -> Self {
        self.kernel = Some(path.into());
        self
    }

    pub fn rootfs(mut self, path: impl Into<String>) -> Self {
        self.rootfs = Some(path.into());
        self
    }

    pub fn initrd(mut self, path: impl Into<String>) -> Self {
        self.initrd = Some(path.into());
        self
    }

    pub fn cpus(mut self, n: usize) -> Self {
        self.cpus = n;
        self
    }

    pub fn memory_mb(mut self, mb: u64) -> Self {
        self.memory_mb = mb;
        self
    }

    /// Attach a network device via a socketpair fd for proxy-based networking.
    pub fn network_fd(mut self, fd: i32) -> Self {
        self.network_fd = Some(fd);
        self
    }

    pub fn nbd_uri(mut self, uri: impl Into<String>) -> Self {
        self.nbd_uri = Some(uri.into());
        self
    }

    /// Add a host directory mount (virtio-fs).
    pub fn mount(mut self, config: MountConfig) -> Self {
        self.mounts.push(config);
        self
    }

    pub fn build(self) -> Result<Sandbox> {
        let kernel_path = self.kernel.context("kernel path is required")?;
        let rootfs_path = self.rootfs.context("rootfs path is required")?;

        let memory_bytes = self.memory_mb * 1024 * 1024;
        let (shared_dirs, mount_requests) = build_mount_plan(&self.mounts);

        Ok(Sandbox {
            vm: lsb_platform::create_vm(PlatformVmConfig {
                kernel_path,
                rootfs_path,
                initrd_path: self.initrd,
                cpus: self.cpus,
                memory_bytes,
                console: self.console,
                verbose: self.verbose,
                network_fd: self.network_fd,
                nbd_uri: self.nbd_uri,
                shared_dirs,
            })?,
            mounts: Mutex::new(mount_requests),
            #[cfg(not(target_os = "macos"))]
            control_session: Mutex::new(()),
        })
    }
}

// --- Sandbox ---

pub struct Sandbox {
    vm: Arc<dyn PlatformVm>,
    mounts: Mutex<Vec<MountRequest>>,
    #[cfg(not(target_os = "macos"))]
    control_session: Mutex<()>,
}

fn build_mount_plan(mounts: &[MountConfig]) -> (Vec<PlatformSharedDir>, Vec<MountRequest>) {
    let mut mount_requests = Vec::new();
    let mut shared_dirs = Vec::new();

    for (i, mount) in mounts.iter().enumerate() {
        let tag = format!("mount{}", i);
        match mount {
            MountConfig::Overlay {
                host_path,
                guest_path,
            } => {
                shared_dirs.push(PlatformSharedDir {
                    host_path: host_path.clone(),
                    tag: tag.clone(),
                    read_only: true,
                });
                mount_requests.push(MountRequest::Overlay {
                    source: tag,
                    target: guest_path.clone(),
                });
            }
            MountConfig::Direct {
                host_path,
                guest_path,
                flags,
            } => {
                shared_dirs.push(PlatformSharedDir {
                    host_path: host_path.clone(),
                    tag: tag.clone(),
                    read_only: flags & MS_RDONLY != 0,
                });
                mount_requests.push(MountRequest::Direct {
                    source: tag,
                    target: guest_path.clone(),
                    flags: *flags,
                });
            }
        }
    }

    (shared_dirs, mount_requests)
}

impl Sandbox {
    pub fn builder() -> VmConfigBuilder {
        VmConfigBuilder::new()
    }

    pub fn start(&self) -> Result<()> {
        self.vm.start().context("Failed to start VM")
    }

    pub fn stop(&self) -> Result<()> {
        self.vm.stop().context("Failed to stop VM")
    }

    pub fn state_channel(&self) -> Receiver<VmState> {
        self.vm.state_channel()
    }

    /// Send pending mount requests over an established vsock connection.
    /// Drains the mount list so subsequent calls are no-ops.
    fn send_mount_requests(&self, writer: &mut impl Write, reader: &mut impl Read) -> Result<()> {
        let mounts = std::mem::take(&mut *self.mounts.lock().unwrap());
        for req in &mounts {
            frame::send_json(writer, frame::MOUNT_REQ, &req).context("sending mount request")?;
            let (_msg_type, payload) = frame::read_frame(reader)
                .context("reading mount response")?
                .context("guest closed connection during mount init")?;
            let resp: MountResponse = match serde_json::from_slice(&payload) {
                Ok(r) => r,
                Err(_) => {
                    bail!(
                        "guest does not support directory mounts. \
                         Run `lsb upgrade` and recreate the checkpoint to enable --mount."
                    );
                }
            };
            if !resp.ok {
                let (source, target) = match req {
                    MountRequest::Overlay { source, target } => (source, target),
                    MountRequest::Direct { source, target, .. } => (source, target),
                };
                bail!(
                    "mount failed: {} -> {}: {}",
                    source,
                    target,
                    resp.error.unwrap_or_else(|| "unknown error".into())
                );
            }
        }
        Ok(())
    }

    /// Run a command non-interactively over vsock, streaming output to the
    /// provided writers. Returns the guest process exit code.
    pub fn exec(
        &self,
        argv: &[impl AsRef<str>],
        stdout: &mut impl Write,
        stderr: &mut impl Write,
    ) -> Result<i32> {
        self.exec_with_env(argv, &HashMap::new(), stdout, stderr)
    }

    pub fn exec_with_env(
        &self,
        argv: &[impl AsRef<str>],
        env: &HashMap<String, String>,
        stdout: &mut impl Write,
        stderr: &mut impl Write,
    ) -> Result<i32> {
        self.exec_with_env_and_cwd(argv, env, None, stdout, stderr)
    }

    pub fn exec_with_env_and_cwd(
        &self,
        argv: &[impl AsRef<str>],
        env: &HashMap<String, String>,
        cwd: Option<&str>,
        stdout: &mut impl Write,
        stderr: &mut impl Write,
    ) -> Result<i32> {
        #[cfg(not(target_os = "macos"))]
        let _control_guard = self
            .control_session
            .lock()
            .map_err(|_| anyhow::anyhow!("Windows guest control session lock poisoned"))?;

        let stream = self.connect_exec_control()?;
        let mut writer = stream.try_clone()?;
        let mut reader = stream;

        self.send_mount_requests(&mut writer, &mut reader)?;

        let req = build_exec_request(argv, env, cwd, None, Some(true));
        send_exec_request(&mut writer, &req)?;
        collect_exec_response(&mut reader, stdout, stderr)
    }

    pub fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        let stream = self.connect_vsock()?;
        let mut writer = stream.try_clone()?;
        let mut reader = stream;

        self.send_mount_requests(&mut writer, &mut reader)?;

        let req = ReadFileRequest {
            path: path.to_string(),
        };
        frame::send_json(&mut writer, frame::READ_FILE_REQ, &req)?;

        match frame::read_frame(&mut reader).context("reading read_file response")? {
            Some((frame::READ_FILE_RESP, payload)) => Ok(payload),
            Some((frame::ERROR, payload)) => {
                bail!("{}", String::from_utf8_lossy(&payload));
            }
            Some((other, _)) => {
                bail!(
                    "unexpected frame type 0x{:02x} in read_file response",
                    other
                );
            }
            None => bail!("guest closed connection during read_file"),
        }
    }

    pub fn write_file(&self, path: &str, content: &[u8]) -> Result<()> {
        let stream = self.connect_vsock()?;
        let mut writer = stream.try_clone()?;
        let mut reader = stream;

        self.send_mount_requests(&mut writer, &mut reader)?;

        let req = WriteFileRequest {
            path: path.to_string(),
            len: content.len() as u64,
        };
        frame::send_json(&mut writer, frame::WRITE_FILE_REQ, &req)?;
        frame::write_frame(&mut writer, frame::WRITE_FILE_DATA, content)?;

        let (_msg_type, payload) = frame::read_frame(&mut reader)
            .context("reading write_file response")?
            .context("guest closed connection during write_file")?;

        let resp: WriteFileResponse =
            serde_json::from_slice(&payload).context("parsing write_file response")?;

        if !resp.ok {
            bail!(
                "write_file failed: {}",
                resp.error.unwrap_or_else(|| "unknown error".into())
            );
        }

        Ok(())
    }

    /// Send a request and expect FS_OK_RESP or ERROR. Used by void fs ops.
    fn void_fs_op(&self, req_frame: u8, req: &impl serde::Serialize) -> Result<()> {
        let stream = self.connect_vsock()?;
        let mut writer = stream.try_clone()?;
        let mut reader = stream;

        self.send_mount_requests(&mut writer, &mut reader)?;

        frame::send_json(&mut writer, req_frame, req)?;

        match frame::read_frame(&mut reader).context("reading fs op response")? {
            Some((frame::FS_OK_RESP, payload)) => {
                let resp: FsOkResponse =
                    serde_json::from_slice(&payload).context("parsing fs ok response")?;
                if !resp.ok {
                    bail!("{}", resp.error.unwrap_or_else(|| "unknown error".into()));
                }
                Ok(())
            }
            Some((frame::ERROR, payload)) => {
                bail!("{}", String::from_utf8_lossy(&payload));
            }
            Some((other, _)) => {
                bail!("unexpected frame type 0x{:02x}", other);
            }
            None => bail!("guest closed connection"),
        }
    }

    pub fn mkdir(&self, path: &str, recursive: bool) -> Result<()> {
        self.void_fs_op(
            frame::MKDIR_REQ,
            &MkdirRequest {
                path: path.to_string(),
                recursive,
            },
        )
    }

    pub fn read_dir(&self, path: &str) -> Result<ReadDirResponse> {
        let stream = self.connect_vsock()?;
        let mut writer = stream.try_clone()?;
        let mut reader = stream;

        self.send_mount_requests(&mut writer, &mut reader)?;

        let req = ReadDirRequest {
            path: path.to_string(),
        };
        frame::send_json(&mut writer, frame::READ_DIR_REQ, &req)?;

        match frame::read_frame(&mut reader).context("reading read_dir response")? {
            Some((frame::READ_DIR_RESP, payload)) => {
                Ok(serde_json::from_slice(&payload).context("parsing read_dir response")?)
            }
            Some((frame::ERROR, payload)) => {
                bail!("{}", String::from_utf8_lossy(&payload));
            }
            Some((other, _)) => {
                bail!("unexpected frame type 0x{:02x} in read_dir response", other);
            }
            None => bail!("guest closed connection during read_dir"),
        }
    }

    pub fn stat(&self, path: &str) -> Result<StatResponse> {
        let stream = self.connect_vsock()?;
        let mut writer = stream.try_clone()?;
        let mut reader = stream;

        self.send_mount_requests(&mut writer, &mut reader)?;

        let req = StatRequest {
            path: path.to_string(),
        };
        frame::send_json(&mut writer, frame::STAT_REQ, &req)?;

        match frame::read_frame(&mut reader).context("reading stat response")? {
            Some((frame::STAT_RESP, payload)) => {
                Ok(serde_json::from_slice(&payload).context("parsing stat response")?)
            }
            Some((frame::ERROR, payload)) => {
                bail!("{}", String::from_utf8_lossy(&payload));
            }
            Some((other, _)) => {
                bail!("unexpected frame type 0x{:02x} in stat response", other);
            }
            None => bail!("guest closed connection during stat"),
        }
    }

    pub fn remove(&self, path: &str, recursive: bool) -> Result<()> {
        self.void_fs_op(
            frame::REMOVE_REQ,
            &RemoveRequest {
                path: path.to_string(),
                recursive,
            },
        )
    }

    pub fn rename(&self, old_path: &str, new_path: &str) -> Result<()> {
        self.void_fs_op(
            frame::RENAME_REQ,
            &RenameRequest {
                old_path: old_path.to_string(),
                new_path: new_path.to_string(),
            },
        )
    }

    pub fn copy(&self, src: &str, dst: &str, recursive: bool) -> Result<()> {
        self.void_fs_op(
            frame::COPY_REQ,
            &CopyRequest {
                src: src.to_string(),
                dst: dst.to_string(),
                recursive,
            },
        )
    }

    pub fn chmod(&self, path: &str, mode: u32) -> Result<()> {
        self.void_fs_op(
            frame::CHMOD_REQ,
            &ChmodRequest {
                path: path.to_string(),
                mode,
            },
        )
    }

    /// Open a vsock connection for streaming exec. Returns the raw stream
    /// after sending mounts + ExecRequest. Caller manages I/O (reads
    /// STDOUT/STDERR/EXIT frames, writes STDIN/KILL frames).
    pub fn open_exec(
        &self,
        argv: &[impl AsRef<str>],
        env: &HashMap<String, String>,
        cwd: Option<&str>,
    ) -> Result<TcpStream> {
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (argv, env, cwd);
            return Err(unsupported_runtime(
                "streaming exec stdin/kill",
                "M11 transport multiplexer; M08 supports non-interactive exec through Sandbox::exec",
            ));
        }

        #[cfg(target_os = "macos")]
        {
            let stream = self.connect_vsock()?;
            let mut writer = stream.try_clone()?;
            let mut reader = stream.try_clone()?;

            self.send_mount_requests(&mut writer, &mut reader)?;

            let req = build_exec_request(argv, env, cwd, None, None);
            send_exec_request(&mut writer, &req)?;

            Ok(stream)
        }
    }

    /// Open a vsock connection for an interactive shell with PTY support.
    /// Like `open_exec` but with `tty=true`. Returns the raw stream after
    /// sending mounts + ExecRequest. Caller manages I/O using the binary
    /// frame protocol (STDIN/STDOUT/RESIZE/EXIT frames).
    pub fn open_shell(
        &self,
        argv: &[impl AsRef<str>],
        env: &HashMap<String, String>,
        rows: u16,
        cols: u16,
    ) -> Result<TcpStream> {
        let stream = self.connect_vsock()?;
        let mut writer = stream.try_clone()?;
        let mut reader = stream.try_clone()?;

        self.send_mount_requests(&mut writer, &mut reader)?;

        let req = ExecRequest {
            argv: argv.iter().map(|s| s.as_ref().to_string()).collect(),
            env: env.clone(),
            tty: Some(true),
            rows: Some(rows),
            cols: Some(cols),
            cwd: None,
            stdin_closed: None,
        };
        frame::send_json(&mut writer, frame::EXEC_REQ, &req)?;

        Ok(stream)
    }

    /// Open a vsock connection for file watching. Returns a stream that
    /// emits WATCH_EVENT frames until the connection is closed.
    pub fn open_watch(&self, path: &str, recursive: bool) -> Result<TcpStream> {
        let stream = self.connect_vsock()?;
        let mut writer = stream.try_clone()?;
        let mut reader = stream.try_clone()?;

        self.send_mount_requests(&mut writer, &mut reader)?;

        let req = WatchRequest {
            path: path.to_string(),
            recursive,
        };
        frame::send_json(&mut writer, frame::WATCH_REQ, &req)?;

        Ok(stream)
    }

    /// Run an interactive shell session with PTY support.
    /// Puts the host terminal in raw mode, relays I/O bidirectionally over
    /// vsock, and handles SIGWINCH for window resize.
    /// Returns the guest process exit code.
    #[cfg(target_os = "macos")]
    pub fn shell(&self, argv: &[impl AsRef<str>], env: &HashMap<String, String>) -> Result<i32> {
        let stdin_fd = std::io::stdin().as_raw_fd();
        let (rows, cols) = terminal::terminal_size(stdin_fd);

        let stream = self.connect_vsock()?;
        let mut writer = stream.try_clone()?;
        let mut reader = stream;

        // Mount phase (sync, before raw mode)
        self.send_mount_requests(&mut writer, &mut reader)?;

        // Send ExecRequest with tty=true
        let req = ExecRequest {
            argv: argv.iter().map(|s| s.as_ref().to_string()).collect(),
            env: env.clone(),
            tty: Some(true),
            rows: Some(rows),
            cols: Some(cols),
            cwd: None,
            stdin_closed: None,
        };
        frame::send_json(&mut writer, frame::EXEC_REQ, &req)?;

        // Enter raw mode - TerminalState restores on drop
        let _raw_guard = terminal::TerminalState::enter_raw_mode(stdin_fd);

        // Set up kqueue-based stdin relay (zero-latency I/O multiplexing)
        let (relay, shutdown_signal) =
            terminal::StdinRelay::new(stdin_fd).expect("failed to init stdin relay");

        let exit_code = Arc::new(Mutex::new(0i32));

        // Thread A: stdin → vsock (kqueue blocks until data/resize/shutdown)
        let mut vsock_writer = writer.try_clone()?;
        let stdin_thread = std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match relay.wait() {
                    terminal::StdinEvent::Ready => {
                        let n = terminal::read_raw(stdin_fd, &mut buf);
                        if n == 0 {
                            break;
                        }
                        if frame::write_frame(&mut vsock_writer, frame::STDIN, &buf[..n]).is_err() {
                            break;
                        }
                    }
                    terminal::StdinEvent::Resize => {
                        let (rows, cols) = terminal::terminal_size(stdin_fd);
                        let payload = frame::resize_payload(rows, cols);
                        if frame::write_frame(&mut vsock_writer, frame::RESIZE, &payload).is_err() {
                            break;
                        }
                    }
                    terminal::StdinEvent::Shutdown => break,
                }
            }
        });

        // Thread B: vsock -> stdout (read binary frames, write raw output)
        // Uses BufWriter + deferred flush to batch rapid TUI updates into
        // fewer terminal writes, preventing visible tearing/flickering.
        let exit_code_b = exit_code.clone();
        let vsock_thread = std::thread::spawn(move || {
            let mut reader = BufReader::new(reader);
            let mut stdout = BufWriter::new(std::io::stdout());
            loop {
                match frame::read_frame(&mut reader) {
                    Ok(Some((frame::STDOUT, payload))) => {
                        let _ = stdout.write_all(&payload);
                        // Only flush to the terminal when no more data is
                        // already buffered from the vsock. This batches
                        // rapid sequential messages (e.g. a full TUI
                        // screen redraw) into a single terminal write.
                        if reader.buffer().is_empty() {
                            let _ = stdout.flush();
                        }
                    }
                    Ok(Some((frame::EXIT, payload))) => {
                        let _ = stdout.flush();
                        *exit_code_b.lock().unwrap() =
                            frame::parse_exit_code(&payload).unwrap_or(0);
                        break;
                    }
                    Ok(Some((frame::ERROR, payload))) => {
                        let _ = stdout.flush();
                        let msg = String::from_utf8_lossy(&payload);
                        let _ = std::io::stderr()
                            .write_all(format!("guest error: {}\r\n", msg).as_bytes());
                        *exit_code_b.lock().unwrap() = 1;
                        break;
                    }
                    Ok(Some(_)) => {} // unknown type, skip
                    Ok(None) | Err(_) => break,
                }
            }
            let _ = stdout.flush();
            shutdown_signal.signal();
        });

        // Wait for threads
        let _ = vsock_thread.join();
        let _ = stdin_thread.join();

        // Terminal restored by _raw_guard drop
        // SIGWINCH restored by StdinRelay drop
        let code = *exit_code.lock().unwrap();
        Ok(code)
    }

    /// Interactive shell support on Windows depends on the future control
    /// transport and PTY work; M01 only guarantees compile-time scaffolding.
    #[cfg(not(target_os = "macos"))]
    pub fn shell(&self, _argv: &[impl AsRef<str>], _env: &HashMap<String, String>) -> Result<i32> {
        Err(unsupported_runtime(
            "interactive shell",
            "M06 virtio-serial control transport and M08 exec",
        ))
    }

    /// Start port forwarding proxies. Returns a handle that stops all
    /// listeners when dropped.
    #[cfg(target_os = "macos")]
    pub fn start_port_forwarding(&self, forwards: &[PortMapping]) -> Result<PortForwardHandle> {
        let stop = Arc::new(AtomicBool::new(false));
        let mut listeners = Vec::new();

        for mapping in forwards {
            let addr = format!("127.0.0.1:{}", mapping.host_port);
            let tcp_listener = TcpListener::bind(&addr)
                .with_context(|| format!("Failed to bind port {}", mapping.host_port))?;
            tcp_listener.set_nonblocking(true)?;

            let guest_port = mapping.guest_port;
            let vm = Arc::clone(&self.vm);
            let stop_flag = stop.clone();

            eprintln!(
                "lsb: forwarding 127.0.0.1:{} -> guest:{}",
                mapping.host_port, mapping.guest_port
            );

            let handle = std::thread::spawn(move || {
                while !stop_flag.load(Ordering::Relaxed) {
                    match tcp_listener.accept() {
                        Ok((tcp_stream, _)) => {
                            // macOS accept() inherits non-blocking from the
                            // listener — force blocking for the relay.
                            let _ = tcp_stream.set_nonblocking(false);
                            let vm = Arc::clone(&vm);
                            std::thread::spawn(move || {
                                if let Err(e) =
                                    handle_forward_connection(tcp_stream, vm.as_ref(), guest_port)
                                {
                                    tracing::debug!("port forward error: {}", e);
                                }
                            });
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(50));
                        }
                        Err(e) => {
                            if !stop_flag.load(Ordering::Relaxed) {
                                tracing::debug!("accept error on port forward listener: {}", e);
                            }
                            break;
                        }
                    }
                }
            });

            listeners.push(handle);
        }

        Ok(PortForwardHandle {
            stop,
            threads: listeners,
        })
    }

    /// Windows port forwarding must preserve no-network-by-default. Until the
    /// transport is implemented, fail before opening any host listener.
    #[cfg(not(target_os = "macos"))]
    pub fn start_port_forwarding(&self, _forwards: &[PortMapping]) -> Result<PortForwardHandle> {
        Err(unsupported_runtime(
            "port forwarding",
            "M11 port forwarding; no listener was opened",
        ))
    }

    #[cfg(target_os = "macos")]
    fn connect_vsock(&self) -> Result<TcpStream> {
        let state_rx = self.vm.state_channel();
        for attempt in 1..=50 {
            // Check if VM died (e.g. guest mount failure -> reboot POWER_OFF)
            if let Ok(state) = state_rx.try_recv() {
                match state {
                    VmState::Stopped => {
                        bail!("VM stopped during startup - check boot output above for errors")
                    }
                    VmState::Error => bail!("VM encountered an error during startup"),
                    _ => {}
                }
            }
            match self.vm.connect_to_vsock_port(VSOCK_PORT) {
                Ok(s) => {
                    let _ = s.set_nodelay(true);
                    return Ok(s);
                }
                Err(e) => {
                    if attempt == 50 {
                        bail!(
                            "Failed to connect to guest after {} attempts: {}",
                            attempt,
                            e
                        );
                    }
                    tracing::debug!("vsock connect attempt {} failed: {}", attempt, e);
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        }
        unreachable!()
    }

    #[cfg(not(target_os = "macos"))]
    fn connect_vsock(&self) -> Result<TcpStream> {
        Err(unsupported_runtime(
            "macOS-style vsock guest control transport",
            "Windows M08 supports non-interactive exec over virtio-serial; file APIs, watch, shell, streaming spawn, port forwarding, and muxed sessions are later milestones",
        ))
    }

    #[cfg(target_os = "macos")]
    fn connect_exec_control(&self) -> Result<PlatformControlStream> {
        self.connect_vsock()
            .map(PlatformControlStream::from_tcp_stream)
    }

    #[cfg(not(target_os = "macos"))]
    fn connect_exec_control(&self) -> Result<PlatformControlStream> {
        let stream = self
            .vm
            .connect_control()
            .context("opening Windows virtio-serial exec control stream")?;
        let _ = stream.set_nodelay_if_tcp(true);
        Ok(stream)
    }
}

fn build_exec_request(
    argv: &[impl AsRef<str>],
    env: &HashMap<String, String>,
    cwd: Option<&str>,
    tty: Option<bool>,
    stdin_closed: Option<bool>,
) -> ExecRequest {
    ExecRequest {
        argv: argv.iter().map(|s| s.as_ref().to_string()).collect(),
        env: env.clone(),
        tty,
        rows: None,
        cols: None,
        cwd: cwd.map(|s| s.to_string()),
        stdin_closed,
    }
}

fn send_exec_request(writer: &mut impl Write, req: &ExecRequest) -> Result<()> {
    frame::send_json(writer, frame::EXEC_REQ, req).context("sending exec request")
}

fn collect_exec_response(
    reader: &mut impl Read,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<i32> {
    loop {
        match frame::read_frame(reader).context("reading guest exec response")? {
            Some((frame::STDOUT, payload)) => {
                stdout.write_all(&payload)?;
            }
            Some((frame::STDERR, payload)) => {
                stderr.write_all(&payload)?;
            }
            Some((frame::EXIT, payload)) => {
                return Ok(frame::parse_exit_code(&payload).unwrap_or(0));
            }
            Some((frame::ERROR, payload)) => {
                let msg = String::from_utf8_lossy(&payload);
                write!(stderr, "guest error: {}", msg)?;
                return Ok(1);
            }
            Some(_) => {} // unknown frame, skip
            None => bail!("guest closed exec stream before exit"),
        }
    }
}

// --- Port forwarding ---

/// Handle returned by `start_port_forwarding`. Signals all listener threads
/// to stop and joins them when dropped.
pub struct PortForwardHandle {
    stop: Arc<AtomicBool>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

impl Drop for PortForwardHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

#[cfg(target_os = "macos")]
fn handle_forward_connection(
    tcp_stream: TcpStream,
    vm: &dyn PlatformVm,
    guest_port: u16,
) -> Result<()> {
    let mut vsock_stream = vm
        .connect_to_vsock_port(VSOCK_PORT_FORWARD)
        .map_err(|e| anyhow::anyhow!("vsock connect for port forward: {}", e))?;
    let _ = vsock_stream.set_nodelay(true);

    // Send forward request
    let req = ForwardRequest { port: guest_port };
    frame::send_json(&mut vsock_stream, frame::FWD_REQ, &req)?;

    // Read response frame
    let (_msg_type, payload) = frame::read_frame(&mut vsock_stream)
        .context("reading forward response")?
        .context("guest closed connection during forward handshake")?;
    let resp: ForwardResponse =
        serde_json::from_slice(&payload).context("parsing forward response")?;

    if resp.status != "ok" {
        bail!(
            "guest refused forward: {}",
            resp.message.unwrap_or_default()
        );
    }

    // Bidirectional relay between TCP and vsock
    relay(tcp_stream, vsock_stream);
    Ok(())
}

#[cfg(target_os = "macos")]
fn relay(a: TcpStream, b: TcpStream) {
    let mut a_read = a.try_clone().expect("clone tcp stream");
    let mut b_write = b.try_clone().expect("clone vsock stream");
    let mut b_read = b;
    let mut a_write = a;

    let t1 = std::thread::spawn(move || {
        let _ = std::io::copy(&mut a_read, &mut b_write);
        let _ = b_write.shutdown(Shutdown::Write);
    });
    let t2 = std::thread::spawn(move || {
        let _ = std::io::copy(&mut b_read, &mut a_write);
        let _ = a_write.shutdown(Shutdown::Write);
    });
    let _ = t1.join();
    let _ = t2.join();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    use std::path::PathBuf;

    #[test]
    fn overlay_mount_generates_readonly_shared_dir_and_overlay_request() {
        let mounts = vec![MountConfig::Overlay {
            host_path: "/host".into(),
            guest_path: "/workspace".into(),
        }];

        let (shared_dirs, mount_requests) = build_mount_plan(&mounts);

        assert_eq!(shared_dirs.len(), 1);
        assert_eq!(shared_dirs[0].host_path, "/host");
        assert_eq!(shared_dirs[0].tag, "mount0");
        assert!(shared_dirs[0].read_only);

        match &mount_requests[0] {
            MountRequest::Overlay { source, target } => {
                assert_eq!(source, "mount0");
                assert_eq!(target, "/workspace");
            }
            MountRequest::Direct { .. } => panic!("expected overlay request"),
        }
    }

    #[test]
    fn direct_mount_preserves_flags_and_derives_platform_readonly() {
        let mounts = vec![
            MountConfig::Direct {
                host_path: "/rw".into(),
                guest_path: "/rw".into(),
                flags: 0,
            },
            MountConfig::Direct {
                host_path: "/ro".into(),
                guest_path: "/ro".into(),
                flags: MS_RDONLY,
            },
        ];

        let (shared_dirs, mount_requests) = build_mount_plan(&mounts);

        assert!(!shared_dirs[0].read_only);
        assert!(shared_dirs[1].read_only);

        match &mount_requests[0] {
            MountRequest::Direct {
                source,
                target,
                flags,
            } => {
                assert_eq!(source, "mount0");
                assert_eq!(target, "/rw");
                assert_eq!(*flags, 0);
            }
            MountRequest::Overlay { .. } => panic!("expected direct request"),
        }

        match &mount_requests[1] {
            MountRequest::Direct {
                source,
                target,
                flags,
            } => {
                assert_eq!(source, "mount1");
                assert_eq!(target, "/ro");
                assert_eq!(*flags, MS_RDONLY);
            }
            MountRequest::Overlay { .. } => panic!("expected direct request"),
        }
    }

    #[test]
    fn exec_request_frame_includes_argv_env_and_cwd() {
        let mut env = HashMap::new();
        env.insert("LSB_M08_ENV".to_string(), "present".to_string());
        let req = build_exec_request(
            &["/bin/sh", "-c", "printf test"],
            &env,
            Some("/workspace"),
            None,
            Some(true),
        );
        let mut encoded = Vec::new();

        send_exec_request(&mut encoded, &req).expect("exec request should encode");

        let mut reader = Cursor::new(encoded);
        let (msg_type, payload) = frame::read_frame(&mut reader)
            .expect("frame should decode")
            .expect("frame should be present");
        let decoded: ExecRequest =
            serde_json::from_slice(&payload).expect("exec request should decode");

        assert_eq!(msg_type, frame::EXEC_REQ);
        assert_eq!(decoded.argv, ["/bin/sh", "-c", "printf test"]);
        assert_eq!(
            decoded.env.get("LSB_M08_ENV").map(String::as_str),
            Some("present")
        );
        assert_eq!(decoded.cwd.as_deref(), Some("/workspace"));
        assert_eq!(decoded.tty, None);
        assert_eq!(decoded.stdin_closed, Some(true));
    }

    #[test]
    fn exec_response_streams_stdout_stderr_and_exit_code() {
        let mut reader = exec_response_stream(&[
            (frame::STDOUT, b"hello ".as_slice()),
            (frame::STDERR, b"warn".as_slice()),
            (frame::STDOUT, b"world\n".as_slice()),
            (frame::EXIT, &frame::exit_payload(0)),
        ]);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code =
            collect_exec_response(&mut reader, &mut stdout, &mut stderr).expect("exec response");

        assert_eq!(exit_code, 0);
        assert_eq!(stdout, b"hello world\n");
        assert_eq!(stderr, b"warn");
    }

    #[test]
    fn exec_response_preserves_nonzero_exit_code() {
        let mut reader = exec_response_stream(&[(frame::EXIT, &frame::exit_payload(7))]);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code =
            collect_exec_response(&mut reader, &mut stdout, &mut stderr).expect("exec response");

        assert_eq!(exit_code, 7);
        assert!(stdout.is_empty());
        assert!(stderr.is_empty());
    }

    #[test]
    fn exec_response_collects_large_stdout_frame() {
        let large = vec![b'x'; 256 * 1024];
        let mut reader = exec_response_stream(&[
            (frame::STDOUT, &large),
            (frame::EXIT, &frame::exit_payload(0)),
        ]);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code =
            collect_exec_response(&mut reader, &mut stdout, &mut stderr).expect("exec response");

        assert_eq!(exit_code, 0);
        assert_eq!(stdout, large);
        assert!(stderr.is_empty());
    }

    #[test]
    fn exec_response_maps_guest_error_to_stderr_and_exit_one() {
        let mut reader = exec_response_stream(&[(frame::ERROR, b"failed to spawn: missing")]);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code =
            collect_exec_response(&mut reader, &mut stdout, &mut stderr).expect("exec response");

        assert_eq!(exit_code, 1);
        assert!(stdout.is_empty());
        assert_eq!(stderr, b"guest error: failed to spawn: missing");
    }

    #[test]
    fn exec_response_ignores_guest_ready_frames_before_output() {
        let mut ready =
            lsb_proto::GuestReady::new(lsb_proto::GuestTransport::VirtioSerial, "guest-test");
        ready.capabilities.push("exec".to_string());
        let ready_payload = serde_json::to_vec(&ready).expect("ready should encode");
        let mut reader = exec_response_stream(&[
            (frame::GUEST_READY, &ready_payload),
            (frame::STDOUT, b"after-ready\n"),
            (frame::EXIT, &frame::exit_payload(0)),
        ]);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code =
            collect_exec_response(&mut reader, &mut stdout, &mut stderr).expect("exec response");

        assert_eq!(exit_code, 0);
        assert_eq!(stdout, b"after-ready\n");
        assert!(stderr.is_empty());
    }

    #[test]
    fn exec_response_errors_when_guest_closes_before_exit() {
        let mut reader = exec_response_stream(&[(frame::STDOUT, b"partial")]);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let err = collect_exec_response(&mut reader, &mut stdout, &mut stderr)
            .expect_err("missing exit should fail");

        assert!(err.to_string().contains("before exit"));
        assert_eq!(stdout, b"partial");
        assert!(stderr.is_empty());
    }

    fn exec_response_stream(frames: &[(u8, &[u8])]) -> Cursor<Vec<u8>> {
        let mut stream = Cursor::new(Vec::new());
        for (msg_type, payload) in frames {
            frame::write_frame(&mut stream, *msg_type, payload).expect("frame should write");
        }
        stream.set_position(0);
        stream
    }

    #[test]
    #[ignore = "requires Windows 11 x86_64 with WHPX, QEMU, and disposable LocalSandbox assets"]
    fn windows_qemu_exec_smoke() {
        #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
        {
            eprintln!("skipping Windows QEMU exec smoke on non-Windows host");
        }

        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        {
            let kernel = required_env_path("LSB_WINDOWS_BOOT_KERNEL");
            let initrd = required_env_path("LSB_WINDOWS_BOOT_INITRD");
            let rootfs = required_env_path("LSB_WINDOWS_BOOT_ROOTFS");
            let sandbox = Sandbox::builder()
                .kernel(kernel.display().to_string())
                .initrd(initrd.display().to_string())
                .rootfs(rootfs.display().to_string())
                .console(false)
                .build()
                .expect("Windows exec smoke sandbox should build");

            sandbox
                .start()
                .expect("Windows exec smoke should reach guest ready before exec");

            let result = (|| -> Result<()> {
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();

                let code = sandbox.exec(&["/bin/true"], &mut stdout, &mut stderr)?;
                assert_eq!(code, 0);
                assert!(stdout.is_empty());
                assert!(stderr.is_empty());

                stdout.clear();
                stderr.clear();
                let code = sandbox.exec(&["/bin/echo", "hello"], &mut stdout, &mut stderr)?;
                assert_eq!(code, 0);
                assert_eq!(String::from_utf8_lossy(&stdout), "hello\n");
                assert!(stderr.is_empty());

                stdout.clear();
                stderr.clear();
                let code = sandbox.exec(
                    &["/bin/sh", "-c", "printf err >&2"],
                    &mut stdout,
                    &mut stderr,
                )?;
                assert_eq!(code, 0);
                assert!(stdout.is_empty());
                assert_eq!(String::from_utf8_lossy(&stderr), "err");

                stdout.clear();
                stderr.clear();
                let mut env = HashMap::new();
                env.insert("LSB_M08_ENV".to_string(), "present".to_string());
                let code = sandbox.exec_with_env_and_cwd(
                    &["/bin/sh", "-c", "printf '%s:%s' \"$PWD\" \"$LSB_M08_ENV\""],
                    &env,
                    Some("/tmp"),
                    &mut stdout,
                    &mut stderr,
                )?;
                assert_eq!(code, 0);
                assert_eq!(String::from_utf8_lossy(&stdout), "/tmp:present");
                assert!(stderr.is_empty());

                stdout.clear();
                stderr.clear();
                let code = sandbox.exec(
                    &["/bin/sh", "-c", "printf nope >&2; exit 7"],
                    &mut stdout,
                    &mut stderr,
                )?;
                assert_eq!(code, 7);
                assert!(stdout.is_empty());
                assert_eq!(String::from_utf8_lossy(&stderr), "nope");

                Ok(())
            })();

            let stop_result = sandbox.stop();
            result.expect("Windows exec smoke commands should pass");
            stop_result.expect("Windows exec smoke QEMU should stop cleanly");
        }
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn required_env_path(name: &str) -> PathBuf {
        std::env::var_os(name)
            .map(PathBuf::from)
            .unwrap_or_else(|| panic!("{name} must point to a disposable boot asset path"))
    }
}
