use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use crossbeam_channel::Receiver;

use shuru_darwin::terminal;
use shuru_darwin::*;

use crate::proto::{
    ControlMessage, ExecRequest, ExecResponse, ForwardRequest, ForwardResponse, MountRequest,
    MountResponse, PortMapping,
};
use crate::{VSOCK_PORT, VSOCK_PORT_FORWARD};

// --- Mount types ---

#[derive(Debug, Clone)]
pub struct MountConfig {
    pub host_path: String,
    pub guest_path: String,
}

// --- VmConfigBuilder ---

pub struct VmConfigBuilder {
    kernel: Option<String>,
    rootfs: Option<String>,
    initrd: Option<String>,
    cpus: usize,
    memory_mb: u64,
    console: bool,
    allow_net: bool,
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
            allow_net: false,
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

    /// Enable network access (NAT). Disabled by default for sandboxing.
    pub fn allow_net(mut self, enabled: bool) -> Self {
        self.allow_net = enabled;
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

        if !VirtualMachine::supported() {
            bail!("Virtualization is not supported on this machine");
        }

        let boot_loader = LinuxBootLoader::new_with_kernel(&kernel_path);
        if let Some(ref initrd) = self.initrd {
            boot_loader.set_initrd(initrd);
        }

        boot_loader.set_command_line("console=hvc0 root=/dev/vda rw");

        let memory_bytes = self.memory_mb * 1024 * 1024;
        let config = VirtualMachineConfiguration::new(&boot_loader, self.cpus, memory_bytes);

        let serial_attachment = if self.console {
            FileHandleSerialAttachment::new(
                std::io::stdin().as_raw_fd(),
                std::io::stdout().as_raw_fd(),
            )
        } else {
            FileHandleSerialAttachment::new_write_only(std::io::stderr().as_raw_fd())
        };
        let serial = VirtioConsoleSerialPort::new_with_attachment(&serial_attachment);
        config.set_serial_ports(&[serial]);

        let disk_attachment = DiskImageAttachment::new_with_options(
            &rootfs_path,
            false,
            DiskImageCachingMode::Cached,
            DiskImageSynchronizationMode::Fsync,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create disk attachment: {}", e))?;
        let block_device = VirtioBlockDevice::new(&disk_attachment);
        config.set_storage_devices(&[&block_device]);

        if self.allow_net {
            let net_attachment = NATNetworkAttachment::new();
            let net_device = VirtioNetworkDevice::new_with_attachment(&net_attachment);
            net_device.set_mac_address(&MACAddress::random_local());
            config.set_network_devices(&[net_device]);
        }

        // Set up directory sharing devices (virtio-fs) and mount metadata
        let mut fs_devices: Vec<VirtioFileSystemDevice> = Vec::new();
        let mut mount_requests: Vec<MountRequest> = Vec::new();

        for (i, m) in self.mounts.iter().enumerate() {
            let tag = format!("mount{}", i);
            // Host directory is always read-only from the VM side.
            // Overlay mode uses tmpfs upper layer inside the guest.
            let shared_dir = SharedDirectory::new(&m.host_path, true);
            fs_devices.push(VirtioFileSystemDevice::new(&tag, &shared_dir));
            mount_requests.push(MountRequest {
                tag,
                guest_path: m.guest_path.clone(),
            });
        }

        if !fs_devices.is_empty() {
            config.set_directory_sharing_devices(&fs_devices);
        }

        let socket_device = VirtioSocketDevice::new();
        config.set_socket_devices(&[socket_device]);

        config.set_entropy_devices(&[VirtioEntropyDevice::new()]);
        config.set_memory_balloon_devices(&[VirtioMemoryBalloonDevice::new()]);

        config
            .validate()
            .map_err(|e| anyhow::anyhow!("VM configuration invalid: {}", e))?;

        Ok(Sandbox {
            vm: Arc::new(VirtualMachine::new(&config)),
            mounts: Mutex::new(mount_requests),
        })
    }
}

// --- Sandbox ---

pub struct Sandbox {
    vm: Arc<VirtualMachine>,
    mounts: Mutex<Vec<MountRequest>>,
}

impl Sandbox {
    pub fn builder() -> VmConfigBuilder {
        VmConfigBuilder::new()
    }

    pub fn start(&self) -> Result<()> {
        self.vm
            .start()
            .map_err(|e| anyhow::anyhow!("Failed to start VM: {}", e))
    }

    pub fn stop(&self) -> Result<()> {
        self.vm
            .stop()
            .map_err(|e| anyhow::anyhow!("Failed to stop VM: {}", e))
    }

    pub fn state_channel(&self) -> Receiver<VmState> {
        self.vm.state_channel()
    }

    /// Send pending mount requests over an established vsock connection.
    /// Drains the mount list so subsequent calls are no-ops.
    fn send_mount_requests(
        &self,
        writer: &mut impl Write,
        reader: &mut BufReader<TcpStream>,
    ) -> Result<()> {
        let mounts = std::mem::take(&mut *self.mounts.lock().unwrap());
        for req in &mounts {
            writeln!(writer, "{}", serde_json::to_string(req)?)?;
            writer.flush()?;
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .context("reading mount response")?;
            let line = line.trim();
            if line.is_empty() {
                bail!("guest closed connection during mount init");
            }
            let resp: MountResponse = match serde_json::from_str(line) {
                Ok(r) => r,
                Err(_) => {
                    bail!(
                        "guest does not support directory mounts. \
                         Run `shuru upgrade` and recreate the checkpoint to enable --mount."
                    );
                }
            };
            if !resp.ok {
                bail!(
                    "mount failed: {} -> {}: {}",
                    req.tag,
                    req.guest_path,
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
        let stream = self.connect_vsock()?;
        let mut writer = stream.try_clone()?;
        let mut reader = BufReader::new(stream);

        self.send_mount_requests(&mut writer, &mut reader)?;

        let req = ExecRequest {
            argv: argv.iter().map(|s| s.as_ref().to_string()).collect(),
            env: HashMap::new(),
            tty: None,
            rows: None,
            cols: None,
        };
        writeln!(writer, "{}", serde_json::to_string(&req)?)?;
        writer.flush()?;

        let mut exit_code = 0;

        for line in reader.lines() {
            let line = line.context("reading vsock response")?;
            if line.is_empty() {
                continue;
            }

            let resp: ExecResponse =
                serde_json::from_str(&line).context("parsing vsock response")?;

            match resp.msg_type.as_str() {
                "stdout" => {
                    if let Some(data) = &resp.data {
                        write!(stdout, "{}", data)?;
                    }
                }
                "stderr" => {
                    if let Some(data) = &resp.data {
                        write!(stderr, "{}", data)?;
                    }
                }
                "exit" => {
                    exit_code = resp.code.unwrap_or(0);
                    break;
                }
                "error" => {
                    if let Some(data) = &resp.data {
                        write!(stderr, "guest error: {}", data)?;
                    }
                    exit_code = 1;
                    break;
                }
                _ => {}
            }
        }

        Ok(exit_code)
    }

    /// Run an interactive shell session with PTY support.
    /// Puts the host terminal in raw mode, relays I/O bidirectionally over
    /// vsock, and handles SIGWINCH for window resize.
    /// Returns the guest process exit code.
    pub fn shell(
        &self,
        argv: &[impl AsRef<str>],
        env: &HashMap<String, String>,
    ) -> Result<i32> {
        let stdin_fd = std::io::stdin().as_raw_fd();
        let (rows, cols) = terminal::terminal_size(stdin_fd);

        let stream = self.connect_vsock()?;
        let mut writer = stream.try_clone()?;
        let mut reader = BufReader::new(stream);

        // Mount phase (sync, before raw mode)
        self.send_mount_requests(&mut writer, &mut reader)?;

        // Send ExecRequest with tty=true
        let req = ExecRequest {
            argv: argv.iter().map(|s| s.as_ref().to_string()).collect(),
            env: env.clone(),
            tty: Some(true),
            rows: Some(rows),
            cols: Some(cols),
        };
        writeln!(writer, "{}", serde_json::to_string(&req)?)?;
        writer.flush()?;

        // Enter raw mode - TerminalState restores on drop
        let _raw_guard = terminal::TerminalState::enter_raw_mode(stdin_fd);

        // Install SIGWINCH handler
        terminal::install_sigwinch_handler();

        let done = Arc::new(AtomicBool::new(false));
        let exit_code = Arc::new(Mutex::new(0i32));

        // Thread A: stdin → vsock (send stdin data + resize messages)
        let done_a = done.clone();
        let mut vsock_writer = writer.try_clone()?;
        let stdin_thread = std::thread::spawn(move || {
            let mut buf = [0u8; 4096];

            while !done_a.load(Ordering::SeqCst) {
                if terminal::poll_read(stdin_fd, 100) {
                    let n = terminal::read_raw(stdin_fd, &mut buf);
                    if n == 0 {
                        break;
                    }
                    let data = String::from_utf8_lossy(&buf[..n]);
                    let msg = ControlMessage::Stdin {
                        data: data.into_owned(),
                    };
                    if writeln!(vsock_writer, "{}", serde_json::to_string(&msg).unwrap()).is_err() {
                        break;
                    }
                    let _ = vsock_writer.flush();
                }

                // Check SIGWINCH
                if terminal::sigwinch_received() {
                    let (rows, cols) = terminal::terminal_size(stdin_fd);
                    let msg = ControlMessage::Resize { rows, cols };
                    if writeln!(vsock_writer, "{}", serde_json::to_string(&msg).unwrap()).is_err() {
                        break;
                    }
                    let _ = vsock_writer.flush();
                }
            }
        });

        // Thread B: vsock → stdout (read responses, write output)
        let done_b = done.clone();
        let exit_code_b = exit_code.clone();
        let vsock_thread = std::thread::spawn(move || {
            let mut stdout = std::io::stdout();
            for line in reader.lines() {
                let line = match line {
                    Ok(l) => l,
                    Err(_) => break,
                };
                if line.is_empty() {
                    continue;
                }

                let resp: ExecResponse = match serde_json::from_str(&line) {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                match resp.msg_type.as_str() {
                    "stdout" => {
                        if let Some(data) = &resp.data {
                            let _ = stdout.write_all(data.as_bytes());
                            let _ = stdout.flush();
                        }
                    }
                    "exit" => {
                        *exit_code_b.lock().unwrap() = resp.code.unwrap_or(0);
                        break;
                    }
                    "error" => {
                        if let Some(data) = &resp.data {
                            let _ = std::io::stderr()
                                .write_all(format!("guest error: {}\r\n", data).as_bytes());
                        }
                        *exit_code_b.lock().unwrap() = 1;
                        break;
                    }
                    _ => {}
                }
            }
            done_b.store(true, Ordering::SeqCst);
        });

        // Wait for threads
        let _ = vsock_thread.join();
        let _ = stdin_thread.join();

        // Restore SIGWINCH to default
        terminal::reset_sigwinch_handler();

        // Terminal restored by _raw_guard drop
        let code = *exit_code.lock().unwrap();
        Ok(code)
    }

    /// Start port forwarding proxies. Returns a handle that stops all
    /// listeners when dropped.
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
                "shuru: forwarding 127.0.0.1:{} -> guest:{}",
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
                                if let Err(e) = handle_forward_connection(tcp_stream, &vm, guest_port) {
                                    eprintln!("shuru: port forward error: {}", e);
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
            _threads: listeners,
        })
    }

    fn connect_vsock(&self) -> Result<TcpStream> {
        let state_rx = self.vm.state_channel();
        for attempt in 1..=10 {
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
                Ok(s) => return Ok(s),
                Err(e) => {
                    if attempt == 10 {
                        bail!("Failed to connect to guest after 10 attempts: {}", e);
                    }
                    tracing::debug!("vsock connect attempt {} failed: {}", attempt, e);
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
        }
        unreachable!()
    }
}

// --- Port forwarding ---

/// Handle returned by `start_port_forwarding`. Signals all listener threads
/// to stop when dropped.
pub struct PortForwardHandle {
    stop: Arc<AtomicBool>,
    _threads: Vec<std::thread::JoinHandle<()>>,
}

impl Drop for PortForwardHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn handle_forward_connection(
    tcp_stream: TcpStream,
    vm: &VirtualMachine,
    guest_port: u16,
) -> Result<()> {
    let mut vsock_stream = vm
        .connect_to_vsock_port(VSOCK_PORT_FORWARD)
        .map_err(|e| anyhow::anyhow!("vsock connect for port forward: {}", e))?;

    // Send forward request
    let req = ForwardRequest { port: guest_port };
    writeln!(vsock_stream, "{}", serde_json::to_string(&req)?)?;
    vsock_stream.flush()?;

    // Read response - byte-by-byte to avoid buffering past the newline
    let line = read_line_raw(&mut vsock_stream)
        .context("reading forward response")?;
    let resp: ForwardResponse =
        serde_json::from_str(line.trim()).context("parsing forward response")?;

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

/// Read one line from a stream without any buffering beyond the newline.
/// This prevents a BufReader from consuming bytes that belong to the relay phase.
fn read_line_raw(stream: &mut TcpStream) -> Result<String> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => bail!("unexpected EOF"),
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                buf.push(byte[0]);
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(String::from_utf8(buf)?)
}

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
