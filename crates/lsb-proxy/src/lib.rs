pub mod config;
#[cfg(any(unix, windows))]
mod device;
#[cfg(any(unix, windows))]
mod dns;
#[cfg(any(unix, windows))]
mod http1;
mod policy;
#[cfg(any(unix, windows))]
mod proxy;
#[cfg(any(unix, windows))]
mod stack;
#[cfg(any(unix, windows))]
mod stream;
#[cfg(any(unix, windows))]
mod tls;

pub use config::{
    HostScope, HttpsInterceptionConfig, ProxyConfig, RequestHeaderRule, UpstreamProxyConfig,
};

#[cfg(any(unix, windows))]
use std::collections::HashMap;
use std::net::Ipv4Addr;
#[cfg(windows)]
use std::net::TcpListener;
#[cfg(unix)]
use std::os::unix::io::RawFd;
#[cfg(any(unix, windows))]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(any(unix, windows))]
use std::sync::{mpsc as std_mpsc, Arc};
#[cfg(any(unix, windows))]
use std::time::Duration;

#[cfg(windows)]
use device::QemuStreamDevice;
#[cfg(unix)]
use device::VZDevice;
#[cfg(any(unix, windows))]
use proxy::ProxyEngine;
#[cfg(any(unix, windows))]
use stack::NetworkStack;
#[cfg(any(unix, windows))]
use tls::CertificateAuthority;
#[cfg(any(unix, windows))]
use tokio::sync::mpsc;
#[cfg(any(unix, windows))]
use tracing::info;

#[cfg(any(unix, windows))]
const PROXY_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

#[cfg(unix)]
pub type PlatformNetworkFd = RawFd;

#[cfg(not(unix))]
pub type PlatformNetworkFd = i32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmNetworkAttachment {
    FileDescriptor(PlatformNetworkFd),
    QemuStream { host: Ipv4Addr, port: u16 },
}

pub enum ProxyHostAttachment {
    #[cfg(unix)]
    FileDescriptor(PlatformNetworkFd),
    #[cfg(windows)]
    QemuStreamListener(TcpListener),
}

pub struct ProxyLink {
    pub vm: VmNetworkAttachment,
    pub host: ProxyHostAttachment,
}

#[cfg(any(unix, windows))]
struct ManagedThread {
    name: &'static str,
    handle: Option<std::thread::JoinHandle<()>>,
    done_rx: std_mpsc::Receiver<()>,
}

#[cfg(any(unix, windows))]
impl ManagedThread {
    fn join_timeout(&mut self, timeout: Duration) -> anyhow::Result<()> {
        if self.handle.is_none() {
            return Ok(());
        }

        match self.done_rx.recv_timeout(timeout) {
            Ok(()) | Err(std_mpsc::RecvTimeoutError::Disconnected) => {
                let handle = self.handle.take().expect("handle checked above");
                handle
                    .join()
                    .map_err(|_| anyhow::anyhow!("proxy thread '{}' panicked", self.name))
            }
            Err(std_mpsc::RecvTimeoutError::Timeout) => {
                anyhow::bail!("timed out waiting for proxy thread '{}' to stop", self.name);
            }
        }
    }
}

#[cfg(any(unix, windows))]
fn spawn_managed_thread<F>(name: &'static str, f: F) -> std::io::Result<ManagedThread>
where
    F: FnOnce() + Send + 'static,
{
    let (done_tx, done_rx) = std_mpsc::sync_channel(1);
    let handle = std::thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            f();
            let _ = done_tx.send(());
        })?;

    Ok(ManagedThread {
        name,
        handle: Some(handle),
        done_rx,
    })
}

/// Handle to a running proxy. Shuts down on drop.
pub struct ProxyHandle {
    #[cfg(any(unix, windows))]
    shutdown: Arc<AtomicBool>,
    #[cfg(any(unix, windows))]
    stack_thread: Option<ManagedThread>,
    #[cfg(any(unix, windows))]
    runtime_thread: Option<ManagedThread>,
    /// Placeholder tokens generated for secrets. Key = env var name, Value = placeholder.
    pub placeholders: std::collections::HashMap<String, String>,
    /// CA certificate in PEM format (for injecting into guest trust store).
    pub ca_cert_pem: Vec<u8>,
    /// Whether this proxy configuration requires its CA in the guest trust store.
    pub requires_guest_ca: bool,
}

#[cfg(any(unix, windows))]
impl ProxyHandle {
    pub fn shutdown(mut self) -> anyhow::Result<()> {
        self.shutdown_inner(PROXY_SHUTDOWN_TIMEOUT)
    }

    fn shutdown_inner(&mut self, timeout: Duration) -> anyhow::Result<()> {
        self.shutdown.store(true, Ordering::SeqCst);

        let mut first_error = None;
        if let Some(thread) = &mut self.stack_thread {
            if let Err(error) = thread.join_timeout(timeout) {
                first_error.get_or_insert(error);
            }
        }
        if let Some(thread) = &mut self.runtime_thread {
            if let Err(error) = thread.join_timeout(timeout) {
                first_error.get_or_insert(error);
            }
        }

        if let Some(error) = first_error {
            Err(error)
        } else {
            Ok(())
        }
    }
}

#[cfg(any(unix, windows))]
impl Drop for ProxyHandle {
    fn drop(&mut self) {
        if let Err(error) = self.shutdown_inner(PROXY_SHUTDOWN_TIMEOUT) {
            tracing::debug!("proxy shutdown did not complete cleanly: {error}");
        }
    }
}

/// Generate a unique placeholder token for a secret.
#[cfg(unix)]
fn generate_placeholder() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("lsb_tok_{:016x}{:04x}", ts, seq)
}

#[cfg(windows)]
fn generate_placeholder() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("lsb_tok_{:016x}{:04x}", ts, seq)
}

pub fn create_proxy_link() -> anyhow::Result<ProxyLink> {
    #[cfg(unix)]
    {
        let (vm_fd, host_fd) = create_socketpair()?;
        return Ok(ProxyLink {
            vm: VmNetworkAttachment::FileDescriptor(vm_fd),
            host: ProxyHostAttachment::FileDescriptor(host_fd),
        });
    }

    #[cfg(windows)]
    {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let port = listener.local_addr()?.port();
        listener.set_nonblocking(true)?;
        return Ok(ProxyLink {
            vm: VmNetworkAttachment::QemuStream {
                host: Ipv4Addr::LOCALHOST,
                port,
            },
            host: ProxyHostAttachment::QemuStreamListener(listener),
        });
    }

    #[cfg(not(any(unix, windows)))]
    {
        anyhow::bail!(
            "proxy networking is unsupported on this host platform; no VM network device was created"
        );
    }
}

/// Create a Unix datagram socketpair for VZFileHandleNetworkDeviceAttachment.
/// Returns (vm_fd, host_fd). The vm_fd goes to VZ, host_fd goes to the proxy.
#[cfg(unix)]
pub fn create_socketpair() -> anyhow::Result<(PlatformNetworkFd, PlatformNetworkFd)> {
    let mut fds = [0i32; 2];
    let ret = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
    if ret != 0 {
        return Err(anyhow::anyhow!(
            "socketpair failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let host_fd = fds[1];

    // Apple recommends SO_RCVBUF >= 2x SO_SNDBUF for VZFileHandleNetworkDeviceAttachment
    unsafe {
        let sndbuf: libc::c_int = 1024 * 1024;
        let rcvbuf: libc::c_int = 4 * 1024 * 1024;
        libc::setsockopt(
            host_fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &sndbuf as *const _ as _,
            std::mem::size_of::<libc::c_int>() as _,
        );
        libc::setsockopt(
            host_fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &rcvbuf as *const _ as _,
            std::mem::size_of::<libc::c_int>() as _,
        );
    }

    Ok((fds[0], fds[1]))
}

/// Windows networking uses QEMU stream attachments instead of fd socketpairs.
#[cfg(not(unix))]
pub fn create_socketpair() -> anyhow::Result<(PlatformNetworkFd, PlatformNetworkFd)> {
    Err(anyhow::anyhow!(
        "Windows proxy networking requires create_proxy_link/start_link with a QEMU stream attachment; legacy fd socketpair startup is unsupported and no QEMU user networking was enabled"
    ))
}

/// Start the proxy engine. Returns a handle that keeps it running.
///
/// - `host_fd`: the host end of the socketpair (raw L2 Ethernet frames)
/// - `config`: proxy configuration (secrets, network rules)
#[cfg(unix)]
pub fn start(host_fd: PlatformNetworkFd, config: ProxyConfig) -> anyhow::Result<ProxyHandle> {
    start_link(ProxyHostAttachment::FileDescriptor(host_fd), config)
}

/// Start the proxy engine from a platform-specific host attachment.
///
/// The attachment must be the host side returned by `create_proxy_link`.
#[cfg(any(unix, windows))]
pub fn start_link(
    attachment: ProxyHostAttachment,
    config: ProxyConfig,
) -> anyhow::Result<ProxyHandle> {
    config.validate()?;
    let requires_guest_ca = config.requires_guest_ca();
    // Install rustls crypto provider (process-wide, idempotent)
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let ca = CertificateAuthority::new()?;
    let ca_cert_pem = ca.ca_cert_pem();

    // Generate placeholder tokens for each secret
    let mut placeholders = HashMap::new();
    for name in config.secrets.keys() {
        placeholders.insert(name.clone(), generate_placeholder());
    }

    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();

    let proxy_config = config;
    let proxy_placeholders = placeholders.clone();
    let mut engine = ProxyEngine::new(proxy_config, event_rx, cmd_tx, ca, proxy_placeholders)?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let mut stack_thread = spawn_stack_thread(attachment, event_tx, cmd_rx, shutdown.clone())?;
    let runtime_thread = match spawn_managed_thread("lsb-proxy", move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("failed to create tokio runtime for proxy");

        rt.block_on(async move {
            engine.run().await;
        });
    }) {
        Ok(thread) => thread,
        Err(error) => {
            shutdown.store(true, Ordering::SeqCst);
            let _ = stack_thread.join_timeout(PROXY_SHUTDOWN_TIMEOUT);
            return Err(error.into());
        }
    };

    info!("proxy started");

    Ok(ProxyHandle {
        shutdown,
        stack_thread: Some(stack_thread),
        runtime_thread: Some(runtime_thread),
        placeholders,
        ca_cert_pem,
        requires_guest_ca,
    })
}

#[cfg(unix)]
fn spawn_stack_thread(
    attachment: ProxyHostAttachment,
    event_tx: mpsc::UnboundedSender<stack::StackEvent>,
    cmd_rx: mpsc::UnboundedReceiver<stack::StackCommand>,
    shutdown: Arc<AtomicBool>,
) -> anyhow::Result<ManagedThread> {
    let ProxyHostAttachment::FileDescriptor(host_fd) = attachment;
    spawn_managed_thread("lsb-netstack", move || {
        let mut stack = NetworkStack::new(VZDevice::new(host_fd), event_tx, cmd_rx);
        stack.run_until_shutdown(&shutdown);
    })
    .map_err(Into::into)
}

#[cfg(windows)]
fn spawn_stack_thread(
    attachment: ProxyHostAttachment,
    event_tx: mpsc::UnboundedSender<stack::StackEvent>,
    cmd_rx: mpsc::UnboundedReceiver<stack::StackCommand>,
    shutdown: Arc<AtomicBool>,
) -> anyhow::Result<ManagedThread> {
    let ProxyHostAttachment::QemuStreamListener(listener) = attachment;
    spawn_managed_thread("lsb-netstack", move || loop {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }

        match listener.accept() {
            Ok((stream, addr)) => {
                info!("proxy QEMU stream link connected from {addr}");
                match QemuStreamDevice::new(stream) {
                    Ok(device) => {
                        let mut stack = NetworkStack::new(device, event_tx, cmd_rx);
                        stack.run_until_shutdown(&shutdown);
                    }
                    Err(error) => {
                        tracing::debug!("failed to initialize QEMU stream proxy link: {error}");
                    }
                }
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => {
                tracing::debug!("QEMU stream proxy listener failed: {error}");
                break;
            }
        }
    })
    .map_err(Into::into)
}

/// Legacy Windows fd proxy startup is intentionally unavailable; use
/// `create_proxy_link` and `start_link` so the Windows backend receives a
/// policy-bearing QEMU stream attachment instead of a raw integer fd.
#[cfg(not(unix))]
pub fn start(_host_fd: PlatformNetworkFd, _config: ProxyConfig) -> anyhow::Result<ProxyHandle> {
    Err(anyhow::anyhow!(
        "Windows proxy networking requires create_proxy_link/start_link with a QEMU stream attachment; legacy fd startup is unsupported and no QEMU user networking was enabled"
    ))
}

#[cfg(all(test, windows))]
mod non_unix_tests {
    use super::*;

    #[test]
    fn socketpair_rejects_legacy_fd_path() {
        let message = match create_socketpair() {
            Ok(_) => panic!("socketpair should be unsupported"),
            Err(error) => error.to_string(),
        };

        assert!(message.contains("QEMU stream"));
        assert!(message.contains("legacy fd"));
    }

    #[test]
    fn windows_proxy_link_uses_loopback_stream_endpoint() {
        let link = create_proxy_link().expect("proxy link should bind loopback listener");

        match link.vm {
            VmNetworkAttachment::QemuStream { host, port } => {
                assert_eq!(host, Ipv4Addr::LOCALHOST);
                assert_ne!(port, 0);
            }
            VmNetworkAttachment::FileDescriptor(_) => panic!("Windows should not use fd link"),
        }
    }
}

#[cfg(all(test, any(unix, windows)))]
mod lifecycle_tests {
    use super::*;

    #[test]
    fn proxy_handle_shutdown_stops_idle_threads() {
        let ProxyLink { vm, host } = create_proxy_link().expect("proxy link should be created");
        let handle = start_link(host, ProxyConfig::default()).expect("proxy should start");

        handle
            .shutdown()
            .expect("proxy shutdown should join idle stack and runtime threads");

        #[cfg(unix)]
        if let VmNetworkAttachment::FileDescriptor(fd) = vm {
            unsafe {
                libc::close(fd);
            }
        }

        #[cfg(windows)]
        drop(vm);
    }
}
