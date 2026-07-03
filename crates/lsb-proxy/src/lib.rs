pub mod config;
#[cfg(unix)]
mod device;
#[cfg(unix)]
mod dns;
#[cfg(unix)]
mod proxy;
#[cfg(unix)]
mod stack;
#[cfg(unix)]
mod stream;
#[cfg(unix)]
mod tls;

pub use config::ProxyConfig;

#[cfg(unix)]
use std::collections::HashMap;
#[cfg(unix)]
use std::os::unix::io::RawFd;

#[cfg(unix)]
use proxy::ProxyEngine;
#[cfg(unix)]
use stack::NetworkStack;
#[cfg(unix)]
use tls::CertificateAuthority;
#[cfg(unix)]
use tokio::sync::mpsc;
#[cfg(unix)]
use tracing::info;

#[cfg(unix)]
pub type PlatformNetworkFd = RawFd;

#[cfg(not(unix))]
pub type PlatformNetworkFd = i32;

/// Handle to a running proxy. Shuts down on drop.
pub struct ProxyHandle {
    #[cfg(unix)]
    _stack_thread: std::thread::JoinHandle<()>,
    #[cfg(unix)]
    _runtime_thread: std::thread::JoinHandle<()>,
    /// Placeholder tokens generated for secrets. Key = env var name, Value = placeholder.
    pub placeholders: std::collections::HashMap<String, String>,
    /// CA certificate in PEM format (for injecting into guest trust store).
    pub ca_cert_pem: Vec<u8>,
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

/// Windows networking requires the future QEMU/proxy attachment strategy.
#[cfg(not(unix))]
pub fn create_socketpair() -> anyhow::Result<(PlatformNetworkFd, PlatformNetworkFd)> {
    Err(anyhow::anyhow!(
        "Windows support is in progress: proxy networking is not implemented yet (M12 network policy and proxy integration); M01 does not create a QEMU network device"
    ))
}

/// Start the proxy engine. Returns a handle that keeps it running.
///
/// - `host_fd`: the host end of the socketpair (raw L2 Ethernet frames)
/// - `config`: proxy configuration (secrets, network rules)
#[cfg(unix)]
pub fn start(host_fd: PlatformNetworkFd, config: ProxyConfig) -> anyhow::Result<ProxyHandle> {
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

    let stack_thread = std::thread::Builder::new()
        .name("lsb-netstack".into())
        .spawn(move || {
            let mut stack = NetworkStack::new(host_fd, event_tx, cmd_rx);
            stack.run();
        })?;

    let proxy_config = config;
    let proxy_placeholders = placeholders.clone();
    let runtime_thread = std::thread::Builder::new()
        .name("lsb-proxy".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("failed to create tokio runtime for proxy");

            rt.block_on(async move {
                let mut engine =
                    ProxyEngine::new(proxy_config, event_rx, cmd_tx, ca, proxy_placeholders);
                engine.run().await;
            });
        })?;

    info!("proxy started");

    Ok(ProxyHandle {
        _stack_thread: stack_thread,
        _runtime_thread: runtime_thread,
        placeholders,
        ca_cert_pem,
    })
}

/// Windows proxy startup is intentionally unavailable until the policy-bearing
/// network backend is designed and implemented.
#[cfg(not(unix))]
pub fn start(_host_fd: PlatformNetworkFd, _config: ProxyConfig) -> anyhow::Result<ProxyHandle> {
    Err(anyhow::anyhow!(
        "Windows support is in progress: proxy networking is not implemented yet (M12 network policy and proxy integration); M01 only provides compile stubs"
    ))
}
