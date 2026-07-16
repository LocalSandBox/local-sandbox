use std::collections::HashMap;
#[cfg(windows)]
use std::ffi::c_void;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use boring::ssl::{SslConnector, SslConnectorBuilder, SslMethod};
#[cfg(windows)]
use boring::x509::X509;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, info, trace};
#[cfg(windows)]
use windows_sys::Win32::Security::Cryptography::{
    CertCloseStore, CertEnumCertificatesInStore, CertOpenStore, CERT_CONTEXT,
    CERT_STORE_PROV_SYSTEM_W, CERT_STORE_READONLY_FLAG, CERT_SYSTEM_STORE_CURRENT_USER,
    CERT_SYSTEM_STORE_LOCAL_MACHINE,
};

use crate::config::{ProxyConfig, RequestHeaderRule, SMB_MOUNT_PORT};
use crate::dns::{self, SharedDnsCache};
use crate::stack::{ConnectionId, StackCommand, StackEvent, TcpConnection};
use crate::stream::ChannelStream;
use crate::tls::CertificateAuthority;

/// The async proxy engine.
///
/// Receives events from the smoltcp NetworkStack and proxies TCP connections
/// to the real internet, with optional MITM for secret injection.
///
/// Uses BoringSSL (Chrome's TLS stack) for upstream connections so that
/// Cloudflare-protected sites accept the TLS fingerprint. The client-side
/// (guest <-> proxy) uses rustls with our generated CA cert.
pub struct ProxyEngine {
    config: Arc<ProxyConfig>,
    event_rx: mpsc::UnboundedReceiver<StackEvent>,
    cmd_tx: mpsc::UnboundedSender<StackCommand>,
    connections: HashMap<ConnectionId, mpsc::UnboundedSender<Vec<u8>>>,
    dns_cache: SharedDnsCache,
    placeholders: Arc<HashMap<String, String>>,
    ca: Arc<tokio::sync::Mutex<CertificateAuthority>>,
    upstream_ssl: SslConnector,
}

impl ProxyEngine {
    pub fn new(
        config: ProxyConfig,
        event_rx: mpsc::UnboundedReceiver<StackEvent>,
        cmd_tx: mpsc::UnboundedSender<StackCommand>,
        ca: CertificateAuthority,
        placeholders: HashMap<String, String>,
    ) -> Self {
        // BoringSSL upstream connector — Chrome's TLS stack so Cloudflare
        // doesn't reject our MITM connections based on JA3/JA4 fingerprint.
        let mut builder = SslConnector::builder(SslMethod::tls()).expect("SslConnector");
        builder.set_alpn_protos(b"\x08http/1.1").expect("ALPN");
        configure_upstream_tls_roots(&mut builder);
        let upstream_ssl = builder.build();

        ProxyEngine {
            config: Arc::new(config),
            event_rx,
            cmd_tx,
            connections: HashMap::new(),
            dns_cache: dns::new_shared_dns_cache(),
            placeholders: Arc::new(placeholders),
            ca: Arc::new(tokio::sync::Mutex::new(ca)),
            upstream_ssl,
        }
    }

    /// Run the proxy event loop.
    pub async fn run(&mut self) {
        info!("proxy engine started");
        while let Some(event) = self.event_rx.recv().await {
            match event {
                StackEvent::NewConnection(conn) => {
                    self.handle_new_connection(conn);
                }
                StackEvent::Data { id, payload } => {
                    if let Some(tx) = self.connections.get(&id) {
                        if tx.send(payload).is_err() {
                            self.connections.remove(&id);
                        }
                    }
                }
                StackEvent::Closed { id } => {
                    self.connections.remove(&id);
                }
                StackEvent::DnsQuery { src, payload } => {
                    let cmd_tx = self.cmd_tx.clone();
                    let config = self.config.clone();
                    let dns_cache = self.dns_cache.clone();
                    tokio::spawn(async move {
                        dns::handle_dns_query(src, payload, cmd_tx, &config, dns_cache).await;
                    });
                }
            }
        }
    }

    fn handle_new_connection(&mut self, conn: TcpConnection) {
        let (data_tx, data_rx) = mpsc::unbounded_channel();
        self.connections.insert(conn.id, data_tx);

        let cmd_tx = self.cmd_tx.clone();
        let config = self.config.clone();
        let dns_cache = self.dns_cache.clone();
        let ca = self.ca.clone();
        let placeholders = self.placeholders.clone();
        let upstream_ssl = self.upstream_ssl.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(
                conn.id,
                conn.dst,
                data_rx,
                cmd_tx,
                &config,
                &dns_cache,
                ca,
                &placeholders,
                upstream_ssl,
            )
            .await
            {
                debug!("connection to {} ended: {e}", conn.dst);
            }
        });
    }
}

fn configure_upstream_tls_roots(builder: &mut SslConnectorBuilder) {
    #[cfg(windows)]
    match add_windows_system_roots(builder) {
        Ok(count) => debug!("loaded {count} Windows root certificate(s) for upstream TLS"),
        Err(error) => debug!("failed to load Windows root certificates for upstream TLS: {error}"),
    }

    #[cfg(not(windows))]
    let _ = builder;
}

#[cfg(windows)]
fn add_windows_system_roots(builder: &mut SslConnectorBuilder) -> anyhow::Result<usize> {
    let mut count = 0;
    for location in [
        CERT_SYSTEM_STORE_CURRENT_USER,
        CERT_SYSTEM_STORE_LOCAL_MACHINE,
    ] {
        for store_name in ["ROOT", "CA"] {
            count += add_windows_cert_store(builder, location, store_name)?;
        }
    }
    Ok(count)
}

#[cfg(windows)]
fn add_windows_cert_store(
    builder: &mut SslConnectorBuilder,
    location: u32,
    store_name: &str,
) -> anyhow::Result<usize> {
    let store_name = store_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let store = unsafe {
        CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            0,
            0,
            CERT_STORE_READONLY_FLAG | location,
            store_name.as_ptr().cast::<c_void>(),
        )
    };
    if store.is_null() {
        return Ok(0);
    }

    let _guard = WindowsCertStore(store);
    let mut loaded = 0;
    let mut previous: *const CERT_CONTEXT = std::ptr::null();
    loop {
        let context = unsafe { CertEnumCertificatesInStore(store, previous) };
        if context.is_null() {
            break;
        }
        previous = context;

        let cert = unsafe { &*context };
        if cert.pbCertEncoded.is_null() || cert.cbCertEncoded == 0 {
            continue;
        }

        let der =
            unsafe { std::slice::from_raw_parts(cert.pbCertEncoded, cert.cbCertEncoded as usize) };
        let Ok(cert) = X509::from_der(der) else {
            continue;
        };

        match builder.cert_store_mut().add_cert(cert) {
            Ok(()) => loaded += 1,
            Err(error) => {
                trace!("skipping Windows root certificate that BoringSSL rejected: {error}");
            }
        }
    }

    Ok(loaded)
}

#[cfg(windows)]
struct WindowsCertStore(windows_sys::Win32::Security::Cryptography::HCERTSTORE);

#[cfg(windows)]
impl Drop for WindowsCertStore {
    fn drop(&mut self) {
        unsafe {
            let _ = CertCloseStore(self.0, 0);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionRoute {
    SmbMountRelay(SocketAddr),
    ExposeHost(SocketAddr),
    DenyMountOnly,
    Outbound,
}

fn classify_connection_route(config: &ProxyConfig, dst: SocketAddr) -> ConnectionRoute {
    if let IpAddr::V4(ipv4) = dst.ip() {
        if config.permits_smb_mount_relay(ipv4, dst.port()) {
            return ConnectionRoute::SmbMountRelay(host_loopback_socket(SMB_MOUNT_PORT));
        }

        if let Some(host_port) = config.exposed_host_port(ipv4, dst.port()) {
            return ConnectionRoute::ExposeHost(host_loopback_socket(host_port));
        }
    }

    if config.is_mount_only_smb() {
        ConnectionRoute::DenyMountOnly
    } else {
        ConnectionRoute::Outbound
    }
}

fn host_loopback_socket(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), port)
}

/// Handle a single proxied TCP connection.
async fn handle_connection(
    id: ConnectionId,
    dst: SocketAddr,
    mut data_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    cmd_tx: mpsc::UnboundedSender<StackCommand>,
    config: &ProxyConfig,
    dns_cache: &SharedDnsCache,
    ca: Arc<tokio::sync::Mutex<CertificateAuthority>>,
    placeholders: &HashMap<String, String>,
    upstream_ssl: SslConnector,
) -> anyhow::Result<()> {
    match classify_connection_route(config, dst) {
        ConnectionRoute::SmbMountRelay(local_dst) => {
            debug!("SMB mount relay: guest 10.0.0.1:445 -> localhost:445");
            let upstream = TcpStream::connect(local_dst).await?;
            let (mut upstream_rd, mut upstream_wr) = upstream.into_split();
            return blind_relay(id, &mut upstream_rd, &mut upstream_wr, data_rx, cmd_tx).await;
        }
        ConnectionRoute::ExposeHost(local_dst) => {
            debug!(
                "expose-host: guest :{} -> localhost:{}",
                dst.port(),
                local_dst.port()
            );
            let upstream = TcpStream::connect(local_dst).await?;
            let (mut upstream_rd, mut upstream_wr) = upstream.into_split();
            return blind_relay(id, &mut upstream_rd, &mut upstream_wr, data_rx, cmd_tx).await;
        }
        ConnectionRoute::DenyMountOnly => {
            let _ = cmd_tx.send(StackCommand::Close { id });
            anyhow::bail!("mount-only SMB proxy denied TCP connection to {dst}");
        }
        ConnectionRoute::Outbound => {}
    }

    let is_tls = dst.port() == 443;

    if is_tls {
        // Buffer data until we have a complete TLS ClientHello record.
        // The ClientHello may span multiple TCP segments.
        let mut tls_buf = data_rx
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("connection closed before data"))?;

        // TLS record header: type(1) + version(2) + length(2) = 5 bytes
        // Keep reading until we have the full record
        while tls_buf.len() >= 5 {
            let record_len = u16::from_be_bytes([tls_buf[3], tls_buf[4]]) as usize;
            if tls_buf.len() >= 5 + record_len {
                break; // have the complete record
            }
            match data_rx.recv().await {
                Some(chunk) => tls_buf.extend_from_slice(&chunk),
                None => break, // connection closed
            }
        }

        let sni = extract_sni(&tls_buf);
        debug!("TLS to {dst}, SNI: {sni:?}");

        enforce_connection_policy(config, dns_cache, sni.as_deref(), dst, "TLS")?;

        if let Some(domain) = sni {
            let substitutions = config.secrets_for_domain(&domain, placeholders);
            let header_rules = config.active_header_rules_for_domain(&domain);
            if !substitutions.is_empty() || !header_rules.is_empty() {
                debug!("MITM: {domain}");
                return handle_mitm(
                    id,
                    dst,
                    domain,
                    tls_buf,
                    data_rx,
                    cmd_tx,
                    ca,
                    substitutions,
                    header_rules,
                    upstream_ssl,
                )
                .await;
            }
        }

        // Blind tunnel: forward the buffered data and relay the rest
        debug!("blind tunnel to {dst}");
        let upstream = TcpStream::connect(dst).await?;
        let (mut upstream_rd, mut upstream_wr) = upstream.into_split();

        // Send the buffered TLS data
        upstream_wr.write_all(&tls_buf).await?;

        return blind_relay(id, &mut upstream_rd, &mut upstream_wr, data_rx, cmd_tx).await;
    }

    if config.has_domain_allowlist() {
        let first_chunk = data_rx
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("connection closed before data"))?;
        let host = extract_http_host(&first_chunk);
        enforce_connection_policy(config, dns_cache, host.as_deref(), dst, "TCP")?;

        debug!("TCP tunnel to {dst}");
        let upstream = TcpStream::connect(dst).await?;
        let (mut upstream_rd, mut upstream_wr) = upstream.into_split();
        upstream_wr.write_all(&first_chunk).await?;

        return blind_relay(id, &mut upstream_rd, &mut upstream_wr, data_rx, cmd_tx).await;
    }

    // Non-TLS without an explicit allowlist: blind tunnel.
    debug!("TCP tunnel to {dst}");
    let upstream = TcpStream::connect(dst).await?;
    let (mut upstream_rd, mut upstream_wr) = upstream.into_split();

    blind_relay(id, &mut upstream_rd, &mut upstream_wr, data_rx, cmd_tx).await
}

/// Blind bidirectional relay (no inspection).
async fn blind_relay(
    id: ConnectionId,
    upstream_rd: &mut tokio::net::tcp::OwnedReadHalf,
    upstream_wr: &mut tokio::net::tcp::OwnedWriteHalf,
    mut data_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    cmd_tx: mpsc::UnboundedSender<StackCommand>,
) -> anyhow::Result<()> {
    let cmd_tx_clone = cmd_tx.clone();
    let upstream_to_guest = async {
        let mut buf = vec![0u8; 65536];
        loop {
            match upstream_rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if cmd_tx_clone
                        .send(StackCommand::Send {
                            id,
                            payload: buf[..n].to_vec(),
                        })
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    };

    let guest_to_upstream = async {
        while let Some(payload) = data_rx.recv().await {
            if upstream_wr.write_all(&payload).await.is_err() {
                break;
            }
        }
    };

    tokio::select! {
        _ = upstream_to_guest => {},
        _ = guest_to_upstream => {},
    }

    let _ = cmd_tx.send(StackCommand::Close { id });
    Ok(())
}

fn enforce_connection_policy(
    config: &ProxyConfig,
    dns_cache: &SharedDnsCache,
    domain: Option<&str>,
    dst: SocketAddr,
    protocol: &str,
) -> anyhow::Result<()> {
    if !config.permits_network_policy() {
        anyhow::bail!("{protocol} connection denied by mount-only SMB policy");
    }

    if !config.has_domain_allowlist() {
        return Ok(());
    }

    let Some(domain) = domain else {
        anyhow::bail!("{protocol} connection denied: no policy-visible domain");
    };

    if config.is_domain_allowed(domain) {
        enforce_destination_policy(dns_cache, domain, dst, protocol)
    } else {
        anyhow::bail!("{protocol} connection denied by network policy for {domain}");
    }
}

fn enforce_destination_policy(
    dns_cache: &SharedDnsCache,
    domain: &str,
    dst: SocketAddr,
    protocol: &str,
) -> anyhow::Result<()> {
    let IpAddr::V4(dst_ip) = dst.ip() else {
        anyhow::bail!(
            "{protocol} connection denied: IPv6 destination {dst} is not supported by the IPv4 proxy policy"
        );
    };

    if dns::destination_matches_dns_answer(dns_cache, domain, dst_ip)? {
        Ok(())
    } else {
        anyhow::bail!(
            "{protocol} connection denied: policy-visible domain {domain} did not resolve to destination {dst}"
        );
    }
}

/// MITM: terminate TLS on both sides, relay with secret substitution.
async fn handle_mitm(
    id: ConnectionId,
    dst: SocketAddr,
    domain: String,
    first_chunk: Vec<u8>,
    data_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    cmd_tx: mpsc::UnboundedSender<StackCommand>,
    ca: Arc<tokio::sync::Mutex<CertificateAuthority>>,
    substitutions: Vec<(String, String)>,
    header_rules: Vec<RequestHeaderRule>,
    upstream_ssl: SslConnector,
) -> anyhow::Result<()> {
    debug!(
        "MITM {domain}: starting interception for {dst} with {} secret placeholder(s) and {} header rule(s)",
        substitutions.len(),
        header_rules.len()
    );

    // Get fake cert for this domain
    let acceptor = {
        let mut ca = ca.lock().await;
        ca.acceptor_for_domain(&domain)?
    };

    // Wrap guest data channel as AsyncRead+AsyncWrite
    let mut guest_stream = ChannelStream::new(id, data_rx, cmd_tx.clone());
    guest_stream.prepend(first_chunk);

    // TLS handshake with guest (fake cert)
    debug!("MITM {domain}: accepting guest TLS");
    let guest_tls = acceptor.accept(guest_stream).await?;
    debug!("MITM {domain}: guest TLS accepted");

    // Upstream: BoringSSL — Chrome's TLS fingerprint passes Cloudflare
    debug!("MITM {domain}: opening upstream TCP {dst}");
    let upstream_tcp = match TcpStream::connect(dst).await {
        Ok(stream) => stream,
        Err(error) => {
            let _ = cmd_tx.send(StackCommand::Close { id });
            return Err(error.into());
        }
    };
    debug!("MITM {domain}: opening upstream TLS with SNI {domain}");
    let connect_config = match upstream_ssl.configure() {
        Ok(config) => config,
        Err(error) => {
            let _ = cmd_tx.send(StackCommand::Close { id });
            return Err(error.into());
        }
    };
    let upstream_tls = match tokio_boring::connect(connect_config, &domain, upstream_tcp).await {
        Ok(stream) => stream,
        Err(error) => {
            let _ = cmd_tx.send(StackCommand::Close { id });
            return Err(anyhow::anyhow!("BoringSSL connect to {domain}: {error}"));
        }
    };
    debug!("MITM {domain}: upstream TLS connected");

    let (mut guest_rd, mut guest_wr) = tokio::io::split(guest_tls);
    let (mut upstream_rd, mut upstream_wr) = tokio::io::split(upstream_tls);
    let opaque_upgrade = Arc::new(AtomicBool::new(false));
    let upgrade_pending = Arc::new(AtomicBool::new(false));

    let request_domain = domain.clone();
    let request_opaque_upgrade = opaque_upgrade.clone();
    let request_upgrade_pending = upgrade_pending.clone();
    let guest_to_upstream = async move {
        let result = crate::http1::transform_requests(
            &mut guest_rd,
            &mut upstream_wr,
            &header_rules,
            &substitutions,
            request_opaque_upgrade,
            request_upgrade_pending,
        )
        .await;
        if result.is_err() {
            debug!("MITM {request_domain}: rejected invalid HTTP/1.1 request");
        }
        result
    };

    let response_domain = domain.clone();
    let response_opaque_upgrade = opaque_upgrade.clone();
    let response_upgrade_pending = upgrade_pending.clone();
    let upstream_to_guest = async move {
        relay_upstream_response(
            &response_domain,
            &mut upstream_rd,
            &mut guest_wr,
            response_opaque_upgrade,
            response_upgrade_pending,
        )
        .await
    };

    tokio::select! {
        result = guest_to_upstream => {
            match result {
                Ok(stats) => debug!(
                    "MITM {domain}: guest->upstream relay ended after {} bytes in {} request(s), {} replacement(s)",
                    stats.bytes_read, stats.requests, stats.replacements
                ),
                Err(error) => debug!("MITM {domain}: guest->upstream relay failed: {error}"),
            }
        },
        result = upstream_to_guest => {
            match result {
                Ok(stats) => debug!(
                    "MITM {domain}: upstream->guest relay ended after {} bytes in {} chunk(s)",
                    stats.bytes, stats.chunks
                ),
                Err(error) => debug!("MITM {domain}: upstream->guest relay failed: {error}"),
            }
        },
    }

    let _ = cmd_tx.send(StackCommand::Close { id });
    Ok(())
}

#[derive(Debug, Default, PartialEq, Eq)]
struct RelayStats {
    bytes: u64,
    chunks: u64,
    replacements: u64,
}

#[derive(Debug, Default)]
struct HttpHeaderProgress {
    buffer: Vec<u8>,
    logged: bool,
}

impl HttpHeaderProgress {
    fn observe_response(&mut self, domain: &str, data: &[u8], total_bytes: u64) {
        self.observe(domain, data, total_bytes, "response");
    }

    fn observe(&mut self, domain: &str, data: &[u8], total_bytes: u64, kind: &str) {
        if self.logged {
            return;
        }

        const MAX_HEADER_SCAN_BYTES: usize = 64 * 1024;
        let remaining = MAX_HEADER_SCAN_BYTES.saturating_sub(self.buffer.len());
        self.buffer
            .extend_from_slice(&data[..data.len().min(remaining)]);

        if self.buffer.windows(4).any(|window| window == b"\r\n\r\n") {
            debug!("MITM {domain}: HTTP {kind} headers observed after {total_bytes} byte(s)");
            self.logged = true;
            self.buffer.clear();
        } else if self.buffer.len() >= MAX_HEADER_SCAN_BYTES {
            trace!("MITM {domain}: HTTP {kind} headers not observed in first {MAX_HEADER_SCAN_BYTES} bytes");
            self.logged = true;
            self.buffer.clear();
        }
    }
}

async fn relay_upstream_response<R, W>(
    domain: &str,
    reader: &mut R,
    writer: &mut W,
    opaque_upgrade: Arc<AtomicBool>,
    upgrade_pending: Arc<AtomicBool>,
) -> io::Result<RelayStats>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut stats = RelayStats::default();
    let mut progress = HttpHeaderProgress::default();
    let mut upgrade_buffer = Vec::new();
    let mut buf = vec![0u8; 65536];

    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            debug!("MITM {domain}: upstream closed response stream");
            return Ok(stats);
        }

        stats.bytes += n as u64;
        stats.chunks += 1;
        progress.observe_response(domain, &buf[..n], stats.bytes);

        if upgrade_pending.load(Ordering::Acquire) && !opaque_upgrade.load(Ordering::Acquire) {
            upgrade_buffer.extend_from_slice(&buf[..n]);
            while let Some(end) = upgrade_buffer
                .windows(4)
                .position(|bytes| bytes == b"\r\n\r\n")
                .map(|position| position + 4)
            {
                let response = &upgrade_buffer[..end];
                if crate::http1::response_accepts_upgrade(response) {
                    opaque_upgrade.store(true, Ordering::Release);
                    upgrade_pending.store(false, Ordering::Release);
                    upgrade_buffer.clear();
                    debug!("MITM {domain}: HTTP upgrade accepted; switching to opaque relay");
                    break;
                }
                let interim =
                    response_status(response).is_some_and(|status| (100..200).contains(&status));
                upgrade_buffer.drain(..end);
                if !interim {
                    upgrade_pending.store(false, Ordering::Release);
                    upgrade_buffer.clear();
                    break;
                }
            }
            if upgrade_buffer.len() > 64 * 1024 {
                upgrade_pending.store(false, Ordering::Release);
                upgrade_buffer.clear();
            }
        }

        writer.write_all(&buf[..n]).await?;
        writer.flush().await?;
        trace!("MITM {domain}: forwarded response chunk {} byte(s)", n);
    }
}

fn response_status(response: &[u8]) -> Option<u16> {
    let end = response.windows(2).position(|bytes| bytes == b"\r\n")?;
    let mut parts = response[..end].split(|byte| *byte == b' ');
    if parts.next()? != b"HTTP/1.1" {
        return None;
    }
    std::str::from_utf8(parts.next()?).ok()?.parse().ok()
}

/// Extract SNI from a TLS ClientHello.
pub fn extract_sni(data: &[u8]) -> Option<String> {
    if data.len() < 5 || data[0] != 0x16 {
        return None;
    }

    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + record_len {
        return None;
    }

    let hs = &data[5..];
    if hs.is_empty() || hs[0] != 0x01 {
        return None;
    }

    if hs.len() < 38 {
        return None;
    }
    let mut pos = 38;

    // Session ID
    if pos >= hs.len() {
        return None;
    }
    let session_id_len = hs[pos] as usize;
    pos += 1 + session_id_len;

    // Cipher suites
    if pos + 2 > hs.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([hs[pos], hs[pos + 1]]) as usize;
    pos += 2 + cs_len;

    // Compression methods
    if pos >= hs.len() {
        return None;
    }
    let cm_len = hs[pos] as usize;
    pos += 1 + cm_len;

    // Extensions
    if pos + 2 > hs.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([hs[pos], hs[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_len;

    while pos + 4 <= ext_end && pos + 4 <= hs.len() {
        let ext_type = u16::from_be_bytes([hs[pos], hs[pos + 1]]);
        let ext_data_len = u16::from_be_bytes([hs[pos + 2], hs[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 {
            if ext_data_len >= 5 && pos + ext_data_len <= hs.len() {
                let name_type = hs[pos + 2];
                if name_type == 0x00 {
                    let name_len = u16::from_be_bytes([hs[pos + 3], hs[pos + 4]]) as usize;
                    if pos + 5 + name_len <= hs.len() {
                        return String::from_utf8(hs[pos + 5..pos + 5 + name_len].to_vec()).ok();
                    }
                }
            }
            return None;
        }

        pos += ext_data_len;
    }

    None
}

fn extract_http_host(data: &[u8]) -> Option<String> {
    let header_end = data.windows(4).position(|window| window == b"\r\n\r\n")?;
    let headers = std::str::from_utf8(&data[..header_end]).ok()?;
    for line in headers.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("host") {
            let host = value.trim();
            if host.is_empty() {
                return None;
            }
            return Some(strip_host_port(host).to_string());
        }
    }
    None
}

fn strip_host_port(host: &str) -> &str {
    if host.starts_with('[') {
        return host;
    }
    host.rsplit_once(':')
        .and_then(|(name, port)| port.parse::<u16>().ok().map(|_| name))
        .unwrap_or(host)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use super::*;
    use tokio::io::AsyncWrite;

    fn allowed_config(domain: &str) -> ProxyConfig {
        ProxyConfig {
            network: crate::config::NetworkConfig {
                allow: vec![domain.into()],
            },
            ..Default::default()
        }
    }

    fn cache_answer(domain: &str, addr: Ipv4Addr) -> SharedDnsCache {
        let cache = dns::new_shared_dns_cache();
        dns::record_allowed_dns_answer(&cache, domain, &[addr]);
        cache
    }

    fn dst(addr: Ipv4Addr, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(addr), port)
    }

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    #[derive(Default)]
    struct FlushCountingWriter {
        bytes: Vec<u8>,
        flushes: usize,
    }

    impl AsyncWrite for FlushCountingWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.bytes.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.flushes += 1;
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn test_extract_sni_none_for_non_tls() {
        assert_eq!(extract_sni(b"GET / HTTP/1.1\r\n"), None);
        assert_eq!(extract_sni(&[]), None);
    }

    #[tokio::test]
    async fn upstream_response_relay_flushes_after_forwarding_chunk() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
        let mut reader = &response[..];
        let mut writer = FlushCountingWriter::default();

        let stats = relay_upstream_response(
            "api.example.test",
            &mut reader,
            &mut writer,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .expect("response relay should succeed");

        assert_eq!(writer.bytes, response);
        assert_eq!(writer.flushes, 1);
        assert_eq!(
            stats,
            RelayStats {
                bytes: response.len() as u64,
                chunks: 1,
                replacements: 0,
            }
        );
    }

    #[test]
    fn allowlist_policy_allows_visible_allowed_domain() {
        let config = allowed_config("api.example.test");
        let allowed_ip = Ipv4Addr::new(203, 0, 113, 10);
        let cache = cache_answer("api.example.test", allowed_ip);

        enforce_connection_policy(
            &config,
            &cache,
            Some("api.example.test"),
            dst(allowed_ip, 443),
            "TLS",
        )
        .expect("allowed domain should pass");
    }

    #[test]
    fn mount_only_smb_route_allows_only_gateway_smb_to_host_loopback() {
        let config = ProxyConfig::mount_only_smb();

        assert_eq!(
            classify_connection_route(&config, dst(crate::config::GUEST_GATEWAY_IP, 445)),
            ConnectionRoute::SmbMountRelay(loopback(445))
        );
        assert_eq!(
            classify_connection_route(&config, dst(crate::config::GUEST_GATEWAY_IP, 80)),
            ConnectionRoute::DenyMountOnly
        );
        assert_eq!(
            classify_connection_route(&config, dst(Ipv4Addr::new(203, 0, 113, 10), 445)),
            ConnectionRoute::DenyMountOnly
        );
    }

    #[test]
    fn mount_only_smb_route_ignores_expose_host_and_network_policy() {
        let mut config = ProxyConfig::mount_only_smb();
        config.expose_host.push(crate::config::ExposeHostMapping {
            host_port: 3000,
            guest_port: 8080,
        });
        config.network.allow.push("api.example.test".into());

        assert_eq!(
            classify_connection_route(&config, dst(crate::config::GUEST_GATEWAY_IP, 8080)),
            ConnectionRoute::DenyMountOnly
        );
        assert!(enforce_connection_policy(
            &config,
            &dns::new_shared_dns_cache(),
            Some("api.example.test"),
            dst(Ipv4Addr::new(203, 0, 113, 10), 443),
            "TLS",
        )
        .is_err());
    }

    #[test]
    fn combined_smb_route_preserves_network_and_expose_host_behavior() {
        let mut config = allowed_config("api.example.test").with_smb_mount_relay();
        config.expose_host.push(crate::config::ExposeHostMapping {
            host_port: 3000,
            guest_port: 8080,
        });

        assert_eq!(
            classify_connection_route(&config, dst(crate::config::GUEST_GATEWAY_IP, 445)),
            ConnectionRoute::SmbMountRelay(loopback(445))
        );
        assert_eq!(
            classify_connection_route(&config, dst(crate::config::GUEST_GATEWAY_IP, 8080)),
            ConnectionRoute::ExposeHost(loopback(3000))
        );
        assert_eq!(
            classify_connection_route(&config, dst(Ipv4Addr::new(203, 0, 113, 10), 443)),
            ConnectionRoute::Outbound
        );
    }

    #[test]
    fn allowlist_policy_blocks_direct_ip_or_missing_domain() {
        let config = allowed_config("api.example.test");
        let cache = dns::new_shared_dns_cache();

        let err = enforce_connection_policy(
            &config,
            &cache,
            None,
            dst(Ipv4Addr::new(203, 0, 113, 10), 80),
            "TCP",
        )
        .expect_err("missing domain should be blocked");

        assert!(err.to_string().contains("no policy-visible domain"));
    }

    #[test]
    fn allowlist_policy_blocks_unlisted_sni() {
        let config = allowed_config("api.example.test");
        let cache = dns::new_shared_dns_cache();

        let err = enforce_connection_policy(
            &config,
            &cache,
            Some("blocked.example.test"),
            dst(Ipv4Addr::new(203, 0, 113, 10), 443),
            "TLS",
        )
        .expect_err("blocked domain should fail");

        assert!(err.to_string().contains("denied by network policy"));
        assert!(err.to_string().contains("blocked.example.test"));
    }

    #[test]
    fn allowlist_policy_blocks_forged_http_host_to_arbitrary_ip() {
        let config = allowed_config("api.example.test");
        let cache = cache_answer("api.example.test", Ipv4Addr::new(203, 0, 113, 10));

        let err = enforce_connection_policy(
            &config,
            &cache,
            Some("api.example.test"),
            dst(Ipv4Addr::new(198, 51, 100, 42), 80),
            "TCP",
        )
        .expect_err("forged Host header must not authorize arbitrary destination IP");

        assert!(err.to_string().contains("did not resolve to destination"));
    }

    #[test]
    fn allowlist_policy_blocks_forged_sni_to_arbitrary_ip() {
        let config = allowed_config("api.example.test");
        let cache = cache_answer("api.example.test", Ipv4Addr::new(203, 0, 113, 10));

        let err = enforce_connection_policy(
            &config,
            &cache,
            Some("api.example.test"),
            dst(Ipv4Addr::new(198, 51, 100, 42), 443),
            "TLS",
        )
        .expect_err("forged SNI must not authorize arbitrary destination IP");

        assert!(err.to_string().contains("did not resolve to destination"));
    }

    #[test]
    fn http_host_is_policy_visible_without_leaking_payloads() {
        let host = extract_http_host(
            b"GET / HTTP/1.1\r\nHost: api.example.test:443\r\nUser-Agent: test\r\n\r\nbody",
        )
        .expect("host header should parse");

        assert_eq!(host, "api.example.test");
    }

    #[test]
    fn secret_substitution_is_reachable_only_after_domain_policy_allows() {
        let mut config = allowed_config("api.example.test");
        config.secrets.insert(
            "API_KEY".into(),
            crate::config::SecretConfig {
                value: "real-secret".into(),
                hosts: vec!["api.example.test".into()],
            },
        );
        let placeholders = HashMap::from([("API_KEY".into(), "lsb_tok_placeholder".into())]);
        let allowed_ip = Ipv4Addr::new(203, 0, 113, 10);
        let cache = cache_answer("api.example.test", allowed_ip);

        enforce_connection_policy(
            &config,
            &cache,
            Some("api.example.test"),
            dst(allowed_ip, 443),
            "TLS",
        )
        .expect("secret host is allowed");
        assert_eq!(
            config.secrets_for_domain("api.example.test", &placeholders),
            vec![("lsb_tok_placeholder".into(), "real-secret".into())]
        );

        assert!(enforce_connection_policy(
            &config,
            &cache,
            Some("blocked.example.test"),
            dst(allowed_ip, 443),
            "TLS",
        )
        .is_err());
        assert!(config
            .secrets_for_domain("blocked.example.test", &placeholders)
            .is_empty());
    }
}
