use std::collections::HashMap;
#[cfg(windows)]
use std::ffi::c_void;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use boring::ssl::{SslConnector, SslConnectorBuilder, SslMethod};
use boring::x509::X509;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Notify};
use tracing::{debug, info, trace};
#[cfg(windows)]
use windows_sys::Win32::Security::Cryptography::{
    CertCloseStore, CertEnumCertificatesInStore, CertOpenStore, CERT_CONTEXT,
    CERT_STORE_PROV_SYSTEM_W, CERT_STORE_READONLY_FLAG, CERT_SYSTEM_STORE_LOCAL_MACHINE,
};
use zeroize::Zeroize;

use crate::config::{ProxyConfig, RequestHeaderRule, UpstreamProxyConfig, SMB_MOUNT_PORT};
use crate::dns::{self, SharedDnsCache};
use crate::policy::is_public_destination;
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
    ) -> anyhow::Result<Self> {
        // BoringSSL upstream connector — Chrome's TLS stack so Cloudflare
        // doesn't reject our MITM connections based on JA3/JA4 fingerprint.
        let mut builder = SslConnector::builder(SslMethod::tls()).expect("SslConnector");
        builder.set_alpn_protos(b"\x08http/1.1").expect("ALPN");
        configure_upstream_tls_roots(&mut builder, &config.product_ca_bundle_pem)?;
        let upstream_ssl = builder.build();

        Ok(ProxyEngine {
            config: Arc::new(config),
            event_rx,
            cmd_tx,
            connections: HashMap::new(),
            dns_cache: dns::new_shared_dns_cache(),
            placeholders: Arc::new(placeholders),
            ca: Arc::new(tokio::sync::Mutex::new(ca)),
            upstream_ssl,
        })
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

fn configure_upstream_tls_roots(
    builder: &mut SslConnectorBuilder,
    product_ca_bundle_pem: &[u8],
) -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        let count = add_windows_system_roots(builder)?;
        if count == 0 {
            anyhow::bail!("Windows LocalMachine ROOT/CA stores contained no usable certificates");
        }
        debug!("loaded {count} Windows LocalMachine root certificate(s) for upstream TLS");
    }

    #[cfg(not(windows))]
    let _ = builder;

    if !product_ca_bundle_pem.is_empty() {
        let certificates = X509::stack_from_pem(product_ca_bundle_pem)?;
        if certificates.is_empty() {
            anyhow::bail!("product CA bundle contains no certificates");
        }
        for certificate in certificates {
            builder.cert_store_mut().add_cert(certificate)?;
        }
        debug!("loaded installer-protected product CA bundle for upstream TLS");
    }

    Ok(())
}

#[cfg(windows)]
fn add_windows_system_roots(builder: &mut SslConnectorBuilder) -> anyhow::Result<usize> {
    let mut count = 0;
    for store_name in ["ROOT", "CA"] {
        count += add_windows_cert_store(builder, CERT_SYSTEM_STORE_LOCAL_MACHINE, store_name)?;
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
        return Err(std::io::Error::last_os_error().into());
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

const UPSTREAM_PROXY_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const MAX_UPSTREAM_PROXY_RESPONSE_BYTES: usize = 16 * 1024;
const MAX_POLICY_VISIBLE_HTTP_HEADER_BYTES: usize = 64 * 1024;

async fn connect_outbound(
    proxy: Option<&UpstreamProxyConfig>,
    destination: SocketAddr,
) -> anyhow::Result<TcpStream> {
    let Some(proxy) = proxy else {
        return Ok(TcpStream::connect(destination).await?);
    };

    let proxy_host = proxy
        .host
        .parse::<IpAddr>()
        .map(|address| address.to_string())
        .unwrap_or_else(|_| {
            crate::policy::normalize_domain(&proxy.host).unwrap_or_else(|| proxy.host.clone())
        });
    let mut stream = tokio::time::timeout(
        UPSTREAM_PROXY_CONNECT_TIMEOUT,
        TcpStream::connect((proxy_host.as_str(), proxy.port)),
    )
    .await
    .map_err(|_| anyhow::anyhow!("upstream proxy connection timed out"))??;

    establish_connect_tunnel(&mut stream, destination, proxy.authorization.as_deref()).await?;
    Ok(stream)
}

async fn establish_connect_tunnel<S>(
    stream: &mut S,
    destination: SocketAddr,
    authorization: Option<&str>,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let authority = destination.to_string();
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some(authorization) = authorization {
        request.push_str("Proxy-Authorization: ");
        request.push_str(authorization);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    let write_result = stream.write_all(request.as_bytes()).await;
    request.zeroize();
    write_result?;
    stream.flush().await?;

    let mut response = Vec::new();
    let read_result = tokio::time::timeout(UPSTREAM_PROXY_CONNECT_TIMEOUT, async {
        let mut chunk = [0u8; 1024];
        loop {
            let count = stream.read(&mut chunk).await?;
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "upstream proxy closed during CONNECT",
                ));
            }
            response.extend_from_slice(&chunk[..count]);
            if response.len() > MAX_UPSTREAM_PROXY_RESPONSE_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "upstream proxy CONNECT response exceeds limit",
                ));
            }
            if let Some(end) = response
                .windows(4)
                .position(|bytes| bytes == b"\r\n\r\n")
                .map(|position| position + 4)
            {
                if response.len() != end {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "upstream proxy sent unexpected tunnel bytes during CONNECT",
                    ));
                }
                return Ok(end);
            }
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("upstream proxy CONNECT timed out"))?;

    let result = match read_result {
        Ok(end) => parse_connect_response(&response[..end]),
        Err(error) => Err(error.into()),
    };
    response.zeroize();
    result
}

fn parse_connect_response(response: &[u8]) -> anyhow::Result<()> {
    let line_end = response
        .windows(2)
        .position(|bytes| bytes == b"\r\n")
        .ok_or_else(|| anyhow::anyhow!("upstream proxy returned a malformed CONNECT response"))?;
    let mut parts = response[..line_end].split(|byte| *byte == b' ');
    let version = parts.next().unwrap_or_default();
    if !matches!(version, b"HTTP/1.0" | b"HTTP/1.1") {
        anyhow::bail!("upstream proxy returned an unsupported HTTP version");
    }
    let status = parts
        .next()
        .and_then(|value| std::str::from_utf8(value).ok())
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|status| (100..=999).contains(status))
        .ok_or_else(|| anyhow::anyhow!("upstream proxy returned a malformed CONNECT status"))?;
    if !(200..300).contains(&status) {
        anyhow::bail!("upstream proxy rejected CONNECT with status {status}");
    }
    Ok(())
}

async fn connect_default_tcp(
    config: &ProxyConfig,
    dns_cache: &SharedDnsCache,
    destination: SocketAddr,
) -> anyhow::Result<TcpStream> {
    enforce_connection_policy(config, dns_cache, None, destination, "TCP")?;
    connect_outbound(config.upstream_proxy.as_ref(), destination).await
}

async fn read_policy_visible_http_request(
    data_rx: &mut mpsc::UnboundedReceiver<Vec<u8>>,
) -> anyhow::Result<Vec<u8>> {
    let mut buffered = Vec::new();
    loop {
        if let Some(end) = buffered
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .map(|position| position + 4)
        {
            if end > MAX_POLICY_VISIBLE_HTTP_HEADER_BYTES {
                anyhow::bail!("policy-visible HTTP request headers exceed limit");
            }
            return Ok(buffered);
        }
        if buffered.len() > MAX_POLICY_VISIBLE_HTTP_HEADER_BYTES {
            anyhow::bail!("policy-visible HTTP request headers exceed limit");
        }
        let chunk = data_rx
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("connection closed before complete HTTP headers"))?;
        buffered.extend_from_slice(&chunk);
    }
}

async fn relay_authorized_http(
    id: ConnectionId,
    destination: SocketAddr,
    domain: String,
    first_request: Vec<u8>,
    data_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    cmd_tx: mpsc::UnboundedSender<StackCommand>,
    upstream: TcpStream,
) -> anyhow::Result<()> {
    let mut guest = ChannelStream::new(id, data_rx, cmd_tx.clone());
    guest.prepend(first_request);
    let (mut guest_rd, mut guest_wr) = tokio::io::split(guest);
    let (mut upstream_rd, mut upstream_wr) = upstream.into_split();
    let opaque_upgrade = Arc::new(AtomicBool::new(false));
    let upgrade_pending = Arc::new(AtomicBool::new(false));
    let upgrade_notify = Arc::new(Notify::new());

    let request_domain = domain.clone();
    let request_opaque = opaque_upgrade.clone();
    let request_pending = upgrade_pending.clone();
    let request_notify = upgrade_notify.clone();
    let guest_to_upstream = async move {
        crate::http1::transform_requests(
            &mut guest_rd,
            &mut upstream_wr,
            crate::http1::RequestTransformPolicy::new(
                &request_domain,
                destination.port(),
                &[],
                &[],
            ),
            request_opaque,
            request_pending,
            request_notify,
        )
        .await
    };

    let upstream_to_guest = relay_upstream_response(
        &domain,
        &mut upstream_rd,
        &mut guest_wr,
        opaque_upgrade,
        upgrade_pending,
        upgrade_notify,
    );

    let result = tokio::select! {
        result = guest_to_upstream => result.map(|_| ()),
        result = upstream_to_guest => result.map(|_| ()),
    };
    let _ = cmd_tx.send(StackCommand::Close { id });
    result?;
    Ok(())
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
                    config.upstream_proxy.clone(),
                    upstream_ssl,
                )
                .await;
            }
        }

        // Blind tunnel: forward the buffered data and relay the rest
        debug!("blind tunnel to {dst}");
        let upstream = connect_outbound(config.upstream_proxy.as_ref(), dst).await?;
        let (mut upstream_rd, mut upstream_wr) = upstream.into_split();

        // Send the buffered TLS data
        upstream_wr.write_all(&tls_buf).await?;

        return blind_relay(id, &mut upstream_rd, &mut upstream_wr, data_rx, cmd_tx).await;
    }

    if config.has_domain_allowlist() {
        let first_request = read_policy_visible_http_request(&mut data_rx).await?;
        let host = extract_http_host(&first_request)
            .ok_or_else(|| anyhow::anyhow!("TCP connection denied: no policy-visible domain"))?;
        enforce_connection_policy(config, dns_cache, Some(&host), dst, "TCP")?;

        debug!("TCP tunnel to {dst}");
        let upstream = connect_outbound(config.upstream_proxy.as_ref(), dst).await?;
        return relay_authorized_http(id, dst, host, first_request, data_rx, cmd_tx, upstream)
            .await;
    }

    // Non-TLS without an explicit allowlist: blind tunnel.
    debug!("TCP tunnel to {dst}");
    let upstream = connect_default_tcp(config, dns_cache, dst).await?;
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

    if !is_public_destination(dst.ip()) {
        anyhow::bail!("{protocol} connection denied: destination is not globally routable");
    }

    if let Some(domain) = domain.filter(|domain| !config.is_domain_allowed(domain)) {
        anyhow::bail!("{protocol} connection denied by network policy for {domain}");
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
    if dns::destination_matches_dns_answer(dns_cache, domain, dst.ip())? {
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
    upstream_proxy: Option<UpstreamProxyConfig>,
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
    let upstream_tcp = match connect_outbound(upstream_proxy.as_ref(), dst).await {
        Ok(stream) => stream,
        Err(error) => {
            let _ = cmd_tx.send(StackCommand::Close { id });
            return Err(error);
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
    let upgrade_notify = Arc::new(Notify::new());

    let request_domain = domain.clone();
    let request_opaque_upgrade = opaque_upgrade.clone();
    let request_upgrade_pending = upgrade_pending.clone();
    let request_upgrade_notify = upgrade_notify.clone();
    let guest_to_upstream = async move {
        let result = crate::http1::transform_requests(
            &mut guest_rd,
            &mut upstream_wr,
            crate::http1::RequestTransformPolicy::new(
                &request_domain,
                dst.port(),
                &header_rules,
                &substitutions,
            ),
            request_opaque_upgrade,
            request_upgrade_pending,
            request_upgrade_notify,
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
    let response_upgrade_notify = upgrade_notify.clone();
    let upstream_to_guest = async move {
        relay_upstream_response(
            &response_domain,
            &mut upstream_rd,
            &mut guest_wr,
            response_opaque_upgrade,
            response_upgrade_pending,
            response_upgrade_notify,
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

async fn relay_upstream_response<R, W>(
    domain: &str,
    reader: &mut R,
    writer: &mut W,
    opaque_upgrade: Arc<AtomicBool>,
    upgrade_pending: Arc<AtomicBool>,
    upgrade_notify: Arc<Notify>,
) -> io::Result<RelayStats>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut stats = RelayStats::default();
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
                    upgrade_notify.notify_one();
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
        dns::record_allowed_dns_answer(&cache, domain, &[IpAddr::V4(addr)]);
        cache
    }

    fn dst(addr: Ipv4Addr, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(addr), port)
    }

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    async fn read_connect_request<S>(stream: &mut S) -> Vec<u8>
    where
        S: AsyncRead + Unpin,
    {
        let mut request = Vec::new();
        let mut byte = [0u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            request.push(byte[0]);
            assert!(request.len() <= 16 * 1024);
        }
        request
    }

    #[tokio::test]
    async fn explicit_proxy_connect_scopes_authorization_to_the_proxy_handshake() {
        let listener = tokio::net::TcpListener::bind(loopback(0)).await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_connect_request(&mut stream).await;
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            request
        });

        let proxy = UpstreamProxyConfig {
            host: endpoint.ip().to_string(),
            port: endpoint.port(),
            authorization: Some("Basic explicit-credential".into()),
        };
        let destination = dst(Ipv4Addr::new(93, 184, 216, 34), 443);
        let stream = connect_outbound(Some(&proxy), destination).await.unwrap();
        drop(stream);
        let request = String::from_utf8(server.await.unwrap()).unwrap();
        assert!(request
            .starts_with("CONNECT 93.184.216.34:443 HTTP/1.1\r\nHost: 93.184.216.34:443\r\n"));
        assert!(request.contains("Proxy-Authorization: Basic explicit-credential\r\n"));
        assert_eq!(request.matches("Proxy-Authorization").count(), 1);
    }

    #[tokio::test]
    async fn explicit_proxy_connect_brackets_ipv6_authorities() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let request = read_connect_request(&mut server).await;
            server
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            request
        });
        let destination = SocketAddr::new(IpAddr::V6("2606:4700:4700::1111".parse().unwrap()), 443);

        establish_connect_tunnel(&mut client, destination, None)
            .await
            .unwrap();

        let request = String::from_utf8(server_task.await.unwrap()).unwrap();
        assert!(request.starts_with(
            "CONNECT [2606:4700:4700::1111]:443 HTTP/1.1\r\nHost: [2606:4700:4700::1111]:443\r\n"
        ));
    }

    #[tokio::test]
    async fn proxy_rejection_never_echoes_explicit_credentials() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let request = read_connect_request(&mut server).await;
            server
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .await
                .unwrap();
            request
        });
        let error = establish_connect_tunnel(
            &mut client,
            dst(Ipv4Addr::new(93, 184, 216, 34), 443),
            Some("Bearer never-echo-this"),
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "upstream proxy rejected CONNECT with status 407"
        );
        assert!(!error.to_string().contains("never-echo-this"));
        let request = String::from_utf8(server_task.await.unwrap()).unwrap();
        assert!(request.contains("Proxy-Authorization: Bearer never-echo-this"));
    }

    #[tokio::test]
    async fn proxy_connect_without_explicit_authorization_sends_no_credentials() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let request = read_connect_request(&mut server).await;
            server
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            request
        });
        establish_connect_tunnel(&mut client, dst(Ipv4Addr::new(93, 184, 216, 34), 443), None)
            .await
            .unwrap();
        let request = String::from_utf8(server_task.await.unwrap()).unwrap();
        assert!(!request.contains("Proxy-Authorization"));
        assert!(!request.contains("Negotiate"));
        assert!(!request.contains("NTLM"));
    }

    #[tokio::test]
    async fn default_non_tls_private_destination_is_denied_before_proxy_connection() {
        let listener = tokio::net::TcpListener::bind(loopback(0)).await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let config = ProxyConfig {
            upstream_proxy: Some(UpstreamProxyConfig {
                host: endpoint.ip().to_string(),
                port: endpoint.port(),
                authorization: Some("Basic must-not-be-sent".into()),
            }),
            ..Default::default()
        };
        let cache = dns::new_shared_dns_cache();
        let error = connect_default_tcp(&config, &cache, loopback(80))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("not globally routable"));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn policy_visible_http_headers_are_bounded_and_may_span_guest_frames() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        tx.send(b"GET / HTTP/1.1\r\nHo".to_vec()).unwrap();
        tx.send(b"st: api.example.test\r\n\r\nbody".to_vec())
            .unwrap();
        let request = read_policy_visible_http_request(&mut rx).await.unwrap();
        assert_eq!(
            request,
            b"GET / HTTP/1.1\r\nHost: api.example.test\r\n\r\nbody"
        );

        let (tx, mut rx) = mpsc::unbounded_channel();
        tx.send(vec![b'x'; MAX_POLICY_VISIBLE_HTTP_HEADER_BYTES + 1])
            .unwrap();
        assert!(read_policy_visible_http_request(&mut rx).await.is_err());
    }

    #[test]
    fn connect_response_parser_accepts_only_bounded_success_statuses() {
        parse_connect_response(b"HTTP/1.0 200 OK\r\n\r\n").unwrap();
        parse_connect_response(b"HTTP/1.1 204 No Content\r\n\r\n").unwrap();
        for invalid in [
            b"HTTP/2 200 OK\r\n\r\n".as_slice(),
            b"HTTP/1.1 nope\r\n\r\n".as_slice(),
            b"HTTP/1.1 407 Required\r\n\r\n".as_slice(),
        ] {
            assert!(parse_connect_response(invalid).is_err());
        }
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
            Arc::new(Notify::new()),
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

    #[tokio::test]
    async fn response_relay_preserves_continue_and_accepts_upgrade() {
        let response = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nopaque";
        let mut reader = &response[..];
        let mut writer = FlushCountingWriter::default();
        let opaque = Arc::new(AtomicBool::new(false));
        let pending = Arc::new(AtomicBool::new(true));
        let notify = Arc::new(Notify::new());

        relay_upstream_response(
            "api.example.test",
            &mut reader,
            &mut writer,
            opaque.clone(),
            pending.clone(),
            notify.clone(),
        )
        .await
        .unwrap();

        assert_eq!(writer.bytes, response);
        assert!(opaque.load(Ordering::Acquire));
        assert!(!pending.load(Ordering::Acquire));
        tokio::time::timeout(std::time::Duration::from_secs(1), notify.notified())
            .await
            .expect("accepted upgrade should notify the request relay");
    }

    #[tokio::test]
    async fn response_relay_resumes_http_after_rejected_upgrade() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
        let mut reader = &response[..];
        let mut writer = FlushCountingWriter::default();
        let opaque = Arc::new(AtomicBool::new(false));
        let pending = Arc::new(AtomicBool::new(true));

        relay_upstream_response(
            "api.example.test",
            &mut reader,
            &mut writer,
            opaque.clone(),
            pending.clone(),
            Arc::new(Notify::new()),
        )
        .await
        .unwrap();

        assert_eq!(writer.bytes, response);
        assert!(!opaque.load(Ordering::Acquire));
        assert!(!pending.load(Ordering::Acquire));
    }

    #[test]
    fn allowlist_policy_allows_visible_allowed_domain() {
        let config = allowed_config("api.example.test");
        let allowed_ip = Ipv4Addr::new(93, 184, 216, 34);
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
    fn allowlist_policy_supports_public_ipv6_dns_binding() {
        let config = allowed_config("api.example.test");
        let allowed: std::net::Ipv6Addr = "2606:4700:4700::1111".parse().unwrap();
        let other: std::net::Ipv6Addr = "2606:4700:4700::1001".parse().unwrap();
        let cache = dns::new_shared_dns_cache();
        dns::record_allowed_dns_answer(&cache, "api.example.test", &[IpAddr::V6(allowed)]);

        enforce_connection_policy(
            &config,
            &cache,
            Some("api.example.test"),
            SocketAddr::new(IpAddr::V6(allowed), 443),
            "TLS",
        )
        .expect("allowed IPv6 DNS destination should pass");
        assert!(enforce_connection_policy(
            &config,
            &cache,
            Some("api.example.test"),
            SocketAddr::new(IpAddr::V6(other), 443),
            "TLS",
        )
        .is_err());
        assert!(enforce_connection_policy(
            &ProxyConfig::default(),
            &cache,
            None,
            SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 443),
            "TLS",
        )
        .is_err());
    }

    #[test]
    fn default_network_allows_public_destinations_and_denies_non_global_ranges() {
        let config = ProxyConfig::default();
        let cache = dns::new_shared_dns_cache();
        enforce_connection_policy(
            &config,
            &cache,
            None,
            dst(Ipv4Addr::new(93, 184, 216, 34), 443),
            "TLS",
        )
        .expect("globally routable direct IP should pass default policy");

        for denied in [
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(169, 254, 169, 254),
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(198, 51, 100, 1),
            Ipv4Addr::new(203, 0, 113, 1),
        ] {
            let error = enforce_connection_policy(&config, &cache, None, dst(denied, 80), "TCP")
                .expect_err("non-global destination must fail closed");
            assert!(error.to_string().contains("not globally routable"));
        }
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
            classify_connection_route(&config, dst(Ipv4Addr::new(93, 184, 216, 34), 445)),
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
            dst(Ipv4Addr::new(93, 184, 216, 34), 443),
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
            classify_connection_route(&config, dst(Ipv4Addr::new(93, 184, 216, 34), 443)),
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
            dst(Ipv4Addr::new(93, 184, 216, 34), 80),
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
            dst(Ipv4Addr::new(93, 184, 216, 34), 443),
            "TLS",
        )
        .expect_err("blocked domain should fail");

        assert!(err.to_string().contains("denied by network policy"));
        assert!(err.to_string().contains("blocked.example.test"));
    }

    #[test]
    fn allowlist_policy_blocks_forged_http_host_to_arbitrary_ip() {
        let config = allowed_config("api.example.test");
        let cache = cache_answer("api.example.test", Ipv4Addr::new(93, 184, 216, 34));

        let err = enforce_connection_policy(
            &config,
            &cache,
            Some("api.example.test"),
            dst(Ipv4Addr::new(1, 1, 1, 1), 80),
            "TCP",
        )
        .expect_err("forged Host header must not authorize arbitrary destination IP");

        assert!(err.to_string().contains("did not resolve to destination"));
    }

    #[test]
    fn allowlist_policy_blocks_forged_sni_to_arbitrary_ip() {
        let config = allowed_config("api.example.test");
        let cache = cache_answer("api.example.test", Ipv4Addr::new(93, 184, 216, 34));

        let err = enforce_connection_policy(
            &config,
            &cache,
            Some("api.example.test"),
            dst(Ipv4Addr::new(1, 1, 1, 1), 443),
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
        let allowed_ip = Ipv4Addr::new(93, 184, 216, 34);
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
