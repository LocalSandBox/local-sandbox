use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use boring::ssl::{SslConnector, SslMethod};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, info, trace};

use crate::config::{ProxyConfig, SMB_MOUNT_PORT};
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
            if !substitutions.is_empty() {
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
    upstream_ssl: SslConnector,
) -> anyhow::Result<()> {
    debug!(
        "MITM {domain}: starting interception for {dst} with {} secret placeholder(s)",
        substitutions.len()
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
    let upstream_tcp = TcpStream::connect(dst).await?;
    debug!("MITM {domain}: opening upstream TLS with SNI {domain}");
    let upstream_tls = tokio_boring::connect(upstream_ssl.configure()?, &domain, upstream_tcp)
        .await
        .map_err(|e| anyhow::anyhow!("BoringSSL connect to {domain}: {e}"))?;
    debug!("MITM {domain}: upstream TLS connected");

    let (mut guest_rd, mut guest_wr) = tokio::io::split(guest_tls);
    let (mut upstream_rd, mut upstream_wr) = tokio::io::split(upstream_tls);

    let request_domain = domain.clone();
    let guest_to_upstream = async move {
        relay_guest_request(
            &request_domain,
            &mut guest_rd,
            &mut upstream_wr,
            &substitutions,
        )
        .await
    };

    let response_domain = domain.clone();
    let upstream_to_guest = async move {
        relay_upstream_response(&response_domain, &mut upstream_rd, &mut guest_wr).await
    };

    tokio::select! {
        result = guest_to_upstream => {
            match result {
                Ok(stats) => debug!(
                    "MITM {domain}: guest->upstream relay ended after {} bytes in {} chunk(s), {} replacement(s)",
                    stats.bytes, stats.chunks, stats.replacements
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
    fn observe_request(&mut self, domain: &str, data: &[u8], total_bytes: u64) {
        self.observe(domain, data, total_bytes, "request");
    }

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

async fn relay_guest_request<R, W>(
    domain: &str,
    reader: &mut R,
    writer: &mut W,
    substitutions: &[(String, String)],
) -> io::Result<RelayStats>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut stats = RelayStats::default();
    let mut progress = HttpHeaderProgress::default();
    let mut buf = vec![0u8; 65536];

    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            debug!("MITM {domain}: guest closed request stream");
            return Ok(stats);
        }

        stats.bytes += n as u64;
        stats.chunks += 1;
        progress.observe_request(domain, &buf[..n], stats.bytes);

        let mut data = buf[..n].to_vec();
        for (placeholder, real_value) in substitutions {
            let (replaced, count) =
                replace_bytes_count(&data, placeholder.as_bytes(), real_value.as_bytes());
            stats.replacements += count as u64;
            data = replaced;
        }

        writer.write_all(&data).await?;
        writer.flush().await?;
        trace!(
            "MITM {domain}: forwarded request chunk {} byte(s), {} replacement(s) total",
            n,
            stats.replacements
        );
    }
}

async fn relay_upstream_response<R, W>(
    domain: &str,
    reader: &mut R,
    writer: &mut W,
) -> io::Result<RelayStats>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut stats = RelayStats::default();
    let mut progress = HttpHeaderProgress::default();
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

        writer.write_all(&buf[..n]).await?;
        writer.flush().await?;
        trace!("MITM {domain}: forwarded response chunk {} byte(s)", n);
    }
}

fn replace_bytes_count(data: &[u8], from: &[u8], to: &[u8]) -> (Vec<u8>, usize) {
    if from.is_empty() || data.len() < from.len() {
        return (data.to_vec(), 0);
    }

    let mut result = Vec::with_capacity(data.len());
    let mut replacements = 0;
    let mut i = 0;

    while i <= data.len() - from.len() {
        if &data[i..i + from.len()] == from {
            result.extend_from_slice(to);
            replacements += 1;
            i += from.len();
        } else {
            result.push(data[i]);
            i += 1;
        }
    }

    // Append remaining bytes that can't contain the pattern
    result.extend_from_slice(&data[i..]);
    (result, replacements)
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

    #[test]
    fn test_replace_bytes() {
        assert_eq!(
            replace_bytes_count(b"hello world", b"world", b"rust").0,
            b"hello rust"
        );
        assert_eq!(
            replace_bytes_count(
                b"key=lsb_tok_abc123&other=val",
                b"lsb_tok_abc123",
                b"real_secret"
            )
            .0,
            b"key=real_secret&other=val"
        );
        assert_eq!(
            replace_bytes_count(b"no match", b"xyz", b"abc").0,
            b"no match"
        );
        assert_eq!(replace_bytes_count(b"", b"x", b"y").0, b"");
    }

    #[test]
    fn test_replace_bytes_count() {
        assert_eq!(
            replace_bytes_count(b"one token two token", b"token", b"secret"),
            (b"one secret two secret".to_vec(), 2)
        );
        assert_eq!(
            replace_bytes_count(b"unchanged", b"missing", b"secret"),
            (b"unchanged".to_vec(), 0)
        );
    }

    #[tokio::test]
    async fn upstream_response_relay_flushes_after_forwarding_chunk() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
        let mut reader = &response[..];
        let mut writer = FlushCountingWriter::default();

        let stats = relay_upstream_response("api.example.test", &mut reader, &mut writer)
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
    async fn guest_request_relay_substitutes_and_flushes_forwarded_chunk() {
        let request =
            b"GET / HTTP/1.1\r\nHost: api.example.test\r\nAuthorization: Bearer lsb_tok_test\r\n\r\n";
        let substitutions = vec![("lsb_tok_test".to_string(), "real-token".to_string())];
        let mut reader = &request[..];
        let mut writer = FlushCountingWriter::default();

        let stats =
            relay_guest_request("api.example.test", &mut reader, &mut writer, &substitutions)
                .await
                .expect("request relay should succeed");

        assert_eq!(
            writer.bytes,
            b"GET / HTTP/1.1\r\nHost: api.example.test\r\nAuthorization: Bearer real-token\r\n\r\n"
        );
        assert_eq!(writer.flushes, 1);
        assert_eq!(
            stats,
            RelayStats {
                bytes: request.len() as u64,
                chunks: 1,
                replacements: 1,
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
