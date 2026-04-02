use std::net::UdpSocket;

use simple_dns::Packet;
use smoltcp::wire::IpEndpoint;
use tokio::sync::mpsc;
use tracing::debug;

use crate::config::ProxyConfig;
use crate::stack::StackCommand;

/// Handle a DNS query from the guest.
///
/// Resolves the query on the host and sends the response back via the stack.
pub async fn handle_dns_query(
    src: IpEndpoint,
    payload: Vec<u8>,
    cmd_tx: mpsc::UnboundedSender<StackCommand>,
    config: &ProxyConfig,
) {
    let response = match resolve_query(&payload, &config).await {
        Ok(resp) => resp,
        Err(e) => {
            debug!("DNS resolution failed: {e}");
            return;
        }
    };

    let _ = cmd_tx.send(StackCommand::DnsResponse {
        dst: src,
        payload: response,
    });
}

async fn resolve_query(query_bytes: &[u8], config: &ProxyConfig) -> anyhow::Result<Vec<u8>> {
    let query = Packet::parse(query_bytes)?;

    let question = query
        .questions
        .first()
        .ok_or_else(|| anyhow::anyhow!("empty DNS query"))?;

    let qname = question.qname.to_string();
    let domain = qname.trim_end_matches('.');

    // The VM network stack is IPv4-only.
    let qtype = question.qtype;
    if qtype == simple_dns::QTYPE::TYPE(simple_dns::TYPE::AAAA) {
        debug!("DNS AAAA empty (IPv4-only): {domain}");
        return build_empty_response(query_bytes);
    }

    if domain == "host.shuru.internal" {
        debug!("DNS host.shuru.internal -> 10.0.0.1");
        return build_a_response(query_bytes, std::net::Ipv4Addr::new(10, 0, 0, 1));
    }

    debug!("DNS query: {domain}");

    if !config.is_domain_allowed(domain) {
        debug!("DNS blocked: {domain}");
        return build_refused_response(query_bytes);
    }

    // Resolve on the host by forwarding to system resolver
    let response_bytes = tokio::task::spawn_blocking({
        let query = query_bytes.to_vec();
        move || forward_to_system_resolver(&query)
    })
    .await??;

    Ok(response_bytes)
}

/// Forward a raw DNS query to the system resolver and return the raw response.
fn forward_to_system_resolver(query: &[u8]) -> anyhow::Result<Vec<u8>> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    sock.send_to(query, "8.8.8.8:53")?;
    let mut buf = [0u8; 4096];
    let n = sock.recv(&mut buf)?;
    Ok(buf[..n].to_vec())
}

fn build_response_with_rcode(query_bytes: &[u8], rcode: u8) -> anyhow::Result<Vec<u8>> {
    let mut response = query_bytes.to_vec();
    if response.len() < 12 {
        return Err(anyhow::anyhow!("query too short"));
    }
    // Set QR=1 (response), keep opcode, set RCODE
    response[2] |= 0x80;
    response[3] = (response[3] & 0xF0) | (rcode & 0x0F);
    Ok(response)
}

fn build_empty_response(query_bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    build_response_with_rcode(query_bytes, 0)
}

fn build_a_response(query_bytes: &[u8], addr: std::net::Ipv4Addr) -> anyhow::Result<Vec<u8>> {
    use simple_dns::{rdata, ResourceRecord, CLASS};

    let query = Packet::parse(query_bytes)?;
    let qname = query
        .questions
        .first()
        .ok_or_else(|| anyhow::anyhow!("empty DNS query"))?
        .qname
        .clone();

    let mut reply = query.into_reply();
    reply.answers.push(ResourceRecord::new(
        qname,
        CLASS::IN,
        60,
        rdata::RData::A(rdata::A::from(addr)),
    ));

    Ok(reply.build_bytes_vec()?)
}

/// Build a REFUSED response for blocked domains.
fn build_refused_response(query_bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    build_response_with_rcode(query_bytes, 5)
}
