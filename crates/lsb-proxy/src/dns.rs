use std::net::{Ipv4Addr, ToSocketAddrs};

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
    let domain = match classify_query(query_bytes, config)? {
        QueryAction::Respond(response) => return Ok(response),
        QueryAction::ResolveA(domain) => domain,
    };

    // Resolve on the host so macOS scoped/VPN DNS rules are honored.
    let addresses = match tokio::task::spawn_blocking({
        let domain = domain.clone();
        move || system_ipv4_lookup(&domain)
    })
    .await?
    {
        Ok(addresses) => addresses,
        Err(e) => {
            debug!("DNS host resolver failed for {domain}: {e}");
            Vec::new()
        }
    };

    build_a_responses(query_bytes, &addresses)
}

#[cfg(test)]
fn resolve_query_with_resolver<F>(
    query_bytes: &[u8],
    config: &ProxyConfig,
    resolver: F,
) -> anyhow::Result<Vec<u8>>
where
    F: FnOnce(&str) -> anyhow::Result<Vec<Ipv4Addr>>,
{
    let domain = match classify_query(query_bytes, config)? {
        QueryAction::Respond(response) => return Ok(response),
        QueryAction::ResolveA(domain) => domain,
    };

    let addresses = match resolver(&domain) {
        Ok(addresses) => addresses,
        Err(e) => {
            debug!("DNS host resolver failed for {domain}: {e}");
            Vec::new()
        }
    };
    build_a_responses(query_bytes, &addresses)
}

enum QueryAction {
    Respond(Vec<u8>),
    ResolveA(String),
}

fn classify_query(query_bytes: &[u8], config: &ProxyConfig) -> anyhow::Result<QueryAction> {
    let query = Packet::parse(query_bytes)?;

    let question = query
        .questions
        .first()
        .ok_or_else(|| anyhow::anyhow!("empty DNS query"))?;

    let qname = question.qname.to_string();
    let domain = qname.trim_end_matches('.');

    let qtype = question.qtype;
    if qtype == simple_dns::QTYPE::TYPE(simple_dns::TYPE::AAAA) {
        debug!("DNS AAAA empty (IPv4-only): {domain}");
        return Ok(QueryAction::Respond(build_empty_response(query_bytes)?));
    }

    if domain == "host.lsb.internal" {
        debug!("DNS host.lsb.internal -> 10.0.0.1");
        return Ok(QueryAction::Respond(build_a_response(
            query_bytes,
            Ipv4Addr::new(10, 0, 0, 1),
        )?));
    }

    debug!("DNS query: {domain}");

    if !config.is_domain_allowed(domain) {
        debug!("DNS blocked: {domain}");
        return Ok(QueryAction::Respond(build_refused_response(query_bytes)?));
    }

    if qtype != simple_dns::QTYPE::TYPE(simple_dns::TYPE::A) {
        debug!("DNS unsupported query type for IPv4 proxy: {domain}");
        return Ok(QueryAction::Respond(build_empty_response(query_bytes)?));
    }

    Ok(QueryAction::ResolveA(domain.to_string()))
}

fn system_ipv4_lookup(domain: &str) -> anyhow::Result<Vec<Ipv4Addr>> {
    let mut addresses = Vec::new();
    for addr in (domain, 0).to_socket_addrs()? {
        if let std::net::IpAddr::V4(ipv4) = addr.ip() {
            if !addresses.contains(&ipv4) {
                addresses.push(ipv4);
            }
        }
    }
    Ok(addresses)
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
    build_a_responses(query_bytes, &[addr])
}

fn build_a_responses(query_bytes: &[u8], addrs: &[std::net::Ipv4Addr]) -> anyhow::Result<Vec<u8>> {
    use simple_dns::{rdata, ResourceRecord, CLASS};

    let query = Packet::parse(query_bytes)?;
    let qname = query
        .questions
        .first()
        .ok_or_else(|| anyhow::anyhow!("empty DNS query"))?
        .qname
        .clone();

    let mut reply = query.into_reply();
    for addr in addrs {
        reply.answers.push(ResourceRecord::new(
            qname.clone(),
            CLASS::IN,
            60,
            rdata::RData::A(rdata::A::from(*addr)),
        ));
    }

    Ok(reply.build_bytes_vec()?)
}

/// Build a REFUSED response for blocked domains.
fn build_refused_response(query_bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    build_response_with_rcode(query_bytes, 5)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use simple_dns::{rdata::RData, Packet, RCODE, TYPE};

    use super::*;

    fn build_query(domain: &str, qtype: u16) -> Vec<u8> {
        let mut bytes = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // standard recursive query
            0x00, 0x01, // one question
            0x00, 0x00, // answers
            0x00, 0x00, // authorities
            0x00, 0x00, // additional
        ];

        for label in domain.split('.') {
            bytes.push(label.len() as u8);
            bytes.extend_from_slice(label.as_bytes());
        }
        bytes.push(0);
        bytes.extend_from_slice(&qtype.to_be_bytes());
        bytes.extend_from_slice(&1u16.to_be_bytes()); // IN
        bytes
    }

    fn a_addresses(response: &[u8]) -> Vec<Ipv4Addr> {
        let packet = Packet::parse(response).expect("parse DNS response");
        packet
            .answers
            .into_iter()
            .filter_map(|answer| match answer.rdata {
                RData::A(addr) => Some(Ipv4Addr::from(addr.address)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn resolves_a_query_with_host_resolver_addresses() {
        let query = build_query("internal.example.test", 1);
        let response = resolve_query_with_resolver(&query, &ProxyConfig::default(), |domain| {
            assert_eq!(domain, "internal.example.test");
            Ok(vec![
                Ipv4Addr::new(10, 134, 2, 6),
                Ipv4Addr::new(10, 134, 2, 7),
            ])
        })
        .expect("resolve query");

        let packet = Packet::parse(&response).expect("parse DNS response");
        assert_eq!(packet.rcode(), RCODE::NoError);
        assert_eq!(
            a_addresses(&response),
            vec![Ipv4Addr::new(10, 134, 2, 6), Ipv4Addr::new(10, 134, 2, 7)]
        );
    }

    #[test]
    fn returns_empty_noerror_when_host_resolver_has_no_ipv4_addresses() {
        let query = build_query("ipv6-only.example.test", 1);
        let response =
            resolve_query_with_resolver(&query, &ProxyConfig::default(), |_domain| Ok(vec![]))
                .expect("resolve query");

        let packet = Packet::parse(&response).expect("parse DNS response");
        assert_eq!(packet.rcode(), RCODE::NoError);
        assert!(packet.answers.is_empty());
    }

    #[test]
    fn returns_empty_noerror_when_host_resolver_errors() {
        let query = build_query("missing.example.test", 1);
        let response = resolve_query_with_resolver(&query, &ProxyConfig::default(), |_domain| {
            Err(anyhow::anyhow!("host resolver failed"))
        })
        .expect("resolve query");

        let packet = Packet::parse(&response).expect("parse DNS response");
        assert_eq!(packet.rcode(), RCODE::NoError);
        assert!(packet.answers.is_empty());
    }

    #[test]
    fn keeps_host_internal_special_case_inside_proxy() {
        let query = build_query("host.lsb.internal", 1);
        let response = resolve_query_with_resolver(&query, &ProxyConfig::default(), |_domain| {
            panic!("host.lsb.internal should not use host resolver");
        })
        .expect("resolve query");

        assert_eq!(a_addresses(&response), vec![Ipv4Addr::new(10, 0, 0, 1)]);
    }

    #[test]
    fn refuses_blocked_domains_without_calling_host_resolver() {
        let query = build_query("blocked.example.test", 1);
        let config = ProxyConfig {
            network: crate::config::NetworkConfig {
                allow: vec!["allowed.example.test".into()],
            },
            ..Default::default()
        };
        let response = resolve_query_with_resolver(&query, &config, |_domain| {
            panic!("blocked domains should not use host resolver");
        })
        .expect("resolve query");

        let packet = Packet::parse(&response).expect("parse DNS response");
        assert_eq!(packet.rcode(), RCODE::Refused);
        assert!(packet.answers.is_empty());
    }

    #[test]
    fn returns_empty_noerror_for_aaaa_queries() {
        let query = build_query("example.com", u16::from(TYPE::AAAA));
        let response = resolve_query_with_resolver(&query, &ProxyConfig::default(), |_domain| {
            panic!("IPv6 is intentionally not resolved by the IPv4-only proxy");
        })
        .expect("resolve query");

        let packet = Packet::parse(&response).expect("parse DNS response");
        assert_eq!(packet.rcode(), RCODE::NoError);
        assert!(packet.answers.is_empty());
    }
}
