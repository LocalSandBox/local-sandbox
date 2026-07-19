use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use simple_dns::Packet;
use smoltcp::wire::IpEndpoint;
use tokio::sync::mpsc;
use tracing::debug;

use crate::config::{ProxyConfig, GUEST_GATEWAY_IP, HOST_LSB_INTERNAL};
use crate::policy::{is_public_ipv4, is_wpad_name, normalize_domain};
use crate::stack::StackCommand;

const DNS_CACHE_TTL: Duration = Duration::from_secs(60);

pub(crate) type SharedDnsCache = Arc<Mutex<DnsResolutionCache>>;

#[derive(Debug, Default)]
pub(crate) struct DnsResolutionCache {
    records: HashMap<String, CachedDnsRecord>,
}

#[derive(Debug)]
struct CachedDnsRecord {
    addresses: HashSet<Ipv4Addr>,
    expires_at: Instant,
}

impl DnsResolutionCache {
    fn record(&mut self, domain: &str, addresses: &[Ipv4Addr]) {
        self.purge_expired();

        let Some(domain) = normalize_domain(domain) else {
            return;
        };
        let addresses = addresses
            .iter()
            .copied()
            .filter(|address| is_public_ipv4(*address))
            .collect::<HashSet<_>>();
        if addresses.is_empty() {
            self.records.remove(&domain);
            return;
        }

        self.records.insert(
            domain,
            CachedDnsRecord {
                addresses,
                expires_at: Instant::now() + DNS_CACHE_TTL,
            },
        );
    }

    fn allows_destination(&mut self, domain: &str, addr: Ipv4Addr) -> bool {
        self.purge_expired();
        if !is_public_ipv4(addr) {
            return false;
        }
        let Some(domain) = normalize_domain(domain) else {
            return false;
        };
        self.records
            .get(&domain)
            .is_some_and(|record| record.addresses.contains(&addr))
    }

    fn purge_expired(&mut self) {
        let now = Instant::now();
        self.records.retain(|_, record| record.expires_at > now);
    }
}

pub(crate) fn new_shared_dns_cache() -> SharedDnsCache {
    Arc::new(Mutex::new(DnsResolutionCache::default()))
}

pub(crate) fn record_allowed_dns_answer(
    cache: &SharedDnsCache,
    domain: &str,
    addresses: &[Ipv4Addr],
) {
    match cache.lock() {
        Ok(mut cache) => cache.record(domain, addresses),
        Err(_) => debug!("DNS policy cache lock poisoned; answer not recorded"),
    }
}

pub(crate) fn destination_matches_dns_answer(
    cache: &SharedDnsCache,
    domain: &str,
    addr: Ipv4Addr,
) -> anyhow::Result<bool> {
    let mut cache = cache
        .lock()
        .map_err(|_| anyhow::anyhow!("DNS policy cache unavailable"))?;
    Ok(cache.allows_destination(domain, addr))
}

/// Handle a DNS query from the guest.
///
/// Resolves the query on the host and sends the response back via the stack.
pub async fn handle_dns_query(
    src: IpEndpoint,
    payload: Vec<u8>,
    cmd_tx: mpsc::UnboundedSender<StackCommand>,
    config: &ProxyConfig,
    dns_cache: SharedDnsCache,
) {
    let response = match resolve_query(&payload, config).await {
        Ok(resolved) => {
            if let Some(answer) = &resolved.allowed_answer {
                record_allowed_dns_answer(&dns_cache, &answer.domain, &answer.addresses);
            }
            resolved.response
        }
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

struct ResolvedQuery {
    response: Vec<u8>,
    allowed_answer: Option<AllowedDnsAnswer>,
}

struct AllowedDnsAnswer {
    domain: String,
    addresses: Vec<Ipv4Addr>,
}

async fn resolve_query(query_bytes: &[u8], config: &ProxyConfig) -> anyhow::Result<ResolvedQuery> {
    let domain = match classify_query(query_bytes, config)? {
        QueryAction::Respond(response) => {
            return Ok(ResolvedQuery {
                response,
                allowed_answer: None,
            })
        }
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

    let addresses = public_answers(addresses);
    Ok(ResolvedQuery {
        response: build_a_responses(query_bytes, &addresses)?,
        allowed_answer: Some(AllowedDnsAnswer { domain, addresses }),
    })
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
    Ok(resolve_query_with_resolver_result(query_bytes, config, resolver)?.response)
}

#[cfg(test)]
fn resolve_query_with_resolver_result<F>(
    query_bytes: &[u8],
    config: &ProxyConfig,
    resolver: F,
) -> anyhow::Result<ResolvedQuery>
where
    F: FnOnce(&str) -> anyhow::Result<Vec<Ipv4Addr>>,
{
    let domain = match classify_query(query_bytes, config)? {
        QueryAction::Respond(response) => {
            return Ok(ResolvedQuery {
                response,
                allowed_answer: None,
            })
        }
        QueryAction::ResolveA(domain) => domain,
    };

    let addresses = match resolver(&domain) {
        Ok(addresses) => addresses,
        Err(e) => {
            debug!("DNS host resolver failed for {domain}: {e}");
            Vec::new()
        }
    };
    let addresses = public_answers(addresses);
    Ok(ResolvedQuery {
        response: build_a_responses(query_bytes, &addresses)?,
        allowed_answer: Some(AllowedDnsAnswer { domain, addresses }),
    })
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
    let is_a_query = qtype == simple_dns::QTYPE::TYPE(simple_dns::TYPE::A);
    let is_aaaa_query = qtype == simple_dns::QTYPE::TYPE(simple_dns::TYPE::AAAA);

    if config.is_mount_only_smb() {
        if domain == HOST_LSB_INTERNAL {
            if is_a_query {
                debug!("DNS host.lsb.internal -> 10.0.0.1");
                return Ok(QueryAction::Respond(build_a_response(
                    query_bytes,
                    GUEST_GATEWAY_IP,
                )?));
            }

            debug!("DNS host.lsb.internal empty non-A response");
            return Ok(QueryAction::Respond(build_empty_response(query_bytes)?));
        }

        debug!("DNS blocked by mount-only SMB mode: {domain}");
        return Ok(QueryAction::Respond(build_refused_response(query_bytes)?));
    }

    if is_aaaa_query {
        debug!("DNS AAAA empty (IPv4-only): {domain}");
        return Ok(QueryAction::Respond(build_empty_response(query_bytes)?));
    }

    if domain == HOST_LSB_INTERNAL {
        debug!("DNS host.lsb.internal -> 10.0.0.1");
        return Ok(QueryAction::Respond(build_a_response(
            query_bytes,
            GUEST_GATEWAY_IP,
        )?));
    }

    debug!("DNS query: {domain}");

    if is_wpad_name(domain) {
        debug!("DNS blocked WPAD name: {domain}");
        return Ok(QueryAction::Respond(build_refused_response(query_bytes)?));
    }

    if !config.is_domain_allowed(domain) {
        debug!("DNS blocked: {domain}");
        return Ok(QueryAction::Respond(build_refused_response(query_bytes)?));
    }

    if !is_a_query {
        debug!("DNS unsupported query type for IPv4 proxy: {domain}");
        return Ok(QueryAction::Respond(build_empty_response(query_bytes)?));
    }

    let domain = normalize_domain(domain)
        .ok_or_else(|| anyhow::anyhow!("DNS query name is not valid IDNA"))?;
    Ok(QueryAction::ResolveA(domain))
}

fn public_answers(addresses: Vec<Ipv4Addr>) -> Vec<Ipv4Addr> {
    addresses
        .into_iter()
        .filter(|address| is_public_ipv4(*address))
        .collect()
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
    fn removes_non_public_host_resolver_addresses() {
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
        assert!(a_addresses(&response).is_empty());
    }

    #[test]
    fn records_allowed_answers_for_destination_policy() {
        let query = build_query("Api.Example.Test", 1);
        let resolved =
            resolve_query_with_resolver_result(&query, &ProxyConfig::default(), |domain| {
                assert_eq!(domain, "api.example.test");
                Ok(vec![Ipv4Addr::new(93, 184, 216, 34)])
            })
            .expect("resolve query");
        let answer = resolved
            .allowed_answer
            .expect("allowed A answer should be policy-visible");
        let cache = new_shared_dns_cache();

        record_allowed_dns_answer(&cache, &answer.domain, &answer.addresses);

        assert!(destination_matches_dns_answer(
            &cache,
            "api.example.test",
            Ipv4Addr::new(93, 184, 216, 34)
        )
        .expect("DNS cache should be available"));
        assert!(!destination_matches_dns_answer(
            &cache,
            "api.example.test",
            Ipv4Addr::new(1, 1, 1, 1)
        )
        .expect("DNS cache should be available"));
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
    fn mount_only_smb_keeps_host_internal_but_refuses_other_dns() {
        let config = ProxyConfig::mount_only_smb();
        let host_query = build_query("host.lsb.internal", 1);
        let host_response = resolve_query_with_resolver(&host_query, &config, |_domain| {
            panic!("host.lsb.internal should not use host resolver");
        })
        .expect("resolve host alias");

        assert_eq!(
            a_addresses(&host_response),
            vec![crate::config::GUEST_GATEWAY_IP]
        );

        let blocked_query = build_query("api.example.test", 1);
        let blocked_response = resolve_query_with_resolver(&blocked_query, &config, |_domain| {
            panic!("mount-only SMB mode should not forward arbitrary DNS");
        })
        .expect("resolve blocked query");
        let packet = Packet::parse(&blocked_response).expect("parse DNS response");

        assert_eq!(packet.rcode(), RCODE::Refused);
        assert!(packet.answers.is_empty());
    }

    #[test]
    fn combined_smb_mode_preserves_dns_network_policy() {
        let query = build_query("api.example.test", 1);
        let config = ProxyConfig {
            network: crate::config::NetworkConfig {
                allow: vec!["api.example.test".into()],
            },
            ..Default::default()
        }
        .with_smb_mount_relay();

        let response = resolve_query_with_resolver(&query, &config, |domain| {
            assert_eq!(domain, "api.example.test");
            Ok(vec![Ipv4Addr::new(93, 184, 216, 34)])
        })
        .expect("resolve allowed query");

        assert_eq!(
            a_addresses(&response),
            vec![Ipv4Addr::new(93, 184, 216, 34)]
        );
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
    fn refuses_wpad_even_when_default_public_networking_is_enabled() {
        for name in ["wpad", "WPAD.corp.example"] {
            let query = build_query(name, 1);
            let response =
                resolve_query_with_resolver(&query, &ProxyConfig::default(), |_domain| {
                    panic!("WPAD must never use the host resolver")
                })
                .expect("build refused response");
            assert_eq!(Packet::parse(&response).unwrap().rcode(), RCODE::Refused);
        }
    }

    #[test]
    fn mixed_dns_answer_retains_only_public_addresses_in_response_and_cache() {
        let query = build_query("api.example.test", 1);
        let resolved =
            resolve_query_with_resolver_result(&query, &ProxyConfig::default(), |_domain| {
                Ok(vec![
                    Ipv4Addr::new(93, 184, 216, 34),
                    Ipv4Addr::new(127, 0, 0, 1),
                    Ipv4Addr::new(169, 254, 169, 254),
                ])
            })
            .unwrap();
        assert_eq!(
            a_addresses(&resolved.response),
            vec![Ipv4Addr::new(93, 184, 216, 34)]
        );
        let answer = resolved.allowed_answer.unwrap();
        let cache = new_shared_dns_cache();
        record_allowed_dns_answer(&cache, &answer.domain, &answer.addresses);
        assert!(destination_matches_dns_answer(
            &cache,
            &answer.domain,
            Ipv4Addr::new(93, 184, 216, 34)
        )
        .unwrap());
        assert!(
            !destination_matches_dns_answer(&cache, &answer.domain, Ipv4Addr::LOCALHOST).unwrap()
        );
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
