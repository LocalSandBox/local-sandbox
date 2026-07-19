use std::collections::HashMap;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use simple_dns::Packet;
use smoltcp::wire::IpEndpoint;
use tokio::sync::mpsc;
use tracing::debug;

use crate::config::{ProxyConfig, GUEST_GATEWAY_IP, HOST_LSB_INTERNAL};
use crate::policy::{is_public_destination, is_wpad_name, normalize_domain};
use crate::stack::StackCommand;

const DNS_CACHE_TTL: Duration = Duration::from_secs(60);

pub(crate) type SharedDnsCache = Arc<Mutex<DnsResolutionCache>>;

#[derive(Debug, Default)]
pub(crate) struct DnsResolutionCache {
    records: HashMap<String, CachedDnsRecord>,
}

#[derive(Debug)]
struct CachedDnsRecord {
    addresses: HashMap<IpAddr, Instant>,
}

impl DnsResolutionCache {
    fn record(&mut self, domain: &str, family: DnsFamily, addresses: &[IpAddr]) {
        self.purge_expired();

        let Some(domain) = normalize_domain(domain) else {
            return;
        };
        let record = self
            .records
            .entry(domain.clone())
            .or_insert_with(|| CachedDnsRecord {
                addresses: HashMap::new(),
            });

        // A and AAAA are independently refreshed. Replace only the queried
        // family so parallel dual-stack lookups cannot erase each other.
        record
            .addresses
            .retain(|address, _| !family.matches(*address));
        let expires_at = Instant::now() + DNS_CACHE_TTL;
        for address in addresses
            .iter()
            .copied()
            .filter(|address| family.matches(*address) && is_public_destination(*address))
        {
            record.addresses.insert(address, expires_at);
        }
        if record.addresses.is_empty() {
            self.records.remove(&domain);
        }
    }

    fn allows_destination(&mut self, domain: &str, addr: IpAddr) -> bool {
        self.purge_expired();
        if !is_public_destination(addr) {
            return false;
        }
        let Some(domain) = normalize_domain(domain) else {
            return false;
        };
        self.records
            .get(&domain)
            .is_some_and(|record| record.addresses.contains_key(&addr))
    }

    fn purge_expired(&mut self) {
        let now = Instant::now();
        self.records.retain(|_, record| {
            record.addresses.retain(|_, expires_at| *expires_at > now);
            !record.addresses.is_empty()
        });
    }
}

pub(crate) fn new_shared_dns_cache() -> SharedDnsCache {
    Arc::new(Mutex::new(DnsResolutionCache::default()))
}

#[cfg(test)]
pub(crate) fn record_allowed_dns_answer(
    cache: &SharedDnsCache,
    domain: &str,
    addresses: &[IpAddr],
) {
    match cache.lock() {
        Ok(mut cache) => {
            for family in [DnsFamily::Ipv4, DnsFamily::Ipv6] {
                if addresses.iter().any(|address| family.matches(*address)) {
                    cache.record(domain, family, addresses);
                }
            }
        }
        Err(_) => debug!("DNS policy cache lock poisoned; answer not recorded"),
    }
}

fn record_allowed_dns_family(
    cache: &SharedDnsCache,
    domain: &str,
    family: DnsFamily,
    addresses: &[IpAddr],
) {
    match cache.lock() {
        Ok(mut cache) => cache.record(domain, family, addresses),
        Err(_) => debug!("DNS policy cache lock poisoned; answer not recorded"),
    }
}

pub(crate) fn destination_matches_dns_answer(
    cache: &SharedDnsCache,
    domain: &str,
    addr: IpAddr,
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
                record_allowed_dns_family(
                    &dns_cache,
                    &answer.domain,
                    answer.family,
                    &answer.addresses,
                );
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
    family: DnsFamily,
    addresses: Vec<IpAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DnsFamily {
    Ipv4,
    Ipv6,
}

impl DnsFamily {
    fn matches(self, address: IpAddr) -> bool {
        matches!(
            (self, address),
            (Self::Ipv4, IpAddr::V4(_)) | (Self::Ipv6, IpAddr::V6(_))
        )
    }
}

async fn resolve_query(query_bytes: &[u8], config: &ProxyConfig) -> anyhow::Result<ResolvedQuery> {
    let (domain, family) = match classify_query(query_bytes, config)? {
        QueryAction::Respond(response) => {
            return Ok(ResolvedQuery {
                response,
                allowed_answer: None,
            })
        }
        QueryAction::Resolve { domain, family } => (domain, family),
    };

    // Resolve on the host so macOS scoped/VPN DNS rules are honored.
    let addresses = match tokio::task::spawn_blocking({
        let domain = domain.clone();
        move || system_ip_lookup(&domain)
    })
    .await?
    {
        Ok(addresses) => addresses,
        Err(e) => {
            debug!("DNS host resolver failed for {domain}: {e}");
            Vec::new()
        }
    };

    let addresses = public_answers(addresses, family);
    Ok(ResolvedQuery {
        response: build_ip_responses(query_bytes, &addresses)?,
        allowed_answer: Some(AllowedDnsAnswer {
            domain,
            family,
            addresses,
        }),
    })
}

#[cfg(test)]
fn resolve_query_with_resolver<F>(
    query_bytes: &[u8],
    config: &ProxyConfig,
    resolver: F,
) -> anyhow::Result<Vec<u8>>
where
    F: FnOnce(&str) -> anyhow::Result<Vec<IpAddr>>,
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
    F: FnOnce(&str) -> anyhow::Result<Vec<IpAddr>>,
{
    let (domain, family) = match classify_query(query_bytes, config)? {
        QueryAction::Respond(response) => {
            return Ok(ResolvedQuery {
                response,
                allowed_answer: None,
            })
        }
        QueryAction::Resolve { domain, family } => (domain, family),
    };

    let addresses = match resolver(&domain) {
        Ok(addresses) => addresses,
        Err(e) => {
            debug!("DNS host resolver failed for {domain}: {e}");
            Vec::new()
        }
    };
    let addresses = public_answers(addresses, family);
    Ok(ResolvedQuery {
        response: build_ip_responses(query_bytes, &addresses)?,
        allowed_answer: Some(AllowedDnsAnswer {
            domain,
            family,
            addresses,
        }),
    })
}

enum QueryAction {
    Respond(Vec<u8>),
    Resolve { domain: String, family: DnsFamily },
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

    if domain == HOST_LSB_INTERNAL {
        if is_a_query {
            debug!("DNS host.lsb.internal -> 10.0.0.1");
            return Ok(QueryAction::Respond(build_a_response(
                query_bytes,
                GUEST_GATEWAY_IP,
            )?));
        }
        return Ok(QueryAction::Respond(build_empty_response(query_bytes)?));
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

    if !is_a_query && !is_aaaa_query {
        debug!("DNS unsupported query type for dual-stack proxy: {domain}");
        return Ok(QueryAction::Respond(build_empty_response(query_bytes)?));
    }

    let domain = normalize_domain(domain)
        .ok_or_else(|| anyhow::anyhow!("DNS query name is not valid IDNA"))?;
    Ok(QueryAction::Resolve {
        domain,
        family: if is_a_query {
            DnsFamily::Ipv4
        } else {
            DnsFamily::Ipv6
        },
    })
}

fn public_answers(addresses: Vec<IpAddr>, family: DnsFamily) -> Vec<IpAddr> {
    addresses
        .into_iter()
        .filter(|address| {
            matches!(
                (family, address),
                (DnsFamily::Ipv4, IpAddr::V4(_)) | (DnsFamily::Ipv6, IpAddr::V6(_))
            ) && is_public_destination(*address)
        })
        .collect()
}

fn system_ip_lookup(domain: &str) -> anyhow::Result<Vec<IpAddr>> {
    let mut addresses = Vec::new();
    for addr in (domain, 0).to_socket_addrs()? {
        let address = addr.ip();
        if !addresses.contains(&address) {
            addresses.push(address);
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
    build_ip_responses(query_bytes, &[IpAddr::V4(addr)])
}

fn build_ip_responses(query_bytes: &[u8], addrs: &[IpAddr]) -> anyhow::Result<Vec<u8>> {
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
        let rdata = match addr {
            IpAddr::V4(address) => rdata::RData::A(rdata::A::from(*address)),
            IpAddr::V6(address) => rdata::RData::AAAA(rdata::AAAA::from(*address)),
        };
        reply
            .answers
            .push(ResourceRecord::new(qname.clone(), CLASS::IN, 60, rdata));
    }

    Ok(reply.build_bytes_vec()?)
}

/// Build a REFUSED response for blocked domains.
fn build_refused_response(query_bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    build_response_with_rcode(query_bytes, 5)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

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

    fn aaaa_addresses(response: &[u8]) -> Vec<Ipv6Addr> {
        let packet = Packet::parse(response).expect("parse DNS response");
        packet
            .answers
            .into_iter()
            .filter_map(|answer| match answer.rdata {
                RData::AAAA(addr) => Some(Ipv6Addr::from(addr.address)),
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
                IpAddr::V4(Ipv4Addr::new(10, 134, 2, 6)),
                IpAddr::V4(Ipv4Addr::new(10, 134, 2, 7)),
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
                Ok(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))])
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
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))
        )
        .expect("DNS cache should be available"));
        assert!(!destination_matches_dns_answer(
            &cache,
            "api.example.test",
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))
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
            Ok(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))])
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
                    IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
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
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))
        )
        .unwrap());
        assert!(!destination_matches_dns_answer(
            &cache,
            &answer.domain,
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        )
        .unwrap());
    }

    #[test]
    fn aaaa_query_retains_only_public_ipv6_answers_and_cache_entries() {
        let query = build_query("example.com", u16::from(TYPE::AAAA));
        let public: Ipv6Addr = "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap();
        let resolved =
            resolve_query_with_resolver_result(&query, &ProxyConfig::default(), |_domain| {
                Ok(vec![
                    IpAddr::V6(public),
                    IpAddr::V6(Ipv6Addr::LOCALHOST),
                    IpAddr::V6("fc00::1".parse().unwrap()),
                    IpAddr::V6("fe80::1".parse().unwrap()),
                    IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                ])
            })
            .expect("resolve query");

        assert_eq!(aaaa_addresses(&resolved.response), vec![public]);
        assert!(a_addresses(&resolved.response).is_empty());
        let answer = resolved.allowed_answer.unwrap();
        let cache = new_shared_dns_cache();
        record_allowed_dns_answer(&cache, &answer.domain, &answer.addresses);
        assert!(
            destination_matches_dns_answer(&cache, &answer.domain, IpAddr::V6(public)).unwrap()
        );
        assert!(!destination_matches_dns_answer(
            &cache,
            &answer.domain,
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        )
        .unwrap());
    }

    #[test]
    fn dual_stack_cache_refreshes_each_address_family_independently() {
        let cache = new_shared_dns_cache();
        let ipv4 = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let ipv6 = IpAddr::V6("2606:2800:220:1:248:1893:25c8:1946".parse().unwrap());

        record_allowed_dns_family(&cache, "example.com", DnsFamily::Ipv4, &[ipv4]);
        record_allowed_dns_family(&cache, "example.com", DnsFamily::Ipv6, &[ipv6]);
        assert!(destination_matches_dns_answer(&cache, "example.com", ipv4).unwrap());
        assert!(destination_matches_dns_answer(&cache, "example.com", ipv6).unwrap());

        record_allowed_dns_family(&cache, "example.com", DnsFamily::Ipv6, &[]);
        assert!(destination_matches_dns_answer(&cache, "example.com", ipv4).unwrap());
        assert!(!destination_matches_dns_answer(&cache, "example.com", ipv6).unwrap());

        record_allowed_dns_family(&cache, "example.com", DnsFamily::Ipv4, &[]);
        assert!(!destination_matches_dns_answer(&cache, "example.com", ipv4).unwrap());
    }
}
