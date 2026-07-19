use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub(crate) fn normalize_domain(domain: &str) -> Option<String> {
    let domain = domain.trim().trim_end_matches('.');
    if domain.is_empty() || domain.contains('*') {
        return None;
    }
    let ascii = idna::domain_to_ascii(domain).ok()?.to_ascii_lowercase();
    if ascii.is_empty()
        || ascii.len() > 253
        || ascii.split('.').any(|label| {
            label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-')
        })
    {
        return None;
    }
    Some(ascii)
}

pub(crate) fn domain_matches(pattern: &str, domain: &str) -> bool {
    let Some(domain) = normalize_domain(domain) else {
        return false;
    };
    if let Some(suffix) = pattern.trim().strip_prefix("*.") {
        let Some(suffix) = normalize_domain(suffix) else {
            return false;
        };
        domain.len() > suffix.len()
            && domain.ends_with(&suffix)
            && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.'
    } else {
        normalize_domain(pattern).is_some_and(|pattern| pattern == domain)
    }
}

pub(crate) fn is_wpad_name(domain: &str) -> bool {
    normalize_domain(domain).is_some_and(|domain| domain == "wpad" || domain.starts_with("wpad."))
}

pub(crate) fn is_public_destination(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_ipv4(address),
        IpAddr::V6(address) => is_public_ipv6(address),
    }
}

pub(crate) fn is_public_ipv4(address: Ipv4Addr) -> bool {
    let [a, b, c, d] = address.octets();
    if [a, b, c, d] == [192, 0, 0, 9] || [a, b, c, d] == [192, 0, 0, 10] {
        return true;
    }
    !matches!(
        (a, b, c),
        (0, _, _)
            | (10, _, _)
            | (100, 64..=127, _)
            | (127, _, _)
            | (169, 254, _)
            | (172, 16..=31, _)
            | (192, 0, 0)
            | (192, 0, 2)
            | (192, 88, 99)
            | (192, 168, _)
            | (198, 18..=19, _)
            | (198, 51, 100)
            | (203, 0, 113)
            | (224..=255, _, _)
    )
}

pub(crate) fn is_public_ipv6(address: Ipv6Addr) -> bool {
    if address.to_ipv4_mapped().is_some() {
        return false;
    }

    // The well-known NAT64 prefix is globally reachable, but the embedded
    // IPv4 destination must independently satisfy the public-address policy.
    if in_ipv6_prefix(address, Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0), 96) {
        return is_public_ipv4(Ipv4Addr::from(u128::from(address) as u32));
    }

    if !in_ipv6_prefix(address, Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0), 3) {
        return false;
    }

    // IANA marks 2001::/23 non-global except for these more-specific entries.
    if in_ipv6_prefix(address, Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0), 23) {
        let globally_reachable_exception = address == Ipv6Addr::new(0x2001, 1, 0, 0, 0, 0, 0, 1)
            || address == Ipv6Addr::new(0x2001, 1, 0, 0, 0, 0, 0, 2)
            || address == Ipv6Addr::new(0x2001, 1, 0, 0, 0, 0, 0, 3)
            || in_ipv6_prefix(address, Ipv6Addr::new(0x2001, 3, 0, 0, 0, 0, 0, 0), 32)
            || in_ipv6_prefix(address, Ipv6Addr::new(0x2001, 4, 0x112, 0, 0, 0, 0, 0), 48)
            || in_ipv6_prefix(address, Ipv6Addr::new(0x2001, 0x20, 0, 0, 0, 0, 0, 0), 28)
            || in_ipv6_prefix(address, Ipv6Addr::new(0x2001, 0x30, 0, 0, 0, 0, 0, 0), 28);
        return globally_reachable_exception;
    }

    !in_ipv6_prefix(address, Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32)
        && !in_ipv6_prefix(address, Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0), 16)
        && !in_ipv6_prefix(address, Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0), 20)
}

fn in_ipv6_prefix(address: Ipv6Addr, prefix: Ipv6Addr, prefix_length: u32) -> bool {
    let mask = u128::MAX << (128 - prefix_length);
    u128::from(address) & mask == u128::from(prefix) & mask
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_patterns_are_idna_normalized_and_wildcards_exclude_apex() {
        assert!(domain_matches("xn--bcher-kva.example", "BÜCHER.example."));
        assert!(domain_matches("*.Example.COM", "deep.API.example.com."));
        assert!(!domain_matches("*.example.com", "example.com"));
        assert!(!domain_matches("*.example.com", "notexample.com"));
        assert!(!domain_matches(
            "bad*pattern.example",
            "badxpattern.example"
        ));
    }

    #[test]
    fn wpad_is_denied_at_every_search_suffix_depth() {
        assert!(is_wpad_name("wpad"));
        assert!(is_wpad_name("WPAD.corp.example."));
        assert!(!is_wpad_name("notwpad.example"));
    }

    #[test]
    fn only_globally_routable_addresses_are_public() {
        for denied in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.0.0.1",
            "192.0.2.1",
            "192.168.0.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            assert!(!is_public_destination(denied.parse().unwrap()), "{denied}");
        }
        for allowed in ["1.1.1.1", "8.8.8.8", "93.184.216.34"] {
            assert!(is_public_destination(allowed.parse().unwrap()), "{allowed}");
        }
        for allowed in ["192.0.0.9", "192.0.0.10"] {
            assert!(is_public_destination(allowed.parse().unwrap()), "{allowed}");
        }
        for denied in [
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "::ffff:1.1.1.1",
            "64:ff9b::a00:1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "2001:2::1",
            "2001:db8::1",
            "2002::1",
            "3fff::1",
        ] {
            assert!(!is_public_destination(denied.parse().unwrap()), "{denied}");
        }
        for allowed in [
            "64:ff9b::101:101",
            "2001:1::1",
            "2001:3::1",
            "2001:20::1",
            "2606:4700:4700::1111",
        ] {
            assert!(is_public_destination(allowed.parse().unwrap()), "{allowed}");
        }
    }
}
