use std::collections::BTreeSet;
use std::net::IpAddr;

use anyhow::{bail, Result};

#[derive(Debug, Clone)]
pub struct EgressPolicy {
    allowed_hosts: BTreeSet<String>,
}

impl EgressPolicy {
    pub fn new(allowed_hosts: impl IntoIterator<Item = String>) -> Result<Self> {
        let mut normalized = BTreeSet::new();
        for host in allowed_hosts {
            let host = host.trim().trim_end_matches('.').to_lowercase();
            if host.is_empty() || !host.contains('.') || host == "wpad" {
                bail!("egress host must be a nonempty qualified DNS name");
            }
            normalized.insert(host);
        }
        Ok(Self {
            allowed_hosts: normalized,
        })
    }

    pub fn authorize_resolution(&self, host: &str, addresses: &[IpAddr]) -> Result<()> {
        let host = host.trim().trim_end_matches('.').to_lowercase();
        if !self.allowed_hosts.contains(&host) || addresses.is_empty() {
            bail!("egress destination is not allowed");
        }
        if addresses.iter().any(denied_address) {
            bail!("egress resolution includes a local or non-routable address");
        }
        Ok(())
    }
}

fn denied_address(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(value) => {
            value.is_loopback()
                || value.is_private()
                || value.is_link_local()
                || value.is_multicast()
                || value.is_unspecified()
                || value.octets()[0] == 0
        }
        IpAddr::V6(value) => {
            value.is_loopback()
                || value.is_multicast()
                || value.is_unspecified()
                || (value.segments()[0] & 0xfe00) == 0xfc00
                || (value.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rebinding_to_private_or_loopback_fails_closed() {
        let policy = EgressPolicy::new(["example.com".to_string()]).unwrap();
        assert!(policy
            .authorize_resolution("example.com", &["127.0.0.1".parse().unwrap()])
            .is_err());
        assert!(policy
            .authorize_resolution("example.com", &["8.8.8.8".parse().unwrap()])
            .is_ok());
    }
}
