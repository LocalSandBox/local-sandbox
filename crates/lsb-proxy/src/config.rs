use std::collections::HashMap;
use std::fmt;
use std::net::Ipv4Addr;

pub const GUEST_GATEWAY_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
pub const HOST_LSB_INTERNAL: &str = "host.lsb.internal";
pub const SMB_MOUNT_PORT: u16 = 445;

/// A host port exposed to the guest via host.lsb.internal.
#[derive(Debug, Clone)]
pub struct ExposeHostMapping {
    pub host_port: u16,
    pub guest_port: u16,
}

/// Top-level proxy traffic policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProxyMode {
    /// Preserve existing network proxy behavior.
    #[default]
    NetworkPolicy,
    /// Permit only SMB mount traffic to the host gateway.
    MountOnlySmb,
    /// Preserve network proxy behavior and add SMB mount gateway relay.
    NetworkPolicyWithSmbMount,
}

impl ProxyMode {
    fn permits_network_policy(self) -> bool {
        matches!(
            self,
            ProxyMode::NetworkPolicy | ProxyMode::NetworkPolicyWithSmbMount
        )
    }

    fn permits_smb_mount_relay(self) -> bool {
        matches!(
            self,
            ProxyMode::MountOnlySmb | ProxyMode::NetworkPolicyWithSmbMount
        )
    }
}

/// Configuration for the proxy engine.
#[derive(Debug, Clone, Default)]
pub struct ProxyConfig {
    /// Traffic mode for the proxy.
    pub mode: ProxyMode,
    /// Secrets to inject. Key is the env var name visible to the guest.
    /// The guest gets a random placeholder token; the proxy substitutes
    /// the real value only when the request targets an allowed host.
    pub secrets: HashMap<String, SecretConfig>,
    /// Network access rules.
    pub network: NetworkConfig,
    /// Host ports exposed to the guest via host.lsb.internal.
    pub expose_host: Vec<ExposeHostMapping>,
}

/// A secret that the proxy injects into HTTP requests.
#[derive(Clone)]
pub struct SecretConfig {
    /// Literal secret value held on the host.
    pub value: String,
    /// Domain patterns where this secret may be sent (e.g., "api.openai.com").
    /// The proxy only substitutes the placeholder on requests to these hosts.
    pub hosts: Vec<String>,
}

impl fmt::Debug for SecretConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretConfig")
            .field("value", &"<redacted>")
            .field("hosts", &self.hosts)
            .finish()
    }
}

/// Network access policy.
#[derive(Debug, Clone, Default)]
pub struct NetworkConfig {
    /// Allowed domain patterns. Empty = allow all.
    /// Supports wildcards: "*.openai.com", "registry.npmjs.org".
    pub allow: Vec<String>,
}

impl ProxyConfig {
    /// Build a proxy config that only permits Windows SMB mount relay traffic.
    pub fn mount_only_smb() -> Self {
        Self {
            mode: ProxyMode::MountOnlySmb,
            ..Default::default()
        }
    }

    /// Enable SMB mount relay while preserving normal network proxy behavior.
    pub fn with_smb_mount_relay(mut self) -> Self {
        if self.mode == ProxyMode::NetworkPolicy {
            self.mode = ProxyMode::NetworkPolicyWithSmbMount;
        }
        self
    }

    pub fn is_mount_only_smb(&self) -> bool {
        self.mode == ProxyMode::MountOnlySmb
    }

    pub fn permits_network_policy(&self) -> bool {
        self.mode.permits_network_policy()
    }

    pub fn permits_smb_mount_relay(&self, dst_ip: Ipv4Addr, dst_port: u16) -> bool {
        self.mode.permits_smb_mount_relay()
            && dst_ip == GUEST_GATEWAY_IP
            && dst_port == SMB_MOUNT_PORT
    }

    /// Check if a domain is allowed by the network policy.
    /// Empty allowlist means all domains are allowed.
    pub fn is_domain_allowed(&self, domain: &str) -> bool {
        if !self.permits_network_policy() {
            return false;
        }
        if self.network.allow.is_empty() {
            return true;
        }
        self.network
            .allow
            .iter()
            .any(|pattern| domain_matches(pattern, domain))
    }

    /// Whether this proxy config has an explicit allowlist. Empty allowlists
    /// preserve existing allow-all `--allow-net` behavior.
    pub fn has_domain_allowlist(&self) -> bool {
        self.permits_network_policy() && !self.network.allow.is_empty()
    }

    /// Look up whether a connection to the gateway IP on `guest_port` should
    /// be forwarded to a host port.
    pub fn exposed_host_port(&self, dst_ip: Ipv4Addr, guest_port: u16) -> Option<u16> {
        if !self.permits_network_policy() || dst_ip != GUEST_GATEWAY_IP {
            return None;
        }
        self.expose_host
            .iter()
            .find(|mapping| mapping.guest_port == guest_port)
            .map(|mapping| mapping.host_port)
    }

    /// Get all secret placeholder→real value mappings for a given domain.
    pub fn secrets_for_domain(
        &self,
        domain: &str,
        placeholders: &HashMap<String, String>,
    ) -> Vec<(String, String)> {
        if !self.permits_network_policy() {
            return Vec::new();
        }

        let mut result = Vec::new();
        for (name, secret) in &self.secrets {
            if secret
                .hosts
                .iter()
                .any(|pattern| domain_matches(pattern, domain))
            {
                if let Some(placeholder) = placeholders.get(name) {
                    result.push((placeholder.clone(), secret.value.clone()));
                }
            }
        }
        result
    }
}

/// Simple wildcard domain matching.
/// "*.example.com" matches "api.example.com" but not "example.com".
/// "example.com" matches exactly "example.com".
fn domain_matches(pattern: &str, domain: &str) -> bool {
    let pattern = pattern.trim_end_matches('.');
    let domain = domain.trim_end_matches('.');
    if let Some(suffix) = pattern.strip_prefix("*.") {
        domain.len() > suffix.len()
            && domain[domain.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
            && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.'
    } else {
        pattern.eq_ignore_ascii_case(domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_matching() {
        assert!(domain_matches("example.com", "example.com"));
        assert!(domain_matches("Example.COM", "example.com."));
        assert!(domain_matches("*.Example.COM", "api.EXAMPLE.com."));
        assert!(!domain_matches("example.com", "api.example.com"));
        assert!(domain_matches("*.example.com", "api.example.com"));
        assert!(domain_matches("*.example.com", "deep.api.example.com"));
        assert!(!domain_matches("*.example.com", "example.com"));
        assert!(!domain_matches("*.example.com", "notexample.com"));
    }

    #[test]
    fn test_secrets_for_domain_uses_literal_values() {
        let mut config = ProxyConfig::default();
        config.secrets.insert(
            "API_KEY".into(),
            SecretConfig {
                value: "sk-test".into(),
                hosts: vec!["api.openai.com".into()],
            },
        );

        let placeholders = HashMap::from([("API_KEY".into(), "lsb_tok_123".into())]);

        assert_eq!(
            config.secrets_for_domain("api.openai.com", &placeholders),
            vec![("lsb_tok_123".into(), "sk-test".into())]
        );
        assert!(config
            .secrets_for_domain("api.anthropic.com", &placeholders)
            .is_empty());
    }

    #[test]
    fn secret_debug_redacts_literal_value() {
        let mut config = ProxyConfig::default();
        config.secrets.insert(
            "API_KEY".into(),
            SecretConfig {
                value: "sk-test-never-log".into(),
                hosts: vec!["api.openai.com".into()],
            },
        );

        let rendered = format!("{config:?}");

        assert!(!rendered.contains("sk-test-never-log"));
        assert!(rendered.contains("<redacted>"));
        assert!(rendered.contains("api.openai.com"));
    }

    #[test]
    fn mount_only_smb_policy_allows_only_gateway_smb() {
        let mut config = ProxyConfig::mount_only_smb();
        config.expose_host.push(ExposeHostMapping {
            host_port: 3000,
            guest_port: SMB_MOUNT_PORT,
        });

        assert!(config.permits_smb_mount_relay(GUEST_GATEWAY_IP, SMB_MOUNT_PORT));
        assert!(!config.permits_smb_mount_relay(GUEST_GATEWAY_IP, 80));
        assert!(!config.permits_smb_mount_relay(Ipv4Addr::new(203, 0, 113, 10), SMB_MOUNT_PORT));
        assert!(!config.is_domain_allowed("api.example.test"));
        assert_eq!(
            config.exposed_host_port(GUEST_GATEWAY_IP, SMB_MOUNT_PORT),
            None
        );
    }

    #[test]
    fn network_policy_with_smb_mount_preserves_network_controls() {
        let config = ProxyConfig {
            network: NetworkConfig {
                allow: vec!["api.example.test".into()],
            },
            ..Default::default()
        }
        .with_smb_mount_relay();

        assert_eq!(config.mode, ProxyMode::NetworkPolicyWithSmbMount);
        assert!(config.permits_smb_mount_relay(GUEST_GATEWAY_IP, SMB_MOUNT_PORT));
        assert!(config.is_domain_allowed("api.example.test"));
        assert!(!config.is_domain_allowed("blocked.example.test"));
        assert!(config.has_domain_allowlist());
    }

    #[test]
    fn mount_only_smb_does_not_return_secret_substitutions() {
        let mut config = ProxyConfig::mount_only_smb();
        config.secrets.insert(
            "API_KEY".into(),
            SecretConfig {
                value: "real-secret".into(),
                hosts: vec!["api.example.test".into()],
            },
        );

        let placeholders = HashMap::from([("API_KEY".into(), "lsb_tok_placeholder".into())]);

        assert!(config
            .secrets_for_domain("api.example.test", &placeholders)
            .is_empty());
    }

    #[test]
    fn test_exposed_host_port() {
        let config = ProxyConfig {
            expose_host: vec![
                ExposeHostMapping {
                    host_port: 3000,
                    guest_port: 8080,
                },
                ExposeHostMapping {
                    host_port: 5432,
                    guest_port: 5432,
                },
            ],
            ..Default::default()
        };

        assert_eq!(
            config.exposed_host_port(Ipv4Addr::new(10, 0, 0, 1), 8080),
            Some(3000)
        );
        assert_eq!(
            config.exposed_host_port(Ipv4Addr::new(10, 0, 0, 1), 5432),
            Some(5432)
        );
        assert_eq!(
            config.exposed_host_port(Ipv4Addr::new(10, 0, 0, 1), 9999),
            None
        );
        assert_eq!(
            config.exposed_host_port(Ipv4Addr::new(1, 2, 3, 4), 8080),
            None
        );
    }
}
