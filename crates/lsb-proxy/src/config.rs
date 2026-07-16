use std::collections::HashMap;
use std::fmt;
use std::net::Ipv4Addr;

use anyhow::{bail, Result};

pub const GUEST_GATEWAY_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
pub const HOST_LSB_INTERNAL: &str = "host.lsb.internal";
pub const SMB_MOUNT_PORT: u16 = 445;
pub const MAX_REQUEST_HEADER_RULES: usize = 64;
pub const MAX_REQUEST_HEADER_NAME_BYTES: usize = 128;
pub const MAX_REQUEST_HEADER_VALUE_BYTES: usize = 8 * 1024;
pub const MAX_REQUEST_HEADER_TOTAL_BYTES: usize = 64 * 1024;

const FORBIDDEN_REQUEST_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "proxy-connection",
    "proxy-authorization",
    "te",
    "trailer",
    "upgrade",
    "expect",
];

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
    /// Opt-in HTTPS request interception and mutation.
    pub https_interception: HttpsInterceptionConfig,
    /// Host ports exposed to the guest via host.lsb.internal.
    pub expose_host: Vec<ExposeHostMapping>,
}

/// HTTPS request interception configuration.
#[derive(Debug, Clone, Default)]
pub struct HttpsInterceptionConfig {
    /// Whether configured request-header rules are active.
    pub enabled: bool,
    /// Header rules applied in configuration order.
    pub request_headers: Vec<RequestHeaderRule>,
}

/// A request header to set on matching HTTPS destinations.
#[derive(Clone, PartialEq, Eq)]
pub struct RequestHeaderRule {
    pub name: String,
    pub value: String,
    pub hosts: HostScope,
}

impl fmt::Debug for RequestHeaderRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestHeaderRule")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .field("hosts", &self.hosts)
            .finish()
    }
}

/// Optional allow and deny patterns for a request-header rule.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostScope {
    pub allow: Option<Vec<String>>,
    pub deny: Option<Vec<String>>,
}

impl HostScope {
    pub fn applies_to(&self, domain: &str) -> bool {
        let allowed = self.allow.as_ref().is_none_or(|patterns| {
            patterns
                .iter()
                .any(|pattern| domain_matches(pattern, domain))
        });
        let denied = self.deny.as_ref().is_some_and(|patterns| {
            patterns
                .iter()
                .any(|pattern| domain_matches(pattern, domain))
        });
        allowed && !denied
    }

    fn validate(&self) -> Result<()> {
        if self.allow.as_ref().is_some_and(Vec::is_empty) {
            bail!("request header host allow list must not be empty when supplied");
        }
        if self.deny.as_ref().is_some_and(Vec::is_empty) {
            bail!("request header host deny list must not be empty when supplied");
        }
        Ok(())
    }
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
    /// Validate request-interception configuration before starting a VM.
    pub fn validate(&self) -> Result<()> {
        let rules = &self.https_interception.request_headers;
        if self.https_interception.enabled && rules.is_empty() {
            bail!("HTTPS interception is enabled but no request header rules are configured");
        }
        if rules.len() > MAX_REQUEST_HEADER_RULES {
            bail!("too many HTTPS request header rules (maximum {MAX_REQUEST_HEADER_RULES})");
        }

        let mut total_bytes = 0usize;
        let mut names = std::collections::HashSet::new();
        for rule in rules {
            validate_request_header_name(&rule.name)?;
            validate_request_header_value(&rule.value)?;
            rule.hosts.validate()?;
            total_bytes = total_bytes
                .checked_add(rule.name.len() + rule.value.len())
                .ok_or_else(|| {
                    anyhow::anyhow!("HTTPS request header configuration is too large")
                })?;
            let normalized = rule.name.to_ascii_lowercase();
            if !names.insert(normalized) {
                bail!("duplicate HTTPS request header rule name: {}", rule.name);
            }
        }
        if total_bytes > MAX_REQUEST_HEADER_TOTAL_BYTES {
            bail!(
                "HTTPS request header configuration exceeds {MAX_REQUEST_HEADER_TOTAL_BYTES} bytes"
            );
        }
        Ok(())
    }

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

    /// Enabled request-header rules that apply to the normalized TLS SNI domain.
    pub fn active_header_rules_for_domain(&self, domain: &str) -> Vec<RequestHeaderRule> {
        if !self.permits_network_policy() || !self.https_interception.enabled {
            return Vec::new();
        }
        self.https_interception
            .request_headers
            .iter()
            .filter(|rule| rule.hosts.applies_to(domain))
            .cloned()
            .collect()
    }

    pub fn requires_mitm_for_domain(
        &self,
        domain: &str,
        placeholders: &HashMap<String, String>,
    ) -> bool {
        !self.secrets_for_domain(domain, placeholders).is_empty()
            || !self.active_header_rules_for_domain(domain).is_empty()
    }

    pub fn requires_guest_ca(&self) -> bool {
        !self.secrets.is_empty()
            || (self.https_interception.enabled
                && !self.https_interception.request_headers.is_empty())
    }
}

fn validate_request_header_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("HTTPS request header name must not be empty");
    }
    if name.len() > MAX_REQUEST_HEADER_NAME_BYTES {
        bail!("HTTPS request header name exceeds {MAX_REQUEST_HEADER_NAME_BYTES} bytes");
    }
    if !name.bytes().all(is_http_token_byte) {
        bail!("invalid HTTPS request header name: {name}");
    }
    if FORBIDDEN_REQUEST_HEADERS
        .iter()
        .any(|forbidden| name.eq_ignore_ascii_case(forbidden))
    {
        bail!("HTTPS request header is not allowed to modify routing or framing: {name}");
    }
    Ok(())
}

fn validate_request_header_value(value: &str) -> Result<()> {
    if value.len() > MAX_REQUEST_HEADER_VALUE_BYTES {
        bail!("HTTPS request header value exceeds {MAX_REQUEST_HEADER_VALUE_BYTES} bytes");
    }
    if value
        .bytes()
        .any(|byte| (byte < 0x20 && byte != b'\t') || byte == 0x7f)
    {
        bail!("invalid HTTPS request header value");
    }
    Ok(())
}

fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
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

    fn header_rule(name: &str, value: &str, hosts: HostScope) -> RequestHeaderRule {
        RequestHeaderRule {
            name: name.into(),
            value: value.into(),
            hosts,
        }
    }

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
    fn header_scope_semantics_normalize_domains_and_deny_wins() {
        let global = HostScope::default();
        assert!(global.applies_to("anything.example"));

        let allow_only = HostScope {
            allow: Some(vec!["*.Example.COM.".into()]),
            deny: None,
        };
        assert!(allow_only.applies_to("API.example.com."));
        assert!(!allow_only.applies_to("example.com"));

        let deny_only = HostScope {
            allow: None,
            deny: Some(vec!["private.example.com".into()]),
        };
        assert!(deny_only.applies_to("public.example.com"));
        assert!(!deny_only.applies_to("PRIVATE.EXAMPLE.COM."));

        let combined = HostScope {
            allow: Some(vec!["*.example.com".into()]),
            deny: Some(vec!["billing.example.com".into()]),
        };
        assert!(combined.applies_to("api.example.com"));
        assert!(!combined.applies_to("billing.example.com"));
        assert!(!combined.applies_to("outside.test"));
    }

    #[test]
    fn interception_defaults_off_and_requires_rules_when_enabled() {
        let default = ProxyConfig::default();
        assert!(!default.https_interception.enabled);
        assert!(!default.requires_guest_ca());
        default.validate().unwrap();

        let invalid = ProxyConfig {
            https_interception: HttpsInterceptionConfig {
                enabled: true,
                request_headers: Vec::new(),
            },
            ..Default::default()
        };
        assert!(invalid.validate().is_err());

        let disabled_with_rule = ProxyConfig {
            https_interception: HttpsInterceptionConfig {
                enabled: false,
                request_headers: vec![header_rule(
                    "User-Agent",
                    "configured",
                    HostScope::default(),
                )],
            },
            ..Default::default()
        };
        disabled_with_rule.validate().unwrap();
        assert!(disabled_with_rule
            .active_header_rules_for_domain("example.com")
            .is_empty());
        assert!(!disabled_with_rule.requires_guest_ca());
    }

    #[test]
    fn active_header_rules_are_scoped_and_trigger_mitm_without_secrets() {
        let config = ProxyConfig {
            https_interception: HttpsInterceptionConfig {
                enabled: true,
                request_headers: vec![header_rule(
                    "User-Agent",
                    "agent/1.0",
                    HostScope {
                        allow: Some(vec!["*.example.com".into()]),
                        deny: Some(vec!["private.example.com".into()]),
                    },
                )],
            },
            ..Default::default()
        };
        config.validate().unwrap();
        assert_eq!(
            config
                .active_header_rules_for_domain("api.example.com")
                .len(),
            1
        );
        assert!(config
            .active_header_rules_for_domain("private.example.com")
            .is_empty());
        assert!(config.requires_mitm_for_domain("api.example.com", &HashMap::new()));
        assert!(!config.requires_mitm_for_domain("private.example.com", &HashMap::new()));
        assert!(config.requires_guest_ca());
    }

    #[test]
    fn validation_rejects_unsafe_or_ambiguous_header_rules() {
        for name in ["", "Bad Header", "Host", "content-length", "Expect"] {
            let config = ProxyConfig {
                https_interception: HttpsInterceptionConfig {
                    enabled: true,
                    request_headers: vec![header_rule(name, "value", HostScope::default())],
                },
                ..Default::default()
            };
            assert!(config.validate().is_err(), "name {name:?}");
        }

        let duplicate = ProxyConfig {
            https_interception: HttpsInterceptionConfig {
                enabled: true,
                request_headers: vec![
                    header_rule("User-Agent", "one", HostScope::default()),
                    header_rule("user-agent", "two", HostScope::default()),
                ],
            },
            ..Default::default()
        };
        assert!(duplicate.validate().is_err());

        for value in ["bad\r\nInjected: yes", "nul\0byte", "control\u{7f}"] {
            let config = ProxyConfig {
                https_interception: HttpsInterceptionConfig {
                    enabled: true,
                    request_headers: vec![header_rule("X-Test", value, HostScope::default())],
                },
                ..Default::default()
            };
            assert!(config.validate().is_err());
        }
    }

    #[test]
    fn validation_rejects_explicit_empty_scopes_and_enforces_limits() {
        for hosts in [
            HostScope {
                allow: Some(Vec::new()),
                deny: None,
            },
            HostScope {
                allow: None,
                deny: Some(Vec::new()),
            },
        ] {
            let config = ProxyConfig {
                https_interception: HttpsInterceptionConfig {
                    enabled: true,
                    request_headers: vec![header_rule("X-Test", "value", hosts)],
                },
                ..Default::default()
            };
            assert!(config.validate().is_err());
        }

        let too_many = ProxyConfig {
            https_interception: HttpsInterceptionConfig {
                enabled: true,
                request_headers: (0..=MAX_REQUEST_HEADER_RULES)
                    .map(|index| header_rule(&format!("X-{index}"), "value", HostScope::default()))
                    .collect(),
            },
            ..Default::default()
        };
        assert!(too_many.validate().is_err());

        let too_long = ProxyConfig {
            https_interception: HttpsInterceptionConfig {
                enabled: true,
                request_headers: vec![header_rule(
                    "X-Test",
                    &"x".repeat(MAX_REQUEST_HEADER_VALUE_BYTES + 1),
                    HostScope::default(),
                )],
            },
            ..Default::default()
        };
        assert!(too_long.validate().is_err());
    }

    #[test]
    fn header_rule_debug_redacts_values() {
        let rule = header_rule("User-Agent", "never-log-this-value", HostScope::default());
        let rendered = format!("{rule:?}");
        assert!(rendered.contains("User-Agent"));
        assert!(!rendered.contains("never-log-this-value"));
        assert!(rendered.contains("<redacted>"));
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
