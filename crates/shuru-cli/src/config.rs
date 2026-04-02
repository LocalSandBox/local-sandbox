use std::collections::HashMap;

use anyhow::{bail, Result};
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
pub(crate) struct ShuruConfig {
    pub cpus: Option<usize>,
    pub memory: Option<u64>,
    pub disk_size: Option<u64>,
    pub allow_net: Option<bool>,
    pub allow_host_writes: Option<bool>,
    pub ports: Option<Vec<String>>,
    pub mounts: Option<Vec<String>>,
    pub command: Option<Vec<String>>,
    pub secrets: Option<HashMap<String, SecretEntry>>,
    pub network: Option<NetworkEntry>,
    pub expose_host: Option<Vec<String>>,
}

/// A secret to inject via the proxy.
/// Example: `{ "value": "sk-your-openai-key", "hosts": ["api.openai.com"] }`
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SecretEntry {
    /// Literal secret value held on the host.
    pub value: String,
    /// Domains where this secret may be sent.
    pub hosts: Vec<String>,
}

/// Network access policy.
#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct NetworkEntry {
    /// Allowed domain patterns. Empty or absent = allow all.
    pub allow: Option<Vec<String>>,
}

impl ShuruConfig {
    /// Convert config sections into a ProxyConfig for shuru-proxy.
    pub fn to_proxy_config(&self) -> shuru_proxy::config::ProxyConfig {
        let mut proxy = shuru_proxy::config::ProxyConfig::default();

        if let Some(ref secrets) = self.secrets {
            for (name, entry) in secrets {
                proxy.secrets.insert(
                    name.clone(),
                    shuru_proxy::config::SecretConfig {
                        value: entry.value.clone(),
                        hosts: entry.hosts.clone(),
                    },
                );
            }
        }

        if let Some(ref network) = self.network {
            if let Some(ref allow) = network.allow {
                proxy.network.allow = allow.clone();
            }
        }

        if let Some(ref mappings) = self.expose_host {
            for mapping in mappings {
                if let Ok(mapping) = parse_expose_host(mapping) {
                    proxy.expose_host.push(mapping);
                }
            }
        }

        proxy
    }
}

pub(crate) fn parse_expose_host(s: &str) -> Result<shuru_proxy::config::ExposeHostMapping> {
    let parts: Vec<&str> = s.split(':').collect();
    match parts.len() {
        1 => {
            let port: u16 = parts[0]
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid port: '{}'", parts[0]))?;
            Ok(shuru_proxy::config::ExposeHostMapping {
                host_port: port,
                guest_port: port,
            })
        }
        2 => {
            let host_port: u16 = parts[0]
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid host port: '{}'", parts[0]))?;
            let guest_port: u16 = parts[1]
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid guest port: '{}'", parts[1]))?;
            Ok(shuru_proxy::config::ExposeHostMapping {
                host_port,
                guest_port,
            })
        }
        _ => bail!("expected HOST_PORT:GUEST_PORT or PORT format"),
    }
}

pub(crate) fn load_config(config_flag: Option<&str>) -> Result<ShuruConfig> {
    let path = match config_flag {
        Some(p) => std::path::PathBuf::from(p),
        None => std::path::PathBuf::from("shuru.json"),
    };

    match std::fs::read_to_string(&path) {
        Ok(contents) => {
            let cfg: ShuruConfig = serde_json::from_str(&contents)
                .map_err(|e| anyhow::anyhow!("Failed to parse {}: {}", path.display(), e))?;
            Ok(cfg)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if config_flag.is_some() {
                bail!("Config file not found: {}", path.display());
            }
            Ok(ShuruConfig::default())
        }
        Err(e) => bail!("Failed to read {}: {}", path.display(), e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_literal_secret_entries() {
        let cfg: ShuruConfig = serde_json::from_str(
            r#"{
                "secrets": {
                    "API_KEY": {
                        "value": "sk-test",
                        "hosts": ["api.openai.com"]
                    }
                }
            }"#,
        )
        .expect("config should parse");

        let proxy = cfg.to_proxy_config();
        let secret = proxy.secrets.get("API_KEY").expect("secret should exist");
        assert_eq!(secret.value, "sk-test");
        assert_eq!(secret.hosts, vec!["api.openai.com"]);
    }

    #[test]
    fn rejects_legacy_from_secret_entries() {
        let err = serde_json::from_str::<ShuruConfig>(
            r#"{
                "secrets": {
                    "API_KEY": {
                        "from": "OPENAI_API_KEY",
                        "hosts": ["api.openai.com"]
                    }
                }
            }"#,
        )
        .expect_err("legacy secret schema should fail");

        assert!(err.to_string().contains("unknown field `from`"));
    }

    #[test]
    fn parses_expose_host_config_entries() {
        let cfg: ShuruConfig = serde_json::from_str(
            r#"{
                "expose_host": ["3000:8080", "5432"]
            }"#,
        )
        .expect("config should parse");

        let proxy = cfg.to_proxy_config();
        assert_eq!(proxy.expose_host.len(), 2);
        assert_eq!(proxy.expose_host[0].host_port, 3000);
        assert_eq!(proxy.expose_host[0].guest_port, 8080);
        assert_eq!(proxy.expose_host[1].host_port, 5432);
        assert_eq!(proxy.expose_host[1].guest_port, 5432);
    }
}
