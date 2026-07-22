use std::path::Path;

use anyhow::{bail, Context, Result};
pub use lsb_seawork_update::ReleaseChannel as UpdateChannel;
use serde::Deserialize;

const MAX_CONFIG_SIZE: u64 = 256 * 1024;
const MAX_PRODUCT_CA_BUNDLE_SIZE: u64 = lsb_proxy::config::MAX_PRODUCT_CA_BUNDLE_BYTES as u64;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    pub schema_version: u32,
    pub config_revision: u32,
    #[serde(default)]
    pub update_channel: UpdateChannel,
    #[serde(default)]
    pub quotas: Quotas,
    #[serde(default)]
    pub publisher_thumbprints: Vec<String>,
    #[serde(default)]
    pub client_roots: Vec<String>,
    #[serde(default)]
    pub maintenance_roots: Vec<String>,
    #[serde(default)]
    pub ports_enabled: bool,
    #[serde(default)]
    pub egress_allow: Vec<String>,
    #[serde(default)]
    pub upstream_proxy: Option<ServiceUpstreamProxyConfig>,
}

#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceUpstreamProxyConfig {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub authorization: Option<String>,
}

impl std::fmt::Debug for ServiceUpstreamProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceUpstreamProxyConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field(
                "authorization",
                &self.authorization.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl Drop for ServiceUpstreamProxyConfig {
    fn drop(&mut self) {
        if let Some(authorization) = &mut self.authorization {
            zeroize::Zeroize::zeroize(authorization);
        }
    }
}

impl ServiceUpstreamProxyConfig {
    pub fn to_proxy_config(&self) -> lsb_proxy::UpstreamProxyConfig {
        lsb_proxy::UpstreamProxyConfig {
            host: self.host.clone(),
            port: self.port,
            authorization: self.authorization.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Quotas {
    pub connections_global: u16,
    pub connections_per_user: u16,
    pub sandboxes_global: u16,
    pub sandboxes_per_user: u16,
    pub sandboxes_per_connection: u16,
    pub memory_mib_global: u32,
}

impl Default for Quotas {
    fn default() -> Self {
        Self {
            connections_global: 32,
            connections_per_user: 4,
            sandboxes_global: 8,
            sandboxes_per_user: 4,
            sandboxes_per_connection: 2,
            memory_mib_global: 24 * 1024,
        }
    }
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            schema_version: 1,
            config_revision: 1,
            update_channel: UpdateChannel::Stable,
            quotas: Quotas::default(),
            publisher_thumbprints: Vec::new(),
            client_roots: Vec::new(),
            maintenance_roots: Vec::new(),
            ports_enabled: false,
            egress_allow: Vec::new(),
            upstream_proxy: None,
        }
    }
}

impl ServiceConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let metadata = std::fs::metadata(path)
            .with_context(|| format!("read service config metadata {}", path.display()))?;
        if metadata.len() > MAX_CONFIG_SIZE {
            bail!("service config exceeds {MAX_CONFIG_SIZE} bytes");
        }
        let config: Self = serde_json::from_slice(
            &std::fs::read(path).with_context(|| format!("read config {}", path.display()))?,
        )
        .context("parse strict service config")?;
        config.validate()?;
        Ok(config)
    }

    pub fn load_or_default(path: &Path) -> Result<Self> {
        match Self::load(path) {
            Ok(config) => Ok(config),
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
            {
                Ok(Self::default())
            }
            Err(error) => Err(error),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            bail!("unsupported service config schema {}", self.schema_version);
        }
        if !matches!(self.config_revision, 1 | 2) {
            bail!(
                "unsupported service config revision {}",
                self.config_revision
            );
        }
        if self.config_revision == 1 && self.update_channel != UpdateChannel::Stable {
            bail!("service config revision 1 implies the stable update channel");
        }
        let q = &self.quotas;
        if q.connections_global == 0
            || q.connections_global > 32
            || q.connections_per_user == 0
            || q.connections_per_user > 4
            || q.sandboxes_global == 0
            || q.sandboxes_global > 8
            || q.sandboxes_per_user == 0
            || q.sandboxes_per_user > 4
            || q.sandboxes_per_connection == 0
            || q.sandboxes_per_connection > 2
            || q.memory_mib_global < 512
            || q.memory_mib_global > 24 * 1024
        {
            bail!("service config exceeds compiled quota ceilings");
        }
        if self.publisher_thumbprints.len() > 8
            || self.publisher_thumbprints.iter().any(|value| {
                value.len() != 40 && value.len() != 64
                    || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        {
            bail!("publisher thumbprint allowlist is invalid");
        }
        validate_roots(&self.client_roots, "client")?;
        validate_roots(&self.maintenance_roots, "maintenance")?;
        if self.egress_allow.len() > 256 {
            bail!("protected egress allowlist exceeds compiled bounds");
        }
        lsb_proxy::ProxyConfig {
            protected_network: lsb_proxy::config::NetworkConfig {
                allow: self.egress_allow.clone(),
            },
            upstream_proxy: self
                .upstream_proxy
                .as_ref()
                .map(ServiceUpstreamProxyConfig::to_proxy_config),
            ..Default::default()
        }
        .validate()
        .context("protected egress allowlist is invalid")?;
        if self.ports_enabled {
            bail!("host ports are compiled fail-closed until WFP isolation is proven");
        }
        Ok(())
    }
}

pub fn load_product_ca_bundle(path: &Path) -> Result<Vec<u8>> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("read product CA metadata {}", path.display()))
        }
    };
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_PRODUCT_CA_BUNDLE_SIZE {
        bail!("product CA bundle must be a non-empty regular file no larger than {MAX_PRODUCT_CA_BUNDLE_SIZE} bytes");
    }
    let bundle = std::fs::read(path)
        .with_context(|| format!("read product CA bundle {}", path.display()))?;
    lsb_proxy::ProxyConfig {
        product_ca_bundle_pem: bundle.clone(),
        ..Default::default()
    }
    .validate()
    .context("product CA bundle is invalid")?;
    Ok(bundle)
}

fn validate_roots(roots: &[String], policy: &str) -> Result<()> {
    if roots.len() > 8
        || roots.iter().any(|value| {
            value.len() > 1024
                || value.contains('\0')
                || !Path::new(value).is_absolute()
                || Path::new(value).components().any(|component| {
                    matches!(
                        component,
                        std::path::Component::ParentDir | std::path::Component::CurDir
                    )
                })
        })
    {
        bail!("{policy} image root allowlist is invalid");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_fields_and_ceiling_bypass() {
        assert!(serde_json::from_str::<ServiceConfig>(
            r#"{"schema_version":1,"config_revision":1,"unknown":true}"#
        )
        .is_err());
        let mut config = ServiceConfig::default();
        config.quotas.sandboxes_global = 9;
        assert!(config.validate().is_err());
        config.quotas.sandboxes_global = 8;
        config.ports_enabled = true;
        assert!(config.validate().is_err());
    }

    #[test]
    fn update_channel_is_strict_and_revision_compatible() {
        let revision_one: ServiceConfig =
            serde_json::from_str(r#"{"schema_version":1,"config_revision":1}"#).unwrap();
        assert_eq!(revision_one.update_channel, UpdateChannel::Stable);
        revision_one.validate().unwrap();

        let stable: ServiceConfig = serde_json::from_str(
            r#"{"schema_version":1,"config_revision":2,"update_channel":"stable"}"#,
        )
        .unwrap();
        assert_eq!(stable.update_channel, UpdateChannel::Stable);
        stable.validate().unwrap();

        let prerelease: ServiceConfig = serde_json::from_str(
            r#"{"schema_version":1,"config_revision":2,"update_channel":"prerelease"}"#,
        )
        .unwrap();
        assert_eq!(prerelease.update_channel, UpdateChannel::Prerelease);
        prerelease.validate().unwrap();

        let revision_one_prerelease: ServiceConfig = serde_json::from_str(
            r#"{"schema_version":1,"config_revision":1,"update_channel":"prerelease"}"#,
        )
        .unwrap();
        assert!(revision_one_prerelease.validate().is_err());
        assert!(serde_json::from_str::<ServiceConfig>(
            r#"{"schema_version":1,"config_revision":2,"update_channel":"preview"}"#,
        )
        .is_err());
        let mut unsupported = ServiceConfig::default();
        unsupported.config_revision = 3;
        assert!(unsupported.validate().is_err());
    }

    #[test]
    fn maintenance_policy_is_bounded_and_normalized() {
        let mut config = ServiceConfig::default();
        config.publisher_thumbprints = vec!["a".repeat(40)];
        config.client_roots = vec![if cfg!(windows) {
            r"C:\Program Files\SeaWork".to_string()
        } else {
            "/Applications/SeaWork".to_string()
        }];
        config.maintenance_roots = vec![if cfg!(windows) {
            r"C:\Program Files\LocalSandbox".to_string()
        } else {
            "/Library/Application Support/LocalSandbox".to_string()
        }];
        assert!(config.validate().is_ok());
        config.client_roots = vec![if cfg!(windows) {
            r"C:\Program Files\..\Windows".to_string()
        } else {
            "/Applications/../System".to_string()
        }];
        assert!(config.validate().is_err());
    }

    #[test]
    fn protected_egress_policy_is_bounded_and_validated() {
        let mut config = ServiceConfig {
            egress_allow: vec![
                "api.example.com".to_string(),
                "*.packages.example".to_string(),
            ],
            ..Default::default()
        };
        config.validate().unwrap();
        config.egress_allow = vec!["bad*pattern.example".to_string()];
        assert!(config.validate().is_err());
        config.egress_allow = vec!["api.example.com".to_string(); 257];
        assert!(config.validate().is_err());
    }

    #[test]
    fn optional_product_ca_bundle_is_bounded_and_validated() {
        let path =
            std::env::temp_dir().join(format!("lsbsw-product-ca-{}.pem", std::process::id()));
        let _ = std::fs::remove_file(&path);
        assert!(load_product_ca_bundle(&path).unwrap().is_empty());
        std::fs::write(&path, b"not a certificate").unwrap();
        assert!(load_product_ca_bundle(&path).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn explicit_upstream_proxy_is_strict_and_redacted() {
        let config: ServiceConfig = serde_json::from_str(
            r#"{
                "schema_version": 1,
                "config_revision": 1,
                "upstream_proxy": {
                    "host": "proxy.example.test",
                    "port": 8080,
                    "authorization": "Basic never-log-this"
                }
            }"#,
        )
        .unwrap();
        config.validate().unwrap();
        assert!(!format!("{config:?}").contains("never-log-this"));

        let mut invalid = config.clone();
        invalid.upstream_proxy.as_mut().unwrap().host = "wpad".into();
        assert!(invalid.validate().is_err());
        assert!(serde_json::from_str::<ServiceConfig>(
            r#"{
                "schema_version": 1,
                "config_revision": 1,
                "upstream_proxy": {
                    "host": "proxy.example.test",
                    "port": 8080,
                    "use_default_credentials": true
                }
            }"#
        )
        .is_err());
    }
}
