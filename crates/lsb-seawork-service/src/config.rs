use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

const MAX_CONFIG_SIZE: u64 = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    pub schema_version: u32,
    pub config_revision: u32,
    #[serde(default)]
    pub quotas: Quotas,
    #[serde(default)]
    pub publisher_thumbprints: Vec<String>,
    #[serde(default)]
    pub maintenance_roots: Vec<String>,
    #[serde(default)]
    pub ports_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
            quotas: Quotas::default(),
            publisher_thumbprints: Vec::new(),
            maintenance_roots: Vec::new(),
            ports_enabled: false,
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
        if self.maintenance_roots.len() > 8
            || self.maintenance_roots.iter().any(|value| {
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
            bail!("maintenance image root allowlist is invalid");
        }
        if self.ports_enabled {
            bail!("host ports are compiled fail-closed until WFP isolation is proven");
        }
        Ok(())
    }
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
    fn maintenance_policy_is_bounded_and_normalized() {
        let mut config = ServiceConfig::default();
        config.publisher_thumbprints = vec!["a".repeat(40)];
        config.maintenance_roots = vec![r"C:\Program Files\LocalSandbox".to_string()];
        assert!(config.validate().is_ok());
        config.maintenance_roots = vec![r"C:\Program Files\..\Windows".to_string()];
        assert!(config.validate().is_err());
    }
}
