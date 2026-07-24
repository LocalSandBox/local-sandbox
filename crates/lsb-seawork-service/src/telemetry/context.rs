use std::collections::BTreeMap;

use serde::Serialize;

use crate::LEDGER_SCHEMA_VERSION;

pub const COMPONENT: &str = "local-sandbox-service";
pub const SERVICE_NAME: &str = "localsandbox-seawork-service";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CommonContext {
    pub component: &'static str,
    pub service: ServiceContext,
    pub build: BuildContext,
    pub runtime: RuntimeContext,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServiceContext {
    pub name: &'static str,
    pub version: &'static str,
    pub protocol_version: String,
    pub ledger_schema_version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BuildContext {
    pub commit: String,
    pub bundle_digest: Option<String>,
    pub installation_channel: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeContext {
    pub architecture: &'static str,
    pub cpu_count: usize,
}

impl CommonContext {
    pub fn collect(
        build_commit: impl Into<String>,
        bundle_digest: Option<String>,
        installation_channel: Option<String>,
    ) -> Self {
        Self {
            component: COMPONENT,
            service: ServiceContext {
                name: SERVICE_NAME,
                version: env!("CARGO_PKG_VERSION"),
                protocol_version: format!(
                    "{}.{}",
                    lsb_service_proto::CURRENT.major,
                    lsb_service_proto::CURRENT.minor
                ),
                ledger_schema_version: LEDGER_SCHEMA_VERSION,
            },
            build: BuildContext {
                commit: bounded(build_commit.into(), 128),
                bundle_digest: bundle_digest.map(|value| bounded(value, 256)),
                installation_channel: installation_channel.map(|value| bounded(value, 64)),
            },
            runtime: RuntimeContext {
                architecture: std::env::consts::ARCH,
                cpu_count: std::thread::available_parallelism().map_or(1, usize::from),
            },
        }
    }

    pub fn as_contexts(&self) -> BTreeMap<String, serde_json::Value> {
        let mut contexts = BTreeMap::new();
        contexts.insert(
            "service".to_string(),
            serde_json::to_value(&self.service).expect("service context is serializable"),
        );
        contexts.insert(
            "build".to_string(),
            serde_json::to_value(&self.build).expect("build context is serializable"),
        );
        contexts.insert(
            "runtime".to_string(),
            serde_json::to_value(&self.runtime).expect("runtime context is serializable"),
        );
        contexts
    }
}

fn bounded(mut value: String, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value;
    }
    while !value.is_char_boundary(max_bytes.min(value.len())) {
        value.pop();
    }
    value.truncate(max_bytes);
    value
}

#[cfg(test)]
mod tests {
    use super::{CommonContext, COMPONENT, SERVICE_NAME};

    #[test]
    fn common_context_is_deterministic_and_bounded() {
        let context = CommonContext::collect(
            "x".repeat(512),
            Some("digest".to_string()),
            Some("internal".to_string()),
        );
        assert_eq!(context.component, COMPONENT);
        assert_eq!(context.service.name, SERVICE_NAME);
        assert_eq!(context.build.commit.len(), 128);

        let first = serde_json::to_string(&context).unwrap();
        let second = serde_json::to_string(&context).unwrap();
        assert_eq!(first, second);
        assert!(first.len() < 2_048);
    }
}
