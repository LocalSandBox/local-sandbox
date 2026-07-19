use std::collections::HashMap;

use anyhow::Result;
use lsb_service_proto::ServiceNetworkSpec;

pub fn build_proxy_config(
    mut policy: ServiceNetworkSpec,
    protected_allow: Vec<String>,
    product_ca_bundle_pem: Vec<u8>,
) -> Result<lsb_proxy::ProxyConfig> {
    let secrets = std::mem::take(&mut policy.secrets)
        .into_iter()
        .map(|(name, mut secret)| {
            (
                name,
                lsb_proxy::config::SecretConfig {
                    value: std::mem::take(&mut secret.value),
                    hosts: std::mem::take(&mut secret.hosts),
                },
            )
        })
        .collect();
    let https_interception = policy.https_interception.take().map_or_else(
        lsb_proxy::HttpsInterceptionConfig::default,
        |mut interception| lsb_proxy::HttpsInterceptionConfig {
            enabled: interception.enabled,
            request_headers: std::mem::take(&mut interception.request_headers)
                .into_iter()
                .map(|mut header| lsb_proxy::RequestHeaderRule {
                    name: std::mem::take(&mut header.name),
                    value: std::mem::take(&mut header.value),
                    hosts: lsb_proxy::HostScope {
                        allow: header.hosts.allow.take(),
                        deny: header.hosts.deny.take(),
                    },
                })
                .collect(),
        },
    );
    let config = lsb_proxy::ProxyConfig {
        secrets,
        network: lsb_proxy::config::NetworkConfig {
            allow: std::mem::take(&mut policy.allowed_hosts),
        },
        protected_network: lsb_proxy::config::NetworkConfig {
            allow: protected_allow,
        },
        product_ca_bundle_pem,
        https_interception,
        ..Default::default()
    };
    config.validate()?;
    Ok(config)
}

pub fn merge_proxy_environment(
    proxy_environment: &HashMap<String, String>,
    command_environment: HashMap<String, String>,
) -> HashMap<String, String> {
    let mut environment = proxy_environment.clone();
    environment.extend(command_environment);
    environment
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_network_maps_to_redacted_validated_proxy_config() {
        let policy = ServiceNetworkSpec {
            allowed_hosts: vec!["api.example.test".to_string()],
            secrets: std::collections::BTreeMap::from([(
                "API_TOKEN".to_string(),
                lsb_service_proto::ServiceSecretSpec {
                    value: "never-log-secret".to_string(),
                    hosts: vec!["api.example.test".to_string()],
                },
            )]),
            https_interception: Some(lsb_service_proto::ServiceHttpsInterceptionSpec {
                enabled: true,
                request_headers: vec![lsb_service_proto::ServiceRequestHeaderSpec {
                    name: "Authorization".to_string(),
                    value: "never-log-header".to_string(),
                    hosts: lsb_service_proto::ServiceHostScope {
                        allow: Some(vec!["api.example.test".to_string()]),
                        deny: None,
                    },
                }],
            }),
        };
        let config =
            build_proxy_config(policy, vec!["api.example.test".to_string()], Vec::new()).unwrap();
        let debug = format!("{config:?}");
        assert!(!debug.contains("never-log-secret"));
        assert!(!debug.contains("never-log-header"));
        assert!(config.is_domain_allowed("api.example.test"));
        assert!(config.requires_guest_ca());
    }

    #[test]
    fn command_environment_overrides_placeholder_without_dropping_other_values() {
        let proxy = HashMap::from([("API_TOKEN".to_string(), "opaque-placeholder".to_string())]);
        let merged = merge_proxy_environment(
            &proxy,
            HashMap::from([
                ("USER_VALUE".to_string(), "visible".to_string()),
                ("API_TOKEN".to_string(), "caller-override".to_string()),
            ]),
        );
        assert_eq!(
            merged.get("USER_VALUE").map(String::as_str),
            Some("visible")
        );
        assert_eq!(
            merged.get("API_TOKEN").map(String::as_str),
            Some("caller-override")
        );
    }
}
