use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::error::{ErrorEnvelope, ProtocolError};
use crate::limits::{MAX_CONTROL_PAYLOAD, MAX_JSON_DEPTH, MAX_STRING_LEN};
use crate::version::{HexU64, ProtocolRange};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    pub min_minor: u16,
    pub max_minor: u16,
    pub client_version: String,
    pub feature_bits_hex: HexU64,
}

impl Hello {
    pub fn range(&self, major: u16) -> ProtocolRange {
        ProtocolRange {
            major,
            min_minor: self.min_minor,
            max_minor: self.max_minor,
        }
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        self.range(1).validate()?;
        validate_string(&self.client_version)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelloReply {
    pub selected_minor: u16,
    pub connection_epoch_hex: HexU64,
    pub service_version: String,
    pub bundle_version: String,
    pub ledger_schema: ProtocolRange,
    pub selected_feature_bits_hex: HexU64,
    pub health: Health,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deadline_ms: Option<u32>,
    pub op: RequestOp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RequestOp {
    GetServiceInfo {},
    HealthCheck {},
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    Ok { result: ResponseValue },
    Err { error: ErrorEnvelope },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResponseValue {
    ServiceInfo { info: ServiceInfo },
    Health { health: Health },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceInfo {
    pub service_version: String,
    pub bundle_version: String,
    pub protocol: ProtocolRange,
    pub ledger_schema: ProtocolRange,
    pub feature_bits_hex: HexU64,
    pub capabilities: CapabilityHealth,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Health {
    pub ready: bool,
    pub admissions_open: bool,
    pub stable_code: String,
    pub whpx: HealthState,
    pub smb: HealthState,
    pub wfp: HealthState,
    pub bundle: HealthState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthState {
    Ready,
    Unavailable,
    Degraded,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityHealth {
    pub direct_mount: bool,
    pub direct_mount_backends: Vec<String>,
    pub watch: bool,
    pub ports: bool,
}

pub fn parse_control<T: DeserializeOwned>(payload: &[u8]) -> Result<T, ProtocolError> {
    if payload.len() > MAX_CONTROL_PAYLOAD {
        return Err(ProtocolError::MessageTooLarge);
    }
    let text = std::str::from_utf8(payload).map_err(|_| ProtocolError::InvalidUtf8)?;
    validate_json_depth(text)?;
    serde_json::from_str(text).map_err(|_| ProtocolError::InvalidJson)
}

fn validate_string(value: &str) -> Result<(), ProtocolError> {
    if value.len() > MAX_STRING_LEN {
        return Err(ProtocolError::MessageTooLarge);
    }
    Ok(())
}

fn validate_json_depth(json: &str) -> Result<(), ProtocolError> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for byte in json.bytes() {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > MAX_JSON_DEPTH {
                    return Err(ProtocolError::JsonTooDeep);
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_is_strict_and_bounded() {
        let valid = br#"{"min_minor":0,"max_minor":1,"client_version":"0.4.6","feature_bits_hex":"0000000000000000"}"#;
        let hello: Hello = parse_control(valid).unwrap();
        hello.validate().unwrap();

        let unknown = br#"{"min_minor":0,"max_minor":1,"client_version":"0.4.6","feature_bits_hex":"0000000000000000","identity":"forged"}"#;
        assert_eq!(
            parse_control::<Hello>(unknown),
            Err(ProtocolError::InvalidJson)
        );
        let duplicate = br#"{"min_minor":0,"min_minor":1,"max_minor":1,"client_version":"0.4.6","feature_bits_hex":"0000000000000000"}"#;
        assert_eq!(
            parse_control::<Hello>(duplicate),
            Err(ProtocolError::InvalidJson)
        );
    }

    #[test]
    fn rejects_invalid_utf8_and_deep_json() {
        assert_eq!(
            parse_control::<Hello>(&[0xff]),
            Err(ProtocolError::InvalidUtf8)
        );
        let deep = format!("{}0{}", "[".repeat(33), "]".repeat(33));
        assert_eq!(
            parse_control::<serde_json::Value>(deep.as_bytes()),
            Err(ProtocolError::JsonTooDeep)
        );
    }

    #[test]
    fn request_surface_is_health_only() {
        let info: Request = parse_control(br#"{"op":{"type":"get_service_info"}}"#).unwrap();
        assert!(matches!(info.op, RequestOp::GetServiceInfo {}));
        let sandbox = br#"{"op":{"type":"start_sandbox","cpus":2}}"#;
        assert_eq!(
            parse_control::<Request>(sandbox),
            Err(ProtocolError::InvalidJson)
        );
    }
}
