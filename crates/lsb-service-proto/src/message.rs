use std::collections::BTreeMap;

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

impl Request {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self
            .deadline_ms
            .is_some_and(|value| !(1..=60_000).contains(&value))
        {
            return Err(ProtocolError::InvalidJson);
        }
        match &self.op {
            RequestOp::GetServiceInfo {}
            | RequestOp::HealthCheck {}
            | RequestOp::CloseSession {} => {}
            RequestOp::StartSandbox {
                cpus,
                memory_mib,
                disk_mib,
                mounts,
                ports,
                network,
            } => {
                if !(1..=16).contains(cpus)
                    || !(256..=32 * 1024).contains(memory_mib)
                    || !(512..=64 * 1024).contains(disk_mib)
                    || mounts.len() > 32
                    || ports.len() > 32
                {
                    return Err(ProtocolError::InvalidJson);
                }
                for mount in mounts {
                    validate_string(&mount.host_path)?;
                    validate_string(&mount.guest_path)?;
                }
                for port in ports {
                    if port.guest_port == 0 || port.host_port == Some(0) {
                        return Err(ProtocolError::InvalidJson);
                    }
                }
                if let Some(network) = network {
                    if network.allowed_hosts.len() > 256 {
                        return Err(ProtocolError::InvalidJson);
                    }
                    for host in &network.allowed_hosts {
                        validate_string(host)?;
                    }
                }
            }
            RequestOp::StopSandbox { sandbox_id } => validate_resource_id(sandbox_id)?,
            RequestOp::Exec {
                sandbox_id,
                command,
                cwd,
                env,
            } => {
                validate_resource_id(sandbox_id)?;
                match command {
                    ServiceCommand::Argv(command) => {
                        if command.argv.is_empty() || command.argv.len() > 256 {
                            return Err(ProtocolError::InvalidJson);
                        }
                        let mut total = 0usize;
                        for argument in &command.argv {
                            validate_string(argument)?;
                            total = total
                                .checked_add(argument.len())
                                .ok_or(ProtocolError::MessageTooLarge)?;
                        }
                        if total > 64 * 1024 {
                            return Err(ProtocolError::MessageTooLarge);
                        }
                    }
                    ServiceCommand::Shell(command) => {
                        validate_string(&command.shell)?;
                        if command.shell.is_empty() || command.shell.len() > 64 * 1024 {
                            return Err(ProtocolError::InvalidJson);
                        }
                    }
                }
                if let Some(cwd) = cwd {
                    validate_guest_path(cwd)?;
                }
                if env.len() > 256 {
                    return Err(ProtocolError::InvalidJson);
                }
                let mut env_bytes = 0usize;
                for (key, value) in env {
                    validate_string(key)?;
                    validate_string(value)?;
                    if key.is_empty() || key.contains(['=', '\0']) {
                        return Err(ProtocolError::InvalidJson);
                    }
                    env_bytes = env_bytes
                        .checked_add(key.len())
                        .and_then(|total| total.checked_add(value.len()))
                        .ok_or(ProtocolError::MessageTooLarge)?;
                }
                if env_bytes > 128 * 1024 {
                    return Err(ProtocolError::MessageTooLarge);
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RequestOp {
    GetServiceInfo {},
    HealthCheck {},
    StartSandbox {
        cpus: u16,
        memory_mib: u32,
        disk_mib: u32,
        mounts: Vec<ServiceMountSpec>,
        ports: Vec<ServicePortSpec>,
        #[serde(skip_serializing_if = "Option::is_none")]
        network: Option<ServiceNetworkSpec>,
    },
    StopSandbox {
        sandbox_id: String,
    },
    Exec {
        sandbox_id: String,
        command: ServiceCommand,
        #[serde(skip_serializing_if = "Option::is_none")]
        cwd: Option<String>,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        env: BTreeMap<String, String>,
    },
    CloseSession {},
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ServiceCommand {
    Argv(ArgvCommand),
    Shell(ShellCommand),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArgvCommand {
    pub argv: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShellCommand {
    pub shell: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceMountSpec {
    pub host_path: String,
    pub guest_path: String,
    pub read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServicePortSpec {
    pub guest_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceNetworkSpec {
    pub allowed_hosts: Vec<String>,
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
    ServiceInfo {
        info: ServiceInfo,
    },
    Health {
        health: Health,
    },
    SandboxStarted {
        sandbox_id: String,
        mounts: Vec<SelectedMount>,
        host_ports: Vec<u16>,
    },
    ExecCompleted {
        stdout: String,
        stderr: String,
        exit_code: i32,
    },
    Empty {},
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedMount {
    pub guest_path: String,
    pub backend: String,
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

fn validate_resource_id(value: &str) -> Result<(), ProtocolError> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ProtocolError::InvalidJson);
    }
    Ok(())
}

fn validate_guest_path(value: &str) -> Result<(), ProtocolError> {
    validate_string(value)?;
    if !value.starts_with('/')
        || value.contains(['\\', '\0'])
        || (value.len() > 1 && value.ends_with('/'))
        || value.split('/').any(|part| part == "." || part == "..")
        || value.contains("//")
    {
        return Err(ProtocolError::InvalidJson);
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
    fn request_surface_has_no_trusted_runtime_fields() {
        let info: Request = parse_control(br#"{"op":{"type":"get_service_info"}}"#).unwrap();
        assert!(matches!(info.op, RequestOp::GetServiceInfo {}));
        let sandbox = br#"{"op":{"type":"start_sandbox","cpus":2,"memory_mib":2048,"disk_mib":4096,"mounts":[],"ports":[]}}"#;
        let request: Request = parse_control(sandbox).unwrap();
        request.validate().unwrap();
        let forbidden = br#"{"op":{"type":"start_sandbox","cpus":2,"memory_mib":2048,"disk_mib":4096,"mounts":[],"ports":[],"data_dir":"C:\\caller"}}"#;
        assert_eq!(
            parse_control::<Request>(forbidden),
            Err(ProtocolError::InvalidJson)
        );
    }

    #[test]
    fn sandbox_request_bounds_and_resource_ids_are_strict() {
        let oversized = Request {
            deadline_ms: None,
            op: RequestOp::StartSandbox {
                cpus: 17,
                memory_mib: 2048,
                disk_mib: 4096,
                mounts: Vec::new(),
                ports: Vec::new(),
                network: None,
            },
        };
        assert_eq!(oversized.validate(), Err(ProtocolError::InvalidJson));
        let stop = Request {
            deadline_ms: None,
            op: RequestOp::StopSandbox {
                sandbox_id: "not-an-id".to_string(),
            },
        };
        assert_eq!(stop.validate(), Err(ProtocolError::InvalidJson));
        let deadline = Request {
            deadline_ms: Some(0),
            op: RequestOp::HealthCheck {},
        };
        assert_eq!(deadline.validate(), Err(ProtocolError::InvalidJson));
    }

    #[test]
    fn exec_contract_is_bounded_and_rejects_host_style_paths() {
        let request = Request {
            deadline_ms: Some(30_000),
            op: RequestOp::Exec {
                sandbox_id: "0123456789abcdef0123456789abcdef".to_string(),
                command: ServiceCommand::Argv(ArgvCommand {
                    argv: vec!["printf".to_string(), "ok".to_string()],
                }),
                cwd: Some("/workspace".to_string()),
                env: BTreeMap::new(),
            },
        };
        request.validate().unwrap();
        let mut invalid = request;
        if let RequestOp::Exec { cwd, .. } = &mut invalid.op {
            *cwd = Some(r"C:\\caller".to_string());
        }
        assert_eq!(invalid.validate(), Err(ProtocolError::InvalidJson));
    }
}
