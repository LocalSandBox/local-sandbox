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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cancel {
    pub request_id: String,
}

impl Cancel {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        validate_resource_id(&self.request_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowUpdate {
    pub stream_id: String,
    pub credit_bytes: u32,
}

impl WindowUpdate {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        validate_resource_id(&self.stream_id)?;
        if !(1..=4 * 1024 * 1024).contains(&self.credit_bytes) {
            return Err(ProtocolError::InvalidJson);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Event {
    ProcessExited {
        process_id: String,
        exit_code: i32,
    },
    WatchChanged {
        watch_id: String,
        path: String,
        change: WatchChange,
    },
    StreamClosed {
        stream_id: String,
    },
}

impl Event {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::ProcessExited { process_id, .. } => validate_resource_id(process_id),
            Self::WatchChanged { watch_id, path, .. } => {
                validate_resource_id(watch_id)?;
                validate_guest_path(path)
            }
            Self::StreamClosed { stream_id } => validate_resource_id(stream_id),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchChange {
    Created,
    Modified,
    Removed,
    Renamed,
    Overflow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Close {
    pub code: CloseCode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloseCode {
    Normal,
    ProtocolError,
    ServiceDraining,
    SessionClosed,
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
            | RequestOp::CloseSession {}
            | RequestOp::PrepareUninstall {} => {}
            RequestOp::PrepareUpdate {
                target_bundle,
                target_protocol_range,
            } => {
                validate_string(target_bundle)?;
                if target_bundle.is_empty() || target_bundle.len() > 128 {
                    return Err(ProtocolError::InvalidJson);
                }
                target_protocol_range.validate()?;
            }
            RequestOp::CommitUpdate { update_id } | RequestOp::AbortUpdate { update_id } => {
                validate_resource_id(update_id)?;
            }
            RequestOp::StartSandbox {
                client_instance_id,
                from,
                cpus,
                memory_mib,
                disk_mib,
                mounts,
                ports,
                network,
            } => {
                if let Some(value) = client_instance_id {
                    validate_legacy_start_hint(value)?;
                }
                if let Some(value) = from {
                    validate_legacy_start_hint(value)?;
                }
                if !(1..=8).contains(cpus)
                    || !(512..=8 * 1024).contains(memory_mib)
                    || !(1024..=32 * 1024).contains(disk_mib)
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
                    if network.secrets.len() > 64 {
                        return Err(ProtocolError::InvalidJson);
                    }
                    for (name, secret) in &network.secrets {
                        validate_string(name)?;
                        validate_string(&secret.value)?;
                        if !valid_environment_name(name)
                            || secret.value.is_empty()
                            || secret.hosts.is_empty()
                            || secret.hosts.len() > 64
                        {
                            return Err(ProtocolError::InvalidJson);
                        }
                        for host in &secret.hosts {
                            validate_string(host)?;
                        }
                    }
                    if let Some(interception) = &network.https_interception {
                        if interception.request_headers.len() > 64 {
                            return Err(ProtocolError::InvalidJson);
                        }
                        for header in &interception.request_headers {
                            validate_string(&header.name)?;
                            validate_string(&header.value)?;
                            validate_host_scope(&header.hosts)?;
                        }
                    }
                }
            }
            RequestOp::StopSandbox { sandbox_id } => validate_resource_id(sandbox_id)?,
            RequestOp::Exec {
                sandbox_id,
                command,
                cwd,
                env,
            }
            | RequestOp::Spawn {
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
            RequestOp::KillProcess { process_id } => validate_resource_id(process_id)?,
            RequestOp::Watch {
                sandbox_id, path, ..
            } => {
                validate_resource_id(sandbox_id)?;
                validate_guest_path(path)?;
            }
            RequestOp::StopWatch { watch_id } => validate_resource_id(watch_id)?,
            RequestOp::Mkdir {
                sandbox_id, path, ..
            }
            | RequestOp::ReadDir { sandbox_id, path }
            | RequestOp::Stat { sandbox_id, path }
            | RequestOp::Remove {
                sandbox_id, path, ..
            }
            | RequestOp::Exists { sandbox_id, path }
            | RequestOp::ReadFile { sandbox_id, path } => {
                validate_resource_id(sandbox_id)?;
                validate_guest_path(path)?;
            }
            RequestOp::WriteFile {
                sandbox_id,
                path,
                stream_id,
                length,
            } => {
                validate_resource_id(sandbox_id)?;
                validate_guest_path(path)?;
                validate_resource_id(stream_id)?;
                if *length as usize > crate::limits::MAX_FILE_TRANSFER_BYTES {
                    return Err(ProtocolError::MessageTooLarge);
                }
            }
            RequestOp::Rename {
                sandbox_id,
                old_path,
                new_path,
            } => {
                validate_resource_id(sandbox_id)?;
                validate_guest_path(old_path)?;
                validate_guest_path(new_path)?;
            }
            RequestOp::Copy {
                sandbox_id,
                src,
                dst,
                ..
            } => {
                validate_resource_id(sandbox_id)?;
                validate_guest_path(src)?;
                validate_guest_path(dst)?;
            }
            RequestOp::Chmod {
                sandbox_id,
                path,
                mode,
            } => {
                validate_resource_id(sandbox_id)?;
                validate_guest_path(path)?;
                if *mode > 0o7777 {
                    return Err(ProtocolError::InvalidJson);
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
        /// Caller correlation/cache hint. The service never derives a path or resource id from it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client_instance_id: Option<String>,
        /// Legacy checkpoint selector, accepted only to return CHECKPOINT_UNSUPPORTED.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        from: Option<String>,
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
    Spawn {
        sandbox_id: String,
        command: ServiceCommand,
        #[serde(skip_serializing_if = "Option::is_none")]
        cwd: Option<String>,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        env: BTreeMap<String, String>,
    },
    KillProcess {
        process_id: String,
    },
    Watch {
        sandbox_id: String,
        path: String,
        recursive: bool,
    },
    StopWatch {
        watch_id: String,
    },
    Mkdir {
        sandbox_id: String,
        path: String,
        recursive: bool,
    },
    ReadDir {
        sandbox_id: String,
        path: String,
    },
    Stat {
        sandbox_id: String,
        path: String,
    },
    Remove {
        sandbox_id: String,
        path: String,
        recursive: bool,
    },
    Rename {
        sandbox_id: String,
        old_path: String,
        new_path: String,
    },
    Copy {
        sandbox_id: String,
        src: String,
        dst: String,
        recursive: bool,
    },
    Chmod {
        sandbox_id: String,
        path: String,
        mode: u32,
    },
    Exists {
        sandbox_id: String,
        path: String,
    },
    ReadFile {
        sandbox_id: String,
        path: String,
    },
    WriteFile {
        sandbox_id: String,
        path: String,
        stream_id: String,
        length: u32,
    },
    PrepareUpdate {
        target_bundle: String,
        target_protocol_range: ProtocolRange,
    },
    CommitUpdate {
        update_id: String,
    },
    AbortUpdate {
        update_id: String,
    },
    PrepareUninstall {},
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

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceNetworkSpec {
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    #[serde(default)]
    pub secrets: BTreeMap<String, ServiceSecretSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub https_interception: Option<ServiceHttpsInterceptionSpec>,
}

impl ServiceNetworkSpec {
    pub fn required_feature_bits(&self) -> u64 {
        let mut required = crate::FEATURE_NETWORK_EGRESS;
        if !self.secrets.is_empty() {
            required |= crate::FEATURE_NETWORK_SECRETS;
        }
        if self.https_interception.is_some() {
            required |= crate::FEATURE_HTTPS_INTERCEPTION;
        }
        required
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceSecretSpec {
    pub value: String,
    pub hosts: Vec<String>,
}

impl std::fmt::Debug for ServiceSecretSpec {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ServiceSecretSpec")
            .field("value", &"<redacted>")
            .field("hosts", &self.hosts)
            .finish()
    }
}

impl Drop for ServiceSecretSpec {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.value);
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceHttpsInterceptionSpec {
    pub enabled: bool,
    #[serde(default)]
    pub request_headers: Vec<ServiceRequestHeaderSpec>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceRequestHeaderSpec {
    pub name: String,
    pub value: String,
    #[serde(default)]
    pub hosts: ServiceHostScope,
}

impl std::fmt::Debug for ServiceRequestHeaderSpec {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ServiceRequestHeaderSpec")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .field("hosts", &self.hosts)
            .finish()
    }
}

impl Drop for ServiceRequestHeaderSpec {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.value);
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceHostScope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny: Option<Vec<String>>,
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
    ProcessStarted {
        process_id: String,
        stdout_stream_id: String,
        stderr_stream_id: String,
    },
    WatchStarted {
        watch_id: String,
    },
    Directory {
        entries: Vec<ServiceDirEntry>,
    },
    FileStat {
        stat: ServiceFileStat,
    },
    Exists {
        exists: bool,
    },
    FileRead {
        stream_id: String,
        length: u32,
    },
    UpdatePrepared {
        update_id: String,
    },
    UninstallPrepared {
        clean: bool,
        quarantine_ids: Vec<String>,
    },
    Empty {},
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceDirEntry {
    pub name: String,
    pub entry_type: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceFileStat {
    pub size: u64,
    pub mode: u32,
    pub mtime: u64,
    pub is_dir: bool,
    pub is_file: bool,
    pub is_symlink: bool,
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

fn valid_environment_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn validate_host_scope(scope: &ServiceHostScope) -> Result<(), ProtocolError> {
    for patterns in [&scope.allow, &scope.deny].into_iter().flatten() {
        if patterns.is_empty() || patterns.len() > 64 {
            return Err(ProtocolError::InvalidJson);
        }
        for pattern in patterns {
            validate_string(pattern)?;
        }
    }
    Ok(())
}

fn validate_legacy_start_hint(value: &str) -> Result<(), ProtocolError> {
    validate_string(value)?;
    if value.is_empty()
        || value.len() > 128
        || value.chars().any(char::is_control)
        || value.trim() != value
    {
        return Err(ProtocolError::InvalidJson);
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
    use crate::SUPPORTED;

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
        let sandbox = br#"{"op":{"type":"start_sandbox","client_instance_id":"seawork-session","from":"legacy-checkpoint","cpus":2,"memory_mib":2048,"disk_mib":4096,"mounts":[],"ports":[]}}"#;
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
                client_instance_id: None,
                from: None,
                cpus: 9,
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
    fn network_contract_is_bounded_feature_gated_and_redacted() {
        let network = ServiceNetworkSpec {
            allowed_hosts: vec!["api.example.test".to_string()],
            secrets: BTreeMap::from([(
                "API_TOKEN".to_string(),
                ServiceSecretSpec {
                    value: "never-log-secret".to_string(),
                    hosts: vec!["api.example.test".to_string()],
                },
            )]),
            https_interception: Some(ServiceHttpsInterceptionSpec {
                enabled: true,
                request_headers: vec![ServiceRequestHeaderSpec {
                    name: "Authorization".to_string(),
                    value: "never-log-header".to_string(),
                    hosts: ServiceHostScope {
                        allow: Some(vec!["api.example.test".to_string()]),
                        deny: None,
                    },
                }],
            }),
        };
        assert_eq!(network.required_feature_bits(), crate::CLIENT_FEATURE_BITS);
        let request = Request {
            deadline_ms: None,
            op: RequestOp::StartSandbox {
                client_instance_id: None,
                from: None,
                cpus: 2,
                memory_mib: 2048,
                disk_mib: 4096,
                mounts: Vec::new(),
                ports: Vec::new(),
                network: Some(network),
            },
        };
        request.validate().unwrap();
        let debug = format!("{request:?}");
        assert!(!debug.contains("never-log-secret"));
        assert!(!debug.contains("never-log-header"));
        assert!(debug.contains("<redacted>"));

        let invalid = br#"{"op":{"type":"start_sandbox","cpus":2,"memory_mib":2048,"disk_mib":4096,"mounts":[],"ports":[],"network":{"allowed_hosts":[],"secrets":{"TOKEN":{"value":"secret","hosts":[]}}}}}"#;
        let invalid: Request = parse_control(invalid).unwrap();
        assert_eq!(invalid.validate(), Err(ProtocolError::InvalidJson));
    }

    #[test]
    fn legacy_start_hints_are_bounded_and_do_not_enable_runtime_paths() {
        let valid = Request {
            deadline_ms: None,
            op: RequestOp::StartSandbox {
                client_instance_id: Some("seawork-session-1".to_string()),
                from: Some("checkpoint-name".to_string()),
                cpus: 2,
                memory_mib: 2048,
                disk_mib: 4096,
                mounts: Vec::new(),
                ports: Vec::new(),
                network: None,
            },
        };
        valid.validate().unwrap();

        let mut invalid = valid;
        if let RequestOp::StartSandbox {
            client_instance_id, ..
        } = &mut invalid.op
        {
            *client_instance_id = Some("x".repeat(129));
        }
        assert_eq!(invalid.validate(), Err(ProtocolError::InvalidJson));

        let forbidden = br#"{"op":{"type":"start_sandbox","cpus":2,"memory_mib":2048,"disk_mib":4096,"mounts":[],"ports":[],"data_dir":"C:\\caller"}}"#;
        assert_eq!(
            parse_control::<Request>(forbidden),
            Err(ProtocolError::InvalidJson)
        );
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

    #[test]
    fn spawn_and_kill_use_strict_owner_bound_handles() {
        let spawn = Request {
            deadline_ms: Some(30_000),
            op: RequestOp::Spawn {
                sandbox_id: "0123456789abcdef0123456789abcdef".to_string(),
                command: ServiceCommand::Shell(ShellCommand {
                    shell: "sleep 10".to_string(),
                }),
                cwd: Some("/workspace".to_string()),
                env: BTreeMap::new(),
            },
        };
        spawn.validate().unwrap();
        let kill = Request {
            deadline_ms: None,
            op: RequestOp::KillProcess {
                process_id: "not-a-handle".to_string(),
            },
        };
        assert_eq!(kill.validate(), Err(ProtocolError::InvalidJson));
    }

    #[test]
    fn watch_contract_uses_canonical_paths_and_opaque_handles() {
        let watch = Request {
            deadline_ms: None,
            op: RequestOp::Watch {
                sandbox_id: "0123456789abcdef0123456789abcdef".to_string(),
                path: "/workspace".to_string(),
                recursive: true,
            },
        };
        watch.validate().unwrap();

        let invalid_path = Request {
            deadline_ms: None,
            op: RequestOp::Watch {
                sandbox_id: "0123456789abcdef0123456789abcdef".to_string(),
                path: "/workspace/../etc".to_string(),
                recursive: false,
            },
        };
        assert_eq!(invalid_path.validate(), Err(ProtocolError::InvalidJson));

        let stop = Request {
            deadline_ms: None,
            op: RequestOp::StopWatch {
                watch_id: "not-a-handle".to_string(),
            },
        };
        assert_eq!(stop.validate(), Err(ProtocolError::InvalidJson));
    }

    #[test]
    fn guest_file_contract_rejects_noncanonical_paths_and_modes() {
        let request = Request {
            deadline_ms: None,
            op: RequestOp::Rename {
                sandbox_id: "0123456789abcdef0123456789abcdef".to_string(),
                old_path: "/workspace/a".to_string(),
                new_path: "/workspace/b".to_string(),
            },
        };
        request.validate().unwrap();
        let invalid = Request {
            deadline_ms: None,
            op: RequestOp::Chmod {
                sandbox_id: "0123456789abcdef0123456789abcdef".to_string(),
                path: "/workspace/../etc".to_string(),
                mode: 0o10_000,
            },
        };
        assert_eq!(invalid.validate(), Err(ProtocolError::InvalidJson));
    }

    #[test]
    fn write_file_is_bounded_by_compiled_transfer_limit() {
        let request = Request {
            deadline_ms: None,
            op: RequestOp::WriteFile {
                sandbox_id: "0123456789abcdef0123456789abcdef".to_string(),
                path: "/workspace/output".to_string(),
                stream_id: "fedcba9876543210fedcba9876543210".to_string(),
                length: (crate::limits::MAX_FILE_TRANSFER_BYTES + 1) as u32,
            },
        };
        assert_eq!(request.validate(), Err(ProtocolError::MessageTooLarge));
    }

    #[test]
    fn stream_controls_and_events_are_closed_and_bounded() {
        let update = WindowUpdate {
            stream_id: "0123456789abcdef0123456789abcdef".to_string(),
            credit_bytes: 256 * 1024,
        };
        update.validate().unwrap();
        let mut invalid = update;
        invalid.credit_bytes = 0;
        assert_eq!(invalid.validate(), Err(ProtocolError::InvalidJson));

        let event = Event::WatchChanged {
            watch_id: "fedcba9876543210fedcba9876543210".to_string(),
            path: "/workspace/file".to_string(),
            change: WatchChange::Modified,
        };
        event.validate().unwrap();
        assert_eq!(
            parse_control::<Close>(br#"{"code":"unknown"}"#),
            Err(ProtocolError::InvalidJson)
        );
    }

    #[test]
    fn administrator_contracts_are_bounded_and_path_free() {
        let prepare = Request {
            deadline_ms: None,
            op: RequestOp::PrepareUpdate {
                target_bundle: "0.4.7-windows-x86_64".to_string(),
                target_protocol_range: SUPPORTED,
            },
        };
        prepare.validate().unwrap();
        let commit = Request {
            deadline_ms: None,
            op: RequestOp::CommitUpdate {
                update_id: "0123456789abcdef0123456789abcdef".to_string(),
            },
        };
        commit.validate().unwrap();
        let invalid: ProtocolError = parse_control::<Request>(
            br#"{"op":{"type":"prepare_update","target_bundle":"next","target_protocol_range":{"major":1,"min_minor":2,"max_minor":1},"image_path":"C:\\caller.exe"}}"#,
        )
        .unwrap_err();
        assert_eq!(invalid, ProtocolError::InvalidJson);
    }
}
