use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Binary framing for all vsock communication.
///
/// Frame format: `[u32 BE length][u8 type][payload...]`
/// Length = size of type byte + payload (excludes the 4-byte length prefix).
/// Max frame size: 1 MB.
pub mod frame;

// --- Exec protocol ---

#[derive(Serialize, Deserialize)]
pub struct ExecRequest {
    pub argv: Vec<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tty: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cols: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
}

// --- Port forwarding protocol ---

/// A host:guest port mapping for port forwarding over vsock.
#[derive(Debug, Clone)]
pub struct PortMapping {
    pub host_port: u16,
    pub guest_port: u16,
}

/// Sent by the host over vsock to request forwarding to a guest port.
#[derive(Serialize, Deserialize)]
pub struct ForwardRequest {
    pub port: u16,
}

/// Sent by the guest in response to a ForwardRequest.
#[derive(Serialize, Deserialize)]
pub struct ForwardResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

// --- Mount protocol ---

/// Sent by the host over vsock to instruct the guest to mount a virtiofs device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountRequest {
    pub tag: String,
    pub guest_path: String,
    /// When true (default), guest mounts via overlay (writes go to tmpfs).
    /// When false, guest mounts VirtioFS directly (writes go to host).
    #[serde(default = "default_true")]
    pub read_only: bool,
}

/// Sent by the guest in response to a MountRequest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountResponse {
    pub tag: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// --- File I/O protocol ---

#[derive(Serialize, Deserialize)]
pub struct ReadFileRequest {
    pub path: String,
}

#[derive(Serialize, Deserialize)]
pub struct WriteFileRequest {
    pub path: String,
    pub len: u64,
}

#[derive(Serialize, Deserialize)]
pub struct WriteFileResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// --- Filesystem operations protocol ---

#[derive(Serialize, Deserialize)]
pub struct FsOkResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct MkdirRequest {
    pub path: String,
    #[serde(default = "default_true")]
    pub recursive: bool,
}

#[derive(Serialize, Deserialize)]
pub struct ReadDirRequest {
    pub path: String,
}

#[derive(Serialize, Deserialize)]
pub struct DirEntry {
    pub name: String,
    #[serde(rename = "type")]
    pub entry_type: String,
    pub size: u64,
}

#[derive(Serialize, Deserialize)]
pub struct ReadDirResponse {
    pub entries: Vec<DirEntry>,
}

#[derive(Serialize, Deserialize)]
pub struct StatRequest {
    pub path: String,
}

#[derive(Serialize, Deserialize)]
pub struct StatResponse {
    pub size: u64,
    pub mode: u32,
    pub mtime: u64,
    pub is_dir: bool,
    pub is_file: bool,
    pub is_symlink: bool,
}

#[derive(Serialize, Deserialize)]
pub struct RemoveRequest {
    pub path: String,
    #[serde(default)]
    pub recursive: bool,
}

#[derive(Serialize, Deserialize)]
pub struct RenameRequest {
    pub old_path: String,
    pub new_path: String,
}

#[derive(Serialize, Deserialize)]
pub struct CopyRequest {
    pub src: String,
    pub dst: String,
    #[serde(default)]
    pub recursive: bool,
}

#[derive(Serialize, Deserialize)]
pub struct ChmodRequest {
    pub path: String,
    pub mode: u32,
}

// --- File watching protocol ---

#[derive(Serialize, Deserialize)]
pub struct WatchRequest {
    pub path: String,
    #[serde(default = "default_true")]
    pub recursive: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Serialize, Deserialize)]
pub struct WatchEvent {
    pub path: String,
    pub event: String,
}

pub const VSOCK_PORT: u32 = 1024;
pub const VSOCK_PORT_FORWARD: u32 = 1025;

#[cfg(test)]
mod tests {
    use super::MountRequest;

    #[test]
    fn mount_request_defaults_to_read_only() {
        let json = r#"{"tag":"mount0","guest_path":"/workspace"}"#;
        let req: MountRequest = serde_json::from_str(json).expect("mount request should parse");
        assert!(req.read_only);
    }

    #[test]
    fn mount_request_round_trips_rw() {
        let req = MountRequest {
            tag: "mount0".into(),
            guest_path: "/workspace".into(),
            read_only: false,
        };
        let json = serde_json::to_string(&req).expect("mount request should serialize");
        let req2: MountRequest =
            serde_json::from_str(&json).expect("mount request should deserialize");
        assert!(!req2.read_only);
    }
}
