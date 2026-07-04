use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Binary framing for all vsock communication.
///
/// Frame format: `[u32 BE length][u8 type][payload...]`
/// Length = size of type byte + payload (excludes the 4-byte length prefix).
/// Max frame size: 1 MB.
pub mod frame;

pub const PROTOCOL_VERSION: u16 = 1;
pub const CAP_FILE_RANGE_IO: &str = "file_range_io";
pub const FILE_TRANSFER_CHUNK_SIZE: usize = 512 * 1024;

// --- Guest lifecycle protocol ---

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestTransport {
    Vsock,
    VirtioSerial,
}

/// Sent by the guest after minimal agent initialization is complete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestReady {
    pub protocol_version: u16,
    pub transport: GuestTransport,
    pub guest_version: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

impl GuestReady {
    pub fn new(transport: GuestTransport, guest_version: impl Into<String>) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            transport,
            guest_version: guest_version.into(),
            capabilities: Vec::new(),
        }
    }
}

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdin_closed: Option<bool>,
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
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MountRequest {
    /// Mount a VirtioFS source as the lower layer of a tmpfs-backed overlay.
    Overlay { source: String, target: String },
    /// Mount a VirtioFS source directly with libc mount flags.
    Direct {
        source: String,
        target: String,
        flags: u64,
    },
}

/// Sent by the guest in response to a MountRequest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountResponse {
    pub source: String,
    pub target: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// --- File I/O protocol ---

#[derive(Serialize, Deserialize)]
pub struct ReadFileRequest {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub len: Option<u64>,
}

#[derive(Serialize, Deserialize)]
pub struct WriteFileRequest {
    pub path: String,
    pub len: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub truncate: Option<bool>,
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
pub const VIRTIO_SERIAL_CONTROL_PORT_NAME: &str = "org.localsandbox.control";

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::Cursor;

    use super::{
        ExecRequest, GuestReady, GuestTransport, MountRequest, ReadFileRequest, WriteFileRequest,
        PROTOCOL_VERSION,
    };
    use crate::frame;

    #[test]
    fn guest_ready_round_trips_with_empty_capabilities() {
        let ready = GuestReady::new(GuestTransport::VirtioSerial, "0.5.2-test");

        let json = serde_json::to_string(&ready).expect("guest ready should serialize");
        let decoded: GuestReady =
            serde_json::from_str(&json).expect("guest ready should deserialize");

        assert_eq!(decoded.protocol_version, PROTOCOL_VERSION);
        assert_eq!(decoded.transport, GuestTransport::VirtioSerial);
        assert_eq!(decoded.guest_version, "0.5.2-test");
        assert!(decoded.capabilities.is_empty());
    }

    #[test]
    fn guest_ready_frame_round_trips() {
        let ready = GuestReady::new(GuestTransport::VirtioSerial, "0.5.2-test");
        let mut stream = Cursor::new(Vec::new());

        frame::send_json(&mut stream, frame::GUEST_READY, &ready)
            .expect("guest ready frame should write");
        stream.set_position(0);

        let (msg_type, payload) = frame::read_frame(&mut stream)
            .expect("guest ready frame should read")
            .expect("guest ready frame should be present");
        let decoded: GuestReady =
            serde_json::from_slice(&payload).expect("guest ready payload should decode");

        assert_eq!(msg_type, frame::GUEST_READY);
        assert_eq!(decoded, ready);
    }

    #[test]
    fn mount_request_round_trips_overlay() {
        let json = r#"{"type":"overlay","source":"mount0","target":"/workspace"}"#;
        let req: MountRequest = serde_json::from_str(json).expect("mount request should parse");
        match req {
            MountRequest::Overlay { source, target } => {
                assert_eq!(source, "mount0");
                assert_eq!(target, "/workspace");
            }
            MountRequest::Direct { .. } => panic!("expected overlay request"),
        }
    }

    #[test]
    fn mount_request_round_trips_direct_flags() {
        let req = MountRequest::Direct {
            source: "mount1".into(),
            target: "/workspace".into(),
            flags: 1,
        };
        let json = serde_json::to_string(&req).expect("mount request should serialize");
        let req2: MountRequest =
            serde_json::from_str(&json).expect("mount request should deserialize");
        match req2 {
            MountRequest::Direct {
                source,
                target,
                flags,
            } => {
                assert_eq!(source, "mount1");
                assert_eq!(target, "/workspace");
                assert_eq!(flags, 1);
            }
            MountRequest::Overlay { .. } => panic!("expected direct request"),
        }
    }

    #[test]
    fn exec_request_defaults_stdin_closed_when_field_is_absent() {
        let request: ExecRequest =
            serde_json::from_str(r#"{"argv":["/bin/true"]}"#).expect("exec request");

        assert_eq!(request.argv, ["/bin/true"]);
        assert_eq!(request.env, HashMap::new());
        assert_eq!(request.stdin_closed, None);
    }

    #[test]
    fn file_range_requests_omit_optional_fields_when_absent() {
        let read = ReadFileRequest {
            path: "/tmp/file".to_string(),
            offset: None,
            len: None,
        };
        let write = WriteFileRequest {
            path: "/tmp/file".to_string(),
            len: 5,
            offset: None,
            truncate: None,
        };

        let read_json = serde_json::to_string(&read).expect("read request should serialize");
        let write_json = serde_json::to_string(&write).expect("write request should serialize");

        assert_eq!(read_json, r#"{"path":"/tmp/file"}"#);
        assert_eq!(write_json, r#"{"path":"/tmp/file","len":5}"#);
    }

    #[test]
    fn file_range_requests_round_trip_offsets() {
        let read = ReadFileRequest {
            path: "/tmp/file".to_string(),
            offset: Some(1024),
            len: Some(4096),
        };
        let write = WriteFileRequest {
            path: "/tmp/file".to_string(),
            len: 4096,
            offset: Some(1024),
            truncate: Some(false),
        };

        let read_json = serde_json::to_string(&read).expect("read request should serialize");
        let write_json = serde_json::to_string(&write).expect("write request should serialize");

        assert!(read_json.contains(r#""offset":1024"#));
        assert!(read_json.contains(r#""len":4096"#));
        assert!(write_json.contains(r#""offset":1024"#));
        assert!(write_json.contains(r#""truncate":false"#));
    }
}
