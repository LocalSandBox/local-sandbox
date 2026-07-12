use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Binary framing for all vsock communication.
///
/// Frame format: `[u32 BE length][u8 type][payload...]`
/// Length = size of type byte + payload (excludes the 4-byte length prefix).
/// Max frame size: 1 MB.
pub mod frame;
pub mod mount_cache;
pub mod mux;

pub use mount_cache::{
    MountSnapshotEncodingError, MountSnapshotKey, MountSnapshotKeyEncoder,
    MOUNT_CACHE_KEY_ABI_VERSION, MOUNT_IMPORT_DIRECTORY_MODE, MOUNT_IMPORT_FILE_MODE,
    MOUNT_IMPORT_SEMANTICS_VERSION,
};

pub const PROTOCOL_VERSION: u16 = 1;
pub const CAP_FILE_RANGE_IO: &str = "file_range_io";
pub const CAP_PORT_FORWARD: &str = "port_forward";
pub const CAP_CIFS_MOUNT: &str = "cifs_mount";
pub const CAP_SESSION_MUX: &str = "session_mux";
pub const CAP_DEFERRED_FILE_SYNC: &str = "deferred_file_sync";
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardRequest {
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<u64>,
}

/// Sent by the guest in response to a ForwardRequest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForwardPayloadError;

impl std::fmt::Display for ForwardPayloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("forward payload is shorter than the 8-byte session id")
    }
}

impl std::error::Error for ForwardPayloadError {}

pub fn encode_forward_payload(session_id: u64, data: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(8 + data.len());
    payload.extend_from_slice(&session_id.to_be_bytes());
    payload.extend_from_slice(data);
    payload
}

pub fn decode_forward_payload(payload: &[u8]) -> Result<(u64, &[u8]), ForwardPayloadError> {
    if payload.len() < 8 {
        return Err(ForwardPayloadError);
    }
    let mut id = [0u8; 8];
    id.copy_from_slice(&payload[..8]);
    Ok((u64::from_be_bytes(id), &payload[8..]))
}

pub fn encode_forward_close(session_id: u64) -> [u8; 8] {
    session_id.to_be_bytes()
}

pub fn decode_forward_close(payload: &[u8]) -> Result<u64, ForwardPayloadError> {
    if payload.len() != 8 {
        return Err(ForwardPayloadError);
    }
    let mut id = [0u8; 8];
    id.copy_from_slice(payload);
    Ok(u64::from_be_bytes(id))
}

// --- Mount protocol ---

/// Sent by the host over vsock to instruct the guest to mount a filesystem.
#[derive(Clone, Serialize, Deserialize)]
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
    /// Mount a Windows SMB/CIFS share directly.
    Smb {
        server: String,
        share: String,
        target: String,
        username: String,
        password: String,
        domain: String,
        read_only: bool,
        uid: u32,
        gid: u32,
        file_mode: u32,
        dir_mode: u32,
        #[serde(default)]
        options: Vec<String>,
    },
}

impl std::fmt::Debug for MountRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Overlay { source, target } => f
                .debug_struct("Overlay")
                .field("source", source)
                .field("target", target)
                .finish(),
            Self::Direct {
                source,
                target,
                flags,
            } => f
                .debug_struct("Direct")
                .field("source", source)
                .field("target", target)
                .field("flags", flags)
                .finish(),
            Self::Smb {
                server,
                share,
                target,
                domain,
                read_only,
                uid,
                gid,
                file_mode,
                dir_mode,
                options,
                ..
            } => f
                .debug_struct("Smb")
                .field("server", server)
                .field("share", share)
                .field("target", target)
                .field("username", &"<redacted>")
                .field("password", &"<redacted>")
                .field("domain", domain)
                .field("read_only", read_only)
                .field("uid", uid)
                .field("gid", gid)
                .field("file_mode", file_mode)
                .field("dir_mode", dir_mode)
                .field("options", options)
                .finish(),
        }
    }
}

impl std::fmt::Display for MountRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Overlay { source, target } => {
                write!(f, "overlay mount source={source} target={target}")
            }
            Self::Direct {
                source,
                target,
                flags,
            } => write!(f, "direct mount source={source} target={target} flags={flags}"),
            Self::Smb {
                server,
                share,
                target,
                domain,
                read_only,
                uid,
                gid,
                file_mode,
                dir_mode,
                options,
                ..
            } => write!(
                f,
                "smb mount server={server} share={share} target={target} username=<redacted> password=<redacted> domain={domain} read_only={read_only} uid={uid} gid={gid} file_mode={file_mode:o} dir_mode={dir_mode:o} options={options:?}"
            ),
        }
    }
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteFileRequest {
    pub path: String,
    pub len: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub truncate: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub defer_sync: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncFsRequest {
    pub path: String,
}

#[derive(Serialize, Deserialize)]
pub struct MkdirRequest {
    pub path: String,
    #[serde(default = "default_true")]
    pub recursive: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
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
pub const VIRTIO_SERIAL_FORWARD_PORT_NAME: &str = "org.localsandbox.forward";

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::Cursor;

    use super::{
        decode_forward_close, decode_forward_payload, encode_forward_close, encode_forward_payload,
        ExecRequest, ForwardRequest, ForwardResponse, GuestReady, GuestTransport, MountRequest,
        ReadFileRequest, SyncFsRequest, WriteFileRequest, CAP_SESSION_MUX, PROTOCOL_VERSION,
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
    fn guest_ready_can_advertise_session_mux_capability() {
        let mut ready = GuestReady::new(GuestTransport::VirtioSerial, "0.5.2-test");
        ready.capabilities.push(CAP_SESSION_MUX.to_string());

        let json = serde_json::to_string(&ready).expect("guest ready should serialize");
        let decoded: GuestReady =
            serde_json::from_str(&json).expect("guest ready should deserialize");

        assert_eq!(decoded.capabilities, [CAP_SESSION_MUX]);
    }

    #[test]
    fn forward_request_round_trips_with_optional_session_id() {
        let request = ForwardRequest {
            port: 8080,
            session_id: Some(42),
        };

        let json = serde_json::to_string(&request).expect("forward request serializes");
        let decoded: ForwardRequest =
            serde_json::from_str(&json).expect("forward request deserializes");

        assert_eq!(decoded, request);
    }

    #[test]
    fn forward_response_round_trips_without_session_id_for_vsock_compatibility() {
        let response = ForwardResponse {
            status: "ok".to_string(),
            message: None,
            session_id: None,
        };

        let json = serde_json::to_string(&response).expect("forward response serializes");
        assert!(!json.contains("session_id"));
        let decoded: ForwardResponse =
            serde_json::from_str(&json).expect("forward response deserializes");

        assert_eq!(decoded, response);
    }

    #[test]
    fn forward_payload_encodes_session_prefix() {
        let payload = encode_forward_payload(0x0102_0304_0506_0708, b"hello");
        let (session_id, data) = decode_forward_payload(&payload).expect("payload should decode");

        assert_eq!(session_id, 0x0102_0304_0506_0708);
        assert_eq!(data, b"hello");
        assert_eq!(
            decode_forward_close(&encode_forward_close(session_id)).expect("close decodes"),
            session_id
        );
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
            MountRequest::Direct { .. } | MountRequest::Smb { .. } => {
                panic!("expected overlay request")
            }
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
            MountRequest::Overlay { .. } | MountRequest::Smb { .. } => {
                panic!("expected direct request")
            }
        }
    }

    #[test]
    fn mount_request_round_trips_smb() {
        let req = MountRequest::Smb {
            server: "10.0.0.1".into(),
            share: "lsb-test-m0-abcd".into(),
            target: "/workspace".into(),
            username: "lsb_123456789abc".into(),
            password: "SecretPassword123!".into(),
            domain: "WINHOST".into(),
            read_only: false,
            uid: 0,
            gid: 0,
            file_mode: 0o666,
            dir_mode: 0o777,
            options: vec!["echo_interval=30".into()],
        };

        let json = serde_json::to_string(&req).expect("mount request should serialize");
        assert!(json.contains(r#""type":"smb""#));
        assert!(json.contains("SecretPassword123!"));

        let req2: MountRequest =
            serde_json::from_str(&json).expect("mount request should deserialize");
        match req2 {
            MountRequest::Smb {
                server,
                share,
                target,
                username,
                password,
                domain,
                read_only,
                uid,
                gid,
                file_mode,
                dir_mode,
                options,
            } => {
                assert_eq!(server, "10.0.0.1");
                assert_eq!(share, "lsb-test-m0-abcd");
                assert_eq!(target, "/workspace");
                assert_eq!(username, "lsb_123456789abc");
                assert_eq!(password, "SecretPassword123!");
                assert_eq!(domain, "WINHOST");
                assert!(!read_only);
                assert_eq!(uid, 0);
                assert_eq!(gid, 0);
                assert_eq!(file_mode, 0o666);
                assert_eq!(dir_mode, 0o777);
                assert_eq!(options, ["echo_interval=30"]);
            }
            MountRequest::Overlay { .. } | MountRequest::Direct { .. } => {
                panic!("expected smb request")
            }
        }
    }

    #[test]
    fn mount_request_smb_debug_and_display_redact_password() {
        let req = MountRequest::Smb {
            server: "10.0.0.1".into(),
            share: "lsb-test-m0-abcd".into(),
            target: "/workspace".into(),
            username: "lsb_123456789abc".into(),
            password: "DoNotLeakThisPassword".into(),
            domain: "WINHOST".into(),
            read_only: true,
            uid: 0,
            gid: 0,
            file_mode: 0o644,
            dir_mode: 0o755,
            options: Vec::new(),
        };

        let debug = format!("{req:?}");
        let display = req.to_string();

        assert!(!debug.contains("DoNotLeakThisPassword"));
        assert!(!display.contains("DoNotLeakThisPassword"));
        assert!(!debug.contains("lsb_123456789abc"));
        assert!(!display.contains("lsb_123456789abc"));
        assert!(debug.contains("<redacted>"));
        assert!(display.contains("<redacted>"));
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
            defer_sync: None,
            mode: None,
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
            defer_sync: None,
            mode: None,
        };

        let read_json = serde_json::to_string(&read).expect("read request should serialize");
        let write_json = serde_json::to_string(&write).expect("write request should serialize");

        assert!(read_json.contains(r#""offset":1024"#));
        assert!(read_json.contains(r#""len":4096"#));
        assert!(write_json.contains(r#""offset":1024"#));
        assert!(write_json.contains(r#""truncate":false"#));
    }

    #[test]
    fn deferred_write_and_sync_fs_requests_round_trip() {
        let write = WriteFileRequest {
            path: "/tmp/file".to_string(),
            len: 4096,
            offset: Some(0),
            truncate: Some(true),
            defer_sync: Some(true),
            mode: None,
        };
        let sync = SyncFsRequest {
            path: "/tmp/lsb/mounts".to_string(),
        };

        let write_json = serde_json::to_string(&write).expect("deferred write should serialize");
        let decoded_write: WriteFileRequest =
            serde_json::from_str(&write_json).expect("deferred write should deserialize");
        let sync_json = serde_json::to_string(&sync).expect("sync request should serialize");
        let decoded_sync: SyncFsRequest =
            serde_json::from_str(&sync_json).expect("sync request should deserialize");

        assert!(write_json.contains(r#""defer_sync":true"#));
        assert_eq!(decoded_write.defer_sync, Some(true));
        assert_eq!(decoded_sync, sync);
    }
}
