pub mod error;
pub mod frame;
pub mod limits;
pub mod message;
pub mod version;

pub use error::{ErrorCode, ErrorEnvelope, ProtocolError};
pub use frame::{
    decode_stream_payload, encode_stream_payload, Correlation, Frame, FrameHeader, FrameKind,
};
pub use message::{
    parse_control, ArgvCommand, Cancel, CapabilityHealth, Close, CloseCode, Event, Health,
    HealthState, Hello, HelloReply, Request, RequestOp, Response, ResponseValue, SelectedMount,
    ServiceCommand, ServiceDirEntry, ServiceFileStat, ServiceHostScope,
    ServiceHttpsInterceptionSpec, ServiceInfo, ServiceMountSpec, ServiceNetworkSpec,
    ServicePortSpec, ServiceRequestHeaderSpec, ServiceSecretSpec, ShellCommand, WatchChange,
    WindowUpdate,
};
pub use version::{
    negotiate, HexU64, ProtocolRange, ProtocolVersion, CANCELLATION_COMMIT_MIN_MINOR,
    CLIENT_FEATURE_BITS, CURRENT, FEATURE_HTTPS_INTERCEPTION, FEATURE_NETWORK_EGRESS,
    FEATURE_NETWORK_SECRETS, START_REPLAY_MIN_MINOR, SUPPORTED,
};
