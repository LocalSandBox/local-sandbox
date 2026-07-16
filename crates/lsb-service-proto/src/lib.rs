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
    ServiceCommand, ServiceDirEntry, ServiceFileStat, ServiceInfo, ServiceMountSpec,
    ServiceNetworkSpec, ServicePortSpec, ShellCommand, WatchChange, WindowUpdate,
};
pub use version::{negotiate, HexU64, ProtocolRange, ProtocolVersion, CURRENT, SUPPORTED};
