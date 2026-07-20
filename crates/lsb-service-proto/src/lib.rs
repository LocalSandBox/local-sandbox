pub mod error;
pub mod frame;
pub mod limits;
pub mod message;
pub mod version;

#[cfg(feature = "development-service")]
pub const SERVICE_NAME: &str = "LocalSandboxSeaWorkDev";
#[cfg(not(feature = "development-service"))]
pub const SERVICE_NAME: &str = "LocalSandboxSeaWork";

#[cfg(feature = "development-service")]
pub const PIPE_NAME: &str = r"\\.\pipe\LocalSandbox.SeaWork.Dev.v1";
#[cfg(not(feature = "development-service"))]
pub const PIPE_NAME: &str = r"\\.\pipe\LocalSandbox.SeaWork.v1";

#[cfg(feature = "development-service")]
pub const STATE_DIRECTORY_NAME: &str = "SeaWorkDev";
#[cfg(not(feature = "development-service"))]
pub const STATE_DIRECTORY_NAME: &str = "SeaWork";

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

#[cfg(test)]
mod endpoint_tests {
    use super::*;

    #[test]
    fn endpoint_identity_matches_the_selected_build_flavor() {
        #[cfg(feature = "development-service")]
        assert_eq!(
            (SERVICE_NAME, PIPE_NAME, STATE_DIRECTORY_NAME),
            (
                "LocalSandboxSeaWorkDev",
                r"\\.\pipe\LocalSandbox.SeaWork.Dev.v1",
                "SeaWorkDev"
            )
        );
        #[cfg(not(feature = "development-service"))]
        assert_eq!(
            (SERVICE_NAME, PIPE_NAME, STATE_DIRECTORY_NAME),
            (
                "LocalSandboxSeaWork",
                r"\\.\pipe\LocalSandbox.SeaWork.v1",
                "SeaWork"
            )
        );
    }
}
