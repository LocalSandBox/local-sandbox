use std::fmt;

#[derive(Debug)]
pub enum ClientError {
    UnsupportedPlatform,
    ServiceUnavailable(String),
    ServerNotTrusted(String),
    IncompatibleProtocol,
    Service(lsb_service_proto::ErrorEnvelope),
    Protocol(String),
    Io(std::io::Error),
}

impl fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => {
                formatter.write_str("SeaWork service is supported only on Windows")
            }
            Self::ServiceUnavailable(_) => {
                formatter.write_str("LocalSandbox service is unavailable")
            }
            Self::ServerNotTrusted(_) => {
                formatter.write_str("LocalSandbox service identity could not be verified")
            }
            Self::IncompatibleProtocol => {
                formatter.write_str("SeaWork and LocalSandbox protocol versions are incompatible")
            }
            Self::Service(error) => formatter.write_str(&error.message),
            Self::Protocol(_) => formatter.write_str("LocalSandbox service protocol error"),
            Self::Io(error) => write!(formatter, "LocalSandbox service I/O error: {error}"),
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ClientError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<lsb_service_proto::ProtocolError> for ClientError {
    fn from(value: lsb_service_proto::ProtocolError) -> Self {
        Self::Protocol(value.to_string())
    }
}

impl From<serde_json::Error> for ClientError {
    fn from(value: serde_json::Error) -> Self {
        Self::Protocol(value.to_string())
    }
}
