use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    AccessDenied,
    ClientNotTrusted,
    ServerNotTrusted,
    ServiceUnavailable,
    ServiceDraining,
    IncompatibleProtocol,
    LedgerSchemaIncompatible,
    ProtocolError,
    InvalidRequest,
    InvalidSequence,
    MessageTooLarge,
    DuplicateRequest,
    RequestNotActive,
    ResourceNotFound,
    QuotaExceeded,
    DeadlineExceeded,
    Cancelled,
    OutputLimit,
    OutputBackpressure,
    PathPolicyDenied,
    PathChanged,
    MountPathBecameUnsafe,
    MountConflict,
    MountUnavailable,
    NetworkPolicyDenied,
    PortIsolationUnavailable,
    BundleInvalid,
    InternalError,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorEnvelope {
    pub code: ErrorCode,
    pub message: String,
    pub retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u32>,
    pub correlation_id: String,
}

impl ErrorEnvelope {
    pub fn safe(code: ErrorCode, correlation_id: impl Into<String>) -> Self {
        let (message, retryable) = match code {
            ErrorCode::ServiceUnavailable => ("The LocalSandbox service is unavailable.", true),
            ErrorCode::ServiceDraining => ("The LocalSandbox service is stopping.", true),
            ErrorCode::IncompatibleProtocol => {
                ("SeaWork and LocalSandbox require an update.", false)
            }
            ErrorCode::PortIsolationUnavailable => ("Isolated host ports are unavailable.", false),
            ErrorCode::AccessDenied | ErrorCode::ClientNotTrusted => ("Access was denied.", false),
            ErrorCode::InvalidRequest | ErrorCode::ProtocolError => {
                ("The request was invalid.", false)
            }
            _ => ("The LocalSandbox operation failed.", false),
        };
        Self {
            code,
            message: message.to_string(),
            retryable,
            retry_after_ms: None,
            correlation_id: correlation_id.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    InvalidMagic,
    InvalidHeaderVersion,
    InvalidKind,
    InvalidFlags,
    MessageTooLarge,
    TruncatedFrame,
    InvalidUtf8,
    JsonTooDeep,
    InvalidJson,
    InvalidVersionRange,
    IncompatibleProtocol,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidMagic => "invalid frame magic",
            Self::InvalidHeaderVersion => "invalid header version",
            Self::InvalidKind => "invalid frame kind",
            Self::InvalidFlags => "unknown frame flags",
            Self::MessageTooLarge => "message exceeds its size limit",
            Self::TruncatedFrame => "frame is truncated",
            Self::InvalidUtf8 => "control payload is not UTF-8",
            Self::JsonTooDeep => "control JSON exceeds nesting limit",
            Self::InvalidJson => "control payload does not match its schema",
            Self::InvalidVersionRange => "protocol version range is invalid",
            Self::IncompatibleProtocol => "protocol ranges do not intersect",
        })
    }
}

impl std::error::Error for ProtocolError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_errors_do_not_echo_internal_details() {
        let envelope = ErrorEnvelope::safe(ErrorCode::InternalError, "test-correlation");
        let json = serde_json::to_string(&envelope).unwrap();
        assert!(!json.contains("password"));
        assert!(!json.contains("path"));
        assert_eq!(envelope.message, "The LocalSandbox operation failed.");
    }
}
