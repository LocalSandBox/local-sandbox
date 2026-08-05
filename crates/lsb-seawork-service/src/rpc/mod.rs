pub mod file;
pub mod process;
pub mod sandbox;
pub mod watch;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RpcError {
    code: lsb_service_proto::ErrorCode,
    mount_message: Option<String>,
}

impl RpcError {
    pub(crate) fn mount(code: lsb_service_proto::ErrorCode, message: impl Into<String>) -> Self {
        debug_assert!(matches!(
            code,
            lsb_service_proto::ErrorCode::MountInvalid
                | lsb_service_proto::ErrorCode::MountLimitExceeded
        ));
        Self {
            code,
            mount_message: Some(message.into()),
        }
    }

    pub(crate) fn code(&self) -> lsb_service_proto::ErrorCode {
        self.code
    }

    pub(crate) fn mount_message(&self) -> Option<&str> {
        self.mount_message.as_deref()
    }
}

impl From<lsb_service_proto::ErrorCode> for RpcError {
    fn from(code: lsb_service_proto::ErrorCode) -> Self {
        Self {
            code,
            mount_message: None,
        }
    }
}
