mod error;
mod stream;

#[cfg(windows)]
mod authenticode;
#[cfg(windows)]
mod connection;
#[cfg(windows)]
mod package_acl;
#[cfg(windows)]
mod pipe;

pub use error::ClientError;
pub use lsb_service_proto::{PIPE_NAME, SERVICE_NAME};
pub use stream::CreditWindow;

#[cfg(windows)]
pub use connection::{
    ExecOptions, RemoteCommand, RemoteExecOperation, RemoteExecResult, RemoteProcess,
    RemoteSandbox, RemoteWatch, RemoteWatchEvent, ServiceClient, StartSandboxOptions,
    UninstallPreparation,
};

#[derive(Debug, Clone, Copy)]
pub struct ConnectOptions {
    pub timeout: std::time::Duration,
}

impl Default for ConnectOptions {
    fn default() -> Self {
        Self {
            timeout: std::time::Duration::from_secs(10),
        }
    }
}

#[cfg(windows)]
pub async fn connect(options: ConnectOptions) -> Result<ServiceClient, ClientError> {
    ServiceClient::connect(options).await
}

#[cfg(not(windows))]
pub struct ServiceClient;

#[cfg(not(windows))]
pub async fn connect(_options: ConnectOptions) -> Result<ServiceClient, ClientError> {
    Err(ClientError::UnsupportedPlatform)
}
