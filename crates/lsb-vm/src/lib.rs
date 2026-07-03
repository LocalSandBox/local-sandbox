#![forbid(unsafe_code)]

mod sandbox;

pub use lsb_platform::VmState;
pub use lsb_proto::{
    frame, ExecRequest, ForwardRequest, ForwardResponse, MountRequest, MountResponse, PortMapping,
    ReadFileRequest, WriteFileRequest, WriteFileResponse, VSOCK_PORT, VSOCK_PORT_FORWARD,
};
pub use sandbox::{MountConfig, PortForwardHandle, Sandbox, VmConfigBuilder};

/// Reject checkpoint names that could escape the checkpoints directory.
pub fn validate_checkpoint_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("checkpoint name cannot be empty".into());
    }
    if name.contains('/') || name.contains('\\') || name.contains('\0') || name.contains("..") {
        return Err(format!("invalid checkpoint name: '{}'", name));
    }
    Ok(())
}

pub fn default_data_dir() -> String {
    lsb_platform::default_data_dir()
}
