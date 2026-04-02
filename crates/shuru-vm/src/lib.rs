#![forbid(unsafe_code)]

#[cfg(not(target_os = "macos"))]
compile_error!(
    "shuru-vm currently only supports macOS hosts. Future platform slots exist in shuru-platform, but their runtimes are not implemented yet."
);

mod sandbox;

pub use sandbox::{MountConfig, PortForwardHandle, Sandbox, VmConfigBuilder};
pub use shuru_platform::VmState;
pub use shuru_proto::{
    frame, ExecRequest, ForwardRequest, ForwardResponse, MountRequest, MountResponse, PortMapping,
    ReadFileRequest, WriteFileRequest, WriteFileResponse, VSOCK_PORT, VSOCK_PORT_FORWARD,
};

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
    shuru_platform::default_data_dir()
}
