#![forbid(unsafe_code)]

mod sandbox;

pub use shuru_proto::{
    frame, ExecRequest, ForwardRequest, ForwardResponse, MountRequest, MountResponse, PortMapping,
    VSOCK_PORT, VSOCK_PORT_FORWARD,
};
pub use sandbox::{MountConfig, PortForwardHandle, Sandbox, VmConfigBuilder};

// Re-exports from shuru-darwin for advanced/escape-hatch use
pub use shuru_darwin::VirtualMachine;
pub use shuru_darwin::VmState;
pub use shuru_darwin::VzError;

pub fn default_data_dir() -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    format!("{}/.local/share/shuru", home)
}
