#![forbid(unsafe_code)]

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
compile_error!(
    "shuru-vm currently only supports macos/aarch64. Future platform slots exist in shuru-platform, but their runtimes are not implemented yet."
);

mod sandbox;

pub use shuru_proto::{
    frame, ExecRequest, ForwardRequest, ForwardResponse, MountRequest, MountResponse, PortMapping,
    ReadFileRequest, WriteFileRequest, WriteFileResponse,
    VSOCK_PORT, VSOCK_PORT_FORWARD,
};
pub use sandbox::{MountConfig, PortForwardHandle, Sandbox, VmConfigBuilder};
pub use shuru_platform::VmState;

pub fn default_data_dir() -> String {
    shuru_platform::default_data_dir()
}
