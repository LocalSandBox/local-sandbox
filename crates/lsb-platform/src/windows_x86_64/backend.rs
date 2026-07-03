use std::net::TcpStream;
use std::sync::Arc;

use anyhow::Result;
use crossbeam_channel::{unbounded, Receiver, Sender};

use crate::{PlatformVm, PlatformVmConfig, VmState};

use super::config::WindowsVmConfig;
use super::errors::unsupported;

#[derive(Debug)]
struct WindowsVm {
    _config: WindowsVmConfig,
    _state_tx: Sender<VmState>,
    state_rx: Receiver<VmState>,
}

impl WindowsVm {
    fn new(config: PlatformVmConfig) -> Self {
        let (state_tx, state_rx) = unbounded();
        let _ = state_tx.send(VmState::Stopped);
        Self {
            _config: WindowsVmConfig::from_platform_config(&config),
            _state_tx: state_tx,
            state_rx,
        }
    }
}

impl PlatformVm for WindowsVm {
    fn start(&self) -> Result<()> {
        Err(unsupported(
            "VM startup",
            "M04 QEMU process lifecycle and M05 direct Linux boot",
        ))
    }

    fn stop(&self) -> Result<()> {
        Err(unsupported("VM shutdown", "M04 QEMU process lifecycle"))
    }

    fn state_channel(&self) -> Receiver<VmState> {
        self.state_rx.clone()
    }

    fn connect_to_vsock_port(&self, _port: u32) -> Result<TcpStream> {
        Err(unsupported(
            "guest control transport",
            "M06 virtio-serial control transport",
        ))
    }
}

pub(crate) fn create_vm(config: PlatformVmConfig) -> Result<Arc<dyn PlatformVm>> {
    Ok(Arc::new(WindowsVm::new(config)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PlatformSharedDir, PlatformVmConfig};

    fn test_config() -> PlatformVmConfig {
        PlatformVmConfig {
            kernel_path: "Image".into(),
            rootfs_path: "rootfs.ext4".into(),
            initrd_path: Some("initramfs.cpio.gz".into()),
            cpus: 2,
            memory_bytes: 512 * 1024 * 1024,
            console: false,
            verbose: false,
            network_fd: None,
            nbd_uri: None,
            shared_dirs: vec![PlatformSharedDir {
                host_path: "host".into(),
                tag: "mount0".into(),
                read_only: true,
            }],
        }
    }

    #[test]
    fn windows_stub_vm_reports_startup_capability_error() {
        let vm = create_vm(test_config()).expect("stub vm should be constructible");
        let err = vm.start().expect_err("startup should be unsupported");
        let message = err.to_string();

        assert!(message.contains("Windows support is in progress"));
        assert!(message.contains("VM startup"));
        assert!(message.contains("M04"));
    }

    #[test]
    fn windows_stub_vm_exposes_initial_stopped_state() {
        let vm = create_vm(test_config()).expect("stub vm should be constructible");
        assert_eq!(vm.state_channel().try_recv().ok(), Some(VmState::Stopped));
    }
}
