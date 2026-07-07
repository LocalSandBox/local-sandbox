use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use crossbeam_channel::{unbounded, Receiver, Sender};

use crate::{PlatformControlStream, PlatformVm, PlatformVmConfig, VmState};

use super::config::WindowsVmConfig;
use super::control::VirtioSerialControlEndpoint;
use super::errors::unsupported;
use super::network::qemu_network_config;
use super::qemu::boot::{launch_windows_qemu_boot, WindowsQemuBoot, WindowsQemuBootConfig};
use super::qemu::config::QemuDiskImageFormat;

struct WindowsVm {
    config: WindowsVmConfig,
    state_tx: Sender<VmState>,
    state_rx: Receiver<VmState>,
    boot: Mutex<Option<WindowsQemuBoot>>,
}

impl WindowsVm {
    fn new(config: PlatformVmConfig) -> Self {
        let (state_tx, state_rx) = unbounded();
        let _ = state_tx.send(VmState::Stopped);
        Self {
            config: WindowsVmConfig::from_platform_config(&config),
            state_tx,
            state_rx,
            boot: Mutex::new(None),
        }
    }

    fn direct_boot_config(&self) -> Result<WindowsQemuBootConfig> {
        self.ensure_supported_config()?;
        let initrd_path = self.config.initrd_path.clone().ok_or_else(|| {
            anyhow!(
                "Windows direct QEMU boot requires initramfs.cpio.gz for guest-ready diagnostics; \
                 run `lsb init` or provide an initrd path"
            )
        })?;
        let mut config = WindowsQemuBootConfig::new(
            &self.config.kernel_path,
            initrd_path,
            &self.config.rootfs_path,
            self.config.memory_bytes,
            self.config.cpus,
        );
        config.data_dir = self.config.data_dir.clone().map(PathBuf::from);
        config.root_disk_format = root_disk_format_for_path(&self.config.rootfs_path)?;
        config.control_endpoint = Some(VirtioSerialControlEndpoint::for_instance(
            &instance_dir_for_rootfs(&self.config.rootfs_path)?,
        )?);
        config.forward_endpoint = Some(VirtioSerialControlEndpoint::for_forwarding(
            &instance_dir_for_rootfs(&self.config.rootfs_path)?,
        )?);
        config.network = qemu_network_config(self.config.network_attachment.as_ref())?;
        config.diagnostic_label = Some("windows-direct-linux-boot".to_string());
        Ok(config)
    }

    fn ensure_supported_config(&self) -> Result<()> {
        if self.config.nbd_requested {
            return Err(unsupported(
                "NBD/CAS root storage",
                "Windows checkpoint/store uses qcow2/raw disk artifacts; Unix-socket NBD/CAS root storage remains unsupported on Windows",
            ));
        }
        if self.config.shared_dir_count > 0 {
            return Err(unsupported(
                "live shared directory devices",
                "Windows overlay mounts use lsb-vm copy-import staging after guest-ready, and explicit direct mounts use SMB/CIFS orchestration outside the QEMU device list; the Windows QEMU backend does not attach VirtioFS, 9p, virtual FAT, or other live host shared-directory devices",
            ));
        }
        Ok(())
    }

    fn send_state(&self, state: VmState) {
        let _ = self.state_tx.send(state);
    }
}

impl PlatformVm for WindowsVm {
    fn start(&self) -> Result<()> {
        let mut boot = self
            .boot
            .lock()
            .map_err(|_| anyhow!("Windows QEMU boot state lock poisoned"))?;
        if boot.is_some() {
            return Err(anyhow!(
                "Windows QEMU direct boot is already running; stop the VM before starting it again"
            ));
        }

        self.send_state(VmState::Starting);
        let config = match self.direct_boot_config() {
            Ok(config) => config,
            Err(err) => {
                self.send_state(VmState::Error);
                return Err(err);
            }
        };

        match launch_windows_qemu_boot(config) {
            Ok(running_boot) => {
                *boot = Some(running_boot);
                self.send_state(VmState::Running);
                Ok(())
            }
            Err(err) => {
                self.send_state(VmState::Error);
                Err(anyhow!("Windows QEMU direct boot failed: {err}"))
            }
        }
    }

    fn stop(&self) -> Result<()> {
        let mut boot = self
            .boot
            .lock()
            .map_err(|_| anyhow!("Windows QEMU boot state lock poisoned"))?;
        let Some(running_boot) = boot.as_mut() else {
            self.send_state(VmState::Stopped);
            return Ok(());
        };

        self.send_state(VmState::Stopping);
        match running_boot.stop() {
            Ok(_) => {
                *boot = None;
                self.send_state(VmState::Stopped);
                Ok(())
            }
            Err(err) => {
                self.send_state(VmState::Error);
                Err(anyhow!("Windows QEMU direct boot stop failed: {err}"))
            }
        }
    }

    fn state_channel(&self) -> Receiver<VmState> {
        self.state_rx.clone()
    }

    fn guest_capabilities(&self) -> Vec<String> {
        self.boot
            .lock()
            .ok()
            .and_then(|boot| {
                boot.as_ref()
                    .and_then(|running_boot| running_boot.guest_ready())
                    .map(|ready| ready.capabilities.clone())
            })
            .unwrap_or_default()
    }

    fn connect_control(&self) -> Result<PlatformControlStream> {
        let boot = self
            .boot
            .lock()
            .map_err(|_| anyhow!("Windows QEMU boot state lock poisoned"))?;
        let Some(running_boot) = boot.as_ref() else {
            return Err(anyhow!(
                "Windows virtio-serial control transport is unavailable because the VM is not running; start the VM before opening guest control"
            ));
        };

        running_boot.open_control().map_err(|err| {
            anyhow!(
                "Windows virtio-serial control transport is unavailable: {err}. Captured artifacts: {}",
                running_boot.artifacts().summary()
            )
        })
    }

    fn connect_port_forward(&self) -> Result<PlatformControlStream> {
        let boot = self
            .boot
            .lock()
            .map_err(|_| anyhow!("Windows QEMU boot state lock poisoned"))?;
        let Some(running_boot) = boot.as_ref() else {
            return Err(anyhow!(
                "Windows virtio-serial port-forward transport is unavailable because the VM is not running; start the VM before opening port forwarding"
            ));
        };

        running_boot.open_port_forward().map_err(|err| {
            anyhow!(
                "Windows virtio-serial port-forward transport is unavailable: {err}. Captured artifacts: {}",
                running_boot.artifacts().summary()
            )
        })
    }

    fn connect_to_vsock_port(&self, _port: u32) -> Result<TcpStream> {
        Err(unsupported(
            "guest control transport",
            "Windows guest control uses PlatformVm::connect_control over virtio-serial; macOS-style vsock guest control remains unsupported on Windows",
        ))
    }
}

pub(crate) fn create_vm(config: PlatformVmConfig) -> Result<Arc<dyn PlatformVm>> {
    Ok(Arc::new(WindowsVm::new(config)))
}

fn instance_dir_for_rootfs(rootfs_path: &str) -> Result<PathBuf> {
    let path = Path::new(rootfs_path);
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .ok_or_else(|| {
            anyhow!(
                "Windows virtio-serial control transport requires the rootfs path to live under a per-instance directory"
            )
        })
}

fn root_disk_format_for_path(rootfs_path: &str) -> Result<QemuDiskImageFormat> {
    let path = Path::new(rootfs_path);
    match path.extension().and_then(|extension| extension.to_str()) {
        Some(extension) if extension.eq_ignore_ascii_case("qcow2") => {
            Ok(QemuDiskImageFormat::Qcow2)
        }
        Some(extension) if extension.eq_ignore_ascii_case("ext4") => Ok(QemuDiskImageFormat::Raw),
        Some(extension) => Err(unsupported(
            "Windows root disk image format",
            &format!(
                "Windows supports QEMU-compatible raw .ext4 disks and qcow2 .qcow2 overlays, but '{}' has unsupported extension '.{}'",
                path.display(),
                extension
            ),
        )),
        None => Err(unsupported(
            "Windows root disk image format",
            &format!(
                "Windows supports QEMU-compatible raw .ext4 disks and qcow2 .qcow2 overlays, but '{}' has no file extension",
                path.display()
            ),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PlatformNetworkAttachment, PlatformSharedDir, PlatformVmConfig};

    fn test_config() -> PlatformVmConfig {
        PlatformVmConfig {
            data_dir: None,
            kernel_path: "Image".into(),
            rootfs_path: "rootfs.ext4".into(),
            initrd_path: Some("initramfs.cpio.gz".into()),
            cpus: 2,
            memory_bytes: 512 * 1024 * 1024,
            console: false,
            verbose: false,
            network_fd: None,
            network_attachment: None,
            nbd_uri: None,
            shared_dirs: Vec::new(),
        }
    }

    #[test]
    fn windows_vm_reports_missing_asset_error_before_preflight() {
        let root = std::env::temp_dir().join(format!(
            "lsb-windows-backend-missing-asset-{}",
            std::process::id()
        ));
        let mut config = test_config();
        config.kernel_path = root.join("instance").join("Image").display().to_string();
        config.initrd_path = Some(
            root.join("instance")
                .join("initramfs.cpio.gz")
                .display()
                .to_string(),
        );
        config.rootfs_path = root
            .join("instance")
            .join("rootfs.ext4")
            .display()
            .to_string();
        let vm = create_vm(config).expect("vm should be constructible");

        let err = vm.start().expect_err("missing kernel should not boot");
        let message = err.to_string();

        assert!(message.contains("kernel Image"));
        assert!(message.contains("serial.log"));
        assert!(message.contains("qemu.stderr.log"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn windows_vm_exposes_initial_stopped_state() {
        let vm = create_vm(test_config()).expect("vm should be constructible");
        assert_eq!(vm.state_channel().try_recv().ok(), Some(VmState::Stopped));
    }

    #[test]
    fn windows_vm_rejects_live_shared_directory_devices() {
        let mut config = test_config();
        config.shared_dirs = vec![PlatformSharedDir {
            host_path: "host".into(),
            tag: "mount0".into(),
            read_only: true,
        }];
        let vm = create_vm(config).expect("vm should be constructible");

        let err = vm
            .start()
            .expect_err("live shared directory devices should be unsupported");
        let message = err.to_string();

        assert!(message.contains("live shared directory devices"));
        assert!(message.contains("copy-import staging"));
        assert!(message.contains("SMB/CIFS"));
        assert!(message.contains("Windows overlay mounts"));
    }

    #[test]
    fn windows_vm_stop_without_start_is_idempotent() {
        let vm = create_vm(test_config()).expect("vm should be constructible");

        vm.stop().expect("stop without a boot should be harmless");
    }

    #[test]
    fn direct_boot_config_enables_private_control_endpoint() {
        let mut config = test_config();
        config.rootfs_path = "/tmp/lsb/instances/12345/rootfs.ext4".to_string();
        let vm = WindowsVm::new(config);

        let boot_config = vm
            .direct_boot_config()
            .expect("supported config should build");
        let endpoint = boot_config
            .control_endpoint
            .expect("Windows boot should configure control endpoint");
        let forward_endpoint = boot_config
            .forward_endpoint
            .expect("Windows boot should configure forwarding endpoint");

        assert_eq!(
            endpoint.port_name(),
            lsb_proto::VIRTIO_SERIAL_CONTROL_PORT_NAME
        );
        assert!(endpoint.pipe_name().starts_with("lsb-12345-"));
        assert!(endpoint.pipe_name().ends_with("-control"));
        assert_eq!(
            forward_endpoint.port_name(),
            lsb_proto::VIRTIO_SERIAL_FORWARD_PORT_NAME
        );
        assert!(forward_endpoint.pipe_name().starts_with("lsb-12345-"));
        assert!(forward_endpoint.pipe_name().ends_with("-forward"));
    }

    #[test]
    fn direct_boot_config_uses_qcow2_for_windows_checkpoint_overlay() {
        let mut config = test_config();
        config.rootfs_path = "/tmp/lsb/instances/12345/root.qcow2".to_string();
        let vm = WindowsVm::new(config);

        let boot_config = vm
            .direct_boot_config()
            .expect("qcow2 root disk config should build");

        assert_eq!(boot_config.root_disk_format, QemuDiskImageFormat::Qcow2);
    }

    #[test]
    fn direct_boot_config_uses_raw_for_ext4_debug_disk() {
        let mut config = test_config();
        config.rootfs_path = "/tmp/lsb/instances/12345/rootfs.ext4".to_string();
        let vm = WindowsVm::new(config);

        let boot_config = vm
            .direct_boot_config()
            .expect("raw ext4 root disk config should build");

        assert_eq!(boot_config.root_disk_format, QemuDiskImageFormat::Raw);
    }

    #[test]
    fn direct_boot_config_rejects_unknown_disk_extension() {
        let mut config = test_config();
        config.rootfs_path = "/tmp/lsb/instances/12345/root.img".to_string();
        let vm = WindowsVm::new(config);

        let err = vm
            .direct_boot_config()
            .expect_err("unknown disk extension should fail closed");
        let message = err.to_string();

        assert!(message.contains("Windows root disk image format"));
        assert!(message.contains(".ext4"));
        assert!(message.contains(".qcow2"));
    }

    #[test]
    fn direct_boot_config_accepts_proxy_stream_network_attachment() {
        let mut config = test_config();
        config.rootfs_path = "/tmp/lsb/instances/12345/rootfs.ext4".to_string();
        config.network_attachment = Some(PlatformNetworkAttachment::qemu_stream(
            std::net::Ipv4Addr::LOCALHOST,
            49152,
        ));
        let vm = WindowsVm::new(config);

        let boot_config = vm
            .direct_boot_config()
            .expect("proxy stream network config should build");

        let super::super::qemu::config::QemuNetworkConfig::ProxyStream(proxy) = boot_config.network
        else {
            panic!("proxy stream attachment should produce proxy stream QEMU config");
        };
        assert_eq!(proxy.host, "127.0.0.1");
        assert_eq!(proxy.port, 49152);
        let first_octet = u8::from_str_radix(&proxy.mac[..2], 16).expect("MAC first octet");
        assert_eq!(first_octet & 0x01, 0, "proxy MAC should be unicast");
        assert_eq!(first_octet & 0x02, 0x02, "proxy MAC should be local");
    }

    #[test]
    fn direct_boot_config_rejects_legacy_network_fd_on_windows() {
        let mut config = test_config();
        config.rootfs_path = "/tmp/lsb/instances/12345/rootfs.ext4".to_string();
        config.network_fd = Some(7);
        let vm = WindowsVm::new(config);

        let err = vm
            .direct_boot_config()
            .expect_err("legacy fd network attachment should fail closed");
        let message = err.to_string();

        assert!(message.contains("fd/socketpair network attachments are macOS-only"));
        assert!(message.contains("No QEMU user networking"));
    }
}
