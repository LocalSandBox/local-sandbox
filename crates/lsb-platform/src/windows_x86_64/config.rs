use crate::{PlatformNetworkAttachment, PlatformVmConfig};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WindowsVmConfig {
    pub data_dir: Option<String>,
    pub qemu_executable: Option<String>,
    pub kernel_path: String,
    pub rootfs_path: String,
    pub initrd_path: Option<String>,
    pub cpus: usize,
    pub memory_bytes: u64,
    pub console: bool,
    pub verbose: bool,
    pub network_requested: bool,
    pub network_attachment: Option<PlatformNetworkAttachment>,
    pub nbd_requested: bool,
    pub shared_dir_count: usize,
}

impl WindowsVmConfig {
    pub(crate) fn from_platform_config(config: &PlatformVmConfig) -> Self {
        Self {
            data_dir: config.data_dir.clone(),
            qemu_executable: config.qemu_executable.clone(),
            kernel_path: config.kernel_path.clone(),
            rootfs_path: config.rootfs_path.clone(),
            initrd_path: config.initrd_path.clone(),
            cpus: config.cpus,
            memory_bytes: config.memory_bytes,
            console: config.console,
            verbose: config.verbose,
            network_requested: config.network_fd.is_some() || config.network_attachment.is_some(),
            network_attachment: config.network_attachment.clone().or_else(|| {
                config
                    .network_fd
                    .map(PlatformNetworkAttachment::file_descriptor)
            }),
            nbd_requested: config.nbd_uri.is_some(),
            shared_dir_count: config.shared_dirs.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PlatformSharedDir, PlatformVmConfig};

    #[test]
    fn windows_config_records_requested_backend_options() {
        let config = PlatformVmConfig {
            data_dir: None,
            qemu_executable: None,
            kernel_path: "Image".into(),
            rootfs_path: "rootfs.ext4".into(),
            initrd_path: None,
            cpus: 4,
            memory_bytes: 1024,
            console: true,
            verbose: true,
            network_fd: Some(7),
            network_attachment: None,
            nbd_uri: Some("nbd+unix:///export?socket=nbd.sock".into()),
            shared_dirs: vec![PlatformSharedDir {
                host_path: "host".into(),
                tag: "mount0".into(),
                read_only: true,
            }],
        };

        let windows = WindowsVmConfig::from_platform_config(&config);

        assert_eq!(windows.kernel_path, "Image");
        assert!(windows.network_requested);
        assert_eq!(
            windows.network_attachment,
            Some(PlatformNetworkAttachment::file_descriptor(7))
        );
        assert!(windows.nbd_requested);
        assert_eq!(windows.shared_dir_count, 1);
    }
}
