use std::path::PathBuf;

pub(crate) const DEFAULT_CPU_MODEL: &str = "Westmere";
pub(crate) const DEFAULT_MACHINE_TYPE: &str = "q35";
pub(crate) const DEFAULT_KERNEL_CONSOLE: &str = "ttyS0";
pub(crate) const DEFAULT_ROOT_DEVICE: &str = "/dev/vda";
pub(crate) const CONTROL_BUS_ID: &str = "lsbserial0";
pub(crate) const CONTROL_CHARDEV_ID: &str = "lsbctl";
pub(crate) const CONTROL_PORT_NAME: &str = "org.localsandbox.control";
pub(crate) const ROOT_DRIVE_ID: &str = "root";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QemuBootConfig {
    pub qemu_executable: PathBuf,
    pub kernel_image: PathBuf,
    pub initrd_image: PathBuf,
    pub root_disk: QemuDiskConfig,
    pub machine: QemuMachineConfig,
    pub kernel_append: QemuKernelAppend,
    pub serial: QemuSerialConfig,
    pub control_channel: Option<QemuControlChannelConfig>,
    pub qmp: Option<QemuQmpEndpoint>,
    pub diagnostic_label: Option<String>,
}

impl QemuBootConfig {
    pub(crate) fn direct_linux_boot(
        qemu_executable: impl Into<PathBuf>,
        kernel_image: impl Into<PathBuf>,
        initrd_image: impl Into<PathBuf>,
        root_disk: impl Into<PathBuf>,
        serial_log: impl Into<PathBuf>,
        memory_mib: u64,
        vcpu_count: u16,
    ) -> Self {
        Self::direct_linux_boot_with_disk(
            qemu_executable,
            kernel_image,
            initrd_image,
            QemuDiskConfig::qcow2(root_disk),
            serial_log,
            memory_mib,
            vcpu_count,
        )
    }

    pub(crate) fn direct_linux_boot_raw_rootfs(
        qemu_executable: impl Into<PathBuf>,
        kernel_image: impl Into<PathBuf>,
        initrd_image: impl Into<PathBuf>,
        root_disk: impl Into<PathBuf>,
        serial_log: impl Into<PathBuf>,
        memory_mib: u64,
        vcpu_count: u16,
    ) -> Self {
        Self::direct_linux_boot_with_disk(
            qemu_executable,
            kernel_image,
            initrd_image,
            QemuDiskConfig::raw(root_disk),
            serial_log,
            memory_mib,
            vcpu_count,
        )
    }

    fn direct_linux_boot_with_disk(
        qemu_executable: impl Into<PathBuf>,
        kernel_image: impl Into<PathBuf>,
        initrd_image: impl Into<PathBuf>,
        root_disk: QemuDiskConfig,
        serial_log: impl Into<PathBuf>,
        memory_mib: u64,
        vcpu_count: u16,
    ) -> Self {
        Self {
            qemu_executable: qemu_executable.into(),
            kernel_image: kernel_image.into(),
            initrd_image: initrd_image.into(),
            root_disk,
            machine: QemuMachineConfig {
                memory_mib,
                vcpu_count,
            },
            kernel_append: QemuKernelAppend::direct_boot_default(),
            serial: QemuSerialConfig::File(serial_log.into()),
            control_channel: None,
            qmp: None,
            diagnostic_label: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QemuMachineConfig {
    pub memory_mib: u64,
    pub vcpu_count: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QemuDiskConfig {
    pub path: PathBuf,
    pub format: QemuDiskImageFormat,
}

impl QemuDiskConfig {
    pub(crate) fn qcow2(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            format: QemuDiskImageFormat::Qcow2,
        }
    }

    pub(crate) fn raw(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            format: QemuDiskImageFormat::Raw,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QemuDiskImageFormat {
    Qcow2,
    Raw,
}

impl QemuDiskImageFormat {
    pub(crate) fn as_qemu_arg(self) -> &'static str {
        match self {
            Self::Qcow2 => "qcow2",
            Self::Raw => "raw",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QemuKernelAppend {
    pub console: String,
    pub root_device: String,
    pub root_mode: QemuRootMode,
    pub panic_timeout: Option<i32>,
    pub guest_transport: Option<QemuGuestTransport>,
}

impl QemuKernelAppend {
    pub(crate) fn direct_boot_default() -> Self {
        Self {
            console: DEFAULT_KERNEL_CONSOLE.to_string(),
            root_device: DEFAULT_ROOT_DEVICE.to_string(),
            root_mode: QemuRootMode::ReadWrite,
            panic_timeout: Some(-1),
            guest_transport: None,
        }
    }

    pub(crate) fn with_guest_transport(mut self, transport: QemuGuestTransport) -> Self {
        self.guest_transport = Some(transport);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QemuRootMode {
    ReadOnly,
    ReadWrite,
}

impl QemuRootMode {
    pub(crate) fn as_kernel_arg(self) -> &'static str {
        match self {
            Self::ReadOnly => "ro",
            Self::ReadWrite => "rw",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QemuGuestTransport {
    VirtioSerial,
}

impl QemuGuestTransport {
    pub(crate) fn as_kernel_arg(self) -> &'static str {
        match self {
            Self::VirtioSerial => "lsb.transport=virtio-serial",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum QemuSerialConfig {
    File(PathBuf),
    Null,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QemuControlChannelConfig {
    pub pipe_name: String,
    pub port_name: String,
}

impl QemuControlChannelConfig {
    pub(crate) fn named_pipe(pipe_name: impl Into<String>) -> Self {
        Self {
            pipe_name: pipe_name.into(),
            port_name: CONTROL_PORT_NAME.to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum QemuQmpEndpoint {
    NamedPipe { pipe_name: String },
}

impl QemuQmpEndpoint {
    pub(crate) fn named_pipe(pipe_name: impl Into<String>) -> Self {
        Self::NamedPipe {
            pipe_name: pipe_name.into(),
        }
    }
}
