use std::env;
use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use lsb_proto::{frame, GuestReady, GuestTransport};
use serde::Serialize;

use crate::windows_x86_64::control::{
    mux::{MuxManager, MuxSession, MuxSessionError, MuxSessionKind},
    VirtioSerialControlEndpoint, VirtioSerialControlError,
};

use super::argv::{QemuArgvBuilder, QemuArgvError};
use super::config::{
    QemuBootConfig as QemuArgvBootConfig, QemuDataDiskConfig, QemuDiskImageFormat,
    QemuNetworkConfig,
};
use super::discovery::{QemuDiscovery, StdQemuDiscoveryHost};
use super::preflight::{QemuPreflight, QemuPreflightReport};
use super::process::{
    QemuExitStatus, QemuProcessArtifacts, QemuProcessError, QemuProcessState, QemuSupervisor,
    QemuSupervisorConfig,
};
use super::{lossy_excerpt, QemuPreflightError, StdQemuCommandRunner};

pub(crate) const DEFAULT_BOOT_OBSERVATION_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const DEFAULT_GUEST_READY_TIMEOUT: Duration = Duration::from_secs(90);
const BOOT_POLL_INTERVAL: Duration = Duration::from_millis(100);
const SERIAL_LOG_FILE: &str = "serial.log";
const PREFLIGHT_FILE: &str = "preflight.json";
const BOOT_STATUS_FILE: &str = "boot.status.json";
const SERIAL_OBSERVED_SUCCESS_DEFINITION: &str =
    "qemu_process_alive_after_boot_observation_window_with_serial_output";
const GUEST_READY_SUCCESS_DEFINITION: &str =
    "localsandbox_guest_ready_frame_received_over_control_transport";
const CONTROL_STATE_OPENING_FOR_READY: &str = "opening_control_channel_for_guest_ready";
const CONTROL_STATE_OPENING_FORWARD_CHANNEL: &str = "opening_forwarding_channel";
const CONTROL_STATE_WAITING_FOR_READY: &str = "control_channel_open_waiting_for_guest_ready";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WindowsQemuBootConfig {
    pub data_dir: Option<PathBuf>,
    pub kernel_image: PathBuf,
    pub initrd_image: PathBuf,
    pub rootfs_image: PathBuf,
    pub root_disk_format: QemuDiskImageFormat,
    pub data_disks: Vec<QemuDataDiskConfig>,
    pub memory_bytes: u64,
    pub vcpu_count: usize,
    pub diagnostic_label: Option<String>,
    pub artifact_directory: Option<PathBuf>,
    pub boot_observation_timeout: Duration,
    pub guest_ready_timeout: Duration,
    pub control_endpoint: Option<VirtioSerialControlEndpoint>,
    pub forward_endpoint: Option<VirtioSerialControlEndpoint>,
    pub network: QemuNetworkConfig,
}

impl WindowsQemuBootConfig {
    pub(crate) fn new(
        kernel_image: impl Into<PathBuf>,
        initrd_image: impl Into<PathBuf>,
        rootfs_image: impl Into<PathBuf>,
        memory_bytes: u64,
        vcpu_count: usize,
    ) -> Self {
        Self {
            data_dir: None,
            kernel_image: kernel_image.into(),
            initrd_image: initrd_image.into(),
            rootfs_image: rootfs_image.into(),
            root_disk_format: QemuDiskImageFormat::Raw,
            data_disks: Vec::new(),
            memory_bytes,
            vcpu_count,
            diagnostic_label: None,
            artifact_directory: None,
            boot_observation_timeout: DEFAULT_BOOT_OBSERVATION_TIMEOUT,
            guest_ready_timeout: DEFAULT_GUEST_READY_TIMEOUT,
            control_endpoint: None,
            forward_endpoint: None,
            network: QemuNetworkConfig::None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QemuBootArtifacts {
    pub directory: PathBuf,
    pub serial: PathBuf,
    pub preflight: PathBuf,
    pub boot_status: PathBuf,
    pub process: QemuProcessArtifacts,
}

impl QemuBootArtifacts {
    pub(crate) fn new(directory: impl Into<PathBuf>) -> Self {
        let directory = directory.into();
        Self {
            serial: directory.join(SERIAL_LOG_FILE),
            preflight: directory.join(PREFLIGHT_FILE),
            boot_status: directory.join(BOOT_STATUS_FILE),
            process: QemuProcessArtifacts::new(directory.clone()),
            directory,
        }
    }

    pub(crate) fn summary(&self) -> String {
        format!(
            "diagnostics '{}', serial '{}', stdout '{}', stderr '{}', redacted argv '{}', boot status '{}'",
            self.directory.display(),
            self.serial.display(),
            self.process.stdout.display(),
            self.process.stderr.display(),
            self.process.argv.display(),
            self.boot_status.display()
        )
    }
}

#[derive(Debug)]
pub(crate) struct WindowsQemuBoot {
    supervisor: QemuSupervisor,
    artifacts: QemuBootArtifacts,
    control_stream: Option<crate::PlatformControlStream>,
    control_mux: Option<MuxManager>,
    forward_stream: Option<crate::PlatformControlStream>,
    guest_ready: Option<GuestReady>,
    #[cfg(test)]
    guest_ready_elapsed: Option<Duration>,
}

impl WindowsQemuBoot {
    pub(crate) fn artifacts(&self) -> &QemuBootArtifacts {
        &self.artifacts
    }

    pub(crate) fn guest_ready(&self) -> Option<&GuestReady> {
        self.guest_ready.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn guest_ready_elapsed(&self) -> Option<Duration> {
        self.guest_ready_elapsed
    }

    pub(crate) fn open_control(
        &self,
    ) -> Result<crate::PlatformControlStream, VirtioSerialControlError> {
        if self.control_mux.is_some() {
            return Err(VirtioSerialControlError::MuxActive);
        }
        let stream = self
            .control_stream
            .as_ref()
            .ok_or(VirtioSerialControlError::EndpointUnavailable)?;
        stream
            .try_clone()
            .map_err(|error| VirtioSerialControlError::OpenFailed {
                detail: format!("failed to clone the established control pipe handle: {error}"),
            })
    }

    pub(crate) fn open_mux_session(
        &self,
        kind: MuxSessionKind,
    ) -> Result<MuxSession, MuxSessionError> {
        let mux = self
            .control_mux
            .as_ref()
            .ok_or_else(|| MuxSessionError::ManagerClosed {
                reason: "guest did not advertise session_mux".to_string(),
            })?;
        mux.open_session(kind)
    }

    pub(crate) fn open_port_forward(
        &self,
    ) -> Result<crate::PlatformControlStream, VirtioSerialControlError> {
        let stream = self
            .forward_stream
            .as_ref()
            .ok_or(VirtioSerialControlError::EndpointUnavailable)?;
        stream
            .try_clone()
            .map_err(|error| VirtioSerialControlError::OpenFailed {
                detail: format!("failed to clone the established forwarding pipe handle: {error}"),
            })
    }

    pub(crate) fn stop(&mut self) -> Result<Option<QemuExitStatus>, QemuBootError> {
        self.supervisor
            .terminate()
            .map_err(|source| QemuBootError::StopFailed {
                source,
                artifacts: self.artifacts.clone(),
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum QemuBootErrorKind {
    AssetMissing,
    InvalidConfig,
    ArtifactIo,
    Preflight,
    Argv,
    ProcessStart,
    ControlOpen,
    ProcessStatus,
    GuestBootExited,
    GuestReadyProcessExited,
    GuestReadyTimeout,
    GuestReadyProtocol,
    GuestReadyTransport,
    UnsupportedWindowsRuntimeCapability,
    SerialOutputMissing,
    StopFailed,
}

impl QemuBootErrorKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::AssetMissing => "asset_missing",
            Self::InvalidConfig => "invalid_config",
            Self::ArtifactIo => "artifact_io",
            Self::Preflight => "preflight",
            Self::Argv => "argv",
            Self::ProcessStart => "process_start",
            Self::ControlOpen => "control_open",
            Self::ProcessStatus => "process_status",
            Self::GuestBootExited => "guest_boot_exited",
            Self::GuestReadyProcessExited => "guest_ready_process_exited",
            Self::GuestReadyTimeout => "guest_ready_timeout",
            Self::GuestReadyProtocol => "guest_ready_protocol",
            Self::GuestReadyTransport => "guest_ready_transport",
            Self::UnsupportedWindowsRuntimeCapability => "unsupported_windows_runtime_capability",
            Self::SerialOutputMissing => "serial_output_missing",
            Self::StopFailed => "stop_failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum QemuBootError {
    AssetMissing {
        asset: &'static str,
        path: PathBuf,
        reason: String,
        artifacts: QemuBootArtifacts,
    },
    InvalidConfig {
        field: &'static str,
        reason: String,
        artifacts: Option<QemuBootArtifacts>,
    },
    ArtifactIo {
        path: PathBuf,
        operation: &'static str,
        detail: String,
        artifacts: Option<QemuBootArtifacts>,
    },
    Preflight {
        source: QemuPreflightError,
        artifacts: QemuBootArtifacts,
    },
    Argv {
        source: QemuArgvError,
        artifacts: QemuBootArtifacts,
    },
    ProcessStart {
        source: QemuProcessError,
        artifacts: QemuBootArtifacts,
    },
    ControlOpen {
        source: VirtioSerialControlError,
        artifacts: QemuBootArtifacts,
    },
    ProcessStatus {
        source: QemuProcessError,
        artifacts: QemuBootArtifacts,
    },
    GuestBootExited {
        state: QemuProcessState,
        exit_status: Option<QemuExitStatus>,
        artifacts: QemuBootArtifacts,
        stderr_excerpt: String,
        serial_excerpt: String,
    },
    GuestReadyProcessExited {
        state: QemuProcessState,
        exit_status: Option<QemuExitStatus>,
        artifacts: QemuBootArtifacts,
        elapsed: Duration,
        control_state: &'static str,
        stderr_excerpt: String,
        serial_excerpt: String,
    },
    GuestReadyTimeout {
        timeout: Duration,
        elapsed: Duration,
        artifacts: QemuBootArtifacts,
        serial_excerpt: String,
        stderr_excerpt: String,
    },
    GuestReadyProtocol {
        reason: String,
        frame_type: Option<u8>,
        artifacts: QemuBootArtifacts,
        serial_excerpt: String,
    },
    GuestReadyTransport {
        detail: String,
        artifacts: QemuBootArtifacts,
        serial_excerpt: String,
    },
    UnsupportedWindowsRuntimeCapability {
        capabilities: Vec<String>,
        artifacts: QemuBootArtifacts,
        serial_excerpt: String,
    },
    SerialOutputMissing {
        artifacts: QemuBootArtifacts,
        stderr_excerpt: String,
    },
    StopFailed {
        source: QemuProcessError,
        artifacts: QemuBootArtifacts,
    },
}

impl QemuBootError {
    pub(crate) fn kind(&self) -> QemuBootErrorKind {
        match self {
            Self::AssetMissing { .. } => QemuBootErrorKind::AssetMissing,
            Self::InvalidConfig { .. } => QemuBootErrorKind::InvalidConfig,
            Self::ArtifactIo { .. } => QemuBootErrorKind::ArtifactIo,
            Self::Preflight { .. } => QemuBootErrorKind::Preflight,
            Self::Argv { .. } => QemuBootErrorKind::Argv,
            Self::ProcessStart { .. } => QemuBootErrorKind::ProcessStart,
            Self::ControlOpen { .. } => QemuBootErrorKind::ControlOpen,
            Self::ProcessStatus { .. } => QemuBootErrorKind::ProcessStatus,
            Self::GuestBootExited { .. } => QemuBootErrorKind::GuestBootExited,
            Self::GuestReadyProcessExited { .. } => QemuBootErrorKind::GuestReadyProcessExited,
            Self::GuestReadyTimeout { .. } => QemuBootErrorKind::GuestReadyTimeout,
            Self::GuestReadyProtocol { .. } => QemuBootErrorKind::GuestReadyProtocol,
            Self::GuestReadyTransport { .. } => QemuBootErrorKind::GuestReadyTransport,
            Self::UnsupportedWindowsRuntimeCapability { .. } => {
                QemuBootErrorKind::UnsupportedWindowsRuntimeCapability
            }
            Self::SerialOutputMissing { .. } => QemuBootErrorKind::SerialOutputMissing,
            Self::StopFailed { .. } => QemuBootErrorKind::StopFailed,
        }
    }

    fn artifacts(&self) -> Option<&QemuBootArtifacts> {
        match self {
            Self::AssetMissing { artifacts, .. }
            | Self::Preflight { artifacts, .. }
            | Self::Argv { artifacts, .. }
            | Self::ProcessStart { artifacts, .. }
            | Self::ControlOpen { artifacts, .. }
            | Self::ProcessStatus { artifacts, .. }
            | Self::GuestBootExited { artifacts, .. }
            | Self::GuestReadyProcessExited { artifacts, .. }
            | Self::GuestReadyTimeout { artifacts, .. }
            | Self::GuestReadyProtocol { artifacts, .. }
            | Self::GuestReadyTransport { artifacts, .. }
            | Self::UnsupportedWindowsRuntimeCapability { artifacts, .. }
            | Self::SerialOutputMissing { artifacts, .. }
            | Self::StopFailed { artifacts, .. } => Some(artifacts),
            Self::InvalidConfig { artifacts, .. } | Self::ArtifactIo { artifacts, .. } => {
                artifacts.as_ref()
            }
        }
    }

    fn artifact_sentence(&self) -> String {
        self.artifacts()
            .map(|artifacts| format!(" Captured artifacts: {}.", artifacts.summary()))
            .unwrap_or_default()
    }
}

impl fmt::Display for QemuBootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AssetMissing {
                asset,
                path,
                reason,
                ..
            } => write!(
                f,
                "missing Windows QEMU boot asset {asset} at '{}': {reason}. Run `lsb init` or check the configured asset paths.{}",
                path.display(),
                self.artifact_sentence()
            ),
            Self::InvalidConfig { field, reason, .. } => write!(
                f,
                "invalid Windows QEMU boot configuration {field}: {reason}.{}",
                self.artifact_sentence()
            ),
            Self::ArtifactIo {
                path,
                operation,
                detail,
                ..
            } => write!(
                f,
                "failed to {operation} Windows QEMU boot artifact '{}': {detail}.{}",
                path.display(),
                self.artifact_sentence()
            ),
            Self::Preflight { source, .. } => write!(
                f,
                "Windows QEMU preflight failed before boot: {source}.{}",
                self.artifact_sentence()
            ),
            Self::Argv { source, .. } => write!(
                f,
                "failed to build Windows QEMU boot argv: {source}.{}",
                self.artifact_sentence()
            ),
            Self::ProcessStart { source, .. } => write!(
                f,
                "failed to start Windows QEMU direct boot: {source}.{}",
                self.artifact_sentence()
            ),
            Self::ControlOpen { source, .. } => write!(
                f,
                "failed to connect the Windows virtio-serial control pipe during QEMU boot: {source}.{}",
                self.artifact_sentence()
            ),
            Self::ProcessStatus { source, .. } => write!(
                f,
                "failed while observing Windows QEMU boot status: {source}.{}",
                self.artifact_sentence()
            ),
            Self::GuestBootExited {
                state,
                exit_status,
                stderr_excerpt,
                serial_excerpt,
                ..
            } => write!(
                f,
                "Windows QEMU exited before the boot observation completed (state '{}', status {}). Inspect serial and QEMU logs. stderr excerpt: {}; serial excerpt: {}.{}",
                state.as_str(),
                exit_status
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "unknown".to_string()),
                empty_as_placeholder(stderr_excerpt),
                empty_as_placeholder(serial_excerpt),
                self.artifact_sentence()
            ),
            Self::GuestReadyProcessExited {
                state,
                exit_status,
                elapsed,
                control_state,
                stderr_excerpt,
                serial_excerpt,
                ..
            } => write!(
                f,
                "Windows QEMU exited before the LocalSandbox guest-ready handshake completed (state '{}', status {}, elapsed {} ms, control state '{}'). Inspect serial and QEMU logs. stderr excerpt: {}; serial excerpt: {}.{}",
                state.as_str(),
                exit_status
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "unknown".to_string()),
                elapsed.as_millis(),
                control_state,
                empty_as_placeholder(stderr_excerpt),
                empty_as_placeholder(serial_excerpt),
                self.artifact_sentence()
            ),
            Self::GuestReadyTimeout {
                timeout,
                elapsed,
                serial_excerpt,
                stderr_excerpt,
                ..
            } => write!(
                f,
                "timed out after {} ms waiting for the LocalSandbox guest-ready handshake over the Windows virtio-serial control channel (elapsed {} ms, control state '{}'). Inspect serial and QEMU logs. stderr excerpt: {}; serial excerpt: {}.{}",
                timeout.as_millis(),
                elapsed.as_millis(),
                CONTROL_STATE_WAITING_FOR_READY,
                empty_as_placeholder(stderr_excerpt),
                empty_as_placeholder(serial_excerpt),
                self.artifact_sentence()
            ),
            Self::GuestReadyProtocol {
                reason,
                frame_type,
                serial_excerpt,
                ..
            } => write!(
                f,
                "invalid LocalSandbox guest-ready handshake frame{}: {reason}. serial excerpt: {}.{}",
                frame_type
                    .map(|value| format!(" type 0x{value:02x}"))
                    .unwrap_or_default(),
                empty_as_placeholder(serial_excerpt),
                self.artifact_sentence()
            ),
            Self::GuestReadyTransport {
                detail,
                serial_excerpt,
                ..
            } => write!(
                f,
                "failed while reading the LocalSandbox guest-ready handshake over the Windows virtio-serial control channel: {detail}. serial excerpt: {}.{}",
                empty_as_placeholder(serial_excerpt),
                self.artifact_sentence()
            ),
            Self::UnsupportedWindowsRuntimeCapability {
                capabilities,
                serial_excerpt,
                ..
            } => write!(
                f,
                "the Windows guest advertised unsupported runtime capabilities during readiness: {}. The Windows backend currently accepts the base guest-ready handshake plus '{}', '{}', '{}', '{}', and '{}' capabilities. Update lsb-proto and host handling before advertising additional capabilities. serial excerpt: {}.{}",
                capability_summary(capabilities),
                lsb_proto::CAP_FILE_RANGE_IO,
                lsb_proto::CAP_PORT_FORWARD,
                lsb_proto::CAP_CIFS_MOUNT,
                lsb_proto::CAP_SESSION_MUX,
                lsb_proto::CAP_DEFERRED_FILE_SYNC,
                empty_as_placeholder(serial_excerpt),
                self.artifact_sentence()
            ),
            Self::SerialOutputMissing {
                stderr_excerpt, ..
            } => write!(
                f,
                "Windows QEMU stayed alive for the boot observation window, but serial.log remained empty. Treat this as inconclusive boot evidence; inspect QEMU stderr and kernel console configuration. stderr excerpt: {}.{}",
                empty_as_placeholder(stderr_excerpt),
                self.artifact_sentence()
            ),
            Self::StopFailed { source, .. } => write!(
                f,
                "failed to stop Windows QEMU direct boot process: {source}.{}",
                self.artifact_sentence()
            ),
        }
    }
}

impl std::error::Error for QemuBootError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Preflight { source, .. } => Some(source),
            Self::Argv { source, .. } => Some(source),
            Self::ProcessStart { source, .. } => Some(source),
            Self::ControlOpen { source, .. } => Some(source),
            Self::ProcessStatus { source, .. } => Some(source),
            Self::StopFailed { source, .. } => Some(source),
            _ => None,
        }
    }
}

pub(crate) fn launch_windows_qemu_boot(
    config: WindowsQemuBootConfig,
) -> Result<WindowsQemuBoot, QemuBootError> {
    let artifacts = resolve_artifacts(&config)?;
    let observation_goal = BootObservationGoal::for_config(&config);
    prepare_artifacts(&artifacts)?;

    let kernel_image = require_existing_file("kernel Image", &config.kernel_image, &artifacts)
        .map_err(|error| {
            record_error(
                &artifacts,
                config.boot_observation_timeout,
                observation_goal,
                error,
            )
        })?;
    let initrd_image = require_existing_file("initramfs", &config.initrd_image, &artifacts)
        .map_err(|error| {
            record_error(
                &artifacts,
                config.boot_observation_timeout,
                observation_goal,
                error,
            )
        })?;
    let rootfs_image =
        require_existing_file("rootfs", &config.rootfs_image, &artifacts).map_err(|error| {
            record_error(
                &artifacts,
                config.boot_observation_timeout,
                observation_goal,
                error,
            )
        })?;
    let mut data_disks = config.data_disks.clone();
    for disk in &mut data_disks {
        disk.path =
            require_existing_file("data disk", &disk.path, &artifacts).map_err(|error| {
                record_error(
                    &artifacts,
                    config.boot_observation_timeout,
                    observation_goal,
                    error,
                )
            })?;
    }
    let memory_mib = memory_mib(config.memory_bytes, &artifacts).map_err(|error| {
        record_error(
            &artifacts,
            config.boot_observation_timeout,
            observation_goal,
            error,
        )
    })?;
    let vcpu_count = vcpu_count(config.vcpu_count, &artifacts).map_err(|error| {
        record_error(
            &artifacts,
            config.boot_observation_timeout,
            observation_goal,
            error,
        )
    })?;

    let preflight = run_preflight(config.data_dir.as_deref()).map_err(|source| {
        let error = QemuBootError::Preflight {
            source,
            artifacts: artifacts.clone(),
        };
        record_failure(
            &artifacts,
            config.boot_observation_timeout,
            observation_goal,
            &error,
        );
        error
    })?;
    write_preflight_report(&artifacts, &preflight).map_err(|error| {
        record_error(
            &artifacts,
            config.boot_observation_timeout,
            observation_goal,
            error,
        )
    })?;

    let mut argv_config = match config.root_disk_format {
        QemuDiskImageFormat::Raw => QemuArgvBootConfig::direct_linux_boot_raw_rootfs(
            preflight.qemu.path,
            kernel_image,
            initrd_image,
            rootfs_image,
            artifacts.serial.clone(),
            memory_mib,
            vcpu_count,
        ),
        QemuDiskImageFormat::Qcow2 => QemuArgvBootConfig::direct_linux_boot(
            preflight.qemu.path,
            kernel_image,
            initrd_image,
            rootfs_image,
            artifacts.serial.clone(),
            memory_mib,
            vcpu_count,
        ),
    };
    if let Some(endpoint) = &config.control_endpoint {
        argv_config.control_channel = Some(endpoint.qemu_config());
    }
    argv_config.data_disks = data_disks;
    if let Some(endpoint) = &config.forward_endpoint {
        argv_config.forward_channel = Some(endpoint.qemu_config());
    }
    argv_config.network = config.network.clone();
    argv_config.diagnostic_label = config.diagnostic_label.clone();

    let command = QemuArgvBuilder::new(argv_config)
        .build()
        .map_err(|source| {
            let error = QemuBootError::Argv {
                source,
                artifacts: artifacts.clone(),
            };
            record_failure(
                &artifacts,
                config.boot_observation_timeout,
                observation_goal,
                &error,
            );
            error
        })?;

    let mut supervisor_config = QemuSupervisorConfig::new(command, artifacts.directory.clone());
    supervisor_config.working_directory = artifacts.directory.clone();
    let mut supervisor = QemuSupervisor::new(supervisor_config);
    supervisor.start().map_err(|source| {
        let error = QemuBootError::ProcessStart {
            source,
            artifacts: artifacts.clone(),
        };
        record_failure(
            &artifacts,
            config.boot_observation_timeout,
            observation_goal,
            &error,
        );
        error
    })?;

    let mut control_stream = if let Some(endpoint) = &config.control_endpoint {
        let control_open_started_at = Instant::now();
        match endpoint.open() {
            Ok(stream) => Some(stream),
            Err(source) => {
                let error = map_control_open_error(
                    source,
                    &mut supervisor,
                    &artifacts,
                    control_open_started_at.elapsed(),
                );
                record_failure(
                    &artifacts,
                    config.guest_ready_timeout,
                    observation_goal,
                    &error,
                );
                let _ = supervisor.terminate();
                return Err(error);
            }
        }
    } else {
        None
    };

    let forward_stream = if let Some(endpoint) = &config.forward_endpoint {
        let forward_open_started_at = Instant::now();
        match endpoint.open() {
            Ok(stream) => Some(stream),
            Err(source) => {
                let error = map_forward_open_error(
                    source,
                    &mut supervisor,
                    &artifacts,
                    forward_open_started_at.elapsed(),
                );
                record_failure(
                    &artifacts,
                    config.guest_ready_timeout,
                    observation_goal,
                    &error,
                );
                let _ = supervisor.terminate();
                return Err(error);
            }
        }
    } else {
        None
    };

    let mut guest_ready = None;
    let mut control_mux = None;
    #[cfg(test)]
    let mut guest_ready_elapsed = None;
    if let Some(stream) = control_stream.as_ref() {
        let ready_reader = match stream.try_clone() {
            Ok(reader) => reader,
            Err(error) => {
                let error = QemuBootError::GuestReadyTransport {
                    detail: format!("failed to clone established control stream: {error}"),
                    artifacts: artifacts.clone(),
                    serial_excerpt: read_excerpt(&artifacts.serial),
                };
                record_failure(
                    &artifacts,
                    config.guest_ready_timeout,
                    observation_goal,
                    &error,
                );
                let _ = supervisor.terminate();
                return Err(error);
            }
        };
        match wait_for_guest_ready(
            &mut supervisor,
            &artifacts,
            config.guest_ready_timeout,
            ready_reader,
            GuestTransport::VirtioSerial,
        ) {
            Ok(result) => {
                let elapsed = result.elapsed;
                let message = result.message;
                if guest_has_session_mux(&message) {
                    let stream = control_stream.take().ok_or_else(|| {
                        QemuBootError::GuestReadyTransport {
                            detail:
                                "guest advertised session_mux without an established control stream"
                                    .to_string(),
                            artifacts: artifacts.clone(),
                            serial_excerpt: read_excerpt(&artifacts.serial),
                        }
                    })?;
                    match MuxManager::start(stream) {
                        Ok(manager) => {
                            control_mux = Some(manager);
                        }
                        Err(error) => {
                            let error = QemuBootError::GuestReadyTransport {
                                detail: format!(
                                    "failed to start Windows session mux manager: {error}"
                                ),
                                artifacts: artifacts.clone(),
                                serial_excerpt: read_excerpt(&artifacts.serial),
                            };
                            record_failure(
                                &artifacts,
                                config.guest_ready_timeout,
                                observation_goal,
                                &error,
                            );
                            let _ = supervisor.terminate();
                            return Err(error);
                        }
                    }
                }

                write_boot_status_file(
                    &artifacts,
                    observation_goal.success_state,
                    observation_goal.success_definition,
                    config.guest_ready_timeout,
                    Some(elapsed.as_millis()),
                    Some(&message),
                    None,
                    None,
                )?;
                #[cfg(test)]
                {
                    guest_ready_elapsed = Some(elapsed);
                }
                guest_ready = Some(message);
            }
            Err(error) => {
                record_failure(
                    &artifacts,
                    config.guest_ready_timeout,
                    observation_goal,
                    &error,
                );
                let _ = supervisor.terminate();
                return Err(error);
            }
        }
    } else {
        if let Err(error) =
            observe_boot(&mut supervisor, &artifacts, config.boot_observation_timeout)
        {
            record_failure(
                &artifacts,
                config.boot_observation_timeout,
                observation_goal,
                &error,
            );
            return Err(error);
        }

        write_boot_status_file(
            &artifacts,
            observation_goal.success_state,
            observation_goal.success_definition,
            config.boot_observation_timeout,
            None,
            None,
            None,
            None,
        )?;
    }

    Ok(WindowsQemuBoot {
        supervisor,
        artifacts,
        control_stream,
        control_mux,
        forward_stream,
        guest_ready,
        #[cfg(test)]
        guest_ready_elapsed,
    })
}

fn run_preflight(data_dir: Option<&Path>) -> Result<QemuPreflightReport, QemuPreflightError> {
    let host = StdQemuDiscoveryHost;
    let runner = StdQemuCommandRunner;
    let discovery = match data_dir {
        Some(data_dir) => QemuDiscovery::new(&host).with_managed_data_dir(data_dir),
        None => QemuDiscovery::new(&host),
    };
    QemuPreflight::new(discovery, &runner).run()
}

fn map_control_open_error(
    source: VirtioSerialControlError,
    supervisor: &mut QemuSupervisor,
    artifacts: &QemuBootArtifacts,
    elapsed: Duration,
) -> QemuBootError {
    match supervisor.try_status() {
        Ok(
            state @ (QemuProcessState::Exited
            | QemuProcessState::Failed
            | QemuProcessState::Terminated),
        ) => guest_ready_process_exited_error(
            state,
            supervisor,
            artifacts,
            elapsed,
            CONTROL_STATE_OPENING_FOR_READY,
        ),
        Ok(
            QemuProcessState::Running | QemuProcessState::Starting | QemuProcessState::NotStarted,
        ) => QemuBootError::ControlOpen {
            source,
            artifacts: artifacts.clone(),
        },
        Err(source) => QemuBootError::ProcessStatus {
            source,
            artifacts: artifacts.clone(),
        },
    }
}

fn map_forward_open_error(
    source: VirtioSerialControlError,
    supervisor: &mut QemuSupervisor,
    artifacts: &QemuBootArtifacts,
    elapsed: Duration,
) -> QemuBootError {
    match supervisor.try_status() {
        Ok(
            state @ (QemuProcessState::Exited
            | QemuProcessState::Failed
            | QemuProcessState::Terminated),
        ) => guest_ready_process_exited_error(
            state,
            supervisor,
            artifacts,
            elapsed,
            CONTROL_STATE_OPENING_FORWARD_CHANNEL,
        ),
        Ok(
            QemuProcessState::Running | QemuProcessState::Starting | QemuProcessState::NotStarted,
        ) => QemuBootError::ControlOpen {
            source,
            artifacts: artifacts.clone(),
        },
        Err(source) => QemuBootError::ProcessStatus {
            source,
            artifacts: artifacts.clone(),
        },
    }
}

fn guest_ready_process_exited_error(
    state: QemuProcessState,
    supervisor: &QemuSupervisor,
    artifacts: &QemuBootArtifacts,
    elapsed: Duration,
    control_state: &'static str,
) -> QemuBootError {
    QemuBootError::GuestReadyProcessExited {
        state,
        exit_status: supervisor.exit_status().cloned(),
        artifacts: artifacts.clone(),
        elapsed,
        control_state,
        stderr_excerpt: read_excerpt(&artifacts.process.stderr),
        serial_excerpt: read_excerpt(&artifacts.serial),
    }
}

fn resolve_artifacts(config: &WindowsQemuBootConfig) -> Result<QemuBootArtifacts, QemuBootError> {
    let directory = if let Some(directory) = &config.artifact_directory {
        absolute_path(directory).map_err(|err| QemuBootError::ArtifactIo {
            path: directory.clone(),
            operation: "resolve diagnostics directory",
            detail: err.to_string(),
            artifacts: None,
        })?
    } else {
        let instance_dir =
            config
                .rootfs_image
                .parent()
                .ok_or_else(|| QemuBootError::InvalidConfig {
                    field: "rootfs_image",
                    reason: "must include a parent instance directory when no artifact directory is supplied".to_string(),
                    artifacts: None,
                })?;
        absolute_path(&instance_dir.join("diagnostics")).map_err(|err| {
            QemuBootError::ArtifactIo {
                path: instance_dir.join("diagnostics"),
                operation: "resolve default diagnostics directory",
                detail: err.to_string(),
                artifacts: None,
            }
        })?
    };
    Ok(QemuBootArtifacts::new(directory))
}

fn prepare_artifacts(artifacts: &QemuBootArtifacts) -> Result<(), QemuBootError> {
    fs::create_dir_all(&artifacts.directory).map_err(|err| QemuBootError::ArtifactIo {
        path: artifacts.directory.clone(),
        operation: "create diagnostics directory",
        detail: err.to_string(),
        artifacts: Some(artifacts.clone()),
    })?;
    fs::File::create(&artifacts.serial).map_err(|err| QemuBootError::ArtifactIo {
        path: artifacts.serial.clone(),
        operation: "create serial log",
        detail: err.to_string(),
        artifacts: Some(artifacts.clone()),
    })?;
    Ok(())
}

fn require_existing_file(
    asset: &'static str,
    path: &Path,
    artifacts: &QemuBootArtifacts,
) -> Result<PathBuf, QemuBootError> {
    if path.as_os_str().is_empty() {
        return Err(QemuBootError::InvalidConfig {
            field: asset,
            reason: "path must not be empty".to_string(),
            artifacts: Some(artifacts.clone()),
        });
    }
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => canonical_or_absolute(path, artifacts),
        Ok(_) => Err(QemuBootError::AssetMissing {
            asset,
            path: path.to_path_buf(),
            reason: "path exists but is not a file".to_string(),
            artifacts: artifacts.clone(),
        }),
        Err(err) => Err(QemuBootError::AssetMissing {
            asset,
            path: path.to_path_buf(),
            reason: err.to_string(),
            artifacts: artifacts.clone(),
        }),
    }
}

fn canonical_or_absolute(
    path: &Path,
    artifacts: &QemuBootArtifacts,
) -> Result<PathBuf, QemuBootError> {
    if let Ok(path) = fs::canonicalize(path) {
        return Ok(path);
    }
    absolute_path(path).map_err(|err| QemuBootError::ArtifactIo {
        path: path.to_path_buf(),
        operation: "resolve absolute asset path",
        detail: err.to_string(),
        artifacts: Some(artifacts.clone()),
    })
}

fn absolute_path(path: &Path) -> io::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(env::current_dir()?.join(path))
    }
}

fn memory_mib(memory_bytes: u64, artifacts: &QemuBootArtifacts) -> Result<u64, QemuBootError> {
    let memory_mib = memory_bytes / 1024 / 1024;
    if memory_mib == 0 {
        Err(QemuBootError::InvalidConfig {
            field: "memory_bytes",
            reason: "must be at least 1 MiB".to_string(),
            artifacts: Some(artifacts.clone()),
        })
    } else {
        Ok(memory_mib)
    }
}

fn vcpu_count(vcpu_count: usize, artifacts: &QemuBootArtifacts) -> Result<u16, QemuBootError> {
    u16::try_from(vcpu_count)
        .ok()
        .filter(|count| *count > 0)
        .ok_or_else(|| QemuBootError::InvalidConfig {
            field: "vcpu_count",
            reason: "must be between 1 and 65535".to_string(),
            artifacts: Some(artifacts.clone()),
        })
}

fn write_preflight_report(
    artifacts: &QemuBootArtifacts,
    report: &QemuPreflightReport,
) -> Result<(), QemuBootError> {
    let contents =
        serde_json::to_string_pretty(report).map_err(|err| QemuBootError::ArtifactIo {
            path: artifacts.preflight.clone(),
            operation: "serialize QEMU preflight report",
            detail: err.to_string(),
            artifacts: Some(artifacts.clone()),
        })?;
    fs::write(&artifacts.preflight, format!("{contents}\n")).map_err(|err| {
        QemuBootError::ArtifactIo {
            path: artifacts.preflight.clone(),
            operation: "write QEMU preflight report",
            detail: err.to_string(),
            artifacts: Some(artifacts.clone()),
        }
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BootObservationGoal {
    success_state: &'static str,
    success_definition: &'static str,
}

impl BootObservationGoal {
    fn for_config(config: &WindowsQemuBootConfig) -> Self {
        if config.control_endpoint.is_some() {
            Self::virtio_serial_control()
        } else {
            Self::serial_output()
        }
    }

    fn serial_output() -> Self {
        Self {
            success_state: "serial_observed_alive",
            success_definition: SERIAL_OBSERVED_SUCCESS_DEFINITION,
        }
    }

    fn virtio_serial_control() -> Self {
        Self {
            success_state: "guest_ready",
            success_definition: GUEST_READY_SUCCESS_DEFINITION,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GuestReadyResult {
    message: GuestReady,
    elapsed: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum GuestReadyFrameError {
    Eof,
    Transport(String),
    Protocol {
        reason: String,
        frame_type: Option<u8>,
    },
    UnsupportedCapabilities(Vec<String>),
}

fn wait_for_guest_ready<R>(
    supervisor: &mut QemuSupervisor,
    artifacts: &QemuBootArtifacts,
    timeout: Duration,
    mut reader: R,
    expected_transport: GuestTransport,
) -> Result<GuestReadyResult, QemuBootError>
where
    R: Read + Send + 'static,
{
    let started_at = Instant::now();
    let deadline = started_at + timeout;
    let (sender, receiver) = mpsc::channel();

    std::thread::spawn(move || {
        let result = read_guest_ready_frame(&mut reader, expected_transport);
        let _ = sender.send(result);
    });

    loop {
        match receiver.try_recv() {
            Ok(Ok(message)) => {
                return Ok(GuestReadyResult {
                    message,
                    elapsed: started_at.elapsed(),
                });
            }
            Ok(Err(error)) => return Err(map_guest_ready_frame_error(error, artifacts)),
            Err(mpsc::TryRecvError::Disconnected) => {
                return Err(QemuBootError::GuestReadyTransport {
                    detail: "guest-ready reader thread ended before sending a result".to_string(),
                    artifacts: artifacts.clone(),
                    serial_excerpt: read_excerpt(&artifacts.serial),
                });
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }

        match supervisor.try_status() {
            Ok(QemuProcessState::Running | QemuProcessState::Starting) => {}
            Ok(
                state @ (QemuProcessState::Exited
                | QemuProcessState::Failed
                | QemuProcessState::Terminated),
            ) => {
                return Err(guest_ready_process_exited_error(
                    state,
                    supervisor,
                    artifacts,
                    started_at.elapsed(),
                    CONTROL_STATE_WAITING_FOR_READY,
                ));
            }
            Ok(QemuProcessState::NotStarted) => {
                return Err(QemuBootError::ProcessStatus {
                    source: QemuProcessError::NotStarted,
                    artifacts: artifacts.clone(),
                });
            }
            Err(source) => {
                return Err(QemuBootError::ProcessStatus {
                    source,
                    artifacts: artifacts.clone(),
                });
            }
        }

        if Instant::now() >= deadline {
            return Err(QemuBootError::GuestReadyTimeout {
                timeout,
                elapsed: started_at.elapsed(),
                artifacts: artifacts.clone(),
                serial_excerpt: read_excerpt(&artifacts.serial),
                stderr_excerpt: read_excerpt(&artifacts.process.stderr),
            });
        }

        std::thread::sleep(BOOT_POLL_INTERVAL);
    }
}

fn read_guest_ready_frame(
    reader: &mut impl Read,
    expected_transport: GuestTransport,
) -> Result<GuestReady, GuestReadyFrameError> {
    let (msg_type, payload) = frame::read_frame(reader)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::InvalidData {
                GuestReadyFrameError::Protocol {
                    reason: error.to_string(),
                    frame_type: None,
                }
            } else {
                GuestReadyFrameError::Transport(error.to_string())
            }
        })?
        .ok_or(GuestReadyFrameError::Eof)?;

    if msg_type != frame::GUEST_READY {
        return Err(GuestReadyFrameError::Protocol {
            reason: format!(
                "expected GUEST_READY frame type 0x{:02x}, got frame type 0x{msg_type:02x} with {} payload bytes",
                frame::GUEST_READY,
                payload.len()
            ),
            frame_type: Some(msg_type),
        });
    }

    let ready: GuestReady =
        serde_json::from_slice(&payload).map_err(|error| GuestReadyFrameError::Protocol {
            reason: format!(
                "failed to decode GUEST_READY JSON payload with {} bytes: {error}",
                payload.len()
            ),
            frame_type: Some(msg_type),
        })?;

    if ready.protocol_version != lsb_proto::PROTOCOL_VERSION {
        return Err(GuestReadyFrameError::Protocol {
            reason: format!(
                "unsupported guest protocol version {}; expected {}",
                ready.protocol_version,
                lsb_proto::PROTOCOL_VERSION
            ),
            frame_type: Some(msg_type),
        });
    }

    if ready.transport != expected_transport {
        return Err(GuestReadyFrameError::Protocol {
            reason: format!(
                "guest reported transport {}; expected {}",
                transport_label(&ready.transport),
                transport_label(&expected_transport)
            ),
            frame_type: Some(msg_type),
        });
    }

    let unsupported = unsupported_guest_capabilities(&ready.capabilities);
    if !unsupported.is_empty() {
        return Err(GuestReadyFrameError::UnsupportedCapabilities(unsupported));
    }

    Ok(ready)
}

fn map_guest_ready_frame_error(
    error: GuestReadyFrameError,
    artifacts: &QemuBootArtifacts,
) -> QemuBootError {
    match error {
        GuestReadyFrameError::Eof => QemuBootError::GuestReadyTransport {
            detail: "control channel closed before the guest-ready frame arrived".to_string(),
            artifacts: artifacts.clone(),
            serial_excerpt: read_excerpt(&artifacts.serial),
        },
        GuestReadyFrameError::Transport(detail) => QemuBootError::GuestReadyTransport {
            detail,
            artifacts: artifacts.clone(),
            serial_excerpt: read_excerpt(&artifacts.serial),
        },
        GuestReadyFrameError::Protocol { reason, frame_type } => {
            QemuBootError::GuestReadyProtocol {
                reason,
                frame_type,
                artifacts: artifacts.clone(),
                serial_excerpt: read_excerpt(&artifacts.serial),
            }
        }
        GuestReadyFrameError::UnsupportedCapabilities(capabilities) => {
            QemuBootError::UnsupportedWindowsRuntimeCapability {
                capabilities,
                artifacts: artifacts.clone(),
                serial_excerpt: read_excerpt(&artifacts.serial),
            }
        }
    }
}

fn observe_boot(
    supervisor: &mut QemuSupervisor,
    artifacts: &QemuBootArtifacts,
    timeout: Duration,
) -> Result<(), QemuBootError> {
    let deadline = Instant::now() + timeout;
    loop {
        match supervisor.try_status() {
            Ok(QemuProcessState::Running | QemuProcessState::Starting) => {}
            Ok(
                state @ (QemuProcessState::Exited
                | QemuProcessState::Failed
                | QemuProcessState::Terminated),
            ) => {
                return Err(QemuBootError::GuestBootExited {
                    state,
                    exit_status: supervisor.exit_status().cloned(),
                    artifacts: artifacts.clone(),
                    stderr_excerpt: read_excerpt(&artifacts.process.stderr),
                    serial_excerpt: read_excerpt(&artifacts.serial),
                });
            }
            Ok(QemuProcessState::NotStarted) => {
                return Err(QemuBootError::ProcessStatus {
                    source: QemuProcessError::NotStarted,
                    artifacts: artifacts.clone(),
                });
            }
            Err(source) => {
                return Err(QemuBootError::ProcessStatus {
                    source,
                    artifacts: artifacts.clone(),
                });
            }
        }

        if Instant::now() >= deadline {
            let serial = fs::read(&artifacts.serial).unwrap_or_default();
            if !serial.is_empty() {
                return Ok(());
            }
            return Err(QemuBootError::SerialOutputMissing {
                artifacts: artifacts.clone(),
                stderr_excerpt: read_excerpt(&artifacts.process.stderr),
            });
        }
        std::thread::sleep(BOOT_POLL_INTERVAL);
    }
}

fn record_error(
    artifacts: &QemuBootArtifacts,
    timeout: Duration,
    observation_goal: BootObservationGoal,
    error: QemuBootError,
) -> QemuBootError {
    record_failure(artifacts, timeout, observation_goal, &error);
    error
}

fn record_failure(
    artifacts: &QemuBootArtifacts,
    timeout: Duration,
    observation_goal: BootObservationGoal,
    error: &QemuBootError,
) {
    let _ = write_boot_status_file(
        artifacts,
        "failed",
        observation_goal.success_definition,
        timeout,
        None,
        None,
        Some(error.kind()),
        Some(error.to_string()),
    );
}

fn write_boot_status_file(
    artifacts: &QemuBootArtifacts,
    state: &'static str,
    success_definition: &'static str,
    observation_timeout: Duration,
    elapsed_ms: Option<u128>,
    guest_ready: Option<&GuestReady>,
    error_kind: Option<QemuBootErrorKind>,
    error_message: Option<String>,
) -> Result<(), QemuBootError> {
    let artifact = QemuBootStatusArtifact {
        state,
        success_definition,
        observation_timeout_ms: observation_timeout.as_millis(),
        elapsed_ms,
        artifacts: QemuBootStatusFiles {
            serial: file_name(&artifacts.serial),
            stdout: file_name(&artifacts.process.stdout),
            stderr: file_name(&artifacts.process.stderr),
            argv: file_name(&artifacts.process.argv),
            process_status: file_name(&artifacts.process.status),
            preflight: file_name(&artifacts.preflight),
            boot_status: file_name(&artifacts.boot_status),
        },
        guest_ready: guest_ready.map(QemuGuestReadyStatus::from_ready),
        error_kind: error_kind.map(QemuBootErrorKind::as_str),
        error_message,
    };
    let contents =
        serde_json::to_string_pretty(&artifact).map_err(|err| QemuBootError::ArtifactIo {
            path: artifacts.boot_status.clone(),
            operation: "serialize boot status",
            detail: err.to_string(),
            artifacts: Some(artifacts.clone()),
        })?;
    fs::write(&artifacts.boot_status, format!("{contents}\n")).map_err(|err| {
        QemuBootError::ArtifactIo {
            path: artifacts.boot_status.clone(),
            operation: "write boot status",
            detail: err.to_string(),
            artifacts: Some(artifacts.clone()),
        }
    })
}

#[derive(Debug, Serialize)]
struct QemuBootStatusArtifact {
    state: &'static str,
    success_definition: &'static str,
    observation_timeout_ms: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    elapsed_ms: Option<u128>,
    artifacts: QemuBootStatusFiles,
    #[serde(skip_serializing_if = "Option::is_none")]
    guest_ready: Option<QemuGuestReadyStatus>,
    error_kind: Option<&'static str>,
    error_message: Option<String>,
}

#[derive(Debug, Serialize)]
struct QemuBootStatusFiles {
    serial: String,
    stdout: String,
    stderr: String,
    argv: String,
    process_status: String,
    preflight: String,
    boot_status: String,
}

#[derive(Debug, Serialize)]
struct QemuGuestReadyStatus {
    protocol_version: u16,
    transport: &'static str,
    guest_version: String,
    capabilities: Vec<String>,
}

impl QemuGuestReadyStatus {
    fn from_ready(ready: &GuestReady) -> Self {
        Self {
            protocol_version: ready.protocol_version,
            transport: transport_label(&ready.transport),
            guest_version: ready.guest_version.clone(),
            capabilities: ready.capabilities.clone(),
        }
    }
}

fn read_excerpt(path: &Path) -> String {
    fs::read(path)
        .map(|bytes| lossy_excerpt(&bytes))
        .unwrap_or_else(|err| format!("<could not read '{}': {err}>", path.display()))
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "<unknown>".to_string())
}

fn empty_as_placeholder(value: &str) -> &str {
    if value.is_empty() {
        "<empty>"
    } else {
        value
    }
}

fn transport_label(transport: &GuestTransport) -> &'static str {
    match transport {
        GuestTransport::Vsock => "vsock",
        GuestTransport::VirtioSerial => "virtio_serial",
    }
}

fn capability_summary(capabilities: &[String]) -> String {
    if capabilities.is_empty() {
        return "<none>".to_string();
    }
    let mut labels = capabilities
        .iter()
        .take(5)
        .map(|value| sanitize_capability_label(value))
        .collect::<Vec<_>>();
    if capabilities.len() > labels.len() {
        labels.push(format!("and {} more", capabilities.len() - labels.len()));
    }
    labels.join(", ")
}

fn unsupported_guest_capabilities(capabilities: &[String]) -> Vec<String> {
    capabilities
        .iter()
        .filter(|capability| {
            !matches!(
                capability.as_str(),
                lsb_proto::CAP_FILE_RANGE_IO
                    | lsb_proto::CAP_PORT_FORWARD
                    | lsb_proto::CAP_CIFS_MOUNT
                    | lsb_proto::CAP_SESSION_MUX
                    | lsb_proto::CAP_DEFERRED_FILE_SYNC
            )
        })
        .cloned()
        .collect()
}

fn guest_has_session_mux(ready: &GuestReady) -> bool {
    ready
        .capabilities
        .iter()
        .any(|capability| capability == lsb_proto::CAP_SESSION_MUX)
}

fn sanitize_capability_label(value: &str) -> String {
    let mut label = value
        .chars()
        .take(64)
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    if value.chars().count() > 64 {
        label.push_str("...");
    }
    if label.is_empty() {
        "<empty>".to_string()
    } else {
        label
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::io::{Cursor, Write};
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::windows_x86_64::qemu::argv::QemuArgvBuilder;
    use crate::windows_x86_64::qemu::config::QemuBootConfig;

    const FAKE_BOOT_CHILD_ENV: &str = "LSB_QEMU_BOOT_TEST_CHILD";
    const FAKE_BOOT_CHILD_TEST_NAME: &str =
        "windows_x86_64::qemu::boot::tests::fake_boot_child_entrypoint";
    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir(label: &str) -> PathBuf {
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        env::temp_dir().join(format!(
            "lsb-qemu-boot-{label}-{}-{counter}",
            std::process::id()
        ))
    }

    fn boot_config(rootfs: PathBuf) -> WindowsQemuBootConfig {
        WindowsQemuBootConfig::new(
            rootfs.with_file_name("Image"),
            rootfs.with_file_name("initramfs.cpio.gz"),
            rootfs,
            512 * 1024 * 1024,
            2,
        )
    }

    fn fake_child_args() -> Vec<OsString> {
        ["--exact", "--nocapture", FAKE_BOOT_CHILD_TEST_NAME]
            .into_iter()
            .map(OsString::from)
            .collect()
    }

    fn fake_command() -> super::super::argv::QemuCommand {
        let executable = env::current_exe().expect("test executable path should be available");
        let mut command = QemuArgvBuilder::new(QemuBootConfig::direct_linux_boot(
            executable,
            "Image",
            "initramfs.cpio.gz",
            "root.qcow2",
            "serial.log",
            256,
            1,
        ))
        .build()
        .expect("fake command should build");
        command.argv = fake_child_args();
        command
    }

    fn fake_supervisor(mode: &str, artifact_dir: PathBuf) -> QemuSupervisor {
        let mut config = QemuSupervisorConfig::new(fake_command(), artifact_dir);
        config.startup_timeout = Duration::from_millis(100);
        config.terminate_timeout = Duration::from_secs(2);
        config.environment.variables.push((
            OsString::from(FAKE_BOOT_CHILD_ENV),
            OsString::from(mode.to_string()),
        ));
        QemuSupervisor::new(config)
    }

    #[test]
    fn fake_boot_child_entrypoint() {
        let Ok(mode) = env::var(FAKE_BOOT_CHILD_ENV) else {
            return;
        };

        if mode == "sleep" {
            eprintln!("fake boot child running without serial output");
            let _ = std::io::stderr().flush();
            std::thread::sleep(Duration::from_secs(60));
        } else if mode == "exit-after-start" {
            eprintln!("fake boot child exiting after startup");
            let _ = std::io::stderr().flush();
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    #[test]
    fn default_artifacts_are_under_rootfs_parent_diagnostics() {
        let rootfs = temp_dir("paths").join("instance").join("rootfs.ext4");
        let artifacts =
            resolve_artifacts(&boot_config(rootfs.clone())).expect("artifacts should resolve");

        assert_eq!(
            artifacts.directory,
            rootfs.parent().expect("parent").join("diagnostics")
        );
        assert_eq!(artifacts.serial, artifacts.directory.join("serial.log"));
        assert_eq!(
            artifacts.process.stderr,
            artifacts.directory.join("qemu.stderr.log")
        );
        assert_eq!(
            artifacts.boot_status,
            artifacts.directory.join("boot.status.json")
        );
    }

    #[test]
    fn missing_asset_error_includes_deterministic_log_locations() {
        let root = temp_dir("missing-asset");
        let rootfs = root.join("instance").join("rootfs.ext4");
        let mut config = boot_config(rootfs);
        config.boot_observation_timeout = Duration::ZERO;

        let err = launch_windows_qemu_boot(config).expect_err("missing kernel should fail first");

        assert_eq!(err.kind(), QemuBootErrorKind::AssetMissing);
        let message = err.to_string();
        assert!(message.contains("kernel Image"));
        assert!(message.contains("serial.log"));
        assert!(message.contains("qemu.stderr.log"));
        assert!(message.contains("boot.status.json"));

        let artifacts = err.artifacts().expect("artifacts");
        assert!(artifacts.serial.is_file());
        assert!(artifacts.boot_status.is_file());
        let status = fs::read_to_string(&artifacts.boot_status).expect("boot status artifact");
        assert!(status.contains("\"state\": \"failed\""));
        assert!(status.contains("\"error_kind\": \"asset_missing\""));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn boot_status_success_artifact_records_serial_observation_definition() {
        let artifact_dir = temp_dir("status");
        let artifacts = QemuBootArtifacts::new(&artifact_dir);
        fs::create_dir_all(&artifact_dir).expect("artifact dir should be writable");

        write_boot_status_file(
            &artifacts,
            "serial_observed_alive",
            SERIAL_OBSERVED_SUCCESS_DEFINITION,
            Duration::from_millis(1500),
            None,
            None,
            None,
            None,
        )
        .expect("status should write");

        let status = fs::read_to_string(&artifacts.boot_status).expect("status artifact");
        assert!(status.contains("\"state\": \"serial_observed_alive\""));
        assert!(
            status.contains("qemu_process_alive_after_boot_observation_window_with_serial_output")
        );
        assert!(status.contains("\"serial\": \"serial.log\""));
        assert!(status.contains("\"observation_timeout_ms\": 1500"));

        let _ = fs::remove_dir_all(artifact_dir);
    }

    #[test]
    fn boot_status_success_artifact_records_guest_ready_details() {
        let artifact_dir = temp_dir("ready-status");
        let artifacts = QemuBootArtifacts::new(&artifact_dir);
        fs::create_dir_all(&artifact_dir).expect("artifact dir should be writable");
        let mut ready = GuestReady::new(GuestTransport::VirtioSerial, "guest-test");
        ready
            .capabilities
            .push(lsb_proto::CAP_FILE_RANGE_IO.to_string());
        ready
            .capabilities
            .push(lsb_proto::CAP_PORT_FORWARD.to_string());

        write_boot_status_file(
            &artifacts,
            "guest_ready",
            GUEST_READY_SUCCESS_DEFINITION,
            Duration::from_secs(30),
            Some(1234),
            Some(&ready),
            None,
            None,
        )
        .expect("ready status should write");

        let status = fs::read_to_string(&artifacts.boot_status).expect("status artifact");
        assert!(status.contains("\"state\": \"guest_ready\""));
        assert!(status.contains(GUEST_READY_SUCCESS_DEFINITION));
        assert!(status.contains("\"elapsed_ms\": 1234"));
        assert!(status.contains("\"protocol_version\": 1"));
        assert!(status.contains("\"transport\": \"virtio_serial\""));
        assert!(status.contains("\"guest_version\": \"guest-test\""));
        assert!(status.contains(lsb_proto::CAP_FILE_RANGE_IO));
        assert!(status.contains(lsb_proto::CAP_PORT_FORWARD));

        let _ = fs::remove_dir_all(artifact_dir);
    }

    fn guest_ready_frame(ready: &GuestReady) -> Cursor<Vec<u8>> {
        let mut stream = Cursor::new(Vec::new());
        frame::send_json(&mut stream, frame::GUEST_READY, ready)
            .expect("ready frame should serialize");
        stream.set_position(0);
        stream
    }

    fn unsupported_capability_ready_frame() -> Cursor<Vec<u8>> {
        let mut ready = GuestReady::new(GuestTransport::VirtioSerial, "guest-test");
        ready.capabilities.push("exec".to_string());
        guest_ready_frame(&ready)
    }

    fn supported_windows_ready_frame() -> Cursor<Vec<u8>> {
        let mut ready = GuestReady::new(GuestTransport::VirtioSerial, "guest-test");
        ready
            .capabilities
            .push(lsb_proto::CAP_FILE_RANGE_IO.to_string());
        ready
            .capabilities
            .push(lsb_proto::CAP_PORT_FORWARD.to_string());
        ready
            .capabilities
            .push(lsb_proto::CAP_CIFS_MOUNT.to_string());
        ready
            .capabilities
            .push(lsb_proto::CAP_SESSION_MUX.to_string());
        ready
            .capabilities
            .push(lsb_proto::CAP_DEFERRED_FILE_SYNC.to_string());
        guest_ready_frame(&ready)
    }

    struct BlockingReader {
        receiver: mpsc::Receiver<u8>,
    }

    impl Read for BlockingReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.receiver.recv() {
                Ok(byte) => {
                    if buf.is_empty() {
                        Ok(0)
                    } else {
                        buf[0] = byte;
                        Ok(1)
                    }
                }
                Err(_) => Ok(0),
            }
        }
    }

    #[test]
    fn observe_boot_fails_when_serial_log_stays_empty() {
        let artifact_dir = temp_dir("empty-serial");
        let artifacts = QemuBootArtifacts::new(&artifact_dir);
        prepare_artifacts(&artifacts).expect("artifacts should prepare");
        let mut supervisor = fake_supervisor("sleep", artifact_dir.clone());
        supervisor.start().expect("fake supervisor should start");

        let err = observe_boot(&mut supervisor, &artifacts, Duration::from_millis(100))
            .expect_err("empty serial should fail boot observation");
        assert_eq!(err.kind(), QemuBootErrorKind::SerialOutputMissing);
        assert!(err.to_string().contains("serial.log remained empty"));

        supervisor
            .terminate()
            .expect("fake supervisor should terminate");
        let _ = fs::remove_dir_all(artifact_dir);
    }

    #[test]
    fn wait_for_guest_ready_accepts_valid_virtio_serial_ready() {
        let artifact_dir = temp_dir("ready-success");
        let artifacts = QemuBootArtifacts::new(&artifact_dir);
        prepare_artifacts(&artifacts).expect("artifacts should prepare");
        let ready = GuestReady::new(GuestTransport::VirtioSerial, "guest-test");
        let mut supervisor = fake_supervisor("sleep", artifact_dir.clone());
        supervisor.start().expect("fake supervisor should start");

        let result = wait_for_guest_ready(
            &mut supervisor,
            &artifacts,
            Duration::from_secs(1),
            guest_ready_frame(&ready),
            GuestTransport::VirtioSerial,
        )
        .expect("valid guest ready should pass");

        assert_eq!(result.message, ready);
        assert!(result.elapsed < Duration::from_secs(1));

        supervisor
            .terminate()
            .expect("fake supervisor should terminate");
        let _ = fs::remove_dir_all(artifact_dir);
    }

    #[test]
    fn wait_for_guest_ready_accepts_windows_runtime_capabilities() {
        let artifact_dir = temp_dir("ready-file-range-capability");
        let artifacts = QemuBootArtifacts::new(&artifact_dir);
        prepare_artifacts(&artifacts).expect("artifacts should prepare");
        let mut supervisor = fake_supervisor("sleep", artifact_dir.clone());
        supervisor.start().expect("fake supervisor should start");

        let result = wait_for_guest_ready(
            &mut supervisor,
            &artifacts,
            Duration::from_secs(1),
            supported_windows_ready_frame(),
            GuestTransport::VirtioSerial,
        )
        .expect("Windows runtime capabilities should be accepted");

        assert_eq!(
            result.message.capabilities,
            [
                lsb_proto::CAP_FILE_RANGE_IO.to_string(),
                lsb_proto::CAP_PORT_FORWARD.to_string(),
                lsb_proto::CAP_CIFS_MOUNT.to_string(),
                lsb_proto::CAP_SESSION_MUX.to_string(),
                lsb_proto::CAP_DEFERRED_FILE_SYNC.to_string()
            ]
        );

        supervisor
            .terminate()
            .expect("fake supervisor should terminate");
        let _ = fs::remove_dir_all(artifact_dir);
    }

    #[test]
    fn wait_for_guest_ready_times_out_without_ready_frame() {
        let artifact_dir = temp_dir("ready-timeout");
        let artifacts = QemuBootArtifacts::new(&artifact_dir);
        prepare_artifacts(&artifacts).expect("artifacts should prepare");
        let (sender, receiver) = mpsc::channel();
        let mut supervisor = fake_supervisor("sleep", artifact_dir.clone());
        supervisor.start().expect("fake supervisor should start");

        let err = wait_for_guest_ready(
            &mut supervisor,
            &artifacts,
            Duration::from_millis(100),
            BlockingReader { receiver },
            GuestTransport::VirtioSerial,
        )
        .expect_err("missing ready should time out");
        drop(sender);

        assert_eq!(err.kind(), QemuBootErrorKind::GuestReadyTimeout);
        assert!(err.to_string().contains("guest-ready handshake"));
        assert!(err.to_string().contains(CONTROL_STATE_WAITING_FOR_READY));

        supervisor
            .terminate()
            .expect("fake supervisor should terminate");
        let _ = fs::remove_dir_all(artifact_dir);
    }

    #[test]
    fn wait_for_guest_ready_rejects_invalid_frame_type() {
        let artifact_dir = temp_dir("ready-invalid-frame");
        let artifacts = QemuBootArtifacts::new(&artifact_dir);
        prepare_artifacts(&artifacts).expect("artifacts should prepare");
        let mut frame_stream = Cursor::new(Vec::new());
        frame::write_frame(&mut frame_stream, frame::STDOUT, b"hello")
            .expect("invalid frame fixture should write");
        frame_stream.set_position(0);
        let mut supervisor = fake_supervisor("sleep", artifact_dir.clone());
        supervisor.start().expect("fake supervisor should start");

        let err = wait_for_guest_ready(
            &mut supervisor,
            &artifacts,
            Duration::from_secs(1),
            frame_stream,
            GuestTransport::VirtioSerial,
        )
        .expect_err("wrong frame type should fail readiness");

        assert_eq!(err.kind(), QemuBootErrorKind::GuestReadyProtocol);
        assert!(err.to_string().contains("type 0x02"));
        assert!(err.to_string().contains("expected GUEST_READY"));

        supervisor
            .terminate()
            .expect("fake supervisor should terminate");
        let _ = fs::remove_dir_all(artifact_dir);
    }

    #[test]
    fn wait_for_guest_ready_rejects_protocol_version_mismatch() {
        let artifact_dir = temp_dir("ready-version-mismatch");
        let artifacts = QemuBootArtifacts::new(&artifact_dir);
        prepare_artifacts(&artifacts).expect("artifacts should prepare");
        let mut ready = GuestReady::new(GuestTransport::VirtioSerial, "guest-test");
        ready.protocol_version = lsb_proto::PROTOCOL_VERSION + 1;
        let mut supervisor = fake_supervisor("sleep", artifact_dir.clone());
        supervisor.start().expect("fake supervisor should start");

        let err = wait_for_guest_ready(
            &mut supervisor,
            &artifacts,
            Duration::from_secs(1),
            guest_ready_frame(&ready),
            GuestTransport::VirtioSerial,
        )
        .expect_err("protocol version mismatch should fail readiness");

        assert_eq!(err.kind(), QemuBootErrorKind::GuestReadyProtocol);
        assert!(err
            .to_string()
            .contains("unsupported guest protocol version"));

        supervisor
            .terminate()
            .expect("fake supervisor should terminate");
        let _ = fs::remove_dir_all(artifact_dir);
    }

    #[test]
    fn wait_for_guest_ready_rejects_unsupported_capabilities() {
        let artifact_dir = temp_dir("ready-unsupported-capability");
        let artifacts = QemuBootArtifacts::new(&artifact_dir);
        prepare_artifacts(&artifacts).expect("artifacts should prepare");
        let mut supervisor = fake_supervisor("sleep", artifact_dir.clone());
        supervisor.start().expect("fake supervisor should start");

        let err = wait_for_guest_ready(
            &mut supervisor,
            &artifacts,
            Duration::from_secs(1),
            unsupported_capability_ready_frame(),
            GuestTransport::VirtioSerial,
        )
        .expect_err("unsupported guest capabilities should fail readiness");

        assert_eq!(
            err.kind(),
            QemuBootErrorKind::UnsupportedWindowsRuntimeCapability
        );
        assert!(err.to_string().contains("exec"));

        supervisor
            .terminate()
            .expect("fake supervisor should terminate");
        let _ = fs::remove_dir_all(artifact_dir);
    }

    #[test]
    fn wait_for_guest_ready_reports_qemu_exit_before_ready() {
        let artifact_dir = temp_dir("ready-early-exit");
        let artifacts = QemuBootArtifacts::new(&artifact_dir);
        prepare_artifacts(&artifacts).expect("artifacts should prepare");
        let (sender, receiver) = mpsc::channel();
        let mut supervisor = fake_supervisor("exit-after-start", artifact_dir.clone());
        supervisor.start().expect("fake supervisor should start");

        let err = wait_for_guest_ready(
            &mut supervisor,
            &artifacts,
            Duration::from_secs(2),
            BlockingReader { receiver },
            GuestTransport::VirtioSerial,
        )
        .expect_err("QEMU exit before ready should fail readiness");
        drop(sender);

        assert_eq!(err.kind(), QemuBootErrorKind::GuestReadyProcessExited);
        assert!(err.to_string().contains("exited before"));
        assert!(err.to_string().contains("guest-ready handshake"));

        let _ = supervisor.terminate();
        let _ = fs::remove_dir_all(artifact_dir);
    }

    #[test]
    fn control_open_failure_after_qemu_exit_reports_guest_ready_process_exit() {
        let artifact_dir = temp_dir("control-open-early-exit");
        let artifacts = QemuBootArtifacts::new(&artifact_dir);
        prepare_artifacts(&artifacts).expect("artifacts should prepare");
        fs::write(
            &artifacts.serial,
            "guest serial before control pipe opened\n",
        )
        .expect("serial fixture should write");
        let mut supervisor = fake_supervisor("exit-after-start", artifact_dir.clone());
        supervisor.start().expect("fake supervisor should start");
        let control_open_started_at = Instant::now();
        let deadline = Instant::now() + Duration::from_secs(2);

        loop {
            match supervisor.try_status() {
                Ok(
                    QemuProcessState::Exited
                    | QemuProcessState::Failed
                    | QemuProcessState::Terminated,
                ) => break,
                Ok(QemuProcessState::Running | QemuProcessState::Starting)
                    if Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Ok(state) => panic!("fake supervisor reached unexpected state {state:?}"),
                Err(err) => panic!("fake supervisor status failed: {err}"),
            }
        }

        let err = map_control_open_error(
            VirtioSerialControlError::ConnectTimeout {
                timeout: Duration::from_millis(25),
                last_error: Some("pipe not found".to_string()),
            },
            &mut supervisor,
            &artifacts,
            control_open_started_at.elapsed(),
        );

        assert_eq!(err.kind(), QemuBootErrorKind::GuestReadyProcessExited);
        let message = err.to_string();
        assert!(message.contains("exited before"));
        assert!(message.contains(CONTROL_STATE_OPENING_FOR_READY));
        assert!(message.contains("fake boot child exiting after startup"));
        assert!(message.contains("guest serial before control pipe opened"));

        let _ = supervisor.terminate();
        let _ = fs::remove_dir_all(artifact_dir);
    }

    #[test]
    #[ignore = "requires Windows 11 x86_64 with WHPX, QEMU, and disposable LocalSandbox assets"]
    fn windows_qemu_boot_smoke() {
        #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
        {
            eprintln!("skipping Windows QEMU boot smoke on non-Windows host");
        }

        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        {
            let kernel = required_env_path("LSB_WINDOWS_BOOT_KERNEL");
            let initrd = required_env_path("LSB_WINDOWS_BOOT_INITRD");
            let rootfs = required_env_path("LSB_WINDOWS_BOOT_ROOTFS");
            let artifact_dir = env::var_os("LSB_WINDOWS_BOOT_ARTIFACT_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| temp_dir("smoke"));
            let timeout = env::var("LSB_WINDOWS_BOOT_OBSERVATION_SECS")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .map(Duration::from_secs)
                .unwrap_or(DEFAULT_BOOT_OBSERVATION_TIMEOUT);
            let ready_timeout = env::var("LSB_WINDOWS_GUEST_READY_SECS")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .map(Duration::from_secs)
                .unwrap_or(DEFAULT_GUEST_READY_TIMEOUT);

            let mut config =
                WindowsQemuBootConfig::new(kernel, initrd, rootfs, 2 * 1024 * 1024 * 1024, 2);
            let control_endpoint = VirtioSerialControlEndpoint::for_instance(&artifact_dir)
                .expect("smoke control endpoint name should be valid");
            config.artifact_directory = Some(artifact_dir);
            config.boot_observation_timeout = timeout;
            config.guest_ready_timeout = ready_timeout;
            config.diagnostic_label = Some("windows-qemu-boot-smoke".to_string());
            config.control_endpoint = Some(control_endpoint);

            let mut boot = launch_windows_qemu_boot(config)
                .expect("QEMU should boot and the guest should send LocalSandbox ready");
            let argv = fs::read_to_string(&boot.artifacts().process.argv)
                .expect("redacted QEMU argv should be readable");
            assert!(
                argv.contains("virtio-serial-pci"),
                "redacted argv should contain virtio-serial controller: {argv}"
            );
            assert!(
                argv.contains("virtserialport"),
                "redacted argv should contain virtio-serial control port: {argv}"
            );
            assert!(
                argv.contains("lsb.transport=virtio-serial"),
                "kernel cmdline should select virtio-serial transport: {argv}"
            );
            assert!(
                argv.contains("-nic none"),
                "redacted argv should preserve no guest NIC by default: {argv}"
            );
            let ready = boot
                .guest_ready()
                .expect("boot smoke should record guest ready");
            assert_eq!(ready.protocol_version, lsb_proto::PROTOCOL_VERSION);
            assert_eq!(ready.transport, GuestTransport::VirtioSerial);
            assert_eq!(
                ready.capabilities,
                [
                    lsb_proto::CAP_FILE_RANGE_IO.to_string(),
                    lsb_proto::CAP_PORT_FORWARD.to_string(),
                    lsb_proto::CAP_CIFS_MOUNT.to_string(),
                    lsb_proto::CAP_SESSION_MUX.to_string(),
                    lsb_proto::CAP_DEFERRED_FILE_SYNC.to_string()
                ]
            );
            let status = fs::read_to_string(&boot.artifacts().boot_status)
                .expect("boot status should be readable");
            assert!(status.contains("\"state\": \"guest_ready\""));
            assert!(status.contains(GUEST_READY_SUCCESS_DEFINITION));
            assert!(status.contains("\"transport\": \"virtio_serial\""));
            eprintln!(
                "Windows QEMU boot smoke reached LocalSandbox guest-ready in {} ms; logs: {}",
                boot.guest_ready_elapsed()
                    .map(|elapsed| elapsed.as_millis())
                    .unwrap_or_default(),
                boot.artifacts().summary()
            );
            boot.stop().expect("smoke QEMU should stop cleanly");
        }
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn required_env_path(name: &str) -> PathBuf {
        env::var_os(name)
            .map(PathBuf::from)
            .unwrap_or_else(|| panic!("{name} must point to a disposable boot asset path"))
    }
}
