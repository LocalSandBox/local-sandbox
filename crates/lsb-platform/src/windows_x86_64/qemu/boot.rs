use std::env;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::Serialize;

use super::argv::{QemuArgvBuilder, QemuArgvError};
use super::config::QemuBootConfig as QemuArgvBootConfig;
use super::discovery::{QemuDiscovery, StdQemuDiscoveryHost};
use super::preflight::{QemuPreflight, QemuPreflightReport};
use super::process::{
    QemuExitStatus, QemuProcessArtifacts, QemuProcessError, QemuProcessState, QemuSupervisor,
    QemuSupervisorConfig,
};
use super::{lossy_excerpt, QemuPreflightError, StdQemuCommandRunner};

pub(crate) const DEFAULT_BOOT_OBSERVATION_TIMEOUT: Duration = Duration::from_secs(10);
const BOOT_POLL_INTERVAL: Duration = Duration::from_millis(100);
const SERIAL_LOG_FILE: &str = "serial.log";
const PREFLIGHT_FILE: &str = "preflight.json";
const BOOT_STATUS_FILE: &str = "boot.status.json";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WindowsQemuBootConfig {
    pub kernel_image: PathBuf,
    pub initrd_image: PathBuf,
    pub rootfs_image: PathBuf,
    pub memory_bytes: u64,
    pub vcpu_count: usize,
    pub diagnostic_label: Option<String>,
    pub artifact_directory: Option<PathBuf>,
    pub boot_observation_timeout: Duration,
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
            kernel_image: kernel_image.into(),
            initrd_image: initrd_image.into(),
            rootfs_image: rootfs_image.into(),
            memory_bytes,
            vcpu_count,
            diagnostic_label: None,
            artifact_directory: None,
            boot_observation_timeout: DEFAULT_BOOT_OBSERVATION_TIMEOUT,
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
    observation_timeout: Duration,
}

impl WindowsQemuBoot {
    pub(crate) fn state(&self) -> QemuProcessState {
        self.supervisor.state()
    }

    pub(crate) fn artifacts(&self) -> &QemuBootArtifacts {
        &self.artifacts
    }

    pub(crate) fn observation_timeout(&self) -> Duration {
        self.observation_timeout
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
    UnsupportedConfig,
    InvalidConfig,
    ArtifactIo,
    Preflight,
    Argv,
    ProcessStart,
    ProcessStatus,
    GuestBootExited,
    StopFailed,
}

impl QemuBootErrorKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::AssetMissing => "asset_missing",
            Self::UnsupportedConfig => "unsupported_config",
            Self::InvalidConfig => "invalid_config",
            Self::ArtifactIo => "artifact_io",
            Self::Preflight => "preflight",
            Self::Argv => "argv",
            Self::ProcessStart => "process_start",
            Self::ProcessStatus => "process_status",
            Self::GuestBootExited => "guest_boot_exited",
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
    UnsupportedConfig {
        capability: &'static str,
        milestone: &'static str,
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
    StopFailed {
        source: QemuProcessError,
        artifacts: QemuBootArtifacts,
    },
}

impl QemuBootError {
    pub(crate) fn kind(&self) -> QemuBootErrorKind {
        match self {
            Self::AssetMissing { .. } => QemuBootErrorKind::AssetMissing,
            Self::UnsupportedConfig { .. } => QemuBootErrorKind::UnsupportedConfig,
            Self::InvalidConfig { .. } => QemuBootErrorKind::InvalidConfig,
            Self::ArtifactIo { .. } => QemuBootErrorKind::ArtifactIo,
            Self::Preflight { .. } => QemuBootErrorKind::Preflight,
            Self::Argv { .. } => QemuBootErrorKind::Argv,
            Self::ProcessStart { .. } => QemuBootErrorKind::ProcessStart,
            Self::ProcessStatus { .. } => QemuBootErrorKind::ProcessStatus,
            Self::GuestBootExited { .. } => QemuBootErrorKind::GuestBootExited,
            Self::StopFailed { .. } => QemuBootErrorKind::StopFailed,
        }
    }

    fn artifacts(&self) -> Option<&QemuBootArtifacts> {
        match self {
            Self::AssetMissing { artifacts, .. }
            | Self::UnsupportedConfig { artifacts, .. }
            | Self::Preflight { artifacts, .. }
            | Self::Argv { artifacts, .. }
            | Self::ProcessStart { artifacts, .. }
            | Self::ProcessStatus { artifacts, .. }
            | Self::GuestBootExited { artifacts, .. }
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
            Self::UnsupportedConfig {
                capability,
                milestone,
                ..
            } => write!(
                f,
                "Windows direct boot cannot start because {capability} is not implemented until {milestone}.{}",
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
                "Windows QEMU exited before the M05 boot observation window completed (state '{}', status {}). Inspect serial and QEMU logs. stderr excerpt: {}; serial excerpt: {}.{}",
                state.as_str(),
                exit_status
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "unknown".to_string()),
                empty_as_placeholder(stderr_excerpt),
                empty_as_placeholder(serial_excerpt),
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
    prepare_artifacts(&artifacts)?;

    let kernel_image = require_existing_file("kernel Image", &config.kernel_image, &artifacts)?;
    let initrd_image = require_existing_file("initramfs", &config.initrd_image, &artifacts)?;
    let rootfs_image = require_existing_file("rootfs", &config.rootfs_image, &artifacts)?;
    let memory_mib = memory_mib(config.memory_bytes, &artifacts)?;
    let vcpu_count = vcpu_count(config.vcpu_count, &artifacts)?;

    let preflight = run_preflight().map_err(|source| {
        let error = QemuBootError::Preflight {
            source,
            artifacts: artifacts.clone(),
        };
        record_failure(&artifacts, config.boot_observation_timeout, &error);
        error
    })?;
    write_preflight_report(&artifacts, &preflight)?;

    let mut argv_config = QemuArgvBootConfig::direct_linux_boot_raw_rootfs(
        preflight.qemu.path,
        kernel_image,
        initrd_image,
        rootfs_image,
        artifacts.serial.clone(),
        memory_mib,
        vcpu_count,
    );
    argv_config.diagnostic_label = config.diagnostic_label.clone();

    let command = QemuArgvBuilder::new(argv_config)
        .build()
        .map_err(|source| {
            let error = QemuBootError::Argv {
                source,
                artifacts: artifacts.clone(),
            };
            record_failure(&artifacts, config.boot_observation_timeout, &error);
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
        record_failure(&artifacts, config.boot_observation_timeout, &error);
        error
    })?;

    if let Err(error) = observe_boot(&mut supervisor, &artifacts, config.boot_observation_timeout) {
        record_failure(&artifacts, config.boot_observation_timeout, &error);
        return Err(error);
    }

    write_boot_status_file(
        &artifacts,
        "observed_alive",
        config.boot_observation_timeout,
        None,
        None,
    )?;

    Ok(WindowsQemuBoot {
        supervisor,
        artifacts,
        observation_timeout: config.boot_observation_timeout,
    })
}

fn run_preflight() -> Result<QemuPreflightReport, QemuPreflightError> {
    let host = StdQemuDiscoveryHost;
    let runner = StdQemuCommandRunner;
    QemuPreflight::new(QemuDiscovery::new(&host), &runner).run()
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
    let contents = serde_json::to_string_pretty(report).map_err(|err| QemuBootError::ArtifactIo {
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

fn observe_boot(
    supervisor: &mut QemuSupervisor,
    artifacts: &QemuBootArtifacts,
    timeout: Duration,
) -> Result<(), QemuBootError> {
    let deadline = Instant::now() + timeout;
    loop {
        match supervisor.try_status() {
            Ok(QemuProcessState::Running | QemuProcessState::Starting) => {}
            Ok(state @ (QemuProcessState::Exited
            | QemuProcessState::Failed
            | QemuProcessState::Terminated)) => {
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
            return Ok(());
        }
        std::thread::sleep(BOOT_POLL_INTERVAL);
    }
}

fn record_failure(artifacts: &QemuBootArtifacts, timeout: Duration, error: &QemuBootError) {
    let _ = write_boot_status_file(
        artifacts,
        "failed",
        timeout,
        Some(error.kind()),
        Some(error.to_string()),
    );
}

fn write_boot_status_file(
    artifacts: &QemuBootArtifacts,
    state: &'static str,
    observation_timeout: Duration,
    error_kind: Option<QemuBootErrorKind>,
    error_message: Option<String>,
) -> Result<(), QemuBootError> {
    let artifact = QemuBootStatusArtifact {
        state,
        success_definition: "qemu_process_alive_after_boot_observation_window",
        observation_timeout_ms: observation_timeout.as_millis(),
        artifacts: QemuBootStatusFiles {
            serial: file_name(&artifacts.serial),
            stdout: file_name(&artifacts.process.stdout),
            stderr: file_name(&artifacts.process.stderr),
            argv: file_name(&artifacts.process.argv),
            process_status: file_name(&artifacts.process.status),
            preflight: file_name(&artifacts.preflight),
            boot_status: file_name(&artifacts.boot_status),
        },
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
    artifacts: QemuBootStatusFiles,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

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

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn boot_status_success_artifact_records_observation_definition() {
        let artifact_dir = temp_dir("status");
        let artifacts = QemuBootArtifacts::new(&artifact_dir);
        fs::create_dir_all(&artifact_dir).expect("artifact dir should be writable");

        write_boot_status_file(
            &artifacts,
            "observed_alive",
            Duration::from_millis(1500),
            None,
            None,
        )
        .expect("status should write");

        let status = fs::read_to_string(&artifacts.boot_status).expect("status artifact");
        assert!(status.contains("\"state\": \"observed_alive\""));
        assert!(status.contains("qemu_process_alive_after_boot_observation_window"));
        assert!(status.contains("\"serial\": \"serial.log\""));
        assert!(status.contains("\"observation_timeout_ms\": 1500"));

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

            let mut config =
                WindowsQemuBootConfig::new(kernel, initrd, rootfs, 2 * 1024 * 1024 * 1024, 2);
            config.artifact_directory = Some(artifact_dir);
            config.boot_observation_timeout = timeout;
            config.diagnostic_label = Some("windows-qemu-boot-smoke".to_string());

            let mut boot =
                launch_windows_qemu_boot(config).expect("QEMU should stay alive during boot smoke");
            eprintln!(
                "Windows QEMU boot smoke observed QEMU alive for {} ms; logs: {}",
                boot.observation_timeout().as_millis(),
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
