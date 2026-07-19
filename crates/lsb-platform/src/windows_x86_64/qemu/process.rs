use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::windows_x86_64::apply_qemu_contained_creation_flags;

use super::argv::QemuCommand;
use super::lossy_excerpt;

pub(crate) const DEFAULT_STARTUP_TIMEOUT: Duration = Duration::from_millis(250);
pub(crate) const DEFAULT_TERMINATE_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QemuProcessState {
    NotStarted,
    Starting,
    Running,
    Exited,
    Failed,
    Terminated,
}

impl QemuProcessState {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::NotStarted => "not-started",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Exited => "exited",
            Self::Failed => "failed",
            Self::Terminated => "terminated",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QemuProcessArtifacts {
    pub directory: PathBuf,
    pub argv: PathBuf,
    pub stdout: PathBuf,
    pub stderr: PathBuf,
    pub status: PathBuf,
}

impl QemuProcessArtifacts {
    pub(crate) fn new(directory: impl Into<PathBuf>) -> Self {
        let directory = directory.into();
        Self {
            argv: directory.join("qemu.argv.redacted.txt"),
            stdout: directory.join("qemu.stdout.log"),
            stderr: directory.join("qemu.stderr.log"),
            status: directory.join("qemu.status.json"),
            directory,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QemuProcessEnvironment {
    pub inherit_parent: bool,
    pub variables: Vec<(OsString, OsString)>,
}

impl Default for QemuProcessEnvironment {
    fn default() -> Self {
        Self {
            inherit_parent: false,
            variables: minimal_qemu_environment(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QemuSupervisorConfig {
    pub command: QemuCommand,
    pub artifacts: QemuProcessArtifacts,
    pub working_directory: PathBuf,
    pub environment: QemuProcessEnvironment,
    pub startup_timeout: Duration,
    pub terminate_timeout: Duration,
}

impl QemuSupervisorConfig {
    pub(crate) fn new(command: QemuCommand, artifact_directory: impl Into<PathBuf>) -> Self {
        let artifacts = QemuProcessArtifacts::new(artifact_directory);
        Self {
            command,
            working_directory: artifacts.directory.clone(),
            environment: QemuProcessEnvironment::default(),
            artifacts,
            startup_timeout: DEFAULT_STARTUP_TIMEOUT,
            terminate_timeout: DEFAULT_TERMINATE_TIMEOUT,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct QemuExitStatus {
    pub code: Option<i32>,
    pub success: bool,
}

impl From<ExitStatus> for QemuExitStatus {
    fn from(status: ExitStatus) -> Self {
        Self {
            code: status.code(),
            success: status.success(),
        }
    }
}

impl fmt::Display for QemuExitStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.code {
            Some(code) => write!(f, "exit code {code}"),
            None if self.success => write!(f, "success"),
            None => write!(f, "terminated by signal or system request"),
        }
    }
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QemuProcessDiagnostics {
    pub state: QemuProcessState,
    pub pid: Option<u32>,
    pub exit_status: Option<QemuExitStatus>,
    pub artifacts: QemuProcessArtifacts,
    pub redacted_command: String,
    pub diagnostic_label: Option<String>,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum QemuProcessErrorKind {
    AlreadyStarted,
    NotStarted,
    InvalidCommand,
    MissingExecutable,
    PermissionDenied,
    ArtifactIo,
    SpawnFailed,
    JobObjectCreateFailed,
    JobObjectConfigureFailed,
    JobObjectAssignFailed,
    ProcessAlreadyInJob,
    JobObjectTerminateFailed,
    WhpxPreflightMismatch,
    EarlyExit,
    WaitTimeout,
    CleanupFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum QemuProcessError {
    AlreadyStarted {
        state: QemuProcessState,
    },
    NotStarted,
    InvalidCommand {
        reason: String,
    },
    MissingExecutable {
        path: PathBuf,
        reason: String,
    },
    PermissionDenied {
        path: PathBuf,
        operation: &'static str,
        detail: String,
    },
    ArtifactIo {
        path: PathBuf,
        operation: &'static str,
        detail: String,
    },
    SpawnFailed {
        path: PathBuf,
        detail: String,
    },
    JobObjectCreateFailed {
        detail: String,
    },
    JobObjectConfigureFailed {
        detail: String,
    },
    JobObjectAssignFailed {
        pid: u32,
        detail: String,
    },
    ProcessAlreadyInJob {
        pid: u32,
        detail: String,
    },
    JobObjectTerminateFailed {
        detail: String,
    },
    WhpxPreflightMismatch {
        status: QemuExitStatus,
        stderr_path: PathBuf,
        stderr_excerpt: String,
    },
    EarlyExit {
        status: QemuExitStatus,
        stderr_path: PathBuf,
        stderr_excerpt: String,
    },
    WaitTimeout {
        timeout: Duration,
    },
    CleanupFailed {
        operation: &'static str,
        detail: String,
    },
}

impl QemuProcessError {
    #[cfg(test)]
    pub(crate) fn kind(&self) -> QemuProcessErrorKind {
        match self {
            Self::AlreadyStarted { .. } => QemuProcessErrorKind::AlreadyStarted,
            Self::NotStarted => QemuProcessErrorKind::NotStarted,
            Self::InvalidCommand { .. } => QemuProcessErrorKind::InvalidCommand,
            Self::MissingExecutable { .. } => QemuProcessErrorKind::MissingExecutable,
            Self::PermissionDenied { .. } => QemuProcessErrorKind::PermissionDenied,
            Self::ArtifactIo { .. } => QemuProcessErrorKind::ArtifactIo,
            Self::SpawnFailed { .. } => QemuProcessErrorKind::SpawnFailed,
            Self::JobObjectCreateFailed { .. } => QemuProcessErrorKind::JobObjectCreateFailed,
            Self::JobObjectConfigureFailed { .. } => QemuProcessErrorKind::JobObjectConfigureFailed,
            Self::JobObjectAssignFailed { .. } => QemuProcessErrorKind::JobObjectAssignFailed,
            Self::ProcessAlreadyInJob { .. } => QemuProcessErrorKind::ProcessAlreadyInJob,
            Self::JobObjectTerminateFailed { .. } => QemuProcessErrorKind::JobObjectTerminateFailed,
            Self::WhpxPreflightMismatch { .. } => QemuProcessErrorKind::WhpxPreflightMismatch,
            Self::EarlyExit { .. } => QemuProcessErrorKind::EarlyExit,
            Self::WaitTimeout { .. } => QemuProcessErrorKind::WaitTimeout,
            Self::CleanupFailed { .. } => QemuProcessErrorKind::CleanupFailed,
        }
    }

    pub(crate) fn remediation(&self) -> &'static str {
        match self {
            Self::AlreadyStarted { .. } => {
                "Create a new QEMU supervisor for a new VM process, or stop the current process before restarting it."
            }
            Self::NotStarted => {
                "Call start before waiting for or terminating the QEMU process."
            }
            Self::InvalidCommand { .. } => {
                "Use the QEMU discovery/preflight result and QEMU argv builder instead of constructing a process command manually."
            }
            Self::MissingExecutable { .. } => {
                "Run `lsb init` to install managed QEMU host tools, or set LSB_QEMU to qemu-system-x86_64.exe and rerun Windows QEMU preflight."
            }
            Self::PermissionDenied { .. } => {
                "Check file permissions, endpoint protection policy, and whether this user account may execute the selected QEMU binary and write diagnostics."
            }
            Self::ArtifactIo { .. } => {
                "Ensure the LocalSandbox instance diagnostics directory is writable by the current user."
            }
            Self::SpawnFailed { .. } => {
                "Verify QEMU preflight still passes and the selected executable can be launched by this user."
            }
            Self::JobObjectCreateFailed { .. } => {
                "Check Windows process-management policy and retry on a Windows 11 host that allows Job Object creation."
            }
            Self::JobObjectConfigureFailed { .. } => {
                "Check Windows process-management policy; LocalSandbox requires JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE for QEMU cleanup."
            }
            Self::JobObjectAssignFailed { .. } => {
                "Check whether host policy prevents assigning QEMU to a Job Object; LocalSandbox fails closed to avoid orphaned QEMU helper processes."
            }
            Self::ProcessAlreadyInJob { .. } => {
                "Run LocalSandbox outside the conflicting parent Job Object or configure the runner to allow nested/breakaway jobs; LocalSandbox fails closed when containment cannot be guaranteed."
            }
            Self::JobObjectTerminateFailed { .. } => {
                "Check whether QEMU already exited or whether host policy blocked Job Object termination, then inspect the process id and diagnostics."
            }
            Self::WhpxPreflightMismatch { .. } => {
                "Rerun QEMU preflight and confirm Windows Hypervisor Platform is enabled; preflight can report WHPX support in the binary before runtime WHPX initialization is proven."
            }
            Self::EarlyExit { .. } => {
                "Inspect the redacted argv and QEMU stderr log for invalid argv, missing assets, unsupported devices, or WHPX runtime failures."
            }
            Self::WaitTimeout { .. } => {
                "Inspect QEMU stdout/stderr and retry with a longer timeout if the process is expected to keep running."
            }
            Self::CleanupFailed { .. } => {
                "Check whether the process already exited or was protected by host policy, then inspect the QEMU pid and diagnostic logs."
            }
        }
    }
}

impl fmt::Display for QemuProcessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyStarted { state } => write!(
                f,
                "QEMU supervisor cannot start from state '{}'. {}",
                state.as_str(),
                self.remediation()
            ),
            Self::NotStarted => write!(
                f,
                "QEMU process has not been started. {}",
                self.remediation()
            ),
            Self::InvalidCommand { reason } => write!(
                f,
                "invalid QEMU process command: {reason}. {}",
                self.remediation()
            ),
            Self::MissingExecutable { path, reason } => write!(
                f,
                "QEMU executable '{}' is unavailable: {reason}. {}",
                path.display(),
                self.remediation()
            ),
            Self::PermissionDenied {
                path,
                operation,
                detail,
            } => write!(
                f,
                "permission denied while attempting to {operation} '{}': {detail}. {}",
                path.display(),
                self.remediation()
            ),
            Self::ArtifactIo {
                path,
                operation,
                detail,
            } => write!(
                f,
                "failed to {operation} QEMU artifact '{}': {detail}. {}",
                path.display(),
                self.remediation()
            ),
            Self::SpawnFailed { path, detail } => write!(
                f,
                "failed to spawn QEMU executable '{}': {detail}. {}",
                path.display(),
                self.remediation()
            ),
            Self::JobObjectCreateFailed { detail } => write!(
                f,
                "failed to create Windows Job Object for QEMU cleanup: {detail}. {}",
                self.remediation()
            ),
            Self::JobObjectConfigureFailed { detail } => write!(
                f,
                "failed to configure Windows Job Object cleanup limits: {detail}. {}",
                self.remediation()
            ),
            Self::JobObjectAssignFailed { pid, detail } => write!(
                f,
                "failed to assign QEMU process {pid} to the cleanup Job Object: {detail}. {}",
                self.remediation()
            ),
            Self::ProcessAlreadyInJob { pid, detail } => write!(
                f,
                "QEMU process {pid} is already in a Windows Job Object and cannot be assigned to the LocalSandbox cleanup Job Object: {detail}. {}",
                self.remediation()
            ),
            Self::JobObjectTerminateFailed { detail } => write!(
                f,
                "failed to terminate the QEMU cleanup Job Object: {detail}. {}",
                self.remediation()
            ),
            Self::WhpxPreflightMismatch {
                status,
                stderr_path,
                stderr_excerpt,
            } => write!(
                f,
                "QEMU exited during startup with {status}; stderr at '{}' indicates a WHPX/runtime preflight mismatch: {}. {}",
                stderr_path.display(),
                empty_as_placeholder(stderr_excerpt),
                self.remediation()
            ),
            Self::EarlyExit {
                status,
                stderr_path,
                stderr_excerpt,
            } => write!(
                f,
                "QEMU exited during startup with {status}; stderr at '{}': {}. {}",
                stderr_path.display(),
                empty_as_placeholder(stderr_excerpt),
                self.remediation()
            ),
            Self::WaitTimeout { timeout } => write!(
                f,
                "timed out after {} ms while waiting for QEMU process status. {}",
                timeout.as_millis(),
                self.remediation()
            ),
            Self::CleanupFailed { operation, detail } => write!(
                f,
                "failed to {operation} QEMU process during cleanup: {detail}. {}",
                self.remediation()
            ),
        }
    }
}

impl std::error::Error for QemuProcessError {}

#[derive(Debug)]
pub(crate) struct QemuSupervisor {
    config: QemuSupervisorConfig,
    state: QemuProcessState,
    child: Option<Child>,
    pid: Option<u32>,
    exit_status: Option<QemuExitStatus>,
    containment: ProcessContainment,
}

impl QemuSupervisor {
    pub(crate) fn new(config: QemuSupervisorConfig) -> Self {
        Self {
            config,
            state: QemuProcessState::NotStarted,
            child: None,
            pid: None,
            exit_status: None,
            containment: ProcessContainment::default(),
        }
    }

    #[cfg(test)]
    pub(crate) fn state(&self) -> QemuProcessState {
        self.state
    }

    #[cfg(test)]
    pub(crate) fn artifacts(&self) -> &QemuProcessArtifacts {
        &self.config.artifacts
    }

    #[cfg(test)]
    pub(crate) fn pid(&self) -> Option<u32> {
        self.pid
    }

    pub(crate) fn exit_status(&self) -> Option<&QemuExitStatus> {
        self.exit_status.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn diagnostics(&self) -> QemuProcessDiagnostics {
        QemuProcessDiagnostics {
            state: self.state,
            pid: self.pid,
            exit_status: self.exit_status.clone(),
            artifacts: self.config.artifacts.clone(),
            redacted_command: self.config.command.sanitized_display(),
            diagnostic_label: self
                .config
                .command
                .diagnostic_label()
                .map(ToOwned::to_owned),
        }
    }

    pub(crate) fn start(&mut self) -> Result<(), QemuProcessError> {
        if self.child.is_some() || self.state != QemuProcessState::NotStarted {
            return Err(QemuProcessError::AlreadyStarted { state: self.state });
        }

        self.validate_start_inputs()?;
        self.prepare_artifacts()?;
        self.write_argv_artifact()?;
        self.state = QemuProcessState::Starting;
        self.write_status_artifact()?;

        let stdout = create_artifact_file(&self.config.artifacts.stdout, "create stdout log")?;
        let stderr = create_artifact_file(&self.config.artifacts.stderr, "create stderr log")?;

        let mut command = Command::new(&self.config.command.program);
        command
            .args(&self.config.command.argv)
            .current_dir(&self.config.working_directory)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        apply_environment(&mut command, &self.config.environment);
        apply_qemu_contained_creation_flags(&mut command);

        let (mut child, suspended_primary_thread) = match spawn_suspended(&mut command) {
            Ok(child) => child,
            Err(err) => {
                self.state = QemuProcessState::Failed;
                let error = spawn_error(&self.config.command.program, err);
                let _ = self.write_status_artifact();
                return Err(error);
            }
        };
        let pid = child.id();
        self.pid = Some(pid);

        self.containment = match ProcessContainment::create_for_child(&child) {
            Ok(containment) => containment,
            Err(err) => {
                let _ = child.kill();
                let _ = child.wait();
                self.state = QemuProcessState::Failed;
                let _ = self.write_status_artifact();
                return Err(err);
            }
        };

        if let Err(err) = suspended_primary_thread.resume() {
            let _ = self.containment.terminate();
            let _ = child.kill();
            let _ = child.wait();
            self.state = QemuProcessState::Failed;
            let _ = self.write_status_artifact();
            return Err(QemuProcessError::CleanupFailed {
                operation: "resume Job-contained QEMU primary thread",
                detail: err.to_string(),
            });
        }
        self.child = Some(child);

        if let Err(err) = self.finish_startup_after_spawn() {
            self.cleanup_after_failed_start();
            return Err(err);
        }

        Ok(())
    }

    pub(crate) fn try_status(&mut self) -> Result<QemuProcessState, QemuProcessError> {
        let Some(child) = self.child.as_mut() else {
            return Ok(self.state);
        };
        match child.try_wait() {
            Ok(Some(status)) => {
                let status = QemuExitStatus::from(status);
                self.exit_status = Some(status);
                self.child = None;
                self.state = QemuProcessState::Exited;
                self.write_status_artifact()?;
                Ok(self.state)
            }
            Ok(None) => {
                self.state = QemuProcessState::Running;
                self.write_status_artifact()?;
                Ok(self.state)
            }
            Err(err) => {
                self.state = QemuProcessState::Failed;
                let _ = self.write_status_artifact();
                Err(QemuProcessError::CleanupFailed {
                    operation: "poll",
                    detail: err.to_string(),
                })
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn wait(&mut self, timeout: Duration) -> Result<QemuExitStatus, QemuProcessError> {
        if self.child.is_none() {
            return self.exit_status.clone().ok_or(QemuProcessError::NotStarted);
        }

        let status = self.wait_for_exit_without_status(timeout)?;
        self.state = QemuProcessState::Exited;
        self.write_status_artifact()?;
        Ok(status)
    }

    pub(crate) fn terminate(&mut self) -> Result<Option<QemuExitStatus>, QemuProcessError> {
        if self.child.is_none() {
            return Ok(self.exit_status.clone());
        }

        // There is no QMP shutdown channel, so termination falls back to Job
        // Object/process cleanup.
        let terminate_result = self.request_child_termination("terminate");
        let wait_result = self.wait_for_exit_without_status(self.config.terminate_timeout);

        match (terminate_result, wait_result) {
            (Ok(()), Ok(status)) => {
                self.state = QemuProcessState::Terminated;
                self.write_status_artifact()?;
                Ok(Some(status))
            }
            (Err(terminate_error), Ok(_status)) => {
                self.state = QemuProcessState::Terminated;
                let _ = self.write_status_artifact();
                Err(terminate_error)
            }
            (Ok(()), Err(wait_error)) => {
                self.state = QemuProcessState::Failed;
                let _ = self.write_status_artifact();
                Err(wait_error)
            }
            (Err(terminate_error), Err(_wait_error)) => {
                self.state = QemuProcessState::Failed;
                let _ = self.write_status_artifact();
                Err(terminate_error)
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn kill(&mut self) -> Result<Option<QemuExitStatus>, QemuProcessError> {
        self.terminate()
    }

    fn validate_start_inputs(&self) -> Result<(), QemuProcessError> {
        if self.config.command.program.as_os_str().is_empty() {
            return Err(QemuProcessError::InvalidCommand {
                reason: "qemu executable path is empty".to_string(),
            });
        }
        if !self.config.command.program.is_absolute() {
            return Err(QemuProcessError::InvalidCommand {
                reason: format!(
                    "qemu executable path '{}' must be absolute",
                    self.config.command.program.display()
                ),
            });
        }
        if self.config.working_directory.as_os_str().is_empty() {
            return Err(QemuProcessError::InvalidCommand {
                reason: "working directory path is empty".to_string(),
            });
        }
        if !self.config.working_directory.is_absolute() {
            return Err(QemuProcessError::InvalidCommand {
                reason: format!(
                    "working directory '{}' must be absolute",
                    self.config.working_directory.display()
                ),
            });
        }

        match fs::metadata(&self.config.command.program) {
            Ok(metadata) if metadata.is_file() => Ok(()),
            Ok(_) => Err(QemuProcessError::MissingExecutable {
                path: self.config.command.program.clone(),
                reason: "path is not a file".to_string(),
            }),
            Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
                Err(QemuProcessError::PermissionDenied {
                    path: self.config.command.program.clone(),
                    operation: "inspect",
                    detail: err.to_string(),
                })
            }
            Err(err) => Err(QemuProcessError::MissingExecutable {
                path: self.config.command.program.clone(),
                reason: err.to_string(),
            }),
        }
    }

    fn prepare_artifacts(&self) -> Result<(), QemuProcessError> {
        fs::create_dir_all(&self.config.artifacts.directory).map_err(|err| {
            artifact_error(
                &self.config.artifacts.directory,
                "create diagnostics directory",
                err,
            )
        })
    }

    fn write_argv_artifact(&self) -> Result<(), QemuProcessError> {
        let contents = format!("{}\n", self.config.command.sanitized_display());
        fs::write(&self.config.artifacts.argv, contents)
            .map_err(|err| artifact_error(&self.config.artifacts.argv, "write redacted argv", err))
    }

    fn write_status_artifact(&self) -> Result<(), QemuProcessError> {
        let artifact = QemuStatusArtifact {
            state: self.state.as_str(),
            pid: self.pid,
            exit_status: self.exit_status.as_ref(),
            diagnostic_label: self.config.command.diagnostic_label(),
            artifacts: QemuStatusArtifactFiles {
                argv: file_name(&self.config.artifacts.argv),
                stdout: file_name(&self.config.artifacts.stdout),
                stderr: file_name(&self.config.artifacts.stderr),
                status: file_name(&self.config.artifacts.status),
            },
            environment: QemuEnvironmentArtifact {
                inherit_parent: self.config.environment.inherit_parent,
                override_count: self.config.environment.variables.len(),
            },
        };
        let contents = serde_json::to_string_pretty(&artifact).map_err(|err| {
            QemuProcessError::ArtifactIo {
                path: self.config.artifacts.status.clone(),
                operation: "serialize status",
                detail: err.to_string(),
            }
        })?;
        fs::write(&self.config.artifacts.status, format!("{contents}\n")).map_err(|err| {
            artifact_error(&self.config.artifacts.status, "write lifecycle status", err)
        })
    }

    fn finish_startup_after_spawn(&mut self) -> Result<(), QemuProcessError> {
        if let Some(status) = self.wait_for_startup_exit()? {
            self.exit_status = Some(status.clone());
            self.state = QemuProcessState::Failed;
            let _ = self.write_status_artifact();
            return Err(startup_exit_error(status, &self.config.artifacts.stderr));
        }

        self.state = QemuProcessState::Running;
        self.write_status_artifact()?;
        Ok(())
    }

    fn cleanup_after_failed_start(&mut self) {
        if self.child.is_some() {
            let _ = self.request_child_termination("cleanup after failed startup");
            let _ = self.wait_for_exit_without_status(self.config.terminate_timeout);
        }
        self.state = QemuProcessState::Failed;
        let _ = self.write_status_artifact();
    }

    fn wait_for_startup_exit(&mut self) -> Result<Option<QemuExitStatus>, QemuProcessError> {
        let deadline = Instant::now() + self.config.startup_timeout;
        loop {
            if let Some(status) = self.poll_exit()? {
                return Ok(Some(status));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    fn wait_for_exit_without_status(
        &mut self,
        timeout: Duration,
    ) -> Result<QemuExitStatus, QemuProcessError> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.poll_exit()? {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(QemuProcessError::WaitTimeout { timeout });
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    fn poll_exit(&mut self) -> Result<Option<QemuExitStatus>, QemuProcessError> {
        let Some(child) = self.child.as_mut() else {
            return Ok(self.exit_status.clone());
        };
        child
            .try_wait()
            .map_err(|err| QemuProcessError::CleanupFailed {
                operation: "poll",
                detail: err.to_string(),
            })
            .map(|status| {
                status.map(|status| {
                    let status = QemuExitStatus::from(status);
                    self.exit_status = Some(status.clone());
                    self.child = None;
                    status
                })
            })
    }

    fn request_child_termination(
        &mut self,
        operation: &'static str,
    ) -> Result<(), QemuProcessError> {
        match self.containment.terminate() {
            Ok(true) => Ok(()),
            Ok(false) => self.kill_direct_child(operation),
            Err(containment_error) => {
                let direct_kill_result = self.kill_direct_child(operation);
                match direct_kill_result {
                    Ok(()) => Err(containment_error),
                    Err(direct_kill_error) => Err(attach_direct_kill_error(
                        containment_error,
                        direct_kill_error,
                    )),
                }
            }
        }
    }

    fn kill_direct_child(&mut self, operation: &'static str) -> Result<(), QemuProcessError> {
        let Some(child) = self.child.as_mut() else {
            return Ok(());
        };
        child.kill().map_err(|err| QemuProcessError::CleanupFailed {
            operation,
            detail: err.to_string(),
        })
    }
}

#[derive(Debug, Serialize)]
struct QemuStatusArtifact<'a> {
    state: &'static str,
    pid: Option<u32>,
    exit_status: Option<&'a QemuExitStatus>,
    diagnostic_label: Option<&'a str>,
    artifacts: QemuStatusArtifactFiles,
    environment: QemuEnvironmentArtifact,
}

#[derive(Debug, Serialize)]
struct QemuStatusArtifactFiles {
    argv: String,
    stdout: String,
    stderr: String,
    status: String,
}

#[derive(Debug, Serialize)]
struct QemuEnvironmentArtifact {
    inherit_parent: bool,
    override_count: usize,
}

#[cfg(target_os = "windows")]
struct SuspendedPrimaryThread {
    handle: std::os::windows::io::OwnedHandle,
}

#[cfg(target_os = "windows")]
impl SuspendedPrimaryThread {
    fn resume(self) -> io::Result<()> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::HANDLE;
        use windows_sys::Win32::System::Threading::ResumeThread;

        let previous = unsafe { ResumeThread(self.handle.as_raw_handle() as HANDLE) };
        if previous == u32::MAX {
            return Err(io::Error::last_os_error());
        }
        if previous != 1 {
            return Err(io::Error::other(format!(
                "unexpected primary-thread suspend count {previous}"
            )));
        }
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn spawn_suspended(command: &mut Command) -> io::Result<(Child, SuspendedPrimaryThread)> {
    let mut child = command.spawn()?;
    match open_only_thread_for_process(child.id()) {
        Ok(thread) => Ok((child, SuspendedPrimaryThread { handle: thread })),
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(error)
        }
    }
}

#[cfg(target_os = "windows")]
fn open_only_thread_for_process(pid: u32) -> io::Result<std::os::windows::io::OwnedHandle> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use windows_sys::Win32::System::Threading::{
        GetProcessIdOfThread, OpenThread, THREAD_QUERY_LIMITED_INFORMATION, THREAD_SUSPEND_RESUME,
    };

    let snapshot_raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot_raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let snapshot = unsafe { OwnedHandle::from_raw_handle(snapshot_raw as _) };
    let mut entry = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        ..THREADENTRY32::default()
    };
    if unsafe { Thread32First(snapshot.as_raw_handle() as _, &mut entry) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut thread_id = None;
    loop {
        if entry.th32OwnerProcessID == pid && thread_id.replace(entry.th32ThreadID).is_some() {
            return Err(io::Error::other(
                "suspended child exposed more than one thread before Job assignment",
            ));
        }
        if unsafe { Thread32Next(snapshot.as_raw_handle() as _, &mut entry) } == 0 {
            break;
        }
    }
    let thread_id = thread_id.ok_or_else(|| {
        io::Error::other("suspended child primary thread was not present in the thread snapshot")
    })?;
    let raw = unsafe {
        OpenThread(
            THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION,
            0,
            thread_id,
        )
    };
    if raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    let thread = unsafe { OwnedHandle::from_raw_handle(raw as _) };
    if unsafe { GetProcessIdOfThread(thread.as_raw_handle() as _) } != pid {
        return Err(io::Error::other(
            "suspended primary-thread owner changed during acquisition",
        ));
    }
    Ok(thread)
}

#[cfg(not(target_os = "windows"))]
struct SuspendedPrimaryThread;

#[cfg(not(target_os = "windows"))]
impl SuspendedPrimaryThread {
    fn resume(self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(not(target_os = "windows"))]
fn spawn_suspended(command: &mut Command) -> io::Result<(Child, SuspendedPrimaryThread)> {
    command.spawn().map(|child| (child, SuspendedPrimaryThread))
}

#[cfg(target_os = "windows")]
#[derive(Debug, Default)]
struct ProcessContainment {
    job: Option<JobObject>,
}

#[cfg(target_os = "windows")]
impl ProcessContainment {
    fn create_for_child(child: &Child) -> Result<Self, QemuProcessError> {
        let job = JobObject::create_kill_on_close()?;
        job.assign_child(child)?;
        Ok(Self { job: Some(job) })
    }

    fn terminate(&self) -> Result<bool, QemuProcessError> {
        if let Some(job) = &self.job {
            job.terminate()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

#[cfg(not(target_os = "windows"))]
#[derive(Debug, Default)]
struct ProcessContainment;

#[cfg(not(target_os = "windows"))]
impl ProcessContainment {
    fn create_for_child(_child: &Child) -> Result<Self, QemuProcessError> {
        Ok(Self)
    }

    fn terminate(&self) -> Result<bool, QemuProcessError> {
        Ok(false)
    }
}

#[cfg(target_os = "windows")]
#[derive(Debug)]
struct JobObject {
    handle: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(target_os = "windows")]
impl JobObject {
    fn create_kill_on_close() -> Result<Self, QemuProcessError> {
        use std::mem::size_of;
        use windows_sys::Win32::System::JobObjects::{
            CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        };

        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err(QemuProcessError::JobObjectCreateFailed {
                detail: io::Error::last_os_error().to_string(),
            });
        }

        let job = Self { handle };
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

        let ok = unsafe {
            SetInformationJobObject(
                job.handle,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const core::ffi::c_void,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if ok == 0 {
            return Err(QemuProcessError::JobObjectConfigureFailed {
                detail: io::Error::last_os_error().to_string(),
            });
        }

        Ok(job)
    }

    fn assign_child(&self, child: &Child) -> Result<(), QemuProcessError> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::HANDLE;
        use windows_sys::Win32::System::JobObjects::{AssignProcessToJobObject, IsProcessInJob};

        let process_handle = child.as_raw_handle() as HANDLE;
        let ok = unsafe { AssignProcessToJobObject(self.handle, process_handle) };
        if ok != 0 {
            return Ok(());
        }

        let detail = io::Error::last_os_error().to_string();
        let mut in_job = 0;
        let check_ok = unsafe { IsProcessInJob(process_handle, std::ptr::null_mut(), &mut in_job) };
        if check_ok != 0 && in_job != 0 {
            Err(QemuProcessError::ProcessAlreadyInJob {
                pid: child.id(),
                detail,
            })
        } else {
            Err(QemuProcessError::JobObjectAssignFailed {
                pid: child.id(),
                detail,
            })
        }
    }

    fn terminate(&self) -> Result<(), QemuProcessError> {
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;

        let ok = unsafe { TerminateJobObject(self.handle, 1) };
        if ok == 0 {
            Err(QemuProcessError::JobObjectTerminateFailed {
                detail: io::Error::last_os_error().to_string(),
            })
        } else {
            Ok(())
        }
    }
}

#[cfg(target_os = "windows")]
impl Drop for JobObject {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;

        let _ = unsafe { CloseHandle(self.handle) };
    }
}

#[cfg(target_os = "windows")]
// SAFETY: `JobObject` owns a kernel HANDLE, uses it only through thread-safe
// Windows process-management calls, and closes it exactly once in `Drop`.
unsafe impl Send for JobObject {}

impl Drop for QemuSupervisor {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}

fn apply_environment(command: &mut Command, environment: &QemuProcessEnvironment) {
    if !environment.inherit_parent {
        command.env_clear();
    }
    for (key, value) in &environment.variables {
        command.env(key, value);
    }
}

fn minimal_qemu_environment() -> Vec<(OsString, OsString)> {
    #[cfg(target_os = "windows")]
    {
        ["SystemRoot", "WINDIR"]
            .into_iter()
            .filter_map(|key| std::env::var_os(key).map(|value| (OsString::from(key), value)))
            .collect()
    }

    #[cfg(not(target_os = "windows"))]
    {
        Vec::new()
    }
}

fn create_artifact_file(path: &PathBuf, operation: &'static str) -> Result<File, QemuProcessError> {
    File::create(path).map_err(|err| artifact_error(path, operation, err))
}

fn artifact_error(path: &Path, operation: &'static str, err: io::Error) -> QemuProcessError {
    if err.kind() == io::ErrorKind::PermissionDenied {
        QemuProcessError::PermissionDenied {
            path: path.to_path_buf(),
            operation,
            detail: err.to_string(),
        }
    } else {
        QemuProcessError::ArtifactIo {
            path: path.to_path_buf(),
            operation,
            detail: err.to_string(),
        }
    }
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "<unknown>".to_string())
}

fn spawn_error(path: &Path, err: io::Error) -> QemuProcessError {
    if err.kind() == io::ErrorKind::PermissionDenied {
        QemuProcessError::PermissionDenied {
            path: path.to_path_buf(),
            operation: "execute",
            detail: err.to_string(),
        }
    } else {
        QemuProcessError::SpawnFailed {
            path: path.to_path_buf(),
            detail: err.to_string(),
        }
    }
}

fn attach_direct_kill_error(
    containment_error: QemuProcessError,
    direct_kill_error: QemuProcessError,
) -> QemuProcessError {
    match containment_error {
        QemuProcessError::JobObjectTerminateFailed { detail } => {
            QemuProcessError::JobObjectTerminateFailed {
                detail: format!(
                    "{detail}; direct child kill fallback also failed: {direct_kill_error}"
                ),
            }
        }
        other => other,
    }
}

fn startup_exit_error(status: QemuExitStatus, stderr_path: &PathBuf) -> QemuProcessError {
    let stderr_excerpt = fs::read(stderr_path)
        .map(|bytes| lossy_excerpt(&bytes))
        .unwrap_or_else(|err| format!("<could not read stderr log: {err}>"));
    if looks_like_whpx_runtime_failure(&stderr_excerpt) {
        QemuProcessError::WhpxPreflightMismatch {
            status,
            stderr_path: stderr_path.clone(),
            stderr_excerpt,
        }
    } else {
        QemuProcessError::EarlyExit {
            status,
            stderr_path: stderr_path.clone(),
            stderr_excerpt,
        }
    }
}

fn looks_like_whpx_runtime_failure(stderr_excerpt: &str) -> bool {
    let lower = stderr_excerpt.to_ascii_lowercase();
    lower.contains("whpx")
        || lower.contains("windows hypervisor platform")
        || lower.contains("hyper-v")
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
    use std::env;
    use std::ffi::OsString;
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::windows_x86_64::qemu::argv::QemuArgvBuilder;
    use crate::windows_x86_64::qemu::config::QemuBootConfig;

    const FAKE_CHILD_ENV: &str = "LSB_QEMU_PROCESS_TEST_CHILD";
    const FAKE_PID_FILE_ENV: &str = "LSB_QEMU_PROCESS_TEST_PID_FILE";
    const FAKE_STATUS_PATH_ENV: &str = "LSB_QEMU_PROCESS_TEST_STATUS_PATH";
    const FAKE_SECRET_ENV_NAME_ENV: &str = "LSB_QEMU_PROCESS_TEST_SECRET_ENV_NAME";
    const FAKE_CHILD_TEST_NAME: &str =
        "windows_x86_64::qemu::process::tests::fake_qemu_child_entrypoint";
    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct EnvVarGuard {
        key: String,
    }

    impl EnvVarGuard {
        fn set(key: String, value: &str) -> Self {
            env::set_var(&key, value);
            Self { key }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            env::remove_var(&self.key);
        }
    }

    fn command() -> QemuCommand {
        QemuArgvBuilder::new(QemuBootConfig::direct_linux_boot(
            r"C:\qemu\qemu-system-x86_64.exe",
            r"C:\lsb\Image",
            r"C:\lsb\initramfs.cpio.gz",
            r"C:\lsb\instances\abc\root.qcow2",
            r"C:\lsb\instances\abc\serial.log",
            2048,
            2,
        ))
        .build()
        .expect("test command should build")
    }

    fn fake_child_args() -> Vec<OsString> {
        ["--exact", "--nocapture", FAKE_CHILD_TEST_NAME]
            .into_iter()
            .map(OsString::from)
            .collect()
    }

    fn fake_command() -> QemuCommand {
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

    fn temp_artifact_dir(label: &str) -> PathBuf {
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        env::temp_dir().join(format!(
            "lsb-qemu-process-{label}-{}-{counter}",
            std::process::id()
        ))
    }

    fn fake_supervisor(mode: &str, artifact_dir: PathBuf) -> QemuSupervisor {
        let mut config = QemuSupervisorConfig::new(fake_command(), artifact_dir);
        config.startup_timeout = Duration::from_millis(100);
        config.terminate_timeout = Duration::from_secs(2);
        config.environment.variables.push((
            OsString::from(FAKE_CHILD_ENV),
            OsString::from(mode.to_string()),
        ));
        QemuSupervisor::new(config)
    }

    fn wait_for_file_contains(path: &PathBuf, needle: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Ok(contents) = fs::read_to_string(path) {
                if contents.contains(needle) {
                    return contents;
                }
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for '{}' to contain '{needle}'",
                path.display()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait_for_pid_file(path: &PathBuf) -> u32 {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Ok(contents) = fs::read_to_string(path) {
                if let Ok(pid) = contents.trim().parse::<u32>() {
                    return pid;
                }
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for pid file '{}'",
                path.display()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn fake_qemu_child_entrypoint() {
        let Ok(mode) = env::var(FAKE_CHILD_ENV) else {
            return;
        };

        match mode.as_str() {
            "log" => {
                println!("fake qemu stdout ready");
                eprintln!("fake qemu stderr ready");
                let _ = std::io::stdout().flush();
                let _ = std::io::stderr().flush();
                std::thread::sleep(Duration::from_secs(60));
            }
            "exit-whpx" => {
                eprintln!("WHPX runtime initialization failed in fake QEMU");
                let _ = std::io::stderr().flush();
                std::process::exit(17);
            }
            "exit-after-startup" => {
                println!("fake qemu will exit after startup window");
                let _ = std::io::stdout().flush();
                std::thread::sleep(Duration::from_millis(500));
            }
            "block-status" => {
                let status_path =
                    PathBuf::from(env::var_os(FAKE_STATUS_PATH_ENV).expect("status path env"));
                let deadline = Instant::now() + Duration::from_secs(2);
                loop {
                    if status_path.is_file() {
                        fs::remove_file(&status_path).expect("status file should be removable");
                        fs::create_dir(&status_path).expect("status path should become directory");
                        break;
                    }
                    if Instant::now() >= deadline {
                        eprintln!("timed out waiting for status artifact");
                        std::process::exit(18);
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                println!("fake qemu blocked status artifact");
                let _ = std::io::stdout().flush();
                std::thread::sleep(Duration::from_secs(60));
            }
            "assert-secret-not-inherited" => {
                let secret_name =
                    env::var(FAKE_SECRET_ENV_NAME_ENV).expect("secret env name should be set");
                if env::var_os(&secret_name).is_some() {
                    eprintln!("secret-like parent environment variable was inherited");
                    std::process::exit(19);
                }
                println!("secret environment was not inherited");
                let _ = std::io::stdout().flush();
                std::thread::sleep(Duration::from_secs(60));
            }
            #[cfg(target_os = "windows")]
            "assert-job-contained-at-entry" => {
                use windows_sys::Win32::System::JobObjects::IsProcessInJob;
                use windows_sys::Win32::System::Threading::GetCurrentProcess;

                let mut in_job = 0;
                let check_ok = unsafe {
                    IsProcessInJob(GetCurrentProcess(), std::ptr::null_mut(), &mut in_job)
                };
                if check_ok == 0 || in_job == 0 {
                    eprintln!("fake QEMU reached its entrypoint outside a Job Object");
                    std::process::exit(20);
                }
                println!("fake QEMU entered already Job-contained");
                let _ = std::io::stdout().flush();
                std::thread::sleep(Duration::from_secs(60));
            }
            "spawn-grandchild" => {
                let pid_file = env::var(FAKE_PID_FILE_ENV).expect("pid file env should be set");
                let mut child = Command::new(env::current_exe().expect("current exe"))
                    .args(fake_child_args())
                    .env(FAKE_CHILD_ENV, "log")
                    .spawn()
                    .expect("fake grandchild should start");
                fs::write(pid_file, child.id().to_string()).expect("pid file should be writable");
                std::thread::sleep(Duration::from_secs(60));
                let _ = child.wait();
            }
            other => panic!("unknown fake child mode: {other}"),
        }
    }

    #[test]
    fn artifact_paths_are_deterministic() {
        let artifacts = QemuProcessArtifacts::new(r"C:\lsb\instances\abc\diagnostics");

        assert_eq!(
            artifacts.argv,
            PathBuf::from(r"C:\lsb\instances\abc\diagnostics").join("qemu.argv.redacted.txt")
        );
        assert_eq!(
            artifacts.stdout,
            PathBuf::from(r"C:\lsb\instances\abc\diagnostics").join("qemu.stdout.log")
        );
        assert_eq!(
            artifacts.stderr,
            PathBuf::from(r"C:\lsb\instances\abc\diagnostics").join("qemu.stderr.log")
        );
        assert_eq!(
            artifacts.status,
            PathBuf::from(r"C:\lsb\instances\abc\diagnostics").join("qemu.status.json")
        );
    }

    #[test]
    fn supervisor_starts_in_not_started_state() {
        let supervisor = QemuSupervisor::new(QemuSupervisorConfig::new(command(), "artifacts"));

        assert_eq!(supervisor.state(), QemuProcessState::NotStarted);
        assert_eq!(
            supervisor.artifacts().argv,
            PathBuf::from("artifacts").join("qemu.argv.redacted.txt")
        );
    }

    #[test]
    fn default_environment_does_not_inherit_parent() {
        let environment = QemuProcessEnvironment::default();

        assert!(!environment.inherit_parent);
    }

    #[test]
    fn fake_process_start_timeout_terminate_and_artifacts_work() {
        let artifact_dir = temp_artifact_dir("log");
        let mut supervisor = fake_supervisor("log", artifact_dir.clone());

        supervisor.start().expect("fake process should start");

        assert_eq!(supervisor.state(), QemuProcessState::Running);
        assert!(supervisor.pid().is_some());
        assert_eq!(
            supervisor
                .wait(Duration::from_millis(20))
                .expect_err("running fake should time out")
                .kind(),
            QemuProcessErrorKind::WaitTimeout
        );

        let stdout = wait_for_file_contains(&supervisor.artifacts().stdout, "fake qemu stdout");
        let stderr = wait_for_file_contains(&supervisor.artifacts().stderr, "fake qemu stderr");
        assert!(stdout.contains("fake qemu stdout ready"));
        assert!(stderr.contains("fake qemu stderr ready"));

        let exit = supervisor
            .terminate()
            .expect("terminate should succeed")
            .expect("terminate should return an exit status");
        assert!(!exit.success);
        assert_eq!(supervisor.state(), QemuProcessState::Terminated);
        assert!(supervisor
            .kill()
            .expect("second kill should be idempotent")
            .is_some());

        let argv = fs::read_to_string(&supervisor.artifacts().argv).expect("argv artifact");
        assert!(argv.contains("<qemu-system-x86_64.exe>"));
        assert!(!argv.contains(FAKE_CHILD_ENV));

        let status = fs::read_to_string(&supervisor.artifacts().status).expect("status artifact");
        let override_count = supervisor.config.environment.variables.len();
        assert!(status.contains("\"state\": \"terminated\""));
        assert!(status.contains("\"stdout\": \"qemu.stdout.log\""));
        assert!(status.contains("\"inherit_parent\": false"));
        assert!(status.contains(&format!("\"override_count\": {override_count}")));
        assert!(!status.contains(FAKE_CHILD_ENV));
        assert!(!status.contains("fake qemu stderr ready"));

        let diagnostics = supervisor.diagnostics();
        assert_eq!(diagnostics.state, QemuProcessState::Terminated);
        assert!(diagnostics
            .redacted_command
            .contains("<qemu-system-x86_64.exe>"));

        let _ = fs::remove_dir_all(artifact_dir);
    }

    #[test]
    fn fake_process_does_not_inherit_secret_like_parent_environment() {
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let secret_name = format!(
            "LSB_QEMU_PROCESS_TEST_SECRET_{}_{}",
            std::process::id(),
            counter
        );
        let _secret_guard = EnvVarGuard::set(secret_name.clone(), "super-secret-token");
        let artifact_dir = temp_artifact_dir("secret-env");
        let mut supervisor = fake_supervisor("assert-secret-not-inherited", artifact_dir.clone());
        supervisor.config.environment.variables.push((
            OsString::from(FAKE_SECRET_ENV_NAME_ENV),
            OsString::from(secret_name.clone()),
        ));

        supervisor
            .start()
            .expect("fake process should start without inherited secrets");

        let stdout = wait_for_file_contains(
            &supervisor.artifacts().stdout,
            "secret environment was not inherited",
        );
        assert!(stdout.contains("secret environment was not inherited"));

        supervisor
            .terminate()
            .expect("terminate after secret environment test should succeed");

        let status = fs::read_to_string(&supervisor.artifacts().status).expect("status artifact");
        let argv = fs::read_to_string(&supervisor.artifacts().argv).expect("argv artifact");
        assert!(status.contains("\"inherit_parent\": false"));
        assert!(!status.contains(&secret_name));
        assert!(!status.contains("super-secret-token"));
        assert!(!argv.contains(&secret_name));
        assert!(!argv.contains("super-secret-token"));

        let _ = fs::remove_dir_all(artifact_dir);
    }

    #[test]
    fn fake_process_early_whpx_exit_reports_structured_error() {
        let artifact_dir = temp_artifact_dir("early-exit");
        let mut supervisor = fake_supervisor("exit-whpx", artifact_dir.clone());
        supervisor.config.startup_timeout = Duration::from_secs(2);

        let err = supervisor
            .start()
            .expect_err("fake WHPX startup failure should be reported");

        assert_eq!(err.kind(), QemuProcessErrorKind::WhpxPreflightMismatch);
        assert!(err.to_string().contains("WHPX"));
        assert_eq!(supervisor.state(), QemuProcessState::Failed);
        assert_eq!(
            supervisor.exit_status().expect("exit status").code,
            Some(17)
        );

        let stderr = fs::read_to_string(&supervisor.artifacts().stderr).expect("stderr artifact");
        assert!(stderr.contains("WHPX runtime initialization failed"));
        let status = fs::read_to_string(&supervisor.artifacts().status).expect("status artifact");
        assert!(status.contains("\"state\": \"failed\""));

        let _ = fs::remove_dir_all(artifact_dir);
    }

    #[test]
    fn spawn_failure_updates_status_artifact_to_failed() {
        let artifact_dir = temp_artifact_dir("spawn-failure");
        let missing_working_directory = artifact_dir.join("missing-working-directory");
        let mut supervisor = QemuSupervisor::new(QemuSupervisorConfig::new(
            fake_command(),
            artifact_dir.clone(),
        ));
        supervisor.config.working_directory = missing_working_directory;

        let err = supervisor
            .start()
            .expect_err("invalid executable should fail during spawn");

        assert!(matches!(
            err.kind(),
            QemuProcessErrorKind::PermissionDenied | QemuProcessErrorKind::SpawnFailed
        ));
        assert_eq!(supervisor.state(), QemuProcessState::Failed);
        let status = fs::read_to_string(&supervisor.artifacts().status).expect("status artifact");
        assert!(status.contains("\"state\": \"failed\""));

        let _ = fs::remove_dir_all(&supervisor.artifacts().directory);
    }

    #[test]
    fn post_spawn_status_failure_terminates_fake_process() {
        let artifact_dir = temp_artifact_dir("post-spawn-status-failure");
        let mut supervisor = fake_supervisor("block-status", artifact_dir.clone());
        supervisor.config.startup_timeout = Duration::from_millis(500);
        supervisor.config.environment.variables.push((
            OsString::from(FAKE_STATUS_PATH_ENV),
            supervisor.artifacts().status.as_os_str().to_owned(),
        ));

        let err = supervisor
            .start()
            .expect_err("post-spawn status artifact failure should fail startup");

        assert!(matches!(
            err.kind(),
            QemuProcessErrorKind::ArtifactIo | QemuProcessErrorKind::PermissionDenied
        ));
        assert_eq!(supervisor.state(), QemuProcessState::Failed);
        assert!(
            supervisor.child.is_none(),
            "failed startup cleanup should not leave a tracked child process"
        );
        assert!(
            supervisor.exit_status().is_some(),
            "failed startup cleanup should wait best-effort for the child"
        );

        let _ = fs::remove_dir_all(artifact_dir);
    }

    #[test]
    fn supervisor_is_single_use_after_terminal_states() {
        let failed_artifact_dir = temp_artifact_dir("single-use-failed");
        let mut failed = fake_supervisor("exit-whpx", failed_artifact_dir.clone());
        failed.config.startup_timeout = Duration::from_secs(2);
        failed
            .start()
            .expect_err("fake WHPX startup failure should be reported");
        assert_eq!(failed.state(), QemuProcessState::Failed);
        assert_eq!(
            failed
                .start()
                .expect_err("failed supervisor should be single-use")
                .kind(),
            QemuProcessErrorKind::AlreadyStarted
        );

        let exited_artifact_dir = temp_artifact_dir("single-use-exited");
        let mut exited = fake_supervisor("exit-after-startup", exited_artifact_dir.clone());
        exited.config.startup_timeout = Duration::from_millis(50);
        exited
            .start()
            .expect("fake process should survive startup window");
        exited
            .wait(Duration::from_secs(2))
            .expect("fake process should exit");
        assert_eq!(exited.state(), QemuProcessState::Exited);
        assert_eq!(
            exited
                .start()
                .expect_err("exited supervisor should be single-use")
                .kind(),
            QemuProcessErrorKind::AlreadyStarted
        );

        let terminated_artifact_dir = temp_artifact_dir("single-use-terminated");
        let mut terminated = fake_supervisor("log", terminated_artifact_dir.clone());
        terminated.start().expect("fake process should start");
        terminated
            .terminate()
            .expect("fake process should terminate");
        assert_eq!(terminated.state(), QemuProcessState::Terminated);
        assert_eq!(
            terminated
                .start()
                .expect_err("terminated supervisor should be single-use")
                .kind(),
            QemuProcessErrorKind::AlreadyStarted
        );

        let _ = fs::remove_dir_all(failed_artifact_dir);
        let _ = fs::remove_dir_all(exited_artifact_dir);
        let _ = fs::remove_dir_all(terminated_artifact_dir);
    }

    #[test]
    fn invalid_relative_executable_is_rejected_before_spawn() {
        let artifact_dir = temp_artifact_dir("relative-exe");
        let mut command = fake_command();
        command.program = PathBuf::from("qemu-system-x86_64.exe");
        let mut supervisor = QemuSupervisor::new(QemuSupervisorConfig::new(command, artifact_dir));

        let err = supervisor
            .start()
            .expect_err("relative executable should fail before spawn");

        assert_eq!(err.kind(), QemuProcessErrorKind::InvalidCommand);
        assert!(err.to_string().contains("must be absolute"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_qemu_creation_flags_hide_console_window() {
        assert_ne!(
            crate::windows_x86_64::qemu_no_window_creation_flags()
                & windows_sys::Win32::System::Threading::CREATE_NO_WINDOW,
            0,
            "QEMU must be spawned with CREATE_NO_WINDOW for GUI parents"
        );
        assert_ne!(
            crate::windows_x86_64::qemu_contained_creation_flags()
                & windows_sys::Win32::System::Threading::CREATE_SUSPENDED,
            0,
            "QEMU must be spawned suspended until Job assignment completes"
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_child_entrypoint_observes_job_containment() {
        let artifact_dir = temp_artifact_dir("job-at-entry");
        let mut supervisor = fake_supervisor("assert-job-contained-at-entry", artifact_dir.clone());

        if let Err(err) = supervisor.start() {
            if err.kind() == QemuProcessErrorKind::ProcessAlreadyInJob {
                eprintln!("skipping Job Object entrypoint test: {err}");
                return;
            }
            panic!("fake process should start already contained by a Job Object: {err}");
        }

        let stdout = wait_for_file_contains(
            &supervisor.artifacts().stdout,
            "fake QEMU entered already Job-contained",
        );
        assert!(stdout.contains("fake QEMU entered already Job-contained"));
        supervisor
            .terminate()
            .expect("contained fake process should terminate cleanly");

        let _ = fs::remove_dir_all(artifact_dir);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_job_object_drop_terminates_fake_child_tree() {
        let artifact_dir = temp_artifact_dir("job-object");
        let pid_file = artifact_dir.join("grandchild.pid");
        let mut config = QemuSupervisorConfig::new(fake_command(), artifact_dir.clone());
        config.startup_timeout = Duration::from_millis(250);
        config.terminate_timeout = Duration::from_secs(3);
        config.environment.variables.push((
            OsString::from(FAKE_CHILD_ENV),
            OsString::from("spawn-grandchild"),
        ));
        config.environment.variables.push((
            OsString::from(FAKE_PID_FILE_ENV),
            pid_file.as_os_str().to_owned(),
        ));

        let mut supervisor = QemuSupervisor::new(config);
        if let Err(err) = supervisor.start() {
            if err.kind() == QemuProcessErrorKind::ProcessAlreadyInJob {
                eprintln!("skipping Job Object child-tree test: {err}");
                return;
            }
            panic!("fake process should start under Job Object: {err}");
        }

        let grandchild_pid = wait_for_pid_file(&pid_file);
        drop(supervisor);

        assert!(
            wait_for_windows_process_exit(grandchild_pid, Duration::from_secs(5)),
            "grandchild process {grandchild_pid} should exit when the Job Object is dropped"
        );

        let _ = fs::remove_dir_all(artifact_dir);
    }

    #[cfg(target_os = "windows")]
    fn wait_for_windows_process_exit(pid: u32, timeout: Duration) -> bool {
        use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
        use windows_sys::Win32::System::Threading::{
            OpenProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
            PROCESS_SYNCHRONIZE,
        };

        let handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                pid,
            )
        };
        if handle.is_null() {
            return true;
        }

        let wait_ms = timeout.as_millis().min(u128::from(u32::MAX)) as u32;
        let result = unsafe { WaitForSingleObject(handle, wait_ms) };
        let _ = unsafe { CloseHandle(handle) };
        result == WAIT_OBJECT_0
    }
}
