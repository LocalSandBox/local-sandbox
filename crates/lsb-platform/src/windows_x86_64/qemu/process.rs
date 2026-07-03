use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File};
use std::io;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

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
            inherit_parent: true,
            variables: Vec::new(),
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

#[derive(Debug, Clone, PartialEq, Eq)]
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
                "Install QEMU for Windows, set LSB_QEMU to qemu-system-x86_64.exe, and rerun Windows QEMU preflight."
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
            Self::WhpxPreflightMismatch { .. } => {
                "Rerun QEMU preflight and confirm Windows Hypervisor Platform is enabled; M02 preflight can report WHPX support in the binary before runtime WHPX initialization is proven."
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
}

impl QemuSupervisor {
    pub(crate) fn new(config: QemuSupervisorConfig) -> Self {
        Self {
            config,
            state: QemuProcessState::NotStarted,
            child: None,
            pid: None,
            exit_status: None,
        }
    }

    pub(crate) fn state(&self) -> QemuProcessState {
        self.state
    }

    pub(crate) fn artifacts(&self) -> &QemuProcessArtifacts {
        &self.config.artifacts
    }

    pub(crate) fn pid(&self) -> Option<u32> {
        self.pid
    }

    pub(crate) fn exit_status(&self) -> Option<&QemuExitStatus> {
        self.exit_status.as_ref()
    }

    pub(crate) fn start(&mut self) -> Result<(), QemuProcessError> {
        if self.child.is_some() {
            return Err(QemuProcessError::AlreadyStarted { state: self.state });
        }
        if !matches!(
            self.state,
            QemuProcessState::NotStarted
                | QemuProcessState::Failed
                | QemuProcessState::Exited
                | QemuProcessState::Terminated
        ) {
            return Err(QemuProcessError::AlreadyStarted { state: self.state });
        }

        self.validate_start_inputs()?;
        self.prepare_artifacts()?;
        self.state = QemuProcessState::Starting;

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

        let child = command.spawn().map_err(|err| {
            self.state = QemuProcessState::Failed;
            spawn_error(&self.config.command.program, err)
        })?;
        self.pid = Some(child.id());
        self.child = Some(child);

        if let Some(status) = self.wait_for_startup_exit()? {
            self.child = None;
            self.exit_status = Some(status.clone());
            self.state = QemuProcessState::Failed;
            return Err(startup_exit_error(status, &self.config.artifacts.stderr));
        }

        self.state = QemuProcessState::Running;
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
                Ok(self.state)
            }
            Ok(None) => {
                self.state = QemuProcessState::Running;
                Ok(self.state)
            }
            Err(err) => {
                self.state = QemuProcessState::Failed;
                Err(QemuProcessError::CleanupFailed {
                    operation: "poll",
                    detail: err.to_string(),
                })
            }
        }
    }

    pub(crate) fn wait(&mut self, timeout: Duration) -> Result<QemuExitStatus, QemuProcessError> {
        if self.child.is_none() {
            return self.exit_status.clone().ok_or(QemuProcessError::NotStarted);
        }

        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.poll_exit()? {
                self.state = QemuProcessState::Exited;
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(QemuProcessError::WaitTimeout { timeout });
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    pub(crate) fn terminate(&mut self) -> Result<Option<QemuExitStatus>, QemuProcessError> {
        if self.child.is_none() {
            return Ok(self.exit_status.clone());
        }

        self.kill_child("terminate")?;
        let status = self.wait(self.config.terminate_timeout)?;
        self.state = QemuProcessState::Terminated;
        Ok(Some(status))
    }

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

    fn kill_child(&mut self, operation: &'static str) -> Result<(), QemuProcessError> {
        let Some(child) = self.child.as_mut() else {
            return Ok(());
        };
        child.kill().map_err(|err| QemuProcessError::CleanupFailed {
            operation,
            detail: err.to_string(),
        })
    }
}

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

fn create_artifact_file(path: &PathBuf, operation: &'static str) -> Result<File, QemuProcessError> {
    File::create(path).map_err(|err| artifact_error(path, operation, err))
}

fn artifact_error(path: &PathBuf, operation: &'static str, err: io::Error) -> QemuProcessError {
    if err.kind() == io::ErrorKind::PermissionDenied {
        QemuProcessError::PermissionDenied {
            path: path.clone(),
            operation,
            detail: err.to_string(),
        }
    } else {
        QemuProcessError::ArtifactIo {
            path: path.clone(),
            operation,
            detail: err.to_string(),
        }
    }
}

fn spawn_error(path: &PathBuf, err: io::Error) -> QemuProcessError {
    if err.kind() == io::ErrorKind::PermissionDenied {
        QemuProcessError::PermissionDenied {
            path: path.clone(),
            operation: "execute",
            detail: err.to_string(),
        }
    } else {
        QemuProcessError::SpawnFailed {
            path: path.clone(),
            detail: err.to_string(),
        }
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
    use crate::windows_x86_64::qemu::argv::QemuArgvBuilder;
    use crate::windows_x86_64::qemu::config::QemuBootConfig;

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
}
