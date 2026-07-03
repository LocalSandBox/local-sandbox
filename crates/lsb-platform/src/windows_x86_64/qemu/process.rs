use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File};
use std::io;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use serde::Serialize;

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
                "Run LocalSandbox outside the conflicting parent Job Object or configure the runner to allow nested/breakaway jobs; this milestone fails closed when containment cannot be guaranteed."
            }
            Self::JobObjectTerminateFailed { .. } => {
                "Check whether QEMU already exited or whether host policy blocked Job Object termination, then inspect the process id and diagnostics."
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

        let mut child = command.spawn().map_err(|err| {
            self.state = QemuProcessState::Failed;
            spawn_error(&self.config.command.program, err)
        })?;
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
        self.child = Some(child);

        if let Some(status) = self.wait_for_startup_exit()? {
            self.child = None;
            self.exit_status = Some(status.clone());
            self.state = QemuProcessState::Failed;
            let _ = self.write_status_artifact();
            return Err(startup_exit_error(status, &self.config.artifacts.stderr));
        }

        self.state = QemuProcessState::Running;
        self.write_status_artifact()?;
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

    pub(crate) fn wait(&mut self, timeout: Duration) -> Result<QemuExitStatus, QemuProcessError> {
        if self.child.is_none() {
            return self.exit_status.clone().ok_or(QemuProcessError::NotStarted);
        }

        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.poll_exit()? {
                self.state = QemuProcessState::Exited;
                self.write_status_artifact()?;
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
        self.write_status_artifact()?;
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
        if self.containment.terminate()? {
            return Ok(());
        }
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
#[derive(Debug)]
struct ProcessContainment {
    job: Option<JobObject>,
}

#[cfg(target_os = "windows")]
impl Default for ProcessContainment {
    fn default() -> Self {
        Self { job: None }
    }
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

fn file_name(path: &PathBuf) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "<unknown>".to_string())
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
