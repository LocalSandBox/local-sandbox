use std::collections::{HashMap, HashSet};
use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::sync::Mutex;

use anyhow::{bail, Context, Result};
use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE, WAIT_TIMEOUT};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob,
    JobObjectAssociateCompletionPortInformation, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject, JOBOBJECT_ASSOCIATE_COMPLETION_PORT,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::SystemServices::{
    JOB_OBJECT_MSG_ABNORMAL_EXIT_PROCESS, JOB_OBJECT_MSG_ACTIVE_PROCESS_LIMIT,
    JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO, JOB_OBJECT_MSG_END_OF_JOB_TIME,
    JOB_OBJECT_MSG_END_OF_PROCESS_TIME, JOB_OBJECT_MSG_EXIT_PROCESS,
    JOB_OBJECT_MSG_JOB_MEMORY_LIMIT, JOB_OBJECT_MSG_NEW_PROCESS, JOB_OBJECT_MSG_NOTIFICATION_LIMIT,
    JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT,
};
use windows_sys::Win32::System::IO::{CreateIoCompletionPort, GetQueuedCompletionStatus};

use crate::ledger::schema::{LifecycleState, ResourceRecord};
use crate::resource::transaction::ResourceTransaction;
use crate::telemetry::{Breadcrumb, SpanDescription, SpanGuard, SpanParent, SpanStatus, Telemetry};

struct QemuJournal {
    transaction: ResourceTransaction,
    image_relative_path: String,
    job_id: String,
    intent: Option<usize>,
    finished: bool,
}

const COMPLETION_KEY: usize = 0x4c53424a;
const MAX_NOTIFICATIONS_PER_POLL: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JobNotification {
    NewProcess(u32),
    ExitProcess(u32),
    ActiveProcessZero,
    LimitViolation(u32),
}

#[derive(Default)]
struct JobMonitor {
    active_processes: HashSet<u32>,
    pending_exit_notifications: HashSet<u32>,
    saw_active_zero: bool,
    decoded_notification_count: u64,
    last_notification_type: Option<String>,
    last_notification_utc: Option<String>,
    termination_requested: bool,
    termination_succeeded: Option<bool>,
}

#[derive(Default)]
struct QemuLifecycleTrace {
    parent: Option<SpanParent>,
    telemetry: Option<Telemetry>,
    active: HashMap<lsb_platform::PlatformQemuLifecyclePhase, SpanGuard>,
}

impl QemuLifecycleTrace {
    fn attach(&mut self, telemetry: Telemetry, parent: SpanParent) {
        self.active.clear();
        self.telemetry = Some(telemetry);
        self.parent = Some(parent);
    }

    fn clear(&mut self) {
        self.active.clear();
        self.telemetry = None;
        self.parent = None;
    }

    fn record(&mut self, event: lsb_platform::PlatformQemuLifecycleEvent) {
        let operation = lifecycle_operation(event.phase);
        match event.state {
            lsb_platform::PlatformQemuLifecycleState::Started => {
                if let (Some(parent), Some(telemetry)) = (&self.parent, &self.telemetry) {
                    self.active.remove(&event.phase);
                    self.active.insert(
                        event.phase,
                        parent.start_child(SpanDescription::child(operation, operation)),
                    );
                    telemetry.breadcrumb(
                        Breadcrumb::lifecycle("qemu", "phase_started")
                            .with_data("phase", operation),
                    );
                }
            }
            lsb_platform::PlatformQemuLifecycleState::Completed => {
                if let Some(span) = self.active.remove(&event.phase) {
                    span.finish(if event.succeeded == Some(true) {
                        SpanStatus::Ok
                    } else {
                        SpanStatus::InternalError
                    });
                }
                if let Some(telemetry) = &self.telemetry {
                    telemetry.breadcrumb(
                        Breadcrumb::lifecycle("qemu", "phase_completed")
                            .with_data("phase", operation)
                            .with_data(
                                "outcome",
                                if event.succeeded == Some(true) {
                                    "success"
                                } else {
                                    "failure"
                                },
                            ),
                    );
                }
            }
        }
    }
}

fn lifecycle_operation(phase: lsb_platform::PlatformQemuLifecyclePhase) -> &'static str {
    use lsb_platform::PlatformQemuLifecyclePhase as Phase;
    match phase {
        Phase::Preflight => "qemu.preflight",
        Phase::Spawn => "qemu.spawn",
        Phase::JobAssign => "qemu.job_assign",
        Phase::ControlOpen => "qemu.control_open",
        Phase::ForwardOpen => "qemu.forward_open",
        Phase::GuestReadyWait => "qemu.guest_ready_wait",
        Phase::HangSnapshot => "qemu.hang_snapshot",
        Phase::Dump => "qemu.dump",
        Phase::Terminate => "qemu.terminate",
        Phase::WaitExit => "qemu.wait_exit",
        Phase::JobDrain => "qemu.job_drain",
    }
}

impl JobMonitor {
    fn apply(&mut self, notification: JobNotification) -> Result<()> {
        self.decoded_notification_count = self.decoded_notification_count.saturating_add(1);
        self.last_notification_type = Some(notification_type(notification).to_string());
        self.last_notification_utc = Some(
            time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| "unknown".to_string()),
        );
        match notification {
            JobNotification::NewProcess(pid) => {
                if self.pending_exit_notifications.contains(&pid)
                    || !self.active_processes.insert(pid)
                {
                    bail!("QEMU Job reported a duplicate process admission");
                }
                self.saw_active_zero = false;
            }
            JobNotification::ExitProcess(pid) => {
                if !self.active_processes.remove(&pid)
                    && !self.pending_exit_notifications.remove(&pid)
                {
                    bail!("QEMU Job reported an exit for an untracked process");
                }
            }
            JobNotification::ActiveProcessZero => {
                // Windows may dequeue ACTIVE_PROCESS_ZERO before the corresponding
                // EXIT_PROCESS packets. The zero notification is authoritative;
                // retain the known PIDs only to validate those late exit packets.
                self.pending_exit_notifications
                    .extend(self.active_processes.drain());
                self.saw_active_zero = true;
            }
            JobNotification::LimitViolation(message) => {
                bail!("QEMU Job reported resource limit notification {message}")
            }
        }
        Ok(())
    }

    fn snapshot(&self, limits: JobLimits) -> lsb_platform::PlatformQemuJobSnapshot {
        let mut active_pids = self.active_processes.iter().copied().collect::<Vec<_>>();
        active_pids.sort_unstable();
        lsb_platform::PlatformQemuJobSnapshot {
            active_pids,
            active_process_zero_observed: self.saw_active_zero,
            decoded_notification_count: self.decoded_notification_count,
            last_notification_type: self.last_notification_type.clone(),
            last_notification_utc: self.last_notification_utc.clone(),
            active_process_limit: limits.active_processes,
            memory_limit_bytes: u64::try_from(limits.memory_bytes).unwrap_or(u64::MAX),
            termination_requested: self.termination_requested,
            termination_succeeded: self.termination_succeeded,
        }
    }
}

fn notification_type(notification: JobNotification) -> &'static str {
    match notification {
        JobNotification::NewProcess(_) => "new_process",
        JobNotification::ExitProcess(_) => "exit_process",
        JobNotification::ActiveProcessZero => "active_process_zero",
        JobNotification::LimitViolation(_) => "limit_violation",
    }
}

#[derive(Debug, Clone, Copy)]
pub struct JobLimits {
    pub active_processes: u32,
    pub memory_bytes: usize,
}

pub struct SandboxJob {
    handle: OwnedHandle,
    completion_port: OwnedHandle,
    monitor: Mutex<JobMonitor>,
    limits: JobLimits,
    journal: Option<Mutex<QemuJournal>>,
    qemu_telemetry: Option<lsb_platform::PlatformQemuTelemetryContext>,
    lifecycle_trace: Mutex<QemuLifecycleTrace>,
}

impl SandboxJob {
    pub fn create(limits: JobLimits) -> Result<Self> {
        if limits.active_processes == 0 || limits.memory_bytes == 0 {
            bail!("Job limits must be nonzero");
        }
        let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if raw.is_null() {
            bail!(
                "CreateJobObjectW failed: {}",
                std::io::Error::last_os_error()
            );
        }
        let completion_raw = unsafe {
            CreateIoCompletionPort(
                INVALID_HANDLE_VALUE,
                std::ptr::null_mut(),
                COMPLETION_KEY,
                1,
            )
        };
        if completion_raw.is_null() {
            bail!(
                "CreateIoCompletionPort for QEMU Job failed: {}",
                std::io::Error::last_os_error()
            );
        }
        let job = Self {
            handle: unsafe { OwnedHandle::from_raw_handle(raw as _) },
            completion_port: unsafe { OwnedHandle::from_raw_handle(completion_raw as _) },
            monitor: Mutex::new(JobMonitor::default()),
            limits,
            journal: None,
            qemu_telemetry: None,
            lifecycle_trace: Mutex::new(QemuLifecycleTrace::default()),
        };
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_JOB_MEMORY;
        info.BasicLimitInformation.ActiveProcessLimit = limits.active_processes;
        info.JobMemoryLimit = limits.memory_bytes;
        if unsafe {
            SetInformationJobObject(
                job.raw(),
                JobObjectExtendedLimitInformation,
                (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } == 0
        {
            bail!(
                "SetInformationJobObject failed: {}",
                std::io::Error::last_os_error()
            );
        }
        let association = JOBOBJECT_ASSOCIATE_COMPLETION_PORT {
            CompletionKey: COMPLETION_KEY as *mut _,
            CompletionPort: job.completion_port.as_raw_handle() as HANDLE,
        };
        if unsafe {
            SetInformationJobObject(
                job.raw(),
                JobObjectAssociateCompletionPortInformation,
                (&association as *const JOBOBJECT_ASSOCIATE_COMPLETION_PORT).cast(),
                size_of::<JOBOBJECT_ASSOCIATE_COMPLETION_PORT>() as u32,
            )
        } == 0
        {
            bail!(
                "associate QEMU Job completion port failed: {}",
                std::io::Error::last_os_error()
            );
        }
        Ok(job)
    }

    pub fn attach_qemu_telemetry(&mut self, context: lsb_platform::PlatformQemuTelemetryContext) {
        self.qemu_telemetry = Some(context);
    }

    pub fn attach_qemu_lifecycle(&self, telemetry: Telemetry, parent: SpanParent) {
        if let Ok(mut trace) = self.lifecycle_trace.lock() {
            trace.attach(telemetry, parent);
        }
    }

    pub fn clear_qemu_lifecycle(&self) {
        if let Ok(mut trace) = self.lifecycle_trace.lock() {
            trace.clear();
        }
    }

    pub fn start_lifecycle_span(
        &self,
        operation: &'static str,
        description: &'static str,
    ) -> Option<SpanGuard> {
        self.lifecycle_trace
            .lock()
            .ok()?
            .parent
            .as_ref()
            .map(|parent| parent.start_child(SpanDescription::child(operation, description)))
    }

    pub fn check_notifications(&self) -> Result<()> {
        let mut monitor = self
            .monitor
            .lock()
            .map_err(|_| anyhow::anyhow!("QEMU Job monitor lock poisoned"))?;
        self.refresh_monitor(&mut monitor)?;
        if monitor.saw_active_zero {
            bail!("QEMU Job has no active processes while the VM is running");
        }
        Ok(())
    }

    fn refresh_monitor(&self, monitor: &mut JobMonitor) -> Result<()> {
        for _ in 0..MAX_NOTIFICATIONS_PER_POLL {
            let Some(notification) = self.poll_notification()? else {
                return Ok(());
            };
            monitor.apply(notification)?;
        }
        bail!("QEMU Job completion notification batch exceeded its bound")
    }

    fn poll_notification(&self) -> Result<Option<JobNotification>> {
        let mut message = 0u32;
        let mut key = 0usize;
        let mut process = std::ptr::null_mut();
        let ok = unsafe {
            GetQueuedCompletionStatus(
                self.completion_port.as_raw_handle() as HANDLE,
                &mut message,
                &mut key,
                &mut process,
                0,
            )
        };
        if ok == 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(WAIT_TIMEOUT as i32) {
                return Ok(None);
            }
            return Err(error.into());
        }
        if key != COMPLETION_KEY {
            bail!("QEMU Job completion notification used an unexpected key");
        }
        decode_notification(message, process as usize).map(Some)
    }

    pub fn attach_journal(
        &mut self,
        transaction: ResourceTransaction,
        image_relative_path: String,
        job_id: String,
    ) -> Result<()> {
        if self.journal.is_some() {
            bail!("QEMU Job already has a resource journal");
        }
        self.journal = Some(Mutex::new(QemuJournal {
            transaction,
            image_relative_path,
            job_id,
            intent: None,
            finished: false,
        }));
        Ok(())
    }

    pub fn set_transaction_state(&self, state: LifecycleState) -> Result<()> {
        if let Some(journal) = &self.journal {
            journal
                .lock()
                .map_err(|_| anyhow::anyhow!("QEMU journal lock poisoned"))?
                .transaction
                .set_state(state)?;
        }
        Ok(())
    }

    pub fn finish_transaction(&self) -> Result<()> {
        let Some(journal) = &self.journal else {
            return Ok(());
        };
        let mut journal = journal
            .lock()
            .map_err(|_| anyhow::anyhow!("QEMU journal lock poisoned"))?;
        if !journal.finished {
            journal.transaction.finish()?;
            journal.finished = true;
        }
        Ok(())
    }

    pub fn require_staging_identity(&self, relative_path: &str, file_id: &str) -> Result<()> {
        let journal = self
            .journal
            .as_ref()
            .context("QEMU Job has no resource journal")?
            .lock()
            .map_err(|_| anyhow::anyhow!("QEMU journal lock poisoned"))?;
        journal
            .transaction
            .require_staging_identity(relative_path, file_id)
    }

    fn prepare_journal(&self) -> Result<()> {
        let Some(journal) = &self.journal else {
            return Ok(());
        };
        let mut journal = journal
            .lock()
            .map_err(|_| anyhow::anyhow!("QEMU journal lock poisoned"))?;
        if journal.intent.is_some() {
            bail!("QEMU creation intent was already persisted");
        }
        let resource = ResourceRecord::QemuProcess {
            pid: 0,
            creation_time: 0,
            image_relative_path: journal.image_relative_path.clone(),
            job_id: journal.job_id.clone(),
            committed: false,
        };
        let intent = journal.transaction.intent(resource)?;
        journal.intent = Some(intent);
        Ok(())
    }

    fn commit_journal(&self, process: &std::process::Child) -> Result<()> {
        let Some(journal) = &self.journal else {
            return Ok(());
        };
        let creation_time =
            crate::windows::process::process_creation_time(process.as_raw_handle())?;
        let mut journal = journal
            .lock()
            .map_err(|_| anyhow::anyhow!("QEMU journal lock poisoned"))?;
        let intent = journal.intent.context("QEMU creation intent is missing")?;
        let resource = ResourceRecord::QemuProcess {
            pid: process.id(),
            creation_time,
            image_relative_path: journal.image_relative_path.clone(),
            job_id: journal.job_id.clone(),
            committed: true,
        };
        journal.transaction.replace_and_commit(intent, resource)
    }

    pub fn assign_process(&self, process: RawHandle) -> Result<()> {
        if unsafe { AssignProcessToJobObject(self.raw(), process as HANDLE) } == 0 {
            bail!(
                "AssignProcessToJobObject failed: {}",
                std::io::Error::last_os_error()
            );
        }
        let mut contained = 0;
        if unsafe { IsProcessInJob(process as HANDLE, self.raw(), &mut contained) } == 0 {
            bail!(
                "IsProcessInJob failed after assignment: {}",
                std::io::Error::last_os_error()
            );
        }
        if contained == 0 {
            bail!("assigned process did not enter the authoritative Job");
        }
        Ok(())
    }

    pub fn terminate(&self, exit_code: u32) -> Result<()> {
        let result = if unsafe { TerminateJobObject(self.raw(), exit_code) } == 0 {
            Err(anyhow::anyhow!(
                "TerminateJobObject failed: {}",
                std::io::Error::last_os_error()
            ))
        } else {
            Ok(())
        };
        if let Ok(mut monitor) = self.monitor.lock() {
            monitor.termination_requested = true;
            monitor.termination_succeeded = Some(result.is_ok());
        }
        result
    }

    fn raw(&self) -> HANDLE {
        self.handle.as_raw_handle() as HANDLE
    }
}

fn decode_notification(message: u32, process_value: usize) -> Result<JobNotification> {
    match message {
        JOB_OBJECT_MSG_NEW_PROCESS => Ok(JobNotification::NewProcess(notification_pid(
            process_value,
        )?)),
        JOB_OBJECT_MSG_EXIT_PROCESS | JOB_OBJECT_MSG_ABNORMAL_EXIT_PROCESS => Ok(
            JobNotification::ExitProcess(notification_pid(process_value)?),
        ),
        JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO if process_value == 0 => {
            Ok(JobNotification::ActiveProcessZero)
        }
        JOB_OBJECT_MSG_ACTIVE_PROCESS_LIMIT
        | JOB_OBJECT_MSG_END_OF_JOB_TIME
        | JOB_OBJECT_MSG_END_OF_PROCESS_TIME
        | JOB_OBJECT_MSG_JOB_MEMORY_LIMIT
        | JOB_OBJECT_MSG_NOTIFICATION_LIMIT
        | JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT => Ok(JobNotification::LimitViolation(message)),
        JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO => {
            bail!("QEMU Job zero-process notification carried a process id")
        }
        _ => bail!("QEMU Job reported an unsupported completion notification"),
    }
}

fn notification_pid(value: usize) -> Result<u32> {
    let pid = u32::try_from(value).context("QEMU Job notification process id overflow")?;
    if pid == 0 {
        bail!("QEMU Job process notification carried a zero process id");
    }
    Ok(pid)
}

impl lsb_vm::PlatformProcessContainment for SandboxJob {
    fn prepare_process(&self) -> Result<()> {
        self.prepare_journal()
    }

    fn qemu_telemetry_context(&self) -> Option<lsb_platform::PlatformQemuTelemetryContext> {
        self.qemu_telemetry.clone()
    }

    fn capture_qemu_live_evidence(
        &self,
        incident: &lsb_platform::PlatformQemuLiveIncident,
    ) -> Result<()> {
        crate::telemetry::capture_hyperv_evidence(incident)
    }

    fn qemu_job_snapshot(&self) -> Result<Option<lsb_platform::PlatformQemuJobSnapshot>> {
        let mut monitor = self
            .monitor
            .lock()
            .map_err(|_| anyhow::anyhow!("QEMU Job monitor lock poisoned"))?;
        self.refresh_monitor(&mut monitor)?;
        Ok(Some(monitor.snapshot(self.limits)))
    }

    fn qemu_lifecycle_event(&self, event: lsb_platform::PlatformQemuLifecycleEvent) -> Result<()> {
        let mut trace = self
            .lifecycle_trace
            .lock()
            .map_err(|_| anyhow::anyhow!("QEMU lifecycle trace lock poisoned"))?;
        trace.record(event);
        Ok(())
    }

    fn assign_process(&self, process: &std::process::Child) -> Result<()> {
        SandboxJob::assign_process(self, process.as_raw_handle())?;
        self.commit_journal(process)
    }

    fn terminate(&self) -> Result<()> {
        SandboxJob::terminate(self, 1)
    }
}

impl std::fmt::Debug for SandboxJob {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("SandboxJob").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::time::Duration;

    use crate::windows::process::ContainedProcess;

    const CHILD_TEST_NAME: &str = "windows::job::tests::contained_child_entrypoint";

    #[test]
    fn completion_notifications_decode_closed_shapes_without_kernel_objects() {
        assert_eq!(
            decode_notification(JOB_OBJECT_MSG_NEW_PROCESS, 42).unwrap(),
            JobNotification::NewProcess(42)
        );
        assert_eq!(
            decode_notification(JOB_OBJECT_MSG_ABNORMAL_EXIT_PROCESS, 42).unwrap(),
            JobNotification::ExitProcess(42)
        );
        assert_eq!(
            decode_notification(JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO, 0).unwrap(),
            JobNotification::ActiveProcessZero
        );
        assert!(decode_notification(JOB_OBJECT_MSG_NEW_PROCESS, 0).is_err());
        assert!(decode_notification(JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO, 42).is_err());
        assert!(decode_notification(u32::MAX, 0).is_err());
    }

    #[test]
    fn completion_monitor_tracks_every_process_and_fails_closed() {
        let mut monitor = JobMonitor::default();
        monitor.apply(JobNotification::NewProcess(10)).unwrap();
        monitor.apply(JobNotification::NewProcess(11)).unwrap();
        assert!(monitor.apply(JobNotification::NewProcess(10)).is_err());
        assert!(monitor.apply(JobNotification::ExitProcess(12)).is_err());
        monitor.apply(JobNotification::ExitProcess(11)).unwrap();
        monitor.apply(JobNotification::ActiveProcessZero).unwrap();
        assert!(monitor.active_processes.is_empty());
        assert!(monitor.saw_active_zero);
        monitor.apply(JobNotification::ExitProcess(10)).unwrap();
        assert!(monitor.pending_exit_notifications.is_empty());
        let snapshot = monitor.snapshot(JobLimits {
            active_processes: 8,
            memory_bytes: 1024,
        });
        assert!(snapshot.active_pids.is_empty());
        assert!(snapshot.active_process_zero_observed);
        assert_eq!(snapshot.active_process_limit, 8);
        assert_eq!(snapshot.memory_limit_bytes, 1024);
        assert_eq!(
            snapshot.last_notification_type.as_deref(),
            Some("exit_process")
        );
        assert!(monitor
            .apply(JobNotification::LimitViolation(
                JOB_OBJECT_MSG_JOB_MEMORY_LIMIT
            ))
            .is_err());
    }

    #[test]
    #[ignore = "launched as the suspended child by the service Job containment test"]
    fn contained_child_entrypoint() {
        use windows_sys::Win32::System::JobObjects::IsProcessInJob;
        use windows_sys::Win32::System::Threading::GetCurrentProcess;

        let mut contained = 0;
        assert_ne!(
            unsafe { IsProcessInJob(GetCurrentProcess(), std::ptr::null_mut(), &mut contained) },
            0,
            "child should be able to query Job membership"
        );
        assert_ne!(
            contained, 0,
            "child entrypoint must already be Job-contained"
        );
        std::thread::sleep(Duration::from_secs(60));
    }

    #[test]
    fn service_job_contains_suspended_child_and_terminates_it() {
        let job = SandboxJob::create(JobLimits {
            active_processes: 2,
            memory_bytes: 512 * 1024 * 1024,
        })
        .expect("service Job should be created");
        let executable = std::env::current_exe().expect("test executable path");
        let working_directory = std::env::current_dir().expect("test working directory");
        let arguments = ["--ignored", "--exact", CHILD_TEST_NAME, "--nocapture"]
            .into_iter()
            .map(OsString::from)
            .collect::<Vec<_>>();
        let process = ContainedProcess::spawn_suspended_into_job(
            &job,
            &executable,
            &arguments,
            &working_directory,
        )
        .expect("suspended child should enter service Job before resume");

        assert_eq!(
            process.wait(Duration::from_millis(100)).unwrap(),
            None,
            "contained child should reach its sleeping entrypoint"
        );
        job.terminate(1)
            .expect("service Job should terminate child");
        assert!(
            process.wait(Duration::from_secs(2)).unwrap().is_some(),
            "contained child should exit after authoritative Job termination"
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let snapshot = loop {
            let snapshot = lsb_vm::PlatformProcessContainment::qemu_job_snapshot(&job)
                .unwrap()
                .unwrap();
            if snapshot.active_process_zero_observed || std::time::Instant::now() >= deadline {
                break snapshot;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(snapshot.active_pids.is_empty());
        assert!(snapshot.active_process_zero_observed);
        assert!(snapshot.termination_requested);
        assert_eq!(snapshot.termination_succeeded, Some(true));
    }
}
