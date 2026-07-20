use std::collections::HashSet;
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
    saw_active_zero: bool,
}

impl JobMonitor {
    fn apply(&mut self, notification: JobNotification) -> Result<()> {
        match notification {
            JobNotification::NewProcess(pid) => {
                if !self.active_processes.insert(pid) {
                    bail!("QEMU Job reported a duplicate process admission");
                }
                self.saw_active_zero = false;
            }
            JobNotification::ExitProcess(pid) => {
                if !self.active_processes.remove(&pid) {
                    bail!("QEMU Job reported an exit for an untracked process");
                }
            }
            JobNotification::ActiveProcessZero => {
                if !self.active_processes.is_empty() {
                    bail!("QEMU Job reported zero active processes with tracked children");
                }
                self.saw_active_zero = true;
            }
            JobNotification::LimitViolation(message) => {
                bail!("QEMU Job reported resource limit notification {message}")
            }
        }
        Ok(())
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
    journal: Option<Mutex<QemuJournal>>,
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
            journal: None,
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

    pub fn check_notifications(&self) -> Result<()> {
        let mut monitor = self
            .monitor
            .lock()
            .map_err(|_| anyhow::anyhow!("QEMU Job monitor lock poisoned"))?;
        for _ in 0..MAX_NOTIFICATIONS_PER_POLL {
            let Some(notification) = self.poll_notification()? else {
                if monitor.saw_active_zero {
                    bail!("QEMU Job has no active processes while the VM is running");
                }
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
        if unsafe { TerminateJobObject(self.raw(), exit_code) } == 0 {
            bail!(
                "TerminateJobObject failed: {}",
                std::io::Error::last_os_error()
            );
        }
        Ok(())
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
        assert!(monitor.apply(JobNotification::ActiveProcessZero).is_err());
        monitor.apply(JobNotification::ExitProcess(10)).unwrap();
        monitor.apply(JobNotification::ActiveProcessZero).unwrap();
        assert!(monitor.saw_active_zero);
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
    }
}
