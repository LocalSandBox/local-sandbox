use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::sync::Mutex;

use anyhow::{bail, Context, Result};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_JOB_MEMORY,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};

use crate::ledger::schema::{LifecycleState, ResourceRecord};
use crate::resource::transaction::ResourceTransaction;

struct QemuJournal {
    transaction: ResourceTransaction,
    image_relative_path: String,
    job_id: String,
    intent: Option<usize>,
    finished: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct JobLimits {
    pub active_processes: u32,
    pub memory_bytes: usize,
}

pub struct SandboxJob {
    handle: OwnedHandle,
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
        let job = Self {
            handle: unsafe { OwnedHandle::from_raw_handle(raw as _) },
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
        Ok(job)
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
