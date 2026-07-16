use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};

use anyhow::{bail, Result};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_JOB_MEMORY,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};

#[derive(Debug, Clone, Copy)]
pub struct JobLimits {
    pub active_processes: u32,
    pub memory_bytes: usize,
}

pub struct SandboxJob {
    handle: OwnedHandle,
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

    pub fn assign_process(&self, process: RawHandle) -> Result<()> {
        if unsafe { AssignProcessToJobObject(self.raw(), process as HANDLE) } == 0 {
            bail!(
                "AssignProcessToJobObject failed: {}",
                std::io::Error::last_os_error()
            );
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

impl std::fmt::Debug for SandboxJob {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("SandboxJob").finish_non_exhaustive()
    }
}
