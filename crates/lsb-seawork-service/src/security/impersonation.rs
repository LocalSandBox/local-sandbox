use std::os::windows::io::RawHandle;

use anyhow::{bail, Result};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Security::RevertToSelf;
use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;

pub struct ImpersonationGuard {
    active: bool,
}

impl ImpersonationGuard {
    pub fn for_named_pipe(pipe: RawHandle) -> Result<Self> {
        if unsafe { ImpersonateNamedPipeClient(pipe as HANDLE) } == 0 {
            bail!(
                "ImpersonateNamedPipeClient failed: {}",
                std::io::Error::last_os_error()
            );
        }
        Ok(Self { active: true })
    }

    pub fn revert(mut self) -> Result<()> {
        self.revert_inner()
    }

    fn revert_inner(&mut self) -> Result<()> {
        if self.active {
            if unsafe { RevertToSelf() } == 0 {
                bail!("RevertToSelf failed: {}", std::io::Error::last_os_error());
            }
            self.active = false;
        }
        Ok(())
    }
}

impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        if self.active {
            if unsafe { RevertToSelf() } == 0 {
                std::process::abort();
            }
            self.active = false;
        }
    }
}
