use std::os::windows::io::{AsRawHandle, OwnedHandle, RawHandle};

use anyhow::{bail, Result};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Security::RevertToSelf;
use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;
use windows_sys::Win32::System::Threading::SetThreadToken;

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

    pub fn for_token(token: &OwnedHandle) -> Result<Self> {
        if unsafe { SetThreadToken(std::ptr::null(), token.as_raw_handle() as HANDLE) } == 0 {
            bail!("SetThreadToken failed: {}", std::io::Error::last_os_error());
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
