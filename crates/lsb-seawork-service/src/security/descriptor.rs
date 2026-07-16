use std::os::windows::ffi::OsStrExt;
use std::ptr;

use anyhow::{bail, Result};
use windows_sys::Win32::Foundation::{LocalFree, HLOCAL};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::PSECURITY_DESCRIPTOR;

pub struct SecurityDescriptor {
    raw: PSECURITY_DESCRIPTOR,
}

impl SecurityDescriptor {
    pub fn from_sddl(sddl: &str) -> Result<Self> {
        let wide = std::ffi::OsStr::new(sddl)
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let mut raw = ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut raw,
                ptr::null_mut(),
            )
        } == 0
        {
            bail!("convert SDDL failed: {}", std::io::Error::last_os_error());
        }
        Ok(Self { raw })
    }

    pub fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.raw
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        unsafe { LocalFree(self.raw as HLOCAL) };
    }
}
