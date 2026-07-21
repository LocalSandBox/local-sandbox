use std::ptr::{null, null_mut};

use anyhow::{bail, Result};
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SetSecurityInfo, SDDL_REVISION_1,
    SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    GetSecurityDescriptorDacl, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

// Interactive clients may pin the service process identity without receiving any
// process mutation, memory, handle-duplication, or termination rights.
const SERVICE_PROCESS_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00101000;;;IU)";

struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0) };
        }
    }
}

pub fn allow_interactive_identity_queries() -> Result<()> {
    let descriptor_text = SERVICE_PROCESS_SDDL
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut descriptor = null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            descriptor_text.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
    {
        bail!(
            "convert service process security descriptor: {}",
            std::io::Error::last_os_error()
        );
    }
    let descriptor = LocalSecurityDescriptor(descriptor);

    let mut dacl_present = 0;
    let mut dacl_defaulted = 0;
    let mut dacl = null_mut();
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor.0,
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    } == 0
    {
        bail!(
            "read service process security descriptor: {}",
            std::io::Error::last_os_error()
        );
    }
    if dacl_present == 0 || dacl.is_null() {
        bail!("service process security descriptor has no DACL");
    }

    let status = unsafe {
        SetSecurityInfo(
            GetCurrentProcess(),
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null(),
        )
    };
    if status != 0 {
        bail!(
            "set service process security descriptor: {}",
            std::io::Error::from_raw_os_error(status as i32)
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::SERVICE_PROCESS_SDDL;

    #[test]
    fn interactive_grant_is_identity_query_only() {
        assert!(SERVICE_PROCESS_SDDL.contains("(A;;0x00101000;;;IU)"));
        assert!(!SERVICE_PROCESS_SDDL.contains(";;;BU)"));
        assert!(!SERVICE_PROCESS_SDDL.contains(";;;AU)"));
    }
}
