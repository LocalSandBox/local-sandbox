use super::types::{WindowsSmbLifecycleError, WindowsSmbLifecyclePhase};

pub trait WindowsSmbAdmin {
    fn ensure_elevated_admin(&mut self) -> Result<(), WindowsSmbLifecycleError>;

    fn ensure_windows_smb_policy_allows_generated_users(
        &mut self,
    ) -> Result<(), WindowsSmbLifecycleError> {
        Ok(())
    }

    fn ensure_smb_loopback_available(&mut self) -> Result<(), WindowsSmbLifecycleError> {
        Ok(())
    }
}

#[cfg(windows)]
#[derive(Default)]
pub struct NativeWindowsSmbAdmin;

#[cfg(windows)]
impl WindowsSmbAdmin for NativeWindowsSmbAdmin {
    fn ensure_elevated_admin(&mut self) -> Result<(), WindowsSmbLifecycleError> {
        use std::ptr;

        use windows_sys::Win32::Foundation::GetLastError;
        use windows_sys::Win32::Security::{
            AllocateAndInitializeSid, CheckTokenMembership, FreeSid, PSID, SECURITY_NT_AUTHORITY,
        };
        use windows_sys::Win32::System::SystemServices::{
            DOMAIN_ALIAS_RID_ADMINS, SECURITY_BUILTIN_DOMAIN_RID,
        };

        let mut admin_sid: PSID = ptr::null_mut();
        let allocated = unsafe {
            AllocateAndInitializeSid(
                &SECURITY_NT_AUTHORITY,
                2,
                SECURITY_BUILTIN_DOMAIN_RID as u32,
                DOMAIN_ALIAS_RID_ADMINS as u32,
                0,
                0,
                0,
                0,
                0,
                0,
                &mut admin_sid,
            )
        };
        if allocated == 0 {
            let code = unsafe { GetLastError() };
            return Err(WindowsSmbLifecycleError::operation_failed(
                WindowsSmbLifecyclePhase::AdminPreflight,
                format!("failed to create Administrators SID: win32 error {code}"),
            ));
        }

        let mut is_member = 0;
        let checked =
            unsafe { CheckTokenMembership(std::ptr::null_mut(), admin_sid, &mut is_member) };
        unsafe {
            FreeSid(admin_sid);
        }

        if checked == 0 {
            let code = unsafe { GetLastError() };
            return Err(WindowsSmbLifecycleError::operation_failed(
                WindowsSmbLifecyclePhase::AdminPreflight,
                format!("failed to check Administrators token membership: win32 error {code}"),
            ));
        }
        if is_member == 0 {
            return Err(WindowsSmbLifecycleError::NotElevated);
        }
        Ok(())
    }

    fn ensure_windows_smb_policy_allows_generated_users(
        &mut self,
    ) -> Result<(), WindowsSmbLifecycleError> {
        super::policy::ensure_windows_smb_policy_allows_generated_users()
    }

    fn ensure_smb_loopback_available(&mut self) -> Result<(), WindowsSmbLifecycleError> {
        use std::net::{Ipv4Addr, SocketAddr, TcpStream};
        use std::time::Duration;

        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 445));
        TcpStream::connect_timeout(&addr, Duration::from_secs(2))
            .map(|_| ())
            .map_err(|error| {
                WindowsSmbLifecycleError::operation_failed(
                    WindowsSmbLifecyclePhase::SmbLoopbackPreflight,
                    format!(
                        "Windows SMB server is unavailable on host loopback port 445: {error}. \
                         Start the Server service and ensure local policy allows SMB on 127.0.0.1:445."
                    ),
                )
            })
    }
}
