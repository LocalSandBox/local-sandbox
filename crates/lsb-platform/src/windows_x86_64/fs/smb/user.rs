use std::fmt;

use super::password::WindowsSmbPassword;
use super::types::{validate_smb_user_name, WindowsSmbLifecycleError, WindowsSmbLifecyclePhase};

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct WindowsSmbUserName(String);

impl WindowsSmbUserName {
    pub(crate) fn new_unchecked(name: String) -> Self {
        Self(name)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for WindowsSmbUserName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("WindowsSmbUserName").field(&self.0).finish()
    }
}

impl fmt::Display for WindowsSmbUserName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsSmbUserAccount {
    pub name: WindowsSmbUserName,
    pub domain: String,
    pub principal: String,
}

pub trait WindowsSmbUserManager {
    fn create_user(
        &mut self,
        name: &WindowsSmbUserName,
        password: &WindowsSmbPassword,
    ) -> Result<WindowsSmbUserAccount, WindowsSmbLifecycleError>;

    fn delete_user(
        &mut self,
        account: &WindowsSmbUserAccount,
    ) -> Result<(), WindowsSmbLifecycleError>;
}

#[cfg(windows)]
#[derive(Default)]
pub struct NativeWindowsSmbUserManager;

#[cfg(windows)]
impl WindowsSmbUserManager for NativeWindowsSmbUserManager {
    fn create_user(
        &mut self,
        name: &WindowsSmbUserName,
        password: &WindowsSmbPassword,
    ) -> Result<WindowsSmbUserAccount, WindowsSmbLifecycleError> {
        use std::ptr;

        use windows_sys::Win32::NetworkManagement::NetManagement::{
            NetUserAdd, UF_DONT_EXPIRE_PASSWD, UF_NORMAL_ACCOUNT, UF_PASSWD_CANT_CHANGE, UF_SCRIPT,
            USER_INFO_1, USER_PRIV_USER,
        };

        validate_smb_user_name(name.as_str())?;
        let mut name_w = wide_null(name.as_str());
        let mut password_w = wide_null(password.expose_secret());
        let mut comment_w = wide_null("LocalSandbox temporary SMB mount user");
        let mut info = USER_INFO_1 {
            usri1_name: name_w.as_mut_ptr(),
            usri1_password: password_w.as_mut_ptr(),
            usri1_password_age: 0,
            usri1_priv: USER_PRIV_USER,
            usri1_home_dir: ptr::null_mut(),
            usri1_comment: comment_w.as_mut_ptr(),
            usri1_flags: UF_SCRIPT
                | UF_NORMAL_ACCOUNT
                | UF_DONT_EXPIRE_PASSWD
                | UF_PASSWD_CANT_CHANGE,
            usri1_script_path: ptr::null_mut(),
        };
        let mut parm_err = 0;
        let status = unsafe {
            NetUserAdd(
                ptr::null(),
                1,
                &mut info as *mut USER_INFO_1 as *const u8,
                &mut parm_err,
            )
        };
        zero_wide(&mut password_w);
        if status != 0 {
            return Err(WindowsSmbLifecycleError::operation_failed(
                WindowsSmbLifecyclePhase::UserCreate,
                format!("NetUserAdd failed with status {status} at parameter {parm_err}"),
            ));
        }

        let domain = local_computer_name()?;
        let principal = format!(r"{domain}\{}", name.as_str());
        Ok(WindowsSmbUserAccount {
            name: name.clone(),
            domain,
            principal,
        })
    }

    fn delete_user(
        &mut self,
        account: &WindowsSmbUserAccount,
    ) -> Result<(), WindowsSmbLifecycleError> {
        use std::ptr;

        use windows_sys::Win32::NetworkManagement::NetManagement::{NERR_UserNotFound, NetUserDel};

        let name_w = wide_null(account.name.as_str());
        let status = unsafe { NetUserDel(ptr::null(), name_w.as_ptr()) };
        if status != 0 && status != NERR_UserNotFound {
            return Err(WindowsSmbLifecycleError::operation_failed(
                WindowsSmbLifecyclePhase::UserDelete,
                format!("NetUserDel failed with status {status}"),
            ));
        }
        Ok(())
    }
}

#[cfg(windows)]
fn local_computer_name() -> Result<String, WindowsSmbLifecycleError> {
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::System::WindowsProgramming::GetComputerNameW;

    let mut len = 256u32;
    let mut buffer = vec![0u16; len as usize];
    let ok = unsafe { GetComputerNameW(buffer.as_mut_ptr(), &mut len) };
    if ok == 0 {
        let code = unsafe { GetLastError() };
        return Err(WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::ComputerName,
            format!("GetComputerNameW failed with win32 error {code}"),
        ));
    }
    buffer.truncate(len as usize);
    Ok(String::from_utf16_lossy(&buffer))
}

#[cfg(windows)]
pub(crate) fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
pub(crate) fn zero_wide(value: &mut [u16]) {
    value.fill(0);
}
