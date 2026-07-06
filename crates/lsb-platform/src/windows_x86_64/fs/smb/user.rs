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

        let domain = match local_computer_name() {
            Ok(domain) => domain,
            Err(error) => {
                let _ = delete_local_user(name);
                return Err(error);
            }
        };
        let principal = format!(r"{domain}\{}", name.as_str());
        if let Err(error) = add_user_to_builtin_users_group(&principal) {
            let _ = delete_local_user(name);
            return Err(error);
        }
        if let Err(error) = grant_network_logon_right(&principal) {
            let _ = delete_local_user(name);
            return Err(error);
        }
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
        let revoke_result = revoke_network_logon_right(&account.principal);
        let delete_result = delete_local_user(&account.name);
        match (revoke_result, delete_result) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) => Err(error),
            (_, Err(error)) => Err(error),
        }
    }
}

#[cfg(windows)]
fn add_user_to_builtin_users_group(principal: &str) -> Result<(), WindowsSmbLifecycleError> {
    use std::ptr;

    use windows_sys::Win32::Foundation::ERROR_MEMBER_IN_ALIAS;
    use windows_sys::Win32::NetworkManagement::NetManagement::{
        NERR_UserInGroup, NetLocalGroupAddMembers, LOCALGROUP_MEMBERS_INFO_3,
    };

    let group_name = builtin_users_group_name()?;
    let group_name_w = wide_null(&group_name);
    let mut principal_w = wide_null(principal);
    let mut member = LOCALGROUP_MEMBERS_INFO_3 {
        lgrmi3_domainandname: principal_w.as_mut_ptr(),
    };
    let status = unsafe {
        NetLocalGroupAddMembers(
            ptr::null(),
            group_name_w.as_ptr(),
            3,
            &mut member as *mut LOCALGROUP_MEMBERS_INFO_3 as *const u8,
            1,
        )
    };
    if status != 0 && status != NERR_UserInGroup && status != ERROR_MEMBER_IN_ALIAS {
        return Err(WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::UserGroupAdd,
            format!(
                "NetLocalGroupAddMembers failed with status {status} for local group {group_name}"
            ),
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn builtin_users_group_name() -> Result<String, WindowsSmbLifecycleError> {
    use std::ptr;

    use windows_sys::Win32::Foundation::{GetLastError, ERROR_INSUFFICIENT_BUFFER};
    use windows_sys::Win32::Security::{
        CreateWellKnownSid, LookupAccountSidW, SidTypeAlias, SidTypeWellKnownGroup,
        WinBuiltinUsersSid, SECURITY_MAX_SID_SIZE, SID_NAME_USE,
    };

    let mut sid_len = SECURITY_MAX_SID_SIZE;
    let mut sid = vec![0u8; sid_len as usize];
    let created = unsafe {
        CreateWellKnownSid(
            WinBuiltinUsersSid,
            ptr::null_mut(),
            sid.as_mut_ptr().cast(),
            &mut sid_len,
        )
    };
    if created == 0 {
        let code = unsafe { GetLastError() };
        return Err(WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::UserGroupAdd,
            format!("CreateWellKnownSid(WinBuiltinUsersSid) failed with win32 error {code}"),
        ));
    }

    let mut name_len = 0;
    let mut domain_len = 0;
    let mut sid_use: SID_NAME_USE = 0;
    let sized = unsafe {
        LookupAccountSidW(
            ptr::null(),
            sid.as_mut_ptr().cast(),
            ptr::null_mut(),
            &mut name_len,
            ptr::null_mut(),
            &mut domain_len,
            &mut sid_use,
        )
    };
    if sized != 0 {
        return Err(WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::UserGroupAdd,
            "LookupAccountSidW unexpectedly succeeded without buffers",
        ));
    }
    let code = unsafe { GetLastError() };
    if code != ERROR_INSUFFICIENT_BUFFER {
        return Err(WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::UserGroupAdd,
            format!("LookupAccountSidW failed to size builtin Users alias: win32 error {code}"),
        ));
    }

    let mut name = vec![0u16; name_len as usize];
    let mut domain = vec![0u16; domain_len as usize];
    let looked_up = unsafe {
        LookupAccountSidW(
            ptr::null(),
            sid.as_mut_ptr().cast(),
            name.as_mut_ptr(),
            &mut name_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut sid_use,
        )
    };
    if looked_up == 0 {
        let code = unsafe { GetLastError() };
        return Err(WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::UserGroupAdd,
            format!("LookupAccountSidW failed for builtin Users alias: win32 error {code}"),
        ));
    }
    if sid_use != SidTypeAlias && sid_use != SidTypeWellKnownGroup {
        return Err(WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::UserGroupAdd,
            format!("builtin Users SID resolved to unexpected account type {sid_use}"),
        ));
    }

    name.truncate(name_len as usize);
    while name.last() == Some(&0) {
        name.pop();
    }
    if name.is_empty() {
        return Err(WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::UserGroupAdd,
            "builtin Users alias resolved to an empty name",
        ));
    }
    Ok(String::from_utf16_lossy(&name))
}

#[cfg(windows)]
fn grant_network_logon_right(principal: &str) -> Result<(), WindowsSmbLifecycleError> {
    update_network_logon_right(principal, true)
}

#[cfg(windows)]
fn revoke_network_logon_right(principal: &str) -> Result<(), WindowsSmbLifecycleError> {
    update_network_logon_right(principal, false)
}

#[cfg(windows)]
fn update_network_logon_right(
    principal: &str,
    grant: bool,
) -> Result<(), WindowsSmbLifecycleError> {
    use windows_sys::Win32::Security::Authentication::Identity::{
        LsaAddAccountRights, LsaClose, LsaNtStatusToWinError, LsaRemoveAccountRights,
        LSA_UNICODE_STRING,
    };

    let phase = if grant {
        WindowsSmbLifecyclePhase::UserNetworkLogonGrant
    } else {
        WindowsSmbLifecyclePhase::UserNetworkLogonRevoke
    };
    let Some(mut sid) = lookup_account_sid(principal, phase)? else {
        return Ok(());
    };
    let policy = open_lsa_policy(phase)?;
    let mut right_name_w = wide_null("SeNetworkLogonRight");
    let right_name = LSA_UNICODE_STRING {
        Length: ((right_name_w.len() - 1) * 2) as u16,
        MaximumLength: (right_name_w.len() * 2) as u16,
        Buffer: right_name_w.as_mut_ptr(),
    };
    let status = if grant {
        unsafe { LsaAddAccountRights(policy, sid.as_mut_ptr().cast(), &right_name, 1) }
    } else {
        unsafe { LsaRemoveAccountRights(policy, sid.as_mut_ptr().cast(), false, &right_name, 1) }
    };
    let close_status = unsafe { LsaClose(policy) };
    if status != 0 {
        let code = unsafe { LsaNtStatusToWinError(status) };
        return Err(WindowsSmbLifecycleError::operation_failed(
            phase,
            format!(
                "{} SeNetworkLogonRight failed with win32 error {code}",
                if grant { "granting" } else { "revoking" }
            ),
        ));
    }
    if close_status != 0 {
        let code = unsafe { LsaNtStatusToWinError(close_status) };
        return Err(WindowsSmbLifecycleError::operation_failed(
            phase,
            format!("closing LSA policy handle failed with win32 error {code}"),
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn open_lsa_policy(
    phase: WindowsSmbLifecyclePhase,
) -> Result<
    windows_sys::Win32::Security::Authentication::Identity::LSA_HANDLE,
    WindowsSmbLifecycleError,
> {
    use std::mem;
    use std::ptr;

    use windows_sys::Win32::Security::Authentication::Identity::{
        LsaNtStatusToWinError, LsaOpenPolicy, LSA_HANDLE, LSA_OBJECT_ATTRIBUTES,
        POLICY_CREATE_ACCOUNT, POLICY_LOOKUP_NAMES,
    };

    let mut attrs = LSA_OBJECT_ATTRIBUTES {
        Length: mem::size_of::<LSA_OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: ptr::null_mut(),
        ObjectName: ptr::null_mut(),
        Attributes: 0,
        SecurityDescriptor: ptr::null_mut(),
        SecurityQualityOfService: ptr::null_mut(),
    };
    let mut policy: LSA_HANDLE = 0;
    let status = unsafe {
        LsaOpenPolicy(
            ptr::null(),
            &mut attrs,
            (POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT) as u32,
            &mut policy,
        )
    };
    if status != 0 {
        let code = unsafe { LsaNtStatusToWinError(status) };
        return Err(WindowsSmbLifecycleError::operation_failed(
            phase,
            format!("LsaOpenPolicy failed with win32 error {code}"),
        ));
    }
    Ok(policy)
}

#[cfg(windows)]
fn lookup_account_sid(
    principal: &str,
    phase: WindowsSmbLifecyclePhase,
) -> Result<Option<Vec<u8>>, WindowsSmbLifecycleError> {
    use std::ptr;

    use windows_sys::Win32::Foundation::{
        GetLastError, ERROR_INSUFFICIENT_BUFFER, ERROR_NONE_MAPPED,
    };
    use windows_sys::Win32::Security::{LookupAccountNameW, SidTypeUser, SID_NAME_USE};

    let principal_w = wide_null(principal);
    let mut sid_len = 0;
    let mut domain_len = 0;
    let mut sid_use: SID_NAME_USE = 0;
    let sized = unsafe {
        LookupAccountNameW(
            ptr::null(),
            principal_w.as_ptr(),
            ptr::null_mut(),
            &mut sid_len,
            ptr::null_mut(),
            &mut domain_len,
            &mut sid_use,
        )
    };
    if sized != 0 {
        return Err(WindowsSmbLifecycleError::operation_failed(
            phase,
            "LookupAccountNameW unexpectedly succeeded without buffers",
        ));
    }
    let code = unsafe { GetLastError() };
    if code == ERROR_NONE_MAPPED {
        return Ok(None);
    }
    if code != ERROR_INSUFFICIENT_BUFFER {
        return Err(WindowsSmbLifecycleError::operation_failed(
            phase,
            format!("LookupAccountNameW failed to size account SID: win32 error {code}"),
        ));
    }

    let mut sid = vec![0u8; sid_len as usize];
    let mut domain = vec![0u16; domain_len as usize];
    let looked_up = unsafe {
        LookupAccountNameW(
            ptr::null(),
            principal_w.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut sid_use,
        )
    };
    if looked_up == 0 {
        let code = unsafe { GetLastError() };
        if code == ERROR_NONE_MAPPED {
            return Ok(None);
        }
        return Err(WindowsSmbLifecycleError::operation_failed(
            phase,
            format!("LookupAccountNameW failed for account SID: win32 error {code}"),
        ));
    }
    if sid_use != SidTypeUser {
        return Err(WindowsSmbLifecycleError::operation_failed(
            phase,
            format!("account resolved to unexpected SID type {sid_use}"),
        ));
    }
    sid.truncate(sid_len as usize);
    Ok(Some(sid))
}

#[cfg(windows)]
fn delete_local_user(name: &WindowsSmbUserName) -> Result<(), WindowsSmbLifecycleError> {
    use std::ptr;

    use windows_sys::Win32::NetworkManagement::NetManagement::{NERR_UserNotFound, NetUserDel};

    let name_w = wide_null(name.as_str());
    let status = unsafe { NetUserDel(ptr::null(), name_w.as_ptr()) };
    if status != 0 && status != NERR_UserNotFound {
        return Err(WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::UserDelete,
            format!("NetUserDel failed with status {status}"),
        ));
    }
    Ok(())
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
