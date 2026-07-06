use super::types::{WindowsSmbLifecycleError, WindowsSmbLifecyclePhase};

pub const WINDOWS_SMB_LOCAL_ACCOUNT_SID: &str = "S-1-5-113";
pub const WINDOWS_SMB_LOCAL_ADMIN_ACCOUNT_SID: &str = "S-1-5-114";
pub const WINDOWS_SMB_GUESTS_SID: &str = "S-1-5-32-546";

const WINDOWS_SMB_EVERYONE_SID: &str = "S-1-1-0";
const WINDOWS_SMB_AUTHENTICATED_USERS_SID: &str = "S-1-5-11";
const WINDOWS_SMB_BUILTIN_USERS_SID: &str = "S-1-5-32-545";
const SE_NETWORK_LOGON_RIGHT: &str = "SeNetworkLogonRight";
const SE_DENY_NETWORK_LOGON_RIGHT: &str = "SeDenyNetworkLogonRight";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsSmbPolicyPrincipal {
    pub sid: String,
    pub label: String,
}

impl WindowsSmbPolicyPrincipal {
    fn new(sid: impl Into<String>) -> Self {
        let sid = sid.into();
        let label = known_sid_label(&sid).unwrap_or(&sid).to_string();
        Self { sid, label }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsSmbPolicyDiagnosis {
    pub network_logon: Vec<WindowsSmbPolicyPrincipal>,
    pub deny_network_logon: Vec<WindowsSmbPolicyPrincipal>,
}

impl WindowsSmbPolicyDiagnosis {
    pub fn blocks_generated_smb_users(&self) -> bool {
        self.deny_network_logon
            .iter()
            .any(|principal| principal.sid == WINDOWS_SMB_LOCAL_ACCOUNT_SID)
    }

    pub fn risky_network_logon_principals(&self) -> Vec<&WindowsSmbPolicyPrincipal> {
        self.network_logon
            .iter()
            .filter(|principal| is_broad_network_logon_allow(&principal.sid))
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsSmbPolicyFixReport {
    pub before: WindowsSmbPolicyDiagnosis,
    pub after: WindowsSmbPolicyDiagnosis,
    pub changed: bool,
}

pub fn ensure_windows_smb_policy_allows_generated_users() -> Result<(), WindowsSmbLifecycleError> {
    let diagnosis = diagnose_windows_smb_policy()?;
    if !diagnosis.blocks_generated_smb_users() {
        return Ok(());
    }

    Err(WindowsSmbLifecycleError::operation_failed(
        WindowsSmbLifecyclePhase::SmbPolicyPreflight,
        "Windows direct SMB mounts are blocked by local security policy: \
         'Deny access to this computer from the network' contains \
         NT AUTHORITY\\Local account (S-1-5-113). Run \
         'lsb doctor windows-smb-policy --fix' from an elevated PowerShell \
         to replace that broad deny with the narrower local-Administrator-account deny.",
    ))
}

#[cfg(windows)]
pub fn diagnose_windows_smb_policy() -> Result<WindowsSmbPolicyDiagnosis, WindowsSmbLifecycleError>
{
    Ok(WindowsSmbPolicyDiagnosis {
        network_logon: enumerate_user_right(SE_NETWORK_LOGON_RIGHT)?,
        deny_network_logon: enumerate_user_right(SE_DENY_NETWORK_LOGON_RIGHT)?,
    })
}

#[cfg(not(windows))]
pub fn diagnose_windows_smb_policy() -> Result<WindowsSmbPolicyDiagnosis, WindowsSmbLifecycleError>
{
    Err(WindowsSmbLifecycleError::operation_failed(
        WindowsSmbLifecyclePhase::SmbPolicyPreflight,
        "Windows SMB policy diagnosis is only available on Windows hosts",
    ))
}

#[cfg(windows)]
pub fn fix_windows_smb_policy() -> Result<WindowsSmbPolicyFixReport, WindowsSmbLifecycleError> {
    let before = diagnose_windows_smb_policy()?;
    if !before.blocks_generated_smb_users() {
        return Ok(WindowsSmbPolicyFixReport {
            before: before.clone(),
            after: before,
            changed: false,
        });
    }

    let risky = before.risky_network_logon_principals();
    if !risky.is_empty() {
        let principals = risky
            .iter()
            .map(|principal| format!("{} ({})", principal.label, principal.sid))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::SmbPolicyPreflight,
            format!(
                "automatic SMB policy fix refused because SeNetworkLogonRight includes broad \
                 principal(s): {principals}. Remove or narrow those allow entries before retrying."
            ),
        ));
    }

    update_account_right_for_sid(
        WINDOWS_SMB_LOCAL_ADMIN_ACCOUNT_SID,
        SE_DENY_NETWORK_LOGON_RIGHT,
        true,
    )?;
    update_account_right_for_sid(
        WINDOWS_SMB_LOCAL_ACCOUNT_SID,
        SE_DENY_NETWORK_LOGON_RIGHT,
        false,
    )?;

    let after = diagnose_windows_smb_policy()?;
    if after.blocks_generated_smb_users() {
        return Err(WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::SmbPolicyPreflight,
            "automatic SMB policy fix did not remove NT AUTHORITY\\Local account from \
             SeDenyNetworkLogonRight",
        ));
    }

    Ok(WindowsSmbPolicyFixReport {
        before,
        after,
        changed: true,
    })
}

#[cfg(not(windows))]
pub fn fix_windows_smb_policy() -> Result<WindowsSmbPolicyFixReport, WindowsSmbLifecycleError> {
    Err(WindowsSmbLifecycleError::operation_failed(
        WindowsSmbLifecyclePhase::SmbPolicyPreflight,
        "Windows SMB policy fix is only available on Windows hosts",
    ))
}

fn known_sid_label(sid: &str) -> Option<&'static str> {
    match sid {
        WINDOWS_SMB_EVERYONE_SID => Some("Everyone"),
        WINDOWS_SMB_AUTHENTICATED_USERS_SID => Some("NT AUTHORITY\\Authenticated Users"),
        WINDOWS_SMB_LOCAL_ACCOUNT_SID => Some("NT AUTHORITY\\Local account"),
        WINDOWS_SMB_LOCAL_ADMIN_ACCOUNT_SID => {
            Some("NT AUTHORITY\\Local account and member of Administrators group")
        }
        WINDOWS_SMB_BUILTIN_USERS_SID => Some("BUILTIN\\Users"),
        "S-1-5-32-544" => Some("BUILTIN\\Administrators"),
        WINDOWS_SMB_GUESTS_SID => Some("BUILTIN\\Guests"),
        "S-1-5-32-555" => Some("BUILTIN\\Remote Desktop Users"),
        _ => None,
    }
}

fn is_broad_network_logon_allow(sid: &str) -> bool {
    matches!(
        sid,
        WINDOWS_SMB_EVERYONE_SID
            | WINDOWS_SMB_AUTHENTICATED_USERS_SID
            | WINDOWS_SMB_BUILTIN_USERS_SID
    )
}

#[cfg(windows)]
pub(crate) fn grant_network_logon_right(principal: &str) -> Result<(), WindowsSmbLifecycleError> {
    update_named_account_right(
        principal,
        SE_NETWORK_LOGON_RIGHT,
        true,
        WindowsSmbLifecyclePhase::UserNetworkLogonGrant,
    )
}

#[cfg(windows)]
pub(crate) fn revoke_network_logon_right(principal: &str) -> Result<(), WindowsSmbLifecycleError> {
    update_named_account_right(
        principal,
        SE_NETWORK_LOGON_RIGHT,
        false,
        WindowsSmbLifecyclePhase::UserNetworkLogonRevoke,
    )
}

#[cfg(windows)]
fn update_named_account_right(
    principal: &str,
    right_name: &str,
    grant: bool,
    phase: WindowsSmbLifecyclePhase,
) -> Result<(), WindowsSmbLifecycleError> {
    let Some(mut sid) = lookup_account_sid(principal, phase)? else {
        return Ok(());
    };
    update_account_right(sid.as_mut_ptr().cast(), right_name, grant, phase)
}

#[cfg(windows)]
fn update_account_right_for_sid(
    sid: &str,
    right_name: &str,
    grant: bool,
) -> Result<(), WindowsSmbLifecycleError> {
    let sid = sid_from_string(sid)?;
    update_account_right(
        sid.0,
        right_name,
        grant,
        WindowsSmbLifecyclePhase::SmbPolicyPreflight,
    )
}

#[cfg(windows)]
fn update_account_right(
    sid: windows_sys::Win32::Security::PSID,
    right_name_text: &str,
    grant: bool,
    phase: WindowsSmbLifecyclePhase,
) -> Result<(), WindowsSmbLifecycleError> {
    use windows_sys::Win32::Foundation::{STATUS_NO_MORE_ENTRIES, STATUS_OBJECT_NAME_NOT_FOUND};
    use windows_sys::Win32::Security::Authentication::Identity::{
        LsaAddAccountRights, LsaClose, LsaNtStatusToWinError, LsaRemoveAccountRights,
        LSA_UNICODE_STRING, POLICY_CREATE_ACCOUNT, POLICY_LOOKUP_NAMES,
    };

    let policy = open_lsa_policy((POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT) as u32, phase)?;
    let mut right_name_w = wide_null(right_name_text);
    let right_name = LSA_UNICODE_STRING {
        Length: ((right_name_w.len() - 1) * 2) as u16,
        MaximumLength: (right_name_w.len() * 2) as u16,
        Buffer: right_name_w.as_mut_ptr(),
    };
    let status = if grant {
        unsafe { LsaAddAccountRights(policy, sid, &right_name, 1) }
    } else {
        unsafe { LsaRemoveAccountRights(policy, sid, false, &right_name, 1) }
    };
    let close_status = unsafe { LsaClose(policy) };

    if !grant
        && matches!(
            status,
            STATUS_NO_MORE_ENTRIES | STATUS_OBJECT_NAME_NOT_FOUND
        )
    {
        return Ok(());
    }
    if status != 0 {
        let code = unsafe { LsaNtStatusToWinError(status) };
        return Err(WindowsSmbLifecycleError::operation_failed(
            phase,
            format!(
                "{} {right_name_text} failed with win32 error {code}",
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
fn enumerate_user_right(
    right_name_text: &str,
) -> Result<Vec<WindowsSmbPolicyPrincipal>, WindowsSmbLifecycleError> {
    use std::ffi::c_void;
    use std::ptr;
    use std::slice;

    use windows_sys::Win32::Foundation::{STATUS_NO_MORE_ENTRIES, STATUS_OBJECT_NAME_NOT_FOUND};
    use windows_sys::Win32::Security::Authentication::Identity::{
        LsaClose, LsaEnumerateAccountsWithUserRight, LsaFreeMemory, LsaNtStatusToWinError,
        LSA_ENUMERATION_INFORMATION, LSA_UNICODE_STRING, POLICY_LOOKUP_NAMES,
        POLICY_VIEW_LOCAL_INFORMATION,
    };

    let phase = WindowsSmbLifecyclePhase::SmbPolicyPreflight;
    let policy = open_lsa_policy(
        (POLICY_VIEW_LOCAL_INFORMATION | POLICY_LOOKUP_NAMES) as u32,
        phase,
    )?;
    let mut right_name_w = wide_null(right_name_text);
    let right_name = LSA_UNICODE_STRING {
        Length: ((right_name_w.len() - 1) * 2) as u16,
        MaximumLength: (right_name_w.len() * 2) as u16,
        Buffer: right_name_w.as_mut_ptr(),
    };
    let mut buffer: *mut c_void = ptr::null_mut();
    let mut count = 0;
    let status =
        unsafe { LsaEnumerateAccountsWithUserRight(policy, &right_name, &mut buffer, &mut count) };
    let close_status = unsafe { LsaClose(policy) };

    if matches!(
        status,
        STATUS_NO_MORE_ENTRIES | STATUS_OBJECT_NAME_NOT_FOUND
    ) {
        return Ok(Vec::new());
    }
    if status != 0 {
        let code = unsafe { LsaNtStatusToWinError(status) };
        return Err(WindowsSmbLifecycleError::operation_failed(
            phase,
            format!("enumerating {right_name_text} failed with win32 error {code}"),
        ));
    }

    let entries = unsafe {
        slice::from_raw_parts(buffer.cast::<LSA_ENUMERATION_INFORMATION>(), count as usize)
    };
    let mut principals = Vec::with_capacity(entries.len());
    for entry in entries {
        principals.push(WindowsSmbPolicyPrincipal::new(sid_to_string(entry.Sid)?));
    }
    let free_status = unsafe { LsaFreeMemory(buffer) };

    if free_status != 0 {
        let code = unsafe { LsaNtStatusToWinError(free_status) };
        return Err(WindowsSmbLifecycleError::operation_failed(
            phase,
            format!("freeing LSA enumeration buffer failed with win32 error {code}"),
        ));
    }
    if close_status != 0 {
        let code = unsafe { LsaNtStatusToWinError(close_status) };
        return Err(WindowsSmbLifecycleError::operation_failed(
            phase,
            format!("closing LSA policy handle failed with win32 error {code}"),
        ));
    }

    principals.sort_by(|left, right| left.sid.cmp(&right.sid));
    Ok(principals)
}

#[cfg(windows)]
fn open_lsa_policy(
    desired_access: u32,
    phase: WindowsSmbLifecyclePhase,
) -> Result<
    windows_sys::Win32::Security::Authentication::Identity::LSA_HANDLE,
    WindowsSmbLifecycleError,
> {
    use std::mem;
    use std::ptr;

    use windows_sys::Win32::Security::Authentication::Identity::{
        LsaNtStatusToWinError, LsaOpenPolicy, LSA_HANDLE, LSA_OBJECT_ATTRIBUTES,
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
    let status = unsafe { LsaOpenPolicy(ptr::null(), &mut attrs, desired_access, &mut policy) };
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
struct LocalSid(windows_sys::Win32::Security::PSID);

#[cfg(windows)]
impl Drop for LocalSid {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::LocalFree;

        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0.cast());
            }
        }
    }
}

#[cfg(windows)]
fn sid_from_string(sid: &str) -> Result<LocalSid, WindowsSmbLifecycleError> {
    use std::ptr;

    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;

    let sid_w = wide_null(sid);
    let mut parsed = ptr::null_mut();
    let ok = unsafe { ConvertStringSidToSidW(sid_w.as_ptr(), &mut parsed) };
    if ok == 0 {
        let code = unsafe { GetLastError() };
        return Err(WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::SmbPolicyPreflight,
            format!("ConvertStringSidToSidW failed for {sid}: win32 error {code}"),
        ));
    }
    Ok(LocalSid(parsed))
}

#[cfg(windows)]
fn sid_to_string(
    sid: windows_sys::Win32::Security::PSID,
) -> Result<String, WindowsSmbLifecycleError> {
    use std::ptr;
    use std::slice;

    use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;

    let mut string_sid = ptr::null_mut();
    let ok = unsafe { ConvertSidToStringSidW(sid, &mut string_sid) };
    if ok == 0 {
        let code = unsafe { GetLastError() };
        return Err(WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::SmbPolicyPreflight,
            format!("ConvertSidToStringSidW failed with win32 error {code}"),
        ));
    }

    let mut len = 0usize;
    while unsafe { *string_sid.add(len) } != 0 {
        len += 1;
    }
    let value = String::from_utf16_lossy(unsafe { slice::from_raw_parts(string_sid, len) });
    unsafe {
        LocalFree(string_sid.cast());
    }
    Ok(value)
}

#[cfg(windows)]
fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnosis_detects_local_account_deny() {
        let diagnosis = WindowsSmbPolicyDiagnosis {
            network_logon: vec![WindowsSmbPolicyPrincipal::new("S-1-5-32-544")],
            deny_network_logon: vec![
                WindowsSmbPolicyPrincipal::new(WINDOWS_SMB_GUESTS_SID),
                WindowsSmbPolicyPrincipal::new(WINDOWS_SMB_LOCAL_ACCOUNT_SID),
            ],
        };

        assert!(diagnosis.blocks_generated_smb_users());
    }

    #[test]
    fn diagnosis_flags_broad_network_logon_allows() {
        let diagnosis = WindowsSmbPolicyDiagnosis {
            network_logon: vec![
                WindowsSmbPolicyPrincipal::new("S-1-5-32-544"),
                WindowsSmbPolicyPrincipal::new(WINDOWS_SMB_BUILTIN_USERS_SID),
            ],
            deny_network_logon: vec![WindowsSmbPolicyPrincipal::new(
                WINDOWS_SMB_LOCAL_ACCOUNT_SID,
            )],
        };

        let risky = diagnosis.risky_network_logon_principals();
        assert_eq!(risky.len(), 1);
        assert_eq!(risky[0].sid, WINDOWS_SMB_BUILTIN_USERS_SID);
    }
}
