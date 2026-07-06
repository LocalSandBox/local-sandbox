use std::fmt;
use std::path::PathBuf;

use super::types::{
    validate_smb_share_name, WindowsSmbAccess, WindowsSmbLifecycleError, WindowsSmbLifecyclePhase,
};
use super::user::WindowsSmbUserAccount;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct WindowsSmbShareName(String);

impl WindowsSmbShareName {
    pub(crate) fn new_unchecked(name: String) -> Self {
        Self(name)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for WindowsSmbShareName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("WindowsSmbShareName").field(&self.0).finish()
    }
}

impl fmt::Display for WindowsSmbShareName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsSmbShareCreateRequest {
    pub name: WindowsSmbShareName,
    pub path: PathBuf,
    pub account: WindowsSmbUserAccount,
    pub access: WindowsSmbAccess,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsSmbShare {
    pub name: WindowsSmbShareName,
    pub path: PathBuf,
    pub principal: String,
    pub access: WindowsSmbAccess,
}

pub trait WindowsSmbShareManager {
    fn create_share(
        &mut self,
        request: WindowsSmbShareCreateRequest,
    ) -> Result<WindowsSmbShare, WindowsSmbLifecycleError>;

    fn remove_share(&mut self, share: &WindowsSmbShare) -> Result<(), WindowsSmbLifecycleError>;
}

#[cfg(windows)]
#[derive(Default)]
pub struct NativeWindowsSmbShareManager;

#[cfg(windows)]
impl WindowsSmbShareManager for NativeWindowsSmbShareManager {
    fn create_share(
        &mut self,
        request: WindowsSmbShareCreateRequest,
    ) -> Result<WindowsSmbShare, WindowsSmbLifecycleError> {
        use std::ptr;

        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::{
            BuildSecurityDescriptorW, EXPLICIT_ACCESS_W, GRANT_ACCESS, NO_MULTIPLE_TRUSTEE,
            TRUSTEE_IS_NAME, TRUSTEE_IS_USER, TRUSTEE_W,
        };
        use windows_sys::Win32::Storage::FileSystem::{
            NetShareAdd, SHARE_INFO_502, STYPE_DISKTREE,
        };

        validate_smb_share_name(request.name.as_str())?;

        let mut principal_w = super::user::wide_null(&request.account.principal);
        let trustee = TRUSTEE_W {
            pMultipleTrustee: ptr::null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_NAME,
            TrusteeType: TRUSTEE_IS_USER,
            ptstrName: principal_w.as_mut_ptr(),
        };
        let mut entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: share_access_mask(request.access),
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: 0,
            Trustee: trustee,
        };
        let mut sd_size = 0;
        let mut security_descriptor = ptr::null_mut();
        let status = unsafe {
            BuildSecurityDescriptorW(
                ptr::null(),
                ptr::null(),
                1,
                &mut entry,
                0,
                ptr::null(),
                ptr::null_mut(),
                &mut sd_size,
                &mut security_descriptor,
            )
        };
        if status != 0 {
            return Err(WindowsSmbLifecycleError::operation_failed(
                WindowsSmbLifecyclePhase::ShareCreate,
                format!("BuildSecurityDescriptorW failed with win32 error {status}"),
            ));
        }

        let mut name_w = super::user::wide_null(request.name.as_str());
        let mut path_w = super::user::wide_null(&request.path.display().to_string());
        let mut remark_w = super::user::wide_null("LocalSandbox temporary SMB mount");
        let mut info = SHARE_INFO_502 {
            shi502_netname: name_w.as_mut_ptr(),
            shi502_type: STYPE_DISKTREE,
            shi502_remark: remark_w.as_mut_ptr(),
            shi502_permissions: 0,
            shi502_max_uses: u32::MAX,
            shi502_current_uses: 0,
            shi502_path: path_w.as_mut_ptr(),
            shi502_passwd: ptr::null_mut(),
            shi502_reserved: 0,
            shi502_security_descriptor: security_descriptor,
        };
        let mut parm_err = 0;
        let status = unsafe {
            NetShareAdd(
                ptr::null(),
                502,
                &mut info as *mut SHARE_INFO_502 as *const u8,
                &mut parm_err,
            )
        };
        unsafe {
            LocalFree(security_descriptor);
        }
        if status != 0 {
            return Err(WindowsSmbLifecycleError::operation_failed(
                WindowsSmbLifecyclePhase::ShareCreate,
                format!("NetShareAdd failed with status {status} at parameter {parm_err}"),
            ));
        }

        Ok(WindowsSmbShare {
            name: request.name,
            path: request.path,
            principal: request.account.principal,
            access: request.access,
        })
    }

    fn remove_share(&mut self, share: &WindowsSmbShare) -> Result<(), WindowsSmbLifecycleError> {
        use std::ptr;

        use windows_sys::Win32::NetworkManagement::NetManagement::NERR_NetNameNotFound;
        use windows_sys::Win32::Storage::FileSystem::NetShareDel;

        let name_w = super::user::wide_null(share.name.as_str());
        let status = unsafe { NetShareDel(ptr::null(), name_w.as_ptr(), 0) };
        if status != 0 && status != NERR_NetNameNotFound {
            return Err(WindowsSmbLifecycleError::operation_failed(
                WindowsSmbLifecyclePhase::ShareRemove,
                format!("NetShareDel failed with status {status}"),
            ));
        }
        Ok(())
    }
}

#[cfg(windows)]
fn share_access_mask(access: WindowsSmbAccess) -> u32 {
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_DELETE_CHILD, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    };

    match access {
        WindowsSmbAccess::ReadOnly => FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
        WindowsSmbAccess::ReadWrite => {
            FILE_GENERIC_READ
                | FILE_GENERIC_EXECUTE
                | FILE_GENERIC_WRITE
                | FILE_DELETE_CHILD
                | DELETE
        }
    }
}
