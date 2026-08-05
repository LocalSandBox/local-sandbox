use std::path::PathBuf;

use super::types::{WindowsSmbAccess, WindowsSmbLifecycleError, WindowsSmbLifecyclePhase};
use super::user::WindowsSmbUserAccount;
use super::WindowsSmbPassword;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsSmbAclGrantRequest {
    pub path: PathBuf,
    pub account: WindowsSmbUserAccount,
    pub access: WindowsSmbAccess,
    pub prune_subtrees: Vec<String>,
    /// Maximum number of non-pruned entries this mount may contribute to the
    /// lifecycle-wide ACL inspection budget.
    pub entry_limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsSmbAclPlanEntry {
    pub path: PathBuf,
    pub is_dir: bool,
}

/// A recoverable ACL operation. New grants place one inheritable ACE on `path`.
/// `descendant_aces` remains journaled for cleanup of manifests produced by the
/// legacy per-entry grant implementation. Ancestor traverse grants are tracked
/// separately because they are outside the mount tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsSmbAclGrant {
    pub path: PathBuf,
    /// Ancestors that receive a non-inheriting traverse-only ACE for the
    /// generated SID. Stored explicitly so crash recovery can remove them.
    pub traverse_paths: Vec<PathBuf>,
    /// Case-insensitive subtree basenames skipped during budget inspection and
    /// legacy descendant cleanup.
    pub prune_subtrees: Vec<String>,
    pub principal: String,
    pub sid: String,
    pub access: WindowsSmbAccess,
    pub original_dacl_control: Option<u16>,
    /// Number of non-pruned entries inspected before this grant was accepted.
    pub inspected_entries: usize,
    /// Whether cleanup must sweep descendants for legacy explicit ACEs.
    pub descendant_aces: bool,
}

pub trait WindowsSmbAclManager {
    fn prepare_grant(
        &mut self,
        request: &WindowsSmbAclGrantRequest,
    ) -> Result<WindowsSmbAclGrant, WindowsSmbLifecycleError> {
        Ok(WindowsSmbAclGrant {
            path: request.path.clone(),
            traverse_paths: Vec::new(),
            prune_subtrees: request.prune_subtrees.clone(),
            principal: request.account.principal.clone(),
            sid: request.account.sid.clone(),
            access: request.access,
            original_dacl_control: None,
            inspected_entries: 1,
            descendant_aces: false,
        })
    }

    fn grant_access(
        &mut self,
        grant: WindowsSmbAclGrant,
    ) -> Result<WindowsSmbAclGrant, WindowsSmbLifecycleError>;

    fn revoke_access(&mut self, grant: &WindowsSmbAclGrant)
        -> Result<(), WindowsSmbLifecycleError>;

    fn verify_access(
        &mut self,
        _account: &WindowsSmbUserAccount,
        _password: &WindowsSmbPassword,
        _grants: &[WindowsSmbAclGrant],
    ) -> Result<(), WindowsSmbLifecycleError> {
        Ok(())
    }
}

pub(crate) const MAX_ACL_AGGREGATE_ENTRIES: usize = 10_000;
#[cfg(windows)]
const MAX_LEGACY_ACL_CLEANUP_ENTRIES: usize = 100_000;
#[cfg(windows)]
const MAX_WINDOWS_PATH_UNITS: usize = 32_767;

#[cfg(windows)]
#[derive(Default)]
pub struct NativeWindowsSmbAclManager;

#[cfg(windows)]
impl WindowsSmbAclManager for NativeWindowsSmbAclManager {
    fn prepare_grant(
        &mut self,
        request: &WindowsSmbAclGrantRequest,
    ) -> Result<WindowsSmbAclGrant, WindowsSmbLifecycleError> {
        let inspected_entries = inspect_tree(
            &request.path,
            &request.prune_subtrees,
            request.entry_limit,
            WindowsSmbLifecyclePhase::AclGrant,
        )?;
        Ok(WindowsSmbAclGrant {
            path: request.path.clone(),
            traverse_paths: request
                .path
                .ancestors()
                .skip(1)
                .map(std::path::Path::to_path_buf)
                .collect(),
            prune_subtrees: request.prune_subtrees.clone(),
            principal: request.account.principal.clone(),
            sid: request.account.sid.clone(),
            access: request.access,
            original_dacl_control: Some(security_descriptor_control(&request.path)?),
            inspected_entries,
            descendant_aces: false,
        })
    }

    fn grant_access(
        &mut self,
        grant: WindowsSmbAclGrant,
    ) -> Result<WindowsSmbAclGrant, WindowsSmbLifecycleError> {
        for path in grant.traverse_paths.iter().rev() {
            apply_traverse_acl_change(
                path,
                &grant.sid,
                windows_sys::Win32::Security::Authorization::GRANT_ACCESS,
                WindowsSmbLifecyclePhase::AclGrant,
            )?;
        }
        apply_acl_change(
            &grant.path,
            &grant.sid,
            grant.access,
            windows_sys::Win32::Security::Authorization::GRANT_ACCESS,
            true,
            WindowsSmbLifecyclePhase::AclGrant,
        )?;
        Ok(grant)
    }

    fn revoke_access(
        &mut self,
        grant: &WindowsSmbAclGrant,
    ) -> Result<(), WindowsSmbLifecycleError> {
        let mut failures = Vec::new();

        // Remove the root ACE before walking the mutable tree. This immediately
        // withdraws inherited access even when a descendant later disappears or
        // cannot be inspected during the best-effort sweep.
        revoke_acl_entry_best_effort(
            &grant.path,
            &grant.sid,
            grant.access,
            true,
            true,
            &mut failures,
        );

        if grant.descendant_aces {
            let (entries, enumeration_failures) =
                enumerate_tree_for_cleanup(&grant.path, &grant.prune_subtrees);
            failures.extend(enumeration_failures);
            for entry in entries.iter().rev() {
                revoke_acl_entry_best_effort(
                    &entry.path,
                    &grant.sid,
                    grant.access,
                    entry.is_dir,
                    false,
                    &mut failures,
                );
            }
        }
        for path in &grant.traverse_paths {
            revoke_traverse_acl_best_effort(path, &grant.sid, &mut failures);
        }
        if let Some(control) = grant.original_dacl_control {
            if !path_is_absent(&grant.path) {
                if let Err(error) = restore_security_descriptor_control(&grant.path, control) {
                    if !path_is_absent(&grant.path) {
                        failures.push(cleanup_error_at(&grant.path, error));
                    }
                }
            }
        }

        if let Some(first) = failures.first() {
            let path = first.operation_path().unwrap_or(&grant.path).to_path_buf();
            return Err(WindowsSmbLifecycleError::operation_failed_at(
                WindowsSmbLifecyclePhase::AclRevoke,
                path,
                format!(
                    "{} ACL cleanup operation(s) failed; first failure: {first}",
                    failures.len()
                ),
            ));
        }
        Ok(())
    }

    fn verify_access(
        &mut self,
        account: &WindowsSmbUserAccount,
        password: &WindowsSmbPassword,
        grants: &[WindowsSmbAclGrant],
    ) -> Result<(), WindowsSmbLifecycleError> {
        verify_mount_roots_as_account(account, password, grants)
    }
}

#[cfg(windows)]
fn verify_mount_roots_as_account(
    account: &WindowsSmbUserAccount,
    password: &WindowsSmbPassword,
    grants: &[WindowsSmbAclGrant],
) -> Result<(), WindowsSmbLifecycleError> {
    use std::ptr;
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
    use windows_sys::Win32::Security::{
        ImpersonateLoggedOnUser, LogonUserW, RevertToSelf, LOGON32_LOGON_NETWORK,
        LOGON32_PROVIDER_DEFAULT,
    };

    let username = super::user::wide_null(account.name.as_str());
    let domain = super::user::wide_null(&account.domain);
    let mut password_w = super::user::wide_null(password.expose_secret());
    let mut token: HANDLE = ptr::null_mut();
    let logged_on = unsafe {
        LogonUserW(
            username.as_ptr(),
            domain.as_ptr(),
            password_w.as_ptr(),
            LOGON32_LOGON_NETWORK,
            LOGON32_PROVIDER_DEFAULT,
            &mut token,
        )
    };
    super::user::zero_wide(&mut password_w);
    if logged_on == 0 {
        let code = unsafe { GetLastError() };
        return Err(WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::AclGrant,
            format!("LogonUserW access verification failed with win32 error {code}"),
        ));
    }
    if unsafe { ImpersonateLoggedOnUser(token) } == 0 {
        let code = unsafe { GetLastError() };
        unsafe {
            CloseHandle(token);
        }
        return Err(WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::AclGrant,
            format!("ImpersonateLoggedOnUser failed with win32 error {code}"),
        ));
    }

    let result = (|| {
        for grant in grants {
            verify_path_open(&grant.path, true, grant.access)?;
        }
        Ok(())
    })();
    let reverted = unsafe { RevertToSelf() };
    unsafe {
        CloseHandle(token);
    }
    if reverted == 0 {
        return Err(WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::AclGrant,
            "RevertToSelf failed after access verification",
        ));
    }
    result
}

#[cfg(windows)]
fn verify_path_open(
    path: &std::path::Path,
    is_dir: bool,
    access: WindowsSmbAccess,
) -> Result<(), WindowsSmbLifecycleError> {
    use windows_sys::Win32::Foundation::{
        CloseHandle, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, DELETE, FILE_DELETE_CHILD, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        OPEN_EXISTING,
    };

    let path_w = super::user::wide_null(&path.display().to_string());
    let desired = GENERIC_READ
        | GENERIC_EXECUTE
        | if access == WindowsSmbAccess::ReadWrite {
            GENERIC_WRITE | DELETE | if is_dir { FILE_DELETE_CHILD } else { 0 }
        } else {
            0
        };
    let handle = unsafe {
        CreateFileW(
            path_w.as_ptr(),
            desired,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT
                | if is_dir {
                    FILE_FLAG_BACKUP_SEMANTICS
                } else {
                    0
                },
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::AclGrant,
            format!(
                "generated SID lacks effective access on '{}': {}",
                path.display(),
                std::io::Error::last_os_error()
            ),
        ));
    }
    unsafe {
        CloseHandle(handle);
    }
    Ok(())
}

#[cfg(windows)]
fn security_descriptor_control(path: &std::path::Path) -> Result<u16, WindowsSmbLifecycleError> {
    use std::ptr;
    use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
    use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{GetSecurityDescriptorControl, DACL_SECURITY_INFORMATION};

    let mut path_w = super::user::wide_null(&path.display().to_string());
    let mut descriptor = ptr::null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            path_w.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::AclGrant,
            format!("failed to read DACL control with win32 error {status}"),
        ));
    }
    let mut control = 0;
    let mut revision = 0;
    let ok = unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) };
    unsafe {
        LocalFree(descriptor);
    }
    if ok == 0 {
        let code = unsafe { GetLastError() };
        return Err(WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::AclGrant,
            format!("GetSecurityDescriptorControl failed with win32 error {code}"),
        ));
    }
    Ok(control)
}

#[cfg(windows)]
fn restore_security_descriptor_control(
    path: &std::path::Path,
    original: u16,
) -> Result<(), WindowsSmbLifecycleError> {
    use std::ptr;
    use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
    use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        SetFileSecurityW, SetSecurityDescriptorControl, DACL_SECURITY_INFORMATION,
        SE_DACL_AUTO_INHERITED, SE_DACL_AUTO_INHERIT_REQ, SE_DACL_PROTECTED,
    };

    let mut path_w = super::user::wide_null(&path.display().to_string());
    let mut descriptor = ptr::null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            path_w.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::AclRevoke,
            format!("failed to read DACL control with win32 error {status}"),
        ));
    }
    let interest = SE_DACL_AUTO_INHERIT_REQ | SE_DACL_PROTECTED;
    let restored = (original & SE_DACL_PROTECTED)
        | if original & SE_DACL_AUTO_INHERITED != 0 {
            SE_DACL_AUTO_INHERIT_REQ
        } else {
            0
        };
    let ok = unsafe { SetSecurityDescriptorControl(descriptor, interest, restored) };
    if ok != 0 {
        let set_ok =
            unsafe { SetFileSecurityW(path_w.as_ptr(), DACL_SECURITY_INFORMATION, descriptor) };
        unsafe {
            LocalFree(descriptor);
        }
        if set_ok != 0 {
            let observed = security_descriptor_control(path)?;
            let observable = SE_DACL_AUTO_INHERITED | SE_DACL_PROTECTED;
            if observed & observable == original & observable {
                return Ok(());
            }
            return Err(WindowsSmbLifecycleError::operation_failed(
                WindowsSmbLifecyclePhase::AclRevoke,
                format!(
                    "restored DACL control differs for '{}': expected 0x{:04x}, observed 0x{:04x}",
                    path.display(),
                    original & observable,
                    observed & observable
                ),
            ));
        }
    } else {
        unsafe {
            LocalFree(descriptor);
        }
    }
    let code = unsafe { GetLastError() };
    Err(WindowsSmbLifecycleError::operation_failed(
        WindowsSmbLifecyclePhase::AclRevoke,
        format!("restoring DACL control failed with win32 error {code}"),
    ))
}

#[cfg(windows)]
fn inspect_tree(
    root: &std::path::Path,
    prune_subtrees: &[String],
    entry_limit: usize,
    phase: WindowsSmbLifecyclePhase,
) -> Result<usize, WindowsSmbLifecycleError> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let mut entries = 0usize;
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        if path.as_os_str().encode_wide().count() > MAX_WINDOWS_PATH_UNITS {
            return Err(WindowsSmbLifecycleError::operation_failed(
                phase,
                format!(
                    "SMB mount tree path exceeds the Windows path limit: '{}'",
                    path.display()
                ),
            ));
        }
        let metadata = std::fs::symlink_metadata(&path).map_err(|error| {
            WindowsSmbLifecycleError::operation_failed(
                phase,
                format!(
                    "failed to inspect SMB mount tree entry '{}': {error}",
                    path.display()
                ),
            )
        })?;
        if path != root && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(WindowsSmbLifecycleError::operation_failed(
                phase,
                format!(
                    "SMB mount tree contains an unsafe reparse-point descendant: '{}'",
                    path.display()
                ),
            ));
        }
        let is_dir = metadata.is_dir();
        entries += 1;
        if entries > entry_limit {
            return Err(WindowsSmbLifecycleError::operation_failed(
                phase,
                "SMB mounts exceed the 10,000-entry aggregate safety limit",
            ));
        }
        if is_dir {
            let children = std::fs::read_dir(&path).map_err(|error| {
                WindowsSmbLifecycleError::operation_failed(
                    phase,
                    format!(
                        "failed to enumerate SMB mount directory '{}': {error}",
                        path.display()
                    ),
                )
            })?;
            for child in children {
                let child = child.map_err(|error| {
                    WindowsSmbLifecycleError::operation_failed(
                        phase,
                        format!(
                            "failed to enumerate SMB mount directory '{}': {error}",
                            path.display()
                        ),
                    )
                })?;
                if is_pruned_subtree(&child.file_name(), prune_subtrees) {
                    continue;
                }
                pending.push(child.path());
            }
        }
    }
    Ok(entries)
}

#[cfg(windows)]
fn enumerate_tree_for_cleanup(
    root: &std::path::Path,
    prune_subtrees: &[String],
) -> (Vec<WindowsSmbAclPlanEntry>, Vec<WindowsSmbLifecycleError>) {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let mut result = Vec::new();
    let mut failures = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        if path.as_os_str().encode_wide().count() > MAX_WINDOWS_PATH_UNITS {
            failures.push(WindowsSmbLifecycleError::operation_failed_at(
                WindowsSmbLifecyclePhase::AclRevoke,
                path.clone(),
                "SMB mount cleanup path exceeds the Windows path limit",
            ));
            continue;
        }
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                failures.push(WindowsSmbLifecycleError::operation_failed_at(
                    WindowsSmbLifecyclePhase::AclRevoke,
                    path.clone(),
                    format!("failed to inspect SMB mount cleanup entry: {error}"),
                ));
                continue;
            }
        };
        if path != root && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            // Reparse-point descendants were rejected during grant planning, so
            // any created later are outside the journaled ACL mutation set.
            continue;
        }
        let is_dir = metadata.is_dir();
        if path != root {
            result.push(WindowsSmbAclPlanEntry {
                path: path.clone(),
                is_dir,
            });
            if result.len() > MAX_LEGACY_ACL_CLEANUP_ENTRIES {
                failures.push(WindowsSmbLifecycleError::operation_failed_at(
                    WindowsSmbLifecyclePhase::AclRevoke,
                    root.to_path_buf(),
                    format!(
                        "SMB mount cleanup tree exceeds the {MAX_LEGACY_ACL_CLEANUP_ENTRIES}-entry safety limit"
                    ),
                ));
                break;
            }
        }
        if !is_dir {
            continue;
        }
        let children = match std::fs::read_dir(&path) {
            Ok(children) => children,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                failures.push(WindowsSmbLifecycleError::operation_failed_at(
                    WindowsSmbLifecyclePhase::AclRevoke,
                    path.clone(),
                    format!("failed to enumerate SMB mount cleanup directory: {error}"),
                ));
                continue;
            }
        };
        for child in children {
            match child {
                Ok(child) if is_pruned_subtree(&child.file_name(), prune_subtrees) => {}
                Ok(child) => pending.push(child.path()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => failures.push(WindowsSmbLifecycleError::operation_failed_at(
                    WindowsSmbLifecyclePhase::AclRevoke,
                    path.clone(),
                    format!("failed to read SMB mount cleanup directory entry: {error}"),
                )),
            }
        }
    }
    (result, failures)
}

#[cfg(windows)]
fn revoke_acl_entry_best_effort(
    path: &std::path::Path,
    sid: &str,
    access: WindowsSmbAccess,
    is_dir: bool,
    verify: bool,
    failures: &mut Vec<WindowsSmbLifecycleError>,
) {
    if let Err(error) = apply_acl_change(
        path,
        sid,
        access,
        windows_sys::Win32::Security::Authorization::REVOKE_ACCESS,
        is_dir,
        WindowsSmbLifecyclePhase::AclRevoke,
    ) {
        if !path_is_absent(path) {
            failures.push(cleanup_error_at(path, error));
        }
        return;
    }
    if verify {
        verify_explicit_sid_removed(path, sid, failures);
    }
}

#[cfg(windows)]
fn revoke_traverse_acl_best_effort(
    path: &std::path::Path,
    sid: &str,
    failures: &mut Vec<WindowsSmbLifecycleError>,
) {
    if let Err(error) = apply_traverse_acl_change(
        path,
        sid,
        windows_sys::Win32::Security::Authorization::REVOKE_ACCESS,
        WindowsSmbLifecyclePhase::AclRevoke,
    ) {
        if !path_is_absent(path) {
            failures.push(cleanup_error_at(path, error));
        }
        return;
    }
    verify_explicit_sid_removed(path, sid, failures);
}

#[cfg(windows)]
fn verify_explicit_sid_removed(
    path: &std::path::Path,
    sid: &str,
    failures: &mut Vec<WindowsSmbLifecycleError>,
) {
    match contains_explicit_sid(path, sid) {
        Ok(false) => {}
        Ok(true) => failures.push(WindowsSmbLifecycleError::operation_failed_at(
            WindowsSmbLifecyclePhase::AclRevoke,
            path.to_path_buf(),
            format!("explicit ACE for generated SID {sid} remains"),
        )),
        Err(error) if path_is_absent(path) => {}
        Err(error) => failures.push(cleanup_error_at(path, error)),
    }
}

#[cfg(windows)]
fn cleanup_error_at(
    path: &std::path::Path,
    error: WindowsSmbLifecycleError,
) -> WindowsSmbLifecycleError {
    WindowsSmbLifecycleError::operation_failed_at(
        WindowsSmbLifecyclePhase::AclRevoke,
        path.to_path_buf(),
        error.to_string(),
    )
}

#[cfg(windows)]
fn path_is_absent(path: &std::path::Path) -> bool {
    matches!(path.try_exists(), Ok(false))
}

#[cfg(windows)]
fn is_pruned_subtree(name: &std::ffi::OsStr, prune_subtrees: &[String]) -> bool {
    let name = name.to_string_lossy();
    prune_subtrees
        .iter()
        .any(|pruned| name.eq_ignore_ascii_case(pruned))
}

#[cfg(windows)]
fn apply_acl_change(
    path: &std::path::Path,
    sid_string: &str,
    access: WindowsSmbAccess,
    mode: windows_sys::Win32::Security::Authorization::ACCESS_MODE,
    is_dir: bool,
    phase: WindowsSmbLifecyclePhase,
) -> Result<(), WindowsSmbLifecycleError> {
    use windows_sys::Win32::Security::{NO_INHERITANCE, SUB_CONTAINERS_AND_OBJECTS_INHERIT};

    apply_acl_entry_change(
        path,
        sid_string,
        ntfs_access_mask(access),
        mode,
        if is_dir {
            SUB_CONTAINERS_AND_OBJECTS_INHERIT
        } else {
            NO_INHERITANCE
        },
        phase,
    )
}

#[cfg(windows)]
fn apply_traverse_acl_change(
    path: &std::path::Path,
    sid_string: &str,
    mode: windows_sys::Win32::Security::Authorization::ACCESS_MODE,
    phase: WindowsSmbLifecyclePhase,
) -> Result<(), WindowsSmbLifecycleError> {
    use windows_sys::Win32::Security::NO_INHERITANCE;
    use windows_sys::Win32::Storage::FileSystem::FILE_TRAVERSE;

    apply_acl_entry_change(path, sid_string, FILE_TRAVERSE, mode, NO_INHERITANCE, phase)
}

#[cfg(windows)]
fn apply_acl_entry_change(
    path: &std::path::Path,
    sid_string: &str,
    access_mask: u32,
    mode: windows_sys::Win32::Security::Authorization::ACCESS_MODE,
    inheritance: u32,
    phase: WindowsSmbLifecyclePhase,
) -> Result<(), WindowsSmbLifecycleError> {
    use std::ptr;
    use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSidToSidW, GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW,
        EXPLICIT_ACCESS_W, NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN,
        TRUSTEE_W,
    };
    use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;

    let mut path_w = super::user::wide_null(&path.display().to_string());
    let sid_w = super::user::wide_null(sid_string);
    let mut sid = ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(sid_w.as_ptr(), &mut sid) } == 0 {
        let code = unsafe { GetLastError() };
        return Err(WindowsSmbLifecycleError::operation_failed(
            phase,
            format!("ConvertStringSidToSidW failed with win32 error {code}"),
        ));
    }
    let mut old_dacl = ptr::null_mut();
    let mut security_descriptor = ptr::null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            path_w.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut old_dacl,
            ptr::null_mut(),
            &mut security_descriptor,
        )
    };
    if status != 0 {
        unsafe {
            LocalFree(sid.cast());
        }
        return Err(WindowsSmbLifecycleError::operation_failed(
            phase,
            format!(
                "GetNamedSecurityInfoW failed for '{}' with win32 error {status}",
                path.display()
            ),
        ));
    }

    let trustee = TRUSTEE_W {
        pMultipleTrustee: ptr::null_mut(),
        MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
        TrusteeForm: TRUSTEE_IS_SID,
        TrusteeType: TRUSTEE_IS_UNKNOWN,
        ptstrName: sid.cast(),
    };
    let mut entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: access_mask,
        grfAccessMode: mode,
        grfInheritance: inheritance,
        Trustee: trustee,
    };
    let mut new_acl = ptr::null_mut();
    let status = unsafe { SetEntriesInAclW(1, &mut entry, old_dacl, &mut new_acl) };
    if status == 0 {
        let set_status = unsafe {
            SetNamedSecurityInfoW(
                path_w.as_mut_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                new_acl,
                ptr::null_mut(),
            )
        };
        unsafe {
            LocalFree(new_acl.cast());
            LocalFree(security_descriptor);
            LocalFree(sid.cast());
        }
        if set_status == 0 {
            return Ok(());
        }
        return Err(WindowsSmbLifecycleError::operation_failed(
            phase,
            format!(
                "SetNamedSecurityInfoW failed for '{}' with win32 error {set_status}",
                path.display()
            ),
        ));
    }
    unsafe {
        LocalFree(security_descriptor);
        LocalFree(sid.cast());
    }
    Err(WindowsSmbLifecycleError::operation_failed(
        phase,
        format!(
            "SetEntriesInAclW failed for '{}' with win32 error {status}",
            path.display()
        ),
    ))
}

#[cfg(windows)]
fn contains_explicit_sid(
    path: &std::path::Path,
    sid_string: &str,
) -> Result<bool, WindowsSmbLifecycleError> {
    use std::ptr;
    use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSidToSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        EqualSid, GetAce, ACE_HEADER, DACL_SECURITY_INFORMATION, INHERITED_ACE,
    };
    use windows_sys::Win32::System::SystemServices::{
        ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE,
    };

    let mut path_w = super::user::wide_null(&path.display().to_string());
    let sid_w = super::user::wide_null(sid_string);
    let mut sid = ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(sid_w.as_ptr(), &mut sid) } == 0 {
        let code = unsafe { GetLastError() };
        return Err(WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::AclRevoke,
            format!("ConvertStringSidToSidW failed with win32 error {code}"),
        ));
    }
    let mut dacl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            path_w.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        unsafe {
            LocalFree(sid.cast());
        }
        return Err(WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::AclRevoke,
            format!(
                "GetNamedSecurityInfoW failed for '{}' with win32 error {status}",
                path.display()
            ),
        ));
    }
    let ace_count = if dacl.is_null() {
        0
    } else {
        unsafe { (*dacl).AceCount }
    };
    let mut found = false;
    for index in 0..ace_count {
        let mut raw = ptr::null_mut();
        if unsafe { GetAce(dacl, index as u32, &mut raw) } == 0 {
            continue;
        }
        let header = unsafe { &*(raw.cast::<ACE_HEADER>()) };
        if header.AceFlags & INHERITED_ACE as u8 != 0
            || !matches!(
                header.AceType as u32,
                ACCESS_ALLOWED_ACE_TYPE | ACCESS_DENIED_ACE_TYPE
            )
        {
            continue;
        }
        let ace_sid = unsafe { raw.cast::<u8>().add(8).cast() };
        if unsafe { EqualSid(sid, ace_sid) } != 0 {
            found = true;
            break;
        }
    }
    unsafe {
        LocalFree(descriptor);
        LocalFree(sid.cast());
    }
    Ok(found)
}

#[cfg(windows)]
fn ntfs_access_mask(access: WindowsSmbAccess) -> u32 {
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

#[cfg(all(test, windows))]
mod tests {
    use std::process::Command;

    use super::*;
    use crate::windows_x86_64::fs::smb::{
        generate_smb_user_name, NativeWindowsSmbPasswordGenerator, NativeWindowsSmbUserManager,
        WindowsSmbPasswordGenerator, WindowsSmbUserManager,
    };

    fn powershell(script: &str) -> String {
        let output = Command::new("pwsh.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .output()
            .expect("run PowerShell");
        assert!(
            output.status.success(),
            "PowerShell failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

    fn quoted(path: &std::path::Path) -> String {
        path.display().to_string().replace('\'', "''")
    }

    #[test]
    fn acl_plan_prunes_configured_subtrees_at_any_depth_case_insensitively() {
        let fixture =
            std::env::temp_dir().join(format!("lsb-windows-smb-prune-plan-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&fixture);
        std::fs::create_dir_all(fixture.join("node_modules/pkg")).unwrap();
        std::fs::create_dir_all(fixture.join("nested/.SeaWork/cache")).unwrap();
        std::fs::create_dir_all(fixture.join("nested/src")).unwrap();
        std::fs::write(fixture.join("node_modules/pkg/index.js"), b"ignored").unwrap();
        std::fs::write(fixture.join("nested/.SeaWork/cache/state"), b"ignored").unwrap();
        std::fs::write(fixture.join("nested/src/main.rs"), b"included").unwrap();

        let entries = inspect_tree(
            &fixture,
            &["node_modules".to_string(), ".seawork".to_string()],
            MAX_ACL_AGGREGATE_ENTRIES,
            WindowsSmbLifecyclePhase::AclGrant,
        )
        .unwrap();
        assert_eq!(entries, 4);
        let error = inspect_tree(
            &fixture,
            &["node_modules".to_string(), ".seawork".to_string()],
            3,
            WindowsSmbLifecyclePhase::AclGrant,
        )
        .expect_err("the fourth non-pruned entry must exceed the remaining budget");
        assert!(error
            .to_string()
            .contains("10,000-entry aggregate safety limit"));

        let (cleanup_entries, cleanup_failures) = enumerate_tree_for_cleanup(
            &fixture,
            &["node_modules".to_string(), ".seawork".to_string()],
        );
        assert!(cleanup_failures.is_empty());
        let cleanup_relative = cleanup_entries
            .iter()
            .map(|entry| entry.path.strip_prefix(&fixture).unwrap().to_path_buf())
            .collect::<Vec<_>>();
        assert!(cleanup_relative.contains(&PathBuf::from("nested/src/main.rs")));
        assert!(cleanup_relative.iter().all(|path| {
            !path.components().any(|component| {
                matches!(
                    component.as_os_str().to_str(),
                    Some("node_modules" | ".SeaWork")
                )
            })
        }));
        let _ = std::fs::remove_dir_all(fixture);
    }

    #[test]
    fn windows_smb_protected_acl() {
        let fixture = std::env::temp_dir().join(format!(
            "lsb-windows-smb-protected-acl-{}",
            std::process::id()
        ));
        let root = fixture.join("skills");
        let protected = root.join("mis-it-center");
        let skill = protected.join("SKILL.md");
        let _ = std::fs::remove_dir_all(&fixture);
        std::fs::create_dir_all(&fixture).expect("protected fixture parent");
        powershell(&format!(
            "$s=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;$a=New-Object Security.AccessControl.DirectorySecurity;$a.SetSecurityDescriptorSddlForm(('O:BAG:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{0})' -f $s));Set-Acl -LiteralPath '{}' -AclObject $a",
            quoted(&fixture)
        ));
        std::fs::create_dir_all(&protected).expect("protected test tree");
        std::fs::write(&skill, b"protected skill").expect("skill fixture");
        powershell(&format!(
            "$a=Get-Acl -LiteralPath '{}';$a.SetAccessRuleProtection($true,$true);Set-Acl -LiteralPath '{}' -AclObject $a",
            quoted(&protected),
            quoted(&protected)
        ));
        let before = [
            powershell(&format!(
                "(Get-Acl -LiteralPath '{}').Sddl",
                quoted(&fixture)
            )),
            powershell(&format!("(Get-Acl -LiteralPath '{}').Sddl", quoted(&root))),
            powershell(&format!(
                "(Get-Acl -LiteralPath '{}').Sddl",
                quoted(&protected)
            )),
            powershell(&format!("(Get-Acl -LiteralPath '{}').Sddl", quoted(&skill))),
        ];

        let mut passwords = NativeWindowsSmbPasswordGenerator;
        let name = generate_smb_user_name(&mut passwords).expect("temporary user name");
        let password = passwords.generate_password().expect("temporary password");
        let mut users = NativeWindowsSmbUserManager;
        let account = users
            .create_user(&name, &password)
            .expect("create temporary SMB user");
        let mut acls = NativeWindowsSmbAclManager;
        let request = WindowsSmbAclGrantRequest {
            path: root.clone(),
            account: account.clone(),
            access: WindowsSmbAccess::ReadOnly,
            prune_subtrees: Vec::new(),
            entry_limit: MAX_ACL_AGGREGATE_ENTRIES,
        };
        let plan = acls.prepare_grant(&request).expect("prepare ACL plan");
        assert!(
            plan.traverse_paths.contains(&fixture),
            "protected mount ancestor must be included in the recoverable ACL plan"
        );
        assert!(plan.prune_subtrees.is_empty());
        assert_eq!(plan.inspected_entries, 3);
        assert!(!plan.descendant_aces);
        let grant = acls
            .grant_access(plan)
            .expect("grant root across protected ancestor boundary");
        acls.verify_access(&account, &password, std::slice::from_ref(&grant))
            .expect("generated account should open the mount root");
        acls.revoke_access(&grant).expect("revoke exact SID grants");
        users.delete_user(&account).expect("delete temporary user");

        let after = [
            powershell(&format!(
                "(Get-Acl -LiteralPath '{}').Sddl",
                quoted(&fixture)
            )),
            powershell(&format!("(Get-Acl -LiteralPath '{}').Sddl", quoted(&root))),
            powershell(&format!(
                "(Get-Acl -LiteralPath '{}').Sddl",
                quoted(&protected)
            )),
            powershell(&format!("(Get-Acl -LiteralPath '{}').Sddl", quoted(&skill))),
        ];
        assert_eq!(
            after, before,
            "ancestor, root, protected child, and file SDDL"
        );
        let _ = std::fs::remove_dir_all(fixture);
    }
}
