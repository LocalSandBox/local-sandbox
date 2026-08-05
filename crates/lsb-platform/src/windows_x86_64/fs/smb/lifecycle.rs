use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use lsb_proto::MountRequest;
use serde::{Deserialize, Serialize};

use super::acl::{
    WindowsSmbAclGrant, WindowsSmbAclGrantRequest, WindowsSmbAclManager, MAX_ACL_AGGREGATE_ENTRIES,
};
use super::admin::WindowsSmbAdmin;
use super::password::{WindowsSmbPassword, WindowsSmbPasswordGenerator};
use super::share::{
    WindowsSmbShare, WindowsSmbShareCreateRequest, WindowsSmbShareManager, WindowsSmbShareName,
};
use super::types::{
    generate_smb_share_name, generate_smb_user_name, WindowsSmbCleanupFailure,
    WindowsSmbLifecycleConfig, WindowsSmbLifecycleError, WindowsSmbLifecycleEvent,
    WindowsSmbLifecycleObserver, WindowsSmbLifecyclePhase, WindowsSmbLifecycleState,
    WINDOWS_SMB_GATEWAY_SERVER,
};
use super::user::{WindowsSmbUserAccount, WindowsSmbUserManager, WindowsSmbUserName};

pub const WINDOWS_SMB_CLEANUP_MANIFEST_FILE: &str = "windows-smb-cleanup.json";
pub const WINDOWS_SMB_INSTANCE_LOCK_FILE: &str = "windows-smb-active.lock";
const WINDOWS_SMB_CLEANUP_SCHEMA_VERSION: u32 = 5;

#[cfg(windows)]
pub struct WindowsSmbInstanceGuard {
    path: PathBuf,
    file: Option<fs::File>,
}

#[cfg(windows)]
impl WindowsSmbInstanceGuard {
    pub fn acquire(instance_dir: &Path) -> Result<Self, WindowsSmbLifecycleError> {
        try_acquire_windows_smb_instance_guard(instance_dir)?.ok_or_else(|| {
            WindowsSmbLifecycleError::operation_failed(
                WindowsSmbLifecyclePhase::InstanceLock,
                format!(
                    "instance directory '{}' is active in another LocalSandbox process",
                    instance_dir.display()
                ),
            )
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(windows)]
impl fmt::Debug for WindowsSmbInstanceGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WindowsSmbInstanceGuard")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

#[cfg(windows)]
impl Drop for WindowsSmbInstanceGuard {
    fn drop(&mut self) {
        drop(self.file.take());
        let _ = fs::remove_file(&self.path);
    }
}

pub struct WindowsSmbLifecycleManager<A, P, U, L, S> {
    admin: A,
    passwords: P,
    users: U,
    acls: L,
    shares: S,
    observer: Option<Arc<dyn WindowsSmbLifecycleObserver>>,
}

impl<A, P, U, L, S> WindowsSmbLifecycleManager<A, P, U, L, S> {
    pub fn new(admin: A, passwords: P, users: U, acls: L, shares: S) -> Self {
        Self {
            admin,
            passwords,
            users,
            acls,
            shares,
            observer: None,
        }
    }

    pub fn with_observer(mut self, observer: Arc<dyn WindowsSmbLifecycleObserver>) -> Self {
        self.observer = Some(observer);
        self
    }

    fn phase(&self, phase: WindowsSmbLifecyclePhase) -> WindowsSmbPhaseGuard {
        WindowsSmbPhaseGuard::start(self.observer.as_ref(), phase)
    }
}

struct WindowsSmbPhaseGuard {
    observer: Option<Arc<dyn WindowsSmbLifecycleObserver>>,
    phase: WindowsSmbLifecyclePhase,
    completed: bool,
}

impl WindowsSmbPhaseGuard {
    fn start(
        observer: Option<&Arc<dyn WindowsSmbLifecycleObserver>>,
        phase: WindowsSmbLifecyclePhase,
    ) -> Self {
        let observer = observer.cloned();
        if let Some(observer) = &observer {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                observer.record(WindowsSmbLifecycleEvent {
                    phase,
                    state: WindowsSmbLifecycleState::Started,
                    succeeded: None,
                    data: BTreeMap::new(),
                });
            }));
        }
        Self {
            observer,
            phase,
            completed: false,
        }
    }

    fn finish(mut self, succeeded: bool, data: BTreeMap<String, String>) {
        self.complete(succeeded, data);
    }

    fn complete(&mut self, succeeded: bool, data: BTreeMap<String, String>) {
        if self.completed {
            return;
        }
        if let Some(observer) = &self.observer {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                observer.record(WindowsSmbLifecycleEvent {
                    phase: self.phase,
                    state: WindowsSmbLifecycleState::Completed,
                    succeeded: Some(succeeded),
                    data,
                });
            }));
        }
        self.completed = true;
    }
}

impl Drop for WindowsSmbPhaseGuard {
    fn drop(&mut self) {
        self.complete(false, BTreeMap::new());
    }
}

impl<A, P, U, L, S> WindowsSmbLifecycleManager<A, P, U, L, S>
where
    A: WindowsSmbAdmin,
    P: WindowsSmbPasswordGenerator,
    U: WindowsSmbUserManager,
    L: WindowsSmbAclManager,
    S: WindowsSmbShareManager,
{
    pub fn prepare(
        &mut self,
        config: &WindowsSmbLifecycleConfig,
    ) -> Result<WindowsSmbActiveResources, WindowsSmbLifecycleError> {
        self.prepare_internal(config, None)
    }

    pub fn prepare_with_cleanup_manifest(
        &mut self,
        config: &WindowsSmbLifecycleConfig,
        manifest_path: &Path,
    ) -> Result<WindowsSmbActiveResources, WindowsSmbLifecycleError> {
        self.prepare_internal(config, Some(manifest_path))
    }

    fn prepare_internal(
        &mut self,
        config: &WindowsSmbLifecycleConfig,
        manifest_path: Option<&Path>,
    ) -> Result<WindowsSmbActiveResources, WindowsSmbLifecycleError> {
        let admin_phase = self.phase(WindowsSmbLifecyclePhase::AdminPreflight);
        let admin_result = self.admin.ensure_elevated_admin();
        admin_phase.finish(admin_result.is_ok(), BTreeMap::new());
        admin_result?;

        let policy_phase = self.phase(WindowsSmbLifecyclePhase::SmbPolicyPreflight);
        let policy_result = self
            .admin
            .ensure_windows_smb_policy_allows_generated_users();
        policy_phase.finish(policy_result.is_ok(), BTreeMap::new());
        policy_result?;

        let loopback_phase = self.phase(WindowsSmbLifecyclePhase::SmbLoopbackPreflight);
        let loopback_result = self.admin.ensure_smb_loopback_available();
        loopback_phase.finish(loopback_result.is_ok(), BTreeMap::new());
        loopback_result?;

        let credential_phase = self.phase(WindowsSmbLifecyclePhase::CredentialGeneration);
        let credentials = (|| {
            let user_name = generate_smb_user_name(&mut self.passwords)?;
            let password = self.passwords.generate_password()?;
            Ok((user_name, password))
        })();
        credential_phase.finish(credentials.is_ok(), BTreeMap::new());
        let (user_name, password) = credentials?;
        let mut journal = WindowsSmbCleanupManifest::new(
            config.instance_id.clone(),
            user_name.as_str().to_string(),
        );
        if let Some(path) = manifest_path {
            write_windows_smb_cleanup_journal(path, &journal)?;
        }
        let account_phase = self.phase(WindowsSmbLifecyclePhase::UserCreate);
        let account_result = self.users.create_user(&user_name, &password);
        account_phase.finish(account_result.is_ok(), BTreeMap::new());
        let account = match account_result {
            Ok(account) => account,
            Err(error) => {
                let failures = if let Some(path) = manifest_path {
                    match self.recover_cleanup_manifest(path) {
                        Ok(()) => Vec::new(),
                        Err(cleanup) => cleanup.cleanup_failures().to_vec(),
                    }
                } else {
                    Vec::new()
                };
                return Err(error.with_cleanup_failures(failures));
            }
        };
        journal.account.domain = account.domain.clone();
        journal.account.principal = account.principal.clone();
        journal.account.sid = Some(account.sid.clone());
        if let Some(path) = manifest_path {
            if let Err(error) = write_windows_smb_cleanup_journal(path, &journal) {
                let failures = match self.recover_cleanup_manifest(path) {
                    Ok(()) => Vec::new(),
                    Err(cleanup) => cleanup.cleanup_failures().to_vec(),
                };
                return Err(error.with_cleanup_failures(failures));
            }
        }

        let mut acl_grants = Vec::new();
        let mut shares = Vec::new();
        let mut intended_grants = Vec::with_capacity(config.mounts.len());
        let mut remaining_acl_entries = MAX_ACL_AGGREGATE_ENTRIES;
        let acl_plan_phase = self.phase(WindowsSmbLifecyclePhase::AclPlan);
        for mount in &config.mounts {
            let request = WindowsSmbAclGrantRequest {
                path: mount.source.clone(),
                account: account.clone(),
                access: mount.access,
                prune_subtrees: mount.prune_subtrees.clone(),
                entry_limit: remaining_acl_entries,
            };
            let intended_grant = match self.acls.prepare_grant(&request) {
                Ok(grant) => grant,
                Err(error) => {
                    acl_plan_phase.finish(
                        false,
                        BTreeMap::from([(
                            "mount.count".to_string(),
                            config.mounts.len().to_string(),
                        )]),
                    );
                    let failures = if let Some(path) = manifest_path {
                        match self.recover_cleanup_manifest(path) {
                            Ok(()) => Vec::new(),
                            Err(cleanup) => cleanup.cleanup_failures().to_vec(),
                        }
                    } else {
                        self.cleanup_created(&account, &mut shares, &mut acl_grants)
                    };
                    return Err(error.with_cleanup_failures(failures));
                }
            };
            if intended_grant.inspected_entries > remaining_acl_entries {
                acl_plan_phase.finish(
                    false,
                    BTreeMap::from([("mount.count".to_string(), config.mounts.len().to_string())]),
                );
                let error = WindowsSmbLifecycleError::mount_limit_exceeded_at(
                    MAX_ACL_AGGREGATE_ENTRIES,
                    &intended_grant.path,
                );
                let failures = if let Some(path) = manifest_path {
                    match self.recover_cleanup_manifest(path) {
                        Ok(()) => Vec::new(),
                        Err(cleanup) => cleanup.cleanup_failures().to_vec(),
                    }
                } else {
                    self.cleanup_created(&account, &mut shares, &mut acl_grants)
                };
                return Err(error.with_cleanup_failures(failures));
            }
            remaining_acl_entries -= intended_grant.inspected_entries;
            intended_grants.push(intended_grant);
        }
        let inspected_entries = intended_grants
            .iter()
            .map(|grant| grant.inspected_entries)
            .sum::<usize>();
        acl_plan_phase.finish(
            true,
            BTreeMap::from([
                ("mount.count".to_string(), config.mounts.len().to_string()),
                (
                    "acl.inspected_entries".to_string(),
                    inspected_entries.to_string(),
                ),
            ]),
        );

        let mut mount_requests = Vec::new();

        let acl_apply_phase = self.phase(WindowsSmbLifecyclePhase::AclGrant);
        let intended_grant_count = intended_grants.len();
        for intended_grant in intended_grants {
            journal
                .acl_grants
                .push(WindowsSmbCleanupAclGrant::from_grant(&intended_grant));
            if let Some(path) = manifest_path {
                if let Err(error) = write_windows_smb_cleanup_journal(path, &journal) {
                    let failures = match self.recover_cleanup_manifest(path) {
                        Ok(()) => Vec::new(),
                        Err(cleanup) => cleanup.cleanup_failures().to_vec(),
                    };
                    return Err(error.with_cleanup_failures(failures));
                }
            }
            let grant = match self.acls.grant_access(intended_grant) {
                Ok(grant) => grant,
                Err(error) => {
                    acl_apply_phase.finish(
                        false,
                        BTreeMap::from([(
                            "acl.grant_count".to_string(),
                            acl_grants.len().to_string(),
                        )]),
                    );
                    let failures = if let Some(path) = manifest_path {
                        match self.recover_cleanup_manifest(path) {
                            Ok(()) => Vec::new(),
                            Err(cleanup) => cleanup.cleanup_failures().to_vec(),
                        }
                    } else {
                        self.cleanup_created(&account, &mut shares, &mut acl_grants)
                    };
                    return Err(error.with_cleanup_failures(failures));
                }
            };
            acl_grants.push(grant);
            if let Some(record) = journal.acl_grants.last_mut() {
                record.original_dacl_control = acl_grants
                    .last()
                    .and_then(|grant| grant.original_dacl_control);
            }
            if let Some(path) = manifest_path {
                if let Err(error) = write_windows_smb_cleanup_journal(path, &journal) {
                    let failures = match self.recover_cleanup_manifest(path) {
                        Ok(()) => Vec::new(),
                        Err(cleanup) => cleanup.cleanup_failures().to_vec(),
                    };
                    return Err(error.with_cleanup_failures(failures));
                }
            }
        }
        acl_apply_phase.finish(
            true,
            BTreeMap::from([(
                "acl.grant_count".to_string(),
                intended_grant_count.to_string(),
            )]),
        );

        let acl_verify_phase = self.phase(WindowsSmbLifecyclePhase::AclVerify);
        let acl_verify_result = self.acls.verify_access(&account, &password, &acl_grants);
        acl_verify_phase.finish(
            acl_verify_result.is_ok(),
            BTreeMap::from([("acl.grant_count".to_string(), acl_grants.len().to_string())]),
        );
        if let Err(error) = acl_verify_result {
            let failures = if let Some(path) = manifest_path {
                match self.recover_cleanup_manifest(path) {
                    Ok(()) => Vec::new(),
                    Err(cleanup) => cleanup.cleanup_failures().to_vec(),
                }
            } else {
                self.cleanup_created(&account, &mut shares, &mut acl_grants)
            };
            return Err(error.with_cleanup_failures(failures));
        }

        let share_create_phase = self.phase(WindowsSmbLifecyclePhase::ShareCreate);
        for (index, mount) in config.mounts.iter().enumerate() {
            let share_name =
                match generate_smb_share_name(&config.instance_id, index, &mut self.passwords) {
                    Ok(name) => name,
                    Err(error) => {
                        share_create_phase.finish(
                            false,
                            BTreeMap::from([("share.count".to_string(), shares.len().to_string())]),
                        );
                        let failures = if let Some(path) = manifest_path {
                            match self.recover_cleanup_manifest(path) {
                                Ok(()) => Vec::new(),
                                Err(cleanup) => cleanup.cleanup_failures().to_vec(),
                            }
                        } else {
                            self.cleanup_created(&account, &mut shares, &mut acl_grants)
                        };
                        return Err(error.with_cleanup_failures(failures));
                    }
                };
            journal.shares.push(WindowsSmbCleanupShare {
                name: share_name.as_str().to_string(),
                path: mount.source.clone(),
                principal: account.principal.clone(),
                access: mount.access,
            });
            if let Some(path) = manifest_path {
                if let Err(error) = write_windows_smb_cleanup_journal(path, &journal) {
                    let failures = match self.recover_cleanup_manifest(path) {
                        Ok(()) => Vec::new(),
                        Err(cleanup) => cleanup.cleanup_failures().to_vec(),
                    };
                    return Err(error.with_cleanup_failures(failures));
                }
            }
            let share = match self.shares.create_share(WindowsSmbShareCreateRequest {
                name: share_name,
                path: mount.source.clone(),
                account: account.clone(),
                access: mount.access,
            }) {
                Ok(share) => share,
                Err(error) => {
                    share_create_phase.finish(
                        false,
                        BTreeMap::from([("share.count".to_string(), shares.len().to_string())]),
                    );
                    let failures = if let Some(path) = manifest_path {
                        match self.recover_cleanup_manifest(path) {
                            Ok(()) => Vec::new(),
                            Err(cleanup) => cleanup.cleanup_failures().to_vec(),
                        }
                    } else {
                        self.cleanup_created(&account, &mut shares, &mut acl_grants)
                    };
                    return Err(error.with_cleanup_failures(failures));
                }
            };
            mount_requests.push(build_mount_request(
                &account,
                &password,
                &share,
                &mount.target,
            ));
            shares.push(share);
        }
        share_create_phase.finish(
            true,
            BTreeMap::from([("share.count".to_string(), shares.len().to_string())]),
        );

        Ok(WindowsSmbActiveResources {
            account,
            acl_grants,
            shares,
            mount_requests,
        })
    }

    pub fn cleanup(
        &mut self,
        mut resources: WindowsSmbActiveResources,
    ) -> Result<(), WindowsSmbLifecycleError> {
        let failures = self.cleanup_created(
            &resources.account,
            &mut resources.shares,
            &mut resources.acl_grants,
        );
        if failures.is_empty() {
            Ok(())
        } else {
            Err(WindowsSmbLifecycleError::CleanupFailed { failures })
        }
    }

    pub fn recover_cleanup_manifest(
        &mut self,
        path: &Path,
    ) -> Result<(), WindowsSmbLifecycleError> {
        let read_phase = self.phase(WindowsSmbLifecyclePhase::CleanupManifest);
        let manifest_result = read_windows_smb_cleanup_manifest(path);
        read_phase.finish(
            manifest_result.is_ok(),
            BTreeMap::from([("manifest.operation".to_string(), "read".to_string())]),
        );
        let manifest = manifest_result?;
        let resources = manifest.into_active_resources()?;
        self.cleanup(resources)?;
        let remove_phase = self.phase(WindowsSmbLifecyclePhase::CleanupManifest);
        let result = remove_windows_smb_cleanup_manifest(path);
        remove_phase.finish(
            result.is_ok(),
            BTreeMap::from([("manifest.operation".to_string(), "remove".to_string())]),
        );
        result
    }

    fn cleanup_created(
        &mut self,
        account: &WindowsSmbUserAccount,
        shares: &mut Vec<WindowsSmbShare>,
        acl_grants: &mut Vec<WindowsSmbAclGrant>,
    ) -> Vec<WindowsSmbCleanupFailure> {
        let mut failures = Vec::new();

        let share_phase = self.phase(WindowsSmbLifecyclePhase::ShareRemove);
        for share in shares.iter().rev() {
            if let Err(error) = self.shares.remove_share(&share) {
                failures.push(WindowsSmbCleanupFailure::at_path(
                    WindowsSmbLifecyclePhase::ShareRemove,
                    share.path.clone(),
                    error.to_string(),
                ));
            }
        }
        share_phase.finish(
            failures.is_empty(),
            BTreeMap::from([
                ("share.count".to_string(), shares.len().to_string()),
                (
                    "cleanup.failure_count".to_string(),
                    failures.len().to_string(),
                ),
            ]),
        );
        if !failures.is_empty() {
            return failures;
        }

        let mut account = account.clone();
        let acl_phase = self.phase(WindowsSmbLifecyclePhase::AclRevoke);
        if !acl_grants.is_empty() {
            if let Err(error) = self.users.resolve_account_sid(&mut account) {
                failures.push(WindowsSmbCleanupFailure::new(
                    WindowsSmbLifecyclePhase::AclRevoke,
                    error.to_string(),
                ));
                acl_phase.finish(
                    false,
                    BTreeMap::from([
                        ("acl.grant_count".to_string(), acl_grants.len().to_string()),
                        ("cleanup.failure_count".to_string(), "1".to_string()),
                    ]),
                );
                return failures;
            }
            for grant in acl_grants.iter_mut() {
                if grant.sid.is_empty() {
                    grant.sid = account.sid.clone();
                }
            }
        }
        for grant in acl_grants.iter().rev() {
            if let Err(error) = self.acls.revoke_access(&grant) {
                failures.push(WindowsSmbCleanupFailure::at_path(
                    WindowsSmbLifecyclePhase::AclRevoke,
                    error.operation_path().unwrap_or(&grant.path).to_path_buf(),
                    error.to_string(),
                ));
            }
        }
        acl_phase.finish(
            failures.is_empty(),
            BTreeMap::from([
                ("acl.grant_count".to_string(), acl_grants.len().to_string()),
                (
                    "cleanup.failure_count".to_string(),
                    failures.len().to_string(),
                ),
            ]),
        );
        if !failures.is_empty() {
            return failures;
        }

        let user_phase = self.phase(WindowsSmbLifecyclePhase::UserDelete);
        let user_result = self.users.delete_user(&account);
        user_phase.finish(user_result.is_ok(), BTreeMap::new());
        if let Err(error) = user_result {
            failures.push(WindowsSmbCleanupFailure::new(
                WindowsSmbLifecyclePhase::UserDelete,
                error.to_string(),
            ));
        }

        failures
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WindowsSmbRecoveryReport {
    pub attempted: usize,
    pub recovered: usize,
    pub skipped_live: usize,
    pub failures: Vec<WindowsSmbCleanupFailure>,
}

impl WindowsSmbRecoveryReport {
    pub fn has_failures(&self) -> bool {
        !self.failures.is_empty()
    }
}

#[cfg(windows)]
impl
    WindowsSmbLifecycleManager<
        super::admin::NativeWindowsSmbAdmin,
        super::password::NativeWindowsSmbPasswordGenerator,
        super::user::NativeWindowsSmbUserManager,
        super::acl::NativeWindowsSmbAclManager,
        super::share::NativeWindowsSmbShareManager,
    >
{
    pub fn native() -> Self {
        Self::new(
            super::admin::NativeWindowsSmbAdmin::default(),
            super::password::NativeWindowsSmbPasswordGenerator::default(),
            super::user::NativeWindowsSmbUserManager::default(),
            super::acl::NativeWindowsSmbAclManager::default(),
            super::share::NativeWindowsSmbShareManager::default(),
        )
    }
}

#[derive(Clone)]
pub struct WindowsSmbActiveResources {
    pub account: WindowsSmbUserAccount,
    pub acl_grants: Vec<WindowsSmbAclGrant>,
    pub shares: Vec<WindowsSmbShare>,
    pub mount_requests: Vec<MountRequest>,
}

impl WindowsSmbActiveResources {
    pub fn mount_requests(&self) -> &[MountRequest] {
        &self.mount_requests
    }
}

impl fmt::Debug for WindowsSmbActiveResources {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WindowsSmbActiveResources")
            .field("account", &self.account)
            .field("acl_grants", &self.acl_grants)
            .field("shares", &self.shares)
            .field("mount_requests", &self.mount_requests)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowsSmbCleanupManifest {
    pub schema_version: u32,
    pub instance_id: String,
    pub account: WindowsSmbCleanupAccount,
    pub acl_grants: Vec<WindowsSmbCleanupAclGrant>,
    pub shares: Vec<WindowsSmbCleanupShare>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowsSmbCleanupAccount {
    pub name: String,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub principal: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowsSmbCleanupAclGrant {
    pub path: PathBuf,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub traverse_paths: Vec<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prune_subtrees: Vec<String>,
    #[serde(default)]
    pub principal: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    pub access: super::types::WindowsSmbAccess,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_dacl_control: Option<u16>,
    /// Older manifests omitted this field and may contain explicit descendant
    /// ACEs, so absence must retain the legacy cleanup sweep.
    #[serde(default = "default_true")]
    pub descendant_aces: bool,
}

fn default_true() -> bool {
    true
}

impl WindowsSmbCleanupAclGrant {
    fn from_grant(grant: &WindowsSmbAclGrant) -> Self {
        Self {
            path: grant.path.clone(),
            traverse_paths: grant.traverse_paths.clone(),
            prune_subtrees: grant.prune_subtrees.clone(),
            principal: grant.principal.clone(),
            sid: Some(grant.sid.clone()),
            access: grant.access,
            original_dacl_control: grant.original_dacl_control,
            descendant_aces: grant.descendant_aces,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowsSmbCleanupShare {
    pub name: String,
    pub path: PathBuf,
    pub principal: String,
    pub access: super::types::WindowsSmbAccess,
}

impl WindowsSmbCleanupManifest {
    fn new(instance_id: String, account_name: String) -> Self {
        Self {
            schema_version: WINDOWS_SMB_CLEANUP_SCHEMA_VERSION,
            instance_id,
            account: WindowsSmbCleanupAccount {
                name: account_name,
                domain: String::new(),
                principal: String::new(),
                sid: None,
            },
            acl_grants: Vec::new(),
            shares: Vec::new(),
        }
    }

    pub fn from_active_resources(
        instance_id: impl Into<String>,
        resources: &WindowsSmbActiveResources,
    ) -> Self {
        Self {
            schema_version: WINDOWS_SMB_CLEANUP_SCHEMA_VERSION,
            instance_id: instance_id.into(),
            account: WindowsSmbCleanupAccount {
                name: resources.account.name.as_str().to_string(),
                domain: resources.account.domain.clone(),
                principal: resources.account.principal.clone(),
                sid: Some(resources.account.sid.clone()),
            },
            acl_grants: resources
                .acl_grants
                .iter()
                .map(WindowsSmbCleanupAclGrant::from_grant)
                .collect(),
            shares: resources
                .shares
                .iter()
                .map(|share| WindowsSmbCleanupShare {
                    name: share.name.as_str().to_string(),
                    path: share.path.clone(),
                    principal: share.principal.clone(),
                    access: share.access,
                })
                .collect(),
        }
    }

    fn into_active_resources(self) -> Result<WindowsSmbActiveResources, WindowsSmbLifecycleError> {
        if !(1..=WINDOWS_SMB_CLEANUP_SCHEMA_VERSION).contains(&self.schema_version) {
            return Err(WindowsSmbLifecycleError::operation_failed(
                WindowsSmbLifecyclePhase::CleanupManifest,
                format!(
                    "unsupported Windows SMB cleanup manifest schema version {}",
                    self.schema_version
                ),
            ));
        }
        super::types::validate_smb_user_name(&self.account.name)?;
        for share in &self.shares {
            super::types::validate_smb_share_name(&share.name)?;
        }

        Ok(WindowsSmbActiveResources {
            account: WindowsSmbUserAccount {
                name: WindowsSmbUserName::new_unchecked(self.account.name),
                domain: self.account.domain,
                principal: self.account.principal,
                sid: self.account.sid.unwrap_or_default(),
            },
            acl_grants: self
                .acl_grants
                .into_iter()
                .map(|grant| WindowsSmbAclGrant {
                    path: grant.path,
                    traverse_paths: grant.traverse_paths,
                    prune_subtrees: grant.prune_subtrees,
                    principal: grant.principal,
                    sid: grant.sid.unwrap_or_default(),
                    access: grant.access,
                    original_dacl_control: grant.original_dacl_control,
                    inspected_entries: 0,
                    descendant_aces: grant.descendant_aces,
                })
                .collect(),
            shares: self
                .shares
                .into_iter()
                .map(|share| WindowsSmbShare {
                    name: WindowsSmbShareName::new_unchecked(share.name),
                    path: share.path,
                    principal: share.principal,
                    access: share.access,
                })
                .collect(),
            mount_requests: Vec::new(),
        })
    }
}

pub fn write_windows_smb_cleanup_manifest(
    path: &Path,
    instance_id: &str,
    resources: &WindowsSmbActiveResources,
) -> Result<(), WindowsSmbLifecycleError> {
    let manifest = WindowsSmbCleanupManifest::from_active_resources(instance_id, resources);
    write_windows_smb_cleanup_journal(path, &manifest)
}

fn write_windows_smb_cleanup_journal(
    path: &Path,
    manifest: &WindowsSmbCleanupManifest,
) -> Result<(), WindowsSmbLifecycleError> {
    let json = serde_json::to_vec_pretty(manifest).map_err(|error| {
        WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::CleanupManifest,
            format!("failed to serialize cleanup manifest: {error}"),
        )
    })?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            WindowsSmbLifecycleError::operation_failed(
                WindowsSmbLifecyclePhase::CleanupManifest,
                format!(
                    "failed to create cleanup manifest directory '{}': {error}",
                    parent.display()
                ),
            )
        })?;
    }

    let temp_path = path.with_extension("json.tmp");
    let write_result = (|| -> std::io::Result<()> {
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temp_path)?;
        file.write_all(&json)?;
        file.sync_all()
    })();
    write_result.map_err(|error| {
        WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::CleanupManifest,
            format!(
                "failed to write cleanup manifest '{}': {error}",
                temp_path.display()
            ),
        )
    })?;
    replace_cleanup_journal(&temp_path, path).map_err(|error| {
        WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::CleanupManifest,
            format!(
                "failed to commit cleanup manifest '{}': {error}",
                path.display()
            ),
        )
    })
}

#[cfg(windows)]
fn replace_cleanup_journal(source: &Path, target: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, ReplaceFileW, MOVEFILE_WRITE_THROUGH, REPLACEFILE_WRITE_THROUGH,
    };
    let wide = |path: &Path| {
        path.as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>()
    };
    let source = wide(source);
    let target_w = wide(target);
    let ok = if target.exists() {
        unsafe {
            ReplaceFileW(
                target_w.as_ptr(),
                source.as_ptr(),
                std::ptr::null(),
                REPLACEFILE_WRITE_THROUGH,
                std::ptr::null(),
                std::ptr::null(),
            )
        }
    } else {
        unsafe { MoveFileExW(source.as_ptr(), target_w.as_ptr(), MOVEFILE_WRITE_THROUGH) }
    };
    if ok == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn replace_cleanup_journal(source: &Path, target: &Path) -> std::io::Result<()> {
    fs::rename(source, target)?;
    if let Some(parent) = target.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

pub fn read_windows_smb_cleanup_manifest(
    path: &Path,
) -> Result<WindowsSmbCleanupManifest, WindowsSmbLifecycleError> {
    let bytes = fs::read(path).map_err(|error| {
        WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::CleanupManifest,
            format!(
                "failed to read cleanup manifest '{}': {error}",
                path.display()
            ),
        )
    })?;
    serde_json::from_slice(&bytes).map_err(|error| {
        WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::CleanupManifest,
            format!(
                "failed to parse cleanup manifest '{}': {error}",
                path.display()
            ),
        )
    })
}

pub fn remove_windows_smb_cleanup_manifest(path: &Path) -> Result<(), WindowsSmbLifecycleError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(WindowsSmbLifecycleError::operation_failed_at(
            WindowsSmbLifecyclePhase::CleanupManifest,
            path.to_path_buf(),
            format!(
                "failed to remove cleanup manifest '{}': {error}",
                path.display()
            ),
        )),
    }
}

pub fn windows_smb_cleanup_manifest_path(instance_dir: &Path) -> PathBuf {
    instance_dir.join(WINDOWS_SMB_CLEANUP_MANIFEST_FILE)
}

pub fn windows_smb_instance_lock_path(instance_dir: &Path) -> PathBuf {
    instance_dir.join(WINDOWS_SMB_INSTANCE_LOCK_FILE)
}

#[cfg(windows)]
fn try_acquire_windows_smb_instance_guard(
    instance_dir: &Path,
) -> Result<Option<WindowsSmbInstanceGuard>, WindowsSmbLifecycleError> {
    use std::io::Write;
    use std::os::windows::fs::OpenOptionsExt;

    fs::create_dir_all(instance_dir).map_err(|error| {
        WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::InstanceLock,
            format!(
                "failed to create instance lock directory '{}': {error}",
                instance_dir.display()
            ),
        )
    })?;

    let path = windows_smb_instance_lock_path(instance_dir);
    let mut file = match fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .share_mode(0)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if is_windows_lock_held(&error) => return Ok(None),
        Err(error) => {
            return Err(WindowsSmbLifecycleError::operation_failed(
                WindowsSmbLifecyclePhase::InstanceLock,
                format!(
                    "failed to acquire instance lock '{}': {error}",
                    path.display()
                ),
            ));
        }
    };

    file.set_len(0).map_err(|error| {
        WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::InstanceLock,
            format!(
                "failed to reset instance lock '{}': {error}",
                path.display()
            ),
        )
    })?;
    write!(file, "pid={}\n", std::process::id()).map_err(|error| {
        WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::InstanceLock,
            format!(
                "failed to write instance lock '{}': {error}",
                path.display()
            ),
        )
    })?;
    file.sync_data().map_err(|error| {
        WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::InstanceLock,
            format!(
                "failed to flush instance lock '{}': {error}",
                path.display()
            ),
        )
    })?;

    Ok(Some(WindowsSmbInstanceGuard {
        path,
        file: Some(file),
    }))
}

#[cfg(windows)]
fn is_windows_lock_held(error: &std::io::Error) -> bool {
    const ERROR_SHARING_VIOLATION: i32 = 32;
    const ERROR_LOCK_VIOLATION: i32 = 33;
    matches!(
        error.raw_os_error(),
        Some(ERROR_SHARING_VIOLATION) | Some(ERROR_LOCK_VIOLATION)
    )
}

#[cfg(windows)]
pub fn recover_stale_windows_smb_cleanup_manifests(
    instances_dir: &Path,
) -> WindowsSmbRecoveryReport {
    let mut report = WindowsSmbRecoveryReport::default();
    let Ok(entries) = fs::read_dir(instances_dir) else {
        return report;
    };

    for entry in entries {
        let Ok(entry) = entry else {
            report.failures.push(WindowsSmbCleanupFailure::new(
                WindowsSmbLifecyclePhase::CleanupManifest,
                "failed to read stale instance entry",
            ));
            continue;
        };
        let manifest_path = windows_smb_cleanup_manifest_path(&entry.path());
        if !manifest_path.is_file() {
            continue;
        }

        let instance_dir = entry.path();
        let _guard = match try_acquire_windows_smb_instance_guard(&instance_dir) {
            Ok(Some(guard)) => guard,
            Ok(None) => {
                report.skipped_live += 1;
                continue;
            }
            Err(error) => {
                report.failures.push(WindowsSmbCleanupFailure::new(
                    WindowsSmbLifecyclePhase::InstanceLock,
                    error.to_string(),
                ));
                continue;
            }
        };

        report.attempted += 1;
        let mut manager = WindowsSmbLifecycleManager::native();
        match manager.recover_cleanup_manifest(&manifest_path) {
            Ok(()) => report.recovered += 1,
            Err(error) => {
                let cleanup_failures = error.cleanup_failures();
                if cleanup_failures.is_empty() {
                    report.failures.push(WindowsSmbCleanupFailure::new(
                        WindowsSmbLifecyclePhase::CleanupManifest,
                        error.to_string(),
                    ));
                } else {
                    report.failures.extend(cleanup_failures.iter().cloned());
                }
            }
        }
    }

    report
}

fn build_mount_request(
    account: &WindowsSmbUserAccount,
    password: &WindowsSmbPassword,
    share: &WindowsSmbShare,
    target: &str,
) -> MountRequest {
    let access = share.access;
    MountRequest::Smb {
        server: WINDOWS_SMB_GATEWAY_SERVER.to_string(),
        share: share.name.as_str().to_string(),
        target: target.to_string(),
        username: account.name.as_str().to_string(),
        password: password.expose_secret().to_string(),
        domain: account.domain.clone(),
        read_only: access.read_only(),
        uid: 0,
        gid: 0,
        file_mode: access.file_mode(),
        dir_mode: access.dir_mode(),
        options: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::path::PathBuf;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    use super::*;
    use crate::windows_x86_64::fs::smb::{
        generate_smb_share_name, generate_smb_user_name, validate_smb_share_name,
        validate_smb_user_name, NativeWindowsSmbPasswordGenerator, WindowsSmbMount,
    };

    #[derive(Clone, Default)]
    struct EventLog(Rc<RefCell<Vec<String>>>);

    impl EventLog {
        fn push(&self, event: impl Into<String>) {
            self.0.borrow_mut().push(event.into());
        }

        fn snapshot(&self) -> Vec<String> {
            self.0.borrow().clone()
        }
    }

    #[derive(Debug, Default)]
    struct LifecycleRecorder(Mutex<Vec<WindowsSmbLifecycleEvent>>);

    impl WindowsSmbLifecycleObserver for LifecycleRecorder {
        fn record(&self, event: WindowsSmbLifecycleEvent) {
            self.0.lock().unwrap().push(event);
        }
    }

    #[derive(Debug)]
    struct PanickingLifecycleObserver;

    impl WindowsSmbLifecycleObserver for PanickingLifecycleObserver {
        fn record(&self, _event: WindowsSmbLifecycleEvent) {
            panic!("telemetry observer failure");
        }
    }

    struct FakeAdmin {
        log: EventLog,
        elevated: bool,
    }

    impl WindowsSmbAdmin for FakeAdmin {
        fn ensure_elevated_admin(&mut self) -> Result<(), WindowsSmbLifecycleError> {
            self.log.push("admin");
            if self.elevated {
                Ok(())
            } else {
                Err(WindowsSmbLifecycleError::NotElevated)
            }
        }
    }

    struct LoopbackFailAdmin {
        log: EventLog,
    }

    impl WindowsSmbAdmin for LoopbackFailAdmin {
        fn ensure_elevated_admin(&mut self) -> Result<(), WindowsSmbLifecycleError> {
            self.log.push("admin");
            Ok(())
        }

        fn ensure_smb_loopback_available(&mut self) -> Result<(), WindowsSmbLifecycleError> {
            self.log.push("smb_loopback");
            Err(WindowsSmbLifecycleError::operation_failed(
                WindowsSmbLifecyclePhase::SmbLoopbackPreflight,
                "Windows SMB server is unavailable on host loopback port 445",
            ))
        }
    }

    struct PolicyFailAdmin {
        log: EventLog,
    }

    impl WindowsSmbAdmin for PolicyFailAdmin {
        fn ensure_elevated_admin(&mut self) -> Result<(), WindowsSmbLifecycleError> {
            self.log.push("admin");
            Ok(())
        }

        fn ensure_windows_smb_policy_allows_generated_users(
            &mut self,
        ) -> Result<(), WindowsSmbLifecycleError> {
            self.log.push("smb_policy");
            Err(WindowsSmbLifecycleError::operation_failed(
                WindowsSmbLifecyclePhase::SmbPolicyPreflight,
                "Windows direct SMB mounts are blocked by local security policy",
            ))
        }
    }

    struct FakePasswords {
        log: EventLog,
        random: VecDeque<Vec<u8>>,
        password: String,
    }

    impl FakePasswords {
        fn new(log: EventLog, random: impl IntoIterator<Item = Vec<u8>>) -> Self {
            Self {
                log,
                random: random.into_iter().collect(),
                password: "SecretPassword123!".to_string(),
            }
        }
    }

    impl WindowsSmbPasswordGenerator for FakePasswords {
        fn generate_password(&mut self) -> Result<WindowsSmbPassword, WindowsSmbLifecycleError> {
            self.log.push("password");
            Ok(WindowsSmbPassword::from_ascii(
                self.password.as_bytes().to_vec(),
            ))
        }

        fn fill_random_bytes(&mut self, dest: &mut [u8]) -> Result<(), WindowsSmbLifecycleError> {
            let bytes = self.random.pop_front().expect("test random bytes");
            assert_eq!(bytes.len(), dest.len());
            dest.copy_from_slice(&bytes);
            self.log.push(format!("random:{}", dest.len()));
            Ok(())
        }
    }

    struct FakeUsers {
        log: EventLog,
        create_fail: bool,
        delete_fail: bool,
    }

    impl WindowsSmbUserManager for FakeUsers {
        fn create_user(
            &mut self,
            name: &crate::windows_x86_64::fs::smb::WindowsSmbUserName,
            _password: &WindowsSmbPassword,
        ) -> Result<WindowsSmbUserAccount, WindowsSmbLifecycleError> {
            self.log.push(format!("create_user:{name}"));
            if self.create_fail {
                return Err(WindowsSmbLifecycleError::operation_failed(
                    WindowsSmbLifecyclePhase::UserCreate,
                    "create user failed",
                ));
            }
            Ok(WindowsSmbUserAccount {
                name: name.clone(),
                domain: "WINHOST".to_string(),
                principal: format!(r"WINHOST\{name}"),
                sid: "S-1-5-21-1000-1001-1002-1003".to_string(),
            })
        }

        fn delete_user(
            &mut self,
            account: &WindowsSmbUserAccount,
        ) -> Result<(), WindowsSmbLifecycleError> {
            self.log.push(format!("delete_user:{}", account.name));
            if self.delete_fail {
                Err(WindowsSmbLifecycleError::operation_failed(
                    WindowsSmbLifecyclePhase::UserDelete,
                    "delete user failed",
                ))
            } else {
                Ok(())
            }
        }
    }

    struct FakeAcls {
        log: EventLog,
        fail_grant_index: Option<usize>,
        fail_revoke: bool,
        grants: usize,
        entries_per_grant: usize,
    }

    impl WindowsSmbAclManager for FakeAcls {
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
                inspected_entries: self.entries_per_grant,
                descendant_aces: false,
            })
        }

        fn grant_access(
            &mut self,
            grant: WindowsSmbAclGrant,
        ) -> Result<WindowsSmbAclGrant, WindowsSmbLifecycleError> {
            let index = self.grants;
            self.grants += 1;
            self.log
                .push(format!("grant_acl:{index}:{}", grant.path.display()));
            if self.fail_grant_index == Some(index) {
                return Err(WindowsSmbLifecycleError::operation_failed(
                    WindowsSmbLifecyclePhase::AclGrant,
                    "grant failed",
                ));
            }
            Ok(grant)
        }

        fn revoke_access(
            &mut self,
            grant: &WindowsSmbAclGrant,
        ) -> Result<(), WindowsSmbLifecycleError> {
            self.log
                .push(format!("revoke_acl:{}", grant.path.display()));
            if self.fail_revoke {
                Err(WindowsSmbLifecycleError::operation_failed(
                    WindowsSmbLifecyclePhase::AclRevoke,
                    "revoke failed",
                ))
            } else {
                Ok(())
            }
        }
    }

    struct FakeShares {
        log: EventLog,
        fail_create_index: Option<usize>,
        fail_remove: bool,
        creates: usize,
    }

    impl WindowsSmbShareManager for FakeShares {
        fn create_share(
            &mut self,
            request: WindowsSmbShareCreateRequest,
        ) -> Result<WindowsSmbShare, WindowsSmbLifecycleError> {
            let index = self.creates;
            self.creates += 1;
            self.log
                .push(format!("create_share:{index}:{}", request.name));
            if self.fail_create_index == Some(index) {
                return Err(WindowsSmbLifecycleError::operation_failed(
                    WindowsSmbLifecyclePhase::ShareCreate,
                    "share failed",
                ));
            }
            Ok(WindowsSmbShare {
                name: request.name,
                path: request.path,
                principal: request.account.principal,
                access: request.access,
            })
        }

        fn remove_share(
            &mut self,
            share: &WindowsSmbShare,
        ) -> Result<(), WindowsSmbLifecycleError> {
            self.log.push(format!("remove_share:{}", share.name));
            if self.fail_remove {
                Err(WindowsSmbLifecycleError::operation_failed(
                    WindowsSmbLifecyclePhase::ShareRemove,
                    "remove failed",
                ))
            } else {
                Ok(())
            }
        }
    }

    fn fake_manager(
        log: EventLog,
        random: impl IntoIterator<Item = Vec<u8>>,
    ) -> WindowsSmbLifecycleManager<FakeAdmin, FakePasswords, FakeUsers, FakeAcls, FakeShares> {
        WindowsSmbLifecycleManager::new(
            FakeAdmin {
                log: log.clone(),
                elevated: true,
            },
            FakePasswords::new(log.clone(), random),
            FakeUsers {
                log: log.clone(),
                create_fail: false,
                delete_fail: false,
            },
            FakeAcls {
                log: log.clone(),
                fail_grant_index: None,
                fail_revoke: false,
                grants: 0,
                entries_per_grant: 1,
            },
            FakeShares {
                log,
                fail_create_index: None,
                fail_remove: false,
                creates: 0,
            },
        )
    }

    fn config() -> WindowsSmbLifecycleConfig {
        WindowsSmbLifecycleConfig::new(
            "Instance Mounts 01",
            vec![
                WindowsSmbMount::read_write(PathBuf::from("/host/a"), "/work"),
                WindowsSmbMount::read_only(PathBuf::from("/host/b"), "/readonly"),
            ],
        )
    }

    fn temp_dir(label: &str) -> PathBuf {
        static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
        let nonce = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "lsb-windows-smb-{label}-{}-{nonce}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    #[test]
    fn lifecycle_success_creates_mount_requests_and_cleans_in_order() {
        let log = EventLog::default();
        let mut manager = fake_manager(
            log.clone(),
            [
                vec![0, 1, 2, 3, 4, 5],
                vec![0xaa, 0xbb, 0xcc, 0xdd],
                vec![0xee, 0xff, 0x10, 0x20],
            ],
        );

        let resources = manager.prepare(&config()).expect("prepare succeeds");

        assert_eq!(resources.mount_requests.len(), 2);
        assert!(matches!(
            &resources.mount_requests[0],
            MountRequest::Smb {
                server,
                share,
                target,
                username,
                password,
                domain,
                read_only,
                file_mode,
                dir_mode,
                ..
            } if server == "10.0.0.1"
                && share == "lsb-instancemounts01-m0-aabbccdd"
                && target == "/work"
                && username == "lsb_000102030405"
                && password == "SecretPassword123!"
                && domain == "WINHOST"
                && !read_only
                && *file_mode == 0o666
                && *dir_mode == 0o777
        ));
        assert!(matches!(
            &resources.mount_requests[1],
            MountRequest::Smb {
                share,
                target,
                read_only,
                file_mode,
                dir_mode,
                ..
            } if share == "lsb-instancemounts01-m1-eeff1020"
                && target == "/readonly"
                && *read_only
                && *file_mode == 0o644
                && *dir_mode == 0o755
        ));

        let debug = format!("{resources:?}");
        assert!(!debug.contains("SecretPassword123!"));
        assert!(debug.contains("<redacted>"));

        manager.cleanup(resources).expect("cleanup succeeds");

        assert_eq!(
            log.snapshot(),
            [
                "admin",
                "random:6",
                "password",
                "create_user:lsb_000102030405",
                "grant_acl:0:/host/a",
                "grant_acl:1:/host/b",
                "random:4",
                "create_share:0:lsb-instancemounts01-m0-aabbccdd",
                "random:4",
                "create_share:1:lsb-instancemounts01-m1-eeff1020",
                "remove_share:lsb-instancemounts01-m1-eeff1020",
                "remove_share:lsb-instancemounts01-m0-aabbccdd",
                "revoke_acl:/host/b",
                "revoke_acl:/host/a",
                "delete_user:lsb_000102030405",
            ]
        );
    }

    #[test]
    fn lifecycle_observer_breaks_setup_and_cleanup_into_aggregate_phases() {
        let recorder = Arc::new(LifecycleRecorder::default());
        let mut manager = fake_manager(
            EventLog::default(),
            [
                vec![0, 1, 2, 3, 4, 5],
                vec![0xaa, 0xbb, 0xcc, 0xdd],
                vec![0xee, 0xff, 0x10, 0x20],
            ],
        )
        .with_observer(recorder.clone());

        let resources = manager.prepare(&config()).expect("prepare succeeds");
        manager.cleanup(resources).expect("cleanup succeeds");

        let events = recorder.0.lock().unwrap();
        let completed = events
            .iter()
            .filter(|event| event.state == WindowsSmbLifecycleState::Completed)
            .collect::<Vec<_>>();
        assert_eq!(
            completed
                .iter()
                .map(|event| event.phase)
                .collect::<Vec<_>>(),
            [
                WindowsSmbLifecyclePhase::AdminPreflight,
                WindowsSmbLifecyclePhase::SmbPolicyPreflight,
                WindowsSmbLifecyclePhase::SmbLoopbackPreflight,
                WindowsSmbLifecyclePhase::CredentialGeneration,
                WindowsSmbLifecyclePhase::UserCreate,
                WindowsSmbLifecyclePhase::AclPlan,
                WindowsSmbLifecyclePhase::AclGrant,
                WindowsSmbLifecyclePhase::AclVerify,
                WindowsSmbLifecyclePhase::ShareCreate,
                WindowsSmbLifecyclePhase::ShareRemove,
                WindowsSmbLifecyclePhase::AclRevoke,
                WindowsSmbLifecyclePhase::UserDelete,
            ]
        );
        assert!(completed.iter().all(|event| event.succeeded == Some(true)));
        let acl_plan = completed
            .iter()
            .find(|event| event.phase == WindowsSmbLifecyclePhase::AclPlan)
            .unwrap();
        assert_eq!(acl_plan.data["mount.count"], "2");
        assert_eq!(acl_plan.data["acl.inspected_entries"], "2");
    }

    #[test]
    fn lifecycle_observer_panics_fail_open() {
        let mut manager = fake_manager(
            EventLog::default(),
            [
                vec![0, 1, 2, 3, 4, 5],
                vec![0xaa, 0xbb, 0xcc, 0xdd],
                vec![0xee, 0xff, 0x10, 0x20],
            ],
        )
        .with_observer(Arc::new(PanickingLifecycleObserver));

        let resources = manager
            .prepare(&config())
            .expect("telemetry must not fail setup");
        manager
            .cleanup(resources)
            .expect("telemetry must not fail cleanup");
    }

    #[test]
    fn lifecycle_rejects_mounts_over_the_aggregate_acl_entry_budget_before_granting() {
        let log = EventLog::default();
        let mut manager = fake_manager(log.clone(), [vec![0, 1, 2, 3, 4, 5]]);
        manager.acls.entries_per_grant = 6_000;

        let error = manager
            .prepare(&config())
            .expect_err("two 6,000-entry mounts must exceed the aggregate budget");

        assert!(error.to_string().contains("10000-entry aggregate limit"));
        assert!(log
            .snapshot()
            .iter()
            .all(|event| !event.starts_with("grant_acl:")));
        assert!(log
            .snapshot()
            .iter()
            .any(|event| event.starts_with("delete_user:")));
    }

    #[test]
    fn cleanup_manifest_roundtrips_without_password_and_recovers_resources() {
        let prepare_log = EventLog::default();
        let mut prepare_manager = fake_manager(
            prepare_log,
            [
                vec![0, 1, 2, 3, 4, 5],
                vec![0xaa, 0xbb, 0xcc, 0xdd],
                vec![0xee, 0xff, 0x10, 0x20],
            ],
        );
        let mut resources = prepare_manager
            .prepare(&config())
            .expect("prepare succeeds");
        resources.acl_grants[0].traverse_paths = vec![PathBuf::from("/"), PathBuf::from("/host")];
        resources.acl_grants[0].prune_subtrees =
            vec!["node_modules".to_string(), ".seawork".to_string()];
        let root = temp_dir("cleanup-manifest");
        std::fs::create_dir_all(&root).expect("manifest dir");
        let manifest_path = windows_smb_cleanup_manifest_path(&root);

        write_windows_smb_cleanup_manifest(&manifest_path, "Instance Mounts 01", &resources)
            .expect("cleanup manifest should write");

        let manifest_text = std::fs::read_to_string(&manifest_path).expect("manifest text");
        assert!(!manifest_text.contains("SecretPassword123!"));
        assert!(!manifest_text.contains("password"));
        assert!(!manifest_text.contains("mount_requests"));
        assert!(manifest_text.contains("lsb_000102030405"));
        assert!(manifest_text.contains("lsb-instancemounts01-m0-aabbccdd"));

        let manifest =
            read_windows_smb_cleanup_manifest(&manifest_path).expect("manifest should parse");
        assert_eq!(manifest.schema_version, 5);
        assert_eq!(
            manifest.account.sid.as_deref(),
            Some("S-1-5-21-1000-1001-1002-1003")
        );
        assert_eq!(
            manifest.acl_grants[0].traverse_paths,
            [PathBuf::from("/"), PathBuf::from("/host")]
        );
        assert_eq!(
            manifest.acl_grants[0].prune_subtrees,
            ["node_modules", ".seawork"]
        );
        assert!(!manifest.acl_grants[0].descendant_aces);
        assert_eq!(manifest.shares.len(), 2);

        let recover_log = EventLog::default();
        let mut recover_manager = WindowsSmbLifecycleManager::new(
            FakeAdmin {
                log: recover_log.clone(),
                elevated: true,
            },
            FakePasswords::new(recover_log.clone(), Vec::<Vec<u8>>::new()),
            FakeUsers {
                log: recover_log.clone(),
                create_fail: false,
                delete_fail: false,
            },
            FakeAcls {
                log: recover_log.clone(),
                fail_grant_index: None,
                fail_revoke: false,
                grants: 0,
                entries_per_grant: 1,
            },
            FakeShares {
                log: recover_log.clone(),
                fail_create_index: None,
                fail_remove: false,
                creates: 0,
            },
        );

        recover_manager
            .recover_cleanup_manifest(&manifest_path)
            .expect("manifest recovery should clean resources");

        assert!(!manifest_path.exists());
        assert_eq!(
            recover_log.snapshot(),
            [
                "remove_share:lsb-instancemounts01-m1-eeff1020",
                "remove_share:lsb-instancemounts01-m0-aabbccdd",
                "revoke_acl:/host/b",
                "revoke_acl:/host/a",
                "delete_user:lsb_000102030405",
            ]
        );

        let _ = std::fs::remove_dir_all(root);
        drop(resources);
    }

    #[test]
    fn cleanup_manifest_recovery_keeps_manifest_when_cleanup_fails() {
        let prepare_log = EventLog::default();
        let mut prepare_manager = fake_manager(
            prepare_log,
            [
                vec![0, 1, 2, 3, 4, 5],
                vec![0xaa, 0xbb, 0xcc, 0xdd],
                vec![0xee, 0xff, 0x10, 0x20],
            ],
        );
        let resources = prepare_manager
            .prepare(&config())
            .expect("prepare succeeds");
        let root = temp_dir("cleanup-manifest-failure");
        std::fs::create_dir_all(&root).expect("manifest dir");
        let manifest_path = windows_smb_cleanup_manifest_path(&root);
        write_windows_smb_cleanup_manifest(&manifest_path, "Instance Mounts 01", &resources)
            .expect("cleanup manifest should write");

        let recover_log = EventLog::default();
        let mut recover_manager = WindowsSmbLifecycleManager::new(
            FakeAdmin {
                log: recover_log.clone(),
                elevated: true,
            },
            FakePasswords::new(recover_log.clone(), Vec::<Vec<u8>>::new()),
            FakeUsers {
                log: recover_log.clone(),
                create_fail: false,
                delete_fail: false,
            },
            FakeAcls {
                log: recover_log.clone(),
                fail_grant_index: None,
                fail_revoke: false,
                grants: 0,
                entries_per_grant: 1,
            },
            FakeShares {
                log: recover_log.clone(),
                fail_create_index: None,
                fail_remove: true,
                creates: 0,
            },
        );

        let error = recover_manager
            .recover_cleanup_manifest(&manifest_path)
            .expect_err("cleanup failure should be reported");

        assert!(matches!(
            error,
            WindowsSmbLifecycleError::CleanupFailed { .. }
        ));
        assert!(
            manifest_path.exists(),
            "failed cleanup should keep manifest for a later retry"
        );

        let _ = std::fs::remove_dir_all(root);
        drop(resources);
    }

    #[test]
    fn schema_one_manifest_parses_but_never_heuristically_revokes_an_unresolved_ace() {
        let root = temp_dir("schema-one");
        std::fs::create_dir_all(&root).expect("manifest dir");
        let manifest_path = windows_smb_cleanup_manifest_path(&root);
        std::fs::write(
            &manifest_path,
            br#"{
              "schema_version": 1,
              "instance_id": "legacy",
              "account": {
                "name": "lsb_001122334455",
                "domain": "OLDHOST",
                "principal": "OLDHOST\\lsb_001122334455"
              },
              "acl_grants": [{
                "path": "/host/legacy",
                "principal": "OLDHOST\\lsb_001122334455",
                "access": "ReadOnly"
              }],
              "shares": []
            }"#,
        )
        .expect("legacy fixture");

        let manifest =
            read_windows_smb_cleanup_manifest(&manifest_path).expect("schema 1 should parse");
        assert_eq!(manifest.schema_version, 1);
        assert!(manifest.account.sid.is_none());
        assert!(manifest.acl_grants[0].traverse_paths.is_empty());
        assert!(manifest.acl_grants[0].prune_subtrees.is_empty());
        assert!(manifest.acl_grants[0].descendant_aces);

        let log = EventLog::default();
        let mut manager = fake_manager(log.clone(), Vec::<Vec<u8>>::new());
        let error = manager
            .recover_cleanup_manifest(&manifest_path)
            .expect_err("unresolvable legacy SID must remain for manual recovery");
        assert!(error.to_string().contains("cleanup failed"));
        assert!(manifest_path.exists());
        assert!(log
            .snapshot()
            .iter()
            .all(|event| !event.starts_with("revoke_acl:") && !event.starts_with("delete_user:")));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn journal_records_sid_and_acl_intent_before_a_partial_acl_failure() {
        let root = temp_dir("acl-intent");
        std::fs::create_dir_all(&root).expect("manifest dir");
        let manifest_path = windows_smb_cleanup_manifest_path(&root);
        let log = EventLog::default();
        let mut manager = fake_manager(log.clone(), [vec![0, 1, 2, 3, 4, 5]]);
        manager.acls.fail_grant_index = Some(0);
        manager.acls.fail_revoke = true;

        manager
            .prepare_with_cleanup_manifest(&config(), &manifest_path)
            .expect_err("ACL grant should fail");

        let manifest = read_windows_smb_cleanup_manifest(&manifest_path).expect("journal retained");
        assert_eq!(manifest.schema_version, 5);
        assert_eq!(
            manifest.account.sid.as_deref(),
            Some("S-1-5-21-1000-1001-1002-1003")
        );
        assert_eq!(manifest.acl_grants.len(), 1);
        assert_eq!(
            manifest.acl_grants[0].sid.as_deref(),
            manifest.account.sid.as_deref()
        );
        assert!(manifest.shares.is_empty());
        assert!(log
            .snapshot()
            .iter()
            .all(|event| !event.starts_with("delete_user:")));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn windows_smb_sid_recovery_retries_cleanup_without_name_lookup() {
        let root = temp_dir("sid-retry");
        std::fs::create_dir_all(&root).expect("manifest dir");
        let manifest_path = windows_smb_cleanup_manifest_path(&root);
        let prepare_log = EventLog::default();
        let mut prepare = fake_manager(
            prepare_log,
            [
                vec![0, 1, 2, 3, 4, 5],
                vec![0xaa, 0xbb, 0xcc, 0xdd],
                vec![0xee, 0xff, 0x10, 0x20],
            ],
        );
        let resources = prepare.prepare(&config()).expect("prepare");
        write_windows_smb_cleanup_manifest(&manifest_path, "Instance Mounts 01", &resources)
            .expect("journal");

        let failed_log = EventLog::default();
        let mut failed = fake_manager(failed_log.clone(), Vec::<Vec<u8>>::new());
        failed.acls.fail_revoke = true;
        failed
            .recover_cleanup_manifest(&manifest_path)
            .expect_err("first cleanup should fail");
        assert!(manifest_path.exists());
        assert!(failed_log
            .snapshot()
            .iter()
            .all(|event| !event.starts_with("delete_user:")));

        let retry_log = EventLog::default();
        let mut retry = fake_manager(retry_log.clone(), Vec::<Vec<u8>>::new());
        retry
            .recover_cleanup_manifest(&manifest_path)
            .expect("stored SID should make retry independent of name lookup");
        assert!(!manifest_path.exists());
        assert!(retry_log
            .snapshot()
            .iter()
            .any(|event| event.starts_with("delete_user:")));
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn windows_smb_sid_recovery_after_account_deletion_and_manager_restart() {
        use std::process::Command;

        let _guard = crate::windows_x86_64::fs::smb::lock_native_acl_tests();

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

        fn quote(path: &Path) -> String {
            path.display().to_string().replace('\'', "''")
        }

        fn net_resource_exists(kind: &str, name: &str) -> bool {
            Command::new("net.exe")
                .args([kind, name])
                .output()
                .expect("query net resource")
                .status
                .success()
        }

        let root = temp_dir("native-sid-recovery");
        let mount = root.join("mount");
        let protected = mount.join("mis-it-center");
        let skill = protected.join("SKILL.md");
        let instance = root.join("instance");
        std::fs::create_dir_all(&protected).expect("protected test tree");
        std::fs::create_dir_all(&instance).expect("instance dir");
        std::fs::write(&skill, b"protected-skill-input").expect("skill fixture");
        powershell(&format!(
            "$a=Get-Acl -LiteralPath '{}';$a.SetAccessRuleProtection($true,$true);Set-Acl -LiteralPath '{}' -AclObject $a",
            quote(&protected),
            quote(&protected)
        ));
        let before = [
            powershell(&format!("(Get-Acl -LiteralPath '{}').Sddl", quote(&mount))),
            powershell(&format!(
                "(Get-Acl -LiteralPath '{}').Sddl",
                quote(&protected)
            )),
            powershell(&format!("(Get-Acl -LiteralPath '{}').Sddl", quote(&skill))),
        ];

        let manifest_path = windows_smb_cleanup_manifest_path(&instance);
        let config = WindowsSmbLifecycleConfig::new(
            format!("native-sid-recovery-{}", std::process::id()),
            vec![WindowsSmbMount::read_only(mount.clone(), "/skills")],
        );
        let mut preparing = WindowsSmbLifecycleManager::native();
        let resources = preparing
            .prepare_with_cleanup_manifest(&config, &manifest_path)
            .expect("prepare native SMB resources and committed journal");
        let user_name = resources.account.name.as_str().to_string();
        let sid = resources.account.sid.clone();
        let share_names = resources
            .shares
            .iter()
            .map(|share| share.name.as_str().to_string())
            .collect::<Vec<_>>();
        let journal =
            read_windows_smb_cleanup_manifest(&manifest_path).expect("committed SID journal");
        let journal_has_sid = journal.account.sid.as_deref() == Some(sid.as_str())
            && journal
                .acl_grants
                .iter()
                .all(|grant| grant.sid.as_deref() == Some(sid.as_str()));
        let user_existed_before_crash = net_resource_exists("user", &user_name);
        let shares_existed_before_crash = share_names
            .iter()
            .all(|name| net_resource_exists("share", name));

        // Simulate the old failure ordering: the account disappears while the
        // SID ACE and committed cleanup journal remain, then the process restarts.
        let deleted = Command::new("net.exe")
            .args(["user", &user_name, "/delete"])
            .output()
            .expect("delete temporary user before recovery")
            .status
            .success();
        let name_lookup_unavailable = !net_resource_exists("user", &user_name);
        drop(resources);
        drop(preparing);

        let renamed = mount.join("mis-it-center-renamed");
        let rename_result = std::fs::rename(&protected, &renamed);
        let renamed_skill = renamed.join("SKILL.md");

        let mut recovering = WindowsSmbLifecycleManager::native();
        recovering
            .recover_cleanup_manifest(&manifest_path)
            .expect("fresh manager should recover by stored SID");

        let after = [
            powershell(&format!("(Get-Acl -LiteralPath '{}').Sddl", quote(&mount))),
            powershell(&format!(
                "(Get-Acl -LiteralPath '{}').Sddl",
                quote(&renamed)
            )),
            powershell(&format!(
                "(Get-Acl -LiteralPath '{}').Sddl",
                quote(&renamed_skill)
            )),
        ];
        let shares_removed = share_names
            .iter()
            .all(|name| !net_resource_exists("share", name));

        assert!(journal_has_sid, "journal must retain the canonical SID");
        assert!(user_existed_before_crash);
        assert!(shares_existed_before_crash);
        assert!(deleted);
        assert!(name_lookup_unavailable);
        assert!(rename_result.is_ok(), "protected boundary rename");
        assert!(
            !manifest_path.exists(),
            "successful recovery removes journal"
        );
        assert!(shares_removed);
        assert!(
            !net_resource_exists("user", &user_name),
            "temporary user remains absent"
        );
        assert_eq!(after, before, "exact SDDL after SID-only recovery");
        assert!(
            after.iter().all(|sddl| !sddl.contains(&sid)),
            "no explicit generated SID ACE remains"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn stale_recovery_skips_manifest_when_instance_lock_is_held() {
        let root = temp_dir("locked-stale-recovery");
        let instance = root.join("live-instance");
        std::fs::create_dir_all(&instance).expect("instance dir");
        let manifest_path = windows_smb_cleanup_manifest_path(&instance);
        std::fs::write(&manifest_path, b"not valid json").expect("manifest fixture");
        let guard = WindowsSmbInstanceGuard::acquire(&instance).expect("instance lock");

        let report = recover_stale_windows_smb_cleanup_manifests(&root);

        assert_eq!(report.attempted, 0);
        assert_eq!(report.recovered, 0);
        assert_eq!(report.skipped_live, 1);
        assert!(report.failures.is_empty());
        assert!(
            manifest_path.exists(),
            "live manifest should remain for the owning sandbox stop path"
        );

        drop(guard);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn lifecycle_share_failure_cleans_created_resources() {
        let log = EventLog::default();
        let mut manager = fake_manager(
            log.clone(),
            [
                vec![0, 1, 2, 3, 4, 5],
                vec![0xaa, 0xbb, 0xcc, 0xdd],
                vec![0xee, 0xff, 0x10, 0x20],
            ],
        );
        manager.shares.fail_create_index = Some(1);

        let error = manager
            .prepare(&config())
            .expect_err("second share should fail");

        assert!(matches!(
            error,
            WindowsSmbLifecycleError::OperationFailed {
                phase: WindowsSmbLifecyclePhase::ShareCreate,
                ..
            }
        ));
        assert_eq!(
            log.snapshot(),
            [
                "admin",
                "random:6",
                "password",
                "create_user:lsb_000102030405",
                "grant_acl:0:/host/a",
                "grant_acl:1:/host/b",
                "random:4",
                "create_share:0:lsb-instancemounts01-m0-aabbccdd",
                "random:4",
                "create_share:1:lsb-instancemounts01-m1-eeff1020",
                "remove_share:lsb-instancemounts01-m0-aabbccdd",
                "revoke_acl:/host/b",
                "revoke_acl:/host/a",
                "delete_user:lsb_000102030405",
            ]
        );
    }

    #[test]
    fn lifecycle_acl_failure_cleans_user_and_prior_acl() {
        let log = EventLog::default();
        let mut manager = fake_manager(log.clone(), [vec![0, 1, 2, 3, 4, 5]]);
        manager.acls.fail_grant_index = Some(1);

        let error = manager
            .prepare(&config())
            .expect_err("second ACL grant should fail");

        assert!(matches!(
            error,
            WindowsSmbLifecycleError::OperationFailed {
                phase: WindowsSmbLifecyclePhase::AclGrant,
                ..
            }
        ));
        assert_eq!(
            log.snapshot(),
            [
                "admin",
                "random:6",
                "password",
                "create_user:lsb_000102030405",
                "grant_acl:0:/host/a",
                "grant_acl:1:/host/b",
                "revoke_acl:/host/a",
                "delete_user:lsb_000102030405",
            ]
        );
    }

    #[test]
    fn cleanup_stops_at_failed_dependency_and_retains_account() {
        let log = EventLog::default();
        let mut manager = fake_manager(
            log.clone(),
            [
                vec![0, 1, 2, 3, 4, 5],
                vec![0xaa, 0xbb, 0xcc, 0xdd],
                vec![0xee, 0xff, 0x10, 0x20],
            ],
        );
        let resources = manager.prepare(&config()).expect("prepare succeeds");
        manager.shares.fail_remove = true;
        manager.acls.fail_revoke = true;
        manager.users.delete_fail = true;

        let error = manager
            .cleanup(resources)
            .expect_err("cleanup should report failures");

        assert!(matches!(
            error,
            WindowsSmbLifecycleError::CleanupFailed { .. }
        ));
        assert_eq!(error.cleanup_failures().len(), 2);
        assert!(log
            .snapshot()
            .iter()
            .all(|event| !event.starts_with("revoke_acl:") && !event.starts_with("delete_user:")));
    }

    #[test]
    fn cleanup_records_each_failed_acl_root_and_retains_account() {
        let log = EventLog::default();
        let mut manager = fake_manager(
            log.clone(),
            [
                vec![0, 1, 2, 3, 4, 5],
                vec![0xaa, 0xbb, 0xcc, 0xdd],
                vec![0xee, 0xff, 0x10, 0x20],
            ],
        );
        let resources = manager.prepare(&config()).expect("prepare succeeds");
        manager.acls.fail_revoke = true;

        let error = manager
            .cleanup(resources)
            .expect_err("ACL cleanup should report every failed mount root");

        let failures = error.cleanup_failures();
        assert_eq!(failures.len(), 2);
        assert_eq!(failures[0].path.as_deref(), Some(Path::new("/host/b")));
        assert_eq!(failures[1].path.as_deref(), Some(Path::new("/host/a")));
        assert!(error.to_string().contains("/host/b"));
        assert_eq!(
            log.snapshot(),
            [
                "admin",
                "random:6",
                "password",
                "create_user:lsb_000102030405",
                "grant_acl:0:/host/a",
                "grant_acl:1:/host/b",
                "random:4",
                "create_share:0:lsb-instancemounts01-m0-aabbccdd",
                "random:4",
                "create_share:1:lsb-instancemounts01-m1-eeff1020",
                "remove_share:lsb-instancemounts01-m1-eeff1020",
                "remove_share:lsb-instancemounts01-m0-aabbccdd",
                "revoke_acl:/host/b",
                "revoke_acl:/host/a",
            ]
        );
    }

    #[test]
    fn admin_failure_is_actionable_and_creates_nothing() {
        let log = EventLog::default();
        let mut manager = WindowsSmbLifecycleManager::new(
            FakeAdmin {
                log: log.clone(),
                elevated: false,
            },
            FakePasswords::new(log.clone(), [vec![0, 1, 2, 3, 4, 5]]),
            FakeUsers {
                log: log.clone(),
                create_fail: false,
                delete_fail: false,
            },
            FakeAcls {
                log: log.clone(),
                fail_grant_index: None,
                fail_revoke: false,
                grants: 0,
                entries_per_grant: 1,
            },
            FakeShares {
                log: log.clone(),
                fail_create_index: None,
                fail_remove: false,
                creates: 0,
            },
        );

        let error = manager
            .prepare(&config())
            .expect_err("admin preflight should fail");

        assert_eq!(
            error.to_string(),
            "Windows direct mounts require an elevated Administrator shell"
        );
        assert_eq!(log.snapshot(), ["admin"]);
    }

    #[test]
    fn smb_loopback_preflight_failure_creates_nothing() {
        let log = EventLog::default();
        let mut manager = WindowsSmbLifecycleManager::new(
            LoopbackFailAdmin { log: log.clone() },
            FakePasswords::new(log.clone(), [vec![0, 1, 2, 3, 4, 5]]),
            FakeUsers {
                log: log.clone(),
                create_fail: false,
                delete_fail: false,
            },
            FakeAcls {
                log: log.clone(),
                fail_grant_index: None,
                fail_revoke: false,
                grants: 0,
                entries_per_grant: 1,
            },
            FakeShares {
                log: log.clone(),
                fail_create_index: None,
                fail_remove: false,
                creates: 0,
            },
        );

        let error = manager
            .prepare(&config())
            .expect_err("SMB loopback preflight should fail");

        assert!(error
            .to_string()
            .contains("Windows SMB server is unavailable on host loopback port 445"));
        assert_eq!(log.snapshot(), ["admin", "smb_loopback"]);
    }

    #[test]
    fn smb_policy_preflight_failure_creates_nothing() {
        let log = EventLog::default();
        let mut manager = WindowsSmbLifecycleManager::new(
            PolicyFailAdmin { log: log.clone() },
            FakePasswords::new(log.clone(), [vec![0, 1, 2, 3, 4, 5]]),
            FakeUsers {
                log: log.clone(),
                create_fail: false,
                delete_fail: false,
            },
            FakeAcls {
                log: log.clone(),
                fail_grant_index: None,
                fail_revoke: false,
                grants: 0,
                entries_per_grant: 1,
            },
            FakeShares {
                log: log.clone(),
                fail_create_index: None,
                fail_remove: false,
                creates: 0,
            },
        );

        let error = manager
            .prepare(&config())
            .expect_err("SMB policy preflight should fail");

        assert!(matches!(
            error,
            WindowsSmbLifecycleError::OperationFailed {
                phase: WindowsSmbLifecyclePhase::SmbPolicyPreflight,
                ..
            }
        ));
        assert_eq!(log.snapshot(), ["admin", "smb_policy"]);
    }

    #[test]
    fn generated_names_respect_windows_limits_and_character_rules() {
        let log = EventLog::default();
        let mut passwords = FakePasswords::new(
            log,
            [vec![0xde, 0xad, 0xbe, 0xef, 0x10, 0x20], vec![1, 2, 3, 4]],
        );

        let user = generate_smb_user_name(&mut passwords).expect("user name");
        assert_eq!(user.as_str(), "lsb_deadbeef1020");
        assert!(user.as_str().len() <= 20);

        let share = generate_smb_share_name(
            "Bad Chars: /Tenant_With_A_Very_Long_Name",
            42,
            &mut passwords,
        )
        .expect("share name");
        assert_eq!(share.as_str(), "lsb-badcharstenantwi-m42-01020304");
        assert!(share.as_str().len() <= 80);

        assert!(validate_smb_user_name("lsb_valid123").is_ok());
        assert!(validate_smb_user_name("lsb_bad-name").is_err());
        assert!(validate_smb_user_name("lsb_12345678901234567890").is_err());
        assert!(validate_smb_share_name("lsb-good-m0-deadbeef").is_ok());
        assert!(validate_smb_share_name("lsb-bad,path").is_err());
        assert!(validate_smb_share_name("ADMIN$").is_err());
    }

    #[test]
    fn password_generation_policy_and_formatting_redact_secret() {
        let mut generator = NativeWindowsSmbPasswordGenerator;
        let password = generator.generate_password().expect("password");
        let secret = password.expose_secret_for_tests().to_string();

        assert_eq!(secret.len(), 32);
        assert!(secret.chars().any(|ch| ch.is_ascii_uppercase()));
        assert!(secret.chars().any(|ch| ch.is_ascii_lowercase()));
        assert!(secret.chars().any(|ch| ch.is_ascii_digit()));
        assert!(secret.chars().any(|ch| !ch.is_ascii_alphanumeric()));
        assert!(!secret.chars().any(|ch| ch.is_whitespace() || ch == ','));

        let debug = format!("{password:?}");
        let display = password.to_string();
        assert!(!debug.contains(&secret));
        assert!(!display.contains(&secret));
        assert!(debug.contains("<redacted>"));
        assert_eq!(display, "<redacted>");
    }
}
