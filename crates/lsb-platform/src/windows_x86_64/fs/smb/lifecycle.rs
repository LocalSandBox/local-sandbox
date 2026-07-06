use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use lsb_proto::MountRequest;
use serde::{Deserialize, Serialize};

use super::acl::{WindowsSmbAclGrant, WindowsSmbAclGrantRequest, WindowsSmbAclManager};
use super::admin::WindowsSmbAdmin;
use super::password::{WindowsSmbPassword, WindowsSmbPasswordGenerator};
use super::share::{
    WindowsSmbShare, WindowsSmbShareCreateRequest, WindowsSmbShareManager, WindowsSmbShareName,
};
use super::types::{
    generate_smb_share_name, generate_smb_user_name, WindowsSmbCleanupFailure,
    WindowsSmbLifecycleConfig, WindowsSmbLifecycleError, WindowsSmbLifecyclePhase,
};
use super::user::{WindowsSmbUserAccount, WindowsSmbUserManager, WindowsSmbUserName};

pub const WINDOWS_SMB_CLEANUP_MANIFEST_FILE: &str = "windows-smb-cleanup.json";

pub struct WindowsSmbLifecycleManager<A, P, U, L, S> {
    admin: A,
    passwords: P,
    users: U,
    acls: L,
    shares: S,
}

impl<A, P, U, L, S> WindowsSmbLifecycleManager<A, P, U, L, S> {
    pub fn new(admin: A, passwords: P, users: U, acls: L, shares: S) -> Self {
        Self {
            admin,
            passwords,
            users,
            acls,
            shares,
        }
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
        self.admin.ensure_elevated_admin()?;
        self.admin.ensure_smb_loopback_available()?;

        let user_name = generate_smb_user_name(&mut self.passwords)?;
        let password = self.passwords.generate_password()?;
        let account = self.users.create_user(&user_name, &password)?;

        let mut acl_grants = Vec::new();
        let mut shares = Vec::new();
        let mut mount_requests = Vec::new();

        for mount in &config.mounts {
            let grant = match self.acls.grant_access(WindowsSmbAclGrantRequest {
                path: mount.source.clone(),
                account: account.clone(),
                access: mount.access,
            }) {
                Ok(grant) => grant,
                Err(error) => {
                    let failures = self.cleanup_created(&account, &mut shares, &mut acl_grants);
                    return Err(error.with_cleanup_failures(failures));
                }
            };
            acl_grants.push(grant);
        }

        for (index, mount) in config.mounts.iter().enumerate() {
            let share_name =
                match generate_smb_share_name(&config.instance_id, index, &mut self.passwords) {
                    Ok(name) => name,
                    Err(error) => {
                        let failures = self.cleanup_created(&account, &mut shares, &mut acl_grants);
                        return Err(error.with_cleanup_failures(failures));
                    }
                };
            let share = match self.shares.create_share(WindowsSmbShareCreateRequest {
                name: share_name,
                path: mount.source.clone(),
                account: account.clone(),
                access: mount.access,
            }) {
                Ok(share) => share,
                Err(error) => {
                    let failures = self.cleanup_created(&account, &mut shares, &mut acl_grants);
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
        let manifest = read_windows_smb_cleanup_manifest(path)?;
        let resources = manifest.into_active_resources()?;
        self.cleanup(resources)?;
        remove_windows_smb_cleanup_manifest(path)
    }

    fn cleanup_created(
        &mut self,
        account: &WindowsSmbUserAccount,
        shares: &mut Vec<WindowsSmbShare>,
        acl_grants: &mut Vec<WindowsSmbAclGrant>,
    ) -> Vec<WindowsSmbCleanupFailure> {
        let mut failures = Vec::new();

        while let Some(share) = shares.pop() {
            if let Err(error) = self.shares.remove_share(&share) {
                failures.push(WindowsSmbCleanupFailure::new(
                    WindowsSmbLifecyclePhase::ShareRemove,
                    error.to_string(),
                ));
            }
        }

        while let Some(grant) = acl_grants.pop() {
            if let Err(error) = self.acls.revoke_access(&grant) {
                failures.push(WindowsSmbCleanupFailure::new(
                    WindowsSmbLifecyclePhase::AclRevoke,
                    error.to_string(),
                ));
            }
        }

        if let Err(error) = self.users.delete_user(account) {
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
    pub domain: String,
    pub principal: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowsSmbCleanupAclGrant {
    pub path: PathBuf,
    pub principal: String,
    pub access: super::types::WindowsSmbAccess,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowsSmbCleanupShare {
    pub name: String,
    pub path: PathBuf,
    pub principal: String,
    pub access: super::types::WindowsSmbAccess,
}

impl WindowsSmbCleanupManifest {
    pub fn from_active_resources(
        instance_id: impl Into<String>,
        resources: &WindowsSmbActiveResources,
    ) -> Self {
        Self {
            schema_version: 1,
            instance_id: instance_id.into(),
            account: WindowsSmbCleanupAccount {
                name: resources.account.name.as_str().to_string(),
                domain: resources.account.domain.clone(),
                principal: resources.account.principal.clone(),
            },
            acl_grants: resources
                .acl_grants
                .iter()
                .map(|grant| WindowsSmbCleanupAclGrant {
                    path: grant.path.clone(),
                    principal: grant.principal.clone(),
                    access: grant.access,
                })
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
        if self.schema_version != 1 {
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
            },
            acl_grants: self
                .acl_grants
                .into_iter()
                .map(|grant| WindowsSmbAclGrant {
                    path: grant.path,
                    principal: grant.principal,
                    access: grant.access,
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
    let json = serde_json::to_vec_pretty(&manifest).map_err(|error| {
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
    fs::write(&temp_path, json).map_err(|error| {
        WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::CleanupManifest,
            format!(
                "failed to write cleanup manifest '{}': {error}",
                temp_path.display()
            ),
        )
    })?;
    if path.exists() {
        fs::remove_file(path).map_err(|error| {
            WindowsSmbLifecycleError::operation_failed(
                WindowsSmbLifecyclePhase::CleanupManifest,
                format!(
                    "failed to replace cleanup manifest '{}': {error}",
                    path.display()
                ),
            )
        })?;
    }
    fs::rename(&temp_path, path).map_err(|error| {
        WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::CleanupManifest,
            format!(
                "failed to commit cleanup manifest '{}': {error}",
                path.display()
            ),
        )
    })
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
        Err(error) => Err(WindowsSmbLifecycleError::operation_failed(
            WindowsSmbLifecyclePhase::CleanupManifest,
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
        server: account.domain.clone(),
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
    }

    impl WindowsSmbAclManager for FakeAcls {
        fn grant_access(
            &mut self,
            request: WindowsSmbAclGrantRequest,
        ) -> Result<WindowsSmbAclGrant, WindowsSmbLifecycleError> {
            let index = self.grants;
            self.grants += 1;
            self.log
                .push(format!("grant_acl:{index}:{}", request.path.display()));
            if self.fail_grant_index == Some(index) {
                return Err(WindowsSmbLifecycleError::operation_failed(
                    WindowsSmbLifecyclePhase::AclGrant,
                    "grant failed",
                ));
            }
            Ok(WindowsSmbAclGrant {
                path: request.path,
                principal: request.account.principal,
                access: request.access,
            })
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
            } if server == "WINHOST"
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
        let resources = prepare_manager
            .prepare(&config())
            .expect("prepare succeeds");
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
        assert_eq!(manifest.schema_version, 1);
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
    fn cleanup_continues_after_individual_failures() {
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
        assert_eq!(error.cleanup_failures().len(), 5);
        assert_eq!(
            log.snapshot().last().expect("last event"),
            "delete_user:lsb_000102030405"
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
