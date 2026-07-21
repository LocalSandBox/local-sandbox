use std::os::windows::io::OwnedHandle;
use std::path::PathBuf;
use std::sync::mpsc;

use anyhow::{Context, Result};

use crate::resource::mount::ProtectedStagingRoot;
use crate::security::impersonation::ImpersonationGuard;

use super::identity::{AuthorizedMountRoot, MountAccess};
use super::policy::MountPolicy;
use super::ExportOptions;
use crate::resource::mount_sync::{EntryFingerprint, SyncDirection, SyncOperation, TreeSnapshot};

enum Command {
    Authorize {
        path: PathBuf,
        access: MountAccess,
        owner_sid: String,
        reply: mpsc::SyncSender<Result<AuthorizedMountRoot>>,
    },
    StageSnapshot {
        root_pin: OwnedHandle,
        source: PathBuf,
        final_root: PathBuf,
        destination: PathBuf,
        reply: mpsc::SyncSender<Result<TreeSnapshot>>,
    },
    SnapshotHost {
        root_pin: OwnedHandle,
        reply: mpsc::SyncSender<Result<TreeSnapshot>>,
    },
    SnapshotProtected {
        root_pin: OwnedHandle,
        reply: mpsc::SyncSender<Result<TreeSnapshot>>,
    },
    ImportOperation {
        root_pin: OwnedHandle,
        staging_root_pin: OwnedHandle,
        relative: PathBuf,
        desired: Option<EntryFingerprint>,
        reply: mpsc::SyncSender<Result<()>>,
    },
    ExportOperation {
        root_pin: OwnedHandle,
        staging_root_pin: OwnedHandle,
        relative: PathBuf,
        desired: Option<EntryFingerprint>,
        reply: mpsc::SyncSender<Result<()>>,
    },
    ExportFile {
        root_pin: OwnedHandle,
        staging_root_pin: OwnedHandle,
        relative_source: PathBuf,
        relative_destination: PathBuf,
        options: ExportOptions,
        reply: mpsc::SyncSender<Result<u64>>,
    },
    Stop,
}

pub struct PathWorker {
    commands: mpsc::SyncSender<Command>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl PathWorker {
    pub fn start(token: OwnedHandle, policy: MountPolicy) -> Result<Self> {
        let (commands, receiver) = mpsc::sync_channel(8);
        let thread = std::thread::Builder::new()
            .name("lsbsw-client-fs".to_string())
            .spawn(move || run(token, policy, receiver))
            .context("spawn client filesystem worker")?;
        Ok(Self {
            commands,
            thread: Some(thread),
        })
    }

    pub fn authorize_mount(
        &self,
        path: PathBuf,
        access: MountAccess,
        owner_sid: String,
    ) -> Result<AuthorizedMountRoot> {
        let (reply, response) = mpsc::sync_channel(1);
        self.commands
            .send(Command::Authorize {
                path,
                access,
                owner_sid,
                reply,
            })
            .context("filesystem worker stopped")?;
        response.recv().context("filesystem worker lost reply")?
    }

    pub fn stage_snapshot(
        &self,
        authorized: &AuthorizedMountRoot,
        destination: PathBuf,
    ) -> Result<TreeSnapshot> {
        let (reply, response) = mpsc::sync_channel(1);
        self.commands
            .send(Command::StageSnapshot {
                root_pin: authorized.duplicate_root_handle()?,
                source: authorized.requested_path().to_path_buf(),
                final_root: authorized.identity().final_path.clone(),
                destination,
                reply,
            })
            .context("filesystem worker stopped")?;
        response.recv().context("filesystem worker lost reply")?
    }

    pub fn export_file(
        &self,
        authorized: &AuthorizedMountRoot,
        protected: &ProtectedStagingRoot,
        relative_source: PathBuf,
        relative_destination: PathBuf,
        options: ExportOptions,
    ) -> Result<u64> {
        if authorized.access() != MountAccess::ReadWrite {
            anyhow::bail!("writeback requires a read-write mount capability");
        }
        let (reply, response) = mpsc::sync_channel(1);
        self.commands
            .send(Command::ExportFile {
                root_pin: authorized.duplicate_root_handle()?,
                staging_root_pin: protected.duplicate_root_handle()?,
                relative_source,
                relative_destination,
                options,
                reply,
            })
            .context("filesystem worker stopped")?;
        response.recv().context("filesystem worker lost reply")?
    }

    pub fn snapshot_host(&self, authorized: &AuthorizedMountRoot) -> Result<TreeSnapshot> {
        let (reply, response) = mpsc::sync_channel(1);
        self.commands
            .send(Command::SnapshotHost {
                root_pin: authorized.duplicate_root_handle()?,
                reply,
            })
            .context("filesystem worker stopped")?;
        response.recv().context("filesystem worker lost reply")?
    }

    pub fn snapshot_protected(&self, protected: &ProtectedStagingRoot) -> Result<TreeSnapshot> {
        let (reply, response) = mpsc::sync_channel(1);
        self.commands
            .send(Command::SnapshotProtected {
                root_pin: protected.duplicate_root_handle()?,
                reply,
            })
            .context("filesystem worker stopped")?;
        response.recv().context("filesystem worker lost reply")?
    }

    pub fn import_operation(
        &self,
        authorized: &AuthorizedMountRoot,
        protected: &ProtectedStagingRoot,
        operation: &SyncOperation,
    ) -> Result<()> {
        if operation.direction != SyncDirection::ImportHost {
            anyhow::bail!("host import requires an import reconciliation operation");
        }
        let (reply, response) = mpsc::sync_channel(1);
        self.commands
            .send(Command::ImportOperation {
                root_pin: authorized.duplicate_root_handle()?,
                staging_root_pin: protected.duplicate_root_handle()?,
                relative: operation.relative.clone(),
                desired: operation.desired.clone(),
                reply,
            })
            .context("filesystem worker stopped")?;
        response.recv().context("filesystem worker lost reply")?
    }

    pub fn export_operation(
        &self,
        authorized: &AuthorizedMountRoot,
        protected: &ProtectedStagingRoot,
        operation: &SyncOperation,
    ) -> Result<()> {
        if operation.direction != SyncDirection::ExportGuest {
            anyhow::bail!("guest export requires an export reconciliation operation");
        }
        if authorized.access() != MountAccess::ReadWrite {
            anyhow::bail!("guest export requires a read-write mount capability");
        }
        let (reply, response) = mpsc::sync_channel(1);
        self.commands
            .send(Command::ExportOperation {
                root_pin: authorized.duplicate_root_handle()?,
                staging_root_pin: protected.duplicate_root_handle()?,
                relative: operation.relative.clone(),
                desired: operation.desired.clone(),
                reply,
            })
            .context("filesystem worker stopped")?;
        response.recv().context("filesystem worker lost reply")?
    }
}

impl Drop for PathWorker {
    fn drop(&mut self) {
        let _ = self.commands.send(Command::Stop);
        if self
            .thread
            .take()
            .is_some_and(|thread| thread.join().is_err())
        {
            std::process::abort();
        }
    }
}

fn run(token: OwnedHandle, policy: MountPolicy, commands: mpsc::Receiver<Command>) {
    while let Ok(command) = commands.recv() {
        match command {
            Command::Authorize {
                path,
                access,
                owner_sid,
                reply,
            } => {
                let result = authorize_once(&token, &policy, path, access, owner_sid);
                let _ = reply.send(result);
            }
            Command::StageSnapshot {
                root_pin,
                source,
                final_root,
                destination,
                reply,
            } => {
                let result = super::walk::stage_snapshot(
                    &token,
                    root_pin,
                    &source,
                    &final_root,
                    &destination,
                );
                let _ = reply.send(result);
            }
            Command::SnapshotHost { root_pin, reply } => {
                let result = snapshot_host_once(&token, root_pin);
                let _ = reply.send(result);
            }
            Command::SnapshotProtected { root_pin, reply } => {
                let result = super::snapshot::protected_tree(root_pin);
                let _ = reply.send(result);
            }
            Command::ImportOperation {
                root_pin,
                staging_root_pin,
                relative,
                desired,
                reply,
            } => {
                let result = super::import::apply_host_import(
                    &token,
                    &root_pin,
                    &staging_root_pin,
                    &relative,
                    desired.as_ref(),
                );
                let _ = reply.send(result);
            }
            Command::ExportOperation {
                root_pin,
                staging_root_pin,
                relative,
                desired,
                reply,
            } => {
                let result = export_operation_once(
                    &token,
                    &root_pin,
                    &staging_root_pin,
                    &relative,
                    desired.as_ref(),
                );
                let _ = reply.send(result);
            }
            Command::ExportFile {
                root_pin,
                staging_root_pin,
                relative_source,
                relative_destination,
                options,
                reply,
            } => {
                let result = export_once(
                    &token,
                    &root_pin,
                    &staging_root_pin,
                    &relative_source,
                    &relative_destination,
                    options,
                );
                let _ = reply.send(result);
            }
            Command::Stop => return,
        }
    }
}

fn snapshot_host_once(token: &OwnedHandle, root_pin: OwnedHandle) -> Result<TreeSnapshot> {
    let guard = ImpersonationGuard::for_token(token)?;
    let result = super::snapshot::host_tree(token, root_pin);
    guard.revert().context("revert filesystem worker token")?;
    result
}

fn export_operation_once(
    token: &OwnedHandle,
    root_pin: &OwnedHandle,
    staging_root_pin: &OwnedHandle,
    relative: &std::path::Path,
    desired: Option<&EntryFingerprint>,
) -> Result<()> {
    let components = super::import::relative_components(relative)?;
    match desired {
        None => {
            super::export::require_protected_absent(staging_root_pin, relative)?;
            let guard = ImpersonationGuard::for_token(token)?;
            let result = super::import::delete_target(root_pin, &components);
            guard.revert().context("revert export operation token")?;
            result
        }
        Some(entry) if entry.directory => {
            super::export::require_protected_directory(staging_root_pin, relative, entry.len)?;
            let guard = ImpersonationGuard::for_token(token)?;
            let result = super::import::ensure_target_directory(root_pin, &components);
            guard.revert().context("revert export operation token")?;
            result
        }
        Some(entry) => {
            let expected_hash = entry
                .content_hash
                .context("guest export file fingerprint lacks a content hash")?;
            let mut source = super::export::open_protected_source(staging_root_pin, relative)?;
            let metadata = source.metadata()?;
            if !metadata.is_file() || metadata.len() != entry.len {
                anyhow::bail!("protected export source changed after observation");
            }
            let guard = ImpersonationGuard::for_token(token)?;
            let result = super::export::export_planned_file_under_client_token(
                &mut source,
                metadata.len(),
                metadata.modified()?,
                expected_hash,
                root_pin,
                relative,
            )
            .map(|_| ());
            guard.revert().context("revert export operation token")?;
            result
        }
    }
}

fn export_once(
    token: &OwnedHandle,
    root_pin: &OwnedHandle,
    staging_root_pin: &OwnedHandle,
    relative_source: &std::path::Path,
    relative_destination: &std::path::Path,
    options: ExportOptions,
) -> Result<u64> {
    let mut source = super::export::open_protected_source(staging_root_pin, relative_source)?;
    let metadata = source.metadata()?;
    if !metadata.is_file() {
        anyhow::bail!("opened protected export source is not a regular file");
    }
    let guard = ImpersonationGuard::for_token(token)?;
    let result = super::export::export_open_file_under_client_token(
        &mut source,
        metadata.len(),
        metadata.modified()?,
        root_pin,
        relative_destination,
        options,
    );
    guard.revert().context("revert filesystem worker token")?;
    result
}

fn authorize_once(
    token: &OwnedHandle,
    policy: &MountPolicy,
    path: PathBuf,
    access: MountAccess,
    owner_sid: String,
) -> Result<AuthorizedMountRoot> {
    let guard = ImpersonationGuard::for_token(token)?;
    let result = super::walk::authorize(token, policy, path, access, owner_sid);
    guard.revert().context("revert filesystem worker token")?;
    result
}

#[allow(dead_code)]
fn require_send<T: Send>() {}

#[test]
fn worker_commands_and_capability_are_send() {
    require_send::<Command>();
    require_send::<AuthorizedMountRoot>();
    require_send::<ProtectedStagingRoot>();
}

#[cfg(test)]
mod export_operation_tests {
    use super::*;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::path::Path;
    use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::{
        DuplicateTokenEx, SecurityImpersonation, TokenImpersonation, TOKEN_DUPLICATE,
        TOKEN_IMPERSONATE, TOKEN_QUERY,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_DELETE_CHILD,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY,
        FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, SYNCHRONIZE,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    #[test]
    fn exports_planned_namespace_changes_under_the_caller_token() {
        let root = unique_path("export-operation");
        let host = root.join("host");
        let stage = root.join("stage");
        std::fs::create_dir_all(stage.join("newdir")).unwrap();
        std::fs::create_dir_all(stage.join("type-dir")).unwrap();
        std::fs::write(stage.join("newdir").join("file.txt"), b"new file").unwrap();
        std::fs::write(stage.join("replace.txt"), b"replacement").unwrap();
        std::fs::write(stage.join("bad.txt"), b"planned").unwrap();
        std::fs::create_dir_all(host.join("gone")).unwrap();
        std::fs::write(host.join("gone").join("child.txt"), b"gone").unwrap();
        std::fs::write(host.join("type-dir"), b"old type").unwrap();
        std::fs::write(host.join("replace.txt"), b"old").unwrap();

        let host_root = open_root(&host, target_access());
        let stage_root = open_root(
            &stage,
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        );
        let token = current_impersonation_token();
        let directory = EntryFingerprint {
            directory: true,
            len: 0,
            modified_ns: 0,
            content_hash: None,
        };
        let file = |contents: &[u8]| EntryFingerprint {
            directory: false,
            len: contents.len() as u64,
            modified_ns: 0,
            content_hash: Some(*blake3::hash(contents).as_bytes()),
        };

        for relative in ["gone/child.txt", "gone"] {
            export_operation_once(&token, &host_root, &stage_root, Path::new(relative), None)
                .unwrap();
        }
        for relative in ["newdir", "type-dir"] {
            export_operation_once(
                &token,
                &host_root,
                &stage_root,
                Path::new(relative),
                Some(&directory),
            )
            .unwrap();
        }
        for (relative, contents) in [
            ("newdir/file.txt", b"new file".as_slice()),
            ("replace.txt", b"replacement".as_slice()),
        ] {
            let fingerprint = file(contents);
            export_operation_once(
                &token,
                &host_root,
                &stage_root,
                Path::new(relative),
                Some(&fingerprint),
            )
            .unwrap();
        }

        let wrong_hash = EntryFingerprint {
            content_hash: Some(*blake3::hash(b"wrong!!").as_bytes()),
            ..file(b"planned")
        };
        assert!(export_operation_once(
            &token,
            &host_root,
            &stage_root,
            Path::new("bad.txt"),
            Some(&wrong_hash),
        )
        .is_err());
        assert!(!host.join("bad.txt").exists());
        std::fs::remove_file(stage.join("bad.txt")).unwrap();

        let host_snapshot =
            super::super::snapshot::protected_tree(host_root.try_clone().unwrap()).unwrap();
        let stage_snapshot =
            super::super::snapshot::protected_tree(stage_root.try_clone().unwrap()).unwrap();
        assert_eq!(normalized(host_snapshot), normalized(stage_snapshot));
        assert!(std::fs::read_dir(&host).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".tmp")));

        drop(stage_root);
        drop(host_root);
        std::fs::remove_dir_all(root).unwrap();
    }

    fn normalized(
        mut snapshot: crate::resource::mount_sync::TreeSnapshot,
    ) -> crate::resource::mount_sync::TreeSnapshot {
        for entry in snapshot.entries.values_mut() {
            entry.modified_ns = 0;
        }
        snapshot
    }

    fn target_access() -> u32 {
        FILE_LIST_DIRECTORY
            | FILE_ADD_FILE
            | FILE_ADD_SUBDIRECTORY
            | FILE_DELETE_CHILD
            | FILE_READ_ATTRIBUTES
            | DELETE
            | SYNCHRONIZE
    }

    fn open_root(path: &Path, access: u32) -> OwnedHandle {
        let wide = path
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(raw, INVALID_HANDLE_VALUE);
        unsafe { OwnedHandle::from_raw_handle(raw as _) }
    }

    fn current_impersonation_token() -> OwnedHandle {
        let mut primary = std::ptr::null_mut();
        assert_ne!(
            unsafe {
                OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_QUERY | TOKEN_DUPLICATE,
                    &mut primary,
                )
            },
            0
        );
        let primary = unsafe { OwnedHandle::from_raw_handle(primary as _) };
        let mut impersonation = std::ptr::null_mut();
        assert_ne!(
            unsafe {
                DuplicateTokenEx(
                    primary.as_raw_handle() as HANDLE,
                    TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
                    std::ptr::null(),
                    SecurityImpersonation,
                    TokenImpersonation,
                    &mut impersonation,
                )
            },
            0
        );
        unsafe { OwnedHandle::from_raw_handle(impersonation as _) }
    }

    fn unique_path(label: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("target")
            .join(format!(
                "lsbsw-{label}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ))
    }
}
