use std::os::windows::io::OwnedHandle;
use std::path::PathBuf;
use std::sync::mpsc;

use anyhow::{Context, Result};

use crate::resource::mount::ProtectedStagingRoot;
use crate::security::impersonation::ImpersonationGuard;

use super::identity::{AuthorizedMountRoot, MountAccess};
use super::policy::MountPolicy;
use super::ExportOptions;
use crate::resource::mount_sync::TreeSnapshot;

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
