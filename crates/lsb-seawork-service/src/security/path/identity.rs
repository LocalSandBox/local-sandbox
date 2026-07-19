use std::os::windows::io::{AsRawHandle, OwnedHandle, RawHandle};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountAccess {
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountBackend {
    StagedSync,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileIdentity {
    pub volume_serial: u32,
    pub file_index: u64,
    pub final_path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalkSummary {
    pub entries: u32,
    pub file_bytes: u64,
    pub access_checks: u32,
}

pub struct AuthorizedMountRoot {
    root: OwnedHandle,
    _ancestor_pins: Vec<OwnedHandle>,
    requested_path: PathBuf,
    identity: FileIdentity,
    owner_sid: String,
    access: MountAccess,
    backend: MountBackend,
    summary: WalkSummary,
}

impl AuthorizedMountRoot {
    pub(super) fn new(
        root: OwnedHandle,
        ancestor_pins: Vec<OwnedHandle>,
        requested_path: PathBuf,
        identity: FileIdentity,
        owner_sid: String,
        access: MountAccess,
        summary: WalkSummary,
    ) -> Self {
        Self {
            root,
            _ancestor_pins: ancestor_pins,
            requested_path,
            identity,
            owner_sid,
            access,
            backend: MountBackend::StagedSync,
            summary,
        }
    }

    pub fn requested_path(&self) -> &Path {
        &self.requested_path
    }

    pub fn identity(&self) -> &FileIdentity {
        &self.identity
    }

    pub fn owner_sid(&self) -> &str {
        &self.owner_sid
    }

    pub fn access(&self) -> MountAccess {
        self.access
    }

    pub fn backend(&self) -> MountBackend {
        self.backend
    }

    pub fn summary(&self) -> WalkSummary {
        self.summary
    }

    pub fn raw_root_handle(&self) -> RawHandle {
        self.root.as_raw_handle()
    }

    pub fn duplicate_root_handle(&self) -> std::io::Result<OwnedHandle> {
        self.root.try_clone()
    }
}

impl std::fmt::Debug for AuthorizedMountRoot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorizedMountRoot")
            .field("requested_path", &self.requested_path)
            .field("identity", &self.identity)
            .field("owner_sid", &self.owner_sid)
            .field("access", &self.access)
            .field("backend", &self.backend)
            .field("summary", &self.summary)
            .finish_non_exhaustive()
    }
}
