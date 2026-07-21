use std::os::windows::io::OwnedHandle;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Result};

use crate::ledger::schema::ResourceRecord;
use crate::security::path::{AuthorizedMountRoot, MountBackend, PathWorker};

use super::mount_sync::StagedReconciler;
use super::transaction::ResourceTransaction;

pub struct StagedMount {
    pub mount_id: String,
    pub staging_root: PathBuf,
    protected_root: ProtectedStagingRoot,
    pub reconciliation: StagedReconciler,
    pub backend: MountBackend,
}

impl StagedMount {
    pub fn prepare(
        authorized: &AuthorizedMountRoot,
        worker: &PathWorker,
        protected_instance_root: &Path,
        mount_id: &str,
        transaction: &mut ResourceTransaction,
    ) -> Result<Self> {
        require_hex_id(mount_id)?;
        if !protected_instance_root.is_absolute() {
            bail!("protected instance root must be absolute");
        }
        let relative = PathBuf::from("mounts").join(mount_id);
        let staging_root = protected_instance_root.join(&relative);
        let identity = authorized.identity();
        let root_intent = transaction.intent(ResourceRecord::AuthorizedMountRoot {
            mount_id: mount_id.to_string(),
            volume_serial: identity.volume_serial,
            file_index: format!("{:016x}", identity.file_index),
            final_path: identity.final_path.display().to_string(),
            access: format!("{:?}", authorized.access()).to_lowercase(),
            backend: "staged_sync".to_string(),
            committed: false,
        })?;
        transaction.commit(root_intent)?;
        let staging_intent = transaction.intent(ResourceRecord::StagingRoot {
            relative_path: relative.display().to_string(),
            file_id: "pending".to_string(),
            committed: false,
        })?;
        worker.stage_snapshot(authorized, staging_root.clone())?;
        let protected_root = ProtectedStagingRoot::open(&staging_root)?;
        let baseline = worker.snapshot_protected(&protected_root)?;
        transaction.replace_and_commit(
            staging_intent,
            ResourceRecord::StagingRoot {
                relative_path: relative.display().to_string(),
                file_id: protected_root.ledger_identity().to_string(),
                committed: true,
            },
        )?;
        Ok(Self {
            mount_id: mount_id.to_string(),
            staging_root,
            protected_root,
            reconciliation: StagedReconciler::new(baseline, Duration::ZERO)?,
            backend: MountBackend::StagedSync,
        })
    }

    pub fn protected_root(&self) -> &ProtectedStagingRoot {
        &self.protected_root
    }
}

pub struct ProtectedStagingRoot {
    root: OwnedHandle,
    ledger_identity: String,
}

impl ProtectedStagingRoot {
    fn open(path: &Path) -> Result<Self> {
        if !path.is_absolute() {
            bail!("protected staging root must be absolute");
        }
        let (root, info) = open_protected_directory(path)?;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_ENCRYPTED, FILE_ATTRIBUTE_OFFLINE,
            FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, FILE_ATTRIBUTE_RECALL_ON_OPEN,
            FILE_ATTRIBUTE_REPARSE_POINT,
        };
        let denied = FILE_ATTRIBUTE_REPARSE_POINT
            | FILE_ATTRIBUTE_ENCRYPTED
            | FILE_ATTRIBUTE_OFFLINE
            | FILE_ATTRIBUTE_RECALL_ON_OPEN
            | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;
        if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
            || info.dwFileAttributes & denied != 0
        {
            bail!("protected staging root has an unsafe type or attributes");
        }
        Ok(Self {
            root,
            ledger_identity: format!(
                "{:08x}:{:016x}",
                info.dwVolumeSerialNumber,
                ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64
            ),
        })
    }

    pub fn ledger_identity(&self) -> &str {
        &self.ledger_identity
    }

    pub(crate) fn duplicate_root_handle(&self) -> std::io::Result<OwnedHandle> {
        self.root.try_clone()
    }
}

impl std::fmt::Debug for ProtectedStagingRoot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProtectedStagingRoot")
            .field("ledger_identity", &self.ledger_identity)
            .finish_non_exhaustive()
    }
}

pub(crate) fn protected_identity(path: &Path) -> Result<String> {
    let (_handle, info) = open_protected_directory(path)?;
    Ok(format!(
        "{:08x}:{:016x}",
        info.dwVolumeSerialNumber,
        ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64
    ))
}

fn open_protected_directory(
    path: &Path,
) -> Result<(
    OwnedHandle,
    windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION,
)> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, GetFileInformationByHandle, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING, SYNCHRONIZE,
    };

    let wide = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error().into());
    }
    let handle = unsafe { OwnedHandle::from_raw_handle(raw as _) };
    let mut info = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(handle.as_raw_handle() as _, &mut info) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok((handle, info))
}

fn require_hex_id(value: &str) -> Result<()> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("mount id must be 32 lowercase hexadecimal characters");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_staging_capability_pins_the_committed_directory_identity() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("target")
            .join(format!(
                "lsbsw-staging-pin-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
        std::fs::create_dir_all(&root).unwrap();
        let protected = ProtectedStagingRoot::open(&root).unwrap();
        assert_eq!(
            protected.ledger_identity(),
            protected_identity(&root).unwrap()
        );
        assert!(std::fs::remove_dir(&root).is_err());
        drop(protected);
        std::fs::remove_dir(root).unwrap();
    }
}
