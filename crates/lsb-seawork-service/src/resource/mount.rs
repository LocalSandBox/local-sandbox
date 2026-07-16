use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

use crate::ledger::schema::ResourceRecord;
use crate::security::path::{AuthorizedMountRoot, MountBackend, PathWorker};

use super::mount_sync::TreeSnapshot;
use super::transaction::ResourceTransaction;

pub struct StagedMount {
    pub mount_id: String,
    pub staging_root: PathBuf,
    pub baseline: TreeSnapshot,
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
        let baseline = worker.stage_snapshot(authorized, staging_root.clone())?;
        transaction.replace_and_commit(
            staging_intent,
            ResourceRecord::StagingRoot {
                relative_path: relative.display().to_string(),
                file_id: protected_identity(&staging_root)?,
                committed: true,
            },
        )?;
        Ok(Self {
            mount_id: mount_id.to_string(),
            staging_root,
            baseline,
            backend: MountBackend::StagedSync,
        })
    }
}

fn protected_identity(path: &Path) -> Result<String> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, GetFileInformationByHandle, FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };

    let wide = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
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
    Ok(format!(
        "{:08x}:{:016x}",
        info.dwVolumeSerialNumber,
        ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64
    ))
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
