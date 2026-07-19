use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use lsb_service_proto::{
    ErrorCode, ResponseValue, ServiceMountSpec, ServiceNetworkSpec, ServicePortSpec,
};
use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

use crate::engine::ServiceEngineConfig;
use crate::resource::vm::ManagedVmSpec;
use crate::session::{
    CancellationToken, ClientIdentityKey, QuotaError, ResourceHandle, SandboxResources,
    SessionManager,
};

#[allow(clippy::too_many_arguments)]
pub async fn start(
    admissions_open: bool,
    engine: Option<ServiceEngineConfig>,
    sessions: SessionManager,
    session_id: ResourceHandle,
    identity: ClientIdentityKey,
    protected_egress_allow: Vec<String>,
    _client_instance_id: Option<String>,
    from: Option<String>,
    cpus: u16,
    memory_mib: u32,
    disk_mib: u32,
    mounts: Vec<ServiceMountSpec>,
    ports: Vec<ServicePortSpec>,
    network: Option<ServiceNetworkSpec>,
    cancellation: CancellationToken,
) -> Result<ResponseValue, ErrorCode> {
    if from.is_some() {
        return Err(ErrorCode::CheckpointUnsupported);
    }
    let proxy_config = network
        .map(|policy| crate::network_policy::build_proxy_config(policy, protected_egress_allow))
        .transpose()
        .map_err(|_| ErrorCode::InvalidRequest)?;
    if !admissions_open {
        return Err(ErrorCode::ServiceUnavailable);
    }
    if !mounts.is_empty() {
        return Err(ErrorCode::MountUnavailable);
    }
    if !ports.is_empty() {
        return Err(ErrorCode::PortIsolationUnavailable);
    }
    let engine = engine.ok_or(ErrorCode::BundleInvalid)?;
    let requested_bytes = u64::from(disk_mib) * 1024 * 1024;
    let base_bytes = std::fs::metadata(engine.base_rootfs())
        .map_err(|_| ErrorCode::BundleInvalid)?
        .len();
    if requested_bytes < base_bytes {
        return Err(ErrorCode::InvalidRequest);
    }
    let free_bytes =
        available_disk_bytes(engine.resources_root()).map_err(|_| ErrorCode::ServiceUnavailable)?;
    if requested_bytes > free_bytes {
        return Err(ErrorCode::QuotaExceeded);
    }
    let sandbox_id = sessions
        .reserve_managed_vm(
            session_id,
            &identity,
            SandboxResources {
                cpus,
                memory_mib,
                disk_mib,
            },
        )
        .map_err(|error| {
            if error.downcast_ref::<QuotaError>().is_some() {
                ErrorCode::QuotaExceeded
            } else {
                ErrorCode::ResourceNotFound
            }
        })?;
    let cleanup_sessions = sessions.clone();
    let cleanup_identity = identity.clone();
    let cleanup_engine = engine.clone();
    let cleanup_instance_dir = engine
        .resources_root()
        .join(identity_hash(&identity))
        .join("instances")
        .join(sandbox_id.to_string());
    let result = tokio::task::spawn_blocking(move || {
        let spec = match prepare_instance(
            &engine,
            &identity,
            sandbox_id,
            cpus,
            memory_mib,
            disk_mib,
            proxy_config,
            &cancellation,
        ) {
            Ok(spec) => spec,
            Err(error) => {
                let _ = sessions.cancel_managed_vm_reservation(session_id, &identity, sandbox_id);
                return Err(if error.to_string().contains("cancelled") {
                    ErrorCode::Cancelled
                } else {
                    ErrorCode::InternalError
                });
            }
        };
        let instance_dir = spec.instance_dir.clone();
        let started = sessions.start_reserved_managed_vm(
            session_id,
            &identity,
            sandbox_id,
            &engine,
            spec,
            cancellation,
        );
        match started {
            Ok(handle) => Ok(ResponseValue::SandboxStarted {
                sandbox_id: handle.to_string(),
                mounts: Vec::new(),
                host_ports: Vec::new(),
            }),
            Err(error) => {
                let _ = remove_prepared_instance(&engine, &instance_dir);
                if error.downcast_ref::<QuotaError>().is_some() {
                    Err(ErrorCode::QuotaExceeded)
                } else {
                    Err(ErrorCode::ServiceUnavailable)
                }
            }
        }
    })
    .await;
    match result {
        Ok(result) => result,
        Err(_) => {
            if cleanup_sessions
                .cancel_managed_vm_reservation(session_id, &cleanup_identity, sandbox_id)
                .unwrap_or(false)
            {
                let _ = remove_prepared_instance(&cleanup_engine, &cleanup_instance_dir);
            }
            Err(ErrorCode::InternalError)
        }
    }
}

fn available_disk_bytes(path: &Path) -> Result<u64> {
    let wide = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut available = 0u64;
    if unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut available,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } == 0
    {
        anyhow::bail!(
            "GetDiskFreeSpaceExW failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(available)
}

pub async fn stop(
    sessions: SessionManager,
    session_id: ResourceHandle,
    identity: ClientIdentityKey,
    sandbox_id: String,
    deadline_ms: Option<u32>,
) -> Result<ResponseValue, ErrorCode> {
    let handle = ResourceHandle::parse(&sandbox_id).map_err(|_| ErrorCode::InvalidRequest)?;
    let timeout =
        Duration::from_millis(u64::from(deadline_ms.unwrap_or(30_000).clamp(100, 60_000)));
    tokio::task::spawn_blocking(move || {
        sessions
            .stop_managed_vm(session_id, &identity, handle, timeout)
            .map_err(|_| ErrorCode::ServiceUnavailable)
            .and_then(|found| {
                if found {
                    Ok(ResponseValue::Empty {})
                } else {
                    Err(ErrorCode::ResourceNotFound)
                }
            })
    })
    .await
    .map_err(|_| ErrorCode::InternalError)?
}

fn prepare_instance(
    engine: &ServiceEngineConfig,
    identity: &ClientIdentityKey,
    sandbox_id: ResourceHandle,
    cpus: u16,
    memory_mib: u32,
    disk_mib: u32,
    proxy_config: Option<lsb_proxy::ProxyConfig>,
    cancellation: &CancellationToken,
) -> Result<ManagedVmSpec> {
    cancellation.check()?;
    let identity_dir = engine.resources_root().join(identity_hash(identity));
    let instances = identity_dir.join("instances");
    engine.require_resource_path(&instances)?;
    std::fs::create_dir_all(&instances).context("create protected identity instances root")?;
    let instance_dir = instances.join(sandbox_id.to_string());
    engine.require_resource_path(&instance_dir)?;
    std::fs::create_dir(&instance_dir).context("create protected VM instance")?;
    let rootfs_image = instance_dir.join("rootfs.ext4");
    let result = (|| {
        copy_with_cancellation(engine.base_rootfs(), &rootfs_image, cancellation)
            .context("copy protected base rootfs")?;
        let requested_bytes = u64::from(disk_mib) * 1024 * 1024;
        let base_bytes = std::fs::metadata(&rootfs_image)?.len();
        if requested_bytes < base_bytes {
            anyhow::bail!("requested disk is smaller than the verified base rootfs");
        }
        OpenOptions::new()
            .write(true)
            .open(&rootfs_image)?
            .set_len(requested_bytes)
            .context("size managed rootfs")?;
        Ok(ManagedVmSpec {
            instance_dir: instance_dir.clone(),
            rootfs_image,
            cpus: usize::from(cpus),
            memory_mib: u64::from(memory_mib),
            proxy_config,
        })
    })();
    if result.is_err() {
        let _ = remove_prepared_instance(engine, &instance_dir);
    }
    result
}

fn copy_with_cancellation(
    source: &Path,
    destination: &Path,
    cancellation: &CancellationToken,
) -> Result<()> {
    let mut source = File::open(source)?;
    let mut destination = File::create(destination)?;
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        cancellation.check()?;
        let read = source.read(&mut buffer)?;
        if read == 0 {
            destination.sync_all()?;
            return Ok(());
        }
        destination.write_all(&buffer[..read])?;
    }
}

fn identity_hash(identity: &ClientIdentityKey) -> String {
    let mut hasher = blake3::Hasher::new();
    for value in [
        identity.user_sid.as_bytes(),
        identity.logon_sid.as_bytes(),
        &identity.authentication_luid.to_le_bytes(),
        &identity.session_id.to_le_bytes(),
    ] {
        hasher.update(value);
        hasher.update(&[0]);
    }
    hasher.finalize().to_hex().to_string()
}

fn remove_prepared_instance(engine: &ServiceEngineConfig, path: &Path) -> Result<()> {
    engine.require_resource_path(path)?;
    if path.exists() {
        std::fs::remove_dir_all(path).context("remove prepared VM instance")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_directory_is_stable_and_logon_bound() {
        let first = ClientIdentityKey::for_test("S-1-5-21-1", "S-1-5-5-1-1", 1);
        let second = ClientIdentityKey::for_test("S-1-5-21-1", "S-1-5-5-2-2", 2);
        assert_eq!(identity_hash(&first), identity_hash(&first));
        assert_ne!(identity_hash(&first), identity_hash(&second));
        assert_eq!(identity_hash(&first).len(), 64);
    }

    #[test]
    fn cancelled_rootfs_copy_stops_before_committing_bytes() {
        let root = std::env::temp_dir().join(format!("lsbsw-copy-cancel-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let source = root.join("source");
        let destination = root.join("destination");
        std::fs::write(&source, vec![1u8; 1024]).unwrap();
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        assert!(copy_with_cancellation(&source, &destination, &cancellation).is_err());
        assert_eq!(std::fs::metadata(&destination).unwrap().len(), 0);
        let _ = std::fs::remove_dir_all(root);
    }
}
