use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use lsb_service_proto::{
    ErrorCode, ResponseValue, SelectedMount, ServiceMountSpec, ServiceNetworkSpec, ServicePortSpec,
};
use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

use crate::engine::ServiceEngineConfig;
use crate::ledger::schema::ResourceRecord;
use crate::resource::transaction::ResourceTransaction;
use crate::resource::vm::{ManagedVmMountSpec, ManagedVmSpec};
use crate::session::{
    CancellationToken, ClientIdentityKey, QuotaError, ResourceHandle, SandboxResources,
    SessionManager, StartReplayDecision,
};

#[allow(clippy::too_many_arguments)]
pub async fn start(
    engine: Option<ServiceEngineConfig>,
    sessions: SessionManager,
    session_id: ResourceHandle,
    identity: ClientIdentityKey,
    protected_egress_allow: Vec<String>,
    product_ca_bundle_pem: Vec<u8>,
    upstream_proxy: Option<lsb_proxy::UpstreamProxyConfig>,
    client_instance_id: Option<String>,
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
    let (mounts, selected_mounts) = normalize_mounts(mounts)?;
    let mut proxy_config = network
        .map(|policy| {
            crate::network_policy::build_proxy_config(
                policy,
                protected_egress_allow,
                product_ca_bundle_pem,
                upstream_proxy,
            )
        })
        .transpose()
        .map_err(|_| ErrorCode::InvalidRequest)?;
    proxy_config = proxy_config_for_mounts(proxy_config, !mounts.is_empty());
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
    if let Some(replay_id) = client_instance_id.as_deref() {
        match sessions
            .begin_start_replay(session_id, &identity, replay_id)
            .map_err(|_| ErrorCode::ResourceNotFound)?
        {
            StartReplayDecision::Begin => {}
            StartReplayDecision::InProgress => return Err(ErrorCode::DuplicateRequest),
            StartReplayDecision::Replay { sandbox_id, mounts } => {
                return Ok(sandbox_started(sandbox_id, mounts));
            }
            StartReplayDecision::Expired => return Err(ErrorCode::StartResultExpired),
            StartReplayDecision::CapacityExceeded => return Err(ErrorCode::QuotaExceeded),
        }
    }
    let sandbox_id = match sessions.reserve_managed_vm(
        session_id,
        &identity,
        SandboxResources {
            cpus,
            memory_mib,
            disk_mib,
        },
    ) {
        Ok(sandbox_id) => sandbox_id,
        Err(error) => {
            abandon_start_replay(
                &sessions,
                session_id,
                &identity,
                client_instance_id.as_deref(),
            );
            if error.downcast_ref::<QuotaError>().is_some() {
                return Err(ErrorCode::QuotaExceeded);
            } else if !sessions.admissions().accepts_work() {
                return Err(ErrorCode::ServiceDraining);
            } else {
                return Err(ErrorCode::ResourceNotFound);
            }
        }
    };
    let mut transaction = match ResourceTransaction::reserve(
        engine.ledger_root(),
        &sandbox_id.to_string(),
        &identity,
    ) {
        Ok(transaction) => transaction,
        Err(_) => {
            let _ = sessions.cancel_managed_vm_reservation(session_id, &identity, sandbox_id);
            abandon_start_replay(
                &sessions,
                session_id,
                &identity,
                client_instance_id.as_deref(),
            );
            return Err(ErrorCode::ServiceUnavailable);
        }
    };
    let cleanup_sessions = sessions.clone();
    let cleanup_identity = identity.clone();
    let cleanup_client_instance_id = client_instance_id.clone();
    let result = tokio::task::spawn_blocking(move || {
        let spec = match prepare_instance(
            &engine,
            &identity,
            sandbox_id,
            PrepareInstanceOptions {
                cpus,
                memory_mib,
                disk_mib,
                mounts,
                proxy_config,
            },
            &cancellation,
            &mut transaction,
        ) {
            Ok(spec) => spec,
            Err(error) => {
                let _ = sessions.cancel_managed_vm_reservation(session_id, &identity, sandbox_id);
                abandon_start_replay(
                    &sessions,
                    session_id,
                    &identity,
                    client_instance_id.as_deref(),
                );
                return Err(if error.to_string().contains("cancelled") {
                    ErrorCode::Cancelled
                } else {
                    ErrorCode::InternalError
                });
            }
        };
        let started = sessions.start_reserved_managed_vm(
            session_id,
            &identity,
            sandbox_id,
            &engine,
            transaction,
            spec,
            cancellation,
        );
        match started {
            Ok(handle) => {
                if let Some(replay_id) = client_instance_id.as_deref() {
                    let committed = sessions
                        .complete_start_replay(
                            session_id,
                            &identity,
                            replay_id,
                            handle,
                            selected_mounts.clone(),
                        )
                        .unwrap_or(false);
                    if !committed {
                        let _ = sessions.stop_managed_vm(
                            session_id,
                            &identity,
                            handle,
                            Duration::from_secs(30),
                        );
                        return Err(ErrorCode::ServiceUnavailable);
                    }
                }
                Ok(sandbox_started(handle, selected_mounts))
            }
            Err(error) => {
                abandon_start_replay(
                    &sessions,
                    session_id,
                    &identity,
                    client_instance_id.as_deref(),
                );
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
            abandon_start_replay(
                &cleanup_sessions,
                session_id,
                &cleanup_identity,
                cleanup_client_instance_id.as_deref(),
            );
            // The worker owned the durable transaction. A panic makes its last
            // filesystem boundary ambiguous, so startup recovery must decide it.
            let _ = cleanup_sessions.cancel_managed_vm_reservation(
                session_id,
                &cleanup_identity,
                sandbox_id,
            );
            Err(ErrorCode::InternalError)
        }
    }
}

fn sandbox_started(sandbox_id: ResourceHandle, mounts: Vec<SelectedMount>) -> ResponseValue {
    ResponseValue::SandboxStarted {
        sandbox_id: sandbox_id.to_string(),
        mounts,
        host_ports: Vec::new(),
    }
}

fn normalize_mounts(
    mounts: Vec<ServiceMountSpec>,
) -> Result<(Vec<ManagedVmMountSpec>, Vec<SelectedMount>), ErrorCode> {
    let mut guest_paths = BTreeSet::new();
    let mut normalized = Vec::with_capacity(mounts.len());
    let mut selected = Vec::with_capacity(mounts.len());
    for mount in mounts {
        if mount.host_path.trim().is_empty()
            || !valid_guest_mount_path(&mount.guest_path)
            || !guest_paths.insert(mount.guest_path.clone())
        {
            return Err(ErrorCode::InvalidRequest);
        }
        let host_path =
            std::fs::canonicalize(&mount.host_path).map_err(|_| ErrorCode::InvalidRequest)?;
        if !host_path.is_dir() {
            return Err(ErrorCode::InvalidRequest);
        }
        let host_path = host_path
            .into_os_string()
            .into_string()
            .map_err(|_| ErrorCode::InvalidRequest)?;
        selected.push(SelectedMount {
            guest_path: mount.guest_path.clone(),
            backend: "compat-smb-direct".to_string(),
        });
        normalized.push(ManagedVmMountSpec {
            host_path,
            guest_path: mount.guest_path,
            read_only: mount.read_only,
        });
    }
    Ok((normalized, selected))
}

fn valid_guest_mount_path(path: &str) -> bool {
    if !path.starts_with('/')
        || path == "/"
        || path.contains('\\')
        || path.contains('\0')
        || path == "/tmp/lsb/mounts"
        || path.starts_with("/tmp/lsb/mounts/")
        || "/tmp/lsb/mounts".starts_with(&format!("{path}/"))
    {
        return false;
    }
    path.split('/')
        .skip(1)
        .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn proxy_config_for_mounts(
    proxy_config: Option<lsb_proxy::ProxyConfig>,
    has_mounts: bool,
) -> Option<lsb_proxy::ProxyConfig> {
    if !has_mounts {
        return proxy_config;
    }
    Some(match proxy_config {
        Some(config) => config.with_smb_mount_relay(),
        None => lsb_proxy::ProxyConfig::mount_only_smb(),
    })
}

fn abandon_start_replay(
    sessions: &SessionManager,
    session_id: ResourceHandle,
    identity: &ClientIdentityKey,
    client_instance_id: Option<&str>,
) {
    if let Some(replay_id) = client_instance_id {
        let _ = sessions.abandon_start_replay(session_id, identity, replay_id);
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

struct PrepareInstanceOptions {
    cpus: u16,
    memory_mib: u32,
    disk_mib: u32,
    mounts: Vec<ManagedVmMountSpec>,
    proxy_config: Option<lsb_proxy::ProxyConfig>,
}

fn prepare_instance(
    engine: &ServiceEngineConfig,
    identity: &ClientIdentityKey,
    sandbox_id: ResourceHandle,
    options: PrepareInstanceOptions,
    cancellation: &CancellationToken,
    transaction: &mut ResourceTransaction,
) -> Result<ManagedVmSpec> {
    cancellation.check()?;
    let identity_dir = engine.resources_root().join(identity_hash(identity));
    let instances = identity_dir.join("instances");
    engine.require_resource_path(&instances)?;
    std::fs::create_dir_all(&instances).context("create protected identity instances root")?;
    let instance_dir = instances.join(sandbox_id.to_string());
    engine.require_resource_path(&instance_dir)?;
    let relative_path = instance_dir
        .strip_prefix(engine.resources_root())
        .context("protected instance is not relative to resources root")?
        .display()
        .to_string();
    let instance_intent = transaction.intent(ResourceRecord::StagingRoot {
        relative_path: relative_path.clone(),
        file_id: "pending".to_string(),
        committed: false,
    })?;
    std::fs::create_dir(&instance_dir).context("create protected VM instance")?;
    let instance_file_id = crate::resource::mount::protected_identity(&instance_dir)?;
    transaction.replace_and_commit(
        instance_intent,
        ResourceRecord::StagingRoot {
            relative_path: relative_path.clone(),
            file_id: instance_file_id.clone(),
            committed: true,
        },
    )?;
    let rootfs_image = instance_dir.join("rootfs.ext4");
    let result = (|| {
        copy_with_cancellation(engine.base_rootfs(), &rootfs_image, cancellation)
            .context("copy protected base rootfs")?;
        let requested_bytes = u64::from(options.disk_mib) * 1024 * 1024;
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
            cpus: usize::from(options.cpus),
            memory_mib: u64::from(options.memory_mib),
            mounts: options.mounts,
            proxy_config: options.proxy_config,
        })
    })();
    if result.is_err()
        && transaction
            .require_staging_identity(&relative_path, &instance_file_id)
            .and_then(|()| remove_prepared_instance(engine, &instance_dir))
            .is_ok()
    {
        let _ = transaction.finish();
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
    crate::ledger::schema::protected_owner_directory_id(
        &identity.user_sid,
        &identity.logon_sid,
        identity.authentication_luid,
        identity.session_id,
    )
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
    use crate::paths::ServicePaths;

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

    #[test]
    fn preparation_is_journaled_before_rootfs_side_effects() {
        let root = std::env::temp_dir().join(format!("lsbsw-preparation-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let paths = ServicePaths::for_test(root.join("programdata"));
        let bundle = root.join("bundle");
        let qemu = bundle.join("tools/qemu/qemu-system-x86_64.exe");
        let kernel = bundle.join("runtime/Image");
        let initrd = bundle.join("runtime/initramfs.cpio.gz");
        let base = bundle.join("runtime/rootfs.ext4");
        std::fs::create_dir_all(base.parent().unwrap()).unwrap();
        std::fs::write(&base, b"verified-rootfs").unwrap();
        let engine =
            ServiceEngineConfig::from_verified_bundle(bundle, qemu, kernel, initrd, base, &paths)
                .unwrap();
        let identity = ClientIdentityKey::for_test("S-1-5-21-owner", "S-1-5-5-1-1", 1);
        let sandbox_id = ResourceHandle::random().unwrap();
        let mut transaction =
            ResourceTransaction::reserve(engine.ledger_root(), &sandbox_id.to_string(), &identity)
                .unwrap();

        let spec = prepare_instance(
            &engine,
            &identity,
            sandbox_id,
            PrepareInstanceOptions {
                cpus: 2,
                memory_mib: 1024,
                disk_mib: 1,
                mounts: Vec::new(),
                proxy_config: None,
            },
            &CancellationToken::default(),
            &mut transaction,
        )
        .unwrap();
        assert_eq!(
            std::fs::metadata(&spec.rootfs_image).unwrap().len(),
            1024 * 1024
        );
        let relative = spec
            .instance_dir
            .strip_prefix(engine.resources_root())
            .unwrap()
            .display()
            .to_string();
        let identity = crate::resource::mount::protected_identity(&spec.instance_dir).unwrap();
        transaction
            .require_staging_identity(&relative, &identity)
            .unwrap();
        remove_prepared_instance(&engine, &spec.instance_dir).unwrap();
        transaction.finish().unwrap();
        assert!(!spec.instance_dir.exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn direct_mounts_preserve_nested_targets_access_and_selected_backend() {
        let root = std::env::temp_dir().join(format!("lsbsw-direct-mounts-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("workspace/output")).unwrap();
        let (mounts, selected) = normalize_mounts(vec![
            ServiceMountSpec {
                host_path: root.join("workspace").display().to_string(),
                guest_path: "/workspace".to_string(),
                read_only: true,
            },
            ServiceMountSpec {
                host_path: root.join("workspace/output").display().to_string(),
                guest_path: "/workspace/output".to_string(),
                read_only: false,
            },
        ])
        .unwrap();

        assert_eq!(mounts.len(), 2);
        assert!(mounts[0].read_only);
        assert!(!mounts[1].read_only);
        assert_eq!(selected[0].guest_path, "/workspace");
        assert_eq!(selected[1].guest_path, "/workspace/output");
        assert!(selected
            .iter()
            .all(|mount| mount.backend == "compat-smb-direct"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn direct_mounts_reject_duplicates_files_and_unsafe_guest_paths() {
        let root = std::env::temp_dir().join(format!(
            "lsbsw-invalid-direct-mounts-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let mount = |guest_path: &str| ServiceMountSpec {
            host_path: root.display().to_string(),
            guest_path: guest_path.to_string(),
            read_only: true,
        };
        assert_eq!(
            normalize_mounts(vec![mount("/workspace"), mount("/workspace")]),
            Err(ErrorCode::InvalidRequest)
        );
        for guest_path in [
            "workspace",
            "/",
            "/workspace/../state",
            "/workspace//output",
            "/tmp/lsb",
            "/tmp/lsb/mounts/escape",
        ] {
            assert_eq!(
                normalize_mounts(vec![mount(guest_path)]),
                Err(ErrorCode::InvalidRequest)
            );
        }
        let file = root.join("file");
        std::fs::write(&file, b"not a directory").unwrap();
        assert_eq!(
            normalize_mounts(vec![ServiceMountSpec {
                host_path: file.display().to_string(),
                guest_path: "/workspace".to_string(),
                read_only: true,
            }]),
            Err(ErrorCode::InvalidRequest)
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn direct_mounts_select_mount_only_or_combined_proxy_modes() {
        let mount_only = proxy_config_for_mounts(None, true).unwrap();
        assert!(mount_only.is_mount_only_smb());
        assert!(!mount_only.permits_network_policy());

        let combined =
            proxy_config_for_mounts(Some(lsb_proxy::ProxyConfig::default()), true).unwrap();
        assert!(!combined.is_mount_only_smb());
        assert!(combined.permits_network_policy());
        assert!(combined.permits_smb_mount_relay("10.0.0.1".parse().unwrap(), 445));
        assert!(proxy_config_for_mounts(None, false).is_none());
    }
}
