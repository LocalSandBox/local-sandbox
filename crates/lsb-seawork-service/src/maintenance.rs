use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use lsb_service_proto::{BundleIdentity, UpdatePhase, UpdateRetryState, UpdateStatus, SUPPORTED};
use serde::{Deserialize, Serialize};

use crate::ledger::atomic;
use crate::session::SessionManager;
use crate::LEDGER_SCHEMA_VERSION;

const MAX_PENDING_SIZE: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingUpdate {
    schema_version: u32,
    update_id: String,
    target: BundleIdentity,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingUninstall {
    schema_version: u32,
}

impl PendingUpdate {
    fn validate(&self) -> Result<()> {
        if self.schema_version != 2
            || self.update_id.len() != 32
            || !self
                .update_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || self.target.validate().is_err()
            || self.target.protocol.major != SUPPORTED.major
            || self.target.ledger.writer_schema != LEDGER_SCHEMA_VERSION
        {
            bail!("pending update record is invalid");
        }
        Ok(())
    }
}

#[derive(Debug)]
enum MaintenanceState {
    Active,
    Pending(PendingUpdate),
    Uninstalling,
    Quarantined,
}

#[derive(Clone)]
pub struct MaintenanceManager {
    pending_path: PathBuf,
    uninstall_path: PathBuf,
    initial_admissions: bool,
    admissions: Arc<AtomicBool>,
    state: Arc<Mutex<MaintenanceState>>,
}

impl MaintenanceManager {
    pub fn load(pending_path: PathBuf, initial_admissions: bool) -> Self {
        let uninstall_path = pending_path.with_file_name("pending-uninstall.json");
        let uninstall_pending = load_uninstall(&uninstall_path);
        let state = match (load_pending(&pending_path), uninstall_pending) {
            (Ok(None), Ok(true)) => MaintenanceState::Uninstalling,
            (Ok(Some(pending)), Ok(false)) => MaintenanceState::Pending(pending),
            (Ok(None), Ok(false)) if initial_admissions => MaintenanceState::Active,
            (Ok(None), Ok(false)) => MaintenanceState::Quarantined,
            _ => MaintenanceState::Quarantined,
        };
        let admissions_open = matches!(state, MaintenanceState::Active);
        Self {
            pending_path,
            uninstall_path,
            initial_admissions,
            admissions: Arc::new(AtomicBool::new(admissions_open)),
            state: Arc::new(Mutex::new(state)),
        }
    }

    pub fn admissions(&self) -> Arc<AtomicBool> {
        self.admissions.clone()
    }

    pub fn stable_code(&self) -> &'static str {
        match self.state.lock() {
            Ok(state) => match &*state {
                MaintenanceState::Active => "READY",
                MaintenanceState::Pending(_) => "UPDATE_PENDING",
                MaintenanceState::Uninstalling => "UNINSTALL_PENDING",
                MaintenanceState::Quarantined => "MAINTENANCE_QUARANTINE",
            },
            Err(_) => "MAINTENANCE_QUARANTINE",
        }
    }

    pub fn prepare_update(
        &self,
        sessions: &SessionManager,
        target: BundleIdentity,
    ) -> Result<String> {
        if target.validate().is_err()
            || target.protocol.major != SUPPORTED.major
            || target.ledger.writer_schema != LEDGER_SCHEMA_VERSION
        {
            bail!("target bundle identity is incompatible");
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("maintenance state poisoned"))?;
        if let MaintenanceState::Pending(pending) = &*state {
            if pending.target == target {
                return Ok(pending.update_id.clone());
            }
            bail!("another update is already pending");
        }
        if !matches!(*state, MaintenanceState::Active) {
            bail!("service is not available for update preparation");
        }
        let pending = PendingUpdate {
            schema_version: 2,
            update_id: random_id()?,
            target,
        };
        pending.validate()?;
        atomic::write_value(&self.pending_path, &pending)?;
        self.admissions.store(false, Ordering::Release);
        *state = MaintenanceState::Pending(pending.clone());
        drop(state);
        sessions.drain_all()?;
        Ok(pending.update_id)
    }

    pub fn commit_update(
        &self,
        update_id: &str,
        running_version: &str,
        running_bundle_manifest_sha256: &str,
        running_protocol_range: lsb_service_proto::ProtocolRange,
        running_ledger_writer_schema: u32,
        running_service_configuration_revision: u32,
    ) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("maintenance state poisoned"))?;
        let pending = require_pending_id(&state, update_id)?;
        if pending.target.version != running_version
            || pending.target.bundle_manifest_sha256 != running_bundle_manifest_sha256
            || pending.target.protocol != running_protocol_range
            || pending.target.ledger.writer_schema != running_ledger_writer_schema
            || pending.target.service_configuration_revision
                != running_service_configuration_revision
        {
            bail!("running service does not match the pending update target");
        }
        clear_pending(
            &mut state,
            &self.pending_path,
            &self.admissions,
            self.initial_admissions,
        )
    }

    pub fn abort_update(&self, update_id: &str) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("maintenance state poisoned"))?;
        require_pending_id(&state, update_id)?;
        clear_pending(
            &mut state,
            &self.pending_path,
            &self.admissions,
            self.initial_admissions,
        )
    }

    pub fn update_status(
        &self,
        current: Option<BundleIdentity>,
        active_use_count: u32,
    ) -> UpdateStatus {
        let (phase, target) = match self.state.lock() {
            Ok(state) => match &*state {
                MaintenanceState::Active => (UpdatePhase::UpdateIdle, None),
                MaintenanceState::Pending(pending) => (
                    UpdatePhase::UpdateWaitingForIdle,
                    Some(pending.target.clone()),
                ),
                MaintenanceState::Uninstalling => (UpdatePhase::UpdateIdle, None),
                MaintenanceState::Quarantined => (UpdatePhase::UpdateRecoveryQuarantine, None),
            },
            Err(_) => (UpdatePhase::UpdateRecoveryQuarantine, None),
        };
        UpdateStatus {
            phase,
            current,
            target,
            active_use_count,
            last_check_category: None,
            retry: UpdateRetryState {
                attempt_count: 0,
                retry_after_utc: None,
                suppressed: false,
            },
        }
    }

    pub fn prepare_uninstall(&self, sessions: &SessionManager) -> Result<bool> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("maintenance state poisoned"))?;
        if !matches!(
            *state,
            MaintenanceState::Active | MaintenanceState::Uninstalling
        ) {
            bail!("service is not available for uninstall preparation");
        }
        if matches!(*state, MaintenanceState::Active) {
            atomic::write_value(
                &self.uninstall_path,
                &PendingUninstall { schema_version: 1 },
            )?;
        }
        self.admissions.store(false, Ordering::Release);
        *state = MaintenanceState::Uninstalling;
        drop(state);
        sessions.drain_all()?;
        Ok(sessions.is_empty())
    }
}

fn clear_pending(
    state: &mut MaintenanceState,
    pending_path: &Path,
    admissions: &AtomicBool,
    initial_admissions: bool,
) -> Result<()> {
    remove_pending(pending_path)?;
    *state = if initial_admissions {
        MaintenanceState::Active
    } else {
        MaintenanceState::Quarantined
    };
    admissions.store(initial_admissions, Ordering::Release);
    Ok(())
}

fn require_pending_id<'a>(
    state: &'a MaintenanceState,
    update_id: &str,
) -> Result<&'a PendingUpdate> {
    match state {
        MaintenanceState::Pending(pending) if pending.update_id == update_id => Ok(pending),
        MaintenanceState::Pending(_) => bail!("update identifier does not match pending state"),
        _ => bail!("no update is pending"),
    }
}

fn load_pending(path: &Path) -> Result<Option<PendingUpdate>> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if metadata.len() > MAX_PENDING_SIZE {
        bail!("pending update record exceeds size limit");
    }
    let pending: PendingUpdate = serde_json::from_slice(
        &std::fs::read(path).with_context(|| format!("read {}", path.display()))?,
    )?;
    pending.validate()?;
    Ok(Some(pending))
}

fn load_uninstall(path: &Path) -> Result<bool> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if metadata.len() > MAX_PENDING_SIZE {
        bail!("pending uninstall record exceeds size limit");
    }
    let pending: PendingUninstall = serde_json::from_slice(&std::fs::read(path)?)?;
    if pending.schema_version != 1 {
        bail!("pending uninstall record is invalid");
    }
    Ok(true)
}

fn remove_pending(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            bail!("pending update record disappeared")
        }
        Err(error) => Err(error.into()),
    }
}

fn random_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|error| anyhow::anyhow!("generate update identifier: {error}"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::QuotaLimits;

    fn path(name: &str) -> PathBuf {
        std::env::temp_dir()
            .join(format!("lsbsw-maintenance-{}", std::process::id()))
            .join(name)
            .join("pending-update.json")
    }

    fn target(version: &str) -> BundleIdentity {
        BundleIdentity {
            version: version.to_string(),
            bundle_manifest_sha256: "a".repeat(64),
            archive_sha256: "b".repeat(64),
            protocol: SUPPORTED,
            ledger: lsb_service_proto::LedgerCompatibility {
                reader_min_schema: LEDGER_SCHEMA_VERSION,
                reader_max_schema: LEDGER_SCHEMA_VERSION,
                writer_schema: LEDGER_SCHEMA_VERSION,
            },
            service_configuration_revision: 2,
        }
    }

    #[test]
    fn pending_update_is_durable_idempotent_and_abortable() {
        let path = path("pending.json");
        let _ = std::fs::remove_file(&path);
        let sessions = SessionManager::new(QuotaLimits::default());
        let manager = MaintenanceManager::load(path.clone(), true);
        let target_bundle = target("0.5.0-rc.2");
        let update_id = manager
            .prepare_update(&sessions, target_bundle.clone())
            .unwrap();
        assert!(!manager.admissions.load(Ordering::Acquire));
        assert_eq!(
            manager
                .prepare_update(&sessions, target_bundle.clone())
                .unwrap(),
            update_id
        );
        let restarted = MaintenanceManager::load(path.clone(), true);
        assert_eq!(restarted.stable_code(), "UPDATE_PENDING");
        assert!(restarted
            .commit_update(
                &update_id,
                "0.5.0-rc.3",
                &target_bundle.bundle_manifest_sha256,
                target_bundle.protocol,
                target_bundle.ledger.writer_schema,
                target_bundle.service_configuration_revision,
            )
            .is_err());
        assert_eq!(restarted.stable_code(), "UPDATE_PENDING");
        restarted.abort_update(&update_id).unwrap();
        assert!(restarted.admissions.load(Ordering::Acquire));
    }

    #[test]
    fn commit_requires_the_complete_exact_bundle_identity() {
        let path = path("exact-identity");
        let _ = std::fs::remove_file(&path);
        let sessions = SessionManager::new(QuotaLimits::default());
        let manager = MaintenanceManager::load(path.clone(), true);
        let target = target("0.5.0-rc.2");
        let update_id = manager.prepare_update(&sessions, target.clone()).unwrap();
        let mut wrong_digest = target.clone();
        wrong_digest.bundle_manifest_sha256 = "c".repeat(64);
        assert!(manager
            .commit_update(
                &update_id,
                &wrong_digest.version,
                &wrong_digest.bundle_manifest_sha256,
                wrong_digest.protocol,
                wrong_digest.ledger.writer_schema,
                wrong_digest.service_configuration_revision,
            )
            .is_err());
        manager
            .commit_update(
                &update_id,
                &target.version,
                &target.bundle_manifest_sha256,
                target.protocol,
                target.ledger.writer_schema,
                target.service_configuration_revision,
            )
            .unwrap();
        assert!(manager.admissions.load(Ordering::Acquire));
    }

    #[test]
    fn corrupt_pending_state_quarantines_admissions() {
        let path = path("corrupt.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"not json").unwrap();
        let manager = MaintenanceManager::load(path.clone(), true);
        assert_eq!(manager.stable_code(), "MAINTENANCE_QUARANTINE");
        assert!(!manager.admissions.load(Ordering::Acquire));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn uninstall_drain_survives_restart() {
        let path = path("uninstall");
        let uninstall = path.with_file_name("pending-uninstall.json");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&uninstall);
        let sessions = SessionManager::new(QuotaLimits::default());
        let manager = MaintenanceManager::load(path.clone(), true);
        assert!(manager.prepare_uninstall(&sessions).unwrap());
        let restarted = MaintenanceManager::load(path, true);
        assert_eq!(restarted.stable_code(), "UNINSTALL_PENDING");
        assert!(!restarted.admissions.load(Ordering::Acquire));
        let _ = std::fs::remove_file(uninstall);
    }
}
