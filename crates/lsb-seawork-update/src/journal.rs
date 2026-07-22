use anyhow::{bail, Result};
use lsb_service_proto::{BundleIdentity, UpdateCheckCategory};
use serde::{Deserialize, Serialize};

use crate::{
    is_lower_hex, sha256_json, validate_id, validate_utc, validate_windows_absolute_path,
    UPDATE_STATE_SCHEMA_VERSION,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperProtocol {
    pub major: u16,
    pub minor: u16,
}

impl HelperProtocol {
    pub fn validate(self) -> Result<()> {
        if self.major == 0 || self.minor == 0 {
            bail!("helper protocol is invalid");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionPhase {
    Prepared,
    HelperStarted,
    FinalPathVerified,
    OldServiceStopRequested,
    OldServiceStopped,
    ImagePathChanged,
    TargetStartRequested,
    TargetHealthPending,
    TargetCommitted,
    RollbackRequested,
    TargetStopped,
    OldPathRestored,
    OldServiceRestarted,
    RollbackComplete,
    Quarantined,
}

impl TransactionPhase {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::TargetCommitted | Self::RollbackComplete | Self::Quarantined
        )
    }

    fn can_transition_to(self, next: Self) -> bool {
        use TransactionPhase::*;
        matches!(
            (self, next),
            (Prepared, HelperStarted)
                | (HelperStarted, FinalPathVerified)
                | (FinalPathVerified, OldServiceStopRequested)
                | (OldServiceStopRequested, OldServiceStopped)
                | (OldServiceStopped, ImagePathChanged)
                | (ImagePathChanged, TargetStartRequested)
                | (TargetStartRequested, TargetHealthPending)
                | (TargetHealthPending, TargetCommitted)
                | (
                    HelperStarted
                        | FinalPathVerified
                        | OldServiceStopRequested
                        | OldServiceStopped
                        | ImagePathChanged
                        | TargetStartRequested
                        | TargetHealthPending,
                    RollbackRequested
                )
                | (RollbackRequested, TargetStopped)
                | (TargetStopped, OldPathRestored)
                | (OldPathRestored, OldServiceRestarted)
                | (OldServiceRestarted, RollbackComplete)
                | (
                    Prepared
                        | HelperStarted
                        | FinalPathVerified
                        | OldServiceStopRequested
                        | OldServiceStopped
                        | ImagePathChanged
                        | TargetStartRequested
                        | TargetHealthPending
                        | RollbackRequested
                        | TargetStopped
                        | OldPathRestored
                        | OldServiceRestarted,
                    Quarantined
                )
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateTransaction {
    pub transaction_id: String,
    pub update_id: String,
    pub phase: TransactionPhase,
    pub created_utc: String,
    pub old_bundle_identity: BundleIdentity,
    pub target_bundle_identity: BundleIdentity,
    pub old_image_path: String,
    pub target_image_path: String,
    pub old_event_message_path: String,
    pub target_event_message_path: String,
    pub staged_root: String,
    pub final_version_root: String,
    pub helper_protocol: HelperProtocol,
    pub attempt_count: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error_category: Option<UpdateCheckCategory>,
}

impl UpdateTransaction {
    pub fn validate(&self) -> Result<()> {
        validate_id(&self.transaction_id)?;
        validate_id(&self.update_id)?;
        validate_utc(&self.created_utc)?;
        self.old_bundle_identity
            .validate()
            .map_err(|_| anyhow::anyhow!("old bundle identity is invalid"))?;
        self.target_bundle_identity
            .validate()
            .map_err(|_| anyhow::anyhow!("target bundle identity is invalid"))?;
        let old = semver::Version::parse(&self.old_bundle_identity.version)?;
        let target = semver::Version::parse(&self.target_bundle_identity.version)?;
        if target <= old || self.old_bundle_identity == self.target_bundle_identity {
            bail!("transaction target is not a strict upgrade");
        }
        if self.old_bundle_identity.ledger.writer_schema
            != self.target_bundle_identity.ledger.writer_schema
        {
            bail!("transaction changes the ledger writer schema");
        }
        for path in [
            &self.old_image_path,
            &self.target_image_path,
            &self.old_event_message_path,
            &self.target_event_message_path,
            &self.staged_root,
            &self.final_version_root,
        ] {
            validate_windows_absolute_path(path)?;
        }
        if self.old_image_path == self.target_image_path
            || self.old_event_message_path == self.target_event_message_path
            || self.attempt_count == 0
            || self.attempt_count > 3
        {
            bail!("transaction mutation identity or attempt count is invalid");
        }
        self.helper_protocol.validate()?;
        Ok(())
    }

    pub fn transition(&mut self, next: TransactionPhase) -> Result<()> {
        if self.phase == next {
            return Ok(());
        }
        if !self.phase.can_transition_to(next) {
            bail!("invalid transaction phase transition");
        }
        self.phase = next;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionEnvelope {
    pub schema_version: u32,
    pub checksum_sha256: String,
    pub transaction: UpdateTransaction,
}

impl TransactionEnvelope {
    pub fn new(transaction: UpdateTransaction) -> Result<Self> {
        transaction.validate()?;
        Ok(Self {
            schema_version: UPDATE_STATE_SCHEMA_VERSION,
            checksum_sha256: sha256_json(&transaction)?,
            transaction,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != UPDATE_STATE_SCHEMA_VERSION
            || !is_lower_hex(&self.checksum_sha256, 64)
        {
            bail!("transaction envelope is invalid");
        }
        self.transaction.validate()?;
        if sha256_json(&self.transaction)? != self.checksum_sha256 {
            bail!("transaction checksum does not match");
        }
        Ok(())
    }

    pub fn transition(&mut self, next: TransactionPhase) -> Result<()> {
        self.validate()?;
        self.transaction.transition(next)?;
        self.checksum_sha256 = sha256_json(&self.transaction)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lsb_service_proto::{LedgerCompatibility, ProtocolRange};

    fn identity(version: &str, byte: char) -> BundleIdentity {
        BundleIdentity {
            version: version.to_string(),
            bundle_manifest_sha256: byte.to_string().repeat(64),
            archive_sha256: byte
                .to_ascii_uppercase()
                .to_ascii_lowercase()
                .to_string()
                .repeat(64),
            protocol: ProtocolRange {
                major: 1,
                min_minor: 0,
                max_minor: 6,
            },
            ledger: LedgerCompatibility {
                reader_min_schema: 1,
                reader_max_schema: 1,
                writer_schema: 1,
            },
            service_configuration_revision: 2,
        }
    }

    fn transaction() -> UpdateTransaction {
        UpdateTransaction {
            transaction_id: "1".repeat(32),
            update_id: "2".repeat(32),
            phase: TransactionPhase::Prepared,
            created_utc: "2026-07-22T12:00:00Z".to_string(),
            old_bundle_identity: identity("0.5.0-rc.1", 'a'),
            target_bundle_identity: identity("0.5.0-rc.2", 'b'),
            old_image_path: r"C:\Program Files\SeaWork\LocalSandbox\versions\0.5.0-rc.1\bin\localsandbox-seawork-service.exe".to_string(),
            target_image_path: r"C:\Program Files\SeaWork\LocalSandbox\versions\0.5.0-rc.2\bin\localsandbox-seawork-service.exe".to_string(),
            old_event_message_path: r"C:\Program Files\SeaWork\LocalSandbox\versions\0.5.0-rc.1\bin\localsandbox-seawork-service.exe".to_string(),
            target_event_message_path: r"C:\Program Files\SeaWork\LocalSandbox\versions\0.5.0-rc.2\bin\localsandbox-seawork-service.exe".to_string(),
            staged_root: r"C:\ProgramData\LocalSandbox\SeaWork\updates\staging\11111111111111111111111111111111\LocalSandbox".to_string(),
            final_version_root: r"C:\Program Files\SeaWork\LocalSandbox\versions\0.5.0-rc.2".to_string(),
            helper_protocol: HelperProtocol { major: 1, minor: 1 },
            attempt_count: 1,
            last_error_category: None,
        }
    }

    #[test]
    fn checksums_strict_transactions_and_detects_tamper() {
        let mut envelope = TransactionEnvelope::new(transaction()).unwrap();
        envelope.validate().unwrap();
        envelope.transaction.target_image_path.push_str(".tampered");
        assert!(envelope.validate().is_err());
    }

    #[test]
    fn forward_and_rollback_transitions_are_monotonic_and_idempotent() {
        let mut envelope = TransactionEnvelope::new(transaction()).unwrap();
        envelope
            .transition(TransactionPhase::HelperStarted)
            .unwrap();
        envelope
            .transition(TransactionPhase::FinalPathVerified)
            .unwrap();
        envelope
            .transition(TransactionPhase::FinalPathVerified)
            .unwrap();
        assert!(envelope
            .transition(TransactionPhase::TargetCommitted)
            .is_err());
        envelope
            .transition(TransactionPhase::RollbackRequested)
            .unwrap();
        envelope
            .transition(TransactionPhase::TargetStopped)
            .unwrap();
        envelope
            .transition(TransactionPhase::OldPathRestored)
            .unwrap();
        envelope
            .transition(TransactionPhase::OldServiceRestarted)
            .unwrap();
        envelope
            .transition(TransactionPhase::RollbackComplete)
            .unwrap();
        assert!(envelope.transaction.phase.is_terminal());
        assert!(envelope.transition(TransactionPhase::Quarantined).is_err());
    }

    #[test]
    fn rejects_downgrade_schema_change_and_untrusted_paths() {
        let mut value = transaction();
        value.target_bundle_identity.version = "0.4.9".to_string();
        assert!(value.validate().is_err());
        let mut value = transaction();
        value.target_bundle_identity.ledger.writer_schema = 2;
        assert!(value.validate().is_err());
        let mut value = transaction();
        value.final_version_root = r"C:\Program Files\..\Windows".to_string();
        assert!(value.validate().is_err());
    }
}
