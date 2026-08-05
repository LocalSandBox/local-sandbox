use anyhow::{bail, Result};
use lsb_service_proto::{BundleIdentity, UpdateCheckCategory};
use serde::{Deserialize, Serialize};

use crate::{
    is_lower_hex, sha256_json, validate_id, validate_utc, validate_windows_absolute_path,
    UPDATE_STATE_SCHEMA_VERSION,
};

pub(crate) const MAX_TIMELINE_ENTRIES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateActor {
    Service,
    Updater,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateTransitionOutcome {
    Succeeded,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateFailureBoundary {
    FirstError,
    RetryExhausted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateTransition {
    pub phase: String,
    pub actor: UpdateActor,
    pub started_utc: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_utc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<UpdateTransitionOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retryable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_attempt: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_error_event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_exhausted_event_id: Option<String>,
}

impl UpdateTransition {
    pub fn started(
        phase: impl Into<String>,
        actor: UpdateActor,
        started_utc: impl Into<String>,
    ) -> Result<Self> {
        let transition = Self {
            phase: phase.into(),
            actor,
            started_utc: started_utc.into(),
            completed_utc: None,
            duration_ms: None,
            outcome: None,
            failure_code: None,
            retryable: None,
            retry_attempt: None,
            started_event_id: None,
            completed_event_id: None,
            first_error_event_id: None,
            retry_exhausted_event_id: None,
        };
        transition.validate()?;
        Ok(transition)
    }

    pub fn complete(
        &mut self,
        completed_utc: impl Into<String>,
        duration_ms: u64,
        outcome: UpdateTransitionOutcome,
        failure_code: Option<String>,
    ) -> Result<()> {
        if self.completed_utc.is_some() {
            bail!("update timeline transition is already complete");
        }
        self.completed_utc = Some(completed_utc.into());
        self.duration_ms = Some(duration_ms);
        self.outcome = Some(outcome);
        self.failure_code = failure_code;
        self.validate()
    }

    pub fn mark_reported(
        &mut self,
        boundary: crate::UpdateCheckpointBoundary,
        event_id: impl Into<String>,
    ) -> Result<()> {
        let event_id = event_id.into();
        if !is_lower_hex(&event_id, 32) {
            bail!("checkpoint Sentry event id is invalid");
        }
        match boundary {
            crate::UpdateCheckpointBoundary::Started => self.started_event_id = Some(event_id),
            crate::UpdateCheckpointBoundary::Completed if self.outcome.is_some() => {
                self.completed_event_id = Some(event_id)
            }
            crate::UpdateCheckpointBoundary::Completed => {
                bail!("incomplete checkpoint cannot have a completion receipt")
            }
        }
        self.validate()
    }

    pub fn mark_failure_reported(
        &mut self,
        boundary: UpdateFailureBoundary,
        event_id: impl Into<String>,
    ) -> Result<()> {
        let event_id = event_id.into();
        if self.outcome != Some(UpdateTransitionOutcome::Failed) || !is_lower_hex(&event_id, 32) {
            bail!("update failure Sentry receipt is invalid");
        }
        match boundary {
            UpdateFailureBoundary::FirstError => self.first_error_event_id = Some(event_id),
            UpdateFailureBoundary::RetryExhausted => self.retry_exhausted_event_id = Some(event_id),
        }
        self.validate()
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.phase.is_empty()
            || self.phase.len() > 64
            || !self.phase.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_')
            })
        {
            bail!("update timeline phase is invalid");
        }
        validate_utc(&self.started_utc)?;
        if let Some(completed) = &self.completed_utc {
            validate_utc(completed)?;
        }
        if self.completed_utc.is_some() != self.duration_ms.is_some()
            || self.completed_utc.is_some() != self.outcome.is_some()
            || self.outcome != Some(UpdateTransitionOutcome::Failed) && self.failure_code.is_some()
            || self.retry_attempt.is_some() != self.retryable.is_some()
            || self
                .retry_attempt
                .is_some_and(|attempt| attempt == 0 || attempt > 10)
            || self
                .started_event_id
                .as_ref()
                .is_some_and(|event_id| !is_lower_hex(event_id, 32))
            || self
                .completed_event_id
                .as_ref()
                .is_some_and(|event_id| self.completed_utc.is_none() || !is_lower_hex(event_id, 32))
            || self.first_error_event_id.as_ref().is_some_and(|event_id| {
                self.outcome != Some(UpdateTransitionOutcome::Failed) || !is_lower_hex(event_id, 32)
            })
            || self
                .retry_exhausted_event_id
                .as_ref()
                .is_some_and(|event_id| {
                    self.outcome != Some(UpdateTransitionOutcome::Failed)
                        || !is_lower_hex(event_id, 32)
                })
            || self
                .failure_code
                .as_ref()
                .is_some_and(|code| code.is_empty() || code.len() > 64 || !code.is_ascii())
        {
            bail!("update timeline completion is inconsistent");
        }
        Ok(())
    }
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateFailureStep {
    HandoffVerify,
    TargetStart,
    TargetConnect,
    TargetHealthAssertion,
    RollbackTargetStop,
    RollbackRestoreConfiguration,
    RollbackOldStart,
    RollbackAbortConnect,
    RollbackIdentityAssertion,
    RollbackHealthAssertion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateFailureCode {
    OperationFailed,
    TargetConnectTimeout,
    TargetHealthAssertionFailed,
    RollbackAbortConnectTimeout,
    RollbackIdentityContradiction,
    RollbackHealthAssertionFailed,
    ProtectedStateContradiction,
}

impl UpdateFailureCode {
    pub fn stable_code(self) -> &'static str {
        match self {
            Self::OperationFailed => "UPDATE_OPERATION_FAILED",
            Self::TargetConnectTimeout => "TARGET_CONNECT_TIMEOUT",
            Self::TargetHealthAssertionFailed => "TARGET_HEALTH_ASSERTION_FAILED",
            Self::RollbackAbortConnectTimeout => "ROLLBACK_ABORT_CONNECT_TIMEOUT",
            Self::RollbackIdentityContradiction => "ROLLBACK_IDENTITY_CONTRADICTION",
            Self::RollbackHealthAssertionFailed => "ROLLBACK_HEALTH_ASSERTION_FAILED",
            Self::ProtectedStateContradiction => "PROTECTED_STATE_CONTRADICTION",
        }
    }
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt_id: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_failure_step: Option<UpdateFailureStep>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_failure_code: Option<UpdateFailureCode>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub timeline: Vec<UpdateTransition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reported_event_id: Option<String>,
}

impl UpdateTransaction {
    pub fn attempt_id(&self) -> &str {
        self.attempt_id.as_deref().unwrap_or(&self.update_id)
    }

    pub fn validate(&self) -> Result<()> {
        validate_id(&self.transaction_id)?;
        validate_id(&self.update_id)?;
        if let Some(attempt_id) = &self.attempt_id {
            validate_id(attempt_id)?;
        }
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
            || self.last_failure_step.is_some() != self.last_failure_code.is_some()
            || self.timeline.len() > MAX_TIMELINE_ENTRIES
            || self
                .reported_event_id
                .as_ref()
                .is_some_and(|event_id| !self.phase.is_terminal() || !is_lower_hex(event_id, 32))
        {
            bail!("transaction mutation identity or attempt count is invalid");
        }
        self.helper_protocol.validate()?;
        for transition in &self.timeline {
            transition.validate()?;
        }
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

    pub fn record_failure(
        &mut self,
        step: UpdateFailureStep,
        code: UpdateFailureCode,
    ) -> Result<()> {
        self.validate()?;
        self.transaction.last_failure_step = Some(step);
        self.transaction.last_failure_code = Some(code);
        if let Some(transition) = self
            .transaction
            .timeline
            .iter_mut()
            .rev()
            .find(|transition| transition.outcome == Some(UpdateTransitionOutcome::Failed))
        {
            transition.failure_code = Some(code.stable_code().to_string());
        }
        self.checksum_sha256 = sha256_json(&self.transaction)?;
        Ok(())
    }

    pub fn begin_transition(
        &mut self,
        phase: impl Into<String>,
        actor: UpdateActor,
        started_utc: impl Into<String>,
    ) -> Result<()> {
        self.validate()?;
        if self.transaction.timeline.len() >= MAX_TIMELINE_ENTRIES {
            bail!("update transition timeline is full");
        }
        let transition = UpdateTransition::started(phase, actor, started_utc)?;
        self.transaction.timeline.push(transition);
        self.checksum_sha256 = sha256_json(&self.transaction)?;
        Ok(())
    }

    pub fn complete_transition(
        &mut self,
        completed_utc: impl Into<String>,
        duration_ms: u64,
        outcome: UpdateTransitionOutcome,
    ) -> Result<()> {
        self.validate()?;
        let transition = self
            .transaction
            .timeline
            .last_mut()
            .filter(|transition| transition.completed_utc.is_none())
            .ok_or_else(|| anyhow::anyhow!("update timeline has no active transition"))?;
        transition.complete(completed_utc, duration_ms, outcome, None)?;
        self.checksum_sha256 = sha256_json(&self.transaction)?;
        Ok(())
    }

    pub fn mark_reported(&mut self, event_id: impl Into<String>) -> Result<()> {
        self.validate()?;
        if !self.transaction.phase.is_terminal() {
            bail!("only terminal update transactions can be reported");
        }
        let event_id = event_id.into();
        if !is_lower_hex(&event_id, 32) {
            bail!("reported Sentry event id is invalid");
        }
        self.transaction.reported_event_id = Some(event_id);
        self.checksum_sha256 = sha256_json(&self.transaction)?;
        Ok(())
    }

    pub fn mark_checkpoint_reported(
        &mut self,
        index: usize,
        boundary: crate::UpdateCheckpointBoundary,
        event_id: impl Into<String>,
    ) -> Result<()> {
        self.validate()?;
        let transition = self
            .transaction
            .timeline
            .get_mut(index)
            .ok_or_else(|| anyhow::anyhow!("update checkpoint index is invalid"))?;
        transition.mark_reported(boundary, event_id)?;
        self.checksum_sha256 = sha256_json(&self.transaction)?;
        Ok(())
    }

    pub fn mark_failure_reported(
        &mut self,
        index: usize,
        boundary: UpdateFailureBoundary,
        event_id: impl Into<String>,
    ) -> Result<()> {
        self.validate()?;
        let transition = self
            .transaction
            .timeline
            .get_mut(index)
            .ok_or_else(|| anyhow::anyhow!("update failure index is invalid"))?;
        transition.mark_failure_reported(boundary, event_id)?;
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
            attempt_id: None,
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
            last_failure_step: None,
            last_failure_code: None,
            timeline: Vec::new(),
            reported_event_id: None,
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
    fn empty_timeline_preserves_previous_transaction_wire_checksum() {
        let transaction = transaction();
        let checksum_sha256 = sha256_json(&transaction).unwrap();
        let value = serde_json::to_value(&transaction).unwrap();
        assert!(value.get("timeline").is_none());
        assert!(value.get("reported_event_id").is_none());

        let envelope = TransactionEnvelope {
            schema_version: UPDATE_STATE_SCHEMA_VERSION,
            checksum_sha256,
            transaction: serde_json::from_value(value).unwrap(),
        };
        envelope.validate().unwrap();
    }

    #[test]
    fn bounded_failure_diagnostics_are_checksum_protected() {
        let mut envelope = TransactionEnvelope::new(transaction()).unwrap();
        envelope
            .record_failure(
                UpdateFailureStep::RollbackAbortConnect,
                UpdateFailureCode::RollbackAbortConnectTimeout,
            )
            .unwrap();
        envelope.validate().unwrap();
        assert_eq!(
            envelope.transaction.last_failure_code,
            Some(UpdateFailureCode::RollbackAbortConnectTimeout)
        );
        envelope.transaction.last_failure_step = None;
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
