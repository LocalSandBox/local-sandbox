use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::journal::MAX_TIMELINE_ENTRIES;
use crate::{
    is_lower_hex, sha256_json, validate_id, validate_utc, ReleaseChannel, UpdateActor,
    UpdateTransition, UpdateTransitionOutcome, UPDATE_STATE_SCHEMA_VERSION,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateAttemptOutcome {
    Active,
    Succeeded,
    Failed,
    Suppressed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateCheckpointBoundary {
    Started,
    Completed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateFailureBoundary {
    FirstError,
    RetryExhausted,
}

/// Service-owned telemetry metadata for a transition. This type must never be embedded in a
/// helper-facing protocol 1.1 document.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateTransitionTelemetry {
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

impl UpdateTransitionTelemetry {
    fn validate(&self) -> Result<()> {
        if self.retry_attempt.is_some() != self.retryable.is_some()
            || self
                .retry_attempt
                .is_some_and(|attempt| attempt == 0 || attempt > 10)
            || [
                &self.started_event_id,
                &self.completed_event_id,
                &self.first_error_event_id,
                &self.retry_exhausted_event_id,
            ]
            .into_iter()
            .flatten()
            .any(|event_id| !is_lower_hex(event_id, 32))
        {
            bail!("update transition telemetry is invalid");
        }
        Ok(())
    }

    pub fn checkpoint_reported(
        &self,
        transition: &UpdateTransition,
        boundary: UpdateCheckpointBoundary,
    ) -> bool {
        match boundary {
            UpdateCheckpointBoundary::Started => self.started_event_id.is_some(),
            UpdateCheckpointBoundary::Completed => {
                transition.completed_utc.is_none() || self.completed_event_id.is_some()
            }
        }
    }

    fn mark_checkpoint_reported(
        &mut self,
        transition: &UpdateTransition,
        boundary: UpdateCheckpointBoundary,
        event_id: String,
    ) -> Result<()> {
        validate_id(&event_id)?;
        match boundary {
            UpdateCheckpointBoundary::Started => self.started_event_id = Some(event_id),
            UpdateCheckpointBoundary::Completed if transition.outcome.is_some() => {
                self.completed_event_id = Some(event_id);
            }
            UpdateCheckpointBoundary::Completed => {
                bail!("incomplete checkpoint cannot have a completion receipt");
            }
        }
        self.validate()
    }

    fn mark_failure_reported(
        &mut self,
        transition: &UpdateTransition,
        boundary: UpdateFailureBoundary,
        event_id: String,
    ) -> Result<()> {
        validate_id(&event_id)?;
        if transition.outcome != Some(UpdateTransitionOutcome::Failed) {
            bail!("only a failed transition can have a failure receipt");
        }
        match boundary {
            UpdateFailureBoundary::FirstError => self.first_error_event_id = Some(event_id),
            UpdateFailureBoundary::RetryExhausted => self.retry_exhausted_event_id = Some(event_id),
        }
        self.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateAttempt {
    pub attempt_id: String,
    pub created_utc: String,
    pub source_version: String,
    pub channel: ReleaseChannel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_archive_sha256: Option<String>,
    pub retry_count: u8,
    pub outcome: UpdateAttemptOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub timeline: Vec<UpdateTransition>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub timeline_telemetry: Vec<UpdateTransitionTelemetry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transaction_telemetry: Vec<UpdateTransitionTelemetry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_trace_event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_trace_event_id: Option<String>,
}

impl UpdateAttempt {
    pub fn validate(&self) -> Result<()> {
        validate_id(&self.attempt_id)?;
        validate_utc(&self.created_utc)?;
        semver::Version::parse(&self.source_version)?;
        if let Some(version) = &self.target_version {
            if semver::Version::parse(version)? <= semver::Version::parse(&self.source_version)? {
                bail!("update attempt target is not a strict upgrade");
            }
        }
        if self.target_version.is_some() != self.target_archive_sha256.is_some()
            || self
                .target_archive_sha256
                .as_ref()
                .is_some_and(|digest| !is_lower_hex(digest, 64))
            || self.retry_count > 10
            || self.timeline.len() > MAX_TIMELINE_ENTRIES
            || self.timeline_telemetry.len() > self.timeline.len()
            || self.transaction_telemetry.len() > MAX_TIMELINE_ENTRIES
            || self
                .failure_code
                .as_ref()
                .is_some_and(|code| !valid_code(code))
            || self.failure_code.is_some() != (self.outcome == UpdateAttemptOutcome::Failed)
            || self
                .transaction_id
                .as_ref()
                .is_some_and(|id| validate_id(id).is_err())
            || self
                .terminal_trace_event_id
                .as_ref()
                .is_some_and(|id| validate_id(id).is_err())
            || (self.terminal_trace_event_id.is_some()
                && (self.outcome == UpdateAttemptOutcome::Active || self.transaction_id.is_some()))
            || self.transaction_trace_event_id.is_some() && self.transaction_id.is_none()
        {
            bail!("update attempt metadata is invalid");
        }
        for transition in &self.timeline {
            transition.validate()?;
        }
        for telemetry in self
            .timeline_telemetry
            .iter()
            .chain(&self.transaction_telemetry)
        {
            telemetry.validate()?;
        }
        Ok(())
    }

    pub fn begin_transition(
        &mut self,
        phase: impl Into<String>,
        actor: UpdateActor,
        started_utc: impl Into<String>,
    ) -> Result<()> {
        self.validate()?;
        if self.outcome != UpdateAttemptOutcome::Active
            || self.timeline.len() >= MAX_TIMELINE_ENTRIES
            || self
                .timeline
                .last()
                .is_some_and(|item| item.outcome.is_none())
        {
            bail!("update attempt cannot begin another transition");
        }
        self.timeline_telemetry
            .resize(self.timeline.len(), UpdateTransitionTelemetry::default());
        let transition = UpdateTransition::started(phase, actor, started_utc)?;
        self.timeline.push(transition);
        self.timeline_telemetry
            .push(UpdateTransitionTelemetry::default());
        Ok(())
    }

    pub fn complete_transition(
        &mut self,
        completed_utc: impl Into<String>,
        duration_ms: u64,
        outcome: UpdateTransitionOutcome,
        failure_code: Option<String>,
    ) -> Result<()> {
        self.validate()?;
        let transition = self
            .timeline
            .last_mut()
            .filter(|item| item.outcome.is_none())
            .ok_or_else(|| anyhow::anyhow!("update attempt has no active transition"))?;
        transition.complete(completed_utc, duration_ms, outcome, failure_code)?;
        Ok(())
    }

    pub fn finish(
        &mut self,
        outcome: UpdateAttemptOutcome,
        failure_code: Option<String>,
    ) -> Result<()> {
        self.validate()?;
        if self.outcome != UpdateAttemptOutcome::Active
            || outcome == UpdateAttemptOutcome::Active
            || self
                .timeline
                .last()
                .is_some_and(|item| item.outcome.is_none())
        {
            bail!("update attempt cannot finish in its requested state");
        }
        let mut finished = self.clone();
        finished.outcome = outcome;
        finished.failure_code = failure_code;
        finished.validate()?;
        *self = finished;
        Ok(())
    }

    pub fn snapshot(&self) -> UpdateSnapshot {
        let transition = self.timeline.last();
        UpdateSnapshot {
            target_version: self.target_version.clone(),
            phase: transition.map(|item| item.phase.clone()),
            outcome: transition.and_then(|item| item.outcome),
            attempt_id: self.attempt_id.clone(),
            retry_count: self.retry_count,
            last_transition_utc: transition.map(|item| {
                item.completed_utc
                    .clone()
                    .unwrap_or_else(|| item.started_utc.clone())
            }),
        }
    }

    pub fn mark_terminal_trace_reported(&mut self, event_id: impl Into<String>) -> Result<()> {
        self.validate()?;
        if self.outcome == UpdateAttemptOutcome::Active || self.terminal_trace_event_id.is_some() {
            bail!("update attempt terminal trace cannot be acknowledged");
        }
        let event_id = event_id.into();
        validate_id(&event_id)?;
        self.terminal_trace_event_id = Some(event_id);
        self.validate()
    }

    pub fn mark_transaction_trace_reported(&mut self, event_id: impl Into<String>) -> Result<()> {
        self.validate()?;
        if self.transaction_id.is_none() || self.transaction_trace_event_id.is_some() {
            bail!("update transaction trace cannot be acknowledged");
        }
        let event_id = event_id.into();
        validate_id(&event_id)?;
        self.transaction_trace_event_id = Some(event_id);
        self.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateSnapshot {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<UpdateTransitionOutcome>,
    pub attempt_id: String,
    pub retry_count: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_transition_utc: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateAttemptEnvelope {
    pub schema_version: u32,
    pub checksum_sha256: String,
    pub attempt: UpdateAttempt,
}

impl UpdateAttemptEnvelope {
    pub fn new(attempt: UpdateAttempt) -> Result<Self> {
        attempt.validate()?;
        Ok(Self {
            schema_version: UPDATE_STATE_SCHEMA_VERSION,
            checksum_sha256: sha256_json(&attempt)?,
            attempt,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != UPDATE_STATE_SCHEMA_VERSION
            || !is_lower_hex(&self.checksum_sha256, 64)
        {
            bail!("update attempt envelope is invalid");
        }
        self.attempt.validate()?;
        if self.checksum_sha256 != sha256_json(&self.attempt)? {
            bail!("update attempt checksum does not match");
        }
        Ok(())
    }

    pub fn refresh(&mut self) -> Result<()> {
        self.attempt.validate()?;
        self.checksum_sha256 = sha256_json(&self.attempt)?;
        Ok(())
    }

    pub fn mark_checkpoint_reported(
        &mut self,
        index: usize,
        boundary: UpdateCheckpointBoundary,
        event_id: impl Into<String>,
    ) -> Result<()> {
        self.validate()?;
        let transition = self
            .attempt
            .timeline
            .get(index)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("update checkpoint index is invalid"))?;
        self.attempt.timeline_telemetry.resize(
            self.attempt.timeline.len(),
            UpdateTransitionTelemetry::default(),
        );
        let telemetry = &mut self.attempt.timeline_telemetry[index];
        telemetry.mark_checkpoint_reported(&transition, boundary, event_id.into())?;
        self.refresh()
    }

    pub fn mark_failure_reported(
        &mut self,
        index: usize,
        boundary: UpdateFailureBoundary,
        event_id: impl Into<String>,
    ) -> Result<()> {
        self.validate()?;
        let transition = self
            .attempt
            .timeline
            .get(index)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("update failure index is invalid"))?;
        self.attempt.timeline_telemetry.resize(
            self.attempt.timeline.len(),
            UpdateTransitionTelemetry::default(),
        );
        let telemetry = &mut self.attempt.timeline_telemetry[index];
        telemetry.mark_failure_reported(&transition, boundary, event_id.into())?;
        self.refresh()
    }

    pub fn transaction_telemetry_mut(
        &mut self,
        index: usize,
    ) -> Result<&mut UpdateTransitionTelemetry> {
        if index >= MAX_TIMELINE_ENTRIES {
            bail!("update transaction telemetry index is invalid");
        }
        while self.attempt.transaction_telemetry.len() <= index {
            self.attempt
                .transaction_telemetry
                .push(UpdateTransitionTelemetry::default());
        }
        Ok(&mut self.attempt.transaction_telemetry[index])
    }

    pub fn mark_transaction_checkpoint_reported(
        &mut self,
        index: usize,
        transition: &UpdateTransition,
        boundary: UpdateCheckpointBoundary,
        event_id: impl Into<String>,
    ) -> Result<()> {
        self.validate()?;
        self.transaction_telemetry_mut(index)?
            .mark_checkpoint_reported(transition, boundary, event_id.into())?;
        self.refresh()
    }

    pub fn mark_transaction_failure_reported(
        &mut self,
        index: usize,
        transition: &UpdateTransition,
        boundary: UpdateFailureBoundary,
        event_id: impl Into<String>,
    ) -> Result<()> {
        self.validate()?;
        self.transaction_telemetry_mut(index)?
            .mark_failure_reported(transition, boundary, event_id.into())?;
        self.refresh()
    }
}

fn valid_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= 64
        && code
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attempt() -> UpdateAttempt {
        UpdateAttempt {
            attempt_id: "a".repeat(32),
            created_utc: "2026-08-05T01:02:03Z".to_string(),
            source_version: "0.6.0".to_string(),
            channel: ReleaseChannel::Stable,
            target_version: None,
            target_archive_sha256: None,
            retry_count: 0,
            outcome: UpdateAttemptOutcome::Active,
            failure_code: None,
            timeline: Vec::new(),
            timeline_telemetry: Vec::new(),
            transaction_id: None,
            transaction_telemetry: Vec::new(),
            terminal_trace_event_id: None,
            transaction_trace_event_id: None,
        }
    }

    #[test]
    fn attempt_exists_before_discovery_and_exposes_last_observed_snapshot() {
        let mut attempt = attempt();
        attempt
            .begin_transition(
                "update.discovery",
                UpdateActor::Service,
                "2026-08-05T01:02:03Z",
            )
            .unwrap();
        let snapshot = attempt.snapshot();
        assert_eq!(snapshot.attempt_id, "a".repeat(32));
        assert_eq!(snapshot.phase.as_deref(), Some("update.discovery"));
        assert_eq!(snapshot.outcome, None);
        assert_eq!(
            snapshot.last_transition_utc.as_deref(),
            Some("2026-08-05T01:02:03Z")
        );
    }

    #[test]
    fn checkpoint_receipts_are_independent_and_checksummed() {
        let mut attempt = attempt();
        attempt
            .begin_transition(
                "update.discovery",
                UpdateActor::Service,
                "2026-08-05T01:02:03Z",
            )
            .unwrap();
        attempt
            .complete_transition(
                "2026-08-05T01:02:04Z",
                1_000,
                UpdateTransitionOutcome::Succeeded,
                None,
            )
            .unwrap();
        let mut envelope = UpdateAttemptEnvelope::new(attempt).unwrap();
        let before = envelope.checksum_sha256.clone();
        envelope
            .mark_checkpoint_reported(0, UpdateCheckpointBoundary::Started, "b".repeat(32))
            .unwrap();
        envelope
            .mark_checkpoint_reported(0, UpdateCheckpointBoundary::Completed, "c".repeat(32))
            .unwrap();
        assert_ne!(envelope.checksum_sha256, before);
        assert_eq!(
            envelope.attempt.timeline_telemetry[0]
                .started_event_id
                .as_deref(),
            Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        );
        assert!(envelope.validate().is_ok());
    }

    #[test]
    fn terminal_failure_requires_a_stable_code() {
        let mut attempt = attempt();
        assert!(attempt.finish(UpdateAttemptOutcome::Failed, None).is_err());
        assert!(attempt
            .finish(
                UpdateAttemptOutcome::Failed,
                Some("UPDATE_DISCOVERY_FAILED".to_string())
            )
            .is_ok());
        assert!(attempt
            .finish(UpdateAttemptOutcome::Suppressed, None)
            .is_err());
    }

    #[test]
    fn terminal_trace_receipt_is_single_assignment() {
        let mut invalid_active = attempt();
        invalid_active.terminal_trace_event_id = Some("b".repeat(32));
        assert!(invalid_active.validate().is_err());

        let mut attempt = attempt();
        attempt
            .finish(UpdateAttemptOutcome::Succeeded, None)
            .unwrap();
        attempt
            .mark_terminal_trace_reported("b".repeat(32))
            .unwrap();
        assert!(attempt
            .mark_terminal_trace_reported("c".repeat(32))
            .is_err());
        assert!(attempt.validate().is_ok());
    }
}
