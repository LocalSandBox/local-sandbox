use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::{is_update_transaction_id, validate_utc, UPDATE_STATE_SCHEMA_VERSION};

const ACTOR: &str = "seawork-updater";
const ACTIVATE_REASON: &str = "activate_update";
const ROLLBACK_REASON: &str = "rollback_update";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminationIntent {
    pub schema_version: u32,
    pub run_id: String,
    pub actor: String,
    pub reason: String,
    pub transaction_id: String,
    pub requested_utc: String,
    pub target_version: String,
    pub acknowledged_utc: Option<String>,
}

impl TerminationIntent {
    pub fn update_activation(
        run_id: impl Into<String>,
        transaction_id: impl Into<String>,
        requested_utc: impl Into<String>,
        target_version: impl Into<String>,
    ) -> Result<Self> {
        Self::update(
            run_id,
            transaction_id,
            requested_utc,
            target_version,
            ACTIVATE_REASON,
        )
    }

    pub fn update_rollback(
        run_id: impl Into<String>,
        transaction_id: impl Into<String>,
        requested_utc: impl Into<String>,
        target_version: impl Into<String>,
    ) -> Result<Self> {
        Self::update(
            run_id,
            transaction_id,
            requested_utc,
            target_version,
            ROLLBACK_REASON,
        )
    }

    fn update(
        run_id: impl Into<String>,
        transaction_id: impl Into<String>,
        requested_utc: impl Into<String>,
        target_version: impl Into<String>,
        reason: &'static str,
    ) -> Result<Self> {
        let intent = Self {
            schema_version: UPDATE_STATE_SCHEMA_VERSION,
            run_id: run_id.into(),
            actor: ACTOR.to_string(),
            reason: reason.to_string(),
            transaction_id: transaction_id.into(),
            requested_utc: requested_utc.into(),
            target_version: target_version.into(),
            acknowledged_utc: None,
        };
        intent.validate()?;
        Ok(intent)
    }

    pub fn acknowledge(&mut self, acknowledged_utc: impl Into<String>) -> Result<()> {
        self.validate()?;
        if self.acknowledged_utc.is_some() {
            return Ok(());
        }
        let acknowledged_utc = acknowledged_utc.into();
        validate_utc(&acknowledged_utc)?;
        self.acknowledged_utc = Some(acknowledged_utc);
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != UPDATE_STATE_SCHEMA_VERSION
            || !is_update_transaction_id(&self.run_id)
            || !is_update_transaction_id(&self.transaction_id)
            || self.actor != ACTOR
            || !matches!(self.reason.as_str(), ACTIVATE_REASON | ROLLBACK_REASON)
            || self.target_version.is_empty()
            || self.target_version.len() > 128
            || !self
                .target_version
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
        {
            bail!("termination intent is invalid");
        }
        validate_utc(&self.requested_utc)?;
        if let Some(acknowledged_utc) = &self.acknowledged_utc {
            validate_utc(acknowledged_utc)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_intent_validates_and_can_be_acknowledged() {
        let mut intent = TerminationIntent::update_activation(
            "1".repeat(32),
            "2".repeat(32),
            "2026-07-27T12:00:00Z",
            "0.5.0-rc.6",
        )
        .unwrap();
        intent.acknowledge("2026-07-27T12:00:01Z").unwrap();
        intent.validate().unwrap();
        assert_eq!(
            intent.acknowledged_utc.as_deref(),
            Some("2026-07-27T12:00:01Z")
        );
    }

    #[test]
    fn update_intent_rejects_unbounded_or_untrusted_fields() {
        let mut intent = TerminationIntent::update_activation(
            "1".repeat(32),
            "2".repeat(32),
            "2026-07-27T12:00:00Z",
            "0.5.0",
        )
        .unwrap();
        intent.actor = "other-process".to_string();
        assert!(intent.validate().is_err());
    }

    #[test]
    fn rollback_intent_has_distinct_attribution() {
        let intent = TerminationIntent::update_rollback(
            "1".repeat(32),
            "2".repeat(32),
            "2026-07-27T12:00:00Z",
            "0.5.0-rc.6",
        )
        .unwrap();
        assert_eq!(intent.reason, "rollback_update");
    }
}
