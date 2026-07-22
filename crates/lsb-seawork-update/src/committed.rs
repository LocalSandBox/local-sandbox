use anyhow::{bail, Result};
use lsb_service_proto::BundleIdentity;
use serde::{Deserialize, Serialize};

use crate::{
    is_lower_hex, sha256_json, validate_id, validate_utc, HelperProtocol,
    UPDATE_STATE_SCHEMA_VERSION,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommittedState {
    pub current: BundleIdentity,
    pub highest_committed_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_last_known_good: Option<BundleIdentity>,
    pub helper_protocol: HelperProtocol,
    pub last_completed_transaction_id: String,
}

impl CommittedState {
    pub fn validate(&self) -> Result<()> {
        self.current
            .validate()
            .map_err(|_| anyhow::anyhow!("current committed identity is invalid"))?;
        if let Some(previous) = &self.previous_last_known_good {
            previous
                .validate()
                .map_err(|_| anyhow::anyhow!("previous identity is invalid"))?;
            if previous == &self.current {
                bail!("previous and current identities are equal");
            }
        }
        let highest = semver::Version::parse(&self.highest_committed_version)?;
        if highest.to_string() != self.highest_committed_version
            || !highest.build.is_empty()
            || highest < semver::Version::parse(&self.current.version)?
        {
            bail!("highest committed version is invalid");
        }
        self.helper_protocol.validate()?;
        validate_id(&self.last_completed_transaction_id)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommittedStateEnvelope {
    pub schema_version: u32,
    pub checksum_sha256: String,
    pub committed: CommittedState,
}

impl CommittedStateEnvelope {
    pub fn new(committed: CommittedState) -> Result<Self> {
        committed.validate()?;
        Ok(Self {
            schema_version: UPDATE_STATE_SCHEMA_VERSION,
            checksum_sha256: sha256_json(&committed)?,
            committed,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != UPDATE_STATE_SCHEMA_VERSION
            || !is_lower_hex(&self.checksum_sha256, 64)
        {
            bail!("committed-state envelope is invalid");
        }
        self.committed.validate()?;
        if sha256_json(&self.committed)? != self.checksum_sha256 {
            bail!("committed-state checksum does not match");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailedTargetState {
    pub target_version: String,
    pub archive_sha256: String,
    pub rollback_count: u8,
    pub last_rollback_utc: String,
    pub suppressed: bool,
}

impl FailedTargetState {
    pub fn validate(&self) -> Result<()> {
        let version = semver::Version::parse(&self.target_version)?;
        if version.to_string() != self.target_version
            || !version.build.is_empty()
            || !is_lower_hex(&self.archive_sha256, 64)
            || self.rollback_count == 0
            || self.rollback_count > 3
            || self.suppressed != (self.rollback_count >= 3)
        {
            bail!("failed-target state is invalid");
        }
        validate_utc(&self.last_rollback_utc)
    }

    pub fn record_rollback(&mut self, observed_utc: String) -> Result<()> {
        validate_utc(&observed_utc)?;
        self.rollback_count = self.rollback_count.saturating_add(1).min(3);
        self.last_rollback_utc = observed_utc;
        self.suppressed = self.rollback_count >= 3;
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
            archive_sha256: byte.to_string().repeat(64),
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

    #[test]
    fn committed_state_is_checksums_and_anti_rollback_state() {
        let committed = CommittedState {
            current: identity("0.5.0", 'b'),
            highest_committed_version: "0.5.1".to_string(),
            previous_last_known_good: Some(identity("0.4.9", 'a')),
            helper_protocol: HelperProtocol { major: 1, minor: 1 },
            last_completed_transaction_id: "1".repeat(32),
        };
        let mut envelope = CommittedStateEnvelope::new(committed).unwrap();
        envelope.validate().unwrap();
        envelope.committed.highest_committed_version = "0.4.0".to_string();
        assert!(envelope.validate().is_err());
    }

    #[test]
    fn exact_digest_is_suppressed_after_three_rollbacks() {
        let mut failed = FailedTargetState {
            target_version: "0.5.1".to_string(),
            archive_sha256: "a".repeat(64),
            rollback_count: 1,
            last_rollback_utc: "2026-07-22T12:00:00Z".to_string(),
            suppressed: false,
        };
        failed.validate().unwrap();
        failed
            .record_rollback("2026-07-23T12:00:00Z".to_string())
            .unwrap();
        assert!(!failed.suppressed);
        failed
            .record_rollback("2026-07-24T12:00:00Z".to_string())
            .unwrap();
        assert!(failed.suppressed);
        failed.validate().unwrap();
    }
}
