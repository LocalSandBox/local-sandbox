use anyhow::{bail, Result};
use lsb_service_proto::BundleIdentity;
use serde::{Deserialize, Serialize};

use crate::{
    is_lower_hex, sha256_json, validate_id, validate_utc, validate_windows_absolute_path,
    HelperProtocol, ReleaseCandidate, UPDATE_STATE_SCHEMA_VERSION,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreinstallRequest {
    pub request_id: String,
    pub created_utc: String,
    pub candidate: ReleaseCandidate,
    pub old_bundle_identity: BundleIdentity,
    pub target_bundle_identity: BundleIdentity,
    pub staged_root: String,
    pub final_version_root: String,
    pub helper_protocol: HelperProtocol,
}

impl PreinstallRequest {
    pub fn validate(&self) -> Result<()> {
        validate_id(&self.request_id)?;
        validate_utc(&self.created_utc)?;
        self.candidate.validate()?;
        self.old_bundle_identity
            .validate()
            .map_err(|_| anyhow::anyhow!("preinstall old bundle identity is invalid"))?;
        self.target_bundle_identity
            .validate()
            .map_err(|_| anyhow::anyhow!("preinstall target bundle identity is invalid"))?;
        let old = semver::Version::parse(&self.old_bundle_identity.version)?;
        let target = semver::Version::parse(&self.target_bundle_identity.version)?;
        if target <= old
            || self.old_bundle_identity == self.target_bundle_identity
            || self.old_bundle_identity.ledger.writer_schema
                != self.target_bundle_identity.ledger.writer_schema
            || self.candidate.version != self.target_bundle_identity.version
            || self.candidate.archive_sha256 != self.target_bundle_identity.archive_sha256
        {
            bail!("preinstall request identities are inconsistent");
        }
        validate_windows_absolute_path(&self.staged_root)?;
        validate_windows_absolute_path(&self.final_version_root)?;
        self.helper_protocol.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreinstallRequestEnvelope {
    pub schema_version: u32,
    pub checksum_sha256: String,
    pub request: PreinstallRequest,
}

impl PreinstallRequestEnvelope {
    pub fn new(request: PreinstallRequest) -> Result<Self> {
        request.validate()?;
        Ok(Self {
            schema_version: UPDATE_STATE_SCHEMA_VERSION,
            checksum_sha256: sha256_json(&request)?,
            request,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != UPDATE_STATE_SCHEMA_VERSION
            || !is_lower_hex(&self.checksum_sha256, 64)
        {
            bail!("preinstall request envelope is invalid");
        }
        self.request.validate()?;
        if sha256_json(&self.request)? != self.checksum_sha256 {
            bail!("preinstall request checksum does not match");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreinstallReceipt {
    pub request: PreinstallRequest,
    pub completed_utc: String,
}

impl PreinstallReceipt {
    pub fn validate(&self) -> Result<()> {
        self.request.validate()?;
        validate_utc(&self.completed_utc)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreinstallReceiptEnvelope {
    pub schema_version: u32,
    pub checksum_sha256: String,
    pub receipt: PreinstallReceipt,
}

impl PreinstallReceiptEnvelope {
    pub fn new(receipt: PreinstallReceipt) -> Result<Self> {
        receipt.validate()?;
        Ok(Self {
            schema_version: UPDATE_STATE_SCHEMA_VERSION,
            checksum_sha256: sha256_json(&receipt)?,
            receipt,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != UPDATE_STATE_SCHEMA_VERSION
            || !is_lower_hex(&self.checksum_sha256, 64)
        {
            bail!("preinstall receipt envelope is invalid");
        }
        self.receipt.validate()?;
        if sha256_json(&self.receipt)? != self.checksum_sha256 {
            bail!("preinstall receipt checksum does not match");
        }
        Ok(())
    }

    pub fn matches_request(&self, request: &PreinstallRequestEnvelope) -> bool {
        self.receipt.request == request.request
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

    fn request() -> PreinstallRequest {
        let target = identity("0.5.0-rc.5", 'b');
        PreinstallRequest {
            request_id: "1".repeat(32),
            created_utc: "2026-07-24T08:00:00Z".to_string(),
            candidate: ReleaseCandidate {
                release_id: 1,
                version: target.version.clone(),
                prerelease: true,
                asset_name:
                    "lsb-seawork-service-v0.5.0-rc.5-windows-x86_64.zip".to_string(),
                asset_url: "https://github.com/LocalSandBox/local-sandbox/releases/download/v0.5.0-rc.5/lsb-seawork-service-v0.5.0-rc.5-windows-x86_64.zip".to_string(),
                asset_size: 1024,
                archive_sha256: target.archive_sha256.clone(),
            },
            old_bundle_identity: identity("0.5.0-rc.4", 'a'),
            target_bundle_identity: target,
            staged_root: r"C:\ProgramData\LocalSandbox\SeaWork\updates\staging\11111111111111111111111111111111\LocalSandbox".to_string(),
            final_version_root:
                r"C:\Program Files\SeaWork\LocalSandbox\versions\0.5.0-rc.5".to_string(),
            helper_protocol: HelperProtocol { major: 1, minor: 1 },
        }
    }

    #[test]
    fn request_and_receipt_are_checksums_and_exactly_bound() {
        let request = PreinstallRequestEnvelope::new(request()).unwrap();
        request.validate().unwrap();
        let receipt = PreinstallReceiptEnvelope::new(PreinstallReceipt {
            request: request.request.clone(),
            completed_utc: "2026-07-24T08:01:00Z".to_string(),
        })
        .unwrap();
        receipt.validate().unwrap();
        assert!(receipt.matches_request(&request));

        let mut tampered = receipt.clone();
        tampered
            .receipt
            .request
            .final_version_root
            .push_str("-other");
        assert!(tampered.validate().is_err());
        assert!(!tampered.matches_request(&request));
    }

    #[test]
    fn request_rejects_candidate_or_identity_drift() {
        let mut candidate_drift = request();
        candidate_drift.candidate.archive_sha256 = "c".repeat(64);
        assert!(candidate_drift.validate().is_err());
        let mut identity_drift = request();
        identity_drift.target_bundle_identity.version = "0.5.0-rc.3".to_string();
        assert!(identity_drift.validate().is_err());
    }
}
