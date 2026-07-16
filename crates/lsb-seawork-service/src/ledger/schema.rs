use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use lsb_service_proto::limits::{MAX_LEDGER_RESOURCES, MAX_STRING_LEN};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerDocument {
    pub schema_version: u32,
    pub bundle_version: String,
    pub ownership_id: String,
    pub owner: OwnerIdentity,
    pub state: LifecycleState,
    pub resources: Vec<ResourceRecord>,
    pub created_unix_ms: u64,
    pub updated_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerIdentity {
    pub user_sid: String,
    pub logon_sid: String,
    pub authentication_luid: String,
    pub session_id: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleState {
    Reserved,
    Preparing,
    Running,
    Draining,
    Cleaning,
    FailedSetup,
    Quarantined,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResourceRecord {
    AuthorizedMountRoot {
        mount_id: String,
        volume_serial: u32,
        file_index: String,
        final_path: String,
        access: String,
        backend: String,
        committed: bool,
    },
    ProtectedFile {
        relative_path: String,
        committed: bool,
    },
    TemporaryAccount {
        name: String,
        sid: String,
        committed: bool,
    },
    Share {
        name: String,
        ownership_comment: String,
        root_file_id: String,
        committed: bool,
    },
    PinnedAce {
        root_file_id: String,
        sid: String,
        mask: u32,
        inheritance: u32,
        committed: bool,
    },
    StagingRoot {
        relative_path: String,
        file_id: String,
        committed: bool,
    },
    QemuProcess {
        pid: u32,
        creation_time: u64,
        image_relative_path: String,
        job_id: String,
        committed: bool,
    },
    WfpFilter {
        provider_guid: String,
        sublayer_guid: String,
        filter_guid: String,
        committed: bool,
    },
}

impl ResourceRecord {
    pub fn committed(&self) -> bool {
        match self {
            Self::AuthorizedMountRoot { committed, .. }
            | Self::ProtectedFile { committed, .. }
            | Self::TemporaryAccount { committed, .. }
            | Self::Share { committed, .. }
            | Self::PinnedAce { committed, .. }
            | Self::StagingRoot { committed, .. }
            | Self::QemuProcess { committed, .. }
            | Self::WfpFilter { committed, .. } => *committed,
        }
    }

    pub fn set_committed(&mut self, value: bool) {
        match self {
            Self::AuthorizedMountRoot { committed, .. }
            | Self::ProtectedFile { committed, .. }
            | Self::TemporaryAccount { committed, .. }
            | Self::Share { committed, .. }
            | Self::PinnedAce { committed, .. }
            | Self::StagingRoot { committed, .. }
            | Self::QemuProcess { committed, .. }
            | Self::WfpFilter { committed, .. } => *committed = value,
        }
    }
}

impl LedgerDocument {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != crate::LEDGER_SCHEMA_VERSION {
            bail!("unsupported ledger schema {}", self.schema_version);
        }
        if !is_hex_id(&self.ownership_id) {
            bail!("ownership_id must be 32 lowercase hexadecimal characters");
        }
        if self.resources.len() > MAX_LEDGER_RESOURCES {
            bail!("ledger has too many resource records");
        }
        let encoded = serde_json::to_vec(self)?;
        if encoded.len() > lsb_service_proto::limits::MAX_LEDGER_DOCUMENT_SIZE {
            bail!("ledger document exceeds serialized size bound");
        }
        validate_strings(&encoded)?;
        Ok(())
    }
}

fn is_hex_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_strings(encoded: &[u8]) -> Result<()> {
    let value: serde_json::Value = serde_json::from_slice(encoded)?;
    fn visit(value: &serde_json::Value) -> bool {
        match value {
            serde_json::Value::String(value) => value.len() <= MAX_STRING_LEN,
            serde_json::Value::Array(values) => values.iter().all(visit),
            serde_json::Value::Object(values) => values.values().all(visit),
            _ => true,
        }
    }
    if !visit(&value) {
        bail!("ledger string exceeds bound");
    }
    Ok(())
}

#[cfg(test)]
pub fn sample() -> LedgerDocument {
    LedgerDocument {
        schema_version: 1,
        bundle_version: "0.4.6".to_string(),
        ownership_id: "0123456789abcdef0123456789abcdef".to_string(),
        owner: OwnerIdentity {
            user_sid: "S-1-5-21-test".to_string(),
            logon_sid: "S-1-5-5-test".to_string(),
            authentication_luid: "0000000000000001".to_string(),
            session_id: 1,
        },
        state: LifecycleState::Reserved,
        resources: Vec::new(),
        created_unix_ms: 1,
        updated_unix_ms: 1,
    }
}
