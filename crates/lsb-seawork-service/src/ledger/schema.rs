use std::collections::HashSet;

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
        if self.bundle_version.is_empty()
            || !self.owner.user_sid.starts_with("S-")
            || !self.owner.logon_sid.starts_with("S-")
            || !is_lower_hex(&self.owner.authentication_luid, 16)
        {
            bail!("ledger owner or bundle identity is invalid");
        }
        if self.created_unix_ms == 0
            || self.updated_unix_ms == 0
            || self.updated_unix_ms < self.created_unix_ms
        {
            bail!("ledger timestamps are invalid or non-monotonic");
        }
        if self.resources.len() > MAX_LEDGER_RESOURCES {
            bail!("ledger has too many resource records");
        }
        let mut resource_keys = HashSet::with_capacity(self.resources.len());
        for resource in &self.resources {
            resource.validate(&self.ownership_id)?;
            if !resource_keys.insert(resource.stable_key()) {
                bail!("ledger contains duplicate resource identities");
            }
        }
        let encoded = serde_json::to_vec(self)?;
        if encoded.len() > lsb_service_proto::limits::MAX_LEDGER_DOCUMENT_SIZE {
            bail!("ledger document exceeds serialized size bound");
        }
        validate_strings(&encoded)?;
        Ok(())
    }
}

impl ResourceRecord {
    fn validate(&self, ownership_id: &str) -> Result<()> {
        match self {
            Self::AuthorizedMountRoot {
                mount_id,
                file_index,
                final_path,
                access,
                backend,
                ..
            } => {
                require_hex_id(mount_id, "mount id")?;
                if !is_lower_hex(file_index, 16)
                    || final_path.is_empty()
                    || access.is_empty()
                    || backend.is_empty()
                {
                    bail!("authorized mount proof is incomplete");
                }
            }
            Self::ProtectedFile { relative_path, .. } => {
                require_safe_relative_path(relative_path)?;
            }
            Self::TemporaryAccount { name, sid, .. } => {
                if !name.starts_with("lsbsw_") || !sid.starts_with("S-") {
                    bail!("temporary account lacks an exact service identity");
                }
            }
            Self::Share {
                name,
                ownership_comment,
                root_file_id,
                ..
            } => {
                if !name.starts_with("lsbsw-")
                    || ownership_comment != &format!("lsbsw:{ownership_id}")
                    || root_file_id.is_empty()
                {
                    bail!("share lacks an exact ownership proof");
                }
            }
            Self::PinnedAce {
                root_file_id, sid, ..
            } => {
                if root_file_id.is_empty() || !sid.starts_with("S-") {
                    bail!("pinned ACE lacks an exact file or SID identity");
                }
            }
            Self::StagingRoot {
                relative_path,
                file_id,
                committed,
            } => {
                require_safe_relative_path(relative_path)?;
                if (*committed && !is_file_id(file_id)) || (!*committed && file_id != "pending") {
                    bail!("staging root lacks its exact protected file identity");
                }
            }
            Self::QemuProcess {
                pid,
                creation_time,
                image_relative_path,
                job_id,
                committed,
            } => {
                require_safe_relative_path(image_relative_path)?;
                require_hex_id(job_id, "QEMU job id")?;
                if (*committed && (*pid == 0 || *creation_time == 0))
                    || (!*committed && (*pid != 0 || *creation_time != 0))
                {
                    bail!("QEMU process proof does not match intent/commit state");
                }
            }
            Self::WfpFilter {
                provider_guid,
                sublayer_guid,
                filter_guid,
                ..
            } => {
                if !is_guid(provider_guid) || !is_guid(sublayer_guid) || !is_guid(filter_guid) {
                    bail!("WFP filter proof contains an invalid GUID");
                }
            }
        }
        Ok(())
    }

    fn stable_key(&self) -> String {
        match self {
            Self::AuthorizedMountRoot { mount_id, .. } => format!("mount:{mount_id}"),
            Self::ProtectedFile { relative_path, .. } => format!("file:{relative_path}"),
            Self::TemporaryAccount { name, .. } => format!("account:{name}"),
            Self::Share { name, .. } => format!("share:{name}"),
            Self::PinnedAce {
                root_file_id,
                sid,
                mask,
                inheritance,
                ..
            } => format!("ace:{root_file_id}:{sid}:{mask}:{inheritance}"),
            Self::StagingRoot { relative_path, .. } => format!("staging:{relative_path}"),
            Self::QemuProcess { job_id, .. } => format!("qemu:{job_id}"),
            Self::WfpFilter { filter_guid, .. } => format!("wfp:{filter_guid}"),
        }
    }
}

fn is_hex_id(value: &str) -> bool {
    is_lower_hex(value, 32)
}

fn require_hex_id(value: &str, name: &str) -> Result<()> {
    if !is_hex_id(value) {
        bail!("{name} must be 32 lowercase hexadecimal characters");
    }
    Ok(())
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_file_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 25
        && bytes[8] == b':'
        && bytes[..8]
            .iter()
            .chain(&bytes[9..])
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn is_guid(value: &str) -> bool {
    value.len() == 36
        && [8, 13, 18, 23]
            .into_iter()
            .all(|index| value.as_bytes().get(index) == Some(&b'-'))
        && value
            .bytes()
            .enumerate()
            .all(|(index, byte)| [8, 13, 18, 23].contains(&index) || byte.is_ascii_hexdigit())
}

fn require_safe_relative_path(value: &str) -> Result<()> {
    if value.is_empty()
        || value.starts_with('/')
        || value.starts_with('\\')
        || value.contains(':')
        || value
            .split(['/', '\\'])
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        bail!("ledger relative path is unsafe");
    }
    Ok(())
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

#[cfg(test)]
mod validation_tests {
    use super::*;

    #[test]
    fn rejects_forged_ownership_markers_and_duplicate_resource_identities() {
        let mut forged = sample();
        forged.resources.push(ResourceRecord::Share {
            name: "lsbsw-example".to_string(),
            ownership_comment: "lsbsw:attacker".to_string(),
            root_file_id: "proof".to_string(),
            committed: true,
        });
        assert!(forged.validate().is_err());

        let mut duplicate = sample();
        duplicate.resources = vec![
            ResourceRecord::ProtectedFile {
                relative_path: "mounts/one".to_string(),
                committed: true,
            },
            ResourceRecord::ProtectedFile {
                relative_path: "mounts/one".to_string(),
                committed: false,
            },
        ];
        assert!(duplicate.validate().is_err());
    }

    #[test]
    fn validates_intent_and_commit_specific_external_proofs() {
        let mut document = sample();
        document.resources = vec![
            ResourceRecord::StagingRoot {
                relative_path: "mounts/one".to_string(),
                file_id: "pending".to_string(),
                committed: false,
            },
            ResourceRecord::QemuProcess {
                pid: 42,
                creation_time: 7,
                image_relative_path: "tools/qemu/qemu-system-x86_64.exe".to_string(),
                job_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                committed: true,
            },
        ];
        document.validate().unwrap();

        if let ResourceRecord::StagingRoot {
            file_id, committed, ..
        } = &mut document.resources[0]
        {
            *file_id = "pending".to_string();
            *committed = true;
        }
        assert!(document.validate().is_err());
    }
}
