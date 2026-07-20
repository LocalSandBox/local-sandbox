use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};

use crate::ledger::atomic;
use crate::ledger::schema::{LedgerDocument, LifecycleState, OwnerIdentity, ResourceRecord};
use crate::session::ClientIdentityKey;

pub const ACCOUNT_PREFIX: &str = "lsbsw_";
pub const SHARE_PREFIX: &str = "lsbsw-";
pub const OWNERSHIP_MARKER_PREFIX: &str = "lsbsw:";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupProof {
    Removed,
    AlreadyAbsent,
    IdentityMismatch,
}

pub struct ResourceTransaction {
    path: PathBuf,
    document: LedgerDocument,
}

impl ResourceTransaction {
    pub fn reserve(
        ledger_root: &Path,
        sandbox_id: &str,
        owner: &ClientIdentityKey,
    ) -> Result<Self> {
        require_hex_id(sandbox_id)?;
        let now = now_unix_ms()?;
        let document = LedgerDocument {
            schema_version: crate::LEDGER_SCHEMA_VERSION,
            bundle_version: env!("CARGO_PKG_VERSION").to_string(),
            ownership_id: random_hex_id()?,
            owner: OwnerIdentity {
                user_sid: owner.user_sid.clone(),
                logon_sid: owner.logon_sid.clone(),
                authentication_luid: format!("{:016x}", owner.authentication_luid),
                session_id: owner.session_id,
            },
            state: LifecycleState::Reserved,
            resources: Vec::new(),
            created_unix_ms: now,
            updated_unix_ms: now,
        };
        let transaction = Self {
            path: ledger_root.join(format!("{sandbox_id}.json")),
            document,
        };
        atomic::create(&transaction.path, &transaction.document)?;
        Ok(transaction)
    }

    pub fn ownership_id(&self) -> &str {
        &self.document.ownership_id
    }

    pub fn ownership_marker(&self) -> String {
        format!("{OWNERSHIP_MARKER_PREFIX}{}", self.ownership_id())
    }

    pub fn document(&self) -> &LedgerDocument {
        &self.document
    }

    pub fn set_state(&mut self, state: LifecycleState) -> Result<()> {
        self.document.state = state;
        self.touch_and_persist()
    }

    pub fn intent(&mut self, mut resource: ResourceRecord) -> Result<usize> {
        resource.set_committed(false);
        self.document.resources.push(resource);
        self.touch_and_persist()?;
        Ok(self.document.resources.len() - 1)
    }

    pub fn commit(&mut self, index: usize) -> Result<()> {
        self.document
            .resources
            .get_mut(index)
            .context("resource intent index is out of range")?
            .set_committed(true);
        self.touch_and_persist()
    }

    pub fn replace_and_commit(&mut self, index: usize, mut resource: ResourceRecord) -> Result<()> {
        resource.set_committed(true);
        *self
            .document
            .resources
            .get_mut(index)
            .context("resource intent index is out of range")? = resource;
        self.touch_and_persist()
    }

    /// Remove a transaction only after the caller has proved every external resource absent.
    pub fn finish(&mut self) -> Result<()> {
        self.document.state = LifecycleState::Cleaning;
        self.touch_and_persist()?;
        self.document.resources.clear();
        self.touch_and_persist()?;
        atomic::remove_if_exists(&self.path).map(|_| ())
    }

    pub fn require_staging_identity(&self, relative_path: &str, file_id: &str) -> Result<()> {
        let matches = self.document.resources.iter().filter(|resource| {
            matches!(
                resource,
                ResourceRecord::StagingRoot {
                    relative_path: expected_path,
                    file_id: expected_id,
                    committed: true,
                } if expected_path == relative_path && expected_id == file_id
            )
        });
        if matches.count() != 1 {
            bail!("protected staging identity does not match its committed ledger proof");
        }
        Ok(())
    }

    fn touch_and_persist(&mut self) -> Result<()> {
        self.document.updated_unix_ms = now_unix_ms()?;
        self.persist()
    }

    fn persist(&self) -> Result<()> {
        atomic::write(&self.path, &self.document)
    }
}

pub fn generate_account_name() -> Result<String> {
    Ok(format!("{ACCOUNT_PREFIX}{}", random_base32(13)?))
}

pub fn generate_share_name() -> Result<String> {
    Ok(format!("{SHARE_PREFIX}{}", random_base32(26)?))
}

pub fn remove_proven_staging_root(
    protected_instance_root: &Path,
    relative_path: &str,
    expected_file_id: &str,
) -> Result<CleanupProof> {
    let relative = Path::new(relative_path);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
        || relative
            .components()
            .next()
            .and_then(|component| match component {
                std::path::Component::Normal(value) => value.to_str(),
                _ => None,
            })
            != Some("mounts")
    {
        bail!("staging ledger path is not a safe relative mounts path");
    }
    let path = protected_instance_root.join(relative);
    if !path.exists() {
        return Ok(CleanupProof::AlreadyAbsent);
    }
    let actual = super::mount::protected_identity(&path)?;
    if actual != expected_file_id {
        return Ok(CleanupProof::IdentityMismatch);
    }
    std::fs::remove_dir_all(path)?;
    Ok(CleanupProof::Removed)
}

fn random_hex_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|error| anyhow::anyhow!("OS random source failed: {error}"))?;
    Ok(bytes.iter().map(|value| format!("{value:02x}")).collect())
}

fn random_base32(length: usize) -> Result<String> {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let byte_count = (length * 5).div_ceil(8);
    let mut bytes = vec![0u8; byte_count];
    getrandom::fill(&mut bytes)
        .map_err(|error| anyhow::anyhow!("OS random source failed: {error}"))?;
    let mut output = String::with_capacity(length);
    let mut accumulator = 0u32;
    let mut bits = 0u8;
    for byte in bytes {
        accumulator = (accumulator << 8) | byte as u32;
        bits += 8;
        while bits >= 5 && output.len() < length {
            bits -= 5;
            output.push(ALPHABET[((accumulator >> bits) & 31) as usize] as char);
        }
    }
    Ok(output)
}

fn require_hex_id(value: &str) -> Result<()> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("sandbox id must be 32 lowercase hexadecimal characters");
    }
    Ok(())
}

fn now_unix_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_millis()
        .try_into()
        .context("system time does not fit ledger timestamp")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> ClientIdentityKey {
        ClientIdentityKey {
            user_sid: "S-1-5-21-owner".to_string(),
            logon_sid: "S-1-5-5-owner".to_string(),
            authentication_luid: 7,
            session_id: 2,
        }
    }

    #[test]
    fn journals_intent_before_commit() {
        let root = std::env::temp_dir().join(format!("lsbsw-transaction-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let mut transaction =
            ResourceTransaction::reserve(&root, "0123456789abcdef0123456789abcdef", &owner())
                .unwrap();
        let index = transaction
            .intent(ResourceRecord::ProtectedFile {
                relative_path: "mounts/id".to_string(),
                committed: true,
            })
            .unwrap();
        assert!(!transaction.document().resources[index].committed());
        transaction.commit(index).unwrap();
        assert!(transaction.document().resources[index].committed());
        assert!(transaction
            .ownership_marker()
            .starts_with(OWNERSHIP_MARKER_PREFIX));
        transaction.finish().unwrap();
        assert!(!root.join("0123456789abcdef0123456789abcdef.json").exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn generated_service_names_have_exact_prefix_and_entropy_length() {
        let account = generate_account_name().unwrap();
        let share = generate_share_name().unwrap();
        assert_eq!(account.len(), 19);
        assert_eq!(share.len(), 32);
        assert!(account.starts_with(ACCOUNT_PREFIX));
        assert!(share.starts_with(SHARE_PREFIX));
        assert!(account[ACCOUNT_PREFIX.len()..]
            .bytes()
            .all(|value| value.is_ascii_lowercase() || (b'2'..=b'7').contains(&value)));
    }

    #[test]
    fn staging_cleanup_requires_one_exact_committed_ledger_identity() {
        let root =
            std::env::temp_dir().join(format!("lsbsw-staging-transaction-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let mut transaction =
            ResourceTransaction::reserve(&root, "0123456789abcdef0123456789abcdef", &owner())
                .unwrap();
        let intent = transaction
            .intent(ResourceRecord::StagingRoot {
                relative_path: "owner/instances/id".to_string(),
                file_id: "pending".to_string(),
                committed: false,
            })
            .unwrap();
        transaction
            .replace_and_commit(
                intent,
                ResourceRecord::StagingRoot {
                    relative_path: "owner/instances/id".to_string(),
                    file_id: "12345678:0123456789abcdef".to_string(),
                    committed: true,
                },
            )
            .unwrap();

        transaction
            .require_staging_identity("owner/instances/id", "12345678:0123456789abcdef")
            .unwrap();
        assert!(transaction
            .require_staging_identity("owner/instances/id", "12345678:fedcba9876543210")
            .is_err());
        transaction.finish().unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn staging_cleanup_requires_exact_protected_identity() {
        let root = std::env::temp_dir().join(format!("lsbsw-proof-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let staging = root.join("mounts").join("0123456789abcdef0123456789abcdef");
        std::fs::create_dir_all(&staging).unwrap();
        assert_eq!(
            remove_proven_staging_root(&root, "mounts/0123456789abcdef0123456789abcdef", "wrong")
                .unwrap(),
            CleanupProof::IdentityMismatch
        );
        assert!(staging.exists());
        let identity = super::super::mount::protected_identity(&staging).unwrap();
        assert_eq!(
            remove_proven_staging_root(&root, "mounts/0123456789abcdef0123456789abcdef", &identity)
                .unwrap(),
            CleanupProof::Removed
        );
        assert!(!staging.exists());
        let _ = std::fs::remove_dir_all(root);
    }
}
