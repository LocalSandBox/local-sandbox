use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

use super::atomic;
use super::schema::{LedgerDocument, LifecycleState, ResourceRecord};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryProof {
    Removed,
    AlreadyAbsent,
    IdentityMismatch,
    TemporarilyUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryOutcome {
    Removed,
    Quarantined,
    RetryRequired,
}

/// Windows implementations must re-query every external identity encoded by `resource`
/// and return `Removed` only after removing that exact object. Prefix matches are not proof.
pub trait ExternalResourceCleaner {
    fn remove_if_exact(
        &mut self,
        ledger_id: &str,
        document: &LedgerDocument,
        resource: &ResourceRecord,
    ) -> Result<RecoveryProof>;
}

trait RecoveryStore {
    fn persist(&mut self, path: &Path, document: &LedgerDocument) -> Result<()>;
    fn remove(&mut self, path: &Path) -> Result<()>;
}

struct DurableRecoveryStore;

impl RecoveryStore for DurableRecoveryStore {
    fn persist(&mut self, path: &Path, document: &LedgerDocument) -> Result<()> {
        atomic::write(path, document)
    }

    fn remove(&mut self, path: &Path) -> Result<()> {
        atomic::remove_if_exists(path).map(|_| ())
    }
}

pub fn recover_document(
    path: &Path,
    document: LedgerDocument,
    cleaner: &mut impl ExternalResourceCleaner,
) -> Result<RecoveryOutcome> {
    recover_with_store(path, document, cleaner, &mut DurableRecoveryStore)
}

fn recover_with_store(
    path: &Path,
    mut document: LedgerDocument,
    cleaner: &mut impl ExternalResourceCleaner,
    store: &mut impl RecoveryStore,
) -> Result<RecoveryOutcome> {
    document.validate()?;
    if document.state == LifecycleState::Quarantined {
        return Ok(RecoveryOutcome::Quarantined);
    }

    document.state = LifecycleState::Cleaning;
    touch(&mut document)?;
    store.persist(path, &document)?;

    let ledger_id = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_string();
    while let Some(resource) = document.resources.last() {
        match cleaner.remove_if_exact(&ledger_id, &document, resource)? {
            RecoveryProof::Removed | RecoveryProof::AlreadyAbsent => {
                document.resources.pop();
                touch(&mut document)?;
                store.persist(path, &document)?;
            }
            RecoveryProof::IdentityMismatch => {
                document.state = LifecycleState::Quarantined;
                touch(&mut document)?;
                store.persist(path, &document)?;
                return Ok(RecoveryOutcome::Quarantined);
            }
            RecoveryProof::TemporarilyUnavailable => {
                return Ok(RecoveryOutcome::RetryRequired);
            }
        }
    }

    store.remove(path)?;
    Ok(RecoveryOutcome::Removed)
}

fn touch(document: &mut LedgerDocument) -> Result<()> {
    let now: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_millis()
        .try_into()
        .context("system time does not fit ledger timestamp")?;
    document.updated_unix_ms = document.updated_unix_ms.max(now);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[derive(Default)]
    struct FakeCleaner {
        calls: Vec<String>,
        unavailable_at: Option<usize>,
        mismatch_at: Option<usize>,
    }

    struct FailingStore {
        persist_calls: usize,
        fail_at: usize,
    }

    impl RecoveryStore for FailingStore {
        fn persist(&mut self, path: &Path, document: &LedgerDocument) -> Result<()> {
            let call = self.persist_calls;
            self.persist_calls += 1;
            if call == self.fail_at {
                anyhow::bail!("injected persistence failure");
            }
            atomic::write(path, document)
        }

        fn remove(&mut self, path: &Path) -> Result<()> {
            atomic::remove_if_exists(path).map(|_| ())
        }
    }

    #[derive(Default)]
    struct StatefulCleaner {
        removed: HashSet<String>,
        calls: Vec<String>,
    }

    impl ExternalResourceCleaner for StatefulCleaner {
        fn remove_if_exact(
            &mut self,
            _ledger_id: &str,
            _document: &LedgerDocument,
            resource: &ResourceRecord,
        ) -> Result<RecoveryProof> {
            let name = resource_name(resource);
            self.calls.push(name.clone());
            if self.removed.insert(name) {
                Ok(RecoveryProof::Removed)
            } else {
                Ok(RecoveryProof::AlreadyAbsent)
            }
        }
    }

    impl ExternalResourceCleaner for FakeCleaner {
        fn remove_if_exact(
            &mut self,
            _ledger_id: &str,
            document: &LedgerDocument,
            resource: &ResourceRecord,
        ) -> Result<RecoveryProof> {
            assert_eq!(document.ownership_id, "0123456789abcdef0123456789abcdef");
            let call = self.calls.len();
            self.calls.push(resource_name(resource));
            if self.unavailable_at == Some(call) {
                return Ok(RecoveryProof::TemporarilyUnavailable);
            }
            if self.mismatch_at == Some(call) {
                return Ok(RecoveryProof::IdentityMismatch);
            }
            Ok(RecoveryProof::Removed)
        }
    }

    fn resource_name(resource: &ResourceRecord) -> String {
        match resource {
            ResourceRecord::ProtectedFile { relative_path, .. } => relative_path.clone(),
            _ => panic!("unexpected test resource"),
        }
    }

    fn document() -> LedgerDocument {
        let mut document = crate::ledger::schema::sample();
        document.state = LifecycleState::Running;
        document.resources = vec![
            ResourceRecord::ProtectedFile {
                relative_path: "resources/first".to_string(),
                committed: true,
            },
            ResourceRecord::ProtectedFile {
                relative_path: "resources/second".to_string(),
                committed: true,
            },
            ResourceRecord::ProtectedFile {
                relative_path: "resources/third".to_string(),
                committed: false,
            },
        ];
        document
    }

    fn path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir()
            .join(format!("lsbsw-recovery-{label}-{}", std::process::id()))
            .join("0123456789abcdef0123456789abcdef.json")
    }

    fn stored(path: &Path) -> LedgerDocument {
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    #[test]
    fn removes_in_reverse_order_and_deletes_only_after_every_proof() {
        let path = path("complete");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let mut cleaner = FakeCleaner::default();

        assert_eq!(
            recover_document(&path, document(), &mut cleaner).unwrap(),
            RecoveryOutcome::Removed
        );
        assert_eq!(
            cleaner.calls,
            ["resources/third", "resources/second", "resources/first"]
        );
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn every_cleanup_boundary_checkpoints_progress_and_retry_is_idempotent() {
        for unavailable_at in 0..3 {
            let path = path(&format!("retry-{unavailable_at}"));
            let _ = std::fs::remove_dir_all(path.parent().unwrap());
            let mut first = FakeCleaner {
                unavailable_at: Some(unavailable_at),
                ..Default::default()
            };
            assert_eq!(
                recover_document(&path, document(), &mut first).unwrap(),
                RecoveryOutcome::RetryRequired
            );
            assert_eq!(first.calls.len(), unavailable_at + 1);
            let checkpoint = stored(&path);
            assert_eq!(checkpoint.state, LifecycleState::Cleaning);
            assert_eq!(checkpoint.resources.len(), 3 - unavailable_at);

            let mut retry = FakeCleaner::default();
            assert_eq!(
                recover_document(&path, checkpoint, &mut retry).unwrap(),
                RecoveryOutcome::Removed
            );
            assert_eq!(retry.calls.len(), 3 - unavailable_at);
            assert!(!path.exists());
            let _ = std::fs::remove_dir_all(path.parent().unwrap());
        }
    }

    #[test]
    fn identity_mismatch_quarantines_without_dropping_the_record() {
        let path = path("mismatch");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let mut cleaner = FakeCleaner {
            mismatch_at: Some(0),
            ..Default::default()
        };
        assert_eq!(
            recover_document(&path, document(), &mut cleaner).unwrap(),
            RecoveryOutcome::Quarantined
        );
        let quarantined = stored(&path);
        assert_eq!(quarantined.state, LifecycleState::Quarantined);
        assert_eq!(quarantined.resources.len(), 3);

        let mut accidental_retry = FakeCleaner::default();
        assert_eq!(
            recover_document(&path, quarantined, &mut accidental_retry).unwrap(),
            RecoveryOutcome::Quarantined
        );
        assert!(accidental_retry.calls.is_empty());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn crash_after_external_remove_before_checkpoint_requeries_as_already_absent() {
        let path = path("post-remove-crash");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let mut cleaner = StatefulCleaner::default();
        let mut store = FailingStore {
            persist_calls: 0,
            fail_at: 1,
        };

        assert!(recover_with_store(&path, document(), &mut cleaner, &mut store).is_err());
        assert_eq!(cleaner.calls, ["resources/third"]);
        let checkpoint = stored(&path);
        assert_eq!(checkpoint.state, LifecycleState::Cleaning);
        assert_eq!(checkpoint.resources.len(), 3);

        assert_eq!(
            recover_document(&path, checkpoint, &mut cleaner).unwrap(),
            RecoveryOutcome::Removed
        );
        assert_eq!(
            cleaner.calls,
            [
                "resources/third",
                "resources/third",
                "resources/second",
                "resources/first"
            ]
        );
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
