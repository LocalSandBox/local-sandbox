use std::collections::HashMap;
use std::fs::DirEntry;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use lsb_service_proto::limits::{
    MAX_LEDGER_DOCUMENTS, MAX_LEDGER_DOCUMENT_SIZE, MAX_LEDGER_TOTAL_SIZE,
};

use super::schema::LedgerDocument;
use super::{recover_document, ExternalResourceCleaner, RecoveryOutcome};

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReconcileSummary {
    pub valid_documents: usize,
    pub quarantined_documents: usize,
    pub unproven_documents: usize,
    pub admissions_open: bool,
}

struct Candidate {
    path: PathBuf,
    document: LedgerDocument,
}

pub fn reconcile(ledger_dir: &Path, quarantine_dir: &Path) -> Result<ReconcileSummary> {
    std::fs::create_dir_all(ledger_dir)?;
    std::fs::create_dir_all(quarantine_dir)?;
    let Some(mut entries) = read_bounded_entries(ledger_dir, MAX_LEDGER_DOCUMENTS)? else {
        return Ok(ReconcileSummary {
            unproven_documents: 1,
            admissions_open: false,
            ..Default::default()
        });
    };
    entries.sort_by_key(DirEntry::file_name);

    let mut total = 0usize;
    let mut summary = ReconcileSummary {
        admissions_open: true,
        ..Default::default()
    };
    let mut candidates = Vec::with_capacity(entries.len());
    for entry in entries {
        let path = entry.path();
        match validate_entry(&entry, &mut total).and_then(|()| read_document_bounded(&path)) {
            Ok(document) => candidates.push(Candidate { path, document }),
            Err(_) => quarantine_or_mark_unproven(&path, quarantine_dir, &mut summary),
        }
    }

    let mut ownership_counts = HashMap::new();
    for candidate in &candidates {
        *ownership_counts
            .entry(candidate.document.ownership_id.clone())
            .or_insert(0usize) += 1;
    }
    for candidate in candidates {
        if ownership_counts[&candidate.document.ownership_id] == 1 {
            summary.valid_documents += 1;
        } else {
            quarantine_or_mark_unproven(&candidate.path, quarantine_dir, &mut summary);
        }
    }
    // A valid document is still an outstanding cleanup obligation. Until the Windows
    // exact-proof cleaner has converged it, admitting new work would lose fail-closed
    // crash semantics even though the document itself is well formed.
    if summary.valid_documents != 0 {
        summary.admissions_open = false;
    }
    Ok(summary)
}

pub fn reconcile_and_recover(
    ledger_dir: &Path,
    quarantine_dir: &Path,
    cleaner: &mut impl ExternalResourceCleaner,
) -> Result<ReconcileSummary> {
    let mut summary = reconcile(ledger_dir, quarantine_dir)?;
    if summary.valid_documents == 0 {
        return Ok(summary);
    }

    let expected_documents = summary.valid_documents;
    summary.valid_documents = 0;
    let Some(mut entries) = read_bounded_entries(ledger_dir, MAX_LEDGER_DOCUMENTS)? else {
        summary.unproven_documents += 1;
        summary.admissions_open = false;
        return Ok(summary);
    };
    entries.sort_by_key(DirEntry::file_name);
    let mut total = 0usize;
    let mut candidates = Vec::with_capacity(expected_documents);
    for entry in entries {
        let path = entry.path();
        let document =
            match validate_entry(&entry, &mut total).and_then(|()| read_document_bounded(&path)) {
                Ok(document) => document,
                Err(_) => {
                    quarantine_or_mark_unproven(&path, quarantine_dir, &mut summary);
                    continue;
                }
            };
        candidates.push(Candidate { path, document });
    }
    if summary.quarantined_documents != 0 || summary.unproven_documents != 0 {
        summary.admissions_open = false;
        return Ok(summary);
    }
    let mut ownership_counts = HashMap::new();
    for candidate in &candidates {
        *ownership_counts
            .entry(candidate.document.ownership_id.clone())
            .or_insert(0usize) += 1;
    }
    if candidates.len() != expected_documents || ownership_counts.values().any(|count| *count != 1)
    {
        summary.unproven_documents += 1;
        summary.admissions_open = false;
        return Ok(summary);
    }

    for candidate in candidates {
        match recover_document(&candidate.path, candidate.document, cleaner)? {
            RecoveryOutcome::Removed => {}
            RecoveryOutcome::Quarantined | RecoveryOutcome::RetryRequired => {
                summary.valid_documents += 1;
            }
        }
    }
    summary.admissions_open = summary.valid_documents == 0
        && summary.quarantined_documents == 0
        && summary.unproven_documents == 0;
    Ok(summary)
}

fn read_bounded_entries(directory: &Path, maximum: usize) -> Result<Option<Vec<DirEntry>>> {
    let mut entries = Vec::with_capacity(maximum.min(64));
    for entry in std::fs::read_dir(directory)? {
        if entries.len() == maximum {
            return Ok(None);
        }
        entries.push(entry?);
    }
    Ok(Some(entries))
}

fn validate_entry(entry: &DirEntry, total: &mut usize) -> Result<()> {
    let file_type = entry.file_type()?;
    anyhow::ensure!(file_type.is_file(), "ledger entry is not a regular file");
    let name = entry
        .file_name()
        .into_string()
        .map_err(|_| anyhow::anyhow!("ledger filename is not UTF-8"))?;
    let stem = name
        .strip_suffix(".json")
        .context("ledger filename does not end in .json")?;
    anyhow::ensure!(
        is_hex_id(stem),
        "ledger filename is not an opaque sandbox id"
    );

    let size = usize::try_from(entry.metadata()?.len()).context("ledger entry size overflow")?;
    *total = total
        .checked_add(size)
        .context("ledger total size overflow")?;
    anyhow::ensure!(
        size <= MAX_LEDGER_DOCUMENT_SIZE && *total <= MAX_LEDGER_TOTAL_SIZE,
        "protected ledger exceeds serialized state bounds"
    );
    Ok(())
}

fn read_document_bounded(path: &Path) -> Result<LedgerDocument> {
    let file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take((MAX_LEDGER_DOCUMENT_SIZE + 1) as u64)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= MAX_LEDGER_DOCUMENT_SIZE,
        "ledger document grew beyond its bound while reading"
    );
    let document: LedgerDocument = serde_json::from_slice(&bytes)?;
    document.validate()?;
    Ok(document)
}

fn quarantine_or_mark_unproven(path: &Path, quarantine_dir: &Path, summary: &mut ReconcileSummary) {
    summary.admissions_open = false;
    for sequence in 0..=MAX_LEDGER_DOCUMENTS {
        let destination = quarantine_dir.join(format!("ledger-corrupt-{sequence:04}.entry"));
        if destination.exists() {
            continue;
        }
        if std::fs::rename(path, destination).is_ok() {
            summary.quarantined_documents += 1;
            return;
        }
        break;
    }
    summary.unproven_documents += 1;
}

fn is_hex_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("lsbsw-reconcile-{label}-{}", std::process::id()))
    }

    fn write_valid(path: &Path, ownership_id: &str) {
        let mut document = crate::ledger::schema::sample();
        document.ownership_id = ownership_id.to_string();
        std::fs::write(path, serde_json::to_vec(&document).unwrap()).unwrap();
    }

    struct RemovingCleaner;

    impl ExternalResourceCleaner for RemovingCleaner {
        fn remove_if_exact(
            &mut self,
            _ledger_id: &str,
            _document: &crate::ledger::schema::LedgerDocument,
            _resource: &crate::ledger::schema::ResourceRecord,
        ) -> Result<crate::ledger::RecoveryProof> {
            Ok(crate::ledger::RecoveryProof::AlreadyAbsent)
        }
    }

    #[test]
    fn quarantines_corruption_without_interpreting_it() {
        let root = root("corrupt");
        let _ = std::fs::remove_dir_all(&root);
        let ledger = root.join("ledger");
        let quarantine = root.join("quarantine");
        std::fs::create_dir_all(&ledger).unwrap();
        std::fs::write(
            ledger.join("0123456789abcdef0123456789abcdef.json"),
            b"not-json",
        )
        .unwrap();
        let summary = reconcile(&ledger, &quarantine).unwrap();
        assert_eq!(summary.quarantined_documents, 1);
        assert_eq!(summary.unproven_documents, 0);
        assert!(!summary.admissions_open);
        assert!(std::fs::read_dir(&ledger).unwrap().next().is_none());
        assert_eq!(std::fs::read_dir(&quarantine).unwrap().count(), 1);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn accepts_one_strict_document_with_unique_ownership() {
        let root = root("valid");
        let _ = std::fs::remove_dir_all(&root);
        let ledger = root.join("ledger");
        let quarantine = root.join("quarantine");
        std::fs::create_dir_all(&ledger).unwrap();
        write_valid(
            &ledger.join("0123456789abcdef0123456789abcdef.json"),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );

        let summary = reconcile(&ledger, &quarantine).unwrap();
        assert_eq!(summary.valid_documents, 1);
        assert_eq!(summary.quarantined_documents, 0);
        assert_eq!(summary.unproven_documents, 0);
        assert!(!summary.admissions_open);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn exact_recovery_removes_valid_obligations_before_opening_admissions() {
        let root = root("recover-valid");
        let _ = std::fs::remove_dir_all(&root);
        let ledger = root.join("ledger");
        let quarantine = root.join("quarantine");
        std::fs::create_dir_all(&ledger).unwrap();
        write_valid(
            &ledger.join("0123456789abcdef0123456789abcdef.json"),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );

        let summary = reconcile_and_recover(&ledger, &quarantine, &mut RemovingCleaner).unwrap();
        assert_eq!(summary.valid_documents, 0);
        assert!(summary.admissions_open);
        assert!(std::fs::read_dir(&ledger).unwrap().next().is_none());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn ignores_no_unknown_or_temporary_ledger_entries() {
        let root = root("unknown");
        let _ = std::fs::remove_dir_all(&root);
        let ledger = root.join("ledger");
        let quarantine = root.join("quarantine");
        std::fs::create_dir_all(&ledger).unwrap();
        write_valid(&ledger.join("bad.json"), "0123456789abcdef0123456789abcdef");
        std::fs::write(ledger.join(".orphan.tmp"), b"pending").unwrap();

        let summary = reconcile(&ledger, &quarantine).unwrap();
        assert_eq!(summary.valid_documents, 0);
        assert_eq!(summary.quarantined_documents, 2);
        assert!(!summary.admissions_open);
        assert!(std::fs::read_dir(&ledger).unwrap().next().is_none());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn duplicate_ownership_ids_quarantine_every_ambiguous_document() {
        let root = root("duplicate-owner");
        let _ = std::fs::remove_dir_all(&root);
        let ledger = root.join("ledger");
        let quarantine = root.join("quarantine");
        std::fs::create_dir_all(&ledger).unwrap();
        let ownership = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        write_valid(
            &ledger.join("0123456789abcdef0123456789abcdef.json"),
            ownership,
        );
        write_valid(
            &ledger.join("fedcba9876543210fedcba9876543210.json"),
            ownership,
        );

        let summary = reconcile(&ledger, &quarantine).unwrap();
        assert_eq!(summary.valid_documents, 0);
        assert_eq!(summary.quarantined_documents, 2);
        assert!(!summary.admissions_open);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn excessive_entry_count_is_bounded_and_fails_health_only() {
        let root = root("bounded");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("one"), b"1").unwrap();
        std::fs::write(root.join("two"), b"2").unwrap();
        std::fs::write(root.join("three"), b"3").unwrap();

        assert!(read_bounded_entries(&root, 3).unwrap().is_some());
        assert!(read_bounded_entries(&root, 2).unwrap().is_none());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_entry_is_quarantined_without_reading_or_removing_its_target() {
        use std::os::unix::fs::symlink;

        let root = root("symlink");
        let _ = std::fs::remove_dir_all(&root);
        let ledger = root.join("ledger");
        let quarantine = root.join("quarantine");
        std::fs::create_dir_all(&ledger).unwrap();
        let target = root.join("target");
        std::fs::write(&target, b"do-not-read-or-delete").unwrap();
        symlink(
            &target,
            ledger.join("0123456789abcdef0123456789abcdef.json"),
        )
        .unwrap();

        let summary = reconcile(&ledger, &quarantine).unwrap();
        assert_eq!(summary.quarantined_documents, 1);
        assert_eq!(std::fs::read(&target).unwrap(), b"do-not-read-or-delete");
        let _ = std::fs::remove_dir_all(root);
    }
}
