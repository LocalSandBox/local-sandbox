use std::collections::HashSet;
use std::path::Path;

use anyhow::{bail, Context, Result};

use lsb_service_proto::limits::{
    MAX_LEDGER_DOCUMENTS, MAX_LEDGER_DOCUMENT_SIZE, MAX_LEDGER_TOTAL_SIZE,
};

use super::schema::LedgerDocument;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReconcileSummary {
    pub valid_documents: usize,
    pub quarantined_documents: usize,
    pub admissions_open: bool,
}

pub fn reconcile(ledger_dir: &Path, quarantine_dir: &Path) -> Result<ReconcileSummary> {
    std::fs::create_dir_all(ledger_dir)?;
    std::fs::create_dir_all(quarantine_dir)?;
    let mut entries = std::fs::read_dir(ledger_dir)?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    if entries.len() > MAX_LEDGER_DOCUMENTS {
        bail!("protected ledger contains too many documents");
    }
    let mut names = HashSet::new();
    let mut total = 0usize;
    let mut summary = ReconcileSummary {
        admissions_open: true,
        ..Default::default()
    };
    for entry in entries {
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if !names.insert(name.to_lowercase()) {
            bail!("case-conflicting protected ledger filenames");
        }
        let size = entry.metadata()?.len() as usize;
        total = total
            .checked_add(size)
            .context("ledger total size overflow")?;
        if size > MAX_LEDGER_DOCUMENT_SIZE || total > MAX_LEDGER_TOTAL_SIZE {
            bail!("protected ledger exceeds serialized state bounds");
        }
        let valid = std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<LedgerDocument>(&bytes).ok())
            .is_some_and(|document| document.validate().is_ok());
        if valid {
            summary.valid_documents += 1;
        } else {
            let quarantine = quarantine_dir.join(format!("ledger-corrupt-{name}"));
            std::fs::rename(&path, &quarantine).with_context(|| {
                format!("quarantine invalid protected ledger {}", path.display())
            })?;
            summary.quarantined_documents += 1;
            summary.admissions_open = false;
        }
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quarantines_corruption_without_interpreting_it() {
        let root = std::env::temp_dir().join(format!("lsbsw-reconcile-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let ledger = root.join("ledger");
        let quarantine = root.join("quarantine");
        std::fs::create_dir_all(&ledger).unwrap();
        std::fs::write(ledger.join("bad.json"), b"not-json").unwrap();
        let summary = reconcile(&ledger, &quarantine).unwrap();
        assert_eq!(summary.quarantined_documents, 1);
        assert!(!summary.admissions_open);
        assert!(!ledger.join("bad.json").exists());
        assert!(quarantine.join("ledger-corrupt-bad.json").exists());
        let _ = std::fs::remove_dir_all(root);
    }
}
