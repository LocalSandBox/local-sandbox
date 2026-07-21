use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use anyhow::{bail, Context, Result};

use lsb_service_proto::limits::{
    MAX_MOUNT_COMPONENTS, MAX_MOUNT_ENTRIES, MAX_MOUNT_FILE_BYTES, MAX_MOUNT_QUEUED_CHANGES,
    MAX_MOUNT_TREE_BYTES, MAX_MOUNT_WINDOWS_UTF16,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryFingerprint {
    pub directory: bool,
    pub len: u64,
    pub modified_ns: u128,
    pub content_hash: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TreeSnapshot {
    pub entries: BTreeMap<PathBuf, EntryFingerprint>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountConflict {
    pub relative_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncDecision {
    Unchanged,
    ImportHost,
    ExportGuest,
    Converged,
    Conflict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeBatch {
    Paths(Vec<PathBuf>),
    FullRescan,
}

#[derive(Debug, Default)]
pub struct ChangeQueue {
    paths: BTreeSet<PathBuf>,
    full_rescan: bool,
}

pub const DIRTY_RECONCILE_INTERVAL: Duration = Duration::from_secs(1);
pub const IDLE_RECONCILE_INTERVAL: Duration = Duration::from_secs(30);
pub const FINAL_FLUSH_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SyncDirection {
    ImportHost,
    ExportGuest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncOperation {
    pub direction: SyncDirection,
    pub relative: PathBuf,
    pub desired: Option<EntryFingerprint>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileTrigger {
    Dirty,
    Periodic,
    Final,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileState {
    Active,
    Finalizing,
    Complete,
    Failed,
}

#[derive(Debug)]
pub struct ReconciliationPlan {
    controller_id: [u8; 16],
    epoch: u64,
    generation: u64,
    trigger: ReconcileTrigger,
    operations: Vec<SyncOperation>,
    next_baseline: TreeSnapshot,
}

impl ReconciliationPlan {
    pub fn trigger(&self) -> ReconcileTrigger {
        self.trigger
    }

    pub fn operations(&self) -> &[SyncOperation] {
        &self.operations
    }
}

#[derive(Debug)]
pub struct StagedReconciler {
    controller_id: [u8; 16],
    baseline: TreeSnapshot,
    changes: ChangeQueue,
    generation: u64,
    next_epoch: u64,
    pending: Option<(u64, u64, ReconcileTrigger)>,
    dirty_since: Option<Duration>,
    last_completed: Duration,
    last_observed: Duration,
    final_deadline: Option<Duration>,
    state: ReconcileState,
    conflict: Option<MountConflict>,
}

impl StagedReconciler {
    pub fn new(baseline: TreeSnapshot, now: Duration) -> Result<Self> {
        let mut controller_id = [0u8; 16];
        getrandom::fill(&mut controller_id).map_err(|error| {
            anyhow::anyhow!("OS random source failed for staged reconciliation: {error}")
        })?;
        Ok(Self {
            controller_id,
            baseline,
            changes: ChangeQueue::default(),
            generation: 0,
            next_epoch: 1,
            pending: None,
            dirty_since: None,
            last_completed: now,
            last_observed: now,
            final_deadline: None,
            state: ReconcileState::Active,
            conflict: None,
        })
    }

    pub fn baseline(&self) -> &TreeSnapshot {
        &self.baseline
    }

    pub fn state(&self) -> ReconcileState {
        self.state
    }

    pub fn conflict(&self) -> Option<&MountConflict> {
        self.conflict.as_ref()
    }

    pub fn notify_change(&mut self, relative: PathBuf, now: Duration) -> Result<()> {
        self.observe(now)?;
        if !matches!(
            self.state,
            ReconcileState::Active | ReconcileState::Finalizing
        ) {
            bail!("staged reconciliation is no longer accepting changes");
        }
        self.changes.push(relative)?;
        self.generation = self
            .generation
            .checked_add(1)
            .context("staged reconciliation generation overflow")?;
        self.dirty_since.get_or_insert(now);
        Ok(())
    }

    pub fn notify_full_rescan(&mut self, now: Duration) -> Result<()> {
        self.observe(now)?;
        if !matches!(
            self.state,
            ReconcileState::Active | ReconcileState::Finalizing
        ) {
            bail!("staged reconciliation is no longer accepting changes");
        }
        self.changes.mark_full_rescan();
        self.generation = self
            .generation
            .checked_add(1)
            .context("staged reconciliation generation overflow")?;
        self.dirty_since.get_or_insert(now);
        Ok(())
    }

    pub fn begin_final_flush(&mut self, now: Duration) -> Result<Duration> {
        self.observe(now)?;
        if self.state != ReconcileState::Active || self.pending.is_some() {
            bail!("staged reconciliation cannot begin final flush in its current state");
        }
        let deadline = now
            .checked_add(FINAL_FLUSH_TIMEOUT)
            .context("staged final-flush deadline overflow")?;
        self.final_deadline = Some(deadline);
        self.state = ReconcileState::Finalizing;
        Ok(deadline)
    }

    pub fn due(&mut self, now: Duration) -> Result<Option<ReconcileTrigger>> {
        self.observe(now)?;
        if self.pending.is_some()
            || matches!(
                self.state,
                ReconcileState::Complete | ReconcileState::Failed
            )
        {
            return Ok(None);
        }
        if self.state == ReconcileState::Finalizing {
            if self.final_deadline.is_some_and(|deadline| now > deadline) {
                self.state = ReconcileState::Failed;
                bail!("staged mount final flush exceeded its 30-second deadline");
            }
            return Ok(Some(ReconcileTrigger::Final));
        }
        if self
            .dirty_since
            .is_some_and(|dirty| now.saturating_sub(dirty) >= DIRTY_RECONCILE_INTERVAL)
        {
            return Ok(Some(ReconcileTrigger::Dirty));
        }
        if now.saturating_sub(self.last_completed) >= IDLE_RECONCILE_INTERVAL {
            return Ok(Some(ReconcileTrigger::Periodic));
        }
        Ok(None)
    }

    pub fn plan_due(
        &mut self,
        host: &TreeSnapshot,
        guest: &TreeSnapshot,
        now: Duration,
    ) -> Result<Option<ReconciliationPlan>> {
        let Some(trigger) = self.due(now)? else {
            return Ok(None);
        };
        if let Err(error) = validate_snapshot(&self.baseline)
            .and_then(|_| validate_snapshot(host))
            .and_then(|_| validate_snapshot(guest))
        {
            self.state = ReconcileState::Failed;
            return Err(error);
        }
        let (operations, next_baseline) =
            match build_reconciliation_plan(&self.baseline, host, guest) {
                Ok(plan) => plan,
                Err(conflict) => {
                    self.conflict = Some(conflict.clone());
                    self.state = ReconcileState::Failed;
                    return Err(conflict.into());
                }
            };
        let epoch = self.next_epoch;
        self.next_epoch = self
            .next_epoch
            .checked_add(1)
            .context("staged reconciliation epoch overflow")?;
        self.pending = Some((epoch, self.generation, trigger));
        Ok(Some(ReconciliationPlan {
            controller_id: self.controller_id,
            epoch,
            generation: self.generation,
            trigger,
            operations,
            next_baseline,
        }))
    }

    pub fn complete_cycle(&mut self, plan: ReconciliationPlan, now: Duration) -> Result<()> {
        self.observe(now)?;
        self.require_pending(&plan)?;
        if plan.trigger == ReconcileTrigger::Final {
            if let Err(error) = self.require_before_final_deadline(now) {
                self.pending = None;
                self.state = ReconcileState::Failed;
                return Err(error);
            }
        }
        self.baseline = plan.next_baseline;
        self.last_completed = now;
        self.pending = None;
        let caught_up = self.generation == plan.generation;
        if caught_up {
            let _ = self.changes.drain();
            self.dirty_since = None;
        } else {
            self.dirty_since = Some(now);
        }
        if plan.trigger == ReconcileTrigger::Final && caught_up {
            self.state = ReconcileState::Complete;
        }
        Ok(())
    }

    pub fn complete_verified_cycle(
        &mut self,
        plan: ReconciliationPlan,
        host: &TreeSnapshot,
        guest: &TreeSnapshot,
        now: Duration,
    ) -> Result<()> {
        self.observe(now)?;
        self.require_pending(&plan)?;
        if let Err(error) = validate_snapshot(host)
            .and_then(|_| validate_snapshot(guest))
            .and_then(|_| require_same_snapshot(&plan.next_baseline, host))
            .and_then(|_| require_same_snapshot(&plan.next_baseline, guest))
        {
            self.pending = None;
            self.state = ReconcileState::Failed;
            return Err(error);
        }
        self.complete_cycle(plan, now)
    }

    pub fn fail_cycle(&mut self, plan: ReconciliationPlan, now: Duration) -> Result<()> {
        self.observe(now)?;
        self.require_pending(&plan)?;
        self.pending = None;
        self.state = ReconcileState::Failed;
        Ok(())
    }

    pub fn fail_observation(&mut self, now: Duration) -> Result<()> {
        self.observe(now)?;
        if self.pending.is_some()
            || !matches!(
                self.state,
                ReconcileState::Active | ReconcileState::Finalizing
            )
        {
            bail!("staged reconciliation cannot fail an observation in its current state");
        }
        self.state = ReconcileState::Failed;
        Ok(())
    }

    pub fn fail_monitor(&mut self, now: Duration) -> Result<()> {
        self.observe(now)?;
        if !matches!(
            self.state,
            ReconcileState::Active | ReconcileState::Finalizing
        ) {
            bail!("staged reconciliation monitor cannot fail in its current state");
        }
        self.pending = None;
        self.state = ReconcileState::Failed;
        Ok(())
    }

    fn observe(&mut self, now: Duration) -> Result<()> {
        if now < self.last_observed {
            bail!("staged reconciliation clock moved backwards");
        }
        self.last_observed = now;
        Ok(())
    }

    fn require_before_final_deadline(&self, now: Duration) -> Result<()> {
        if self.final_deadline.is_some_and(|deadline| now > deadline) {
            bail!("staged mount final flush exceeded its 30-second deadline");
        }
        Ok(())
    }

    fn require_pending(&self, plan: &ReconciliationPlan) -> Result<()> {
        if plan.controller_id != self.controller_id
            || self.pending != Some((plan.epoch, plan.generation, plan.trigger))
        {
            bail!("staged reconciliation plan is stale or belongs to another cycle");
        }
        Ok(())
    }
}

impl ChangeQueue {
    pub fn mark_full_rescan(&mut self) {
        self.paths.clear();
        self.full_rescan = true;
    }

    pub fn push(&mut self, relative: PathBuf) -> Result<()> {
        validate_relative_path(&relative)?;
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            bail!("mount change must be a safe relative path");
        }
        if self.full_rescan || self.paths.contains(&relative) {
            return Ok(());
        }
        if self.paths.len() == MAX_MOUNT_QUEUED_CHANGES {
            self.paths.clear();
            self.full_rescan = true;
            return Ok(());
        }
        self.paths.insert(relative);
        Ok(())
    }

    pub fn drain(&mut self) -> ChangeBatch {
        if std::mem::take(&mut self.full_rescan) {
            self.paths.clear();
            ChangeBatch::FullRescan
        } else {
            ChangeBatch::Paths(std::mem::take(&mut self.paths).into_iter().collect())
        }
    }
}

impl std::fmt::Display for MountConflict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "MOUNT_CONFLICT on {} path(s)",
            self.relative_paths.len()
        )
    }
}

impl std::error::Error for MountConflict {}

pub fn snapshot_tree(root: &Path) -> Result<TreeSnapshot> {
    let root_metadata = std::fs::symlink_metadata(root)?;
    if root_metadata.file_type().is_symlink() || !root_metadata.file_type().is_dir() {
        bail!("staged mount root must be a regular directory");
    }
    let mut snapshot = TreeSnapshot::default();
    let mut pending = vec![(root.to_path_buf(), PathBuf::new())];
    let mut total_bytes = 0u64;
    while let Some((directory, relative_directory)) = pending.pop() {
        for entry in std::fs::read_dir(&directory)? {
            let entry = entry?;
            let metadata = std::fs::symlink_metadata(entry.path())?;
            let file_type = metadata.file_type();
            if file_type.is_symlink() || (!file_type.is_file() && !file_type.is_dir()) {
                bail!("staged mount contains an unsupported entry type");
            }
            let relative = relative_directory.join(entry.file_name());
            validate_relative_path(&relative)?;
            if snapshot.entries.len() >= MAX_MOUNT_ENTRIES {
                bail!("staged mount exceeds entry limit");
            }
            let modified = metadata.modified()?;
            let modified_ns = modified
                .duration_since(UNIX_EPOCH)
                .context("file modified time is before Unix epoch")?
                .as_nanos();
            let content_hash = if file_type.is_file() {
                if metadata.len() > MAX_MOUNT_FILE_BYTES {
                    bail!("staged mount file exceeds per-file byte limit");
                }
                total_bytes = total_bytes
                    .checked_add(metadata.len())
                    .context("staged byte overflow")?;
                if total_bytes > MAX_MOUNT_TREE_BYTES {
                    bail!("staged mount exceeds byte limit");
                }
                Some(hash_file(&entry.path(), metadata.len(), modified)?)
            } else {
                pending.push((entry.path(), relative.clone()));
                None
            };
            snapshot.entries.insert(
                relative,
                EntryFingerprint {
                    directory: file_type.is_dir(),
                    len: metadata.len(),
                    modified_ns,
                    content_hash,
                },
            );
        }
    }
    Ok(snapshot)
}

pub(crate) fn validate_relative_path(path: &Path) -> Result<()> {
    if path.components().count() > MAX_MOUNT_COMPONENTS {
        bail!("staged mount exceeds path component limit");
    }
    let value = path
        .to_str()
        .context("staged mount path is not valid Unicode")?;
    if value.encode_utf16().count() > MAX_MOUNT_WINDOWS_UTF16 {
        bail!("staged mount exceeds Windows extended-path limit");
    }
    Ok(())
}

fn validate_snapshot(snapshot: &TreeSnapshot) -> Result<()> {
    if snapshot.entries.len() > MAX_MOUNT_ENTRIES {
        bail!("staged snapshot exceeds entry limit");
    }
    let mut total_bytes = 0u64;
    for (relative, entry) in &snapshot.entries {
        validate_relative_path(relative)?;
        if relative.as_os_str().is_empty()
            || relative.is_absolute()
            || relative
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            bail!("staged snapshot contains an unsafe relative path");
        }
        if entry.directory != entry.content_hash.is_none() {
            bail!("staged snapshot fingerprint has an invalid type/hash shape");
        }
        if !entry.directory {
            if entry.len > MAX_MOUNT_FILE_BYTES {
                bail!("staged snapshot file exceeds per-file byte limit");
            }
            total_bytes = total_bytes
                .checked_add(entry.len)
                .context("staged snapshot byte overflow")?;
            if total_bytes > MAX_MOUNT_TREE_BYTES {
                bail!("staged snapshot exceeds byte limit");
            }
        }
    }
    Ok(())
}

pub fn detect_conflicts(
    baseline: &TreeSnapshot,
    host: &TreeSnapshot,
    guest: &TreeSnapshot,
) -> std::result::Result<(), MountConflict> {
    let paths = baseline
        .entries
        .keys()
        .chain(host.entries.keys())
        .chain(guest.entries.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let conflicts = paths
        .into_iter()
        .filter(|path| {
            classify_change(
                baseline.entries.get(path),
                host.entries.get(path),
                guest.entries.get(path),
            ) == SyncDecision::Conflict
        })
        .collect::<Vec<_>>();
    if conflicts.is_empty() {
        Ok(())
    } else {
        Err(MountConflict {
            relative_paths: conflicts,
        })
    }
}

pub fn plan_changes(
    baseline: &TreeSnapshot,
    host: &TreeSnapshot,
    guest: &TreeSnapshot,
) -> BTreeMap<PathBuf, SyncDecision> {
    baseline
        .entries
        .keys()
        .chain(host.entries.keys())
        .chain(guest.entries.keys())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter_map(|path| {
            let decision = classify_change(
                baseline.entries.get(&path),
                host.entries.get(&path),
                guest.entries.get(&path),
            );
            (decision != SyncDecision::Unchanged).then_some((path, decision))
        })
        .collect()
}

pub fn build_reconciliation_plan(
    baseline: &TreeSnapshot,
    host: &TreeSnapshot,
    guest: &TreeSnapshot,
) -> std::result::Result<(Vec<SyncOperation>, TreeSnapshot), MountConflict> {
    let paths = baseline
        .entries
        .keys()
        .chain(host.entries.keys())
        .chain(guest.entries.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut conflicts = Vec::new();
    let mut operations = Vec::new();
    let mut next_baseline = TreeSnapshot::default();
    for path in paths {
        let host_entry = host.entries.get(&path);
        let guest_entry = guest.entries.get(&path);
        let decision = classify_change(baseline.entries.get(&path), host_entry, guest_entry);
        let converged = match decision {
            SyncDecision::Unchanged | SyncDecision::ImportHost | SyncDecision::Converged => {
                host_entry
            }
            SyncDecision::ExportGuest => guest_entry,
            SyncDecision::Conflict => {
                conflicts.push(path);
                continue;
            }
        };
        if let Some(entry) = converged {
            next_baseline.entries.insert(path.clone(), entry.clone());
        }
        let operation = match decision {
            SyncDecision::ImportHost => Some((SyncDirection::ImportHost, host_entry)),
            SyncDecision::ExportGuest => Some((SyncDirection::ExportGuest, guest_entry)),
            SyncDecision::Unchanged | SyncDecision::Converged | SyncDecision::Conflict => None,
        };
        if let Some((direction, desired)) = operation {
            operations.push(SyncOperation {
                direction,
                relative: path,
                desired: desired.cloned(),
            });
        }
    }
    if !conflicts.is_empty() {
        return Err(MountConflict {
            relative_paths: conflicts,
        });
    }
    operations.sort_by(|left, right| {
        let left_depth = left.relative.components().count();
        let right_depth = right.relative.components().count();
        let left_group = operation_group(left);
        let right_group = operation_group(right);
        left_group
            .cmp(&right_group)
            .then_with(|| {
                if left_group == 0 {
                    right_depth.cmp(&left_depth)
                } else {
                    left_depth.cmp(&right_depth)
                }
            })
            .then_with(|| left.relative.cmp(&right.relative))
            .then_with(|| left.direction.cmp(&right.direction))
    });
    Ok((operations, next_baseline))
}

fn operation_group(operation: &SyncOperation) -> u8 {
    match operation.desired.as_ref() {
        None => 0,
        Some(entry) if entry.directory => 1,
        Some(_) => 2,
    }
}

fn classify_change(
    baseline: Option<&EntryFingerprint>,
    host: Option<&EntryFingerprint>,
    guest: Option<&EntryFingerprint>,
) -> SyncDecision {
    let host_changed = !same_entry(host, baseline);
    let guest_changed = !same_entry(guest, baseline);
    match (host_changed, guest_changed) {
        (false, false) => SyncDecision::Unchanged,
        (true, false) => SyncDecision::ImportHost,
        (false, true) => SyncDecision::ExportGuest,
        (true, true) if same_entry(host, guest) => SyncDecision::Converged,
        (true, true) => SyncDecision::Conflict,
    }
}

pub fn conflict_artifact_path(relative: &Path, session_id: &str, sequence: u64) -> Result<PathBuf> {
    validate_relative_path(relative)?;
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        bail!("conflict path must be a safe relative path");
    }
    if session_id.len() != 32
        || !session_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("conflict session id must be 32 lowercase hexadecimal characters");
    }
    let name = relative
        .file_name()
        .and_then(|name| name.to_str())
        .context("conflict path must have a Unicode filename")?;
    let conflict_name = format!("{name}.lsb-conflict-{session_id}-{sequence}");
    if conflict_name.encode_utf16().count() > 255 {
        bail!("conflict artifact filename exceeds the filesystem component limit");
    }
    let artifact = relative.with_file_name(conflict_name);
    validate_relative_path(&artifact)?;
    Ok(artifact)
}

fn same_entry(left: Option<&EntryFingerprint>, right: Option<&EntryFingerprint>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => {
            left.directory == right.directory
                && left.len == right.len
                && (left.directory || left.content_hash == right.content_hash)
        }
        _ => false,
    }
}

fn require_same_snapshot(expected: &TreeSnapshot, actual: &TreeSnapshot) -> Result<()> {
    let paths = expected
        .entries
        .keys()
        .chain(actual.entries.keys())
        .collect::<BTreeSet<_>>();
    if paths
        .into_iter()
        .any(|path| !same_entry(expected.entries.get(path), actual.entries.get(path)))
    {
        bail!("staged reconciliation result differs from its planned snapshot");
    }
    Ok(())
}

#[allow(dead_code)]
pub(super) fn mirror_tree(source: &Path, destination: &Path) -> Result<TreeSnapshot> {
    if destination.exists() {
        std::fs::remove_dir_all(destination)?;
    }
    std::fs::create_dir_all(destination)?;
    copy_directory(source, destination)?;
    snapshot_tree(destination)
}

fn copy_directory(source: &Path, destination: &Path) -> Result<()> {
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let target = destination.join(entry.file_name());
        if file_type.is_dir() {
            std::fs::create_dir(&target)?;
            copy_directory(&entry.path(), &target)?;
        } else if file_type.is_file() {
            std::fs::copy(entry.path(), target)?;
        } else {
            bail!("cannot mirror reparse or special entry");
        }
    }
    Ok(())
}

fn hash_file(
    path: &Path,
    expected_len: u64,
    expected_modified: std::time::SystemTime,
) -> Result<[u8; 32]> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut actual_len = 0u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        actual_len = actual_len
            .checked_add(read as u64)
            .context("staged file byte overflow")?;
        if actual_len > MAX_MOUNT_FILE_BYTES {
            bail!("staged mount file grew beyond its per-file byte limit");
        }
        hasher.update(&buffer[..read]);
    }
    let final_metadata = file.metadata()?;
    if actual_len != expected_len
        || final_metadata.len() != expected_len
        || final_metadata.modified()? != expected_modified
    {
        bail!("staged mount file changed while it was being snapshotted");
    }
    Ok(*hasher.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fingerprint(value: u8) -> EntryFingerprint {
        EntryFingerprint {
            directory: false,
            len: 1,
            modified_ns: value as u128,
            content_hash: Some([value; 32]),
        }
    }

    fn directory_fingerprint() -> EntryFingerprint {
        EntryFingerprint {
            directory: true,
            len: 0,
            modified_ns: 0,
            content_hash: None,
        }
    }

    #[test]
    fn one_sided_change_is_not_a_conflict() {
        let path = PathBuf::from("file");
        let baseline = TreeSnapshot {
            entries: [(path.clone(), fingerprint(1))].into(),
        };
        let host = TreeSnapshot {
            entries: [(path.clone(), fingerprint(2))].into(),
        };
        assert!(detect_conflicts(&baseline, &host, &baseline).is_ok());
    }

    #[test]
    fn divergent_two_sided_change_is_deterministic_conflict() {
        let path = PathBuf::from("file");
        let baseline = TreeSnapshot {
            entries: [(path.clone(), fingerprint(1))].into(),
        };
        let host = TreeSnapshot {
            entries: [(path.clone(), fingerprint(2))].into(),
        };
        let guest = TreeSnapshot {
            entries: [(path.clone(), fingerprint(3))].into(),
        };
        assert_eq!(
            detect_conflicts(&baseline, &host, &guest)
                .unwrap_err()
                .relative_paths,
            vec![path]
        );
    }

    #[test]
    fn planning_classifies_import_export_convergence_and_conflict() {
        let baseline = TreeSnapshot {
            entries: [
                (PathBuf::from("host"), fingerprint(1)),
                (PathBuf::from("guest"), fingerprint(1)),
                (PathBuf::from("same"), fingerprint(1)),
                (PathBuf::from("conflict"), fingerprint(1)),
            ]
            .into(),
        };
        let host = TreeSnapshot {
            entries: [
                (PathBuf::from("host"), fingerprint(2)),
                (PathBuf::from("guest"), fingerprint(1)),
                (PathBuf::from("same"), fingerprint(2)),
                (PathBuf::from("conflict"), fingerprint(2)),
            ]
            .into(),
        };
        let guest = TreeSnapshot {
            entries: [
                (PathBuf::from("host"), fingerprint(1)),
                (PathBuf::from("guest"), fingerprint(2)),
                (PathBuf::from("same"), fingerprint(2)),
                (PathBuf::from("conflict"), fingerprint(3)),
            ]
            .into(),
        };
        assert_eq!(
            plan_changes(&baseline, &host, &guest),
            [
                (PathBuf::from("conflict"), SyncDecision::Conflict),
                (PathBuf::from("guest"), SyncDecision::ExportGuest),
                (PathBuf::from("host"), SyncDecision::ImportHost),
                (PathBuf::from("same"), SyncDecision::Converged),
            ]
            .into()
        );
    }

    #[test]
    fn reconciliation_preflights_conflicts_and_orders_namespace_dependencies() {
        let directory = directory_fingerprint();
        let baseline = TreeSnapshot {
            entries: [
                (PathBuf::from("d"), directory.clone()),
                (PathBuf::from("d/old"), fingerprint(1)),
                (PathBuf::from("g"), fingerprint(1)),
                (PathBuf::from("gone"), directory.clone()),
                (PathBuf::from("gone/child"), fingerprint(1)),
            ]
            .into(),
        };
        let host = TreeSnapshot {
            entries: [
                (PathBuf::from("d"), fingerprint(2)),
                (PathBuf::from("g"), fingerprint(1)),
                (PathBuf::from("gone"), directory.clone()),
                (PathBuf::from("gone/child"), fingerprint(1)),
                (PathBuf::from("newdir"), directory.clone()),
                (PathBuf::from("newdir/file"), fingerprint(3)),
            ]
            .into(),
        };
        let guest = TreeSnapshot {
            entries: [
                (PathBuf::from("d"), directory),
                (PathBuf::from("d/old"), fingerprint(1)),
                (PathBuf::from("g"), fingerprint(4)),
            ]
            .into(),
        };

        let (operations, next) = build_reconciliation_plan(&baseline, &host, &guest).unwrap();
        assert_eq!(
            operations
                .iter()
                .map(|operation| (
                    operation.direction,
                    operation.relative.to_string_lossy().replace('\\', "/"),
                    operation.desired.as_ref().map(|entry| entry.directory),
                ))
                .collect::<Vec<_>>(),
            vec![
                (SyncDirection::ImportHost, "d/old".to_string(), None),
                (SyncDirection::ExportGuest, "gone/child".to_string(), None,),
                (SyncDirection::ExportGuest, "gone".to_string(), None),
                (SyncDirection::ImportHost, "newdir".to_string(), Some(true),),
                (SyncDirection::ImportHost, "d".to_string(), Some(false),),
                (SyncDirection::ExportGuest, "g".to_string(), Some(false),),
                (
                    SyncDirection::ImportHost,
                    "newdir/file".to_string(),
                    Some(false),
                ),
            ]
        );
        assert_eq!(next.entries.get(Path::new("g")), Some(&fingerprint(4)));
        assert!(!next.entries.contains_key(Path::new("gone")));

        let conflicting_host = TreeSnapshot {
            entries: [(PathBuf::from("g"), fingerprint(5))].into(),
        };
        assert_eq!(
            build_reconciliation_plan(&baseline, &conflicting_host, &guest)
                .unwrap_err()
                .relative_paths,
            vec![PathBuf::from("g")]
        );
    }

    #[test]
    fn reconciler_preserves_inflight_dirt_and_enforces_final_deadline() {
        let baseline = TreeSnapshot {
            entries: [(PathBuf::from("file"), fingerprint(1))].into(),
        };
        let mut reconciler = StagedReconciler::new(baseline.clone(), Duration::ZERO).unwrap();
        reconciler
            .notify_change(PathBuf::from("file"), Duration::ZERO)
            .unwrap();
        assert_eq!(
            reconciler
                .due(DIRTY_RECONCILE_INTERVAL - Duration::from_millis(1))
                .unwrap(),
            None
        );
        let plan = reconciler
            .plan_due(&baseline, &baseline, DIRTY_RECONCILE_INTERVAL)
            .unwrap()
            .unwrap();
        assert_eq!(plan.trigger(), ReconcileTrigger::Dirty);
        assert!(plan.operations().is_empty());
        let during_cycle = DIRTY_RECONCILE_INTERVAL + Duration::from_millis(100);
        reconciler
            .notify_change(PathBuf::from("later"), during_cycle)
            .unwrap();
        let completed = during_cycle + Duration::from_millis(100);
        reconciler.complete_cycle(plan, completed).unwrap();
        assert_eq!(reconciler.state(), ReconcileState::Active);
        assert_eq!(
            reconciler
                .due(completed + DIRTY_RECONCILE_INTERVAL - Duration::from_millis(1))
                .unwrap(),
            None
        );
        assert_eq!(
            reconciler
                .due(completed + DIRTY_RECONCILE_INTERVAL)
                .unwrap(),
            Some(ReconcileTrigger::Dirty)
        );

        let mut first = StagedReconciler::new(baseline.clone(), Duration::ZERO).unwrap();
        let mut second = StagedReconciler::new(baseline.clone(), Duration::ZERO).unwrap();
        for controller in [&mut first, &mut second] {
            controller
                .notify_change(PathBuf::from("file"), Duration::ZERO)
                .unwrap();
        }
        let foreign = first
            .plan_due(&baseline, &baseline, DIRTY_RECONCILE_INTERVAL)
            .unwrap()
            .unwrap();
        let _second_plan = second
            .plan_due(&baseline, &baseline, DIRTY_RECONCILE_INTERVAL)
            .unwrap()
            .unwrap();
        assert!(second
            .complete_cycle(foreign, DIRTY_RECONCILE_INTERVAL)
            .is_err());

        let start = Duration::from_secs(50);
        let mut finalizer = StagedReconciler::new(baseline.clone(), start).unwrap();
        assert_eq!(
            finalizer.due(start + IDLE_RECONCILE_INTERVAL).unwrap(),
            Some(ReconcileTrigger::Periodic)
        );
        let deadline = finalizer
            .begin_final_flush(start + IDLE_RECONCILE_INTERVAL)
            .unwrap();
        let final_plan = finalizer
            .plan_due(&baseline, &baseline, start + IDLE_RECONCILE_INTERVAL)
            .unwrap()
            .unwrap();
        assert_eq!(final_plan.trigger(), ReconcileTrigger::Final);
        let final_change = start + IDLE_RECONCILE_INTERVAL + Duration::from_secs(1);
        finalizer
            .notify_change(PathBuf::from("final-change"), final_change)
            .unwrap();
        finalizer.complete_cycle(final_plan, final_change).unwrap();
        assert_eq!(finalizer.state(), ReconcileState::Finalizing);
        let catchup = finalizer
            .plan_due(&baseline, &baseline, final_change)
            .unwrap()
            .unwrap();
        assert_eq!(catchup.trigger(), ReconcileTrigger::Final);
        finalizer.complete_cycle(catchup, deadline).unwrap();
        assert_eq!(finalizer.state(), ReconcileState::Complete);

        let mut timeout = StagedReconciler::new(baseline.clone(), Duration::ZERO).unwrap();
        let deadline = timeout.begin_final_flush(Duration::ZERO).unwrap();
        let plan = timeout
            .plan_due(&baseline, &baseline, Duration::ZERO)
            .unwrap()
            .unwrap();
        assert!(timeout
            .complete_cycle(plan, deadline + Duration::from_nanos(1))
            .is_err());
        assert_eq!(timeout.state(), ReconcileState::Failed);

        let mut failed = StagedReconciler::new(baseline.clone(), Duration::ZERO).unwrap();
        failed
            .notify_change(PathBuf::from("file"), Duration::ZERO)
            .unwrap();
        let plan = failed
            .plan_due(&baseline, &baseline, DIRTY_RECONCILE_INTERVAL)
            .unwrap()
            .unwrap();
        failed.fail_cycle(plan, DIRTY_RECONCILE_INTERVAL).unwrap();
        assert_eq!(failed.state(), ReconcileState::Failed);
        assert!(failed
            .notify_change(PathBuf::from("file"), DIRTY_RECONCILE_INTERVAL)
            .is_err());

        let mut observation_failed =
            StagedReconciler::new(baseline.clone(), Duration::ZERO).unwrap();
        observation_failed
            .fail_observation(DIRTY_RECONCILE_INTERVAL)
            .unwrap();
        assert_eq!(observation_failed.state(), ReconcileState::Failed);
        assert!(observation_failed
            .fail_observation(DIRTY_RECONCILE_INTERVAL)
            .is_err());

        let changed = TreeSnapshot {
            entries: [(PathBuf::from("file"), fingerprint(2))].into(),
        };
        let mut verified = StagedReconciler::new(baseline.clone(), Duration::ZERO).unwrap();
        verified
            .notify_change(PathBuf::from("file"), Duration::ZERO)
            .unwrap();
        let plan = verified
            .plan_due(&changed, &baseline, DIRTY_RECONCILE_INTERVAL)
            .unwrap()
            .unwrap();
        verified
            .complete_verified_cycle(plan, &changed, &changed, DIRTY_RECONCILE_INTERVAL)
            .unwrap();
        assert_eq!(verified.baseline(), &changed);

        let mut drifted = StagedReconciler::new(baseline.clone(), Duration::ZERO).unwrap();
        drifted
            .notify_change(PathBuf::from("file"), Duration::ZERO)
            .unwrap();
        let plan = drifted
            .plan_due(&changed, &baseline, DIRTY_RECONCILE_INTERVAL)
            .unwrap()
            .unwrap();
        assert!(drifted
            .complete_verified_cycle(plan, &changed, &baseline, DIRTY_RECONCILE_INTERVAL)
            .is_err());
        assert_eq!(drifted.state(), ReconcileState::Failed);

        let divergent = TreeSnapshot {
            entries: [(PathBuf::from("file"), fingerprint(3))].into(),
        };
        let mut conflicted = StagedReconciler::new(baseline.clone(), Duration::ZERO).unwrap();
        conflicted
            .notify_change(PathBuf::from("file"), Duration::ZERO)
            .unwrap();
        assert!(conflicted
            .plan_due(&changed, &divergent, DIRTY_RECONCILE_INTERVAL)
            .is_err());
        assert_eq!(
            conflicted.conflict().unwrap().relative_paths,
            vec![PathBuf::from("file")]
        );
        assert_eq!(conflicted.state(), ReconcileState::Failed);

        let mut invalid = StagedReconciler::new(baseline.clone(), Duration::ZERO).unwrap();
        invalid
            .notify_change(PathBuf::from("file"), Duration::ZERO)
            .unwrap();
        let unsafe_host = TreeSnapshot {
            entries: [(PathBuf::from("../escape"), fingerprint(1))].into(),
        };
        assert!(invalid
            .plan_due(&unsafe_host, &baseline, DIRTY_RECONCILE_INTERVAL)
            .is_err());
        assert_eq!(invalid.state(), ReconcileState::Failed);
    }

    #[test]
    fn conflict_artifact_name_is_exact_and_bounded() {
        let session = "0123456789abcdef0123456789abcdef";
        assert_eq!(
            conflict_artifact_path(Path::new("output/report.txt"), session, 17).unwrap(),
            PathBuf::from(format!("output/report.txt.lsb-conflict-{session}-17"))
        );
        assert!(conflict_artifact_path(Path::new("../report.txt"), session, 1).is_err());
        assert!(conflict_artifact_path(Path::new("report.txt"), "UPPER", 1).is_err());
        assert!(conflict_artifact_path(Path::new(&"a".repeat(230)), session, 1).is_err());
    }

    #[test]
    fn snapshot_rejects_symlink_roots_entries_and_oversized_sparse_files() {
        let root = std::env::temp_dir().join(format!("lsbsw-mount-sync-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let oversized = root.join("oversized");
        std::fs::File::create(&oversized)
            .unwrap()
            .set_len(MAX_MOUNT_FILE_BYTES + 1)
            .unwrap();
        assert!(snapshot_tree(&root).is_err());
        std::fs::remove_file(oversized).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let target = root.join("target");
            std::fs::write(&target, b"data").unwrap();
            symlink(&target, root.join("link")).unwrap();
            assert!(snapshot_tree(&root).is_err());
            std::fs::remove_file(root.join("link")).unwrap();
            let root_link = root.with_extension("link");
            let _ = std::fs::remove_file(&root_link);
            symlink(&root, &root_link).unwrap();
            assert!(snapshot_tree(&root_link).is_err());
            std::fs::remove_file(root_link).unwrap();
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn path_limits_are_enforced_without_filesystem_dependent_setup() {
        let deep = (0..=MAX_MOUNT_COMPONENTS).fold(PathBuf::new(), |path, _| path.join("d"));
        assert!(validate_relative_path(&deep).is_err());
        assert!(
            validate_relative_path(Path::new(&"x".repeat(MAX_MOUNT_WINDOWS_UTF16 + 1))).is_err()
        );
    }

    #[test]
    fn change_queue_coalesces_and_overflow_becomes_one_bounded_rescan() {
        let mut queue = ChangeQueue::default();
        queue.push(PathBuf::from("same")).unwrap();
        queue.push(PathBuf::from("same")).unwrap();
        assert_eq!(
            queue.drain(),
            ChangeBatch::Paths(vec![PathBuf::from("same")])
        );

        for index in 0..=MAX_MOUNT_QUEUED_CHANGES {
            queue.push(PathBuf::from(format!("path-{index}"))).unwrap();
        }
        assert_eq!(queue.drain(), ChangeBatch::FullRescan);
        assert_eq!(queue.drain(), ChangeBatch::Paths(Vec::new()));
        assert!(queue.push(PathBuf::from("../unsafe")).is_err());
    }

    #[test]
    fn full_rescan_notification_schedules_one_dirty_cycle() {
        let baseline = TreeSnapshot::default();
        let mut reconciler = StagedReconciler::new(baseline, Duration::ZERO).unwrap();
        reconciler
            .notify_full_rescan(Duration::from_millis(10))
            .unwrap();
        assert_eq!(
            reconciler
                .due(Duration::from_millis(10) + DIRTY_RECONCILE_INTERVAL)
                .unwrap(),
            Some(ReconcileTrigger::Dirty)
        );
    }

    #[test]
    fn monitor_failure_invalidates_an_inflight_plan() {
        let baseline = TreeSnapshot::default();
        let mut reconciler = StagedReconciler::new(baseline.clone(), Duration::ZERO).unwrap();
        reconciler
            .notify_change(PathBuf::from("file"), Duration::ZERO)
            .unwrap();
        let planned_at = DIRTY_RECONCILE_INTERVAL;
        let plan = reconciler
            .plan_due(&baseline, &baseline, planned_at)
            .unwrap()
            .unwrap();
        reconciler.fail_monitor(planned_at).unwrap();
        assert_eq!(reconciler.state(), ReconcileState::Failed);
        assert!(reconciler.complete_cycle(plan, planned_at).is_err());
    }
}
