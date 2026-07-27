use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

const MARKER_NAME: &str = "run-marker.json";
const CONTEXT_NAME: &str = "crash-context.json";
const MAX_MARKER_BYTES: u64 = 256 * 1024;
const MAX_ACTIVE_INSTANCES: usize = 64;
const MAX_PREVIOUS_RUNS: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviousRun {
    pub run_id: String,
    pub started_utc: String,
    pub last_updated_utc: String,
    pub current_phase: String,
    pub last_completed_boundary: Option<String>,
    pub active_instances: BTreeMap<String, String>,
    pub marker_path: PathBuf,
    pub context_path: PathBuf,
    pub termination_intent: Option<lsb_seawork_update::TerminationIntent>,
    pub termination_intent_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunDocument {
    schema_version: u32,
    run_id: String,
    started_utc: String,
    last_updated_utc: String,
    current_phase: String,
    last_completed_boundary: Option<String>,
    active_instances: BTreeMap<String, String>,
    orderly_stop: bool,
}

pub struct RunState {
    marker_path: PathBuf,
    context_path: PathBuf,
    document: Mutex<RunDocument>,
}

impl std::fmt::Debug for RunState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RunState")
            .field("marker_path", &self.marker_path)
            .field("context_path", &self.context_path)
            .finish_non_exhaustive()
    }
}

impl RunState {
    pub fn begin(
        runtime_root: &Path,
        now_utc: impl Into<String>,
    ) -> Result<(Self, Option<PreviousRun>)> {
        let now_utc = bounded(now_utc.into(), 64);
        let marker_path = runtime_root.join(MARKER_NAME);
        let context_path = runtime_root.join(CONTEXT_NAME);
        let previous = read_previous(runtime_root, &marker_path, &context_path)?;
        let document = RunDocument {
            schema_version: 1,
            run_id: random_id()?,
            started_utc: now_utc.clone(),
            last_updated_utc: now_utc,
            current_phase: "service.start".to_string(),
            last_completed_boundary: None,
            active_instances: BTreeMap::new(),
            orderly_stop: false,
        };
        crate::ledger::atomic::write_value(&marker_path, &document)
            .context("write telemetry run marker")?;
        crate::ledger::atomic::write_value(&context_path, &document)
            .context("write telemetry crash context")?;
        Ok((
            Self {
                marker_path,
                context_path,
                document: Mutex::new(document),
            },
            previous,
        ))
    }

    pub fn run_id(&self) -> Result<String> {
        Ok(self
            .document
            .lock()
            .map_err(|_| anyhow::anyhow!("telemetry run state poisoned"))?
            .run_id
            .clone())
    }

    pub fn update(
        &self,
        phase: String,
        resource_id: Option<&str>,
        instance_path: Option<&Path>,
        boundary_completed: bool,
    ) -> Result<()> {
        let mut document = self
            .document
            .lock()
            .map_err(|_| anyhow::anyhow!("telemetry run state poisoned"))?;
        document.current_phase = bounded(phase, 128);
        document.last_updated_utc = now_utc();
        if boundary_completed {
            document.last_completed_boundary = Some(document.current_phase.clone());
        }
        match (resource_id, instance_path) {
            (Some(resource_id), Some(instance_path)) => {
                if document.active_instances.len() >= MAX_ACTIVE_INSTANCES
                    && !document.active_instances.contains_key(resource_id)
                {
                    bail!("telemetry active instance bound reached");
                }
                document.active_instances.insert(
                    bounded(resource_id.to_string(), 128),
                    bounded(instance_path.display().to_string(), 2_048),
                );
            }
            (Some(resource_id), None) => {
                document.active_instances.remove(resource_id);
            }
            (None, _) => {}
        }
        crate::ledger::atomic::write_value(&self.context_path, &*document)
            .context("update telemetry crash context")?;
        crate::ledger::atomic::write_value(&self.marker_path, &*document)
            .context("update telemetry run marker")
    }

    pub fn close(&self) -> Result<()> {
        let mut document = self
            .document
            .lock()
            .map_err(|_| anyhow::anyhow!("telemetry run state poisoned"))?;
        document.current_phase = "service.stopped".to_string();
        document.last_completed_boundary = Some("service.stopped".to_string());
        document.last_updated_utc = now_utc();
        document.orderly_stop = true;
        document.active_instances.clear();
        crate::ledger::atomic::write_value(&self.context_path, &*document)
            .context("close telemetry crash context")?;
        crate::ledger::atomic::write_value(&self.marker_path, &*document)
            .context("close telemetry run marker")
    }
}

fn read_previous(
    runtime_root: &Path,
    marker_path: &Path,
    context_path: &Path,
) -> Result<Option<PreviousRun>> {
    let active_intent_path = runtime_root.join("termination-intent.json");
    let Some(marker) = read_document(marker_path)? else {
        let _ = lsb_seawork_update::remove_file_if_exists(&active_intent_path);
        return Ok(None);
    };
    let termination_intent =
        lsb_seawork_update::load_json::<lsb_seawork_update::TerminationIntent>(&active_intent_path)
            .ok()
            .filter(|intent| intent.validate().is_ok() && intent.run_id == marker.run_id);
    if marker.orderly_stop {
        let _ = lsb_seawork_update::remove_file_if_exists(&active_intent_path);
        return Ok(None);
    }
    let context = read_document(context_path)?.unwrap_or_else(|| marker.clone());
    let snapshot_root = runtime_root
        .join("telemetry")
        .join("previous-runs")
        .join(&marker.run_id);
    let snapshot_marker = snapshot_root.join(MARKER_NAME);
    let snapshot_context = snapshot_root.join(CONTEXT_NAME);
    let snapshot_intent = snapshot_root.join("termination-intent.json");
    crate::ledger::atomic::write_value(&snapshot_marker, &marker)
        .context("snapshot previous telemetry run marker")?;
    crate::ledger::atomic::write_value(&snapshot_context, &context)
        .context("snapshot previous telemetry crash context")?;
    let termination_intent_path = termination_intent.as_ref().and_then(|intent| {
        crate::ledger::atomic::write_value(&snapshot_intent, intent)
            .ok()
            .map(|()| snapshot_intent)
    });
    let _ = lsb_seawork_update::remove_file_if_exists(&active_intent_path);
    prune_previous_runs(
        snapshot_root
            .parent()
            .context("previous-run snapshot has no parent")?,
    );
    Ok(Some(PreviousRun {
        run_id: marker.run_id,
        started_utc: marker.started_utc,
        last_updated_utc: context.last_updated_utc,
        current_phase: context.current_phase,
        last_completed_boundary: context.last_completed_boundary,
        active_instances: context.active_instances,
        marker_path: snapshot_marker,
        context_path: snapshot_context,
        termination_intent,
        termination_intent_path,
    }))
}

fn prune_previous_runs(root: &Path) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    let mut directories = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let metadata = entry.metadata().ok()?;
            metadata
                .is_dir()
                .then(|| (metadata.modified().ok(), entry.path()))
        })
        .collect::<Vec<_>>();
    directories.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
    let remove_count = directories.len().saturating_sub(MAX_PREVIOUS_RUNS);
    for (_, path) in directories.into_iter().take(remove_count) {
        let _ = std::fs::remove_dir_all(path);
    }
}

fn read_document(path: &Path) -> Result<Option<RunDocument>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_MARKER_BYTES
    {
        bail!("telemetry run marker is not a bounded regular file");
    }
    let bytes = std::fs::read(path).context("read telemetry run marker")?;
    let document: RunDocument =
        serde_json::from_slice(&bytes).context("parse telemetry run marker")?;
    validate_document(&document)?;
    Ok(Some(document))
}

fn validate_document(document: &RunDocument) -> Result<()> {
    if document.schema_version != 1
        || !valid_id(&document.run_id)
        || document.started_utc.len() > 64
        || document.last_updated_utc.len() > 64
        || document.current_phase.len() > 128
        || document
            .last_completed_boundary
            .as_ref()
            .is_some_and(|value| value.len() > 128)
        || document.active_instances.len() > MAX_ACTIVE_INSTANCES
        || document
            .active_instances
            .iter()
            .any(|(id, path)| id.len() > 128 || path.len() > 2_048)
    {
        bail!("telemetry run marker violates compiled bounds");
    }
    Ok(())
}

fn random_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|error| anyhow::anyhow!("generate telemetry run ID: {error}"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn valid_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn bounded(mut value: String, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value;
    }
    let mut boundary = max_bytes;
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value.truncate(boundary);
    value
}

fn now_utc() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "lsbs-run-marker-{label}-{}",
            crate::session::ResourceHandle::random().unwrap()
        ))
    }

    #[test]
    fn orderly_run_is_not_reported_on_next_start() {
        let root = root("orderly");
        let (state, previous) = RunState::begin(&root, "2026-07-25T00:00:00Z").unwrap();
        assert!(previous.is_none());
        state.close().unwrap();
        let (_, previous) = RunState::begin(&root, "2026-07-25T00:01:00Z").unwrap();
        assert!(previous.is_none());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unclean_run_preserves_last_crash_context() {
        let root = root("unclean");
        let (state, _) = RunState::begin(&root, "2026-07-25T00:00:00Z").unwrap();
        let previous_id = state.run_id().unwrap();
        state
            .update(
                "sandbox.boot".to_string(),
                Some("sandbox-1"),
                Some(Path::new(r"C:\ProgramData\instance")),
                false,
            )
            .unwrap();
        drop(state);

        let (_, previous) = RunState::begin(&root, "2026-07-25T00:01:00Z").unwrap();
        let previous = previous.unwrap();
        assert_eq!(previous.run_id, previous_id);
        assert_eq!(previous.current_phase, "sandbox.boot");
        assert!(previous.active_instances.contains_key("sandbox-1"));
        assert!(previous.marker_path.is_file());
        assert!(previous.context_path.is_file());
        assert_ne!(previous.marker_path, root.join(MARKER_NAME));
        assert!(std::fs::read_to_string(&previous.context_path)
            .unwrap()
            .contains(&previous_id));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unclean_run_snapshots_matching_updater_termination_intent() {
        let root = root("termination-intent");
        let (state, _) = RunState::begin(&root, "2026-07-25T00:00:00Z").unwrap();
        let run_id = state.run_id().unwrap();
        let intent = lsb_seawork_update::TerminationIntent::update_activation(
            run_id,
            "2".repeat(32),
            "2026-07-25T00:00:01Z",
            "0.5.1",
        )
        .unwrap();
        let intent_path = root.join("termination-intent.json");
        lsb_seawork_update::write_json_atomic(&intent_path, &intent).unwrap();
        drop(state);

        let (_, previous) = RunState::begin(&root, "2026-07-25T00:01:00Z").unwrap();
        let previous = previous.unwrap();
        assert_eq!(previous.termination_intent, Some(intent));
        assert!(previous
            .termination_intent_path
            .as_ref()
            .is_some_and(|path| path.is_file()));
        assert!(!intent_path.exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn telemetry_updates_are_fail_open_when_state_write_fails() {
        let root = root("fail-open");
        let (state, _) = RunState::begin(&root, "2026-07-25T00:00:00Z").unwrap();
        let telemetry = crate::telemetry::Telemetry::disabled().with_run_state(Arc::new(state));
        let context_path = root.join(CONTEXT_NAME);
        std::fs::remove_file(&context_path).unwrap();
        std::fs::create_dir(&context_path).unwrap();
        telemetry.update_crash_context("sandbox.boot", Some("sandbox-1"), Some(&root), false);
        telemetry.close_run();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn markers_are_atomically_replaced_without_temporary_files() {
        let root = root("atomic");
        let (state, _) = RunState::begin(&root, "2026-07-25T00:00:00Z").unwrap();
        for index in 0..10 {
            state
                .update(format!("phase-{index}"), None, None, true)
                .unwrap();
        }
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 2);
        std::fs::remove_dir_all(root).unwrap();
    }
}
