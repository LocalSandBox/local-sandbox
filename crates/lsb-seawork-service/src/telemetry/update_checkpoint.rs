use sha2::{Digest, Sha256};

use lsb_seawork_update::{UpdateCheckpointBoundary, UpdateTransition, UpdateTransitionOutcome};

use super::{
    update_trace::timestamp_micros, SpanDescription, SpanStatus, Telemetry,
    TRANSACTION_SERVICE_UPDATE_CHECKPOINT,
};

pub(crate) struct UpdateCheckpoint<'a> {
    pub hostname: &'a str,
    pub attempt_id: &'a str,
    pub transaction_id: Option<&'a str>,
    pub source_version: &'a str,
    pub target_version: Option<&'a str>,
    pub target_archive_sha256: Option<&'a str>,
    pub installed_version: &'a str,
    pub channel: &'a str,
    pub run_id: Option<&'a str>,
    pub retry_count: u8,
    pub transition: &'a UpdateTransition,
    pub boundary: UpdateCheckpointBoundary,
}

pub(crate) fn checkpoint_identity(checkpoint: &UpdateCheckpoint<'_>) -> String {
    format!(
        "{:x}",
        Sha256::digest(format!(
            "{}\0{}\0{}\0{}\0{}",
            checkpoint.hostname,
            checkpoint.attempt_id,
            checkpoint.transition.phase,
            transition_utc(checkpoint),
            checkpoint_outcome(checkpoint)
        ))
    )
}

pub(crate) fn emit_update_checkpoint(
    telemetry: &Telemetry,
    checkpoint: &UpdateCheckpoint<'_>,
) -> Option<String> {
    let timestamp = timestamp_micros(transition_utc(checkpoint))?;
    let outcome = checkpoint_outcome(checkpoint);
    let actor = format!("{:?}", checkpoint.transition.actor).to_ascii_lowercase();
    let mut description = SpanDescription::transaction(TRANSACTION_SERVICE_UPDATE_CHECKPOINT)
        .always_sampled()
        .started_at(timestamp)
        .with_tag("update.phase", &checkpoint.transition.phase)
        .with_tag("update.outcome", outcome)
        .with_tag("update.channel", checkpoint.channel)
        .with_tag("update.source_version", checkpoint.source_version)
        .with_data("user.id", checkpoint.hostname)
        .with_data("update.attempt_id", checkpoint.attempt_id)
        .with_data("update.source_version", checkpoint.source_version)
        .with_data("update.phase", &checkpoint.transition.phase)
        .with_data("update.outcome", outcome)
        .with_data("update.actor", actor)
        .with_data("update.transition_utc", transition_utc(checkpoint))
        .with_data("update.event_identity", checkpoint_identity(checkpoint))
        .with_data("update.retry_count", checkpoint.retry_count.to_string())
        .with_data("service.version", checkpoint.installed_version)
        .with_data("update.channel", checkpoint.channel);
    if let Some(target) = checkpoint.target_version {
        description = description
            .with_tag("update.target_version", target)
            .with_data("update.target_version", target);
    }
    if let Some(digest) = checkpoint.target_archive_sha256 {
        description = description.with_data("update.target_archive_sha256", digest);
    }
    if let Some(transaction_id) = checkpoint.transaction_id {
        description = description.with_data("update.transaction_id", transaction_id);
    }
    if let Some(run_id) = checkpoint.run_id {
        description = description.with_data("run_id", run_id);
    }
    if let Some(duration_ms) = checkpoint.transition.duration_ms {
        description = description.with_data("update.duration_ms", duration_ms.to_string());
    }
    if let Some(code) = checkpoint.transition.failure_code.as_deref() {
        description = description
            .with_tag("update.failure_code", code)
            .with_data("update.failure_code", code);
    }
    if let Some(retryable) = checkpoint.transition.retryable {
        description = description.with_data("update.retryable", retryable.to_string());
    }
    if let Some(attempt) = checkpoint.transition.retry_attempt {
        description = description.with_data("update.retry_attempt", attempt.to_string());
    }
    telemetry
        .start_span(description)
        .finish_at(checkpoint_status(checkpoint), timestamp)
}

fn checkpoint_outcome(checkpoint: &UpdateCheckpoint<'_>) -> &'static str {
    match checkpoint.boundary {
        UpdateCheckpointBoundary::Started => "started",
        UpdateCheckpointBoundary::Completed => match checkpoint.transition.outcome {
            Some(UpdateTransitionOutcome::Succeeded) => "succeeded",
            Some(UpdateTransitionOutcome::Failed) => "failed",
            Some(UpdateTransitionOutcome::Skipped) => "skipped",
            None => "unknown",
        },
    }
}

fn checkpoint_status(checkpoint: &UpdateCheckpoint<'_>) -> SpanStatus {
    match checkpoint.boundary {
        UpdateCheckpointBoundary::Started => SpanStatus::Ok,
        UpdateCheckpointBoundary::Completed => match checkpoint.transition.outcome {
            Some(UpdateTransitionOutcome::Succeeded | UpdateTransitionOutcome::Skipped) => {
                SpanStatus::Ok
            }
            Some(UpdateTransitionOutcome::Failed) => SpanStatus::InternalError,
            None => SpanStatus::Unavailable,
        },
    }
}

fn transition_utc<'a>(checkpoint: &'a UpdateCheckpoint<'a>) -> &'a str {
    match checkpoint.boundary {
        UpdateCheckpointBoundary::Started => &checkpoint.transition.started_utc,
        UpdateCheckpointBoundary::Completed => checkpoint
            .transition
            .completed_utc
            .as_deref()
            .unwrap_or(&checkpoint.transition.started_utc),
    }
}

#[cfg(test)]
mod tests {
    use lsb_seawork_update::{UpdateActor, UpdateCheckpointBoundary, UpdateTransition};

    use super::*;

    fn transition() -> UpdateTransition {
        UpdateTransition::started(
            "update.discovery",
            UpdateActor::Service,
            "2026-08-05T01:02:03Z",
        )
        .unwrap()
    }

    #[test]
    fn identity_is_deterministic_and_boundary_sensitive() {
        let transition = transition();
        let mut checkpoint = UpdateCheckpoint {
            hostname: "host-01",
            attempt_id: "a",
            transaction_id: None,
            source_version: "0.6.0",
            target_version: None,
            target_archive_sha256: None,
            installed_version: "0.6.0",
            channel: "stable",
            run_id: Some("run-01"),
            retry_count: 0,
            transition: &transition,
            boundary: UpdateCheckpointBoundary::Started,
        };
        let started = checkpoint_identity(&checkpoint);
        assert_eq!(started, checkpoint_identity(&checkpoint));
        checkpoint.boundary = UpdateCheckpointBoundary::Completed;
        assert_ne!(started, checkpoint_identity(&checkpoint));
    }
}
