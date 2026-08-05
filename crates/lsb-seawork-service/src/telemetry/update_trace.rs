use lsb_seawork_update::{
    TransactionEnvelope, TransactionPhase, UpdateAttempt, UpdateAttemptOutcome, UpdateTransition,
    UpdateTransitionOutcome,
};

use super::{
    fresh_trace_context, FailureEvent, Level, SpanDescription, SpanStatus, Telemetry,
    TRANSACTION_SERVICE_UPDATE,
};

pub(crate) fn reconstruct_attempt(
    telemetry: &Telemetry,
    attempt: &UpdateAttempt,
    hostname: &str,
    channel: &str,
) -> Option<String> {
    if attempt.validate().is_err()
        || attempt.outcome == UpdateAttemptOutcome::Active
        || attempt.terminal_trace_event_id.is_some()
        || attempt.transaction_id.is_some()
    {
        return None;
    }
    let start = attempt
        .timeline
        .first()
        .and_then(|transition| timestamp_micros(&transition.started_utc))
        .or_else(|| timestamp_micros(&attempt.created_utc))?;
    let end = attempt
        .timeline
        .iter()
        .rev()
        .find_map(|transition| {
            transition
                .completed_utc
                .as_deref()
                .and_then(timestamp_micros)
                .or_else(|| timestamp_micros(&transition.started_utc))
        })
        .unwrap_or(start)
        .max(start);
    let (result, status) = match attempt.outcome {
        UpdateAttemptOutcome::Succeeded => ("succeeded", SpanStatus::Ok),
        UpdateAttemptOutcome::Failed => ("failed", SpanStatus::InternalError),
        UpdateAttemptOutcome::Suppressed => ("suppressed", SpanStatus::Cancelled),
        UpdateAttemptOutcome::Active => return None,
    };
    let mut description = SpanDescription::transaction(TRANSACTION_SERVICE_UPDATE)
        .always_sampled()
        .started_at(start)
        .with_tag("update.source_version", &attempt.source_version)
        .with_tag("update.result", result)
        .with_tag("update.channel", channel)
        .with_data("user.id", hostname)
        .with_data("update.attempt_id", &attempt.attempt_id)
        .with_data("update.source_version", &attempt.source_version)
        .with_data("update.result", result)
        .with_data("update.channel", channel)
        .with_data(
            "update.total_duration_ms",
            end.saturating_sub(start).saturating_div(1_000).to_string(),
        );
    if let Some(target) = attempt.target_version.as_deref() {
        description = description
            .with_tag("update.target_version", target)
            .with_data("update.target_version", target);
    }
    if let Some(digest) = attempt.target_archive_sha256.as_deref() {
        description = description.with_data("update.target_archive_sha256", digest);
    }
    if let Some(code) = attempt.failure_code.as_deref() {
        description = description
            .with_tag("update.failure_code", code)
            .with_data("update.failure_code", code);
    }
    if let Some(run_id) = telemetry.run_id() {
        description = description.with_data("run_id", run_id);
    }
    let root = telemetry.start_span(description);
    for transition in &attempt.timeline {
        emit_transition(&root, transition, end);
    }
    root.finish_at(status, end)
}

pub(crate) fn reconstruct_update(
    telemetry: &Telemetry,
    journal: &TransactionEnvelope,
    hostname: Option<&str>,
    channel: Option<&str>,
) -> Option<String> {
    if journal.validate().is_err()
        || !journal.transaction.phase.is_terminal()
        || journal.transaction.reported_event_id.is_some()
    {
        return None;
    }
    let trace = fresh_trace_context();
    let start = journal
        .transaction
        .timeline
        .first()
        .and_then(|transition| timestamp_micros(&transition.started_utc))
        .or_else(|| timestamp_micros(&journal.transaction.created_utc))?;
    let end = journal
        .transaction
        .timeline
        .iter()
        .rev()
        .find_map(|transition| {
            transition
                .completed_utc
                .as_deref()
                .and_then(timestamp_micros)
        })
        .unwrap_or(start);
    let (result, status) = terminal_result(journal.transaction.phase);
    let mut description = SpanDescription::transaction(TRANSACTION_SERVICE_UPDATE)
        .always_sampled()
        .started_at(start)
        .with_tag(
            "update.source_version",
            &journal.transaction.old_bundle_identity.version,
        )
        .with_tag(
            "update.target_version",
            &journal.transaction.target_bundle_identity.version,
        )
        .with_tag("update.result", result)
        .with_data(
            "source.version",
            &journal.transaction.old_bundle_identity.version,
        )
        .with_data(
            "target.version",
            &journal.transaction.target_bundle_identity.version,
        )
        .with_data("result", result)
        .with_data("update.attempt_id", journal.transaction.attempt_id())
        .with_data("update.transaction_id", &journal.transaction.transaction_id);
    description = description
        .with_data(
            "update.target_archive_sha256",
            &journal.transaction.target_bundle_identity.archive_sha256,
        )
        .with_data(
            "update.total_duration_ms",
            end.saturating_sub(start).saturating_div(1_000).to_string(),
        );
    if let Some(hostname) = hostname {
        description = description.with_data("user.id", hostname);
    }
    if let Some(channel) = channel {
        description = description
            .with_tag("update.channel", channel)
            .with_data("update.channel", channel);
    }
    if let Some(run_id) = telemetry.run_id() {
        description = description.with_data("run_id", run_id);
    }
    if let Some(step) = journal.transaction.last_failure_step {
        description = description.with_data("failure.phase", format!("{step:?}"));
    }
    if let Some(code) = journal.transaction.last_failure_code {
        description = description
            .with_tag("update.failure_code", code.stable_code())
            .with_data("failure.code", code.stable_code());
    }
    let root = telemetry.continue_trace(trace.clone(), description);
    for transition in &journal.transaction.timeline {
        emit_transition(&root, transition, end);
    }
    if status != SpanStatus::Ok {
        let code = journal
            .transaction
            .last_failure_code
            .map_or("UPDATE_ROLLED_BACK", |code| code.stable_code());
        let mut event = FailureEvent::new(
            "service.update",
            code,
            Level::Error,
            format!("service update ended as {result}"),
        )
        .with_detailed_failure_kind(failure_kind(journal.transaction.phase))
        .with_failure_boundary(failure_kind(journal.transaction.phase))
        .with_correlation_id(&journal.transaction.transaction_id)
        .with_tag("update.result", result)
        .with_tag(
            "update.source_version",
            &journal.transaction.old_bundle_identity.version,
        )
        .with_tag(
            "update.target_version",
            &journal.transaction.target_bundle_identity.version,
        )
        .with_tag("trace.id", &trace.trace_id);
        event.contexts.insert(
            "update".to_string(),
            serde_json::json!({
                "transaction_id": journal.transaction.transaction_id,
                "source_version": journal.transaction.old_bundle_identity.version,
                "target_version": journal.transaction.target_bundle_identity.version,
                "failure_phase": journal.transaction.last_failure_step,
                "failure_code": journal.transaction.last_failure_code.map(|code| code.stable_code()),
                "trace_id": trace.trace_id,
                "timeline": journal.transaction.timeline,
            }),
        );
        let _ = root.capture_failure(event);
    }
    root.finish_at(status, end)
}

fn emit_transition(root: &super::SpanGuard, transition: &UpdateTransition, root_end: u64) {
    let Some(start) = timestamp_micros(&transition.started_utc) else {
        return;
    };
    let description = transition_name(&transition.phase);
    let child = root.start_child(
        SpanDescription::child(description, description)
            .started_at(start)
            .with_data(
                "actor",
                format!("{:?}", transition.actor).to_ascii_lowercase(),
            )
            .with_data(
                "outcome",
                format!("{:?}", transition.outcome).to_ascii_lowercase(),
            ),
    );
    let status = match transition.outcome {
        Some(UpdateTransitionOutcome::Succeeded | UpdateTransitionOutcome::Skipped) => {
            SpanStatus::Ok
        }
        Some(UpdateTransitionOutcome::Failed) => SpanStatus::InternalError,
        None => SpanStatus::Unavailable,
    };
    let end = transition
        .completed_utc
        .as_deref()
        .and_then(timestamp_micros)
        .unwrap_or(root_end)
        .max(start);
    let _ = child.finish_at(status, end);
}

fn transition_name(phase: &str) -> &'static str {
    match phase {
        "update.check" | "update.discovery" => "update.discovery",
        "update.release_selection" => "update.release_selection",
        "update.download" => "update.download",
        "update.extraction" => "update.extraction",
        "update.verification" => "update.verification",
        "update.preinstall" => "update.preinstall",
        "update.idle_wait" => "update.idle_wait",
        "update.activation" => "update.activation",
        "update.service_stop" => "update.service_stop",
        "update.image_path_switch" => "update.image_path_switch",
        "update.target_start" => "update.target_start",
        "update.target_health" => "update.target_health",
        "update.commit" => "update.commit",
        "update.rollback_target_stop" => "update.rollback_target_stop",
        "update.rollback_restore_configuration" => "update.rollback_restore_configuration",
        "update.rollback_old_start" => "update.rollback_old_start",
        _ => "update.phase",
    }
}

fn terminal_result(phase: TransactionPhase) -> (&'static str, SpanStatus) {
    match phase {
        TransactionPhase::TargetCommitted => ("committed", SpanStatus::Ok),
        TransactionPhase::RollbackComplete => ("rolled_back", SpanStatus::Cancelled),
        TransactionPhase::Quarantined => ("quarantined", SpanStatus::InternalError),
        _ => ("incomplete", SpanStatus::Unavailable),
    }
}

fn failure_kind(phase: TransactionPhase) -> &'static str {
    match phase {
        TransactionPhase::RollbackComplete => "rollback",
        TransactionPhase::Quarantined => "quarantine",
        _ => "activation",
    }
}

pub(super) fn timestamp_micros(value: &str) -> Option<u64> {
    let timestamp =
        time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).ok()?;
    u64::try_from(timestamp.unix_timestamp_nanos() / 1_000).ok()
}
