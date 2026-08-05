use anyhow::{Context, Result};
use lsb_seawork_update::{
    TransactionEnvelope, TransactionPhase, UpdateActor, UpdateFailureCode, UpdateFailureStep,
    UpdateTransitionOutcome,
};
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureDisposition {
    Retryable,
    Quarantine,
}

#[derive(Debug)]
pub struct RecoveryFailure {
    pub step: UpdateFailureStep,
    pub code: UpdateFailureCode,
    pub disposition: FailureDisposition,
}

impl std::fmt::Display for RecoveryFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code.stable_code())
    }
}

impl std::error::Error for RecoveryFailure {}

#[cfg_attr(not(windows), allow(dead_code))]
impl RecoveryFailure {
    pub fn retryable(step: UpdateFailureStep, code: UpdateFailureCode) -> Self {
        Self {
            step,
            code,
            disposition: FailureDisposition::Retryable,
        }
    }

    pub fn quarantine(step: UpdateFailureStep, code: UpdateFailureCode) -> Self {
        Self {
            step,
            code,
            disposition: FailureDisposition::Quarantine,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryOutcome {
    Committed,
    RolledBack,
    Quarantined,
}

pub trait TransactionStore {
    fn persist(&mut self, transaction: &TransactionEnvelope) -> Result<()>;
}

pub trait UpdateBackend {
    fn verify_handoff(&mut self, transaction: &TransactionEnvelope) -> Result<()>;
    fn install_and_verify_target(&mut self, transaction: &TransactionEnvelope) -> Result<()>;
    fn stop_old_service(&mut self, transaction: &TransactionEnvelope) -> Result<()>;
    fn change_to_target(&mut self, transaction: &TransactionEnvelope) -> Result<()>;
    fn start_target(&mut self, transaction: &TransactionEnvelope) -> Result<()>;
    fn health_and_commit_target(&mut self, transaction: &TransactionEnvelope) -> Result<()>;
    fn finalize_commit(&mut self, transaction: &TransactionEnvelope) -> Result<()>;
    fn stop_target(&mut self, transaction: &TransactionEnvelope) -> Result<()>;
    fn restore_old_configuration(&mut self, transaction: &TransactionEnvelope) -> Result<()>;
    fn start_and_abort_old(&mut self, transaction: &TransactionEnvelope) -> Result<()>;
}

pub fn recover_transaction(
    transaction: &mut TransactionEnvelope,
    store: &mut impl TransactionStore,
    backend: &mut impl UpdateBackend,
) -> Result<RecoveryOutcome> {
    transaction.validate()?;
    loop {
        let phase = transaction.transaction.phase;
        let result = match phase {
            TransactionPhase::Prepared => {
                run_action(transaction, store, "update.verification", |transaction| {
                    backend.verify_handoff(transaction)
                })
                .and_then(|()| transition(transaction, store, TransactionPhase::HelperStarted))
            }
            TransactionPhase::HelperStarted => {
                run_action(transaction, store, "update.preinstall", |transaction| {
                    backend.install_and_verify_target(transaction)
                })
                .and_then(|()| transition(transaction, store, TransactionPhase::FinalPathVerified))
            }
            TransactionPhase::FinalPathVerified => {
                transition(
                    transaction,
                    store,
                    TransactionPhase::OldServiceStopRequested,
                )?;
                continue;
            }
            TransactionPhase::OldServiceStopRequested => {
                run_action(transaction, store, "update.service_stop", |transaction| {
                    backend.stop_old_service(transaction)
                })
                .and_then(|()| transition(transaction, store, TransactionPhase::OldServiceStopped))
            }
            TransactionPhase::OldServiceStopped => run_action(
                transaction,
                store,
                "update.image_path_switch",
                |transaction| backend.change_to_target(transaction),
            )
            .and_then(|()| transition(transaction, store, TransactionPhase::ImagePathChanged)),
            TransactionPhase::ImagePathChanged => {
                run_action(transaction, store, "update.target_start", |transaction| {
                    backend.start_target(transaction)
                })
                .and_then(|()| {
                    transition(transaction, store, TransactionPhase::TargetStartRequested)
                })
            }
            TransactionPhase::TargetStartRequested => {
                transition(transaction, store, TransactionPhase::TargetHealthPending)?;
                continue;
            }
            TransactionPhase::TargetHealthPending => {
                run_action(transaction, store, "update.target_health", |transaction| {
                    backend.health_and_commit_target(transaction)
                })
                .and_then(|()| transition(transaction, store, TransactionPhase::TargetCommitted))
            }
            TransactionPhase::TargetCommitted => {
                if !completed_action(transaction, "update.commit") {
                    run_action(transaction, store, "update.commit", |transaction| {
                        backend.finalize_commit(transaction)
                    })?;
                }
                return Ok(RecoveryOutcome::Committed);
            }
            TransactionPhase::RollbackRequested => run_action(
                transaction,
                store,
                "update.rollback_target_stop",
                |transaction| backend.stop_target(transaction),
            )
            .and_then(|()| transition(transaction, store, TransactionPhase::TargetStopped)),
            TransactionPhase::TargetStopped => run_action(
                transaction,
                store,
                "update.rollback_restore_configuration",
                |transaction| backend.restore_old_configuration(transaction),
            )
            .and_then(|()| transition(transaction, store, TransactionPhase::OldPathRestored)),
            TransactionPhase::OldPathRestored => run_action(
                transaction,
                store,
                "update.rollback_old_start",
                |transaction| backend.start_and_abort_old(transaction),
            )
            .and_then(|()| transition(transaction, store, TransactionPhase::OldServiceRestarted)),
            TransactionPhase::OldServiceRestarted => {
                transition(transaction, store, TransactionPhase::RollbackComplete)?;
                continue;
            }
            TransactionPhase::RollbackComplete => return Ok(RecoveryOutcome::RolledBack),
            TransactionPhase::Quarantined => return Ok(RecoveryOutcome::Quarantined),
        };

        if let Err(error) = result {
            let failure = error
                .downcast_ref::<RecoveryFailure>()
                .map(|failure| (failure.step, failure.code, failure.disposition))
                .unwrap_or_else(|| {
                    (
                        failure_step_for_phase(phase),
                        UpdateFailureCode::OperationFailed,
                        FailureDisposition::Retryable,
                    )
                });
            transaction.record_failure(failure.0, failure.1)?;
            store
                .persist(transaction)
                .context("persist bounded update recovery failure")?;
            if failure.2 == FailureDisposition::Quarantine {
                transition(transaction, store, TransactionPhase::Quarantined)
                    .context("persist update recovery quarantine")?;
                return Err(error).context("update recovery entered quarantine");
            }
            if is_rollback_phase(phase) || phase == TransactionPhase::Prepared {
                return Err(error).context("update recovery remains resumable");
            }
            transition(transaction, store, TransactionPhase::RollbackRequested)
                .context("persist update rollback request")?;
        }
    }
}

fn failure_step_for_phase(phase: TransactionPhase) -> UpdateFailureStep {
    match phase {
        TransactionPhase::Prepared => UpdateFailureStep::HandoffVerify,
        TransactionPhase::ImagePathChanged | TransactionPhase::TargetStartRequested => {
            UpdateFailureStep::TargetStart
        }
        TransactionPhase::TargetHealthPending => UpdateFailureStep::TargetHealthAssertion,
        TransactionPhase::RollbackRequested => UpdateFailureStep::RollbackTargetStop,
        TransactionPhase::TargetStopped => UpdateFailureStep::RollbackRestoreConfiguration,
        TransactionPhase::OldPathRestored | TransactionPhase::OldServiceRestarted => {
            UpdateFailureStep::RollbackOldStart
        }
        _ => UpdateFailureStep::TargetHealthAssertion,
    }
}

fn transition(
    transaction: &mut TransactionEnvelope,
    store: &mut impl TransactionStore,
    next: TransactionPhase,
) -> Result<()> {
    transaction.transition(next)?;
    store.persist(transaction)
}

fn run_action(
    transaction: &mut TransactionEnvelope,
    store: &mut impl TransactionStore,
    phase: &'static str,
    action: impl FnOnce(&TransactionEnvelope) -> Result<()>,
) -> Result<()> {
    if transaction
        .transaction
        .timeline
        .last()
        .is_some_and(|transition| transition.completed_utc.is_none())
    {
        transaction.complete_transition(now_utc(), 0, UpdateTransitionOutcome::Failed)?;
        store
            .persist(transaction)
            .context("persist interrupted update transition")?;
    }
    transaction.begin_transition(phase, UpdateActor::Updater, now_utc())?;
    store
        .persist(transaction)
        .context("persist update transition intent")?;
    let started = Instant::now();
    let result = action(transaction);
    transaction.complete_transition(
        now_utc(),
        started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
        if result.is_ok() {
            UpdateTransitionOutcome::Succeeded
        } else {
            UpdateTransitionOutcome::Failed
        },
    )?;
    store
        .persist(transaction)
        .context("persist update transition completion")?;
    result
}

fn now_utc() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

fn completed_action(transaction: &TransactionEnvelope, phase: &str) -> bool {
    transaction.transaction.timeline.iter().any(|transition| {
        transition.phase == phase && transition.outcome == Some(UpdateTransitionOutcome::Succeeded)
    })
}

fn is_rollback_phase(phase: TransactionPhase) -> bool {
    matches!(
        phase,
        TransactionPhase::RollbackRequested
            | TransactionPhase::TargetStopped
            | TransactionPhase::OldPathRestored
            | TransactionPhase::OldServiceRestarted
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use lsb_seawork_update::{HelperProtocol, UpdateTransaction};
    use lsb_service_proto::{BundleIdentity, LedgerCompatibility, ProtocolRange};

    #[derive(Default)]
    struct MemoryStore {
        phases: Vec<TransactionPhase>,
        snapshots: Vec<TransactionEnvelope>,
    }

    impl TransactionStore for MemoryStore {
        fn persist(&mut self, transaction: &TransactionEnvelope) -> Result<()> {
            transaction.validate()?;
            self.phases.push(transaction.transaction.phase);
            self.snapshots.push(transaction.clone());
            Ok(())
        }
    }

    #[derive(Default)]
    struct Backend {
        calls: Vec<&'static str>,
        fail: Option<&'static str>,
        failure: Option<(UpdateFailureStep, UpdateFailureCode, FailureDisposition)>,
    }

    impl Backend {
        fn call(&mut self, name: &'static str) -> Result<()> {
            self.calls.push(name);
            if self.fail == Some(name) {
                let error = anyhow::anyhow!("injected {name} failure");
                if let Some((step, code, disposition)) = self.failure {
                    return Err(error.context(RecoveryFailure {
                        step,
                        code,
                        disposition,
                    }));
                }
                return Err(error);
            }
            Ok(())
        }
    }

    impl UpdateBackend for Backend {
        fn verify_handoff(&mut self, _: &TransactionEnvelope) -> Result<()> {
            self.call("handoff")
        }
        fn install_and_verify_target(&mut self, _: &TransactionEnvelope) -> Result<()> {
            self.call("install")
        }
        fn stop_old_service(&mut self, _: &TransactionEnvelope) -> Result<()> {
            self.call("stop_old")
        }
        fn change_to_target(&mut self, _: &TransactionEnvelope) -> Result<()> {
            self.call("change")
        }
        fn start_target(&mut self, _: &TransactionEnvelope) -> Result<()> {
            self.call("start_target")
        }
        fn health_and_commit_target(&mut self, _: &TransactionEnvelope) -> Result<()> {
            self.call("commit")
        }
        fn finalize_commit(&mut self, _: &TransactionEnvelope) -> Result<()> {
            self.call("finalize")
        }
        fn stop_target(&mut self, _: &TransactionEnvelope) -> Result<()> {
            self.call("stop_target")
        }
        fn restore_old_configuration(&mut self, _: &TransactionEnvelope) -> Result<()> {
            self.call("restore")
        }
        fn start_and_abort_old(&mut self, _: &TransactionEnvelope) -> Result<()> {
            self.call("restart_old")
        }
    }

    #[test]
    fn success_persists_every_phase_and_commits() {
        let mut transaction = transaction(TransactionPhase::Prepared);
        let mut store = MemoryStore::default();
        let mut backend = Backend::default();
        assert_eq!(
            recover_transaction(&mut transaction, &mut store, &mut backend).unwrap(),
            RecoveryOutcome::Committed
        );
        assert_eq!(
            backend.calls,
            [
                "handoff",
                "install",
                "stop_old",
                "change",
                "start_target",
                "commit",
                "finalize"
            ]
        );
        assert_eq!(
            store.phases.last(),
            Some(&TransactionPhase::TargetCommitted)
        );
        assert!(transaction.transaction.timeline.iter().all(|transition| {
            transition.completed_utc.is_some()
                && transition.outcome == Some(UpdateTransitionOutcome::Succeeded)
        }));
        for transition in &transaction.transaction.timeline {
            let intent = store.snapshots.iter().position(|snapshot| {
                snapshot
                    .transaction
                    .timeline
                    .last()
                    .is_some_and(|candidate| {
                        candidate.phase == transition.phase && candidate.completed_utc.is_none()
                    })
            });
            let completion = store.snapshots.iter().position(|snapshot| {
                snapshot
                    .transaction
                    .timeline
                    .last()
                    .is_some_and(|candidate| {
                        candidate.phase == transition.phase && candidate.completed_utc.is_some()
                    })
            });
            assert!(intent.is_some_and(|intent| completion.is_some_and(|done| intent < done)));
        }
    }

    #[test]
    fn every_forward_failure_after_ownership_rolls_back() {
        for failure in ["install", "stop_old", "change", "start_target", "commit"] {
            let mut transaction = transaction(TransactionPhase::HelperStarted);
            let mut store = MemoryStore::default();
            let mut backend = Backend {
                fail: Some(failure),
                ..Backend::default()
            };
            assert_eq!(
                recover_transaction(&mut transaction, &mut store, &mut backend).unwrap(),
                RecoveryOutcome::RolledBack,
                "failure {failure} did not roll back"
            );
            assert!(backend
                .calls
                .ends_with(&["stop_target", "restore", "restart_old"]));
        }
    }

    #[test]
    fn each_nonterminal_phase_resumes_idempotently() {
        for phase in [
            TransactionPhase::Prepared,
            TransactionPhase::HelperStarted,
            TransactionPhase::FinalPathVerified,
            TransactionPhase::OldServiceStopRequested,
            TransactionPhase::OldServiceStopped,
            TransactionPhase::ImagePathChanged,
            TransactionPhase::TargetStartRequested,
            TransactionPhase::TargetHealthPending,
            TransactionPhase::RollbackRequested,
            TransactionPhase::TargetStopped,
            TransactionPhase::OldPathRestored,
            TransactionPhase::OldServiceRestarted,
        ] {
            let mut transaction = transaction(phase);
            let mut store = MemoryStore::default();
            let mut backend = Backend::default();
            let outcome = recover_transaction(&mut transaction, &mut store, &mut backend).unwrap();
            let expected = if is_rollback_phase(phase) {
                RecoveryOutcome::RolledBack
            } else {
                RecoveryOutcome::Committed
            };
            assert_eq!(outcome, expected, "phase {phase:?} did not recover");
        }
    }

    #[test]
    fn preinstalled_activation_skips_handoff_and_install() {
        let mut transaction = transaction(TransactionPhase::FinalPathVerified);
        let mut store = MemoryStore::default();
        let mut backend = Backend::default();

        assert_eq!(
            recover_transaction(&mut transaction, &mut store, &mut backend).unwrap(),
            RecoveryOutcome::Committed
        );
        assert_eq!(
            backend.calls,
            ["stop_old", "change", "start_target", "commit", "finalize"]
        );
    }

    #[test]
    fn rollback_operational_failure_remains_resumable() {
        let mut transaction = transaction(TransactionPhase::RollbackRequested);
        let mut store = MemoryStore::default();
        let mut backend = Backend {
            fail: Some("restore"),
            ..Backend::default()
        };
        assert!(recover_transaction(&mut transaction, &mut store, &mut backend).is_err());
        assert_eq!(
            transaction.transaction.phase,
            TransactionPhase::TargetStopped
        );
        assert_eq!(
            transaction.transaction.last_failure_step,
            Some(UpdateFailureStep::RollbackRestoreConfiguration)
        );
        assert_eq!(
            transaction.transaction.last_failure_code,
            Some(UpdateFailureCode::OperationFailed)
        );
        assert_eq!(store.phases.last(), Some(&TransactionPhase::TargetStopped));
        let failed = transaction.transaction.timeline.last().unwrap();
        assert_eq!(failed.phase, "update.rollback_restore_configuration");
        assert_eq!(failed.outcome, Some(UpdateTransitionOutcome::Failed));
        assert_eq!(
            failed.failure_code.as_deref(),
            Some("UPDATE_OPERATION_FAILED")
        );
    }

    #[test]
    fn interrupted_action_is_closed_before_retry() {
        let mut transaction = transaction(TransactionPhase::OldServiceStopRequested);
        transaction
            .begin_transition(
                "update.service_stop",
                UpdateActor::Updater,
                "2026-07-22T12:01:00Z",
            )
            .unwrap();
        let mut store = MemoryStore::default();
        let mut backend = Backend::default();

        assert_eq!(
            recover_transaction(&mut transaction, &mut store, &mut backend).unwrap(),
            RecoveryOutcome::Committed
        );
        assert_eq!(
            transaction.transaction.timeline[0].outcome,
            Some(UpdateTransitionOutcome::Failed)
        );
        assert_eq!(
            transaction.transaction.timeline[1].phase,
            "update.service_stop"
        );
        assert_eq!(
            transaction.transaction.timeline[1].outcome,
            Some(UpdateTransitionOutcome::Succeeded)
        );
    }

    #[test]
    fn rollback_connect_timeout_persists_exact_code_without_quarantine() {
        let mut transaction = transaction(TransactionPhase::OldPathRestored);
        let mut store = MemoryStore::default();
        let mut backend = Backend {
            fail: Some("restart_old"),
            failure: Some((
                UpdateFailureStep::RollbackAbortConnect,
                UpdateFailureCode::RollbackAbortConnectTimeout,
                FailureDisposition::Retryable,
            )),
            ..Backend::default()
        };

        assert!(recover_transaction(&mut transaction, &mut store, &mut backend).is_err());
        assert_eq!(
            transaction.transaction.phase,
            TransactionPhase::OldPathRestored
        );
        assert_eq!(
            transaction.transaction.last_failure_code,
            Some(UpdateFailureCode::RollbackAbortConnectTimeout)
        );
        assert_ne!(store.phases.last(), Some(&TransactionPhase::Quarantined));
    }

    #[test]
    fn protected_state_contradiction_quarantines() {
        let mut transaction = transaction(TransactionPhase::TargetStopped);
        let mut store = MemoryStore::default();
        let mut backend = Backend {
            fail: Some("restore"),
            failure: Some((
                UpdateFailureStep::RollbackRestoreConfiguration,
                UpdateFailureCode::ProtectedStateContradiction,
                FailureDisposition::Quarantine,
            )),
            ..Backend::default()
        };

        assert!(recover_transaction(&mut transaction, &mut store, &mut backend).is_err());
        assert_eq!(transaction.transaction.phase, TransactionPhase::Quarantined);
        assert_eq!(store.phases.last(), Some(&TransactionPhase::Quarantined));
    }

    fn transaction(phase: TransactionPhase) -> TransactionEnvelope {
        let mut envelope = TransactionEnvelope::new(UpdateTransaction {
            transaction_id: "1".repeat(32),
            update_id: "2".repeat(32),
            attempt_id: None,
            phase: TransactionPhase::Prepared,
            created_utc: "2026-07-22T12:00:00Z".to_string(),
            old_bundle_identity: identity("0.5.0-rc.1", 'a'),
            target_bundle_identity: identity("0.5.0-rc.2", 'b'),
            old_image_path: r"C:\Program Files\SeaWork\LocalSandbox\versions\0.5.0-rc.1\bin\localsandbox-seawork-service.exe".to_string(),
            target_image_path: r"C:\Program Files\SeaWork\LocalSandbox\versions\0.5.0-rc.2\bin\localsandbox-seawork-service.exe".to_string(),
            old_event_message_path: r"C:\Program Files\SeaWork\LocalSandbox\versions\0.5.0-rc.1\bin\localsandbox-seawork-service.exe".to_string(),
            target_event_message_path: r"C:\Program Files\SeaWork\LocalSandbox\versions\0.5.0-rc.2\bin\localsandbox-seawork-service.exe".to_string(),
            staged_root: r"C:\ProgramData\LocalSandbox\SeaWork\updates\staging\11111111111111111111111111111111\LocalSandbox".to_string(),
            final_version_root: r"C:\Program Files\SeaWork\LocalSandbox\versions\0.5.0-rc.2".to_string(),
            helper_protocol: HelperProtocol { major: 1, minor: 1 },
            attempt_count: 1,
            last_error_category: None,
            last_failure_step: None,
            last_failure_code: None,
            timeline: Vec::new(),
            reported_event_id: None,
        }).unwrap();
        advance_to(&mut envelope, phase);
        envelope
    }

    fn advance_to(transaction: &mut TransactionEnvelope, target: TransactionPhase) {
        use TransactionPhase::*;
        let path: &[TransactionPhase] = match target {
            Prepared => &[],
            HelperStarted => &[HelperStarted],
            FinalPathVerified => &[HelperStarted, FinalPathVerified],
            OldServiceStopRequested => &[HelperStarted, FinalPathVerified, OldServiceStopRequested],
            OldServiceStopped => &[
                HelperStarted,
                FinalPathVerified,
                OldServiceStopRequested,
                OldServiceStopped,
            ],
            ImagePathChanged => &[
                HelperStarted,
                FinalPathVerified,
                OldServiceStopRequested,
                OldServiceStopped,
                ImagePathChanged,
            ],
            TargetStartRequested => &[
                HelperStarted,
                FinalPathVerified,
                OldServiceStopRequested,
                OldServiceStopped,
                ImagePathChanged,
                TargetStartRequested,
            ],
            TargetHealthPending => &[
                HelperStarted,
                FinalPathVerified,
                OldServiceStopRequested,
                OldServiceStopped,
                ImagePathChanged,
                TargetStartRequested,
                TargetHealthPending,
            ],
            RollbackRequested => &[HelperStarted, RollbackRequested],
            TargetStopped => &[HelperStarted, RollbackRequested, TargetStopped],
            OldPathRestored => &[
                HelperStarted,
                RollbackRequested,
                TargetStopped,
                OldPathRestored,
            ],
            OldServiceRestarted => &[
                HelperStarted,
                RollbackRequested,
                TargetStopped,
                OldPathRestored,
                OldServiceRestarted,
            ],
            RollbackComplete => &[
                HelperStarted,
                RollbackRequested,
                TargetStopped,
                OldPathRestored,
                OldServiceRestarted,
                RollbackComplete,
            ],
            TargetCommitted => &[
                HelperStarted,
                FinalPathVerified,
                OldServiceStopRequested,
                OldServiceStopped,
                ImagePathChanged,
                TargetStartRequested,
                TargetHealthPending,
                TargetCommitted,
            ],
            Quarantined => &[Quarantined],
        };
        for phase in path {
            transaction.transition(*phase).unwrap();
        }
    }

    fn identity(version: &str, byte: char) -> BundleIdentity {
        BundleIdentity {
            version: version.to_string(),
            bundle_manifest_sha256: byte.to_string().repeat(64),
            archive_sha256: byte.to_string().repeat(64),
            protocol: ProtocolRange {
                major: 1,
                min_minor: 0,
                max_minor: 6,
            },
            ledger: LedgerCompatibility {
                reader_min_schema: 1,
                reader_max_schema: 1,
                writer_schema: 1,
            },
            service_configuration_revision: 2,
        }
    }
}
