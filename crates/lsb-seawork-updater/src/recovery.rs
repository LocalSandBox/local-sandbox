use anyhow::{Context, Result};
use lsb_seawork_update::{TransactionEnvelope, TransactionPhase};

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
            TransactionPhase::Prepared => backend
                .verify_handoff(transaction)
                .and_then(|()| transition(transaction, store, TransactionPhase::HelperStarted)),
            TransactionPhase::HelperStarted => backend
                .install_and_verify_target(transaction)
                .and_then(|()| transition(transaction, store, TransactionPhase::FinalPathVerified)),
            TransactionPhase::FinalPathVerified => {
                transition(
                    transaction,
                    store,
                    TransactionPhase::OldServiceStopRequested,
                )?;
                continue;
            }
            TransactionPhase::OldServiceStopRequested => backend
                .stop_old_service(transaction)
                .and_then(|()| transition(transaction, store, TransactionPhase::OldServiceStopped)),
            TransactionPhase::OldServiceStopped => backend
                .change_to_target(transaction)
                .and_then(|()| transition(transaction, store, TransactionPhase::ImagePathChanged)),
            TransactionPhase::ImagePathChanged => {
                backend.start_target(transaction).and_then(|()| {
                    transition(transaction, store, TransactionPhase::TargetStartRequested)
                })
            }
            TransactionPhase::TargetStartRequested => {
                transition(transaction, store, TransactionPhase::TargetHealthPending)?;
                continue;
            }
            TransactionPhase::TargetHealthPending => backend
                .health_and_commit_target(transaction)
                .and_then(|()| transition(transaction, store, TransactionPhase::TargetCommitted)),
            TransactionPhase::TargetCommitted => {
                backend.finalize_commit(transaction)?;
                return Ok(RecoveryOutcome::Committed);
            }
            TransactionPhase::RollbackRequested => backend
                .stop_target(transaction)
                .and_then(|()| transition(transaction, store, TransactionPhase::TargetStopped)),
            TransactionPhase::TargetStopped => backend
                .restore_old_configuration(transaction)
                .and_then(|()| transition(transaction, store, TransactionPhase::OldPathRestored)),
            TransactionPhase::OldPathRestored => {
                backend.start_and_abort_old(transaction).and_then(|()| {
                    transition(transaction, store, TransactionPhase::OldServiceRestarted)
                })
            }
            TransactionPhase::OldServiceRestarted => {
                transition(transaction, store, TransactionPhase::RollbackComplete)?;
                continue;
            }
            TransactionPhase::RollbackComplete => return Ok(RecoveryOutcome::RolledBack),
            TransactionPhase::Quarantined => return Ok(RecoveryOutcome::Quarantined),
        };

        if let Err(error) = result {
            if is_rollback_phase(phase) || phase == TransactionPhase::Prepared {
                transition(transaction, store, TransactionPhase::Quarantined)
                    .context("persist update recovery quarantine")?;
                return Err(error).context("update recovery entered quarantine");
            }
            transition(transaction, store, TransactionPhase::RollbackRequested)
                .context("persist update rollback request")?;
        }
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
    }

    impl TransactionStore for MemoryStore {
        fn persist(&mut self, transaction: &TransactionEnvelope) -> Result<()> {
            transaction.validate()?;
            self.phases.push(transaction.transaction.phase);
            Ok(())
        }
    }

    #[derive(Default)]
    struct Backend {
        calls: Vec<&'static str>,
        fail: Option<&'static str>,
    }

    impl Backend {
        fn call(&mut self, name: &'static str) -> Result<()> {
            self.calls.push(name);
            if self.fail == Some(name) {
                anyhow::bail!("injected {name} failure");
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
    fn rollback_failure_quarantines_without_fallback() {
        let mut transaction = transaction(TransactionPhase::RollbackRequested);
        let mut store = MemoryStore::default();
        let mut backend = Backend {
            fail: Some("restore"),
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
