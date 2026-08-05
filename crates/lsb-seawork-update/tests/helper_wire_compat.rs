use lsb_seawork_update::{
    CommittedState, CommittedStateEnvelope, HelperProtocol, PreinstallReceipt,
    PreinstallReceiptEnvelope, PreinstallRequest, PreinstallRequestEnvelope, ReleaseCandidate,
    TransactionEnvelope, TransactionPhase, UpdateActor, UpdateFailureCode, UpdateFailureStep,
    UpdateTransaction, UpdateTransition, UpdateTransitionOutcome,
};
use lsb_service_proto::{BundleIdentity, LedgerCompatibility, ProtocolRange, UpdateCheckCategory};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};

const COMMITTED: &[u8] = include_bytes!("../fixtures/protocol-1.1/committed.json");
const PREINSTALL_REQUEST: &[u8] =
    include_bytes!("../fixtures/protocol-1.1/preinstall-request.json");
const PREINSTALL_RECEIPT: &[u8] =
    include_bytes!("../fixtures/protocol-1.1/preinstall-receipt.json");
const TRANSACTION_ACTIVE: &[u8] =
    include_bytes!("../fixtures/protocol-1.1/transaction-active.json");
const TRANSACTION_TERMINAL: &[u8] =
    include_bytes!("../fixtures/protocol-1.1/transaction-terminal.json");
const TRANSACTION_FAILURE: &[u8] =
    include_bytes!("../fixtures/protocol-1.1/transaction-failure.json");

const FIXTURE_DIGESTS: [(&str, &[u8], &str); 6] = [
    (
        "committed.json",
        COMMITTED,
        "3e1d1bf9539f55d79c711d963f6acdefab6babdde9dc216bceadb55e2a3131a2",
    ),
    (
        "preinstall-request.json",
        PREINSTALL_REQUEST,
        "b6daa77d599d20e05060ddc6f04c0efe387e1b547fdbd939d81e3ade88eab33d",
    ),
    (
        "preinstall-receipt.json",
        PREINSTALL_RECEIPT,
        "acdfaf5e337bb351a51183c883599ae3cd4236cb32f9c86fdfef705a118cbe16",
    ),
    (
        "transaction-active.json",
        TRANSACTION_ACTIVE,
        "96990cf5d89220a5006df3c5ef1aa6d0b443854c32a5d7968abc0e650fe8e973",
    ),
    (
        "transaction-terminal.json",
        TRANSACTION_TERMINAL,
        "20c501b2188289ded09b050037e9174e4e4126d0702f506ead0b8bfcaa032e1d",
    ),
    (
        "transaction-failure.json",
        TRANSACTION_FAILURE,
        "a3aabaafdf4f75d73a96dd667fd24eb862446b457f33353e4ce2a7444a86c7ea",
    ),
];

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
        service_configuration_revision: 3,
    }
}

fn transition(phase: &str, outcome: UpdateTransitionOutcome) -> UpdateTransition {
    UpdateTransition {
        phase: phase.to_string(),
        actor: UpdateActor::Updater,
        started_utc: "2026-07-31T08:01:00Z".to_string(),
        completed_utc: Some("2026-07-31T08:01:02Z".to_string()),
        duration_ms: Some(2_000),
        outcome: Some(outcome),
        failure_code: (outcome == UpdateTransitionOutcome::Failed)
            .then(|| "TARGET_CONNECT_TIMEOUT".to_string()),
    }
}

fn request() -> PreinstallRequest {
    let target = identity("0.7.0", 'b');
    PreinstallRequest {
        request_id: "1".repeat(32),
        created_utc: "2026-07-31T08:00:00Z".to_string(),
        candidate: ReleaseCandidate {
            release_id: 700,
            version: target.version.clone(),
            prerelease: false,
            asset_name: "lsb-seawork-service-v0.7.0-windows-x86_64.zip".to_string(),
            asset_url: "https://github.com/LocalSandBox/local-sandbox/releases/download/v0.7.0/lsb-seawork-service-v0.7.0-windows-x86_64.zip".to_string(),
            asset_size: 12_345,
            archive_sha256: target.archive_sha256.clone(),
        },
        old_bundle_identity: identity("0.6.0", 'a'),
        target_bundle_identity: target,
        staged_root: r"C:\ProgramData\LocalSandbox\SeaWork\updates\staging\11111111111111111111111111111111\LocalSandbox".to_string(),
        final_version_root: r"C:\Program Files\SeaWork\LocalSandbox\versions\0.7.0".to_string(),
        helper_protocol: HelperProtocol { major: 1, minor: 1 },
        timeline: vec![transition("update.preinstall", UpdateTransitionOutcome::Succeeded)],
    }
}

fn transaction(phase: TransactionPhase, failed: bool) -> UpdateTransaction {
    UpdateTransaction {
        transaction_id: "1".repeat(32),
        update_id: "2".repeat(32),
        phase,
        created_utc: "2026-07-31T08:00:00Z".to_string(),
        old_bundle_identity: identity("0.6.0", 'a'),
        target_bundle_identity: identity("0.7.0", 'b'),
        old_image_path: r"C:\Program Files\SeaWork\LocalSandbox\versions\0.6.0\bin\localsandbox-seawork-service.exe".to_string(),
        target_image_path: r"C:\Program Files\SeaWork\LocalSandbox\versions\0.7.0\bin\localsandbox-seawork-service.exe".to_string(),
        old_event_message_path: r"C:\Program Files\SeaWork\LocalSandbox\versions\0.6.0\bin\localsandbox-seawork-service.exe".to_string(),
        target_event_message_path: r"C:\Program Files\SeaWork\LocalSandbox\versions\0.7.0\bin\localsandbox-seawork-service.exe".to_string(),
        staged_root: r"C:\ProgramData\LocalSandbox\SeaWork\updates\staging\11111111111111111111111111111111\LocalSandbox".to_string(),
        final_version_root: r"C:\Program Files\SeaWork\LocalSandbox\versions\0.7.0".to_string(),
        helper_protocol: HelperProtocol { major: 1, minor: 1 },
        attempt_count: 1,
        last_error_category: failed.then_some(UpdateCheckCategory::Network),
        last_failure_step: failed.then_some(UpdateFailureStep::TargetConnect),
        last_failure_code: failed.then_some(UpdateFailureCode::TargetConnectTimeout),
        timeline: vec![transition(
            if failed { "update.target_start" } else { "update.activation" },
            if failed { UpdateTransitionOutcome::Failed } else { UpdateTransitionOutcome::Succeeded },
        )],
        reported_event_id: None,
    }
}

fn committed() -> CommittedStateEnvelope {
    CommittedStateEnvelope::new(CommittedState {
        current: identity("0.6.0", 'a'),
        highest_committed_version: "0.6.0".to_string(),
        previous_last_known_good: None,
        helper_protocol: HelperProtocol { major: 1, minor: 1 },
        last_completed_transaction_id: "0".repeat(32),
    })
    .unwrap()
}

fn assert_n_to_x<T: Serialize, X: DeserializeOwned + pinned::Validate>(value: &T, fixture: &[u8]) {
    let bytes = serde_json::to_vec_pretty(value).unwrap();
    assert_eq!(bytes, fixture);
    serde_json::from_slice::<X>(&bytes).unwrap().validate();
}

#[test]
fn fixtures_are_immutable_protocol_1_1_evidence() {
    for (name, bytes, expected) in FIXTURE_DIGESTS {
        assert_eq!(format!("{:x}", Sha256::digest(bytes)), expected, "{name}");
    }
}

#[test]
fn n_serialization_is_accepted_by_pinned_helper_x_and_byte_exact() {
    assert_n_to_x::<_, pinned::CommittedEnvelope>(&committed(), COMMITTED);
    let request = PreinstallRequestEnvelope::new(request()).unwrap();
    assert_n_to_x::<_, pinned::PreinstallRequestEnvelope>(&request, PREINSTALL_REQUEST);
    assert_n_to_x::<_, pinned::PreinstallReceiptEnvelope>(
        &PreinstallReceiptEnvelope::new(PreinstallReceipt {
            request: request.request,
            completed_utc: "2026-07-31T08:01:03Z".to_string(),
        })
        .unwrap(),
        PREINSTALL_RECEIPT,
    );
    assert_n_to_x::<_, pinned::TransactionEnvelope>(
        &TransactionEnvelope::new(transaction(TransactionPhase::TargetHealthPending, false))
            .unwrap(),
        TRANSACTION_ACTIVE,
    );
    assert_n_to_x::<_, pinned::TransactionEnvelope>(
        &TransactionEnvelope::new(transaction(TransactionPhase::TargetCommitted, false)).unwrap(),
        TRANSACTION_TERMINAL,
    );
    assert_n_to_x::<_, pinned::TransactionEnvelope>(
        &TransactionEnvelope::new(transaction(TransactionPhase::RollbackComplete, true)).unwrap(),
        TRANSACTION_FAILURE,
    );
}

#[test]
fn n_decodes_every_helper_x_fixture() {
    serde_json::from_slice::<CommittedStateEnvelope>(COMMITTED)
        .unwrap()
        .validate()
        .unwrap();
    serde_json::from_slice::<PreinstallRequestEnvelope>(PREINSTALL_REQUEST)
        .unwrap()
        .validate()
        .unwrap();
    serde_json::from_slice::<PreinstallReceiptEnvelope>(PREINSTALL_RECEIPT)
        .unwrap()
        .validate()
        .unwrap();
    for fixture in [
        TRANSACTION_ACTIVE,
        TRANSACTION_TERMINAL,
        TRANSACTION_FAILURE,
    ] {
        serde_json::from_slice::<TransactionEnvelope>(fixture)
            .unwrap()
            .validate()
            .unwrap();
    }
}

#[test]
fn protocol_1_1_rejects_n_only_request_and_transition_fields() {
    let mut request: serde_json::Value = serde_json::from_slice(PREINSTALL_REQUEST).unwrap();
    request["request"]["attempt_id"] = serde_json::json!("a".repeat(32));
    let bytes = serde_json::to_vec(&request).unwrap();
    assert!(serde_json::from_slice::<pinned::PreinstallRequestEnvelope>(&bytes).is_err());
    assert!(serde_json::from_slice::<PreinstallRequestEnvelope>(&bytes).is_err());

    let mut transaction: serde_json::Value = serde_json::from_slice(TRANSACTION_ACTIVE).unwrap();
    transaction["transaction"]["timeline"][0]["retryable"] = serde_json::json!(true);
    let bytes = serde_json::to_vec(&transaction).unwrap();
    assert!(serde_json::from_slice::<pinned::TransactionEnvelope>(&bytes).is_err());
    assert!(serde_json::from_slice::<TransactionEnvelope>(&bytes).is_err());
}

#[test]
fn committed_baseline_is_identical_when_fresh_or_retained() {
    let fresh = committed();
    let retained: CommittedStateEnvelope = serde_json::from_slice(COMMITTED).unwrap();
    assert_eq!(serde_json::to_vec_pretty(&fresh).unwrap(), COMMITTED);
    assert_eq!(serde_json::to_vec_pretty(&retained).unwrap(), COMMITTED);
    assert_eq!(fresh.checksum_sha256, retained.checksum_sha256);
}

mod pinned {
    use super::*;

    pub trait Validate {
        fn validate(&self);
    }

    fn assert_envelope<T: Serialize>(schema_version: u32, checksum: &str, body: &T) {
        assert_eq!(schema_version, 1);
        assert_eq!(
            format!("{:x}", Sha256::digest(serde_json::to_vec(body).unwrap())),
            checksum
        );
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct CommittedEnvelope {
        schema_version: u32,
        checksum_sha256: String,
        committed: Committed,
    }
    impl Validate for CommittedEnvelope {
        fn validate(&self) {
            assert_envelope(self.schema_version, &self.checksum_sha256, &self.committed);
        }
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Committed {
        current: Identity,
        highest_committed_version: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        previous_last_known_good: Option<Identity>,
        helper_protocol: Protocol,
        last_completed_transaction_id: String,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct PreinstallRequestEnvelope {
        schema_version: u32,
        checksum_sha256: String,
        request: Request,
    }
    impl Validate for PreinstallRequestEnvelope {
        fn validate(&self) {
            assert_envelope(self.schema_version, &self.checksum_sha256, &self.request);
        }
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct PreinstallReceiptEnvelope {
        schema_version: u32,
        checksum_sha256: String,
        receipt: Receipt,
    }
    impl Validate for PreinstallReceiptEnvelope {
        fn validate(&self) {
            assert_envelope(self.schema_version, &self.checksum_sha256, &self.receipt);
        }
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Receipt {
        request: Request,
        completed_utc: String,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Request {
        request_id: String,
        created_utc: String,
        candidate: Candidate,
        old_bundle_identity: Identity,
        target_bundle_identity: Identity,
        staged_root: String,
        final_version_root: String,
        helper_protocol: Protocol,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        timeline: Vec<Transition>,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Candidate {
        release_id: u64,
        version: String,
        prerelease: bool,
        asset_name: String,
        asset_url: String,
        asset_size: u64,
        archive_sha256: String,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct TransactionEnvelope {
        schema_version: u32,
        checksum_sha256: String,
        transaction: Transaction,
    }
    impl Validate for TransactionEnvelope {
        fn validate(&self) {
            assert_envelope(
                self.schema_version,
                &self.checksum_sha256,
                &self.transaction,
            );
        }
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Transaction {
        transaction_id: String,
        update_id: String,
        phase: Phase,
        created_utc: String,
        old_bundle_identity: Identity,
        target_bundle_identity: Identity,
        old_image_path: String,
        target_image_path: String,
        old_event_message_path: String,
        target_event_message_path: String,
        staged_root: String,
        final_version_root: String,
        helper_protocol: Protocol,
        attempt_count: u8,
        #[serde(skip_serializing_if = "Option::is_none")]
        last_error_category: Option<Category>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        last_failure_step: Option<FailureStep>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        last_failure_code: Option<FailureCode>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        timeline: Vec<Transition>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reported_event_id: Option<String>,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Transition {
        phase: String,
        actor: Actor,
        started_utc: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        completed_utc: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        duration_ms: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        outcome: Option<Outcome>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        failure_code: Option<String>,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Identity {
        version: String,
        bundle_manifest_sha256: String,
        archive_sha256: String,
        protocol: Range,
        ledger: Ledger,
        service_configuration_revision: u32,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Range {
        major: u16,
        min_minor: u16,
        max_minor: u16,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Ledger {
        reader_min_schema: u32,
        reader_max_schema: u32,
        writer_schema: u32,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Protocol {
        major: u16,
        minor: u16,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum Actor {
        Service,
        Updater,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum Outcome {
        Succeeded,
        Failed,
        Skipped,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum Category {
        Network,
        Tls,
        Http,
        RateLimited,
        MetadataInvalid,
        NoCandidate,
        Download,
        Verification,
        HelperTooOld,
        Internal,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum FailureStep {
        HandoffVerify,
        TargetStart,
        TargetConnect,
        TargetHealthAssertion,
        RollbackTargetStop,
        RollbackRestoreConfiguration,
        RollbackOldStart,
        RollbackAbortConnect,
        RollbackIdentityAssertion,
        RollbackHealthAssertion,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum FailureCode {
        OperationFailed,
        TargetConnectTimeout,
        TargetHealthAssertionFailed,
        RollbackAbortConnectTimeout,
        RollbackIdentityContradiction,
        RollbackHealthAssertionFailed,
        ProtectedStateContradiction,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum Phase {
        Prepared,
        HelperStarted,
        FinalPathVerified,
        OldServiceStopRequested,
        OldServiceStopped,
        ImagePathChanged,
        TargetStartRequested,
        TargetHealthPending,
        TargetCommitted,
        RollbackRequested,
        TargetStopped,
        OldPathRestored,
        OldServiceRestarted,
        RollbackComplete,
        Quarantined,
    }
}
