use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use lsb_seawork_update::{
    bounded_retry_delay, cached_candidate, classify_release_response, create_json,
    download_cache_digest, extract_zip_archive, failed_target_decision, is_update_transaction_id,
    load_json, parse_retry_after_utc, remove_file_if_exists, retry_delay, stream_exact_asset,
    validate_download_url, validate_helper_install_output, validate_release_page,
    verify_bundle_root, verify_windows_directory_protection, verify_windows_file_protection,
    verify_windows_file_publisher, verify_windows_package, write_json_atomic,
    CommittedStateEnvelope, FailedTargetDecision, FailedTargetState, HelperProtocol, PackagePolicy,
    PreinstallReceiptEnvelope, PreinstallRequest, PreinstallRequestEnvelope, ReleaseCandidate,
    ReleaseChannel, ReleaseResponseStatus, ReleaseSelector, TransactionEnvelope, TransactionPhase,
    UpdateTransaction,
};
use lsb_service_proto::{UpdateCheckCategory, UpdatePhase, UpdateRetryState, SUPPORTED};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use windows_service::service::{ServiceAccess, ServiceState, ServiceType};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use crate::logging::ServiceLogger;
use crate::paths::ServicePaths;
use crate::pipe::HealthContext;
use crate::{PIPE_NAME, PIPE_SDDL, SERVICE_NAME};

const RELEASES_API: &str = "https://api.github.com/repos/LocalSandBox/local-sandbox/releases";
const USER_AGENT: &str = "LocalSandbox-SeaWork-Updater/0.5";
const API_VERSION: &str = "2022-11-28";
const MAX_RELEASE_PAGE_BYTES: usize = 2 * 1024 * 1024;
const MAX_REDIRECTS: usize = 5;
const HELPER_SERVICE_NAME: &str = "LocalSandboxSeaWorkUpdater";
const HELPER_EXE: &str = "localsandbox-seawork-updater.exe";
const MAIN_EXE: &str = "localsandbox-seawork-service.exe";
const STATUS_SCHEMA: u32 = 1;
const REQUIRED_HELPER_PROTOCOL: HelperProtocol = HelperProtocol { major: 1, minor: 1 };
const HELPER_VERSION_TIMEOUT: Duration = Duration::from_secs(5);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(2 * 60 * 60);
const PREINSTALL_TIMEOUT: Duration = Duration::from_secs(30 * 60);

pub enum StartupRecovery {
    None,
    OldService {
        update_id: String,
        target: lsb_service_proto::BundleIdentity,
    },
    TargetService {
        update_id: String,
        target: lsb_service_proto::BundleIdentity,
    },
    Quarantined,
}

pub fn inspect_startup(paths: &ServicePaths) -> StartupRecovery {
    let transaction =
        match protected_load_json::<TransactionEnvelope>(&paths.updates.current_transaction) {
            Ok(transaction) if transaction.validate().is_ok() => transaction,
            Err(error) if is_not_found(&error) => return StartupRecovery::None,
            _ => return StartupRecovery::Quarantined,
        };
    if transaction.transaction.phase == TransactionPhase::Quarantined {
        return StartupRecovery::Quarantined;
    }
    let Ok(current) = std::env::current_exe() else {
        return StartupRecovery::Quarantined;
    };
    if transaction.transaction.phase.is_terminal() {
        let committed = protected_load_json::<CommittedStateEnvelope>(&paths.updates.committed)
            .ok()
            .filter(|state| state.validate().is_ok());
        let coherent = match transaction.transaction.phase {
            TransactionPhase::TargetCommitted => {
                current == Path::new(&transaction.transaction.target_image_path)
                    && committed.as_ref().is_some_and(|state| {
                        state.committed.current == transaction.transaction.target_bundle_identity
                    })
            }
            TransactionPhase::RollbackComplete => {
                current == Path::new(&transaction.transaction.old_image_path)
                    && committed.as_ref().is_some_and(|state| {
                        state.committed.current == transaction.transaction.old_bundle_identity
                    })
            }
            _ => false,
        };
        return if coherent {
            StartupRecovery::None
        } else {
            StartupRecovery::Quarantined
        };
    }
    if current == Path::new(&transaction.transaction.target_image_path) {
        StartupRecovery::TargetService {
            update_id: transaction.transaction.update_id,
            target: transaction.transaction.target_bundle_identity,
        }
    } else if current == Path::new(&transaction.transaction.old_image_path) {
        StartupRecovery::OldService {
            update_id: transaction.transaction.update_id,
            target: transaction.transaction.target_bundle_identity,
        }
    } else {
        StartupRecovery::Quarantined
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinatorStatus {
    schema_version: u32,
    phase: UpdatePhase,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_successful_check_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    etag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    selected: Option<ReleaseCandidate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_check_category: Option<UpdateCheckCategory>,
    retry: UpdateRetryState,
}

impl Default for CoordinatorStatus {
    fn default() -> Self {
        Self {
            schema_version: STATUS_SCHEMA,
            phase: UpdatePhase::UpdateIdle,
            last_successful_check_utc: None,
            etag: None,
            selected: None,
            last_check_category: None,
            retry: UpdateRetryState {
                attempt_count: 0,
                retry_after_utc: None,
                suppressed: false,
            },
        }
    }
}

impl CoordinatorStatus {
    fn validate(&self) -> Result<()> {
        if self.schema_version != STATUS_SCHEMA
            || self.etag.as_ref().is_some_and(|value| {
                value.is_empty() || value.len() > 512 || value.chars().any(char::is_control)
            })
            || self.retry.attempt_count > 10
            || self
                .selected
                .as_ref()
                .is_some_and(|value| value.validate().is_err())
            || self.retry.retry_after_utc.as_ref().is_some_and(|value| {
                value.len() > 40
                    || time::OffsetDateTime::parse(
                        value,
                        &time::format_description::well_known::Rfc3339,
                    )
                    .is_err()
            })
        {
            bail!("coordinator status is invalid");
        }
        Ok(())
    }
}

pub struct CoordinatorHandle {
    stop: Arc<AtomicBool>,
    finished: Option<mpsc::Receiver<()>>,
}

impl CoordinatorHandle {
    pub fn stop(&mut self) {
        let Some(finished) = self.finished.take() else {
            return;
        };
        self.stop.store(true, Ordering::Release);
        let _ = finished.recv_timeout(Duration::from_secs(5));
    }
}

impl Drop for CoordinatorHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

pub fn start(
    context: HealthContext,
    paths: ServicePaths,
    channel: ReleaseChannel,
    logger: Arc<ServiceLogger>,
) -> CoordinatorHandle {
    let stop = Arc::new(AtomicBool::new(false));
    let (finished_tx, finished) = mpsc::channel();
    let thread_stop = stop.clone();
    std::thread::spawn(move || {
        let _finished = FinishedSignal(finished_tx);
        let mut coordinator = match Coordinator::new(context, paths, channel, thread_stop, logger) {
            Ok(coordinator) => coordinator,
            Err(_) => return,
        };
        coordinator.run();
    });
    CoordinatorHandle {
        stop,
        finished: Some(finished),
    }
}

struct FinishedSignal(mpsc::Sender<()>);

impl Drop for FinishedSignal {
    fn drop(&mut self) {
        let _ = self.0.send(());
    }
}

struct Coordinator {
    context: HealthContext,
    paths: ServicePaths,
    channel: ReleaseChannel,
    stop: Arc<AtomicBool>,
    trigger: Arc<AtomicBool>,
    http: GithubHttp,
    status: Arc<Mutex<CoordinatorStatus>>,
    logger: Arc<ServiceLogger>,
}

impl Coordinator {
    fn new(
        context: HealthContext,
        paths: ServicePaths,
        channel: ReleaseChannel,
        stop: Arc<AtomicBool>,
        logger: Arc<ServiceLogger>,
    ) -> Result<Self> {
        for path in [
            paths.root.as_path(),
            paths.updates.root.as_path(),
            paths.updates.downloads.as_path(),
            paths.updates.staging.as_path(),
            paths
                .updates
                .current_transaction
                .parent()
                .context("fixed transaction path has no parent")?,
            paths.updates.history.as_path(),
        ] {
            verify_windows_directory_protection(path)?;
        }
        let status = load_status(&paths.updates.status).unwrap_or_default();
        status.validate()?;
        context.observe_update(
            status.phase,
            status.last_check_category,
            status.retry.clone(),
        );
        let trigger = context.update_trigger();
        Ok(Self {
            context,
            paths,
            channel,
            stop,
            trigger,
            http: GithubHttp::new()?,
            status: Arc::new(Mutex::new(status)),
            logger,
        })
    }

    fn run(&mut self) {
        let first_delay = machine_jitter(Duration::from_secs(5 * 60), 10 * 60)
            .unwrap_or(Duration::from_secs(10 * 60));
        let mut next = Instant::now() + first_delay;
        let mut recovering = false;
        while !self.stop.load(Ordering::Acquire) {
            if self.transaction_journal_blocks_updates() {
                recovering = true;
                if Instant::now() >= next {
                    let _ = start_recovery_helper();
                    next = Instant::now() + Duration::from_secs(5 * 60);
                }
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
            match self.resume_preinstall_if_present() {
                Ok(true) => {
                    std::thread::sleep(Duration::from_secs(1));
                    continue;
                }
                Ok(false) => {}
                Err(error) => {
                    self.record_failure(&error);
                    let _ = self.cleanup_abandoned_preinstall();
                    next = Instant::now() + retry_delay(1);
                    std::thread::sleep(Duration::from_secs(1));
                    continue;
                }
            }
            if recovering {
                recovering = false;
                next = Instant::now() + first_delay;
            }
            let manual = self.trigger.swap(false, Ordering::AcqRel);
            if manual || Instant::now() >= next {
                let result = self.check_once();
                if let Err(error) = result {
                    self.record_failure(&error);
                }
                let retry = self
                    .status
                    .lock()
                    .ok()
                    .map(|status| status.retry.attempt_count)
                    .unwrap_or(1);
                next = Instant::now()
                    + if let Some(delay) = self.persisted_retry_delay() {
                        delay
                    } else if retry == 0 {
                        Duration::from_secs(6 * 60 * 60)
                            + machine_jitter(Duration::ZERO, 30 * 60).unwrap_or(Duration::ZERO)
                    } else {
                        retry_delay(retry)
                    };
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    fn transaction_journal_blocks_updates(&self) -> bool {
        match protected_load_json::<TransactionEnvelope>(&self.paths.updates.current_transaction) {
            Ok(_) => true,
            Err(error) => !is_not_found(&error),
        }
    }

    fn resume_preinstall_if_present(&mut self) -> Result<bool> {
        let request: PreinstallRequestEnvelope =
            match protected_load_json(&self.paths.updates.preinstall_request) {
                Ok(request) => request,
                Err(error) if is_not_found(&error) => return Ok(false),
                Err(error) => return Err(error).context("load protected preinstall request"),
            };
        request.validate()?;
        match protected_load_json::<PreinstallReceiptEnvelope>(
            &self.paths.updates.preinstall_receipt,
        ) {
            Ok(receipt) => {
                receipt.validate()?;
                if !receipt.matches_request(&request) {
                    bail!("protected preinstall receipt differs from its request");
                }
                self.activate_preinstalled(&request)?;
            }
            Err(error) if is_not_found(&error) => {
                let fixed = FixedProductPaths::discover()?;
                let observed = verify_helper(
                    &fixed.updater.join(HELPER_EXE),
                    request.request.helper_protocol,
                )?;
                if observed != request.request.helper_protocol {
                    bail!("installed helper protocol changed during preinstall recovery");
                }
                start_helper()?;
                self.wait_for_preinstall_receipt(&request)?;
                self.activate_preinstalled(&request)?;
            }
            Err(error) => return Err(error).context("load protected preinstall receipt"),
        }
        Ok(true)
    }

    fn wait_for_preinstall_receipt(
        &self,
        request: &PreinstallRequestEnvelope,
    ) -> Result<PreinstallReceiptEnvelope> {
        let deadline = Instant::now() + PREINSTALL_TIMEOUT;
        let mut saw_helper_active = false;
        loop {
            self.require_not_stopping("preinstall receipt wait")?;
            match protected_load_json::<PreinstallReceiptEnvelope>(
                &self.paths.updates.preinstall_receipt,
            ) {
                Ok(receipt) => {
                    receipt.validate()?;
                    if !receipt.matches_request(request) {
                        bail!("preinstall helper produced a contradictory receipt");
                    }
                    return Ok(receipt);
                }
                Err(error) if is_not_found(&error) => {}
                Err(error) => return Err(error).context("load preinstall helper receipt"),
            }
            let helper_state = helper_service_state()?;
            if helper_state != ServiceState::Stopped {
                saw_helper_active = true;
            } else if saw_helper_active {
                bail!("preinstall helper stopped without producing a receipt");
            }
            if Instant::now() >= deadline {
                bail!("preinstall helper exceeded its bounded preparation time");
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    fn activate_preinstalled(&mut self, request: &PreinstallRequestEnvelope) -> Result<()> {
        request.validate()?;
        let receipt: PreinstallReceiptEnvelope =
            protected_load_json(&self.paths.updates.preinstall_receipt)
                .context("activation requires a protected preinstall receipt")?;
        receipt.validate()?;
        if !receipt.matches_request(request) {
            bail!("activation preinstall receipt differs from its request");
        }
        let fixed = FixedProductPaths::discover()?;
        if Path::new(&request.request.final_version_root)
            != fixed.versions.join(&request.request.candidate.version)
        {
            bail!("preinstalled final root differs from fixed product policy");
        }
        let helper = fixed.updater.join(HELPER_EXE);
        let observed = verify_helper(&helper, request.request.helper_protocol)?;
        if observed != request.request.helper_protocol {
            bail!("installed helper protocol changed before activation");
        }
        let committed: CommittedStateEnvelope = protected_load_json(&self.paths.updates.committed)?;
        committed.validate()?;
        if committed.committed.current != request.request.old_bundle_identity {
            bail!("preinstall request no longer matches committed state");
        }

        self.wait_for_helper_stopped()?;
        self.set_phase(
            UpdatePhase::UpdateWaitingForIdle,
            Some(request.request.candidate.clone()),
        )?;
        while !self.context.admissions().try_seal_if_idle()? {
            self.require_not_stopping("atomic idle seal")?;
            std::thread::sleep(Duration::from_millis(250));
        }

        let mut update_id = None;
        let mut journal_created = false;
        let handoff = (|| {
            self.require_not_stopping("sealed activation handoff")?;
            self.set_phase(
                UpdatePhase::UpdateSealed,
                Some(request.request.candidate.clone()),
            )?;
            let id = self
                .context
                .prepare_preinstalled_update(request.request.target_bundle_identity.clone())?;
            update_id = Some(id.clone());
            let old_image = std::env::current_exe()?;
            let final_root = Path::new(&request.request.final_version_root);
            let target_image = final_root.join("bin").join(MAIN_EXE);
            let transaction = TransactionEnvelope::new(UpdateTransaction {
                transaction_id: request.request.request_id.clone(),
                update_id: id,
                phase: TransactionPhase::FinalPathVerified,
                created_utc: now_utc()?,
                old_bundle_identity: request.request.old_bundle_identity.clone(),
                target_bundle_identity: request.request.target_bundle_identity.clone(),
                old_image_path: path_string(&old_image)?,
                target_image_path: path_string(&target_image)?,
                old_event_message_path: path_string(&old_image)?,
                target_event_message_path: path_string(&target_image)?,
                staged_root: request.request.staged_root.clone(),
                final_version_root: request.request.final_version_root.clone(),
                helper_protocol: request.request.helper_protocol,
                attempt_count: 1,
                last_error_category: None,
            })?;
            create_json(&self.paths.updates.current_transaction, &transaction)?;
            journal_created = true;
            self.require_not_stopping("activation helper start")?;
            self.set_phase(
                UpdatePhase::UpdateHelperStarting,
                Some(request.request.candidate.clone()),
            )?;
            start_helper()
        })();
        if let Err(error) = handoff {
            if journal_created {
                let _ = remove_file_if_exists(&self.paths.updates.current_transaction);
            }
            if let Some(update_id) = update_id {
                let _ = self.context.abort_automatic_update(&update_id);
            } else {
                let _ = self.context.cancel_preinstalled_seal();
            }
            return Err(error);
        }
        Ok(())
    }

    fn wait_for_helper_stopped(&self) -> Result<()> {
        let deadline = Instant::now() + PREINSTALL_TIMEOUT;
        loop {
            self.require_not_stopping("preinstall helper shutdown")?;
            if helper_service_state()? == ServiceState::Stopped {
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!("preinstall helper did not stop before activation");
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    fn cleanup_abandoned_preinstall(&self) -> Result<()> {
        let request = protected_load_json::<PreinstallRequestEnvelope>(
            &self.paths.updates.preinstall_request,
        )
        .ok()
        .filter(|request| request.validate().is_ok());
        let mut failed = false;
        for path in [
            &self.paths.updates.preinstall_receipt,
            &self.paths.updates.preinstall_request,
        ] {
            if remove_file_if_exists(path).is_err() {
                failed = true;
            }
        }
        if let Some(request) = request {
            if remove_owned_staging(&self.paths.updates.staging, &request.request.request_id)
                .is_err()
            {
                failed = true;
            }
        }
        if failed {
            bail!("abandoned preinstall cleanup was incomplete");
        }
        Ok(())
    }

    fn check_once(&mut self) -> Result<()> {
        if self.stop.load(Ordering::Acquire) {
            bail!("service shutdown cancelled update check");
        }
        prune_staging_root(&self.paths.updates.staging)?;
        self.set_phase(UpdatePhase::UpdateChecking, None)?;
        let committed: CommittedStateEnvelope = protected_load_json(&self.paths.updates.committed)
            .context("automatic activation requires valid committed state")?;
        committed.validate()?;
        self.context
            .set_committed_identity(committed.committed.current.clone());
        let ReleasePages {
            pages,
            etag,
            not_modified,
        } = self.http.release_pages(self.current_etag().as_deref())?;
        let candidate = if not_modified {
            self.cached_candidate(&committed)?
        } else {
            let mut selector = ReleaseSelector::new();
            for page in pages {
                selector.push_page(&page)?;
            }
            selector.select(
                self.channel,
                &committed.committed.current.version,
                &committed.committed.highest_committed_version,
            )?
        };
        let Some(candidate) = candidate else {
            self.record_success(UpdatePhase::UpdateNoCandidate, None, etag)?;
            return Ok(());
        };
        if let Some((retry_after_utc, permanently_suppressed)) =
            self.failed_target_suppression(&candidate)?
        {
            self.record_suppressed(candidate, retry_after_utc, permanently_suppressed, etag)?;
            return Ok(());
        }
        self.set_phase(UpdatePhase::UpdateDownloading, Some(candidate.clone()))?;
        let archive = self
            .http
            .download(&candidate, &self.paths.updates.downloads, &self.stop)?;
        self.set_phase(UpdatePhase::UpdateVerifying, Some(candidate.clone()))?;
        let transaction_id = random_id()?;
        let staging = self.paths.updates.staging.join(&transaction_id);
        let extraction = extract_zip_archive(&archive, &staging)?;
        if extraction.archive_sha256 != candidate.archive_sha256 {
            let _ = remove_owned_staging(&self.paths.updates.staging, &transaction_id);
            bail!("staged archive digest differs from release identity");
        }
        let staged_root = staging.join("LocalSandbox");
        let verified_target = (|| {
            let policy = PackagePolicy {
                expected_version: &candidate.version,
                supported_protocol: SUPPORTED,
                ledger_writer_schema: committed.committed.current.ledger.writer_schema,
                service_configuration_revision: crate::bundle::SERVICE_CONFIGURATION_REVISION,
                service_name: SERVICE_NAME,
                service_display_name: "LocalSandbox for SeaWork",
                service_account: "LocalSystem",
                service_type: "SERVICE_WIN32_OWN_PROCESS",
                pipe_name: PIPE_NAME,
                pipe_sddl: PIPE_SDDL,
            };
            let verification = verify_bundle_root(&staged_root, &policy)?;
            let target = verification.bundle_identity(&candidate.archive_sha256)?;
            let required_helper_protocol = verification.required_helper_protocol;
            verify_windows_directory_protection(&staged_root)?;
            verify_windows_package(&staged_root, &verification, &compiled_publishers())?;
            if target.version != candidate.version
                || target.ledger.writer_schema != committed.committed.current.ledger.writer_schema
            {
                bail!("verified target is incompatible with committed service state");
            }
            Ok::<_, anyhow::Error>((target, required_helper_protocol))
        })();
        let (target, required_helper_protocol) = match verified_target {
            Ok(target) => target,
            Err(error) => {
                let _ = remove_owned_staging(&self.paths.updates.staging, &transaction_id);
                return Err(error);
            }
        };

        let pre_handoff = (|| {
            self.require_not_stopping("candidate activation")?;
            let fixed = FixedProductPaths::discover()?;
            let helper = fixed.updater.join(HELPER_EXE);
            verify_helper(&helper, required_helper_protocol)?;
            Ok::<_, anyhow::Error>((fixed, helper))
        })();
        let (fixed, helper) = match pre_handoff {
            Ok(value) => value,
            Err(error) => {
                let _ = remove_owned_staging(&self.paths.updates.staging, &transaction_id);
                return Err(error);
            }
        };

        let final_root = fixed.versions.join(&candidate.version);
        let helper_protocol = verify_helper(&helper, required_helper_protocol)?;
        let request = PreinstallRequestEnvelope::new(PreinstallRequest {
            request_id: transaction_id,
            created_utc: now_utc()?,
            candidate: candidate.clone(),
            old_bundle_identity: committed.committed.current,
            target_bundle_identity: target,
            staged_root: path_string(&staged_root)?,
            final_version_root: path_string(&final_root)?,
            helper_protocol,
        })?;
        create_json(&self.paths.updates.preinstall_request, &request)
            .context("persist protected preinstall request")?;
        if let Err(error) = start_helper()
            .and_then(|()| self.wait_for_preinstall_receipt(&request).map(|_| ()))
            .and_then(|()| self.activate_preinstalled(&request))
        {
            let _ = self.cleanup_abandoned_preinstall();
            return Err(error);
        }
        self.record_success(UpdatePhase::UpdateActivationPending, Some(candidate), etag)
    }

    fn current_etag(&self) -> Option<String> {
        self.status
            .lock()
            .ok()
            .and_then(|status| status.etag.clone())
    }

    fn require_not_stopping(&self, operation: &str) -> Result<()> {
        if self.stop.load(Ordering::Acquire) {
            bail!("service shutdown cancelled update {operation}");
        }
        Ok(())
    }

    fn cached_candidate(
        &self,
        committed: &CommittedStateEnvelope,
    ) -> Result<Option<ReleaseCandidate>> {
        let candidate = self
            .status
            .lock()
            .map_err(|_| anyhow::anyhow!("coordinator status poisoned"))?
            .selected
            .clone();
        cached_candidate(
            candidate.as_ref(),
            self.channel,
            &committed.committed.current.version,
            &committed.committed.highest_committed_version,
        )
    }

    fn set_phase(&self, phase: UpdatePhase, selected: Option<ReleaseCandidate>) -> Result<()> {
        let mut status = self
            .status
            .lock()
            .map_err(|_| anyhow::anyhow!("coordinator status poisoned"))?;
        status.phase = phase;
        status.selected = selected;
        status.validate()?;
        write_json_atomic(&self.paths.updates.status, &*status)?;
        self.context.observe_update(
            status.phase,
            status.last_check_category,
            status.retry.clone(),
        );
        self.log_status(&status);
        Ok(())
    }

    fn record_success(
        &self,
        phase: UpdatePhase,
        selected: Option<ReleaseCandidate>,
        etag: Option<String>,
    ) -> Result<()> {
        let mut status = self
            .status
            .lock()
            .map_err(|_| anyhow::anyhow!("coordinator status poisoned"))?;
        status.phase = phase;
        status.selected = selected;
        status.etag = etag.or_else(|| status.etag.clone());
        status.last_successful_check_utc = Some(now_utc()?);
        status.last_check_category = if phase == UpdatePhase::UpdateNoCandidate {
            Some(UpdateCheckCategory::NoCandidate)
        } else {
            None
        };
        status.retry = UpdateRetryState {
            attempt_count: 0,
            retry_after_utc: None,
            suppressed: false,
        };
        status.validate()?;
        write_json_atomic(&self.paths.updates.status, &*status)?;
        self.context.observe_update(
            status.phase,
            status.last_check_category,
            status.retry.clone(),
        );
        self.log_status(&status);
        Ok(())
    }

    fn record_failure(&self, error: &anyhow::Error) {
        let Ok(mut status) = self.status.lock() else {
            return;
        };
        status.phase = UpdatePhase::UpdateIdle;
        status.last_check_category = Some(classify_error(error));
        status.retry.attempt_count = status.retry.attempt_count.saturating_add(1).min(10);
        status.retry.retry_after_utc = error
            .downcast_ref::<RateLimited>()
            .and_then(|failure| failure.retry_after_utc.clone())
            .or_else(|| {
                error
                    .downcast_ref::<HttpStatusFailure>()
                    .and_then(|failure| failure.retry_after_utc.clone())
            });
        let _ = write_json_atomic(&self.paths.updates.status, &*status);
        self.context.observe_update(
            status.phase,
            status.last_check_category,
            status.retry.clone(),
        );
        self.log_status(&status);
    }

    fn persisted_retry_delay(&self) -> Option<Duration> {
        let retry_after = self.status.lock().ok()?.retry.retry_after_utc.clone()?;
        let retry_after = time::OffsetDateTime::parse(
            &retry_after,
            &time::format_description::well_known::Rfc3339,
        )
        .ok()?;
        Some(bounded_retry_delay(
            retry_after,
            time::OffsetDateTime::now_utc(),
        ))
    }

    fn failed_target_suppression(
        &self,
        candidate: &ReleaseCandidate,
    ) -> Result<Option<(Option<String>, bool)>> {
        let failed =
            match protected_load_json::<FailedTargetState>(&self.paths.updates.failed_target) {
                Ok(failed) => failed,
                Err(error) if is_not_found(&error) => return Ok(None),
                Err(error) => return Err(error).context("load protected failed-target state"),
            };
        match failed_target_decision(candidate, &failed, time::OffsetDateTime::now_utc())? {
            FailedTargetDecision::Allowed => Ok(None),
            FailedTargetDecision::Cooldown { retry_after_utc } => {
                Ok(Some((Some(retry_after_utc), false)))
            }
            FailedTargetDecision::Suppressed => Ok(Some((None, true))),
        }
    }

    fn record_suppressed(
        &self,
        candidate: ReleaseCandidate,
        retry_after_utc: Option<String>,
        permanently_suppressed: bool,
        etag: Option<String>,
    ) -> Result<()> {
        let mut status = self
            .status
            .lock()
            .map_err(|_| anyhow::anyhow!("coordinator status poisoned"))?;
        status.phase = UpdatePhase::UpdateFailedTargetSuppressed;
        status.selected = Some(candidate);
        status.etag = etag.or_else(|| status.etag.clone());
        status.last_successful_check_utc = Some(now_utc()?);
        status.last_check_category = Some(UpdateCheckCategory::NoCandidate);
        status.retry = UpdateRetryState {
            attempt_count: 0,
            retry_after_utc,
            suppressed: permanently_suppressed,
        };
        status.validate()?;
        write_json_atomic(&self.paths.updates.status, &*status)?;
        self.context.observe_update(
            status.phase,
            status.last_check_category,
            status.retry.clone(),
        );
        self.log_status(&status);
        Ok(())
    }

    fn log_status(&self, status: &CoordinatorStatus) {
        let selected = status.selected.as_ref();
        let _ = self.logger.write_update(
            update_phase_token(status.phase),
            status
                .last_check_category
                .map(update_category_code)
                .unwrap_or_else(|| update_phase_code(status.phase)),
            selected.map(|candidate| candidate.version.as_str()),
            selected.map(|candidate| &candidate.archive_sha256[..32]),
        );
    }
}

fn update_phase_token(phase: UpdatePhase) -> &'static str {
    match phase {
        UpdatePhase::UpdateIdle => "update_idle",
        UpdatePhase::UpdateChecking => "update_checking",
        UpdatePhase::UpdateNoCandidate => "update_no_candidate",
        UpdatePhase::UpdateDownloading => "update_downloading",
        UpdatePhase::UpdateVerifying => "update_verifying",
        UpdatePhase::UpdateWaitingForIdle => "update_waiting_for_idle",
        UpdatePhase::UpdateSealed => "update_sealed",
        UpdatePhase::UpdateHelperStarting => "update_helper_starting",
        UpdatePhase::UpdateActivationPending => "update_activation_pending",
        UpdatePhase::UpdateRollbackPending => "update_rollback_pending",
        UpdatePhase::UpdateFailedTargetSuppressed => "update_failed_target_suppressed",
        UpdatePhase::UpdateRecoveryQuarantine => "update_recovery_quarantine",
    }
}

fn update_phase_code(phase: UpdatePhase) -> &'static str {
    match phase {
        UpdatePhase::UpdateIdle => "UPDATE_IDLE",
        UpdatePhase::UpdateChecking => "UPDATE_CHECKING",
        UpdatePhase::UpdateNoCandidate => "UPDATE_NO_CANDIDATE",
        UpdatePhase::UpdateDownloading => "UPDATE_DOWNLOADING",
        UpdatePhase::UpdateVerifying => "UPDATE_VERIFYING",
        UpdatePhase::UpdateWaitingForIdle => "UPDATE_WAITING_FOR_IDLE",
        UpdatePhase::UpdateSealed => "UPDATE_SEALED",
        UpdatePhase::UpdateHelperStarting => "UPDATE_HELPER_STARTING",
        UpdatePhase::UpdateActivationPending => "UPDATE_ACTIVATION_PENDING",
        UpdatePhase::UpdateRollbackPending => "UPDATE_ROLLBACK_PENDING",
        UpdatePhase::UpdateFailedTargetSuppressed => "UPDATE_FAILED_TARGET_SUPPRESSED",
        UpdatePhase::UpdateRecoveryQuarantine => "UPDATE_RECOVERY_QUARANTINE",
    }
}

fn update_category_code(category: UpdateCheckCategory) -> &'static str {
    match category {
        UpdateCheckCategory::Network => "UPDATE_NETWORK",
        UpdateCheckCategory::Tls => "UPDATE_TLS",
        UpdateCheckCategory::Http => "UPDATE_HTTP",
        UpdateCheckCategory::RateLimited => "UPDATE_RATE_LIMITED",
        UpdateCheckCategory::MetadataInvalid => "UPDATE_METADATA_INVALID",
        UpdateCheckCategory::NoCandidate => "UPDATE_NO_CANDIDATE",
        UpdateCheckCategory::Download => "UPDATE_DOWNLOAD_FAILED",
        UpdateCheckCategory::Verification => "UPDATE_VERIFICATION_FAILED",
        UpdateCheckCategory::HelperTooOld => "UPDATE_HELPER_TOO_OLD",
        UpdateCheckCategory::Internal => "UPDATE_INTERNAL",
    }
}

#[derive(Debug)]
struct RateLimited {
    retry_after_utc: Option<String>,
}

impl std::fmt::Display for RateLimited {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("GitHub API rate limited the update check")
    }
}

impl std::error::Error for RateLimited {}

#[derive(Debug)]
struct HttpStatusFailure {
    status: u16,
    retry_after_utc: Option<String>,
}

impl std::fmt::Display for HttpStatusFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "GitHub update endpoint returned HTTP {}",
            self.status
        )
    }
}

impl std::error::Error for HttpStatusFailure {}

struct ReleasePages {
    pages: Vec<Vec<u8>>,
    etag: Option<String>,
    not_modified: bool,
}

struct GithubHttp {
    agent: ureq::Agent,
}

impl GithubHttp {
    fn new() -> Result<Self> {
        let config = ureq::Agent::config_builder()
            .proxy(None)
            .https_only(true)
            .max_redirects(0)
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(120)))
            .timeout_connect(Some(Duration::from_secs(15)))
            .timeout_recv_response(Some(Duration::from_secs(30)))
            .timeout_recv_body(Some(Duration::from_secs(60)))
            .user_agent(USER_AGENT)
            .build();
        Ok(Self {
            agent: config.into(),
        })
    }

    fn release_pages(&self, etag: Option<&str>) -> Result<ReleasePages> {
        let mut pages = Vec::new();
        let mut observed_etag = None;
        for page in 1..=10 {
            let url = format!("{RELEASES_API}?per_page=50&page={page}");
            let mut request = self
                .agent
                .get(&url)
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", API_VERSION)
                .header("Accept-Encoding", "identity");
            if page == 1 {
                if let Some(etag) = etag {
                    request = request.header("If-None-Match", etag);
                }
            }
            let mut response = request.call()?;
            let status = response.status().as_u16();
            match classify_release_response(page, status, etag)? {
                ReleaseResponseStatus::Success => {}
                ReleaseResponseStatus::NotModified { etag } => {
                    return Ok(ReleasePages {
                        pages,
                        etag: Some(etag),
                        not_modified: true,
                    });
                }
                ReleaseResponseStatus::RateLimited => {
                    return Err(RateLimited {
                        retry_after_utc: retry_after_utc(&response),
                    }
                    .into());
                }
                ReleaseResponseStatus::HttpFailure { status } => {
                    return Err(HttpStatusFailure {
                        status,
                        retry_after_utc: retry_after_utc(&response),
                    }
                    .into());
                }
            }
            let response_etag = if page == 1 {
                header(&response, "etag")
            } else {
                None
            };
            let body = response
                .body_mut()
                .with_config()
                .limit(MAX_RELEASE_PAGE_BYTES as u64)
                .read_to_vec()?;
            let count = serde_json::from_slice::<serde_json::Value>(&body)?
                .as_array()
                .context("GitHub releases response is not an array")?
                .len();
            let progress = validate_release_page(page, count, response_etag.as_deref())?;
            if page == 1 {
                observed_etag = progress.etag;
            }
            pages.push(body);
            if progress.complete {
                break;
            }
        }
        Ok(ReleasePages {
            pages,
            etag: observed_etag,
            not_modified: false,
        })
    }

    fn download(
        &self,
        candidate: &ReleaseCandidate,
        downloads: &Path,
        stop: &AtomicBool,
    ) -> Result<PathBuf> {
        prune_download_cache(downloads, &candidate.archive_sha256)?;
        let final_path = downloads.join(format!("{}.zip", candidate.archive_sha256));
        match fs::symlink_metadata(&final_path) {
            Ok(metadata) if regular_non_reparse(&metadata) => {
                if metadata.len() == candidate.asset_size
                    && sha256_file(&final_path)? == candidate.archive_sha256
                {
                    return Ok(final_path);
                }
                bail!("digest-addressed archive cache contains contradictory bytes");
            }
            Ok(_) => bail!("digest-addressed archive cache path is ambiguous"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let partial = downloads.join(format!("{}.partial", candidate.archive_sha256));
        match fs::symlink_metadata(&partial) {
            Ok(metadata) if regular_non_reparse(&metadata) => {
                fs::remove_file(&partial)?;
            }
            Ok(_) => bail!("download partial path is ambiguous"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let mut url = candidate.asset_url.clone();
        let mut response = None;
        let deadline = Instant::now() + DOWNLOAD_TIMEOUT;
        for redirect in 0..=MAX_REDIRECTS {
            validate_download_url(&url, redirect == 0)?;
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                bail!("GitHub asset download exceeded its compiled overall timeout");
            }
            let result = self
                .agent
                .get(&url)
                .config()
                .timeout_global(Some(remaining))
                .timeout_recv_body(Some(remaining))
                .build()
                .header("Accept", "application/octet-stream")
                .header("Accept-Encoding", "identity")
                .call()?;
            let status = result.status().as_u16();
            if matches!(status, 301 | 302 | 303 | 307 | 308) {
                url =
                    header(&result, "location").context("GitHub asset redirect has no Location")?;
                continue;
            }
            if status != 200 {
                if matches!(status, 403 | 429) {
                    return Err(RateLimited {
                        retry_after_utc: retry_after_utc(&result),
                    }
                    .into());
                }
                return Err(HttpStatusFailure {
                    status,
                    retry_after_utc: retry_after_utc(&result),
                }
                .into());
            }
            response = Some(result);
            break;
        }
        let response = response.context("GitHub asset redirect limit exceeded")?;
        if header(&response, "content-length")
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|size| size != candidate.asset_size)
        {
            bail!("GitHub asset Content-Length differs from immutable release metadata");
        }
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .share_mode(0)
            .open(&partial)?;
        let result = (|| {
            let mut reader = BufReader::new(response.into_body().into_reader());
            stream_exact_asset(
                &mut reader,
                &mut output,
                candidate.asset_size,
                &candidate.archive_sha256,
                || stop.load(Ordering::Acquire),
            )?;
            output.sync_all()?;
            drop(output);
            fs::rename(&partial, &final_path)?;
            sync_directory_metadata(downloads)?;
            Ok(final_path.clone())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&partial);
        }
        result
    }
}

fn prune_download_cache(downloads: &Path, retained_digest: &str) -> Result<()> {
    let mut removed = false;
    for entry in fs::read_dir(downloads)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("download cache entry name is not Unicode"))?;
        let digest =
            download_cache_digest(&name).context("download cache contains an unexpected entry")?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if !regular_non_reparse(&metadata) {
            bail!("download cache entry is not a regular non-reparse file");
        }
        if digest != retained_digest {
            fs::remove_file(entry.path())?;
            removed = true;
        }
    }
    if removed {
        sync_directory_metadata(downloads)?;
    }
    Ok(())
}

fn prune_staging_root(staging: &Path) -> Result<()> {
    let mut removed = false;
    for entry in fs::read_dir(staging)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("update staging entry name is not Unicode"))?;
        if !is_update_transaction_id(&name) {
            bail!("update staging contains an unexpected entry");
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        use std::os::windows::fs::MetadataExt;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.file_attributes() & 0x400 != 0
        {
            bail!("update staging entry is not a regular non-reparse directory");
        }
        fs::remove_dir_all(entry.path())?;
        removed = true;
    }
    if removed {
        sync_directory_metadata(staging)?;
    }
    Ok(())
}

fn header(response: &http::Response<ureq::Body>, name: &str) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

fn retry_after_utc(response: &http::Response<ureq::Body>) -> Option<String> {
    let retry_after = header(response, "retry-after");
    let reset = header(response, "x-ratelimit-reset");
    parse_retry_after_utc(
        retry_after.as_deref(),
        reset.as_deref(),
        time::OffsetDateTime::now_utc(),
    )
}

fn verify_helper(path: &Path, required_protocol: HelperProtocol) -> Result<HelperProtocol> {
    let updater = path
        .parent()
        .context("fixed updater executable has no parent")?;
    let product = updater
        .parent()
        .context("fixed updater directory has no parent")?;
    verify_windows_directory_protection(product)?;
    verify_windows_directory_protection(updater)?;
    verify_windows_file_publisher(path, &compiled_publishers())?;
    let protocol = verify_helper_protocol(path, required_protocol)?;
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(HELPER_SERVICE_NAME, ServiceAccess::QUERY_CONFIG)?;
    let config = service.query_config()?;
    let expected = format!("\"{}\" --service", path_string(path)?);
    if config.service_type != ServiceType::OWN_PROCESS
        || config.executable_path.as_os_str() != std::ffi::OsStr::new(&expected)
        || config
            .account_name
            .as_deref()
            .and_then(std::ffi::OsStr::to_str)
            .is_none_or(|account| !account.eq_ignore_ascii_case("LocalSystem"))
    {
        bail!("updater SCM configuration differs from compiled product policy");
    }
    Ok(protocol)
}

fn verify_helper_protocol(
    path: &Path,
    required_protocol: HelperProtocol,
) -> Result<HelperProtocol> {
    let mut child = Command::new(path)
        .args(["--verify-install", "--json"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW)
        .spawn()
        .context("start updater helper protocol query")?;
    let deadline = Instant::now() + HELPER_VERSION_TIMEOUT;
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .context("poll updater helper protocol query")?
        {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("helper protocol query exceeded its fixed timeout");
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    if !status.success() {
        bail!("helper protocol query failed with status {status}");
    }
    let output = child
        .wait_with_output()
        .context("collect updater helper protocol query")?;
    let output =
        validate_helper_install_output(&output.stdout, HELPER_SERVICE_NAME, required_protocol)?;
    Ok(HelperProtocol {
        major: output.helper_protocol_major,
        minor: output.helper_protocol_minor,
    })
}

fn sync_directory_metadata(path: &Path) -> Result<()> {
    use windows_sys::Win32::Foundation::ERROR_INVALID_HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
    };

    let directory = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    match directory.sync_all() {
        Ok(()) => Ok(()),
        Err(error) if error.raw_os_error() == Some(ERROR_INVALID_HANDLE as i32) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn start_helper() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(
        HELPER_SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::START,
    )?;
    if service.query_status()?.current_state == ServiceState::Stopped {
        if let Err(error) = service.start::<&std::ffi::OsStr>(&[]) {
            if service
                .query_status()
                .is_ok_and(|status| status.current_state == ServiceState::Stopped)
            {
                return Err(error.into());
            }
        }
    }
    Ok(())
}

fn helper_service_state() -> Result<ServiceState> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(HELPER_SERVICE_NAME, ServiceAccess::QUERY_STATUS)?;
    Ok(service.query_status()?.current_state)
}

pub fn start_recovery_helper() -> Result<()> {
    let fixed = FixedProductPaths::discover()?;
    verify_helper(&fixed.updater.join(HELPER_EXE), REQUIRED_HELPER_PROTOCOL)?;
    start_helper()
}

struct FixedProductPaths {
    updater: PathBuf,
    versions: PathBuf,
}

impl FixedProductPaths {
    fn discover() -> Result<Self> {
        let root = known_folder(&windows_sys::Win32::UI::Shell::FOLDERID_ProgramFiles)?
            .join("SeaWork")
            .join("LocalSandbox");
        Ok(Self {
            updater: root.join("updater"),
            versions: root.join("versions"),
        })
    }
}

fn known_folder(id: *const windows_sys::core::GUID) -> Result<PathBuf> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::SHGetKnownFolderPath;
    let mut raw = std::ptr::null_mut();
    let result = unsafe { SHGetKnownFolderPath(id, 0, std::ptr::null_mut(), &mut raw) };
    if result < 0 {
        bail!("SHGetKnownFolderPath failed: HRESULT 0x{result:08x}");
    }
    let length = (0..)
        .take_while(|index| unsafe { *raw.add(*index) } != 0)
        .count();
    let path = PathBuf::from(OsString::from_wide(unsafe {
        std::slice::from_raw_parts(raw, length)
    }));
    unsafe { CoTaskMemFree(raw.cast()) };
    Ok(path)
}

fn load_status(path: &Path) -> Result<CoordinatorStatus> {
    match protected_load_json(path) {
        Ok(status) => Ok(status),
        Err(error) if is_not_found(&error) => Ok(CoordinatorStatus::default()),
        Err(error) => Err(error),
    }
}

fn protected_load_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    verify_windows_file_protection(path)?;
    load_json(path)
}

fn is_not_found(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    })
}

fn now_utc() -> Result<String> {
    Ok(time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339)?)
}

fn random_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|error| anyhow::anyhow!("generate update id: {error}"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn path_string(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_string)
        .context("protected update path is not Unicode")
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut reader = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn regular_non_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    metadata.is_file()
        && !metadata.file_type().is_symlink()
        && metadata.file_attributes() & 0x400 == 0
}

fn remove_owned_staging(root: &Path, transaction_id: &str) -> Result<()> {
    use std::os::windows::fs::MetadataExt;

    let path = root.join(transaction_id);
    if path.parent() != Some(root) || path.file_name() != Some(std::ffi::OsStr::new(transaction_id))
    {
        bail!("transaction staging cleanup path is not exactly owned");
    }
    match fs::symlink_metadata(&path) {
        Ok(metadata)
            if metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.file_attributes() & 0x400 == 0 =>
        {
            fs::remove_dir_all(path)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => bail!("transaction staging cleanup path is ambiguous"),
    }
    Ok(())
}

fn compiled_publishers() -> Vec<String> {
    env!("LSB_COMPILED_SEAWORK_PUBLISHERS_SHA256")
        .split(',')
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}

fn classify_error(error: &anyhow::Error) -> UpdateCheckCategory {
    if error.downcast_ref::<RateLimited>().is_some() {
        return UpdateCheckCategory::RateLimited;
    }
    if error.downcast_ref::<HttpStatusFailure>().is_some() {
        return UpdateCheckCategory::Http;
    }
    let text = format!("{error:#}").to_ascii_lowercase();
    if text.contains("tls") || text.contains("certificate") {
        UpdateCheckCategory::Tls
    } else if text.contains("http") || text.contains("github") {
        UpdateCheckCategory::Http
    } else if text.contains("network")
        || text.contains("connect")
        || text.contains("dns")
        || text.contains("transport")
    {
        UpdateCheckCategory::Network
    } else if text.contains("download") || text.contains("asset") {
        UpdateCheckCategory::Download
    } else if text.contains("bundle")
        || text.contains("catalog")
        || text.contains("signature")
        || text.contains("publisher")
    {
        UpdateCheckCategory::Verification
    } else if text.contains("release")
        || text.contains("semver")
        || text.contains("json")
        || text.contains("immutable")
        || text.contains("metadata")
    {
        UpdateCheckCategory::MetadataInvalid
    } else if text.contains("helper protocol is incompatible") {
        UpdateCheckCategory::HelperTooOld
    } else {
        UpdateCheckCategory::Internal
    }
}

fn machine_jitter(base: Duration, range_seconds: u64) -> Result<Duration> {
    let machine = machine_guid()?;
    let digest = Sha256::digest(machine.as_bytes());
    let value = u64::from_le_bytes(digest[..8].try_into()?);
    Ok(base
        + if range_seconds == 0 {
            Duration::ZERO
        } else {
            Duration::from_secs(value % (range_seconds + 1))
        })
}

fn machine_guid() -> Result<String> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ};
    let wide = |value: &str| value.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let key = wide(r"SOFTWARE\Microsoft\Cryptography");
    let name = wide("MachineGuid");
    let mut buffer = [0u16; 128];
    let mut bytes = (buffer.len() * 2) as u32;
    let result = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            name.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    if result != 0 {
        bail!("read MachineGuid failed with {result}");
    }
    let length = buffer.iter().position(|value| *value == 0).unwrap_or(0);
    let value = OsString::from_wide(&buffer[..length])
        .into_string()
        .map_err(|_| anyhow::anyhow!("MachineGuid is not Unicode"))?;
    if value.is_empty() || value.len() > 128 {
        bail!("MachineGuid is invalid");
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coordinator_status_rejects_unbounded_etag() {
        let mut status = CoordinatorStatus::default();
        status.etag = Some("x".repeat(513));
        assert!(status.validate().is_err());
    }
}
