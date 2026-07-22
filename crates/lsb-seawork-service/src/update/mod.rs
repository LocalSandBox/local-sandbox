use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{bail, Context, Result};
use lsb_seawork_update::{
    cached_candidate, create_json, extract_zip_archive, failed_target_decision, load_json,
    parse_retry_after_utc, remove_file_if_exists, retry_delay, stream_exact_asset,
    validate_download_url, validate_helper_version_output, verify_bundle_root,
    verify_windows_file_publisher, verify_windows_package, write_json_atomic,
    CommittedStateEnvelope, FailedTargetDecision, FailedTargetState, HelperProtocol, PackagePolicy,
    ReleaseCandidate, ReleaseChannel, ReleaseSelector, TransactionEnvelope, TransactionPhase,
    UpdateTransaction,
};
use lsb_service_proto::{UpdateCheckCategory, UpdatePhase, UpdateRetryState, SUPPORTED};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use windows_service::service::{ServiceAccess, ServiceState, ServiceType};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use crate::admission::AdmissionState;
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
    let transaction = match load_json::<TransactionEnvelope>(&paths.updates.current_transaction) {
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
        let committed = load_json::<CommittedStateEnvelope>(&paths.updates.committed)
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
    finished: mpsc::Receiver<()>,
}

impl CoordinatorHandle {
    fn stop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = self.finished.recv_timeout(Duration::from_secs(5));
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
) -> CoordinatorHandle {
    let stop = Arc::new(AtomicBool::new(false));
    let (finished_tx, finished) = mpsc::channel();
    let thread_stop = stop.clone();
    std::thread::spawn(move || {
        let _finished = FinishedSignal(finished_tx);
        let mut coordinator = match Coordinator::new(context, paths, channel, thread_stop) {
            Ok(coordinator) => coordinator,
            Err(_) => return,
        };
        coordinator.run();
    });
    CoordinatorHandle { stop, finished }
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
}

impl Coordinator {
    fn new(
        context: HealthContext,
        paths: ServicePaths,
        channel: ReleaseChannel,
        stop: Arc<AtomicBool>,
    ) -> Result<Self> {
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
        })
    }

    fn run(&mut self) {
        let first_delay = machine_jitter(Duration::from_secs(5 * 60), 10 * 60)
            .unwrap_or(Duration::from_secs(10 * 60));
        let mut next = SystemTime::now() + first_delay;
        let mut recovering = false;
        while !self.stop.load(Ordering::Acquire) {
            if self.transaction_recovery_pending() {
                recovering = true;
                if SystemTime::now() >= next {
                    let _ = start_recovery_helper();
                    next = SystemTime::now() + Duration::from_secs(5 * 60);
                }
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
            if recovering {
                recovering = false;
                next = SystemTime::now() + first_delay;
            }
            let manual = self.trigger.swap(false, Ordering::AcqRel);
            if manual || SystemTime::now() >= next {
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
                next = SystemTime::now()
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

    fn transaction_recovery_pending(&self) -> bool {
        match load_json::<TransactionEnvelope>(&self.paths.updates.current_transaction) {
            Ok(transaction) => transaction.validate().is_ok(),
            Err(error) => !is_not_found(&error),
        }
    }

    fn check_once(&mut self) -> Result<()> {
        if self.stop.load(Ordering::Acquire) {
            bail!("service shutdown cancelled update check");
        }
        self.set_phase(UpdatePhase::UpdateChecking, None)?;
        let committed: CommittedStateEnvelope = load_json(&self.paths.updates.committed)
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
            verify_windows_package(&staged_root, &verification, &compiled_publishers())?;
            if target.version != candidate.version
                || target.ledger.writer_schema != committed.committed.current.ledger.writer_schema
            {
                bail!("verified target is incompatible with committed service state");
            }
            Ok::<_, anyhow::Error>(target)
        })();
        let target = match verified_target {
            Ok(target) => target,
            Err(error) => {
                let _ = remove_owned_staging(&self.paths.updates.staging, &transaction_id);
                return Err(error);
            }
        };

        let update_id = self.context.prepare_automatic_update(target.clone())?;
        let mut helper_owns_transaction = false;
        let handoff = (|| {
            self.set_phase(UpdatePhase::UpdateWaitingForIdle, Some(candidate.clone()))?;
            self.context
                .admissions()
                .wait_until_update_sealed(&self.stop)?;
            self.set_phase(UpdatePhase::UpdateSealed, Some(candidate.clone()))?;
            let fixed = FixedProductPaths::discover()?;
            let old_image = std::env::current_exe()?;
            let final_root = fixed.versions.join(&candidate.version);
            let target_image = final_root.join("bin").join(MAIN_EXE);
            let helper = fixed.updater.join(HELPER_EXE);
            verify_helper(&helper)?;
            let transaction = TransactionEnvelope::new(UpdateTransaction {
                transaction_id: transaction_id.clone(),
                update_id: update_id.clone(),
                phase: TransactionPhase::Prepared,
                created_utc: now_utc()?,
                old_bundle_identity: committed.committed.current,
                target_bundle_identity: target,
                old_image_path: path_string(&old_image)?,
                target_image_path: path_string(&target_image)?,
                old_event_message_path: path_string(&old_image)?,
                target_event_message_path: path_string(&target_image)?,
                staged_root: path_string(&staged_root)?,
                final_version_root: path_string(&final_root)?,
                helper_protocol: REQUIRED_HELPER_PROTOCOL,
                attempt_count: 1,
                last_error_category: None,
            })?;
            if self.context.admissions().snapshot().state != AdmissionState::UpdateSealed {
                bail!("admissions changed before durable helper handoff");
            }
            create_json(&self.paths.updates.current_transaction, &transaction)?;
            self.set_phase(UpdatePhase::UpdateHelperStarting, Some(candidate.clone()))?;
            start_helper()?;
            helper_owns_transaction = true;
            Ok::<_, anyhow::Error>(())
        })();
        if let Err(error) = handoff {
            if !helper_owns_transaction {
                let _ = remove_file_if_exists(&self.paths.updates.current_transaction);
                let _ = self.context.abort_automatic_update(&update_id);
                let _ = remove_owned_staging(&self.paths.updates.staging, &transaction_id);
            }
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
    }

    fn persisted_retry_delay(&self) -> Option<Duration> {
        let retry_after = self.status.lock().ok()?.retry.retry_after_utc.clone()?;
        let retry_after = time::OffsetDateTime::parse(
            &retry_after,
            &time::format_description::well_known::Rfc3339,
        )
        .ok()?;
        let seconds = (retry_after - time::OffsetDateTime::now_utc()).whole_seconds();
        Some(Duration::from_secs(seconds.clamp(60, 24 * 60 * 60) as u64))
    }

    fn failed_target_suppression(
        &self,
        candidate: &ReleaseCandidate,
    ) -> Result<Option<(Option<String>, bool)>> {
        let failed = match load_json::<FailedTargetState>(&self.paths.updates.failed_target) {
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
        Ok(())
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
            if page == 1 && status == 304 {
                return Ok(ReleasePages {
                    pages,
                    etag: etag.map(str::to_string),
                    not_modified: true,
                });
            }
            if matches!(status, 403 | 429) {
                return Err(RateLimited {
                    retry_after_utc: retry_after_utc(&response),
                }
                .into());
            }
            if status != 200 {
                return Err(HttpStatusFailure {
                    status,
                    retry_after_utc: retry_after_utc(&response),
                }
                .into());
            }
            if page == 1 {
                observed_etag = header(&response, "etag");
            }
            let body = response
                .body_mut()
                .with_config()
                .limit(MAX_RELEASE_PAGE_BYTES as u64)
                .read_to_vec()?;
            let count = serde_json::from_slice::<serde_json::Value>(&body)?
                .as_array()
                .context("GitHub releases response is not an array")?
                .len();
            pages.push(body);
            if count < 50 {
                break;
            }
            if page == 10 {
                bail!("GitHub release pagination exceeds the compiled limit");
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
        for redirect in 0..=MAX_REDIRECTS {
            validate_download_url(&url, redirect == 0)?;
            let result = self
                .agent
                .get(&url)
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
            Ok(final_path.clone())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&partial);
        }
        result
    }
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

fn verify_helper(path: &Path) -> Result<()> {
    verify_windows_file_publisher(path, &compiled_publishers())?;
    verify_helper_protocol(path)?;
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
    Ok(())
}

fn verify_helper_protocol(path: &Path) -> Result<()> {
    let mut child = Command::new(path)
        .args(["--version", "--json"])
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
    validate_helper_version_output(
        &output.stdout,
        HELPER_SERVICE_NAME,
        REQUIRED_HELPER_PROTOCOL,
    )?;
    Ok(())
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

pub fn start_recovery_helper() -> Result<()> {
    let fixed = FixedProductPaths::discover()?;
    verify_helper(&fixed.updater.join(HELPER_EXE))?;
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
    match load_json(path) {
        Ok(status) => Ok(status),
        Err(error) if is_not_found(&error) => Ok(CoordinatorStatus::default()),
        Err(error) => Err(error),
    }
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
    } else if text.contains("helper protocol") || text.contains("updater scm configuration") {
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
