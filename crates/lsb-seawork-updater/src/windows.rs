use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use lsb_seawork_update::{
    archive_file, load_json, verify_bundle_root, verify_windows_directory_protection,
    verify_windows_file_protection, verify_windows_file_publisher, verify_windows_package,
    write_json_atomic, CommittedState, CommittedStateEnvelope, FailedTargetState, PackagePolicy,
    TransactionEnvelope,
};
use lsb_service_proto::{HealthState, UpdatePhase, PIPE_NAME, SERVICE_NAME, SUPPORTED};
use windows_service::define_windows_service;
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod, ServiceSidType,
    ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_sys::Win32::Foundation::{
    CloseHandle, LocalFree, GENERIC_READ, GENERIC_WRITE, HANDLE, WAIT_ABANDONED, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
};
use windows_sys::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_DIRECTORY, SYNCHRONIZE};
use windows_sys::Win32::System::Services::{
    ChangeServiceConfigW, QueryServiceObjectSecurity, SERVICE_NO_CHANGE,
};
use windows_sys::Win32::System::Threading::{
    CreateMutexW, OpenProcess, ReleaseMutex, WaitForSingleObject, PROCESS_SYNCHRONIZE,
};

use crate::recovery::{recover_transaction, RecoveryOutcome, TransactionStore, UpdateBackend};
use crate::relative::{self, Kind};
use crate::{HELPER_PROTOCOL_MAJOR, HELPER_PROTOCOL_MINOR, UPDATER_SERVICE_NAME};

const UPDATER_EXE: &str = "localsandbox-seawork-updater.exe";
const MAIN_EXE: &str = "localsandbox-seawork-service.exe";
const UPDATE_MUTEX: &str = r"Global\LocalSandbox.SeaWork.Update.v1";
const EVENT_LOG_KEY: &str =
    r"SYSTEM\CurrentControlSet\Services\EventLog\Application\LocalSandboxSeaWork";
const EVENT_MESSAGE_VALUE: &str = "EventMessageFile";
const PIPE_SDDL: &str =
    "O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;IU)(A;;0x00000002;;;IU)S:(ML;;NW;;;ME)";
const STATE_TIMEOUT: Duration = Duration::from_secs(120);
const MAIN_STOP_TIMEOUT: Duration = Duration::from_secs(60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const UPDATER_SERVICE_SDDL: &str = "O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00000005;;;IU)";
const FAILURE_RESET: Duration = Duration::from_secs(86_400);
const FAILURE_DELAYS: [Duration; 3] = [
    Duration::from_secs(5),
    Duration::from_secs(30),
    Duration::from_secs(120),
];

define_windows_service!(ffi_service_main, service_main);

pub fn dispatch() -> Result<()> {
    service_dispatcher::start(UPDATER_SERVICE_NAME, ffi_service_main)
        .context("connect LocalSandboxSeaWorkUpdater to the SCM dispatcher")
}

pub fn verify_install() -> Result<()> {
    let paths = FixedPaths::discover()?;
    verify_fixed_directories(&paths)?;
    require_exact_current_executable(&paths.updater_executable)?;
    verify_updater_service_config(&paths.updater_executable)?;
    verify_windows_file_publisher(&paths.updater_executable, &compiled_publishers())?;
    Ok(())
}

fn service_main(_arguments: Vec<OsString>) {
    let _ = run_service();
}

fn run_service() -> Result<()> {
    let (stop_tx, stop_rx) = std::sync::mpsc::channel();
    let status_handle =
        service_control_handler::register(UPDATER_SERVICE_NAME, move |event| match event {
            ServiceControl::Stop => {
                let _ = stop_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        })?;
    status_handle.set_service_status(service_status(ServiceState::StartPending, 1, 120))?;
    status_handle.set_service_status(service_status(ServiceState::Running, 0, 0))?;
    let result = run_recovery(&stop_rx);
    let exit = if result.is_ok() { 0 } else { 1 };
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::ServiceSpecific(exit),
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: None,
    })?;
    result
}

fn run_recovery(stop_rx: &std::sync::mpsc::Receiver<()>) -> Result<()> {
    let paths = FixedPaths::discover()?;
    verify_fixed_directories(&paths)?;
    require_exact_current_executable(&paths.updater_executable)?;
    verify_updater_service_config(&paths.updater_executable)?;
    verify_windows_file_publisher(&paths.updater_executable, &compiled_publishers())?;
    let _mutex = UpdateMutex::acquire()?;
    if stop_rx.try_recv().is_ok() {
        return Ok(());
    }
    let mut backend = WindowsBackend::new(paths)?;
    let mut transaction: TransactionEnvelope =
        match protected_load_json(&backend.paths.current_transaction) {
            Ok(transaction) => transaction,
            Err(error) if is_not_found(&error) => return Ok(()),
            Err(error) => return Err(error).context("load current protected update transaction"),
        };
    transaction.validate()?;
    let mut store = DiskStore {
        current: backend.paths.current_transaction.clone(),
    };
    let outcome = match recover_transaction(&mut transaction, &mut store, &mut backend) {
        Ok(outcome) => outcome,
        Err(error) => {
            let _ = report_update_event(
                12,
                "update_recovery_quarantine",
                "UPDATE_RECOVERY_QUARANTINE",
                &transaction.transaction.target_bundle_identity.version,
                &transaction
                    .transaction
                    .target_bundle_identity
                    .archive_sha256,
            );
            return Err(error);
        }
    };
    match outcome {
        RecoveryOutcome::Committed | RecoveryOutcome::RolledBack => {
            let (event_id, phase, code) = if outcome == RecoveryOutcome::Committed {
                (11, "update_committed", "UPDATE_COMMITTED")
            } else {
                (12, "update_rollback_complete", "UPDATE_ROLLBACK_COMPLETE")
            };
            let _ = report_update_event(
                event_id,
                phase,
                code,
                &transaction.transaction.target_bundle_identity.version,
                &transaction
                    .transaction
                    .target_bundle_identity
                    .archive_sha256,
            );
            let history = backend
                .paths
                .history
                .join(format!("{}.json", transaction.transaction.transaction_id));
            archive_file(&backend.paths.current_transaction, &history)?;
        }
        RecoveryOutcome::Quarantined => {
            let _ = report_update_event(
                12,
                "update_recovery_quarantine",
                "UPDATE_RECOVERY_QUARANTINE",
                &transaction.transaction.target_bundle_identity.version,
                &transaction
                    .transaction
                    .target_bundle_identity
                    .archive_sha256,
            );
        }
    }
    Ok(())
}

fn report_update_event(
    event_id: u32,
    phase: &str,
    stable_code: &str,
    version: &str,
    digest: &str,
) -> Result<()> {
    use windows_sys::Win32::System::EventLog::{
        DeregisterEventSource, RegisterEventSourceW, ReportEventW, EVENTLOG_INFORMATION_TYPE,
        EVENTLOG_WARNING_TYPE,
    };

    let source = wide(OsStr::new(SERVICE_NAME));
    let handle = unsafe { RegisterEventSourceW(ptr::null(), source.as_ptr()) };
    if handle.is_null() {
        return Err(io::Error::last_os_error()).context("register update Event Log source");
    }
    let digest_prefix = digest.get(..32).unwrap_or("");
    let insertions =
        [version, phase, stable_code, digest_prefix].map(|value| wide(OsStr::new(value)));
    let insertion_pointers = insertions
        .iter()
        .map(|value| value.as_ptr())
        .collect::<Vec<_>>();
    let event_type = if event_id == 12 {
        EVENTLOG_WARNING_TYPE
    } else {
        EVENTLOG_INFORMATION_TYPE
    };
    let reported = unsafe {
        ReportEventW(
            handle,
            event_type,
            0,
            event_id,
            ptr::null_mut(),
            u16::try_from(insertion_pointers.len()).unwrap_or(0),
            0,
            insertion_pointers.as_ptr(),
            ptr::null(),
        )
    };
    let report_error = (reported == 0).then(io::Error::last_os_error);
    unsafe { DeregisterEventSource(handle) };
    if let Some(error) = report_error {
        return Err(error).context("write update Event Log record");
    }
    Ok(())
}

fn is_not_found(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .is_some_and(|error| error.kind() == io::ErrorKind::NotFound)
    })
}

fn protected_load_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    verify_windows_file_protection(path)?;
    load_json(path)
}

struct DiskStore {
    current: PathBuf,
}

impl TransactionStore for DiskStore {
    fn persist(&mut self, transaction: &TransactionEnvelope) -> Result<()> {
        transaction.validate()?;
        write_json_atomic(&self.current, transaction)
    }
}

struct WindowsBackend {
    paths: FixedPaths,
}

impl WindowsBackend {
    fn new(paths: FixedPaths) -> Result<Self> {
        verify_fixed_directories(&paths)?;
        Ok(Self { paths })
    }

    fn verify_package_identity(
        &self,
        root: &Path,
        identity: &lsb_service_proto::BundleIdentity,
        helper_protocol: lsb_seawork_update::HelperProtocol,
    ) -> Result<()> {
        verify_windows_directory_protection(root)?;
        let policy = PackagePolicy {
            expected_version: &identity.version,
            supported_protocol: SUPPORTED,
            ledger_writer_schema: identity.ledger.writer_schema,
            service_configuration_revision: identity.service_configuration_revision,
            service_name: SERVICE_NAME,
            service_display_name: "LocalSandbox for SeaWork",
            service_account: "LocalSystem",
            service_type: "SERVICE_WIN32_OWN_PROCESS",
            pipe_name: PIPE_NAME,
            pipe_sddl: PIPE_SDDL,
        };
        let report = verify_bundle_root(root, &policy)?;
        if report.required_helper_protocol.major != helper_protocol.major
            || report.required_helper_protocol.minor > helper_protocol.minor
        {
            bail!("verified package requires an incompatible updater helper protocol");
        }
        let observed = report.bundle_identity(&identity.archive_sha256)?;
        if observed != *identity {
            bail!("verified package identity differs from the protected transaction");
        }
        verify_windows_package(root, &report, &compiled_publishers())?;
        Ok(())
    }

    fn main_service(&self, access: ServiceAccess) -> Result<windows_service::service::Service> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        manager
            .open_service(SERVICE_NAME, access)
            .context("open existing LocalSandboxSeaWork service")
    }

    fn require_main_command(&self, executable: &str) -> Result<()> {
        let service = self.main_service(ServiceAccess::QUERY_CONFIG)?;
        let config = service.query_config()?;
        if config.service_type != ServiceType::OWN_PROCESS
            || config.executable_path.as_os_str() != OsStr::new(&service_command(executable))
            || config
                .account_name
                .as_deref()
                .and_then(OsStr::to_str)
                .is_none_or(|account| !account.eq_ignore_ascii_case("LocalSystem"))
        {
            bail!("LocalSandboxSeaWork SCM configuration is contradictory");
        }
        Ok(())
    }

    fn wait_main_state(&self, expected: ServiceState) -> Result<()> {
        let service = self.main_service(ServiceAccess::QUERY_STATUS)?;
        let deadline = Instant::now() + STATE_TIMEOUT;
        loop {
            let observed = service.query_status()?.current_state;
            if observed == expected {
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!("LocalSandboxSeaWork did not reach {expected:?}");
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    fn connect_runtime(&self) -> Result<tokio::runtime::Runtime> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("create updater maintenance runtime")
    }
}

fn verify_fixed_directories(paths: &FixedPaths) -> Result<()> {
    for path in [
        &paths.product,
        &paths.updater,
        &paths.versions,
        &paths.state_root,
        &paths.updates,
        &paths.staging,
        &paths.transactions,
        &paths.history,
    ] {
        verify_windows_directory_protection(path)?;
    }
    Ok(())
}

fn stop_service_and_confirm_process_exit(
    service: &windows_service::service::Service,
) -> Result<()> {
    let initial = service.query_status()?;
    let process = match initial.process_id {
        Some(process_id) => {
            let raw = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, process_id) };
            if raw.is_null() {
                if service.query_status()?.current_state == ServiceState::Stopped {
                    None
                } else {
                    bail!(
                        "pin main service process {process_id} failed: {}",
                        std::io::Error::last_os_error()
                    );
                }
            } else {
                Some(unsafe { OwnedHandle::from_raw_handle(raw as _) })
            }
        }
        None => None,
    };
    if initial.current_state != ServiceState::Stopped {
        service.stop()?;
    }
    let deadline = Instant::now() + MAIN_STOP_TIMEOUT;
    loop {
        if service.query_status()?.current_state == ServiceState::Stopped {
            break;
        }
        if Instant::now() >= deadline {
            bail!("LocalSandboxSeaWork did not stop within the generated preshutdown bound");
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    if let Some(process) = process {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let wait_ms = u32::try_from(remaining.as_millis()).unwrap_or(u32::MAX);
        if unsafe { WaitForSingleObject(process.as_raw_handle() as HANDLE, wait_ms) }
            != WAIT_OBJECT_0
        {
            bail!("main service process remained live after SCM reported stopped");
        }
    }
    Ok(())
}

impl UpdateBackend for WindowsBackend {
    fn verify_handoff(&mut self, transaction: &TransactionEnvelope) -> Result<()> {
        let update = &transaction.transaction;
        let old_root = bundle_root_for_image(
            &self.paths.versions,
            &update.old_image_path,
            &update.old_bundle_identity.version,
        )?;
        if update.helper_protocol.major != HELPER_PROTOCOL_MAJOR
            || update.helper_protocol.minor > HELPER_PROTOCOL_MINOR
            || Path::new(&update.target_image_path)
                != Path::new(&update.final_version_root)
                    .join("bin")
                    .join(MAIN_EXE)
            || update.target_event_message_path != update.target_image_path
            || Path::new(&update.staged_root)
                != self
                    .paths
                    .staging
                    .join(&update.transaction_id)
                    .join("LocalSandbox")
            || Path::new(&update.final_version_root)
                != self
                    .paths
                    .versions
                    .join(&update.target_bundle_identity.version)
        {
            bail!("transaction paths or helper protocol differ from compiled product policy");
        }
        let committed: CommittedStateEnvelope = protected_load_json(&self.paths.committed)?;
        committed.validate()?;
        if committed.committed.current != update.old_bundle_identity {
            bail!("transaction old identity differs from committed anti-rollback state");
        }
        self.verify_package_identity(
            &old_root,
            &update.old_bundle_identity,
            update.helper_protocol,
        )?;
        self.require_main_command(&update.old_image_path)?;
        require_event_message_path(&update.old_event_message_path)?;
        let runtime = self.connect_runtime()?;
        runtime.block_on(async {
            let client = lsb_service_client::connect(lsb_service_client::ConnectOptions {
                timeout: CONNECT_TIMEOUT,
            })
            .await?;
            let status = client.get_update_status().await?;
            if status.target.as_ref() != Some(&update.target_bundle_identity)
                || status.active_use_count != 0
                || !matches!(
                    status.phase,
                    UpdatePhase::UpdateSealed | UpdatePhase::UpdateActivationPending
                )
            {
                anyhow::bail!("old service has not sealed the exact update target");
            }
            Ok::<_, anyhow::Error>(())
        })
    }

    fn install_and_verify_target(&mut self, transaction: &TransactionEnvelope) -> Result<()> {
        let update = &transaction.transaction;
        let staged = Path::new(&update.staged_root);
        let final_root = Path::new(&update.final_version_root);
        let temporary = self
            .paths
            .versions
            .join(format!(".staging-{}", update.transaction_id));
        remove_incomplete_final_staging(&self.paths.versions, &temporary, &update.transaction_id)?;
        self.verify_package_identity(
            staged,
            &update.target_bundle_identity,
            update.helper_protocol,
        )?;
        if final_root.exists() {
            return self.verify_package_identity(
                final_root,
                &update.target_bundle_identity,
                update.helper_protocol,
            );
        }
        copy_new_tree(staged, &temporary)?;
        let result = (|| {
            self.verify_package_identity(
                &temporary,
                &update.target_bundle_identity,
                update.helper_protocol,
            )?;
            fs::rename(&temporary, final_root).context("atomically place verified version root")?;
            self.verify_package_identity(
                final_root,
                &update.target_bundle_identity,
                update.helper_protocol,
            )
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&temporary);
        }
        result
    }

    fn stop_old_service(&mut self, transaction: &TransactionEnvelope) -> Result<()> {
        self.require_main_command(&transaction.transaction.old_image_path)?;
        let service = self.main_service(ServiceAccess::QUERY_STATUS | ServiceAccess::STOP)?;
        stop_service_and_confirm_process_exit(&service)
    }

    fn change_to_target(&mut self, transaction: &TransactionEnvelope) -> Result<()> {
        let update = &transaction.transaction;
        self.verify_package_identity(
            Path::new(&update.final_version_root),
            &update.target_bundle_identity,
            update.helper_protocol,
        )?;
        change_main_configuration(
            &update.old_image_path,
            &update.target_image_path,
            &update.old_event_message_path,
            &update.target_event_message_path,
        )
    }

    fn start_target(&mut self, transaction: &TransactionEnvelope) -> Result<()> {
        let update = &transaction.transaction;
        self.verify_package_identity(
            Path::new(&update.final_version_root),
            &update.target_bundle_identity,
            update.helper_protocol,
        )?;
        self.require_main_command(&update.target_image_path)?;
        let service = self.main_service(ServiceAccess::QUERY_STATUS | ServiceAccess::START)?;
        if service.query_status()?.current_state == ServiceState::Stopped {
            service.start::<&OsStr>(&[])?;
        }
        self.wait_main_state(ServiceState::Running)
    }

    fn health_and_commit_target(&mut self, transaction: &TransactionEnvelope) -> Result<()> {
        let update = &transaction.transaction;
        self.verify_package_identity(
            Path::new(&update.final_version_root),
            &update.target_bundle_identity,
            update.helper_protocol,
        )?;
        self.require_main_command(&update.target_image_path)?;
        let runtime = self.connect_runtime()?;
        let result = runtime.block_on(async {
            let client = lsb_service_client::connect(lsb_service_client::ConnectOptions {
                timeout: CONNECT_TIMEOUT,
            })
            .await?;
            let mut committed_recovery = false;
            for observation in 0..2 {
                let info = client.get_service_info().await?;
                let health = client.health_check().await?;
                let status = client.get_update_status().await?;
                if info.service_version == update.target_bundle_identity.version
                    && info.bundle_version == update.target_bundle_identity.version
                    && health.ready
                    && health.admissions_open
                    && health.stable_code == "READY"
                    && status.phase == UpdatePhase::UpdateIdle
                    && status.target.is_none()
                {
                    let committed: CommittedStateEnvelope =
                        protected_load_json(&self.paths.committed)?;
                    committed.validate()?;
                    if committed.committed.current != update.target_bundle_identity
                        && committed.committed.current != update.old_bundle_identity
                    {
                        anyhow::bail!(
                            "READY target contradicts protected committed update identities"
                        );
                    }
                    committed_recovery = true;
                } else if committed_recovery {
                    anyhow::bail!("target committed recovery observations are inconsistent");
                } else if info.service_version != update.target_bundle_identity.version
                    || info.bundle_version != update.target_bundle_identity.version
                    || health.admissions_open
                    || health.bundle != HealthState::Ready
                    || health.whpx != HealthState::Ready
                    || health.smb != HealthState::Ready
                    || status.target.as_ref() != Some(&update.target_bundle_identity)
                    || status.active_use_count != 0
                {
                    anyhow::bail!("target failed restricted pre-commit health");
                }
                if observation == 0 {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
            if committed_recovery {
                return Ok::<_, anyhow::Error>(());
            }
            client.commit_update(update.update_id.clone()).await?;
            let info = client.get_service_info().await?;
            let health = client.health_check().await?;
            let status = client.get_update_status().await?;
            if info.service_version != update.target_bundle_identity.version
                || info.bundle_version != update.target_bundle_identity.version
                || !health.ready
                || !health.admissions_open
                || health.stable_code != "READY"
                || status.phase != UpdatePhase::UpdateIdle
                || status.target.is_some()
            {
                anyhow::bail!("target failed post-commit READY health");
            }
            Ok::<_, anyhow::Error>(())
        });
        let result = result.and_then(|()| self.finalize_commit(transaction));
        if let Err(error) = result {
            self.record_failed_target(update).with_context(|| {
                format!("record failed target after activation health failure: {error:#}")
            })?;
            return Err(error);
        }
        Ok(())
    }

    fn finalize_commit(&mut self, transaction: &TransactionEnvelope) -> Result<()> {
        let update = &transaction.transaction;
        let mut committed: CommittedStateEnvelope = protected_load_json(&self.paths.committed)?;
        committed.validate()?;
        if committed.committed.current == update.target_bundle_identity {
            return Ok(());
        }
        if committed.committed.current != update.old_bundle_identity {
            bail!("committed state changed to an unrelated identity during activation");
        }
        let target_version = semver::Version::parse(&update.target_bundle_identity.version)?;
        let highest = semver::Version::parse(&committed.committed.highest_committed_version)?;
        committed = CommittedStateEnvelope::new(CommittedState {
            current: update.target_bundle_identity.clone(),
            highest_committed_version: target_version.max(highest).to_string(),
            previous_last_known_good: Some(update.old_bundle_identity.clone()),
            helper_protocol: update.helper_protocol,
            last_completed_transaction_id: update.transaction_id.clone(),
        })?;
        write_json_atomic(&self.paths.committed, &committed)
    }

    fn stop_target(&mut self, transaction: &TransactionEnvelope) -> Result<()> {
        let update = &transaction.transaction;
        let command = current_main_command()?;
        let event = query_event_message_path()?;
        let old_command = service_command(&update.old_image_path);
        let target_command = service_command(&update.target_image_path);
        if !matches_transaction_value(&command, &old_command, &target_command)
            || !matches_transaction_value(
                &event,
                &update.old_event_message_path,
                &update.target_event_message_path,
            )
        {
            bail!("refusing to stop a main service with unrelated ImagePath");
        }
        if command == old_command {
            return Ok(());
        }
        let service = self.main_service(ServiceAccess::QUERY_STATUS | ServiceAccess::STOP)?;
        stop_service_and_confirm_process_exit(&service)
    }

    fn restore_old_configuration(&mut self, transaction: &TransactionEnvelope) -> Result<()> {
        let update = &transaction.transaction;
        change_main_configuration(
            &update.target_image_path,
            &update.old_image_path,
            &update.target_event_message_path,
            &update.old_event_message_path,
        )
    }

    fn start_and_abort_old(&mut self, transaction: &TransactionEnvelope) -> Result<()> {
        let update = &transaction.transaction;
        let old_root = bundle_root_for_image(
            &self.paths.versions,
            &update.old_image_path,
            &update.old_bundle_identity.version,
        )?;
        self.verify_package_identity(
            &old_root,
            &update.old_bundle_identity,
            update.helper_protocol,
        )?;
        self.require_main_command(&update.old_image_path)?;
        let service = self.main_service(ServiceAccess::QUERY_STATUS | ServiceAccess::START)?;
        if service.query_status()?.current_state == ServiceState::Stopped {
            service.start::<&OsStr>(&[])?;
        }
        self.wait_main_state(ServiceState::Running)?;
        let runtime = self.connect_runtime()?;
        runtime.block_on(async {
            let client = lsb_service_client::connect(lsb_service_client::ConnectOptions {
                timeout: CONNECT_TIMEOUT,
            })
            .await?;
            let info = client.get_service_info().await?;
            if info.service_version != update.old_bundle_identity.version
                || info.bundle_version != update.old_bundle_identity.version
            {
                anyhow::bail!("rollback service identity is not the recorded old version");
            }
            let status = client.get_update_status().await?;
            if status.target.as_ref() == Some(&update.target_bundle_identity) {
                client.abort_update(update.update_id.clone()).await?;
            }
            let health = client.health_check().await?;
            if !health.ready || !health.admissions_open || health.stable_code != "READY" {
                anyhow::bail!("old service did not return to READY after rollback");
            }
            Ok::<_, anyhow::Error>(())
        })
    }
}

impl WindowsBackend {
    fn record_failed_target(&self, update: &lsb_seawork_update::UpdateTransaction) -> Result<()> {
        let now = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)?;
        let failed = match protected_load_json::<FailedTargetState>(&self.paths.failed_target) {
            Ok(mut failed)
                if failed.validate().is_ok()
                    && failed.archive_sha256 == update.target_bundle_identity.archive_sha256 =>
            {
                failed.record_rollback(now)?;
                failed
            }
            _ => FailedTargetState {
                target_version: update.target_bundle_identity.version.clone(),
                archive_sha256: update.target_bundle_identity.archive_sha256.clone(),
                rollback_count: 1,
                last_rollback_utc: now,
                suppressed: false,
            },
        };
        failed.validate()?;
        write_json_atomic(&self.paths.failed_target, &failed)
    }
}

fn change_main_configuration(
    expected_image: &str,
    replacement_image: &str,
    expected_event: &str,
    replacement_event: &str,
) -> Result<()> {
    let current_command = current_main_command()?;
    let current_event = query_event_message_path()?;
    let expected_command = service_command(expected_image);
    let replacement_command = service_command(replacement_image);
    if !matches_transaction_value(&current_command, &expected_command, &replacement_command)
        || !matches_transaction_value(&current_event, expected_event, replacement_event)
    {
        bail!("SCM or Event Log path is outside the protected transaction identities");
    }
    if current_command != replacement_command {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let service = manager.open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_CONFIG | ServiceAccess::CHANGE_CONFIG,
        )?;
        let wide_command = wide(OsStr::new(&replacement_command));
        let ok = unsafe {
            ChangeServiceConfigW(
                service.raw_handle(),
                SERVICE_NO_CHANGE,
                SERVICE_NO_CHANGE,
                SERVICE_NO_CHANGE,
                wide_command.as_ptr(),
                ptr::null(),
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error()).context("change exact main-service ImagePath");
        }
    }
    if current_event != replacement_event {
        set_event_message_path(replacement_event)?;
    }
    if current_main_command()? != replacement_command
        || query_event_message_path()? != replacement_event
    {
        bail!("SCM or Event Log path did not persist the exact replacement");
    }
    Ok(())
}

fn matches_transaction_value(observed: &str, old: &str, target: &str) -> bool {
    observed == old || observed == target
}

fn bundle_root_for_image(versions: &Path, image: &str, version: &str) -> Result<PathBuf> {
    let expected = versions.join(version);
    if Path::new(image) != expected.join("bin").join(MAIN_EXE) {
        bail!("main-service image path is outside the fixed version root");
    }
    Ok(expected)
}

fn current_main_command() -> Result<String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_CONFIG)?;
    service
        .query_config()?
        .executable_path
        .into_os_string()
        .into_string()
        .map_err(|_| anyhow::anyhow!("main-service ImagePath is not Unicode"))
}

fn service_command(executable: &str) -> String {
    format!("\"{executable}\" --service")
}

fn verify_updater_service_config(expected_executable: &Path) -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(
        UPDATER_SERVICE_NAME,
        ServiceAccess::QUERY_CONFIG | ServiceAccess::READ_CONTROL,
    )?;
    let config = service.query_config()?;
    let expected = service_command(
        expected_executable
            .to_str()
            .context("compiled updater path is not Unicode")?,
    );
    if config.service_type != ServiceType::OWN_PROCESS
        || config.start_type != ServiceStartType::AutoStart
        || config.executable_path.as_os_str() != OsStr::new(&expected)
        || config.display_name.as_os_str() != OsStr::new("LocalSandbox for SeaWork Updater")
        || !config.dependencies.is_empty()
        || config
            .account_name
            .as_deref()
            .and_then(OsStr::to_str)
            .is_none_or(|account| !account.eq_ignore_ascii_case("LocalSystem"))
    {
        bail!("LocalSandboxSeaWorkUpdater SCM identity is incompatible");
    }
    if service.get_config_service_sid_info()? != ServiceSidType::Unrestricted
        || !service.get_failure_actions_on_non_crash_failures()?
        || service.get_failure_actions()? != expected_failure_actions()
    {
        bail!("LocalSandboxSeaWorkUpdater SCM recovery policy is incompatible");
    }
    verify_updater_service_security(&service)?;
    Ok(())
}

fn expected_failure_actions() -> ServiceFailureActions {
    ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(FAILURE_RESET),
        reboot_msg: None,
        command: None,
        actions: Some(
            FAILURE_DELAYS
                .into_iter()
                .map(|delay| ServiceAction {
                    action_type: ServiceActionType::Restart,
                    delay,
                })
                .collect(),
        ),
    }
}

fn verify_updater_service_security(service: &windows_service::service::Service) -> Result<()> {
    let information =
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let mut required = 0u32;
    unsafe {
        QueryServiceObjectSecurity(
            service.raw_handle(),
            information,
            std::ptr::null_mut(),
            0,
            &mut required,
        )
    };
    if required == 0 || required > 64 * 1024 {
        bail!("LocalSandboxSeaWorkUpdater SCM security descriptor size is invalid");
    }
    let mut actual = vec![0u8; required as usize];
    if unsafe {
        QueryServiceObjectSecurity(
            service.raw_handle(),
            information,
            actual.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        bail!(
            "query LocalSandboxSeaWorkUpdater SCM security failed: {}",
            std::io::Error::last_os_error()
        );
    }
    let expected_wide = OsStr::new(UPDATER_SERVICE_SDDL)
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut expected: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            expected_wide.as_ptr(),
            SDDL_REVISION_1,
            &mut expected,
            std::ptr::null_mut(),
        )
    } == 0
        || expected.is_null()
    {
        bail!("compile generated updater SCM security policy failed");
    }
    let _expected = LocalAllocation(expected.cast());
    let actual_sddl = normalized_sddl(actual.as_mut_ptr().cast(), information)?;
    let expected_sddl = normalized_sddl(expected, information)?;
    if actual_sddl != expected_sddl {
        bail!("LocalSandboxSeaWorkUpdater SCM DACL differs from generated policy");
    }
    Ok(())
}

fn normalized_sddl(descriptor: PSECURITY_DESCRIPTOR, information: u32) -> Result<String> {
    let mut raw = std::ptr::null_mut();
    let mut length = 0u32;
    if unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            information,
            &mut raw,
            &mut length,
        )
    } == 0
        || raw.is_null()
        || length == 0
        || length > 4096
    {
        bail!("normalize updater SCM security descriptor failed");
    }
    let _raw = LocalAllocation(raw.cast());
    let units = unsafe { std::slice::from_raw_parts(raw, length as usize) };
    let end = units
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(units.len());
    String::from_utf16(&units[..end]).context("updater SCM security descriptor is not Unicode")
}

struct LocalAllocation(*mut std::ffi::c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0) };
        }
    }
}

fn require_exact_current_executable(expected: &Path) -> Result<()> {
    let current = std::env::current_exe()?;
    if current != expected {
        bail!("updater is not running from its fixed protected product path");
    }
    require_regular_file(expected)
}

fn remove_incomplete_final_staging(
    versions: &Path,
    temporary: &Path,
    transaction_id: &str,
) -> Result<()> {
    let expected_name = format!(".staging-{transaction_id}");
    if temporary.parent() != Some(versions)
        || temporary.file_name() != Some(OsStr::new(&expected_name))
        || transaction_id.len() != 32
        || !transaction_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("transaction-owned final staging path is not exact");
    }
    match fs::symlink_metadata(temporary) {
        Ok(metadata) => {
            reject_reparse(&metadata)?;
            if !metadata.is_dir() {
                bail!("transaction-owned final staging path is not a directory");
            }
            fs::remove_dir_all(temporary)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn copy_new_tree(source: &Path, destination: &Path) -> Result<()> {
    require_regular_directory(source)?;
    let source_handle = relative::open_directory(source, GENERIC_READ | SYNCHRONIZE)?;
    let destination_parent = destination
        .parent()
        .context("transaction-owned final staging has no parent")?;
    let destination_name = destination
        .file_name()
        .context("transaction-owned final staging has no name")?;
    let destination_parent_handle = relative::open_directory(
        destination_parent,
        GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
    )?;
    let Some((destination_handle, _)) = relative::create_relative(
        &destination_parent_handle,
        destination_name,
        GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
        Kind::Directory,
    )?
    else {
        bail!("transaction-owned final staging directory already exists");
    };
    let result =
        copy_directory_contents(source, &source_handle, destination, &destination_handle, 0);
    if result.is_err() {
        let _ = fs::remove_dir_all(destination);
    }
    result
}

fn copy_directory_contents(
    source: &Path,
    source_handle: &OwnedHandle,
    destination: &Path,
    destination_handle: &OwnedHandle,
    depth: usize,
) -> Result<()> {
    if depth > 32 {
        bail!("candidate directory depth exceeds the compiled limit");
    }
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let name = entry.file_name();
        let (source_child, info) =
            relative::open_relative(source_handle, &name, GENERIC_READ | SYNCHRONIZE)?;
        let is_directory = info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        let destination_path = destination.join(&name);
        if is_directory {
            let Some((destination_child, _)) = relative::create_relative(
                destination_handle,
                &name,
                GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
                Kind::Directory,
            )?
            else {
                bail!("handle-relative update destination entry already exists");
            };
            copy_directory_contents(
                &entry.path(),
                &source_child,
                &destination_path,
                &destination_child,
                depth + 1,
            )?;
        } else {
            let Some((destination_child, _)) = relative::create_relative(
                destination_handle,
                &name,
                GENERIC_WRITE | SYNCHRONIZE,
                Kind::File,
            )?
            else {
                bail!("handle-relative update destination entry already exists");
            };
            let mut reader = File::from(source_child);
            let file = File::from(destination_child);
            let mut writer = BufWriter::new(file);
            let copied = io::copy(&mut reader, &mut writer)?;
            let expected = u64::from(info.nFileSizeHigh) << 32 | u64::from(info.nFileSizeLow);
            if copied != expected {
                bail!("candidate file changed while copied");
            }
            writer.flush()?;
            writer.get_ref().sync_all()?;
        }
    }
    Ok(())
}

fn require_regular_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    reject_reparse(&metadata)?;
    if !metadata.is_file() {
        bail!("protected product path is not a regular file");
    }
    Ok(())
}

fn require_regular_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    reject_reparse(&metadata)?;
    if !metadata.is_dir() {
        bail!("protected product path is not a regular directory");
    }
    Ok(())
}

fn reject_reparse(metadata: &fs::Metadata) -> Result<()> {
    use std::os::windows::fs::MetadataExt;
    if metadata.file_type().is_symlink() || metadata.file_attributes() & 0x400 != 0 {
        bail!("protected product path crosses a reparse point");
    }
    Ok(())
}

fn require_event_message_path(expected: &str) -> Result<()> {
    if query_event_message_path()? != expected {
        bail!("Event Log message path differs from the protected transaction");
    }
    Ok(())
}

fn query_event_message_path() -> Result<String> {
    use windows_sys::Win32::System::Registry::{
        RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ,
    };
    let key = wide(OsStr::new(EVENT_LOG_KEY));
    let value = wide(OsStr::new(EVENT_MESSAGE_VALUE));
    let mut bytes = 0u32;
    let first = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_EXPAND_SZ | RRF_RT_REG_SZ,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut bytes,
        )
    };
    if first != 0 || bytes == 0 || bytes > 4096 {
        bail!("query EventMessageFile size failed with {first}");
    }
    let mut buffer = vec![0u16; (bytes as usize).div_ceil(2)];
    let result = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_EXPAND_SZ | RRF_RT_REG_SZ,
            ptr::null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    if result != 0 {
        bail!("query EventMessageFile failed with {result}");
    }
    let length = buffer
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(buffer.len());
    OsString::from_wide(&buffer[..length])
        .into_string()
        .map_err(|_| anyhow::anyhow!("EventMessageFile is not Unicode"))
}

fn set_event_message_path(path: &str) -> Result<()> {
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegSetValueExW, HKEY_LOCAL_MACHINE, KEY_SET_VALUE,
        REG_EXPAND_SZ,
    };
    let key_name = wide(OsStr::new(EVENT_LOG_KEY));
    let value_name = wide(OsStr::new(EVENT_MESSAGE_VALUE));
    let value = wide(OsStr::new(path));
    let mut key = ptr::null_mut();
    let opened = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            key_name.as_ptr(),
            0,
            KEY_SET_VALUE,
            &mut key,
        )
    };
    if opened != 0 {
        bail!("open Event Log registry key failed with {opened}");
    }
    let result = unsafe {
        RegSetValueExW(
            key,
            value_name.as_ptr(),
            0,
            REG_EXPAND_SZ,
            value.as_ptr().cast(),
            (value.len() * 2) as u32,
        )
    };
    unsafe { RegCloseKey(key) };
    if result != 0 {
        bail!("set EventMessageFile failed with {result}");
    }
    Ok(())
}

struct FixedPaths {
    product: PathBuf,
    updater: PathBuf,
    updater_executable: PathBuf,
    state_root: PathBuf,
    updates: PathBuf,
    committed: PathBuf,
    failed_target: PathBuf,
    staging: PathBuf,
    transactions: PathBuf,
    current_transaction: PathBuf,
    history: PathBuf,
    versions: PathBuf,
}

impl FixedPaths {
    fn discover() -> Result<Self> {
        let program_data = known_folder(&windows_sys::Win32::UI::Shell::FOLDERID_ProgramData)?;
        let program_files = known_folder(&windows_sys::Win32::UI::Shell::FOLDERID_ProgramFiles)?;
        let state_root = program_data.join("LocalSandbox").join("SeaWork");
        let updates = state_root.join("updates");
        let transactions = updates.join("transactions");
        let product = program_files.join("SeaWork").join("LocalSandbox");
        let updater = product.join("updater");
        Ok(Self {
            updater_executable: updater.join(UPDATER_EXE),
            committed: updates.join("committed.json"),
            failed_target: updates.join("failed-target.json"),
            staging: updates.join("staging"),
            current_transaction: transactions.join("current.json"),
            history: updates.join("history"),
            versions: product.join("versions"),
            product,
            updater,
            state_root,
            updates,
            transactions,
        })
    }
}

fn known_folder(id: *const windows_sys::core::GUID) -> Result<PathBuf> {
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::SHGetKnownFolderPath;
    let mut raw = ptr::null_mut();
    let result = unsafe { SHGetKnownFolderPath(id, 0, ptr::null_mut(), &mut raw) };
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
    if !path.is_absolute() {
        bail!("known-folder result is not absolute");
    }
    Ok(path)
}

struct UpdateMutex(HANDLE);

impl UpdateMutex {
    fn acquire() -> Result<Self> {
        let name = wide(OsStr::new(UPDATE_MUTEX));
        let handle = unsafe { CreateMutexW(ptr::null(), 0, name.as_ptr()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error()).context("create global update mutex");
        }
        let wait = unsafe { WaitForSingleObject(handle, 30_000) };
        if wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED {
            unsafe { CloseHandle(handle) };
            bail!("global update mutex could not be acquired");
        }
        Ok(Self(handle))
    }
}

impl Drop for UpdateMutex {
    fn drop(&mut self) {
        unsafe {
            ReleaseMutex(self.0);
            CloseHandle(self.0);
        }
    }
}

fn service_status(state: ServiceState, checkpoint: u32, wait_seconds: u64) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: ServiceExitCode::NO_ERROR,
        checkpoint,
        wait_hint: Duration::from_secs(wait_seconds),
        process_id: None,
    }
}

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

fn compiled_publishers() -> Vec<String> {
    env!("LSB_COMPILED_SEAWORK_PUBLISHERS_SHA256")
        .split(',')
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}
