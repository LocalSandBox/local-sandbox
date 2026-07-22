use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::ptr;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use lsb_seawork_update::{
    archive_file, load_json, verify_bundle_root, verify_windows_file_publisher,
    verify_windows_package, write_json_atomic, CommittedState, CommittedStateEnvelope,
    FailedTargetState, PackagePolicy, TransactionEnvelope,
};
use lsb_service_proto::{HealthState, UpdatePhase, PIPE_NAME, SERVICE_NAME, SUPPORTED};
use windows_service::define_windows_service;
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState,
    ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_ABANDONED, WAIT_OBJECT_0};
use windows_sys::Win32::System::Services::{ChangeServiceConfigW, SERVICE_NO_CHANGE};
use windows_sys::Win32::System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject};

use crate::recovery::{recover_transaction, RecoveryOutcome, TransactionStore, UpdateBackend};
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
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

define_windows_service!(ffi_service_main, service_main);

pub fn dispatch() -> Result<()> {
    service_dispatcher::start(UPDATER_SERVICE_NAME, ffi_service_main)
        .context("connect LocalSandboxSeaWorkUpdater to the SCM dispatcher")
}

pub fn verify_install() -> Result<()> {
    let paths = FixedPaths::discover()?;
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
    require_exact_current_executable(&paths.updater_executable)?;
    verify_updater_service_config(&paths.updater_executable)?;
    verify_windows_file_publisher(&paths.updater_executable, &compiled_publishers())?;
    let _mutex = UpdateMutex::acquire()?;
    if stop_rx.try_recv().is_ok() {
        return Ok(());
    }
    let mut transaction: TransactionEnvelope = match load_json(&paths.current_transaction) {
        Ok(transaction) => transaction,
        Err(error) if is_not_found(&error) => return Ok(()),
        Err(error) => return Err(error).context("load current protected update transaction"),
    };
    transaction.validate()?;
    let mut store = DiskStore {
        current: paths.current_transaction.clone(),
    };
    let mut backend = WindowsBackend::new(paths)?;
    let outcome = recover_transaction(&mut transaction, &mut store, &mut backend)?;
    match outcome {
        RecoveryOutcome::Committed | RecoveryOutcome::RolledBack => {
            let history = backend
                .paths
                .history
                .join(format!("{}.json", transaction.transaction.transaction_id));
            archive_file(&backend.paths.current_transaction, &history)?;
        }
        RecoveryOutcome::Quarantined => {}
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
        require_regular_directory(&paths.transactions)?;
        require_regular_directory(&paths.history)?;
        require_regular_directory(&paths.versions)?;
        Ok(Self { paths })
    }

    fn verify_package(&self, root: &Path, transaction: &TransactionEnvelope) -> Result<()> {
        require_regular_directory(root)?;
        let update = &transaction.transaction;
        let policy = PackagePolicy {
            expected_version: &update.target_bundle_identity.version,
            supported_protocol: SUPPORTED,
            ledger_writer_schema: update.old_bundle_identity.ledger.writer_schema,
            service_configuration_revision: update
                .target_bundle_identity
                .service_configuration_revision,
            service_name: SERVICE_NAME,
            service_display_name: "LocalSandbox for SeaWork",
            service_account: "LocalSystem",
            service_type: "SERVICE_WIN32_OWN_PROCESS",
            pipe_name: PIPE_NAME,
            pipe_sddl: PIPE_SDDL,
        };
        let report = verify_bundle_root(root, &policy)?;
        let identity = report.bundle_identity(&update.target_bundle_identity.archive_sha256)?;
        if identity != update.target_bundle_identity {
            bail!("verified package identity differs from the protected transaction target");
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

impl UpdateBackend for WindowsBackend {
    fn verify_handoff(&mut self, transaction: &TransactionEnvelope) -> Result<()> {
        let update = &transaction.transaction;
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
        let committed: CommittedStateEnvelope = load_json(&self.paths.committed)?;
        committed.validate()?;
        if committed.committed.current != update.old_bundle_identity {
            bail!("transaction old identity differs from committed anti-rollback state");
        }
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
        self.verify_package(staged, transaction)?;
        if final_root.exists() {
            return self.verify_package(final_root, transaction);
        }
        let temporary = self
            .paths
            .versions
            .join(format!(".staging-{}", update.transaction_id));
        copy_new_tree(staged, &temporary)?;
        let result = (|| {
            self.verify_package(&temporary, transaction)?;
            fs::rename(&temporary, final_root).context("atomically place verified version root")?;
            self.verify_package(final_root, transaction)
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&temporary);
        }
        result
    }

    fn stop_old_service(&mut self, transaction: &TransactionEnvelope) -> Result<()> {
        self.require_main_command(&transaction.transaction.old_image_path)?;
        let service = self.main_service(ServiceAccess::QUERY_STATUS | ServiceAccess::STOP)?;
        if service.query_status()?.current_state != ServiceState::Stopped {
            service.stop()?;
        }
        self.wait_main_state(ServiceState::Stopped)
    }

    fn change_to_target(&mut self, transaction: &TransactionEnvelope) -> Result<()> {
        let update = &transaction.transaction;
        change_main_configuration(
            &update.old_image_path,
            &update.target_image_path,
            &update.old_event_message_path,
            &update.target_event_message_path,
        )
    }

    fn start_target(&mut self, transaction: &TransactionEnvelope) -> Result<()> {
        self.require_main_command(&transaction.transaction.target_image_path)?;
        let service = self.main_service(ServiceAccess::QUERY_STATUS | ServiceAccess::START)?;
        if service.query_status()?.current_state == ServiceState::Stopped {
            service.start::<&OsStr>(&[])?;
        }
        self.wait_main_state(ServiceState::Running)
    }

    fn health_and_commit_target(&mut self, transaction: &TransactionEnvelope) -> Result<()> {
        let update = &transaction.transaction;
        let runtime = self.connect_runtime()?;
        let result = runtime.block_on(async {
            let client = lsb_service_client::connect(lsb_service_client::ConnectOptions {
                timeout: CONNECT_TIMEOUT,
            })
            .await?;
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
                    return Ok::<_, anyhow::Error>(());
                }
                if info.service_version != update.target_bundle_identity.version
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
            client.commit_update(update.update_id.clone()).await?;
            let health = client.health_check().await?;
            if !health.ready || !health.admissions_open || health.stable_code != "READY" {
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
        let mut committed: CommittedStateEnvelope = load_json(&self.paths.committed)?;
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
        if command != service_command(&update.target_image_path)
            && command != service_command(&update.old_image_path)
        {
            bail!("refusing to stop a main service with unrelated ImagePath");
        }
        let service = self.main_service(ServiceAccess::QUERY_STATUS | ServiceAccess::STOP)?;
        if service.query_status()?.current_state != ServiceState::Stopped {
            service.stop()?;
        }
        self.wait_main_state(ServiceState::Stopped)
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
        let failed = match load_json::<FailedTargetState>(&self.paths.failed_target) {
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
    if current_command == replacement_command && current_event == replacement_event {
        return Ok(());
    }
    if current_command != expected_command || current_event != expected_event {
        bail!("SCM and Event Log paths do not match one coherent transaction identity");
    }
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
    set_event_message_path(replacement_event)?;
    if current_main_command()? != replacement_command
        || query_event_message_path()? != replacement_event
    {
        bail!("SCM or Event Log path did not persist the exact replacement");
    }
    Ok(())
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
    let service = manager.open_service(UPDATER_SERVICE_NAME, ServiceAccess::QUERY_CONFIG)?;
    let config = service.query_config()?;
    let expected = service_command(
        expected_executable
            .to_str()
            .context("compiled updater path is not Unicode")?,
    );
    if config.service_type != ServiceType::OWN_PROCESS
        || config.executable_path.as_os_str() != OsStr::new(&expected)
        || config
            .account_name
            .as_deref()
            .and_then(OsStr::to_str)
            .is_none_or(|account| !account.eq_ignore_ascii_case("LocalSystem"))
    {
        bail!("LocalSandboxSeaWorkUpdater SCM identity is incompatible");
    }
    Ok(())
}

fn require_exact_current_executable(expected: &Path) -> Result<()> {
    let current = std::env::current_exe()?;
    if current != expected {
        bail!("updater is not running from its fixed protected product path");
    }
    require_regular_file(expected)
}

fn copy_new_tree(source: &Path, destination: &Path) -> Result<()> {
    require_regular_directory(source)?;
    if fs::symlink_metadata(destination).is_ok() {
        bail!("transaction-owned final staging directory already exists");
    }
    fs::create_dir(destination)?;
    let result = copy_directory_contents(source, destination, 0);
    if result.is_err() {
        let _ = fs::remove_dir_all(destination);
    }
    result
}

fn copy_directory_contents(source: &Path, destination: &Path, depth: usize) -> Result<()> {
    if depth > 32 {
        bail!("candidate directory depth exceeds the compiled limit");
    }
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path)?;
        reject_reparse(&metadata)?;
        if metadata.is_dir() {
            fs::create_dir(&destination_path)?;
            copy_directory_contents(&source_path, &destination_path, depth + 1)?;
        } else if metadata.is_file() {
            let mut reader = File::open(&source_path)?;
            let file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&destination_path)?;
            let mut writer = BufWriter::new(file);
            let copied = io::copy(&mut reader, &mut writer)?;
            if copied != metadata.len() {
                bail!("candidate file changed while copied");
            }
            writer.flush()?;
            writer.get_ref().sync_all()?;
        } else {
            bail!("candidate contains a nonregular entry");
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
    let mut buffer = vec![0u16; (bytes as usize + 1) / 2];
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
    updater_executable: PathBuf,
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
        let updates = program_data
            .join("LocalSandbox")
            .join("SeaWork")
            .join("updates");
        let transactions = updates.join("transactions");
        let product = program_files.join("SeaWork").join("LocalSandbox");
        Ok(Self {
            updater_executable: product.join("updater").join(UPDATER_EXE),
            committed: updates.join("committed.json"),
            failed_target: updates.join("failed-target.json"),
            staging: updates.join("staging"),
            current_transaction: transactions.join("current.json"),
            history: updates.join("history"),
            versions: product.join("versions"),
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
