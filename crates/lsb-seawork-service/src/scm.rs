use std::ffi::OsString;
use std::sync::mpsc;
use std::time::Duration;

use anyhow::{Context, Result};
use windows_service::define_windows_service;
use windows_service::service::{ServiceControl, ServiceState};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;
use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

use crate::config::ServiceConfig;
use crate::engine::ServiceEngineConfig;
use crate::ledger;
use crate::logging::JsonLogger;
use crate::maintenance::MaintenanceManager;
use crate::paths::ServicePaths;
use crate::pipe::{HealthContext, HealthPipe};
use crate::session::QuotaLimits;
use crate::status;
use crate::SERVICE_NAME;

define_windows_service!(ffi_service_main, service_main);

const STARTUP_WAIT_HINT: Duration = Duration::from_secs(120);

pub fn dispatch() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("connect LocalSandboxSeaWork to the SCM dispatcher")
}

fn service_main(_arguments: Vec<OsString>) {
    let _ = run();
}

fn run() -> Result<()> {
    let (control_tx, control_rx) = mpsc::channel();
    let status_handle =
        service_control_handler::register(SERVICE_NAME, move |event| match event {
            ServiceControl::Stop | ServiceControl::Preshutdown => {
                let _ = control_tx.send(event);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        })?;
    let result = run_registered(&status_handle, control_rx);
    if result.is_err() {
        let _ = status_handle.set_service_status(status::stopped_with_error(1));
    }
    result
}

fn run_registered(
    status_handle: &service_control_handler::ServiceStatusHandle,
    control_rx: mpsc::Receiver<ServiceControl>,
) -> Result<()> {
    status_handle.set_service_status(status::pending(
        ServiceState::StartPending,
        1,
        STARTUP_WAIT_HINT,
    ))?;

    let paths = ServicePaths::discover()?;
    paths.prepare()?;
    let logger = JsonLogger::new(&paths.logs)?;
    logger.write(1, "startup", "START_PENDING")?;
    status_handle.set_service_status(status::pending(
        ServiceState::StartPending,
        2,
        STARTUP_WAIT_HINT,
    ))?;
    let config = ServiceConfig::load_or_default(&paths.config)?;
    let reconciliation = ledger::reconcile(&paths.ledger, &paths.quarantine)?;
    if !reconciliation.admissions_open {
        logger.write(3, "reconcile", "HEALTH_ONLY_QUARANTINE")?;
    }
    status_handle.set_service_status(status::pending(
        ServiceState::StartPending,
        3,
        STARTUP_WAIT_HINT,
    ))?;
    let engine = match ServiceEngineConfig::discover(&paths) {
        Ok(engine) => Some(engine),
        Err(_) => {
            logger.write(3, "bundle", "BUNDLE_INVALID")?;
            None
        }
    };
    status_handle.set_service_status(status::pending(
        ServiceState::StartPending,
        4,
        STARTUP_WAIT_HINT,
    ))?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("create service async runtime")?;
    let maintenance = MaintenanceManager::load(
        paths.pending_update.clone(),
        reconciliation.admissions_open && engine.is_some(),
    );
    let effective_memory_mib = effective_memory_limit(config.quotas.memory_mib_global)?;
    let context = HealthContext::new(
        reconciliation.admissions_open,
        QuotaLimits {
            connections_global: config.quotas.connections_global as usize,
            connections_per_user: config.quotas.connections_per_user as usize,
            sandboxes_global: config.quotas.sandboxes_global as usize,
            sandboxes_per_user: config.quotas.sandboxes_per_user as usize,
            sandboxes_per_connection: config.quotas.sandboxes_per_connection as usize,
            memory_mib_global: effective_memory_mib,
            ..QuotaLimits::default()
        },
    )
    .with_engine(engine)
    .with_client_policy(
        maintenance,
        config.client_roots.clone(),
        config.maintenance_roots.clone(),
        config.publisher_thumbprints.clone(),
    );
    status_handle.set_service_status(status::pending(
        ServiceState::StartPending,
        5,
        Duration::from_secs(30),
    ))?;
    let pipe = runtime.block_on(async { HealthPipe::bind(context.clone()) })?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let pipe_task = runtime.spawn(pipe.run(shutdown_rx));

    status_handle.set_service_status(status::pending(
        ServiceState::StartPending,
        6,
        Duration::from_secs(30),
    ))?;

    status_handle.set_service_status(status::running())?;
    logger.write(1, "runtime", "RUNNING")?;
    let control = control_rx
        .recv()
        .context("SCM control channel disconnected")?;
    let wait_hint = if control == ServiceControl::Preshutdown {
        Duration::from_secs(60)
    } else {
        Duration::from_secs(30)
    };
    status_handle.set_service_status(status::pending(ServiceState::StopPending, 1, wait_hint))?;
    logger.write(2, "shutdown", "STOP_PENDING")?;
    match context.begin_shutdown() {
        Ok(drained) => {
            let _ = logger.write(2, "shutdown", &format!("DRAINED_SESSIONS={drained}"));
        }
        Err(_) => {
            let _ = logger.write(4, "shutdown", "SESSION_DRAIN_FAILED");
        }
    }
    let _ = shutdown_tx.send(());
    match runtime.block_on(pipe_task) {
        Ok(Ok(())) => {}
        Ok(Err(_)) => {
            let _ = logger.write(4, "shutdown", "PIPE_DRAIN_FAILED");
        }
        Err(_) => {
            let _ = logger.write(4, "shutdown", "PIPE_TASK_FAILED");
        }
    }
    status_handle.set_service_status(status::stopped())?;
    Ok(())
}

fn effective_memory_limit(configured_mib: u32) -> Result<u32> {
    let mut status = MEMORYSTATUSEX {
        dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
        ..MEMORYSTATUSEX::default()
    };
    if unsafe { GlobalMemoryStatusEx(&mut status) } == 0 {
        anyhow::bail!(
            "GlobalMemoryStatusEx failed: {}",
            std::io::Error::last_os_error()
        );
    }
    let physical_mib = status.ullTotalPhys / (1024 * 1024);
    cap_memory_limit(configured_mib, physical_mib)
}

fn cap_memory_limit(configured_mib: u32, physical_mib: u64) -> Result<u32> {
    let seventy_five_percent = physical_mib.saturating_mul(3) / 4;
    let effective = u64::from(configured_mib).min(seventy_five_percent);
    if effective < 512 {
        anyhow::bail!("effective service memory quota is below 512 MiB");
    }
    u32::try_from(effective).context("effective memory quota exceeds u32")
}

#[cfg(test)]
mod tests {
    use super::cap_memory_limit;

    #[test]
    fn memory_limit_is_capped_at_three_quarters_of_physical_ram() {
        assert_eq!(cap_memory_limit(24 * 1024, 16 * 1024).unwrap(), 12 * 1024);
        assert_eq!(cap_memory_limit(24 * 1024, 64 * 1024).unwrap(), 24 * 1024);
        assert!(cap_memory_limit(24 * 1024, 682).is_err());
    }
}
