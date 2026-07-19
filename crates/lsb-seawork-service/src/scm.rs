use std::ffi::OsString;
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
const STARTUP_HEARTBEAT: Duration = Duration::from_secs(2);
const SHUTDOWN_HEARTBEAT: Duration = Duration::from_secs(2);

pub fn dispatch() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("connect LocalSandboxSeaWork to the SCM dispatcher")
}

fn service_main(_arguments: Vec<OsString>) {
    let _ = run();
}

fn run() -> Result<()> {
    let (control_tx, control_rx) = tokio::sync::mpsc::unbounded_channel();
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
    mut control_rx: tokio::sync::mpsc::UnboundedReceiver<ServiceControl>,
) -> Result<()> {
    let mut startup_checkpoint = 1u32;
    status_handle.set_service_status(status::pending(
        ServiceState::StartPending,
        startup_checkpoint,
        STARTUP_WAIT_HINT,
    ))?;

    let paths = ServicePaths::discover()?;
    paths.prepare()?;
    let logger = JsonLogger::new(&paths.logs)?;
    logger.write(1, "startup", "START_PENDING")?;
    advance_startup_checkpoint(status_handle, &mut startup_checkpoint, STARTUP_WAIT_HINT)?;
    let config = ServiceConfig::load_or_default(&paths.config)?;
    let product_ca_bundle_pem = crate::config::load_product_ca_bundle(&paths.product_ca_bundle)?;
    let reconciliation = ledger::reconcile(&paths.ledger, &paths.quarantine)?;
    if !reconciliation.admissions_open {
        logger.write(3, "reconcile", "HEALTH_ONLY_QUARANTINE")?;
    }
    advance_startup_checkpoint(status_handle, &mut startup_checkpoint, STARTUP_WAIT_HINT)?;
    let engine = match run_startup_operation(
        &mut startup_checkpoint,
        STARTUP_HEARTBEAT,
        || {
            let report = crate::bundle::verify_adjacent_bundle()
                .context("verify adjacent installed bundle")?;
            let engine = ServiceEngineConfig::discover(&paths)?;
            Ok((report.files_verified, engine))
        },
        |checkpoint| {
            status_handle.set_service_status(status::pending(
                ServiceState::StartPending,
                checkpoint,
                STARTUP_WAIT_HINT,
            ))
        },
    ) {
        Ok((files_verified, engine)) => {
            logger.write(
                1,
                "bundle",
                &format!("BUNDLE_VERIFIED_FILES={files_verified}"),
            )?;
            Some(engine)
        }
        Err(_) => {
            logger.write(3, "bundle", "BUNDLE_INVALID")?;
            None
        }
    };
    advance_startup_checkpoint(status_handle, &mut startup_checkpoint, STARTUP_WAIT_HINT)?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("create service async runtime")?;
    let maintenance = MaintenanceManager::load(
        paths.pending_update.clone(),
        reconciliation.admissions_open && engine.is_some(),
    );
    let whpx = crate::windows::whpx::health_state();
    if whpx != lsb_service_proto::HealthState::Ready {
        logger.write(3, "runtime", "WHPX_UNAVAILABLE")?;
    }
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
    .with_whpx(whpx)
    .with_client_policy(
        maintenance,
        config.client_roots.clone(),
        config.maintenance_roots.clone(),
        config.publisher_thumbprints.clone(),
        config.egress_allow.clone(),
        product_ca_bundle_pem,
    );
    advance_startup_checkpoint(
        status_handle,
        &mut startup_checkpoint,
        Duration::from_secs(30),
    )?;
    let pipe = runtime.block_on(async { HealthPipe::bind(context.clone()) })?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let mut pipe_task = runtime.spawn(pipe.run(shutdown_rx));

    advance_startup_checkpoint(
        status_handle,
        &mut startup_checkpoint,
        Duration::from_secs(30),
    )?;

    status_handle.set_service_status(status::running())?;
    logger.write(1, "runtime", "RUNNING")?;
    let control = match runtime.block_on(wait_for_runtime_exit(&mut control_rx, &mut pipe_task)) {
        RuntimeExit::Control(Some(control)) => control,
        RuntimeExit::Control(None) => {
            drain_sessions(&context, &logger);
            let _ = shutdown_tx.send(());
            pipe_task.abort();
            let _ = runtime.block_on(&mut pipe_task);
            anyhow::bail!("SCM control channel disconnected");
        }
        RuntimeExit::Pipe(result) => {
            drain_sessions(&context, &logger);
            let _ = logger.write(4, "runtime", "PIPE_TASK_EXITED");
            match result {
                Ok(Ok(())) => anyhow::bail!("pipe task exited before SCM stop"),
                Ok(Err(error)) => return Err(error).context("pipe task failed before SCM stop"),
                Err(error) => anyhow::bail!("pipe task join failed before SCM stop: {error}"),
            }
        }
    };
    let wait_hint = if control == ServiceControl::Preshutdown {
        Duration::from_secs(60)
    } else {
        Duration::from_secs(30)
    };
    status_handle.set_service_status(status::pending(ServiceState::StopPending, 1, wait_hint))?;
    logger.write(2, "shutdown", "STOP_PENDING")?;
    drain_sessions(&context, &logger);
    let _ = shutdown_tx.send(());
    let pipe_drain = runtime.block_on(wait_for_pipe_drain(
        &mut pipe_task,
        wait_hint,
        SHUTDOWN_HEARTBEAT,
        |checkpoint| {
            status_handle.set_service_status(status::pending(
                ServiceState::StopPending,
                checkpoint,
                wait_hint,
            ))
        },
    ))?;
    match pipe_drain {
        PipeDrainOutcome::Clean => {}
        PipeDrainOutcome::Failed => {
            let _ = logger.write(4, "shutdown", "PIPE_DRAIN_FAILED");
        }
        PipeDrainOutcome::TimedOut => {
            let _ = logger.write(4, "shutdown", "PIPE_DRAIN_TIMEOUT");
        }
    }
    status_handle.set_service_status(status::stopped())?;
    Ok(())
}

enum RuntimeExit {
    Control(Option<ServiceControl>),
    Pipe(std::result::Result<Result<()>, tokio::task::JoinError>),
}

fn advance_startup_checkpoint(
    status_handle: &service_control_handler::ServiceStatusHandle,
    checkpoint: &mut u32,
    wait_hint: Duration,
) -> Result<()> {
    *checkpoint = checkpoint
        .checked_add(1)
        .context("startup checkpoint exhausted")?;
    status_handle.set_service_status(status::pending(
        ServiceState::StartPending,
        *checkpoint,
        wait_hint,
    ))?;
    Ok(())
}

fn run_startup_operation<T, F, R>(
    checkpoint: &mut u32,
    heartbeat: Duration,
    operation: F,
    mut report_checkpoint: R,
) -> Result<T>
where
    T: Send,
    F: FnOnce() -> Result<T> + Send,
    R: FnMut(u32) -> windows_service::Result<()>,
{
    std::thread::scope(|scope| {
        let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
        let worker = scope.spawn(move || {
            let _ = result_tx.send(operation());
        });

        loop {
            match result_rx.recv_timeout(heartbeat) {
                Ok(result) => {
                    worker
                        .join()
                        .map_err(|_| anyhow::anyhow!("startup operation panicked"))?;
                    return result;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    *checkpoint = checkpoint
                        .checked_add(1)
                        .context("startup checkpoint exhausted")?;
                    report_checkpoint(*checkpoint)?;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    worker
                        .join()
                        .map_err(|_| anyhow::anyhow!("startup operation panicked"))?;
                    anyhow::bail!("startup operation disconnected");
                }
            }
        }
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PipeDrainOutcome {
    Clean,
    Failed,
    TimedOut,
}

async fn wait_for_runtime_exit(
    control_rx: &mut tokio::sync::mpsc::UnboundedReceiver<ServiceControl>,
    pipe_task: &mut tokio::task::JoinHandle<Result<()>>,
) -> RuntimeExit {
    tokio::select! {
        biased;
        result = pipe_task => RuntimeExit::Pipe(result),
        control = control_rx.recv() => RuntimeExit::Control(control),
    }
}

async fn wait_for_pipe_drain<F>(
    pipe_task: &mut tokio::task::JoinHandle<Result<()>>,
    deadline: Duration,
    heartbeat: Duration,
    mut report_checkpoint: F,
) -> Result<PipeDrainOutcome>
where
    F: FnMut(u32) -> windows_service::Result<()>,
{
    let started = tokio::time::Instant::now();
    let mut checkpoint = 1u32;
    loop {
        let remaining = deadline.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            pipe_task.abort();
            let _ = pipe_task.await;
            return Ok(PipeDrainOutcome::TimedOut);
        }
        let slice = remaining.min(heartbeat);
        match tokio::time::timeout(slice, &mut *pipe_task).await {
            Ok(Ok(Ok(()))) => return Ok(PipeDrainOutcome::Clean),
            Ok(Ok(Err(_))) | Ok(Err(_)) => return Ok(PipeDrainOutcome::Failed),
            Err(_) if started.elapsed() >= deadline => {
                pipe_task.abort();
                let _ = pipe_task.await;
                return Ok(PipeDrainOutcome::TimedOut);
            }
            Err(_) => {
                checkpoint = checkpoint
                    .checked_add(1)
                    .context("shutdown checkpoint exhausted")?;
                report_checkpoint(checkpoint)?;
            }
        }
    }
}

fn drain_sessions(context: &HealthContext, logger: &JsonLogger) {
    match context.begin_shutdown() {
        Ok(drained) => {
            let _ = logger.write(2, "shutdown", &format!("DRAINED_SESSIONS={drained}"));
        }
        Err(_) => {
            let _ = logger.write(4, "shutdown", "SESSION_DRAIN_FAILED");
        }
    }
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
    use super::{
        cap_memory_limit, run_startup_operation, wait_for_pipe_drain, wait_for_runtime_exit,
        PipeDrainOutcome, RuntimeExit,
    };
    use std::time::Duration;
    use windows_service::service::ServiceControl;

    #[test]
    fn memory_limit_is_capped_at_three_quarters_of_physical_ram() {
        assert_eq!(cap_memory_limit(24 * 1024, 16 * 1024).unwrap(), 12 * 1024);
        assert_eq!(cap_memory_limit(24 * 1024, 64 * 1024).unwrap(), 24 * 1024);
        assert!(cap_memory_limit(24 * 1024, 682).is_err());
    }

    #[test]
    fn startup_operation_heartbeats_with_monotonic_checkpoints() {
        let mut checkpoint = 3u32;
        let mut checkpoints = Vec::new();
        let value = run_startup_operation(
            &mut checkpoint,
            Duration::from_millis(10),
            || {
                std::thread::sleep(Duration::from_millis(35));
                Ok(42)
            },
            |checkpoint| {
                checkpoints.push(checkpoint);
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(value, 42);
        assert_eq!(checkpoints.first(), Some(&4));
        assert!(checkpoints.len() >= 2);
        assert!(checkpoints
            .windows(2)
            .all(|pair| pair[1] == pair[0].saturating_add(1)));
        assert_eq!(checkpoints.last(), Some(&checkpoint));
    }

    #[test]
    fn startup_operation_propagates_operation_error() {
        let mut checkpoint = 1u32;
        let error = run_startup_operation::<(), _, _>(
            &mut checkpoint,
            Duration::from_secs(1),
            || anyhow::bail!("verification failed"),
            |_| Ok(()),
        )
        .unwrap_err();

        assert!(error.to_string().contains("verification failed"));
        assert_eq!(checkpoint, 1);
    }

    #[tokio::test]
    async fn runtime_wait_observes_pipe_exit_without_an_scm_control() {
        let (_control_tx, mut control_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut pipe_task = tokio::spawn(async { anyhow::bail!("pipe failed") });

        assert!(matches!(
            wait_for_runtime_exit(&mut control_rx, &mut pipe_task).await,
            RuntimeExit::Pipe(Ok(Err(_)))
        ));
    }

    #[tokio::test]
    async fn runtime_wait_observes_scm_control_while_pipe_is_running() {
        let (control_tx, mut control_rx) = tokio::sync::mpsc::unbounded_channel();
        control_tx.send(ServiceControl::Stop).unwrap();
        let mut pipe_task = tokio::spawn(std::future::pending());

        assert!(matches!(
            wait_for_runtime_exit(&mut control_rx, &mut pipe_task).await,
            RuntimeExit::Control(Some(ServiceControl::Stop))
        ));
        pipe_task.abort();
    }

    #[tokio::test]
    async fn pipe_drain_reports_clean_and_failed_completion() {
        let mut clean = tokio::spawn(async { Ok(()) });
        assert_eq!(
            wait_for_pipe_drain(
                &mut clean,
                Duration::from_secs(1),
                Duration::from_millis(10),
                |_| Ok(()),
            )
            .await
            .unwrap(),
            PipeDrainOutcome::Clean
        );

        let mut failed = tokio::spawn(async { anyhow::bail!("pipe failed") });
        assert_eq!(
            wait_for_pipe_drain(
                &mut failed,
                Duration::from_secs(1),
                Duration::from_millis(10),
                |_| Ok(()),
            )
            .await
            .unwrap(),
            PipeDrainOutcome::Failed
        );
    }

    #[tokio::test]
    async fn pipe_drain_heartbeats_and_aborts_at_deadline() {
        let mut pipe_task = tokio::spawn(std::future::pending());
        let mut checkpoints = Vec::new();
        let outcome = wait_for_pipe_drain(
            &mut pipe_task,
            Duration::from_millis(35),
            Duration::from_millis(10),
            |checkpoint| {
                checkpoints.push(checkpoint);
                Ok(())
            },
        )
        .await
        .unwrap();

        assert_eq!(outcome, PipeDrainOutcome::TimedOut);
        assert_eq!(checkpoints.first(), Some(&2));
        assert!(checkpoints
            .windows(2)
            .all(|pair| pair[1] == pair[0].saturating_add(1)));
        assert!(pipe_task.is_finished());
    }
}
