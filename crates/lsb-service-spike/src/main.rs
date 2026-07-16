use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

const SERVICE_NAME: &str = "LocalSandboxSeaWorkSpike";
const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ProbeConfig {
    schema_version: u32,
    run_id: String,
    data_dir: PathBuf,
    working_root: PathBuf,
    result_path: PathBuf,
    #[serde(default)]
    test_mounts: bool,
    #[serde(default)]
    test_watches: bool,
    #[serde(default)]
    test_network: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum CheckStatus {
    Passed,
    Failed,
    Blocked,
    NotRun,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CheckResult {
    name: String,
    status: CheckStatus,
    duration_ms: u128,
    detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HostEvidence {
    process_id: u32,
    session_id: u32,
    token_sid: String,
    architecture: String,
    current_directory: String,
    user_profile: Option<String>,
    path_present: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CapabilityDecision {
    ports_enabled: bool,
    reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProbeReport {
    schema_version: u32,
    run_id: String,
    service_name: String,
    sdk_version: String,
    started_unix_ms: u128,
    finished_unix_ms: u128,
    host: Option<HostEvidence>,
    checks: Vec<CheckResult>,
    capability_decisions: CapabilityDecision,
    complete: bool,
}

impl ProbeReport {
    fn new(run_id: String) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            run_id,
            service_name: SERVICE_NAME.to_string(),
            sdk_version: lsb_sdk::CURRENT_VERSION.to_string(),
            started_unix_ms: unix_ms(),
            finished_unix_ms: 0,
            host: None,
            checks: Vec::new(),
            capability_decisions: CapabilityDecision {
                ports_enabled: false,
                reason: "WFP owner/logon-SID isolation is not implemented in the spike; v1 ports remain fail-closed".to_string(),
            },
            complete: false,
        }
    }

    fn record<F>(&mut self, name: &str, operation: F)
    where
        F: FnOnce() -> Result<String>,
    {
        let started = std::time::Instant::now();
        let (status, detail) = match operation() {
            Ok(detail) => (CheckStatus::Passed, detail),
            Err(error) => (CheckStatus::Failed, format!("{error:#}")),
        };
        self.checks.push(CheckResult {
            name: name.to_string(),
            status,
            duration_ms: started.elapsed().as_millis(),
            detail,
        });
    }

    fn note(&mut self, name: &str, status: CheckStatus, detail: impl Into<String>) {
        self.checks.push(CheckResult {
            name: name.to_string(),
            status,
            duration_ms: 0,
            detail: detail.into(),
        });
    }
}

fn unix_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn print_schema() -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&ProbeReport::new("schema-example".to_string()))?
    );
    Ok(())
}

#[cfg(windows)]
mod windows {
    use std::ffi::OsString;
    use std::path::Path;
    use std::ptr;
    use std::sync::mpsc;
    use std::time::Duration;

    use anyhow::{bail, Context, Result};
    use lsb_sdk::{AsyncSandbox, MountConfig, SandboxConfig};
    use windows_service::define_windows_service;
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_dispatcher;
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HLOCAL};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentProcessId, OpenProcessToken,
    };

    use super::{
        unix_ms, CheckResult, CheckStatus, HostEvidence, ProbeConfig, ProbeReport, SCHEMA_VERSION,
        SERVICE_NAME,
    };

    define_windows_service!(ffi_service_main, service_main);

    pub fn dispatch(config_path: String) -> Result<()> {
        std::env::set_var("LSB_SERVICE_SPIKE_CONFIG", config_path);
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
            .context("connect spike process to the Windows service dispatcher")
    }

    fn service_main(arguments: Vec<OsString>) {
        if let Err(error) = run_service(arguments) {
            let _ = write_startup_failure(&error);
        }
    }

    fn run_service(arguments: Vec<OsString>) -> Result<()> {
        let (stop_tx, stop_rx) = mpsc::channel();
        let status_handle =
            service_control_handler::register(SERVICE_NAME, move |event| match event {
                ServiceControl::Stop | ServiceControl::Preshutdown => {
                    let _ = stop_tx.send(());
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            })
            .context("register SCM control handler")?;

        status_handle.set_service_status(service_status(
            ServiceState::StartPending,
            ServiceControlAccept::empty(),
            1,
            Duration::from_secs(120),
        ))?;

        let config_path = arguments
            .iter()
            .skip(1)
            .find_map(|value| value.to_str())
            .map(str::to_string)
            .or_else(|| std::env::var("LSB_SERVICE_SPIKE_CONFIG").ok())
            .context("SCM did not pass the spike config path")?;
        let config = load_config(Path::new(&config_path))?;

        status_handle.set_service_status(service_status(
            ServiceState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::PRESHUTDOWN,
            0,
            Duration::ZERO,
        ))?;
        let probe_result = run_probe(&config, &stop_rx);
        status_handle.set_service_status(service_status(
            ServiceState::StopPending,
            ServiceControlAccept::empty(),
            1,
            Duration::from_secs(30),
        ))?;
        probe_result?;
        status_handle.set_service_status(service_status(
            ServiceState::Stopped,
            ServiceControlAccept::empty(),
            0,
            Duration::ZERO,
        ))?;
        Ok(())
    }

    fn service_status(
        current_state: ServiceState,
        controls_accepted: ServiceControlAccept,
        checkpoint: u32,
        wait_hint: Duration,
    ) -> ServiceStatus {
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state,
            controls_accepted,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint,
            wait_hint,
            process_id: None,
        }
    }

    fn load_config(path: &Path) -> Result<ProbeConfig> {
        let bytes =
            std::fs::read(path).with_context(|| format!("read spike config {}", path.display()))?;
        let config: ProbeConfig = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse spike config {}", path.display()))?;
        if config.schema_version != SCHEMA_VERSION {
            bail!(
                "unsupported spike config schema {}, expected {}",
                config.schema_version,
                SCHEMA_VERSION
            );
        }
        for (name, path) in [
            ("data_dir", &config.data_dir),
            ("working_root", &config.working_root),
            ("result_path", &config.result_path),
        ] {
            if !path.is_absolute() {
                bail!("{name} must be absolute: {}", path.display());
            }
        }
        Ok(config)
    }

    fn run_probe(config: &ProbeConfig, stop_rx: &mpsc::Receiver<()>) -> Result<()> {
        std::fs::create_dir_all(&config.working_root)?;
        if let Some(parent) = config.result_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut report = ProbeReport::new(config.run_id.clone());
        let identity = host_evidence();
        match identity {
            Ok(host) => {
                let valid = host.session_id == 0 && host.token_sid == "S-1-5-18";
                report.note(
                    "service_identity_session0",
                    if valid {
                        CheckStatus::Passed
                    } else {
                        CheckStatus::Failed
                    },
                    format!(
                        "token SID {} in Session {} (PID {})",
                        host.token_sid, host.session_id, host.process_id
                    ),
                );
                report.host = Some(host);
            }
            Err(error) => report.note(
                "service_identity_session0",
                CheckStatus::Failed,
                format!("{error:#}"),
            ),
        }
        report.record("profile_path_independence", || {
            if std::env::var_os("USERPROFILE")
                .is_some_and(|profile| config.data_dir.starts_with(profile))
            {
                bail!("data_dir is under the service profile")
            }
            Ok(format!(
                "runtime uses explicit data directory {}",
                config.data_dir.display()
            ))
        });

        if stop_rx.try_recv().is_ok() {
            report.note(
                "sandbox_boot_exec_stop",
                CheckStatus::NotRun,
                "SCM stop requested",
            );
            return finish_report(config, report);
        }

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .context("create spike async runtime")?;
        let started = std::time::Instant::now();
        if let Err(error) = runtime.block_on(run_sandbox(config, &mut report)) {
            report.checks.push(CheckResult {
                name: "sandbox_boot_exec_stop".to_string(),
                status: CheckStatus::Failed,
                duration_ms: started.elapsed().as_millis(),
                detail: format!("{error:#}"),
            });
        }

        report.note(
            "qemu_nested_kill_on_close_job",
            CheckStatus::Blocked,
            "SDK does not expose authoritative nested-Job evidence; Phase 4 owns suspended spawn/assignment",
        );
        report.note(
            "wfp_ipv4_ipv6_logon_sid_isolation",
            CheckStatus::Blocked,
            "WFP isolation is not implemented; host-port forwarding remains disabled for v1",
        );
        report.note(
            "corporate_proxy_vpn_edr",
            CheckStatus::NotRun,
            "requires a managed downstream machine and active enterprise products",
        );
        finish_report(config, report)
    }

    async fn run_sandbox(config: &ProbeConfig, report: &mut ProbeReport) -> Result<()> {
        let rw_root = config.working_root.join("mount-rw");
        let ro_root = config.working_root.join("mount-ro");
        let mounts = if config.test_mounts {
            std::fs::create_dir_all(&rw_root)?;
            std::fs::create_dir_all(&ro_root)?;
            std::fs::write(rw_root.join("host.txt"), b"rw-host")?;
            std::fs::write(ro_root.join("host.txt"), b"ro-host")?;
            std::env::set_var("LSB_STORAGE", "direct");
            vec![
                MountConfig::Direct {
                    host_path: rw_root.display().to_string(),
                    guest_path: "/spike-rw".to_string(),
                    flags: 0,
                },
                MountConfig::Direct {
                    host_path: ro_root.display().to_string(),
                    guest_path: "/spike-ro".to_string(),
                    flags: 1,
                },
            ]
        } else {
            Vec::new()
        };

        let boot_started = std::time::Instant::now();
        let sandbox = AsyncSandbox::boot(SandboxConfig {
            data_dir: Some(config.data_dir.display().to_string()),
            mounts,
            allow_net: config.test_network,
            allowed_hosts: if config.test_network {
                vec!["example.com".to_string()]
            } else {
                Vec::new()
            },
            instance_id: Some(format!("session0-spike-{}", config.run_id)),
            ..Default::default()
        })
        .await
        .context("boot QEMU/WHPX sandbox from the SCM service")?;

        let operations = async {
            let exec = sandbox
                .exec(&["/bin/sh", "-c", "printf session0-ok"])
                .await
                .context("execute command in Session 0 sandbox")?;
            if exec.exit_code != 0 || exec.stdout != "session0-ok" {
                bail!(
                    "unexpected exec result: exit={} stdout={:?} stderr={:?}",
                    exec.exit_code,
                    exec.stdout,
                    exec.stderr
                );
            }
            report.checks.push(CheckResult {
                name: "sandbox_boot_exec".to_string(),
                status: CheckStatus::Passed,
                duration_ms: boot_started.elapsed().as_millis(),
                detail: "WHPX/QEMU boot and guest exec succeeded under LocalSystem".to_string(),
            });

            if config.test_mounts {
                test_mounts_and_watches(&sandbox, config, &rw_root, report).await?;
            } else {
                report.note("direct_ro_rw_smb", CheckStatus::NotRun, "mount testing disabled by config");
                report.note("watch_propagation", CheckStatus::NotRun, "mount testing disabled by config");
            }

            if config.test_network {
                let network = sandbox
                    .exec(&[
                        "/bin/sh",
                        "-c",
                        "getent hosts example.com >/tmp/dns && curl -fsS --max-time 15 http://example.com/ >/dev/null",
                    ])
                    .await?;
                report.note(
                    "dns_proxy_certificate",
                    if network.exit_code == 0 { CheckStatus::Passed } else { CheckStatus::Failed },
                    format!("guest network probe exit={} stderr={}", network.exit_code, network.stderr),
                );
            } else {
                report.note("dns_proxy_certificate", CheckStatus::NotRun, "network testing disabled by config");
            }
            Ok::<(), anyhow::Error>(())
        }
        .await;

        let stop_started = std::time::Instant::now();
        let stop_result = sandbox.stop().await;
        report.checks.push(CheckResult {
            name: "sandbox_stop_teardown".to_string(),
            status: if stop_result.is_ok() {
                CheckStatus::Passed
            } else {
                CheckStatus::Failed
            },
            duration_ms: stop_started.elapsed().as_millis(),
            detail: stop_result
                .as_ref()
                .map(|_| "sandbox stopped and SDK cleanup completed".to_string())
                .unwrap_or_else(|error| format!("{error:#}")),
        });
        operations?;
        stop_result?;
        Ok(())
    }

    async fn test_mounts_and_watches(
        sandbox: &AsyncSandbox,
        config: &ProbeConfig,
        rw_root: &Path,
        report: &mut ProbeReport,
    ) -> Result<()> {
        let rw = sandbox.read_file("/spike-rw/host.txt").await?;
        let ro = sandbox.read_file("/spike-ro/host.txt").await?;
        if rw != b"rw-host" || ro != b"ro-host" {
            bail!("direct SMB mount contents did not match host files");
        }
        sandbox
            .write_file("/spike-rw/guest.txt", b"guest-rw")
            .await?;
        let sync = sandbox.exec(&["/bin/sync"]).await?;
        if sync.exit_code != 0 || std::fs::read(rw_root.join("guest.txt"))? != b"guest-rw" {
            bail!("direct RW SMB propagation failed");
        }
        if sandbox
            .write_file("/spike-ro/guest-denied.txt", b"denied")
            .await
            .is_ok()
        {
            bail!("direct RO SMB mount accepted a guest write");
        }
        report.note(
            "direct_ro_rw_smb",
            CheckStatus::Passed,
            "direct SMB reads, RW propagation, and RO write denial succeeded",
        );

        if config.test_watches {
            let mut watch = sandbox.watch("/spike-rw", true).await?;
            tokio::time::sleep(Duration::from_millis(500)).await;
            std::fs::write(rw_root.join("watch.txt"), b"watch")?;
            let event = tokio::time::timeout(Duration::from_secs(10), watch.next())
                .await
                .context("timed out waiting for direct SMB watch event")?
                .context("direct SMB watch stream closed")??;
            if !event.path.ends_with("watch.txt") {
                bail!("unexpected watch event path {}", event.path);
            }
            report.note(
                "watch_propagation",
                CheckStatus::Passed,
                format!("observed {} event for {}", event.event, event.path),
            );
        } else {
            report.note(
                "watch_propagation",
                CheckStatus::NotRun,
                "watch testing disabled by config",
            );
        }
        Ok(())
    }

    fn finish_report(config: &ProbeConfig, mut report: ProbeReport) -> Result<()> {
        report.finished_unix_ms = unix_ms();
        report.complete = true;
        let temporary = config.result_path.with_extension("json.tmp");
        std::fs::write(&temporary, serde_json::to_vec_pretty(&report)?)?;
        std::fs::rename(&temporary, &config.result_path)?;
        Ok(())
    }

    fn write_startup_failure(error: &anyhow::Error) -> Result<()> {
        let config_path = std::env::var("LSB_SERVICE_SPIKE_CONFIG")?;
        let config = load_config(Path::new(&config_path))?;
        let mut report = ProbeReport::new(config.run_id.clone());
        report.note("service_startup", CheckStatus::Failed, format!("{error:#}"));
        finish_report(&config, report)
    }

    fn host_evidence() -> Result<HostEvidence> {
        let process_id = unsafe { GetCurrentProcessId() };
        let mut session_id = u32::MAX;
        if unsafe { ProcessIdToSessionId(process_id, &mut session_id) } == 0 {
            bail!(
                "ProcessIdToSessionId failed: {}",
                std::io::Error::last_os_error()
            );
        }
        Ok(HostEvidence {
            process_id,
            session_id,
            token_sid: current_token_sid()?,
            architecture: std::env::consts::ARCH.to_string(),
            current_directory: std::env::current_dir()?.display().to_string(),
            user_profile: std::env::var("USERPROFILE").ok(),
            path_present: std::env::var_os("PATH").is_some(),
        })
    }

    fn current_token_sid() -> Result<String> {
        let mut token = ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            bail!(
                "OpenProcessToken failed: {}",
                std::io::Error::last_os_error()
            );
        }
        let result = (|| {
            let mut required = 0;
            unsafe { GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut required) };
            if required == 0 {
                bail!(
                    "GetTokenInformation size query failed: {}",
                    std::io::Error::last_os_error()
                );
            }
            let mut buffer = vec![0u8; required as usize];
            if unsafe {
                GetTokenInformation(
                    token,
                    TokenUser,
                    buffer.as_mut_ptr().cast(),
                    required,
                    &mut required,
                )
            } == 0
            {
                bail!(
                    "GetTokenInformation failed: {}",
                    std::io::Error::last_os_error()
                );
            }
            let token_user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
            let mut sid_string = ptr::null_mut();
            if unsafe { ConvertSidToStringSidW(token_user.User.Sid, &mut sid_string) } == 0 {
                bail!(
                    "ConvertSidToStringSidW failed: {}",
                    std::io::Error::last_os_error()
                );
            }
            let len = (0..)
                .take_while(|index| unsafe { *sid_string.add(*index) } != 0)
                .count();
            let value = String::from_utf16(unsafe { std::slice::from_raw_parts(sid_string, len) })?;
            unsafe { LocalFree(sid_string as HLOCAL) };
            Ok(value)
        })();
        unsafe { CloseHandle(token) };
        result
    }
}

fn main() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args == ["--schema"] {
        return print_schema();
    }
    if args.first().map(String::as_str) != Some("--service") {
        bail!("usage: lsb-service-spike --schema | --service <absolute-config-path>");
    }
    let config_path = args
        .get(1)
        .cloned()
        .context("--service requires an absolute config path")?;
    #[cfg(windows)]
    {
        windows::dispatch(config_path)
    }
    #[cfg(not(windows))]
    {
        let _ = config_path;
        bail!("the Session 0 service spike is supported only on Windows")
    }
}
