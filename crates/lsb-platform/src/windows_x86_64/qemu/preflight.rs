use std::path::Path;

use serde::Serialize;

use super::discovery::{QemuDiscovery, QemuDiscoveryHost, QemuPath};
use super::version::{probe_qemu_version, QemuVersion};
use super::{QemuCommandOutput, QemuCommandRunner, QemuPreflightError};

pub(crate) const PRODUCTION_ACCELERATOR: &str = "whpx";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct QemuHostReport {
    pub os: String,
    pub arch: String,
    pub windows_major_version: Option<u32>,
    pub windows_version_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct QemuWhpxReport {
    pub required_accelerator: &'static str,
    pub reported_by_qemu: bool,
    pub probe: &'static str,
    pub limitation: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct QemuPreflightReport {
    pub host: QemuHostReport,
    pub qemu: QemuPath,
    pub version: QemuVersion,
    pub whpx: QemuWhpxReport,
}

#[derive(Debug)]
pub(crate) struct QemuPreflight<'a, H, R>
where
    H: QemuDiscoveryHost,
    R: QemuCommandRunner,
{
    discovery: QemuDiscovery<'a, H>,
    runner: &'a R,
}

impl<'a, H, R> QemuPreflight<'a, H, R>
where
    H: QemuDiscoveryHost,
    R: QemuCommandRunner,
{
    pub(crate) fn new(discovery: QemuDiscovery<'a, H>, runner: &'a R) -> Self {
        Self { discovery, runner }
    }

    pub(crate) fn run(&self) -> Result<QemuPreflightReport, QemuPreflightError> {
        let host = validate_host(self.discovery.host())?;
        let qemu = self.discovery.discover()?;
        let version = probe_qemu_version(self.runner, &qemu.path)?;
        validate_x86_64_system_emulator(self.runner, &qemu.path)?;
        validate_whpx(self.runner, &qemu.path)?;

        Ok(QemuPreflightReport {
            host,
            qemu,
            version,
            whpx: QemuWhpxReport {
                required_accelerator: PRODUCTION_ACCELERATOR,
                reported_by_qemu: true,
                probe: "qemu-system-x86_64.exe -accel help",
                limitation: "Preflight does not start a VM; this proves the QEMU binary reports WHPX support, but firmware and Windows Hypervisor Platform runtime readiness are proven by boot validation.",
            },
        })
    }
}

pub(crate) fn validate_host<H>(host: &H) -> Result<QemuHostReport, QemuPreflightError>
where
    H: QemuDiscoveryHost,
{
    let os = host.host_os();
    if os != "windows" {
        return Err(QemuPreflightError::UnsupportedHostOs { actual: os });
    }

    let arch = host.host_arch();
    if arch != "x86_64" {
        return Err(QemuPreflightError::UnsupportedArchitecture { actual: arch });
    }

    let windows_major_version = host.windows_major_version();
    if let Some(major) = windows_major_version {
        if major < 11 {
            return Err(QemuPreflightError::UnsupportedWindowsVersion { major });
        }
    }

    Ok(QemuHostReport {
        os,
        arch,
        windows_major_version,
        windows_version_verified: windows_major_version.is_some(),
    })
}

fn validate_x86_64_system_emulator<R>(
    runner: &R,
    qemu_path: &Path,
) -> Result<(), QemuPreflightError>
where
    R: QemuCommandRunner,
{
    let output = run_required_probe(
        runner,
        qemu_path,
        &["--help"],
        "qemu-system-x86_64.exe --help",
    )?;
    let help = output.combined_excerpt();

    let file_name_matches = qemu_path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("qemu-system-x86_64.exe"));
    let help_mentions_target = help.to_ascii_lowercase().contains("qemu-system-x86_64");

    if file_name_matches || help_mentions_target {
        Ok(())
    } else {
        Err(QemuPreflightError::UnsuitableQemuBinary {
            path: qemu_path.to_path_buf(),
            reason: "neither the executable name nor help output identifies qemu-system-x86_64"
                .to_string(),
            help_excerpt: help,
        })
    }
}

fn validate_whpx<R>(runner: &R, qemu_path: &Path) -> Result<(), QemuPreflightError>
where
    R: QemuCommandRunner,
{
    let output = runner.run(qemu_path, &["-accel", "help"]).map_err(|err| {
        QemuPreflightError::QemuCannotExecute {
            path: qemu_path.to_path_buf(),
            probe: "qemu-system-x86_64.exe -accel help",
            detail: format!("{} ({:?})", err.message, err.kind),
        }
    })?;

    if !output.status.success {
        return Err(QemuPreflightError::WhpxUnavailable {
            path: qemu_path.to_path_buf(),
            accelerator_output_excerpt: output.stdout_excerpt(),
            stderr_excerpt: format!("{}; {}", output.status, output.stderr_excerpt()),
        });
    }

    let accelerator_output = output.combined_excerpt();
    if contains_accelerator(&accelerator_output, PRODUCTION_ACCELERATOR) {
        Ok(())
    } else {
        Err(QemuPreflightError::WhpxUnavailable {
            path: qemu_path.to_path_buf(),
            accelerator_output_excerpt: accelerator_output,
            stderr_excerpt: output.stderr_excerpt(),
        })
    }
}

fn run_required_probe<R>(
    runner: &R,
    qemu_path: &Path,
    args: &[&str],
    probe: &'static str,
) -> Result<QemuCommandOutput, QemuPreflightError>
where
    R: QemuCommandRunner,
{
    let output =
        runner
            .run(qemu_path, args)
            .map_err(|err| QemuPreflightError::QemuCannotExecute {
                path: qemu_path.to_path_buf(),
                probe,
                detail: format!("{} ({:?})", err.message, err.kind),
            })?;
    if output.status.success {
        Ok(output)
    } else {
        Err(QemuPreflightError::QemuCannotExecute {
            path: qemu_path.to_path_buf(),
            probe,
            detail: format!("{}; output: {}", output.status, output.combined_excerpt()),
        })
    }
}

fn contains_accelerator(output: &str, accelerator: &str) -> bool {
    output
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_' && ch != '-')
        .any(|token| token.eq_ignore_ascii_case(accelerator))
}
