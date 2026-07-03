use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;

pub(crate) mod discovery;
pub(crate) mod preflight;
pub(crate) mod version;

const OUTPUT_EXCERPT_LIMIT: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct QemuCommandStatus {
    pub success: bool,
    pub code: Option<i32>,
}

impl fmt::Display for QemuCommandStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.code {
            Some(code) => write!(f, "exit code {code}"),
            None if self.success => write!(f, "success"),
            None => write!(f, "terminated without an exit code"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QemuCommandOutput {
    pub status: QemuCommandStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl QemuCommandOutput {
    pub(crate) fn stdout_excerpt(&self) -> String {
        lossy_excerpt(&self.stdout)
    }

    pub(crate) fn stderr_excerpt(&self) -> String {
        lossy_excerpt(&self.stderr)
    }

    pub(crate) fn combined_excerpt(&self) -> String {
        let stdout = self.stdout_excerpt();
        let stderr = self.stderr_excerpt();
        match (stdout.is_empty(), stderr.is_empty()) {
            (true, true) => String::new(),
            (false, true) => stdout,
            (true, false) => stderr,
            (false, false) => format!("stdout: {stdout}\nstderr: {stderr}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QemuCommandRunError {
    pub kind: io::ErrorKind,
    pub message: String,
}

pub(crate) trait QemuCommandRunner {
    fn run(&self, program: &Path, args: &[&str]) -> Result<QemuCommandOutput, QemuCommandRunError>;
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct StdQemuCommandRunner;

impl QemuCommandRunner for StdQemuCommandRunner {
    fn run(&self, program: &Path, args: &[&str]) -> Result<QemuCommandOutput, QemuCommandRunError> {
        let output =
            Command::new(program)
                .args(args)
                .output()
                .map_err(|err| QemuCommandRunError {
                    kind: err.kind(),
                    message: err.to_string(),
                })?;

        Ok(QemuCommandOutput {
            status: QemuCommandStatus {
                success: output.status.success(),
                code: output.status.code(),
            },
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum QemuPreflightError {
    UnsupportedHostOs {
        actual: String,
    },
    UnsupportedArchitecture {
        actual: String,
    },
    UnsupportedWindowsVersion {
        major: u32,
    },
    QemuNotFound {
        searched_path_entries: usize,
    },
    EnvQemuPathInvalid {
        env_var: &'static str,
        path: PathBuf,
        reason: String,
    },
    ConfigQemuPathInvalid {
        path: PathBuf,
        reason: String,
    },
    QemuCannotExecute {
        path: PathBuf,
        probe: &'static str,
        detail: String,
    },
    UnsuitableQemuBinary {
        path: PathBuf,
        reason: String,
        help_excerpt: String,
    },
    VersionOutputUnparseable {
        path: PathBuf,
        output_excerpt: String,
    },
    WhpxUnavailable {
        path: PathBuf,
        accelerator_output_excerpt: String,
        stderr_excerpt: String,
    },
}

impl QemuPreflightError {
    pub(crate) fn remediation(&self) -> &'static str {
        match self {
            Self::UnsupportedHostOs { .. } => "Run LocalSandbox Windows backend checks on Windows 11 x86_64.",
            Self::UnsupportedArchitecture { .. } => {
                "Run LocalSandbox Windows backend checks on an x86_64 Windows host."
            }
            Self::UnsupportedWindowsVersion { .. } => {
                "Upgrade to Windows 11 x86_64 or use a supported LocalSandbox host."
            }
            Self::QemuNotFound { .. } => {
                "Install QEMU for Windows and add qemu-system-x86_64.exe to PATH, or set LSB_QEMU to its absolute path."
            }
            Self::EnvQemuPathInvalid { .. } => {
                "Set LSB_QEMU to an existing qemu-system-x86_64.exe path, or unset it to use PATH discovery."
            }
            Self::ConfigQemuPathInvalid { .. } => {
                "Point the LocalSandbox QEMU configuration hook at qemu-system-x86_64.exe, or remove it to use PATH discovery."
            }
            Self::QemuCannotExecute { .. } => {
                "Verify the QEMU installation is complete, the executable is not blocked by policy, and qemu-system-x86_64.exe --version works from this user account."
            }
            Self::UnsuitableQemuBinary { .. } => {
                "Use the x86_64 system emulator binary named qemu-system-x86_64.exe."
            }
            Self::VersionOutputUnparseable { .. } => {
                "Install a standard QEMU for Windows build whose qemu-system-x86_64.exe --version output includes a version such as 8.2.0."
            }
            Self::WhpxUnavailable { .. } => {
                "Install a QEMU build with WHPX support and enable Windows Hypervisor Platform in Windows Features or DISM."
            }
        }
    }
}

impl fmt::Display for QemuPreflightError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedHostOs { actual } => write!(
                f,
                "unsupported host OS for LocalSandbox Windows backend: {actual}. {}",
                self.remediation()
            ),
            Self::UnsupportedArchitecture { actual } => write!(
                f,
                "unsupported host architecture for LocalSandbox Windows backend: {actual}. {}",
                self.remediation()
            ),
            Self::UnsupportedWindowsVersion { major } => write!(
                f,
                "unsupported Windows version for LocalSandbox Windows backend: major version {major}. {}",
                self.remediation()
            ),
            Self::QemuNotFound {
                searched_path_entries,
            } => write!(
                f,
                "qemu-system-x86_64.exe was not found after checking LSB_QEMU, the LocalSandbox config hook, and {searched_path_entries} PATH entr{}. {}",
                if *searched_path_entries == 1 { "y" } else { "ies" },
                self.remediation()
            ),
            Self::EnvQemuPathInvalid {
                env_var,
                path,
                reason,
            } => write!(
                f,
                "{env_var} points to an invalid QEMU path '{}': {reason}. {}",
                path.display(),
                self.remediation()
            ),
            Self::ConfigQemuPathInvalid { path, reason } => write!(
                f,
                "configured QEMU path '{}' is invalid: {reason}. {}",
                path.display(),
                self.remediation()
            ),
            Self::QemuCannotExecute {
                path,
                probe,
                detail,
            } => write!(
                f,
                "discovered QEMU at '{}' could not run {probe}: {detail}. {}",
                path.display(),
                self.remediation()
            ),
            Self::UnsuitableQemuBinary {
                path,
                reason,
                help_excerpt,
            } => write!(
                f,
                "discovered binary '{}' is not suitable for x86_64 system emulation: {reason}. Help output excerpt: {}. {}",
                path.display(),
                empty_as_placeholder(help_excerpt),
                self.remediation()
            ),
            Self::VersionOutputUnparseable {
                path,
                output_excerpt,
            } => write!(
                f,
                "could not parse QEMU version output from '{}'. Output excerpt: {}. {}",
                path.display(),
                empty_as_placeholder(output_excerpt),
                self.remediation()
            ),
            Self::WhpxUnavailable {
                path,
                accelerator_output_excerpt,
                stderr_excerpt,
            } => write!(
                f,
                "QEMU at '{}' did not report WHPX as usable through '-accel help'. Output excerpt: {}; stderr excerpt: {}. {}",
                path.display(),
                empty_as_placeholder(accelerator_output_excerpt),
                empty_as_placeholder(stderr_excerpt),
                self.remediation()
            ),
        }
    }
}

impl std::error::Error for QemuPreflightError {}

pub(crate) fn lossy_excerpt(bytes: &[u8]) -> String {
    let end = bytes.len().min(OUTPUT_EXCERPT_LIMIT);
    let mut excerpt = String::from_utf8_lossy(&bytes[..end]).trim().to_string();
    if bytes.len() > OUTPUT_EXCERPT_LIMIT {
        excerpt.push_str(" ... [truncated]");
    }
    excerpt
}

fn empty_as_placeholder(value: &str) -> &str {
    if value.is_empty() {
        "<empty>"
    } else {
        value
    }
}
