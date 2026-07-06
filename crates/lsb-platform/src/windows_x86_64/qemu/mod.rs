use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;

pub(crate) mod argv;
pub(crate) mod boot;
pub(crate) mod config;
pub(crate) mod discovery;
pub(crate) mod preflight;
pub(crate) mod process;
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
                "Run `lsb init` to install the managed QEMU host tools, set LSB_QEMU to an absolute qemu-system-x86_64.exe path, or add QEMU to PATH."
            }
            Self::EnvQemuPathInvalid { .. } => {
                "Set LSB_QEMU to an existing qemu-system-x86_64.exe path, or unset it to use managed/PATH discovery."
            }
            Self::ConfigQemuPathInvalid { .. } => {
                "Point the LocalSandbox QEMU configuration hook at qemu-system-x86_64.exe, or remove it to use managed/PATH discovery."
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
                "qemu-system-x86_64.exe was not found after checking LSB_QEMU, the LocalSandbox config hook, managed QEMU, and {searched_path_entries} PATH entr{}. {}",
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

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::ffi::OsString;

    use super::discovery::{
        QemuDiscovery, QemuDiscoveryHost, QemuPathSource, StdQemuDiscoveryHost, LSB_QEMU_ENV,
    };
    use super::preflight::{QemuPreflight, PRODUCTION_ACCELERATOR};
    use super::version::{probe_qemu_version, QemuVersion};
    use super::{
        QemuCommandOutput, QemuCommandRunError, QemuCommandRunner, QemuCommandStatus,
        QemuPreflightError, StdQemuCommandRunner,
    };
    use std::path::{Path, PathBuf};

    #[derive(Debug, Clone)]
    struct FakeHost {
        env: HashMap<String, OsString>,
        path_entries: Vec<PathBuf>,
        files: HashSet<PathBuf>,
        managed_qemu_system_path: Option<PathBuf>,
        os: String,
        arch: String,
        windows_major_version: Option<u32>,
    }

    impl FakeHost {
        fn windows() -> Self {
            Self {
                env: HashMap::new(),
                path_entries: Vec::new(),
                files: HashSet::new(),
                managed_qemu_system_path: None,
                os: "windows".to_string(),
                arch: "x86_64".to_string(),
                windows_major_version: Some(11),
            }
        }

        fn with_env(mut self, name: &str, value: impl Into<OsString>) -> Self {
            self.env.insert(name.to_string(), value.into());
            self
        }

        fn with_path_entry(mut self, path: impl Into<PathBuf>) -> Self {
            self.path_entries.push(path.into());
            self
        }

        fn with_file(mut self, path: impl Into<PathBuf>) -> Self {
            self.files.insert(path.into());
            self
        }

        fn with_managed_qemu_system_path(mut self, path: impl Into<PathBuf>) -> Self {
            self.managed_qemu_system_path = Some(path.into());
            self
        }

        fn with_os(mut self, os: &str) -> Self {
            self.os = os.to_string();
            self
        }

        fn with_arch(mut self, arch: &str) -> Self {
            self.arch = arch.to_string();
            self
        }

        fn with_windows_major_version(mut self, version: Option<u32>) -> Self {
            self.windows_major_version = version;
            self
        }
    }

    impl QemuDiscoveryHost for FakeHost {
        fn env_var(&self, name: &str) -> Option<OsString> {
            self.env.get(name).cloned()
        }

        fn path_entries(&self) -> Vec<PathBuf> {
            self.path_entries.clone()
        }

        fn is_file(&self, path: &Path) -> bool {
            self.files.contains(path)
        }

        fn canonicalize(&self, path: &Path) -> Option<PathBuf> {
            Some(path.to_path_buf())
        }

        fn managed_qemu_system_path(&self, _data_dir: &Path) -> Option<PathBuf> {
            self.managed_qemu_system_path.clone()
        }

        fn host_os(&self) -> String {
            self.os.clone()
        }

        fn host_arch(&self) -> String {
            self.arch.clone()
        }

        fn windows_major_version(&self) -> Option<u32> {
            self.windows_major_version
        }
    }

    #[derive(Debug, Default, Clone)]
    struct FakeRunner {
        responses: HashMap<(PathBuf, Vec<String>), Result<QemuCommandOutput, QemuCommandRunError>>,
    }

    impl FakeRunner {
        fn with_success(
            mut self,
            program: &Path,
            args: &[&str],
            stdout: impl Into<Vec<u8>>,
        ) -> Self {
            self.responses.insert(
                key(program, args),
                Ok(QemuCommandOutput {
                    status: QemuCommandStatus {
                        success: true,
                        code: Some(0),
                    },
                    stdout: stdout.into(),
                    stderr: Vec::new(),
                }),
            );
            self
        }

        fn with_failure(
            mut self,
            program: &Path,
            args: &[&str],
            code: i32,
            stderr: impl Into<Vec<u8>>,
        ) -> Self {
            self.responses.insert(
                key(program, args),
                Ok(QemuCommandOutput {
                    status: QemuCommandStatus {
                        success: false,
                        code: Some(code),
                    },
                    stdout: Vec::new(),
                    stderr: stderr.into(),
                }),
            );
            self
        }

        fn with_run_error(
            mut self,
            program: &Path,
            args: &[&str],
            kind: std::io::ErrorKind,
            message: &str,
        ) -> Self {
            self.responses.insert(
                key(program, args),
                Err(QemuCommandRunError {
                    kind,
                    message: message.to_string(),
                }),
            );
            self
        }
    }

    impl QemuCommandRunner for FakeRunner {
        fn run(
            &self,
            program: &Path,
            args: &[&str],
        ) -> Result<QemuCommandOutput, QemuCommandRunError> {
            self.responses
                .get(&key(program, args))
                .cloned()
                .unwrap_or_else(|| {
                    Err(QemuCommandRunError {
                        kind: std::io::ErrorKind::NotFound,
                        message: format!(
                            "missing fake response for {} {:?}",
                            program.display(),
                            args
                        ),
                    })
                })
        }
    }

    fn key(program: &Path, args: &[&str]) -> (PathBuf, Vec<String>) {
        (
            program.to_path_buf(),
            args.iter().map(|arg| (*arg).to_string()).collect(),
        )
    }

    fn qemu_path() -> PathBuf {
        PathBuf::from("/qemu/bin/qemu-system-x86_64.exe")
    }

    fn qemu_dir() -> PathBuf {
        PathBuf::from("/qemu/bin")
    }

    fn working_host() -> FakeHost {
        FakeHost::windows()
            .with_path_entry(qemu_dir())
            .with_file(qemu_path())
    }

    fn working_runner(path: &Path) -> FakeRunner {
        FakeRunner::default()
            .with_success(
                path,
                &["--version"],
                "QEMU emulator version 8.2.1 (v8.2.1)\r\nCopyright...",
            )
            .with_success(
                path,
                &["--help"],
                "QEMU emulator version 8.2.1\r\nusage: qemu-system-x86_64 [options]\r\n",
            )
            .with_success(
                path,
                &["-accel", "help"],
                "Accelerators supported in QEMU binary:\r\nwhpx\r\ntcg\r\n",
            )
    }

    #[test]
    fn discovery_prefers_lsb_qemu_over_config_and_path() {
        let env_path = PathBuf::from("/env/qemu-system-x86_64.exe");
        let config_path = PathBuf::from("/config/qemu-system-x86_64.exe");
        let managed_path = PathBuf::from("/managed/qemu-system-x86_64.exe");
        let path_path = qemu_path();
        let host = FakeHost::windows()
            .with_env(LSB_QEMU_ENV, env_path.as_os_str().to_owned())
            .with_managed_qemu_system_path(managed_path.clone())
            .with_path_entry(qemu_dir())
            .with_file(env_path.clone())
            .with_file(config_path.clone())
            .with_file(managed_path)
            .with_file(path_path);

        let qemu = QemuDiscovery::new(&host)
            .with_configured_qemu(config_path)
            .discover()
            .expect("env path should win");

        assert_eq!(qemu.source, QemuPathSource::Env);
        assert_eq!(qemu.path, env_path);
    }

    #[test]
    fn discovery_uses_config_before_path_when_env_absent() {
        let config_path = PathBuf::from("/config/qemu-system-x86_64.exe");
        let managed_path = PathBuf::from("/managed/qemu-system-x86_64.exe");
        let host = working_host()
            .with_managed_qemu_system_path(managed_path.clone())
            .with_file(config_path.clone())
            .with_file(managed_path);

        let qemu = QemuDiscovery::new(&host)
            .with_configured_qemu(config_path.clone())
            .discover()
            .expect("config path should win over PATH");

        assert_eq!(qemu.source, QemuPathSource::Config);
        assert_eq!(qemu.path, config_path);
    }

    #[test]
    fn discovery_uses_managed_before_path_when_env_and_config_absent() {
        let managed_path = PathBuf::from("/managed/qemu-system-x86_64.exe");
        let path_path = qemu_path();
        let host = FakeHost::windows()
            .with_managed_qemu_system_path(managed_path.clone())
            .with_path_entry(qemu_dir())
            .with_file(managed_path.clone())
            .with_file(path_path);

        let qemu = QemuDiscovery::new(&host)
            .with_managed_data_dir("/data/lsb")
            .discover()
            .expect("managed path should win over PATH");

        assert_eq!(qemu.source, QemuPathSource::Managed);
        assert_eq!(qemu.path, managed_path);
    }

    #[test]
    fn discovery_finds_qemu_on_path_with_spaces() {
        let qemu_dir = PathBuf::from("/Program Files/QEMU");
        let qemu_path = qemu_dir.join("qemu-system-x86_64.exe");
        let host = FakeHost::windows()
            .with_path_entry(qemu_dir)
            .with_file(qemu_path.clone());

        let qemu = QemuDiscovery::new(&host)
            .discover()
            .expect("PATH candidate should be discovered");

        assert_eq!(qemu.source, QemuPathSource::Path);
        assert_eq!(qemu.path, qemu_path);
    }

    #[test]
    fn invalid_lsb_qemu_path_reports_env_error() {
        let bad_path = PathBuf::from("/missing/qemu-system-x86_64.exe");
        let host = FakeHost::windows().with_env(LSB_QEMU_ENV, bad_path.as_os_str().to_owned());

        let err = QemuDiscovery::new(&host)
            .discover()
            .expect_err("invalid env path should fail before PATH");

        assert!(matches!(
            err,
            QemuPreflightError::EnvQemuPathInvalid { ref path, .. } if *path == bad_path
        ));
        assert!(err.to_string().contains("Set LSB_QEMU"));
    }

    #[test]
    fn missing_qemu_reports_path_entry_count_without_dumping_path() {
        let host = FakeHost::windows()
            .with_path_entry("/a")
            .with_path_entry("/b");

        let err = QemuDiscovery::new(&host)
            .discover()
            .expect_err("missing qemu should fail");

        assert!(matches!(
            err,
            QemuPreflightError::QemuNotFound {
                searched_path_entries: 2
            }
        ));
        assert!(!err.to_string().contains("/a"));
        assert!(!err.to_string().contains("/b"));
    }

    #[test]
    fn qemu_version_parser_accepts_standard_version_output() {
        let version = QemuVersion::parse(b"QEMU emulator version 9.1.0 (v9.1.0)\r\nCopyright...")
            .expect("version should parse");

        assert_eq!(version.major, 9);
        assert_eq!(version.minor, 1);
        assert_eq!(version.patch, Some(0));
        assert_eq!(version.raw, "QEMU emulator version 9.1.0 (v9.1.0)");
    }

    #[test]
    fn qemu_version_parser_handles_non_utf8_output_defensively() {
        let mut output = b"qemu-system-x86_64 version 8.2.0".to_vec();
        output.push(0xff);

        let version = QemuVersion::parse(&output).expect("version should parse despite suffix");

        assert_eq!(version.major, 8);
        assert_eq!(version.minor, 2);
        assert_eq!(version.patch, Some(0));
    }

    #[test]
    fn version_probe_reports_unparseable_output() {
        let path = qemu_path();
        let runner =
            FakeRunner::default().with_success(&path, &["--version"], "not a qemu version");

        let err = probe_qemu_version(&runner, &path).expect_err("version parse should fail");

        assert!(matches!(
            err,
            QemuPreflightError::VersionOutputUnparseable { .. }
        ));
        assert!(err.to_string().contains("Install a standard QEMU"));
    }

    #[test]
    fn version_probe_reports_command_execution_failure() {
        let path = qemu_path();
        let runner = FakeRunner::default().with_run_error(
            &path,
            &["--version"],
            std::io::ErrorKind::PermissionDenied,
            "access denied",
        );

        let err = probe_qemu_version(&runner, &path).expect_err("execution should fail");

        assert!(matches!(
            err,
            QemuPreflightError::QemuCannotExecute { probe, .. }
                if probe == "qemu-system-x86_64.exe --version"
        ));
        assert!(err.to_string().contains("could not run"));
    }

    #[test]
    fn preflight_returns_structured_report_when_whpx_is_reported() {
        let path = qemu_path();
        let host = working_host();
        let runner = working_runner(&path);

        let report = QemuPreflight::new(QemuDiscovery::new(&host), &runner)
            .run()
            .expect("preflight should pass");

        assert_eq!(report.qemu.path, path);
        assert_eq!(report.version.major, 8);
        assert_eq!(report.version.minor, 2);
        assert_eq!(report.version.patch, Some(1));
        assert_eq!(report.whpx.required_accelerator, PRODUCTION_ACCELERATOR);
        assert!(report.whpx.reported_by_qemu);
        assert!(report.whpx.limitation.contains("does not start a VM"));
    }

    #[test]
    fn preflight_reports_managed_qemu_source() {
        let path = PathBuf::from("/managed/qemu-system-x86_64.exe");
        let host = FakeHost::windows()
            .with_managed_qemu_system_path(path.clone())
            .with_file(path.clone());
        let runner = working_runner(&path);

        let report = QemuPreflight::new(
            QemuDiscovery::new(&host).with_managed_data_dir("/data/lsb"),
            &runner,
        )
        .run()
        .expect("managed preflight should pass");

        assert_eq!(report.qemu.path, path);
        assert_eq!(report.qemu.source, QemuPathSource::Managed);
    }

    #[test]
    fn preflight_allows_unknown_windows_version_but_marks_it_unverified() {
        let path = qemu_path();
        let host = working_host().with_windows_major_version(None);
        let runner = working_runner(&path);

        let report = QemuPreflight::new(QemuDiscovery::new(&host), &runner)
            .run()
            .expect("unknown Windows version is reported, not fatal");

        assert_eq!(report.host.windows_major_version, None);
        assert!(!report.host.windows_version_verified);
    }

    #[test]
    fn preflight_rejects_non_windows_hosts() {
        let host = working_host().with_os("macos");
        let runner = working_runner(&qemu_path());

        let err = QemuPreflight::new(QemuDiscovery::new(&host), &runner)
            .run()
            .expect_err("non-Windows host should fail");

        assert!(matches!(
            err,
            QemuPreflightError::UnsupportedHostOs { ref actual } if actual == "macos"
        ));
        assert!(err.to_string().contains("Windows 11 x86_64"));
    }

    #[test]
    fn preflight_rejects_non_x86_64_architecture() {
        let host = working_host().with_arch("aarch64");
        let runner = working_runner(&qemu_path());

        let err = QemuPreflight::new(QemuDiscovery::new(&host), &runner)
            .run()
            .expect_err("non-x86_64 host should fail");

        assert!(matches!(
            err,
            QemuPreflightError::UnsupportedArchitecture { actual } if actual == "aarch64"
        ));
    }

    #[test]
    fn preflight_rejects_pre_windows_11_when_version_is_known() {
        let host = working_host().with_windows_major_version(Some(10));
        let runner = working_runner(&qemu_path());

        let err = QemuPreflight::new(QemuDiscovery::new(&host), &runner)
            .run()
            .expect_err("Windows 10 should fail when known");

        assert!(matches!(
            err,
            QemuPreflightError::UnsupportedWindowsVersion { major: 10 }
        ));
        assert!(err.to_string().contains("Upgrade to Windows 11"));
    }

    #[test]
    fn preflight_rejects_unsuitable_binary() {
        let path = PathBuf::from("/qemu/bin/qemu-img.exe");
        let host = FakeHost::windows()
            .with_env(LSB_QEMU_ENV, path.as_os_str().to_owned())
            .with_file(path.clone());
        let runner = FakeRunner::default()
            .with_success(&path, &["--version"], "qemu-img version 8.2.1")
            .with_success(&path, &["--help"], "usage: qemu-img [standard options]");

        let err = QemuPreflight::new(QemuDiscovery::new(&host), &runner)
            .run()
            .expect_err("qemu-img should not pass system emulator preflight");

        assert!(matches!(
            err,
            QemuPreflightError::UnsuitableQemuBinary { .. }
        ));
        assert!(err.to_string().contains("x86_64 system emulation"));
    }

    #[test]
    fn preflight_rejects_qemu_without_whpx_accelerator() {
        let path = qemu_path();
        let host = working_host();
        let runner = FakeRunner::default()
            .with_success(&path, &["--version"], "QEMU emulator version 8.2.1")
            .with_success(
                &path,
                &["--help"],
                "usage: qemu-system-x86_64 [options]\r\n",
            )
            .with_success(
                &path,
                &["-accel", "help"],
                "Accelerators supported in QEMU binary:\r\ntcg\r\n",
            );

        let err = QemuPreflight::new(QemuDiscovery::new(&host), &runner)
            .run()
            .expect_err("missing WHPX should fail");

        assert!(matches!(err, QemuPreflightError::WhpxUnavailable { .. }));
        assert!(err
            .to_string()
            .contains("enable Windows Hypervisor Platform"));
    }

    #[test]
    fn preflight_reports_nonzero_accelerator_probe_as_whpx_unavailable() {
        let path = qemu_path();
        let host = working_host();
        let runner = FakeRunner::default()
            .with_success(&path, &["--version"], "QEMU emulator version 8.2.1")
            .with_success(
                &path,
                &["--help"],
                "usage: qemu-system-x86_64 [options]\r\n",
            )
            .with_failure(&path, &["-accel", "help"], 1, "unknown option");

        let err = QemuPreflight::new(QemuDiscovery::new(&host), &runner)
            .run()
            .expect_err("accelerator help failure should be actionable");

        assert!(matches!(err, QemuPreflightError::WhpxUnavailable { .. }));
    }

    #[test]
    #[ignore = "requires Windows 11 x86_64 with managed or override QEMU available; set LSB_TEST_REAL_QEMU=1"]
    fn real_qemu_preflight_when_explicitly_enabled() {
        if std::env::var("LSB_TEST_REAL_QEMU").ok().as_deref() != Some("1") {
            eprintln!("skipping real QEMU preflight; set LSB_TEST_REAL_QEMU=1 to enable");
            return;
        }

        let host = StdQemuDiscoveryHost;
        let runner = StdQemuCommandRunner;
        let report = QemuPreflight::new(QemuDiscovery::new(&host), &runner)
            .run()
            .expect("real QEMU preflight should pass");

        assert_eq!(report.whpx.required_accelerator, PRODUCTION_ACCELERATOR);
    }
}
