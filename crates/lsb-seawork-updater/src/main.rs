#[cfg(any(windows, test))]
mod recovery;
#[cfg(windows)]
mod windows;

use anyhow::{bail, Result};
use serde::Serialize;

const UPDATER_SERVICE_NAME: &str = "LocalSandboxSeaWorkUpdater";
const HELPER_PROTOCOL_MAJOR: u16 = 1;
const HELPER_PROTOCOL_MINOR: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Service,
    VersionJson,
    VerifyInstallJson,
}

#[derive(Serialize)]
struct VersionOutput<'a> {
    service_name: &'a str,
    helper_version: &'a str,
    helper_protocol_major: u16,
    helper_protocol_minor: u16,
}

#[derive(Serialize)]
struct VerifyInstallOutput<'a> {
    valid: bool,
    service_name: &'a str,
    helper_version: &'a str,
    helper_protocol_major: u16,
    helper_protocol_minor: u16,
    error: Option<String>,
}

fn main() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match parse_mode(&args)? {
        Mode::Service => run_service(),
        Mode::VersionJson => {
            println!(
                "{}",
                serde_json::to_string(&VersionOutput {
                    service_name: UPDATER_SERVICE_NAME,
                    helper_version: env!("CARGO_PKG_VERSION"),
                    helper_protocol_major: HELPER_PROTOCOL_MAJOR,
                    helper_protocol_minor: HELPER_PROTOCOL_MINOR,
                })?
            );
            Ok(())
        }
        Mode::VerifyInstallJson => {
            let verification = verify_install();
            println!(
                "{}",
                serde_json::to_string(&VerifyInstallOutput {
                    valid: verification.is_ok(),
                    service_name: UPDATER_SERVICE_NAME,
                    helper_version: env!("CARGO_PKG_VERSION"),
                    helper_protocol_major: HELPER_PROTOCOL_MAJOR,
                    helper_protocol_minor: HELPER_PROTOCOL_MINOR,
                    error: verification.as_ref().err().map(ToString::to_string),
                })?
            );
            verification
        }
    }
}

fn parse_mode(args: &[String]) -> Result<Mode> {
    match args {
        [flag] if flag == "--service" => Ok(Mode::Service),
        [flag, json] if flag == "--version" && json == "--json" => Ok(Mode::VersionJson),
        [flag, json] if flag == "--verify-install" && json == "--json" => {
            Ok(Mode::VerifyInstallJson)
        }
        _ => bail!("supported modes: --service, --version --json, --verify-install --json"),
    }
}

#[cfg(windows)]
fn run_service() -> Result<()> {
    windows::dispatch()
}

#[cfg(not(windows))]
fn run_service() -> Result<()> {
    bail!("LocalSandboxSeaWorkUpdater is supported only on x86-64 Windows")
}

#[cfg(windows)]
fn verify_install() -> Result<()> {
    windows::verify_install()
}

#[cfg(not(windows))]
fn verify_install() -> Result<()> {
    bail!("LocalSandboxSeaWorkUpdater installation can be verified only on Windows")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn exposes_only_exact_service_and_bounded_evidence_modes() {
        assert_eq!(parse_mode(&args(&["--service"])).unwrap(), Mode::Service);
        assert_eq!(
            parse_mode(&args(&["--version", "--json"])).unwrap(),
            Mode::VersionJson
        );
        assert_eq!(
            parse_mode(&args(&["--verify-install", "--json"])).unwrap(),
            Mode::VerifyInstallJson
        );
        assert!(parse_mode(&[]).is_err());
        assert!(parse_mode(&args(&["--service", "unexpected"])).is_err());
    }
}
