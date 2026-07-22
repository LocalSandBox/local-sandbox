mod admission;
mod bundle;
mod config;
#[cfg(windows)]
pub mod engine;
pub mod ipc;
pub mod ledger;
#[cfg(any(windows, test))]
mod logging;
#[cfg(any(windows, test))]
mod maintenance;
mod network_policy;
mod paths;
#[cfg(windows)]
mod pipe;
#[cfg(any(windows, test))]
pub mod resource;
#[cfg(windows)]
mod rpc;
#[cfg(windows)]
mod scm;
#[cfg(windows)]
pub mod security;
pub mod session;
#[cfg(windows)]
mod status;
#[cfg(windows)]
mod update;
#[cfg(windows)]
pub mod windows;

use anyhow::{bail, Result};
use lsb_service_proto::{CURRENT, SUPPORTED};
pub use lsb_service_proto::{PIPE_NAME, SERVICE_NAME};
use serde::Serialize;

#[cfg(windows)]
use windows_sys::Win32::System::LibraryLoader::{
    SetDefaultDllDirectories, LOAD_LIBRARY_SEARCH_SYSTEM32, LOAD_LIBRARY_SEARCH_USER_DIRS,
};

pub const DISPLAY_NAME: &str = "LocalSandbox for SeaWork";
pub const PIPE_SDDL: &str =
    "O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;IU)(A;;0x00000002;;;IU)S:(ML;;NW;;;ME)";
pub const LEDGER_SCHEMA_VERSION: u32 = 1;

#[derive(Serialize)]
struct VersionOutput<'a> {
    service_name: &'a str,
    display_name: &'a str,
    service_version: &'a str,
    protocol_major: u16,
    protocol_minor: u16,
    supported_min_minor: u16,
    supported_max_minor: u16,
    ledger_schema: u32,
}

#[derive(Serialize)]
struct VerifyOutput<'a> {
    valid: bool,
    mode: &'a str,
    service_version: &'a str,
    protocol_major: u16,
    ledger_schema: u32,
    architecture: &'a str,
    files_verified: usize,
    error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Service,
    VersionJson,
    VerifyBundleJson,
}

fn main() -> Result<()> {
    harden_dll_search()?;
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match parse_mode(&args)? {
        Mode::VersionJson => {
            println!(
                "{}",
                serde_json::to_string(&VersionOutput {
                    service_name: SERVICE_NAME,
                    display_name: DISPLAY_NAME,
                    service_version: env!("CARGO_PKG_VERSION"),
                    protocol_major: CURRENT.major,
                    protocol_minor: CURRENT.minor,
                    supported_min_minor: SUPPORTED.min_minor,
                    supported_max_minor: SUPPORTED.max_minor,
                    ledger_schema: LEDGER_SCHEMA_VERSION,
                })?
            );
            Ok(())
        }
        Mode::VerifyBundleJson => {
            let verification = bundle::verify_adjacent_bundle();
            println!(
                "{}",
                serde_json::to_string(&VerifyOutput {
                    valid: verification.is_ok(),
                    mode: "structural-bundle-check",
                    service_version: env!("CARGO_PKG_VERSION"),
                    protocol_major: CURRENT.major,
                    ledger_schema: LEDGER_SCHEMA_VERSION,
                    architecture: std::env::consts::ARCH,
                    files_verified: verification
                        .as_ref()
                        .map_or(0, |report| report.files_verified),
                    error: verification.as_ref().err().map(ToString::to_string),
                })?
            );
            verification.map(|_| ())
        }
        Mode::Service => run_service(),
    }
}

fn parse_mode(args: &[String]) -> Result<Mode> {
    match args {
        [flag] if flag == "--service" => Ok(Mode::Service),
        [flag, json] if flag == "--version" && json == "--json" => Ok(Mode::VersionJson),
        [flag, json] if flag == "--verify-bundle" && json == "--json" => Ok(Mode::VerifyBundleJson),
        _ => bail!("supported modes: --service, --version --json, --verify-bundle --json"),
    }
}

#[cfg(windows)]
fn harden_dll_search() -> Result<()> {
    let flags = LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_USER_DIRS;
    if unsafe { SetDefaultDllDirectories(flags) } == 0 {
        bail!(
            "SetDefaultDllDirectories failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

#[cfg(not(windows))]
fn harden_dll_search() -> Result<()> {
    Ok(())
}

#[cfg(windows)]
fn run_service() -> Result<()> {
    scm::dispatch()
}

#[cfg(not(windows))]
fn run_service() -> Result<()> {
    bail!("LocalSandboxSeaWork is supported only on x86-64 Windows")
}

#[cfg(test)]
mod tests {
    use super::{parse_mode, Mode};

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn service_mode_is_explicit_and_tool_modes_are_exact() {
        assert_eq!(parse_mode(&args(&["--service"])).unwrap(), Mode::Service);
        assert_eq!(
            parse_mode(&args(&["--version", "--json"])).unwrap(),
            Mode::VersionJson
        );
        assert_eq!(
            parse_mode(&args(&["--verify-bundle", "--json"])).unwrap(),
            Mode::VerifyBundleJson
        );
        assert!(parse_mode(&[]).is_err());
        assert!(parse_mode(&args(&["--service", "unexpected"])).is_err());
    }
}
