mod config;
#[cfg(windows)]
pub mod engine;
pub mod ipc;
pub mod ledger;
mod logging;
mod paths;
#[cfg(windows)]
mod pipe;
#[cfg(windows)]
pub mod resource;
#[cfg(windows)]
mod scm;
#[cfg(windows)]
pub mod security;
pub mod session;
#[cfg(windows)]
mod status;
#[cfg(windows)]
pub mod windows;

use anyhow::{bail, Result};
use lsb_service_proto::{CURRENT, SUPPORTED};
use serde::Serialize;

pub const SERVICE_NAME: &str = "LocalSandboxSeaWork";
pub const DISPLAY_NAME: &str = "LocalSandbox for SeaWork";
pub const PIPE_NAME: &str = r"\\.\pipe\LocalSandbox.SeaWork.v1";
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
}

fn main() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [flag, json] if flag == "--version" && json == "--json" => {
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
        [flag, json] if flag == "--verify-bundle" && json == "--json" => {
            println!(
                "{}",
                serde_json::to_string(&VerifyOutput {
                    valid: cfg!(all(windows, target_arch = "x86_64")),
                    mode: "structural-development-check",
                    service_version: env!("CARGO_PKG_VERSION"),
                    protocol_major: CURRENT.major,
                    ledger_schema: LEDGER_SCHEMA_VERSION,
                    architecture: std::env::consts::ARCH,
                })?
            );
            Ok(())
        }
        [] => run_service(),
        [flag] if flag == "--service" => run_service(),
        _ => bail!("supported modes: --service, --version --json, --verify-bundle --json"),
    }
}

#[cfg(windows)]
fn run_service() -> Result<()> {
    scm::dispatch()
}

#[cfg(not(windows))]
fn run_service() -> Result<()> {
    bail!("LocalSandboxSeaWork is supported only on x86-64 Windows")
}
