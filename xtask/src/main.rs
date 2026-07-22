mod args;
mod boot_asset;
mod context;
mod guest;
mod kernel;
mod release;
mod rootfs;
mod seawork_parity;
mod seawork_release;
mod windows_evidence;

use std::env;

use anyhow::{bail, Result};

fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        print_usage();
        bail!("missing xtask command");
    };

    let rest: Vec<String> = args.collect();
    match command.as_str() {
        "platform-meta" => release::platform_meta(&rest),
        "boot-asset-key" => boot_asset::print_boot_asset_key(&rest),
        "build-guest" => guest::build_guest(&rest),
        "build-kernel" => kernel::build_kernel(&rest),
        "prepare-rootfs" => rootfs::prepare_rootfs(&rest),
        "package-release" => release::package_release(&rest),
        "release" => release::release(&rest),
        "verify-seawork-parity" => seawork_parity::verify(&rest),
        "verify-windows-evidence" => windows_evidence::verify(&rest),
        _ => {
            print_usage();
            bail!("unknown xtask command: {command}");
        }
    }
}

fn print_usage() {
    eprintln!("usage:");
    eprintln!("  cargo run -p xtask -- platform-meta [--platform <id>] [--format json|env] [--version <v>]");
    eprintln!(
        "  cargo run -p xtask -- boot-asset-key [--platform windows-x86_64] [--format plain|env]"
    );
    eprintln!("  cargo run -p xtask -- build-guest [--platform <id>]");
    eprintln!("  cargo run -p xtask -- build-kernel [--platform <id>]");
    eprintln!("  cargo run -p xtask -- prepare-rootfs [--platform <id>]");
    eprintln!("  cargo run -p xtask -- package-release --artifact <cli|os-image|seawork-service|seawork-updater> --version <v> [--platform <id>] [--output-dir <dir>] [--mode stage|archive] [--service-profile production|development]");
    eprintln!("  cargo run -p xtask -- release <current|channel>");
    eprintln!("  cargo run -p xtask -- release prepare <patch|minor|major|SEMVER>");
    eprintln!("  cargo run -p xtask -- release verify [--version <SEMVER>]");
    eprintln!(
        "  cargo run -p xtask -- verify-seawork-parity [--contract <path>] [--seawork-repo <path>]"
    );
    eprintln!(
        "  cargo run -p xtask -- verify-windows-evidence --manifest <path> [--artifact <path>] [--require-profile win01|security|full] [--require-complete]"
    );
}
