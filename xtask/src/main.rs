mod args;
mod boot_asset;
mod context;
mod guest;
mod kernel;
mod release;
mod rootfs;
mod seawork_release;

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
    eprintln!("  cargo run -p xtask -- package-release --artifact <cli|os-image|seawork-service> --version <v> [--platform <id>] [--output-dir <dir>] [--mode stage|archive]");
}
