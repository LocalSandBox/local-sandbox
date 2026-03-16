use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use shuru_platform::{default_data_dir, platform_by_id, PlatformSpec};

fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        print_usage();
        bail!("missing xtask command");
    };

    let rest: Vec<String> = args.collect();
    match command.as_str() {
        "platform-meta" => platform_meta(&rest),
        "build-kernel" => run_script("scripts/build-kernel.sh", &rest),
        "prepare-rootfs" => run_script("scripts/prepare-rootfs.sh", &rest),
        "package-release" => package_release(&rest),
        _ => {
            print_usage();
            bail!("unknown xtask command: {command}");
        }
    }
}

fn print_usage() {
    eprintln!("usage:");
    eprintln!("  cargo run -p xtask -- platform-meta [--platform <id>] [--format json|env] [--version <v>]");
    eprintln!("  cargo run -p xtask -- build-kernel [--platform <id>]");
    eprintln!("  cargo run -p xtask -- prepare-rootfs [--platform <id>]");
    eprintln!("  cargo run -p xtask -- package-release --artifact <cli|os-image> --version <v> [--platform <id>] [--output-dir <dir>]");
}

fn resolve_platform(args: &[String]) -> Result<&'static PlatformSpec> {
    let platform_id = flag_value(args, "--platform").unwrap_or("macos-aarch64");
    platform_by_id(platform_id).ok_or_else(|| anyhow!("unknown platform id: {platform_id}"))
}

fn platform_meta(args: &[String]) -> Result<()> {
    let platform = resolve_platform(args)?;
    let version = flag_value(args, "--version");
    let format = flag_value(args, "--format").unwrap_or("json");

    match format {
        "json" => {
            let mut payload = serde_json::Map::new();
            payload.insert("platform".into(), serde_json::to_value(platform)?);
            if let Some(version) = version {
                payload.insert(
                    "cli_tarball".into(),
                    serde_json::Value::String(platform.cli_tarball_name(version)),
                );
                payload.insert(
                    "os_image_tarball".into(),
                    serde_json::Value::String(platform.os_image_tarball_name(version)),
                );
                payload.insert(
                    "release_tag".into(),
                    serde_json::Value::String(platform.release_tag(version)),
                );
            }
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
        "env" => {
            print_env(platform, version);
        }
        other => bail!("unsupported --format value: {other}"),
    }

    Ok(())
}

fn print_env(platform: &PlatformSpec, version: Option<&str>) {
    println!("SHURU_PLATFORM_ID={}", platform.id);
    println!("SHURU_HOST_TARGET={}", platform.host_target);
    println!("SHURU_GUEST_TARGET={}", platform.guest_target);
    println!("SHURU_DOCKER_PLATFORM={}", platform.docker_platform);
    println!("SHURU_KERNEL_ARCH={}", platform.kernel_arch);
    println!("SHURU_DEBOOTSTRAP_ARCH={}", platform.debootstrap_arch);
    println!("SHURU_DEFAULT_DATA_DIR={}", default_data_dir());
    if let Some(entitlements) = platform.codesign_entitlements {
        println!("SHURU_CODESIGN_ENTITLEMENTS={entitlements}");
    }
    if let Some(version) = version {
        println!("SHURU_RELEASE_TAG={}", platform.release_tag(version));
        println!("SHURU_CLI_TARBALL={}", platform.cli_tarball_name(version));
        println!(
            "SHURU_OS_IMAGE_TARBALL={}",
            platform.os_image_tarball_name(version)
        );
    }
}

fn run_script(script: &str, args: &[String]) -> Result<()> {
    let platform = resolve_platform(args)?;
    let root = workspace_root();
    let script_path = root.join(script);

    let status = Command::new(&script_path)
        .current_dir(&root)
        .env("SHURU_PLATFORM_ID", platform.id)
        .env("SHURU_GUEST_TARGET", platform.guest_target)
        .env("SHURU_DOCKER_PLATFORM", platform.docker_platform)
        .env("SHURU_KERNEL_ARCH", platform.kernel_arch)
        .env("SHURU_DEBOOTSTRAP_ARCH", platform.debootstrap_arch)
        .env("SHURU_DEFAULT_DATA_DIR", default_data_dir())
        .env(
            "SHURU_CODESIGN_ENTITLEMENTS",
            platform.codesign_entitlements.unwrap_or(""),
        )
        .status()
        .with_context(|| format!("failed to run {}", script_path.display()))?;

    if !status.success() {
        bail!("{} exited with {}", script_path.display(), status);
    }

    Ok(())
}

fn package_release(args: &[String]) -> Result<()> {
    let platform = resolve_platform(args)?;
    let artifact = required_flag_value(args, "--artifact")?;
    let version = required_flag_value(args, "--version")?;
    let output_dir = PathBuf::from(flag_value(args, "--output-dir").unwrap_or("."));
    let root = workspace_root();

    std::fs::create_dir_all(&output_dir)
        .with_context(|| format!("failed to create {}", output_dir.display()))?;

    match artifact {
        "cli" => package_cli(platform, version, &root, &output_dir),
        "os-image" => package_os_image(platform, version, &output_dir),
        other => bail!("unsupported --artifact value: {other}"),
    }
}

fn package_cli(
    platform: &PlatformSpec,
    version: &str,
    root: &Path,
    output_dir: &Path,
) -> Result<()> {
    let tarball = output_dir.join(platform.cli_tarball_name(version));
    run_tar(
        root,
        &tarball,
        &["-C", "target/release", "shuru"],
    )
}

fn package_os_image(platform: &PlatformSpec, version: &str, output_dir: &Path) -> Result<()> {
    let data_dir = PathBuf::from(default_data_dir());
    let tarball = output_dir.join(platform.os_image_tarball_name(version));
    run_tar(
        &data_dir,
        &tarball,
        &["Image", "initramfs.cpio.gz", "rootfs.ext4"],
    )
}

fn run_tar(base_dir: &Path, tarball: &Path, extra_args: &[&str]) -> Result<()> {
    let mut command = Command::new("tar");
    command.arg("czf").arg(tarball).args(extra_args).current_dir(base_dir);
    let status = command
        .status()
        .with_context(|| format!("failed to run tar for {}", tarball.display()))?;
    if !status.success() {
        bail!("tar exited with {}", status);
    }
    Ok(())
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask has a workspace root")
        .to_path_buf()
}

fn flag_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].as_str())
}

fn required_flag_value<'a>(args: &'a [String], flag: &str) -> Result<&'a str> {
    flag_value(args, flag).ok_or_else(|| anyhow!("missing required flag: {flag}"))
}
