use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Result};
use lsb_platform::{default_data_dir, PlatformSpec};

use crate::args::{flag_value, required_flag_value, resolve_platform};
use crate::context::{resolved_data_dir, run_command, workspace_root};

pub fn platform_meta(args: &[String]) -> Result<()> {
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
            if platform.id == "windows-x86_64" {
                payload.insert(
                    "managed_qemu".into(),
                    serde_json::to_value(
                        lsb_platform::windows_x86_64::host_tools::managed_qemu_package_metadata(),
                    )?,
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

pub fn package_release(args: &[String]) -> Result<()> {
    let platform = resolve_platform(args)?;
    let artifact = required_flag_value(args, "--artifact")?;
    let version = required_flag_value(args, "--version")?;
    let root = workspace_root();
    let output_dir = PathBuf::from(flag_value(args, "--output-dir").unwrap_or("."));
    let output_dir = if output_dir.is_absolute() {
        output_dir
    } else {
        root.join(output_dir)
    };

    fs::create_dir_all(&output_dir)?;

    match artifact {
        "cli" => package_cli(platform, version, &root, &output_dir),
        "os-image" => package_os_image(platform, version, &output_dir),
        "seawork-service" => {
            crate::seawork_release::stage_bundle(args, platform, version, &root, &output_dir)
        }
        other => bail!("unsupported --artifact value: {other}"),
    }
}

fn print_env(platform: &PlatformSpec, version: Option<&str>) {
    println!("LSB_PLATFORM_ID={}", platform.id);
    println!("LSB_HOST_TARGET={}", platform.host_target);
    println!("LSB_CLI_BINARY={}", platform.cli_binary_name());
    println!("LSB_GUEST_TARGET={}", platform.guest_target);
    println!("LSB_DOCKER_PLATFORM={}", platform.docker_platform);
    println!("LSB_KERNEL_ARCH={}", platform.kernel_arch);
    println!("LSB_DEBOOTSTRAP_ARCH={}", platform.debootstrap_arch);
    println!("LSB_DEFAULT_DATA_DIR={}", default_data_dir());
    if let Some(entitlements) = platform.codesign_entitlements {
        println!("LSB_CODESIGN_ENTITLEMENTS={entitlements}");
    }
    if let Some(version) = version {
        println!("LSB_RELEASE_TAG={}", platform.release_tag(version));
        println!("LSB_CLI_TARBALL={}", platform.cli_tarball_name(version));
        println!(
            "LSB_OS_IMAGE_TARBALL={}",
            platform.os_image_tarball_name(version)
        );
    }
    if platform.id == "windows-x86_64" {
        let qemu = lsb_platform::windows_x86_64::host_tools::managed_qemu_package_metadata();
        println!("LSB_MANAGED_QEMU_PLATFORM={}", qemu.platform);
        println!("LSB_MANAGED_QEMU_VERSION={}", qemu.qemu_version);
        println!("LSB_MANAGED_QEMU_LSB_VERSION={}", qemu.lsb_version);
        println!(
            "LSB_MANAGED_QEMU_PACKAGE_REVISION={}",
            qemu.package_revision
        );
        println!("LSB_MANAGED_QEMU_PACKAGE_VERSION={}", qemu.package_version);
        println!("LSB_MANAGED_QEMU_RELEASE_TAG={}", qemu.release_tag);
        println!("LSB_MANAGED_QEMU_TARBALL={}", qemu.tarball_name);
        println!("LSB_MANAGED_QEMU_URL={}", qemu.artifact_url);
        println!("LSB_MANAGED_QEMU_SHA256={}", qemu.artifact_sha256);
        println!("LSB_MANAGED_QEMU_TOP_LEVEL_DIR={}", qemu.top_level_dir);
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
        &["-C", "target/release", platform.cli_binary_name()],
    )
}

fn package_os_image(platform: &PlatformSpec, version: &str, output_dir: &Path) -> Result<()> {
    let data_dir = resolved_data_dir();
    let tarball = output_dir.join(platform.os_image_tarball_name(version));
    run_tar(
        &data_dir,
        &tarball,
        &["Image", "initramfs.cpio.gz", "rootfs.ext4"],
    )
}

fn run_tar(base_dir: &Path, tarball: &Path, extra_args: &[&str]) -> Result<()> {
    run_command(
        Command::new("tar")
            .arg("czf")
            .arg(tarball)
            .args(extra_args)
            .current_dir(base_dir),
        &format!("create tarball {}", tarball.display()),
    )
}
