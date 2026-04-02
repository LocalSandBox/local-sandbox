use std::process::Command;

use anyhow::{bail, Result};
use shuru_platform::PlatformSpec;

use crate::args::resolve_platform;
use crate::context::{ensure_docker_available, env_value, is_macos, run_command, workspace_root};

struct DockerGuestBuilder {
    image: &'static str,
    linker_env_name: &'static str,
    linker_bin: &'static str,
}

pub fn build_guest(args: &[String]) -> Result<()> {
    let platform = resolve_platform(args)?;
    build_guest_for_platform(platform)
}

pub fn build_guest_for_platform(platform: &PlatformSpec) -> Result<()> {
    let guest_target =
        env_value("SHURU_GUEST_TARGET").unwrap_or_else(|| platform.guest_target.to_string());
    let workspace_root = workspace_root();
    let guest_binary = workspace_root
        .join("target")
        .join(&guest_target)
        .join("release")
        .join("shuru-guest");

    println!("==> Building shuru-guest for {guest_target}");

    if let Some(builder) = docker_guest_builder(platform, &guest_target) {
        ensure_docker_available(
            "Docker is required to cross-build the guest binary on this host.",
        )?;
        println!(
            "    Building in Docker ({} via {})",
            platform.docker_platform, builder.image
        );
        run_command(
            Command::new("docker")
                .arg("run")
                .arg("--rm")
                .arg("--platform")
                .arg(platform.docker_platform)
                .arg("-e")
                .arg(format!(
                    "{}={}",
                    builder.linker_env_name, builder.linker_bin
                ))
                .arg("-v")
                .arg(format!("{}:/work", workspace_root.display()))
                .arg("-w")
                .arg("/work")
                .arg(builder.image)
                .arg("cargo")
                .arg("build")
                .arg("-p")
                .arg("shuru-guest")
                .arg("--target")
                .arg(&guest_target)
                .arg("--release"),
            "build shuru-guest in Docker",
        )?;
    } else {
        run_command(
            Command::new("cargo")
                .current_dir(&workspace_root)
                .arg("build")
                .arg("-p")
                .arg("shuru-guest")
                .arg("--target")
                .arg(&guest_target)
                .arg("--release"),
            "build shuru-guest",
        )?;
    }

    if !guest_binary.is_file() {
        bail!(
            "guest binary not found after build at {}",
            guest_binary.display()
        );
    }

    println!("    Guest binary ready at {}", guest_binary.display());
    Ok(())
}

fn docker_guest_builder(
    _platform: &PlatformSpec,
    guest_target: &str,
) -> Option<DockerGuestBuilder> {
    if is_macos() {
        return match guest_target {
            "x86_64-unknown-linux-musl" => Some(DockerGuestBuilder {
                image: "messense/rust-musl-cross:x86_64-musl",
                linker_env_name: "CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER",
                linker_bin: "x86_64-unknown-linux-musl-gcc",
            }),
            "aarch64-unknown-linux-musl" => Some(DockerGuestBuilder {
                image: "messense/rust-musl-cross:aarch64-musl",
                linker_env_name: "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER",
                linker_bin: "aarch64-unknown-linux-musl-gcc",
            }),
            _ => None,
        };
    }

    None
}
