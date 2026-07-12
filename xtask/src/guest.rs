use std::process::Command;

use anyhow::{bail, Result};
use lsb_platform::PlatformSpec;

use crate::args::resolve_platform;
use crate::context::{container_engine, env_value, run_command, workspace_root};

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
        env_value("LSB_GUEST_TARGET").unwrap_or_else(|| platform.guest_target.to_string());
    let workspace_root = workspace_root();
    let guest_binary = workspace_root
        .join("target")
        .join(&guest_target)
        .join("release")
        .join("lsb-guest");

    println!("==> Building lsb-guest for {guest_target}");

    if let Some(builder) = docker_guest_builder(platform, &guest_target) {
        let engine = container_engine(
            "Docker or Podman is required to cross-build the guest binary on this host.",
        )?;
        println!(
            "    Building in {} ({} via {})",
            engine, platform.docker_platform, builder.image
        );
        run_command(
            Command::new(&engine)
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
                .arg("lsb-guest")
                .arg("--target")
                .arg(&guest_target)
                .arg("--release"),
            "build lsb-guest in a container",
        )?;
    } else {
        run_command(
            Command::new("cargo")
                .current_dir(&workspace_root)
                .arg("build")
                .arg("-p")
                .arg("lsb-guest")
                .arg("--target")
                .arg(&guest_target)
                .arg("--release"),
            "build lsb-guest",
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
    if !cfg!(target_os = "linux") {
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
