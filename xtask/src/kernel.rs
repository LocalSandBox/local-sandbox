use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use lsb_platform::PlatformSpec;

use crate::args::resolve_platform;
use crate::context::{
    copy_file, ensure_docker_available, env_value, human_size, is_native_linux_arm64, make_jobs,
    resolved_data_dir, run_command, workspace_root,
};

const DEFAULT_KERNEL_VERSION: &str = "6.12.17";
const KERNEL_BUILD_DOCKER_SCRIPT: &str = r#"set -e
KERNEL_ARCH="${LSB_KERNEL_ARCH:-arm64}"
KERNEL_TARGET="${LSB_KERNEL_TARGET:-Image}"
KERNEL_OUTPUT_RELATIVE_PATH="${LSB_KERNEL_OUTPUT_RELATIVE_PATH:-arch/${KERNEL_ARCH}/boot/Image}"

apt-get update -qq > /dev/null 2>&1
apt-get install -y -qq build-essential bc flex bison libelf-dev libssl-dev > /dev/null 2>&1

cd /src
cp /tmp/lsb_defconfig "arch/${KERNEL_ARCH}/configs/lsb_defconfig"
make ARCH="${KERNEL_ARCH}" lsb_defconfig > /dev/null 2>&1

echo "    Compiling kernel (this takes a few minutes)..."
make ARCH="${KERNEL_ARCH}" -j"$(nproc)" "${KERNEL_TARGET}"

cp "${KERNEL_OUTPUT_RELATIVE_PATH}" /output/Image
"#;

#[derive(Debug, Clone, PartialEq, Eq)]
struct KernelArchiveSource {
    url: String,
    archive_suffix: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KernelBuildLayout {
    defconfig_relpath: &'static str,
    build_target: &'static str,
    output_relpath: &'static str,
}

pub fn build_kernel(args: &[String]) -> Result<()> {
    let platform = resolve_platform(args)?;
    build_kernel_for_platform(platform)
}

pub fn build_kernel_for_platform(platform: &PlatformSpec) -> Result<()> {
    let layout = kernel_build_layout(platform)?;
    let kernel_version =
        env_value("KERNEL_VERSION").unwrap_or_else(|| DEFAULT_KERNEL_VERSION.to_string());
    let kernel_major = kernel_version
        .split('.')
        .next()
        .ok_or_else(|| anyhow!("invalid kernel version: {kernel_version}"))?;
    let data_dir = resolved_data_dir();
    let root = workspace_root();
    let defconfig = root.join(layout.defconfig_relpath);
    let build_dir = data_dir.join("kernel-build");
    let source_dir = build_dir.join(format!("linux-{kernel_version}"));
    let kernel_sources = kernel_archive_sources(&kernel_version, kernel_major);

    println!("==> Building custom kernel {kernel_version} for lsb");

    if !defconfig.is_file() {
        bail!("defconfig not found at {}", defconfig.display());
    }

    fs::create_dir_all(&data_dir)
        .with_context(|| format!("failed to create {}", data_dir.display()))?;

    if !source_dir.is_dir() {
        println!("    Downloading kernel source...");
        fs::create_dir_all(&build_dir)
            .with_context(|| format!("failed to create {}", build_dir.display()))?;
        let archive_path = download_kernel_archive(&kernel_sources, &build_dir, &kernel_version)?;
        println!("    Extracting...");
        run_command(
            Command::new("tar")
                .arg("xf")
                .arg(&archive_path)
                .arg("-C")
                .arg(&build_dir),
            "extract kernel source",
        )?;
        fs::remove_file(&archive_path)
            .with_context(|| format!("failed to remove {}", archive_path.display()))?;
    }

    if is_native_linux_arm64() && platform.kernel_arch == "arm64" {
        println!("    Native aarch64 Linux detected, building without Docker");

        copy_file(
            &defconfig,
            &source_dir.join(format!(
                "arch/{}/configs/lsb_defconfig",
                platform.kernel_arch
            )),
        )?;
        run_command(
            Command::new("make")
                .current_dir(&source_dir)
                .env("ARCH", platform.kernel_arch)
                .arg("lsb_defconfig"),
            "configure kernel build",
        )?;
        println!("    Compiling kernel (this takes a few minutes)...");
        run_command(
            Command::new("make")
                .current_dir(&source_dir)
                .env("ARCH", platform.kernel_arch)
                .arg(format!("-j{}", make_jobs()))
                .arg(layout.build_target),
            "compile kernel image",
        )?;
        copy_file(
            &source_dir.join(layout.output_relpath),
            &data_dir.join("Image"),
        )?;
    } else {
        ensure_docker_available("Docker is required to build the kernel on this host.")?;
        println!(
            "    Building in Docker ({} container)",
            platform.docker_platform
        );
        run_command(
            Command::new("docker")
                .arg("run")
                .arg("--rm")
                .arg("--platform")
                .arg(platform.docker_platform)
                .arg("-e")
                .arg(format!("LSB_KERNEL_ARCH={}", platform.kernel_arch))
                .arg("-e")
                .arg(format!("LSB_KERNEL_TARGET={}", layout.build_target))
                .arg("-e")
                .arg(format!(
                    "LSB_KERNEL_OUTPUT_RELATIVE_PATH={}",
                    layout.output_relpath
                ))
                .arg("-v")
                .arg(format!("{}:/tmp/lsb_defconfig:ro", defconfig.display()))
                .arg("-v")
                .arg(format!("{}:/src:rw", source_dir.display()))
                .arg("-v")
                .arg(format!("{}:/output", data_dir.display()))
                .arg("debian:trixie-slim")
                .arg("/bin/sh")
                .arg("-c")
                .arg(KERNEL_BUILD_DOCKER_SCRIPT),
            "build kernel in Docker",
        )?;
    }

    let kernel_path = data_dir.join("Image");
    println!("    Kernel built: {}", human_size(&kernel_path)?);
    println!("==> Kernel ready at {}", kernel_path.display());
    Ok(())
}

fn kernel_archive_sources(kernel_version: &str, kernel_major: &str) -> Vec<KernelArchiveSource> {
    let xz_archive_name = format!("linux-{kernel_version}.tar.xz");
    let gz_archive_name = format!("linux-{kernel_version}.tar.gz");
    let kernel_dir = format!("v{kernel_major}.x");
    vec![
        KernelArchiveSource {
            url: format!(
                "https://cdn.kernel.org/pub/linux/kernel/{kernel_dir}/{xz_archive_name}"
            ),
            archive_suffix: "tar.xz",
        },
        KernelArchiveSource {
            url: format!("https://mirrors.aliyun.com/linux-kernel/{kernel_dir}/{xz_archive_name}"),
            archive_suffix: "tar.xz",
        },
        KernelArchiveSource {
            url: format!(
                "https://ftp.riken.jp/Linux/kernel.org/linux/kernel/{kernel_dir}/{xz_archive_name}"
            ),
            archive_suffix: "tar.xz",
        },
        KernelArchiveSource {
            url: format!(
                "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/snapshot/{gz_archive_name}"
            ),
            archive_suffix: "tar.gz",
        },
    ]
}

fn download_kernel_archive(
    sources: &[KernelArchiveSource],
    build_dir: &Path,
    kernel_version: &str,
) -> Result<std::path::PathBuf> {
    let mut errors = Vec::new();

    for source in sources {
        let archive_path = build_dir.join(format!(
            "linux-{}.{}",
            kernel_version, source.archive_suffix
        ));
        let tmp_path = archive_path.with_file_name(format!(
            "{}.tmp",
            archive_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("linux-kernel.tar")
        ));

        println!("    Trying {}", source.url);
        let status = Command::new("curl")
            .arg("--fail")
            .arg("--location")
            .arg("--show-error")
            .arg("--silent")
            .arg("-o")
            .arg(&tmp_path)
            .arg(&source.url)
            .status()
            .with_context(|| format!("failed to start curl for {}", source.url))?;

        if status.success() {
            fs::rename(&tmp_path, &archive_path).with_context(|| {
                format!(
                    "failed to move downloaded kernel archive from {} to {}",
                    tmp_path.display(),
                    archive_path.display()
                )
            })?;
            return Ok(archive_path);
        }

        let _ = fs::remove_file(&tmp_path);
        errors.push(format!("{} exited with {status}", source.url));
    }

    bail!(
        "failed to download kernel source from all mirrors:\n       {}",
        errors.join("\n       ")
    )
}

fn kernel_build_layout(platform: &PlatformSpec) -> Result<KernelBuildLayout> {
    match platform.target_arch {
        "aarch64" => Ok(KernelBuildLayout {
            defconfig_relpath: "kernel/lsb_defconfig",
            build_target: "Image",
            output_relpath: "arch/arm64/boot/Image",
        }),
        "x86_64" => Ok(KernelBuildLayout {
            defconfig_relpath: "kernel/lsb_x86_64_defconfig",
            build_target: "bzImage",
            output_relpath: "arch/x86/boot/bzImage",
        }),
        other => bail!("unsupported kernel target architecture: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lsb_platform::platform_by_id;

    #[test]
    fn aarch64_kernel_layout_uses_image() {
        let layout =
            kernel_build_layout(platform_by_id("macos-aarch64").expect("platform should exist"))
                .expect("layout should resolve");

        assert_eq!(
            layout,
            KernelBuildLayout {
                defconfig_relpath: "kernel/lsb_defconfig",
                build_target: "Image",
                output_relpath: "arch/arm64/boot/Image",
            }
        );
    }

    #[test]
    fn x86_64_kernel_layout_uses_bzimage() {
        let layout =
            kernel_build_layout(platform_by_id("macos-x86_64").expect("platform should exist"))
                .expect("layout should resolve");

        assert_eq!(
            layout,
            KernelBuildLayout {
                defconfig_relpath: "kernel/lsb_x86_64_defconfig",
                build_target: "bzImage",
                output_relpath: "arch/x86/boot/bzImage",
            }
        );
    }

    #[test]
    fn kernel_archive_sources_include_primary_mirrors_and_snapshot_fallback() {
        let sources = kernel_archive_sources("6.12.17", "6");

        assert_eq!(
            sources,
            vec![
                KernelArchiveSource {
                    url: "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.12.17.tar.xz"
                        .to_string(),
                    archive_suffix: "tar.xz",
                },
                KernelArchiveSource {
                    url: "https://mirrors.aliyun.com/linux-kernel/v6.x/linux-6.12.17.tar.xz"
                        .to_string(),
                    archive_suffix: "tar.xz",
                },
                KernelArchiveSource {
                    url: "https://ftp.riken.jp/Linux/kernel.org/linux/kernel/v6.x/linux-6.12.17.tar.xz"
                        .to_string(),
                    archive_suffix: "tar.xz",
                },
                KernelArchiveSource {
                    url: "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/snapshot/linux-6.12.17.tar.gz"
                        .to_string(),
                    archive_suffix: "tar.gz",
                },
            ]
        );
    }
}
