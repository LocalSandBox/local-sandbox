use std::fs;
use std::process::Command;

use anyhow::{bail, Context, Result};
use lsb_platform::PlatformSpec;

use crate::args::resolve_platform;
use crate::context::{
    command_exists, create_mount_dir, ensure_docker_available, ensure_linux_rootfs_prerequisites,
    env_value, is_macos, resolved_data_dir, run_command, workspace_root,
};
use crate::guest::build_guest_for_platform;
use crate::kernel::build_kernel_for_platform;

const DEFAULT_DEBIAN_RELEASE: &str = "trixie";
const DEFAULT_ROOTFS_SIZE_MB: u64 = 1024;
const DEFAULT_CODESIGN_ENTITLEMENTS: &str = "lsb.entitlements";
const INITRAMFS_DOCKER_SCRIPT: &str = r#"set -e
apt-get update -qq > /dev/null 2>&1
apt-get install -y -qq busybox-static e2fsprogs pax-utils cpio > /dev/null 2>&1

mkdir -p /initramfs/bin /initramfs/sbin /initramfs/usr/sbin
mkdir -p /initramfs/proc /initramfs/dev /initramfs/newroot

cp /bin/busybox /initramfs/bin/busybox
mkdir -p /initramfs/etc
for cmd in sh mount umount switch_root cp chmod echo ifconfig route cat; do
    ln -sf busybox "/initramfs/bin/${cmd}"
done

lddtree -l /sbin/e2fsck /usr/sbin/resize2fs | sort -u | cpio --quiet -pmdL /initramfs

cp /tmp/lsb-init /initramfs/bin/lsb-init
chmod 755 /initramfs/bin/lsb-init

cat > /initramfs/init <<'INITEOF'
#!/bin/sh
mount -t proc none /proc
mount -t devtmpfs none /dev
/sbin/e2fsck -p /dev/vda > /dev/null 2>&1 || true
/usr/sbin/resize2fs /dev/vda > /dev/null 2>&1 || true
mount -t ext4 /dev/vda /newroot
cp /bin/lsb-init /newroot/usr/bin/lsb-init
chmod 755 /newroot/usr/bin/lsb-init
if ifconfig eth0 up 2>/dev/null; then
    ifconfig eth0 10.0.0.2 netmask 255.255.255.0 up
    route add default gw 10.0.0.1
    echo "nameserver 10.0.0.1" > /newroot/etc/resolv.conf
fi
umount /proc
exec switch_root /newroot /usr/bin/lsb-init
INITEOF

chmod 755 /initramfs/init
cd /initramfs
find . | cpio -o -H newc 2>/dev/null | gzip > /output/initramfs.cpio.gz
"#;
const MACOS_ROOTFS_DOCKER_SCRIPT: &str = r#"set -e
apt-get update -qq
apt-get install -y -qq debootstrap e2fsprogs > /dev/null 2>&1

mkfs.ext4 -F -E lazy_itable_init=0 /rootfs.ext4
mkdir -p /mnt/rootfs
mount -o loop /rootfs.ext4 /mnt/rootfs

echo "==> Running debootstrap (this may take a few minutes)..."
debootstrap --arch="${DEBOOTSTRAP_ARCH}" --variant=minbase "${DEBIAN_RELEASE}" /mnt/rootfs http://deb.debian.org/debian

mkdir -p /mnt/rootfs/etc/dpkg/dpkg.cfg.d
cat > /mnt/rootfs/etc/dpkg/dpkg.cfg.d/01-nodoc <<'DPKGEOF'
path-exclude /usr/share/doc/*
path-exclude /usr/share/man/*
path-exclude /usr/share/info/*
path-exclude /usr/share/locale/*
path-include /usr/share/locale/en*
DPKGEOF

chroot /mnt/rootfs apt-get update -qq
chroot /mnt/rootfs apt-get install -y -qq --no-install-recommends \
    ca-certificates curl git iproute2 \
    openssh-client jq less procps xz-utils libgomp1 libatomic1 > /dev/null 2>&1

rm -rf /mnt/rootfs/usr/share/doc/* /mnt/rootfs/usr/share/man/* /mnt/rootfs/usr/share/info/*
find /mnt/rootfs/usr/share/locale -mindepth 1 -maxdepth 1 ! -name "en*" -exec rm -rf {} + 2>/dev/null || true

chroot /mnt/rootfs apt-get clean
rm -rf /mnt/rootfs/var/lib/apt/lists/*

cp /tmp/lsb-guest /mnt/rootfs/usr/bin/lsb-init
chmod 755 /mnt/rootfs/usr/bin/lsb-init

mkdir -p /mnt/rootfs/proc /mnt/rootfs/sys /mnt/rootfs/dev /mnt/rootfs/tmp /mnt/rootfs/run
echo "lsb" > /mnt/rootfs/etc/hostname
echo "nameserver 8.8.8.8" > /mnt/rootfs/etc/resolv.conf

umount /mnt/rootfs
echo "==> Debian rootfs populated successfully"
"#;
const LINUX_ROOTFS_SCRIPT: &str = r#"set -e
mount -o loop "$ROOTFS_IMG" "$MOUNT_DIR"
cleanup() {
    umount "$MOUNT_DIR" 2>/dev/null || true
    rmdir "$MOUNT_DIR" 2>/dev/null || true
}
trap cleanup EXIT

echo "==> Running debootstrap (this may take a few minutes)..."
debootstrap --arch="$DEBOOTSTRAP_ARCH" --variant=minbase "$DEBIAN_RELEASE" "$MOUNT_DIR" http://deb.debian.org/debian

mkdir -p "$MOUNT_DIR/etc/dpkg/dpkg.cfg.d"
cat > "$MOUNT_DIR/etc/dpkg/dpkg.cfg.d/01-nodoc" <<'DPKGEOF'
path-exclude /usr/share/doc/*
path-exclude /usr/share/man/*
path-exclude /usr/share/info/*
path-exclude /usr/share/locale/*
path-include /usr/share/locale/en*
DPKGEOF

chroot "$MOUNT_DIR" apt-get update -qq
chroot "$MOUNT_DIR" apt-get install -y -qq --no-install-recommends \
    ca-certificates curl git iproute2 \
    openssh-client jq less procps xz-utils libgomp1 libatomic1 \
    nodejs ffmpeg > /dev/null 2>&1

rm -rf "$MOUNT_DIR"/usr/share/doc/* "$MOUNT_DIR"/usr/share/man/* "$MOUNT_DIR"/usr/share/info/*
find "$MOUNT_DIR/usr/share/locale" -mindepth 1 -maxdepth 1 ! -name "en*" -exec rm -rf {} + 2>/dev/null || true

chroot "$MOUNT_DIR" apt-get clean
rm -rf "$MOUNT_DIR"/var/lib/apt/lists/*

cp "$GUEST_BINARY" "$MOUNT_DIR/usr/bin/lsb-init"
chmod 755 "$MOUNT_DIR/usr/bin/lsb-init"

mkdir -p "$MOUNT_DIR/proc" "$MOUNT_DIR/sys" "$MOUNT_DIR/dev" "$MOUNT_DIR/tmp" "$MOUNT_DIR/run"
echo "lsb" > "$MOUNT_DIR/etc/hostname"
echo "nameserver 8.8.8.8" > "$MOUNT_DIR/etc/resolv.conf"

echo "==> Debian rootfs populated successfully"
"#;

fn should_use_docker_rootfs() -> bool {
    env_value("LSB_FORCE_DOCKER_ROOTFS")
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or_else(is_macos)
}

pub fn prepare_rootfs(args: &[String]) -> Result<()> {
    let platform = resolve_platform(args)?;
    prepare_rootfs_for_platform(platform)
}

pub fn prepare_rootfs_for_platform(platform: &PlatformSpec) -> Result<()> {
    let data_dir = resolved_data_dir();
    let rootfs_img = data_dir.join("rootfs.ext4");
    let kernel_path = data_dir.join("Image");
    let initramfs_path = data_dir.join("initramfs.cpio.gz");
    let guest_target =
        env_value("LSB_GUEST_TARGET").unwrap_or_else(|| platform.guest_target.to_string());
    let guest_binary = workspace_root()
        .join("target")
        .join(&guest_target)
        .join("release")
        .join("lsb-guest");
    if !guest_binary.is_file() {
        println!("==> Guest binary missing. Building it first...");
        build_guest_for_platform(platform)?;
    }
    let guest_binary = if guest_binary.is_file() {
        fs::canonicalize(&guest_binary)
            .with_context(|| format!("failed to canonicalize {}", guest_binary.display()))?
    } else {
        bail!(
            "guest binary not found at {}\n       Run: cargo build -p lsb-guest --target {} --release",
            guest_binary.display(),
            guest_target
        );
    };
    let codesign_entitlements = platform
        .codesign_entitlements
        .unwrap_or(DEFAULT_CODESIGN_ENTITLEMENTS);

    println!("==> lsb rootfs preparation");
    println!("    Debian {} (kernel + rootfs)", DEFAULT_DEBIAN_RELEASE);
    println!();

    if is_macos() && !command_exists("docker") {
        bail!(
            "Docker is required on macOS to create ext4 images.\n       Install Docker Desktop or use: brew install --cask docker"
        );
    }

    fs::create_dir_all(&data_dir)
        .with_context(|| format!("failed to create {}", data_dir.display()))?;

    if !kernel_path.is_file() {
        build_kernel_for_platform(platform)?;
    } else {
        println!("==> Kernel already present.");
    }

    if !initramfs_path.is_file() {
        ensure_docker_available("Docker is required to build the initramfs.")?;
        println!("==> Building minimal initramfs...");
        run_command(
            Command::new("docker")
                .arg("run")
                .arg("--rm")
                .arg("--platform")
                .arg(platform.docker_platform)
                .arg("-v")
                .arg(format!("{}:/output", data_dir.display()))
                .arg("-v")
                .arg(format!("{}:/tmp/lsb-init:ro", guest_binary.display()))
                .arg(format!("debian:{DEFAULT_DEBIAN_RELEASE}-slim"))
                .arg("/bin/sh")
                .arg("-c")
                .arg(INITRAMFS_DOCKER_SCRIPT),
            "build initramfs in Docker",
        )?;
        println!("    Initramfs saved to {}", initramfs_path.display());
    } else {
        println!("==> Initramfs already present.");
    }

    if rootfs_img.is_file() {
        println!("==> Rootfs already present.");
    } else {
        println!(
            "==> Creating ext4 rootfs image ({}MB) with Debian {}...",
            DEFAULT_ROOTFS_SIZE_MB, DEFAULT_DEBIAN_RELEASE
        );
        run_command(
            Command::new("truncate")
                .arg("-s")
                .arg(format!("{DEFAULT_ROOTFS_SIZE_MB}M"))
                .arg(&rootfs_img),
            "create rootfs image file",
        )?;

        if should_use_docker_rootfs() {
            println!();
            println!("==> Using Docker for ext4 formatting and Debian bootstrap.");
            println!();
            ensure_docker_available("Docker is required to prepare the rootfs.")?;
            run_command(
                Command::new("docker")
                    .arg("run")
                    .arg("--rm")
                    .arg("--privileged")
                    .arg("--platform")
                    .arg(platform.docker_platform)
                    .arg("-e")
                    .arg(format!("DEBIAN_RELEASE={DEFAULT_DEBIAN_RELEASE}"))
                    .arg("-e")
                    .arg(format!("DEBOOTSTRAP_ARCH={}", platform.debootstrap_arch))
                    .arg("-v")
                    .arg(format!("{}:/rootfs.ext4", rootfs_img.display()))
                    .arg("-v")
                    .arg(format!("{}:/tmp/lsb-guest:ro", guest_binary.display()))
                    .arg(format!("debian:{DEFAULT_DEBIAN_RELEASE}-slim"))
                    .arg("/bin/sh")
                    .arg("-c")
                    .arg(MACOS_ROOTFS_DOCKER_SCRIPT),
                "prepare rootfs in Docker",
            )?;
        } else {
            ensure_linux_rootfs_prerequisites()?;
            let mount_dir = create_mount_dir()?;
            run_command(
                Command::new("sudo")
                    .arg("env")
                    .arg(format!("ROOTFS_IMG={}", rootfs_img.display()))
                    .arg(format!("MOUNT_DIR={}", mount_dir.display()))
                    .arg(format!("DEBIAN_RELEASE={DEFAULT_DEBIAN_RELEASE}"))
                    .arg(format!("DEBOOTSTRAP_ARCH={}", platform.debootstrap_arch))
                    .arg(format!("GUEST_BINARY={}", guest_binary.display()))
                    .arg("/bin/sh")
                    .arg("-c")
                    .arg(LINUX_ROOTFS_SCRIPT),
                "prepare rootfs on Linux",
            )?;
        }
    }

    println!();
    println!("==> Done!");
    println!("    Kernel:     {}", kernel_path.display());
    println!("    Initramfs:  {}", initramfs_path.display());
    println!("    Rootfs:     {}", rootfs_img.display());
    println!();
    println!(
        "    To run:  cargo build -p lsb-cli && codesign --entitlements {} --force -s - target/debug/lsb",
        codesign_entitlements
    );
    println!("             ./target/debug/lsb run -- echo hello");

    Ok(())
}
