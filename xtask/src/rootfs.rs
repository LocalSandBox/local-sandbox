use std::fs;
use std::process::Command;

use anyhow::{bail, Context, Result};
use lsb_platform::PlatformSpec;

use crate::args::resolve_platform;
use crate::context::{
    container_engine, container_engine_available, create_mount_dir,
    ensure_linux_rootfs_prerequisites, env_value, is_macos, resolved_data_dir, run_command,
    workspace_root,
};
use crate::guest::build_guest_for_platform;
use crate::kernel::build_kernel_for_platform;

const DEFAULT_DEBIAN_RELEASE: &str = "trixie";
const DEFAULT_CONFLUENCE_CLI_VERSION: &str = "2.8.0";
const DEFAULT_PCHURI_JIRA_CLI_VERSION: &str = "2.8.0";
const DEFAULT_OFFICEPARSER_VERSION: &str = "7.1.0";
const DEFAULT_XLSX_VERSION: &str = "0.18.5";
const DEFAULT_DOCX_VERSION: &str = "9.7.1";
const DEFAULT_NODE_VERSION: &str = "v24.16.0";
const DEFAULT_ROOTFS_SIZE_MB: u64 = 2048;
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
const MACOS_ROOTFS_DOCKER_SCRIPT_PREFIX: &str = r#"set -e
apt-get update -qq
apt-get install -y -qq ca-certificates curl debootstrap e2fsprogs xz-utils > /dev/null 2>&1

mkdir -p /mnt/rootfs

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
    openssh-client jq less procps xz-utils libgomp1 libatomic1 \
    cifs-utils e2fsprogs > /dev/null 2>&1
test -x /mnt/rootfs/sbin/mount.cifs || test -x /mnt/rootfs/usr/sbin/mount.cifs
test -x /mnt/rootfs/sbin/mkfs.ext4 || test -x /mnt/rootfs/usr/sbin/mkfs.ext4

ROOTFS_DIR="/mnt/rootfs"
"#;
const ROOTFS_TOOLCHAIN_INSTALL_SCRIPT: &str = r#"
TOOLCHAIN_TMP_DIRS=""

track_toolchain_tmp_dir() {
    TOOLCHAIN_TMP_DIRS="${TOOLCHAIN_TMP_DIRS} $1"
}

cleanup_toolchain_tmp_dirs() {
    if [ -n "${TOOLCHAIN_TMP_DIRS}" ]; then
        rm -rf ${TOOLCHAIN_TMP_DIRS}
        TOOLCHAIN_TMP_DIRS=""
    fi
}

install_nodejs() {
    install_rootfs_dir="$1"
    case "${DEBOOTSTRAP_ARCH}" in
        amd64) node_arch="x64" ;;
        arm64) node_arch="arm64" ;;
        *) echo "unsupported Node.js architecture: ${DEBOOTSTRAP_ARCH}" >&2; exit 1 ;;
    esac

    echo "==> Installing Node.js ${NODE_VERSION}..."
    node_dist="node-${NODE_VERSION}-linux-${node_arch}"
    node_tarball="${node_dist}.tar.xz"
    node_url="https://nodejs.org/dist/${NODE_VERSION}"
    node_tmp="$(mktemp -d)"
    track_toolchain_tmp_dir "${node_tmp}"
    curl -fsSLo "${node_tmp}/${node_tarball}" "${node_url}/${node_tarball}"
    curl -fsSLo "${node_tmp}/SHASUMS256.txt" "${node_url}/SHASUMS256.txt"
    checksum_line="$(grep "  ${node_tarball}$" "${node_tmp}/SHASUMS256.txt")"
    (cd "${node_tmp}" && printf '%s\n' "${checksum_line}" | sha256sum -c -)
    mkdir -p "${install_rootfs_dir}/usr/local"
    tar -xJf "${node_tmp}/${node_tarball}" -C "${install_rootfs_dir}/usr/local" --strip-components=1
    for binary in node npm npx corepack; do
        if [ -e "${install_rootfs_dir}/usr/local/bin/${binary}" ]; then
            ln -sf "/usr/local/bin/${binary}" "${install_rootfs_dir}/usr/bin/${binary}"
        fi
    done
    chroot "${install_rootfs_dir}" /usr/bin/node --version | grep -Fx "${NODE_VERSION}" > /dev/null
    chroot "${install_rootfs_dir}" /usr/bin/npm --version > /dev/null
}

configure_node_extra_ca_certs() {
    install_rootfs_dir="$1"
    mkdir -p "${install_rootfs_dir}/root"
    printf '%s\n' 'export NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/lsb-proxy.crt' >> "${install_rootfs_dir}/root/.bashrc"
}

install_google_workspace_cli() {
    install_rootfs_dir="$1"
    echo "==> Installing @googleworkspace/cli..."
    chroot "${install_rootfs_dir}" /usr/bin/npm install -g @googleworkspace/cli
    chroot "${install_rootfs_dir}" /usr/bin/npm list -g @googleworkspace/cli > /dev/null
    test -x "${install_rootfs_dir}/usr/local/bin/gws"
    ln -sf "/usr/local/bin/gws" "${install_rootfs_dir}/usr/bin/gws"
    chroot "${install_rootfs_dir}" /usr/bin/gws --help > /dev/null
}

install_atlassian_node_clis() {
    install_rootfs_dir="$1"
    echo "==> Installing @pchuri/jira-cli ${PCHURI_JIRA_CLI_VERSION}..."
    chroot "${install_rootfs_dir}" /usr/bin/npm install -g "@pchuri/jira-cli@${PCHURI_JIRA_CLI_VERSION}"
    chroot "${install_rootfs_dir}" /usr/bin/npm list -g "@pchuri/jira-cli@${PCHURI_JIRA_CLI_VERSION}" > /dev/null
    test -x "${install_rootfs_dir}/usr/local/bin/jira"
    ln -sf "/usr/local/bin/jira" "${install_rootfs_dir}/usr/bin/jira"
    chroot "${install_rootfs_dir}" /usr/bin/jira --help > /dev/null

    echo "==> Installing confluence-cli ${CONFLUENCE_CLI_VERSION}..."
    chroot "${install_rootfs_dir}" /usr/bin/npm install -g "confluence-cli@${CONFLUENCE_CLI_VERSION}"
    chroot "${install_rootfs_dir}" /usr/bin/npm list -g "confluence-cli@${CONFLUENCE_CLI_VERSION}" > /dev/null
    test -x "${install_rootfs_dir}/usr/local/bin/confluence"
    ln -sf "/usr/local/bin/confluence" "${install_rootfs_dir}/usr/bin/confluence"
    chroot "${install_rootfs_dir}" /usr/bin/confluence --help > /dev/null
    if [ -e "${install_rootfs_dir}/usr/local/bin/confluence-cli" ]; then
        ln -sf "/usr/local/bin/confluence-cli" "${install_rootfs_dir}/usr/bin/confluence-cli"
    fi
}

install_officeparser() {
    install_rootfs_dir="$1"
    echo "==> Installing officeparser ${OFFICEPARSER_VERSION}..."
    chroot "${install_rootfs_dir}" /usr/bin/npm install -g "officeparser@${OFFICEPARSER_VERSION}"
    chroot "${install_rootfs_dir}" /usr/bin/npm list -g "officeparser@${OFFICEPARSER_VERSION}" > /dev/null
    test -x "${install_rootfs_dir}/usr/local/bin/officeparser"
    ln -sf "/usr/local/bin/officeparser" "${install_rootfs_dir}/usr/bin/officeparser"
    chroot "${install_rootfs_dir}" /usr/bin/officeparser > /dev/null
}

install_document_node_packages() {
    install_rootfs_dir="$1"
    echo "==> Installing xlsx ${XLSX_VERSION}..."
    chroot "${install_rootfs_dir}" /usr/bin/npm install -g "xlsx@${XLSX_VERSION}"
    chroot "${install_rootfs_dir}" /usr/bin/npm list -g "xlsx@${XLSX_VERSION}" > /dev/null

    echo "==> Installing docx ${DOCX_VERSION}..."
    chroot "${install_rootfs_dir}" /usr/bin/npm install -g "docx@${DOCX_VERSION}"
    chroot "${install_rootfs_dir}" /usr/bin/npm list -g "docx@${DOCX_VERSION}" > /dev/null
}

install_rootfs_toolchains() {
    install_rootfs_dir="$1"
    install_nodejs "${install_rootfs_dir}"
    configure_node_extra_ca_certs "${install_rootfs_dir}"
    install_google_workspace_cli "${install_rootfs_dir}"
    install_atlassian_node_clis "${install_rootfs_dir}"
    install_officeparser "${install_rootfs_dir}"
    install_document_node_packages "${install_rootfs_dir}"
}

install_rootfs_toolchains "${ROOTFS_DIR}"
cleanup_toolchain_tmp_dirs
"#;
const MACOS_ROOTFS_DOCKER_SCRIPT_SUFFIX: &str = r#"

rm -rf /mnt/rootfs/usr/share/doc/* /mnt/rootfs/usr/share/man/* /mnt/rootfs/usr/share/info/*
find /mnt/rootfs/usr/share/locale -mindepth 1 -maxdepth 1 ! -name "en*" -exec rm -rf {} + 2>/dev/null || true

chroot /mnt/rootfs apt-get clean
rm -rf /mnt/rootfs/var/lib/apt/lists/*

cp /tmp/lsb-guest /mnt/rootfs/usr/bin/lsb-init
chmod 755 /mnt/rootfs/usr/bin/lsb-init

mkdir -p /mnt/rootfs/proc /mnt/rootfs/sys /mnt/rootfs/dev /mnt/rootfs/tmp /mnt/rootfs/run
echo "lsb" > /mnt/rootfs/etc/hostname
echo "nameserver 8.8.8.8" > /mnt/rootfs/etc/resolv.conf

cd /
sync
mkfs.ext4 -F -E lazy_itable_init=0 -d /mnt/rootfs /rootfs.ext4
echo "==> Debian rootfs populated successfully"
"#;
const LINUX_ROOTFS_SCRIPT_PREFIX: &str = r#"set -e
mount -o loop "$ROOTFS_IMG" "$MOUNT_DIR"
cleanup() {
    if command -v cleanup_toolchain_tmp_dirs > /dev/null 2>&1; then
        cleanup_toolchain_tmp_dirs
    fi
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
    ffmpeg cifs-utils e2fsprogs > /dev/null 2>&1
test -x "$MOUNT_DIR/sbin/mount.cifs" || test -x "$MOUNT_DIR/usr/sbin/mount.cifs"
test -x "$MOUNT_DIR/sbin/mkfs.ext4" || test -x "$MOUNT_DIR/usr/sbin/mkfs.ext4"

ROOTFS_DIR="$MOUNT_DIR"
"#;
const LINUX_ROOTFS_SCRIPT_SUFFIX: &str = r#"

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

fn macos_rootfs_docker_script() -> String {
    [
        MACOS_ROOTFS_DOCKER_SCRIPT_PREFIX,
        ROOTFS_TOOLCHAIN_INSTALL_SCRIPT,
        MACOS_ROOTFS_DOCKER_SCRIPT_SUFFIX,
    ]
    .concat()
}

fn linux_rootfs_script() -> String {
    [
        LINUX_ROOTFS_SCRIPT_PREFIX,
        ROOTFS_TOOLCHAIN_INSTALL_SCRIPT,
        LINUX_ROOTFS_SCRIPT_SUFFIX,
    ]
    .concat()
}

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

    if is_macos() && !container_engine_available() {
        bail!("Docker or Podman is required on macOS to create ext4 images.");
    }

    fs::create_dir_all(&data_dir)
        .with_context(|| format!("failed to create {}", data_dir.display()))?;

    if !kernel_path.is_file() {
        build_kernel_for_platform(platform)?;
    } else {
        println!("==> Kernel already present.");
    }

    if !initramfs_path.is_file() {
        let engine = container_engine("Docker or Podman is required to build the initramfs.")?;
        println!("==> Building minimal initramfs...");
        run_command(
            Command::new(&engine)
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
            "build initramfs in a container",
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
        create_sized_rootfs_image(&rootfs_img, DEFAULT_ROOTFS_SIZE_MB)?;

        if should_use_docker_rootfs() {
            println!();
            println!("==> Using a container for ext4 formatting and Debian bootstrap.");
            println!();
            let engine = container_engine("Docker or Podman is required to prepare the rootfs.")?;
            run_command(
                Command::new(&engine)
                    .arg("run")
                    .arg("--rm")
                    .arg("--privileged")
                    .arg("--platform")
                    .arg(platform.docker_platform)
                    .arg("-e")
                    .arg(format!("DEBIAN_RELEASE={DEFAULT_DEBIAN_RELEASE}"))
                    .arg("-e")
                    .arg(format!("DEBOOTSTRAP_ARCH={}", platform.debootstrap_arch))
                    .arg("-e")
                    .arg(format!("NODE_VERSION={DEFAULT_NODE_VERSION}"))
                    .arg("-e")
                    .arg(format!(
                        "PCHURI_JIRA_CLI_VERSION={DEFAULT_PCHURI_JIRA_CLI_VERSION}"
                    ))
                    .arg("-e")
                    .arg(format!(
                        "CONFLUENCE_CLI_VERSION={DEFAULT_CONFLUENCE_CLI_VERSION}"
                    ))
                    .arg("-e")
                    .arg(format!(
                        "OFFICEPARSER_VERSION={DEFAULT_OFFICEPARSER_VERSION}"
                    ))
                    .arg("-e")
                    .arg(format!("XLSX_VERSION={DEFAULT_XLSX_VERSION}"))
                    .arg("-e")
                    .arg(format!("DOCX_VERSION={DEFAULT_DOCX_VERSION}"))
                    .arg("-v")
                    .arg(format!("{}:/rootfs.ext4", rootfs_img.display()))
                    .arg("-v")
                    .arg(format!("{}:/tmp/lsb-guest:ro", guest_binary.display()))
                    .arg(format!("debian:{DEFAULT_DEBIAN_RELEASE}-slim"))
                    .arg("/bin/sh")
                    .arg("-c")
                    .arg(macos_rootfs_docker_script()),
                "prepare rootfs in a container",
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
                    .arg(format!("NODE_VERSION={DEFAULT_NODE_VERSION}"))
                    .arg(format!(
                        "PCHURI_JIRA_CLI_VERSION={DEFAULT_PCHURI_JIRA_CLI_VERSION}"
                    ))
                    .arg(format!(
                        "CONFLUENCE_CLI_VERSION={DEFAULT_CONFLUENCE_CLI_VERSION}"
                    ))
                    .arg(format!(
                        "OFFICEPARSER_VERSION={DEFAULT_OFFICEPARSER_VERSION}"
                    ))
                    .arg(format!("XLSX_VERSION={DEFAULT_XLSX_VERSION}"))
                    .arg(format!("DOCX_VERSION={DEFAULT_DOCX_VERSION}"))
                    .arg(format!("GUEST_BINARY={}", guest_binary.display()))
                    .arg("/bin/sh")
                    .arg("-c")
                    .arg(linux_rootfs_script()),
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

fn create_sized_rootfs_image(path: &std::path::Path, size_mb: u64) -> Result<()> {
    let size = size_mb
        .checked_mul(1024 * 1024)
        .context("rootfs image size overflow")?;
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("failed to create rootfs image {}", path.display()))?;
    if let Err(error) = file.set_len(size) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error)
            .with_context(|| format!("failed to size rootfs image {}", path.display()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{create_sized_rootfs_image, linux_rootfs_script, macos_rootfs_docker_script};

    #[test]
    fn rootfs_image_creation_does_not_require_unix_truncate() {
        let path =
            std::env::temp_dir().join(format!("lsb-xtask-rootfs-image-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);

        create_sized_rootfs_image(&path, 2).expect("rootfs image should be sized");
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 2 * 1024 * 1024);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn macos_rootfs_script_installs_and_checks_runtime_filesystem_tools() {
        let script = macos_rootfs_docker_script();

        assert!(script.contains("cifs-utils"));
        assert!(script.contains("mount.cifs"));
        assert!(script.contains("e2fsprogs"));
        assert!(script.contains("mkfs.ext4"));
    }

    #[test]
    fn container_rootfs_script_populates_without_loop_mounts() {
        let script = macos_rootfs_docker_script();

        assert!(script.contains("mkfs.ext4 -F -E lazy_itable_init=0 -d /mnt/rootfs"));
        assert!(!script.contains("mount -o loop"));
        assert!(!script.contains("umount /mnt/rootfs"));
    }

    #[test]
    fn linux_rootfs_script_installs_and_checks_runtime_filesystem_tools() {
        let script = linux_rootfs_script();

        assert!(script.contains("cifs-utils"));
        assert!(script.contains("mount.cifs"));
        assert!(script.contains("e2fsprogs"));
        assert!(script.contains("mkfs.ext4"));
    }
}
