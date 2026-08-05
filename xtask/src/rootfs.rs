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
const DEFAULT_BUN_VERSION: &str = "1.3.14";
const DEFAULT_BUN_AARCH64_SHA256: &str =
    "a27ffb63a8310375836e0d6f668ae17fa8d8d18b88c37c821c65331973a19a3b";
const DEFAULT_BUN_X64_BASELINE_SHA256: &str =
    "a063908ae08b7852ca10939bbdc6ceed3ddabce8fb9402dce83d65d73b36e6c7";
const DEFAULT_TSX_VERSION: &str = "4.23.5";
const DEFAULT_TYPESCRIPT_VERSION: &str = "6.0.3";
const DEFAULT_XLSX_VERSION: &str = "0.18.5";
const DEFAULT_DOCX_VERSION: &str = "9.7.1";
const DEFAULT_OFFICEPARSER_VERSION: &str = "7.5.1";
const DEFAULT_MJML_VERSION: &str = "5.4.0";
const DEFAULT_GOOGLE_WORKSPACE_CLI_VERSION: &str = "0.22.5";
const DEFAULT_PCHURI_JIRA_CLI_VERSION: &str = "2.8.1";
const DEFAULT_CONFLUENCE_CLI_VERSION: &str = "2.19.1";
const DEFAULT_OPENAPI_TS_VERSION: &str = "0.99.0";
const DEFAULT_YOUTUBE_TRANSCRIPT_VERSION: &str = "1.3.1";
const DEFAULT_FRACTIONAL_INDEXING_VERSION: &str = "4.0.0";
const DEFAULT_NODE_VERSION: &str = "v24.18.1";
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
mount -o noatime -t ext4 /dev/vda /newroot
cp /bin/lsb-init /newroot/usr/bin/lsb-init
chmod 755 /newroot/usr/bin/lsb-init
if ifconfig eth0 up 2>/dev/null; then
    ifconfig eth0 10.0.0.2 netmask 255.255.255.0 up
    route add default gw 10.0.0.1
    ifconfig eth0 add fd00::2/64
    route -A inet6 add default gw fd00::1 dev eth0
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
apt-get install -y -qq ca-certificates curl debootstrap e2fsprogs unzip xz-utils > /dev/null 2>&1

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
    openssh-client jq less procps ripgrep rsync xz-utils libgomp1 libatomic1 \
    cifs-utils e2fsprogs > /dev/null 2>&1
test -x /mnt/rootfs/usr/bin/rg
test -x /mnt/rootfs/sbin/mount.cifs || test -x /mnt/rootfs/usr/sbin/mount.cifs
test -x /mnt/rootfs/sbin/mkfs.ext4 || test -x /mnt/rootfs/usr/sbin/mkfs.ext4

ROOTFS_DIR="/mnt/rootfs"
"#;
const ROOTFS_TOOLCHAIN_INSTALL_SCRIPT: &str = r#"
TOOLCHAIN_TMP_DIRS=""
TOOLCHAIN_PROC_MOUNT=""

track_toolchain_tmp_dir() {
    TOOLCHAIN_TMP_DIRS="${TOOLCHAIN_TMP_DIRS} $1"
}

cleanup_toolchain_tmp_dirs() {
    if [ -n "${TOOLCHAIN_PROC_MOUNT}" ]; then
        umount "${TOOLCHAIN_PROC_MOUNT}" 2>/dev/null || true
        TOOLCHAIN_PROC_MOUNT=""
    fi
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

install_bun() {
    install_rootfs_dir="$1"
    case "${DEBOOTSTRAP_ARCH}" in
        amd64)
            bun_archive="bun-linux-x64-baseline.zip"
            bun_sha256="${BUN_X64_BASELINE_SHA256}"
            ;;
        arm64)
            bun_archive="bun-linux-aarch64.zip"
            bun_sha256="${BUN_AARCH64_SHA256}"
            ;;
        *) echo "unsupported Bun architecture: ${DEBOOTSTRAP_ARCH}" >&2; exit 1 ;;
    esac

    echo "==> Installing Bun ${BUN_VERSION}..."
    bun_tmp="$(mktemp -d)"
    track_toolchain_tmp_dir "${bun_tmp}"
    bun_url="https://github.com/oven-sh/bun/releases/download/bun-v${BUN_VERSION}/${bun_archive}"
    curl -fsSLo "${bun_tmp}/${bun_archive}" "${bun_url}"
    printf '%s  %s\n' "${bun_sha256}" "${bun_tmp}/${bun_archive}" | sha256sum -c -
    unzip -q "${bun_tmp}/${bun_archive}" -d "${bun_tmp}/unpacked"
    bun_binary="$(find "${bun_tmp}/unpacked" -type f -name bun -print -quit)"
    test -n "${bun_binary}"
    mkdir -p "${install_rootfs_dir}/root/.bun/bin"
    install -m 0755 "${bun_binary}" "${install_rootfs_dir}/root/.bun/bin/bun"
    ln -sf /root/.bun/bin/bun "${install_rootfs_dir}/root/.bun/bin/bunx"
    ln -sf /root/.bun/bin/bun "${install_rootfs_dir}/usr/bin/bun"
    ln -sf /root/.bun/bin/bunx "${install_rootfs_dir}/usr/bin/bunx"
    chroot "${install_rootfs_dir}" /usr/bin/bun --version | grep -Fx "${BUN_VERSION}" > /dev/null
}

configure_javascript_environment() {
    install_rootfs_dir="$1"
    mkdir -p "${install_rootfs_dir}/etc/profile.d" "${install_rootfs_dir}/root"
    cat > "${install_rootfs_dir}/etc/profile.d/lsb-javascript.sh" <<'PROFILEEOF'
export HOME=/root
export BUN_INSTALL=/root/.bun
export BUN_INSTALL_GLOBAL_DIR=/root/.bun/install/global
export BUN_INSTALL_BIN=/root/.bun/bin
export PATH=/root/.bun/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export NODE_PATH=/usr/local/lib/node_modules
export NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt
PROFILEEOF
    printf '%s\n' '. /etc/profile.d/lsb-javascript.sh' >> "${install_rootfs_dir}/root/.bashrc"
}

link_node_tool_bins() {
    install_rootfs_dir="$1"
    mkdir -p "${install_rootfs_dir}/root/.bun/bin"
    if [ -d "${install_rootfs_dir}/usr/local/lib/node_modules/.bin" ]; then
        for binary in "${install_rootfs_dir}"/usr/local/lib/node_modules/.bin/*; do
            [ -e "${binary}" ] || continue
            ln -sf "/usr/local/lib/node_modules/.bin/$(basename "${binary}")" \
                "${install_rootfs_dir}/root/.bun/bin/$(basename "${binary}")"
        done
    fi
}

smoke_or_fallback_to_npm() {
    install_rootfs_dir="$1"
    package_spec="$2"
    smoke_command="$3"
    if chroot "${install_rootfs_dir}" /usr/bin/env \
        HOME=/root PATH=/root/.bun/bin:/usr/local/bin:/usr/bin:/bin \
        NODE_PATH=/usr/local/lib/node_modules /bin/sh -c "${smoke_command}"; then
        return
    fi

    echo "==> Bun smoke test failed for ${package_spec}; reinstalling that package with npm..."
    chroot "${install_rootfs_dir}" /usr/bin/npm install -g --force "${package_spec}"
    link_node_tool_bins "${install_rootfs_dir}"
    chroot "${install_rootfs_dir}" /usr/bin/env \
        HOME=/root PATH=/root/.bun/bin:/usr/local/bin:/usr/bin:/bin \
        NODE_PATH=/usr/local/lib/node_modules /bin/sh -c "${smoke_command}"
}

install_bundled_node_tools() {
    install_rootfs_dir="$1"
    mkdir -p "${install_rootfs_dir}/root/.bun/install/global"
    cat > "${install_rootfs_dir}/root/.bun/install/global/package.json" <<PACKAGEEOF
{
  "name": "lsb-bundled-node-tools",
  "private": true,
  "dependencies": {
    "tsx": "${TSX_VERSION}",
    "typescript": "${TYPESCRIPT_VERSION}",
    "xlsx": "${XLSX_VERSION}",
    "docx": "${DOCX_VERSION}",
    "officeparser": "${OFFICEPARSER_VERSION}",
    "mjml": "${MJML_VERSION}",
    "@googleworkspace/cli": "${GOOGLE_WORKSPACE_CLI_VERSION}",
    "@pchuri/jira-cli": "${PCHURI_JIRA_CLI_VERSION}",
    "confluence-cli": "${CONFLUENCE_CLI_VERSION}",
    "@hey-api/openapi-ts": "${OPENAPI_TS_VERSION}",
    "youtube-transcript": "${YOUTUBE_TRANSCRIPT_VERSION}",
    "fractional-indexing": "${FRACTIONAL_INDEXING_VERSION}"
  },
  "trustedDependencies": ["esbuild"]
}
PACKAGEEOF

    echo "==> Installing pinned Node tools with Bun..."
    chroot "${install_rootfs_dir}" /usr/bin/env \
        HOME=/root BUN_INSTALL=/root/.bun \
        BUN_INSTALL_GLOBAL_DIR=/root/.bun/install/global BUN_INSTALL_BIN=/root/.bun/bin \
        BUN_INSTALL_CACHE_DIR=/tmp/bun-install-cache \
        /usr/bin/bun install --global --trust --no-progress \
        "tsx@${TSX_VERSION}" \
        "typescript@${TYPESCRIPT_VERSION}" \
        "xlsx@${XLSX_VERSION}" \
        "docx@${DOCX_VERSION}" \
        "officeparser@${OFFICEPARSER_VERSION}" \
        "mjml@${MJML_VERSION}" \
        "@googleworkspace/cli@${GOOGLE_WORKSPACE_CLI_VERSION}" \
        "@pchuri/jira-cli@${PCHURI_JIRA_CLI_VERSION}" \
        "confluence-cli@${CONFLUENCE_CLI_VERSION}" \
        "@hey-api/openapi-ts@${OPENAPI_TS_VERSION}" \
        "youtube-transcript@${YOUTUBE_TRANSCRIPT_VERSION}" \
        "fractional-indexing@${FRACTIONAL_INDEXING_VERSION}"
    mkdir -p "${install_rootfs_dir}/usr/local/lib/node_modules"
    cp -al "${install_rootfs_dir}/root/.bun/install/global/node_modules/." \
        "${install_rootfs_dir}/usr/local/lib/node_modules/"
    link_node_tool_bins "${install_rootfs_dir}"

    smoke_or_fallback_to_npm "${install_rootfs_dir}" "tsx@${TSX_VERSION}" 'tsx --version >/dev/null'
    smoke_or_fallback_to_npm "${install_rootfs_dir}" "typescript@${TYPESCRIPT_VERSION}" 'tsc --version >/dev/null'
    smoke_or_fallback_to_npm "${install_rootfs_dir}" "xlsx@${XLSX_VERSION}" "node -e \"require('xlsx')\""
    smoke_or_fallback_to_npm "${install_rootfs_dir}" "docx@${DOCX_VERSION}" "node -e \"require('docx')\""
    smoke_or_fallback_to_npm "${install_rootfs_dir}" "officeparser@${OFFICEPARSER_VERSION}" "node -e \"require('officeparser')\""
    smoke_or_fallback_to_npm "${install_rootfs_dir}" "mjml@${MJML_VERSION}" 'mjml --version >/dev/null'
    smoke_or_fallback_to_npm "${install_rootfs_dir}" "@googleworkspace/cli@${GOOGLE_WORKSPACE_CLI_VERSION}" 'gws --help >/dev/null'
    smoke_or_fallback_to_npm "${install_rootfs_dir}" "@pchuri/jira-cli@${PCHURI_JIRA_CLI_VERSION}" 'jira --help >/dev/null'
    smoke_or_fallback_to_npm "${install_rootfs_dir}" "confluence-cli@${CONFLUENCE_CLI_VERSION}" 'confluence --help >/dev/null'
    smoke_or_fallback_to_npm "${install_rootfs_dir}" "@hey-api/openapi-ts@${OPENAPI_TS_VERSION}" 'openapi-ts --version >/dev/null'
    smoke_or_fallback_to_npm "${install_rootfs_dir}" "youtube-transcript@${YOUTUBE_TRANSCRIPT_VERSION}" "node -e \"require('youtube-transcript')\""
    smoke_or_fallback_to_npm "${install_rootfs_dir}" "fractional-indexing@${FRACTIONAL_INDEXING_VERSION}" "node -e \"require('fractional-indexing')\""
}

cleanup_package_manager_state() {
    install_rootfs_dir="$1"
    rm -rf \
        "${install_rootfs_dir}/root/.bun/install/cache" \
        "${install_rootfs_dir}/root/.cache" \
        "${install_rootfs_dir}/root/.npm" \
        "${install_rootfs_dir}/tmp/bun-install-cache"
    find "${install_rootfs_dir}/var/log" -type f -exec truncate -s 0 {} + 2>/dev/null || true
}

install_rootfs_toolchains() {
    install_rootfs_dir="$1"
    mkdir -p "${install_rootfs_dir}/proc"
    mount -t proc proc "${install_rootfs_dir}/proc"
    TOOLCHAIN_PROC_MOUNT="${install_rootfs_dir}/proc"
    install_nodejs "${install_rootfs_dir}"
    install_bun "${install_rootfs_dir}"
    configure_javascript_environment "${install_rootfs_dir}"
    install_bundled_node_tools "${install_rootfs_dir}"
    cleanup_package_manager_state "${install_rootfs_dir}"
    umount "${TOOLCHAIN_PROC_MOUNT}"
    TOOLCHAIN_PROC_MOUNT=""
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
e2fsck -fy /rootfs.ext4 > /dev/null
resize2fs -M /rootfs.ext4 > /dev/null
block_count="$(dumpe2fs -h /rootfs.ext4 2>/dev/null | awk -F: '/Block count:/{gsub(/ /, "", $2); print $2}')"
block_size="$(dumpe2fs -h /rootfs.ext4 2>/dev/null | awk -F: '/Block size:/{gsub(/ /, "", $2); print $2}')"
truncate -s "$((block_count * block_size))" /rootfs.ext4
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
    openssh-client jq less procps ripgrep rsync xz-utils libgomp1 libatomic1 \
    ffmpeg cifs-utils e2fsprogs > /dev/null 2>&1
test -x "$MOUNT_DIR/usr/bin/rg"
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

sync
umount "$MOUNT_DIR"
e2fsck -fy "$ROOTFS_IMG" > /dev/null
resize2fs -M "$ROOTFS_IMG" > /dev/null
block_count="$(dumpe2fs -h "$ROOTFS_IMG" 2>/dev/null | awk -F: '/Block count:/{gsub(/ /, "", $2); print $2}')"
block_size="$(dumpe2fs -h "$ROOTFS_IMG" 2>/dev/null | awk -F: '/Block size:/{gsub(/ /, "", $2); print $2}')"
truncate -s "$((block_count * block_size))" "$ROOTFS_IMG"

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

fn rootfs_toolchain_versions() -> [(&'static str, &'static str); 16] {
    [
        ("NODE_VERSION", DEFAULT_NODE_VERSION),
        ("BUN_VERSION", DEFAULT_BUN_VERSION),
        ("BUN_AARCH64_SHA256", DEFAULT_BUN_AARCH64_SHA256),
        ("BUN_X64_BASELINE_SHA256", DEFAULT_BUN_X64_BASELINE_SHA256),
        ("TSX_VERSION", DEFAULT_TSX_VERSION),
        ("TYPESCRIPT_VERSION", DEFAULT_TYPESCRIPT_VERSION),
        ("XLSX_VERSION", DEFAULT_XLSX_VERSION),
        ("DOCX_VERSION", DEFAULT_DOCX_VERSION),
        ("OFFICEPARSER_VERSION", DEFAULT_OFFICEPARSER_VERSION),
        ("MJML_VERSION", DEFAULT_MJML_VERSION),
        (
            "GOOGLE_WORKSPACE_CLI_VERSION",
            DEFAULT_GOOGLE_WORKSPACE_CLI_VERSION,
        ),
        ("PCHURI_JIRA_CLI_VERSION", DEFAULT_PCHURI_JIRA_CLI_VERSION),
        ("CONFLUENCE_CLI_VERSION", DEFAULT_CONFLUENCE_CLI_VERSION),
        ("OPENAPI_TS_VERSION", DEFAULT_OPENAPI_TS_VERSION),
        (
            "YOUTUBE_TRANSCRIPT_VERSION",
            DEFAULT_YOUTUBE_TRANSCRIPT_VERSION,
        ),
        (
            "FRACTIONAL_INDEXING_VERSION",
            DEFAULT_FRACTIONAL_INDEXING_VERSION,
        ),
    ]
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
            let mut command = Command::new(&engine);
            command
                .arg("run")
                .arg("--rm")
                .arg("--privileged")
                .arg("--platform")
                .arg(platform.docker_platform)
                .arg("-e")
                .arg(format!("DEBIAN_RELEASE={DEFAULT_DEBIAN_RELEASE}"))
                .arg("-e")
                .arg(format!("DEBOOTSTRAP_ARCH={}", platform.debootstrap_arch));
            for (name, version) in rootfs_toolchain_versions() {
                command.arg("-e").arg(format!("{name}={version}"));
            }
            command
                .arg("-v")
                .arg(format!("{}:/rootfs.ext4", rootfs_img.display()))
                .arg("-v")
                .arg(format!("{}:/tmp/lsb-guest:ro", guest_binary.display()))
                .arg(format!("debian:{DEFAULT_DEBIAN_RELEASE}-slim"))
                .arg("/bin/sh")
                .arg("-c")
                .arg(macos_rootfs_docker_script());
            run_command(&mut command, "prepare rootfs in a container")?;
        } else {
            ensure_linux_rootfs_prerequisites()?;
            let mount_dir = create_mount_dir()?;
            let mut command = Command::new("sudo");
            command
                .arg("env")
                .arg(format!("ROOTFS_IMG={}", rootfs_img.display()))
                .arg(format!("MOUNT_DIR={}", mount_dir.display()))
                .arg(format!("DEBIAN_RELEASE={DEFAULT_DEBIAN_RELEASE}"))
                .arg(format!("DEBOOTSTRAP_ARCH={}", platform.debootstrap_arch));
            for (name, version) in rootfs_toolchain_versions() {
                command.arg(format!("{name}={version}"));
            }
            command
                .arg(format!("GUEST_BINARY={}", guest_binary.display()))
                .arg("/bin/sh")
                .arg("-c")
                .arg(linux_rootfs_script());
            run_command(&mut command, "prepare rootfs on Linux")?;
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
    use super::{
        create_sized_rootfs_image, linux_rootfs_script, macos_rootfs_docker_script,
        rootfs_toolchain_versions, INITRAMFS_DOCKER_SCRIPT,
    };

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
    fn initramfs_configures_dual_stack_proxy_routes() {
        assert!(INITRAMFS_DOCKER_SCRIPT.contains("ifconfig eth0 10.0.0.2 netmask 255.255.255.0 up"));
        assert!(INITRAMFS_DOCKER_SCRIPT.contains("route add default gw 10.0.0.1"));
        assert!(INITRAMFS_DOCKER_SCRIPT.contains("ifconfig eth0 add fd00::2/64"));
        assert!(INITRAMFS_DOCKER_SCRIPT.contains("route -A inet6 add default gw fd00::1 dev eth0"));
        assert!(INITRAMFS_DOCKER_SCRIPT.contains("mount -o noatime -t ext4 /dev/vda /newroot"));
    }

    #[test]
    fn macos_rootfs_script_installs_and_checks_runtime_filesystem_tools() {
        let script = macos_rootfs_docker_script();

        assert!(script.contains("cifs-utils"));
        assert!(script.contains("mount.cifs"));
        assert!(script.contains("e2fsprogs"));
        assert!(script.contains("mkfs.ext4"));
        assert!(script.contains("rsync"));
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
        assert!(script.contains("rsync"));
    }

    #[test]
    fn rootfs_scripts_install_and_check_ripgrep() {
        for script in [macos_rootfs_docker_script(), linux_rootfs_script()] {
            assert!(script.contains("ripgrep"));
            assert!(script.contains("/usr/bin/rg"));
        }
    }

    #[test]
    fn rootfs_toolchains_are_pinned_and_bun_is_digest_verified() {
        let script = macos_rootfs_docker_script();

        for (name, version) in rootfs_toolchain_versions() {
            assert!(!version.is_empty(), "{name} must be pinned");
        }
        assert!(script.contains("bun-linux-aarch64.zip"));
        assert!(script.contains("bun-linux-x64-baseline.zip"));
        assert!(script.contains("sha256sum -c -"));
        assert!(script.contains("trustedDependencies"));
        assert!(script.contains("BUN_INSTALL_CACHE_DIR=/tmp/bun-install-cache"));
        assert!(script.contains("Bun smoke test failed"));
        assert!(script.contains("/usr/bin/npm install -g"));
    }

    #[test]
    fn rootfs_bundles_all_planned_node_packages() {
        let script = macos_rootfs_docker_script();

        for package in [
            "tsx",
            "typescript",
            "xlsx",
            "docx",
            "officeparser",
            "mjml",
            "@googleworkspace/cli",
            "@pchuri/jira-cli",
            "confluence-cli",
            "@hey-api/openapi-ts",
            "youtube-transcript",
            "fractional-indexing",
        ] {
            assert!(script.contains(&format!("\"{package}\"")));
        }
        assert!(script.contains("NODE_PATH=/usr/local/lib/node_modules"));
        assert!(script.contains("PATH=/root/.bun/bin:"));
    }

    #[test]
    fn rootfs_scripts_clean_package_caches_and_shrink_the_image() {
        for script in [macos_rootfs_docker_script(), linux_rootfs_script()] {
            assert!(script.contains("/root/.bun/install/cache"));
            assert!(script.contains("/root/.npm"));
            assert!(script.contains("resize2fs -M"));
            assert!(script.contains("truncate -s"));
        }
    }
}
