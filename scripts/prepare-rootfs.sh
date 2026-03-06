#!/bin/bash
set -euo pipefail

DEBIAN_RELEASE="trixie"
DATA_DIR="${HOME}/.local/share/shuru"
ROOTFS_IMG="${DATA_DIR}/rootfs.ext4"
KERNEL_PATH="${DATA_DIR}/Image"
INITRAMFS_PATH="${DATA_DIR}/initramfs.cpio.gz"
GUEST_BINARY="target/aarch64-unknown-linux-musl/release/shuru-guest"
ROOTFS_SIZE_MB=1024

echo "==> Shuru rootfs preparation script"
echo "    Debian ${DEBIAN_RELEASE} (kernel + rootfs)"
echo ""

if [[ "$(uname)" == "Darwin" ]]; then
    if ! command -v docker &>/dev/null; then
        echo "ERROR: Docker is required on macOS to create ext4 images."
        echo "       Install Docker Desktop or use: brew install --cask docker"
        exit 1
    fi
fi

# Check for guest binary
if [ ! -f "$GUEST_BINARY" ]; then
    echo "ERROR: Guest binary not found at ${GUEST_BINARY}"
    echo "       Run: cargo build -p shuru-guest --target aarch64-unknown-linux-musl --release"
    exit 1
fi

GUEST_BINARY="$(cd "$(dirname "$GUEST_BINARY")" && pwd)/$(basename "$GUEST_BINARY")"

mkdir -p "$DATA_DIR"

# --- Extract kernel ---
if [ ! -f "$KERNEL_PATH" ]; then
    echo "==> Extracting Debian cloud kernel..."

    docker run --rm \
        --platform linux/arm64/v8 \
        -v "${DATA_DIR}:/output" \
        debian:${DEBIAN_RELEASE}-slim /bin/sh -c '
            set -e
            apt-get update -qq > /dev/null 2>&1
            apt-get install -y -qq linux-image-cloud-arm64 > /dev/null 2>&1
            VMLINUZ=$(ls /boot/vmlinuz-* | head -1)
            echo "    Found: ${VMLINUZ}"
            cp "${VMLINUZ}" /output/Image
            echo "    Kernel copied to /output/Image"
        '
    echo "    Kernel saved to ${KERNEL_PATH}"
else
    echo "==> Kernel already present."
fi

# --- Build initramfs with VirtIO block + vsock modules ---
# Debian cloud kernel has virtio_pci, virtio_console, ext4, fuse, virtiofs,
# af_packet, crc32c built-in (=y). Only virtio_blk, virtio_net, vsock, overlay
# are modules (=m).
if [ ! -f "$INITRAMFS_PATH" ]; then
    echo "==> Building initramfs with VirtIO modules..."

    # Write udhcpc callback script to a temp file (avoids quoting issues inside docker)
    UDHCPC_SCRIPT=$(mktemp)
    cat > "$UDHCPC_SCRIPT" << 'DHCPEOF'
#!/bin/sh
case "$1" in
bound|renew)
    ifconfig "$interface" "$ip" netmask "$subnet" up
    if [ -n "$router" ]; then
        route add default gw "$router"
    fi
    # Write DNS to the real rootfs (already mounted at /newroot)
    if [ -n "$dns" ] && [ -d /newroot/etc ]; then
        > /newroot/etc/resolv.conf
        for d in $dns; do
            echo "nameserver $d" >> /newroot/etc/resolv.conf
        done
    fi
    ;;
esac
DHCPEOF

    docker run --rm \
        --platform linux/arm64/v8 \
        -v "${DATA_DIR}:/output" \
        -v "${UDHCPC_SCRIPT}:/tmp/udhcpc.sh:ro" \
        -v "${GUEST_BINARY}:/tmp/shuru-init:ro" \
        debian:${DEBIAN_RELEASE}-slim /bin/sh -c '
            set -e
            apt-get update -qq > /dev/null 2>&1
            apt-get install -y -qq linux-image-cloud-arm64 busybox-static \
                e2fsprogs pax-utils kmod cpio > /dev/null 2>&1
            KVER=$(ls /lib/modules/ | head -1)
            echo "Kernel modules version: ${KVER}"

            # Create initramfs structure
            mkdir -p /initramfs/bin /initramfs/sbin /initramfs/etc
            mkdir -p /initramfs/proc /initramfs/sys /initramfs/dev
            mkdir -p /initramfs/newroot
            mkdir -p "/initramfs/lib/modules/${KVER}"

            # Busybox (static) for shell + utilities
            cp /bin/busybox /initramfs/bin/busybox
            for cmd in sh mount umount switch_root modprobe insmod mkdir echo cat sleep mknod ln cp chmod ifconfig route udhcpc; do
                ln -sf busybox "/initramfs/bin/${cmd}"
            done

            # e2fsck + resize2fs for journal recovery and filesystem resize
            lddtree -l /sbin/e2fsck /usr/sbin/resize2fs | sort -u \
                | cpio --quiet -pdm /initramfs

            # Copy needed modules (only those not built-in)
            echo "Copying kernel modules..."
            for mod in \
                kernel/drivers/block/virtio_blk.ko* \
                kernel/lib/libcrc32c.ko* \
                kernel/drivers/net/virtio_net.ko* \
                kernel/drivers/net/net_failover.ko* \
                kernel/net/core/failover.ko* \
                kernel/net/vmw_vsock/vsock.ko* \
                kernel/net/vmw_vsock/vmw_vsock_virtio_transport_common.ko* \
                kernel/net/vmw_vsock/vmw_vsock_virtio_transport.ko* \
                kernel/drivers/char/hw_random/virtio-rng.ko* \
                kernel/drivers/virtio/virtio_balloon.ko* \
                kernel/drivers/virtio/virtio_mmio.ko* \
                kernel/net/vmw_vsock/vsock_loopback.ko* \
                kernel/net/vmw_vsock/vsock_diag.ko* \
                kernel/fs/overlayfs/overlay.ko*; do
                for f in /lib/modules/${KVER}/${mod}; do
                    if [ -f "${f}" ]; then
                        dest_dir="/initramfs/lib/modules/${KVER}/$(dirname ${mod})"
                        mkdir -p "${dest_dir}"
                        cp "${f}" "${dest_dir}/"
                        echo "  copied: $(basename ${f})"
                    fi
                done
            done

            # Copy module metadata
            for dep_file in modules.dep modules.alias modules.symbols modules.builtin modules.order modules.dep.bin modules.alias.bin modules.softdep modules.devname; do
                if [ -f "/lib/modules/${KVER}/${dep_file}" ]; then
                    cp "/lib/modules/${KVER}/${dep_file}" "/initramfs/lib/modules/${KVER}/"
                fi
            done

            # Regenerate modules.dep for our subset
            depmod -b /initramfs ${KVER} 2>/dev/null || true

            # Copy udhcpc callback script (mounted from host temp file)
            cp /tmp/udhcpc.sh /initramfs/etc/udhcpc.sh
            chmod 755 /initramfs/etc/udhcpc.sh

            # Copy guest binary into initramfs (stamped into rootfs on every boot)
            cp /tmp/shuru-init /initramfs/bin/shuru-init
            chmod 755 /initramfs/bin/shuru-init

            # Create init script
            cat > /initramfs/init << '\''INITEOF'\''
#!/bin/sh
/bin/mount -t proc none /proc
/bin/mount -t sysfs none /sys
/bin/mount -t devtmpfs none /dev

echo "initramfs: loading modules..."
for mod in virtio_blk libcrc32c virtio_net vsock vmw_vsock_virtio_transport_common vmw_vsock_virtio_transport overlay; do
    /bin/modprobe ${mod} 2>/dev/null && echo "  loaded: ${mod}" || echo "  FAILED: ${mod}"
done

# Wait for block device to appear
echo "initramfs: waiting for /dev/vda..."
i=0
while [ ! -b /dev/vda ] && [ $i -lt 10 ]; do
    sleep 1
    i=$((i + 1))
done

if [ ! -b /dev/vda ]; then
    echo "initramfs: ERROR - /dev/vda not found!"
    echo "Block devices:"
    ls -la /dev/vd* 2>/dev/null || echo "  (none)"
    cat /proc/partitions
    echo "Dropping to shell..."
    exec /bin/sh
fi

echo "initramfs: resizing filesystem..."
/sbin/e2fsck -fy /dev/vda > /dev/null 2>&1 || true
/usr/sbin/resize2fs /dev/vda > /dev/null 2>&1 || true

echo "initramfs: mounting /dev/vda..."
/bin/mount -t ext4 /dev/vda /newroot

# Stamp latest guest binary from initramfs into rootfs
cp /bin/shuru-init /newroot/usr/bin/shuru-init
chmod 755 /newroot/usr/bin/shuru-init

# Network setup (if eth0 exists) -- do DHCP before switch_root
# so shuru-guest does not race the host NAT attachment
if ifconfig eth0 up 2>/dev/null; then
    echo "initramfs: configuring network via DHCP..."
    udhcpc -i eth0 -n -q -s /etc/udhcpc.sh -t 5 -T 2 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "initramfs: network configured"
    else
        echo "initramfs: DHCP failed (will retry in guest)"
    fi
fi

echo "initramfs: switching to real root..."
/bin/umount /proc
/bin/umount /sys
/bin/umount /dev
exec /bin/switch_root /newroot /usr/bin/shuru-init
INITEOF
            chmod 755 /initramfs/init

            # Build cpio archive
            cd /initramfs
            find . | cpio -o -H newc 2>/dev/null | gzip > /output/initramfs.cpio.gz
            echo "==> Initramfs created: $(du -h /output/initramfs.cpio.gz | cut -f1)"
        '
    rm -f "$UDHCPC_SCRIPT"
    echo "    Initramfs saved to ${INITRAMFS_PATH}"
else
    echo "==> Initramfs already present."
fi

# --- Create ext4 rootfs image with Debian trixie ---
if [ -f "$ROOTFS_IMG" ]; then
    echo "==> Rootfs already present."
else
echo "==> Creating ext4 rootfs image (${ROOTFS_SIZE_MB}MB) with Debian ${DEBIAN_RELEASE}..."

# Create sparse image file
truncate -s ${ROOTFS_SIZE_MB}M "$ROOTFS_IMG"

if [[ "$(uname)" == "Darwin" ]]; then
    echo ""
    echo "==> macOS detected. Using Docker for ext4 formatting and Debian bootstrap."
    echo ""

    # Format + debootstrap + populate entirely inside Docker
    docker run --rm --privileged \
        --platform linux/arm64/v8 \
        -e DEBIAN_RELEASE="${DEBIAN_RELEASE}" \
        -v "${ROOTFS_IMG}:/rootfs.ext4" \
        -v "${GUEST_BINARY}:/tmp/shuru-guest:ro" \
        debian:${DEBIAN_RELEASE}-slim /bin/sh -c '
            set -e
            apt-get update -qq
            apt-get install -y -qq debootstrap e2fsprogs > /dev/null 2>&1

            mkfs.ext4 -F /rootfs.ext4
            mkdir -p /mnt/rootfs
            mount -o loop /rootfs.ext4 /mnt/rootfs

            echo "==> Running debootstrap (this may take a few minutes)..."
            debootstrap --arch=arm64 --variant=minbase ${DEBIAN_RELEASE} /mnt/rootfs http://deb.debian.org/debian

            # Strip docs, man pages, and locales (slim image approach)
            mkdir -p /mnt/rootfs/etc/dpkg/dpkg.cfg.d
            cat > /mnt/rootfs/etc/dpkg/dpkg.cfg.d/01-nodoc << DPKGEOF
path-exclude /usr/share/doc/*
path-exclude /usr/share/man/*
path-exclude /usr/share/info/*
path-exclude /usr/share/locale/*
path-include /usr/share/locale/en*
DPKGEOF

            # Install essential packages
            chroot /mnt/rootfs apt-get update -qq
            chroot /mnt/rootfs apt-get install -y -qq --no-install-recommends \
                ca-certificates curl git iproute2 \
                openssh-client jq less procps xz-utils libgomp1 > /dev/null 2>&1

            # Clean up docs that debootstrap already installed
            rm -rf /mnt/rootfs/usr/share/doc/* /mnt/rootfs/usr/share/man/* /mnt/rootfs/usr/share/info/*
            find /mnt/rootfs/usr/share/locale -mindepth 1 -maxdepth 1 ! -name "en*" -exec rm -rf {} + 2>/dev/null || true

            chroot /mnt/rootfs apt-get clean
            rm -rf /mnt/rootfs/var/lib/apt/lists/*

            # Install guest binary
            cp /tmp/shuru-guest /mnt/rootfs/usr/bin/shuru-init
            chmod 755 /mnt/rootfs/usr/bin/shuru-init

            # Basic configuration
            mkdir -p /mnt/rootfs/proc /mnt/rootfs/sys /mnt/rootfs/dev /mnt/rootfs/tmp /mnt/rootfs/run
            echo "shuru" > /mnt/rootfs/etc/hostname
            echo "nameserver 8.8.8.8" > /mnt/rootfs/etc/resolv.conf

            umount /mnt/rootfs
            echo "==> Debian rootfs populated successfully"
        '
else
    # Linux: can use native tools
    MISSING_PKGS=""
    command -v mkfs.ext4 &>/dev/null || MISSING_PKGS="e2fsprogs"
    command -v debootstrap &>/dev/null || MISSING_PKGS="${MISSING_PKGS} debootstrap"
    if [ -n "$MISSING_PKGS" ]; then
        sudo apt-get update && sudo apt-get install -y $MISSING_PKGS
    fi

    mkfs.ext4 -F "$ROOTFS_IMG"
    MOUNT_DIR=$(mktemp -d)
    sudo mount -o loop "$ROOTFS_IMG" "$MOUNT_DIR"

    echo "==> Running debootstrap (this may take a few minutes)..."
    sudo debootstrap --arch=arm64 --variant=minbase "${DEBIAN_RELEASE}" "$MOUNT_DIR" http://deb.debian.org/debian

    # Strip docs, man pages, and locales (slim image approach)
    sudo mkdir -p "${MOUNT_DIR}/etc/dpkg/dpkg.cfg.d"
    cat <<'DPKGEOF' | sudo tee "${MOUNT_DIR}/etc/dpkg/dpkg.cfg.d/01-nodoc" > /dev/null
path-exclude /usr/share/doc/*
path-exclude /usr/share/man/*
path-exclude /usr/share/info/*
path-exclude /usr/share/locale/*
path-include /usr/share/locale/en*
DPKGEOF

    # Install essential packages
    sudo chroot "$MOUNT_DIR" apt-get update -qq
    sudo chroot "$MOUNT_DIR" apt-get install -y -qq --no-install-recommends \
        ca-certificates curl git iproute2 \
        openssh-client jq less procps xz-utils libgomp1 > /dev/null 2>&1

    # Clean up docs that debootstrap already installed
    sudo rm -rf "${MOUNT_DIR}/usr/share/doc/"* "${MOUNT_DIR}/usr/share/man/"* "${MOUNT_DIR}/usr/share/info/"*
    sudo find "${MOUNT_DIR}/usr/share/locale" -mindepth 1 -maxdepth 1 ! -name "en*" -exec rm -rf {} + 2>/dev/null || true

    sudo chroot "$MOUNT_DIR" apt-get clean
    sudo rm -rf "${MOUNT_DIR}/var/lib/apt/lists/"*

    # Install guest binary
    sudo cp "$GUEST_BINARY" "${MOUNT_DIR}/usr/bin/shuru-init"
    sudo chmod 755 "${MOUNT_DIR}/usr/bin/shuru-init"

    # Basic configuration
    sudo mkdir -p "${MOUNT_DIR}/proc" "${MOUNT_DIR}/sys" "${MOUNT_DIR}/dev" "${MOUNT_DIR}/tmp" "${MOUNT_DIR}/run"
    echo "shuru" | sudo tee "${MOUNT_DIR}/etc/hostname" > /dev/null
    echo "nameserver 8.8.8.8" | sudo tee "${MOUNT_DIR}/etc/resolv.conf" > /dev/null

    sudo umount "$MOUNT_DIR"
    rmdir "$MOUNT_DIR" 2>/dev/null || true
fi
fi # rootfs existence check

echo ""
echo "==> Done!"
echo "    Kernel:     ${KERNEL_PATH}"
echo "    Initramfs:  ${INITRAMFS_PATH}"
echo "    Rootfs:     ${ROOTFS_IMG}"
echo ""
echo "    To run:  cargo build -p shuru-cli && codesign --entitlements shuru.entitlements --force -s - target/debug/shuru"
echo "             ./target/debug/shuru run -- echo hello"
