#!/bin/bash
set -euo pipefail

ALPINE_VERSION="3.21"
ALPINE_RELEASE="3.21.3"
ARCH="aarch64"
DATA_DIR="${HOME}/.local/share/shuru"
ROOTFS_IMG="${DATA_DIR}/rootfs.ext4"
KERNEL_PATH="${DATA_DIR}/Image"
INITRAMFS_PATH="${DATA_DIR}/initramfs.cpio.gz"
GUEST_BINARY="target/aarch64-unknown-linux-musl/release/shuru-guest"
ROOTFS_SIZE_MB=512

ALPINE_MIRROR="https://dl-cdn.alpinelinux.org/alpine"
MINIROOTFS_URL="${ALPINE_MIRROR}/v${ALPINE_VERSION}/releases/${ARCH}/alpine-minirootfs-${ALPINE_RELEASE}-${ARCH}.tar.gz"
KERNEL_PKG_URL="${ALPINE_MIRROR}/v${ALPINE_VERSION}/main/${ARCH}"

echo "==> Shuru rootfs preparation script"
echo "    Alpine ${ALPINE_RELEASE} for ${ARCH}"
echo ""

# Check for required tools
for tool in curl tar dd; do
    if ! command -v "$tool" &>/dev/null; then
        echo "ERROR: Required tool '$tool' not found."
        exit 1
    fi
done

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

mkdir -p "$DATA_DIR"

# --- Download Alpine minirootfs ---
MINIROOTFS_TAR="${DATA_DIR}/alpine-minirootfs-${ALPINE_RELEASE}-${ARCH}.tar.gz"
if [ ! -f "$MINIROOTFS_TAR" ]; then
    echo "==> Downloading Alpine minirootfs..."
    curl -L -o "$MINIROOTFS_TAR" "$MINIROOTFS_URL"
else
    echo "==> Alpine minirootfs already downloaded."
fi

# --- Download kernel ---
if [ ! -f "$KERNEL_PATH" ]; then
    echo "==> Downloading Alpine linux-virt kernel (VirtIO built-in)..."
    TMPDIR=$(mktemp -d)
    trap "rm -rf $TMPDIR" EXIT

    curl -sL -o "${TMPDIR}/APKINDEX.tar.gz" "${KERNEL_PKG_URL}/APKINDEX.tar.gz"
    tar xzf "${TMPDIR}/APKINDEX.tar.gz" -C "$TMPDIR" 2>/dev/null || true

    VIRT_VERSION=$(awk '/^P:linux-virt$/{found=1} found && /^V:/{print substr($0,3); exit}' "${TMPDIR}/APKINDEX")
    if [ -z "$VIRT_VERSION" ]; then
        echo "ERROR: Could not find linux-virt package version in APKINDEX"
        exit 1
    fi
    echo "    Found linux-virt version: ${VIRT_VERSION}"

    VIRT_PKG="linux-virt-${VIRT_VERSION}.apk"
    curl -L -o "${TMPDIR}/${VIRT_PKG}" "${KERNEL_PKG_URL}/${VIRT_PKG}"

    mkdir -p "${TMPDIR}/kernel"
    tar xzf "${TMPDIR}/${VIRT_PKG}" -C "${TMPDIR}/kernel" 2>/dev/null || true

    if [ -f "${TMPDIR}/kernel/boot/vmlinuz-virt" ]; then
        echo "    Extracting uncompressed Image from vmlinuz-virt..."
        # Apple's VZLinuxBootLoader requires the uncompressed ARM64 Image format.
        # vmlinuz-virt is gzip-compressed with a PE32+ EFI stub header.
        # Extract the raw Image by finding and decompressing the gzip stream.
        python3 -c "
import zlib
data = open('${TMPDIR}/kernel/boot/vmlinuz-virt', 'rb').read()
# Find gzip magic (1f 8b 08)
for i in range(len(data) - 2):
    if data[i] == 0x1f and data[i+1] == 0x8b and data[i+2] == 0x08:
        try:
            d = zlib.decompressobj(-15)
            result = d.decompress(data[i+10:])
            result += d.flush()
            if len(result) > 0x40 and result[0x38:0x3c] == b'ARMd':
                with open('${KERNEL_PATH}', 'wb') as f:
                    f.write(result)
                print(f'Extracted {len(result)} byte ARM64 Image')
                break
        except:
            continue
else:
    print('ERROR: Could not extract kernel Image')
    exit(1)
"
        echo "    Kernel saved to ${KERNEL_PATH}"
    else
        echo "ERROR: vmlinuz-virt not found in the kernel package."
        echo "       Contents:"
        find "${TMPDIR}/kernel" -type f | head -20
        exit 1
    fi
else
    echo "==> Kernel already present."
fi

# --- Build initramfs with VirtIO block + vsock modules ---
# linux-virt has virtio, virtio_pci, virtio_console built-in (=y)
# but virtio_blk, virtio_net, vsock are still modules (=m)
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
        alpine:3.21 /bin/sh -c '
            set -e
            apk add --no-cache linux-virt kmod findutils cpio gzip > /dev/null 2>&1
            KVER=$(ls /lib/modules/ | head -1)
            echo "Kernel modules version: ${KVER}"

            # Create initramfs structure
            mkdir -p /initramfs/bin /initramfs/sbin /initramfs/etc
            mkdir -p /initramfs/proc /initramfs/sys /initramfs/dev
            mkdir -p /initramfs/newroot
            mkdir -p "/initramfs/lib/modules/${KVER}"

            # Busybox (static) for shell + utilities — must be statically linked
            # since initramfs has no dynamic linker
            apk add --no-cache busybox-static > /dev/null 2>&1
            cp /bin/busybox.static /initramfs/bin/busybox
            for cmd in sh mount umount switch_root modprobe insmod mkdir echo cat sleep mknod ln ifconfig route udhcpc; do
                ln -sf busybox "/initramfs/bin/${cmd}"
            done

            # resize2fs for growing the ext4 filesystem to fill the disk image
            # (dynamically linked, so we need the musl linker + shared libs)
            apk add --no-cache e2fsprogs-extra > /dev/null 2>&1
            cp /usr/sbin/resize2fs /initramfs/sbin/resize2fs
            mkdir -p /initramfs/lib
            cp /lib/ld-musl-aarch64.so.1 /initramfs/lib/
            for lib in $(ldd /usr/sbin/resize2fs | awk '\''/=>/{print $3}'\''); do
                cp "$lib" /initramfs/lib/
            done

            # Copy needed modules (virtio_blk, ext4, net, vsock and deps)
            echo "Copying kernel modules..."
            for mod in \
                kernel/drivers/block/virtio_blk.ko* \
                kernel/crypto/crc32c_generic.ko* \
                kernel/lib/libcrc32c.ko* \
                kernel/fs/ext4/ext4.ko* \
                kernel/fs/jbd2/jbd2.ko* \
                kernel/fs/mbcache.ko* \
                kernel/lib/crc16.ko* \
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
                kernel/net/packet/af_packet.ko* \
                kernel/fs/fuse/fuse.ko* \
                kernel/fs/fuse/virtiofs.ko* \
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

            # Create init script
            cat > /initramfs/init << '\''INITEOF'\''
#!/bin/sh
/bin/mount -t proc none /proc
/bin/mount -t sysfs none /sys
/bin/mount -t devtmpfs none /dev

echo "initramfs: loading modules..."
for mod in virtio_blk crc32c_generic libcrc32c jbd2 mbcache ext4 af_packet virtio_net vsock vmw_vsock_virtio_transport_common vmw_vsock_virtio_transport fuse virtiofs overlay; do
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
    cat /proc/partitions
    echo "Dropping to shell..."
    exec /bin/sh
fi

echo "initramfs: resizing filesystem..."
/sbin/resize2fs /dev/vda 2>/dev/null || true

echo "initramfs: mounting /dev/vda..."
/bin/mount -t ext4 /dev/vda /newroot

if [ ! -x /newroot/usr/bin/shuru-init ]; then
    echo "initramfs: ERROR - /usr/bin/shuru-init not found on root!"
    ls -la /newroot/sbin/ 2>/dev/null
    exec /bin/sh
fi

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

# --- Create ext4 rootfs image ---
echo "==> Creating ext4 rootfs image (${ROOTFS_SIZE_MB}MB)..."

# Create empty image file
dd if=/dev/zero of="$ROOTFS_IMG" bs=1M count="$ROOTFS_SIZE_MB" 2>&1

if [[ "$(uname)" == "Darwin" ]]; then
    echo ""
    echo "==> macOS detected. Using Docker for ext4 formatting and population."
    echo ""

    DOCKER_WORKDIR=$(mktemp -d)
    cp "$MINIROOTFS_TAR" "${DOCKER_WORKDIR}/rootfs.tar.gz"
    cp "$GUEST_BINARY" "${DOCKER_WORKDIR}/shuru-guest"

    # Format + populate entirely inside Docker
    docker run --rm --privileged \
        --platform linux/arm64/v8 \
        -v "${ROOTFS_IMG}:/rootfs.ext4" \
        -v "${DOCKER_WORKDIR}:/workdir:ro" \
        alpine:3.21 /bin/sh -c '
            set -e
            apk add --no-cache e2fsprogs > /dev/null 2>&1
            mkfs.ext4 -F /rootfs.ext4
            mkdir -p /mnt/rootfs
            mount -o loop /rootfs.ext4 /mnt/rootfs
            tar xzf /workdir/rootfs.tar.gz -C /mnt/rootfs
            cp /workdir/shuru-guest /mnt/rootfs/usr/bin/shuru-init
            chmod 755 /mnt/rootfs/usr/bin/shuru-init
            mkdir -p /mnt/rootfs/proc /mnt/rootfs/sys /mnt/rootfs/dev /mnt/rootfs/tmp /mnt/rootfs/run
            echo "shuru" > /mnt/rootfs/etc/hostname
            echo "nameserver 8.8.8.8" > /mnt/rootfs/etc/resolv.conf
            umount /mnt/rootfs
            echo "==> Rootfs populated successfully"
        '

    rm -rf "$DOCKER_WORKDIR"
else
    # Linux: can use native tools
    if ! command -v mkfs.ext4 &>/dev/null; then
        sudo apt-get update && sudo apt-get install -y e2fsprogs
    fi
    mkfs.ext4 -F "$ROOTFS_IMG"
    MOUNT_DIR=$(mktemp -d)
    sudo mount -o loop "$ROOTFS_IMG" "$MOUNT_DIR"
    sudo tar xzf "$MINIROOTFS_TAR" -C "$MOUNT_DIR"
    sudo cp "$GUEST_BINARY" "${MOUNT_DIR}/usr/bin/shuru-init"
    sudo chmod 755 "${MOUNT_DIR}/usr/bin/shuru-init"
    sudo mkdir -p "${MOUNT_DIR}/proc" "${MOUNT_DIR}/sys" "${MOUNT_DIR}/dev" "${MOUNT_DIR}/tmp" "${MOUNT_DIR}/run"
    echo "shuru" | sudo tee "${MOUNT_DIR}/etc/hostname" > /dev/null
    echo "nameserver 8.8.8.8" | sudo tee "${MOUNT_DIR}/etc/resolv.conf" > /dev/null
    sudo umount "$MOUNT_DIR"
    rmdir "$MOUNT_DIR" 2>/dev/null || true
fi

echo ""
echo "==> Done!"
echo "    Kernel:     ${KERNEL_PATH}"
echo "    Initramfs:  ${INITRAMFS_PATH}"
echo "    Rootfs:     ${ROOTFS_IMG}"
echo ""
echo "    To run:  cargo build -p shuru-cli && codesign --entitlements shuru.entitlements --force -s - target/debug/shuru"
echo "             ./target/debug/shuru run -- echo hello"
