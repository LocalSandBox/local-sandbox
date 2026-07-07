# RFC: Windows Backend for LocalSandbox using QEMU + WHPX

## 2. Status

Status: Historical RFC; Windows MVP implemented for upstream review
Author: Cai Kaian
Date: 2026-07-02
Target repo path: `docs/windows-port/rfc-qemu-whpx.md`

Post-MVP note: this RFC is retained for design rationale and alternatives. The
current implementation status, limitations, validation evidence, and follow-up
work are tracked in `docs/windows-port/mvp-handoff.md`,
`docs/windows-port/decisions.md`, and the other durable docs in
`docs/windows-port/`. In particular, D023 supersedes the original MVP-only
statement that Windows direct `:rw` mounts were unsupported; explicit Windows
direct mounts now use SMB/CIFS.

## 3. Executive Summary

This RFC proposes a native Windows 11 x86_64 backend for LocalSandbox using QEMU as the virtual machine monitor and device model, accelerated by the Windows Hypervisor Platform through QEMU's WHPX accelerator. The backend continues to boot the existing LocalSandbox Linux guest model: a Linux kernel image, initramfs, root filesystem, and `lsb-guest` agent. It does not propose Windows guests, Hyper-V Manager VMs, WSL2, containers, or a custom raw WHP VMM.

The goal is to preserve LocalSandbox product semantics, not merely to make QEMU boot Linux. The Windows backend must keep the public CLI, Rust SDK, and Node API stable; keep no-network-by-default; keep host secrets outside the guest; keep controlled proxy-based network behavior; keep overlay mounts read-only from the product perspective; and keep checkpoint semantics explicit. Explicit direct mounts are the exception covered by D023 and use SMB/CIFS.

The proposed MVP path is staged:

1. Compile on Windows with platform-neutral VM traits and Windows stubs.
2. Discover and preflight `qemu-system-x86_64.exe`, requiring WHPX for production runs.
3. Boot the existing x86_64 Linux guest with QEMU direct Linux boot, a virtio block root disk, serial logs, QMP for QEMU lifecycle diagnostics, and no guest NIC by default.
4. Replace the macOS AF_VSOCK control transport with QEMU virtio-serial over a private Windows named pipe, while keeping `lsb-proto` as the guest command protocol.
5. Implement initial exec and file operations, then add a transport-level multiplexer for concurrent exec, watch, and port forwarding sessions.
6. Implement Windows mount MVP as copy-in/copy-out into guest-owned tmpfs or disk staging, preserving host-read-only and isolated-writes semantics while explicitly not promising live shared mount coherence. Post-MVP direct mounts are covered separately by D023 and use SMB/CIFS.
7. Implement host-to-guest port forwarding without enabling a general guest NIC.
8. Reintroduce policy-bearing proxy networking through a Windows-compatible QEMU network backend only when it can preserve allowlist and secret substitution semantics.
9. Implement checkpoint MVP using immutable base rootfs plus per-sandbox writable qcow2 overlays, deferring CAS/NBD until Windows storage transport is validated.
10. Add Windows Node packaging after core CLI/backend smoke tests pass.

Key platform facts: Microsoft documents WHP as a user-mode API for third-party virtualization stacks such as QEMU to create/manage hypervisor partitions and virtual processors [ms-hyperv-apis]. QEMU documents WHPX as its Windows Hypervisor Platform accelerator backend; QEMU still provides the VMM and virtual devices [qemu-whpx]. QEMU documents direct Linux boot using `-kernel`, `-append`, and `-initrd`, which matches LocalSandbox's current asset model [qemu-linuxboot].

## 4. Goals

### Product goals

- Boot LocalSandbox's existing Linux guest model on Windows 11 x86_64.
- Preserve current CLI, SDK, and Node API shape where possible.
- Preserve no-network-by-default.
- Preserve controlled secret behavior: real secrets remain on the host and are substituted only by the host proxy for approved destinations.
- Preserve proxy-owned egress policy rather than treating QEMU NAT as policy.
- Preserve host-source read-only mount semantics from the product perspective for overlay mounts.
- Preserve isolated guest writes for overlay mounts.
- Preserve explicit checkpoint semantics.
- Make unsupported Windows MVP features fail with precise capability errors rather than silent behavior changes.

### Engineering goals

- Introduce a stable platform-neutral VM backend boundary that supports both the existing macOS backend and a Windows QEMU backend.
- Keep macOS behavior as unchanged as possible while extracting shared abstractions.
- Build Windows support incrementally through testable milestones.
- Make QEMU invocation deterministic through a typed argv builder and golden tests.
- Keep production Windows runs WHPX-only; allow hidden/debug-only TCG only for diagnostics.
- Use private Windows IPC objects for QEMU control and guest control channels.
- Capture enough diagnostics for coding agents and humans to debug boot, control, mount, network, and checkpoint failures.
- Support a self-hosted Windows 11 x86_64 CI runner for WHPX boot smoke tests.

## 5. Non-goals

- Running Windows guests.
- Replacing the Linux guest model.
- Implementing a full VMM directly on raw WHP APIs.
- Managing Hyper-V Manager, WMI, or HCS VMs for the MVP.
- Shipping QEMU inside CLI, npm, or runtime guest asset archives for the MVP.
- Allowing TCG fallback for normal production runs.
- Providing perfect POSIX live filesystem sharing in the MVP.
- Supporting direct Windows host `:rw` mounts in the MVP. This is historical; D023 later approves explicit Windows direct mounts through SMB/CIFS.
- Enabling arbitrary bridged, TAP, or QEMU user networking by default.
- Treating QEMU NAT/user networking as LocalSandbox security policy.
- Production-grade live migration or QEMU VM-state snapshots.
- Supporting Windows on ARM64 in the MVP; ARM64 remains planned/future.

## 6. Current LocalSandbox Architecture

This section describes the repository as of inspection of `main`. Facts in this section come from repository files, with inferences labeled.

### 6.1 Crate map

| Crate / path          | Current role                                                                                                                                                       | Source                                           |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------ |
| `crates/lsb-cli`      | CLI entrypoint, config, checkpoint commands, VM preparation.                                                                                                       | [repo-cargo], [repo-cli-checkpoint]              |
| `crates/lsb-sdk`      | Rust SDK surface used by bindings.                                                                                                                                 | [repo-cargo]                                     |
| `crates/lsb-vm`       | Host-side sandbox orchestration: config builder, VM lifecycle wrapper, exec/file/watch/port APIs, mount request dispatch. Currently hard-gated to macOS.           | [repo-lsb-vm-lib], [repo-lsb-vm-sandbox]         |
| `crates/lsb-platform` | Platform metadata and macOS VM backend. Has planned Windows metadata but no Windows runtime implementation.                                                        | [repo-lsb-platform-lib], [repo-windows-x86-spec] |
| `crates/lsb-proto`    | Custom host/guest frame protocol and request/response types. Defines `VSOCK_PORT = 1024` and `VSOCK_PORT_FORWARD = 1025`.                                          | [repo-lsb-proto]                                 |
| `crates/lsb-guest`    | Linux guest agent. Runs guest init tasks, listens on AF_VSOCK, handles exec, fs, mount, watch, and port-forward protocol.                                          | [repo-lsb-guest]                                 |
| `crates/lsb-proxy`    | Host-side proxy and policy engine for network allowlists, host port exposure, and secret substitution.                                                             | [repo-proxy-config]                              |
| `crates/lsb-store`    | CAS/NBD-backed rootfs/checkpoint storage. Current NBD server is Unix-domain-socket based.                                                                          | [repo-store]                                     |
| `bindings/nodejs`     | NAPI Node/TypeScript binding. Current supported packages are macOS-only.                                                                                           | [repo-node-readme]                               |
| `kernel`              | Linux kernel configs and guest runtime assets. x86_64 config includes virtio block, console, net, vsock, virtiofs, overlayfs, ext4, FUSE, namespaces, and inotify. | [repo-kernel-x86]                                |
| `.github/workflows`   | Current Rust CI and Node binding CI are macOS-oriented for runtime builds; Node binding build matrix targets macOS.                                                | [repo-ci], [repo-node-ci]                        |

The top-level workspace includes `lsb-cli`, `lsb-platform`, `lsb-proto`, `lsb-proxy`, `lsb-sdk`, `lsb-vm`, `lsb-store`, `lsb-guest`, and `xtask` [repo-cargo].

### 6.2 VM lifecycle and asset expectations

Current `lsb-platform::asset_paths(data_dir)` derives these runtime asset paths: `VERSION`, `Image`, `rootfs.ext4`, `initramfs.cpio.gz`, `checkpoints`, and `instances` [repo-lsb-platform-lib]. The Node README states that `Sandbox.start()` expects the runtime data directory to already contain `Image`, `rootfs.ext4`, and `initramfs.cpio.gz`; it does not download assets implicitly [repo-node-readme].

The current VM builder in `lsb-vm` accepts kernel/rootfs/initrd paths, CPU and memory, console/verbose settings, optional network fd, optional NBD URI, and mount configuration. It builds a platform VM through `lsb_platform::create_vm(...)` [repo-lsb-vm-sandbox].

### 6.3 macOS backend

The macOS backend uses Apple Virtualization.framework bindings. It configures:

- `VZLinuxBootLoader` equivalent via wrapper code.
- Kernel command line `console=hvc0 root=/dev/vda rw`, adding `quiet` unless verbose.
- A virtio block root disk from either a disk image attachment or NBD URI.
- Optional file-handle virtio-net device when `network_fd` is provided.
- VirtioFS shared directories for mounts.
- A virtio socket device for host/guest protocol.
- Virtio entropy and memory balloon devices.
- Serial console routing to stdin/stdout, stderr, or `/dev/null` depending on mode.

This is visible in the macOS platform modules and `create_vm` logic [repo-macos-x86], [repo-macos-arm].

### 6.4 Guest/host protocol

`lsb-proto` defines a custom binary framing layer: length-prefixed frames, frame type bytes, and JSON or binary payloads. The protocol includes exec, stdin/stdout/stderr/exit/error/kill, file operations, directory/stat/remove/rename/copy/chmod, mount requests, watch requests, and port-forward requests. The current transport assumption is AF_VSOCK, with control port `1024` and forwarding port `1025` [repo-lsb-proto].

The host `Sandbox` currently opens a vsock connection per operation through `connect_vsock()`, sends pending mount requests before the first operation, and then sends protocol frames for exec or file operations [repo-lsb-vm-sandbox]. The guest creates AF_VSOCK listeners and processes protocol requests [repo-lsb-guest].

### 6.5 Mount semantics

README states that directory mounts use VirtioFS. The host directory is read-only, and guest writes go to a tmpfs overlay layer discarded when the VM exits [repo-readme]. The guest implements this by mounting VirtioFS under `/mnt/.virtiofs/<tag>`, mounting tmpfs for overlay state under `/mnt/.overlay/<tag>`, and mounting overlayfs at the requested target [repo-lsb-guest].

The CLI/Node surfaces also expose direct mounts with flags, where `flags = 0` is read-write and `flags = 1` is `MS_RDONLY`; product documentation treats overlay mounts as the safe default [repo-node-readme].

### 6.6 Networking, proxy, secrets, and port forwarding

README states that `--allow-net` routes guest DNS through the host-side proxy at `10.0.0.1`, and that port forwarding works over vsock without `--allow-net`; the guest needs no network device for port forwarding [repo-readme].

`lsb-proxy` contains product policy. It stores real secret values on the host, gives the guest random placeholder tokens, and substitutes placeholders only when the request targets configured host patterns. It supports exact and wildcard domain allowlists. It also exposes host ports to the guest via gateway IP `10.0.0.1` [repo-proxy-config].

Current implementation details are macOS/Unix-specific: `lsb-vm` has `network_fd`, and the macOS backend attaches that fd as a file-handle network device; `lsb-proxy` uses Unix fd/socket behavior. The Windows backend needs a different QEMU network attachment while preserving the proxy's policy role.

### 6.7 Checkpoints and store

README states that checkpoints save disk state and that CAS/NBD indexes reference a pinned base rootfs by runtime asset version. Existing checkpoints continue to use the base rootfs version they were created from [repo-readme].

The CLI checkpoint code saves `.idx` checkpoints when an NBD handle exists, otherwise it clones an `.ext4` checkpoint file. Listing/deletion handles both `.idx` and `.ext4` checkpoint files [repo-cli-checkpoint]. `lsb-store` currently starts an NBD server over a Unix domain socket and exposes URIs like `nbd+unix:///export?socket=...` [repo-store]. This is not directly portable to native Windows as implemented.

### 6.8 Current architecture diagram

```text
lsb CLI / Rust SDK / Node binding
        |
        v
crates/lsb-vm Sandbox
        |
        v
crates/lsb-platform macOS backend
        |
        +--> Apple Virtualization.framework VM
        |       |
        |       +--> Linux bootloader: Image + initramfs + cmdline
        |       +--> virtio-blk rootfs or NBD URI
        |       +--> VirtioFS shared dirs
        |       +--> virtio socket device
        |       +--> optional file-handle virtio-net device
        |
        +--> lsb-proxy when --allow-net is enabled
        +--> lsb-store for CAS/NBD checkpoints

Inside guest:
Linux kernel + initramfs + rootfs + lsb-guest
        |
        +--> lsb-proto over AF_VSOCK
        +--> exec / fs / mount / watch / port-forward handlers
```

## 7. Proposed Windows Architecture

The proposed Windows backend keeps the LocalSandbox guest model and product API while replacing Apple Virtualization.framework with a QEMU process supervised by Rust.

```text
lsb-cli / lsb-sdk / Node binding
        |
        v
lsb-vm platform-neutral API
        |
        v
Windows QEMU backend
        |
        +--> qemu-system-x86_64.exe
        |       |
        |       +--> WHPX / Windows Hypervisor Platform
        |       +--> direct Linux boot: Image + initramfs + cmdline
        |       +--> virtio-blk root disk
        |       +--> virtio-serial control channel
        |       +--> QMP lifecycle/diagnostic channel
        |       +--> optional virtio-net attached only to lsb-proxy
        |       +--> optional later mount backend experiments
        |
        +--> lsb-proxy
        +--> lsb-store / checkpoint manager
        +--> logs/artifacts
        +--> Windows Job Object cleanup

Inside guest:
Linux kernel + initramfs + rootfs + lsb-guest
        |
        +--> same lsb-proto payloads
        +--> transport adapter: virtio-serial for Windows MVP
        +--> existing exec / fs / watch / forwarding handlers
        +--> mount import/export handlers for Windows MVP
```

### 7.1 Responsibilities

| Layer                       | Provides                                                                                                                                                                                                                 | Does not provide                                                                         |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------- |
| Microsoft Hyper-V/WHP       | Hardware virtualization substrate, partitions, virtual processor execution, memory mappings through WHP APIs.                                                                                                            | LocalSandbox guest protocol, QEMU device model, QEMU argv, LocalSandbox security policy. |
| QEMU                        | VMM process, PC/q35 machine model, virtio devices, direct Linux boot, block device model, chardevs, QMP, optional network backends.                                                                                      | Domain allowlist policy, secret substitution, LocalSandbox exec/fs API semantics.        |
| WHPX                        | QEMU accelerator backend for CPU virtualization through Windows Hypervisor Platform.                                                                                                                                     | A Hyper-V Manager VM or complete device model.                                           |
| LocalSandbox Rust host code | Backend abstraction, QEMU discovery/preflight, argv construction, process supervision, Windows Job Object cleanup, QMP client, guest control transport, mount import/export, proxy/store integration, API compatibility. | Raw hypervisor implementation.                                                           |
| Linux guest                 | Kernel drivers, initramfs/rootfs, `lsb-guest`, exec/fs/watch/forward handlers, proxy-oriented network configuration when allowed.                                                                                        | Host security boundary against QEMU compromise; Windows filesystem semantics.            |

Microsoft distinguishes WHP from HCS/WMI: WHP requires a third-party virtualization stack to run the VM, while HCS/WMI are Windows virtualization stack APIs with different management models [ms-hyperv-apis]. This RFC chooses QEMU + WHPX, not Hyper-V-managed VMs.

## 8. Why QEMU + WHPX

### 8.1 Decision

Use QEMU with `-accel whpx` as the Windows backend for LocalSandbox on Windows 11 x86_64.

QEMU + WHPX is the closest Windows equivalent to the current product architecture because it allows LocalSandbox to keep controlling Linux boot assets, virtio devices, guest protocol, proxy semantics, and checkpoint disks from a normal host process. WHPX accelerates CPU virtualization; QEMU remains the VMM/device model [qemu-whpx].

Production runs must require WHPX. TCG may exist only behind hidden/debug diagnostics and must never be silently selected. QEMU documents that when multiple accelerators are specified, the next one may be used if the previous fails; LocalSandbox must not specify `whpx:tcg` or any equivalent fallback in production [qemu-invocation].

### 8.2 Decision table

| Alternative                  |        Fit | Pros                                                                                                        | Cons                                                                                                                                                                                                     | Decision                                                                   |
| ---------------------------- | ---------: | ----------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| QEMU + WHPX                  |       High | Direct Linux boot, virtio devices, mature block/network tooling, QMP diagnostics, no need to implement VMM. | QEMU process attack surface; Windows-specific chardev/network quirks; live mount uncertainty.                                                                                                            | Select.                                                                    |
| Hyper-V Manager / WMI        |        Low | First-party Hyper-V management.                                                                             | Heavy VM model, default devices/policies, less direct control over LocalSandbox boot/device semantics. Microsoft notes WMI is tailored to higher-level server virtualization workflows [ms-hyperv-apis]. | Reject for MVP.                                                            |
| HCS                          | Medium/low | First-party API used for local VM/container workflows.                                                      | Different lifecycle/model; more Windows-platform ownership; less direct parity with QEMU devices and direct Linux boot; would still need guest/control/mount/proxy design.                               | Reject for MVP; keep as future alternative only if QEMU proves unsuitable. |
| Raw WHP API VMM              |        Low | Maximum control.                                                                                            | Requires implementing VMM/device model, virtio, boot, block, network, debug tooling. Microsoft describes WHP as an API used by third-party stacks, not a full VMM [ms-hyperv-apis].                      | Reject.                                                                    |
| WSL2                         |        Low | Ubiquitous Linux environment on Windows.                                                                    | Shared distro model, different isolation semantics, network/filesystem semantics differ from LocalSandbox microVM model.                                                                                 | Reject.                                                                    |
| Docker/containers            |        Low | Familiar packaging.                                                                                         | Requires container runtime; weaker match to VM isolation and LocalSandbox rootfs/checkpoint model.                                                                                                       | Reject.                                                                    |
| Firecracker/cloud-hypervisor | Medium/low | MicroVM orientation.                                                                                        | Windows host support and WHPX maturity are concerns; QEMU is the better first Windows backend.                                                                                                           | Reject for MVP.                                                            |
| QEMU TCG                     |        Low | Useful for debugging boot without WHPX.                                                                     | Too slow and semantically different for production; would hide preflight failures.                                                                                                                       | Hidden/debug only.                                                         |

## 9. Hyper-V / WHPX / QEMU Mental Model

Hyper-V is a hypervisor-based virtualization technology. Microsoft describes a root partition running Windows and child partitions hosting guest operating systems; child partitions see virtualized devices and memory/CPU resources rather than direct hardware [ms-hyperv-architecture].

WHP is the Windows Hypervisor Platform API for third-party virtualization stacks. It lets a user-mode VMM create and manage partitions, configure memory mappings, and control virtual processors [ms-hyperv-apis]. QEMU is such a VMM. WHPX is QEMU's accelerator backend that uses WHP for CPU virtualization [qemu-whpx].

Practical model for this port:

```text
Windows root partition
        |
        +--> LocalSandbox host process
                |
                +--> qemu-system-x86_64.exe
                        |
                        +--> WHPX: run guest vCPUs through Windows hypervisor
                        +--> QEMU: emulate machine/devices and handle VM exits
                        +--> virtio devices: block, serial, net, rng, balloon
                        +--> QMP: machine lifecycle/diagnostic API

Guest partition/effective VM:
        |
        +--> Linux kernel
        +--> lsb-guest
        +--> sandboxed workload
```

A VM exit matters here only when it affects design: guest I/O to emulated devices exits to QEMU; QEMU handles virtio queues, serial pipes, block I/O, and network backends. The Windows Rust backend must therefore treat QEMU as a long-running supervised subprocess with private control sockets/pipes and robust cleanup.

## 10. Boot Design

### 10.1 Recommendation

Use QEMU direct Linux boot for MVP:

- `-kernel <Image>`
- `-initrd <initramfs.cpio.gz>` when available
- `-append "console=ttyS0 root=/dev/vda rw ..."`
- virtio block root disk attached as `/dev/vda`
- serial console captured to per-instance log file
- no guest NIC by default
- QMP over a private pipe for lifecycle/diagnostics

QEMU documents direct Linux boot with `-kernel`, `-append`, and optional `-initrd` [qemu-linuxboot]. This is a better fit than UEFI/firmware boot because the current LocalSandbox runtime assets are already kernel/initramfs/rootfs paths, not a complete bootable disk image.

### 10.2 Root disk strategy

MVP root disk should be a qcow2 writable overlay over the immutable `rootfs.ext4` raw base:

```powershell
qemu-img.exe create -f qcow2 -F raw -b C:\lsb\rootfs.ext4 C:\lsb\instances\<id>\root.qcow2
```

QEMU documents that qcow2 supports backing files, and that when a backing file is specified, the new image records only differences while the backing file is not modified unless an explicit commit operation is used [qemu-img], [qemu-images]. This matches LocalSandbox's ephemeral-per-run rootfs and checkpoint model better than copying the whole ext4 base for every instance.

Fallback: if qcow2 backing files cause Windows-specific issues, use a full copied raw rootfs for the first boot smoke tests only. Do not make full raw copies the desired long-term Windows checkpoint design.

### 10.3 Guest ready handshake

Current macOS code assumes the host can connect to the guest vsock service once the VM is booted. Windows MVP should make readiness explicit:

1. QEMU process starts.
2. Host connects to the virtio-serial named pipe.
3. Guest `lsb-guest` opens the virtio-serial device.
4. Guest sends `GuestReady { protocol_version, transport, features }`.
5. Host validates version/features and only then exposes `Sandbox.start()` success.

Do not infer readiness from serial log substrings except as diagnostics.

### 10.4 Kernel/initramfs compatibility risks

The x86_64 kernel config is labeled for Apple Virtualization.framework, but it already includes `CONFIG_VIRTIO_BLK`, `CONFIG_VIRTIO_CONSOLE`, `CONFIG_VIRTIO_NET`, `CONFIG_VIRTIO_BALLOON`, `CONFIG_VIRTIO_FS`, `CONFIG_VIRTIO_VSOCKETS`, ext4, overlayfs, FUSE, tmpfs, namespaces, and inotify [repo-kernel-x86]. This is promising but not a guarantee. Validate on Windows/QEMU with a boot smoke test.

Potential changes:

- Ensure `CONFIG_SERIAL_8250` or equivalent serial console support if using `console=ttyS0`. If not present, either enable it or use a virtio console for logs.
- Keep `CONFIG_VIRTIO_CONSOLE` for virtio-serial.
- Keep `CONFIG_EXT4_FS` for root disk.
- Add `CONFIG_HYPERV_VSOCKETS` only if Hyper-V sockets are later selected; they are not MVP.

### 10.5 Illustrative QEMU command

This command is illustrative. The implementation must construct argv as a vector, never by shell-concatenating strings. The MVP uses a conservative `Westmere` CPU model for WHPX compatibility; see `decisions.md` D020.

```powershell
qemu-system-x86_64.exe `
  -nodefaults `
  -machine q35,accel=whpx `
  -cpu Westmere `
  -smp 2 `
  -m 2048M `
  -no-reboot `
  -display none `
  -monitor none `
  -kernel C:\Users\me\AppData\Local\lsb\Image `
  -initrd C:\Users\me\AppData\Local\lsb\initramfs.cpio.gz `
  -append "console=ttyS0 root=/dev/vda rw panic=-1 lsb.transport=virtio-serial" `
  -drive if=none,id=root,file=C:\Users\me\AppData\Local\lsb\instances\abc\root.qcow2,format=qcow2,cache=writeback,discard=unmap `
  -device virtio-blk-pci,drive=root `
  -serial file:C:\Users\me\AppData\Local\lsb\instances\abc\serial.log `
  -device virtio-serial-pci,id=lsbserial0 `
  -chardev pipe,id=lsbctl,path=lsb-abc-control `
  -device virtserialport,chardev=lsbctl,name=org.localsandbox.control `
  -qmp pipe:lsb-abc-qmp,server=on,wait=off `
  -nic none
```

Notes:

- `-nic none` is required because QEMU user networking must not appear by default. QEMU documents user networking as default when no network option is specified in some configurations [qemu-net].
- `-chardev pipe` on Windows creates a duplex named pipe at `\\.\pipe\<path>` [qemu-chardev-pipe]. The backend should use per-instance random pipe names and restrictive ACLs where it creates or connects IPC endpoints.
- QMP is used for QEMU lifecycle and diagnostics, not for LocalSandbox guest exec/file APIs.

## 11. Control Plane Design

### 11.1 Current transport

Current LocalSandbox uses `lsb-proto` over AF_VSOCK. The protocol constants define control port `1024` and port-forward port `1025` [repo-lsb-proto]. The guest creates AF_VSOCK listeners [repo-lsb-guest]. The host opens a new vsock stream per operation and sends mount/exec/file frames [repo-lsb-vm-sandbox].

### 11.2 Transport comparison

| Option                             | Layer                           | Directionality                               | Windows feasibility                                                                                                                                                                                                     | Security implications                                                                           | Fit                                        |
| ---------------------------------- | ------------------------------- | -------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- | ------------------------------------------ |
| Existing AF_VSOCK via virtio-vsock | Guest/host stream transport     | Host to guest and guest to host if supported | Uncertain for QEMU-on-Windows host endpoint. Current kernel has virtio-vsock, but host support must be proven.                                                                                                          | Good if private to VM; preserves current connection model.                                      | Future validation, not MVP.                |
| Virtio-serial over QEMU named pipe | Virtio device plus QEMU chardev | Bidirectional byte stream                    | Good candidate. QEMU documents Windows duplex pipe chardevs [qemu-chardev-pipe], and current kernel has `CONFIG_VIRTIO_CONSOLE` [repo-kernel-x86].                                                                      | Private pipe can be per-user/per-instance; not IP-routable. Needs session mux for concurrency.  | MVP recommendation.                        |
| Hyper-V sockets                    | Hyper-V integration transport   | Bidirectional stream                         | Possible with Hyper-V-managed contexts; Microsoft requires Linux guest `CONFIG_VSOCKET=y` and `CONFIG_HYPERV_VSOCKETS=y` [ms-hvsocket]. Also involves service GUID registration. QEMU/WHPX integration path is not MVP. | Non-network transport, but more Windows-specific and may require admin registry setup.          | Later only if virtio-serial is inadequate. |
| QEMU hostfwd TCP                   | QEMU user networking            | Host to guest TCP                            | Easy with `-netdev user,hostfwd=...` [qemu-hostfwd].                                                                                                                                                                    | Requires guest NIC and QEMU user NAT; conflicts with no-network-by-default if used for control. | Debug fallback only.                       |
| QMP                                | QEMU monitor protocol           | Host to QEMU                                 | Good for VM lifecycle.                                                                                                                                                                                                  | Exposing QMP is dangerous; keep private pipe only.                                              | Use for QEMU control, not guest API.       |
| QEMU Guest Agent                   | Guest daemon protocol           | Host to guest daemon                         | Mature, supports file and exec operations [qemu-ga].                                                                                                                                                                    | Would duplicate/replace `lsb-guest`; different semantics and command model.                     | Do not use for product API MVP.            |

### 11.3 Recommendation

Use virtio-serial over a private QEMU named pipe for the Windows MVP control transport.

Keep existing `lsb-proto` payloads and request/response types. Add a transport abstraction so `lsb-vm` no longer assumes AF_VSOCK. The initial implementation may support one command session for boot smoke and exec. Before exposing full API parity, add a transport-level multiplexer so concurrent `exec`, `spawn`, `watch`, file operations, and host-to-guest port forwarding do not block each other on one physical virtio-serial stream.

Proposed layering:

```text
Windows named pipe
        |
        v
QEMU chardev pipe
        |
        v
virtio-serial port: org.localsandbox.control
        |
        v
Transport envelope: session_id, stream_kind, flags, len
        |
        v
Existing lsb-proto frames unchanged inside each session
```

A transport envelope is preferable to changing every `lsb-proto` request. It lets macOS keep vsock streams and Windows use multiplexed virtio-serial sessions behind the same platform-neutral `ControlTransport` API.

### 11.4 Guest changes

`lsb-guest` should be changed from "always create AF_VSOCK listeners" to "select a transport based on kernel command line or device discovery":

- `transport=vsock`: current macOS behavior.
- `transport=virtio-serial`: Windows MVP.

For virtio-serial, do not assume a udev-created `/dev/virtio-ports/...` symlink exists in the minimal guest. Implement robust discovery:

1. Prefer `/dev/virtio-ports/org.localsandbox.control` if present.
2. Else scan `/sys/class/virtio-ports/*/name` for `org.localsandbox.control` and open the corresponding device node.
3. Log discovered device path to serial.
4. Fail fast with a clear error if no control port is found.

### 11.5 QMP boundary

QMP must be treated as QEMU management only. It is appropriate for:

- query status,
- graceful shutdown attempts,
- block device inspection,
- stop/quit fallback,
- event logging,
- diagnostics.

It is not the LocalSandbox guest exec/file API. QMP documentation describes commands/events supported by the QEMU Monitor Protocol [qmp]. QGA has guest file and exec commands [qemu-ga], but LocalSandbox should keep its custom `lsb-guest` semantics for API compatibility and product-specific behavior.

## 12. Data Plane / File and Mount Design

### 12.1 Intended LocalSandbox semantics

Windows support must preserve these product-level semantics:

- Overlay host source directories are read-only from the product perspective.
- Guest writes to overlay mounted paths are isolated from the host by default.
- Windows overlay mount writes are discarded when the VM exits unless explicitly copied/exported through an API; they must not silently mutate host files.
- Direct host writes (`:rw`) were unsupported in the Windows MVP; D023 supersedes that for explicit SMB/CIFS direct mounts.
- Host file changes after VM start are not guaranteed to appear in the guest during MVP.
- Guest file watching during MVP observes the guest-side copy/staging view, not live host changes.

These are intentionally product semantics, not a promise of full POSIX shared filesystem behavior on Windows.

### 12.2 Root disk images

Recommended MVP:

- Keep `rootfs.ext4` immutable.
- Create per-instance writable qcow2 overlays.
- Open active instance overlays read-write.
- Never write to the base rootfs.
- Store checkpoint metadata that pins the base runtime version.

Use raw only for the immutable rootfs. Use qcow2 for overlays/checkpoints because qcow2 supports backing files and smaller sparse images [qemu-images].

### 12.3 Mount strategy options

| Option                               |    MVP fit | Pros                                                                                                                               | Cons                                                                                                | Decision                                 |
| ------------------------------------ | ---------: | ---------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- | ---------------------------------------- |
| Copy-in/copy-out through guest agent |       High | Preserves host-read-only; avoids uncertain Windows live mount stack; no admin drivers.                                             | No live host/guest coherence; large trees may be slow; file watch is guest-copy only.               | MVP.                                     |
| Read-only import disk image          |     Medium | Better for large trees; can mount read-only in guest.                                                                              | Requires image construction and path metadata mapping; more work than tar stream.                   | Later optimization.                      |
| VirtioFS                             |  Uncertain | Designed for local filesystem semantics and performance [virtiofs]. Current guest kernel has `CONFIG_VIRTIO_FS` [repo-kernel-x86]. | Windows host daemon/QEMU packaging/support must be validated; path/symlink/ACL semantics uncertain. | Validation experiment, not MVP.          |
| 9p/virtfs                            |  Uncertain | QEMU has `-fsdev` plus virtio-9p device options [qemu-virtfs].                                                                     | Semantics/performance weaker than virtiofs; Windows host path behavior must be tested.              | Validation experiment.                   |
| Virtual FAT / vvfat                  | Low/medium | Simple for small read-only source trees.                                                                                           | Poor POSIX metadata; write semantics risky.                                                         | Debug/experiment only.                   |
| Custom sync service                  |     Medium | Full control over Windows path normalization, filtering, copy/export, watch behavior.                                              | More code; eventual consistency complexity.                                                         | Potential long-term if virtiofs/9p fail. |
| Direct Windows `:rw` host mount      |        Low | Existing API has direct mode.                                                                                                      | Host mutation risk, symlink/junction escapes, case-insensitivity, ACL mismatches.                   | Non-goal for MVP; superseded by D023 SMB/CIFS direct mounts. |

### 12.4 Windows MVP mount plan

Implement overlay mounts as guest-side import staging:

1. Host validates and snapshots the mount source path before VM start or immediately after guest ready.
2. Host streams a tar-like archive over the LocalSandbox control protocol to `lsb-guest`.
3. Guest creates a tmpfs-backed staging area for the imported source.
4. Guest creates a tmpfs upper/work area and mounts overlayfs at the requested guest path, or simply exposes the tmpfs copy directly if overlayfs adds no value for a copy-only lower.
5. Guest writes remain in tmpfs and are discarded at VM exit.
6. Optional explicit export can stream selected output paths back to the host later; it must be user/API-directed, not automatic host mutation.

This differs from macOS VirtioFS internally, but preserves the product-level guarantee that host files are not modified and guest writes are isolated. It also avoids overcommitting to Windows VirtioFS or 9p support before validation.

### 12.5 File metadata rules for MVP

Windows source metadata cannot map perfectly to Linux POSIX metadata. MVP rules:

- Regular files and directories are supported.
- Executability may be inferred from existing mode metadata if available, common extensions, or an explicit option later. Default mode should be conservative and documented.
- Symlinks require careful handling. MVP should either preserve symlinks only when they resolve inside the mount root and can be represented safely, or copy their targets as regular files/directories with a warning. Do not follow symlinks/junctions outside the mount root silently.
- Windows junctions/reparse points must be rejected by default unless explicitly handled.
- Case collisions, such as `Foo` and `foo`, must be detected before import and reported as unsupported.
- File times may be preserved best-effort.
- ACLs are not preserved in MVP.
- Device files, FIFOs, sockets, and special files are unsupported.

### 12.6 Validation experiments for live mounts

Create `docs/windows-port/experiments/mounts.md` later with these experiments:

- QEMU 9p/virtfs on Windows host with read-only export of a tree containing symlinks, executable files, large directories, case collisions, unicode names, and file watching.
- VirtioFS on Windows host with QEMU and available virtiofsd variants; record packaging and privilege requirements.
- Read-only ext4 import image generation from Windows host path; measure build time and guest mount time.
- Custom sync service prototype with recursive copy, file watch, and explicit export.

## 13. Networking and Security Design

### 13.1 Product requirements

- No network device by default.
- Host-to-guest port forwarding must work without enabling arbitrary outbound guest networking.
- `--allow-net` must route through LocalSandbox policy code, not raw QEMU NAT.
- Domain allowlists must block unapproved destinations.
- Direct IP and non-proxied UDP must not bypass policy unless explicitly allowed in a future design.
- Real secrets must remain on the host and be substituted only by the host proxy for configured hosts.

### 13.2 Default network mode

Default Windows QEMU argv must include `-nic none`.

Rationale: QEMU user networking is convenient, but QEMU documents it as a user-mode network stack with guest DHCP/DNS and outbound Internet path [qemu-net]. That is not LocalSandbox's no-network-by-default contract.

### 13.3 Port forwarding mode

Host-to-guest port forwarding should preserve current semantics: no guest NIC required.

Recommended design:

```text
Host client
  -> 127.0.0.1:<host_port>
  -> lsb-vm PortForwardHandle
  -> ControlTransport session kind: port-forward
  -> lsb-guest
  -> guest loopback 127.0.0.1:<guest_port>
```

The current vsock forwarding protocol already has `ForwardRequest` and `ForwardResponse` [repo-lsb-proto], and README states that port forwarding works over vsock without `--allow-net` [repo-readme]. Windows should keep that product behavior over virtio-serial mux sessions or a dedicated virtio-serial forwarding port.

QEMU `hostfwd` may be useful as a temporary diagnostic because QEMU documents host port forwarding for user networking [qemu-hostfwd]. It must not be the production LocalSandbox port-forwarding design unless the security model is revisited.

### 13.4 Allowed-network mode

Allowed-network mode should attach a virtio-net device only to a LocalSandbox-owned proxy backend, not to QEMU user NAT.

Recommended path:

1. Introduce a platform-neutral `ProxyLink` abstraction in `lsb-proxy`.
2. Keep the existing smoltcp/proxy policy engine.
3. Add a Windows proxy link backed by a loopback TCP stream or another QEMU-supported netdev transport.
4. Attach QEMU virtio-net to that link.
5. Preserve the guest's proxy gateway model (`10.0.0.1`) and DNS-through-proxy behavior.
6. Enforce domain allowlist and secret substitution in `lsb-proxy`, not QEMU.

Candidate QEMU attachment:

```text
lsb-proxy listens on 127.0.0.1:<ephemeral>
QEMU: -netdev stream,id=lsbnet,server=off,addr.type=inet,addr.host=127.0.0.1,addr.port=<ephemeral>,reconnect-ms=1000
      -device virtio-net-pci,netdev=lsbnet,mac=<random-local>
```

QEMU documents `-netdev stream` as a backend that can connect to another QEMU process or a proxy using a stream-oriented socket [qemu-netdev-stream]. Validation is required to confirm frame boundaries, reconnect behavior, Windows support, and compatibility with the existing proxy engine. If it fails, evaluate TAP/WinTun/HCN as later alternatives, with explicit privilege and cleanup analysis.

### 13.5 Why QEMU user networking is not policy

QEMU user networking provides NAT-like connectivity, DHCP, DNS, and optional host forwarding [qemu-net]. It does not know LocalSandbox domain allowlists, TLS interception, VPN/split-DNS behavior, secret placeholders, or product-specific host exposure rules. Therefore:

- Production default: `-nic none`.
- Production `--allow-net`: proxy-attached NIC only after validation.
- Debug-only: `-netdev user` may be exposed through hidden diagnostics, clearly labeled as bypassing LocalSandbox network policy.

### 13.6 Windows firewall integration

Windows Firewall integration is not required for MVP and must not be the primary policy mechanism. It may be added later as defense-in-depth if:

- QEMU or helper processes have any possible direct outbound path.
- The implementation can install and remove per-instance rules reliably.
- Enterprise policy interactions are understood.
- Rules are scoped to process path, user/session, and lifetime as narrowly as Windows permits.

### 13.7 Windows-specific threat model checklist

- Guest workload is untrusted.
- QEMU is a large native process and part of the attack surface.
- `lsb-guest` is trusted guest-side code but runs in an untrusted guest environment.
- Host secrets are high-value and must not enter guest memory or disk.
- Host source mounts are sensitive; default mode must not mutate them.
- QMP can control the VM and must never be exposed on a public TCP port.
- Named pipes/control sockets must be per-instance, unpredictable, and accessible only to the owning user/session where possible.
- Instance directories must use restrictive ACLs.
- Logs must redact secrets and control payloads that may contain placeholders or environment variables.
- QEMU binary provenance matters; discovered binaries require path/version diagnostics.
- Windows path canonicalization, symlinks, junctions, and case-insensitivity are security-relevant.

## 14. Checkpointing and Store Design

### 14.1 Current semantics

A LocalSandbox checkpoint is product-level disk state, not necessarily a hypervisor snapshot. README states that checkpoints save disk state and pin the base rootfs version for CAS/NBD indexes [repo-readme]. Current CLI code saves `.idx` checkpoint indexes when NBD/CAS is used, otherwise `.ext4` files [repo-cli-checkpoint].

### 14.2 Recommendation for Windows MVP

Use qcow2 overlay files plus metadata:

```text
runtime data dir
  VERSION
  Image
  initramfs.cpio.gz
  rootfs.ext4                       # immutable raw base
  instances/<id>/root.qcow2          # active writable overlay
  checkpoints/<name>.qcow2           # saved checkpoint overlay or flattened qcow2
  checkpoints/<name>.json            # metadata: base version, parent, format, created_at
```

For a new sandbox:

```text
rootfs.ext4 (raw, read-only backing)
        |
        v
instances/<id>/root.qcow2 (writable active overlay)
```

For `lsb run --from myenv`:

```text
rootfs.ext4
        |
        v
checkpoints/myenv.qcow2
        |
        v
instances/<id>/root.qcow2 (ephemeral writable overlay)
```

For `lsb checkpoint create new --from myenv`:

```text
rootfs.ext4
        |
        v
checkpoints/myenv.qcow2
        |
        v
instances/<id>/root.qcow2
        |
        v
checkpoints/new.qcow2 after VM shutdown or block commit/rebase step
```

The first implementation should stop the VM before saving the active overlay. Do not depend on QEMU internal VM snapshots. QEMU documentation distinguishes VM snapshots from simple disk image formats, and QEMU snapshots have device support limitations [qemu-images]. Product checkpoints should be explicit disk artifacts that can be listed, deleted, and pinned to base versions.

### 14.3 CAS/NBD migration path

Do not port Unix-domain-socket NBD as part of Windows boot MVP. The current `lsb-store` implementation uses `std::os::unix::net::UnixListener` and returns `nbd+unix` URIs [repo-store]. Windows options for later:

- TCP-bound NBD on `127.0.0.1` with strict random ports and local-only checks.
- QEMU blockdev protocol integration through QMP.
- Replace host NBD with qcow2 overlays plus chunked checkpoint export.
- Port the CAS backend below a new `BlockStore` trait independent of transport.

### 14.4 Windows filesystem considerations

- Use `AppData\Local\lsb` only as a target layout; current implementation's `default_data_dir` uses `HOME` even for planned Windows metadata and needs Windows-specific correction [repo-lsb-platform-lib], [repo-windows-x86-spec].
- Use `std::path::PathBuf` and Windows-known-folder APIs rather than string concatenation.
- Use restrictive ACLs for instance directories.
- Ensure checkpoint names continue to reject path traversal and both `/` and `\`; current `validate_checkpoint_name` already rejects `/`, `\`, NUL, and `..` [repo-lsb-vm-lib].
- Avoid modifying qcow2 files while QEMU is still running; QEMU warns that modifying images in use may destroy the image [qemu-img].

## 15. Rust Architecture Changes

### 15.1 Main recommendation

Move from a macOS-gated platform API to a backend trait model:

```rust
pub trait VmBackend: Send + Sync {
    fn start(&self) -> Result<()>;
    fn stop(&self) -> Result<()>;
    fn state_channel(&self) -> Receiver<VmState>;
    fn open_session(&self, kind: SessionKind) -> Result<Box<dyn ControlSession>>;
    fn diagnostics(&self) -> VmDiagnostics;
}

pub trait ControlSession: Read + Write + Send {
    fn shutdown(&mut self) -> Result<()>;
}
```

`Sandbox` should depend on `VmBackend` and `ControlTransport`, not on `connect_to_vsock_port` directly.

### 15.2 Crate impact table

| Crate             | Current role                                                                                | Windows impact                                                                         | Proposed changes                                                                                                               | Expose platform details?                                            |
| ----------------- | ------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------- |
| `lsb-vm`          | Sandbox builder and high-level operations. Currently hard-gated to macOS [repo-lsb-vm-lib]. | Must compile on Windows and stop assuming vsock.                                       | Remove non-macOS `compile_error!`; introduce platform-neutral backend/control traits; keep public Sandbox API stable.          | No.                                                                 |
| `lsb-platform`    | Platform metadata and macOS backend.                                                        | Add Windows QEMU backend and shared config types.                                      | Add `windows_x86_64::qemu`; define `PlatformVmConfig` cross-platform; use PathBuf; fix Windows data dir.                       | Internally yes; public API should hide QEMU details where possible. |
| `lsb-proto`       | Frame and request types.                                                                    | Mostly transport-independent; may need ready/import/export/mux messages.               | Keep existing frame types; add version/feature handshake and mount import/export frames if needed.                             | No.                                                                 |
| `lsb-guest`       | Linux guest agent over vsock.                                                               | Add virtio-serial transport and optional transport mux.                                | Refactor transport listener from request handlers; add virtio-serial discovery; add ready handshake; add copy-in mount import. | No, except kernel cmdline feature selection.                        |
| `lsb-proxy`       | Proxy policy and Unix fd link.                                                              | Need Windows-compatible QEMU net link.                                                 | Introduce `ProxyLink` trait; keep policy engine; add Windows stream backend after validation.                                  | No.                                                                 |
| `lsb-store`       | CAS/NBD over Unix socket.                                                                   | Current transport not native Windows.                                                  | Introduce `CheckpointStore`/`BlockStore` trait; implement qcow2 overlay MVP outside NBD; later TCP NBD/CAS.                    | No.                                                                 |
| `lsb-cli`         | CLI orchestration and checkpoint commands.                                                  | Must preserve flags but return capability errors for unsupported Windows MVP features. | Platform capability checks; Windows diagnostics command; no public flag churn.                                                 | No.                                                                 |
| `lsb-sdk`         | Rust SDK.                                                                                   | Must preserve API.                                                                     | Surface capability errors and diagnostics objects.                                                                             | No.                                                                 |
| `bindings/nodejs` | NAPI package.                                                                               | Add win32 package later.                                                               | Add `@local-sandbox/lsb-nodejs-win32-x64-msvc` after core backend passes smoke tests.                                          | No.                                                                 |
| `xtask`           | Builds guest/assets.                                                                        | Need Windows packaging hooks later.                                                    | Add Windows artifact naming and validation tasks.                                                                              | Minimal.                                                            |

### 15.3 QEMU backend modules

Suggested module layout:

```text
crates/lsb-platform/src/
  lib.rs
  backend.rs                    # shared traits/types if kept here
  macos_x86_64/...
  macos_aarch64/...
  windows_x86_64/
    mod.rs
    qemu.rs                     # backend object
    argv.rs                     # typed argv builder
    discovery.rs                # qemu-system/qemu-img discovery
    preflight.rs                # WHPX and feature checks
    process.rs                  # child process + Job Object
    qmp.rs                      # QMP client
    pipe.rs                     # named pipe helpers
    control.rs                  # virtio-serial transport/mux
    disk.rs                     # qcow2 overlay handling
    diagnostics.rs              # logs/artifacts
```

### 15.4 Error taxonomy

Add structured errors with actionable diagnostics:

- `UnsupportedPlatform`
- `QemuNotFound`
- `QemuVersionUnsupported`
- `WhpxUnavailable`
- `HypervisorPlatformFeatureDisabled`
- `AssetMissing`
- `DiskImageCreateFailed`
- `QemuStartFailed`
- `QmpHandshakeFailed`
- `GuestBootTimeout`
- `GuestReadyTimeout`
- `ControlTransportFailed`
- `GuestProtocolVersionMismatch`
- `MountUnsupported`
- `NetworkPolicyBackendUnavailable`
- `CheckpointFormatUnsupported`

Each error should include relevant log paths and a redacted QEMU argv snapshot.

### 15.5 Public APIs that must not change

- CLI `lsb run`, `lsb checkpoint`, `lsb init` flags should remain stable.
- Rust SDK `Sandbox.start`, `exec`, `execShell`, file APIs, ports, mounts, network config should remain stable.
- Node `Sandbox` API shape should remain stable when Windows support is enabled.
- Unsupported Windows MVP features should return capability errors, not require Windows-only flags.

## 16. Implementation Plan

Each milestone should be merged with tests. Coding-agent prompts are intentionally concrete enough to become issue bodies.

### M0: Compile on Windows with stubs

Objective: make core crates compile for `x86_64-pc-windows-msvc` without implementing QEMU yet.

Scope:

- Remove or narrow `compile_error!` in `lsb-vm`.
- Define platform-neutral traits/types.
- Add Windows stub backend returning `UnsupportedPlatform` or `BackendUnavailable`.
- Keep macOS tests passing.

Likely files:

- `crates/lsb-vm/src/lib.rs`
- `crates/lsb-vm/src/sandbox.rs`
- `crates/lsb-platform/src/lib.rs`
- `crates/lsb-platform/src/windows_x86_64/mod.rs`

Design notes:

- Do not pull QEMU-specific types into public SDK types.
- Use `PathBuf` internally.

Risks:

- Accidentally changing macOS behavior.
- Cross-platform conditional compilation sprawl.

Tests:

- `cargo check --target x86_64-pc-windows-msvc`
- Existing macOS checks.
- Unit tests for checkpoint name validation on Windows separators.

Coding-agent task prompt:

```text
Goal: Make lsb-vm, lsb-platform, lsb-sdk, and lsb-cli compile on x86_64-pc-windows-msvc with a stub Windows backend.
Constraints: Do not change public CLI/SDK API. Do not implement QEMU yet. Preserve macOS behavior.
Likely files: crates/lsb-vm/src/lib.rs, crates/lsb-vm/src/sandbox.rs, crates/lsb-platform/src/lib.rs, crates/lsb-platform/src/windows_x86_64/mod.rs.
Tests: Add Windows-target cargo check in CI and unit tests for path/checkpoint validation.
Acceptance: Windows target compiles; macOS tests/checks still pass; Windows runtime returns a clear unsupported/backend-unavailable error.
Do not change: lsb-proto frame types or Node API shape.
```

### M1: QEMU discovery and preflight

Objective: discover QEMU and validate WHPX prerequisites before boot.

Scope:

- Discovery order: `LSB_QEMU`, config, `PATH`.
- Discover `qemu-system-x86_64.exe` and `qemu-img.exe`.
- Run `qemu-system-x86_64.exe -version`.
- Run `qemu-system-x86_64.exe -accel help` or equivalent and require WHPX.
- Check Windows version is Windows 11 x86_64.
- Check required assets exist.

Likely files:

- `windows_x86_64/discovery.rs`
- `windows_x86_64/preflight.rs`
- `windows_x86_64/diagnostics.rs`

Design notes:

- Production requires WHPX only.
- Hidden debug config may allow TCG for boot diagnostics but must emit explicit warnings and never be default.

Risks:

- QEMU distributions may format version/help output differently.

Tests:

- Unit tests with fake QEMU scripts.
- Golden parse tests for version/help output.

Coding-agent task prompt:

```text
Goal: Implement Windows QEMU discovery/preflight for qemu-system-x86_64.exe and qemu-img.exe.
Constraints: Production mode must require WHPX. No silent TCG fallback. Do not start a VM.
Likely files: crates/lsb-platform/src/windows_x86_64/discovery.rs, preflight.rs, diagnostics.rs.
Tests: Fake QEMU executables that emit version/help; missing binary; missing whpx; hidden debug tcg allowed only when explicitly enabled.
Acceptance: Preflight returns structured diagnostics and actionable errors with paths and detected version.
Do not change: macOS backend or public API.
```

### M2: QEMU argv builder

Objective: create a typed, testable QEMU command builder.

Scope:

- Build argv as `Vec<OsString>`.
- Include WHPX, q35, CPU/memory, direct boot, root disk, serial log, virtio-serial control port, QMP pipe, and `-nic none`.
- Persist redacted `qemu.argv.json` in instance diagnostics.

Likely files:

- `windows_x86_64/argv.rs`
- `windows_x86_64/qemu.rs`

Design notes:

- Do not shell-concatenate.
- Normalize Windows paths.
- Include no secrets in argv.

Risks:

- Quoting/path bugs.
- Default QEMU devices accidentally enabled without `-nodefaults`/explicit options.

Tests:

- Golden argv tests.
- Property tests for paths containing spaces and commas.

Coding-agent task prompt:

```text
Goal: Implement a typed QEMU argv builder for the Windows backend.
Constraints: Return Vec<OsString>. Do not shell-escape manually. Include -nic none by default and -accel whpx only.
Likely files: crates/lsb-platform/src/windows_x86_64/argv.rs.
Tests: Golden argv snapshots for minimal boot, verbose boot, QMP enabled, virtio-serial enabled, no-network default.
Acceptance: Golden tests pass on Windows and non-Windows hosts; no secrets appear in argv snapshots.
Do not change: guest protocol or CLI flags.
```

### M3: QEMU process lifecycle and Job Object cleanup

Objective: start, monitor, and clean up QEMU reliably on Windows.

Scope:

- Spawn QEMU with stdout/stderr captured.
- Assign QEMU and helper processes to a Windows Job Object.
- Kill job on backend drop or fatal startup failure.
- Write pid/status/exit logs.

Microsoft documents Job Objects as a way to manage groups of processes as a unit, including terminating all processes associated with a job [ms-job-objects].

Likely files:

- `windows_x86_64/process.rs`
- `windows_x86_64/diagnostics.rs`

Design notes:

- Use `windows-sys` or `windows` crate behind cfg.
- Handle parent process already in a job.
- Avoid orphaned QEMU.

Risks:

- Nested job behavior in CI.
- Cleanup races.

Tests:

- Fake long-running child assigned to job and terminated.
- Drop cleanup test on Windows.

Coding-agent task prompt:

```text
Goal: Implement Windows process supervision for QEMU with Job Object cleanup.
Constraints: No orphaned child processes. Keep diagnostics on failure. Use cfg(windows) APIs only inside Windows module.
Likely files: crates/lsb-platform/src/windows_x86_64/process.rs.
Tests: Fake child process cleanup; process exit status capture; drop terminates child.
Acceptance: On Windows, dropping the backend terminates the fake child tree; diagnostics include pid, exit code, stderr path.
Do not change: macOS process lifecycle.
```

### M4: Direct Linux boot with serial logs

Objective: boot the Linux guest far enough to produce serial output.

Scope:

- Create qcow2 overlay from `rootfs.ext4`.
- Launch QEMU with direct boot.
- Capture serial log.
- Detect boot timeout and QEMU early exit.

Likely files:

- `windows_x86_64/disk.rs`
- `windows_x86_64/qemu.rs`
- `windows_x86_64/diagnostics.rs`

Design notes:

- Start with minimal devices.
- Add `-no-reboot` to preserve failure state.
- Serial console driver may require kernel config changes.

Risks:

- Current kernel lacks required PC serial console support.
- Root device name differs.

Tests:

- Self-hosted Windows 11 WHPX smoke test.
- Assert serial log contains kernel boot and `lsb-guest` startup lines.

Coding-agent task prompt:

```text
Goal: Boot the existing x86_64 LocalSandbox Linux guest under QEMU+WHPX and capture serial logs.
Constraints: WHPX only. No network device. Do not rely on QMP for guest readiness yet.
Likely files: windows_x86_64/qemu.rs, disk.rs, diagnostics.rs, kernel config if needed.
Tests: Self-hosted Windows boot smoke that reaches lsb-guest startup or a clear kernel/initramfs failure.
Acceptance: `lsb run --diagnose-boot` or internal test boots and writes serial.log/qemu.stderr/qemu.argv.json.
Do not change: public CLI semantics yet.
```

### M5: Virtio-serial control transport

Objective: establish a host/guest byte stream over virtio-serial.

Scope:

- Add QEMU virtio-serial port and Windows named pipe.
- Host connects to pipe.
- Guest discovers and opens virtio-serial port.
- Guest sends ready handshake.
- Host validates ready handshake.

Likely files:

- `windows_x86_64/control.rs`
- `windows_x86_64/pipe.rs`
- `crates/lsb-guest/src/main.rs`
- `crates/lsb-proto/src/lib.rs`

Design notes:

- Add transport abstraction in guest.
- Add `GuestReady` frame.
- Keep old vsock path for macOS.

Risks:

- Device path discovery in minimal guest.
- Pipe connection ordering.

Tests:

- Unit test for guest virtio-port sysfs discovery with fixtures.
- Boot smoke waits for `GuestReady`.

Coding-agent task prompt:

```text
Goal: Implement Windows virtio-serial control transport and guest ready handshake.
Constraints: Keep existing lsb-proto command frames. Add only minimal handshake/versioning. Preserve macOS AF_VSOCK behavior.
Likely files: crates/lsb-guest/src/main.rs, crates/lsb-proto/src/lib.rs, crates/lsb-platform/src/windows_x86_64/control.rs, pipe.rs.
Tests: Guest discovery fixture tests; fake transport handshake tests; Windows boot smoke reaches GuestReady.
Acceptance: Host receives protocol version/features from guest over virtio-serial and Sandbox.start can wait for it.
Do not change: public exec/file API.
```

### M6: Exec command

Objective: run a non-interactive command in the guest over Windows control transport.

Scope:

- Adapt `Sandbox.exec` to use `ControlTransport::open_session(SessionKind::Command)`.
- Send existing `ExecRequest` frames.
- Stream stdout/stderr/exit.
- Return exit code.

Likely files:

- `crates/lsb-vm/src/sandbox.rs`
- `windows_x86_64/control.rs`
- `crates/lsb-guest/src/main.rs`

Design notes:

- Initial MVP may serialize operations on one stream.
- Add mux before concurrent APIs are declared supported.

Risks:

- Blocking behavior on long stdout/stderr.
- EOF handling across virtio-serial.

Tests:

- `echo hello` boot smoke.
- Non-zero exit code.
- Large stdout.

Coding-agent task prompt:

```text
Goal: Run `lsb exec`/Sandbox.exec over the Windows virtio-serial transport.
Constraints: Use existing ExecRequest/STDOUT/STDERR/EXIT frames. No public API changes.
Likely files: crates/lsb-vm/src/sandbox.rs, Windows control transport, lsb-guest handler.
Tests: echo, stderr, non-zero exit, large stdout, guest error propagation.
Acceptance: Windows smoke test can run `echo hello` and receive stdout plus exit code 0.
Do not change: macOS vsock exec behavior.
```

### M7: Copy-in/copy-out and Windows mount MVP

Objective: support safe overlay mounts without live host sharing.

Scope:

- Add mount import request or reuse file API with archive stream.
- Host validates source tree.
- Guest extracts into tmpfs/staging and exposes requested guest path.
- Direct `:rw` was an MVP capability error on Windows; D023 later replaces this with SMB/CIFS direct mount planning.

Likely files:

- `crates/lsb-vm/src/sandbox.rs`
- `crates/lsb-proto/src/lib.rs`
- `crates/lsb-guest/src/main.rs`
- `windows_x86_64/mount.rs`

Design notes:

- Reject symlink/junction escapes.
- Detect case collisions.
- Document no live coherence.

Risks:

- Large mount trees and memory use.
- POSIX metadata mismatch.

Tests:

- Mount read file.
- Guest write does not modify host.
- Case collision error.
- Direct rw unsupported error for the historical MVP plan; current direct-mount coverage belongs to D023 SMB/CIFS tests.

Coding-agent task prompt:

```text
Goal: Implement Windows overlay mount MVP using copy-in guest staging, preserving host-read-only and isolated guest writes.
Constraints: Do not promise live file coherence for overlay mounts. Reject symlink/junction escapes and case collisions. This historical task predates D023 SMB/CIFS direct mounts.
Likely files: lsb-vm mount planning, lsb-proto import frames, lsb-guest mount/import handler, Windows mount module.
Tests: read mounted file, write guest file without host mutation, unsupported special files, case collision, direct rw capability error for the historical MVP plan.
Acceptance: `lsb run --mount ./src:/workspace -- cat /workspace/file` works on Windows; host is unchanged after guest writes.
Do not change: macOS VirtioFS mount behavior.
```

### M8: Transport multiplexer and port forwarding

Objective: preserve concurrent stream APIs and no-network port forwarding.

Scope:

- Add mux envelope over virtio-serial physical stream.
- Map `open_session` to mux session IDs.
- Implement port-forward sessions using existing `ForwardRequest` payloads.
- Host listens on `127.0.0.1:<host_port>` and streams bytes to guest session.

Likely files:

- `windows_x86_64/control.rs`
- `crates/lsb-guest/src/main.rs`
- `crates/lsb-vm/src/sandbox.rs`

Design notes:

- Flow control and cancellation matter.
- Keep mux transport-internal, not visible to public API.

Risks:

- Deadlocks under high throughput.
- Session cleanup on guest process exit.

Tests:

- Two concurrent execs.
- File watch plus exec.
- Port forward to guest HTTP server without guest NIC.

Coding-agent task prompt:

```text
Goal: Add a virtio-serial transport multiplexer and implement no-network host-to-guest port forwarding on Windows.
Constraints: Do not use QEMU hostfwd for production. Do not add a guest NIC for port forwarding. Keep lsb-proto payloads unchanged inside sessions.
Likely files: Windows control transport, lsb-guest transport loop, lsb-vm port forward code.
Tests: concurrent exec sessions; host 127.0.0.1 port forwards to guest HTTP server with -nic none; session cancellation.
Acceptance: `lsb run -p 8080:8000 -- python3 -m http.server 8000` works without `--allow-net`.
Do not change: macOS vsock forwarding semantics.
```

### M9: Network policy and proxy integration

Objective: re-enable `--allow-net` with LocalSandbox proxy semantics.

Scope:

- Add `ProxyLink` abstraction.
- Implement Windows QEMU stream/tcp proxy link experiment.
- Attach virtio-net only when `--allow-net` is requested.
- Preserve DNS-through-proxy, allowlist, and secret substitution.

Likely files:

- `crates/lsb-proxy/src/lib.rs`
- `crates/lsb-proxy/src/config.rs`
- `windows_x86_64/network.rs`
- `crates/lsb-cli/src/vm.rs`

Design notes:

- Direct IP and non-proxied UDP must be blocked.
- QEMU user networking debug-only.
- Windows Firewall only defense-in-depth later.

Risks:

- QEMU stream netdev may not match current proxy framing.
- VPN/split-DNS behavior must be preserved by host proxy.

Tests:

- No network by default.
- Allowlisted host succeeds.
- Non-allowlisted host blocked.
- Secret substitution only to configured host.
- Direct IP blocked.

Coding-agent task prompt:

```text
Goal: Implement Windows --allow-net using lsb-proxy policy, not QEMU user NAT.
Constraints: Keep no-network default. Do not use QEMU user networking as policy. Real secrets must not enter the guest. Direct IP and non-proxied UDP blocked unless explicitly allowed by future design.
Likely files: lsb-proxy ProxyLink trait, Windows network backend, CLI VM preparation.
Tests: blocked default egress, allowlisted HTTPS, denied host, secret substitution host match, direct IP denial.
Acceptance: Windows --allow-net preserves current product semantics through the host proxy.
Do not change: proxy config schema unless required and reviewed.
```

### M10: Checkpoint/store MVP

Objective: implement Windows checkpoint semantics with qcow2 overlays.

Scope:

- Create active instance overlays from base/checkpoint.
- Save checkpoints after VM stop.
- Store metadata JSON.
- List/delete Windows checkpoint files.
- Keep CAS/NBD disabled or capability-gated on Windows.

Likely files:

- `windows_x86_64/disk.rs`
- `crates/lsb-cli/src/checkpoint.rs`
- `crates/lsb-store` new traits or Windows-disabled path

Design notes:

- Pin base version.
- Avoid qemu-img operations on running images.
- Keep chain depth manageable; flatten/rebase later.

Risks:

- Backing file absolute paths break if data dir moves.
- Chain corruption if QEMU still running.

Tests:

- Create checkpoint.
- Run from checkpoint ephemerally.
- Branch checkpoint.
- Delete checkpoint.
- Base version metadata preserved.

Coding-agent task prompt:

```text
Goal: Implement Windows checkpoint MVP using immutable rootfs.ext4 and qcow2 overlays plus metadata.
Constraints: Do not port Unix NBD in this task. Do not modify images while QEMU is running. Preserve user-visible checkpoint commands.
Likely files: Windows disk module, CLI checkpoint handling, lsb-store traits if needed.
Tests: create/list/delete checkpoint; run from checkpoint; branch from checkpoint; metadata pins base version.
Acceptance: Windows CLI can create and resume checkpoints with changes isolated from subsequent runs.
Do not change: macOS CAS/NBD behavior.
```

### M11: Node packaging

Objective: add Windows Node package after CLI backend is stable.

Scope:

- Add `win32-x64-msvc` native package.
- Keep unsupported installs failing clearly until package is released.
- Add Windows smoke tests behind self-hosted runner.

Likely files:

- `bindings/nodejs/package.json`
- `bindings/nodejs/npm/*`
- `.github/workflows/nodejs-binding.yml`
- `.github/workflows/release_nodejs.yml`

Design notes:

- Do not require QEMU bundled in MVP package.
- Surface QEMU discovery/preflight errors through Node.

Risks:

- Users install Node package without QEMU.
- CI cannot run WHPX on hosted runners.

Tests:

- Build native binding on hosted Windows.
- Self-hosted VM smoke if assets/QEMU are provisioned.

Coding-agent task prompt:

```text
Goal: Add Windows x64 Node binding packaging after the Windows CLI backend passes smoke tests.
Constraints: Do not bundle QEMU yet. Unsupported platforms must fail clearly until package is published. Preserve TypeScript API.
Likely files: bindings/nodejs package files and CI workflows.
Tests: win32-x64-msvc build, Node API unit tests, self-hosted smoke with pre-provisioned assets/QEMU.
Acceptance: npm can install the Windows platform package and Sandbox.start surfaces QEMU preflight errors or boots successfully.
Do not change: macOS Node package names or API.
```

### M12: CI and diagnostics hardening

Objective: make Windows development reliable for humans and coding agents.

Scope:

- Hosted Windows compile/golden tests.
- Self-hosted Windows 11 WHPX boot smoke tests.
- Diagnostic bundle command.
- Redaction checks.

Likely files:

- `.github/workflows/ci.yml`
- `.github/workflows/windows-smoke.yml`
- `crates/lsb-cli/src/diagnostics.rs`

Tests:

- Generate diagnostics on fake failures.
- Ensure no secret values in logs.

Coding-agent task prompt:

```text
Goal: Add Windows CI lanes and diagnostic bundle support for QEMU/WHPX backend.
Constraints: Hosted runners run compile/unit/golden tests only. WHPX boot tests run only on self-hosted Windows 11 x86_64 runner. Redact secrets.
Likely files: GitHub workflows, diagnostics module.
Tests: CI jobs; diagnostic bundle fixture redaction.
Acceptance: Pull requests run Windows compile/golden tests; self-hosted runner runs boot/exec/mount/port-forward smoke; failures upload redacted artifacts.
Do not change: release publishing behavior without review.
```

## 17. Testing Strategy

### 17.1 Test classes

| Test class              | Purpose                                                 | Examples                                                                                                     |
| ----------------------- | ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| Unit tests              | Validate parsing, paths, argv, errors, protocol frames. | QEMU version parsing, Windows path normalization, case collision detection, handshake frame roundtrip.       |
| Golden argv tests       | Prevent accidental QEMU behavior changes.               | Minimal boot, verbose boot, no-network default, QMP pipe, virtio-serial, proxy NIC.                          |
| Fake QEMU process tests | Exercise process supervision without WHPX.              | Fake process logs, exit code, startup failure, Job Object cleanup.                                           |
| Boot smoke tests        | Validate real QEMU+WHPX boot.                           | Kernel boot, rootfs mount, `GuestReady`.                                                                     |
| Guest protocol tests    | Validate transport-independent protocol.                | exec, stdout/stderr, exit, read/write file, error propagation.                                               |
| Security tests          | Validate no secrets and no unintended host access.      | Secret redaction, no secret in guest env beyond placeholder, symlink escape rejected.                        |
| Mount conformance tests | Validate Windows mount MVP semantics.                   | Read copied file, guest write isolated, host change not live, case collision error.                          |
| Network policy tests    | Validate proxy behavior.                                | No egress default, allowlisted host, denied host, direct IP blocked, secret substitution only on host match. |
| Checkpoint tests        | Validate disk state semantics.                          | Create/list/delete, resume from checkpoint, branch checkpoint, base version metadata.                        |
| Node package tests      | Validate binding build and API surface.                 | win32-x64-msvc build, SDK error mapping, optional boot smoke.                                                |

### 17.2 Minimal Windows CI matrix

| Runner                            | Jobs                                                                                                                                              | Notes                                                                                                                               |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| GitHub-hosted `windows-latest`    | `cargo fmt`, `cargo check --target x86_64-pc-windows-msvc`, unit tests not requiring WHPX, golden argv tests, fake QEMU tests, Node build checks. | Do not assume WHPX/nested virtualization.                                                                                           |
| Self-hosted `windows-11-x64-whpx` | QEMU preflight, boot smoke, guest ready, exec, copy-in mount, port forwarding, checkpoint MVP, proxy tests when implemented.                      | User will provision runner. Must have Windows Hypervisor Platform enabled, managed or override QEMU available, and runtime assets available. |
| macOS existing runners            | Existing macOS runtime checks.                                                                                                                    | Must remain green.                                                                                                                  |

### 17.3 Required smoke sequence for self-hosted runner

1. `lsb diagnose windows-preflight`
2. Boot with no network: `lsb run -- echo hello`
3. Verify no egress: guest curl to public host fails without `--allow-net`.
4. Mount MVP: `lsb run --mount fixture:/workspace -- cat /workspace/hello.txt`.
5. Guest write isolation: write under `/workspace`, verify host unchanged.
6. Port forwarding with no network: serve on guest loopback and curl host `127.0.0.1`.
7. Checkpoint create/resume.
8. When implemented, `--allow-net --allow-host <fixture-host>` succeeds and denied host fails.

## 18. Debugging and Diagnostics

Each Windows VM instance should have a diagnostics directory:

```text
instances/<id>/diagnostics/
  qemu.argv.json
  qemu.version.txt
  preflight.json
  qemu.stderr.log
  qemu.stdout.log
  serial.log
  qmp.log
  guest-ready.json
  control.log.redacted
  proxy.log.redacted
  disk-info.json
  checkpoint-metadata.json
```

### 18.1 Failure guide

| Symptom                          | Likely causes                                                                                    | Capture/checks                                                          | Instrumentation                                        |
| -------------------------------- | ------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------- | ------------------------------------------------------ |
| QEMU fails to start              | Bad path, missing DLLs, invalid argv, unsupported QEMU version.                                  | `qemu.stderr.log`, `qemu.argv.json`, `qemu.version.txt`.                | Preflight command output; include child exit code.     |
| WHPX unavailable                 | Windows Hypervisor Platform disabled, virtualization disabled in firmware, conflicting policies. | `preflight.json`; `qemu -accel help`; Windows optional feature status.  | Structured `WhpxUnavailable` error.                    |
| Kernel does not boot             | Wrong kernel image, missing console driver, wrong machine/CPU, WHPX issue.                       | `serial.log`, QEMU stderr, QMP status.                                  | Boot timeout includes last N serial lines.             |
| Rootfs does not mount            | Wrong root device, qcow2/backing issue, virtio-blk driver missing.                               | Serial kernel panic, `qemu-img info`, argv drive/device.                | Disk creation logs and rootfs metadata.                |
| Initramfs fails                  | Missing initramfs, wrong compression, guest init error.                                          | Serial log.                                                             | Initramfs should log stage markers.                    |
| Guest agent does not start       | Rootfs missing `lsb-guest`, PID1 failure, missing mounts.                                        | Serial log.                                                             | `lsb-guest` startup banner with version and transport. |
| Host cannot connect control pipe | QEMU chardev path mismatch, pipe ordering, ACL issue, virtio-serial not created.                 | Pipe path, QEMU stderr, guest serial.                                   | Log pipe connect attempts and timeout.                 |
| Guest ready timeout              | Guest cannot open virtio-serial device, protocol mismatch.                                       | Serial log, `control.log.redacted`.                                     | Guest logs virtio-port discovery result.               |
| Exec hangs                       | Transport deadlock, mux bug, guest process blocked, stdout backpressure.                         | Control trace, session IDs, guest logs.                                 | Per-session deadlines and byte counters.               |
| Port forwarding fails            | Listener bind conflict, mux stream failure, guest target port closed.                            | Host listener logs, `ForwardResponse`, guest logs.                      | Include host/guest port pair and no-network state.     |
| Mount behavior differs           | Copy import rejected path, symlink/junction/case collision, metadata loss.                       | Mount validation report, guest mount response.                          | Emit clear unsupported-path reason.                    |
| Network policy bypass            | NIC attached to wrong backend, QEMU user NAT accidentally enabled, proxy rule bug.               | Golden argv check for no `-netdev user`; proxy logs; guest route table. | Security test blocks default egress.                   |
| Checkpoint restore fails         | Missing backing file, moved data dir, corrupted qcow2, QEMU still had image open.                | `qemu-img info --backing-chain`, checkpoint metadata.                   | Validate chain before boot.                            |

### 18.2 Useful manual checks

```powershell
# QEMU version
qemu-system-x86_64.exe -version

# QEMU accelerator help
qemu-system-x86_64.exe -accel help

# Enable Windows Hypervisor Platform if needed, from elevated shell
DISM /online /Enable-Feature /FeatureName:HypervisorPlatform /All

# Disk image inspection
qemu-img.exe info C:\Users\me\AppData\Local\lsb\instances\abc\root.qcow2
qemu-img.exe info --backing-chain C:\Users\me\AppData\Local\lsb\checkpoints\myenv.qcow2
```

QEMU documents installing the Windows Hypervisor Platform feature through Windows Features or DISM [qemu-whpx].

## 19. Security Considerations

### 19.1 Process isolation limits

LocalSandbox uses a VM boundary, but QEMU is a large native VMM process. A guest-to-QEMU escape would become host code execution in the QEMU process context. Therefore:

- Run QEMU with the fewest devices needed.
- Use `-nodefaults` and explicitly add devices.
- Avoid unnecessary NICs, USB, display, shared clipboard, host shares, and monitor exposure.
- Keep QEMU updated and record version/path.
- Consider future process token restrictions only after validating QEMU compatibility.

### 19.2 Host file exposure

- Default Windows mounts are copy-in, not live host writes. Explicit direct mounts use SMB/CIFS under D023.
- Reject symlink/junction escapes and case collisions.
- Store mount import staging under the VM instance directory or guest tmpfs.
- Direct `:rw` was unsupported in Windows MVP; explicit direct mounts now use SMB/CIFS under D023 and require elevated setup.
- Instance directories and named pipes must be private to the current user/session.

### 19.3 Network egress

- `-nic none` by default.
- No QEMU user networking in production default.
- `--allow-net` must go through `lsb-proxy` after Windows proxy link validation.
- Host-to-guest port forwarding must not attach a general NIC.
- Firewall rules are optional defense-in-depth, not the source of truth.

### 19.4 Secret handling

- Real secrets stay in host memory only.
- Guest receives placeholders only, matching current proxy behavior [repo-proxy-config].
- Redact secret values from argv, logs, QMP, proxy logs, control traces, and error messages.
- Add tests that intentionally pass a known fake secret and assert it never appears in diagnostics.

### 19.5 QMP exposure

- QMP must use a private per-instance pipe or local-only socket with restrictive ACLs.
- Do not bind QMP to public TCP.
- QMP logs must redact command payloads if future blockdev commands include paths considered sensitive.
- QMP is not a guest API; do not route user commands through it.

### 19.6 QEMU binary provenance

MVP discovers QEMU rather than bundling. Preflight must record:

- Full path.
- Version string.
- SHA-256 hash if cheap enough.
- Whether `qemu-img.exe` came from the same directory as `qemu-system-x86_64.exe`.

Later bundling should require signed/reproducible provenance review.

### 19.7 Denial of service

Guest code may consume CPU, memory, disk, stdout, or port-forward bandwidth. MVP mitigations:

- Respect configured vCPU/memory limits in QEMU argv.
- Use disk size limits for overlays.
- Bound logs and control traces.
- Set operation timeouts where API semantics permit.
- Clean up instance directories and QEMU processes on failure.

## 20. Open Questions

| Question                                                                   | Why it matters                                    | Owner                  | Validation experiment                                                                                           | Blocking?                                                  |
| -------------------------------------------------------------------------- | ------------------------------------------------- | ---------------------- | --------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| Does the current x86_64 kernel boot under QEMU+WHPX with `console=ttyS0`?  | Serial diagnostics and boot command depend on it. | Windows backend owner  | Self-hosted boot with current assets; if no serial, enable required console driver or switch to virtio console. | Blocking for boot MVP.                                     |
| Does QEMU virtio-serial on Windows named pipes behave reliably under load? | Control transport and mux depend on it.           | Platform owner         | Run echo, large stdout, concurrent mux sessions, disconnect/reconnect tests.                                    | Blocking for API MVP.                                      |
| Is `/dev/virtio-ports/<name>` available without udev in the guest?         | Guest transport discovery depends on it.          | Guest owner            | Boot minimal guest and inspect `/dev`/`/sys`; implement sysfs fallback.                                         | Blocking for control MVP.                                  |
| Can QEMU `-netdev stream` on Windows connect cleanly to `lsb-proxy`?       | Determines proxy integration path.                | Proxy owner            | Build minimal frame echo/proxy and run HTTP/DNS through smoltcp.                                                | Blocking for `--allow-net`, not boot/exec.                 |
| How large can copy-in mounts be before tmpfs staging is unacceptable?      | MVP mount UX/performance.                         | Product/VM owner       | Benchmark import of representative repo sizes and memory limits.                                                | Non-blocking for first MVP, blocks polished mount release. |
| Should checkpoints store relative or absolute backing paths?               | Data dir portability and robustness.              | Store owner            | Move data dir test; qemu-img backing-chain validation.                                                          | Blocking for checkpoint MVP.                               |
| Should Windows MVP expose file watch on imported mounts?                   | Current API includes watch.                       | SDK owner              | Define watch as guest-copy-only; test user expectations.                                                        | Non-blocking if capability-gated.                          |
| What QEMU versions are supported?                                          | Reproducibility and support.                      | Release owner          | Test latest stable Windows QEMU build and pin minimum version.                                                  | Blocking for public release.                               |
| Can Windows Firewall add useful defense-in-depth without admin friction?   | Network bypass mitigation.                        | Security owner         | Prototype per-process outbound block/allow rules and cleanup.                                                   | Non-blocking for MVP.                                      |
| How should managed QEMU be distributed?                                    | UX, provenance, package size.                     | Release/security owner | Use a pinned, hash-verified managed host-tool artifact installed by `lsb init`; continue evaluating signing and mirroring. | Non-blocking for MVP.                                      |

## 21. Alternatives Considered

### 21.1 HCS / Hyper-V-managed VM backend

Rejected for MVP. HCS provides platform-level access to VMs and containers [ms-hyperv-apis], but adopting HCS would move LocalSandbox into a different VM management model. The port needs tight control over direct Linux boot, virtio-ish devices, guest protocol, and disk artifacts. QEMU provides those controls immediately.

### 21.2 Raw WHP VMM

Rejected. Raw WHP would require LocalSandbox to implement enough VMM/device model to boot Linux, provide virtio block/serial/net, handle disk images, and provide diagnostics. WHP is appropriate for third-party stacks, but QEMU is that stack for this RFC [ms-hyperv-apis].

### 21.3 WSL2

Rejected. WSL2 is a Windows Linux environment, not a LocalSandbox microVM backend with per-run rootfs/checkpoint/device/proxy semantics. It would change isolation and filesystem/networking expectations.

### 21.4 Docker/containers

Rejected. Containers do not preserve the VM-based guest/rootfs/checkpoint model and introduce a dependency on container runtime semantics.

### 21.5 Firecracker/cloud-hypervisor

Rejected for MVP. They are attractive microVM projects, but Windows host/WHPX maturity and device support are higher uncertainty than QEMU. Reconsider only if QEMU cannot meet product constraints.

### 21.6 QEMU TCG fallback

Rejected for production. TCG may be useful to distinguish kernel boot issues from WHPX availability, but normal LocalSandbox runs must fail clearly if WHPX is unavailable. QEMU's accelerator fallback behavior must not be used silently [qemu-invocation].

### 21.7 Network-only guest control

Rejected. Using TCP over QEMU user networking for control would require a guest NIC and create policy confusion. Control must not depend on general guest networking.

### 21.8 Live shared mounts as MVP

Rejected. VirtioFS is the desired long-term semantic direction, but Windows host support and packaging must be validated. Copy-in/copy-out gives a safer Windows MVP.

## 22. Appendix A: Example QEMU Commands

These commands are illustrative. The implementation must use structured argv construction. The MVP uses a conservative `Westmere` CPU model for WHPX compatibility; see `decisions.md` D020.

### A.1 Minimal boot, no control, serial log only

```powershell
qemu-system-x86_64.exe `
  -nodefaults `
  -machine q35,accel=whpx `
  -cpu Westmere `
  -smp 2 `
  -m 2048M `
  -display none `
  -monitor none `
  -no-reboot `
  -kernel C:\lsb\Image `
  -initrd C:\lsb\initramfs.cpio.gz `
  -append "console=ttyS0 root=/dev/vda rw panic=-1" `
  -drive if=none,id=root,file=C:\lsb\instances\abc\root.qcow2,format=qcow2 `
  -device virtio-blk-pci,drive=root `
  -serial file:C:\lsb\instances\abc\serial.log `
  -nic none
```

### A.2 Boot with virtio-serial control

```powershell
qemu-system-x86_64.exe `
  -nodefaults `
  -machine q35,accel=whpx `
  -cpu Westmere `
  -smp 2 `
  -m 2048M `
  -display none `
  -monitor none `
  -no-reboot `
  -kernel C:\lsb\Image `
  -initrd C:\lsb\initramfs.cpio.gz `
  -append "console=ttyS0 root=/dev/vda rw panic=-1 lsb.transport=virtio-serial" `
  -drive if=none,id=root,file=C:\lsb\instances\abc\root.qcow2,format=qcow2 `
  -device virtio-blk-pci,drive=root `
  -serial file:C:\lsb\instances\abc\serial.log `
  -device virtio-serial-pci,id=lsbserial0 `
  -chardev pipe,id=lsbctl,path=lsb-abc-control `
  -device virtserialport,chardev=lsbctl,name=org.localsandbox.control `
  -nic none
```

### A.3 Boot with QMP diagnostics

```powershell
qemu-system-x86_64.exe `
  <normal boot args> `
  -qmp pipe:lsb-abc-qmp,server=on,wait=off
```

Use QMP for QEMU status and shutdown diagnostics only.

### A.4 Debug-only QEMU user networking with hostfwd

This is not a production LocalSandbox network mode.

```powershell
qemu-system-x86_64.exe `
  <normal boot args> `
  -netdev user,id=debugnet,hostfwd=tcp:127.0.0.1:2222-:22 `
  -device virtio-net-pci,netdev=debugnet
```

QEMU documents `hostfwd` for user networking [qemu-hostfwd]. This bypasses LocalSandbox proxy policy and must remain hidden/debug-only.

### A.5 9p/virtfs experiment

```powershell
qemu-system-x86_64.exe `
  <normal boot args> `
  -fsdev local,id=src,path=C:\work\project,security_model=none,readonly=on `
  -device virtio-9p-pci,fsdev=src,mount_tag=src
```

This is an experiment. Validate Windows host path semantics, symlinks, case collisions, and guest mount behavior before considering product use. QEMU documents `-fsdev` with virtio-9p devices [qemu-virtfs].

### A.6 VirtioFS experiment

Exact command depends on the available Windows-host `virtiofsd` implementation. Experiment goals:

- Start host virtiofs daemon.
- Attach QEMU vhost-user-fs or supported equivalent.
- Mount in guest with `mount -t virtiofs <tag> <target>`.
- Validate read-only exposure, metadata, symlinks, case collisions, file watching, and performance.

VirtioFS is designed for host/guest shared directory trees and local filesystem semantics [virtiofs], but Windows-host packaging/support is not assumed by this RFC.

## 23. Appendix B: Coding-Agent Task Backlog

### Task B1: Extract platform-neutral VM backend trait

Goal: Remove macOS-only coupling from `lsb-vm` and introduce backend traits.

Constraints:

- Preserve public `Sandbox` API.
- Keep macOS behavior unchanged.
- Windows backend may remain stubbed.

Files likely touched:

- `crates/lsb-vm/src/lib.rs`
- `crates/lsb-vm/src/sandbox.rs`
- `crates/lsb-platform/src/lib.rs`

Tests to add:

- Compile on macOS and Windows target.
- Unit tests for backend capability errors.

Acceptance criteria:

- `cargo check --target x86_64-pc-windows-msvc` passes for core crates.
- Existing macOS checks pass.
- No public API churn.

Things not to change:

- `lsb-proto` frame format.
- CLI flags.

### Task B2: Implement QEMU discovery/preflight

Goal: Locate QEMU and validate WHPX-only production support.

Constraints:

- Discovery order: env, config, PATH.
- No production TCG fallback.
- No VM boot.

Files likely touched:

- `crates/lsb-platform/src/windows_x86_64/discovery.rs`
- `crates/lsb-platform/src/windows_x86_64/preflight.rs`

Tests to add:

- Fake QEMU output parse tests.
- Missing QEMU error.
- WHPX missing error.

Acceptance criteria:

- Preflight returns structured JSON diagnostics.
- Errors include remediation hints and paths.

Things not to change:

- macOS backend.

### Task B3: Build QEMU argv golden tests

Goal: Generate deterministic QEMU args for minimal Windows boot.

Constraints:

- Use `Vec<OsString>`.
- Include `-nic none` by default.
- Include no secrets.

Files likely touched:

- `windows_x86_64/argv.rs`
- `windows_x86_64/diagnostics.rs`

Tests to add:

- Golden snapshots.
- Paths with spaces.
- No-network assertion.

Acceptance criteria:

- Golden tests show direct boot, root qcow2, serial log, QMP pipe, virtio-serial control.

Things not to change:

- CLI flag parsing.

### Task B4: Implement Windows Job Object process supervisor

Goal: Ensure QEMU cleanup on normal and failure paths.

Constraints:

- Windows-only code behind cfg.
- Capture logs.
- Terminate job on drop.

Files likely touched:

- `windows_x86_64/process.rs`

Tests to add:

- Fake child tree cleanup.
- Exit code capture.

Acceptance criteria:

- No orphaned fake process remains after backend drop.

Things not to change:

- macOS process lifecycle.

### Task B5: Boot smoke with serial diagnostics

Goal: Boot current x86_64 guest under QEMU+WHPX.

Constraints:

- WHPX only.
- No NIC.
- No guest API yet.

Files likely touched:

- `windows_x86_64/qemu.rs`
- `windows_x86_64/disk.rs`
- kernel config if needed.

Tests to add:

- Self-hosted boot smoke.

Acceptance criteria:

- Serial log reaches `lsb-guest` startup or a precise failure is diagnosed.

Things not to change:

- Product network behavior.

### Task B6: Add virtio-serial guest transport

Goal: Open QEMU virtio-serial from `lsb-guest` and send ready handshake.

Constraints:

- Preserve AF_VSOCK for macOS.
- Keep command protocol frames unchanged.

Files likely touched:

- `crates/lsb-guest/src/main.rs`
- `crates/lsb-proto/src/lib.rs`
- `windows_x86_64/control.rs`

Tests to add:

- Guest device discovery fixture tests.
- Boot smoke ready handshake.

Acceptance criteria:

- Host receives ready handshake over Windows control channel.

Things not to change:

- Existing vsock ports and frame IDs.

### Task B7: Exec over Windows control transport

Goal: Make `Sandbox.exec` work on Windows.

Constraints:

- Existing exec frame types.
- No public API changes.

Files likely touched:

- `lsb-vm/src/sandbox.rs`
- `windows_x86_64/control.rs`
- `lsb-guest/src/main.rs`

Tests to add:

- Echo, stderr, exit code, large output.

Acceptance criteria:

- `lsb run -- echo hello` succeeds on Windows self-hosted runner.

Things not to change:

- macOS exec implementation behavior.

### Task B8: Implement Windows mount MVP

Goal: Support overlay-style mounts with copy-in staging.

Constraints:

- No live host coherence.
- No direct `:rw` in the historical MVP slice; D023 handles explicit SMB/CIFS direct mounts.
- Reject unsafe paths.

Files likely touched:

- `lsb-proto`
- `lsb-guest`
- `lsb-vm`
- Windows mount module.

Tests to add:

- Host read-only preservation.
- Case collision.
- Symlink/junction escape.

Acceptance criteria:

- Mounted files readable in guest; guest writes do not touch host.

Things not to change:

- macOS VirtioFS behavior.

### Task B9: Add virtio-serial mux

Goal: Support multiple logical sessions over one control channel.

Constraints:

- Mux is transport-internal.
- Existing `lsb-proto` payloads nested unchanged.

Files likely touched:

- `windows_x86_64/control.rs`
- `lsb-guest/src/main.rs`

Tests to add:

- Concurrent execs.
- Cancellation.
- Backpressure.

Acceptance criteria:

- Two simultaneous sessions complete without frame corruption.

Things not to change:

- Public API.

### Task B10: Implement no-network port forwarding

Goal: Preserve `-p host:guest` without a guest NIC.

Constraints:

- Do not use QEMU `hostfwd` in production.
- Bind host listener to loopback unless existing API says otherwise.

Files likely touched:

- `lsb-vm/src/sandbox.rs`
- Windows control mux.
- `lsb-guest` forwarding handler.

Tests to add:

- Guest HTTP server reachable from host.
- No NIC/default no network.

Acceptance criteria:

- Port forwarding works with `-nic none`.

Things not to change:

- CLI port syntax.

### Task B11: Implement Windows checkpoint MVP

Goal: Save and resume qcow2 checkpoints.

Constraints:

- No Unix NBD port in this task.
- Do not modify running images.
- Pin base version.

Files likely touched:

- Windows disk module.
- CLI checkpoint code.
- Store traits.

Tests to add:

- Create/list/delete/resume/branch.

Acceptance criteria:

- Windows checkpoint commands preserve disk state and discard ephemeral run changes unless explicitly checkpointed.

Things not to change:

- macOS CAS/NBD checkpoints.

### Task B12: Add Windows proxy link experiment

Goal: Validate QEMU virtio-net attached to `lsb-proxy` without QEMU user NAT.

Constraints:

- Strict allowlist.
- Real secrets stay host-side.
- No firewall dependency for primary policy.

Files likely touched:

- `lsb-proxy`
- Windows network backend.

Tests to add:

- Allowlisted HTTPS.
- Denied host.
- Secret substitution.
- Direct IP blocked.

Acceptance criteria:

- `--allow-net` preserves current proxy semantics on Windows.

Things not to change:

- Proxy config schema without review.

### Task B13: Add Windows Node package

Goal: Publish Windows Node binding after backend is stable.

Constraints:

- Do not bundle QEMU in MVP.
- Preserve TypeScript API.

Files likely touched:

- `bindings/nodejs` package files.
- Node CI/release workflows.

Tests to add:

- win32-x64-msvc build.
- Node smoke with self-hosted runner.

Acceptance criteria:

- npm package installs on Windows and surfaces QEMU preflight errors or boots.

Things not to change:

- macOS platform package names.

## 24. Appendix C: Glossary

Hypervisor: Software layer that creates isolated execution partitions and arbitrates CPU/memory/device access. Hyper-V is Microsoft's hypervisor technology [ms-hyperv-architecture].

VMM: Virtual machine monitor. In this RFC, QEMU is the VMM process that configures the machine and handles emulated/virtio devices.

WHP: Windows Hypervisor Platform. A Windows API for third-party virtualization stacks to create/manage partitions, map memory, and control virtual processors [ms-hyperv-apis].

WHPX: QEMU's Windows Hypervisor Platform accelerator backend [qemu-whpx].

Hyper-V root partition: The Windows partition that owns hardware access and hosts the virtualization management stack [ms-hyperv-architecture].

Child partition: A Hyper-V partition that hosts a guest OS and receives virtualized views of hardware [ms-hyperv-architecture].

VMBus: Hyper-V inter-partition communication channel used by VSP/VSC synthetic device pairs [ms-hyperv-architecture].

Virtio: A family of paravirtualized device interfaces used by Linux guests and VMMs such as QEMU.

virtio-blk: Virtio block device. Used for the LocalSandbox root disk in this RFC.

virtio-net: Virtio network device. In this RFC, attach only for `--allow-net` after proxy backend validation.

virtio-serial: Virtio console/serial device that can expose named byte-stream ports to the guest. Recommended Windows MVP control transport.

virtiofs: Shared filesystem for VMs designed for local filesystem semantics and performance [virtiofs]. Not assumed for Windows MVP.

QMP: QEMU Monitor Protocol. JSON-style machine interface for controlling/querying QEMU, not LocalSandbox guest exec/file API [qmp].

QGA: QEMU Guest Agent. Guest daemon protocol with commands for guest file, exec, fsfreeze, and other operations [qemu-ga]. Not selected for LocalSandbox product API.

qcow2: QEMU copy-on-write disk image format supporting backing files, sparse storage, compression, and snapshots [qemu-images].

raw image: Plain disk image format. Simple and portable; on NTFS sparse behavior may reduce actual space used [qemu-images].

Overlay: A writable layer recording differences from a backing image or lower filesystem.

VM exit: Transition from guest execution back to the VMM/hypervisor to handle privileged operations or device I/O.

Guest physical memory: Memory addresses as seen by the guest OS.

Host virtual memory: Memory addresses in the host process, such as QEMU's address space.

SLAT/EPT/NPT: Second-level address translation hardware support. Microsoft documents SLAT as required for Hyper-V on Windows Server 2016 and later [ms-hyperv-architecture]. EPT is Intel's implementation; NPT/RVI is AMD's.

## References

[repo-cargo]: https://github.com/LocalSandBox/local-sandbox/blob/main/Cargo.toml
[repo-readme]: https://raw.githubusercontent.com/LocalSandBox/local-sandbox/refs/heads/main/README.md
[repo-lsb-vm-lib]: https://raw.githubusercontent.com/LocalSandBox/local-sandbox/refs/heads/main/crates/lsb-vm/src/lib.rs
[repo-lsb-vm-sandbox]: https://raw.githubusercontent.com/LocalSandBox/local-sandbox/refs/heads/main/crates/lsb-vm/src/sandbox.rs
[repo-lsb-platform-lib]: https://raw.githubusercontent.com/LocalSandBox/local-sandbox/refs/heads/main/crates/lsb-platform/src/lib.rs
[repo-windows-x86-spec]: https://raw.githubusercontent.com/LocalSandBox/local-sandbox/main/crates/lsb-platform/src/windows_x86_64/mod.rs
[repo-macos-x86]: https://raw.githubusercontent.com/LocalSandBox/local-sandbox/main/crates/lsb-platform/src/macos_x86_64/mod.rs
[repo-macos-arm]: https://raw.githubusercontent.com/LocalSandBox/local-sandbox/main/crates/lsb-platform/src/macos_aarch64/mod.rs
[repo-lsb-proto]: https://raw.githubusercontent.com/LocalSandBox/local-sandbox/refs/heads/main/crates/lsb-proto/src/lib.rs
[repo-lsb-guest]: https://raw.githubusercontent.com/LocalSandBox/local-sandbox/refs/heads/main/crates/lsb-guest/src/main.rs
[repo-proxy-config]: https://raw.githubusercontent.com/LocalSandBox/local-sandbox/refs/heads/main/crates/lsb-proxy/src/config.rs
[repo-store]: https://raw.githubusercontent.com/LocalSandBox/local-sandbox/main/crates/lsb-store/src/lib.rs
[repo-cli-checkpoint]: https://raw.githubusercontent.com/LocalSandBox/local-sandbox/refs/heads/main/crates/lsb-cli/src/checkpoint.rs
[repo-node-readme]: https://raw.githubusercontent.com/LocalSandBox/local-sandbox/main/bindings/nodejs/README.md
[repo-ci]: https://raw.githubusercontent.com/LocalSandBox/local-sandbox/main/.github/workflows/ci.yml
[repo-node-ci]: https://raw.githubusercontent.com/LocalSandBox/local-sandbox/main/.github/workflows/nodejs-binding.yml
[repo-kernel-x86]: https://raw.githubusercontent.com/LocalSandBox/local-sandbox/main/kernel/lsb_x86_64_defconfig
[ms-hyperv-apis]: https://learn.microsoft.com/en-us/virtualization/api/
[ms-hyperv-architecture]: https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/architecture
[ms-job-objects]: https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects
[ms-named-pipes]: https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipes
[ms-hvsocket]: https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/make-integration-service
[qemu-whpx]: https://www.qemu.org/docs/master/system/whpx.html
[qemu-linuxboot]: https://www.qemu.org/docs/master/system/linuxboot.html
[qemu-invocation]: https://www.qemu.org/docs/master/system/invocation.html
[qemu-chardev-pipe]: https://www.qemu.org/docs/master/system/invocation.html#character-device-options
[qemu-hostfwd]: https://www.qemu.org/docs/master/system/invocation.html#network-options
[qemu-netdev-stream]: https://www.qemu.org/docs/master/system/invocation.html#network-options
[qemu-net]: https://www.qemu.org/docs/master/system/devices/net.html
[qmp]: https://qemu-project.gitlab.io/qemu/interop/qemu-qmp-ref.html
[qemu-ga]: https://qemu-project.gitlab.io/qemu/interop/qemu-ga-ref.html
[qemu-img]: https://www.qemu.org/docs/master/tools/qemu-img.html
[qemu-images]: https://www.qemu.org/docs/master/system/images.html
[qemu-virtfs]: https://www.qemu.org/docs/master/system/invocation.html#filesystem-options
[virtiofs]: https://virtio-fs.gitlab.io/
