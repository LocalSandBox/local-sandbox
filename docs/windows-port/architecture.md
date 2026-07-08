# Windows Backend Architecture

This document summarizes the current Windows backend layout and boundaries.
Read source before editing; this is a map, not an API contract.

## Backend shape

```text
CLI / Rust SDK / Node
        |
        v
lsb-vm: product lifecycle and platform-neutral API
        |
        v
lsb-platform platform backend boundary
        |
        +--> macOS Virtualization.framework backend
        |
        +--> Windows QEMU + WHPX backend
                    |
                    +--> Managed QEMU host-tool install metadata
                    +--> QEMU discovery and preflight
                    +--> QEMU argv builder and redaction
                    +--> QEMU process supervisor and Job Object cleanup
                    +--> direct Linux boot and diagnostics
                    +--> virtio-serial control and forwarding transports
                    +--> virtio-serial session mux for control operations
                    +--> Windows copy/mount/checkpoint strategies
                    +--> Windows direct SMB host watch adapter
                    +--> Windows proxy stream attachment
```

Inside the VM, the guest is still Linux plus `lsb-guest`. Windows changes the
transport and host backend, not the product model.

## Current implementation areas

| Area | Paths | Notes |
|---|---|---|
| VM orchestration | `crates/lsb-vm` | Platform-neutral sandbox lifecycle, exec/file/mount/port APIs, Windows smoke hooks. Keep public APIs platform-neutral. |
| Platform backend | `crates/lsb-platform/src/windows_x86_64` | Windows QEMU/WHPX backend, QEMU modules, control transport, fs planning, networking attachment, backend startup. |
| QEMU support | `crates/lsb-platform/src/windows_x86_64/qemu` | Discovery, version/preflight, argv, process, boot, and diagnostic artifacts. |
| Managed host tools | `crates/lsb-platform/src/windows_x86_64/host_tools.rs`, `crates/lsb-sdk/src/host_tools.rs` | Pinned QEMU metadata, `%LOCALAPPDATA%\lsb\tools\qemu` paths, safe install/extraction, manifest validation, and `current.json`. |
| Control and forwarding | `crates/lsb-platform/src/windows_x86_64/control`, `crates/lsb-proto`, `crates/lsb-guest` | Windows startup reads a raw `GuestReady` frame, then `CAP_SESSION_MUX` switches control traffic to mux virtual sessions. Port forwarding uses a separate virtio-serial channel. |
| File, mounts, and watch | `crates/lsb-platform/src/windows_x86_64/fs`, `crates/lsb-vm`, `crates/lsb-sdk`, `crates/lsb-guest` | Copy-in/copy-out plus guest staging for overlay mounts; SMB/CIFS lifecycle, cleanup manifests, CIFS guest mounts for explicit direct mounts, guest-side watch over mux, and direct-SMB host watch mapping. |
| Networking and secrets | `crates/lsb-proxy`, Windows platform network glue | LocalSandbox proxy policy remains authoritative. Windows uses QEMU stream netdev only for allow-net/proxy. |
| Store/checkpoints | `crates/lsb-store`, `crates/lsb-sdk`, Windows platform disk handling | Windows uses qcow2 overlays and flattened qcow2 checkpoints. macOS CAS/NBD remains unchanged. |
| CLI | `crates/lsb-cli` | Preserve public flags and product behavior; surface platform capability errors. |
| Rust SDK | `crates/lsb-sdk` | Preserve API shape; runtime actor, streaming process/watch abstractions, Windows direct SMB watch registry, and checkpoint smoke coverage live here. |
| Node binding | `bindings/nodejs` | `win32-x64-msvc` package metadata, Windows native target, loader error patching, streaming spawn/watch tests, and Windows smoke script. |
| CI/scripts | `.github/workflows`, `scripts/` | Hosted Windows compile/unit/golden CI and manual self-hosted WHPX workflow. |

## Boundaries

- `lsb-sdk`, CLI, and Node should not know QEMU argv syntax, named pipe paths,
  Job Object details, or WHPX quirks.
- `lsb-sdk` may initialize managed host tools explicitly through `lsb init` or
  `initSandbox()`, but VM boot must not download QEMU implicitly.
- `lsb-vm` owns product-level sandbox operations and calls platform-neutral
  backend hooks.
- `lsb-platform` owns VM/device/process details and Windows-specific error
  context.
- `lsb-proto` owns product protocol semantics. Transport adapters must not
  replace protocol operations with QMP or QGA behavior.
- Windows mux virtual sessions carry existing `lsb-proto` operation frames as
  payload bytes. Do not add Windows-only exec/watch frame variants unless an
  accepted decision changes public protocol semantics.
- `lsb-proxy` owns domain allowlists, DNS-answer binding, and secret
  substitution. QEMU networking is only an attachment mechanism.
- `lsb-store` owns checkpoint product semantics. QEMU snapshots are not the
  product checkpoint abstraction.

## QEMU-specific responsibilities

| Component | Owns | Must not own |
|---|---|---|
| `QemuDiscovery` / preflight | Locating QEMU, version capture, WHPX capability probes, actionable diagnostics | Product feature policy or hidden production fallback to TCG |
| QEMU argv builder | Deterministic structured argv and redacted diagnostic rendering | CLI parsing or secret policy |
| QEMU process supervisor | Spawn, stdout/stderr capture, status artifacts, Windows Job Object cleanup | Guest protocol semantics |
| Boot orchestration | Asset checks, direct Linux boot, serial/preflight/status artifacts, readiness wait | Public API shape |
| Virtio-serial transport | Private host/guest byte streams for control and forwarding, plus mux-owned virtual control sessions after `CAP_SESSION_MUX` | Network/mount/checkpoint policy decisions or public API shape |

## Error expectations

Prefer structured errors with stable categories and actionable remediation.
Useful categories include:

- `UnsupportedPlatform`
- `MissingQemu`
- `UnsupportedQemuVersion`
- `WhpxUnavailable`
- `AssetMissing`
- `QemuStartFailed`
- `GuestBootTimeout`
- `ControlTransportUnavailable`
- `MuxSessionUnavailable`
- `GuestProtocolError`
- `FeatureUnsupportedOnWindows`
- `WindowsHybridWatchUnsupported`
- `NetworkPolicyViolation`
- `CheckpointUnsupported`

Every user-facing error should state what failed, likely cause, safe
remediation, and relevant artifact paths. Redact before logs leave the owning
component.

## Public API guardrails

Do not change without an accepted decision:

- CLI flag names or default behavior.
- Rust SDK public types and methods.
- Node public API shape.
- Existing macOS behavior.
- Existing `lsb-proto` operation semantics.
