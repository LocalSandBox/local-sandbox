# Windows Port State

Last updated: 2026-07-03
Owner: TBD
RFC: `docs/windows-port/rfc-qemu-whpx.md`
Current milestone: M01 - Windows compile stubs
Overall status: Done

## How to update this file

Update this file at the end of every agent run. Keep it factual. Do not use it for design debate; use `decisions.md` for accepted decisions and `risk-register.md` for risk tracking.

## Current branch / issue

- Branch: `codex/windows-m01-compile-stubs`
- Issue: TBD
- Agent: Codex
- Start commit: `3501c2b`
- End commit: TBD (final docs commit)

## Milestone status table

| Milestone | Status | Owner | Branch/PR | Notes |
|---|---|---|---|---|
| M01 Windows compile stubs | Done | Codex | `codex/windows-m01-compile-stubs` | Windows x86_64 compile stubs are in place; runtime remains unsupported. |
| M02 QEMU discovery and preflight | Not started | TBD | TBD | Windows platform module now exists for discovery/preflight work. |
| M03 QEMU argv builder | Blocked by M02 | TBD | TBD | Requires discovered/preflighted QEMU config shape. |
| M04 QEMU process lifecycle | Blocked by M03 | TBD | TBD | Requires argv builder. |
| M05 Direct Linux boot and serial logs | Blocked by M04 | TBD | TBD | Requires process supervision. |
| M06 Virtio-serial control transport | Blocked by M05 | TBD | TBD | Requires bootable guest and QEMU chardev. |
| M07 Guest ready handshake | Blocked by M06 | TBD | TBD | Requires control transport. |
| M08 Exec command | Blocked by M07 | TBD | TBD | First useful guest operation. |
| M09 Copy-in/copy-out data plane | Blocked by M08 | TBD | TBD | Requires guest file protocol. |
| M10 Mount MVP semantics | Blocked by M09 | TBD | TBD | Uses copy/import/export semantics first. |
| M11 Port forwarding | Blocked by M07 | TBD | TBD | Preserve no-network default. |
| M12 Network policy and proxy integration | Blocked by M08/M11 | TBD | TBD | Strict egress; no QEMU NAT by default. |
| M13 Checkpoint/store MVP | Blocked by M09/M10 | TBD | TBD | Simple disk artifact path first. |
| M14 Node packaging | Blocked by core CLI smoke | TBD | TBD | Windows package after Rust backend. |
| M15 CI and diagnostics hardening | Runs throughout, final gate after M14 | TBD | TBD | Self-hosted Windows 11 WHPX runner. |

Status values: `Not started`, `In progress`, `Blocked`, `Review`, `Done`, `Deferred`.

## Current known blockers

- Only the M01 Windows stub backend exists; real QEMU/WHPX discovery, preflight, startup, transport, networking, mounts, and checkpoints are not implemented.
- Full `cargo check --workspace --target x86_64-pc-windows-msvc` from this macOS host is blocked by external Windows C/assembler tooling for transitive crates (`ring` needs Windows/MSVC headers such as `assert.h`; `blake3` needs `ml64.exe`). Run the full check on a Windows/MSVC runner.
- QEMU path/version/WHPX availability are not yet detected.
- Windows hardware workflow exists; physical runner availability has not been verified from this workspace.

## Recently completed work

- 2026-07-03: Completed M01 compile scaffolding. Added `lsb-platform::windows_x86_64` backend/config/error stubs, removed the `lsb-vm` non-macOS compile rejection, added Windows runtime capability errors, cfg-gated Unix-only proxy/store/CLI paths, and added stub coverage tests.
- 2026-07-03: Added macOS helper for manually dispatching Windows hardware workflow, added Windows smoke/e2e script entrypoints, and documented runner trigger usage.

## Active implementation notes

Add short notes here when they affect the next agent. Example:

- `M02` introduced `QemuDiscovery` in `crates/lsb-platform/src/windows_x86_64/qemu.rs`.
- `M03` golden argv tests live under `crates/lsb-platform/tests/windows_qemu_argv.rs`.
- 2026-07-03: M01 started on `codex/windows-m01-compile-stubs` from `3501c2b`; scope is compile scaffolding only, with no QEMU discovery/startup or runtime feature implementation.
- 2026-07-03: M01 placed Windows x86_64 scaffolding under `crates/lsb-platform/src/windows_x86_64/{backend.rs,config.rs,errors.rs}`. The stub VM can be constructed but `start`, `stop`, and guest control transport return explicit unsupported errors.
- 2026-07-03: Windows proxy networking (`M12`), NBD/CAS storage transport (`M13`), port forwarding (`M11`), shell/exec control transport (`M06`/`M08`), and prune process-liveness checks fail closed instead of opening listeners/devices or guessing behavior.

## Test evidence log

Append newest entries at the top.

| Date | Milestone | Platform | Command / test | Result | Notes |
|---|---|---|---|---|---|
| 2026-07-03 | M01 | macOS | `cargo fmt --all -- --check` | Pass | Formatting verified. |
| 2026-07-03 | M01 | macOS | `cargo check --workspace` | Pass | Existing macOS cfg paths remain intact. |
| 2026-07-03 | M01 | macOS | `cargo test -p lsb-platform` | Pass | 8 tests, including Windows platform/stub tests. |
| 2026-07-03 | M01 | macOS | `cargo test -p lsb-vm` | Pass | 2 mount-plan tests. |
| 2026-07-03 | M01 | macOS | `cargo test -p lsb-store` | Pass | 5 storage tests. |
| 2026-07-03 | M01 | macOS | `cargo test -p lsb-proxy` | Pass | 11 proxy/config/DNS tests. |
| 2026-07-03 | M01 | macOS cross-check | `cargo check -p lsb-platform -p lsb-vm -p lsb-proxy -p lsb-proto --target x86_64-pc-windows-msvc` | Pass | Validates core M01 Windows stubs without external Windows C/asm toolchain. |
| 2026-07-03 | M01 | macOS cross-check | `cargo check --workspace --target x86_64-pc-windows-msvc` | Blocked | External toolchain limitation on macOS host: `ring` failed on missing Windows/MSVC `assert.h`; `blake3` failed on missing `ml64.exe`. `rustup target add x86_64-pc-windows-msvc` was completed first. |
| 2026-07-03 | M15 | macOS | Documentation/script update only | Not run | Hardware workflow not dispatched because changes were not committed/pushed. |
| 2026-07-02 | Bootstrap | n/a | n/a | n/a | Workspace created. |

## Open follow-ups

- [x] Confirm final location of Windows backend module under `lsb-platform`.
- [ ] Run full `cargo check --workspace --target x86_64-pc-windows-msvc` on a Windows/MSVC runner.
- [ ] Decide exact hidden/debug flag name for TCG once CLI command parsing is inspected.
- [ ] Decide exact QEMU minimum version after M02 preflight experimentation.
- [ ] Confirm whether the self-hosted runner should keep default `self-hosted, Windows, X64` labels or add custom `whpx` / `local-sandbox` labels.
