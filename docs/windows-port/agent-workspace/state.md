# Windows Port State

Last updated: 2026-07-03
Owner: TBD
RFC: `docs/windows-port/rfc-qemu-whpx.md`
Current milestone: M01 - Windows compile stubs
Overall status: Not started

## How to update this file

Update this file at the end of every agent run. Keep it factual. Do not use it for design debate; use `decisions.md` for accepted decisions and `risk-register.md` for risk tracking.

## Current branch / issue

- Branch: TBD
- Issue: TBD
- Agent: TBD
- Start commit: TBD
- End commit: TBD

## Milestone status table

| Milestone | Status | Owner | Branch/PR | Notes |
|---|---|---|---|---|
| M01 Windows compile stubs | Not started | TBD | TBD | First milestone. |
| M02 QEMU discovery and preflight | Blocked by M01 | TBD | TBD | Requires Windows platform module to compile. |
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

- No Windows backend exists yet.
- `lsb-vm` currently needs non-macOS compile handling.
- QEMU path/version/WHPX availability are not yet detected.
- Windows hardware workflow exists; physical runner availability has not been verified from this workspace.

## Recently completed work

- 2026-07-03: Added macOS helper for manually dispatching Windows hardware workflow, added Windows smoke/e2e script entrypoints, and documented runner trigger usage.

## Active implementation notes

Add short notes here when they affect the next agent. Example:

- `M02` introduced `QemuDiscovery` in `crates/lsb-platform/src/windows_x86_64/qemu.rs`.
- `M03` golden argv tests live under `crates/lsb-platform/tests/windows_qemu_argv.rs`.

## Test evidence log

Append newest entries at the top.

| Date | Milestone | Platform | Command / test | Result | Notes |
|---|---|---|---|---|---|
| 2026-07-03 | M15 | macOS | Documentation/script update only | Not run | Hardware workflow not dispatched because changes were not committed/pushed. |
| 2026-07-02 | Bootstrap | n/a | n/a | n/a | Workspace created. |

## Open follow-ups

- [ ] Confirm final location of Windows backend module under `lsb-platform`.
- [ ] Decide exact hidden/debug flag name for TCG once CLI command parsing is inspected.
- [ ] Decide exact QEMU minimum version after M02 preflight experimentation.
- [ ] Confirm whether the self-hosted runner should keep default `self-hosted, Windows, X64` labels or add custom `whpx` / `local-sandbox` labels.
