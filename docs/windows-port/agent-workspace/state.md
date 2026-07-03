# Windows Port State

Last updated: 2026-07-03
Owner: TBD
RFC: `docs/windows-port/rfc-qemu-whpx.md`
Current milestone: M03 - QEMU argv builder
Overall status: Done

## How to update this file

Update this file at the end of every agent run. Keep it factual. Do not use it for design debate; use `decisions.md` for accepted decisions and `risk-register.md` for risk tracking.

## Current branch / issue

- Branch: `codex/windows-m03-qemu-argv-builder`
- Issue: TBD
- Agent: Codex
- Start commit: `1d0a3c8`
- End commit: M03 handoff commit on `codex/windows-m03-qemu-argv-builder`

## Milestone status table

| Milestone | Status | Owner | Branch/PR | Notes |
|---|---|---|---|---|
| M01 Windows compile stubs | Done | Codex | `codex/windows-m01-compile-stubs` | Windows x86_64 compile stubs are in place; runtime remains unsupported. |
| M02 QEMU discovery and preflight | Done | Codex | `codex/windows-m02-qemu-discovery-preflight` | Private QEMU discovery/version/WHPX preflight scaffolding and fake-runner tests are in place. |
| M03 QEMU argv builder | Done | Codex | `codex/windows-m03-qemu-argv-builder` | Typed deterministic QEMU argv construction, sanitized diagnostics, and golden tests are in place. |
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

- Windows VM startup remains a stub; QEMU process lifecycle, guest boot, transport, networking, mounts, and checkpoints are not implemented.
- M02 safe WHPX preflight does not launch a VM. It proves the selected QEMU binary reports WHPX in `-accel help`, but firmware/Windows Hypervisor Platform runtime readiness is finally proven by later boot smoke tests.
- Full `cargo check --workspace --target x86_64-pc-windows-msvc` from this macOS host is blocked by external Windows C/assembler tooling for transitive crates (`ring` needs Windows/MSVC headers such as `assert.h`; `blake3` needs `ml64.exe`). The changed `lsb-platform` crate passes a targeted Windows compile check; run the full workspace check on a Windows/MSVC runner.
- The current safe host probe verifies target OS/arch and can report a supplied Windows major version. The standard host implementation does not yet query the native Windows build number without adding Windows API or registry probing.

## Recently completed work

- 2026-07-03: Completed M01 compile scaffolding. Added `lsb-platform::windows_x86_64` backend/config/error stubs, removed the `lsb-vm` non-macOS compile rejection, added Windows runtime capability errors, cfg-gated Unix-only proxy/store/CLI paths, and added stub coverage tests.
- 2026-07-03: Ran Windows hardware workflow through `./scripts/win-gh-test`. `check` passed on run `28651692448`. Initial `unit` run `28651764230` failed because Windows-only stub tests used `expect_err` with non-`Debug` handle types; fixed in `066a6c2`, then `unit` passed on run `28651905208`.
- 2026-07-03: Added macOS helper for manually dispatching Windows hardware workflow, added Windows smoke/e2e script entrypoints, and documented runner trigger usage.
- 2026-07-03: Started M02 on `codex/windows-m02-qemu-discovery-preflight` from `958562e`; scope is QEMU discovery, version probing, WHPX preflight diagnostics, and fake-runner unit tests only.
- 2026-07-03: Completed M02 QEMU discovery/preflight scaffolding under `lsb-platform::windows_x86_64::qemu`. Added env/config/PATH discovery, `--version` parsing, `--help` suitability checks, WHPX `-accel help` inspection, structured actionable errors, and fake host/runner unit tests. No VM boot, argv builder, QEMU process lifecycle, or TCG fallback was implemented.
- 2026-07-03: Ran Windows hardware workflow through `./scripts/win-gh-test`. `check` passed on run `28653449586`; `unit` passed on run `28653507512`.
- 2026-07-03: Started M03 on `codex/windows-m03-qemu-argv-builder` from `1d0a3c8`; scope is typed deterministic QEMU argv construction only, with no QEMU spawn, process lifecycle, boot, virtio-serial connection, networking, mounts, or checkpoint implementation.
- 2026-07-03: Completed M03 QEMU argv builder. Added typed QEMU boot/machine/disk/kernel/serial/control/QMP config and `QemuArgvBuilder` under `lsb-platform::windows_x86_64::qemu`. Generated argv uses WHPX-only `q35,accel=whpx`, direct Linux boot, virtio-blk root disk, serial output, optional virtio-serial control pipe placeholder, optional private QMP pipe, and explicit `-nic none`. Added sanitized command diagnostics that redact executable, asset paths, serial log path, control pipe name, and QMP pipe name. No QEMU process is started.

## Active implementation notes

- 2026-07-03: M01 started on `codex/windows-m01-compile-stubs` from `3501c2b`; scope is compile scaffolding only, with no QEMU discovery/startup or runtime feature implementation.
- 2026-07-03: M01 placed Windows x86_64 scaffolding under `crates/lsb-platform/src/windows_x86_64/{backend.rs,config.rs,errors.rs}`. The stub VM can be constructed but `start`, `stop`, and guest control transport return explicit unsupported errors.
- 2026-07-03: Windows proxy networking (`M12`), NBD/CAS storage transport (`M13`), port forwarding (`M11`), shell/exec control transport (`M06`/`M08`), and prune process-liveness checks fail closed instead of opening listeners/devices or guessing behavior.
- 2026-07-03: M02 introduced private QEMU modules at `crates/lsb-platform/src/windows_x86_64/qemu/{discovery.rs,version.rs,preflight.rs}`. The module has a scoped `dead_code` allowance because M02 prepares the reusable preflight API before M04 wires VM startup/process lifecycle.
- 2026-07-03: Real QEMU preflight hook is `windows_x86_64::qemu::tests::real_qemu_preflight_when_explicitly_enabled`; run it only with `LSB_TEST_REAL_QEMU=1` and `LSB_QEMU` pointing at `qemu-system-x86_64.exe`.
- 2026-07-03: M03 added `crates/lsb-platform/src/windows_x86_64/qemu/{config.rs,argv.rs}`. The builder returns a program `PathBuf` plus `Vec<OsString>` argv and a separate redacted diagnostic display. Paths with spaces are preserved as single argv entries; root disk paths embedded in QEMU option syntax escape commas by doubling them. QMP is represented only as a named pipe endpoint and remains QEMU-management-only.

## Test evidence log

Append newest entries at the top.

| Date | Milestone | Platform | Command / test | Result | Notes |
|---|---|---|---|---|---|
| 2026-07-03 | M03 | Windows self-hosted | `./scripts/win-gh-test check` | Pass | Run `28655108246`; manual hardware workflow check lane passed. |
| 2026-07-03 | M03 | Windows self-hosted | `./scripts/win-gh-test unit` | Pass | Run `28655161915`; unit lane passed. The helper dispatched the run; it was watched directly by run ID because the helper matched the earlier same-SHA check run. |
| 2026-07-03 | M03 | macOS | `cargo fmt --all -- --check` | Pass | Formatting verified after code and docs updates. |
| 2026-07-03 | M03 | macOS | `cargo check --workspace` | Pass | Full workspace compile check passed. |
| 2026-07-03 | M03 | macOS | `cargo test --workspace` | Pass | 77 passed, 1 ignored real-QEMU preflight hook. New argv golden tests are target-independent and do not start QEMU. |
| 2026-07-03 | M03 | macOS | `cargo test -p lsb-platform` | Pass | 35 passed, 1 ignored; focused run for QEMU argv/preflight module tests. |
| 2026-07-03 | M03 | macOS cross-check | `cargo check -p lsb-platform --target x86_64-pc-windows-msvc` | Pass | Targeted Windows compile check for the changed crate. |
| 2026-07-03 | M03 | macOS cross-check | `cargo check --workspace --target x86_64-pc-windows-msvc` | Blocked | External toolchain limitation on macOS host: `ring` failed on missing Windows/MSVC `assert.h`; `blake3` failed on missing `ml64.exe`. Run full workspace target check on a Windows/MSVC runner. |
| 2026-07-03 | M02 | macOS | `cargo fmt --all -- --check` | Pass | Formatting verified after code and docs-adjacent edits. |
| 2026-07-03 | M02 | macOS | `cargo check --workspace` | Pass | Full workspace compile check passed. |
| 2026-07-03 | M02 | macOS | `cargo test --workspace` | Pass | 67 passed, 1 ignored real-QEMU preflight hook. |
| 2026-07-03 | M02 | macOS cross-check | `cargo check -p lsb-platform --target x86_64-pc-windows-msvc` | Pass | Targeted Windows compile check for the changed crate; no warnings after scoped QEMU scaffold allowance. |
| 2026-07-03 | M02 | Windows self-hosted | `./scripts/win-gh-test check` | Pass | Run `28653449586`; pushed current code commits and ran `windows-lsb-hardware.yml` with `test_set=check`. |
| 2026-07-03 | M02 | Windows self-hosted | `./scripts/win-gh-test unit` | Pass | Run `28653507512`; unit lane passed. |
| 2026-07-03 | M01 | macOS | `cargo fmt --all -- --check` | Pass | Formatting verified. |
| 2026-07-03 | M01 | macOS | `cargo check --workspace` | Pass | Existing macOS cfg paths remain intact. |
| 2026-07-03 | M01 | macOS | `cargo test -p lsb-platform` | Pass | 8 tests, including Windows platform/stub tests. |
| 2026-07-03 | M01 | macOS | `cargo test -p lsb-vm` | Pass | 2 mount-plan tests. |
| 2026-07-03 | M01 | macOS | `cargo test -p lsb-store` | Pass | 5 storage tests. |
| 2026-07-03 | M01 | macOS | `cargo test -p lsb-proxy` | Pass | 11 proxy/config/DNS tests. |
| 2026-07-03 | M01 | macOS cross-check | `cargo check -p lsb-platform -p lsb-vm -p lsb-proxy -p lsb-proto --target x86_64-pc-windows-msvc` | Pass | Validates core M01 Windows stubs without external Windows C/asm toolchain. |
| 2026-07-03 | M01 | macOS cross-check | `cargo check --workspace --target x86_64-pc-windows-msvc` | Blocked | External toolchain limitation on macOS host: `ring` failed on missing Windows/MSVC `assert.h`; `blake3` failed on missing `ml64.exe`. `rustup target add x86_64-pc-windows-msvc` was completed first. |
| 2026-07-03 | M01 | Windows self-hosted | `./scripts/win-gh-test check` | Pass | Run `28651692448`; pushed branch and ran `windows-lsb-hardware.yml` with `test_set=check`. |
| 2026-07-03 | M01 | Windows self-hosted | `./scripts/win-gh-test unit` | Pass | Run `28651905208`; rerun after fixing Windows-only stub tests in `066a6c2`. |
| 2026-07-03 | M01 | Windows self-hosted | `./scripts/win-gh-test unit` | Fail | Run `28651764230`; failed because `expect_err` required `NbdHandle: Debug` in a Windows-only test. Fixed in `066a6c2`. |
| 2026-07-03 | M15 | macOS | Documentation/script update only | Not run | Hardware workflow not dispatched because changes were not committed/pushed. |
| 2026-07-02 | Bootstrap | n/a | n/a | n/a | Workspace created. |

## Open follow-ups

- [x] Confirm final location of Windows backend module under `lsb-platform`.
- [ ] Run full `cargo check --workspace --target x86_64-pc-windows-msvc` on a Windows/MSVC runner.
- [ ] Wire M02 `QemuPreflight` into the future Windows diagnostic/start path without booting a VM before M04/M05.
- [ ] Wire M03 `QemuArgvBuilder` into M04 process lifecycle without changing public CLI/SDK/Node APIs or claiming boot support.
- [ ] Persist a redacted `qemu.argv.json` or equivalent diagnostics artifact once M04 creates per-instance diagnostics directories.
- [ ] Decide exact hidden/debug flag name for TCG once CLI command parsing is inspected.
- [ ] Decide exact QEMU minimum version after M02 preflight experimentation.
- [ ] Decide whether native Windows build-number probing should use a Windows API, registry query, or remain deferred until a CLI diagnostics command exists.
- [ ] Confirm whether the self-hosted runner should keep default `self-hosted, Windows, X64` labels or add custom `whpx` / `local-sandbox` labels.
