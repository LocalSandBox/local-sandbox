# Windows SMB Direct Mounts Implementation State

This file is for implementation agents to keep progress, decisions, blockers,
and validation results synchronized while implementing `PLAN.md`.

## Current Status

- Overall status: Slice 7 implementation complete locally; self-hosted Windows
  smoke found readiness, SMB mount-preflight, CIFS UTF-8 kernel config, and SMB
  loopback server-name gaps, fixed in working tree; rerun pending
- Current owner: Codex
- Current branch: codex/lsb-direct-mnt
- Last updated: 2026-07-07
- Latest validated commit: working tree Slice 7 edits on codex/lsb-direct-mnt

## Active Focus

- Current task: Slice 7 Windows smoke tests, recovery, redaction scans, and
  docs finalization
- Relevant files: Windows smoke scripts, Node smoke script, Windows SMB
  lifecycle/recovery, Sandbox SMB cleanup wiring, docs, `STATE.md`
- Immediate next step: Amend/commit the smoke-discovered fixes, then rerun
  `./scripts/win-gh-test smoke`.
- Blockers: Self-hosted Windows helper requires a clean committed working tree.

## Maintainer Decisions

- [x] Use SMB/CIFS for Windows direct directory mounts.
- [x] Preserve macOS-like direct semantics, including `:rw`.
- [x] Require Administrator for Windows SMB direct mounts.
- [x] Use the LocalSandbox controlled proxy path.
- [x] Do not use QEMU user networking, `hostfwd`, TAP, bridge, NAT, or public
  listener paths.
- [x] Create ephemeral Windows SMB shares.
- [x] Create ephemeral Windows users and generated SMB credentials.
- [x] Recursive validation for direct mounts is required.
- [x] Keep CLI `:ro` as overlay.
- [x] Do not enable SMB encryption by default.
- [x] Use one ephemeral Windows user per sandbox.
- [x] Update both kernel configs.

## Progress Checklist

- [x] Update Windows decision docs to supersede the old no-direct-rw decision.
- [x] Enable CIFS client support in both kernel configs.
- [x] Add `cifs-utils` to the rootfs package list.
- [x] Add `MountRequest::Smb`.
- [x] Add `cifs_mount` guest capability.
- [x] Add protocol redaction tests for SMB credentials.
- [x] Implement guest `mount.cifs` path using `PASSWD_FD`.
- [x] Add mount-only SMB proxy mode.
- [x] Add CLI detection/startup for mount-only SMB proxy.
- [x] Add SDK detection/startup for mount-only SMB proxy.
- [x] Preserve Node API shape and direct flag mapping.
- [x] Add Windows direct SMB mount planning.
- [x] Add recursive direct path validation.
- [x] Add Windows admin preflight.
- [x] Add ephemeral user manager.
- [x] Add generated password wrapper and redaction.
- [x] Add NTFS ACL grant/revoke manager.
- [x] Add temporary SMB share manager.
- [x] Add SMB lifecycle setup/cleanup guard.
- [x] Wire SMB lifecycle into `Sandbox::start`.
- [x] Wire cleanup into `Sandbox::stop`.
- [x] Add stale cleanup manifest/recovery.
- [x] Add QEMU argv golden tests.
- [x] Add proxy policy tests.
- [x] Add guest mount tests.
- [x] Add Windows unit tests.
- [x] Add Windows WHPX smoke tests.
- [x] Update user-facing docs after validation updates.

## Validation Log

| Date | Commit | Command | Result | Notes |
| --- | --- | --- | --- | --- |
| 2026-07-06 | 092d163 + working tree | `rg -n 'SMB/CIFS|CLI .*:ro|Administrator|D024|allow_net|public API shape|Superseded' docs/windows-port/decisions.md docs/windows-port/README.md docs/windows-port/mvp-handoff.md docs/windows-port/security-checklist.md docs/windows-port/future-work.md PLAN.md STATE.md`; stale-limitation `rg` check; `git diff --check` | Pass | Required Slice 1 claims present, stale exact limitations absent, whitespace clean. No code or tests by scope. |
| 2026-07-06 | 0febf44 + working tree | `cargo fmt --check`; `cargo test -p lsb-proto`; `cargo test -p lsb-guest`; `cargo test -p xtask rootfs` | Pass | Scoped Slice 2 formatting and directly related tests pass. |
| 2026-07-06 | 0febf44 + working tree | `cargo check --workspace` | Blocked | Fails because `crates/lsb-vm/src/sandbox.rs` has an exhaustive `MountRequest` match missing `Smb`; `lsb-vm` is outside the requested touch list. |
| 2026-07-06 | 0febf44 + working tree | `cargo fmt --check`; `cargo check --workspace`; `cargo test -p lsb-vm` | Pass | Minimal `lsb-vm` exhaustiveness update restored workspace compilation without SMB lifecycle/startup behavior. |
| 2026-07-06 | 0febf44 + working tree | `cargo fmt --check`; `cargo test -p lsb-proxy`; `git diff --check` | Pass | Slice 3 proxy policy tests cover mount-only SMB relay, arbitrary TCP/DNS denial, no secret substitutions in mount-only mode, and combined network-plus-SMB behavior. |
| 2026-07-06 | 9ab5fa9 + working tree | `cargo fmt --all -- --check`; `cargo test -p lsb-cli`; `cargo test -p lsb-sdk`; `cargo test -p lsb-platform windows_x86_64::qemu::argv::tests`; `cargo test -p lsb-platform windows_x86_64::network::tests`; `cargo check --workspace`; `git diff --check` | Pass | Slice 4 CLI/SDK tests cover mount-only SMB proxy selection, combined allow-net plus SMB relay, CLI `:ro` overlay parsing, and no-direct unchanged behavior. QEMU/network tests cover default `-nic none`, QEMU stream netdev attachment, loopback-only endpoints, and no user networking/hostfwd/TAP/bridge/NAT tokens. |
| 2026-07-06 | 9ab5fa9 + working tree | `cargo fmt --all -- --check`; `cargo test -p lsb-platform windows_x86_64::fs::smb`; `cargo test -p lsb-platform`; `cargo check -p lsb-platform --target x86_64-pc-windows-msvc`; `cargo check --workspace`; `git diff --check` | Pass | Slice 5 fake-manager tests cover success, admin failure, partial ACL/share failure cleanup, cleanup continuing after failures, name limits, password policy, and redaction. Windows target check covers native admin/user/share/ACL API adapters. |
| 2026-07-06 | working tree | `cargo fmt --all -- --check`; `cargo test -p lsb-platform windows_x86_64::fs::smb`; `cargo test -p lsb-cli`; `cargo test -p lsb-vm`; `cargo test -p lsb-sdk`; `cargo check --workspace`; `git diff --check` | Pass | Slice 7 local validation. SMB tests cover non-secret cleanup manifest roundtrip and failed recovery retry behavior. VM/SDK ignored smoke tests now include direct SMB success/failure cleanup coverage. |
| 2026-07-06 | working tree | `cargo check -p lsb-platform --target x86_64-pc-windows-msvc`; `cargo check -p lsb-vm --target x86_64-pc-windows-msvc` | Pass | Focused Windows cfg checks for platform SMB recovery and VM cleanup wiring pass on macOS host. |
| 2026-07-06 | working tree | `cargo check --workspace --target x86_64-pc-windows-msvc` | Blocked | macOS host lacks MSVC C tooling/Windows headers for transitive native crypto deps (`ml64.exe`, `windows.h`, `assert.h`). Use self-hosted Windows `./scripts/win-gh-test unit` for full Windows workspace validation. |
| 2026-07-06 | working tree | `./scripts/win-gh-test unit`; `./scripts/win-gh-test smoke` | Pending | Not run from this uncommitted workspace. The helper requires a clean committed tree because it pushes the branch before dispatching the self-hosted workflow. |
| 2026-07-06 | 484cc00 | GitHub Actions smoke run 28799295329 / job 85401254717 | Failed | Baseline Node smoke reached guest-ready but Windows readiness validation rejected the newly advertised `cifs_mount` capability. |
| 2026-07-06 | working tree | `cargo fmt --all -- --check`; `cargo test -p lsb-platform windows_x86_64::qemu::boot`; `cargo test -p lsb-platform windows_x86_64::fs::smb`; `cargo check -p lsb-platform --target x86_64-pc-windows-msvc`; `cargo run -p xtask -- platform-meta --platform windows-x86_64 --format env`; `git diff --check` | Pass | Smoke-discovered readiness allowlist bug fixed by accepting `CAP_CIFS_MOUNT` as a supported Windows guest runtime capability. |
| 2026-07-06 | e982bf0 | GitHub Actions smoke run 28802842700 / job 85410910635 | Failed | Node direct read-only SMB smoke reached guest mount and failed with `mount.cifs` status 32 without stderr details. |
| 2026-07-06 | working tree | `cargo fmt --all -- --check`; `cargo test -p lsb-guest smb_mount`; `cargo test -p lsb-platform windows_x86_64::fs::smb`; `cargo test -p lsb-platform windows_x86_64::qemu::boot`; `cargo check -p lsb-platform --target x86_64-pc-windows-msvc`; `cargo check --workspace`; `git diff --check` | Pass | Added SMB loopback preflight before host resource creation, read/execute share ACL rights for direct SMB traversal, and sanitized guest `mount.cifs` stderr in mount failures. |
| 2026-07-06 | working tree | `cargo check -p lsb-guest --target x86_64-unknown-linux-musl` | Blocked | Local Rust toolchain does not have the Linux musl target installed; Windows smoke rebuilds this target during boot asset preparation. |
| 2026-07-07 | e7e92c2 | GitHub Actions smoke run 28804293122 / job 85416740297 | Failed | Node direct read-only SMB smoke failed with `mount.cifs` status 32 and stderr `mount error(79): Can not access a needed shared library`, matching missing CIFS UTF-8 NLS support for `iocharset=utf8`. |
| 2026-07-07 | working tree | `rg -n "CONFIG_NLS|CONFIG_NLS_UTF8|CONFIG_CIFS" kernel/lsb_defconfig kernel/lsb_x86_64_defconfig`; `cargo test -p xtask boot_asset`; `cargo test -p lsb-guest smb_mount`; `cargo test -p lsb-platform windows_x86_64::fs::smb` | Pass | Added built-in `CONFIG_NLS=y` and `CONFIG_NLS_UTF8=y` to both kernels so CIFS `iocharset=utf8` works without loadable modules. |
| 2026-07-07 | c902ff6 | GitHub Actions smoke run 28806371824 / job 85425815050 | Failed | Node direct read-only SMB smoke advanced to `mount error(5): Input/output error` while using `//10.0.0.1/<share>` as the SMB server name. |
| 2026-07-07 | working tree | `cargo fmt --all -- --check`; `cargo test -p lsb-guest smb_mount`; `cargo test -p lsb-platform windows_x86_64::fs::smb`; `cargo test -p lsb-platform windows_x86_64::qemu::boot`; `cargo check -p lsb-platform --target x86_64-pc-windows-msvc`; `cargo check --workspace`; `git diff --check` | Pass | Windows SMB mount requests now use the real Windows computer name as the UNC server and force proxy transport with guest CIFS option `ip=10.0.0.1`. |
| 2026-07-07 | 793c00f | GitHub Actions smoke run 28808688475 / job 85431712360 | Failed | Node direct read-only SMB smoke still failed with `mount error(5): Input/output error` while using `//CYW2LN3/<share>` as the SMB server name. |
| 2026-07-07 | working tree | `cargo fmt --all -- --check`; `cargo test -p lsb-guest smb_mount`; `cargo test -p lsb-platform windows_x86_64::fs::smb`; `cargo check -p lsb-platform --target x86_64-pc-windows-msvc`; `cargo test -p lsb-platform windows_x86_64::qemu::boot`; `cargo check --workspace`; `cargo test -p xtask boot_asset`; `git diff --check` | Pass | Windows SMB mount requests now use `//localhost/<share>` as the UNC server, keep `domain=<host-computer-name>` for auth, keep `ip=10.0.0.1` for proxy transport, and include sanitized CIFS-related `dmesg` lines on guest mount failures. |
| 2026-07-07 | working tree | `cargo check -p lsb-guest --target x86_64-unknown-linux-musl` | Blocked | Local Rust toolchain still does not have the Linux musl target installed; Windows smoke rebuilds this target during boot asset preparation. |
| 2026-07-07 | fbbd7f1 | GitHub Actions smoke run 28811434918 / job 85441710757 | Failed | Node direct read-only SMB smoke reached `//localhost/<share>` and CIFS reported `STATUS_LOGON_TYPE_NOT_GRANTED`, showing Windows rejected the generated account for network logon. |
| 2026-07-07 | local spike | PowerShell SMB spike with generated local user in built-in Users alias | Failed | `net use \\localhost\<share>` failed with system error 1385, confirming built-in Users membership is not sufficient on this Windows policy. |
| 2026-07-07 | working tree | `cargo fmt --all -- --check`; `cargo test -p lsb-guest smb_mount`; `cargo test -p lsb-platform windows_x86_64::fs::smb`; `cargo check -p lsb-platform --target x86_64-pc-windows-msvc`; `cargo test -p lsb-platform windows_x86_64::qemu::boot`; `cargo check --workspace`; `git diff --check` | Pass | Native Windows SMB user creation now grants account-specific `SeNetworkLogonRight` through LSA, revokes it before account deletion, keeps built-in Users alias membership setup, and deletes the account if post-create setup fails. |

## Open Blockers

| Date | Area | Blocker | Owner | Resolution |
| --- | --- | --- | --- | --- |
| | | | | |

## Follow-Up Decisions Needed

| Date | Question | Options | Decision | Owner |
| --- | --- | --- | --- | --- |
| | | | | |

## Changed Files Tracker

Use this section to summarize intentional changes. Do not include generated
artifacts unless they are intentionally checked in.

| File | Status | Notes |
| --- | --- | --- |
| `docs/windows-port/decisions.md` | Updated | Added D024, superseded D011, and scoped D010 for explicit SMB direct mounts. |
| `docs/windows-port/README.md` | Updated | Documents implemented Windows SMB/CIFS direct mount behavior and stale cleanup manifests. |
| `docs/windows-port/mvp-handoff.md` | Updated | Documents current SMB/CIFS direct mount support, limitations, and recovery behavior. |
| `docs/windows-port/security-checklist.md` | Updated | Added D024 guardrails for explicit SMB direct host writes. |
| `docs/windows-port/future-work.md` | Updated | Moves SMB/CIFS direct mounts from implementation work to follow-up hardening. |
| `PLAN.md` | Updated | Avoided duplicate future decision work now that D024 exists. |
| `STATE.md` | Updated | Recorded Slice 1 status and docs-only validation scope. |
| `crates/lsb-proto/src/lib.rs` | Updated | Added `CAP_CIFS_MOUNT`, `MountRequest::Smb`, redacted formatting, and protocol tests. |
| `crates/lsb-guest/src/main.rs` | Updated | Advertises `cifs_mount`, builds sanitized CIFS options, forces SMB transport through `ip=10.0.0.1`, invokes `mount.cifs` with `PASSWD_FD`, and reports sanitized bounded mount stderr plus CIFS-related `dmesg` on failures. |
| `kernel/lsb_defconfig` | Updated | Enabled built-in CIFS client support and UTF-8 NLS support required by CIFS `iocharset=utf8`. |
| `kernel/lsb_x86_64_defconfig` | Updated | Enabled built-in CIFS client support and UTF-8 NLS support required by CIFS `iocharset=utf8`. |
| `xtask/src/rootfs.rs` | Updated | Installs `cifs-utils`, checks for `mount.cifs`, and tests generated rootfs scripts. |
| `crates/lsb-vm/src/sandbox.rs` | Updated | Wires SMB cleanup manifest write/remove into start/stop, removes stale SMB mount requests on cleanup, keeps overlay smoke current, and adds direct SMB failure-cleanup smoke coverage. |
| `crates/lsb-proxy/src/config.rs` | Updated | Added `ProxyMode`, mount-only SMB config helpers, gateway/SMB constants, and policy tests. |
| `crates/lsb-proxy/src/dns.rs` | Updated | Mount-only SMB mode answers `host.lsb.internal` locally and refuses arbitrary DNS without host resolver forwarding. |
| `crates/lsb-proxy/src/proxy.rs` | Updated | Routes only guest `10.0.0.1:445` to host `127.0.0.1:445` in SMB modes and denies other mount-only TCP flows. |
| `crates/lsb-cli/src/vm.rs` | Updated | Detects Windows direct mounts and selects mount-only SMB proxy config when `allow_net` is false, or merges SMB relay into the normal proxy when `allow_net` is true; CLI `:ro` remains overlay. |
| `crates/lsb-sdk/src/runtime.rs` | Updated | Mirrors CLI proxy selection for SDK/Node callers, runs stale SMB recovery before instance reuse, and adds direct SMB rw/no-network/cleanup smoke coverage. |
| `crates/lsb-platform/src/windows_x86_64/qemu/argv.rs` | Updated | Extended stream-network argv assertions to exclude `-nic`, QEMU user networking, `hostfwd`, TAP, bridge, and NAT tokens. |
| `crates/lsb-platform/src/windows_x86_64/qemu/boot.rs` | Updated | Accepts the `cifs_mount` guest-ready capability now that the Windows host implements SMB direct mount handling. |
| `crates/lsb-platform/Cargo.toml` | Updated | Added Windows API feature gates required by native SMB admin, user, share, and ACL adapters. |
| `crates/lsb-platform/src/windows_x86_64/fs/mod.rs` | Updated | Exposes the Windows SMB lifecycle module under the Windows fs namespace. |
| `crates/lsb-platform/src/windows_x86_64/fs/smb/` | Added/Updated | Implements fakeable SMB admin/password/user/ACL/share components, native Windows adapters, host loopback preflight, lifecycle setup/cleanup, non-secret cleanup manifests, stale recovery, mount request generation with localhost UNC targets plus Windows computer-name auth domains, account-specific `SeNetworkLogonRight` grant/revoke, name validation, password redaction, and unit tests. |
| `scripts/windows-smoke.ps1` | Updated | Adds CLI `:ro` overlay smoke plus direct SMB success and failure-cleanup ignored test invocations. |
| `bindings/nodejs/scripts/windows-preflight-smoke.mjs` | Updated | Adds Node direct read-only SMB smoke coverage. |
| `README.md` | Updated | Documents final Windows SMB/CIFS direct mount behavior. |
| `bindings/nodejs/README.md` | Updated | Documents Windows direct mount flags and Administrator requirement. |
| `docs/windows-port/architecture.md` | Updated | Records SMB/CIFS direct mount lifecycle and cleanup manifest architecture. |
| `docs/windows-port/diagnostics.md` | Updated | Documents SMB cleanup manifest diagnostics and redaction rules. |
| `docs/windows-port/validation.md` | Updated | Lists new direct SMB, CLI `:ro`, Node ro, cleanup, and redaction smoke coverage. |
| `docs/windows-port/risk-register.md` | Updated | Adds stale SMB resource cleanup risk and mitigation. |
| `docs/windows-port/runner-setup.md` | Updated | Describes direct SMB smoke scope. |
| `docs/windows-port/review-checklist.md` | Updated | Updates direct mount review rule for D024 SMB/CIFS path. |

## Cleanup/Redaction Audit

- [x] Generated SMB passwords absent from CLI output.
- [x] Generated SMB passwords absent from SDK/Node errors.
- [x] Generated SMB passwords absent from Rust `Debug`/`Display`.
- [x] Generated SMB passwords absent from QEMU argv.
- [x] Generated SMB passwords absent from guest process argv.
- [x] Generated SMB passwords absent from guest environment except fd number.
- [x] Generated SMB passwords absent from proxy diagnostics.
- [x] Generated SMB passwords absent from mount response errors.
- [x] Generated SMB passwords absent from cleanup manifests.
- [x] Generated SMB passwords absent from test snapshots.
- [x] Generated SMB passwords absent from logs.

## Smoke Test State

- Non-admin preflight failure: Unit-covered by SMB lifecycle fake admin test;
  hardware smoke pending.
- Admin rw direct mount guest-to-host write: Covered by
  `windows_qemu_direct_smb_mount_smoke`; hardware smoke pending.
- Admin rw direct mount host-to-guest visibility: Covered by
  `windows_qemu_direct_smb_mount_smoke`; hardware smoke pending.
- SDK/Node direct read-only write denial: Node smoke covers
  `flags: MS_RDONLY`; hardware smoke pending.
- CLI `:ro` overlay compatibility: `scripts/windows-smoke.ps1` runs a CLI
  `:ro` overlay smoke; hardware smoke pending.
- Mount-only proxy no arbitrary outbound network: Covered by SDK direct SMB
  smoke and existing proxy policy tests; hardware smoke pending.
- Cleanup leaves no LocalSandbox shares: Covered by SDK direct SMB smoke and
  VM failure-cleanup smoke; hardware smoke pending.
- Cleanup leaves no LocalSandbox users: Covered by SDK direct SMB smoke and VM
  failure-cleanup smoke; hardware smoke pending.
- Cleanup removes NTFS ACL grants: Covered by SDK direct SMB smoke; hardware
  smoke pending.
- Failure injection cleanup: Covered by fake-manager tests and missing-proxy VM
  smoke; hardware smoke pending.
- Artifact password scan: Cleanup manifest unit scan and SDK/Node/QEMU argv
  smoke scans added; hardware smoke pending.

## Notes

- Keep this file current during implementation.
- Link back to `PLAN.md` for design details.
- Record deviations from `PLAN.md` in "Follow-Up Decisions Needed" before
  implementing them.
