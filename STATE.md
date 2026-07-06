# Windows SMB Direct Mounts Implementation State

This file is for implementation agents to keep progress, decisions, blockers,
and validation results synchronized while implementing `PLAN.md`.

## Current Status

- Overall status: Slice 4 CLI/SDK/QEMU attachment integration implemented;
  scoped validation passing
- Current owner: Codex
- Current branch: codex/lsb-direct-mnt
- Last updated: 2026-07-06
- Latest validated commit: 9ab5fa9 plus uncommitted Slice 4 integration edits

## Active Focus

- Current task: Slice 4 CLI/SDK/QEMU attachment integration
- Relevant files: `crates/lsb-cli/src/vm.rs`,
  `crates/lsb-sdk/src/runtime.rs`,
  `crates/lsb-platform/src/windows_x86_64/qemu/argv.rs`,
  `STATE.md`
- Immediate next step: Begin Slice 5 Windows SMB host lifecycle after review.
- Blockers: None for Slice 4.

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
- [ ] Add Windows direct SMB mount planning.
- [ ] Add recursive direct path validation.
- [ ] Add Windows admin preflight.
- [ ] Add ephemeral user manager.
- [ ] Add generated password wrapper and redaction.
- [ ] Add NTFS ACL grant/revoke manager.
- [ ] Add temporary SMB share manager.
- [ ] Add SMB lifecycle setup/cleanup guard.
- [ ] Wire SMB lifecycle into `Sandbox::start`.
- [ ] Wire cleanup into `Sandbox::stop`.
- [ ] Add stale cleanup manifest/recovery.
- [x] Add QEMU argv golden tests.
- [x] Add proxy policy tests.
- [ ] Add guest mount tests.
- [ ] Add Windows unit tests.
- [ ] Add Windows WHPX smoke tests.
- [ ] Update user-facing docs after validation.

## Validation Log

| Date | Commit | Command | Result | Notes |
| --- | --- | --- | --- | --- |
| 2026-07-06 | 092d163 + working tree | `rg -n 'SMB/CIFS|CLI .*:ro|Administrator|D024|allow_net|public API shape|Superseded' docs/windows-port/decisions.md docs/windows-port/README.md docs/windows-port/mvp-handoff.md docs/windows-port/security-checklist.md docs/windows-port/future-work.md PLAN.md STATE.md`; stale-limitation `rg` check; `git diff --check` | Pass | Required Slice 1 claims present, stale exact limitations absent, whitespace clean. No code or tests by scope. |
| 2026-07-06 | 0febf44 + working tree | `cargo fmt --check`; `cargo test -p lsb-proto`; `cargo test -p lsb-guest`; `cargo test -p xtask rootfs` | Pass | Scoped Slice 2 formatting and directly related tests pass. |
| 2026-07-06 | 0febf44 + working tree | `cargo check --workspace` | Blocked | Fails because `crates/lsb-vm/src/sandbox.rs` has an exhaustive `MountRequest` match missing `Smb`; `lsb-vm` is outside the requested touch list. |
| 2026-07-06 | 0febf44 + working tree | `cargo fmt --check`; `cargo check --workspace`; `cargo test -p lsb-vm` | Pass | Minimal `lsb-vm` exhaustiveness update restored workspace compilation without SMB lifecycle/startup behavior. |
| 2026-07-06 | 0febf44 + working tree | `cargo fmt --check`; `cargo test -p lsb-proxy`; `git diff --check` | Pass | Slice 3 proxy policy tests cover mount-only SMB relay, arbitrary TCP/DNS denial, no secret substitutions in mount-only mode, and combined network-plus-SMB behavior. |
| 2026-07-06 | 9ab5fa9 + working tree | `cargo fmt --all -- --check`; `cargo test -p lsb-cli`; `cargo test -p lsb-sdk`; `cargo test -p lsb-platform windows_x86_64::qemu::argv::tests`; `cargo test -p lsb-platform windows_x86_64::network::tests`; `cargo check --workspace`; `git diff --check` | Pass | Slice 4 CLI/SDK tests cover mount-only SMB proxy selection, combined allow-net plus SMB relay, CLI `:ro` overlay parsing, and no-direct unchanged behavior. QEMU/network tests cover default `-nic none`, QEMU stream netdev attachment, loopback-only endpoints, and no user networking/hostfwd/TAP/bridge/NAT tokens. |

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
| `docs/windows-port/README.md` | Updated | Added accepted direct-mount plan and current planning-status caveat. |
| `docs/windows-port/mvp-handoff.md` | Updated | Separated current MVP limitations from the accepted post-MVP SMB/CIFS direction. |
| `docs/windows-port/security-checklist.md` | Updated | Added D024 guardrails for explicit SMB direct host writes. |
| `docs/windows-port/future-work.md` | Updated | Moved SMB/CIFS direct mounts into accepted follow-up work with constraints. |
| `PLAN.md` | Updated | Avoided duplicate future decision work now that D024 exists. |
| `STATE.md` | Updated | Recorded Slice 1 status and docs-only validation scope. |
| `crates/lsb-proto/src/lib.rs` | Updated | Added `CAP_CIFS_MOUNT`, `MountRequest::Smb`, redacted formatting, and protocol tests. |
| `crates/lsb-guest/src/main.rs` | Updated | Advertises `cifs_mount`, builds sanitized CIFS options, and invokes `mount.cifs` with `PASSWD_FD`. |
| `kernel/lsb_defconfig` | Updated | Enabled built-in CIFS client support. |
| `kernel/lsb_x86_64_defconfig` | Updated | Enabled built-in CIFS client support. |
| `xtask/src/rootfs.rs` | Updated | Installs `cifs-utils`, checks for `mount.cifs`, and tests generated rootfs scripts. |
| `crates/lsb-vm/src/sandbox.rs` | Updated | Minimal exhaustiveness handling for `MountRequest::Smb` so the workspace compiles; no SMB lifecycle/startup implementation. |
| `crates/lsb-proxy/src/config.rs` | Updated | Added `ProxyMode`, mount-only SMB config helpers, gateway/SMB constants, and policy tests. |
| `crates/lsb-proxy/src/dns.rs` | Updated | Mount-only SMB mode answers `host.lsb.internal` locally and refuses arbitrary DNS without host resolver forwarding. |
| `crates/lsb-proxy/src/proxy.rs` | Updated | Routes only guest `10.0.0.1:445` to host `127.0.0.1:445` in SMB modes and denies other mount-only TCP flows. |
| `crates/lsb-cli/src/vm.rs` | Updated | Detects Windows direct mounts and selects mount-only SMB proxy config when `allow_net` is false, or merges SMB relay into the normal proxy when `allow_net` is true; CLI `:ro` remains overlay. |
| `crates/lsb-sdk/src/runtime.rs` | Updated | Mirrors CLI proxy selection for SDK/Node callers without changing `SandboxConfig` or mount API shape. |
| `crates/lsb-platform/src/windows_x86_64/qemu/argv.rs` | Updated | Extended stream-network argv assertions to exclude `-nic`, QEMU user networking, `hostfwd`, TAP, bridge, and NAT tokens. |

## Cleanup/Redaction Audit

- [ ] Generated SMB passwords absent from CLI output.
- [ ] Generated SMB passwords absent from SDK/Node errors.
- [x] Generated SMB passwords absent from Rust `Debug`/`Display`.
- [ ] Generated SMB passwords absent from QEMU argv.
- [x] Generated SMB passwords absent from guest process argv.
- [x] Generated SMB passwords absent from guest environment except fd number.
- [ ] Generated SMB passwords absent from proxy diagnostics.
- [x] Generated SMB passwords absent from mount response errors.
- [ ] Generated SMB passwords absent from cleanup manifests.
- [x] Generated SMB passwords absent from test snapshots.
- [ ] Generated SMB passwords absent from logs.

## Smoke Test State

- Non-admin preflight failure:
- Admin rw direct mount guest-to-host write:
- Admin rw direct mount host-to-guest visibility:
- SDK/Node direct read-only write denial:
- CLI `:ro` overlay compatibility:
- Mount-only proxy no arbitrary outbound network:
- Cleanup leaves no LocalSandbox shares:
- Cleanup leaves no LocalSandbox users:
- Cleanup removes NTFS ACL grants:
- Failure injection cleanup:
- Artifact password scan:

## Notes

- Keep this file current during implementation.
- Link back to `PLAN.md` for design details.
- Record deviations from `PLAN.md` in "Follow-Up Decisions Needed" before
  implementing them.
