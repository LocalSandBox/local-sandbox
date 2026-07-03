# Validation Strategy

This document defines the test and CI expectations for the Windows QEMU + WHPX port.

## Test tiers

| Tier | Runs on | Purpose | Examples |
|---|---|---|---|
| Unit | All supported dev platforms | Pure logic validation | argv builder, path normalization, redaction, config parsing |
| Compile | GitHub-hosted Windows/macOS/Linux as available | Prevent cfg and dependency regressions | `cargo check`, feature-specific compile checks |
| Golden | Any platform, if code is platform-independent | Deterministic output | QEMU argv snapshots, diagnostics messages |
| Fake process | Any platform or Windows | Process supervision logic without QEMU | fake child process, timeout, cleanup behavior |
| Windows integration | Windows 11 x86_64 self-hosted | Native APIs and QEMU process behavior | QEMU discovery, WHPX preflight, named pipes, Job Objects |
| WHPX boot smoke | Windows 11 x86_64 self-hosted with virtualization | End-to-end VM boot | direct Linux boot, serial logs, ready handshake |
| Security/conformance | Windows 11 x86_64 self-hosted | Preserve product guarantees | no network default, control pipe private, path escape prevention |

## Minimal CI matrix

### Hosted runners

- `windows-latest`: compile, unit, golden tests that do not require WHPX.
- `macos-latest`: ensure existing macOS behavior remains intact.
- Optional `ubuntu-latest`: protocol/store/proxy logic where platform-independent.

### Self-hosted runner

The manual hardware workflow uses the default self-hosted Windows labels:

```yaml
runs-on: [self-hosted, Windows, X64]
```

Required runner properties:

- Windows 11 x86_64.
- Hyper-V / Windows Hypervisor Platform enabled.
- QEMU installed and discoverable or configured via `LSB_QEMU`.
- LocalSandbox guest assets available or built during job.
- Non-admin execution path preferred for MVP tests.

Hardware workflow:

- Workflow: `.github/workflows/windows-lsb-hardware.yml`
- Trigger: manual `workflow_dispatch` only.
- macOS/Linux helper: `./scripts/win-gh-test check|unit|smoke|e2e`
- Do not add automatic `pull_request` triggers for the self-hosted Windows hardware runner.

## Milestone validation gates

| Milestone | Required validation |
|---|---|
| M01 | `cargo check` reaches Windows stubs without non-macOS compile failure. Existing macOS checks unaffected. |
| M02 | QEMU discovery unit tests; Windows preflight diagnostic tests; manual/self-hosted preflight evidence. |
| M03 | Golden argv tests for minimal boot, serial logs, virtio-serial, QMP, no-network default. |
| M04 | Fake process and Windows Job Object cleanup tests where possible. |
| M05 | WHPX boot smoke: QEMU starts, serial logs captured, kernel/initramfs reaches guest agent or clear failure point. |
| M06 | Host can open virtio-serial transport; guest accepts framed protocol connection. |
| M07 | Ready handshake succeeds and times out cleanly on failure. |
| M08 | `exec` command returns stdout/stderr/exit status; kill/timeout behavior tested. |
| M09 | Copy-in/copy-out tests for files, dirs, empty dirs, large files, path traversal rejection. |
| M10 | Mount MVP conformance tests for read-only source semantics and isolated writes. |
| M11 | Host-to-guest port forwarding works without guest NIC. |
| M12 | No-network default test; allowed-domain test; blocked-domain/direct-IP test; secret substitution redaction test. |
| M13 | Checkpoint create/list/restore/delete tests for Windows MVP path. |
| M14 | Node package install/import smoke on Windows after Rust backend works. |
| M15 | CI jobs split correctly and diagnostics artifacts uploaded. |

## Artifact capture

For failed integration tests, capture:

- redacted QEMU argv,
- QEMU stdout/stderr,
- serial console log,
- LocalSandbox host logs,
- guest readiness/control handshake logs,
- relevant Windows preflight output,
- test name and seed/temp directory,
- QEMU version and path,
- Windows build/version from runner.

Never capture secret values or unredacted environment dumps.

## Manual validation commands

Use the manual GitHub workflow for tests that require self-hosted Windows hardware:

```bash
./scripts/win-gh-test check
./scripts/win-gh-test unit
./scripts/win-gh-test smoke
./scripts/win-gh-test e2e
```

The helper requires a clean committed working tree because GitHub Actions can only test pushed commits.

Windows-side commands should be filled in by milestones as code lands. Initial placeholders:

```powershell
# Check QEMU discovery once an lsb doctor command exists
lsb doctor windows

# M02 real-QEMU preflight hook; requires Windows 11 x86_64, QEMU, and explicit opt-in
$env:LSB_QEMU="C:\Program Files\qemu\qemu-system-x86_64.exe"
$env:LSB_TEST_REAL_QEMU="1"
cargo test -p lsb-platform real_qemu_preflight_when_explicitly_enabled -- --ignored --nocapture

# Run boot smoke once M05 exists
cargo test -p lsb-platform windows_qemu_boot_smoke -- --ignored --nocapture

# Run all Windows integration tests once M15 exists
cargo test --workspace --features windows-integration -- --ignored --nocapture
```
