# Windows Validation Strategy

This document defines test and CI expectations for the Windows QEMU + WHPX
backend.

## Test tiers

| Tier | Runs on | Purpose | Examples |
|---|---|---|---|
| Unit | All supported dev platforms | Pure logic validation | argv builder, path normalization, redaction, config parsing |
| Compile | Hosted Windows/macOS/Linux | Prevent cfg and dependency regressions | `cargo check`, target-specific checks |
| Golden | Any platform when deterministic | Prevent accidental QEMU behavior changes | QEMU argv snapshots, diagnostics rendering |
| Fake process | Any platform or Windows | Process supervision without QEMU/WHPX | fake child process, timeout, cleanup behavior |
| Windows integration | Self-hosted Windows 11 x64 | Native APIs and QEMU process behavior | QEMU discovery, WHPX preflight, named pipes, Job Objects |
| WHPX smoke | Self-hosted Windows 11 x64 with virtualization | End-to-end runtime behavior | boot, ready, exec, copy, mount, forwarding, network, checkpoints |
| Security/conformance | Self-hosted Windows 11 x64 | Preserve product guarantees | no network default, proxy policy, path escape prevention |

## Hosted CI

Workflow: `.github/workflows/ci.yml`.

Hosted Windows jobs must not require WHPX, nested virtualization, boot assets,
or network QEMU artifact downloads. They are for compile/unit/golden coverage only and
use local archive fixtures for managed-QEMU installer tests.

Expected hosted coverage:

- `cargo check --workspace --locked --target x86_64-pc-windows-msvc`
- focused `lsb-platform` QEMU argv/preflight tests
- managed-QEMU metadata, safe extraction, hash validation, idempotency, and
  discovery precedence tests
- `cargo test --workspace --locked`
- diagnostic collector probes for hosted artifact staging

macOS and Linux hosted jobs preserve existing behavior and run platform-neutral
checks such as formatting, workspace checks, and unit tests.

## Self-hosted WHPX workflow

Workflow: `.github/workflows/windows-lsb-hardware.yml`

Display name: `Windows LSB Hardware (self-hosted WHPX)`

Trigger: automatic `main` branch pushes for the e2e lane, plus manual
`workflow_dispatch` for `check`, `unit`, `smoke`, and `e2e`.

Runner labels:

```yaml
runs-on: [self-hosted, Windows, X64]
```

Do not add automatic `pull_request` triggers for this workflow.

Use the helper from macOS/Linux for manual branch runs:

```bash
./scripts/win-gh-test check
./scripts/win-gh-test unit
./scripts/win-gh-test smoke
./scripts/win-gh-test e2e
```

The helper requires GitHub CLI, an authenticated GitHub session, and a clean
committed working tree. It pushes the current branch, dispatches the workflow,
watches the run, and prints failed logs when available.

## Hardware lane behavior

- `check`: runs native Windows `cargo check --workspace --locked`.
- `unit`: runs native Windows `cargo test --workspace --locked`.
- `smoke`: installs managed QEMU with `lsb init --host-tools-only --force`,
  then runs `scripts/windows-smoke.ps1`.
- `e2e`: installs managed QEMU with `lsb init --host-tools-only --force`,
  then runs `scripts/windows-e2e.ps1`; the e2e script also initializes host
  tools inside its isolated `LOCALAPPDATA`.

The `smoke` and `e2e` lanes use a persistent boot asset cache under
`C:\lsb-assets\by-key\<asset-key>\`. QEMU boots only a disposable per-run copy
under `C:\lsb-assets\work\<run-id>-<attempt>\`.

For normal Windows development, use `lsb init` to install managed QEMU host
tools and released runtime assets. Building `windows-x86_64` runtime assets with
`prepare-rootfs` is an advanced Docker/Linux-hosted path; it is not the
recommended local Windows workflow.

If the local Windows cache is missing, the workflow prepares `windows-x86_64`
boot assets on a hosted Linux job, uploads them as a same-run artifact, hydrates
the Windows cache, then creates the disposable rootfs copy.

The current default-label setup assumes the labels resolve to exactly one
persistent WHPX runner. Before adding another Windows self-hosted runner with
the same labels, either add a dedicated label such as `whpx`/`local-sandbox` or
disable the local-cache skip path.

`scripts/windows-e2e.ps1` stages workflow-provisioned boot assets into an
isolated temporary runtime data directory and runs the real `lsb run` CLI path
through a user-facing workflow.

## Smoke coverage

`scripts/windows-smoke.ps1` currently verifies:

- CLI starts.
- Managed QEMU installs and reports `current.json` paths.
- Real QEMU/WHPX preflight.
- Windows Node source build/import smoke.
- Packed root npm package plus `@local-sandbox/lsb-nodejs-win32-x64-msvc`
  install/import smoke.
- `windows_qemu_boot_smoke`.
- `windows_qemu_exec_smoke`.
- `windows_qemu_copy_transfer_smoke`.
- `windows_qemu_mount_smoke`.
- `windows_qemu_port_forward_smoke`.
- `windows_qemu_checkpoint_store_smoke`.
- `windows_qemu_network_policy_proxy_smoke`.

Smoke tests require these environment variables, normally written by
`scripts/prepare-windows-boot-assets.ps1`:

```powershell
$env:LSB_WINDOWS_BOOT_KERNEL="C:\path\to\Image"
$env:LSB_WINDOWS_BOOT_INITRD="C:\path\to\initramfs.cpio.gz"
$env:LSB_WINDOWS_BOOT_ROOTFS="C:\path\to\disposable\rootfs.ext4"
$env:LSB_WINDOWS_BOOT_ARTIFACT_DIR="C:\path\to\diagnostics"
$env:LSB_WINDOWS_GUEST_READY_SECS="30" # optional readiness timeout override
```

If the asset variables are absent, smoke lanes must print an explicit skip
message and must not claim direct boot validation.

## E2E coverage

`scripts/windows-e2e.ps1` currently verifies:

- boot, guest command execution, stdout capture, and guest kernel visibility;
- default no-network denial;
- mounted project reads with isolated guest writes;
- host-to-guest loopback port forwarding without `--allow-net`;
- scoped `--allow-net` access to a host fixture through `host.lsb.internal`;
- checkpoint create, list, resume isolation, branch, and delete.

## Direct ignored-test commands

Use these only on a Windows 11 x64 host with managed QEMU/WHPX and disposable
boot assets:

```powershell
cargo run -p lsb-cli -- init --host-tools-only --force
$env:LSB_TEST_REAL_QEMU="1"
cargo test -p lsb-platform real_qemu_preflight_when_explicitly_enabled -- --ignored --nocapture

cargo test -p lsb-platform windows_qemu_boot_smoke -- --ignored --nocapture
cargo test -p lsb-vm windows_qemu_exec_smoke -- --ignored --nocapture
cargo test -p lsb-vm windows_qemu_copy_transfer_smoke -- --ignored --nocapture
cargo test -p lsb-vm windows_qemu_mount_smoke -- --ignored --nocapture
cargo test -p lsb-vm windows_qemu_port_forward_smoke -- --ignored --nocapture
cargo test -p lsb-sdk windows_qemu_checkpoint_store_smoke -- --ignored --nocapture
cargo test -p lsb-sdk windows_qemu_network_policy_proxy_smoke -- --ignored --nocapture
```

For manual local reproduction outside GitHub Actions, prepare assets from a
trusted artifact manifest, keep the pristine cache copy out of QEMU, point
`LSB_WINDOWS_BOOT_ROOTFS` at a disposable copy, and set
`LSB_WINDOWS_BOOT_ARTIFACT_DIR` to the diagnostics directory for that one run.

## Artifact capture

For failed integration tests, capture:

- redacted QEMU argv,
- QEMU stdout/stderr,
- serial console log,
- boot/preflight/status JSON,
- LocalSandbox host logs,
- relevant control/forwarding/proxy/checkpoint logs when redacted,
- allowlisted environment/tool summary,
- diagnostic manifest showing collected and skipped files,
- test name and temp directory,
- QEMU version/path,
- Windows version/build where available.

Never capture secret values, raw environment dumps, boot assets, rootfs images,
qcow2 disks, npm caches, private keys, or unredacted QEMU argv.

## Current validation gap

The last full self-hosted WHPX smoke pass recorded in the MVP handoff happened
before later diagnostics scoping follow-up commits. Rerun
`./scripts/win-gh-test smoke` at final branch head before treating the evidence
as current for upstream review.
