# Self-Hosted Windows 11 Runner Setup

This document describes the maintainer-owned Windows 11 WHPX runner used by
`.github/workflows/windows-lsb-hardware.yml`. The workflow display name is
`Windows LSB Hardware (self-hosted WHPX)`. It runs the e2e lane automatically
for trusted `main` branch pushes and still supports maintainer-triggered
`workflow_dispatch` lanes. It must not run on pull requests because untrusted
pull request code must not run automatically on self-hosted hardware.

## Runner labels

The workflow currently targets default self-hosted Windows labels:

```text
self-hosted, Windows, X64
```

The smoke/e2e boot asset cache assumes these labels resolve to exactly one
persistent runner. If more Windows runners are added, give this machine a
dedicated label such as `whpx` or `local-sandbox`, or remove the local-cache
skip path.

Each self-hosted job checks `RUNNER_ENVIRONMENT`, `RUNNER_OS`, and
`RUNNER_ARCH` before running repository commands. The `runs-on` labels remain
the primary routing control.

## Requirements

- Windows 11 x86_64 host.
- Hardware virtualization enabled in firmware.
- Windows Hypervisor Platform enabled.
- Hyper-V compatible configuration sufficient for QEMU WHPX.
- Network access to the pinned managed QEMU release artifact, or a prewarmed
  `%LOCALAPPDATA%\lsb\tools\qemu` cache for the runner account.
- Rust toolchain matching repository expectations.
- Node toolchain for binding smoke coverage.
- Git configured for long paths if needed.
- `C:\lsb-assets` writable by the runner account for the persistent boot asset cache.
- GitHub Actions runner service registered to the target repository or organization.
- `C:\actions-runner\_diag` readable by the runner account if redacted runner
  logs should be included in failed-job artifacts.

## Suggested environment

```powershell
$env:LSB_WINDOWS_INTEGRATION="1"
```

Do not store secrets in runner-level environment variables unless a CI job
explicitly requires them and masks them.

## Preflight checklist

Record output in a secure maintainer note or CI artifact:

```powershell
systeminfo
cargo run -p lsb-cli -- init --host-tools-only --force
Get-Content "$env:LOCALAPPDATA\lsb\tools\qemu\current.json"
cargo --version
rustc --version
node --version
npm --version
```

## Workflow trigger

The hardware workflow runs automatically on every `main` branch push and treats
that event as `test_set=e2e`. It also accepts one required `test_set` input for
manual `workflow_dispatch` runs:

- `check`: runs `cargo check --workspace --locked`.
- `unit`: runs `cargo test --workspace --locked`.
- `smoke`: runs `scripts/windows-smoke.ps1`.
- `e2e`: runs `scripts/windows-e2e.ps1`.

The `check` and `unit` lanes run only on the self-hosted Windows runner and do
not prepare boot assets.

For local runner maintenance and manual Windows development, prefer released
runtime assets from `lsb init`. Building runtime assets with `prepare-rootfs` is
kept as an advanced hosted-Linux/Docker path because creating the rootfs,
kernel, and initramfs directly on Windows is complicated.

The `smoke` and `e2e` lanes first probe the local Windows boot asset cache. On
cache hit, they reuse pristine cached assets and boot only a disposable rootfs
copy. On cache miss, a hosted Linux job prepares `windows-x86_64` assets, uploads
them as a same-run artifact, and the Windows job hydrates the local cache before
running.

Coding agents on macOS should trigger manual hardware runs through:

```bash
./scripts/win-gh-test check
./scripts/win-gh-test unit
./scripts/win-gh-test smoke
./scripts/win-gh-test e2e
```

The helper requires GitHub CLI, an authenticated session, and a clean committed
working tree. Use a WIP commit before invoking it. Automatic `main` push e2e
runs do not use the helper.

## Windows script entrypoints

- `scripts/prepare-windows-boot-assets.ps1`: validates downloaded or cached boot
  assets, maintains `C:\lsb-assets\by-key`, creates disposable rootfs work
  copies, and exports `LSB_WINDOWS_BOOT_KERNEL`,
  `LSB_WINDOWS_BOOT_INITRD`, `LSB_WINDOWS_BOOT_ROOTFS`, and
  `LSB_WINDOWS_BOOT_ARTIFACT_DIR` through `GITHUB_ENV`.
- `scripts/windows-smoke.ps1`: verifies CLI startup, managed QEMU/WHPX preflight,
  repairs the local SMB user-rights policy with
  `lsb doctor windows-smb-policy --fix --yes` when boot assets are present,
  then runs Windows Node source and packed-package smoke, CLI `:ro` overlay
  behavior, and boot/ready/exec/copy/mount/direct-SMB/port-forward/checkpoint/
  network smokes.
- `scripts/windows-e2e.ps1`: current e2e entrypoint; it stages
  workflow-provisioned boot assets into an isolated temporary runtime directory
  and runs a user-facing CLI workflow covering boot/exec, default no-network
  denial, project mount read plus isolated guest writes, host-to-guest port
  forwarding without `--allow-net`, scoped `--allow-net` access to a host
  fixture through `host.lsb.internal`, and checkpoint create/resume/branch/
  delete.
- `scripts/collect-windows-diagnostics.ps1`: stages a redacted diagnostic
  bundle and optional timestamp-bounded runner logs.

## CI safety

- Do not run untrusted pull request code on the self-hosted runner unless
  repository policy explicitly allows it.
- Do not add automatic `pull_request` triggers to
  `.github/workflows/windows-lsb-hardware.yml`.
- Upload redacted artifacts only.
- Periodically clean LocalSandbox debug/temp directories and stale
  `C:\lsb-assets\work\*` directories.
- Keep `C:\lsb-assets\by-key\*` entries that are useful for exact-key smoke/e2e
  runs.
- Ensure QEMU processes are not left running after failed jobs.

## Artifact retention

For failed WHPX jobs, retain:

- redacted QEMU argv,
- serial log,
- QEMU stderr/stdout,
- preflight output,
- host LocalSandbox logs,
- allowlisted environment/tool summary,
- diagnostics manifest,
- test report.

Do not retain secret-bearing env dumps, unredacted proxy logs, boot assets,
rootfs images, or qcow2 disks.
