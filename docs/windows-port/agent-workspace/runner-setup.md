# Self-Hosted Windows 11 Runner Setup Notes

This document describes the maintainer-owned Windows 11 WHPX runner used by `.github/workflows/windows-lsb-hardware.yml`. The workflow display name is `Windows LSB Hardware (self-hosted WHPX)`. It is intentionally manual-only through `workflow_dispatch` so untrusted pull request code does not run automatically on self-hosted hardware.

## Runner labels

The repository workflow currently targets the default self-hosted Windows labels:

```text
self-hosted, Windows, X64
```

Update `.github/workflows/windows-lsb-hardware.yml` and `validation.md`
together if the runner is later moved to custom labels such as `whpx` or
`local-sandbox`. The smoke/e2e boot asset cache optimization assumes these
labels resolve to exactly one persistent runner. If more Windows runners are
added, give this machine a dedicated label or remove the local-cache skip path;
otherwise the probe job can hit one machine's `C:\lsb-assets` cache while the
final smoke/e2e job lands on another machine.

Each self-hosted job also checks `RUNNER_ENVIRONMENT`, `RUNNER_OS`, and
`RUNNER_ARCH` before running repository commands. This is a guardrail against
accidental workflow edits; the `runs-on` labels remain the primary routing
control.

## Runner requirements

- Windows 11 x86_64 host.
- Hardware virtualization enabled in firmware.
- Windows Hypervisor Platform enabled.
- Hyper-V compatible configuration sufficient for QEMU WHPX.
- QEMU installed and discoverable by either `LSB_QEMU` or `PATH`.
- Rust toolchain matching repository expectations.
- Node toolchain for M14 and later.
- Git configured for long paths if the repository needs it.
- `C:\lsb-assets` writable by the runner account for the persistent boot asset cache.
- GitHub Actions runner service registered to the target repository or organization with the labels above.
- `C:\actions-runner\_diag` readable by the runner account if maintainer wants redacted runner logs included in failed-job artifacts.

## Suggested environment variables

```powershell
$env:LSB_QEMU="C:\Program Files\qemu\qemu-system-x86_64.exe"
$env:LSB_WINDOWS_INTEGRATION="1"
```

Do not store secrets in runner-level environment variables unless the CI job explicitly requires them and masks them.

## Preflight checklist

Record output in a secure maintainer note or CI artifact after M02 exists.

```powershell
systeminfo
where qemu-system-x86_64
qemu-system-x86_64 --version
cargo --version
rustc --version
node --version
npm --version
```

After M02:

```powershell
lsb doctor windows
```

## Workflow trigger

The hardware workflow accepts one required `test_set` input:

- `check`: runs `cargo check --workspace --locked`.
- `unit`: runs `cargo test --workspace --locked`.
- `smoke`: runs `scripts/windows-smoke.ps1`.
- `e2e`: runs `scripts/windows-e2e.ps1`.

The `check` and `unit` lanes run only on the self-hosted Windows runner and do
not prepare boot assets. The `smoke` and `e2e` lanes first run a lightweight
Windows cache probe. The probe computes the `windows-x86_64` boot asset key with
`cargo run --quiet -p xtask -- boot-asset-key --platform windows-x86_64`, then
validates `C:\lsb-assets\by-key\<asset-key>\asset-manifest.json` and the cached
`Image`, `initramfs.cpio.gz`, and `rootfs.ext4`.

On a Windows cache hit, the GitHub-hosted Linux preparation job is skipped. The
final Windows smoke/e2e job reuses the pristine cached assets, copies only
`rootfs.ext4` to the per-run disposable path under
`C:\lsb-assets\work\<run-id>-<attempt>\`, and writes the boot asset environment
variables consumed by the test.

On a Windows cache miss, the workflow runs the GitHub-hosted Linux
`prepare-boot-assets` job. That job prepares the `windows-x86_64` LocalSandbox
boot assets with `LSB_FORCE_DOCKER_ROOTFS=1`, uses the same exact boot asset key
for the GitHub cache, and uploads `Image`, `initramfs.cpio.gz`, `rootfs.ext4`,
and `asset-manifest.json` as a short-lived same-run artifact. The final Windows
job downloads that artifact, verifies the manifest, hydrates
`C:\lsb-assets\by-key\<asset-key>\`, creates the disposable `rootfs.ext4` copy,
and then runs the requested smoke/e2e suite. The GitHub cache intentionally has
no broad restore keys.

Coding agents on macOS should trigger the workflow through the repository helper:

```bash
./scripts/win-gh-test check
./scripts/win-gh-test unit
./scripts/win-gh-test smoke
./scripts/win-gh-test e2e
```

The helper requires GitHub CLI (`gh`), an authenticated GitHub session, and a clean committed working tree. It pushes the current branch to `origin`, dispatches `windows-lsb-hardware.yml`, watches the run, and prints failed logs when available. Use a WIP commit before invoking it.

## Windows script entrypoints

The workflow delegates long-running Windows hardware suites to PowerShell scripts in `scripts/`:

- `scripts/prepare-windows-boot-assets.ps1`: validates either a downloaded boot asset artifact or a local `C:\lsb-assets\by-key\<asset-key>\` cache entry, maintains the persistent cache, creates the disposable rootfs work copy, and exports `LSB_WINDOWS_BOOT_KERNEL`, `LSB_WINDOWS_BOOT_INITRD`, `LSB_WINDOWS_BOOT_ROOTFS`, and `LSB_WINDOWS_BOOT_ARTIFACT_DIR` through `GITHUB_ENV`.
- `scripts/windows-smoke.ps1`: current smoke entrypoint; it verifies the CLI starts, runs real QEMU/WHPX preflight, builds and imports the Windows Node package from both source and packed npm tarballs, and then runs the boot, guest-ready, exec, copy, mount, port-forward, checkpoint/store, and network policy/proxy smokes when the workflow-provisioned boot asset variables are present.
- `scripts/windows-e2e.ps1`: current e2e entrypoint; today it runs `cargo test --workspace --locked` with explicit native-command exit-code checking and is the place to expand the full hardware integration suite.
- `scripts/collect-windows-diagnostics.ps1`: deletes and recreates `target\windows-lsb-diagnostics`, then stages a redacted diagnostic bundle for upload. It copies boot diagnostics only from `LSB_WINDOWS_BOOT_ARTIFACT_DIR` or the current GitHub run/attempt work directory. Run with `-IncludeRunnerLogs` only when `LSB_DIAGNOSTICS_RUN_STARTED_UTC` or `-RunnerDiagSinceUtc` bounds runner `_diag` log collection; runner logs are filtered to timestamped lines inside that window.

## CI safety

- Do not run untrusted pull request code on the self-hosted runner unless repository policy allows it.
- Prefer maintainer-triggered integration jobs for branches under review.
- Do not add automatic `pull_request` triggers to `.github/workflows/windows-lsb-hardware.yml`.
- Upload redacted artifacts only.
- Periodically clean LocalSandbox debug/temp directories and stale `C:\lsb-assets\work\*` directories. Keep `C:\lsb-assets\by-key\*` entries that are still useful for exact-key smoke/e2e runs.
- The current key namespace is `boot-assets-v2-windows-x86_64-*`. Old `boot-assets-v1-*` entries may be removed after at least one successful v2 smoke/e2e miss path warms the cache.
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

Do not retain secret-bearing env dumps or unredacted proxy logs.

Boot asset artifacts are retained only briefly because the exact GitHub cache and
the Windows persistent cache provide reuse. The cached `rootfs.ext4` under
`C:\lsb-assets\by-key\<asset-key>\` must remain pristine; QEMU must boot only
the disposable per-run copy.
