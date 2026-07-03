# Self-Hosted Windows 11 Runner Setup Notes

This document describes the maintainer-owned Windows 11 WHPX runner used by `.github/workflows/windows-lsb-hardware.yml`. The workflow is intentionally manual-only through `workflow_dispatch` so untrusted pull request code does not run automatically on self-hosted hardware.

## Runner labels

The repository workflow currently targets the default self-hosted Windows labels:

```text
self-hosted, Windows, X64
```

Update `.github/workflows/windows-lsb-hardware.yml` and `validation.md` together if the runner is later moved to custom labels such as `whpx` or `local-sandbox`.

## Runner requirements

- Windows 11 x86_64 host.
- Hardware virtualization enabled in firmware.
- Windows Hypervisor Platform enabled.
- Hyper-V compatible configuration sufficient for QEMU WHPX.
- QEMU installed and discoverable by either `LSB_QEMU` or `PATH`.
- Rust toolchain matching repository expectations.
- Node toolchain for M14 and later.
- Git configured for long paths if the repository needs it.
- LocalSandbox guest assets available or buildable by CI.
- GitHub Actions runner service registered to the target repository or organization with the labels above.

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

- `scripts/windows-smoke.ps1`: current smoke entrypoint; today it verifies the CLI starts with `cargo run -p lsb-cli -- --help` and is the place to add VM boot smoke commands once the backend can boot.
- `scripts/windows-e2e.ps1`: current e2e entrypoint; today it runs `cargo test --workspace --locked` and is the place to expand the full hardware integration suite.

## CI safety

- Do not run untrusted pull request code on the self-hosted runner unless repository policy allows it.
- Prefer maintainer-triggered integration jobs for branches under review.
- Do not add automatic `pull_request` triggers to `.github/workflows/windows-lsb-hardware.yml`.
- Upload redacted artifacts only.
- Periodically clean LocalSandbox debug/temp directories.
- Ensure QEMU processes are not left running after failed jobs.

## Artifact retention

For failed WHPX jobs, retain:

- redacted QEMU argv,
- serial log,
- QEMU stderr/stdout,
- preflight output,
- host LocalSandbox logs,
- test report.

Do not retain secret-bearing env dumps or unredacted proxy logs.
