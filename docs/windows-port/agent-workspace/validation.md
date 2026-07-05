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

- Workflow: `.github/workflows/ci.yml`.
- `ubuntu-24.04`: `cargo fmt --all -- --check`.
- `windows-latest`: `cargo check --workspace --locked --target x86_64-pc-windows-msvc`, focused `lsb-platform` QEMU argv/preflight tests, and `cargo test --workspace --locked`. These tests must not set `LSB_TEST_REAL_QEMU`, must not require QEMU, and must not require WHPX/nested virtualization.
- `macos-14`: existing macOS Rust check lanes remain in place to preserve current macOS behavior.
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
- `C:\lsb-assets` writable by the runner account for the persistent boot asset cache.
- The smoke/e2e cache optimization assumes the workflow labels resolve to one persistent Windows runner. If multiple runners share these labels, use a dedicated label for this runner or disable the local-cache skip path.
- Non-admin execution path preferred for MVP tests.

Hardware workflow:

- Workflow: `.github/workflows/windows-lsb-hardware.yml`
- Display name: `Windows LSB Hardware (self-hosted WHPX)`.
- Trigger: manual `workflow_dispatch` only.
- macOS/Linux helper: `./scripts/win-gh-test check|unit|smoke|e2e`
- Do not add automatic `pull_request` triggers for the self-hosted Windows hardware runner.
- `check` and `unit` run on the self-hosted Windows runner without boot asset preparation.
- `smoke` and `e2e` first run a Windows cache probe. On a valid
  `C:\lsb-assets\by-key\<asset-key>\` hit, the GitHub-hosted Linux
  `prepare-boot-assets` job and full artifact download are skipped.
- On a Windows cache miss, the Linux job prepares `windows-x86_64` boot assets
  with `LSB_FORCE_DOCKER_ROOTFS=1`, uses the exact source-derived boot asset key
  as the GitHub cache key with no broad restore keys, and uploads `Image`,
  `initramfs.cpio.gz`, `rootfs.ext4`, and `asset-manifest.json` as a same-run
  artifact.
- The final Windows smoke/e2e job either prepares from the validated local
  cache or downloads the artifact on miss. QEMU boots only a disposable per-run
  copy of `rootfs.ext4` from `C:\lsb-assets\work\<run-id>-<attempt>\`.

## Milestone validation gates

| Milestone | Required validation |
|---|---|
| M01 | `cargo check` reaches Windows stubs without non-macOS compile failure. Existing macOS checks unaffected. |
| M02 | QEMU discovery unit tests; Windows preflight diagnostic tests; manual/self-hosted preflight evidence. |
| M03 | Golden argv tests for minimal boot, serial logs, virtio-serial, QMP, no-network default. |
| M04 | Fake process and Windows Job Object cleanup tests where possible. |
| M05 | WHPX boot smoke: QEMU starts with provisioned boot assets, serial/QEMU artifact files are captured, and QEMU stays alive through the M05 observation window with non-empty serial evidence such as kernel, `/init`, rootfs mount, or `lsb-guest` startup lines. Empty serial output must fail with actionable serial/stderr artifacts. The guest-ready handshake remains M06/M07 work. |
| M06 | Host can open virtio-serial transport; guest selects virtio-serial and opens the configured control port. |
| M07 | LocalSandbox `GuestReady` frame is received over the established virtio-serial control stream before VM startup succeeds; fake/unit tests cover timeout, invalid frame, protocol-version mismatch, unsupported capabilities, and early QEMU exit without requiring real QEMU. |
| M08 | Non-interactive `exec` command returns stdout/stderr/exit status over the existing LocalSandbox protocol; Windows streaming `spawn`/kill returns an explicit unsupported error until muxing exists. |
| M09 | Copy-in/copy-out tests for files, dirs, empty dirs, large files, path traversal rejection. |
| M10 | Mount MVP conformance tests for read-only source semantics and isolated writes. |
| M11 | Host-to-guest port forwarding works without guest NIC or QEMU `hostfwd`; host listeners bind loopback, invalid/duplicate ports fail clearly, Windows argv remains `-nic none`, and the WHPX smoke reaches a guest-local TCP service through host `127.0.0.1`. |
| M12 | No-network default test; policy-mediated proxy argv test; allowed-domain test; blocked-domain/direct-IP test; unsupported attachment rejection; secret placeholder/redaction test; WHPX network policy/proxy smoke. |
| M13 | Checkpoint create/list/restore/delete tests for Windows MVP path; ignored WHPX smoke verifies mutate, checkpoint, restore, fresh-base isolation, delete, and failed restore after delete. |
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
- allowlisted environment/tool summary,
- diagnostic manifest showing collected and skipped files,
- test name and seed/temp directory,
- QEMU version and path,
- Windows build/version from runner.

Never capture secret values or unredacted environment dumps.

M15 adds `scripts/collect-windows-diagnostics.ps1` as the common collector for
hosted and self-hosted Windows CI. It stages artifacts under:

```text
target\windows-lsb-diagnostics\
  environment.summary.json
  diagnostics-manifest.json
  explicit-boot-artifact-dir\
  lsb-assets-work\<run-id>-<attempt>\
  actions-runner\                  # self-hosted workflow only
  workspace-target-logs\
  cargo-target-logs\
```

The collector copies only allowlisted text-like diagnostic files (`.json`,
`.log`, `.redacted`, `.txt`) and redacts known secret environment values plus
common token/private-key patterns before upload. Environment capture is
allowlisted; it is not a raw environment dump.

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

# Run guest exec smoke once M08 exists
cargo test -p lsb-vm windows_qemu_exec_smoke -- --ignored --nocapture

# Run host-to-guest port-forward smoke once M11 exists
cargo test -p lsb-vm windows_qemu_port_forward_smoke -- --ignored --nocapture

# Run network policy/proxy smoke once M12 exists
cargo test -p lsb-sdk windows_qemu_network_policy_proxy_smoke -- --ignored --nocapture

# Run checkpoint/store smoke once M13 exists
cargo test -p lsb-sdk windows_qemu_checkpoint_store_smoke -- --ignored --nocapture

# Run all Windows integration tests once M15 exists
cargo test --workspace --features windows-integration -- --ignored --nocapture
```

M05 boot smoke requires disposable boot assets. In the hardware workflow,
`scripts/prepare-windows-boot-assets.ps1` sets these variables before
`scripts/windows-smoke.ps1` runs:

```powershell
$env:LSB_WINDOWS_BOOT_KERNEL="C:\path\to\Image"
$env:LSB_WINDOWS_BOOT_INITRD="C:\path\to\initramfs.cpio.gz"
$env:LSB_WINDOWS_BOOT_ROOTFS="C:\path\to\disposable\rootfs.ext4"
$env:LSB_WINDOWS_BOOT_ARTIFACT_DIR="C:\path\to\diagnostics" # optional
$env:LSB_WINDOWS_GUEST_READY_SECS="30" # optional M07 readiness timeout override
```

M08 exec smoke uses the same asset variables and should be run after the boot
smoke on a Windows 11 x86_64 WHPX runner:

```powershell
cargo test -p lsb-platform windows_qemu_boot_smoke -- --ignored --nocapture
cargo test -p lsb-vm windows_qemu_exec_smoke -- --ignored --nocapture
```

M11 port-forward smoke uses the same asset variables and should be run after
the exec/copy/mount smokes on a Windows 11 x86_64 WHPX runner:

```powershell
cargo test -p lsb-vm windows_qemu_port_forward_smoke -- --ignored --nocapture
```

If the full `./scripts/win-gh-test smoke` lane stalls or is cancelled in an
earlier smoke such as `windows_qemu_exec_smoke`, do not treat that run as M11
runtime evidence. Use the direct ignored test above with the same disposable
asset variables to get a focused port-forward result, then record the run ID and
diagnostics path in `state.md`.

The M11 smoke starts a simple guest-local TCP service through the existing exec
path, forwards a host `127.0.0.1:<host_port>` listener to that guest port over
the LocalSandbox forwarding channel, verifies response bytes from the Windows
host, drops the forwarding handle, and verifies the host listener closes. It
does not validate general Windows networking or any arbitrary guest outbound
access.

The M12 smoke uses the same asset variables after the boot/exec/copy/mount and
port-forward smokes. It starts a sandbox with existing allow-net configuration,
attaches the Windows guest NIC only to the LocalSandbox proxy stream path,
verifies an allowed HTTP destination succeeds, verifies direct-IP and
non-allowlisted destinations fail closed, verifies forged allowed Host/SNI
traffic to arbitrary IPs fails closed, checks the guest receives a secret
placeholder instead of the literal host secret, scans diagnostics for the
sentinel host secret, and inspects the redacted argv for `-netdev stream` with
no QEMU user networking, `hostfwd`, TAP, bridge, or secret material.

If the asset variables are absent, the smoke lane must print an explicit skip
message and must not claim direct boot validation.

For manual Windows-side reproduction outside GitHub Actions, prepare equivalent
assets from a trusted artifact manifest first, keep the pristine cache copy out
of QEMU, and point `LSB_WINDOWS_BOOT_ROOTFS` at a disposable copy.

The hardware workflow stages external diagnostics into the checkout before
uploading them:

```text
target\windows-lsb-diagnostics\lsb-assets-work\<run-id>-<attempt>\
```

The source diagnostics remain under
`C:\lsb-assets\work\<run-id>-<attempt>\diagnostics` on the runner while the job
is active.

The smoke lane also runs a packed Node package install/import smoke after the
local Windows N-API build. It packs the root package plus
`@local-sandbox/lsb-nodejs-win32-x64-msvc`, installs both tarballs into a
temporary project, and imports `@local-sandbox/lsb-nodejs` to verify
`Sandbox.start` is exported before the runtime boot smoke starts.
