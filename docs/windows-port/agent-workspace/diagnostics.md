# Windows Port Diagnostics Guide

Use this guide to keep errors actionable and repeatable.

## General diagnostic principles

- Prefer structured errors over raw strings.
- Include remediation steps in user-facing diagnostics.
- Always capture redacted QEMU argv for QEMU start/boot failures.
- Always capture serial logs for boot/guest-agent failures.
- Never log secrets, proxy substitution values, or full unredacted environment.
- Preserve temporary artifacts when a debug flag is set.

## Failure matrix

| Symptom | Likely causes | Evidence to capture | Recommended checks |
|---|---|---|---|
| QEMU not found | Not installed, not on PATH, `LSB_QEMU` wrong, unsupported arch binary | configured path, PATH lookup summary, error kind | `where qemu-system-x86_64`, `qemu-system-x86_64 --version` |
| WHPX unavailable | Windows feature disabled, virtualization disabled in firmware, running inside unsupported nested VM, non-Windows-11 host | preflight result, QEMU stderr, Windows version | `optionalfeatures.exe`, Windows Features, BIOS virtualization, runner labels |
| QEMU starts then exits | bad argv, missing assets, unsupported device, invalid path quoting | redacted argv, stderr, exit code | run redacted argv manually from temp dir |
| Kernel does not boot | wrong kernel arch, missing `console`, WHPX/device issue, bad initrd | serial log, QEMU stderr, asset hashes | minimal boot command from Appendix A of RFC |
| Rootfs not mounted | wrong virtio-blk device, missing ext4 support, wrong root arg, corrupted disk | serial log, guest panic/initramfs output | confirm `root=/dev/vda` or final chosen arg |
| Guest agent not started | initramfs issue, missing binary, guest panic, transport wait race | serial log, init output, ready timeout | boot with verbose console and preserve artifacts |
| Control pipe unavailable | named pipe race, bad QEMU chardev, guest driver missing, permissions | pipe path, QEMU argv, guest logs | test host pipe open before/after boot; fake transport tests |
| Exec hangs | protocol framing bug, guest process wait bug, stdout/stderr backpressure, timeout missing | protocol trace with redaction, guest logs | small command, large stdout command, timeout test |
| Copy-in fails | Windows path normalization, symlink/junction policy, ACL denial, guest dir missing | source/target paths redacted as needed, error kind | path traversal tests, symlink policy tests |
| Port forwarding fails | listener conflict, control channel unavailable, guest service not listening, NAT accidentally required | host listener log, forward request/response, guest logs | confirm no NIC required, bind only loopback |
| Network policy bypass | QEMU user networking accidentally enabled, proxy bypass, DNS/direct IP hole, UDP path open | redacted network config, QEMU argv, proxy logs | no-network default test, direct IP denial test |
| Checkpoint restore fails | base/writable mismatch, path locking, copy failure, disk image corruption | checkpoint metadata, disk paths, QEMU stderr | restore immediately after create, verify base immutability |

## Suggested `lsb doctor windows` output

M02 should introduce or prepare a diagnostic path that can eventually print:

```text
LocalSandbox Windows diagnostics
Host: Windows 11 x86_64 build <redacted-or-normal>
QEMU: found at C:\...\qemu-system-x86_64.exe
QEMU version: <version>
WHPX: available
Assets: kernel ok, initramfs ok, rootfs ok
Default network: disabled
Control transport: virtio-serial named pipe supported by configured QEMU
Result: ready
```

Failures should name the first blocking condition and include next steps.

M02 implementation note: the safe preflight runs `qemu-system-x86_64.exe --version`,
`qemu-system-x86_64.exe --help`, and `qemu-system-x86_64.exe -accel help`.
`-accel help` proves that the selected QEMU binary reports WHPX support, but it
does not prove firmware virtualization or the Windows Hypervisor Platform feature
will initialize successfully at VM launch. Later boot smoke tests must close that
gap. The standard M02 host probe can also leave Windows build/version
unverified; callers should surface that as uncertainty rather than claiming a
confirmed Windows 11 build.

## Debug artifact directory

M05 uses the prepared rootfs image parent as the default instance directory and
writes QEMU boot artifacts under:

```text
<instance-dir>\diagnostics\
  qemu.argv.redacted.txt
  qemu.stderr.log
  qemu.stdout.log
  serial.log
  preflight.json
  qemu.status.json
  boot.status.json
```

For normal CLI/SDK startup, `<instance-dir>` is the existing per-run instance
directory containing the writable `rootfs.ext4` work copy. The M05 direct boot
smoke test can override the diagnostics directory with
`LSB_WINDOWS_BOOT_ARTIFACT_DIR`.

In the self-hosted Windows hardware workflow, `LSB_WINDOWS_BOOT_ARTIFACT_DIR`
currently points at:

```text
C:\lsb-assets\work\<run-id>-<attempt>\diagnostics
```

Before upload, the workflow stages those files under the checkout workspace at:

```text
target\windows-lsb-diagnostics\lsb-assets-work\<run-id>-<attempt>\
```

The uploaded artifact is named `windows-lsb-diagnostics`.

`boot.status.json` records the M05 success definition:
`qemu_process_alive_after_boot_observation_window`. This is not a guest-ready
handshake. Until M06/M07 add virtio-serial control and readiness, a successful
M05 boot observation means QEMU launched with WHPX and stayed alive for the
observation window while serial/QEMU logs were captured.

M05 uses `-cpu Westmere` for the Windows WHPX boot argv. The first provisioned
boot smoke on QEMU 11.0.50 with `-cpu max` exited before serial output with
APX/MPX feature conflict warnings and `WHPX: Unexpected VP exit code 4`. Treat
that signature as a CPU model/WHPX compatibility failure before changing boot
assets or adding a TCG fallback.

M05 boot error categories include:

- `asset_missing`
- `unsupported_config`
- `invalid_config`
- `artifact_io`
- `preflight`
- `argv`
- `process_start`
- `process_status`
- `guest_boot_exited`
- `stop_failed`

Manual Windows boot smoke:

```powershell
$env:LSB_QEMU="C:\Program Files\qemu\qemu-system-x86_64.exe"
$env:LSB_WINDOWS_BOOT_KERNEL="C:\path\to\Image"
$env:LSB_WINDOWS_BOOT_INITRD="C:\path\to\initramfs.cpio.gz"
$env:LSB_WINDOWS_BOOT_ROOTFS="C:\path\to\disposable\rootfs.ext4"
$env:LSB_WINDOWS_BOOT_ARTIFACT_DIR="C:\path\to\diagnostics" # optional
cargo test -p lsb-platform windows_qemu_boot_smoke -- --ignored --nocapture
```

The rootfs path must be disposable because M05 attaches it as a writable raw
virtio block device. Long-term qcow2 overlay/checkpoint handling remains a later
store/checkpoint milestone.
