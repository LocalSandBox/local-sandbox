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
| Port forwarding fails | host loopback listener conflict, forwarding channel unavailable, guest service not listening/refused connection, invalid port, forwarding channel closed, sandbox stopped | host listener log, forward request/response status, guest logs, redacted QEMU argv | confirm listener binds `127.0.0.1`, argv has `-nic none`, no `hostfwd`, and guest service is listening on guest loopback |
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
  qmp.log                  # if QMP transcript logging is added/enabled
  control.log.redacted     # if control trace logging is added/enabled
  proxy.log.redacted       # if proxy trace logging is added/enabled
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

M15 centralizes upload staging through:

```powershell
.\scripts\collect-windows-diagnostics.ps1
.\scripts\collect-windows-diagnostics.ps1 -IncludeRunnerLogs
.\scripts\collect-windows-diagnostics.ps1 -StageRoot C:\tmp\lsb-diag -AssetWorkRoot C:\lsb-assets\work
```

The collector writes `environment.summary.json` and
`diagnostics-manifest.json`, copies text-like diagnostic files from
`LSB_WINDOWS_BOOT_ARTIFACT_DIR`, `C:\lsb-assets\work\*\diagnostics`, Cargo
target logs, and optionally `C:\actions-runner\_diag`. It allowlists
environment variables and file extensions, redacts known secret values from
environment variables whose names look secret-bearing, and also redacts common
token/private-key patterns. It does not upload raw environment dumps, boot
assets, rootfs images, qcow2 disks, npm caches, private keys, or unredacted QEMU
argv.

For current M07 Windows boots, `boot.status.json` records state `guest_ready`
and success definition
`localsandbox_guest_ready_frame_received_over_control_transport` when the host
receives a valid `GUEST_READY` LocalSandbox protocol frame over the established
virtio-serial control channel. This is the readiness signal for
`Sandbox.start()` on Windows; serial output is diagnostic context only.

M05 uses `-cpu Westmere` for the Windows WHPX boot argv. The first provisioned
boot smoke on QEMU 11.0.50 with `-cpu max` exited before serial output with
APX/MPX feature conflict warnings and `WHPX: Unexpected VP exit code 4`. Treat
that signature as a CPU model/WHPX compatibility failure before changing boot
assets or adding a TCG fallback.

`serial.log` must contain real guest output for M05 success. If QEMU stays alive
but `serial.log` remains empty, the boot path records `serial_output_missing`
instead of success; check the kernel console configuration, QEMU serial device,
and `qemu.stderr.log`.

M05/M07 boot and readiness error categories include:

- `asset_missing`
- `unsupported_config`
- `invalid_config`
- `artifact_io`
- `preflight`
- `argv`
- `process_start`
- `process_status`
- `guest_boot_exited`
- `guest_ready_process_exited`
- `guest_ready_timeout`
- `guest_ready_protocol`
- `guest_ready_transport`
- `unsupported_windows_runtime_capability`
- `serial_output_missing`
- `stop_failed`

Readiness timeout and QEMU-exited-before-ready errors include elapsed time,
control-channel state, serial tail, QEMU stderr tail, and paths to the redacted
argv/status artifacts. If QEMU exits while the host is opening the control pipe,
the failure is reported as `guest_ready_process_exited` rather than a generic
control-open timeout. Invalid ready frames report frame type and payload length,
not raw payload contents; protocol/transport errors do not dump raw payloads.

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

## M11 port-forward diagnostics

Windows M11 port forwarding uses a dedicated private virtio-serial port named
`org.localsandbox.forward`. It is separate from QMP and from the M08/M09 control
channel, and normal product forwarding must not add QEMU `hostfwd`, QEMU user
networking, TAP/bridged networking, or a guest NIC. Redacted argv diagnostics
should show `-nic none` and a `virtserialport` for the forwarding channel.

Actionable failure checks:

- Bind failure: confirm no process already owns `127.0.0.1:<host_port>` and
  that the requested host port is nonzero.
- Guest unavailable or sandbox stopped: check `boot.status.json`, serial tail,
  and whether `Sandbox.start()` reached guest ready before forwarding started.
- Guest refused connection: verify the service is listening inside the guest on
  `127.0.0.1:<guest_port>`; M11 does not expose guest-wide networking.
- Host connection actively refused immediately after LocalSandbox reports
  `forwarding 127.0.0.1:<host_port> -> guest:<guest_port>`: confirm the host
  listener is still alive and inspect VM lifecycle watcher behavior. A stale
  initial terminal state from a cloned VM state receiver can tear down the
  listener before the VM reaches `Running`; listener shutdown should only react
  to terminal states after `Running` has been observed.
- Forwarding channel closed: inspect guest logs for `lsb-guest` forwarding
  errors and QEMU lifecycle artifacts for process exit.
- Duplicate bind: reject duplicate host ports before opening listeners.
- Smoke suite stalls before port-forward: if `./scripts/win-gh-test smoke`
  hangs in an earlier ignored smoke, run
  `cargo test -p lsb-vm windows_qemu_port_forward_smoke -- --ignored --nocapture`
  directly with the same disposable boot asset variables before drawing M11
  conclusions.

Do not log forwarded payload bytes. Logs may include host/guest port numbers,
connection lifecycle events, frame/status names, and high-level errors.

## M12 network policy/proxy diagnostics

Windows M12 networking is policy-mediated through `lsb-proxy`. The default VM
still has no guest NIC and the redacted QEMU argv must contain `-nic none`.
Enabling existing allow-net configuration creates a LocalSandbox-owned proxy
link and attaches the guest NIC only to that link:

```text
-netdev stream,id=lsbproxy0,server=off,addr.type=inet,addr.host=127.0.0.1,addr.port=<proxy-port>
-device virtio-net-pci,netdev=lsbproxy0,mac=<proxy-mac>
```

The diagnostic display redacts the ephemeral proxy port as `<proxy-port>` and
the generated local NIC MAC as `<proxy-mac>`. It must not show QEMU `user`
networking, `hostfwd`, TAP, bridge, NAT, literal secret values, or
guest-visible secret placeholders.

Actionable failure checks:

- Default sandbox has outbound network: inspect `qemu.argv.redacted.txt`; this
  is a regression unless `-nic none` is present and no `-netdev` is present.
- Allow-net sandbox has no connectivity: confirm the proxy thread started, the
  QEMU stream listener is bound to `127.0.0.1`, and QEMU argv uses
  `server=off` with the redacted loopback port.
- Legacy attachment rejected: Windows intentionally rejects fd/socketpair
  network attachments because that path is macOS-only and bypass-prone.
- Non-loopback proxy endpoint rejected: Windows proxy attachments must stay on
  loopback; public control/proxy listeners are not supported.
- Allowed domain fails: capture the requested hostname/SNI/HTTP Host and proxy
  policy decision, plus whether that domain matched a DNS answer the proxy gave
  the guest. Do not log payload bytes or secret values.
- Blocked domain, direct IP, missing domain, or forged allowed Host/SNI to an
  unrelated destination IP succeeds: treat as a security bug. Explicit
  allowlists must bind the policy-visible domain to proxy DNS answers before
  upstream connect and before secret substitution.
- Secret appears in QEMU argv, guest env, serial log, proxy log, or diagnostics:
  treat as a security bug. Guest env should contain only placeholder tokens and
  substitution should occur only in the host-side proxy path for configured
  destinations.
- Proxy thread or host secret config remains alive after VM teardown: treat as a
  lifecycle bug. `ProxyHandle` drop should signal shutdown and join the stack
  and runtime threads; timeout diagnostics should not include secret values.

Logs may include sanitized domain names, policy decision names, local ephemeral
ports, and high-level errors. They must not include proxy payloads, literal host
secret values, unredacted guest environment dumps, or full unredacted QEMU argv.

## M15 CI diagnostic bundle checks

When a hosted Windows Rust CI job fails, `.github/workflows/ci.yml` runs the
collector and uploads `windows-hosted-rust-diagnostics`. This hosted bundle is
compile/unit/golden-only and normally contains environment/tool summaries plus
Cargo logs; it must not contain WHPX smoke artifacts because hosted runners do
not run QEMU boot tests.

When the manual self-hosted WHPX workflow runs, it uploads
`windows-lsb-diagnostics` after `check`, `unit`, `smoke`, and `e2e` lanes. The
smoke/e2e bundle should contain, when present:

- `qemu.argv.redacted.txt`
- `qemu.stdout.log` and `qemu.stderr.log`
- `serial.log`
- `preflight.json`
- `qemu.status.json`
- `boot.status.json`
- control/forwarding/proxy/checkpoint logs if future code writes them as
  `.log`, `.txt`, `.json`, or `.redacted`
- `environment.summary.json`
- `diagnostics-manifest.json`

If a failure needs a file not present in `diagnostics-manifest.json`, add a
redacted text artifact at the producer first or extend the collector allowlist
deliberately. Do not broaden the workflow to upload arbitrary directories.
