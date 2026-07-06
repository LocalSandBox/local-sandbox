# Windows Diagnostics Guide

Use this guide to keep Windows backend failures actionable and repeatable.

## Principles

- Prefer structured errors over raw strings.
- Include likely cause and remediation in user-facing diagnostics.
- Capture redacted QEMU argv for QEMU start/boot failures.
- Capture serial logs for boot and guest-agent failures.
- Never log secrets, proxy substitution values, or raw unredacted environment.
- Preserve temporary artifacts only through documented debug paths.

## Failure matrix

| Symptom | Likely causes | Evidence to capture | Recommended checks |
|---|---|---|---|
| QEMU not found | `lsb init` not run, invalid managed package, `LSB_QEMU` wrong, unsupported binary | configured path, managed `current.json` summary, PATH lookup summary, error kind | `lsb init --host-tools-only`, managed executable `--version` |
| WHPX unavailable | Windows feature disabled, virtualization disabled in firmware, unsupported nested VM, non-Windows-11 host | preflight result, QEMU stderr, Windows version | Windows Features, BIOS virtualization, runner labels |
| QEMU starts then exits | bad argv, missing assets, unsupported device, invalid path quoting | redacted argv, stderr, exit code | run redacted argv manually from temp dir |
| Kernel does not boot | wrong kernel arch, missing `console`, WHPX/device issue, bad initrd | serial log, QEMU stderr, asset hashes | compare direct boot argv and serial config |
| Rootfs not mounted | wrong virtio-blk device, missing ext4 support, wrong root arg, corrupted disk | serial log, guest panic/initramfs output | confirm `root=/dev/vda` and disk format |
| Guest agent not started | initramfs issue, missing binary, guest panic, transport wait race | serial log, init output, ready timeout | inspect `lsb-guest` startup lines |
| Control pipe unavailable | named pipe race, bad QEMU chardev, guest driver missing, permissions | pipe path, QEMU argv, guest logs | confirm host connects during boot |
| Exec hangs | protocol framing bug, guest wait bug, stdout/stderr backpressure, timeout missing | redacted protocol trace, guest logs | small command, large stdout, timeout test |
| Copy-in fails | Windows path normalization, symlink/junction policy, ACL denial, guest dir missing | source/target paths as safe, error kind | path traversal and reparse tests |
| Mount differs | copy import rejected path, case collision, metadata loss, no live coherence | mount validation report, guest mount response | confirm snapshot/import semantics |
| SMB direct mount fails | not elevated, SMB service unavailable, host path rejected, mount-only proxy missing, CIFS guest failure | sanitized guest mount error, cleanup manifest presence, resource cleanup result | confirm Administrator shell, SMB service, `mount.cifs`, and proxy stream argv |
| Port forwarding fails | bind conflict, forwarding channel unavailable, guest service not listening, listener lifecycle bug | listener log, forward status, guest logs, argv | confirm `127.0.0.1`, `-nic none`, no `hostfwd` |
| Network policy bypass | accidental NIC/user networking, proxy bypass, DNS/direct IP hole | redacted network config, argv, proxy logs | no-network default and direct-IP denial tests |
| Checkpoint restore fails | base/writable mismatch, path locking, copy failure, disk corruption | checkpoint metadata, disk paths, QEMU stderr | restore immediately after create, verify base immutability |

## Diagnostic directory

Windows boot/runtime artifacts are written under the instance diagnostics
directory, or under `LSB_WINDOWS_BOOT_ARTIFACT_DIR` for ignored smoke tests:

```text
<instance-dir>\diagnostics\
  qemu.argv.redacted.txt
  qemu.stderr.log
  qemu.stdout.log
  serial.log
  preflight.json
  qemu.status.json
  boot.status.json
  control.log.redacted     # if produced
  proxy.log.redacted       # if produced
```

Managed QEMU host-tool metadata lives under:

```text
%LOCALAPPDATA%\lsb\tools\qemu\
  current.json
  qemu-11.0.50-lsb0.4.0\
    manifest.json
    qemu-system-x86_64.exe
    qemu-img.exe
```

`preflight.json` records the selected QEMU source as `env`, `config`,
`managed`, or `path`. `environment.summary.json` records the managed
`current.json` path, package version, artifact SHA-256, and absolute executable
paths when available.

When SMB direct mounts are active, the instance directory root may also contain
`windows-smb-cleanup.json`; it is non-secret and transient.

For self-hosted workflow runs, the source diagnostics path is:

```text
C:\lsb-assets\work\<run-id>-<attempt>\diagnostics
```

Before upload, the collector stages files under the checkout:

```text
target\windows-lsb-diagnostics\lsb-assets-work\<run-id>-<attempt>\
```

The uploaded artifact is named `windows-lsb-diagnostics`.

## Diagnostic collector

`scripts/collect-windows-diagnostics.ps1` is the common hosted and self-hosted
collector.

Example usage:

```powershell
.\scripts\collect-windows-diagnostics.ps1

$env:LSB_WINDOWS_BOOT_ARTIFACT_DIR="C:\lsb-assets\work\<run-id>-<attempt>\diagnostics"
.\scripts\collect-windows-diagnostics.ps1 -StageRoot C:\tmp\lsb-diag

$env:LSB_DIAGNOSTICS_RUN_STARTED_UTC=(Get-Date).ToUniversalTime().AddMinutes(-30).ToString("o")
.\scripts\collect-windows-diagnostics.ps1 -IncludeRunnerLogs
```

The collector:

- deletes and recreates the stage root at startup,
- writes `environment.summary.json` and `diagnostics-manifest.json`,
- copies text-like diagnostic files only from the current run or explicit
  artifact directory,
- does not scan historical `C:\lsb-assets\work\*` directories,
- includes runner `_diag` logs only with a bounded start timestamp,
- filters runner logs to timestamped lines inside the bounded window plus
  continuations,
- timestamp-scopes workspace `target` logs when a run-start timestamp exists,
- records external persistent `CARGO_TARGET_DIR` caches as skipped instead of
  uploading them,
- probes managed QEMU executables by absolute path when `current.json` exists,
- allowlists environment capture rather than dumping the raw environment,
- redacts known secret values and common token/private-key patterns.

It must not upload raw environment dumps, boot assets, rootfs images, qcow2
disks, npm caches, private keys, stale stage-root contents, historical runner
log lines, persistent target-cache logs, or unredacted QEMU argv.

## SMB direct mount diagnostics

Windows SMB direct mounts create a transient `windows-smb-cleanup.json` file in
the instance directory after host resources are prepared. The manifest is used
only for stale recovery and contains generated user/share names, domains,
principals, paths, and access modes. It must not contain generated SMB
passwords, guest `MountRequest` payloads, proxy endpoints, or secret values.

Normal stop removes the manifest after share removal, ACL revoke, and user
delete complete. If cleanup fails or the host process exits before cleanup, a
later Windows startup scans stale instance manifests and retries cleanup
best-effort. Cleanup errors must stay sanitized and must not print passwords.

## Boot/readiness diagnostics

Current Windows startup readiness is a valid LocalSandbox `GuestReady` frame
over the established virtio-serial control stream. `boot.status.json` records:

- `state: "guest_ready"`
- `success_definition: "localsandbox_guest_ready_frame_received_over_control_transport"`
- elapsed readiness time,
- protocol version,
- transport,
- guest version,
- advertised capabilities.

Important boot signatures:

- `-cpu max` plus WHPX APX/MPX warnings and `WHPX: Unexpected VP exit code 4`
  indicates the known CPU model/WHPX compatibility failure. The production path
  uses `-cpu Westmere`; do not add TCG fallback for normal runs.
- Empty `serial.log` while QEMU stays alive is not success. Inspect kernel
  console configuration, serial device argv, and `qemu.stderr.log`.
- If QEMU exits while opening the control pipe, report QEMU/process context
  rather than a generic control-open timeout.
- Invalid ready frames should report frame type and payload length, not raw
  payload bytes.

## Port forwarding diagnostics

Windows port forwarding uses a dedicated private virtio-serial port named
`org.localsandbox.forward`. Normal product forwarding must not add QEMU
`hostfwd`, QEMU user networking, TAP/bridged networking, or a guest NIC.

Actionable checks:

- Bind failure: confirm no process owns `127.0.0.1:<host_port>` and the host
  port is nonzero.
- Guest unavailable: check `boot.status.json`, serial tail, and whether
  startup reached guest ready.
- Guest refused connection: verify the service is listening inside the guest on
  `127.0.0.1:<guest_port>`.
- Immediate host connect refused after LocalSandbox reports forwarding: inspect
  listener lifecycle. A stale initial terminal VM state must not close the
  listener before `Running` has been observed.
- Forwarding channel closed: inspect guest forwarding logs and QEMU lifecycle
  artifacts.

Do not log forwarded payload bytes.

## Network/proxy diagnostics

Default Windows QEMU argv must contain `-nic none` and no `-netdev`.

With allow-net/proxy configuration, Windows attaches the guest NIC only to a
LocalSandbox-owned loopback proxy stream:

```text
-netdev stream,id=lsbproxy0,server=off,addr.type=inet,addr.host=127.0.0.1,addr.port=<proxy-port>
-device virtio-net-pci,netdev=lsbproxy0,mac=<proxy-mac>
```

Diagnostics redact the ephemeral proxy port and generated local MAC.

Treat as security bugs:

- default sandbox has outbound network,
- blocked domain/direct IP/missing domain succeeds,
- forged allowed Host/SNI to unrelated destination IP succeeds,
- secret appears in QEMU argv, guest env, serial log, proxy log, or diagnostics,
- generated SMB password appears in cleanup manifests, QEMU argv, guest argv,
  guest env, serial log, proxy log, or uploaded diagnostics,
- proxy thread or host secret config survives VM teardown.

Logs may include sanitized domain names, policy decision names, local ephemeral
ports, and high-level errors. They must not include proxy payloads, literal host
secret values, unredacted guest environment dumps, or full unredacted QEMU argv.

## CI diagnostic bundle checks

Hosted Windows CI uploads `windows-hosted-rust-diagnostics` on failure. This is
compile/unit/golden-only and should not contain WHPX smoke artifacts.

The manual self-hosted WHPX workflow uploads:

- `windows-lsb-diagnostics-probe` after smoke/e2e cache probes,
- `windows-lsb-diagnostics` after `check`, `unit`, `smoke`, and `e2e` lanes.

If a failure needs a file not present in `diagnostics-manifest.json`, add a
redacted text artifact at the producer or extend the collector allowlist
deliberately. Do not broaden the workflow to upload arbitrary directories.
