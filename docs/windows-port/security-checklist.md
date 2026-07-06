# Windows Security Checklist

Use this checklist for Windows backend changes and release hardening.

## Threat model summary

- Guest workload is untrusted.
- Host secrets are high-value and must not be copied into the guest by default.
- QEMU is an attack surface, not a security boundary by itself.
- The host filesystem must be exposed minimally. Overlay/import mounts keep host
  sources read-only from the product perspective; explicit Windows SMB direct
  mounts may grant host writes only under D024.
- Localhost sockets, named pipes, QMP endpoints, and temp directories must be
  private to the owning user/session.
- Network policy must be enforced by LocalSandbox-controlled code, not by QEMU
  convenience networking or Windows Firewall alone.

## Change checklist

Before merging Windows backend work, answer:

- [ ] Does this change preserve no-network-by-default?
- [ ] Does this change avoid putting secrets in guest env, argv, logs,
      snapshots, checkpoints, or debug artifacts?
- [ ] Are all host listeners bound to loopback or private pipe/socket mechanisms?
- [ ] Are QMP/control endpoints private and unauthenticated only when private by
      construction?
- [ ] Are temp/debug directories created under an appropriate user-owned location?
- [ ] Does this change avoid direct host writes unless explicitly approved?
- [ ] Are Windows paths normalized and checked for traversal, junction, symlink,
      hardlink, reparse-point, and case-collision surprises where relevant?
- [ ] Does failure cleanup terminate QEMU/helper processes?
- [ ] Does the feature fail closed on unsupported Windows/QEMU capability?
- [ ] Are diagnostics redacted and allowlisted?
- [ ] For managed host tools, are archive entries path-safe, artifact hashes
      pinned, license notices present, and global PATH left unchanged?

## QEMU process

- Validate QEMU path before execution.
- Prefer absolute path after discovery.
- For managed QEMU, execute from `%LOCALAPPDATA%\lsb\tools\qemu\<package>` via
  `current.json`; do not add that directory to user or system `PATH`.
- Do not execute QEMU from world-writable directories unless explicitly allowed
  for development with a warning.
- Use Windows Job Objects or equivalent cleanup so child/helper processes do not
  survive unexpectedly.
- Keep devices minimal; avoid NICs, USB, display, clipboard, and monitor exposure
  unless needed.

## Managed QEMU package

- Verify the downloaded artifact SHA-256 before extraction.
- Reject absolute paths, `..`, Windows path prefixes, symlinks, hardlinks, and
  unsupported archive entry types.
- Read `qemu-system-x86_64.exe` and `qemu-img.exe` relative paths from
  `manifest.json`.
- Validate required notice/provenance files before writing `current.json`.
- Keep CLI archives, runtime OS assets, and npm packages free of QEMU binaries.

## QMP

- QMP is a QEMU management channel only.
- Bind QMP to a private named pipe or loopback socket with an unpredictable
  name/path.
- Do not expose QMP on non-loopback interfaces.
- Do not forward QMP into the guest.

## Control transport

- The LocalSandbox guest control transport must not be reachable by other local
  users under normal configuration.
- Use per-sandbox names and avoid predictable global pipe names unless ACLs are
  restrictive.
- Protocol traces must redact secrets and large payloads.

## Files and mounts

- Overlay/import host source data is read-only from the product perspective.
- CLI `:ro` remains overlay on Windows and must not create a direct SMB mount.
- Explicit Windows SMB direct mounts require Administrator preflight,
  recursive source validation, ephemeral users/shares/credentials, reversible
  NTFS/share ACL grants, non-secret cleanup manifests, startup stale recovery,
  and best-effort cleanup.
- Reject path traversal in copy-in/copy-out and export paths.
- Reject or explicitly define symlink/junction/reparse behavior before following
  links on Windows.
- Direct `:rw` host mounts are approved only through the SMB/CIFS path in D024.

## Networking

- Default QEMU argv must not include a guest NIC.
- QEMU user networking must not be enabled by default.
- Allowlisted egress must be mediated by LocalSandbox proxy policy.
- Direct IP bypass and non-proxied traffic must fail unless explicitly allowed
  by a later accepted design.
- Host-to-guest port forwarding must not attach a general guest NIC.

## Secrets

- Guest receives placeholders only when policy allows.
- Proxy substitutes secrets only for configured host patterns.
- Logs must show placeholder IDs or redacted labels, not secret values.
- Windows SMB cleanup manifests must not contain generated passwords, guest
  mount requests, proxy endpoints, or host secret values.

## Sign-off template

```text
Security review:
- No-network default preserved: yes/no/n/a
- Secret redaction verified: yes/no/n/a
- Host file exposure reviewed: yes/no/n/a
- Control/QMP endpoint privacy reviewed: yes/no/n/a
- Process cleanup reviewed: yes/no/n/a
- New risks added to risk-register.md: yes/no
```
