# Windows Port Documentation

This directory contains the durable documentation for the LocalSandbox Windows
backend after the Windows MVP sprint.

## Current status

The Windows MVP supports Windows 11 x64 hosts through QEMU with WHPX. It boots
the existing Linux guest, uses virtio-serial for LocalSandbox control, supports
non-interactive exec, guest file transfer, staged mount imports, host-to-guest
port forwarding without a guest NIC, policy-mediated `--allow-net`, flattened
qcow2 checkpoints, Windows x64 Node package metadata, and hosted/self-hosted CI
coverage. The release path includes Windows x64 CLI and runtime asset artifacts
plus a native PowerShell installer. `lsb init` installs the managed QEMU host
tool package under `%LOCALAPPDATA%\lsb\tools\qemu` and does not mutate global
`PATH`.

For normal Windows development, download released runtime assets with `lsb init`
instead of building them locally. The Windows package contains `Image`,
`initramfs.cpio.gz`, and `rootfs.ext4` built for the QEMU/WHPX path, including
virtio-serial support. Source-building those assets remains possible through
`xtask prepare-rootfs --platform windows-x86_64`, but it is Docker/Linux-hosted
and more complicated than the recommended release download path.

The MVP is complete for upstream review, but it is not a production-readiness
certification. See `mvp-handoff.md` before planning follow-up work.

## Windows direct mounts

Windows direct directory mounts use SMB/CIFS without changing the public CLI,
Rust SDK, or Node API shape.

- CLI no-suffix mounts and CLI `:ro` mounts remain overlay snapshot imports.
- CLI `:rw` mounts continue to require `--allow-host-writes`; on Windows they
  are SMB/CIFS direct read-write mounts.
- SDK and Node `Direct { flags: 0 }` map to SMB/CIFS read-write direct
  mounts, and `Direct { flags: MS_RDONLY }` maps to SMB/CIFS read-only
  direct mounts.
- Windows SMB direct mounts require an elevated Administrator shell.
- SMB direct mounts must use LocalSandbox-controlled proxy networking and must
  not imply arbitrary outbound `allow_net`.
- LocalSandbox creates ephemeral Windows users, shares, credentials, and
  reversible ACL grants, then records a non-secret cleanup manifest for stale
  recovery.

See `decisions.md` D024 and the implementation tracker in the repository
`STATE.md`.

## Files

| File | Purpose |
|---|---|
| `mvp-handoff.md` | Current Windows MVP support status, known limitations, validation evidence, and future work. Start here. |
| `rfc-qemu-whpx.md` | Original QEMU + WHPX design RFC and rationale. Historical design record, not the current status tracker. |
| `decisions.md` | Accepted Windows backend decisions. Add new decisions here only after review. |
| `architecture.md` | Current crate/module map, backend boundaries, and product invariants. |
| `validation.md` | Test strategy, CI lanes, self-hosted runner commands, and smoke coverage. |
| `diagnostics.md` | Failure triage, diagnostic artifacts, redaction rules, and collector behavior. |
| `runner-setup.md` | Maintainer notes for the self-hosted Windows 11 WHPX runner. |
| `security-checklist.md` | Security checklist for Windows backend changes. |
| `review-checklist.md` | PR review checklist for Windows backend changes. |
| `risk-register.md` | Active, accepted, and retired Windows backend risks. |
| `future-work.md` | Follow-on features and experiments intentionally left out of the MVP. |

## Working rules

- Preserve the public CLI, Rust SDK, and Node API shape unless a new accepted
  decision permits a change.
- Preserve macOS behavior while changing shared code.
- Keep QEMU/WHPX details below the platform/backend boundary.
- Keep default Windows networking disabled.
- Keep host secrets on the host; diagnostics must be redacted.
- Use the self-hosted WHPX workflow for real Windows boot/runtime evidence.

## Standard validation

Use local checks for platform-independent changes, then the Windows hardware
helper when runtime behavior is touched:

```bash
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace

./scripts/win-gh-test check
./scripts/win-gh-test unit
./scripts/win-gh-test smoke
./scripts/win-gh-test e2e
```

The Windows helper dispatches `.github/workflows/windows-lsb-hardware.yml`,
which also runs the e2e lane automatically on trusted `main` pushes and
requires a clean committed working tree for manual branch runs.
