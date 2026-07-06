# Windows Port Documentation

This directory contains the durable documentation for the LocalSandbox Windows
backend after the Windows MVP sprint.

## Current status

The Windows MVP supports Windows 11 x64 hosts through QEMU with WHPX. It boots
the existing Linux guest, uses virtio-serial for LocalSandbox control, supports
non-interactive exec, guest file transfer, staged mount imports, host-to-guest
port forwarding without a guest NIC, policy-mediated `--allow-net`, flattened
qcow2 checkpoints, Windows x64 Node package metadata, and hosted/self-hosted CI
coverage.

The MVP is complete for upstream review, but it is not a production-readiness
certification. See `mvp-handoff.md` before planning follow-up work.

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
