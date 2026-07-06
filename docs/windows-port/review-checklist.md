# Windows Review Checklist

Use this checklist for PRs that touch the Windows backend or shared behavior
used by Windows.

## Scope

- [ ] PR has a clear Windows scope and does not include unrelated refactors.
- [ ] Public CLI/SDK/Node API shape is unchanged, or `decisions.md` records an
      accepted decision permitting the change.
- [ ] Existing macOS behavior is preserved.
- [ ] New limitations or behavior changes are reflected in `mvp-handoff.md`.

## Architecture

- [ ] Windows/QEMU details stay below platform/backend boundaries.
- [ ] New abstractions describe LocalSandbox product needs, not incidental QEMU
      details.
- [ ] QEMU argv is constructed as structured arguments, not shell-concatenated.
- [ ] QMP is not used as a LocalSandbox guest API.

## Security

- [ ] No-network default preserved.
- [ ] No secrets in argv, logs, tests, snapshots, checkpoints, or debug artifacts.
- [ ] Host listeners are loopback/private only.
- [ ] QMP/control/forwarding endpoints are private.
- [ ] Host filesystem exposure is minimized.
- [ ] Direct `:rw` host mounts on Windows use only the D024 SMB/CIFS path with
      Administrator preflight, cleanup, and redaction.
- [ ] Failure modes fail closed.

## Testing

- [ ] Unit/golden/fake-process tests were added or updated for platform-neutral
      logic.
- [ ] Windows-only tests are cfg-gated correctly.
- [ ] Hosted CI does not require QEMU, WHPX, nested virtualization, or boot
      assets.
- [ ] Self-hosted WHPX smoke is run for QEMU, WHPX, lifecycle, transport,
      guest-control, mount, checkpoint, or networking changes.
- [ ] Cross-platform changes include macOS regression coverage.

## Diagnostics

- [ ] Errors name likely cause and remediation.
- [ ] QEMU failures include redacted argv where relevant.
- [ ] Boot/control failures capture serial or protocol context where relevant.
- [ ] Diagnostic collector allowlists are intentional and redacted.

## Documentation

- [ ] `mvp-handoff.md` updated for support status, limitations, or validation
      evidence changes.
- [ ] `decisions.md` updated only for new accepted decisions.
- [ ] `risk-register.md` updated for new, retired, or changed risks.
- [ ] `validation.md` updated for new test commands or CI behavior.
- [ ] `diagnostics.md` updated for new artifacts or triage behavior.
