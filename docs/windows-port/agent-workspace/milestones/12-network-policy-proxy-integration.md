# M12: Network Policy and Proxy Integration

Status: In progress
Depends on: See `00-index.md`
RFC sections: See `traceability.md`

## Objective

Implement strict allowed-network behavior and controlled secret substitution on Windows.

## Scope

- Design and implement Windows attachment path for `lsb-proxy` policy.
- Preserve no-network default.
- Allow network only when requested.
- Prevent direct IP/protocol bypass outside policy.
- Preserve host-side secret substitution semantics.
- Add tests for blocked and allowed egress.

## Out of scope

- Do not trust QEMU NAT as policy.
- Do not enable arbitrary outbound by default.
- Do not copy secret literals into guest.
- Do not require Windows Firewall as primary MVP enforcement unless new decision is recorded.

## Likely files / crates

- `crates/lsb-proxy` Windows backend
- `crates/lsb-platform/src/windows_x86_64/network/`
- `CLI network config flow`

## Design notes

- Preserve existing macOS behavior unless the milestone explicitly states otherwise.
- Keep Windows-specific implementation behind platform/backend boundaries.
- Prefer precise capability errors over silent degradation.
- Update `state.md` when implementation reveals a better file layout or dependency.

## Tests to add or update

The specific tests should match the implementation, but this milestone must include enough validation to satisfy the acceptance criteria below. Prefer unit/golden/fake tests before requiring self-hosted integration tests.

## Acceptance criteria

- [ ] No-network default test passes.
- [ ] Allowed domain succeeds.
- [ ] Blocked domain/direct IP fails.
- [ ] Secret substitution works only for configured host patterns.
- [ ] Logs redact secret values.

## Coding-agent prompt

```text
You are implementing M12: Network Policy and Proxy Integration for the LocalSandbox Windows QEMU + WHPX port.

Read first:
- docs/windows-port/rfc-qemu-whpx.md
- docs/windows-port/AGENTS.md
- docs/windows-port/agent-workspace/state.md
- docs/windows-port/agent-workspace/decisions.md
- docs/windows-port/agent-workspace/milestones/12-network-policy-proxy-integration.md

Implement only this milestone. Preserve public CLI/SDK/Node APIs and existing macOS behavior. Add tests required by the milestone. Do not implement later milestones opportunistically. Update state.md and this milestone handoff before finishing.
```

## Security checklist

Complete the checklist in `../security-checklist.md`. Record any new risk in `../risk-register.md`.

## Handoff

- Branch/PR: TBD
- Summary: TBD
- Tests run: TBD
- Debug artifacts: TBD
- New decisions: TBD
- New risks: TBD
- Next milestone: TBD
