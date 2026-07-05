# M11: Port Forwarding Without Guest Network

Status: In progress
Depends on: See `00-index.md`
RFC sections: See `traceability.md`

## Objective

Preserve host-to-guest port forwarding without enabling arbitrary guest networking.

## Scope

- Implement forwarding over LocalSandbox control/data channel or a dedicated virtio-serial channel.
- Bind host listener to loopback.
- Forward to guest-local service port.
- Handle connection close, backpressure, and errors.
- Keep QEMU `hostfwd` debug-only if present at all.

## Out of scope

- Do not enable guest NIC for normal port forwarding.
- Do not bind public interfaces.
- Do not use QEMU user networking as normal implementation.

## Likely files / crates

- `crates/lsb-vm/src/sandbox.rs` forwarding path
- `Windows control/data transport`
- `crates/lsb-guest` forward handler

## Design notes

- Preserve existing macOS behavior unless the milestone explicitly states otherwise.
- Keep Windows-specific implementation behind platform/backend boundaries.
- Prefer precise capability errors over silent degradation.
- Update `state.md` when implementation reveals a better file layout or dependency.

## Tests to add or update

The specific tests should match the implementation, but this milestone must include enough validation to satisfy the acceptance criteria below. Prefer unit/golden/fake tests before requiring self-hosted integration tests.

## Acceptance criteria

- [ ] Start guest service and reach it from host loopback.
- [ ] Golden argv still has no NIC.
- [ ] Port conflict produces clear error.
- [ ] Forwarding stops cleanly when sandbox exits.

## Coding-agent prompt

```text
You are implementing M11: Port Forwarding Without Guest Network for the LocalSandbox Windows QEMU + WHPX port.

Read first:
- docs/windows-port/rfc-qemu-whpx.md
- docs/windows-port/AGENTS.md
- docs/windows-port/agent-workspace/state.md
- docs/windows-port/agent-workspace/decisions.md
- docs/windows-port/agent-workspace/milestones/11-port-forwarding-no-network.md

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
