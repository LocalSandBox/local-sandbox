# M11: Port Forwarding Without Guest Network

Status: Done
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

- [x] Start guest service and reach it from host loopback. Validated on self-hosted Windows 11 WHPX in smoke run `28734824475` on commit `e38b6a2`.
- [x] Golden argv still has no NIC.
- [x] Port conflict produces clear error.
- [x] Forwarding stops cleanly when sandbox exits.

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

- Branch/PR: `codex/windows-m11-port-forwarding`
- Summary: Implemented Windows host-to-guest port forwarding over a dedicated private LocalSandbox virtio-serial channel, with host listeners bound to `127.0.0.1`, guest proxying only to guest loopback, and QEMU argv remaining `-nic none` with no normal-product `hostfwd`. The public CLI/SDK/Node API shape is unchanged, and macOS vsock forwarding remains on the existing path for valid nonzero mappings.
- Tests run: `cargo fmt --all -- --check`; `cargo check --workspace`; `cargo test --workspace`; `cargo test -p lsb-vm port_forward -- --nocapture`; `cargo check -p lsb-platform -p lsb-vm --tests --target x86_64-pc-windows-msvc`; `git diff --check`; `./scripts/win-gh-test smoke` run `28734824475`; `./scripts/win-gh-test check` run `28734981835`. `cargo check --workspace --target x86_64-pc-windows-msvc` remains blocked on this macOS host by external MSVC C/assembler tooling (`ring` missing Windows/MSVC `assert.h`, `blake3` missing `ml64.exe`), but the Windows/MSVC check lane passed on the self-hosted runner.
- Debug artifacts: passing hardware run `28734824475` uploaded `windows-lsb-diagnostics` artifact ID `8090018787`. The staged diagnostics under `target/windows-lsb-diagnostics/lsb-assets-work/28734824475-1/` show `boot.status.json` state `guest_ready` with `port_forward`, serial logs opening `org.localsandbox.forward`, and redacted QEMU argv with `-nic none`, `org.localsandbox.control`, `org.localsandbox.forward`, no `hostfwd`, and no `-netdev`. The immediately preceding failure run `28734574582` failed with Windows TCP connect refused (`os error 10061`) after the host reported a listener; artifact ID `8089958806` showed the VM and forwarding channel were ready, isolating the root cause to premature host listener shutdown from a stale initial `VmState::Stopped`. Commit `e38b6a2` fixes that by ignoring terminal lifecycle states until `Running` has been observed.
- New decisions: None. The implementation follows the RFC/M11 direction to use a LocalSandbox guest channel rather than QMP, QEMU user networking, or QEMU `hostfwd`.
- New risks: Windows M11 serializes active forwarding sessions over the dedicated forwarding channel until a future mux/session model exists. This preserves the no-network-by-default security model but does not provide concurrent forwarding-session multiplexing yet.
- Next milestone: M12 network policy/proxy integration remains separate; do not treat M11 as general Windows networking support.
