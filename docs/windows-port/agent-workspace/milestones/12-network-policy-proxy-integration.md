# M12: Network Policy and Proxy Integration

Status: Done
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

- [x] No-network default test passes.
- [x] Allowed domain succeeds.
- [x] Blocked domain/direct IP fails.
- [x] Secret substitution works only for configured host patterns.
- [x] Logs redact secret values.

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

- Branch/PR: `codex/windows-m12-network-policy-proxy`
- Summary: Windows allow-net now attaches the guest NIC only to a LocalSandbox-owned `lsb-proxy` QEMU stream path. Default Windows QEMU argv remains `-nic none`; allow-net uses `-netdev stream` plus `virtio-net-pci` and rejects legacy fd/socketpair, non-loopback, and bypass-prone paths. Explicit allowlists now bind policy-visible SNI/HTTP Host values to recent proxy DNS A answers before upstream connect or secret substitution, so direct IP, missing-domain, non-allowlisted-domain, and forged allowed Host/SNI-to-arbitrary-IP traffic fail closed. Guest secret smoke validation captures placeholder output and compares on the host instead of embedding literal host secrets in guest argv. Proxy teardown now signals and joins stack/runtime threads.
- Tests run: `cargo fmt --all -- --check`; `cargo check --workspace`; `cargo test --workspace`; `cargo test -p lsb-proxy`; `cargo test -p lsb-platform`; `cargo test -p lsb-sdk`; `cargo check -p lsb-proxy -p lsb-platform -p lsb-sdk`; `cargo check -p lsb-platform --target x86_64-pc-windows-msvc`; `git diff --check`; `cargo check --workspace --target x86_64-pc-windows-msvc` blocked locally by missing Windows/MSVC C/assembler tooling; prior self-hosted Windows check run `28736521420`; prior self-hosted Windows smoke run `28736441996`.
- Debug artifacts: Windows smoke artifact `windows-lsb-diagnostics` ID `8090499794`, staged under `lsb-assets-work/28736441996-1`. Earlier failed smoke artifact `8090467336` captured the fixed Windows-only SDK smoke compile error from run `28735986498`.
- New decisions: None. The implementation follows existing decisions D012, D013, D014, D015, and D019.
- New risks: No new risk IDs. R005 and R010 are now `Mitigating` with M12 evidence.
- Next milestone: M13 checkpoint/store MVP.
