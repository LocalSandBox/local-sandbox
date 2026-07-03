# M01: Windows Compile Stubs

Status: Done
Depends on: See `00-index.md`
RFC sections: See `traceability.md`

## Objective

Make the repository compile on Windows targets far enough that later work can be implemented behind explicit Windows backend stubs.

## Scope

- Replace hard non-macOS compile failure with cfg-gated platform capability handling.
- Add `windows_x86_64` module skeletons where appropriate.
- Return clear unsupported/not-implemented errors for runtime paths not yet implemented.
- Keep macOS behavior unchanged.

## Out of scope

- Do not start QEMU.
- Do not add QEMU discovery.
- Do not change public CLI/SDK APIs.
- Do not implement guest changes yet.

## Likely files / crates

- `crates/lsb-vm/src/lib.rs`
- `crates/lsb-platform/src/lib.rs`
- `crates/lsb-platform/src/windows_x86_64/`
- `possibly `crates/lsb-cli` for capability error display`

## Design notes

- Preserve existing macOS behavior unless the milestone explicitly states otherwise.
- Keep Windows-specific implementation behind platform/backend boundaries.
- Prefer precise capability errors over silent degradation.
- Update `state.md` when implementation reveals a better file layout or dependency.

## Tests to add or update

The specific tests should match the implementation, but this milestone must include enough validation to satisfy the acceptance criteria below. Prefer unit/golden/fake tests before requiring self-hosted integration tests.

## Acceptance criteria

- [x] Windows `cargo check` succeeds for the targeted crates or produces only documented external dependency limitations.
- [x] macOS cfg paths remain intact.
- [x] Runtime Windows execution fails with a precise `not implemented` or `unsupported feature` error, not a compile-time rejection.
- [x] New tests cover cfg/platform selection where practical.

## Coding-agent prompt

```text
You are implementing M01: Windows Compile Stubs for the LocalSandbox Windows QEMU + WHPX port.

Read first:
- docs/windows-port/rfc-qemu-whpx.md
- docs/windows-port/AGENTS.md
- docs/windows-port/agent-workspace/state.md
- docs/windows-port/agent-workspace/decisions.md
- docs/windows-port/agent-workspace/milestones/01-windows-compile-stubs.md

Implement only this milestone. Preserve public CLI/SDK/Node APIs and existing macOS behavior. Add tests required by the milestone. Do not implement later milestones opportunistically. Update state.md and this milestone handoff before finishing.
```

## Security checklist

Complete the checklist in `../security-checklist.md`. Record any new risk in `../risk-register.md`.

## Handoff

- Branch/PR: `codex/windows-m01-compile-stubs`
- Summary: Added Windows x86_64 compile scaffolding under `lsb-platform`, removed the `lsb-vm` non-macOS compile rejection, added explicit Windows unsupported errors for runtime stubs, and cfg-gated Unix-only proxy/store/CLI paths. No QEMU discovery, startup, WHPX preflight, transport, networking, mounts, checkpoints, or Node packaging was implemented.
- Tests run:
  - `cargo fmt --all -- --check` - pass
  - `cargo check --workspace` - pass
  - `cargo test -p lsb-platform` - pass, 8 tests
  - `cargo test -p lsb-vm` - pass, 2 tests
  - `cargo test -p lsb-store` - pass, 5 tests
  - `cargo test -p lsb-proxy` - pass, 11 tests
  - `cargo check -p lsb-platform -p lsb-vm -p lsb-proxy -p lsb-proto --target x86_64-pc-windows-msvc` - pass
  - `cargo check --workspace --target x86_64-pc-windows-msvc` - blocked on macOS host by external Windows C/assembler tooling for transitive crates (`ring` missing Windows/MSVC headers such as `assert.h`; `blake3` missing `ml64.exe`)
- Debug artifacts: None.
- New decisions: None.
- New risks: None.
- Security review:
  - No-network default preserved: yes
  - Secret redaction verified: n/a
  - Host file exposure reviewed: yes
  - Control/QMP endpoint privacy reviewed: n/a
  - Process cleanup reviewed: n/a
  - New risks added to risk-register.md: no
- Next milestone: M02 QEMU discovery and preflight.
