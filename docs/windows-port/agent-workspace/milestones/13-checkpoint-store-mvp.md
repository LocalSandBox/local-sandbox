# M13: Checkpoint and Store MVP

Status: Review
Depends on: See `00-index.md`
RFC sections: See `traceability.md`

## Objective

Implement Windows-safe product checkpoint semantics using simple disk artifacts before CAS/NBD porting.

## Scope

- Define immutable base rootfs plus per-sandbox writable/checkpoint artifact strategy.
- Create/list/restore/delete checkpoints on Windows.
- Avoid Unix-socket NBD dependency for MVP.
- Keep checkpoint metadata compatible enough for future migration or clearly versioned.
- Protect base image immutability.

## Out of scope

- Do not port full CAS/NBD unless separately scoped.
- Do not rely on QEMU live snapshots as the product checkpoint contract.
- Do not mutate base rootfs in place.

## Likely files / crates

- `crates/lsb-store` Windows path
- `crates/lsb-cli/src/checkpoint.rs`
- `Windows backend disk config`

## Design notes

- Preserve existing macOS behavior unless the milestone explicitly states otherwise.
- Keep Windows-specific implementation behind platform/backend boundaries.
- Prefer precise capability errors over silent degradation.
- Update `state.md` when implementation reveals a better file layout or dependency.

## Tests to add or update

The specific tests should match the implementation, but this milestone must include enough validation to satisfy the acceptance criteria below. Prefer unit/golden/fake tests before requiring self-hosted integration tests.

## Acceptance criteria

- [x] Create/list/delete checkpoint tests.
- [x] Restore smoke test after exec/file mutation is implemented as `windows_qemu_checkpoint_store_smoke`; real self-hosted WHPX execution is pending.
- [x] Base image remains unchanged in the Windows MVP design and smoke assertion.
- [x] Checkpoint errors mention Windows MVP limitations clearly.

## Coding-agent prompt

```text
You are implementing M13: Checkpoint and Store MVP for the LocalSandbox Windows QEMU + WHPX port.

Read first:
- docs/windows-port/rfc-qemu-whpx.md
- docs/windows-port/AGENTS.md
- docs/windows-port/agent-workspace/state.md
- docs/windows-port/agent-workspace/decisions.md
- docs/windows-port/agent-workspace/milestones/13-checkpoint-store-mvp.md

Implement only this milestone. Preserve public CLI/SDK/Node APIs and existing macOS behavior. Add tests required by the milestone. Do not implement later milestones opportunistically. Update state.md and this milestone handoff before finishing.
```

## Security checklist

Complete the checklist in `../security-checklist.md`. Record any new risk in `../risk-register.md`.

## Handoff

- Branch/PR: `codex/windows-m13-checkpoint-store-mvp`
- Summary: Implemented Windows checkpoint/store MVP with immutable base images, private per-instance qcow2 writable overlays, flattened qcow2 checkpoint artifacts plus versioned JSON metadata, explicit unsupported errors for CAS `.idx` restore on Windows, CLI/SDK checkpoint wiring, and Windows QEMU qcow2 disk-format selection. Existing macOS NBD/CAS behavior is unchanged.
- Tests run: `cargo fmt --all -- --check`; `git diff --check`; `cargo check --workspace`; `cargo test --workspace`; `cargo test -p lsb-store windows_checkpoint -- --nocapture`; `cargo test -p lsb-platform windows_x86_64::backend -- --nocapture`; `cargo test -p lsb-sdk windows_qemu_checkpoint_store_smoke -- --ignored --nocapture`; `cargo check -p lsb-platform -p lsb-vm --tests --target x86_64-pc-windows-msvc`. `cargo check --workspace --target x86_64-pc-windows-msvc` remains blocked on this macOS host by external Windows/MSVC C and assembler tooling.
- Debug artifacts: None from local tests. Real WHPX smoke artifacts pending self-hosted runner execution.
- New decisions: D022 records flattened qcow2 checkpoint artifacts for M13.
- New risks: No new risk; R006 moved to mitigating for the MVP while CAS/NBD remains future work.
- Next milestone: Run the M13 self-hosted WHPX checkpoint smoke, then proceed to M14 Node packaging if the smoke passes.
