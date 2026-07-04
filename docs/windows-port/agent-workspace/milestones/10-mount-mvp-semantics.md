# M10: Mount MVP Semantics

Status: In progress
Depends on: See `00-index.md`
RFC sections: See `traceability.md`

## Objective

Provide Windows MVP mount behavior that preserves LocalSandbox product semantics without live shared mounts.

## Scope

- Map requested host mounts to guest imported directories.
- Keep host source read-only from product perspective.
- Store guest writes in isolated guest/writable area.
- Provide explicit export path for results when supported.
- Return clear capability error for direct `:rw` mounts.

## Out of scope

- Do not implement VirtioFS or 9p as MVP unless separately approved.
- Do not promise live file watching.
- Do not allow guest writes directly into host source.

## Likely files / crates

- `crates/lsb-vm` mount planning
- `crates/lsb-platform/src/windows_x86_64/fs/mount_plan.rs`
- `crates/lsb-guest` mount/file handling

## Design notes

- Preserve existing macOS behavior unless the milestone explicitly states otherwise.
- Keep Windows-specific implementation behind platform/backend boundaries.
- Prefer precise capability errors over silent degradation.
- Update `state.md` when implementation reveals a better file layout or dependency.

## Tests to add or update

The specific tests should match the implementation, but this milestone must include enough validation to satisfy the acceptance criteria below. Prefer unit/golden/fake tests before requiring self-hosted integration tests.

## Acceptance criteria

- [ ] Mount request from CLI/SDK succeeds with copy/import semantics.
- [ ] Guest writes do not alter host source.
- [ ] Explicit export behavior tested.
- [ ] `:rw` mount returns Windows capability error.

## Coding-agent prompt

```text
You are implementing M10: Mount MVP Semantics for the LocalSandbox Windows QEMU + WHPX port.

Read first:
- docs/windows-port/rfc-qemu-whpx.md
- docs/windows-port/AGENTS.md
- docs/windows-port/agent-workspace/state.md
- docs/windows-port/agent-workspace/decisions.md
- docs/windows-port/agent-workspace/milestones/10-mount-mvp-semantics.md

Implement only this milestone. Preserve public CLI/SDK/Node APIs and existing macOS behavior. Add tests required by the milestone. Do not implement later milestones opportunistically. Update state.md and this milestone handoff before finishing.
```

## Security checklist

Complete the checklist in `../security-checklist.md`. Record any new risk in `../risk-register.md`.

## Handoff

- Branch/PR: `codex/windows-m10-mount-mvp`
- Summary: TBD
- Tests run: TBD
- Debug artifacts: TBD
- New decisions: TBD
- New risks: TBD
- Next milestone: TBD
