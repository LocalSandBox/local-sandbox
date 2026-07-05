# M14: Node Packaging

Status: In progress
Depends on: See `00-index.md`
RFC sections: See `traceability.md`

## Objective

Add Windows Node package support after the Rust Windows backend is usable.

## Scope

- Add `win32-x64-msvc` package target.
- Keep unsupported-platform errors for unsupported arch/OS clear.
- Ensure package locates/discovers backend assets and QEMU consistently with CLI.
- Add Node import/smoke tests on Windows.

## Out of scope

- Do not block core Rust backend milestones.
- Do not bundle QEMU unless a later packaging decision approves it.
- Do not change Node public API shape.

## Likely files / crates

- `bindings/nodejs`
- `.github/workflows/nodejs-binding.yml`
- `package metadata`

## Design notes

- Preserve existing macOS behavior unless the milestone explicitly states otherwise.
- Keep Windows-specific implementation behind platform/backend boundaries.
- Prefer precise capability errors over silent degradation.
- Update `state.md` when implementation reveals a better file layout or dependency.

## Tests to add or update

The specific tests should match the implementation, but this milestone must include enough validation to satisfy the acceptance criteria below. Prefer unit/golden/fake tests before requiring self-hosted integration tests.

## Acceptance criteria

- [ ] Windows Node package builds.
- [ ] Install/import smoke passes.
- [ ] Existing darwin package behavior unchanged.
- [ ] Unsupported platforms fail clearly.

## Coding-agent prompt

```text
You are implementing M14: Node Packaging for the LocalSandbox Windows QEMU + WHPX port.

Read first:
- docs/windows-port/rfc-qemu-whpx.md
- docs/windows-port/AGENTS.md
- docs/windows-port/agent-workspace/state.md
- docs/windows-port/agent-workspace/decisions.md
- docs/windows-port/agent-workspace/milestones/14-node-packaging.md

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
