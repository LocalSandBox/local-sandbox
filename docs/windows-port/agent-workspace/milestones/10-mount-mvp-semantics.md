# M10: Mount MVP Semantics

Status: Done
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

- [x] Mount request from CLI/SDK succeeds with copy/import semantics.
- [x] Guest writes do not alter host source.
- [x] Explicit export behavior tested.
- [x] `:rw` mount returns Windows capability error.

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
- Summary: Windows mount MVP maps overlay host-directory mounts to staged guest imports using the M09 copy-in data plane, then mounts the imported guest snapshot as the overlay lowerdir. Guest writes stay in guest-local overlay storage and do not mutate the host source. Direct writable/live host mounts fail closed with Windows-specific unsupported errors. macOS VirtioFS behavior and public CLI/SDK/Node API shape were left unchanged.
- Tests run: `cargo fmt --all -- --check`; `cargo check --workspace`; `cargo test -p lsb-platform windows_x86_64::fs -- --nocapture`; `cargo test -p lsb-vm -- --nocapture`; `cargo test -p lsb-guest -- --nocapture`; targeted Windows test compiles for `lsb-platform`/`lsb-vm`; `cargo test --workspace`; `./scripts/win-gh-test unit` runs `28714105683` and `28729436438`; `./scripts/win-gh-test smoke` run `28714141992`.
- Debug artifacts: Windows smoke run `28714141992`, job `85153326347`, uploaded `windows-lsb-diagnostics` artifact ID `8084000670`; review-fix Windows unit run `28729436438`, job `85192454081`, uploaded artifact ID `8088274579`.
- New decisions: None. The implementation follows the RFC and existing decisions for copy/import mount semantics and explicit export.
- New risks: None added. Remaining limitations are intentional MVP boundaries: no VirtioFS/9p/vfat, no live sharing, no direct writable host mounts, no file watching, conservative symlink/reparse/hardlink/special-file behavior. Mount imports are re-planned immediately before guest import so post-build source tree changes are revalidated.
- Next milestone: M11 Port forwarding.
