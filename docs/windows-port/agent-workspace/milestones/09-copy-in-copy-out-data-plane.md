# M09: Copy-In/Copy-Out Data Plane

Status: Done
Depends on: See `00-index.md`
RFC sections: See `traceability.md`

## Objective

Implement safe host-to-guest import and guest-to-host export for files and directories.

## Scope

- Use existing file protocol operations where possible.
- Normalize and validate Windows host paths.
- Reject path traversal and unsafe destination escapes.
- Support files, directories, empty directories, and reasonable large files.
- Define symlink/junction behavior explicitly.

## Out of scope

- Do not implement live shared mounts.
- Do not support direct host writes.
- Do not follow dangerous reparse points without explicit policy.

## Likely files / crates

- `crates/lsb-vm` file APIs
- `crates/lsb-guest` file handlers
- `crates/lsb-platform/src/windows_x86_64/fs/copy.rs`

## Design notes

- Preserve existing macOS behavior unless the milestone explicitly states otherwise.
- Keep Windows-specific implementation behind platform/backend boundaries.
- Prefer precise capability errors over silent degradation.
- Update `state.md` when implementation reveals a better file layout or dependency.

## Tests to add or update

The specific tests should match the implementation, but this milestone must include enough validation to satisfy the acceptance criteria below. Prefer unit/golden/fake tests before requiring self-hosted integration tests.

## Acceptance criteria

- [x] Copy-in/out tests for files/dirs/large files.
- [x] Path traversal rejection tests.
- [x] Windows symlink/junction behavior documented.
- [x] Explicit export does not overwrite unexpected host paths.

## Coding-agent prompt

```text
You are implementing M09: Copy-In/Copy-Out Data Plane for the LocalSandbox Windows QEMU + WHPX port.

Read first:
- docs/windows-port/rfc-qemu-whpx.md
- docs/windows-port/AGENTS.md
- docs/windows-port/agent-workspace/state.md
- docs/windows-port/agent-workspace/decisions.md
- docs/windows-port/agent-workspace/milestones/09-copy-in-copy-out-data-plane.md

Implement only this milestone. Preserve public CLI/SDK/Node APIs and existing macOS behavior. Add tests required by the milestone. Do not implement later milestones opportunistically. Update state.md and this milestone handoff before finishing.
```

## Security checklist

Complete the checklist in `../security-checklist.md`. Record any new risk in `../risk-register.md`.

## Handoff

- Branch/PR: `codex/windows-m09-copy-in-copy-out`
- Summary: Added Windows copy transfer data-plane helpers without live shared mounts. Host copy-in validates and plans recursive files/directories, rejects symlinks/junctions/reparse points, and streams file contents into isolated guest paths. Copy-out validates guest paths and Windows destinations, rejects traversal and unsafe names, uses temp paths plus rename, and requires explicit overwrite for existing host destinations. File contents move over the existing guest file protocol with optional chunked `file_range_io` ranges.
- Review follow-up: commit `db601e7` enforces same-kind copy-out overwrite semantics before deleting an existing destination, validates guest chunk lengths and final byte counts against stat size, and replaces ASCII-only collision folding with best-effort Unicode lowercase folding plus an explicit no-normalization limitation test.
- Tests run: `cargo fmt --all -- --check`; `cargo check --workspace`; `cargo check -p lsb-platform -p lsb-vm --target x86_64-pc-windows-msvc`; `git diff --check`; `cargo test -p lsb-proto file_range -- --nocapture`; `cargo test -p lsb-guest file_range -- --nocapture`; `cargo test -p lsb-platform windows_x86_64::fs -- --nocapture`; `cargo test -p lsb-vm file_response_reader_skips_guest_ready_frames -- --nocapture`; `cargo test --workspace`; `./scripts/win-gh-test unit` run `28709993970`; `./scripts/win-gh-test smoke` run `28710026075`.
- Review follow-up tests: `cargo test -p lsb-vm chunk_validation -- --nocapture`; `cargo check -p lsb-vm --tests --target x86_64-pc-windows-msvc`; `cargo check -p lsb-platform --tests --target x86_64-pc-windows-msvc`; `./scripts/win-gh-test unit` run `28710951842`; `./scripts/win-gh-test smoke` run `28710991403`.
- Debug artifacts: self-hosted Windows runs uploaded `windows-lsb-diagnostics`; smoke run `28710026075` also uploaded `windows-boot-assets`.
- New decisions: none; implementation follows D009/D010/D011.
- New risks: none added. Known limitations: conservative symlink/junction/reparse rejection, no live shared mount semantics, no Windows mount parity with macOS VirtioFS, and Windows streaming/muxed control sessions remain deferred.
- Next milestone: M10 Mount MVP semantics can build on M09 copy-in at sandbox start and explicit copy-out/export at sandbox end or on demand.

Security review:
- No-network default preserved: yes
- Secret redaction verified: yes, no file contents are logged
- Host file exposure reviewed: yes, host source is copied into guest storage and not exposed as a writable host mount
- Control/QMP endpoint privacy reviewed: n/a for this milestone; existing virtio-serial/QMP privacy unchanged
- Process cleanup reviewed: n/a for this milestone
- New risks added to risk-register.md: no
