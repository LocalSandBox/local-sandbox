# M03: QEMU Argv Builder

Status: Done
Depends on: See `00-index.md`
RFC sections: See `traceability.md`

## Objective

Create deterministic, testable QEMU argv construction for the Windows backend.

## Scope

- Build minimal direct Linux boot argv.
- Add rootfs virtio-blk args.
- Add serial console log args.
- Add virtio-serial control chardev args.
- Add private QMP endpoint args if needed for lifecycle diagnostics.
- Ensure default argv contains no guest NIC.
- Provide redacted argv rendering.

## Out of scope

- Do not spawn QEMU.
- Do not implement process cleanup.
- Do not enable QEMU user networking by default.
- Do not include secrets in argv.

## Likely files / crates

- `crates/lsb-platform/src/windows_x86_64/qemu/argv.rs`
- `tests under `crates/lsb-platform/tests/` or module tests`

## Design notes

- Preserve existing macOS behavior unless the milestone explicitly states otherwise.
- Keep Windows-specific implementation behind platform/backend boundaries.
- Prefer precise capability errors over silent degradation.
- Update `state.md` when implementation reveals a better file layout or dependency.

## Tests to add or update

The specific tests should match the implementation, but this milestone must include enough validation to satisfy the acceptance criteria below. Prefer unit/golden/fake tests before requiring self-hosted integration tests.

## Acceptance criteria

- [x] Golden tests for minimal boot argv.
- [x] Golden tests for virtio-serial + QMP argv.
- [x] Golden test proving no network device by default.
- [x] Path quoting/escaping tests for Windows paths.
- [x] Redacted argv test.

## Coding-agent prompt

```text
You are implementing M03: QEMU Argv Builder for the LocalSandbox Windows QEMU + WHPX port.

Read first:
- docs/windows-port/rfc-qemu-whpx.md
- docs/windows-port/AGENTS.md
- docs/windows-port/agent-workspace/state.md
- docs/windows-port/agent-workspace/decisions.md
- docs/windows-port/agent-workspace/milestones/03-qemu-argv-builder.md

Implement only this milestone. Preserve public CLI/SDK/Node APIs and existing macOS behavior. Add tests required by the milestone. Do not implement later milestones opportunistically. Update state.md and this milestone handoff before finishing.
```

## Security checklist

Complete the checklist in `../security-checklist.md`. Record any new risk in `../risk-register.md`.

## Handoff

- Branch/PR: `codex/windows-m03-qemu-argv-builder`
- Summary: Added private Windows QEMU config and argv builder modules under `lsb-platform::windows_x86_64::qemu`. The builder returns a program path plus structured `Vec<OsString>` argv for WHPX direct Linux boot, virtio-blk root disk, serial output, optional virtio-serial control pipe placeholder, optional private QMP pipe, and explicit `-nic none`. Added redacted diagnostic rendering. No QEMU process is spawned and no Windows runtime support is claimed.
- Tests run: `cargo fmt --all -- --check`; `cargo check --workspace`; `cargo test -p lsb-platform`; `cargo test --workspace`; `cargo check -p lsb-platform --target x86_64-pc-windows-msvc`. `cargo check --workspace --target x86_64-pc-windows-msvc` was attempted from macOS and remains blocked by external Windows/MSVC C/assembler tooling for transitive crates.
- Debug artifacts: None.
- New decisions: None.
- New risks: None.
- Security review: no-network default preserved: yes; secret redaction verified: yes for diagnostics; host file exposure reviewed: n/a, argv paths only; control/QMP endpoint privacy reviewed: yes, QMP supports private named pipe only; process cleanup reviewed: n/a, no process lifecycle; new risks added to risk-register.md: no.
- Next milestone: M04 QEMU process lifecycle.
