# M08: Exec Command

Status: Review
Depends on: See `00-index.md`
RFC sections: See `traceability.md`

## Objective

Run a command in the Windows-hosted Linux guest and return stdout, stderr, and exit status through existing LocalSandbox APIs.

## Scope

- Wire `Sandbox::exec` or equivalent through Windows backend.
- Preserve existing exec request/response semantics.
- Handle stdout/stderr streaming and backpressure.
- Support timeout/kill behavior consistent with existing product behavior.
- Add basic environment handling with secret redaction.

## Out of scope

- Do not implement mounts beyond what exec needs.
- Do not enable guest networking.
- Do not copy host secrets into the guest except approved placeholders.

## Likely files / crates

- `crates/lsb-vm/src/sandbox.rs`
- `crates/lsb-guest` exec handler
- `Windows control transport`

## Design notes

- Preserve existing macOS behavior unless the milestone explicitly states otherwise.
- Keep Windows-specific implementation behind platform/backend boundaries.
- Prefer precise capability errors over silent degradation.
- Update `state.md` when implementation reveals a better file layout or dependency.

## Tests to add or update

The specific tests should match the implementation, but this milestone must include enough validation to satisfy the acceptance criteria below. Prefer unit/golden/fake tests before requiring self-hosted integration tests.

## Acceptance criteria

- [x] Exec `true`, `echo`, failing command, large stdout, and stderr coverage. Timeout/kill is exposed through streaming `spawn`, which remains explicitly unsupported on Windows until the muxed control transport work.
- [x] Exit status preserved.
- [x] No guest NIC in exec smoke argv.
- [x] Public API unchanged.

## Coding-agent prompt

```text
You are implementing M08: Exec Command for the LocalSandbox Windows QEMU + WHPX port.

Read first:
- docs/windows-port/rfc-qemu-whpx.md
- docs/windows-port/AGENTS.md
- docs/windows-port/agent-workspace/state.md
- docs/windows-port/agent-workspace/decisions.md
- docs/windows-port/agent-workspace/milestones/08-exec-command.md

Implement only this milestone. Preserve public CLI/SDK/Node APIs and existing macOS behavior. Add tests required by the milestone. Do not implement later milestones opportunistically. Update state.md and this milestone handoff before finishing.
```

## Security checklist

Complete the checklist in `../security-checklist.md`. Record any new risk in `../risk-register.md`.

## Handoff

- Branch/PR: `codex/windows-m08-exec-command`
- Summary: Implemented non-interactive Windows guest exec over the existing LocalSandbox exec protocol on the established virtio-serial control stream. The path supports argv, env, cwd, stdout, stderr, exit status, EOF-before-exit errors, and guest protocol errors through the existing platform-neutral result shape. Windows streaming `spawn`/kill remains a precise unsupported case until a muxed transport exists.
- Tests run: `cargo fmt --all -- --check`; `cargo check --workspace`; `cargo test -p lsb-vm exec_ -- --nocapture`; `cargo test -p lsb-platform windows_qemu_boot_smoke -- --ignored --nocapture`; `cargo test --workspace`; `cargo check -p lsb-vm --tests --target x86_64-pc-windows-msvc`; `cargo check -p lsb-platform --tests --target x86_64-pc-windows-msvc`; `git diff --check HEAD`. `cargo check --workspace --target x86_64-pc-windows-msvc` remains blocked on this macOS host by missing Windows/MSVC C/assembler tooling for transitive crates. Windows hardware smoke run `28704870031` is pending terminal result.
- Debug artifacts: Windows hardware run `28704870031` prepared boot assets successfully and queued `Windows native smoke/e2e`; update with uploaded artifact ID when the run finishes.
- New decisions: None. M08 uses the established virtio-serial control stream and adds only a backward-compatible `ExecRequest.stdin_closed` compatibility field.
- New risks: None added.
- Next milestone: M09 copy-in/copy-out data plane.

Security review:
- No-network default preserved: yes; the smoke boot argv now asserts `-nic none`.
- Secret redaction verified: yes; M08 does not add protocol tracing or new env logging.
- Host file exposure reviewed: yes; no copy, mount, or host file sharing behavior was added.
- Control/QMP endpoint privacy reviewed: yes; M08 reuses the private M06 virtio-serial control transport and does not expose QMP.
- Process cleanup reviewed: yes; smoke scaffolding stops QEMU after command completion, and existing supervisor cleanup remains unchanged.
- New risks added to risk-register.md: no
