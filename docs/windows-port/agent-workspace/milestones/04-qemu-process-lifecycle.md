# M04: QEMU Process Lifecycle and Cleanup

Status: Done
Depends on: See `00-index.md`
RFC sections: See `traceability.md`

## Objective

Start, supervise, stop, and kill QEMU reliably on Windows.

## Scope

- Implement process launch wrapper using argv from M03.
- Capture stdout/stderr and serial artifacts.
- Use Windows Job Objects or equivalent cleanup so QEMU/helper processes are terminated.
- Implement forced process cleanup. Graceful QEMU shutdown via private QMP/control plumbing is explicitly deferred to M05/MQMP work because M04 does not implement guest boot or QMP behavior.
- Add timeouts and structured errors.

## Out of scope

- Do not require successful guest boot.
- Do not implement guest protocol.
- Do not expose QMP publicly.
- Do not leave orphan QEMU processes in tests.

## Likely files / crates

- `crates/lsb-platform/src/windows_x86_64/qemu/process.rs`
- `errors.rs`
- `diagnostics artifact helpers`

## Design notes

- Preserve existing macOS behavior unless the milestone explicitly states otherwise.
- Keep Windows-specific implementation behind platform/backend boundaries.
- Prefer precise capability errors over silent degradation.
- Update `state.md` when implementation reveals a better file layout or dependency.

## Tests to add or update

The specific tests should match the implementation, but this milestone must include enough validation to satisfy the acceptance criteria below. Prefer unit/golden/fake tests before requiring self-hosted integration tests.

## Acceptance criteria

- [x] Fake process tests for timeout/kill.
- [x] Windows integration test for cleanup if possible.
- [x] Failure captures redacted argv and logs.
- [x] Process lifecycle works with a harmless command before QEMU-specific smoke.
- [x] Graceful shutdown deferral is documented; M04 terminate/kill/drop cleanup is forced only.

## Coding-agent prompt

```text
You are implementing M04: QEMU Process Lifecycle and Cleanup for the LocalSandbox Windows QEMU + WHPX port.

Read first:
- docs/windows-port/rfc-qemu-whpx.md
- docs/windows-port/AGENTS.md
- docs/windows-port/agent-workspace/state.md
- docs/windows-port/agent-workspace/decisions.md
- docs/windows-port/agent-workspace/milestones/04-qemu-process-lifecycle.md

Implement only this milestone. Preserve public CLI/SDK/Node APIs and existing macOS behavior. Add tests required by the milestone. Do not implement later milestones opportunistically. Update state.md and this milestone handoff before finishing.
```

## Security checklist

Complete the checklist in `../security-checklist.md`. Record any new risk in `../risk-register.md`.

## Handoff

- Branch/PR: `codex/windows-m04-qemu-lifecycle`
- Summary: Added private Windows QEMU supervisor functionality under `lsb-platform::windows_x86_64::qemu::process`. The supervisor consumes the M03 `QemuCommand`, validates absolute executable and working-directory paths, launches with `Command::args` rather than a shell, redirects stdout/stderr to deterministic files, writes redacted argv and status artifacts, tracks lifecycle state, rejects supervisor reuse after terminal states, detects early exits and WHPX-like runtime mismatch errors, supports wait timeout and idempotent forced terminate/kill/drop cleanup, and uses a Windows Job Object with kill-on-close on Windows. Graceful QEMU shutdown via private QMP/control plumbing is deferred to M05/MQMP work. The public Windows VM backend remains a capability-error stub; no guest boot or readiness is claimed.
- Tests run: See `../state.md` for the final validation log and Windows hardware run IDs. Final review-fix validation included `cargo fmt --all -- --check`; `cargo check --workspace`; `cargo test --workspace`; `cargo test -p lsb-platform windows_x86_64::qemu::process -- --nocapture`; `cargo check -p lsb-platform --target x86_64-pc-windows-msvc`; `./scripts/win-gh-test check`; and `./scripts/win-gh-test unit`. `cargo check --workspace --target x86_64-pc-windows-msvc` was attempted from macOS and remains blocked by external Windows/MSVC C/assembler tooling for transitive crates (`ring` missing `assert.h`, `blake3` missing `ml64.exe`).
- Debug artifacts: Runtime writes `qemu.argv.redacted.txt`, `qemu.stdout.log`, `qemu.stderr.log`, and `qemu.status.json` under the supplied diagnostics directory. Unit tests create temporary artifacts and remove them after successful assertions.
- New decisions: None.
- New risks: None.
- Security review: no-network default preserved: yes, no QEMU networking is added; secret redaction verified: yes, argv artifacts use M03 redaction, the default QEMU environment does not inherit parent secrets, and status artifacts include only environment override counts, not values; host file exposure reviewed: yes, only diagnostics paths are created/written; control/QMP endpoint privacy reviewed: n/a, no new endpoints and no QMP protocol behavior; process cleanup reviewed: yes, drop/terminate is idempotent, Windows uses Job Object kill-on-close, and graceful QMP shutdown is deferred; new risks added to risk-register.md: no.
- Next milestone: M05 direct Linux boot and serial logs. M05 should create/choose per-instance disk/artifact paths, run QEMU through the private supervisor, add or reserve the private graceful shutdown/QMP path before disk/checkpoint work depends on clean QEMU exit, and still avoid guest readiness, virtio-serial protocol, networking, mounts, checkpoints, and Node packaging until their milestones.
