# AGENTS.md: Windows Port Implementation Rules

This file scopes Codex-agent behavior for the LocalSandbox Windows port.

## Source of truth order

1. `docs/windows-port/rfc-qemu-whpx.md`
2. `docs/windows-port/agent-workspace/state.md`
3. `docs/windows-port/agent-workspace/decisions.md`
4. The current milestone document under `docs/windows-port/agent-workspace/milestones/`
5. Existing repo code and tests

When these disagree, stop and record the conflict in `state.md`. Do not silently redesign the port.

## Working rules

- Implement exactly one milestone per branch or issue unless the issue explicitly says otherwise.
- Do not change public CLI, Rust SDK, or Node API semantics unless the milestone says so and `decisions.md` has a recorded decision permitting it.
- Preserve LocalSandbox product semantics: Linux guest, no network by default, controlled egress through LocalSandbox policy, host source mounts read-only from the product perspective, guest writes isolated, explicit result export, and clear checkpoint semantics.
- QEMU + WHPX is the Windows MVP backend. Do not introduce HCS, Hyper-V Manager VMs, WSL2, Docker, or raw WHP VMM work in implementation milestones.
- Production Windows runs must require WHPX. TCG may exist only behind an explicit hidden/debug flag or environment variable.
- Do not expose secrets in logs, QEMU argv examples, panic messages, tests, or snapshots.
- Do not bind QMP, control pipes, debug sockets, or port-forward listeners on non-loopback addresses unless an approved decision says otherwise.
- Keep platform-specific implementation details below platform/backend crates. `lsb-vm`, `lsb-sdk`, CLI, and Node surfaces should stay platform-neutral.

## Windows hardware testing

- Use `./scripts/win-gh-test check` after platform or portability changes.
- Use `./scripts/win-gh-test unit` before opening a PR that touches Windows code.
- Use `./scripts/win-gh-test smoke` after QEMU, WHPX, VM lifecycle, transport, or guest-control changes.
- Use `./scripts/win-gh-test e2e` only when the Windows backend and test assets are ready for the broader hardware suite.
- The script requires a clean committed working tree because GitHub Actions can only test pushed commits.
- Do not add automatic `pull_request` triggers for the self-hosted Windows hardware runner.

## Required updates at the end of every milestone

Update all relevant files:

- `agent-workspace/state.md`: status, branch/commit, tests run, open blockers.
- Current milestone doc: mark checklist items as done or intentionally deferred.
- `agent-workspace/decisions.md`: only if the implementation required a new or changed decision.
- `agent-workspace/validation.md`: only if new commands, runners, or evidence were added.
- `agent-workspace/risk-register.md`: only if a risk was discovered, retired, or changed.

## Completion bar

A milestone is complete only when:

- Code builds on the intended platform targets for that milestone.
- Unit/golden tests required by the milestone pass.
- The implementation preserves public API compatibility unless explicitly scoped otherwise.
- Failure modes produce actionable errors.
- Logs and diagnostics are redacted where necessary.
- The milestone handoff section is filled out.
