# M15: CI and Diagnostics Hardening

Status: Done
Depends on: See `00-index.md`
RFC sections: See `traceability.md`

## Objective

Harden the Windows port with hosted compile/golden CI, self-hosted WHPX smoke tests, and useful artifacts.

## Scope

- Add hosted Windows jobs for compile/unit/golden tests.
- Add self-hosted Windows 11 WHPX jobs for ignored/integration tests.
- Upload redacted debug artifacts on failure.
- Document runner setup and labels.
- Add diagnostic commands to docs.

## Out of scope

- Do not require WHPX on hosted runners.
- Do not upload secrets or unredacted env.
- Do not make flaky boot smoke block unrelated hosted unit tests.

## Likely files / crates

- `.github/workflows/*`
- `test helpers`
- `diagnostics docs`
- `runner setup docs`

## Design notes

- Preserve existing macOS behavior unless the milestone explicitly states otherwise.
- Keep Windows-specific implementation behind platform/backend boundaries.
- Prefer precise capability errors over silent degradation.
- Update `state.md` when implementation reveals a better file layout or dependency.

## Tests to add or update

The specific tests should match the implementation, but this milestone must include enough validation to satisfy the acceptance criteria below. Prefer unit/golden/fake tests before requiring self-hosted integration tests.

## Acceptance criteria

- [x] Hosted Windows compile/golden job is defined in `.github/workflows/ci.yml` for `windows-latest` and is safe for PR/main CI because it does not require QEMU/WHPX.
- [x] Self-hosted WHPX boot/smoke job is manual-only in `.github/workflows/windows-lsb-hardware.yml`, targets `[self-hosted, Windows, X64]`, verifies the runner contract, and passed in run `28743977168`.
- [x] Failure artifacts include redacted argv, serial/QEMU/preflight artifacts when produced, allowlisted environment summary, diagnostic manifest, and timestamp-bounded redacted runner logs through `scripts/collect-windows-diagnostics.ps1`.
- [x] Runner setup documented in `../runner-setup.md`.

## Coding-agent prompt

```text
You are implementing M15: CI and Diagnostics Hardening for the LocalSandbox Windows QEMU + WHPX port.

Read first:
- docs/windows-port/rfc-qemu-whpx.md
- docs/windows-port/AGENTS.md
- docs/windows-port/agent-workspace/state.md
- docs/windows-port/agent-workspace/decisions.md
- docs/windows-port/agent-workspace/milestones/15-ci-diagnostics-hardening.md

Implement only this milestone. Preserve public CLI/SDK/Node APIs and existing macOS behavior. Add tests required by the milestone. Do not implement later milestones opportunistically. Update state.md and this milestone handoff before finishing.
```

## Security checklist

Complete the checklist in `../security-checklist.md`. Record any new risk in `../risk-register.md`.

## Handoff

- Branch/PR: `codex/windows-m15-ci-diagnostics`
- Summary: Added hosted Windows Rust compile/unit/golden CI, preserved macOS CI, kept WHPX tests in a manual self-hosted Windows 11 workflow, added centralized redacted diagnostics collection/upload, wired stable Windows smoke coverage and packed Node npm install/import validation into the self-hosted smoke lane, and updated runner/validation/diagnostics/risk documentation. Review follow-up made the diagnostics stage root fresh per run, scoped asset diagnostics to the current run, and bounded optional runner `_diag` log collection.
- Tests run: local macOS `cargo fmt --all -- --check`, Ruby YAML parse of `.github/workflows/*.yml`, `git diff --check`, `cargo check --workspace`, `cargo test -p lsb-platform windows_x86_64::qemu::argv`, `cargo test -p lsb-platform preflight`, `cargo test --workspace`; self-hosted `./scripts/win-gh-test smoke` passed in run `28743977168`; review follow-up ran a synthetic `pwsh` collector regression for stale stage cleanup, current-run asset scoping, and timestamp-filtered runner logs plus the hosted-CI-style collector probe.
- Tests not run: hosted `CI` workflow did not run on the feature branch because it is configured for `main` pushes and pull requests; local `cargo check --workspace --target x86_64-pc-windows-msvc` remains blocked on this macOS host by missing Windows/MSVC headers/tooling (`assert.h`, `windows.h`, Visual Studio generator, `ml64.exe`); local PowerShell syntax checks were not run because `pwsh`/`powershell` are not installed on this host, but the self-hosted runner executed the PowerShell smoke and collector scripts.
- Debug artifacts: failed smoke run `28743854654` uploaded `windows-lsb-diagnostics` artifact `8092669489`; final passing smoke run `28743977168` uploaded `windows-lsb-diagnostics` artifact `8092721984`.
- New decisions: None.
- New risks: R013 records the default-label single-runner/cache-routing assumption for the self-hosted Windows runner pool.
- Next milestone: The planned Windows port milestone sequence M01-M15 is complete for review; remaining work is release/production hardening, not a new implementation milestone in this sequence.
