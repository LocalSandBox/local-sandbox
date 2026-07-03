# M02: QEMU Discovery and WHPX Preflight

Status: Done
Depends on: See `00-index.md`
RFC sections: See `traceability.md`

## Objective

Find `qemu-system-x86_64.exe`, validate that the host is eligible for production Windows runs, and provide actionable diagnostics.

## Scope

- Implement QEMU path discovery in priority order: explicit config/env, then PATH.
- Capture QEMU version.
- Validate Windows 11 x86_64 host assumption where feasible.
- Validate WHPX availability through safe preflight checks.
- Prepare or implement `lsb doctor windows` if the CLI architecture supports it.

## Out of scope

- Do not boot a VM.
- Do not use TCG in normal paths.
- Do not download or bundle QEMU.
- Do not require admin permissions for normal preflight.

## Likely files / crates

- `crates/lsb-platform/src/windows_x86_64/qemu/discovery.rs`
- `crates/lsb-platform/src/windows_x86_64/qemu/preflight.rs`
- `crates/lsb-cli` diagnostics path

## Design notes

- Preserve existing macOS behavior unless the milestone explicitly states otherwise.
- Keep Windows-specific implementation behind platform/backend boundaries.
- Prefer precise capability errors over silent degradation.
- Update `state.md` when implementation reveals a better file layout or dependency.

## Tests to add or update

The specific tests should match the implementation, but this milestone must include enough validation to satisfy the acceptance criteria below. Prefer unit/golden/fake tests before requiring self-hosted integration tests.

## Acceptance criteria

- [x] Unit tests for discovery precedence.
- [x] Diagnostics are specific for missing QEMU, unsupported version, non-Windows-11, WHPX unavailable.
- [x] Redacted output avoids environment dumps.
- [x] Manual/self-hosted evidence recorded in `state.md` if available.

## Coding-agent prompt

```text
You are implementing M02: QEMU Discovery and WHPX Preflight for the LocalSandbox Windows QEMU + WHPX port.

Read first:
- docs/windows-port/rfc-qemu-whpx.md
- docs/windows-port/AGENTS.md
- docs/windows-port/agent-workspace/state.md
- docs/windows-port/agent-workspace/decisions.md
- docs/windows-port/agent-workspace/milestones/02-qemu-discovery-preflight.md

Implement only this milestone. Preserve public CLI/SDK/Node APIs and existing macOS behavior. Add tests required by the milestone. Do not implement later milestones opportunistically. Update state.md and this milestone handoff before finishing.
```

## Security checklist

Complete the checklist in `../security-checklist.md`. Record any new risk in `../risk-register.md`.

## Handoff

- Branch/PR: `codex/windows-m02-qemu-discovery-preflight`
- Summary: Added private Windows QEMU discovery and preflight scaffolding under `lsb-platform`. Discovery checks `LSB_QEMU`, an optional internal config hook, then `PATH`; version probing runs `--version`; suitability probing runs `--help`; WHPX probing runs `-accel help`. The implementation returns structured actionable errors and includes fake host/runner tests plus an ignored real-QEMU hook. No VM boot, QEMU argv builder, process lifecycle, or TCG production fallback was added.
- Tests run:
  - `cargo fmt --all -- --check` - pass
  - `cargo check --workspace` - pass
  - `cargo test --workspace` - pass, 67 passed and 1 ignored real-QEMU hook
  - `cargo check -p lsb-platform --target x86_64-pc-windows-msvc` - pass
  - `./scripts/win-gh-test check` - pass, run `28653449586`
  - `./scripts/win-gh-test unit` - pass, run `28653507512`
- Debug artifacts: none local. Windows workflow diagnostic artifact upload step completed in runs `28653449586` and `28653507512`.
- New decisions: none.
- New risks: none.
- Security review:
  - No-network default preserved: yes, no QEMU argv/network code was added.
  - Secret redaction verified: yes, diagnostics avoid environment dumps and PATH value dumps; tests assert PATH entries are not included in missing-QEMU output.
  - Host file exposure reviewed: n/a, only executable path metadata is checked.
  - Control/QMP endpoint privacy reviewed: n/a, no control or QMP endpoints are created.
  - Process cleanup reviewed: n/a, only short-lived version/help/accelerator probes are modeled; no VM process is started.
  - New risks added to risk-register.md: no.
- Next milestone: M03 QEMU argv builder.
