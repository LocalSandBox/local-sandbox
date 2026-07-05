# M14: Node Packaging

Status: Review
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

- [x] Windows Node package builds. Workflow/package metadata includes `win32-x64-msvc`; self-hosted Windows smoke run `28742090397` built the local Windows native binding in release mode.
- [x] Install/import smoke passes. Source-tree Yarn install/build plus Node import/start smoke passed on Windows 11 x86_64 in run `28742090397`; packed npm artifact install remains a release-lane/M15 follow-up.
- [x] Existing darwin package behavior unchanged.
- [x] Unsupported platforms fail clearly.

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

- No-network default preserved: yes; this is packaging-only and does not change Windows QEMU networking defaults.
- Secret redaction verified: not applicable; no secret-handling or diagnostics redaction paths changed.
- Host file exposure reviewed: not applicable; no mount/copy/checkpoint data-plane behavior changed.
- Control/QMP endpoint privacy reviewed: not applicable; no control transport or QMP behavior changed.
- Process cleanup reviewed: not applicable; no VM lifecycle or process cleanup behavior changed.
- New risks added to `../risk-register.md`: no.

## Handoff

- Branch/PR: `codex/windows-m14-node-packaging`
- Summary: Added `win32-x64-msvc` package metadata, `x86_64-pc-windows-msvc` NAPI target wiring, hosted Windows build/release workflow entries, Windows x86_64 SDK-backed native binding compilation, Windows-specific missing-native and unsupported-Windows-architecture loader messaging, package-resolution/API-shape tests, Windows package docs with MVP limitations, and a self-hosted Windows Node smoke that verifies backend preflight errors and a minimal `Sandbox.start()` / `stop()` path. No QEMU binary is bundled.
- Tests run: `cargo fmt --all -- --check` passed; `git diff --check` passed; `cargo check --workspace` passed; `cargo test --workspace` passed; `cargo check --manifest-path bindings/nodejs/Cargo.toml` passed; `cargo check --manifest-path bindings/nodejs/Cargo.toml --target x86_64-pc-windows-msvc` was blocked on this macOS host by missing Windows/MSVC headers/tooling; `NPM_CONFIG_CACHE=/private/tmp/lsb-npm-cache COREPACK_HOME=/private/tmp/lsb-corepack-cache YARN_GLOBAL_FOLDER=/private/tmp/lsb-yarn-global YARN_CACHE_FOLDER=/private/tmp/lsb-yarn-cache npx --yes corepack@latest yarn install --immutable` passed; the same environment with `yarn lint` passed; the same environment with `yarn test` passed 31 AVA tests with VM-backed tests skipped for missing macOS virtualization entitlement; the same environment with `yarn napi build --platform --release --js index.js --dts index.d.ts` passed for the host target; `node scripts/patch-generated-loader.mjs` passed; `node --check bindings/nodejs/scripts/windows-preflight-smoke.mjs` passed; `./scripts/win-gh-test smoke` initially failed in run `28741753249` because the N-API error conversion hid the backend chain, then passed after commit `74027f9` in run `28742090397`; review follow-up `node --check bindings/nodejs/scripts/patch-generated-loader.mjs` passed, `git diff --check` passed, and the same temporary-cache Yarn environment passed `yarn lint` plus `yarn test` with 32 AVA tests after adding the unsupported Windows architecture loader assertion.
- Debug artifacts: none committed. Local generated native binding/build artifacts remain ignored.
- New decisions: none.
- New risks: none.
- Next milestone: M15 CI and diagnostics hardening, including packed-package npm install validation for the root package plus `win32-x64-msvc` optional artifact.
