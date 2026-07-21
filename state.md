# SeaWork test-release sprint state

- Updated: 2026-07-21
- LocalSandbox baseline: `feat/lsb-win-service` at `5ac5ca67b3acb5a5dd45a1dc44c62d213cd5db8f`
- SeaWork baseline inspected: contract `test` at `f9c6cd8ff339688a669451e36078d6cbbc91c1b2`; current read-only `dev` at `773e15b2a06e8339f236db124c824a07457b901d` with no relevant runtime/installer drift
- Candidate version: `0.4.7-test.1`
- Current milestone: `TR-2 — Build a safe native Windows release harness`
- Status: TR-1 source bridge and source gates pass; TR-2 signed candidate construction passes; installed-smoke diagnostics fixed invalid test ACL, partial cleanup, PowerShell signing invocation, and SCM preshutdown configuration, but runtime acceptance remains
- Next action: restore Windows SSH connectivity, rerun the focused install diagnostic against commit `5ac5ca6`, then run the exact-commit `installed-service-smoke`
- LocalSandbox candidate: not ready
- Overall test release: blocked on LocalSandbox candidate and mandatory SeaWork NSIS/adapter work
- Active blockers: Windows test host SSH endpoint timed out on three consecutive checks; commit `5ac5ca6` needs native validation when the host returns
- Latest Windows evidence: passing `release-candidate` `20260721t100654z-31135-44e86e10c29a`; failed install diagnostic `20260721t105958z-83144-3601e3818652` reached trusted Node signing and SCM creation before exposing the unsupported `sc.exe preshutdown` call fixed in `5ac5ca6`
- Handoff: `docs/seawork-test-release-handoff.md` (initial draft; append-only)

Update only these fields as work advances. Put implementation history in commits,
Windows result manifests, and append-only handoff entries rather than growing this file.
