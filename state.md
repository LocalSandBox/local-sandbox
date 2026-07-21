# SeaWork test-release sprint state

- Updated: 2026-07-21
- LocalSandbox baseline: `feat/lsb-win-service` at `8209b4d0449c4c036555b02c154e08c7dd12fd8f`
- SeaWork baseline inspected: contract `test` at `f9c6cd8ff339688a669451e36078d6cbbc91c1b2`; current read-only `dev` at `773e15b2a06e8339f236db124c824a07457b901d` with no relevant runtime/installer drift
- Candidate version: `0.4.7-test.1`
- Current milestone: `TR-2 — Build a safe native Windows release harness`
- Status: TR-1 source bridge and source gates pass; TR-2 protected assets, artifact fetch, fast suite, and signed release-candidate construction pass; TR-1/TR-2 installed production-identity runtime gates remain
- Next action: rerun the release candidate against commit `8209b4d`, then run and fix `installed-service-smoke`
- LocalSandbox candidate: not ready
- Overall test release: blocked on LocalSandbox candidate and mandatory SeaWork NSIS/adapter work
- Active blockers: none; installed runtime defects, if any, remain to be discovered by the next gate
- Latest Windows evidence: `20260721t100654z-31135-44e86e10c29a` (`release-candidate`, passed for `0.4.7-test.1`; snapshot `44e86e10c29a5ea151a803ff7aea6de7458840d7` based on commit `dd26449d6dab7c4beafc35125f34d9150c3c0c3e`; validated tree was committed as `8209b4d0449c4c036555b02c154e08c7dd12fd8f`)
- Handoff: `docs/seawork-test-release-handoff.md` (initial draft; append-only)

Update only these fields as work advances. Put implementation history in commits,
Windows result manifests, and append-only handoff entries rather than growing this file.
