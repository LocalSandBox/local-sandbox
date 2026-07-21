# SeaWork test-release sprint state

- Updated: 2026-07-21
- LocalSandbox baseline: `feat/lsb-win-service` at `0470b57be237d181b04dbd558cec4eb2fddebd5c`
- SeaWork baseline inspected: `test` at `f9c6cd8ff339688a669451e36078d6cbbc91c1b2`
- Candidate version: `0.4.7-test.1`
- Current milestone: `TR-2 — Build a safe native Windows release harness`
- Status: TR-1 source bridge committed and source gates pass; TR-1 runtime gate awaits the signed installed-service harness run; TR-2 harness foundation committed and service-fast passes
- Next action: obtain explicit approval to transfer the PFX/password into the protected Windows asset root, provision runtime/QEMU assets, then run release-candidate and installed-service-smoke
- LocalSandbox candidate: not ready
- Overall test release: blocked on LocalSandbox candidate and mandatory SeaWork NSIS/adapter work
- Active blockers: security approval denied remote transfer of the external signing PFX/password; explicit user authorization is required before retrying
- Latest Windows evidence: `20260721t083424z-79176-6fe4821c2f3a` (`service-fast`, passed; snapshot `6fe4821c2f3a59f27aef5c831645edf603affe4b`)
- Handoff: `docs/seawork-test-release-handoff.md` (initial draft; append-only)

Update only these fields as work advances. Put implementation history in commits,
Windows result manifests, and append-only handoff entries rather than growing this file.
