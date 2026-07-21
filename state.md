# SeaWork test-release sprint state

- Updated: 2026-07-21
- LocalSandbox baseline: `feat/lsb-win-service` at `0470b57be237d181b04dbd558cec4eb2fddebd5c`
- SeaWork baseline inspected: contract `test` at `f9c6cd8ff339688a669451e36078d6cbbc91c1b2`; current read-only `dev` at `773e15b2a06e8339f236db124c824a07457b901d` with no relevant runtime/installer drift
- Candidate version: `0.4.7-test.1`
- Current milestone: `TR-2 — Build a safe native Windows release harness`
- Status: TR-1 source bridge committed and source gates pass; TR-1 runtime gate awaits the signed installed-service harness run; TR-2 protected signing/runtime assets and artifact fetch pass; versioned Windows fast gate and signed PE pass, but bundle catalog is blocked by empty QEMU files
- Next action: resolve whether to newline-normalize 50 inert empty QEMU cache/icon placeholders or build a custom catalog writer, then finish release-candidate and installed-service-smoke
- LocalSandbox candidate: not ready
- Overall test release: blocked on LocalSandbox candidate and mandatory SeaWork NSIS/adapter work
- Active blockers: MakeCat cannot catalog zero-byte files; the pinned QEMU tree has 50 inert empty cache/icon placeholders, requiring an explicit payload-normalization versus custom-catalog decision
- Latest Windows evidence: `20260721t093545z-10582-bd0575284ff0` (`service-fast`, passed for `0.4.7-test.1`; snapshot `bd0575284ff0f6bccec5f05aed8016b2b08fabfc` based on commit `5f1c3cbc12c82cc2a0c1790b1dbb3147263af219`)
- Handoff: `docs/seawork-test-release-handoff.md` (initial draft; append-only)

Update only these fields as work advances. Put implementation history in commits,
Windows result manifests, and append-only handoff entries rather than growing this file.
