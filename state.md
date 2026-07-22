# SeaWork test-release sprint state

- Updated: 2026-07-22
- LocalSandbox baseline: interim reboot-fixed source `feat/lsb-win-service` at `edf76bfd45f483d2ab18d9faca96e2cdad4c5720`; the previously pinned non-reboot candidate was superseded by this runtime fix, and the final post-change candidate is not yet frozen
- SeaWork baseline inspected: frozen contract `test` at `f9c6cd8ff339688a669451e36078d6cbbc91c1b2`; current clean read-only `main`/`v1.3.2` at `be189da04a5dbdcb8641e12c997ae5567311d879`, with compatible 0.4.7 package, cancellation, and scoped HTTPS User-Agent drift recorded in the handoff
- Candidate version: `0.4.7-test.1`
- Current milestone: `TR-5 implementation/handoff checkpoint complete; final evidence run deferred; TR-6 remains SeaWork-owned`
- Status: the reboot-only Rust panic was diagnosed and fixed; all 66 service tests pass, and an interim signed production-identity candidate passed the full pre/post-reboot service suite with exact artifact reuse; the user expects more source changes and explicitly deferred final candidate construction, fetch, archive acceptance, full host gates, and promotion evidence
- Next action: after the planned changes are committed, follow the append-only handoff's “Required final evidence run” from a clean worktree; build a fresh candidate rather than reusing the interim tuple, sign in the existing `SGP\SG3937` desktop user after reboot, then fetch and independently verify the exact passing artifacts
- LocalSandbox candidate: interim manifest complete at `edf76bfd45f483d2ab18d9faca96e2cdad4c5720`, but deliberately not promoted as the final pin because more changes will follow
- Overall test release: not ready; final LocalSandbox evidence is deferred and SeaWork-owned TR-6 NSIS/adapter evidence remains open
- Active blockers: none in the completed runtime fix; pending work is the planned source change set plus the explicitly deferred final evidence run; separate-account profile behavior remains not validated and must not be claimed
- Latest Windows evidence: diagnostic run `20260722t045000z-wprdiag2` captured panic-abort `0xC0000409`; interim source run `20260722t045910z-65556-543cbc0e5c76` built/signed the corrected tuple; exact-reuse reboot run `20260722t052350z-77334-4a1d7c20d297` passed pre-reboot, delayed-auto post-reboot mounted-sandbox validation, filtered-current-user privilege proof, and owned uninstall
- Handoff: `docs/seawork-test-release-handoff.md` (interim reboot diagnosis/evidence and the required post-change final evidence procedure appended; TR-6 remains open)

Update only these fields as work advances. Put implementation history in commits,
Windows result manifests, and append-only handoff entries rather than growing this file.
