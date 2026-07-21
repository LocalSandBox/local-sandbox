# SeaWork test-release sprint state

- Updated: 2026-07-22
- LocalSandbox baseline: candidate source `feat/lsb-win-service` at `7d87dcb4fc2efa3a55f9e754ee79c0684249be3d`; exact-archive acceptance and final fast-gate harness at `42c4c59c73e748f05b3bc11681754010dd598802`
- SeaWork baseline inspected: frozen contract `test` at `f9c6cd8ff339688a669451e36078d6cbbc91c1b2`; current clean read-only `main`/`v1.3.2` at `be189da04a5dbdcb8641e12c997ae5567311d879`, with compatible 0.4.7 package, cancellation, and scoped HTTPS User-Agent drift recorded in the handoff
- Candidate version: `0.4.7-test.1`
- Current milestone: `TR-5 complete for the authorized non-reboot scope; TR-6 remains SeaWork-owned`
- Status: TR-0 through TR-5 non-reboot gates pass; the signed production-identity candidate, fetched tuple, exact-archive acceptance, filtered-token runtime matrix, cleanup/uninstall proof, final host gates, and verified artifact-reuse retry are complete; reboot continuation is explicitly deferred by the user
- Next action: when reboot tests are re-authorized, use a clean worktree at `7d87dcb4fc2efa3a55f9e754ee79c0684249be3d`, sign in the existing Windows user after restart, and run `scripts/win-test reboot service-reboot --reuse-candidate 20260721t205247z-36771-34b3bad4e664`; until then the SeaWork owner may proceed with TR-6 against the pinned tuple
- LocalSandbox candidate: complete for the authorized non-reboot scope; manifest intentionally reports only `reboot-continuation` pending
- Overall test release: blocked on SeaWork-owned TR-6 NSIS/adapter evidence; reboot tests are recorded as pending but are not a current blocker under explicit user direction
- Active blockers: none for authorized LocalSandbox work; pending evidence is post-reboot delayed-auto-start/health/sandbox/cleanup, plus separate-account profile behavior (not validated and not claimed)
- Latest Windows evidence: installed-service run `20260721t205247z-36771-34b3bad4e664` passed all non-reboot cases; exact-archive acceptance `20260721t211858z-46201-825090ca54cd` passed; verified-reuse installed-service run `20260721t212708z-49738-a8194f6f31fb` passed; current-tree `service-fast` `20260721t212415z-48692-2930615cef09` passed
- Handoff: `docs/seawork-test-release-handoff.md` (final LocalSandbox tuple appended; TR-6/reboot evidence remains append-only and open)

Update only these fields as work advances. Put implementation history in commits,
Windows result manifests, and append-only handoff entries rather than growing this file.
