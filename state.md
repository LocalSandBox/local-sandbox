# Windows service implementation state

## Status

Phases 0-3 shipping foundations are implemented; Phase 4 engine containment is underway while real-machine evidence and advanced hardening are deferred.

- Baseline branch: `feat/lsb-win-service`
- Investigated commit: `c9e447cec349723f6e70ee3b78dd429af171e879`
- LocalSandbox version: `0.4.6`
- Last verified implementation commit: `5359d31` (`feat(service): launch contained processes suspended`)
- Phase 0 verification: schema test, Windows compile, isolated Clippy, and PowerShell parse pass
- Phase 1 verification: release build passes; 10 protocol and 7 service tests pass; isolated Clippy passes
- Phase 2 verification: release client/service build passes; 30 combined protocol/client/service tests pass; isolated Clippy passes
- Phase 3 verification: 27 service tests pass and isolated warning-clean Clippy passes on Windows
- Phase 4 foundation verification: 32 service tests pass and isolated warning-clean Clippy passes on Windows
- Deferred verification: the current shell is not elevated and has no prepared runtime assets, so SCM LocalSystem/WHPX/SMB execution was not run; details are in `docs/windows-service-feasibility.md`
- Phase 1 backlog: real SCM install/STOP/preshutdown timing and Event Log message compilation require an elevated machine with Windows SDK `mc.exe`/`rc.exe`; health pipe source and SDDL validation are complete
- Phase 2 backlog: real two-user/two-logon SCM tests, Authenticode publisher enforcement, service-SID/config2 verification, active process-exit monitoring, handshake/rate limits wired into the accept loop, and queue/backpressure fault injection. The client verifies SCM PID/type/account/path before sending bytes, and the service derives/cross-checks OS token identity before Hello.
- Phase 3 foundation: privileged mount roots are constructed only on a dedicated client-token filesystem thread; local fixed NTFS/ReFS, protected-root, reparse/EFS/cloud, hard-link, entry, and byte policy fails closed; RO and RW both select staged-sync; staging/export IO crosses the token boundary through held files; protected intent/commit records, exact staging identity cleanup, service ownership markers, and deterministic conflict detection are implemented.
- Phase 3 backlog: wire the capability into `lsb-platform` SMB/VM lifecycle instead of its isolated legacy path API; add handle-relative traversal/`AccessCheck`, relocated ProfileList enumeration, active change monitoring and periodic propagation, caller-token RW writeback, handle-based DACL/post-share proof, exact external account/share/ACE reconciliation, and elevated adversarial fixtures. Pinned-ro remains disabled, so none of these gaps permit raw caller-tree sharing.
- Phase 4 foundation: trusted engine paths are bundle-confined, sandbox lifecycle transitions cannot skip cleanup, Windows Jobs enforce kill-on-close/process/memory limits, and the service launcher uses explicit `CreateProcessW(CREATE_SUSPENDED)` -> Job assignment -> `ResumeThread` ordering with no PATH lookup or inherited environment. Outbound resolution rejects local/private rebinding, and host-port capability fails closed while WFP evidence is absent.
- Phase 4 next: refactor the real SDK/VM engine behind the service configuration, connect sandbox/process/watch resources to session quotas and cancellation, journal process identity before launch, implement bounded stop ordering, and either prove/install logon-SID WFP filters or keep ports disabled.
- Source of truth: `plan.md`; this file is the lightweight entry point and progress record

## Goal

Ship a LocalSandbox-owned, x86-64 Windows SCM service that SeaWork installs once per machine. After installation, standard users use sandboxes without UAC through the upstream Node client.

## Fixed design

- Rust service binary: `localsandbox-seawork-service.exe`
- SCM service: `LocalSandboxSeaWork`, delayed automatic start, `LocalSystem` MVP
- IPC: `\\.\pipe\LocalSandbox.SeaWork.v1`, with explicit DACL and mutual endpoint authentication
- Service calls Rust core directly; it does not host Electron or N-API
- SeaWork owns install/update/repair/uninstall; LocalSandbox owns service, protocol, authorization, lifecycle, and artifact
- Trusted state lives under protected `%ProgramData%\LocalSandbox\SeaWork`
- Caller `dataDir`, runtime paths, QEMU paths, identity claims, and cleanup manifests are not accepted
- Direct RW mounts always use staged-sync under the client token; pinned sharing is RO-only and requires the Phase 0/3 safety proof
- Disconnect stops that connection's resources; v1 has no persistent or adoptable sandboxes
- Production artifacts must be signed; there is no UAC/helper or insecure protocol fallback

## Implementation order

| Phase | State | Purpose |
| --- | --- | --- |
| 0 | Harness complete; real-machine evidence deferred | Prove Session 0 WHPX/QEMU, SMB, watches, WFP, networking, and teardown on real Windows |
| 1 | Source complete; elevated SCM verification deferred | Add protocol model, SCM shell, protected configuration, and ledger primitives |
| 2 | Shipping foundation complete; hardening/integration backlog | Add pipe identity, mutual authentication, sessions, quotas, and authorization foundation |
| 3 | Shipping foundation complete; SMB/adversarial integration backlog | Add handle-safe paths, staged mounts, privileged-resource ledger, and recovery |
| 4 | Foundation underway; engine integration next | Move sandbox lifecycle behind the service; add Job and WFP containment |
| 5 | Pending | Complete RPC plus the upstream Rust/Node client |
| 6 | Pending | Build/sign/package the artifact and complete the SeaWork integration contract |

Do not expose the full privileged RPC surface before Phases 1–3 are complete. Packaging remains last.

## Start here

1. Read repository instructions.
2. Read `plan.md` section 1's “How to use this plan” map—not the entire plan.
3. For the current Phase 4 slice, read sections 3, 5, 8, 9, and 11/Phase 4. Consult section 15 only for sources needed now.
4. Recheck the branch, HEAD, worktree, toolchain, and dependency versions; preserve unrelated changes.
5. Implement Phase 4 trusted service engine, sandbox resources, Job containment, and fail-closed port capability without exposing the full RPC surface.
6. Keep the Phase 0 real-machine gate in the release backlog; host ports remain disabled unless WFP isolation is proven.
7. When advancing phases, update the table and last verified commit, then follow the new phase's reading slice.

## Release-blocking evidence

- LocalSystem can run WHPX/QEMU and complete sandbox boot/exec/stop in Session 0.
- RO and staged RW SMB mounts work and clean every account, right, share, ACE, credential, and staging object.
- WFP isolates loopback ports by logon SID across users and two logons of one account, or ports remain disabled.
- Pinned-ro cannot escape through reparse/hard-link races, or all RO mounts use staged-sync.
- Crash, forced stop, and reboot reconciliation remove only provably owned resources.
- Defender/EDR, enterprise GPO, proxy/VPN, and certificate behavior is documented.
- A production Windows signing identity exists before Phase 6 can ship.

## Working rule

For each phase, implement the exact files/contracts in `plan.md`, add its tests, and stop only when its acceptance criteria pass. Never weaken an authorization or cleanup invariant to make a failing Windows test pass.
