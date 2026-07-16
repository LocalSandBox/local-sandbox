# Windows service implementation state

## Status

Ready to begin Phase 0 of [plan.md](plan.md).

- Baseline branch: `feat/lsb-win-service`
- Investigated commit: `c9e447cec349723f6e70ee3b78dd429af171e879`
- LocalSandbox version: `0.4.6`
- Current repository change: planning documents only; no production implementation exists
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
| 0 | Next | Prove Session 0 WHPX/QEMU, SMB, watches, WFP, networking, and teardown on real Windows |
| 1 | Pending | Add protocol model, SCM shell, protected configuration, and ledger primitives |
| 2 | Pending | Add pipe identity, mutual authentication, sessions, quotas, and authorization foundation |
| 3 | Pending | Add handle-safe paths, staged mounts, privileged-resource ledger, and recovery |
| 4 | Pending | Move sandbox lifecycle behind the service; add Job and WFP containment |
| 5 | Pending | Complete RPC plus the upstream Rust/Node client |
| 6 | Pending | Build/sign/package the artifact and complete the SeaWork integration contract |

Do not expose the full privileged RPC surface before Phases 1–3 are complete. Packaging remains last.

## Start here

1. Read repository instructions.
2. Read `plan.md` section 1's “How to use this plan” map—not the entire plan.
3. For the current Phase 0 slice, read sections 2, 3, 4, 5, 6, 8, 11/Phase 0, 12, and 14. Consult section 15 only for sources needed now.
4. Recheck the branch, HEAD, worktree, toolchain, and dependency versions; preserve unrelated changes.
5. Implement only Phase 0, retaining its reproducible Windows harness and evidence document.
6. Do not start Phase 1 until the Phase 0 acceptance gate is recorded.
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
