# Windows service implementation state

## Status

Phases 0-4 shipping foundations are implemented; the Phase 5 owner-bound sandbox lifecycle RPC/client foundation is executable while the remaining guest-operation surface is in progress.

- Baseline branch: `feat/lsb-win-service`
- Investigated commit: `c9e447cec349723f6e70ee3b78dd429af171e879`
- LocalSandbox version: `0.4.6`
- Last verified implementation commit: `3896091` (`feat(client): expose cancellable exec operations`)
- Phase 0 verification: schema test, Windows compile, isolated Clippy, and PowerShell parse pass
- Phase 1 verification: release build passes; 10 protocol and 7 service tests pass; isolated Clippy passes
- Phase 2 verification: release client/service build passes; 30 combined protocol/client/service tests pass; isolated Clippy passes
- Phase 3 verification: 27 service tests pass and isolated warning-clean Clippy passes on Windows
- Phase 4 verification: 171 platform tests, 36 VM tests, and 33 service tests pass on Windows; 13 hardware/elevation tests are ignored as documented; isolated service Clippy passes with `-D warnings`
- Phase 5 RPC verification: 42 service, 6 Rust client, and 18 protocol tests pass; affected service/client/protocol Clippy passes with `--no-deps -D warnings`
- Phase 5 Node verification: the Windows binding compiles; N-API generation succeeds; 8 focused declaration/package tests pass; TypeScript declarations compile; the built addon exports `SeaWorkService`, `SeaWorkSandbox`, `SeaWorkProcess`, `SeaWorkWatch`, and `SeaWorkExecOperation`
- Deferred verification: the current shell is not elevated and has no prepared runtime assets, so SCM LocalSystem/WHPX/SMB execution was not run; details are in `docs/windows-service-feasibility.md`
- Phase 1 backlog: real SCM install/STOP/preshutdown timing and Event Log message compilation require an elevated machine with Windows SDK `mc.exe`/`rc.exe`; health pipe source and SDDL validation are complete
- Phase 2 backlog: real two-user/two-logon SCM tests, Authenticode publisher enforcement, service-SID/config2 verification, active process-exit monitoring, handshake/rate limits wired into the accept loop, and queue/backpressure fault injection. The client verifies SCM PID/type/account/path before sending bytes, and the service derives/cross-checks OS token identity before Hello.
- Phase 3 foundation: privileged mount roots are constructed only on a dedicated client-token filesystem thread; local fixed NTFS/ReFS, protected-root, reparse/EFS/cloud, hard-link, entry, and byte policy fails closed; RO and RW both select staged-sync; staging/export IO crosses the token boundary through held files; protected intent/commit records, exact staging identity cleanup, service ownership markers, and deterministic conflict detection are implemented.
- Phase 3 backlog: wire the capability into `lsb-platform` SMB/VM lifecycle instead of its isolated legacy path API; add handle-relative traversal/`AccessCheck`, relocated ProfileList enumeration, active change monitoring and periodic propagation, caller-token RW writeback, handle-based DACL/post-share proof, exact external account/share/ACE reconciliation, and elevated adversarial fixtures. Pinned-ro remains disabled, so none of these gaps permit raw caller-tree sharing.
- Phase 4 foundation: trusted engine assets are bundle-confined; the service-selected QEMU path bypasses environment, managed-tool, and PATH discovery; a dedicated service VM thread owns the real `lsb-vm::Sandbox` with protected instance paths and no caller data directory, mounts, ports, checkpoints, or host exposure. Session preparing/running slots reserve quotas before boot, freeze owner identity, propagate disconnect cancellation, and release failed starts. The separate service launcher proves `CREATE_SUSPENDED` -> Job assignment -> resume and durable process intent/commit ordering. Egress rejects local/private rebinding and host ports remain disabled while WFP evidence is absent.
- Phase 4 backlog: make the real platform QEMU supervisor consume the service-owned external Job so a VM-thread stop timeout can force-close it without detaching the thread; connect staged mounts after Phase 3 SMB capability wiring; exercise Session 0 boot/exec/stop and cancellation on prepared assets. Combined platform Clippy currently has existing unrelated warnings, so modified service code was verified with isolated `--no-deps -D warnings`.
- Phase 5 lifecycle foundation: strict start/stop/close schemas exclude trusted runtime and identity fields; installed bundle discovery is fixed to the service-adjacent runtime/QEMU layout; missing assets degrade health and close admissions. Start prepares a bounded rootfs below a stable authenticated-identity hash, session ownership and quota are reserved before boot, unsupported mounts/ports/network policy fail closed, stop is owner-bound, disconnect cancels the VM, and exact instance cleanup runs after VM stop. The Rust client exposes typed lifecycle objects and preserves stable service error envelopes.
- Phase 5 process foundation: owner-bound unary `Exec` accepts only bounded argv-or-shell commands, normalized guest cwd, and bounded environment data. It runs on the managed VM command thread with a bounded queue/deadline and a combined 8 MiB stdout/stderr ceiling; the Rust client returns a typed result. `Spawn` reserves the 64/sandbox, 128/user, and 256/global process quotas before opening a guest session, returns owner-bound process/stdout/stderr handles, and bypasses the SDK's unbounded process channels. Guest frames are split into a 64-frame/under-4-MiB queue, output stalls kill only that process after 30 seconds, kill is idempotent until the ordered exit event retires the handle, and sandbox/session cleanup kills and releases every process.
- Phase 5 file foundation: owner-bound `Mkdir`, `ReadDir`, `Stat`, `Remove`, `Rename`, `Copy`, `Chmod`, and `Exists` validate canonical guest-absolute paths and run through the bounded managed VM command queue. The Rust client exposes typed directory/stat results. `ReadFile` and `WriteFile` transfer bytes only through binary stream frames, never JSON. `WriteFile` now writes a random sibling temporary guest file and renames on success, removing the temporary file if commit fails.
- Phase 5 watch foundation: `Watch` validates a canonical guest path, reserves the 64/sandbox, 128/user, and 512/global quotas before opening the guest session, and returns an owner-bound opaque handle. The service bypasses the SDK's unbounded channel with a 256-event queue that coalesces repeated paths and collapses saturation to `Overflow`; events share the strict server event sequence and bounded writer. `StopWatch` is tombstoned/idempotent, discards buffered events before acknowledgement, and closes the cloned guest control session; sandbox/session cleanup stops and releases every watch. The Rust client installs its route before waking the caller and coalesces a slow consumer to the latest event.
- Phase 5 Node foundation: the existing N-API package now exports experimental `SeaWorkService`/`SeaWorkSandbox` remote objects backed only by `lsb-service-client`. Its generated `SeaWorkStartOptions` contains only CPU, memory, and disk, and the API-shape test rejects trusted path/identity fields. Health, lifecycle, bounded exec, guest filesystem methods, credited spawned processes, managed watches, and cancellable exec operation handles are exposed without JavaScript pipe/security code. `SeaWorkProcess` provides independently consumable bounded stdout/stderr chunks, async kill, and ordered exit; `SeaWorkWatch` provides the opaque ID, coalesced next-event reads, and async stop; `SeaWorkExecOperation` provides the full opaque request ID plus cancel/complete. The existing direct `Sandbox` API remains for compatibility until Phase 6 cutover.
- Phase 5 stream foundation: protocol types define bounded cancel/window-update/event/close controls and sequenced binary stream payloads. `ReadFile` and `WriteFile` use random stream IDs, strict declared lengths and per-stream sequence checks, and binary `StreamData` frames end to end through Rust and Node. Spawned stdout/stderr now use live 256 KiB initial credit with validated replenishment up to a 4 MiB window, a single writer capped at 128 frames/16 MiB, strict event sequencing, and bounded client channels. Late credit for a closed stream is harmless and connection drop releases the reader task. The pipe reader now dispatches up to 16 requests per connection and 64 globally, permits out-of-order responses, handles sequenced Cancel/WindowUpdate controls while operations run, applies server deadlines, and cancels every active RPC on close/break. File transfer remains capped at 256 KiB until its live replenishment path is complete.
- Phase 5 backlog: add administrator update/uninstall RPCs and propagate request cancellation cooperatively into blocking VM boot, guest command, file, and cleanup work; the live dispatcher currently stops the RPC future and returns `CANCELLED`, but an already-running blocking worker can finish independently. Raise `ReadFile`/`WriteFile` beyond 256 KiB only when file credit replenishment is live. Real start/exec/spawn/file/watch/stop remains unverified because this shell has no installed bundle assets or Session 0/WHPX fixture; no hardware-dependent test was forced.
- Phase 5 deferred Node gates: the broader `index.spec.ts` suite detected local runtime assets and entered its VM setup hook, which failed with Windows `Access is denied (os error 5)` in this non-elevated shell. Binding-wide Clippy also fails on many pre-existing direct-SDK `needless_return`/derivable-impl findings plus an existing `lsb-sdk` dead-code warning; the new service surface passes normal compile and generated API tests, so unrelated cleanup is deferred.
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
| 4 | Shipping foundation complete; hard-stop/hardware integration backlog | Move sandbox lifecycle behind the service; add Job and WFP containment |
| 5 | In progress; lifecycle RPC/client foundation complete | Complete RPC plus the upstream Rust/Node client |
| 6 | Pending | Build/sign/package the artifact and complete the SeaWork integration contract |

Do not expose the full privileged RPC surface before Phases 1–3 are complete. Packaging remains last.

## Start here

1. Read repository instructions.
2. Read `plan.md` section 1's “How to use this plan” map—not the entire plan.
3. For the current Phase 5 slice, read sections 3, 5, 7, 9, 10, and 11/Phase 5. Consult section 15 only for sources needed now.
4. Recheck the branch, HEAD, worktree, toolchain, and dependency versions; preserve unrelated changes.
5. Implement Phase 5 bounded RPC dispatch and the upstream Rust/Node client using only owner-bound service resources.
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
