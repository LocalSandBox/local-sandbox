# LocalSandbox-owned Windows service for SeaWork

All external documentation in this plan was accessed on 2026-07-16. Repository observations refer to commit `c9e447cec349723f6e70ee3b78dd429af171e879` unless a tag is named explicitly. “Documented” means an external primary source says it; “observed” means the current repository does it; “recommended” is this plan's design decision.

## 1. Executive summary and recommended design

### How to use this plan

`state.md` identifies the current implementation phase. Do not preload this entire document for every phase. Read the always-required sections and the current phase's slice below; open other sections only when a dependency, test failure, or cross-cutting decision requires them.

Always read:

- Section 3: fixed decisions and non-goals.
- Section 5: target architecture and ownership boundary.
- The current phase in section 11, including its acceptance criteria.

| Current phase | Additional sections to read |
| --- | --- |
| Phase 0 | Sections 2, 4, 6, 8, 12, and 14 |
| Phase 1 | Sections 6, 7, and 9 |
| Phase 2 | Sections 7 and 8 |
| Phase 3 | Sections 8 and 9 |
| Phase 4 | Sections 7–9 |
| Phase 5 | Sections 7 and 10, plus the Node API in section 5 |
| Phase 6 | Sections 2, 6, 10, 12–14 |

Section 15 is a reference index: consult only the sources needed to verify the claim currently being implemented. Section 4 is baseline rationale and normally does not need to be reread after Phase 0. When this reading map conflicts with an explicit dependency in a phase, the phase dependency wins.

### Recommended design

Build a true, product-specific Windows service in this repository and publish it as a separate, self-contained upstream artifact. SeaWork's already-elevated per-machine installer installs and configures that artifact once. Thereafter an unelevated SeaWork process uses an upstream Node client to connect to a fixed local named pipe; it never launches an elevated Electron/helper process and never prompts for UAC during normal use.

The service is a Rust binary, `localsandbox-seawork-service.exe`, in a new `lsb-seawork-service` crate. It uses `windows-service` 0.8.x for the SCM dispatcher, handler, status, and configuration types, while retaining the repository's existing `windows-sys` 0.61.x dependency for named-pipe, token, ACL, path-handle, Job Object, WFP, and other Win32 calls. It calls refactored Rust orchestration in `lsb-sdk`/`lsb-vm` directly; it does not load N-API or Electron. A transport-neutral `lsb-service-proto` crate owns framing/schema and a Windows-only `lsb-service-client` crate owns the named-pipe client. The Node binding wraps that Rust client and exposes remote sandbox/process objects compatible with SeaWork's needs.

The service runs as `LocalSystem` for the MVP. That is deliberately broad, so the release-blocking security boundary is not the service token: it is an explicit pipe DACL, identity derived from the connected pipe token, per-connection opaque resource handles, strict resource caps, client-token access checks, handle-pinned path authorization, protected service-owned state under `%ProgramData%`, and provable/idempotent ownership of every privileged object cleaned after a crash. Caller-controlled `dataDir`, instance IDs, cleanup manifests, QEMU paths, and runtime asset paths are not accepted.

The service supports concurrent app processes and users. A connection owns its sandboxes; resource handles are random and also bound internally to the authenticated user SID, logon SID/authentication LUID, Windows session, and connection. Authentication is mutual at the OS boundary: the service authenticates the client token/process, and the upstream client verifies that the pipe server PID is the RUNNING SCM service whose protected SCM configuration names LocalSystem, the service SID mode, and a protected signed image before sending Hello, paths, or secrets. A pipe break stops that connection's sandboxes within a bounded drain. Sandboxes do not survive disconnect or service restart in v1. Loopback host-port forwarding is exposed only if the Session 0 spike proves that dynamic WFP filters can permit the owning logon SID while blocking other users and another logon of the same account; otherwise port requests fail closed with `PORT_ISOLATION_UNAVAILABLE` rather than publishing a cross-session listener.

The upstream release is `lsb-seawork-service-v<VERSION>-windows-x86_64.zip`, versioned with the LocalSandbox release, containing the service executable, VM assets, pinned QEMU distribution, a complete file manifest, signed catalog, and licenses. PDBs ship separately. LocalSandbox signs the service PE and catalog; SeaWork pins the archive SHA-256 and expected publisher and verifies both before installation. The existing LocalSandbox release pipeline does not yet Windows-sign artifacts, so certificate/signing ownership is a packaging-phase release gate, not an unresolved architecture choice.

The implementation starts with a real Session 0 feasibility spike, then lands the identity/path/ledger security foundation before the full RPC surface, and ends with packaging plus SeaWork's downstream integration contract.

## 2. Baseline — branch/SHA/version/toolchain and investigation limits

### Reproducible repository baseline

| Item | Recorded value | Evidence |
| --- | --- | --- |
| Branch | `feat/lsb-win-service` | `git branch --show-current` |
| Commit | `c9e447cec349723f6e70ee3b78dd429af171e879` | `git rev-parse HEAD` |
| Describe | `v0.4.6-10-gc9e447c` | `git describe --tags --always` |
| LocalSandbox version | Workspace crates and Node packages `0.4.6`; last release tag `v0.4.6` at `92bc4d1` | `crates/*/Cargo.toml`, `bindings/nodejs/package.json`, `bindings/nodejs/npm/win32-x64-msvc/package.json`, and Git history |
| Rust | `rustc 1.92.0 (ded5c06cf 2025-12-08)`, `cargo 1.92.0`, `stable-aarch64-apple-darwin` | Local `rustc --version --verbose`/`cargo --version`; CI installs the moving stable toolchain in `.github/workflows/ci.yml:34-39` |
| Windows production target | `x86_64-pc-windows-msvc` only | `crates/lsb-platform/src/windows_x86_64/mod.rs:22-35`, `crates/lsb-platform/src/windows_aarch64/mod.rs:3-16`, `README.md:13-22,102-116` |
| Windows Arm64 | Recognized but deliberately returns unsupported; not an MVP artifact | Same platform modules above |
| Key Rust packages | direct Windows API line `windows-sys 0.61.2` (a transitive `0.52.0` is also locked), `tokio 1.52.3`, `serde 1.0.228`, `serde_json 1.0.150`, `anyhow 1.0.102` | `Cargo.lock`; `crates/lsb-platform/Cargo.toml:25-47` |
| Bundled host tools | QEMU `11.0.50`; managed revision `lsb0.4.0`; artifact `lsb-qemu-windows-x86_64-qemu-11.0.50-lsb0.4.0.tar.gz` pinned to SHA-256 `49021ed8…c6251` | `crates/lsb-platform/src/windows_x86_64/host_tools.rs:7-18` |
| Node toolchain/packages | Node main and win32-x64 packages `0.4.6`; manifests request `napi`/`napi-derive 3.0.0` with N-API 8, locked to `napi 3.10.3`/`napi-derive 3.5.9`; `@napi-rs/cli ^3.2.0` locked to `3.2.0`; Node >=18; Yarn 4.12.0 | `bindings/nodejs/{package.json,Cargo.toml,Cargo.lock,yarn.lock}`, `bindings/nodejs/npm/win32-x64-msvc/package.json`, root `package.json` |
| Downstream pin inspected | SeaWork catalog pins `@local-sandbox/lsb-nodejs: 0.4.6` and supports win32/x64 | `../seawork/pnpm-workspace.yaml:7-23` |

The worktree was clean before this plan was created. No production source, workflow, lockfile, generated asset, or downstream SeaWork file was modified. The investigation was performed from macOS, so source/documentation conclusions are complete but the real-Windows feasibility probes listed in sections 11 and 14 remain deliberately gated on a disposable Windows 11 x64 machine.

### Release/build baseline

The workspace currently contains libraries, CLI/guest/proxy binaries, and the N-API binding, but no service host (`Cargo.toml:1-20`). Windows CI runs ordinary hosted-runner checks and unit tests; it does not install a service or exercise privileged SMB/WHPX behavior (`.github/workflows/ci.yml:34-78`). The core release workflow builds an MSVC Windows CLI and publishes a one-binary tarball, while a separate Node workflow builds `lsb-nodejs.win32-x64-msvc.node` and publishes the main/platform NPM packages with provenance (`.github/workflows/release.yml:45-138`, `.github/workflows/release_nodejs.yml:40-138`, `bindings/nodejs/npm/win32-x64-msvc/package.json:12-15`). Managed QEMU is a separately downloaded, SHA-256-pinned distribution containing its own executable/DLL payload; the existing workflow validates but does not re-sign it. Windows outputs receive no Authenticode/catalog signing—the only current signing step is ad-hoc macOS signing. The CLI/OS GitHub assets have no published checksum sidecar, attestation, PDB archive, or staged license inventory; the Node package does carry `bindings/nodejs/LICENSE` and NPM provenance. `xtask` packages only CLI and OS-image artifacts, and the CLI bundle is a single binary (`xtask/src/main.rs`, `xtask/src/release.rs:112-136`). Windows dependencies are selected with `cfg(windows)` and `windows-sys` features rather than workspace features (`crates/lsb-platform/Cargo.toml:25-47`); the N-API library is a `cdylib` (`bindings/nodejs/Cargo.toml:9-29`). The future release gate must record `dumpbin /DEPENDENTS` output and include every non-system runtime DLL, rather than assuming a Rust/MSVC executable is intrinsically self-contained. Workspace release profiles strip binaries, so the service needs an explicit PDB/symbol packaging path (`Cargo.toml:15-20`).

## 3. Fixed decisions and non-goals

The following constraints are inputs, not alternatives to revisit:

- The service is exclusively for SeaWork. Stable names may say SeaWork; there is no plugin/product registry or global broker tenancy layer.
- LocalSandbox owns the executable, SCM runtime, IPC schema and both ends of the client/server implementation, authentication/authorization, sandbox/VM/mount/temporary-account lifecycle, tests, versioning, and published artifact.
- SeaWork owns per-machine install/update/repair/uninstall, SCM registration/configuration, artifact pinning and verification, app reconnect/UX/telemetry, and deployment testing. No pipe server, cleanup logic, or security decision remains in SeaWork.
- `LocalSystem` is the MVP account unless the Session 0 spike proves a blocker. Required-privilege minimization, a virtual service account, and further service-token isolation are post-MVP hardening.
- This is a real `SERVICE_WIN32_OWN_PROCESS` SCM service. An ordinary CLI or Electron executable registered as a service is not acceptable.
- Windows x86-64 is the first artifact. Arm64 is follow-up work after platform support exists.
- No persistent/adoptable sandboxes, cross-connection resource transfer, remote named-pipe access, arbitrary caller runtime directories, user-provided QEMU/runtime code, service self-install, or service self-update in v1.
- A normal client can close only its own session. It cannot stop/configure/delete the machine service, request global cleanup, or choose a weaker security policy.
- There is no silent fallback to `--seawork-sandbox-helper`, UAC, direct N-API privilege, an older protocol, or insecure host-port publication. Absence/incompatibility is a clear repair/update error.
- General minimum privilege discovery and enterprise GPO accommodation must not postpone the first secure service release. Concrete GPO/EDR incompatibilities are surfaced and fail closed.

## 4. Current architecture — source-backed call/lifecycle map

### Public API through boot

1. `bindings/nodejs/src/lib.rs:36-80` exports N-API `init_sandbox`; it enters Rust with `spawn_blocking` and calls `lsb_sdk::init`. The binding's `Sandbox` stores `Arc<AsyncSandbox>` and directly starts the SDK runtime (`bindings/nodejs/src/sandbox.rs:29-49`). `exec`, `shell`, `spawn`, watches, guest file methods, `stop`, and `instance_dir` are direct wrappers (`sandbox.rs:62-134,408-432`). This N-API boundary is appropriate for an in-process client, not for a Session 0 host.
2. Caller fields are translated without an authorization boundary: `instanceId`, `baseVersion`, `dataDir`, CPU, memory, disk, ports, mounts, and network settings flow from TypeScript through `bindings/nodejs/src/types.rs:72-167` and `bindings/nodejs/src/config.rs:44-95`. `parse_mount` canonicalizes host paths and selects direct/overlay semantics, but it runs in the current process token and is not a privileged confused-deputy defense (`config.rs:141-176`).
3. `lsb_sdk::init` chooses a caller/default data directory, applies Windows fixes, and downloads runtime/host assets (`crates/lsb-sdk/src/assets.rs:17-31,62-128`). Windows' default directory derives from the current process `LOCALAPPDATA`, then `USERPROFILE`/`HOME`; under `LocalSystem` that becomes the system profile, not the desktop user's state (`crates/lsb-platform/src/lib.rs:153-177`). All runtime/instance/tool paths then derive from this data root (`lsb-platform/src/lib.rs:195-215`).
4. `AsyncSandbox` creates one OS thread and a `std::sync::mpsc` command loop per sandbox (`crates/lsb-sdk/src/runtime.rs:125-199`). Boot accepts the caller's data directory/instance ID, opportunistically recovers stale SMB manifests, and otherwise names an instance `sdk-<pid>-<counter>` using a process-global counter (`runtime.rs:36,551-613`). These are process-local assumptions, not multi-client service ownership.
5. Boot creates Windows storage/proxy/NBD state, constructs `lsb_vm::Sandbox`, starts it, then establishes port forwards and proxy trust (`runtime.rs:615-740`). Storage mode can change through process environment (`LSB_STORAGE=direct`) (`runtime.rs:795-833`), which is unsuitable for trusted service configuration. Commands are serialized through the runtime loop; stop is another command. `Drop` sends stop and immediately removes the instance directory, creating a possible stop/cleanup race (`runtime.rs:519-527,1463-1470`).

### VM/QEMU/process ownership

`lsb-vm`'s `SandboxBuilder` carries path strings for mounts and builds platform VM, Windows storage, locks, and cleanup-manifest paths (`crates/lsb-vm/src/sandbox.rs:129-140,144-384`). Start prepares snapshots, mount cache, and SMB, then starts the VM with partial-failure cleanup (`sandbox.rs:929-1080`). Stop requests a guest sync, stops the VM, updates cache state, and aggregates SMB cleanup errors (`sandbox.rs:1083-1117`). There is no `Drop` implementation on this high-level `Sandbox`; orderly privileged cleanup depends on explicit stop or later manifest recovery.

The Windows QEMU backend constructs q35/WHPX arguments, Westmere CPU, memory/vCPU/disks, no display/monitor, virtio serial, and user networking (`crates/lsb-platform/src/windows_x86_64/qemu/argv.rs:54-164`). `QemuProcess::start` validates an absolute executable, writes per-instance logs, clears the inherited environment except `SystemRoot`/`WINDIR`, hides the window, and fail-closes if the process cannot enter a Job Object (`qemu/process.rs:474-527`). It currently spawns at `process.rs:498` and only creates/assigns the Job at `process.rs:510`, leaving a short pre-containment window the service must close. The job uses `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`; terminate/`Drop` kills QEMU and closes the job (`qemu/process.rs:571-603,829-975`). The containment mechanism is reusable, but that assignment race and service-wide quotas/completion-port monitoring are absent. Boot validates assets, starts QEMU, opens the guest named pipe, and waits up to 90 seconds for readiness, terminating on failure (`qemu/boot.rs:574-901`). QEMU discovery currently considers environment, config, managed tools, and `PATH` (`qemu/discovery.rs:10-64`); a service must use only the verified managed absolute path.

Guest-control operations share a mutex rather than a multiplexed, cancellable transport (`crates/lsb-vm/src/sandbox.rs:2503-2535`). SDK process stdout/stderr channels and the N-API process wrapper are unbounded (`crates/lsb-sdk/src/process.rs:67-71`, `bindings/nodejs/src/process.rs:20-23`). Those would turn a stable service into a local memory-DoS surface unless bounded below the RPC layer.

Port mappings validate only nonzero/unique numbers and listen on `127.0.0.1` (`crates/lsb-vm/src/sandbox.rs:3971-3997`); any local user can normally connect. The listener is RAII-cleaned (`sandbox.rs:4029-4042`) but has no per-user authorization. File watches also observe host paths in the current process context, an assumption that changes in Session 0.

### Direct SMB mounts and persisted cleanup

On Windows, direct mounts create a temporary local user/password, grant network-logon rights, grant filesystem ACL access, create a share, and pass plaintext guest SMB credentials; teardown reverses those operations (`crates/lsb-platform/src/windows_x86_64/fs/smb/lifecycle.rs:94-224`). Administrator membership and loopback TCP/445 are checked (`smb/admin.rs:23-99`). `NetUserAdd`, account flags and LSA network-logon rights are implemented in `smb/user.rs:56-150`; share security/`NetShareAdd`/`NetShareDel` in `smb/share.rs:64-175`; filesystem DACL changes use path-based `GetNamedSecurityInfo`/`SetNamedSecurityInfo` with inheritance in `smb/acl.rs:68-156`. All assume the current process token has machine-wide authority.

The current account/share prefixes are generic (`smb/types.rs:11-17`). Per-instance locking, mount replanning, setup, manifest writing, reverse cleanup, and manifest deletion occur in `lsb-vm/src/sandbox.rs:2619-2755`. The JSON manifest stores caller-selected paths, principal/account/share data beneath the instance directory (`smb/lifecycle.rs:287-475`). Startup scans caller data directories, parses those unsigned files, and reconstructs cleanup resources after only prefix/name checks (`lifecycle.rs:583-639`). A standard user could forge or replace that state. A `LocalSystem` service must therefore never import it as authority for deleting accounts/shares or changing arbitrary ACLs. The service ledger in section 9 replaces it rather than “hardening” the caller-owned file.

The current privileged/identity-sensitive calls and their token assumptions are:

| Current call/operation | Current assumption that must become explicit in the service |
| --- | --- |
| `CheckTokenMembership` plus bind `127.0.0.1:445` (`smb/admin.rs:23-99`) | The process is an elevated Administrator and the local SMB server is reachable; a service instead verifies LocalSystem/service health and reports a capability error |
| `NetUserAdd`/`NetUserDel` (`smb/user.rs:56-150`) | The process can manage local accounts; the service journals intent/actual SID and proves ownership before deletion |
| `LsaOpenPolicy`, `LsaAddAccountRights`, `LsaRemoveAccountRights` (`smb/policy.rs:177-277,353-385`) | The process can open local policy with `POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT`; global policy repair at `policy.rs:90-140` also assumes administrator authority and must not run per request |
| `GetNamedSecurityInfo`, `SetEntriesInAcl`, `SetNamedSecurityInfo` (`smb/acl.rs:68-156`) | The process has `READ_CONTROL`/`WRITE_DAC` or equivalent ownership/privilege on a caller path; under LocalSystem this would bypass the caller, so the service first impersonates/access-checks and later mutates only through a pinned handle |
| `NetShareAdd`/`NetShareDel` level 502 (`smb/share.rs:64-175`) | The process can administer local shares and the supplied path is trustworthy; the service journals, creates, re-queries, and verifies exact root identity/owner marker |
| Windows policy fix through `initSandbox({fix:true})` (`crates/lsb-sdk/src/{assets.rs:115-128,fixes.rs:14-21}`) | The caller intentionally authorized a machine-wide LSA policy change; service runtime must only diagnose, while the SeaWork installer owns any explicitly approved one-time change |
| QEMU process/Job creation and termination (`qemu/process.rs:474-603,829-975`) | The caller owns the child and can assign/terminate it; the service retains this ownership but strengthens limits and treats Job creation as fail-closed |
| File copy/watch `CreateFileW`/`ReadDirectoryChangesW` (`fs/copy.rs:271-385`, `fs/watch.rs:1-37,413-456`) | Access is evaluated with the current process token and current path identity; the service must open under its held client token and preserve verified handles/identity |

Existing path code is still valuable. Mount planning canonicalizes/revalidates direct paths (`fs/mount_plan.rs:116-217`); Windows copy rejects UNC/device/root/ADS paths and reparse components (`fs/copy.rs:271-385`); its handle-oriented traversal opens reparse points explicitly and records object identities. However, current SMB ACL/share operations return to path strings after authorization. The service design must promote the handle/identity machinery into the authoritative boundary and keep roots pinned through ACL/share creation.

### State/concurrency/error summary

| Scope today | State/assumption | Service consequence |
| --- | --- | --- |
| Process global | instance counter, environment-selected storage/QEMU discovery, caller default data root | Replace with protected config, cryptographic IDs, and an explicit service engine |
| Per SDK runtime | downloaded assets and platform paths under a caller-selected root | Installer-provided, signed runtime bundle only |
| Per sandbox/thread | serial command channel, VM/storage/mount state, instance directory | Wrap in service resource ownership/cancellation and bounded queues |
| Per spawned guest process | unbounded output channel | Add stream credit/backpressure and process termination on sustained overflow |
| Per mount | temp user, LSA right, ACL, share, plaintext credential, user-writable manifest | Journal protected state before each privileged side effect and reconcile only provable ownership |
| Cross-user | no manager or owner identity; loopback ports visible machine-wide | Bind all handles to OS identity and use WFP/fail closed |

Partial setup generally attempts reverse cleanup and error aggregation in VM/mount code, and QEMU is strongly contained by its job. Cancellation/deadlines/idempotency are not end-to-end properties: the per-sandbox command loop is serial, stop is explicit, N-API drop races directory removal, output is unbounded, and RPC duplicate/replay behavior does not exist upstream.

### Downstream boundary violation to remove

SeaWork currently creates a one-use pipe/nonce, elevates its own Electron binary via PowerShell `Start-Process -Verb RunAs` (`../seawork/apps/electron/src/main/sandbox-helper/launcher.ts:7-15,102-158`), implements helper launch/retry/lifetime and sends caller `dataDir` (`manager.ts:457-632`), owns protocol/schema/validation (`protocol.ts:9-193`), and runs the N-API sandbox plus cleanup in an elevated helper server (`helper-server.ts:121-400`). Those responsibilities violate the target ownership contract. They are replaced, not adapted into a thin SCM wrapper.

That one-shot protocol has assumptions that must not become service behavior: newline JSON is capped at 1 MiB but repeatedly concatenates buffered data (`protocol.ts:9-10,817-895`); active/used request and stopped-resource ID sets have no lifetime bound and handlers are launched without a concurrency cap (`helper-server.ts:84-152,164-223`); and the manager may retry `startSandbox` after selected connection/startup failures (`manager.ts:582-611`). A machine service instead needs the constant-space sequence, bounded dispatch/streams, and at-most-once resource creation in section 7.

The available downstream checkout confirms the deployment premise: the installed app requests `asInvoker` while NSIS is per-machine (`../seawork/apps/electron/electron-builder.yml:36-45`), and its verification guide requires an administrator installer while expecting only the helper process to elevate (`../seawork/apps/electron/scripts/windows/privilege-separation-verification.md:73-82,139-200`). Therefore the installer is the correct one-time SCM authority and the normal app process is the correct unelevated pipe client.

## 5. Target architecture and ownership boundary

```text
 USER SESSION (unelevated)                       SESSION 0 (LocalSystem)
 +----------------------------+                  +--------------------------------+
 | SeaWork Electron           |                  | LocalSandboxSeaWork SCM service|
 | product UX/reconnect       |                  |                                |
 |                            | N-API calls       | pipe accept/auth/session mgr   |
 | @local-sandbox/lsb-nodejs  +-- named pipe --->| RPC -> service engine          |
 |   lsb-service-client       | token-derived ID  | -> lsb-sdk -> lsb-vm           |
 +----------------------------+                  | -> QEMU Job / SMB / WFP        |
                |                                +-----------+--------------------+
                | mount paths under                   admin-protected state
                | authenticated user's rights        | ProgramData ledger/logs
                v                                    | ProgramFiles signed bundle
          user filesystem                            v
                                             VM + privileged host objects

 INSTALL/UPDATE TRUST BOUNDARY (administrator)
 SeaWork installer: verify pinned upstream archive/signatures -> copy protected
 version -> create/configure/start stable SCM registration -> health-check IPC.
 It never implements RPC authorization or sandbox cleanup.
```

### New upstream components

- `crates/lsb-service-proto`: platform-neutral header, message enums, version/feature negotiation, typed status/error codes, size validation, and golden vectors. No OS access and no Node types.
- `crates/lsb-service-client`: Windows named-pipe connection, Hello negotiation, request correlation/cancel/deadline, bounded stream demultiplexing, and remote `Sandbox`/`Process` handles. On non-Windows it compiles only a deterministic `UnsupportedPlatform` stub for workspace tooling; the Node binding depends on it only for Windows, while macOS continues using the current direct SDK.
- `crates/lsb-seawork-service`: `cdylib` is not needed; `[[bin]] name = "localsandbox-seawork-service"` at `src/main.rs` hosts SCM, IPC, authenticated sessions, quotas, protected state, reconciliation, diagnostics, WFP, and the service-side engine. Windows implementation modules compile only for x86-64 Windows; other workspace targets build a deterministic `UnsupportedPlatform` main so macOS/Linux workspace checks still work. Release packaging rejects every target except `x86_64-pc-windows-msvc`, and no unsupported-target binary is published.
- Refactored `lsb-sdk`: expose an internal service-engine configuration that accepts already-validated trusted runtime paths, cryptographic instance IDs, cancellation/deadlines, bounded output, and a privileged mount capability created only after authorization. Do not make “service mode” a boolean on the existing caller-controlled configuration.
- Refactored `lsb-platform`/`lsb-vm`: handle-pinned mount preparation, exact ACE journaling, strict service prefixes, stronger Job limits, WFP port ownership, and deterministic cleanup. Keep QEMU boot, storage, guest protocol, safe copy traversal, SMB Win32 wrappers, and the current Job supervisor where their contracts remain valid.
- `bindings/nodejs`: export the upstream Windows service client and remote objects. SeaWork imports only upstream APIs; there is no downstream wire implementation.

The three service crates use the workspace's LocalSandbox version but set `publish = false`; the supported distribution surfaces are the signed service archive and existing NPM binding, not new crates.io APIs. `lsb-service-proto` remains a shared internal crate so client/server cannot drift.

The recommended Node API is:

```ts
type SeaWorkServiceConnectOptions = { connectTimeoutMs?: number };
type SeaWorkServiceInfo = {
  serviceVersion: string;
  protocol: { major: number; minor: number; features: string[] };
  bundleVersion: string;
  capabilities: {
    directMount: boolean;
    directMountBackends: Array<"pinned-ro" | "staged-sync">;
    watch: boolean;
    ports: boolean;
  };
};
type SeaWorkServiceHealth = {
  ready: boolean;
  admissionsOpen: boolean;
  stableCode: string;
  serviceInfo: SeaWorkServiceInfo;
};

connectSeaWorkService(options?: SeaWorkServiceConnectOptions):
  Promise<SeaWorkServiceClient>;

interface SeaWorkServiceClient {
  getServiceInfo(): Promise<SeaWorkServiceInfo>;
  healthCheck(): Promise<SeaWorkServiceHealth>;
  startSandbox(options: ServiceSandboxStartOptions): Promise<RemoteSandbox>;
  close(): Promise<void>; // closes only this connection/session
}
```

`ServiceSandboxStartOptions` retains bounded CPU/memory/disk, mounts, ports, network, and supported VM behavior, but deliberately has no `dataDir`, `instanceId`, `baseVersion`, QEMU path, runtime asset path, cleanup path, identity, firewall metadata, or arbitrary service configuration. `RemoteSandbox` and `RemoteProcess` expose the current SeaWork-used start/stop, exec/spawn/kill, guest file, watch, and stream operations. An ordinary client has no `shutdownService` method.

## 6. Windows service design

### SCM implementation choice and entry points

Use maintained `windows-service` 0.8.1 for `service_dispatcher::start`, `ServiceMain`, `service_control_handler::register`, status reporting, preshutdown, and service configuration structures. It is Windows-specific, is built on the same `windows-sys` 0.61 line already locked here, and exposes the required mature SCM behavior. Microsoft's newer `windows-services` crate is promising but currently provides a smaller builder surface; raw `windows-sys` would force this repository to recreate error-prone dispatcher/status/control glue. Keep direct, narrowly wrapped `windows-sys` calls for capabilities the service crate does not cover.

`main` accepts only these modes:

- no mode/`--service`: call `StartServiceCtrlDispatcher` immediately; SCM invokes `ServiceMain`.
- `--version --json`: print artifact/protocol/ledger-schema metadata without writing or requiring admin.
- `--verify-bundle --json`: verify the manifest, catalog membership/hashes, architecture, and asset compatibility without installing, downloading, repairing policy, or modifying machine state. SeaWork normally performs signature trust itself; this mode supplies structural diagnostics.

It does not self-install, self-update, download assets, create/delete the SCM registration, change its service DACL, or accept user-selected configuration paths.

### Required service configuration contract

| Field | Required value |
| --- | --- |
| Service name | `LocalSandboxSeaWork` |
| Display name | `LocalSandbox for SeaWork` |
| Description | `Runs LocalSandbox virtual machines for locally signed SeaWork desktop clients.` |
| Type | `SERVICE_WIN32_OWN_PROCESS` |
| Account | `LocalSystem`; no password |
| Start | Automatic, delayed auto-start; installer also starts it immediately |
| Binary path | `"%ProgramFiles%\SeaWork\LocalSandbox\versions\<version>\bin\localsandbox-seawork-service.exe" --service` after expanding `%ProgramFiles%` to an absolute path before passing it to SCM |
| Dependencies | None at SCM level; lack of BFE/WFP or LanmanServer produces capability-specific fail-closed health/errors rather than a start deadlock |
| Service SID | `SERVICE_SID_TYPE_UNRESTRICTED`; ACL protected state for `NT SERVICE\LocalSandboxSeaWork`, `SYSTEM`, and Administrators |
| Service-object SDDL | `O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00000005;;;IU)` — SYSTEM/Admin full control; `0x5` is exactly `SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS` for interactive users, with no start/stop/change-config/delete right |
| Accepted controls | `STOP` and `PRESHUTDOWN`; do not advertise pause/continue. Do not depend on `SHUTDOWN` when preshutdown is used. |
| Preshutdown timeout | 60,000 ms |
| Failure actions | restart after 5 s, 30 s, 120 s, then no action; reset period 86,400 s; apply to non-crash failures |
| Event source | `LocalSandboxSeaWork` in the Application log, registered by SeaWork installer using the signed service exe as message resource |

Automatic delayed start avoids requiring `SERVICE_START` on the standard-user token, but Windows does not guarantee an exact delayed-start time. The client therefore retries connection with bounded backoff and reports `SERVICE_UNAVAILABLE`; it never attempts `StartService`. The installer starts and health-checks the service immediately after configuration.

SeaWork resolves `NT SERVICE\LocalSandboxSeaWork` to its concrete service SID after setting the SID type and instantiates these protected ACL templates (shown with `<SERVICE_SID>` as a placeholder):

```text
Program Files LocalSandbox tree (apply at `%ProgramFiles%\SeaWork\LocalSandbox`):
O:BAG:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;<SERVICE_SID>)(A;OICI;FRFX;;;BU)

ProgramData service tree:
O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;<SERVICE_SID>)
```

`OICI` propagates to files/directories and `D:P` prevents a permissive inherited user ACE. Builtin Users get read/execute only on the version tree so the unelevated upstream client can inspect and Authenticode-verify the SCM image; every LocalSandbox bundle ancestor below `%ProgramFiles%` grants them at least traverse/read-attributes but no mutation. They get no service-state access. The explicit service SID has read/execute on the version tree and full access to state; because the MVP process is LocalSystem, its SYSTEM SID still has full access to both, an accepted consequence of the broad account rather than a least-privilege claim. SeaWork verifies these effective ACLs and every ancestor for absence of standard-user write/owner/DACL rights after install and repair.

### State machine and control behavior

`ServiceMain` registers the extended control handler before expensive work, creates one control channel, and reports `START_PENDING` with a nonzero wait hint/checkpoint. It then initializes protected logging/config, validates the bundle/ledger, reconciles stale resources, binds the pipe, and reports `RUNNING` only when the server is accepting authenticated Hello messages. During startup it advances the checkpoint at least every two seconds with a realistic wait hint. Fatal startup errors report `STOPPED` with a service-specific exit code and Win32 error where applicable.

The SCM handler performs no blocking I/O: `STOP`/`PRESHUTDOWN` atomically set a drain flag and signal the runtime. The runtime immediately stops pipe admissions and returns `SERVICE_DRAINING` to requests already dequeued but not committed, reports `STOP_PENDING`, cancels active operations, then stops sandboxes concurrently in bounded groups. It advances checkpoints at most every two seconds. Normal STOP has a 30-second internal drain; preshutdown may use the configured 60 seconds. At the deadline it closes all QEMU Job handles (forced kill) and flushes protected ledger/log state. A requested STOP/preshutdown reports `STOPPED` exactly once with success even when durable cleanup remains, while recording a high-severity cleanup-pending event; otherwise `SERVICE_FAILURE_ACTIONS_FLAG` could restart the service in the middle of an installer update or shutdown. Startup reconciliation completes those protected intents on the next start. Only an unexpected fatal start/runtime failure reports a nonzero service-specific exit code and invokes recovery actions.

The restart schedule prevents a tight crash loop; after the fourth failure SCM leaves the service stopped for repair/diagnosis. A failed individual client request or VM boot does not crash the process. Only service-invariant corruption (for example protected state schema/hash corruption that cannot be quarantined safely) fails service startup.

### Account, loading, and diagnostics

`LocalSystem` is functionally suitable on paper: it has extensive local privilege, no normal logged-in user profile, and uses the machine identity on the network. The service must not read `%USERPROFILE%`, `%LOCALAPPDATA%`, mapped drives, interactive desktop state, inherited current directory, user certificate stores, or uncontrolled environment variables. It derives all paths from its signed executable location or fixed `%ProgramData%\LocalSandbox\SeaWork`, uses an explicit system temp subdirectory with protected ACLs, and launches only verified absolute executables/DLLs from the protected bundle. Call `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_USER_DIRS)` and add only the version's protected runtime directory if dynamic dependencies require it; do not search CWD/PATH.

Write lifecycle/security summaries to the Application event log and rotating UTF-8 JSON files under protected `logs` (10 files × 10 MiB). Records include event ID, timestamp, service/bundle/protocol version, correlation ID, hashed SID/session key, resource type/opaque ID, phase, duration, stable error code, and Win32 code. Never log request bodies, commands, arguments, environment, guest output, file contents, full mount paths, SMB passwords, tokens, access tokens, certificate material, or cleanup secrets. A protected per-sandbox diagnostic directory may hold QEMU logs after redacting credentials and is quota/retention bounded. Users receive stable error codes plus safe remediation; administrators can correlate with event IDs.

Event message IDs are append-only across compatible releases. On update/rollback SeaWork updates the protected Event source `EventMessageFile` to the same versioned executable as SCM ImagePath in the installer transaction and health verifies both, while the previous version remains until rollback closes.

## 7. IPC contract

### Pipe creation and exact security descriptor

Use byte-mode async named pipes at `\\.\pipe\LocalSandbox.SeaWork.v1`. The production SCM service is the only accepted creator, but a Windows named-pipe DACL protects an existing pipe instance rather than reserving the global name; client-side server authentication below prevents a pre-start squatter from receiving any protocol data. Its explicit SDDL is:

```text
O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;IU)(A;;0x00000002;;;IU)S:(ML;;NW;;;ME)
```

`0x00000002` is only `FILE_WRITE_DATA`. Combined with the separate `FR` ACE, interactive users can connect/read/write data but are not granted `FILE_APPEND_DATA`/`FILE_CREATE_PIPE_INSTANCE` (the shared `0x4` bit that makes generic write unsafe). SYSTEM and Administrators have full access. The DACL is protected. The mandatory-label SACL denies write-up from below medium integrity; token authorization independently rejects low-integrity and AppContainer clients. The DACL intentionally permits ordinary interactive users so multiple standard accounts can use the installed product.

Create the first server instance with `FILE_FLAG_FIRST_PIPE_INSTANCE`, `PIPE_REJECT_REMOTE_CLIENTS`, byte read mode, maximum 32 instances, and 64 KiB OS input/output buffers. Subsequent pre-created instances use the same security descriptor without the first-instance flag; keep one unconnected instance ready so service availability does not depend on client timing. Tokio 1.52's Windows named-pipe `ServerOptions` and `create_with_security_attributes_raw` provide the async integration, first-instance and remote-client controls. A client opens a non-inheritable overlapped handle with `GENERIC_READ | FILE_WRITE_DATA | SYNCHRONIZE` and `SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION`, then wraps it for Tokio; it must not request `GENERIC_WRITE`.

Before writing Hello, the upstream client mutually authenticates the server without assuming a standard user can open a LocalSystem process token. It obtains the kernel-reported pipe server PID with `GetNamedPipeServerProcessId`, opens `LocalSandboxSeaWork` through SCM with only `SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS`, and requires `QueryServiceStatusEx` to report RUNNING with the same nonzero PID. `QueryServiceConfigW`/`QueryServiceConfig2W` must return `SERVICE_WIN32_OWN_PROCESS`, `LocalSystem`, `SERVICE_SID_TYPE_UNRESTRICTED`, and the exact quoted `--service` command under `%ProgramFiles%\SeaWork\LocalSandbox\versions\<VERSION>`. The client parses that command with Windows command-line rules, opens the executable without share-delete, verifies its final identity and every ancestor under the protected version root, and validates with no UI against the current/overlap LocalSandbox Authenticode publisher allowlist generated into the paired upstream Node package. It then re-queries the pipe PID, SCM status/PID, and configuration to close state-change/race windows and holds the image handle for the connection. Any mismatch or pipe/service exit returns `SERVICE_UNAVAILABLE`/`SERVER_NOT_TRUSTED` without sending even Hello. A low-privilege pipe squatter can therefore cause bounded denial of service until the real service fails/recovers, but cannot collect paths, commands, or credentials.

### OS-derived identity and authorization

Hello must be the first complete frame. Immediately after reading it, the server:

1. Calls `ImpersonateNamedPipeClient`; an RAII guard calls `RevertToSelf` on every success/error/cancellation/unwind path. An impersonation failure terminates the connection—Win32 documents that failure otherwise leaves the thread in its existing security context.
2. Opens the thread token with `TOKEN_QUERY | TOKEN_DUPLICATE`, reads `TokenUser`, `TokenLogonSid`, `TokenSessionId`, `TokenIntegrityLevel`, `TokenStatistics.AuthenticationId`, `TokenIsAppContainer`, and elevation information, and duplicates a `SecurityImpersonation` token held for the connection lifetime.
3. Calls `GetNamedPipeClientProcessId`, opens that process with query rights, compares its current token's user SID, logon SID/authentication LUID, and session to the pipe token, and keeps/monitors the process handle so PID reuse is irrelevant and process exit closes the session even if another process inherited a pipe handle. A mismatch/race fails authentication. The upstream client creates a non-inheritable pipe handle.
4. Requires an interactive, medium-or-higher integrity, non-AppContainer token. It records immutable `ClientIdentity { user_sid, logon_sid, authentication_id, session_id, integrity, process_handle }`; identity fields from protocol payloads are forbidden/ignored.
5. As defense in depth, resolves the process image, opens it without share-delete, verifies its final file identity/path and every ancestor against the protected SeaWork install/staging roots, and rejects a signed executable copied to a user-writable location. It calls `WinVerifyTrust` with no UI and the protected-config SeaWork app/installer publisher allowlist, then rechecks identity. Normal RPC requires the protected installed-app root. Admin maintenance RPC additionally requires an elevated Administrator token and permits only the protected installed-app maintenance entry point or protected installer staging root signed by the configured app/installer publisher. This is required in production but is not claimed as isolation from a compromised/injected process under the same user.

No async task may remain impersonated across an `.await`, yield, callback, or blocking-pool return: impersonation is thread-wide, not task-local. The initial pipe impersonation/read-token/duplicate/revert sequence is one synchronous closure. Later path and user-context file work runs on a dedicated per-session filesystem OS thread; each command sets the duplicated impersonation token, performs only synchronous Win32 work, and reverts before replying or waiting for the next command. The RAII guard is a second line of defense, and service release builds abort on panic; a thread/process exit cannot leak an impersonation token into another request. Tests deliberately inject every early return and unwind in a non-abort test profile and assert the thread token is absent afterward.

Production artifacts compile out unsigned-client support. A feature-gated development build uses `LocalSandboxSeaWorkDev`, `\\.\pipe\LocalSandbox.SeaWork.Dev.v1`, and `%ProgramData%\LocalSandbox\SeaWorkDev`; it cannot open production state or pipe names.

The threat boundary is precise: an unsigned raw program is rejected after bounded Hello parsing, while an authenticated signed client may create only its own bounded session/sandbox. A compromised or injected process in the same logon may be able to act with that user's product privileges, read that user's accessible files, and reach that logon's owner-scoped loopback ports; Authenticode/path checks do not make same-user code a strong boundary. Even then it cannot address an existing connection's random handles or exceed per-SID/global policy. The design still protects other users/logons, service state, privileged paths, host capacity, and existing resource handles.

### Framing and schema

Every frame begins with a fixed 32-byte little-endian header:

| Offset/size | Field |
| --- | --- |
| 0 / 4 | ASCII magic `LSBS` |
| 4 / 1 | header version (`1`) |
| 5 / 1 | kind: `Hello`, `Request`, `Response`, `Event`, `StreamData`, `WindowUpdate`, `Cancel`, `Close` |
| 6 / 2 | flags; unknown/unnegotiated flags are fatal |
| 8 / 2 | protocol major |
| 10 / 2 | protocol minor |
| 12 / 4 | payload length, maximum 262,144 bytes |
| 16 / 16 | Kind-defined correlation described below; encoded as two little-endian `u64`s for sequenced control or as an opaque 128-bit stream ID |

Control payloads are UTF-8 JSON using strict internally tagged Serde enums with unknown/duplicate fields denied, integer range checks before conversion, and maximum nesting depth 32. `StreamData` is an 8-byte stream sequence followed by raw bytes, at most 65,536 bytes total. Binary guest file data and process output use stream frames, not base64-in-JSON. Invalid magic/version/kind/flags/length/UTF-8/schema closes the connection after at most one safe `PROTOCOL_ERROR`; the parser never allocates the claimed size before checking limits. Golden Rust/Node vectors and fuzzing lock framing behavior.

Frame direction and correlation are exact. The initial client `Hello` has all-zero correlation; the server `Hello` reply uses `{connection_epoch, 0}`. `Request` is client-to-server with `{connection_epoch, client_control_sequence}`. A `Response` is server-to-client with the exact corresponding Request or Cancel correlation. `Cancel` is client-to-server. `Event` is server-to-client. `WindowUpdate`, `StreamData`, and `Close` may flow in either direction. Client `Cancel`/`WindowUpdate`/`Close` frames consume the same consecutive client control sequence as Request. Server `Event`/`WindowUpdate`/`Close` frames consume a separate consecutive server control sequence starting at one; the client validates it. `StreamData` correlation is its random stream ID and its binary payload begins with the per-stream sequence. Directions contrary to this table are fatal protocol errors.

The JSON envelopes are `Request { deadline_ms?: u32, op: RequestOp }`, `Response::Ok { result: ResponseValue } | Response::Err { error: ErrorEnvelope }`, typed `Event`, `Cancel { request_id }`, `WindowUpdate { stream_id, credit_bytes: u32 }`, and `Close { code }`; operation/result pairing is validated before dispatch. Resource, request-target, and stream IDs appearing in JSON are exactly 32 lowercase hexadecimal characters, never JSON numbers, avoiding JavaScript integer loss. `deadline_ms` may only shorten the operation-specific server maximum and is clamped to at least one millisecond. Close codes and event variants are a closed negotiated enum, not caller-supplied log text.

The client sends `Hello { min_minor, max_minor, client_version, feature_bits_hex }`; `feature_bits_hex` is exactly 16 lowercase hexadecimal characters. The service responds with the same major, the highest mutually supported minor, the random 64-bit connection epoch as 16 lowercase hexadecimal characters (matching its header), service/bundle versions, ledger schema range, selected feature bits in the same encoding, and capability health. Major `1` is incompatible with any other major. Each release supports the current and immediately previous minor for at least one LocalSandbox release cycle. New fields/features are used only after negotiation. No intersection returns `INCOMPATIBLE_PROTOCOL { service_range, required_client_range }` and closes. Artifact/SeaWork versions are metadata, not exact equality authentication.

The v1 request enum is fixed enough to generate both Rust and TypeScript declarations:

| Operation | Request/result contract |
| --- | --- |
| `GetServiceInfo`, `HealthCheck` | No caller identity/config fields; return versions/ranges, selected features, capacity and redacted WHPX/SMB/WFP/bundle health |
| `StartSandbox` | `{ cpus, memory_mib, disk_mib, mounts[], ports[], network? }` → owner-bound `sandbox_id`, chosen ports, and `{ mount_id, backend: "pinned-ro" | "staged-sync" | "overlay" }[]`; no `dataDir`, instance/base/from/checkpoint ID, runtime/QEMU path, owner SID/PID, or policy override |
| `StopSandbox` | `{ sandbox_id }` → empty idempotent success for the owner; it never stops SCM |
| `Exec`, `Spawn`, `KillProcess` | Sandbox/process IDs plus `command: { argv: string[] } | { shell: string }`, optional guest `cwd`/environment; `Spawn` returns process and stdout/stderr stream IDs, exit is an ordered event |
| Guest files | `ReadFile`, `WriteFile`, `Mkdir`, `ReadDir`, `Stat`, `Remove`, `Rename`, `Copy`, `Chmod`, `Exists`; all paths are guest-absolute normalized strings. File bytes use declared-length credited streams. |
| Watches | `Watch { sandbox_id, guest_path }` → watch/event-stream IDs; `StopWatch` is owner-idempotent and event queues coalesce within the stated cap |
| Session | `CloseSession {}`; the server performs the same owner cleanup on pipe break |
| Installer admin | `PrepareUpdate { target_bundle, target_protocol_range }`, `CommitUpdate { update_id }`, `AbortUpdate { update_id }`, `PrepareUninstall {}`; accepted only when the already authenticated process token is elevated Administrator and its protected image is signed by the configured SeaWork app/installer maintenance publisher |

Mounts are `{ mode: "overlay" | "direct-ro" | "direct-rw", host_path, guest_path }`, not numeric flags. Ports are `{ host: u16, guest: u16, protocol: "tcp" }`; UDP is not v1, and `host=0` asks the service to choose an isolated high port returned by `StartSandbox`. `network` contains bounded outbound host patterns and caller-supplied host-scoped secrets/HTTPS headers; `exposeHost` is deliberately absent as described in section 8. A command is at most 64 KiB, at most 256 environment entries/128 KiB total, 16 mounts/ports, 256 network patterns, and the enclosing control frame still must fit 256 KiB. Secrets are accepted as sensitive bytes, zeroized after transfer to the engine, and never emitted in errors/logs.

### Requests, handles, streams, and errors

- After Hello, the client's single writer encodes the server-issued connection epoch in the high 64 bits and a strictly consecutive control sequence starting at one in the low 64 bits for `Request`, `Cancel`, `WindowUpdate`, and `Close`; a Cancel payload names the target request ID and WindowUpdate names the stream. Because pipe frames arrive in write order, the server stores only `last_accepted_sequence` plus the bounded active-request map: a wrong epoch, gap, duplicate, or old sequence gets `DUPLICATE_REQUEST`/`INVALID_SEQUENCE` and is never executed. This proves duplicate handling without an ever-growing completed-ID set. Responses may complete out of order and retain the original request correlation ID.
- Resource IDs are independent random `u128` values. The capped server map stores connection ID and the full immutable `ClientIdentity` key alongside each sandbox/process/watch/stream. Every lookup checks all bindings before returning a generic `RESOURCE_NOT_FOUND`; guessed handles reveal no ownership. Retired-handle idempotency uses a 4,096-entry/10-minute LRU per connection; after eviction, a repeated close safely returns `RESOURCE_NOT_FOUND` rather than growing memory.
- Resource-creating requests are at-most-once. If `StartSandbox` succeeds but its response is lost, disconnect cleanup destroys it. The client never blindly retries start. Automatic retry is allowed only for Hello and read-only `GetServiceInfo` before resource creation.
- `Cancel { request_id }` is best effort and idempotent for an active request. Unknown/completed IDs return `REQUEST_NOT_ACTIVE`. Cancellation propagates into boot, file copy, guest commands, and waits; cleanup remains shielded from request cancellation.
- Defaults are 30 seconds for unary operations, 120 seconds for boot, 5 minutes for file transfer/copy, with a hard server maximum of 10 minutes. The server enforces its own monotonic deadline even when a client supplies a shorter one.
- At most eight connections globally and two per kernel-reported PID may be in the unauthenticated handshake state; accepts are limited to 20/s with burst 40, and Hello must finish within five seconds. Raw clients therefore cannot allocate sandbox/session machinery. After the first byte of any later frame, its header must finish within five seconds and its payload within ten seconds or the connection closes; an otherwise idle authenticated connection may remain open while its process handle is alive. One reader task feeds a bounded 64-frame dispatch queue. At most 16 request handlers run per connection and 64 globally. One writer owns a queue bounded by both 128 frames and 16 MiB; failure to enqueue a control response within five seconds closes only that connection and starts owner cleanup.
- Each output/file stream has a random owner-bound ID, direction, declared maximum/length where known, and strict chunk sequence. A duplicate/out-of-order chunk aborts that stream; `WriteFile` writes a temporary guest file and commits only after exact declared length/end validation. Streams start with 256 KiB credit. `WindowUpdate` grants more only after the receiver consumes bytes. A stream can buffer at most 4 MiB, a connection 16 MiB, and the service 128 MiB. If credit remains zero for 30 seconds, terminate the associated guest process and return `OUTPUT_BACKPRESSURE`; never block the service-wide writer or grow unbounded. Node `exec` collects at most 8 MiB combined stdout/stderr before cancelling with `OUTPUT_LIMIT`; `spawn` remains streaming and can exceed 8 MiB only as the client consumes credit.
- A clean `CloseSession` stops only that connection's resources and then closes. A broken pipe/process exit does the same immediately with a 30-second cleanup bound. There is no lease, heartbeat, adoption, or survival across disconnect/restart in v1. A reconnect creates a new empty session.

Stable error envelopes contain `code`, safe `message`, `retryable`, optional `retry_after_ms`, and `correlation_id`; Win32/internal details go only to protected diagnostics. Required codes include `ACCESS_DENIED`, `CLIENT_NOT_TRUSTED`, `SERVER_NOT_TRUSTED`, `SERVICE_UNAVAILABLE`, `SERVICE_DRAINING`, `INCOMPATIBLE_PROTOCOL`, `LEDGER_SCHEMA_INCOMPATIBLE`, `PROTOCOL_ERROR`, `INVALID_REQUEST`, `INVALID_SEQUENCE`, `MESSAGE_TOO_LARGE`, `DUPLICATE_REQUEST`, `REQUEST_NOT_ACTIVE`, `RESOURCE_NOT_FOUND`, `QUOTA_EXCEEDED`, `DEADLINE_EXCEEDED`, `CANCELLED`, `CANCELLATION_TOO_LATE`, `OUTPUT_LIMIT`, `OUTPUT_BACKPRESSURE`, `PATH_POLICY_DENIED`, `PATH_CHANGED`, `MOUNT_PATH_BECAME_UNSAFE`, `MOUNT_CONFLICT`, `MOUNT_UNAVAILABLE`, `NETWORK_POLICY_DENIED`, `PORT_ISOLATION_UNAVAILABLE`, `BUNDLE_INVALID`, and `INTERNAL_ERROR`.

Protocol 1.5 adds commit-aware cancellation for synchronous guest filesystem mutations. Cancellation/deadline and commit are one atomic race. Before commit, the request settles only after worker cleanup and returns `CANCELLED` or `DEADLINE_EXCEEDED`; after commit, the Cancel control returns `CANCELLATION_TOO_LATE` and the original request returns its actual result. A negotiated 1.4 client receives known `REQUEST_NOT_ACTIVE` instead of the new error enum. Exact operation commit points and Windows verification requirements are in `docs/filesystem-cancellation.md`.

### Concurrency and quotas

Multiple app instances, Windows sessions, and users are supported; a logon SID/authentication LUID separates two logons of the same account. Defaults are administrator-protected config with compiled ceilings:

| Resource | Per connection | Per user SID | Global | Additional bound |
| --- | ---: | ---: | ---: | --- |
| Pipe connections | — | 4 | 32 | 100 requests/s, burst 200 per connection |
| Sandboxes | 2 | 4 | 8 | random owner-bound handles |
| vCPU | 8/sandbox | 8 | 16 | 1–8 per sandbox |
| Memory | 8 GiB/sandbox | 8 GiB | 24 GiB | minimum 512 MiB |
| Virtual disk | 32 GiB/sandbox | 64 GiB | 128 GiB | minimum 1 GiB |
| Guest processes | 64/sandbox | 128 | 256 | includes exec/spawn concurrency |
| Host ports | 16/sandbox | 32 | 128 | only 1024–65535, owner-isolated |
| Mounts | 16/sandbox | 32 | 128 | traversal/copy bounds below |
| Watches | 64/sandbox | 128 | 512 | bounded event queue/coalescing |
| File transfer | — | — | — | 1 GiB/request, 10 GiB staging/session |

Admission reserves quota before side effects and releases it only after cleanup. CPU/memory/disk arithmetic is overflow-checked; effective global memory is also no more than 75% of detected physical memory, and disk admission checks/reserves the full logical writable-disk plus staging allowance against actual free protected-volume space. Each QEMU Job additionally sets kill-on-close, active process limit 8, a job-memory limit of requested guest memory plus a Phase 0-measured overhead allowance (2 GiB is the candidate, then frozen as a compiled ceiling), CPU-rate control proportional to requested vCPU/logical processors, and an I/O completion port for limit/exit notifications. Global memory admission counts that overhead; protected config may lower but not raise compiled ceilings. Replace the post-spawn assignment window with one Win32 child supervisor: `CreateProcessW(CREATE_SUSPENDED | CREATE_NO_WINDOW)` using a minimal explicit environment and protected absolute image/CWD, assign the process to the fully configured Job, then `ResumeThread`. QEMU, `qemu-img`, and every other service-launched host helper use this path; assignment/resume failure terminates the suspended process. If the service itself is already in a job, nested-job support is verified and failure to apply containment rejects sandbox creation.

Each sandbox also has a 32-command admission queue. Start/stop/checkpoint-style lifecycle transitions are exclusive; guest-control operations remain serial because the current guest channel is not multiplexed, while independent stream delivery continues. Stop changes state before enqueue, cancels queued/running work, and cannot sit behind an unbounded command backlog.

## 8. Authorization and path-safety design

### Threat model and invariants

Assume a standard local user intentionally speaks malformed/raw protocol; a same-user process is compromised; another user/session guesses resources or connects to owner ports; a caller requests system/other-profile/reparse/replaced paths; caller-owned cleanup state is forged; a client attempts capacity exhaustion; service/app/machine/update crashes mid-step; and a lower-privileged user tries to replace binaries, assets, config, ledger, logs, or staged updates.

The first release must maintain these invariants:

1. Once an administrator installs SeaWork, standard-user launch/use causes no UAC prompt.
2. Identity comes only from the live pipe/token/process, never request claims.
3. `LocalSystem` cannot access or mutate a caller path beyond both the caller token's requested access and the explicit product policy.
4. A connection/user cannot observe or control another's handles, VM, files, processes, ports, credentials, or logs.
5. Only protected service-owned state authorizes privileged cleanup.
6. Parsing, work queues, streams, VM resources, host objects, and filesystem work are bounded and fail closed.
7. Binaries, dependencies, trusted config, runtime assets, ledger, and logs are administrator/service writable only.
8. Stop, disconnect, crash, reboot, failed start, and partial setup converge through idempotent cleanup.
9. Incompatibility fails explicitly and never falls back to an unsafe interpretation/helper.

### Trusted state versus caller paths

The service owns `%ProgramData%\LocalSandbox\SeaWork`; callers cannot select it. Mutable VM disks, instance directories, caches, staged overlay copies, secrets, logs, and ledgers live there, partitioned internally by a SHA-256 hash of `{user SID, logon SID/authentication LUID}` and by random sandbox ID. The partition is an accounting/organization boundary, not a user-writable directory. ACL it to the service SID, SYSTEM, and Administrators only.

`dataDir`, `instanceId`, `baseVersion`, and runtime/QEMU paths are absent from the service API. User-visible exports are a separate operation: while impersonating the client, create/open a destination parent and temporary file with the client's token, write only through held handles, flush, and atomically rename within that parent. The result therefore inherits/receives user ownership and ACLs without exposing service control state.

### Exact MVP mount policy

Only an existing absolute directory on a local fixed NTFS or ReFS volume is eligible. Reject UNC, mapped/network drives, device/global-root paths, volume roots, relative paths, ADS, removable media, FAT/exFAT, EFS-encrypted files, offline/cloud-recall placeholders, final or intermediate reparse points/junctions/symlinks, and any existing reparse entry in a recursively authorized tree. Direct mounts also reject regular files with more than one hard link. Always deny `%SystemRoot%`, `%ProgramFiles%`, `%ProgramFiles(x86)%`, `%ProgramData%`, the service install/state trees, volume roots, and every other user's profile root discovered from the protected ProfileList registry—even if an unusually privileged client token could read them. A workspace under the authenticated user's own profile may pass the remaining checks; no other profile root does. There is no MVP administrator allowlist that bypasses protected roots.

V1 never shares a caller tree read-write in place. A temporary SMB account would own newly created host files, and after a crash the service cannot safely recover the caller token to fix an orphan owner SID. Therefore `direct-rw` always uses staged-sync and writes back under the live client token. `direct-ro` may use pinned-ro only if its timing proof and caller `WRITE_DAC` authorization pass; otherwise it also uses staged-sync.

For each requested mount, steps 1–3 authorize the caller tree and select that backend. Steps 4–5 apply only to pinned-ro; a staged selection jumps directly to the fallback workflow and never changes the caller tree's DACL or shares its path.

1. Under the held client impersonation token, walk every path component with `CreateFileW(FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)`. Omitting `FILE_SHARE_DELETE` pins every opened directory against rename/delete. Open the authorized root separately with RO `FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | FILE_READ_EA | READ_CONTROL | SYNCHRONIZE`, adding `FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_DELETE_CHILD` for RW. Reject a reparse tag at every level; query final volume-GUID/DOS paths, volume serial, `FILE_ID_INFO`, filesystem/drive type, attributes and owner/DACL. Compare protected-root ancestry through opened identities/canonical volume paths rather than a case-sensitive string prefix, covering 8.3 aliases. Retain component/root handles until the mount is fully torn down.
2. For every recursively exposed entry, open handle-relative under the client token with exact RO read/attribute rights or RW write/append/delete rights as applicable, then perform `AccessCheck` against the actual descriptor as a recorded explanation—not as a substitute for the kernel open. Pinned-ro additionally requires `WRITE_DAC` on the root and every object that inheritance will modify; read access alone cannot authorize LocalSystem to change an ACL. If RO data access passes but `WRITE_DAC` does not, select staged-sync, which never changes the caller tree's DACL. RW selects staged-sync regardless of `WRITE_DAC`. Query link count and cap the walk at 100,000 entries and 10 GiB of file data. Reject a tree exceeding limits with a non-mutating error.
3. Reject if an untrusted SID other than the caller, SYSTEM, Administrators, or a well-known read-only principal can write/delete/`WRITE_DAC` on any ancestor or mount root. The authenticated caller may mutate its own tree, but held roots prevent replacement. Start a handle-relative change monitor before exposing pinned-ro or beginning staged propagation. A newly created/replaced reparse point, multi-link file, object outside the authorized root identity, or monitor overflow immediately revokes the mount and stops the sandbox with `MOUNT_PATH_BECAME_UNSAFE`. Phase 0/3 must prove on each supported Windows baseline that the SMB server cannot traverse a newly inserted reparse target outside a pinned-ro share before this fail-close; if that proof fails, RO also uses staged-sync—never the raw caller path.
4. For pinned-ro only, record root object identity and the exact intended ACEs in the protected ledger before mutation. Change the DACL with handle-based `SetSecurityInfo`, not the current path-based helper, and preserve its protection/inheritance state plus every unrelated ACE. Add a root ACE and an `OI|CI|IO` inheritance-only ACE containing only `FILE_GENERIC_READ | FILE_GENERIC_EXECUTE`; never grant write, delete, `WRITE_DAC`, `WRITE_OWNER`, or system-security rights. Use the unique temporary account SID; after propagation, verify both exact ACEs/identity. If propagation exceeds a bounded deadline, roll back and fail.
5. For pinned-ro only, `NetShareAdd` still needs a path. Derive that string from `GetFinalPathNameByHandle`, keep all pins open, create a strict service-generated read-only share, query it back, reopen the share root with `OPEN_REPARSE_POINT`, and require the same volume/file ID before handing credentials to the guest. Any mismatch triggers reverse rollback.

The safe staged-sync backend is an implementation requirement, not an insecure compatibility switch. It creates a protected per-mount staging directory, copies the authorized snapshot into it while impersonating the client, and shares only staging. `direct-ro` continuously applies authorized host changes to staging and makes the SMB share read-only. `direct-rw` additionally applies guest staging changes back through handle-relative operations while impersonating the client, so created output receives user ownership/ACLs and no temporary-account SID reaches the caller tree. Watchers are hints; reconciliation runs at least once per second while dirty and periodically while apparently idle to catch loss/overflow. Maintain a per-relative-path baseline `{file ID, size, last-write time, content hash when needed}`; if host and guest both change an entry, return `MOUNT_CONFLICT`, stop propagation/sandbox safely, and preserve the protected staging copy for an explicit user-context export rather than overwrite either side. Existing reparse/link/entry/byte rules apply on every propagation. Guest SMB completion is not represented as a durable host-tree commit when this backend is selected; normal stop performs a final flush, while the protected 10 GiB/session staging quota is the hard crash-loss bound. `HealthCheck` reports available direct backends and `StartSandbox` reports the backend chosen for every mount, so SeaWork can disclose staged durability rather than assume pinned semantics.

Overlay/copy mounts are safer and preferred where semantics permit: while impersonating, copy from the held handle-relative traversal into an immutable service staging directory, enforcing the same reparse/type/entry/byte bounds. Subsequent VM work never reopens the caller path as SYSTEM. Read-write direct mounts always use the explicitly reported staged-sync semantics above.

Refactor current path-based SMB APIs to accept an `AuthorizedMountRoot` capability containing owned handles, identity, normalized display path (diagnostics only), caller SID, mode, verified security descriptor, and ledger transaction. It can only be constructed in service authorization code; `prepare_smb_mount` cannot accept a naked untrusted path in service mode. Existing non-service APIs may build a legacy capability under their own token but must not be callable from the service.

### Temporary SMB and policy behavior

Generate a random 256-bit password per sandbox, zeroize it, and never serialize it after guest handoff. Account names are exactly `lsbsw_` plus 13 lowercase unpadded base32 characters (65 random bits; 19 characters total), and share names are `lsbsw-` plus 26 such characters (130 random bits; 32 total); use the OS CSPRNG and fail after eight collision retries rather than fall back to predictable input. Accounts are verified absent from local groups, cannot change/expire passwords, receive `SeNetworkLogonRight`, and receive account-specific `SeDenyInteractiveLogonRight`, `SeDenyBatchLogonRight`, `SeDenyServiceLogonRight`, and `SeDenyRemoteInteractiveLogonRight`; journal/revoke every right. Share comments and account metadata include a non-secret service ownership GUID/ledger ID. The share DACL has only SYSTEM/Administrators full control plus the temporary SID with `FILE_GENERIC_READ | FILE_GENERIC_EXECUTE` for pinned-ro/staged RO or `FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE` for service-owned staged RW; it contains no Everyone/Users/Authenticated Users ACE. Caller-tree filesystem ACEs are only the exact pinned-ro pair above. Service-owned staging has a separate protected DACL granting the temporary SID only the requested RO/RW data rights; temporary ownership there is safe because cleanup deletes only the proven protected staging identity.

The service does not silently rewrite global LSA/GPO policy per request. Upstream `--verify-bundle` and service health report whether loopback SMB, LanmanServer, network-logon rights, and deny policies permit the design. SeaWork's installer may apply a documented one-time machine policy repair only with explicit product approval; domain GPO denial results in `MOUNT_UNAVAILABLE`, not repeated policy mutation.

### Port authorization

Client requested ports contain only guest/host port and protocol; no SID/firewall claim. Reserve a nonzero high host port (1024–65535) with exclusive IPv4 and IPv6 loopback sockets bound but not listening. In one WFP dynamic session under a fixed LocalSandbox provider/sublayer GUID, use a deliberately low-priority product sublayer and install within it a highest-weight `PERMIT` filter whose `FWPM_CONDITION_ALE_USER_ID` value is a self-relative security descriptor granting only the connection's OS-derived logon SID, with `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT`; then add a lower-weight `BLOCK` filter for everyone else. Scope both to the exact loopback destination port at ALE authorization-connect v4/v6 and the loopback flag/address. Do not substitute the account SID: two interactive logons of one account have distinct logon SIDs and are separate owners in this design. The hard permit resolves only the product's own fallback block; the sublayer must not outrank or clear action rights from Windows Firewall/EDR policy. Only after the transaction commits may the sockets call `listen`/accept; on cleanup close listeners before the WFP session/filters. Dynamic-session objects disappear when the service crashes.

This depends on a real Session 0 proof that `ALE_USER_ID` evaluates the logon-SID ACE as required for local loopback connects and cannot be bypassed by a second logon of the same account or through IPv4/IPv6 variants. If the Phase 0 proof fails or BFE/WFP is unavailable, the capability is false and every port request returns `PORT_ISOLATION_UNAVAILABLE`; there is no account-SID-only or unfiltered fallback. A future authenticated pipe tunnel can replace WFP without changing this fail-closed rule.

### Outbound network and host-exposure policy

Running the proxy as LocalSystem must not silently turn it into a machine-credential or local-network deputy. V1 omits current `network.exposeHost`: the service will not connect a guest to arbitrary host-loopback ports. Outbound guest networking uses only explicit caller host patterns intersected with administrator-protected product egress policy. Resolve and re-check every address at connection time; deny loopback, local interface addresses, link-local, multicast, unspecified, single-label/WPAD, and private ranges unless an administrator explicitly allowlists a destination/CIDR. DNS rebinding to a denied address fails the connection. Disable automatic proxy discovery and Windows integrated/default credentials (SSPI/Negotiate/NTLM); an explicit protected proxy configuration or caller-supplied host-scoped secret is required where authentication is needed. TLS trusts the LocalMachine root/CA stores plus an optional administrator-protected CA bundle, never a user profile/caller path, and the client cannot disable verification. The Session 0 spike verifies DNS, VPN routes, proxy and certificate behavior. These restrictions apply independently of the guest's requested host allowlist.

## 9. Sandbox/resource lifecycle and crash recovery

### Resource model

One accepted pipe creates a `Session` keyed by random connection ID plus immutable `ClientIdentity`. A service-global manager owns maps for sessions, sandboxes, guest processes, streams, watches, mounts, ports, and quota reservations. Public handles are unrelated random 128-bit values; internal records contain their parent handles and owner identity. Children cannot outlive parents. Closing a process/sandbox handle is idempotent; a retired handle remains tombstoned for the connection to distinguish duplicate close from live access without revealing cross-user resources.

The lifecycle state machine is:

```text
Reserved -> Preparing -> Running -> Draining -> Cleaning -> Removed
                |            |           |           |
                +----------->FailedSetup-+---------->Quarantined (only if proof lost)
```

Quota is reserved before `Preparing`. Each external side effect is recorded durably before it occurs and confirmed after it occurs. Cancellation changes admission/forward work, never cleanup. Rollback is reverse dependency order. Disconnect marks all session resources draining immediately; SCM stop drains every session concurrently. `CloseSession` has no SCM effect.

### Protected layout and durable ledger

```text
%ProgramData%\LocalSandbox\SeaWork\
  config\service.json                 # admin/service write; bounded schema
  state\ledger\<sandbox-id>.json      # service-authoritative transactions
  state\users\<identity-hash>\instances\<sandbox-id>\
  state\quarantine\
  runtime\                             # service temp/cache, never executable trust
  logs\
```

Apply a protected ACL for `NT SERVICE\LocalSandboxSeaWork`, SYSTEM, and Administrators; interactive users get no access. Validate that every parent through `%ProgramData%` is not user-writable. Config has a strict schema, compiled bounds, and no DLL/executable override outside the signed active bundle.

Each bounded ledger document includes schema/bundle version, random ownership GUID, caller SID/logon/authentication/session identity, resource IDs/state, QEMU PID creation time and Job identity, temporary account name/SID plus ownership marker, LSA right, share name/comment/path and security descriptor hash, authorized root volume/file ID/final path, optional exact pinned-ro ACE SID/mask/inheritance, staged-root identity and propagation baseline when used, WFP provider/sublayer/filter GUIDs, port reservations, protected files, and timestamps. It contains no password. All generated names include `lsbsw` plus cryptographic entropy; recovery never acts on a prefix alone.

Ledger parsing is sequential and capped at 1,024 documents, 256 KiB/document, 256 resource records/document, 32 KiB/string, and 64 MiB total accepted serialized state; excess/collision/case-conflicting files block admissions and enter administrator repair rather than allocating or deleting. Protected instance/staging disk usage remains within the global quotas in section 7.

Write a random, exclusive `.<id>-<random>.tmp` sibling in the same protected directory, validate/serialize a bounded document, `FlushFileBuffers`, atomically `ReplaceFileW` (or `MoveFileExW(MOVEFILE_WRITE_THROUGH)` for first creation), then flush the parent directory where supported. Concurrent writers never share a temporary; a failed attempt removes only its own sibling, and an interrupted sibling closes admissions through quarantine on restart. Journal `intent` before each privileged API, then query the object and journal `committed`. Deletion occurs only after all queried resources are absent and state directories are removed. The implemented admission/persistence envelope and remaining external-proof boundary are recorded in `docs/protected-ledger-reconciliation.md`.

Startup ignores every manifest below caller/user paths. It parses only protected ledger files with strict size/schema/path bounds. For each recorded object it must prove ownership before removal:

- account: exact recorded SID and service ownership metadata, not name prefix alone;
- share: exact name, ownership comment/GUID, root volume/file ID, and expected share security;
- ACL: exact root identity and exact ACE SID/mask inserted by this ledger; after handle loss prefer `OpenFileById` on the recorded volume and revalidate volume/file ID, removing only that ACE. A path reopen is never authoritative;
- QEMU/process: protected Job handle during life; after reboot, match recorded executable path, PID creation time, command resource ID, and ownership marker before termination—otherwise do not kill;
- WFP: exact provider/sublayer/filter GUID owned by this service (dynamic filters normally already vanished);
- files: only protected instance paths derived from the ledger's random ID after handle verification.

If proof is absent or contradictory, move that resource record to protected quarantine, log a high-severity event, and leave that unproven external object untouched for administrator repair. Continue independently provable neutralization: for example, delete an exactly proven share/account even if an unavailable volume prevents removal of its orphaned unique-SID ACE. Never guess-delete a similarly named user/share/process/path, and never let one unproven cleanup step keep a still-usable temporary account/share alive unnecessarily.

Admissions reflect quarantine scope: an unproven account/share/ACE disables new direct mounts but may leave mount-free sandboxes healthy; ambiguity in bundle/config/instance ownership or quota accounting keeps the service health-only. Health and Event Log expose only stable quarantine IDs/remediation, not secret paths.

### Setup, cleanup, and failure ordering

Setup order is: reserve quota and instance tree/job ledger → authorize/pin mounts and create staged roots where selected → create temp account → apply LSA rights/deny posture → add exact pinned-ro caller-tree ACEs or staged-root ACLs → create/verify shares → create WFP filters and bind ports → create/start QEMU in its Job → connect/boot guest → mark running. Every arrow has an intent/committed ledger transition.

Cleanup is the reverse safety order: stop admissions/cancel guest work → terminate QEMU Job and guest/proxy processes → close port listeners then WFP session → delete shares → remove only exact pinned-ro ACL ACEs by verified handle identity and delete proven protected staging → remove LSA rights then temporary user → delete remaining proven protected instance files → release quotas/delete ledger. Deleting staging before the account avoids leaving its owner SID even inside quarantine. Cleanup aggregates errors, retries transient “in use” conditions with a bounded schedule, and is idempotent.

Consequences by event:

| Event | Required behavior |
| --- | --- |
| Client/app crash or pipe break | Stop only that connection's resources immediately; 30 s graceful bound, then Job kill; ledger handles remaining host cleanup |
| SCM STOP/preshutdown | Stop admissions, drain every session concurrently, report checkpoints, force Jobs at deadline, persist unresolved cleanup, then stop |
| Service crash/forced termination | Job `KILL_ON_JOB_CLOSE` kills QEMU; WFP dynamic session removes filters; protected intents remain for next-start SMB/ACL/account/share cleanup |
| Power loss/reboot | OS kills processes and clears dynamic WFP; automatic service startup reconciles protected ledger before accepting clients |
| Partial setup | Reverse all committed steps; an uncertain API result is queried using recorded identity before retry/undo |
| Failed boot | Same rollback; no public handle returned, quota released only when cleanup converges |
| Normal restart/upgrade | SeaWork requests drain, SCM stops; clients lose sessions and must recreate after health succeeds |
| Uninstall | Administrator-only prepare-uninstall drains/reconciles; SCM removal proceeds only when clean, otherwise signed service/state stay in health-only repair mode |

For staged-sync direct mounts, normal sandbox/session stop drains already observed guest deltas through the still-live client token before SMB teardown. A service crash cannot persist a Windows token, so startup must never apply an uncommitted staging delta as LocalSystem. It quarantines that protected delta, deletes/neutralizes privileged SMB resources, and reports possible recent-write loss; v1 does not promise automatic recovery/adoption after a crash. Tests bound and document the acknowledged-write window, while the implementation minimizes it by syncing continuously rather than only at stop.

The current caller-writable SMB manifests are not migrated or imported. Pre-service SeaWork must stop its one-shot helper and clean its resources using the old version before the service installer proceeds; remaining ambiguous legacy resources are reported for explicit admin remediation.

## 10. Upstream artifact and SeaWork integration contract

### Artifact layout, versioning, and signing

Publish these additional GitHub release assets for every supported LocalSandbox release:

```text
lsb-seawork-service-v<VERSION>-windows-x86_64.zip
  LocalSandbox/
    bin/localsandbox-seawork-service.exe
    runtime/Image
    runtime/initramfs.cpio.gz
    runtime/rootfs.ext4
    runtime/VERSION
    tools/qemu/<complete pinned managed QEMU distribution>
    manifests/bundle.json
    manifests/service-contract.json
    manifests/sbom.spdx.json
    manifests/LocalSandboxSeaWork.cat
    licenses/<LocalSandbox and third-party notices>

lsb-seawork-service-v<VERSION>-windows-x86_64-symbols.zip
  LocalSandbox/bin/localsandbox-seawork-service.pdb
  LocalSandbox/manifests/source-map.json
```

The archive uses the same SemVer/tag as the Rust/Node release, not an independent service version. ZIP is preferable to extending the CLI tarball or hiding this in an NPM postinstall because the per-machine installer needs a fixed multi-file payload, native Windows extraction, catalog verification, and independent pinning. `bundle.json` includes schema version, LocalSandbox/service/client/protocol current and supported ranges, ledger reader/writer ranges, architecture/target, guest asset version, QEMU package/version, every payload file's relative path/size/SHA-256, required service configuration revision, and publisher identity. It does not list itself or the catalog, avoiding a hash cycle. `service-contract.json` machine-encodes every table field in section 6 plus pipe name/full SDDL, health requirements, and install-state schema, so SeaWork validates rather than hand-transcribes the contract. SeaWork pins a pair: its exact upstream NPM packages and archive SHA-256 whose protocol ranges intersect. The wire compatibility rule, not equal package strings, permits staged machine-wide upgrades.

LocalSandbox's release owner must provision an organization-controlled Windows code-signing identity before the packaging phase can ship. Prefer Azure Artifact Signing where organization geography/policy supports it; otherwise an organization EV/managed signing certificate. Embed an SHA-256 Authenticode signature and RFC 3161 timestamp in the service executable. Generate and sign `LocalSandboxSeaWork.cat` covering every payload executable, DLL, VM image, QEMU file, license and `bundle.json`; the catalog necessarily excludes itself. Publish `SHA256SUMS` and a GitHub Actions artifact attestation for the archive and symbols. The signed catalog is the payload integrity root, while the pinned archive digest/attestation covers the catalog and archive structure; PE signatures alone do not cover arbitrary assets. PDBs are never installed by default.

The release order is deterministic: build service/PDB and guest/QEMU payload → embed/timestamp the service PE signature → inventory/hash payload into `bundle.json` and `service-contract.json` → generate catalog membership over both manifests and every payload → sign/timestamp catalog → assemble deterministic ZIP → hash/attest ZIP and symbols. Reproducibility is evaluated before nondeterministic signatures; provenance binds the signed outputs to the commit/workflow.

SeaWork verifies, before copying: its pinned archive SHA-256; GitHub provenance where policy permits; catalog signature chain, timestamp and allowlisted publisher/thumbprint; that `bundle.json` and every listed payload file are catalog members and every payload matches its manifest hash/size; that no unlisted executable/DLL is present; the embedded service signature; architecture; and protocol/config ranges. Its ZIP reader rejects absolute/drive/UNC paths, `..`, ADS, duplicate or case-fold-colliding names, symlinks/reparse entries, non-regular payloads, count/expanded-size bombs, and anything outside the closed archive set (`bundle.json`, `LocalSandboxSeaWork.cat`, and the payload paths listed by `bundle.json`) before extracting into a newly created administrator-only staging directory—never Downloads or a user temp path. After copy, it repeats verification from the final protected version directory.

### Installation/configuration

Install immutable versions under `%ProgramFiles%\SeaWork\LocalSandbox\versions\<VERSION>\...`. Do not use a user-writable path or `current` junction. Stable SCM registration `LocalSandboxSeaWork` points directly to the active version's quoted absolute executable; an upgrade changes `ImagePath` while stopped rather than delete/recreate. Keep the previous verified version until health succeeds and rollback is no longer needed. State remains under `%ProgramData%` and is not version-directory state.

Initial install, owned by SeaWork:

1. Verify the pinned artifact in protected staging; copy an immutable version and apply protected ACLs.
2. Create the stable service and apply every field in section 6: description, delayed auto-start, LocalSystem, unrestricted service SID, service DACL, preshutdown timeout, failure actions, Event Log source, and quoted versioned ImagePath. Validate the resulting SCM configuration, including unquoted-path attacks.
3. Apply protected ProgramData ACL/config and any explicitly approved one-time SMB machine-policy prerequisite. Never make app users owners/writers.
4. Start the service as administrator. Connect through the upstream client and call `GetServiceInfo`/`HealthCheck`, requiring expected publisher/bundle version, protocol intersection, ledger schema compatibility, protected path ACLs, WHPX availability, guest assets, QEMU signature/hash, and capability status for SMB/WFP. A minimal boot/exec smoke test may be installer-selectable because it is slower.
5. Record the installed bundle/client compatibility in SeaWork's protected installer state. Subsequent ordinary app startup only connects; no UAC/elevation/helper fallback.

If SeaWork's existing virtualization prerequisite enables WHPX/Hyper-V but Windows requires reboot, the installer may finish staging/registering the signed automatic service but records `reboot-required` and does not claim a successful runtime smoke test. Before reboot the app shows that non-elevating state; after reboot automatic startup/reconciliation plus the same health check must pass. Versioned directories avoid a reboot merely for locked binary replacement; a marked-for-deletion or OS prerequisite reboot remains an explicit installer state.

NSIS never implements or serializes the pipe protocol. For install health and every admin RPC below, SeaWork launches a narrowly scoped maintenance entry in its already installed, protected, signed app while the installer token is elevated; that entry calls the same upstream Node client API and returns only a bounded JSON status to NSIS. It is not a sandbox helper or server, cannot create sandboxes in maintenance mode, and exits after the single installer transaction. Normal app startup calls the same upstream client unelevated. This preserves SeaWork ownership of installer orchestration without moving wire/authentication/cleanup code downstream.

### Update, rollback, repair, downgrade, uninstall

- **Update:** SeaWork stages/verifies the new version, writes an administrator/service-only pending-update record containing old/new versions, ledger writer schema and a random update ID, then asks the old service through administrator-authorized `PrepareUpdate` to drain that exact target. The service independently verifies the caller token is Administrator and returns the update/drain status; ordinary clients receive `SERVICE_DRAINING`. SeaWork issues SCM stop and waits up to 60 seconds, calls `ChangeServiceConfig` for ImagePath without deleting the service, and starts the new service. Seeing the pending record, the new service reconciles and accepts only Hello/Health/admin RPC—not `StartSandbox`—while continuing to write the old ledger schema. After signature, protocol, state-reader and runtime health pass, SeaWork sends `CommitUpdate { update_id }`; the service atomically selects the new writer schema, removes pending state, and opens admissions. Existing sessions/sandboxes were intentionally stopped; older app processes reconnect only if protocol-compatible, otherwise show “SeaWork update required.”
- **Interrupted update:** before ImagePath change, the old version remains active and `AbortUpdate` clears maintenance. After the change but before commit, protected pending state keeps the new service health-only and the old writer schema intact; repair can stop it and atomically roll ImagePath back to old. After commit, rollback is allowed only by the schema rule below. Files in a partial staging version are never executable trust and are removed only after verification.
- **Rollback:** stop/drain, point ImagePath to the previous signed version, and start/health-check. Permit only if that binary's declared ledger reader range includes the current on-disk schema. Ledgers use additive, versioned records; pending-update mode prevents the new writer schema before `CommitUpdate`.
- **Downgrade:** same as rollback, but refuse with `LEDGER_SCHEMA_INCOMPATIBLE` if the target cannot safely read/reconcile current state. Do not delete state to force a downgrade.
- **Repair:** reverify final files/catalog, restore ACLs and exact SCM configuration, reconcile protected state, restart and health-check. It never imports user cleanup metadata or weakens authorization to regain function.
- **Uninstall:** an elevated SeaWork uninstaller sends administrator-only `PrepareUninstall`, which drains/reconciles all resources and returns either clean or a precise protected quarantine report. Only a clean result permits SCM stop, `DeleteService`, closing all SCM handles, unregistering the Event source/provider, removing owned WFP provider/config if static metadata exists, and removing verified version/state directories. If ownership/cleanup is uncertain, uninstall fails safely and leaves the signed service plus protected state installed in health-only repair mode; it never strands unproven resources by deleting their cleanup authority and never deletes unrelated users, shares, ACEs, files, or processes. After repair/admin resolution, retry uninstall. Handle “marked for deletion”/reboot explicitly rather than recreate the service under the same name.

### Downstream code migration

SeaWork removes `launcher.ts`, helper mode/entry/server/protocol, UAC launch/retry/PID/nonce handshake, elevated-helper shutdown, and downstream path security decisions. Its manager becomes a thin product adapter over upstream `connectSeaWorkService`, maps stable upstream errors to UX, reconnects only to create a new empty session, and never automatically retries resource creation. During rollout there is no standard-user helper fallback. Machines lacking the service show an installer repair/update action that requires an administrator at that explicit maintenance point.

## 11. Implementation phases

### Phase 0 — Session 0 feasibility and security spikes (upstream first)

**Objective/dependencies.** Before a large refactor, prove the broad service account and all context-sensitive Windows behavior from a true SCM `LocalSystem` process on disposable Windows 11 x64. No dependency on later phases.

**Files/modules.** Add nonshipping `crates/lsb-service-spike/{Cargo.toml,src/main.rs,tests/windows_session0.rs}` (`publish = false`) and `scripts/windows-service-spike.ps1`; keep it in the workspace as an ignored, administrator-required integration harness so the evidence remains reproducible. Reuse current SDK/QEMU/SMB code without public API changes. Record results in `docs/windows-service-feasibility.md` and CI machine prerequisites.

**Contracts.** Define a machine-readable result schema for service identity/session, WHPX boot/exec/stop, direct RO/RW SMB, watch propagation, DNS/proxy/VPN/certificate behavior, QEMU nested Job, WFP IPv4/IPv6 loopback user isolation, and full resource teardown. No production protocol yet.

**Migration/compatibility.** The spike is not shipped and changes no public API or persisted schema. Keep source/harness behind an ignored Windows integration-test feature, but delete generated binaries and machine-specific result files before Phase 1. Results are tied to the tested Windows build, QEMU/bundle version, and security policy so later OS/QEMU changes know when to rerun them.

**Tests.** Install/run a real service as LocalSystem; create a brand-new non-admin user with no cached admin credentials; boot/exec; mount RO/RW and watch; verify temp account/right/share/ACE teardown; test corporate proxy/VPN/certificate cases available; connect to a WFP-protected port as owner, a second user, and a second logon session of the owner account; crash/kill service and reboot; verify Job/reconciliation observations. Capture Defender/EDR alerts on a managed downstream machine.

**Acceptance.** The signed-off result demonstrates critical VM/SMB behavior in Session 0 or demonstrates a secure, bounded code adaptation explicitly owned by a later phase. If LocalSystem cannot support core WHPX/QEMU/SMB behavior at all, Phase 1 is blocked until the Windows owner records the evidence and selects another broad SCM account under the fixed MVP rule. WFP demonstrates owner-only loopback on IPv4 and IPv6; otherwise ports are formally disabled for v1 with the fail-closed capability already chosen. QEMU enters a kill-on-close nested Job. No behavior depends on a user profile, mapped drive, desktop, CWD, or PATH. This phase is the only required real-machine architecture gate.

### Phase 1 — Protocol model, SCM shell, protected configuration/state primitives (upstream)

**Objective/dependencies.** Establish a true service lifecycle and bounded parser/state foundations without exposing sandbox operations. Depends on Phase 0 account feasibility.

**Files/modules.** Add `crates/lsb-service-proto/{Cargo.toml,src/{lib.rs,frame.rs,message.rs,version.rs,error.rs,limits.rs}}`; add `crates/lsb-seawork-service/{Cargo.toml,build.rs,resources/LocalSandboxSeaWork.mc,src/{main.rs,scm.rs,status.rs,config.rs,paths.rs,logging.rs,ledger/{mod.rs,atomic.rs,schema.rs,reconcile.rs}}}`; update root `Cargo.toml` and `Cargo.lock`; add target dependencies on `windows-service = 0.8.1`, existing `windows-sys`, Tokio/Serde. Add compile-time service-name/config constants and compile the bounded Event Log message table into the service PE.

**APIs/contracts.** Implement the 32-byte frame and Hello/GetServiceInfo/Health schema, version/feature negotiation, stable errors, fixed protected paths, strict config/ledger schemas, atomic flush/replace, and SCM state/control channel. Add nonmutating `--version --json`/`--verify-bundle --json`.

**Migration/compatibility.** No Node/SeaWork use yet. Protocol golden vectors become compatibility fixtures; major 1/current+previous minor policy begins here.

**Tests.** Unit/property/fuzz tests for frame lengths/overflow/unknown fields/version ranges/error redaction; atomic-ledger crash points/corruption/quarantine; Windows service tests for prompt dispatcher registration, checkpoints/wait hints, STOP/preshutdown, protected path/DLL/config behavior, quoted path and service DACL verification. Hosted CI covers compile/unit; self-hosted installs the SCM service.

**Acceptance.** A signed-or-development service reaches RUNNING only after binding a health-only pipe, responds to compatible Hello, rejects malformed/incompatible frames within bounds, reports correct status transitions, and stops within deadlines. No user-writable input affects executable/config/ledger paths.

### Phase 2 — Named-pipe identity, session manager, quotas, and authorization capability (upstream security foundation)

**Objective/dependencies.** Make the pipe/token the authoritative security boundary before privileged RPC exists. Depends on Phase 1.

**Files/modules.** Add service modules `ipc/{mod.rs,pipe.rs,connection.rs,writer.rs}`, `security/{mod.rs,descriptor.rs,token.rs,impersonation.rs,client_image.rs,access.rs}`, `session/{mod.rs,manager.rs,handle.rs,quota.rs,cancel.rs}`; add `crates/lsb-service-client/{Cargo.toml,src/{lib.rs,pipe.rs,connection.rs,stream.rs,error.rs}}`; add `crates/lsb-seawork-service/tests/{pipe_security.rs,identity.rs,quota.rs}`.

**APIs/contracts.** Implement exact pipe/service SDDL constants and verification, remote rejection, raw narrow client open rights, pre-Hello SCM/PID/config/image server authentication, client token/process cross-check, RAII impersonation, Authenticode publisher policy, immutable client identity, random owner-bound handles, request/cancel/deadline semantics, queues/credit/backpressure, rate and global/per-SID quotas. Expose only Hello/Health plus test resources.

**Migration/compatibility.** Client/service both live upstream and share only the protocol crate; neither imports SeaWork code. Dev unsigned clients use a separately named development service/pipe.

**Tests.** Two users/two sessions/two processes; client and server PID/token-reuse races; a pre-start same-name pipe squatter receives zero bytes; low integrity/AppContainer/unsigned/wrong publisher; remote pipe attempt; ACL access-mask checks proving interactive users cannot create a pipe instance accepted as the service; malformed/oversized/slow/epoch/sequence frames; long-running request/retired-handle bookkeeping remains constant-space; disconnect/cancel/deadline; queue/output exhaustion; handle guessing/cross-control; parser fuzzing.

**Acceptance.** Both endpoints' identities are OS-derived and frozen before application data, impersonation is reverted under panic/cancel/error injection, resources are inaccessible across connection/logon/user, a pipe-name squatter learns nothing, and every listed cap fails deterministically without privileged side effects or unbounded allocation.

### Phase 3 — Handle-safe mount authorization and protected privileged-resource ledger (upstream security foundation)

**Objective/dependencies.** Prevent `LocalSystem` confused-deputy behavior and replace caller-writable SMB recovery. Depends on Phase 2 token capabilities and Phase 1 ledger.

**Files/modules.** Add service `security/path/{mod.rs,policy.rs,worker.rs,walk.rs,identity.rs,export.rs}` and `resource/{mount.rs,mount_sync.rs,transaction.rs}`. Refactor `crates/lsb-platform/src/windows_x86_64/fs/{copy.rs,mount_plan.rs,watch.rs}` and `fs/smb/{acl.rs,lifecycle.rs,share.rs,user.rs,types.rs}` to accept `AuthorizedMountRoot`/handle identities and exact generated ownership markers. Change `crates/lsb-vm/src/sandbox.rs` mount construction/cleanup to consume privileged capabilities rather than raw service paths. Add Windows integration fixtures under `crates/lsb-platform/tests/` and service security tests.

**APIs/contracts.** Implement exact protected-root/filesystem/reparse/EFS/cloud/network/removable policy, impersonated `CreateFile`/`AccessCheck`, recursive bounds, held handles, handle-based DACL changes, post-share identity verification, service prefixes, protected intent/commit ledger, exact-proof reconciliation, user-context export, and the staged-sync fallback/conflict contract.

**Migration/compatibility.** Keep legacy direct SDK APIs for non-service callers, clearly separated so the service cannot construct a privileged mount from a naked path. Do not read legacy user manifests in service mode.

**Tests.** RO allowed workspaces with pinned-ro and staged-sync, RW only with staged-sync, caller-owned output after guest create, and no temporary SID in the caller tree; host/guest one-way changes and deterministic two-sided conflict; denied Windows/Program Files/ProgramData/other profiles; ACL-denied rights; intermediate/final/new reparse/junction; rename/path-swap/hard-link attempts; mapped/UNC/device/ADS/EFS/cloud/removable/network; deep/large traversal; watcher overflow/periodic reconcile; propagation cancellation; forged user manifest; corrupt/forged protected ledger; similarly named unrelated accounts/shares/ACEs; failure after every setup step; crash/reboot reconciliation.

**Acceptance.** A caller cannot induce any host-path read/mutation its token plus product policy does not permit. Direct RO passes with pinned-ro only if the adversarial timing proof passes, otherwise with staged-sync; direct RW passes only with staged-sync and creates caller-owned output. SMB setup/teardown works through pinned identity, and reconciliation removes only externally re-queried, provably owned objects. User-writable metadata has zero cleanup authority and no temporary SID remains in caller-owned files.

### Phase 4 — Service engine, sandbox lifecycle, Job/WFP containment (upstream)

**Objective/dependencies.** Move the complete Node-independent VM lifecycle behind authenticated service resources. Depends on Phases 2–3 and Phase 0 WFP result.

**Files/modules.** Refactor `crates/lsb-sdk/src/{assets.rs,runtime.rs,process.rs,types.rs}` into an internal trusted `ServiceEngineConfig`/cancellable engine while preserving direct SDK behavior. Update `crates/lsb-vm/src/sandbox.rs`, `crates/lsb-proxy/src/{lib.rs,config.rs}`, and `crates/lsb-platform/src/windows_x86_64/qemu/{discovery.rs,process.rs,boot.rs}`; add service `engine.rs`, `resource/{sandbox.rs,process.rs,watch.rs,port.rs,network.rs}`, `windows/{job.rs,wfp.rs}`. Add service/SDK/proxy integration tests.

**APIs/contracts.** Trusted engine accepts verified bundle paths, service-generated instance IDs, `AuthorizedMountRoot`, quota reservation, cancellation token/deadline, bounded output sink, and protected ledger transaction. Force managed QEMU/assets, remove environment/PATH decisions in service mode, launch every host child suspended-before-Job assignment, add Job limits/completion notifications, implement WFP owner-isolated ports or capability false, and enforce the outbound policy/no-`exposeHost` contract in the proxy. Implement setup/cleanup ordering from section 9.

**Migration/compatibility.** Direct macOS and existing CLI/Node SDK behavior stays intact. Windows service behavior is a new explicit engine constructor, not activated by environment. Current helper remains downstream only until Phase 6 cutover.

**Tests.** Boot/exec/spawn/kill/file/watch/stop; bounded output and cancellation; quota reservation rollback; QEMU child/grandchild containment; client crash/service kill/SCM stop/power-reboot; SMB and port cleanup; WFP owner isolation; outbound DNS rebinding/private/loopback/default-credential denial; eight concurrent sandboxes within caps; two users; fault injection at each lifecycle transition.

**Acceptance.** A standard user uses the complete sandbox lifecycle over an authenticated connection with no UAC. Disconnect/stop/crash/reboot converge to the protected ledger, all child processes are Job-contained, and port behavior is owner-isolated or explicitly unavailable.

### Phase 5 — Full RPC and upstream Node client (upstream)

**Objective/dependencies.** Expose the SeaWork-required surface through a stable upstream client while preserving bounded streaming. Depends on Phase 4.

**Files/modules.** Complete `lsb-service-proto/src/message.rs`; service `rpc/{mod.rs,health.rs,sandbox.rs,process.rs,file.rs,watch.rs,admin.rs}`; `lsb-service-client` remote objects; update `bindings/nodejs/src/{lib.rs,config.rs,sandbox.rs,process.rs,types.rs}`, `bindings/nodejs/{Cargo.toml,Cargo.lock,package.json,index.d.ts,README.md}`, binding tests, and `bindings/nodejs/npm/win32-x64-msvc/package.json`. Regenerate binding loader/declarations only through the existing N-API tooling.

**APIs/contracts.** Add `connectSeaWorkService`, `SeaWorkServiceClient`, `SeaWorkServiceInfo`, `SeaWorkServiceHealth`, `ServiceSandboxStartOptions`, `RemoteSandbox`, and `RemoteProcess`; implement GetServiceInfo/HealthCheck/start/stop/exec/spawn/kill/file/watch/CloseSession and administrator-only Prepare/Commit/AbortUpdate plus PrepareUninstall. Remove unbounded process channels from the service route. Document retryability and compatibility.

**Migration/compatibility.** Existing direct `initSandbox`/`Sandbox.start` remain for non-service consumers in this release, but SeaWork's Windows integration must use the explicit service API. No exact SeaWork version check and no helper fallback.

**Tests.** Rust client/server contract, N-API conversion/error/stream/cancel tests, golden vectors shared across crate/binding, old/current minor combinations, lost start response/no retry, reconnect creates empty session, app-close does not SCM-stop, admin RPC token checks.

**Acceptance.** A small unelevated Node program can health-check, boot, use every SeaWork-required operation, stream with backpressure, stop, and close; it contains no pipe/security implementation and cannot send forbidden trusted fields.

### Phase 6 — Release artifact, CI, and downstream SeaWork integration contract (packaging last)

**Objective/dependencies.** Ship a verifiable upstream artifact and cut SeaWork over. Depends on all security/lifecycle phases.

**Upstream files/modules.** Update `xtask/src/{main.rs,release.rs}` with a `seawork-service` packager; `.github/workflows/{ci.yml,release.yml,release_nodejs.yml}` for Windows service/client build, self-hosted gates, catalog/PE signing, hashes, attestations, PDBs, and pair metadata; add bundle manifest/catalog generation/verification scripts, license inventory, release docs, Node package version metadata. Configure release profile to preserve/link PDB then strip/package appropriately.

**Downstream files (SeaWork-owned, not changed upstream).** Rename/update `apps/electron/src/main/sandbox-helper/{index.ts,composition.ts,manager.ts}` as a service-client adapter; remove `client.ts`, `directory-validation.ts`, `launcher.ts`, `helper-entry.ts`, `helper-server.ts`, `mode.ts`, `protocol.ts` and their eight `apps/electron/tests/sandbox-helper-*.spec.ts` tests; add service-manager/install-contract tests and remove helper-mode dispatch from `src/main/main-dispatch.ts`. Update `apps/electron/electron-builder.yml`, `apps/electron/scripts/windows/installer.nsh`, `privilege-separation-verification.md`, package pins, app errors/telemetry, and packaged-file assertions.

**Contracts.** Produce the exact archives/catalog/manifest in section 10; document stable SCM/pipe/config/API contracts, compatibility ranges, install/update/rollback/repair/uninstall recipes, signing publisher rotation procedure, and release checklist. SeaWork pins archive digest + NPM version and verifies final install.

**Migration/compatibility.** The elevated helper is removed only after service install health succeeds. Existing machines upgrade through the elevated SeaWork installer; app launch never invokes UAC as fallback. Old compatible clients may connect during a rolling app update; incompatible clients fail clearly. Service registration is updated, never routinely deleted/recreated.

**Tests.** Reproducible pre-sign bundle, hash/catalog membership and deterministic ZIP validation; archive traversal/collision/reparse/bomb rejection; SignTool signature verification; clean-VM install; standard-user no-UAC after reboot; active-session update; interruption before/after pending record, ImagePath and CommitUpdate; rollback/downgrade schema checks; repair; full uninstall/unrelated-object preservation; old/new client matrix; Defender/EDR evaluation. Upstream owns artifact/service tests; SeaWork owns installer/app E2E with the pinned upstream artifact.

**Acceptance.** A published, signed x86-64 archive and symbols asset can be independently verified and installed by SeaWork. The complete matrix in section 12 passes, the old helper is absent from production paths, standard-user normal use never elevates, and owner/version/signing/rollback documentation is release-ready.

## 12. Test and validation matrix

`H` = upstream hosted Windows CI, `S` = upstream disposable self-hosted Windows 11 x64 with admin/WHPX, `D` = SeaWork downstream installer/app test machine, `M` = managed enterprise Windows/EDR lab. Unit/fuzz tests also run on non-Windows where the module is platform-neutral.

| Scenario | Owner/environment | Pass criterion |
| --- | --- | --- |
| Admin installs once; separate brand-new standard user launches/boots/execs/stops | D + S | No UAC/credential prompt; service identity LocalSystem; result succeeds |
| Standard user has no admin membership/cached credentials and uses after reboot | D | Delayed-auto service/retry works; no `SERVICE_START` or elevation by app |
| WHPX prerequisite install reports reboot-required | D | Installer does not report false health; after reboot automatic service smoke succeeds and standard user sees no UAC |
| Two SeaWork processes, two users, two logon sessions | S + D | Concurrent own resources work; cross-handle/control/streams/files/ports return generic denial/not-found |
| Pipe/service ACL, creator rights, and pre-start pipe squatting | S | IU connects with narrow rights and may query SCM status/config, but cannot create an instance accepted as the service or SCM start/stop/change-config; squatter receives zero client bytes because SCM/PID/config/image verification fails; admin/SYSTEM management works |
| Remote, low-integrity, AppContainer, unsigned/wrong-publisher clients | S | Rejected before privileged request; no side effect; expected safe event |
| Impersonation early return, cancellation and test-profile unwind | H unit + S | No `.await` while impersonated; dedicated worker always returns to no thread token before another command |
| Malformed, oversized, unknown, wrong-epoch/gapped/duplicate sequence, slow-loris, flood messages | H fuzz + S | Bounded allocation/queues; duplicate semantics exact; millions of requests retain constant bookkeeping; offending connection closes; service remains healthy |
| Cancellation/deadline/lost Start response/backpressure | H + S | Work cancels; cleanup continues; Start never auto-replays; stalled stream kills only guest process at bound |
| Windows/system/Program Files/ProgramData/other-profile mount requests | S | `PATH_POLICY_DENIED`; no ACL/share/account change |
| RO/RW token denial and product policy | S two users | AccessCheck and recursive requested-mode checks reject; RO cannot be escalated to RW |
| Existing/new reparse/junction/symlink/multi-hard-link, mapped/UNC/device/ADS, EFS/cloud/removable/network | S | Exact documented rejection; change-monitor overflow fails closed; adversarial test proves pinned-ro SMB cannot escape before teardown or RO selects staged-sync |
| Rename/path-swap during authorize/ACL/share and share-root substitution | S stress | Held no-share-delete handles/identity detect or prevent swap; rollback exact |
| Direct SMB RO/RW and file watch in Session 0 | S + D | Pinned-ro/staged RO and staged RW guest semantics work; output is caller-owned; generated account/right/share/ACE/password cleaned completely; no temporary SID reaches caller tree |
| Staged-sync one-sided/two-sided change, disconnect and service crash | S + D | Authorized propagation/conflict semantics hold; crash never applies pending data as SYSTEM and reports the bounded recent-write-loss case |
| Forged caller cleanup manifest and guessed prefixes | S | Ignored; no external object removed |
| Protected ledger corruption/forgery and similarly named unrelated objects | H + S | Strict quarantine; cleanup only after exact SID/comment/file-ID/ACE proof |
| Failure injection after each temp-user/LSA/ACE/share/WFP/QEMU step | S | Reverse committed steps; second reconciliation idempotent; no unrelated mutation |
| QEMU/WHPX Job containment: child start, client crash, service crash, SCM stop, forced kill | S | Child is suspended until fully assigned; no injected pre-assignment escape; all QEMU/helpers/descendants exit by bound; ledger converges leftovers |
| Requested SCM STOP/preshutdown versus fatal service exit | S | Requested stop does not trigger failure-action restart during update/shutdown; unexpected fatal exit follows 5/30/120-second recovery schedule |
| Power loss/reboot during setup/running/cleanup | S VM snapshot/power cut | Auto-start reconciliation succeeds before pipe acceptance; dynamic WFP gone |
| CPU, memory, disk, process, port, mount/watch, connection, request/message/output limits | H + S | Boundary accepted; +1 returns deterministic quota error; no integer overflow/leak |
| WFP owner-only loopback IPv4/IPv6 including second user and a second logon of the owner account | S | Owning logon SID connects; other user/logon tokens are blocked; filter removal on close/crash. If not provable, ports capability remains false |
| Outbound DNS rebinding, localhost/private/link-local targets, WPAD/system proxy/default credentials, `exposeHost` | H + S + D | Denied unless protected policy explicitly allows a destination; no machine credential or host-loopback deputy; `exposeHost` is absent |
| DNS, proxy, VPN, certificate stores, no profile/CWD/PATH | S + D | Session 0 behavior matches documented supported network config or clear capability error |
| Old client/new service and new client/old service: previous/current minor | H + S + D | Highest intersection selected; feature gating works; other major/nonintersection clear failure |
| Active sandbox plus another logged-in user during upgrade | D | Admissions drain; all sessions stop; no cross-user prompt; compatible clients reconnect empty |
| Interrupted install/update around pending record, ImagePath, health and CommitUpdate; service marked deletion/reboot | D | Pre-commit service is health-only/old-schema; abort or rollback reopens safely; post-commit schema rule holds; stable service not routinely delete/recreated |
| Rollback and downgrade with compatible/incompatible ledger schema | D + S | Compatible previous version starts; incompatible downgrade refuses without deleting state |
| Repair after binary/config/ACL/state tamper attempts | D | User cannot tamper; admin repair restores exact signed/configured state and reports quarantine |
| Full uninstall with owned plus similarly named unrelated resources, and an unproven quarantine case | D + S | Clean case removes service/version/state/owned resources while unrelated objects remain; unproven case refuses SCM deletion and preserves repair authority |
| Binary path quoting, DLL search, protected install/state/log/config ACLs | H static + S | No writable path component/unquoted path/PATH load; exact ACL/service config verified |
| PE/catalog/archive checksums/provenance/PDB/license | H release | SignTool/catalog membership/hash/publisher/timestamp/attestation checks pass; symbols separate |
| Malicious ZIP paths, duplicate/case collisions, reparse entries and expansion bombs | H + D | Rejected before extraction; only exact cataloged manifest payload enters protected staging |
| Defender/EDR: LocalSystem launches QEMU, creates users/shares, LSA rights, ACL/WFP | M jointly | Alerts/policy documented; allowlisting/telemetry approved or release blocked with named product action |

Upstream hosted CI can own pure protocol/path-policy/ledger unit tests, fuzzing, Windows compilation, N-API tests, static artifact checks, and unprivileged pipe-client tests. Upstream self-hosted disposable Windows must own true SCM, multiple users/tokens, WHPX/QEMU, SMB/LSA/ACL, WFP, forced crash and reboot tests. SeaWork must own NSIS install/update/repair/uninstall, packaged Electron behavior, version-pair pinning, UX, active-user upgrade, and no-UAC assertions. Managed Defender/EDR and corporate proxy/VPN/GPO testing is joint because upstream cannot reproduce product fleet policy.

## 13. Migration, rollout, rollback, and hardening follow-ups

### Rollout sequence

1. Land Phases 0–5 behind an explicit experimental Node service API; keep existing direct APIs for other consumers.
2. Produce signed release-candidate artifacts and run upstream self-hosted plus SeaWork clean-machine E2E. Do not ship an unsigned production service.
3. SeaWork installer update installs/health-checks the service before an app build depends on it. The old elevated helper cleans any active legacy resources before cutover; the service never imports its manifests.
4. Roll a compatible SeaWork app that uses only the upstream service client. If service health is absent/incompatible, show repair/update; do not elevate or fall back.
5. After one release cycle, remove old helper files/mode/tests and any unused downstream privilege-separation exceptions. Retain installer rollback to the last signed compatible service.

Machine-wide updates are disruptive to active v1 sandboxes by design. The installer announces/quiesces, the service drains all users, and reconnect creates empty sessions. This deterministic rule avoids orphan adoption and cross-version object ownership. A previous client may keep working only until drain starts and only if its negotiated minor remains supported.

For the one-time helper migration, SeaWork's installer enumerates signed SeaWork app/helper processes across sessions and refuses cutover until they close normally, allowing each parent-owned helper to run its existing cleanup. It reports any remaining legacy `lsb_`/`lsb-` objects for old-version administrator repair but neither the new service nor installer deletes them from a prefix guess or imports user-writable manifests. New `lsbsw_`/`lsbsw-` names avoid collision. There is no period in which both helper and service create sandboxes.

### Post-MVP hardening, in priority order

- Measure actual privileges, then configure `SERVICE_REQUIRED_PRIVILEGES_INFO` or evaluate a virtual service account. Do not change the account without rerunning SMB/WHPX/WFP/enterprise tests.
- Split a narrowly privileged broker from a lower-privilege VM/session worker only if audit data justifies the added IPC/lifecycle complexity.
- Replace direct loopback publication with an authenticated pipe port tunnel if WFP deployment is unreliable or stronger same-user isolation is needed.
- Add persistent/reconnectable sandbox leases only with an explicit user/session authorization model, encrypted capability recovery, and upgrade adoption protocol.
- Support Windows Arm64 only after `lsb-platform`/QEMU/WHPX and release assets are real, then add a distinct `windows-aarch64` artifact.
- Add manifest-based ETW provider/schema if Application Event Log plus protected JSON is insufficient; preserve payload redaction.
- Add publisher-key rotation metadata with an overlap window signed by both old/new trust roots.
- Consider an MVP smaller mount allowlist (for example SeaWork workspace roots explicitly selected while unelevated) if recursive arbitrary-tree authorization has unacceptable performance. It may narrow functionality, never bypass handle/token checks.
- Evaluate RedirectionGuard only as defense in depth; its documented limitations do not replace handle pinning and reparse policy.

## 14. Risks and genuinely unresolved questions

The architecture/API decisions are complete. These remaining questions require evidence unavailable from macOS or an external organizational owner; each has a fail-closed outcome and a decision point.

| Risk/question | Missing evidence | Owner | Decision point / default |
| --- | --- | --- | --- |
| WHPX/QEMU and current proxy/network stack under LocalSystem/Session 0, including nested enterprise jobs | Real Windows execution with current bundle and policies | LocalSandbox Windows maintainer | Phase 0 acceptance before Phase 1; if LocalSystem itself fails, record the concrete blocker and choose another broad SCM account before implementation |
| Direct SMB RO/RW, file watching, LSA rights and inherited ACE propagation under Session 0/GPO | Admin disposable machine plus enterprise GPO machine | LocalSandbox Windows maintainer; SeaWork IT validation | Phase 0/3; unsupported GPO yields `MOUNT_UNAVAILABLE`, never weaker ACL/policy behavior |
| Live pinned-ro SMB cannot escape an authorized root through a reparse/hard-link inserted after authorization but before monitor teardown | Adversarial two-process test on every supported Windows baseline; public docs alone do not prove the timing property | LocalSandbox filesystem security owner | Phase 0/3 before advertising pinned-ro; if proof fails, use service-owned staged-sync for RO as already required for RW |
| WFP `ALE_USER_ID` logon-SID security descriptors fully isolate IPv4/IPv6 loopback across users, two logons of one account, and VPN/filter products | Multi-user/multi-logon Session 0 WFP experiment | LocalSandbox networking owner | Phase 0/4; if not proven, ship v1 with ports disabled and `PORT_ISOLATION_UNAVAILABLE` |
| Defender/EDR accepts a LocalSystem service launching QEMU and changing accounts/shares/LSA/ACL/WFP | Managed-fleet lab/allowlisting review | SeaWork security/desktop engineering with LocalSandbox evidence | Before release candidate; block deployment or document approved allowlist—do not evade controls |
| Windows code-signing publisher, Artifact Signing availability/geography, certificate custody and rotation | Organization account/security decision; current workflow has no Windows signer | LocalSandbox release/security owner | Before Phase 6 signing work; no unsigned production artifact. SeaWork installer owner separately pins/validates the approved publisher |
| Recursive authorization/ACE propagation performance on production-size workspaces | Representative Windows workspaces and AV/EDR timing | LocalSandbox performance owner, SeaWork supplies corpus | Phase 3 acceptance; narrow allowable workspace size/root policy rather than relax authorization |

Top implementation risks are (1) Session 0/network/EDR compatibility, (2) subtle path/ACL/share TOCTOU and exact cleanup proof, (3) cross-user host-port isolation, (4) durable lifecycle correctness at forced-crash boundaries, and (5) adding a trustworthy Windows signing/catalog path to a release pipeline that currently signs only macOS. None permits a temporary insecure fallback.

## 15. Sources

### Repository sources

- Node API/cross-language boundary: `bindings/nodejs/src/lib.rs:36-80`, `bindings/nodejs/src/{config.rs:44-176,sandbox.rs:29-134,408-432,process.rs:20-23,types.rs:72-167}`.
- SDK/assets/runtime: `crates/lsb-sdk/src/{assets.rs:17-128,runtime.rs:36,125-199,519-833,1463-1470,process.rs:67-71}`; platform paths/dispatch in `crates/lsb-platform/src/lib.rs:89-215`.
- VM/mount/ports: `crates/lsb-vm/src/sandbox.rs:129-384,929-1117,2503-2755,3971-4042`.
- Windows QEMU: `crates/lsb-platform/src/windows_x86_64/qemu/{argv.rs:54-164,boot.rs:574-901,discovery.rs:10-64,process.rs:474-603,829-975}`.
- Windows path/SMB: `crates/lsb-platform/src/windows_x86_64/fs/{copy.rs:271-385,mount_plan.rs:116-217,watch.rs:1-37,413-456}` and `fs/smb/{admin.rs:23-99,user.rs:56-150,share.rs:64-175,acl.rs:68-156,policy.rs:55-140,177-385,lifecycle.rs:94-224,287-475,583-639,types.rs:11-17}`.
- Targets/build/release: `Cargo.toml:1-20`, `Cargo.lock`, `README.md:13-22,102-116`, `crates/lsb-platform/{Cargo.toml:25-47,src/windows_x86_64/mod.rs:22-35,src/windows_aarch64/mod.rs:3-16}`, `.github/workflows/{ci.yml:34-78,release.yml:45-138,release_nodejs.yml:40-138}`, `xtask/src/release.rs:112-136`, Node package manifests.
- Downstream baseline inspected read-only: `../seawork/apps/electron/src/main/sandbox-helper/{launcher.ts:7-158,manager.ts:457-860,helper-entry.ts,helper-server.ts:121-400,protocol.ts:9-193,directory-validation.ts}` and `../seawork/pnpm-workspace.yaml:7-23`.

### Windows service/SCM primary documentation

- Microsoft, [Service Programs](https://learn.microsoft.com/en-us/windows/win32/services/service-programs), [Writing a ServiceMain Function](https://learn.microsoft.com/en-us/windows/win32/services/writing-a-servicemain-function), and [Service Status Transitions](https://learn.microsoft.com/en-us/windows/win32/services/service-status-transitions). These document prompt dispatcher connection, handler-first initialization, pending/running/stopped reporting, checkpoints, and wait hints.
- Microsoft, [`StartServiceCtrlDispatcherW`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicectrldispatcherw), [`RegisterServiceCtrlHandlerExW`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-registerservicectrlhandlerexw), and [`SetServiceStatus`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-setservicestatus).
- Microsoft, [`SERVICE_PRESHUTDOWN_INFO`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_preshutdown_info), [`SERVICE_DELAYED_AUTO_START_INFO`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_delayed_auto_start_info), and [`ChangeServiceConfig2W`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-changeserviceconfig2w).
- Microsoft, [`SERVICE_FAILURE_ACTIONS`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_failure_actionsa), [`SERVICE_FAILURE_ACTIONS_FLAG`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_failure_actions_flaga), and [`SetDefaultDllDirectories`](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-setdefaultdlldirectories).
- Microsoft, [LocalSystem Account](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account), [Service Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights), [Modifying the DACL for a Service](https://learn.microsoft.com/en-us/windows/win32/services/modifying-the-dacl-for-a-service), and [`DeleteService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-deleteservice).
- Microsoft, [`SERVICE_SID_INFO`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_sid_info) and [`SERVICE_REQUIRED_PRIVILEGES_INFO`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_required_privileges_infow); Raymond Chen/Microsoft, [What are the tradeoffs among the different ways of providing a service with a unique identity?](https://devblogs.microsoft.com/oldnewthing/20231004-00/?p=108849).
- `windows-service` maintainers, [`windows-service` 0.8.1 documentation](https://docs.rs/windows-service/latest/windows_service/) and [crate manifest/source](https://docs.rs/crate/windows-service/latest/source/Cargo.toml); Microsoft, [`windows-services` crate documentation](https://docs.rs/windows-services).

### Named pipe, identity, and path primary documentation

- Microsoft, [Named Pipe Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights), [`CreateNamedPipeW`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipew), [`ImpersonateNamedPipeClient`](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient), [`GetNamedPipeClientProcessId`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeclientprocessid), and [`GetNamedPipeServerProcessId`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeserverprocessid).
- Microsoft, [`QueryServiceStatusEx`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryservicestatusex), [`QueryServiceConfigW`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfigw), and [`QueryServiceConfig2W`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2w).
- Microsoft, [`GetTokenInformation`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation), [`TOKEN_INFORMATION_CLASS`](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class), [`TOKEN_STATISTICS`](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_statistics), and [Security Identifiers](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-identifiers).
- Microsoft, [Mandatory Integrity Control](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control).
- Microsoft, [`SetThreadToken`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadtoken) and [`RevertToSelf`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-reverttoself).
- Microsoft, [`AccessCheck`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-accesscheck), [`WinVerifyTrust`](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust), and [`GetFinalPathNameByHandleW`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew).
- Tokio maintainers, [`tokio::net::windows::named_pipe::ServerOptions`](https://docs.rs/tokio/latest/tokio/net/windows/named_pipe/struct.ServerOptions.html).
- Microsoft, [`CreateFile`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew), [Reparse Points](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-points), [`SetSecurityInfo`](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo), [Automatic Propagation of Inheritable ACEs](https://learn.microsoft.com/en-us/windows/win32/secauthz/automatic-propagation-of-inheritable-aces), and [`FlushFileBuffers`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers).
- Microsoft, [`OpenFileById`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-openfilebyid), [`ReplaceFileW`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-replacefilew), and [`MoveFileExW`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw).
- Microsoft, [`NetUserAdd`](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netuseradd), [`NetShareAdd`](https://learn.microsoft.com/en-us/windows/win32/api/lmshare/nf-lmshare-netshareadd), [Account Rights Constants](https://learn.microsoft.com/en-us/windows/win32/secauthz/account-rights-constants), and [`LsaAddAccountRights`](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaaddaccountrights).
- Microsoft, [Event Sources](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-sources).
- Microsoft Security Response Center, [RedirectionGuard: Mitigating unsafe junction traversal in Windows](https://www.microsoft.com/en-us/msrc/blog/2025/06/redirectionguard-mitigating-unsafe-junction-traversal-in-windows).

### Containment, network isolation, and signing primary documentation

- Microsoft, [Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects), [Nested Jobs](https://learn.microsoft.com/en-us/windows/win32/procthread/nested-jobs), and [`SetInformationJobObject`](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-setinformationjobobject).
- Microsoft, [`CreateProcessW`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw), [`ResumeThread`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread), and [`AssignProcessToJobObject`](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-assignprocesstojobobject).
- Microsoft, [Application Layer Enforcement](https://learn.microsoft.com/en-us/windows/win32/fwp/application-layer-enforcement--ale-), [Permitting and Blocking Applications and Users](https://learn.microsoft.com/en-us/windows/win32/fwp/permitting-and-blocking-applications-and-users), [About Windows Filtering Platform](https://learn.microsoft.com/en-us/windows/win32/fwp/about-windows-filtering-platform), [Filter Arbitration](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration), [Filtering Condition Flags](https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-condition-flags-), [Filtering Conditions Available at Each Layer](https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer), and [WFP Best Practices](https://learn.microsoft.com/en-us/windows/win32/fwp/best-practices).
- Microsoft, [Code signing options](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options), [Using SignTool to Verify a File Signature](https://learn.microsoft.com/en-us/windows/win32/seccrypto/using-signtool-to-verify-a-file-signature), [Catalog Files](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/catalog-files), and [Using MakeCat](https://learn.microsoft.com/en-us/windows/win32/seccrypto/using-makecat).
- GitHub, [Using artifact attestations to establish provenance for builds](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations).
