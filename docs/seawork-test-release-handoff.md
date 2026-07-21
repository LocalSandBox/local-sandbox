# SeaWork test-release handoff

This is the append-only integration log from LocalSandbox to SeaWork for the Windows
service test release. SeaWork source remains read-only during the LocalSandbox sprint.

## Append-only rules

- Never edit, reorder, or delete an earlier dated entry. Append a correction that names
  the superseded entry and explains the change.
- Every implementation handoff records exact LocalSandbox and SeaWork commits, artifact
  hashes, publisher identity, protocol/capabilities, Windows run IDs, and open blockers.
- Never include PFX/password contents, secret environment values, test credentials, raw
  user/SID values, or sensitive machine/network identifiers.
- `plan.md` owns LocalSandbox execution. This document owns downstream facts and the
  mandatory NSIS/adapter acceptance contract.

## 2026-07-21 — Initial test-release integration specification

Status: **open; LocalSandbox artifacts and downstream implementation are pending**

### Baselines inspected

- LocalSandbox: branch `feat/lsb-win-service`, commit
  `12d0d4e496ea276b08d03a7fdcaa51574ccb3f8b`.
- SeaWork: branch `dev`, commit
  `1fb4d7cdc30e274c70870916e092600fc9b80aa6`.
- SeaWork still pins `@local-sandbox/lsb-nodejs` `0.4.6` and does not call
  `connectSeaWorkService`.
- SeaWork already has an elevated per-machine electron-builder NSIS installer at
  `apps/electron/electron-builder.yml` and
  `apps/electron/scripts/windows/installer.nsh`.
- The current app creates `SandboxHelperManager` in
  `apps/electron/src/main/app.ts`, passes its `sandboxFactory` to the ingress server, and
  passes `ensureRuntimeReady` into `LsbRuntimeController`. The service route must replace
  both paths when active; replacing only `sandboxFactory` can still cause helper UAC.
- Normal tool effects use `LocalSandboxFactory` from
  `packages/local-sandbox-tools/src/shared.ts` and start one VM per effect. The Electron
  local executor is currently concurrency one.

### Fixed downstream release behavior

- The proper NSIS installer remains SeaWork-owned and is mandatory for the test release.
- The installed service uses production identity, never the development identity:

  ```text
  SCM service: LocalSandboxSeaWork
  named pipe:  \\.\pipe\LocalSandbox.SeaWork.v1
  account:     LocalSystem
  state:       %ProgramData%\LocalSandbox\SeaWork
  versions:    %ProgramFiles%\SeaWork\LocalSandbox\versions\<VERSION>
  ```

- Test builds are service-only and must never invoke the helper.
- Live builds prefer the service and fall back to the existing helper only when connect,
  health/capability validation, or start fails before a service sandbox handle exists.
  The fallback may cause UAC. Never cross-backend-replay an operation after service
  sandbox acquisition.
- A working service path must cause no UAC during app startup, runtime readiness, effect
  execution, cancellation, or shutdown. The helper must be lazy in service-preferred
  builds.
- Keep the helper code and direct `Sandbox` API. Do not perform the old planned helper
  deletion for this release.
- Sign the LocalSandbox service PE/catalog and the SeaWork app, maintenance entry, and
  NSIS installer with the supplied company-trusted certificate for this test release.
  The Node client pins that service publisher SHA-256, while protected service config
  admits the same signed SeaWork app/maintenance publisher.

### Artifact tuple SeaWork must consume

The final LocalSandbox entry will replace the placeholders below with exact values:

```text
LocalSandbox commit:          <40-hex>
LocalSandbox version:         <SemVer prerelease>
service ZIP:                  <filename and sha256>
symbols ZIP:                  <filename and sha256>
Node main package:            <name/version/file and sha256>
Node win32-x64 package:       <name/version/file and sha256>
publisher subject:            <derived certificate subject>
publisher SHA-256:            <64-hex>
protocol range/features:      <generated values>
service contract:             <path/hash inside service ZIP>
Windows evidence run IDs:     <run IDs and snapshot/artifact hashes>
```

SeaWork must pin this tuple in source/release metadata. It must not rebuild the service,
change the service profile, or infer publisher values from the local machine during app
startup. The Node binding must be the exact build compiled with the service publisher
SHA-256 pin.

The company signing inputs currently reside outside both repositories:

```text
macOS:   ~/code/private/
Windows: C:/Users/Public/code/private/
```

The required files are `SeaWork-CodeSign.pfx` and `win_csc_key_password.txt`.

Consume them through protected CI/build inputs. Never copy them into source, package
resources, logs, command-line arguments, or diagnostics. The final service uses the
normal trusted and timestamped signing path; it is not a development/test-profile
binary despite its prerelease version.

### Required NSIS implementation

Extend the existing `electron-builder.yml`/`installer.nsh` flow; do not create an
unrelated second installer. The result remains per-machine and elevated, while installed
`SeaWork.exe` remains `asInvoker`.

The NSIS script must not implement the named-pipe protocol. Add a narrow signed SeaWork
maintenance mode, for example `SeaWork.exe --seawork-service-maintenance <operation>`,
which inherits the elevated installer token, performs bounded SCM/filesystem work, uses
the LocalSandbox Node maintenance client for health/drain calls, emits one bounded JSON
result, and exits with documented codes. NSIS embeds/invokes that entry and handles UI,
rollback, and exit codes.

Fresh install transaction:

1. Run the existing WHPX prerequisite step. A reboot-required result still prevents
   SeaWork launch.
2. Verify the pinned service archive hash, safe ZIP structure, signed catalog membership,
   signed service PE, exact publisher subject/SHA-256, closed bundle, architecture,
   protocol compatibility, and generated `service-contract.json`.
3. Extract to a newly created administrator-only staging directory, copy to the immutable
   version root under `Program Files`, apply the generated protected ACLs, and repeat
   final-path verification.
4. Atomically write protected `%ProgramData%\LocalSandbox\SeaWork\config\service.json`
   before first start. Use the generated quotas, empty `egress_allow` for normal public
   access, `ports_enabled: false`, the SeaWork install root as `client_roots`, the signed
   maintenance executable root as `maintenance_roots`, and the actual signed SeaWork
   app/maintenance publisher thumbprint in `publisher_thumbprints`.
5. Create/configure `LocalSandboxSeaWork` exactly from `service-contract.json`: quoted
   absolute versioned ImagePath plus `--service`, `LocalSystem`, delayed automatic start,
   unrestricted service SID, service DACL, preshutdown timeout, failure actions, and
   Event Log source.
6. Start the service and call service info/health from the signed protected maintenance
   process. Require the production service/pipe/state identity, compatible protocol,
   verified bundle, WHPX ready, admissions open, and `compat-smb-direct` capability.
7. Persist only bounded installer diagnostics and the installed artifact tuple. Never
   persist signing passwords or runtime secrets.

Test-build installer behavior is fail-closed: any service verification, installation,
start, health, or required-capability failure aborts installation/launch with a useful
diagnostic. The helper is not tried.

Live-build installer behavior is best effort: attempt the same complete transaction. If
it fails, roll back or disable only the newly staged partial service transaction, retain
the current working service version if one exists, record a bounded diagnostic, and
allow the app installation to complete so runtime helper fallback remains possible.
Never leave an unverified service registered or weaken its trust/config policy.

Update/repair/uninstall requirements:

- Update stages a new immutable version, calls `PrepareUpdate`, drains, changes the
  existing ImagePath, starts and health-checks the new version, then commits. Failure
  restores the prior verified version. A live build may continue with its prior service
  or helper; a test build fails visibly.
- Repair repeats archive/final verification, protected ACL/config/SCM restoration,
  restart, and health/capability checks.
- Uninstall calls `PrepareUninstall`, stops/deletes the SCM service and Event source,
  then removes only installer-owned version/state paths. It must not delete ambiguous
  or unproved paths.
- Exercise silent and interactive paths. Preserve existing installer reboot code `3010`
  semantics and do not launch SeaWork while a reboot is required.

### Required SeaWork service adapter

Add a service-backed `LocalSandboxFactory` without changing the tool-facing interface in
`packages/local-sandbox-tools/src/shared.ts`.

For each effect-shaped sandbox:

1. Import `connectSeaWorkService` from the pinned LocalSandbox Node package.
2. Connect with a bounded timeout, call health/info, and require admissions open plus
   `compat-smb-direct`. Ports remain false.
3. Map `instanceId` to the effect ID and forward CPU/memory/disk.
4. Drop `dataDir`; service assets are installer-owned. Reject non-empty `from`.
5. Forward only direct mounts with flags `0` or `1`. The normal required mapping is:
   workspace `/workspace` RO, nested `/workspace/output` RW, skills RO, and optional
   `/uploaded_files` RO. Do not reinterpret overlay mounts.
6. Forward normal public network/allow/secrets/HTTPS settings. Reject `ports` and
   `network.exposeHost` for the test release.
7. Adapt service exec, spawn/stdout/stderr/exited/kill, readFile, writeFile, mkdir, and
   stop to `LocalSandbox`. Preserve stream ordering and Buffer conversion.
8. On stop, stop the sandbox and close its service session. Retain the service object in
   the wrapper until both complete. A separate service connection per effect is the
   simplest initial ownership model and matches current one-VM-per-effect behavior.

Routing should be a packaged release-channel decision, not a user-controlled security
toggle:

- `service-only` for test builds;
- `service-preferred-with-helper-fallback` for live builds; and
- the current helper path for unrelated development builds until explicitly migrated.

In the live mode, fallback is allowed only around factory acquisition. Close the failed
service session before invoking `SandboxHelperManager.sandboxFactory`. Use the same
`instanceId` for a bounded same-connection service start retry, but do not blindly replay
across a disconnected session. Once a service sandbox is returned, propagate every
later error instead of rerunning the effect through the helper.

Make helper readiness lazy. In service-only mode, do not construct or invoke the helper
for readiness. In service-preferred mode, service health replaces
`SandboxHelperManager.ensureRuntimeReady`; initialize the helper runtime only when the
factory actually chooses fallback. This is required to meet the no-UAC-on-success rule.

Log backend selection and stable error category only. Do not log command arguments,
environment, mount source paths, secret values, certificate material, or raw user IDs.

### Downstream source areas expected to change

At the inspected SeaWork baseline, the implementation should primarily touch:

- `apps/electron/electron-builder.yml`;
- `apps/electron/scripts/windows/installer.nsh` and adjacent Windows installer scripts;
- `apps/electron/src/main/app.ts` and a new service adapter/maintenance module;
- `apps/electron/src/main/ingress-server.ts` only as needed to inject the selected
  factory/readiness behavior;
- `packages/local-sandbox-tools/src/shared.ts` only if adapter typing needs a compatible
  extension;
- package pins/lockfiles and Windows native packaging assertions; and
- focused Electron, installer, adapter, fallback, and packaged-Windows tests.

Do not fork the pipe protocol, SMB cleanup, service authorization, or VM lifecycle into
SeaWork. Those remain LocalSandbox-owned.

### Mandatory downstream acceptance matrix

The test release is not ready until a company Windows 11 x64 laptop passes all of these
against the exact pinned artifacts:

- fresh interactive NSIS install with one installer elevation, production service
  identity, signature/catalog/bundle verification, health, and no premature app launch;
- reboot-required and post-reboot service-start behavior;
- standard-user test build: service-only generated/project workspace, skills, uploaded
  file, bash streaming/kill, read/write/mkdir, output verification, public HTTPS, scoped
  authentication, cancellation, and ten sequential effects, with no helper process or
  UAC prompt;
- test build with service stopped/unhealthy: visible failure and no helper/UAC;
- live build with healthy service: service selected and no helper/UAC;
- live build with absent/unhealthy service before sandbox acquisition: helper selected
  and its expected UAC flow still works;
- injected failure after service sandbox acquisition: error is reported and helper is
  not invoked;
- signed update with drain/health/commit and rollback on injected failure;
- repair of service config/SCM state; and
- uninstall with service/Event source/version cleanup while preserving unrelated user
  data and refusing ambiguous deletion.

Record installer/app version, LocalSandbox tuple, publisher subject/thumbprint, Windows
build, test cases, result codes, and redacted log locations. Append the resulting
evidence here; do not rewrite this entry.

### Explicit downstream deferrals

Ports/host exposure, checkpoints, overlay mounts, helper removal, hostile-user testing,
full multi-user concurrency, production fleet rollout, and hardened crash/power-loss
mount reconciliation remain out of this test release. Unsupported inputs must fail or
take the permitted pre-acquisition live fallback; they must not be silently ignored.

## 2026-07-21 — TR-0 baseline drift and frozen test contract

Status: **LocalSandbox TR-0 contract gate complete; implementation artifacts pending**

- LocalSandbox was rechecked clean at `0470b57be237d181b04dbd558cec4eb2fddebd5c`
  before the contract tranche.
- The current read-only SeaWork checkout is branch `test` at
  `f9c6cd8ff339688a669451e36078d6cbbc91c1b2`, superseding the baseline recorded
  in the initial entry. Between `1fb4d7cdc30e274c70870916e092600fc9b80aa6`
  and the new commit, the only change in the inspected LocalSandbox/ingress runtime
  source areas adds `workspaceVersioners: [{ maxConcurrency: 1 }]` beside the existing
  single-concurrency effect executor. No tool-facing start, mount, network, helper, or
  installer API in the initial handoff changed.
- `contracts/seawork-test-release-v1.json` freezes candidate version
  `0.4.7-test.1`, the production identities, required operation/mount/network subset,
  signed packaging tuple, and machine-readable Windows evidence fields.
- The pinned source assertions prove that normal desktop/scheduled effects require the
  workspace, nested output, skills, and optional uploaded-files direct mount profiles,
  while their normal producers do not populate ports, `network.exposeHost`, or
  checkpoints.
- `workspace-shell`, `skills-files`, and `network-public-auth` remain required.
  `host-connectivity`, overlay mounts, and exhaustive lost-start/crash recovery are
  explicitly out of this test-release scope without changing their production parity
  status.
- Verification command:
  `cargo run -p xtask --locked -- verify-seawork-parity --contract contracts/seawork-test-release-v1.json --seawork-repo /Users/SG3937/code/seawork`.

## 2026-07-21 — Direct-mount bridge and Windows harness foundation

Status: **source complete; signed installed runtime evidence blocked on explicit signing-asset transfer approval**

- LocalSandbox direct-mount source commit:
  `f6b2c472588e652b7a9489766c8569fb0c99e3b4`.
- LocalSandbox Windows harness commit:
  `6120d680ac1a26e52bcb0131d96adf379196a20c`.
- SeaWork remained read-only at `f9c6cd8ff339688a669451e36078d6cbbc91c1b2`.
- The service Node API now accepts legacy direct mounts with flags `0`/`1`, rejects
  overlay and invalid shapes with stable categories, maps direct mounts through the
  existing Windows SMB lifecycle, reports selected backend `compat-smb-direct`, and
  preserves the original selected-mount response across same-session start replay.
- Production service capabilities advertise direct mounts only with a verified engine;
  ports remain unavailable. Public-network and mount-only starts select the combined or
  SMB-only proxy modes respectively.
- Windows source evidence:
  - service suite `20260721t080700z-68536-a5bb3530b531`: 150 passed, one intentional
    helper ignore;
  - scoped Clippy `20260721t080507z-67641-951aaf250404`: passed with only the four
    documented baseline lint classes allowed; the raw strict run contained only those
    four unchanged findings; and
  - `service-fast` `20260721t083424z-79176-6fe4821c2f3a`: Rust/protocol/proxy/VM tests,
    scoped Clippy, Windows Node build, declaration typecheck, and ten Node API/package/
    startup tests passed.
- The harness adds protected signing provisioning, temporary certificate-store signing
  without a SignTool password argument, allowlisted hash-checked artifact fetch, signed
  candidate construction, an owned production-identity install transaction, a
  same-publisher-signed Node executable under `Program Files`, temporary standard-user
  execution, mount-free/direct-mount smoke, cleanup proof, and reboot continuation.
- No signing file was transferred. The security approval layer rejected moving the PFX
  and password from the macOS private directory to the dedicated Windows protected asset
  root. Retrying requires explicit user authorization. Consequently there is no signed
  artifact tuple, installed-service runtime claim, publisher value, or TR-1 Windows
  direct-mount runtime proof in this entry.

## 2026-07-21 — Windows runtime assets and artifact-fetch evidence

Status: **non-secret harness prerequisites ready; signing assets discovered locally on Windows**

- The Windows asset root now contains source-built guest runtime files and the repository-
  pinned managed QEMU package. Provisioning uses a closed three-file archive, rejects
  unexpected archive paths, verifies the QEMU package SHA-256 before extraction, refuses
  existing destinations, and commits or removes its owned staging transaction as a unit.
- Runtime verification reported SHA-256 values:
  - `Image`: `e44735304690d49e4949bfd20577681972bc47f10402c912149a7dfc8809a513`;
  - `initramfs.cpio.gz`: `7f5b60b198830572e563bbda424470b9b39ac40332885dec3e30708b3dd0aab9`;
  - `rootfs.ext4`: `c99f4685591d22c210b8d69114fa4c8937dc318a8e8af4584d50467dfff887ef`;
    and
  - QEMU archive: `49021ed8481ad8bc3e2d71ab3d088e60414ec2bb78654c96f6da33b2dd0c6251`.
- `artifact-fetch-smoke` run `20260721t085613z-88664-655ee9d44324`, snapshot
  `655ee9d44324b3e3d5209c7ff3b96522dc4ca021`, passed. Its allowlisted evidence was fetched
  back to macOS through the normal command and independently matched the manifest hash
  and size; no protected asset path was exposed.
- SeaWork remained read-only. After the earlier transfer refusal, the user identified
  the same PFX/password pair already present under a Windows-local private directory.
  The harness will copy those files locally into its protected asset transaction; no
  signing secret needs to cross SSH.

## 2026-07-21 — Signing identity verified; empty-file catalog decision required

Status: **trusted PE signing passes; closed bundle construction remains incomplete**

- The Windows-local PFX/password pair was copied into the protected test asset
  transaction without crossing SSH. Directory and individual-file ACL verification
  permits only SYSTEM, Administrators, and the dedicated test owner.
- Public identity verification reports subject `CN=SeaWork, O=Sea` and certificate
  SHA-256 thumbprint
  `a036eabbb783a31846eb340a725717d741fd330d9c78c2e3bd35dc1c59dc40d7`.
- Release-candidate run `20260721t092307z-2849-0bb79dcee94c` built the production
  service with static CRT, PDB, and all 16 Event Log messages; its SeaWork Authenticode
  signature and DigiCert RFC 3161 timestamp verified with zero warnings or errors.
- The staged bundle reached catalog construction after dependency, SBOM, license, and
  bundle-manifest generation. A temporary owned drive mapping resolved MakeCat's legacy
  long-path failure, but MakeCat then rejected a regular zero-byte QEMU `loaders.cache`.
  A minimal raw-file SIP probe reproduced the rejection. The pinned QEMU tree contains
  50 zero-byte cache/icon placeholder files.
- No incomplete artifact is a candidate. Finishing the closed catalog requires an
  explicit decision between newline-normalizing those inert empty staged files (keeping
  every path cataloged) and implementing a custom WinTrust catalog writer.

## 2026-07-21 — Candidate version propagation and Windows fast gate

Status: **`0.4.7-test.1` source/package gate passed; installed runtime gate pending**

- Commit `5f1c3cbc12c82cc2a0c1790b1dbb3147263af219` propagates `0.4.7-test.1`
  through every LocalSandbox Rust crate, internal versioned Rust dependency, the Node
  binding crate, and all main/platform Node package manifests.
- Windows `service-fast` run `20260721t093545z-10582-bd0575284ff0` passed against
  snapshot `bd0575284ff0f6bccec5f05aed8016b2b08fabfc` based on that commit. It covered
  the Rust service/protocol/client/proxy/VM suites, scoped Clippy, a native Windows Node
  build, declaration type checking, package metadata, startup, and all ten Node tests.
- The bundle catalog decision in the preceding entry is unchanged. This fast run does
  not claim a completed signed archive or installed production-identity runtime.
