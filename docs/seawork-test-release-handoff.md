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

## 2026-07-21 — Read-only SeaWork drift check

Status: **no downstream LocalSandbox/installer contract drift**

- The read-only SeaWork checkout externally advanced from contract baseline `test` at
  `f9c6cd8ff339688a669451e36078d6cbbc91c1b2` to clean branch `dev` at
  `773e15b2a06e8339f236db124c824a07457b901d`.
- The two intervening commits change the file viewer dependency and IT-center skill
  content only. None of `apps/electron/src/main/app.ts`,
  `apps/electron/src/main/ingress-server.ts`, `apps/electron/electron-builder.yml`,
  `apps/electron/scripts/windows`, or `packages/local-sandbox-tools/src/shared.ts`
  changed.
- The frozen contract verifier still passes all eight pinned source assertions. No
  SeaWork file was modified.

## 2026-07-21 — Native zero-byte catalog and signed candidate construction

Status: **signed archive gate passed; installed production-identity runtime gate pending**

- This entry supersedes the catalog-decision blocker recorded in “Signing identity
  verified; empty-file catalog decision required.” No QEMU payload byte was changed.
  Commit `8209b4d0449c4c036555b02c154e08c7dd12fd8f` replaces MakeCat CDF generation with
  Windows `New-FileCatalog` using catalog version 2.0, then requires signed
  `Test-FileCatalog` validation with SHA-256 and exact closed-set membership.
- The catalog retains the pinned QEMU tree's zero-byte placeholders. The verifier
  explicitly preserves a representative zero-byte `loaders.cache`; SignTool membership
  checks remain bounded to non-empty service, manifest, and QEMU representatives because
  SignTool refuses to memory-map any zero-length file before catalog lookup. The native
  catalog validator remains authoritative for every member.
- Release-candidate run `20260721t100654z-31135-44e86e10c29a` passed against snapshot
  `44e86e10c29a5ea151a803ff7aea6de7458840d7`, based on
  `dd26449d6dab7c4beafc35125f34d9150c3c0c3e`. That validated source tree was then
  committed as `8209b4d0449c4c036555b02c154e08c7dd12fd8f`; an exact-commit rerun remains the next
  gate before the tuple is final.
- The run built production-profile `0.4.7-test.1` with static CRT, PDB, and Event Log
  message IDs 1–16. The service PE and catalog carried trusted SeaWork signatures and
  DigiCert RFC 3161 timestamps. Structural verification covered 3,742 closed bundle
  files.
- Public publisher identity remained `CN=SeaWork, O=Sea` with certificate SHA-256
  `a036eabbb783a31846eb340a725717d741fd330d9c78c2e3bd35dc1c59dc40d7`.
- Fetched artifacts independently matched the run manifest:
  - `lsb-seawork-service-v0.4.7-test.1-windows-x86_64.zip`:
    `1b333a041cd9b76b0490622abccf21df1da464a0f8ed9ed0c79991c0f5315ef6`;
  - `lsb-seawork-service-v0.4.7-test.1-windows-x86_64-symbols.zip`:
    `7a210b350df56698ed4cd4701ec394ac6514831fde25c087cb1863e068aae2ce`.
- These hashes are evidence for the passing construction run, not yet the final SeaWork
  pin. Installed-service smoke, reboot/runtime acceptance, Node package artifacts, and
  the final combined release manifest remain open.

## 2026-07-22 — Final LocalSandbox non-reboot candidate and SeaWork drift

Status: **LocalSandbox candidate complete for the explicitly authorized non-reboot
scope; SeaWork TR-6 and reboot evidence remain open**

This entry supersedes every earlier provisional artifact hash and “runtime pending”
statement. It does not supersede the downstream architecture, installer transaction,
adapter mapping, or acceptance matrix in the initial entry.

### Pinned LocalSandbox tuple

- Candidate source commit:
  `7d87dcb4fc2efa3a55f9e754ee79c0684249be3d` on
  `feat/lsb-win-service`.
- Candidate construction/installed-service snapshot:
  `34b3bad4e66452360e2f432149d340640d9f31eb` in Windows run
  `20260721t205247z-36771-34b3bad4e664`.
- Version: `0.4.7-test.1`; Windows target: `windows-x86_64`; production service
  profile with static CRT and Event Log message IDs 1–16.
- Service ZIP `lsb-seawork-service-v0.4.7-test.1-windows-x86_64.zip`:
  SHA-256 `7764c7d398c0ae1fd083ef501613c0dcdc7c1ffd0cbf81a3361fa0780d64f39f`,
  371,936,405 bytes.
- Symbols ZIP `lsb-seawork-service-v0.4.7-test.1-windows-x86_64-symbols.zip`:
  SHA-256 `4bc045b5108917be41a0cb068bc8f2806d25df455e079e6f45a5028ad178f8a5`,
  2,438,406 bytes.
- `SHA256SUMS`: SHA-256
  `4bb2da28b7413313dff12ea496f76b196a0014cbbf187468eb3a4bdc2d762673`.
- Node main package `@local-sandbox/lsb-nodejs@0.4.7-test.1`, file
  `local-sandbox-lsb-nodejs-0.4.7-test.1.tgz`: SHA-256
  `30c6f063d823476284f3749d10dc8440037e4947b2976406d091d14c360c102b`,
  17,852 bytes.
- Node platform package `@local-sandbox/lsb-nodejs-win32-x64-msvc@0.4.7-test.1`,
  file `local-sandbox-lsb-nodejs-win32-x64-msvc-0.4.7-test.1.tgz`: SHA-256
  `139ae4bd380c45c4ac8315d13a7bee2cee85c2fe216b28c2bad869098350a4f9`,
  5,370,093 bytes.
- Final source-run test-release manifest: SHA-256
  `d49fb555925c911c777ccbeb4e7342ae5bc1747a477c83c07f51b7287005bd81`.
  Its `status` is intentionally `incomplete` only because
  `reboot-continuation` is pending; every non-reboot case is `passed`.
- Publisher subject: `CN=SeaWork, O=Sea`; publisher certificate SHA-256:
  `a036eabbb783a31846eb340a725717d741fd330d9c78c2e3bd35dc1c59dc40d7`.
  The service PE and closed catalog have trusted company chains and DigiCert RFC 3161
  timestamps. No development identity or untrusted-certificate bypass was used.
- Protocol major 1, current minor 5, supported minors 0–5. Production identities remain
  `LocalSandboxSeaWork`, `\\.\pipe\LocalSandbox.SeaWork.v1`, `LocalSystem`, and
  `%ProgramData%\LocalSandbox\SeaWork`.
- Required operations are connect, info/health, start/stop, exec, spawn/stream/kill,
  read/write/mkdir, and cancellation cleanup. Direct mounts use
  `compat-smb-direct`. Public DNS/HTTP/HTTPS, package download, scoped secrets, and
  private/link-local denial are enabled. Ports, checkpoints, and overlay mounts remain
  unavailable in this candidate.

The service ZIP embeds these independently checked records:

- `manifests/bundle.json`:
  `61552572a500203c62d6f867e2b9d28882434d561beed70ee96c56bdecfd1427`;
- `manifests/service-contract.json`:
  `e3eb319d33e308f34d7065bbe262091692d35d0bdb293c8bfd364c3692d715af`;
- `manifests/runtime-dependencies.json`:
  `6d1357b6cb991493f0a407315d4c4b895066502abeba51be00383aebf99e5ed3`;
- `manifests/sbom.spdx.json`:
  `fd83dde3f0118ec14ec88f5ee9841f051666575108faaa83f8a8adfeda2b2024`;
  and
- `licenses/THIRD-PARTY-NOTICES.json`:
  `412df2fd996fc475d7e257caefd4fe809530fc5753bca31e73e2c008e385642a`.

The source-built Windows x86_64 guest runtime used by the candidate has SHA-256 values
`c1bacf126150dfeb77edf7a86d74e443781f7511ed1aabf23b3aad318fc8f746`
for `Image`,
`62c23700673a85e0b45984315df0f0106b00f8d8d3f48c36adb86eea66ace843`
for `initramfs.cpio.gz`, and
`5c9e4b01364aa010c408c44c66d5668e493b5eef207b802f2df6410e98c950a8`
for `rootfs.ext4`. These supersede the earlier wrong-architecture runtime hashes.

### Validation evidence and limits

- Installed-service run `20260721t205247z-36771-34b3bad4e664` passed signed install,
  health, mount-free lifecycle, four direct mounts, exec/files, spawn/stream/kill,
  cancellation, public network/package/scoped-secret checks, private-target denial, ten
  sequential effects, normal cleanup, and owned uninstall. The service was deleted at
  the end of the run.
- Standard-user validation used the existing interactive user's filtered,
  medium-integrity, non-admin token. It proves privilege behavior only: integrity RID
  8192, not elevated, Administrators deny-only, exact saved-user SID at execution, and
  no UAC after the elevated install. It does **not** validate a separate account or
  separate user profile; no such claim may be inferred downstream.
- Exact-archive acceptance run `20260721t211858z-46201-825090ca54cd`, validation
  snapshot `825090ca54cd1a497248f9c0c635ea5249708ba9`, safely expanded the exact service
  ZIP, re-ran trusted PE/catalog closure and the 3,742-file installed-layout verifier,
  and matched the embedded manifest hashes. The same ZIP was fetched to macOS through
  the allowlisted fetch command, matched its fetch-manifest size/hash, passed a complete
  ZIP CRC test, and produced the same embedded hashes when streamed from the fetched
  archive.
- Current-harness Windows `service-fast` run
  `20260721t212415z-48692-2930615cef09`, snapshot
  `2930615cef093f36b4d8ebafa0b904e35fed664c`, passed the Windows Rust/service/protocol/
  proxy/VM matrix, scoped Clippy, native Node build, declaration checks, and ten Node
  tests.
- Final macOS gates passed formatting, 29 protocol tests, one client test, 65 service
  tests, 77 proxy tests, scoped Clippy with the documented Windows-gated dead-code/
  `unused_mut` and two existing Clippy-class allowances, Node build/API/type checks,
  and all eight frozen SeaWork parity assertions. The raw macOS `-D warnings` invocation
  fails only on Windows-gated code being unused on the non-Windows target; it is not
  reported as a strict pass.

Reboot validation is explicitly deferred by user direction and was not run after the
final candidate. Pending evidence is delayed automatic service start, post-reboot
health, one post-reboot filtered-token sandbox, normal stop, and owned cleanup. This
pending test does not block the currently authorized LocalSandbox non-reboot scope, but
must remain visible and must not be described as passed. When reboot tests are
re-authorized, use a clean worktree at the candidate commit and run:

```bash
scripts/win-test reboot service-reboot \
  --reuse-candidate 20260721t205247z-36771-34b3bad4e664
```

After Windows restarts, the existing user must sign in so the filtered-token proof can
run. The harness registers the task by saved SID to avoid domain-name resolution during
registration; the execution proof still requires the exact SID. This remains a current-
user privilege test, not separate-account validation.

### Verified artifact reuse

Commit `7d87dcb4fc2efa3a55f9e754ee79c0684249be3d` adds a fail-closed candidate reuse
path. Reuse requires an exact snapshot tree, base commit, candidate version, protected
publisher, matching owned run roots, non-reparse content, valid source fetch hashes,
and passed release evidence. It re-runs source manifest hashes, trusted signature/catalog
closure, and installed-layout verification; copies into the new owned run; repeats copy
hash, signature/catalog, and layout verification; then records source provenance before
running the full runtime matrix.

Non-reboot reuse run `20260721t212708z-49738-a8194f6f31fb`, snapshot
`a8194f6f31fb4703d443e10e357799795bed4a0a`, passed against the exact source tree and
base. Its reuse evidence SHA-256 is
`142bed27fe3fd172463ab2abb72efa859536418ae6197a362f9c2ff1756836f3`.
It skipped compilation and the roughly 13-minute archive writer, reached production
service startup after about two minutes of complete adoption verification/copying, and
then passed the same non-reboot installed-service matrix and uninstall. Use
`scripts/win-test suite installed-service-smoke --reuse-candidate <run-id>` for a same-
tree non-reboot retry. A source from a different tree/base/version/signer is rejected.

### Current read-only SeaWork drift

SeaWork was rechecked clean and read-only on 2026-07-22 at `main`/`v1.3.2`, commit
`be189da04a5dbdcb8641e12c997ae5567311d879`. This supersedes the earlier clean `dev`
inspection at `773e15b2a06e8339f236db124c824a07457b901d`.

- Commit `5829704c` already changes SeaWork's optional main Node dependency from 0.4.6
  to stable `@local-sandbox/lsb-nodejs` `0.4.7`. TR-6 must replace that with the exact
  `0.4.7-test.1` main/platform package files and hashes above for this test release; a
  registry range or local rebuild is not the pinned tuple.
- Commit `19a8ff74` adds `appVersion` and, whenever scoped secrets exist, emits
  `network.httpsInterception` with a `User-Agent: SeaWork/<appVersion>` request-header
  rule limited to the union of secret hosts. The candidate Node declarations and
  service transport support the exact host-scope/interception/header shapes, and the
  Windows fast gate covers their validation/redaction mapping. TR-6's packaged service-
  only test must exercise this current SeaWork path end to end with a scoped host and
  prove both the header value and secret remain absent from logs.
- Commit `8085ddfa` changes cancellation test timing only. Existing service cancellation
  semantics remain compatible.
- The generated/frozen verifier still passes its eight assertions at contract baseline
  `f9c6cd8ff339688a669451e36078d6cbbc91c1b2`. The three current drift files are
  `apps/electron/src/main/ingress-server.ts`,
  `packages/local-sandbox-tools/src/runtime-options.ts`, and
  `packages/local-sandbox-tools/src/shared.ts`; no SeaWork file was modified here.

The original NSIS transaction, service-only/service-preferred routing, lazy helper
fallback, adapter operation mapping, update/repair/uninstall rules, diagnostics policy,
and downstream non-reboot acceptance matrix remain the required TR-6 implementation.
The SeaWork owner alone may append that evidence and mark the overall test release
ready. Every reboot-dependent row remains recorded as pending, is deferred until the
user re-authorizes reboot testing, and is not a current blocker.

## 2026-07-22 — Reboot panic fix and interim validation checkpoint

Status: **runtime defect fixed and validated on an interim signed tuple; final candidate
evidence deliberately deferred because more source changes will follow**

This entry supersedes the preceding statement that upstream reboot behavior had not
been tested. It does not promote a new final artifact pin and does not change TR-6
ownership. Per the user's handoff request, no final artifact fetch, final archive
acceptance, or final full host-gate run was performed after this checkpoint.

### Root cause and fix

- The first delayed-auto service process consistently reached `RUNNING` and then died
  during the first post-reboot `sandbox.start`. SCM recorded event 7031 and restarted
  it after five seconds. Earlier service logs contained no normal stop or fatal event.
- Diagnostic run `20260722t045000z-wprdiag2` attached the Microsoft-signed Sysinternals
  ProcDump executable to first service PID 11380 and bounded WPR `GeneralProfile`
  tracing around the one failing request. ProcDump reported unhandled `0xC0000409` and
  wrote `service-termination.dmp`, 1,425,446 bytes, SHA-256
  `7de00bb9d7d3f24665164b03c24e24ba06aef6a5c813b0fba8cd72ff9785b693`.
  The bounded ETL is 581,959,680 bytes. Owned service cleanup passed and WPR reported
  that it was no longer recording.
- The matching PDB resolved the abort stack to
  `sandbox.start -> SessionManager::begin_start_replay -> prune_start_replays ->
  std::time::Instant::sub`. `prune_start_replays` computed
  `Instant::now() - START_REPLAY_TTL`; on Windows, a machine uptime shorter than the
  ten-minute TTL makes that subtraction panic. The production panic-abort build turns
  the Rust panic into the observed fast-fail. This explains why pre-reboot tests passed
  and the first short-uptime post-reboot request failed.
- Commit `edf76bfd45f483d2ab18d9faca96e2cdad4c5720` replaces both vulnerable cutoff
  calculations (`prune_start_replays` and `prune_retired`) with saturating elapsed-time
  comparisons and preserves the original strict “older than TTL” boundary. Its focused
  regression test covers an observed instant earlier than a stored timestamp. All 66
  `lsb-seawork-service` tests, formatting, and diff checks pass.
- Commit `91a9035` tested an Event Log best-effort hypothesis before the dump was
  available. The same reboot failure disproved it, and commit `32c5a76` reverted it.
  The diagnostics fail-closed contract is unchanged.

### Interim signed evidence

- Fresh construction run `20260722t045910z-65556-543cbc0e5c76`, synthetic snapshot
  `543cbc0e5c76f5001632036256eb961aff2f52cb`, based on `edf76bf`, built and timestamped
  a production-profile SeaWork tuple. Its pre-reboot matrix later stopped safely on a
  transient external `httpbin.org` header-echo check after DNS, HTTP, HTTPS, and npm
  metadata download had all passed; cleanup succeeded. The build/sign/archive evidence
  remained valid for exact-tree reuse.
- Exact verified-reuse reboot run `20260722t052350z-77334-4a1d7c20d297`, synthetic
  snapshot `4a1d7c20d29796673766b319353d275e9fa08491`, passed the complete pre-reboot matrix,
  a real reboot, delayed automatic service start, post-reboot mounted sandbox, normal
  stop, and owned uninstall. `result-afterreboot.json` reports `passed`, exit 0;
  `reboot-continuation` is `passed`; and the complete interim manifest SHA-256 is
  `110d0d35ef708bc4c4c19498cd5474f7b3d51b0866bf0e1a0df696147a1e3885`.
- The interim manifest records verified-reuse provenance from the fresh construction
  run and pins these artifacts:
  - service ZIP: SHA-256
    `77b2a23538e1b527347de758bc42bd96eef904511b36393421832fe31f94d951`,
    371,936,427 bytes;
  - symbols ZIP: SHA-256
    `c713144fe49e02133ed0c5e9017c528c6d66a958f46ec61b647c0a62c83ca3e3`,
    2,455,588 bytes;
  - `SHA256SUMS`: SHA-256
    `eeafeabcf23a3355adbb0ae7db728716aa89fe4e4efe3c689e2c38b71baa2ee6`;
  - Node main package: SHA-256
    `30c6f063d823476284f3749d10dc8440037e4947b2976406d091d14c360c102b`;
  - Node Windows platform package: SHA-256
    `139ae4bd380c45c4ac8315d13a7bee2cee85c2fe216b28c2bad869098350a4f9`.
- These hashes are an interim debugging/validation tuple only. They were intentionally
  not fetched to macOS and must not be embedded by SeaWork or described as the final
  candidate because additional LocalSandbox changes are expected.
- The desktop session was `SGP\SG3937`. Validation used that existing user's filtered,
  medium-integrity, non-admin token and proves privilege behavior only. The SSH account
  is automation transport and must not be used as the interactive desktop login.
  Separate-account and separate-profile behavior remain **not validated**.

### Required final evidence run after the planned changes

Do not run this sequence until the upcoming LocalSandbox changes are complete and
committed. If the source tree changes at any point, discard reuse assumptions and begin
again with a fresh construction run.

1. Start from a clean `feat/lsb-win-service` worktree. Record `git rev-parse HEAD`,
   `git rev-parse HEAD^{tree}`, and `git status --short`. Recheck that SeaWork remains
   read-only; append drift only if downstream paths or API requirements changed.
2. Verify the Windows host and protected assets without printing secrets:

   ```bash
   scripts/win-test verify
   scripts/win-test verify-signing
   scripts/win-test verify-runtime
   ```

3. Run the complete macOS and Node gates listed in `plan.md`, including formatting,
   protocol/client/service/proxy tests, scoped Clippy, the frozen SeaWork parity check,
   Node native build, API/package tests, and TypeScript check. Then run:

   ```bash
   scripts/win-test preflight
   scripts/win-test suite service-fast
   ```

4. Because the final tree will differ from this interim tuple, build and validate a
   fresh signed candidate through the canonical reboot suite; do **not** pass
   `--reuse-candidate` on the first run:

   ```bash
   scripts/win-test reboot service-reboot
   ```

   After Windows restarts, sign into the desktop as `SGP\SG3937`. The harness must
   detect that interactive session, wait for delayed automatic service start, execute
   the post-reboot filtered-token mounted sandbox, and prove owned uninstall. Record
   the run ID, synthetic snapshot SHA, base commit, tree SHA, publisher, and artifact
   hashes.
5. If an environmental check fails and the source tree, base commit, version, signer,
   catalog, layout, and artifact hashes are unchanged, retry at no loss of accuracy with:

   ```bash
   scripts/win-test reboot service-reboot --reuse-candidate <fresh-run-id>
   ```

   Reuse must remain fail-closed and must repeat source/copy hashes, trusted PE/catalog
   closure, structural bundle verification, and installed-layout verification. Never
   reuse an artifact after any source change.
6. Against the exact passing final tuple, run the remaining promotion gates:

   ```bash
   scripts/win-test suite archive-acceptance --reuse-candidate <passing-run-id>
   scripts/win-test suite installed-service-smoke --reuse-candidate <passing-run-id>
   scripts/win-test fetch <passing-run-id> <new-local-evidence-directory>
   ```

   Independently check the fetched sizes/SHA-256 values, ZIP integrity, embedded
   manifest hashes, publisher identity, complete test-release manifest, and the exact
   archive-acceptance/installed-service/reboot/uninstall result files. The fetch target
   must be a new directory.
7. Only then update `state.md` and append a new handoff entry that explicitly supersedes
   this interim tuple. Mark the final LocalSandbox candidate complete only when every
   final-tree gate passes. Preserve the qualification that the `SG3937` token proof is
   not separate-account profile validation, and leave TR-6 for the SeaWork owner.
