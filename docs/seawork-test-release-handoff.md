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

## 2026-07-22 — Controlled self-upgrade helper integration contract

Status: **open; LocalSandbox implementation is in progress and SeaWork installer,
repair, and uninstall work is required after signed helper artifacts are available**

### Baselines and contract source

- LocalSandbox controlled-update contract: commit
  `de7fc8f779e806d5bcef305c93e23a3743653ddd` on `feat/lsbs-auto-upgrade`.
- SeaWork remains read-only at the last inspected `main`/`v1.3.2` baseline,
  `be189da04a5dbdcb8641e12c997ae5567311d879`.
- The generated `manifests/service-contract.json` is now revision 2. It fixes the
  update repository, archive naming policy, supported channels, protected update
  paths, updater SCM identity, updater path/command, and helper protocol range.
- Protocol minor 6 replaces the version-only maintenance target with the complete
  bundle identity and adds bounded update status and manual-check operations. SeaWork
  maintenance code must pass through the complete generated identity and must not
  reconstruct it from a version string.

No signed helper artifact or final release tuple is asserted by this entry. A later
append-only entry must bind the exact helper PE hash, service ZIP hash, publisher,
protocol, source commit, and Windows evidence before SeaWork pins or ships it.

### Mandatory SeaWork updater-service work

SeaWork continues to own initial install, repair, and uninstall for both SCM entries.
Extend the existing elevated NSIS/maintenance transaction rather than adding a second
installer:

1. Extract the catalog-covered, signed `localsandbox-seawork-updater.exe` from the
   exact pinned LocalSandbox release and independently verify its hash, Authenticode
   chain/timestamp, exact publisher, protected ancestry, and non-reparse final path.
2. Install it at the generated fixed path
   `%ProgramFiles%\SeaWork\LocalSandbox\updater\localsandbox-seawork-updater.exe`.
   The path is intentionally outside the immutable main-service version roots; neither
   the running service nor helper may replace it.
3. Create `LocalSandboxSeaWorkUpdater` as a LocalSystem
   `SERVICE_WIN32_OWN_PROCESS` with the exact quoted command ending in `--service`, the
   generated unrestricted service SID/DACL, automatic boot recovery start, and the
   generated bounded failure restart policy. Do not pass a transaction path, update
   URL, version, or caller-controlled argument on its SCM command line.
4. Configure and verify the updater before first starting the main service. A standard
   user must never receive a UAC prompt from automatic update. If helper installation
   or verification fails, fail closed for a service-only test build and preserve the
   existing live-build helper fallback rules.
5. Repair must reverify the helper binary, ACLs, SCM account/type/name/path/DACL/start
   and failure actions, replace it only from a newer or exact pinned signed artifact,
   and start it to reconcile any protected nonterminal update transaction before
   declaring repair healthy.
6. When update status reports `helper_too_old`, SeaWork installer/repair must update the
   helper first. The helper never self-updates, and the main service must not create,
   delete, or reconfigure its SCM entry.
7. Uninstall must stop and delete both `LocalSandboxSeaWork` and
   `LocalSandboxSeaWorkUpdater`, remove the updater Event/SCM configuration and only
   verified installer-owned helper/version/state paths, and refuse ambiguous or
   reparse-backed deletion. Preserve protected transaction evidence if safe rollback
   or reconciliation has not completed.

The protected `service.json` written by fresh install or repair may remain revision 1
to imply `stable`, or use revision 2 with exactly `update_channel: stable` or
`update_channel: prerelease`. SeaWork must not add repository, URL, asset-name, helper
path, unsigned-mode, or signature-bypass settings.

### Current LocalSandbox release-workflow context

The release dispatch changed after the self-upgrade plan was drafted. At the contract
commit above, `just release <version>` requires a version argument and selects
`service_evidence=skip` by default for prereleases and `required` for stable versions;
the workflow also accepts an explicit `skip|required` override. Follow-up publication
must preserve that current dispatch/evidence policy rather than restoring the older
defaulted `patch` command.

The controlled-update runtime still requires one immutable GitHub release asset named
`lsb-seawork-service-v<VERSION>-windows-x86_64.zip` with GitHub SHA-256 digest metadata.
The LocalSandbox release build must place the signed helper and its generated contract
metadata in that exact verified archive before this downstream work can close. SeaWork
must consume the resulting immutable tuple; it must not fetch a separate mutable
helper, rebuild the helper, or infer its publisher locally.

### Added downstream acceptance rows

Append evidence for all existing install/update/repair/uninstall rows plus:

- helper SCM identity, command, account, start/recovery, DACL, protected path, signature,
  publisher, and helper protocol exactly match the generated contract;
- boot with no transaction makes the helper exit cleanly, while boot with a nonterminal
  transaction resumes or rolls back before normal admissions open;
- a too-old helper prevents activation without affecting the healthy current service,
  then SeaWork repair upgrades the helper and permits a later retry;
- helper crash/restart and reboot recovery cover every durable mutation boundary; and
- uninstall removes both owned SCM entries and the fixed helper while retaining the
  last-known-good version/state whenever reconciliation cannot be proved complete.

## 2026-07-22 — Controlled self-upgrade implementation handoff

Status: **LocalSandbox source implementation complete; signed Windows end-to-end
evidence and downstream SeaWork installer/repair/uninstall implementation remain open**

This entry supersedes only the artifact-location statement in the preceding controlled
self-upgrade entry. It does not alter that entry's SCM, repair, uninstall, or acceptance
requirements.

### Exact LocalSandbox source baseline

- Branch: `feat/lsbs-auto-upgrade`.
- Contract and maintenance API: `de7fc8f779e806d5bcef305c93e23a3743653ddd`.
- Natural-idle admission sealing: `359c1b6`.
- Durable discovery/state, archive, verification, and protected writes:
  `85300d9`, `1733daf`, `6eec754`, `cd48a97`, and `be65a34`.
- Crash-safe SCM updater helper: `73c6fea`.
- Runtime discovery/download/coordinator, activation recovery, rate limiting, and
  failed-target suppression: `7577ca1`.
- Deterministic updater artifact and signing/package contract: `2de5438`.

The implemented binaries are:

- `localsandbox-seawork-service.exe`, protocol major 1/minor 6; and
- `localsandbox-seawork-updater.exe`, helper protocol 1.1.

The service candidate remains the exact immutable GitHub release asset
`lsb-seawork-service-v<VERSION>-windows-x86_64.zip`. The helper is intentionally a
separate immutable installer input:

- `lsb-seawork-updater-v<VERSION>-windows-x86_64.zip`;
- `lsb-seawork-updater-v<VERSION>-windows-x86_64-manifest.json`; and
- `lsb-seawork-updater-v<VERSION>-SHA256SUMS`.

The helper ZIP contains only `localsandbox-seawork-updater.exe` and
`manifests/updater.json`. The manifest binds canonical version, target, binary SHA-256,
publisher subject and SHA-256 thumbprint, helper protocol, SCM name, and exact command
template. GitHub metadata and the manifest are discovery/integrity inputs; SeaWork must
still independently validate the timestamped Authenticode chain and exact publisher of
the PE before installation.

This separate-artifact rule replaces the preceding entry's statement that the helper
would be placed inside the service archive. It preserves the security invariant that
the main service never installs or updates its own helper. SeaWork must pin the service
and updater artifacts from one immutable release tuple and reject a missing, mutable,
cross-version, or contradictory pair.

### Runtime and protected-state contract

The generated revision-2 service contract now includes the fixed release repository,
stable/prerelease channels, updater artifact template, helper SCM identity and command,
helper protocol, and these protected paths:

- `%ProgramData%\LocalSandbox\SeaWork\updates\committed.json`;
- `%ProgramData%\LocalSandbox\SeaWork\updates\status.json`;
- `%ProgramData%\LocalSandbox\SeaWork\updates\failed-target.json`;
- `%ProgramData%\LocalSandbox\SeaWork\updates\transactions\current.json`;
- `%ProgramData%\LocalSandbox\SeaWork\updates\downloads`;
- `%ProgramData%\LocalSandbox\SeaWork\updates\staging`; and
- `%ProgramData%\LocalSandbox\SeaWork\updates\history`.

Maintenance operations gated at protocol minor 6 are `PrepareUpdate` with the complete
bundle identity, `GetUpdateStatus`, `CheckForUpdate`, `CommitUpdate`, and `AbortUpdate`.
The bounded status phases include checking, no-candidate, downloading, verifying,
waiting-for-idle, sealed, helper-starting, activation-pending, rollback-pending,
failed-target-suppressed, and recovery-quarantine. Failure categories include network,
TLS, HTTP, rate-limited, invalid metadata, no candidate, download, verification,
helper-too-old, and internal failure.

Startup recovery compares the protected journal with the exact running executable. An
old-version restart restores zero-use `UpdateSealed`; a target-version restart restores
`ActivationPending`/`UPDATE_PENDING`; a contradictory journal/executable pair remains
health/maintenance-only in recovery quarantine. The service may validate and start the
preinstalled helper but never creates, deletes, or reconfigures either SCM entry.

After an activation-health rollback, `failed-target.json` prevents retry of the exact
archive digest for at least 24 hours. Three such failures suppress that digest across
service restarts until a greater release appears or SeaWork repair explicitly clears
the valid bounded record. Repair must not delete corrupt or contradictory protected
state merely to reopen admissions.

### Release and downstream boundary

No change was made to `.github/workflows/release.yml`. The current `just release
<version>` behavior and `service_evidence=skip|required` policy described in the prior
entry remain authoritative. LocalSandbox release publication must separately adopt the
new `seawork-updater` package command and `SignUpdaterPe`/`VerifyUpdaterPe` modes before
a final tuple can be asserted.

SeaWork must implement every installer, repair, boot-recovery, and uninstall item in
the preceding entry using the separate pinned updater artifact above. In particular,
it must install the helper at the generated fixed Program Files path, seed independently
verified `committed.json`, configure the exact helper SCM recovery policy, reconcile a
nonterminal transaction during repair, and remove only proven installer-owned paths on
uninstall.

### Verification status and evidence still required

Local verification at this baseline includes the service/update/updater source tests,
all journal-phase recovery tests, deterministic updater packaging tests, release-version
consistency, scoped Clippy, PowerShell parser validation, and a successful
`x86_64-pc-windows-msvc` check of the updater binary. The service's Windows-target Cargo
check is locally blocked before project compilation because the macOS host lacks the
Windows SDK C headers required by transitive native dependencies.

Do not treat these source checks as signed Windows acceptance evidence. Before SeaWork
pins a tuple, run and bind exact hashes/publisher identity for successful activation,
indefinite busy wait, idle/start race, pre-stop failure, health rollback, helper crash
at every journal phase, reboot recovery, three-failure suppression, repair, and
uninstall. Append the immutable release URL/ID, source commit/tree, PE and ZIP SHA-256
values, publisher/timestamp evidence, and Windows run IDs here; do not replace this
entry or infer those values from unsigned local builds.

## 2026-07-22 — Controlled self-upgrade source hardening and evidence contract

Status: **LocalSandbox source contract extended; signed Windows execution and all
SeaWork-owned installation, repair, boot-recovery, and uninstall work remain open**

This append-only entry extends the controlled self-upgrade source baseline above. It
does not change the separate immutable updater-artifact rule or the current release
workflow boundary.

Additional LocalSandbox commits are:

- `5f69b4f`: exact recovery when the target committed through the maintenance protocol
  before the helper finalized the protected committed-state record;
- `21ba92c`: host-neutral coordinator policy tests plus a bounded, no-window helper
  `--version --json` query before handoff; the service requires helper protocol 1.1 or
  a compatible newer minor and reports incompatible identity/protocol as
  `helper_too_old` without changing SCM ImagePath;
- `5ede1b2`: a digest-bound Windows controlled-update evidence schema, validator,
  assembler, and complete case/crash/reboot phase matrix; and
- `d2b3b30`: helper candidate placement now opens and creates every child relative to
  pinned NT directory handles, rejects reparse entries, and re-verifies the exact final
  bundle before SCM mutation.

No change was made to `.github/workflows/release.yml`. The current `just release
<version>` and `service_evidence=skip|required` behavior remains authoritative. The
dedicated update evidence is deliberately separate from existing service-release
evidence and lives below:

```text
artifacts/windows-update-evidence/
  <source-git-sha>/<service-archive-sha256>/<helper-binary-sha256>/manifest.json
```

On the authorized Windows host, use
`scripts/assemble-seawork-update-evidence.ps1`; independently validate with:

```powershell
cargo run -p xtask --locked -- verify-seawork-update-evidence `
  --manifest <manifest-path> `
  --service-archive <exact-service-zip> `
  --helper <exact-installed-helper-exe> `
  --require-complete
```

The complete gate binds the source commit, immutable GitHub release ID/tag, service ZIP,
installed helper PE and queried protocol, accepted publisher SHA-256 identity, and exact
previous/candidate bundle identities. It requires stable/prerelease selection, busy
wait, idle/start race, successful activation, health rollback, hostile/incompatible
rejection including a too-old helper, failed-target suppression, SeaWork repair, and
SeaWork uninstall. It also independently requires helper-crash and real-reboot recovery
at every nonterminal durable journal phase. Incomplete `blocked`/`not_run` handoffs are
retained with stable codes but cannot pass `--require-complete`.

SeaWork must continue to implement and prove every installer/SCM/ACL/recovery/uninstall
row from the preceding entries. This LocalSandbox evidence tooling does not install the
helper, synthesize a signed release tuple, authorize remote-host execution, or replace
SeaWork-owned acceptance work.

## 2026-07-22 — Controlled updater install and repair hardening

Status: **LocalSandbox helper/install contract hardened; SeaWork implementation and
signed Windows execution evidence remain open**

This append-only entry extends the controlled self-upgrade entries above. It does not
change the separate immutable updater-artifact rule, transfer install/repair/uninstall
ownership to LocalSandbox, or modify the current release workflow.

### Additional LocalSandbox source baseline

- `7d7b66e`: the service requires the helper's full `--verify-install --json`
  self-check; the helper verifies protected fixed directories/state, its complete SCM
  identity/recovery/DACL policy, the generated 60-second main-service stop bound, and
  pinned old-process exit. Downloads use exclusive partial files and durable directory
  publication where Windows supports it.
- `7b35850`: package verification binds the target service contract's minimum helper
  protocol; the coordinator rejects an incompatible installed helper before sealing
  admissions and records the actual compatible protocol in the transaction. Recovery
  tolerates only transaction-owned mixed ImagePath/Event Log mutation boundaries,
  re-verifies the last-known-good bundle before restart, and emits bounded update
  phase/category/version/digest-prefix diagnostics.
- `3c899c7`: replay from every post-placement phase re-verifies the exact final target,
  target helper-protocol requirement, protected SCM command, and exact post-commit
  state before the transaction can finalize.

The deterministic updater artifact manifest is now schema version 2. In addition to
the existing binary digest, publisher, protocol, service name, and command, it binds:

- display name `LocalSandbox for SeaWork Updater`;
- `SERVICE_WIN32_OWN_PROCESS`, LocalSystem, and automatic start;
- unrestricted service SID;
- service-object SDDL
  `O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00000005;;;IU)`;
- restart delays of 5, 30, and 120 seconds with an 86,400-second reset period; and
- failure actions enabled for non-crash failures.

### Mandatory SeaWork changes

1. Treat updater manifest schema 2 as the complete install/repair input. Reject an
   older, missing, cross-version, or contradictory manifest rather than filling SCM
   fields from local defaults.
2. Create and protect the generated Program Files product/updater/versions roots and
   every generated ProgramData update-state directory before the service or helper is
   started. Child version/staging trees must inherit the generated administrator and
   service-only ACL; neither standard users nor interactive users may obtain write,
   delete, owner, or DACL rights.
3. Install/repair the helper SCM entry with the exact schema-2 display name, own-process
   type, quoted command, LocalSystem account, automatic start, no dependencies,
   unrestricted SID, service-object SDDL, three restart actions/reset period, and the
   non-crash-failure flag. Any mismatch is a failed repair, not a warning.
4. Use the signed helper's bounded `--verify-install --json` mode after binary,
   publisher, path, ACL, and SCM setup. Exit success plus `valid: true`, the exact
   service name, and a compatible protocol are all required. `--version --json` alone
   is not install evidence. The public failure field is deliberately the stable
   `INSTALL_INVALID` code; SeaWork must not depend on raw internal exception text.
5. During repair, preserve a valid nonterminal transaction, restore the exact protected
   helper/SCM policy, and start the helper so it can reconcile the journal. Do not clear
   committed, failed-target, transaction, or version state to make verification pass.
6. A target whose catalog-covered service contract requires a newer helper must remain
   on the healthy current service with `UPDATE_HELPER_TOO_OLD`. Repair must install a
   compatible helper from the same pinned immutable release tuple before retrying.
7. Keep the current `just release <version>` and `service_evidence=skip|required`
   dispatch behavior. LocalSandbox did not modify `.github/workflows/release.yml` for
   this work; publication wiring remains a separate owner task.

Signed Windows evidence must additionally prove schema-2 SCM policy enforcement,
standard-user no-UAC behavior, protected directory/file rejection, exact old-process
exit, pre-switch failure without forced workload loss, recovery from either half of an
ImagePath/Event Log update, and full target/last-known-good re-verification on replay.

The controlled-update evidence manifest is now schema 2 as well. Assembly requires
and records the full successful helper install self-check plus independent valid
timestamped Authenticode and exact publisher-certificate SHA-256 verification. SeaWork
must not submit or accept a schema-1/version-query-only update evidence manifest.

## 2026-07-22 — Reduced controlled-upgrade acceptance profile

Status: **minimum acceptance scope simplified; signed SeaWork-installed execution
remains downstream**

This append-only entry supersedes only the exhaustive controlled-upgrade result and
crash/reboot matrix described in the earlier 2026-07-22 entries. It does not relax
artifact signing, immutable identity, publisher, helper self-check, SCM/ACL, no-UAC,
or exact previous/candidate bundle requirements.

For this task, `--require-complete` requires these five passing cases:

- stable-channel discovery;
- indefinite busy-to-idle waiting;
- successful activation and commit (the happy path);
- unhealthy-target rollback; and
- untrusted or incompatible candidate rejection before SCM mutation.

It also requires one real-reboot recovery pass at the durable
`image_path_changed` phase. The remaining recognized cases and durable phases may be
retained as useful additional evidence, but prerelease selection, a separate idle race,
failed-target suppression, SeaWork repair/uninstall, helper-crash injection, and a
reboot at every phase are not blockers for this reduced gate.

LocalSandbox's `scripts/win-test suite update-fast` runs the service baseline plus the
controlled-update, updater, and evidence-tool tests and Clippy natively on Windows. Its
evidence explicitly records that no signed installation or controlled update was
executed. SeaWork still owns installing/repairing the helper from the pinned immutable
release tuple and running the signed production-profile cases above against the real
SCM entries; record that final evidence in a later append-only handoff entry.
