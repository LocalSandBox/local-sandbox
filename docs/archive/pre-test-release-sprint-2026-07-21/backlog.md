# Production backlog for the SeaWork Windows service replacement

## Goal

Replace SeaWork's current production Windows sandbox helper with the LocalSandbox-owned
`LocalSandboxSeaWork` SCM service without reducing user-visible sandbox functionality,
security, reliability, or supported workflows.

The production replacement is complete only when:

- a standard Windows user can use every SeaWork sandbox workflow without UAC during
  normal application use;
- workspace, output, skills, network, credential, port, process, file, and lifecycle
  behavior is equivalent to or better than the current production helper;
- no production code path launches or falls back to `--seawork-sandbox-helper`;
- the service is installed, updated, repaired, rolled back, and uninstalled through a
  signed and verified SeaWork installer transaction;
- the complete real-Windows, multi-user, crash/reboot, security, and managed-fleet
  acceptance matrix passes; and
- the released x86-64 service and Node client are signed, supportable, observable, and
  protected by enforced release gates.

Windows Arm64 is explicitly out of scope. The required production target is Windows 11
x86-64.

## Priority and completion rules

- **P0 — architecture or release blocker:** complete before a signed release candidate
  is treated as a viable replacement.
- **P1 — production acceptance blocker:** complete before enabling the service for any
  production users.
- **P2 — general-availability blocker:** complete before retiring the helper fleet-wide.

Every item in this document blocks the stated production replacement unless it is
explicitly moved out of scope through a documented product and security decision.
Passing unit tests alone is not sufficient where the definition of done requires real
Windows, installed-artifact, multi-user, or managed-fleet evidence.

## Resolved decisions and implementation authority

The project owner has accepted the defaults in this section. They are binding for this
backlog and remove the need for further product or architecture questions during the
macOS implementation pass. Missing Windows hardware, release credentials, managed-fleet
access, or named approvers prevents only the corresponding external verification; it
does not block implementation, test-harness construction, or documentation on macOS.

### 1. Baseline, repositories, and authority

- The production parity source is SeaWork commit
  `0ae88c6d338ffb10d765296625ea38b3b3991f64` in `~/code/seawork`, paired with
  LocalSandbox version `0.4.6`.
- Preserve every sandbox behavior reachable from that pinned SeaWork application, not
  unrelated LocalSandbox API surface. The pinned source, a golden compatibility fixture,
  and tests are the authority; production telemetry and performance measurement are not
  prerequisites for implementation.
- The coding agent may change this LocalSandbox repository. It must not implement code
  in `~/code/seawork`; all downstream SeaWork work must instead be added to and refined
  in `~/code/seawork/plan.md`.
- Deliver LocalSandbox work as commits on the current branch. Do not commit secrets,
  generated signing credentials, Windows evidence that contains sensitive machine data,
  or changes from the SeaWork worktree.
- When sources disagree, apply this order: this decision record, the pinned SeaWork
  source, LocalSandbox `plan.md`/`state.md`, then other documentation. Preserve behavior
  where safe; otherwise choose the least-privileged fail-closed implementation and
  record the choice in an ADR without waiting for another owner decision.

### 2. Reachability decisions from the pinned SeaWork source

- `ports` and `network.exposeHost` are required parity. At the pinned commit they are
  accepted and persisted by the runtime-context contracts/store, rendered by the agent
  registry, and forwarded by `packages/local-sandbox-tools/src/shared.ts` into sandbox
  start options. They are therefore reachable even though the default Electron startup
  does not hard-code a mapping.
- Sandbox checkpoint creation and restore are out of scope. The pinned source contains
  no production `checkpoint()` call, UI, or producer of checkpoint data. It only carries
  a legacy `from` string through generic context/schema plumbing. The service adapter
  must reject an unexpected non-empty `from` with stable `CHECKPOINT_UNSUPPORTED`
  migration guidance; it must not silently interpret it as a path or checkpoint ID.
- `instanceId` remains correlation/cache identity only. It maps to a service-generated
  opaque identifier and can never select a filesystem path, adopt a sandbox, or survive
  service cleanup as user-controlled identity.

### 3. Mount policy and exact semantics

- Eligibility for the admin fast path is decided only by the service from the
  authenticated caller token. A caller is an admin when the token, or its linked full
  token for a UAC-filtered process, is a member of built-in local Administrators
  (`S-1-5-32-544`). SeaWork itself need not be elevated. No caller-supplied admin flag,
  username, SID, path manifest, or cleanup manifest is trusted.
- An eligible admin uses the current live mount implementation and skips staged sync for
  performance. Before it can be enabled, the implementation must be refactored behind
  caller-token `AccessCheck`, handle-relative traversal, pinned component/final handles,
  protected ledger ownership, exact post-operation identity proof, and exact cleanup.
  Admin membership alone is not authority to access a path denied to the caller token or
  another user's resource.
- A non-admin uses staged sync. Read-only workspace/skills inputs are copied into a
  protected per-sandbox stage and refreshed one-way from host to guest. Read-write output
  is copied guest-to-host after close/rename and during periodic flush, followed by a
  mandatory final flush on stop. Overlay writes remain disposable unless explicitly
  represented as the output mount.
- A host/guest conflict never silently overwrites the changed host file. Publish the
  guest version beside the target as
  `<filename>.lsb-conflict-<128-bit-lowercase-hex-session-id>-<decimal-sequence>`,
  return `MOUNT_CONFLICT`, and retain recovery metadata. A failed final flush returns
  `MOUNT_SYNC_INCOMPLETE` and retains protected staging for bounded repair/retry rather
  than reporting successful teardown or exposing the protected stage path.
- The supported host storage scope is local, fixed NTFS or ReFS only. UNC, mapped/network
  drives, removable media, cloud placeholders, EFS, device/ADS paths, and redirected
  locations outside a local fixed NTFS/ReFS volume fail with stable `MOUNT_UNSUPPORTED`.
- Staged-mount limits are 100,000 entries, 20 GiB logical tree size, 4 GiB per file, 256
  path components, and Windows' 32,767-UTF-16-code-unit extended-path ceiling. With at
  most 100 queued changes, a closed/renamed file of at most 16 MiB propagates within
  1 second p95; a larger copy starts within that window and drains at available local
  disk throughput. Stop allows a 30-second final flush before returning an actionable
  retained-staging error.

### 4. Network and host-connectivity policy

- Match SeaWork's `defaultNetworkEnabled: true` with the most relaxed safe policy:
  public internet is allowed by default for DNS names and direct globally routable
  IPv4/IPv6 addresses. Every resolution and redirect hop must remain globally routable.
  Loopback, local interfaces, RFC1918/ULA, link-local, carrier-grade NAT, multicast,
  unspecified, reserved/documentation ranges, metadata endpoints, and WPAD stay denied.
- Host patterns support exact IDNA-normalized names and `*.example.com`-style subdomain
  wildcards. Redirects are allowed only after policy is reapplied at every hop. Secrets,
  authorization, cookies, and injected headers are stripped when a request leaves their
  declared exact/wildcard host scope.
- HTTPS interception, scoped request-header mutation, and host-scoped secret injection
  are required in the first production replacement. Trust uses LocalMachine roots plus
  an optional installer-protected product CA bundle. Support an explicitly configured
  proxy and explicit scoped proxy credentials; never use WPAD or default Windows/machine
  credentials.
- Implement host-to-guest `ports` with exact requested host/guest TCP port preservation
  and WFP isolation bound to the authenticated owner logon. Implement guest-to-host
  `network.exposeHost` through an authenticated SeaWork app-owned relay so the actual
  host connection is opened under the caller's unelevated token, never LocalSystem.
  Preserve `host.lsb.internal`, TCP, IPv4/IPv6, and existing failure semantics; UDP,
  wildcard/remote binds, dynamic substitution, and undeclared ports are unsupported.
- Port and host-relay quotas are 32 mappings per sandbox, 64 per user, and 128 globally,
  with at most 128 active tunneled connections per sandbox. Quota reservations and WFP/
  relay state must be released on every terminal path.

### 5. Fixed capacity, timeout, and compatibility contract

Use these values without a measurement phase. A coding agent may raise a limit when a
pinned-source fixture proves that is necessary and the same bounded-resource tests pass,
but may not lower one without recording a compatibility exception.

| Area | Required value |
| --- | --- |
| Connections | 32 global; 4 per user |
| Sandboxes | 8 global; 4 per user; 2 per connection |
| Sandbox shape | 1-8 vCPU; 512-8192 MiB RAM; 1024-32768 MiB disk |
| Aggregate compute | 8 vCPU/8 GiB RAM/64 GiB disk per user; 16 vCPU/24 GiB RAM/128 GiB disk global |
| Guest processes | 64 per sandbox; 128 per user; 256 global |
| Watches | 64 per sandbox; 128 per user; 512 global; 256 queued/coalesced events per watch |
| Active RPCs | 16 per connection; 64 global |
| Protocol/control | 256 KiB control payload; 64 KiB stream frame; 32 KiB string; JSON depth 32 |
| Exec/environment | 8 MiB combined unary stdout/stderr; 128 KiB environment; command/argv must fit the control and string limits |
| File transfer | 64 MiB per RPC; 256 KiB initial credit; 5-minute default transfer deadline |
| Process stream | 4 MiB credit window; 30-second stalled-consumer termination |
| Service timing | 120-second boot; 30-second unary default; 10-minute server maximum; 30-second STOP; 60-second preshutdown |
| Protocol support | Current and immediately previous protocol minor for at least one LocalSandbox release cycle |

Stable error codes must distinguish invalid input, unsupported capability, policy denial,
quota, timeout, cancellation, conflict, unavailable/reboot-required, incompatible
protocol, trust failure, and internal failure. Only explicitly retryable read-only or
idempotent operations may be retried automatically; resource creation is at-most-once.

### 6. Security, signing, install, and update decisions

- LocalSystem is the approved Windows x86-64 service account. Production roots are
  `C:\Program Files\LocalSandbox\SeaWork` for immutable service versions,
  `C:\ProgramData\LocalSandbox\SeaWork` for protected state, and
  `C:\Program Files\SeaWork` for the signed client/maintenance application.
- Existing signing inputs are outside both repositories at
  `~/code/private/SeaWork-CodeSign.pfx` and
  `~/code/private/SeaWork-SignCert.cer`. Code and CI consume paths/passwords only through
  `SEAWORK_WINDOWS_PFX_PATH`, `SEAWORK_WINDOWS_PFX_PASSWORD`,
  `SEAWORK_WINDOWS_CERT_PATH`, and `SEAWORK_WINDOWS_TIMESTAMP_URL`; the default RFC 3161
  timestamp endpoint is `http://timestamp.digicert.com`. Never inspect, copy, print, or
  commit private-key material. Subject and SHA-256 thumbprint are derived from the
  signing certificate and pinned into generated release/install contracts.
- NSIS is the installer. First install is elevated and installs/configures/starts the
  service. Repair, rollback, uninstall, and any upgrade before service self-update exists
  are also explicit signed elevated NSIS transactions; ordinary SeaWork use never asks
  for elevation or SCM control.
- The supported in-place migration source is the pinned SeaWork baseline using
  `@local-sandbox/lsb-nodejs` `0.4.6`. An older or unrecognized installation must use
  a signed explicit uninstall/reinstall flow and must not import caller-provided legacy
  cleanup state.
- Keep one previous signed compatible service version until the new version passes
  health and commit. Emergency rollback restores that service version only and never
  enables a runtime helper fallback. Active sandboxes drain for 30 seconds before the
  update proceeds; an unclean drain aborts and leaves the current version active.
- Service self-update is intentionally deferred for a later design pass. It does not
  block the first service cutover because signed elevated NSIS remains the supported
  upgrade mechanism. The future self-update requirement must be recorded in the SeaWork
  plan, but the macOS coding agent must not invent its authority, key, rollback, or
  anti-downgrade design now.
- The release/security on-call role owns signer compromise and rotation incidents.
  LocalSandbox service on-call owns authentication, ledger, quarantine, and cleanup
  incidents, with the SeaWork desktop/support role owning user remediation and fleet
  rollback. Personal names may be attached later without changing these responsibilities.

### 7. External evidence and rollout defaults

- A Windows operator, machine/runner labels, and managed-fleet lab details will be
  provided later. Until then the macOS agent completes every host-neutral implementation,
  Windows cross-build that is locally possible, one-command Windows runner, result
  schema, and evidence validator, then marks only the runtime gate `external verification
  pending`.
- Evidence is stored as `artifacts/windows-evidence/<git-sha>/<artifact-sha256>/` with a
  machine-readable manifest. Logs must be redacted and must not be committed when they
  contain machine, user, certificate, or corporate-network identifiers.
- Rollout stages are internal, 5%, 25%, then 100%, with a minimum three business days at
  each non-internal cohort. Telemetry retention is 30 days and excludes commands,
  arguments, environment, content, full paths, credentials, and raw user/SID values.
- Automatically halt/rollback for any cross-user access, signing/trust bypass, leaked
  privileged resource, helper fallback, or destructive cleanup defect; or when sandbox
  start success falls by more than 1 percentage point or p95 boot latency regresses by
  more than 20% versus the immediately preceding cohort. Role-based product, security,
  desktop, release, and support sign-off is sufficient; personal names are operational
  metadata to be attached later and do not block engineering work.

## Instructions for a coding agent working on macOS

- Treat macOS as an implementation and host-neutral test environment, not as evidence
  that Windows security, SCM, WHPX, SMB, WFP, Job, Event Log, installer, or signing
  behavior works.
- Maintain separate status for each epic: `macOS implementation`, `Windows cross-compile`,
  `Windows runtime verification`, `managed-fleet verification`, and `owner sign-off`.
- Never mark an epic `done` while a required Windows or external definition-of-done item
  remains. Use `implementation complete; Windows verification pending` instead.
- Run host-neutral Rust/Node unit, protocol, parser, property, fuzz, golden, ledger,
  policy, and adapter tests on macOS. Add abstraction boundaries so pure logic is tested
  independently of Win32 calls.
- Cross-compile Windows x86-64 targets and parse PowerShell/workflow files when the local
  toolchain supports it, but do not substitute cross-compilation for runtime evidence.
- Build deterministic Windows test harnesses, fixtures, machine-readable result schemas,
  and one-command PowerShell runners so a Windows owner can execute them without
  redesigning the test.
- Treat `~/code/seawork` as read-only except for `plan.md`. Inspect the pinned commit
  for compatibility evidence, but record every downstream source, packaging, installer,
  migration, and test change as an executable task in that plan instead of implementing
  it during this pass.
- Preserve fail-closed behavior until a capability's implementation and required
  Windows evidence both pass. Do not temporarily enable mounts, networking, ports, or
  unsigned clients to make macOS tests pass.
- Do not remove the helper while implementing SWK-02. CLN-01 is executed only after the
  signed service rollout satisfies ROL-01.
- Do not read, copy, print, or embed the signing private key. Implement only the declared
  path/password contracts and deterministic unsigned/test-signed inputs on macOS.
- All decisions required for the macOS pass are resolved above. Do not wait for a named
  Windows operator, signer password, or rollout owner; finish the code and harness, then
  mark the corresponding execution/sign-off evidence as external and pending.

## Critical path

1. Freeze and automate the current-production parity contract.
2. Implement mounts, networking, host exposure/ports, and start/retry parity.
3. Finish service containment, endpoint authentication, and crash reconciliation.
4. Prove the complete service on a disposable LocalSystem/Session 0 machine.
5. Produce a production-signed release candidate.
6. Implement the SeaWork installer and application cutover.
7. Pass clean-machine, multi-user, lifecycle, adversarial, and managed-fleet acceptance.
8. Remove the production helper and enforce the service-only release gates.

## Summary

| ID | Priority | Owner | Backlog item | Depends on |
| --- | --- | --- | --- | --- |
| PAR-01 | P0 | Joint | Freeze the production feature-parity contract | — |
| MNT-01 | P0 | LocalSandbox | Implement secure production mounts | PAR-01 |
| NET-01 | P0 | LocalSandbox | Implement outbound networking, secrets, and HTTPS policy | PAR-01 |
| NET-02 | P0 | Joint | Implement safe `ports` and `network.exposeHost` parity | PAR-01 |
| LIF-01 | P0 | Joint | Implement start, identity, and retry parity | PAR-01 |
| API-01 | P0 | Joint | Close Node/RPC behavioral and capacity gaps | PAR-01 |
| CAN-01 | P1 | LocalSandbox | Close synchronous filesystem cancellation ambiguity | API-01 |
| CON-01 | P0 | LocalSandbox | Give the service authoritative QEMU Job control | — |
| SEC-01 | P0 | LocalSandbox | Complete client-to-service mutual authentication | — |
| SEC-02 | P0 | LocalSandbox | Complete exact cleanup and recovery proof | MNT-01, NET-01, NET-02, LIF-01, CON-01 |
| WIN-01 | P0 | LocalSandbox | Pass the real LocalSystem/Session 0 runtime gate | All feature-parity P0 items, CON-01, SEC-01, SEC-02 |
| REL-01 | P0 | LocalSandbox | Establish production signing and artifact trust | SEC-01, WIN-01 |
| SWK-01 | P0 | SeaWork | Implement protected install and maintenance transactions | REL-01 |
| SWK-02 | P0 | SeaWork | Replace the helper with the upstream service client | All upstream P0 items, SWK-01 |
| TST-01 | P1 | Joint | Pass multi-user and adversarial security acceptance | SEC-01, SEC-02, SWK-02 |
| TST-02 | P1 | Joint | Pass update, rollback, repair, uninstall, and power-loss acceptance | SEC-02, SWK-01, SWK-02 |
| OBS-01 | P1 | LocalSandbox | Complete production diagnostics and Event Log integration | — |
| ENT-01 | P1 | Joint | Validate Defender/EDR, GPO, proxy, VPN, and certificates | WIN-01, REL-01, SWK-02 |
| CI-01 | P1 | LocalSandbox | Enforce all production gates in CI/release automation | WIN-01, REL-01, TST-01, TST-02, OBS-01, ENT-01 |
| ROL-01 | P2 | Joint | Complete staged rollout, telemetry, and support readiness | All P0 and P1 items |
| CLN-01 | P2 | Joint | Remove the helper and legacy privilege-separation paths | ROL-01 |

## macOS development feasibility

No production epic can be closed solely on macOS because the replacement ultimately
depends on an installed Windows service. The labels below indicate how much useful work
the coding agent can complete before a Windows owner takes over verification:

- **MAC-HIGH:** most design, implementation, and automated host-neutral testing can be
  completed on macOS. Windows cross-compilation and runtime acceptance still remain.
- **MAC-PARTIAL:** meaningful interfaces, pure logic, mocks, scripts, and cross-compiled
  Windows code can be produced, but the central implementation depends heavily on
  Win32 or an installed Windows environment.
- **WINDOWS/EXTERNAL:** the agent can prepare a harness or checklist, but the item's
  substantive execution and sign-off require Windows hardware, production credentials,
  organizational infrastructure, or live rollout evidence.
- **PLAN-ONLY:** implementation belongs to the SeaWork repository and is not authorized
  in this pass. The macOS agent must add concrete files, steps, tests, dependencies, and
  definitions of done to `~/code/seawork/plan.md`.

For a `MAC-HIGH` or `MAC-PARTIAL` item, **macOS implementation complete** means:

- the resolved decisions in this document are reflected in code and tests;
- production code contains no temporary insecure fallback or test-only trust path;
- applicable macOS host-neutral tests, formatting, linting, declarations, fixtures, and
  deterministic artifact tests pass;
- Windows x86-64 targets cross-compile when the required cross toolchain supports the
  crate, or the exact cross-compilation blocker is documented;
- every remaining Windows behavior has an automated test or one-command harness with
  prerequisites, bounded runtime, machine-readable results, and expected assertions;
- the handoff records exact commit SHA, commands, required assets/policies, and evidence
  output locations; and
- the epic status explicitly lists each unexecuted Windows, managed-fleet, signing,
  installer, rollout, or owner-sign-off requirement.

This intermediate status is useful progress but does not satisfy the final definition of
done later in this document.

| ID | macOS scope | Work the macOS agent can complete | Work that remains outside macOS |
| --- | --- | --- | --- |
| PAR-01 | MAC-HIGH | Inventory the pinned SeaWork source; generate the parity schema/fixtures; add adapter-level golden tests; encode the fixed limits in this document | Run the current Windows helper and replacement on real parity workloads; role-based product/security sign-off |
| MNT-01 | MAC-PARTIAL | Design capability APIs; implement the admin live-path and non-admin staged-path state machines, protocol/client/Node types, pure path/admin policy, snapshots, conflicts, ledger state, quotas, and host-neutral tests; cross-compile Win32 code | Execute real linked-token admin detection, caller-token `AccessCheck`, pinned traversal, SMB/LSA/DACL/share/watch, NTFS/ReFS, TOCTOU, GPO, crash/reboot, ownership, and performance tests on Windows |
| NET-01 | MAC-HIGH | Implement protocol/client/Node APIs; policy parsing; hostname/IP/rebinding rules; proxy configuration; secret/header scoping and redaction; proxy-engine integration; unit/fuzz/golden tests | Prove Session 0 networking, Windows certificate stores, enterprise proxy authentication, VPN routing, DNS, and managed policy on Windows |
| NET-02 | MAC-PARTIAL | Implement the selected WFP path and service half of the app-owned relay; protocol/Node APIs, quotas, relay state machine, portable framing/security tests, and Windows cross-build; record the SeaWork relay half in its plan | Prove loopback isolation, WFP behavior, caller-context relay, Firewall/EDR/VPN interaction, port races, crash cleanup, and multi-logon behavior on Windows |
| LIF-01 | MAC-HIGH | Implement opaque identity, protected bundle selection, compatibility, at-most-once start/retry state machine, adapter mapping, unsupported-`from` behavior, and fault-injection tests | Verify real WHPX/QEMU start, lost-response recovery, crash/reboot/update/rollback behavior and performance on Windows |
| API-01 | MAC-HIGH | Implement protocol/Rust client/Node surface parity, shell/options/errors/limits, host-neutral streaming/backpressure tests, and declaration/compatibility fixtures; record SeaWork adapter work in its plan | Run the signed native addon and downstream adapter workloads against the installed Windows service and real VM |
| CAN-01 | MAC-HIGH | Define commit/cancel semantics; refactor state machines; add deterministic scheduling and fault-injection tests around all cancellation points | Validate behavior around real blocking Win32/guest filesystem calls and SCM drain on Windows |
| CON-01 | MAC-PARTIAL | Refactor ownership interfaces; implement external-Job plumbing behind abstractions; add fake supervisor/process-tree tests; cross-compile Windows code | Prove suspended creation, nested Jobs, QEMU/helper containment, forced termination, SCM deadlines, crash, and reboot on Windows |
| SEC-01 | MAC-PARTIAL | Implement command parsing, trust-policy data, state machine, safe error mapping, dev/production name separation, and mock race tests; cross-compile Win32 verification | Exercise SCM/service SID, process/image handles, Authenticode, protected ancestors, token/PID races, low integrity, AppContainer, remote pipe, and squatter attacks on Windows |
| SEC-02 | MAC-HIGH | Implement ledger schemas, transactions, proof requirements, quarantine, quotas, reconciliation state machines, fault injection, corruption, collision, and idempotence tests | Re-query and clean real Jobs, users, LSA rights, shares, ACEs, WFP, ports, processes, staging trees, and filesystem identities after crash/reboot on Windows |
| WIN-01 | WINDOWS/EXTERNAL | Improve the spike, one-command runner, result schema, diagnostics collection, and evidence validator | Run and sign off the entire LocalSystem/Session 0 matrix on Windows hardware |
| REL-01 | MAC-PARTIAL | Implement deterministic packaging, manifests, SBOM/licenses, checksums, dependency policy, workflows, secret contracts, mock/test signing paths, and documentation | Provision production identity; run SignTool/catalog/timestamp/chain checks; verify clean-machine trust and custody controls on Windows/CI |
| SWK-01 | PLAN-ONLY | Expand the SeaWork plan with NSIS files, protected configuration, archive checks, installer-driven update/rollback/repair/uninstall sequencing, tests, and handoff commands | A future SeaWork implementation pass and real Windows installed-machine verification |
| SWK-02 | PLAN-ONLY | Expand the SeaWork plan with adapter files, package pins, error/UX mapping, retry rules, packaging assertions, migration, and test cases | A future SeaWork implementation pass, native addon execution, and installed Electron verification on Windows |
| TST-01 | MAC-PARTIAL | Add parser/property/fuzz tests; deterministic concurrency, quota, sequence, cancellation, malformed-frame, handle-churn, and mock identity tests; build Windows runners | Execute installed signed multi-user, multi-logon, AppContainer/low-integrity, pipe/security, resource isolation, real workload, and saturation tests on Windows |
| TST-02 | WINDOWS/EXTERNAL | Author the lifecycle fault matrix, orchestration scripts, VM snapshot steps, assertions, result schema, and evidence validator | Execute clean install/reboot/update/rollback/repair/uninstall/power-loss cases on Windows VMs |
| OBS-01 | MAC-PARTIAL | Define stable events; implement redaction and JSON logging; author `.mc` resources/build scripts; test rotation/tamper/disk-full logic; cross-compile resources where possible | Compile/verify with Windows SDK tools; register Event source; inspect Application Event Log; test installed update/rollback paths on Windows |
| ENT-01 | WINDOWS/EXTERNAL | Prepare the compatibility checklist, probes, diagnostics bundle, expected fail-closed results, and evidence template | Run and approve on managed Defender/EDR/GPO/proxy/VPN/certificate/Firewall/application-control machines |
| CI-01 | MAC-HIGH | Author workflows, matrices, result/attestation checks, release dependencies, hermetic tests, and Windows runner scripts; validate YAML and host-neutral jobs | Provision/operate self-hosted Windows runners and signing environment; execute and enforce their evidence in protected release settings |
| ROL-01 | WINDOWS/EXTERNAL | Implement LocalSandbox's non-sensitive service telemetry and evidence schema; record downstream dashboards, cohort flags, and playbooks in the SeaWork plan | Implement downstream rollout controls, operate internal/canary/GA cohorts, review live metrics, make rollout decisions, and obtain operational sign-off |
| CLN-01 | PLAN-ONLY, GATED | Record exact helper deletion, static fallback scans, replacement tests, package assertions, and migration work in the SeaWork plan; do not implement or enable deletion before ROL-01 | Future SeaWork implementation after rollout approval and clean/upgraded Windows verification |

### Recommended order for the macOS coding agent

1. Encode the resolved decisions above and complete the code-derived portion of PAR-01.
2. Implement API-01 and CAN-01 so later feature work uses the final bounded transport
   and error semantics.
3. Implement host-neutral start/retry/lifecycle and ledger work in LIF-01 and SEC-02.
4. Implement NET-01, including policy, secret, and proxy tests.
5. Implement the admin live-path, non-admin staged-sync, ledger, protocol, and
   VM-boundary portions of MNT-01.
6. Implement the fixed NET-02 WFP/app-relay architecture and the source portions of CON-01 and
   SEC-01, with Windows cross-compilation and complete handoff harnesses.
7. Add the complete SWK-01/SWK-02 downstream implementation sequence to
   `~/code/seawork/plan.md`; do not change SeaWork source in this pass.
8. Implement the LocalSandbox portions of OBS-01, REL-01, and CI-01 plus the test
   harnesses for TST-01/TST-02/WIN-01/ENT-01.
9. Produce a Windows handoff manifest listing the commit, exact commands, prerequisites,
   expected artifacts, pass/fail schema, and all remaining `Windows verification pending`
   results.
10. Prepare CLN-01, but do not enable or merge the final helper deletion until the
    Windows evidence and ROL-01 rollout approval are complete.

## Detailed backlog

### PAR-01 — Freeze the production feature-parity contract

**Priority:** P0
**Owner:** LocalSandbox and SeaWork

Create a machine-readable parity matrix covering every sandbox behavior reachable in
SeaWork commit `0ae88c6d338ffb10d765296625ea38b3b3991f64` with LocalSandbox
`0.4.6`. At minimum it must cover:

- start options and defaults: CPU, memory, disk, instance identity, base/runtime
  version selection, mounts, ports, and network configuration;
- workspace read-only mount, workspace output read-write mount, skills read-only mount,
  overlay mounts, and any additional caller-configured mounts;
- outbound host allowlists, the current default-network behavior, host-scoped secrets,
  HTTPS interception/request headers, and certificate behavior;
- guest-to-host exposure through `network.exposeHost` and host-to-guest forwarding
  through `ports`;
- `exec`, shell execution, custom shell selection, environment and working directory;
- spawned process stdout/stderr, exit ordering, backpressure, kill behavior, and any
  reachable stdin behavior;
- guest file operations, watches, paths, encodings, atomicity, maximum supported sizes,
  and error behavior;
- sandbox stop, app crash, reconnect, retry, update, and shutdown behavior;
- errors, retryability, telemetry, and user-facing repair/update actions; and
- production limits and performance expectations, including concurrent sandboxes,
  processes, streams, file sizes, output sizes, boot latency, and throughput.

The matrix must distinguish behavior that is actually reachable in production from API
surface that exists only in tests or unused libraries. Security-sensitive legacy
behavior may be replaced by a safer implementation, but the user-visible capability
must remain available.

The source audit is already decisive for two disputed areas: `ports` and
`network.exposeHost` are reachable and required, while sandbox checkpoint
creation/restore is unused and excluded. Preserve the audit paths and assertions in the
machine-readable fixture so this decision cannot silently drift.

**Definition of done**

- A versioned parity document and machine-readable fixture are committed in this
  repository; all required downstream fixture/adapter work is listed in the SeaWork
  `plan.md`.
- Golden tests execute the same representative workload against the current helper and
  the service client and compare results, filesystem effects, network effects, exit
  behavior, and stable error categories.
- Every production start field and sandbox operation is marked `equivalent`,
  `service-superset`, or linked to a blocking backlog item in this document.
- The fixed limits and timeouts in this decision record are represented by boundary
  tests; no production measurement phase is required.
- SeaWork product, LocalSandbox, Windows security, and installer owners sign off the
  matrix as the replacement acceptance contract.

### MNT-01 — Implement secure production mounts

**Priority:** P0
**Owner:** LocalSandbox

Enable the service path to provide the mount behavior SeaWork currently uses:

- the workspace root appears read-only at the expected guest path;
- the workspace output directory is read-write and guest-created output is returned to
  the caller as the caller, never as LocalSystem;
- installed agent skills appear read-only at the expected guest path;
- overlay mounts retain isolated-write semantics; and
- any supported explicit direct mount has equivalent guest path and permission
  behavior.

Complete the existing mount foundation by wiring authorized capabilities into
`lsb-platform`, SMB, and `lsb-vm` rather than passing raw caller paths. Required work
includes handle-relative traversal and `AccessCheck`, protected ProfileList/root
exclusions, held identities, staged import/export, active change monitoring, periodic
propagation, overflow behavior, conflict handling, caller-token writeback, handle-based
DACL updates, post-share identity proof, and exact account/share/ACE reconciliation.

Use two service-selected modes:

- for a caller whose authenticated token/linked token proves membership in built-in
  local Administrators, use the live current mount path and skip staging; and
- for every other caller, use the staged-sync semantics and limits fixed in the decision
  record.

The live admin path is not a raw privileged-path shortcut. It must pin the caller token,
component/final handles and identities, run access checks as that caller, prevent path
replacement for the share lifetime, journal only protected ownership facts, and clean
only exact re-queried objects. The caller never selects the mode.

**Definition of done**

- The service protocol, Rust client, Node client, and SeaWork adapter expose the mount
  semantics required by the parity contract without accepting trusted identity,
  runtime, cleanup, or policy-override fields from the caller.
- A standard user can run existing SeaWork workspace, output, skills, and overlay
  workflows with the same guest paths and observable file results as the current helper.
- Read-only mounts cannot be written from the guest; read-write output is owned by and
  writable by the authenticated caller after sandbox teardown.
- Tests prove both filtered-token admin eligibility and non-admin selection. Local fixed
  NTFS/ReFS succeeds; ACL denial, protected roots, other profiles, UNC/mapped/device/ADS
  paths, EFS/cloud/removable files, intermediate/final reparse points, rename/path-swap/
  hard-link races, deep/large trees, watcher overflow, and cancellation fail safely or
  produce the specified bounded result.
- Admin live mounts have immediate host/guest visibility. Non-admin staged input/output
  meets the small-change 1-second p95 start/propagation and 30-second final-flush
  contract. Two-sided changes create the deterministic conflict artifact/error and never
  silently overwrite either version.
- Failure injection after every user/right/ACE/share/staging step and crash/reboot tests
  prove idempotent cleanup of only externally re-queried, provably owned resources.
- No temporary service SID, SMB account SID, password, or service-owned ACL remains in
  caller-owned files after success, failure, disconnect, service crash, or reboot.
- The capability reports ready only after real-machine admin-live, non-admin-staged,
  SMB/GPO, NTFS, and ReFS acceptance; production SeaWork never receives
  `MOUNT_UNAVAILABLE` for a supported local-fixed-volume parity workload.

### NET-01 — Implement outbound networking, secrets, and HTTPS policy

**Priority:** P0
**Owner:** LocalSandbox

The service VM currently starts without the production proxy/network attachment, and
the Node service start options do not expose SeaWork's network configuration. Implement
the complete service-owned networking route for:

- the current default-network-enabled SeaWork behavior;
- explicit outbound hostname patterns;
- DNS resolution and rebinding checks;
- host-scoped secret injection;
- HTTPS interception and scoped request-header mutation where SeaWork uses it;
- LocalMachine certificate roots and an optional protected product CA bundle;
- an explicitly configured proxy without automatic WPAD or default Windows credentials;
  and
- VPN/proxy/certificate behavior required on managed SeaWork machines.

Caller host patterns must be intersected with administrator-protected product policy.
The service must not become a LocalSystem local-network, loopback, proxy-credential, or
machine-credential deputy. The default permits any globally routable public destination,
including direct IPs, and reapplies policy after DNS and at every redirect. Loopback,
local interface, link-local, carrier-grade NAT, multicast, unspecified, private,
reserved/documentation, metadata, WPAD, and other non-global destinations remain denied.
HTTPS interception is required, not a follow-up capability.

**Definition of done**

- Service protocol, Rust client, Node declarations, and SeaWork adapter support the
  parity-contract allowlists, secrets, and HTTPS configuration with explicit negotiated
  feature bits.
- Normal SeaWork web-search, package download, authenticated API, skill credential, and
  browser-auth workloads work from the guest with no helper and no UAC.
- Secrets and injected headers reach only their authorized hosts, are zeroized after
  handoff, and never appear in logs, errors, diagnostics, manifests, crash state, or
  unrelated requests.
- DNS is rechecked at connection time; rebinding to a denied address fails closed.
- Exact and `*.example.com` host scopes are IDNA-normalized; each redirect is
  reauthorized and credentials/headers are stripped outside their scope.
- Tests cover IPv4/IPv6, redirects, wildcard/IDN/case/trailing-dot handling, DNS changes,
  globally routed and denied direct IP access, explicit proxy authentication, TLS
  interception failure, CA rotation, VPN routes, WPAD,
  default credentials, and concurrent sandboxes owned by different users.
- A real Session 0 and managed-fleet run proves required DNS/proxy/VPN/certificate
  behavior.
- Production parity workloads no longer receive `NETWORK_POLICY_DENIED` merely because
  they use a currently supported SeaWork network feature.

### NET-02 — Implement safe `ports` and `network.exposeHost` parity

**Priority:** P0
**Owner:** LocalSandbox and SeaWork

Preserve both directions of current production host connectivity:

- `ports`: publish a guest TCP port on host loopback for only the owning logon; and
- `network.exposeHost`: let the guest reach an explicitly requested host loopback port
  under an authenticated, bounded, caller-authorized policy.

For `ports`, prove WFP logon-SID isolation across IPv4/IPv6, users, and two logons
of the same account using the selected WFP design. Because feature parity is required,
permanently returning `PORT_ISOLATION_UNAVAILABLE` is not a production-complete outcome.

For `network.exposeHost`, implement the selected authenticated app-owned relay: the
service tunnels only declared connections to the owning SeaWork process, which opens
the host loopback connection under its unelevated caller token. Direct unrestricted
LocalSystem connection is forbidden.

**Definition of done**

- The selected design and threat model are approved by LocalSandbox and SeaWork
  security owners.
- Existing SeaWork workloads using `ports` and `network.exposeHost` pass unchanged or
  through a documented compatible adapter.
- Exact requested host/guest TCP ports, `host.lsb.internal` behavior, connection
  failure, shutdown, and retry semantics match the parity contract; no dynamic port is
  silently substituted.
- A second user and a second logon of the same account cannot connect to another
  session's published port or exposed host relay.
- Remote interfaces, wildcard binds, UDP, unrequested ports, and protected host services
  are unreachable.
- Listeners/tunnels and WFP state are quota-bound and disappear after stop, disconnect,
  service crash, forced kill, and reboot.
- The 32/sandbox, 64/user, 128/global mapping quotas and 128 active tunneled connections
  per sandbox pass boundary and reservation-release tests.
- Adversarial IPv4/IPv6, rebinding, race, port-reuse, inherited-handle, VPN, Firewall,
  and EDR tests pass on real Windows.

### LIF-01 — Implement start, identity, and retry parity

**Priority:** P0
**Owner:** LocalSandbox and SeaWork

Map legacy start behavior to safe service-owned semantics. Caller-provided `dataDir`,
runtime paths, QEMU paths, owner identity, and cleanup manifests remain forbidden, but
their legitimate product behavior must have service-owned replacements.

Required work includes:

- documenting how legacy `instanceId` maps to opaque service resources and product
  telemetry without becoming a trusted filesystem name;
- selecting installed bundle/base versions through protected installer state rather
  than caller paths;
- rejecting an unexpected legacy `from` value with stable
  `CHECKPOINT_UNSUPPORTED` migration guidance, because the pinned SeaWork source does
  not create or use sandbox checkpoints;
- replacing SeaWork's current blind retry of resource-creating starts with a reliable
  at-most-once user experience; and
- preserving reconnect behavior and clear repair/update errors without helper fallback.

**Definition of done**

- Every legacy start field has a documented safe mapping or an approved proof that it
  is unreachable in production; no reachable behavior is silently dropped.
- Static and golden tests preserve the pinned-source proof that no production checkpoint
  workflow exists, and an unexpected `from` cannot select a path or create state.
- A lost `StartSandbox` response cannot create a second VM or leak the first VM; the app
  presents a deterministic retry/reconnect result without blindly replaying creation.
- Legacy `instanceId`, `from`, `baseVersion`, and `dataDir` values cannot select or
  overwrite service-owned paths.
- Delayed automatic startup, reboot-required state, incompatible protocol, unhealthy
  bundle, and service repair flows have equivalent or better user behavior.

### API-01 — Close Node/RPC behavioral and capacity gaps

**Priority:** P0
**Owner:** LocalSandbox and SeaWork

Use PAR-01 to close every remaining difference between the production helper adapter and
the upstream service client. Known review points include custom shell selection,
process-stream behavior, any reachable process stdin behavior, file/watch option
semantics, error mapping, start defaults, and differences introduced by service quotas.

The service's bounds may be stricter for security, but they must accommodate all agreed
production workloads and fail with stable, actionable errors rather than silently
truncating or changing behavior.

**Definition of done**

- Every operation reachable through SeaWork's current production sandbox abstraction
  has a service-backed implementation and golden parity test.
- Command string/argv handling, requested shell, cwd, environment, exit code, stdout,
  stderr, kill, cancellation, and backpressure match the parity contract.
- File operations preserve bytes, metadata semantics required by SeaWork, atomic write
  behavior, recursive options, and watch overflow semantics.
- Boundary tests enforce the fixed command, environment, file, output, stream, process,
  watch, sandbox, compute, and concurrency limits in this decision record.
- Slow consumers cannot cause unbounded memory, cross-client head-of-line blocking, or
  whole-service failure.
- Rust client/server compatibility, generated TypeScript declarations, N-API loading,
  and current/previous protocol-minor matrices pass.
- No JavaScript code implements pipe framing, authentication, security descriptors, or
  privileged cleanup.

### CAN-01 — Close synchronous filesystem cancellation ambiguity

**Priority:** P1
**Owner:** LocalSandbox

An opaque synchronous SDK filesystem operation can currently finish after its request
has been cancelled because it cannot be interrupted mid-call. Define and implement
unambiguous cancellation semantics for every mutating file operation. A physical Win32
call need not be interruptible if the protocol accurately reports that commit was
already unavoidable and no unreported partial state escapes.

**Definition of done**

- Each mutating operation has a documented cancellation/commit point and an atomic or
  journaled failure model.
- A cancellation acknowledged as `CANCELLED` cannot later publish a successful result,
  new resource handle, temporary file, or partially committed multi-step mutation.
- If cancellation arrives too late to prevent a synchronous mutation, the client gets a
  deterministic completed/too-late outcome rather than a false cancellation result.
- Connection loss, deadline, service drain, and caller-process exit use the same
  semantics and cannot leave unbounded worker threads or block global shutdown.
- Tests inject cancellation before dispatch, while queued, during the blocking call,
  immediately before commit, immediately after commit, and during cleanup for every
  mutating file RPC.
- Temporary siblings, staging data, quota reservations, streams, and handles are
  released on every terminal path.

### CON-01 — Give the service authoritative QEMU Job control

**Priority:** P0
**Owner:** LocalSandbox

The real `lsb-platform` QEMU supervisor must consume the service-owned external Job so
the SCM runtime can kill the complete process tree even when the VM command thread is
stuck. The suspended-create, Job-assignment, durable-intent, resume ordering must apply
to the production QEMU path rather than only the standalone launcher proof.

**Definition of done**

- QEMU and every helper/grandchild are created suspended, assigned to the correct
  service-owned Job, journaled, and only then resumed.
- The VM thread cannot create a second independent Job or detach QEMU from the
  service-owned containment boundary.
- Normal stop remains graceful; the 30-second STOP and 60-second preshutdown deadlines
  force-close/terminate the authoritative Job when necessary.
- Stop timeout does not detach a live VM thread or leave a child process after SCM
  reports `STOPPED`.
- Tests prove containment and cleanup on normal stop, blocked VM thread, client crash,
  service crash, SCM kill, process-tree expansion, power loss, and reboot.

### SEC-01 — Complete client-to-service mutual authentication

**Priority:** P0
**Owner:** LocalSandbox

Complete the client verification described in `plan.md`: verify the service SID mode,
publisher, image and protected ancestors, hold the image identity for the connection,
and close PID/config/image race windows before sending Hello or application data.

Also isolate development trust from production: unsigned development clients, if
retained, must use distinct service, pipe, and state names and must be compiled out of
production artifacts.

**Definition of done**

- Before Hello, the client verifies RUNNING SCM PID, own-process type, LocalSystem,
  `SERVICE_SID_TYPE_UNRESTRICTED`, exact packaged command, final executable identity,
  protected non-user-writable ancestors, and an allowlisted Authenticode publisher.
- The executable is opened without share-delete, its identity is held for the
  connection, and PID/status/config/image are revalidated around authentication.
- A same-name pipe squatter, replaced image, writable ancestor, wrong publisher,
  incorrectly configured service SID, or racing SCM update receives no client data.
- Server-side client image verification is equally race-resistant and verifies both
  the authenticated pipe token and held process/image identity.
- Production builds cannot opt into unsigned clients or development names.
- Two-user, two-logon, token/PID reuse, low-integrity, AppContainer, remote pipe,
  unsigned/wrong-publisher, and inherited-pipe-handle tests pass on real Windows.

### SEC-02 — Complete exact cleanup and recovery proof

**Priority:** P0
**Owner:** LocalSandbox

Extend the protected ledger and reconciliation path to every production resource added
for parity: VM/Job, staging trees, mount state, SMB users/rights/shares/ACEs, network
relays, WFP objects, ports, processes, streams, watches, and update state.

**Definition of done**

- Every privileged side effect has durable intent-before-effect and commit-after-proof
  ordering, plus a stable externally verifiable ownership marker where applicable.
- Startup reconciliation re-queries external identity and removes only provably owned
  resources; prefix similarity or caller-writable manifests have zero authority.
- Corrupt, excessive, conflicting, or unproven ledger state enters bounded health-only
  quarantine without deleting ambiguous resources.
- Failure injection after every lifecycle transition and repeated reconciliation prove
  idempotence.
- Client crash, app kill, service crash, forced termination, SCM STOP/preshutdown,
  update interruption, power loss, and reboot converge within documented bounds.
- Similarly named unrelated users, shares, ACEs, files, jobs, filters, ports, and
  staging trees remain untouched.
- `PrepareUninstall` returns clean only when all owned resources are reconciled; an
  ambiguous case preserves the signed cleanup authority in health-only repair mode.

### WIN-01 — Pass the real LocalSystem/Session 0 runtime gate

**Priority:** P0
**Owner:** LocalSandbox

Run the installed service and the final parity workload through SCM as LocalSystem in
Session 0 on a disposable Windows 11 x64 machine with prepared production-format assets.
An elevated console process is not equivalent evidence.

**Definition of done**

- `docs/windows-service-feasibility.md` contains signed-off evidence for LocalSystem SID,
  Session 0, WHPX availability, QEMU boot, exec, spawn, files, watches, mounts,
  networking, ports/host exposure, graceful stop, and forced stop.
- A brand-new non-administrator user boots and uses the complete parity workload after
  reboot without UAC, cached administrator credentials, `SERVICE_START`, or helper use.
- Two SeaWork processes, two users, and two logons of one account operate concurrently
  within quotas without cross-control or data leakage.
- No behavior depends on a user profile, mapped drive, interactive desktop, inherited
  CWD, PATH, or uncontrolled environment.
- Real startup, STOP, preshutdown, delayed-auto-start, checkpoint/wait-hint, Event source,
  and failure-action timing meet the SCM contract. Here `checkpoint` is the SCM
  service-start progress counter, not a sandbox checkpoint feature.
- The evidence records OS build, bundle version, QEMU version, policy, virtualization,
  runner identity, duration, and retained machine-readable results.

### REL-01 — Establish production signing and artifact trust

**Priority:** P0
**Owner:** LocalSandbox release/security

Provision and use an organization-controlled Windows signing identity for both the
service PE and full catalog. The current external inputs are
`~/code/private/SeaWork-CodeSign.pfx` and `SeaWork-SignCert.cer`; consume them only
through the environment contracts in the decision record. Test-only
untrusted/no-timestamp signing is not production evidence.

**Definition of done**

- The service PE and catalog carry trusted SHA-256 Authenticode signatures and an
  RFC 3161 timestamp from the configured endpoint.
- The exact publisher subject and SHA-256 certificate thumbprint are derived from the
  supplied certificate, emitted into generated contracts, pinned, and verified on a
  clean Windows machine.
- Catalog membership covers every required payload file and manifest; the archive
  digest and GitHub attestation cover archive structure and the catalog.
- Dependency inspection proves only Windows-system DLLs are imported and the static CRT
  requirement is met.
- Payload and symbols archives, PDB/source map, SBOM, licenses, manifest closure,
  checksums, protocol/config/ledger metadata, and deterministic pre-sign inputs pass.
- Signing secrets are protected, auditable, unavailable to pull-request jobs, and
  cleaned from runners.
- No task, log, diagnostic, artifact, or repository file reveals the PFX password or
  copies the PFX; macOS tests use unsigned deterministic inputs or an ephemeral test key.
- A documented and tested publisher-rotation/compromise procedure preserves a safe
  overlap without disabling signature checks.
- No workflow can publish an unsigned service artifact under a production name.

### SWK-01 — Implement protected install and maintenance transactions

**Priority:** P0
**Owner:** SeaWork

Implement the SeaWork-owned NSIS installer contract for archive verification, protected
extraction, immutable versions, SCM/Event configuration, protected service config,
health, update, rollback, downgrade, repair, and uninstall.

**Definition of done**

- The installer pins the exact Node package, archive digest, publisher subject, and
  certificate thumbprint and verifies all of them before extraction and after final copy.
- First install is an elevated signed NSIS transaction. Until the separately deferred
  service self-update design is approved and implemented, every update/repair/rollback/
  uninstall is also an explicit elevated signed NSIS transaction.
- ZIP handling rejects absolute/drive/UNC/parent/ADS paths, duplicates and case
  collisions, symlinks/reparse entries, nonregular entries, unlisted files, excessive
  counts, and expansion bombs.
- The final Program Files and ProgramData trees, every ancestor, service DACL, service
  SID, ImagePath, delayed automatic start, preshutdown timeout, failure actions, and
  Event source exactly match `service-contract.json`.
- Protected `service.json` is atomically installed before first start with real client
  and maintenance roots, signer allowlists, quotas, and network/mount policy.
- Update uses Prepare/stop/ImagePath/start/health/Commit ordering; interruption at every
  boundary safely aborts or rolls back without deleting state.
- Repair restores exact signed files, ACLs, config, SCM/Event state, and health without
  importing caller cleanup metadata.
- Uninstall removes only verified owned resources after a clean `PrepareUninstall`; an
  ambiguous cleanup leaves the service and protected state available for repair.
- Reboot-required, marked-for-deletion, compatible rollback, incompatible downgrade,
  and previous-version retention behavior pass automated installed-machine tests.
- `~/code/seawork/plan.md` separately records future LSB service self-update as
  deferred and non-blocking for first cutover; no self-update authority or protocol is
  invented in this implementation pass.

### SWK-02 — Replace the helper with the upstream service client

**Priority:** P0
**Owner:** SeaWork

Replace the current helper manager/server/protocol/launcher with a thin product adapter
over `connectSeaWorkService`. The adapter may translate product configuration into the
safe parity APIs, but it must not implement pipe framing, authentication, privileged
path checks, or cleanup.

**Definition of done**

- Every production sandbox workflow uses the upstream Node service client on Windows
  x64 and passes the PAR-01 golden suite.
- The application never asks SCM to start/stop/configure the service during normal use
  and never launches an elevated sandbox process.
- Missing, unhealthy, incompatible, or reboot-pending service states map to clear
  repair/update/reboot UX and telemetry without helper or direct-N-API fallback.
- Resource-creating calls are not blindly retried; reconnect creates an authorized
  empty session and preserves the documented at-most-once behavior.
- Active app shutdown closes only its own session/resources and does not stop the
  machine service or other users' sandboxes.
- Package pins, packaged-file assertions, Electron builder configuration, installer
  integration, privilege-separation documentation, and tests reference the exact
  service artifact/client pair.
- The old helper may remain only in an explicitly bounded migration build until legacy
  resources are cleaned; no production runtime path selects it once cutover is enabled.

### TST-01 — Pass multi-user and adversarial security acceptance

**Priority:** P1
**Owner:** LocalSandbox and SeaWork

Run the complete protocol, authorization, quota, and resource-isolation matrix against
an installed signed build.

**Definition of done**

- Two users, two logons of one user, and multiple app processes can concurrently use
  their own resources but cannot guess, inspect, stream, stop, mount, connect to, or
  mutate another owner's resources.
- Remote, low-integrity, AppContainer, unsigned, wrong-publisher, stale-version, and
  pipe-squatter clients fail before privileged side effects.
- Malformed, oversized, unknown, slow-loris, flood, sequence/epoch replay, queue
  saturation, output stall, cancellation, deadline, and lost-response tests remain
  bounded and do not degrade other clients or service health.
- Every quota accepts its boundary, rejects boundary-plus-one with a stable error, and
  releases reservations after success, failure, cancellation, disconnect, and panic.
- Parser fuzzing and long-duration request/handle churn demonstrate constant bounded
  bookkeeping.
- The signed installed Node application passes the complete exec/spawn/file/watch/
  mount/network/port workload as a standard user, and rejects legacy `from` with the
  documented unsupported-checkpoint result.

### TST-02 — Pass lifecycle, maintenance, and destructive-event acceptance

**Priority:** P1
**Owner:** LocalSandbox and SeaWork

Exercise the complete installed-machine lifecycle, including destructive events at every
transaction boundary.

**Definition of done**

- Clean install, reboot, delayed automatic start, standard-user use, active-user update,
  rollback, downgrade, repair, and uninstall all pass with no normal-use UAC.
- Power loss/VM snapshot restore is injected during setup, running, cleanup, pending
  update, ImagePath change, new-service health, commit, rollback, and uninstall drain.
- Requested STOP/preshutdown does not trigger failure-action restart during maintenance;
  unexpected fatal exit follows the configured recovery schedule.
- Old/current client and service minor-version combinations negotiate the highest safe
  intersection; incompatible pairs fail with actionable repair/update behavior.
- Rollback refuses an incompatible ledger schema without deleting state.
- Full uninstall preserves similarly named unrelated objects and refuses destructive
  deletion when ownership proof is incomplete.
- All results are retained as machine-readable release evidence tied to the exact signed
  artifact digest.

### OBS-01 — Complete production diagnostics and Event Log integration

**Priority:** P1
**Owner:** LocalSandbox

Compile and embed the `.mc` message table, write lifecycle/security summaries to the
Windows Application Event Log, and complete protected rotating JSON diagnostics.

**Definition of done**

- The Windows SDK `mc.exe`/`rc.exe` pipeline embeds the versioned message resource in
  every release PE, and the installer registers the matching versioned EventMessageFile.
- Startup, RUNNING, STOP, preshutdown, fatal runtime exit, bundle failure, trust failure,
  quota/resource cleanup failure, quarantine, update, rollback, and uninstall states
  have stable append-only event IDs.
- Protected JSON logs rotate at the documented bounds and contain required versions,
  correlation, hashed identity/session, opaque resource, phase, duration, stable code,
  and safe Win32 status fields.
- Logs and events never contain commands, arguments, environment, guest output, file
  content, full mount paths, passwords, tokens, secrets, or certificate private data.
- Standard users receive safe stable errors; administrators can correlate an app error
  to Event Log and protected JSON diagnostics.
- Tamper, disk-full, rotation, crash, update, rollback, and redaction tests pass.

### ENT-01 — Validate managed Windows environments

**Priority:** P1
**Owner:** SeaWork desktop/security with LocalSandbox

Validate the signed installed service on representative managed machines using real
SeaWork Defender/EDR, enterprise GPO, proxy, VPN, certificate, virtualization, nested
Job, firewall, and application-control policies.

**Definition of done**

- Defender/EDR accepts the signed LocalSystem service launching QEMU and performing the
  approved Job, mount/SMB, account/right/ACL, network relay, and WFP operations.
- Required allowlisting is product-approved, narrowly scoped, documented, deployed, and
  observable; the implementation does not evade or disable controls.
- Representative domain GPO, proxy/VPN, certificate, DNS, Windows Firewall, application
  control, and nested Job configurations pass the parity workload or produce an
  approved fail-closed product error.
- Policy incompatibilities have named owners, remediation, telemetry, and deployment
  blocks rather than silent fallback.
- Security/desktop engineering signs off evidence for the exact release candidate.

### CI-01 — Enforce production gates in CI and release automation

**Priority:** P1
**Owner:** LocalSandbox

Convert the documented external gates into enforced release dependencies. The separate
manual Session 0 workflow must not remain merely advisory when a production artifact is
published.

**Definition of done**

- Hosted Windows compile/unit/golden/fuzz/static checks run on every relevant change.
- Required disposable self-hosted Session 0, multi-user, containment, mount, network,
  port, crash/reboot, and installed-artifact suites produce attestable results for the
  exact release commit and artifact digest.
- The production release job cannot publish unless the required self-hosted evidence,
  signing verification, dependency gate, clean-machine installer suite, and protocol
  compatibility suite pass.
- Hardware/elevation tests required for production are not silently ignored or replaced
  by unit mocks in the release gate.
- The full locked workspace and Node test suites are hermetic in clean CI; the existing
  managed-QEMU download/cache-dependent test is fixed or explicitly provisioned so it
  no longer blocks a reproducible full regression run.
- Strict affected Clippy, formatting, PowerShell parsing, deterministic archive,
  malicious archive, SBOM/license, bundle verification, and declaration generation
  checks pass without undocumented exclusions.

### ROL-01 — Complete staged rollout, telemetry, and support readiness

**Priority:** P2
**Owner:** LocalSandbox and SeaWork

Roll out the service with measurable comparison against the current helper before
fleet-wide retirement.

**Definition of done**

- Internal, canary, and general-availability cohorts have explicit entry, success,
  rollback, and stop criteria and progress through internal, 5%, 25%, and 100% stages
  with at least three business days at each non-internal stage.
- Telemetry measures install/repair health, service connection, boot success/latency,
  exec/process/file/mount/network/port success, forced cleanup, quarantine, update,
  rollback, and no-UAC behavior without collecting sensitive payloads.
- Service cohort results meet or improve the signed-off helper baseline for success
  rate, latency, crash/leak rate, and user-visible functionality.
- Operations has repair, rollback, quarantine, log collection, certificate rotation,
  EDR/GPO incompatibility, and uninstall playbooks with named owners and escalation.
- The previous signed compatible service remains available until rollback criteria close.
- The automatic halt/rollback thresholds in the decision record are implemented and
  tested; telemetry is payload-free and retained for 30 days.
- No open P0/P1 defect, unresolved security exception, or undocumented functional
  regression remains.

### CLN-01 — Remove the helper and legacy privilege-separation paths

**Priority:** P2
**Owner:** LocalSandbox and SeaWork

After the service cohort satisfies ROL-01, remove production helper code and packaging so
the old architecture cannot silently return.

**Definition of done**

- `launcher.ts`, helper mode/entry/server/protocol/client, downstream path-security
  implementation, helper dispatch, UAC launch/retry, PID/nonce handshake, and helper
  shutdown code are absent from production source and packages.
- Helper-specific tests are replaced by service adapter, installer, parity, and
  maintenance tests.
- Electron packaging contains the pinned Node client and no sandbox-helper executable
  mode or obsolete privilege-separation exception.
- Upgrade migration refuses cutover while signed legacy helper processes are active,
  lets the old version clean its own resources, and reports ambiguous legacy resources
  for explicit administrator repair rather than prefix deletion.
- Static packaged-file and command-line scans fail the build if
  `--seawork-sandbox-helper`, helper IPC, direct privileged N-API startup, or an insecure
  service fallback is reintroduced.
- A clean production install and an upgraded production install both use only the SCM
  service for every Windows sandbox workflow.

## Explicit non-requirements for this replacement

The following are not required to complete this production replacement unless a future
product requirement changes the scope:

- Windows Arm64 support or a `windows-aarch64` artifact;
- changing the MVP service account away from LocalSystem after the required security
  and managed-fleet gates pass;
- splitting the service into a privileged broker and lower-privilege VM worker;
- general third-party service tenancy or plugin support;
- remote named-pipe access;
- cross-user or cross-connection sandbox transfer;
- arbitrary caller-selected runtime, QEMU, service-state, or cleanup paths;
- service self-install or automatic self-update in the first production cutover
  (future service self-update is recorded as a deferred SeaWork plan item); and
- fallback to UAC, the legacy helper, an older insecure protocol, or direct privileged
  N-API execution.

These exclusions do not waive MNT-01, NET-01, NET-02, or LIF-01. Safe equivalents for
SeaWork's current production mounts, networking, host connectivity, and reachable
lifecycle behavior are required for functional parity.
