# SeaWork Windows service test-release sprint

This is the active implementation plan. It replaces the broad production plan archived
under `docs/archive/pre-test-release-sprint-2026-07-21/` and deliberately narrows the
work to the shortest credible path to an internal SeaWork test release.

The coding agent works only in this `local-sandbox` repository. SeaWork source is
read-only. Every downstream change must be specified in the append-only
`docs/seawork-test-release-handoff.md`.

When compatibility evidence or downstream context is needed, the local agent may inspect
the SeaWork source read-only at `~/code/seawork/` on the macOS development machine or
`C:/Users/Public/code/seawork` on the Windows test machine. Do not modify either checkout;
record required SeaWork changes in the handoff document instead.

## 1. Outcome and completion boundary

The sprint must produce a production-profile Windows service release candidate that:

- uses the production identities `LocalSandboxSeaWork`,
  `\\.\pipe\LocalSandbox.SeaWork.v1`, and
  `%ProgramData%\LocalSandbox\SeaWork`;
- is signed with the SeaWork certificate trusted by company laptops;
- installs and runs as `LocalSystem`, then serves an ordinary standard-user client
  without UAC;
- implements the subset of the Node API used by normal SeaWork tool effects;
- supports SeaWork's workspace, output, skills, and uploaded-file directories through
  the temporary direct-SMB compatibility path;
- supports public outbound HTTPS and one scoped-secret happy path;
- survives a reboot and cleans up normally stopped sandboxes; and
- is accompanied by a pinned Node client artifact, machine-readable Windows evidence,
  and an executable SeaWork handoff.

There are two distinct completion states:

1. **LocalSandbox release candidate complete** means every in-repository gate in this
   plan has passed and the final handoff entry contains exact artifacts and evidence.
2. **SeaWork test release ready** additionally requires SeaWork's proper NSIS installer
   and app adapter to consume those artifacts and pass the downstream matrix. NSIS is a
   mandatory critical-path gate, but its implementation remains SeaWork-owned. The
   local-only agent must never claim the overall test release is ready merely because
   the LocalSandbox candidate is complete.

## 2. Fixed sprint decisions

These are user decisions and are not open for redesign during this sprint:

- Development happens on macOS. Native validation uses the company Windows 11 x64
  laptop and `docs/windows-agent-testing.md`.
- The service and client are built with the production service profile. Do not enable
  the `development-service` Cargo feature and do not package with
  `--service-profile development`.
- A proper per-machine NSIS installer is mandatory. It remains implemented and owned in
  SeaWork; this repository supplies the service artifacts, generated contract, tests,
  and detailed handoff.
- Temporary directory-mount compatibility is acceptable. Wire the service to the
  existing Windows direct-SMB implementation; do not finish the hardened staged-mount
  controller for this release.
- The existing helper remains available. Test builds are service-only. Live builds try
  the service first and may fall back to the helper, with UAC, only if service
  acquisition fails before a sandbox is returned.
- If the service path succeeds, ordinary app use must never request UAC.
- Ports, `network.exposeHost`, checkpoints, overlay mounts, hostile-user hardening, and
  exhaustive crash recovery are not test-release requirements.
- Normal SeaWork execution is one sandbox per tool effect and currently has local
  executor concurrency one. Optimize correctness of sequential happy paths before
  multi-user or high-concurrency behavior.

The signing inputs are external and must never enter Git, a synthetic test snapshot, a
log, or an artifact:

```text
macOS:   ~/code/private/
Windows: C:/Users/Public/code/private/
```

The required files in those directories are `SeaWork-CodeSign.pfx` and
`win_csc_key_password.txt`.

Pass their locations through `SEAWORK_WINDOWS_PFX_PATH` and
`SEAWORK_WINDOWS_PFX_PASSWORD_FILE`. Never print or inspect the password. Derive the
publisher subject and SHA-256 certificate thumbprint on Windows from the PFX, record
only those public values, and use the normal trusted/timestamped signing path. Do not
pass `-AllowUntrustedTestCertificate` or `-SkipTimestamp` for the release candidate.

## 3. Required behavior

### Service and Node operations

The release candidate must support exactly the operations exercised by SeaWork's normal
tool runtime:

- connect, service info, and health;
- start and stop;
- unary exec with argv/string, cwd, env, stdout, stderr, and exit code;
- spawn with independent stdout/stderr, ordered exit, and kill;
- read file, write file, and recursive mkdir; and
- cancellation/cleanup sufficient for a cancelled normal tool effect.

Keep the existing extended service filesystem/watch API if it already works, but do not
spend sprint time expanding it. Preserve the legacy direct `Sandbox` Node API so the
SeaWork live-build fallback can keep using the current helper.

`instanceId` is only the at-most-once start key. Reject non-empty `from` with
`CHECKPOINT_UNSUPPORTED`. Keep `ports` and `network.exposeHost` fail-closed with
`PORT_ISOLATION_UNAVAILABLE`.

### Temporary mount contract

Only legacy `direct` mounts with flags `0` (read-write) or `1` (`MS_RDONLY`) are in
scope. The service maps them to the existing `lsb_vm::MountConfig::Direct` Windows SMB
path and reports backend `compat-smb-direct`.

The required SeaWork layout is:

| Host source | Guest path | Access |
| --- | --- | --- |
| selected/generated workspace | `/workspace` | read-only |
| workspace `output` child | `/workspace/output` | read-write |
| active agent skills directory | caller-declared skills path | read-only |
| uploaded-files directory, when present | `/uploaded_files` | read-only |

Nested `/workspace/output` must remain writable while the containing workspace is
read-only. Writes must be visible to the invoking standard user after normal stop.
Normal stop must remove the temporary SMB share, temporary account, temporary rights,
and compatibility cleanup manifest. The hardened pinned/staged controller, conflict
retention, periodic sync, and crash reconciliation remain deferred.

Overlay mounts are not silently reinterpreted. The Node service API rejects them with a
stable unsupported-capability error. A live SeaWork build may then choose its helper
fallback before a service sandbox exists; a test build reports the service error.

### Network contract

An empty caller and protected allowlist permits otherwise-safe public destinations.
The candidate must demonstrate:

- DNS plus public HTTP/HTTPS from the guest;
- one realistic package or metadata download;
- one scoped secret substituted for an allowed HTTPS host without appearing in logs or
  result metadata; and
- denial of a private/link-local target.

Corporate proxy, VPN, custom CA, exhaustive redirects, and every authentication provider
are follow-ups unless the company test laptop's normal network requires a concrete fix.

### Test-build and live-build routing contract

This routing is implemented downstream but must be reflected in LocalSandbox API/tests
and the handoff:

- **Test build:** service-only. Missing service, failed trust, unhealthy service,
  unsupported required capability, or failed service start is a visible failure. The
  helper is never launched.
- **Live build:** attempt connect, health/capability validation, and start through the
  service. If that acquisition fails before a sandbox handle is returned, close the
  service session and use the existing helper for that effect. The helper may request
  UAC.
- Never replay a command or filesystem mutation on the helper after a service sandbox
  was returned. Mid-effect failure is reported normally; automatic cross-backend replay
  could duplicate side effects.
- Use the effect ID as the stable `instanceId` for bounded same-session start recovery.
- Service success must bypass helper runtime initialization as well as helper sandbox
  start; otherwise the current eager readiness path could still cause UAC.

## 4. Explicitly deferred work

Do not pull these items onto the sprint critical path unless a required happy-path test
proves one is an actual blocker:

- secure staged/admin-live mount selection, monitors, conflicts, retained export,
  periodic writeback, crash recovery, and mount performance tuning;
- overlay and arbitrary mount semantics outside the four required direct profiles;
- host-to-guest ports, `network.exposeHost`, WFP isolation, and app-owned relays;
- checkpoints and adoptable/persistent sandboxes;
- malicious-client, low-integrity, AppContainer, pipe-squatter, and adversarial path
  matrices beyond the signature/identity checks already required for normal operation;
- power-loss cleanup, full multi-user saturation, fleet telemetry, staged rollout, and
  helper removal;
- complete Event Log polish, enterprise GPO/EDR/VPN coverage, production CI publishing,
  GitHub attestations, and public release operations; and
- self-update. SeaWork's elevated NSIS flow owns install, update, repair, rollback, and
  uninstall for this test release.

The archived backlog remains the source for these follow-ups. Deferral does not mean
completion.

## 5. Current baseline and known gaps

Planning was reset at LocalSandbox commit
`12d0d4e496ea276b08d03a7fdcaa51574ccb3f8b` on branch
`feat/lsb-win-service`. Recheck HEAD and worktree before every milestone because another
agent may have advanced the branch.

Already present:

- production SCM/pipe identities and a real `LocalSystem` service host;
- framed protocol, Rust client, Node `connectSeaWorkService`, health, lifecycle, bounded
  process/file APIs, cancellation, quotas, and mutual endpoint checks;
- protected bundle/config/ledger foundations and service-owned QEMU containment;
- public-egress, scoped-secret, and HTTPS proxy implementation;
- deterministic service bundle, PE/catalog signing, checksums, SBOM/licenses, and
  release workflow foundations;
- production/development profile separation; and
- the macOS-to-Windows SSH snapshot/test runner.

Known critical gaps at reset:

- `SeaWorkStartOptions` does not expose mounts;
- the service rejects every non-empty mount list and advertises mounts unavailable;
- `ManagedVmSpec`/`build_and_start` do not pass mounts into `lsb-vm` or enable the SMB
  proxy relay;
- the production-profile service has not completed a real signed installed
  boot/exec/stop run on the Windows laptop;
- there is no focused Windows test-release build/install/acceptance suite or safe
  signing-asset provisioning/fetch flow;
- no exact test-release service/Node artifact tuple has been produced; and
- SeaWork has not implemented the service adapter or NSIS service transaction.

## 6. Execution rules

- Work milestone by milestone in the order below. Do not begin final packaging before
  the required source and Windows runtime gates pass.
- At the start of each milestone, inspect `git status`, recent commits, and overlapping
  work. Preserve unrelated user/agent changes.
- Add focused tests with each source change. A test that only mocks away the changed
  Windows boundary is insufficient for the final gate.
- Use `scripts/win-test`; do not push test snapshots to `origin`. Keep secrets out of
  the snapshot and under the protected Windows test asset root.
- A Windows failure is work to diagnose and fix, not permission to weaken production
  service identity, signature checks, bundle verification, or test-build service-only
  routing.
- Update the intentionally small `state.md` after each milestone or genuine blocker.
  Put detailed downstream facts in the append-only handoff, not in `state.md`.
- Commit coherent implementation tranches. Record the commit and Windows run ID in the
  handoff. Do not rewrite earlier handoff entries.

Before final packaging, choose the next unused prerelease SemVer (normally
`0.4.7-test.1` if no newer version exists), propagate it consistently through the
service crates and Node packages, and record it in `state.md`. Do not publish to npm or
create a public GitHub release during this sprint.

## 7. Critical path

### TR-0 — Freeze the test-release contract

- [x] Recheck LocalSandbox HEAD/worktree and the read-only SeaWork HEAD. Append any
  baseline drift to `docs/seawork-test-release-handoff.md`.
- [x] Add `contracts/seawork-test-release-v1.json` rather than weakening the existing
  production parity contract. Encode the required operation, mount, network, identity,
  packaging, and evidence subset from sections 1–3.
- [x] Update the parity verifier/fixtures as needed so the test contract checks the
  current SeaWork source paths and proves that normal effects require the four direct
  mount profiles while no normal producer currently populates ports, `exposeHost`, or
  checkpoints.
- [x] Keep `workspace-shell`, `skills-files`, and `network-public-auth` as required
  golden workloads. Mark `host-connectivity`, overlay, and exhaustive lost-start/crash
  recovery out of test scope without changing their production status.
- [x] Add a short test-release scope note to `docs/seawork-service-release.md` and
  `docs/seawork-parity-contract.md` pointing to the new contract and this plan. Preserve
  those documents' hardened final-release requirements instead of rewriting history.
- [x] Record the exact candidate SemVer and baseline commits in `state.md`.

Gate: the test contract validates against the inspected SeaWork checkout and has no
unresolved in-scope feature marked unavailable.

### TR-1 — Implement the direct-mount compatibility bridge

- [x] Add mounts to the Node service start shape and generated declarations. Accept
  legacy mount objects, but map only `type: "direct"` with integer flags `0` or `1` to
  `ServiceMountSpec { host_path, guest_path, read_only }`.
- [x] Return stable errors for overlay, invalid flags, empty paths, non-directory
  sources, duplicate guest paths, and unsupported counts. Do not silently drop mounts.
- [x] Remove the blanket service rejection for supported mounts. Carry the normalized
  list through start admission, `ManagedVmSpec`, VM startup, and the start response.
- [x] Construct `lsb_vm::MountConfig::Direct` entries and enable
  `ProxyConfig::with_smb_mount_relay()` when public networking is present or
  `ProxyConfig::mount_only_smb()` when mounts are the only network need.
- [x] Advertise `directMount: true` and backend `compat-smb-direct` only when the build
  can actually execute this path. Keep ports false.
- [x] Ensure partial start and normal stop invoke the existing SMB lifecycle cleanup.
  Do not connect this compatibility path to the unfinished staged-mount controller.
- [x] Add protocol/client/Node/service/VM tests for mapping, capability reporting,
  combined proxy+SMB mode, nested workspace/output selection, rejection cases, partial
  failure cleanup, and selected-mount responses.

Gate on macOS: formatting, focused Rust tests, Node API-shape/type tests, and strict
scoped Clippy pass. Gate on Windows: a production-profile direct-mount VM reads a
read-only input, writes nested output, and leaves no compatibility resource after stop.

### TR-2 — Build a safe native Windows release harness

- [x] Extend the Windows-agent flow with explicit signing-asset provisioning into
  `C:\ProgramData\LocalSandbox\DevTest\assets\signing`. Transfer directly over SSH;
  never add the files to the Git snapshot. Refuse unsafe roots, reparse points, loose
  ACLs, missing files, or an existing unowned destination.
- [x] Make provisioning and verification print only certificate subject/thumbprint,
  file presence, and ACL status. Never print the password, PFX bytes, command-line
  password, or process environment.
- [ ] Add focused suites for fast service tests, signed release-candidate construction,
  installed production-identity smoke, and reboot continuation. Every suite writes
  bounded machine-readable results under the existing run root.
- [x] Add a safe artifact-fetch command that retrieves only an allowlisted run manifest,
  checksums, signed service ZIP/symbols, Node package artifacts, and redacted evidence.
  It must never fetch the protected signing asset directory.
- [ ] The install smoke harness is test infrastructure, not a replacement installer.
  It may perform the exact generated SCM/config transaction on the dedicated laptop,
  but must refuse to touch an existing `LocalSandboxSeaWork` service or install root it
  cannot prove it owns, and must clean only its marked test resources.
- [ ] Exercise the actual Node binding through a protected, same-publisher-signed Windows
  Node executable under an allowlisted `Program Files\SeaWork` test-harness root. This
  proves both service-side client admission and client-side service verification.

Gate: from macOS, one command can build, sign, install, health-check, exercise, and
uninstall the production-identity service on the Windows laptop without exposing signing
secrets or relying on a SeaWork source change.

### TR-3 — Close real Windows happy-path defects

- [ ] Run a mount-free signed production-profile install/health/start/exec/stop smoke
  first. Fix only concrete blockers in bundle verification, SCM startup, WHPX/Session 0,
  client admission, QEMU containment, or normal cleanup.
- [ ] Run the required four-mount layout as a standard user. Prove workspace, skills,
  and uploads are read-only; nested output is writable and visible on the host; and no
  UAC prompt/process occurs after the elevated install transaction.
- [ ] Run exec, spawn/stream/exit, kill, readFile, writeFile, mkdir, cancellation, stop,
  and ten sequential effect-shaped sandbox lifecycles.
- [ ] Run public DNS/HTTP/HTTPS, one package/metadata download, the scoped-secret probe,
  and private/link-local denial. Inspect redacted logs for absence of the test secret.
- [ ] Reboot once with the service installed. Require delayed automatic service start,
  health, one post-reboot sandbox, normal stop, and owned-resource cleanup.
- [ ] For each failure, add the smallest regression test or harness assertion that would
  have caught it before applying the fix.

Gate: the Windows run manifest reports every required happy-path case passed against one
exact commit and signed artifact hash. No test uses the development identity, unsigned
trust bypass, helper, or elevated normal client.

### TR-4 — Produce the pinned LocalSandbox release candidate

- [x] Select and propagate the recorded prerelease version through Rust crates, Node
  packages, manifests, generated declarations, and artifact names.
- [ ] Build the production-profile service with static CRT and Event Log resources.
  Sign and timestamp the PE and catalog using the external PFX through the existing
  normal signing script.
- [ ] Produce and verify the closed service ZIP, symbols ZIP, `SHA256SUMS`, bundle
  manifest, service contract, dependencies, SBOM/licenses, and installed-layout check.
- [ ] Build the Windows x64 Node binding with `SEAWORK_PUBLISHER_SHA256` set to the
  derived signer thumbprint. Produce installable main/platform package artifacts and run
  the API-shape/type/package tests. Preserve the direct `Sandbox` API.
- [ ] Emit one `seawork-test-release-manifest.json` pinning LocalSandbox commit, version,
  protocol range, service ZIP hash, Node package names/hashes, publisher subject and
  SHA-256 thumbprint, production service/pipe/state identities, required capabilities,
  and Windows evidence run IDs.
- [ ] Re-run signature/catalog/bundle verification against the exact fetched artifacts,
  not merely the staging directory.

Gate: all artifacts in the manifest exist, hashes and identities agree, the company
Windows laptop trusts the signature without test flags, and the artifact tuple is ready
for SeaWork to embed without rebuilding LocalSandbox source.

### TR-5 — Finalize the SeaWork handoff

- [ ] Append the final LocalSandbox commit, version, artifact locations/hashes,
  publisher values, protocol/capabilities, generated contract location, Windows run IDs,
  install/uninstall behavior, and known deferrals to the handoff document.
- [ ] Confirm the handoff specifies the existing SeaWork NSIS files to change, exact
  protected install/config/SCM transaction, service-only test routing, service-preferred
  live routing, lazy helper fallback, adapter method mapping, package pinning, signing,
  upgrade/uninstall behavior, diagnostics, and downstream acceptance tests.
- [ ] Reinspect current read-only SeaWork source and append any path/API drift. Do not
  modify SeaWork to make the handoff appear complete.
- [ ] Run the final macOS verification set and the exact Windows artifact acceptance set.
- [ ] Mark `LocalSandbox candidate` complete in `state.md` only after all TR-0 through
  TR-5 gates pass. Leave `Overall test release` blocked until downstream NSIS/adapter
  evidence is appended by the SeaWork owner.

Gate: a SeaWork coding agent can implement the downstream work from the handoff without
choosing a new architecture or guessing an upstream API, artifact, identity, or test.

### TR-6 — Implement and verify SeaWork NSIS/adapter integration (external, mandatory)

Ownership: SeaWork. This remains on the critical path even though the local-only agent
is not authorized to implement or check it off. The LocalSandbox agent finishes every
preceding gate and leaves this milestone explicitly open for the downstream owner.

- [ ] Embed and pin the exact signed service and Node artifact tuple.
- [ ] Extend the existing per-machine NSIS installer to install/configure/start, update,
  repair, roll back, and uninstall the production-identity service.
- [ ] Implement the service-backed sandbox adapter and lazy readiness routing.
- [ ] Make test builds service-only and live builds service-preferred with
  acquisition-only helper fallback.
- [ ] Prove no UAC during successful service-backed standard-user use.
- [ ] Pass the downstream fresh-install, reboot, happy-path, fallback, update, repair,
  and uninstall matrix and append exact evidence to the handoff.

Gate: only the SeaWork owner may mark the overall test release ready, after every TR-6
item passes against the exact LocalSandbox candidate.

## 8. Verification commands

Keep this list current as suites are added. The final agent should run the applicable
superset, not only these examples.

macOS host-neutral gates:

```bash
cargo fmt --all -- --check
cargo test -p lsb-service-proto --locked
cargo test -p lsb-service-client --locked
cargo test -p lsb-seawork-service --locked -- --test-threads=1
cargo test -p lsb-proxy --locked
cargo clippy -p lsb-service-proto -p lsb-service-client -p lsb-seawork-service --locked --no-deps -- -D warnings
cargo run -p xtask --locked -- verify-seawork-parity --contract contracts/seawork-test-release-v1.json --seawork-repo /Users/SG3937/code/seawork
```

Node gates from `bindings/nodejs`:

```bash
corepack yarn install --immutable
corepack yarn napi build --platform
corepack yarn patch-loader
corepack yarn ava test/api-shape.spec.ts test/package-metadata.spec.ts test/startup.spec.ts
corepack yarn tsc --noEmit --project test/tsconfig.json
```

Windows-agent gates, after the milestone adds the named suites:

```bash
scripts/win-test preflight
scripts/win-test suite service-fast
scripts/win-test suite service-test-release-build
scripts/win-test suite service-test-release
scripts/win-test reboot service-test-release-reboot
```

Record every final run ID and synthetic snapshot SHA. A passing ad hoc command without
the result manifest is diagnostic evidence, not a completed gate.

## 9. Local-only stopping rule

After TR-0 through TR-5, the LocalSandbox candidate may be complete, but the overall
test release remains blocked on TR-6. That is a release blocker, not work the local-only
agent is authorized to perform.
