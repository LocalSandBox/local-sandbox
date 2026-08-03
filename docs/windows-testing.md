# Windows testing on `win-1`

`scripts/win-test` is the only supported operator entry point for Windows testing. It
transfers a Git snapshot of the current source tree to the dedicated `win-1` machine,
serializes work with an exclusive host lock, preserves provisioned runtime/signing
assets and the shared Cargo cache, and retains raw run data on the Windows host.

The machine is a dedicated, mutable acceptance host, not a general workstation. The
catalog at `scripts/windows-test/catalog.json` is the source of truth for suite names,
profiles, capabilities, timeouts, mutations, expected artifacts, disk requirements,
and acceptance-check mappings. Use `scripts/win-test list` for its current contents.

## Quick start

```text
scripts/win-test setup
scripts/win-test doctor runtime
scripts/win-test accept runtime
scripts/win-test runs
scripts/win-test show <run-id>
scripts/win-test fetch <run-id> <new-local-directory>
scripts/win-test prune --dry-run
scripts/win-test prune --older-than 14d --keep 20
```

Use `runtime` for product-level WHPX behavior, `diagnostics` for telemetry and QEMU
packaging, `service` for clean-machine signed service behavior, and `release` for an
exact signed candidate and its digest-bound acceptance evidence. Native compile, unit,
and Clippy checks remain hosted-CI or focused-suite checks; they are not hardware
acceptance.

## Host ownership and setup

The runner owns exactly these roots:

- `C:\dev\local-sandbox-agent`: mirror, checkout, installed runner support, and shared
  Cargo build cache;
- `C:\dev\local-sandbox-agent-state`: locks, persistent protected assets, and run
  history.

Both roots must end with those exact directory names, carry a versioned
`.local-sandbox-agent-test-root.json` ownership marker, be outside protected product
state, and have ACLs restricted to SYSTEM, Administrators, and the setup identity.
Setup refuses to adopt a non-empty unmarked directory.

Run `scripts/win-test setup` after runner-support changes, on a new machine, or after
host repair. `scripts/win-test verify` checks Windows 11 x86-64, elevation, WHPX,
automatic OpenSSH service startup, Rust/CMake/Visual Studio tools, owned paths, Git
repositories, and root ACLs.

Provision protected assets separately:

```text
SEAWORK_WINDOWS_PFX_PATH=/path/to/test.pfx \
SEAWORK_WINDOWS_PFX_PASSWORD_FILE=/path/to/password \
  scripts/win-test provision-signing
scripts/win-test verify-signing

LSB_WINDOWS_RUNTIME_ROOT=/path/to/runtime-assets \
  scripts/win-test provision-runtime
scripts/win-test verify-runtime
```

The runtime directory must contain `Image`, `initramfs.cpio.gz`, and `rootfs.ext4`.
Provisioning uses protected staging directories and an atomic prepare/commit/abort
protocol. Signing and runtime assets persist across normal reset and pruning.

## Readiness and disk guards

Run `scripts/win-test doctor [profile]` before acceptance. It reads the catalog and
reports:

- missing profile capabilities and protected assets;
- free space versus the profile minimum;
- Windows servicing or runner continuations that still require a reboot; and
- stale services, product roots, scheduled tasks, SMB resources, local users, and QEMU
  or LocalSandbox processes.

Doctor exits unsuccessfully when a required condition is missing. The runner repeats
the catalog disk guard immediately before a large suite so a stale readiness report
cannot authorize a run after disk pressure changes.

## Reset

Service and release profiles perform a normal reset before executing. An operator can
invoke it directly:

```text
scripts/win-test reset
scripts/win-test reset --full
```

Reset takes the exclusive host lock, stops and deletes the exact SeaWork service names,
removes the LocalSandbox Event Log source and canonical product roots, and cleans only
closed test task/user/share/mapping namespaces or marker-owned client roots. It stops
leftover processes by exact executable name and verifies every target is absent before
success.

Normal reset preserves the mirror, checkout, runtime/signing assets, run history, and
shared Cargo cache. Full reset additionally prints and clears only the owned cache and
run-history targets beneath the two marked runner roots. It never follows a reparse
point or accepts a broad/custom deletion root.

## Profiles and focused suites

```text
scripts/win-test accept runtime
scripts/win-test accept diagnostics
scripts/win-test accept diagnostics --include-optional
scripts/win-test accept service [--reuse-candidate <run-id>]
scripts/win-test accept release --reuse-candidate <run-id>
scripts/win-test suite <suite-name> [--reuse-candidate <run-id>]
```

`runtime` invokes focused ignored Rust tests and small CLI fixtures for WHPX boot/stop,
exec, spawn/watch, copy, overlay and direct mounts, cleanup, forwarding, network policy,
checkpoints, standard-rootfs startup, and office-rootfs behavior. It does not restore a
monolithic smoke script.

`diagnostics` runs offline Sentry, packaged-QEMU checks, and QEMU timeout/dump
telemetry. The real-Sentry suite is optional and runs only when explicitly included and
its protected DSN is present.

`service` resets installation state, proves LocalSystem IPC, runs the exact signed
candidate from a fresh install under a standard-user token, validates reboot recovery,
uninstalls, and verifies owned resources are gone. `release` includes the service
profile, validates the exact candidate archive and artifact-bound release manifest, and
assembles full redacted evidence.

Focused `suite` runs are useful for development and reproducers. Their catalog category
remains visible in `list` and their result envelope; a `native` suite must never be
described as hardware acceptance.

## Snapshots, locking, and reboot recovery

Every run creates a temporary Git commit from tracked, untracked, and modified files
without changing the local index. The snapshot is pushed to the protected mirror and
checked out by exact SHA. Results bind to that snapshot rather than merely to local
`HEAD`.

Only one bootstrap owns the host lock. A reboot suite writes `continuation.json` with
the run, snapshot, suite, candidate, and pre-reboot boot identity before calling
Windows shutdown. The local runner waits for a new boot identity and an interactive
user, then resumes the exact run. If the wait expires, use:

```text
scripts/win-test resume <run-id>
```

Never start a replacement run while a continuation is pending. Doctor and prune expose
and protect that state.

## Results and evidence

Every suite writes the same versioned result envelope. It records the snapshot, suite
catalog metadata, phase, timestamps, stable status/failure code, boot identity,
declared requirements/mutations/artifacts, acceptance-check IDs, and runtime/release
digest bindings. Profile orchestration combines these envelopes and fails if a required
suite or mapped acceptance check is missing.

One shared evidence writer redacts fetchable JSON, verifies the declared outputs, and
always creates `fetch-manifest.json`. Raw output logs, dumps, debugger output, guest
output, user/machine identifiers, absolute paths, credentials, and certificate details
remain under the run directory on `win-1`. Only allowlisted regular files with exact
size and SHA-256 records can be fetched.

Release acceptance additionally creates the digest layout and manifest described in
`docs/windows-acceptance-evidence.md`. The final validator rehashes the exact signed
archive and checks the source SHA, artifact SHA/size, full profile, acceptance mapping,
redaction declarations, and every evidence file digest. Manually authored
`checks.redacted.json` files are not part of the profile workflow.

## Inspecting and fetching runs

```text
scripts/win-test runs
scripts/win-test show <run-id>
scripts/win-test fetch <run-id> <new-local-directory>
```

`runs` shows retained status, pins, and reboot state. `show` reads bounded result and
manifest documents. `fetch` requires a new destination, obtains the remote allowlist,
copies each file, and verifies size and SHA-256 locally. It cannot fetch raw logs or
dumps.

## Pruning

The default retention union keeps the newest 20 runs and every run newer than 14 days:

```text
scripts/win-test prune --dry-run
scripts/win-test prune --older-than 14d --keep 20
```

Prune refuses to run concurrently with a test. It never removes a pinned run, pending
reboot continuation, active marker, or candidate referenced by another run. Within an
expired run it removes reproducible large build trees before the evidence envelope.
The shared Cargo cache is considered only after its configured size limit is exceeded
or host free space falls below the configured threshold. Every target is resolved
beneath the marked runs or cache root, and the command emits a JSON summary.

## Troubleshooting

- `doctor` reports stale resources: run normal reset, then repeat doctor. A reset that
  cannot prove absence fails closed; inspect the named resource rather than deleting a
  broader parent.
- A reboot remains pending: let Windows servicing complete, sign in, and use `resume`
  for the recorded run.
- Runtime/signing/QEMU assets are missing: use the matching provision/verify command;
  do not copy secrets into a source snapshot or run directory.
- Disk pressure blocks a profile: inspect `prune --dry-run`, pin any evidence that must
  remain, then apply the bounded prune policy.
- A fetch rejects a file: inspect `show`; only files in the generated manifest and the
  closed artifact-name allowlist are exportable.
- A focused suite name or requirement is unclear: use `list`. Do not infer behavior by
  reading an individual suite as the first step; catalog validation keeps files and
  declarations synchronized.
