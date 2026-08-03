# SeaWork service Sentry runbook

## Find service telemetry

Use the existing SeaWork Sentry project and start with:

- issues: `component:local-sandbox-service`
- native crashes: `component:local-sandbox-service level:fatal`
- sandbox failures: filter the component by `stable_error_code` and `release`
- QEMU hangs: filter `qemu.failure_kind:guest_ready_timeout` or
  `qemu.failure_kind:qemu_shutdown_timeout`
- traces: filter `service.name:localsandbox-seawork-service` and transaction
  `service.startup`, `service.heartbeat`, `service.update`, `sandbox.start`, or
  `sandbox.stop`
- regressions: group by `release:local-sandbox-service@<version>`

Release Health uses the service's explicit session: it begins only after the
SCM accepts `RUNNING` and ends during an orderly stop. Automatic Native SDK
session tracking is disabled. Group Release Health by `release` for adoption
and crash-free machines.

Create an **Observed active fleet** Discover widget with transaction
`service.heartbeat`, a 30-minute time window, `count_unique(user)` grouped by
`release`, and a 15-minute display interval. The transaction is always sampled
client-side and includes `user.id`, `release`, `service.version`, `run_id`,
`update.channel`, and `uptime.bucket`. Keep the **observed active** label: a
sleeping, offline, or Sentry-blocked machine is absent, so this is not exact
inventory.

Create an issue alert for new or regressed fatal crashes and error events with
`component:local-sandbox-service`, routed to the existing SeaWork notification
channel. Project owners perform that Sentry-side rollout; it is not repository
configuration.

## Correlate a crash

The native crash and the next-start `UNCLEAN_PREVIOUS_EXIT` companion event
share the prior `run_id`/correlation ID and machine context. The companion
event contains bounded `previous-run-marker.json`,
`previous-crash-context.json`, `service.tail.jsonl`, `machine.json`,
`incident.json`, and any still-present allowlisted sandbox diagnostics.
Correlation/resource IDs are event data rather than issue fingerprints.

Filter `UNCLEAN_PREVIOUS_EXIT` by `previous_exit.kind`. A value of
`returned_error`, `panic`, or `explicit_abort` includes bounded
`previous-exit.json` evidence and a controlled `previous_exit.reason` tag.
`unrecorded` means the service could not persist last-exit evidence before the
next start, which is consistent with an external termination, power loss, or
an otherwise uninstrumented abort. The issue fingerprint remains unchanged.

If Sentry transport was unavailable, inspect the protected ProgramData
`logs/service.jsonl`, its bounded rotations, and the `LocalSandboxSeaWork`
Windows Event Log source. Rejected incident snapshots are retained below
`runtime/telemetry/incidents` under the compiled age/count policy.

## Investigate a QEMU hang

The issue fingerprint has four stable parts: component, operation, broad
service code, and detailed failure kind. The observed guest-ready signature
therefore groups independently from shutdown timeouts. Start with the `qemu`
and `diagnostic` contexts, then download `incident.json` and `incident.zip`.
The ZIP contains only bounded metadata and logs; it never contains the process
dump.

On the affected Windows host, correlate the Sentry event ID with:

```text
<runtime>\telemetry\qemu-dumps\<incident-id>\
  qemu-hang.dmp
  qemu-hang-dump.json
  sentry-receipt.json
```

Verify the dump size and SHA-256 against `qemu-hang-dump.json` before opening
it. Do not copy dump bytes into tickets, chat, terminals, or Sentry. Open it
locally in WinDbg and run:

```text
.symfix
.reload
!analyze -hang
~* k
!runaway
lm
```

Use `qemu-timeline.jsonl` to confirm the ordering of QMP, Hyper-V, dump, Job
termination, process exit, and cleanup. `qemu-hang.json` distinguishes an
unresponsive QMP endpoint, a failed/partial dump, Hyper-V channel errors, and
whether serial or stderr output was observed. Disabled or empty Hyper-V
channels are evidence, not a capture failure.

The `sandbox.start` trace contains bounded child spans for instance preparation,
rootfs cloning, proxy startup, QEMU preflight/spawn/Job assignment, control and
forward channel opening, guest-ready wait, and mount initialization. The
`sandbox.stop` trace contains hang snapshot, dump, termination, process-exit,
Job-drain, instance-cleanup, and ledger-finish spans. Platform lifecycle events
drive these spans through a Sentry-independent callback; the local timeline
remains authoritative when trace sampling drops a transaction.

Mount initialization further separates snapshot walking, cache lookup and disk
configuration, SMB setup, `vm.boot`, per-mount transfer, cache
prepare/validation, sync barriers, and overlay mounting. QEMU startup spans are
children of `vm.boot`. The post-start certificate step is reported separately
as `sandbox.proxy_ca_install`.

Cleanup separates dependent process/watch stop, SMB sync, `vm.stop`, cache-disk
detach, cache finalization, SMB teardown, protected identity verification,
instance removal, and ledger completion. QEMU exit spans are children of
`vm.stop`. Automatic cleanup creates a fresh `sandbox.cleanup` root with a
`cleanup.trigger`; its terminal `cleanup.result` is `complete`, `partial`, or
`failed`. Phase failures emit `SANDBOX_LIFECYCLE_PHASE_FAILED` events and the
current phase is persisted in crash context.

Create cleanup duration p50/p95 widgets grouped by span operation, `release`,
and `cache.outcome`. Add a p95 alert just below the default stop deadline and a
separate count of `cleanup.result:partial OR cleanup.result:failed` so a faster
but incomplete cleanup does not look healthy.

## Investigate a service update

Filter traces on transaction `service.update`. The protected update journal is
the timing source because the updater stops and replaces the instrumented
service. The restarted target, or restored old service, reconstructs one trace
with `source.version`, `target.version`, `result`,
`update.transaction_id`, and any stable `failure.phase`/`failure.code`. Child
spans cover the check, release selection, download, extraction, verification,
preinstall, idle wait, activation, service stop, image-path switch, target
start/health, commit, and rollback actions that occurred.

Create update-duration p50/p95 widgets grouped by `result`, `release`, and
`target.version`, plus a count grouped by `failure.code`. Alert on
`result:rolled_back OR result:quarantined`. The transaction ID is correlation
data only; do not group issues, transaction names, or fingerprints by it.

The service writes the returned Sentry event ID into the checksummed journal
only after the SDK accepts the reconstructed transaction. Until then the
terminal journal remains current and is retried after startup or on a
heartbeat. Once reported, the helper moves it to update history. Rollback and
quarantine outcomes also emit a structured error event carrying the same trace
ID and update transaction ID.

Only the newest three completed local QEMU dump incidents are retained. A
missing `sentry-receipt.json` means local evidence was captured but no Sentry
acceptance receipt was committed. A retained incident under
`runtime/telemetry/incidents` usually means event submission or attachment
preparation failed; inspect the protected service log for the bounded failure
message.

The `qemu-hang-test-hooks` feature is exclusively for deterministic Windows
acceptance. Official production builds retain all hang telemetry but must not
contain that feature or its runtime hook names.

## Upload release symbols

Until an internal-network runner is enabled:

1. On an Apple Silicon or Intel macOS host with internal-network access,
   configure `sentry-cli` using either `~/.sentryclirc` or the
   `SENTRY_AUTH_TOKEN`, `SENTRY_URL`, `SENTRY_ORG`, and `SENTRY_PROJECT`
   process-environment variables.
2. Run:

   ```powershell
   just upload-symbols
   ```

The recipe selects the newest GitHub release by publication time, including
prereleases. It downloads the service symbols ZIP,
`lsb-seawork-service-v<VERSION>-SHA256SUMS`, and
`evidence-sentry-symbols.json`; verifies the archive against both checksum
sources; verifies the exact archive layout plus the signed PE and matching PDB
hashes; downloads and verifies the architecture-specific macOS `sentry-cli`
version pinned by `sentry-native.lock.json`; and runs
`sentry-cli debug-files check` before uploading with `--require-all` and waiting
for server processing.

The command succeeds only when every debug identifier in
`evidence-sentry-symbols.json` was found and processed. It writes the redacted
confirmation receipt to
`target/seawork-sentry-symbol-upload/<VERSION>/evidence-sentry-symbol-upload.json`.
The receipt contains the release, dist, archive SHA-256, debug IDs, CLI version,
timestamp, checks, and upload result; it never contains the auth token.

The disabled-by-default `upload-seawork-sentry-symbols` workflow job is the
runner-based alternative when `SEAWORK_SENTRY_SYMBOL_UPLOAD_ENABLED=true` and a
protected runner labeled `sentry-internal-network` is available. Its failure is
non-blocking until owners deliberately promote symbol upload to a release gate.
