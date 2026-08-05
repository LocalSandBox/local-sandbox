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
inventory. The first heartbeat is emitted immediately after the service reaches
`RUNNING`; subsequent heartbeats retain the 15-minute cadence.

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

### Live rollout checkpoints

Filter Discover on transaction `service.update.checkpoint`. Every phase emits
an always-sampled `started` checkpoint and a `succeeded`, `failed`, or `skipped`
completion. Use the low-cardinality fields `update.target_version`,
`update.phase`, `update.outcome`, `update.channel`, and
`update.failure_code` for filters and groups. `user.id` is the hostname. Keep
attempt IDs, transaction IDs, archive digests, run IDs, and the deterministic
`update.event_identity` in the result columns or event context rather than
grouping on them.

Create these Discover saved queries and dashboard widgets:

| View | Filter | Columns / aggregation |
| --- | --- | --- |
| Rollout funnel | `transaction:service.update.checkpoint update.target_version:<VERSION> update.outcome:(succeeded OR failed)` | `count_unique(user.id)` grouped by `update.phase`, `update.outcome` |
| Hosts at phase | `transaction:service.update.checkpoint update.target_version:<VERSION> update.phase:<PHASE>` | `user.id`, `update.outcome`, `update.transition_utc`, ordered newest first |
| One host, last observed | `transaction:service.update.checkpoint user.id:<HOSTNAME>` | `timestamp`, `update.target_version`, `update.phase`, `update.outcome`, `update.retry_count`, `update.transition_utc`, ordered newest first with limit 1 |
| Terminal outcomes | `transaction:service.update` | count grouped by `update.result` for `committed`, `rolled_back`, and `quarantined` |
| Retry exhaustion | `event.type:error update.failure_boundary:retry_exhausted` | count grouped by `update.target_version`, `update.phase`, `error.code` |
| Phase latency | `transaction:service.update.checkpoint update.outcome:succeeded` | p50/p95 of `update.duration_ms` grouped by `update.phase`, `update.target_version` |
| Failures by code | `event.type:error operation:service.update` | count grouped by `error.code`, `update.phase`, `update.failure_boundary` |

Name fleet widgets **Observed rollout fleet**. Checkpoint receipts are durable and
replayed, but an offline host that has not uploaded its transition is absent;
the result is observed fleet state, not exact inventory.

The per-host result is explicitly **last observed**. Start from its newest
checkpoint, copy `update.attempt_id` and (when present)
`update.transaction_id`, and use those as result columns to follow the attempt.
`update.event_identity` is stable across replay and is the duplicate-detection
key. Do not interpret an old observation as the host's current state.

### Completed update trace

Filter traces on transaction `service.update`. The protected update journal is
the timing source because the updater stops and replaces the instrumented
service. The restarted target, or restored old service, reconstructs one trace
with `user.id`, `update.attempt_id`, `update.transaction_id`,
`source.version`, `target.version`, `update.target_archive_sha256`, `result`,
`update.total_duration_ms`, and any stable `failure.phase`/`failure.code`.
Child spans use their persisted start and completion timestamps and cover
discovery, release selection, download, extraction, verification, preinstall,
idle wait, activation, service stop, image-path switch, target start/health,
commit, and rollback actions that occurred.

Create update-duration p50/p95 widgets grouped by `result`, `release`, and
`target.version`, plus a count grouped by `failure.code`. Alert on
`result:rolled_back OR result:quarantined`. The transaction ID is correlation
data only; do not group issues, transaction names, or fingerprints by it.

The service writes each returned Sentry event ID into the checksummed attempt
or transaction timeline only after the SDK accepts that checkpoint, failure
event, or reconstructed transaction. Startup and every telemetry heartbeat
scan both the current files and protected attempt/transaction history. Thus a
terminal journal archived by the helper before service restart remains
replayable. Acknowledged history follows the compiled bounded retention policy;
unacknowledged entries are not pruned. Rollback and quarantine outcomes also
emit a structured error event carrying the same trace ID and update transaction
ID.

### Failure issues and alerts

Update issue fingerprints contain only component, operation, stable failure
code, detailed phase kind, and failure boundary. Hostname, version, attempt ID,
transaction ID, and trace ID remain tags or contexts and never split an issue.
Transient discovery and download failures use boundary `first_error`; the
terminal retry boundary uses `retry_exhausted`. Failed activation phases,
target-health failures, rollback actions, and quarantine are separate stable
issues. The bounded `update.timeline` context preserves the original target
failure alongside rollback evidence.

Create issue alerts for:

- `operation:service.update update.failure_boundary:first_error`
- `operation:service.update update.failure_boundary:retry_exhausted`
- `operation:service.update update.failure_boundary:rollback`
- `operation:service.update update.failure_boundary:quarantine`

Route first-error alerts at lower urgency if the retry policy is expected to
recover automatically. Retry-exhausted, rollback, and quarantine alerts are
actionable terminal boundaries.

### Local fallback and fail-open behavior

The current attempt lives under protected update state in
`updates\attempts\current.json`; completed early attempts are archived under
`updates\attempt-history`. Activation transactions use
`updates\transactions\current.json` and `updates\history`. These checksummed
documents are authoritative for replay, phase timestamps, receipts, and the
last-known snapshot when Sentry is unavailable.

Sentry initialization, submission, replay, receipt persistence, and local
diagnostic failures are telemetry-only. They do not change retry scheduling,
health evaluation, commit, rollback, quarantine, or process exit status. If
both Sentry and diagnostic storage are unavailable, investigate the protected
Windows Event Log/update status evidence; absence of a receipt means only that
delivery was not acknowledged, not that the update action failed.

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
