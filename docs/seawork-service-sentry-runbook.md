# SeaWork service Sentry runbook

## Find service telemetry

Use the existing SeaWork Sentry project and start with:

- issues: `component:local-sandbox-service`
- native crashes: `component:local-sandbox-service level:fatal`
- sandbox failures: filter the component by `stable_error_code` and `release`
- QEMU hangs: filter `qemu.failure_kind:guest_ready_timeout` or
  `qemu.failure_kind:qemu_shutdown_timeout`
- traces: filter `service.name:localsandbox-seawork-service` and transaction
  `service.startup`, `sandbox.start`, or `sandbox.stop`
- regressions: group by `release:local-sandbox-service@<version>`

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
