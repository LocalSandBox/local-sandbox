# SeaWork service Sentry runbook

## Find service telemetry

Use the existing SeaWork Sentry project and start with:

- issues: `component:local-sandbox-service`
- native crashes: `component:local-sandbox-service level:fatal`
- sandbox failures: filter the component by `stable_error_code` and `release`
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
