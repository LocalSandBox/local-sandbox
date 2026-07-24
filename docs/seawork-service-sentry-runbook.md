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

## Manually upload release symbols

Until an internal-network runner is enabled:

1. Download the release's symbols ZIP,
   `lsb-seawork-service-v<VERSION>-SHA256SUMS`, and
   `evidence-sentry-symbols.json`.
2. Verify the symbols ZIP SHA-256 against both files.
3. Use the `sentry-cli` version and checksum pinned in
   `sentry-native.lock.json`; run `sentry-cli debug-files check` on the
   extracted exact signed PE/PDB pair.
4. With internal-network access and `SENTRY_AUTH_TOKEN` supplied only in the
   process environment, run:

   ```powershell
   sentry-cli debug-files upload --include-sources `
     --url $env:SENTRY_URL --org $env:SENTRY_ORG `
     --project $env:SENTRY_PROJECT <extracted-symbols-directory>
   ```

5. Confirm the uploaded debug identifier equals every ID in
   `evidence-sentry-symbols.json`. Save a redacted receipt containing release,
   dist, archive SHA-256, debug IDs, CLI version, timestamp, and upload result;
   never include the auth token.

The disabled-by-default `upload-seawork-sentry-symbols` workflow job performs
the same checks when `SEAWORK_SENTRY_SYMBOL_UPLOAD_ENABLED=true` and a protected
runner labeled `sentry-internal-network` is available. Its failure is
non-blocking until owners deliberately promote symbol upload to a release gate.
