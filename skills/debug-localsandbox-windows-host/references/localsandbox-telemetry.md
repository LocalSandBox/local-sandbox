# LocalSandbox telemetry interpretation

## Contents

- Producer map
- Native service fields and operations
- Correlation workflow
- Common failure interpretations
- Local fallback evidence

## Producer map

The `sea/seawork` project is shared:

- Native LocalSandbox Windows service: `sdk.name:sentry.native`, `component:local-sandbox-service`, `service.name:localsandbox-seawork-service`, releases such as `local-sandbox-service@0.7.0`.
- Electron/Node and installer components: `sdk.name:sentry.javascript.node`, application-style releases such as `1.7.1`; `service.name` may be absent.

Never infer producer from hostname, project, or message alone.

## Native service fields and operations

The Native service sets hostname as `user.id` and also stores `runtime.machine_name` in event context. Common global fields include:

- `component:local-sandbox-service`
- `service.name:localsandbox-seawork-service`
- `service.version`
- `release:local-sandbox-service@<version>`
- `run_id`
- `user.id:<HOSTNAME>`

Important transactions:

- `service.startup`
- `service.heartbeat`
- `service.update.checkpoint`
- `service.update`
- `sandbox.start`
- `sandbox.stop`
- `sandbox.cleanup`

Failure events commonly use `error.code`, `operation`, a detailed failure kind, a failure boundary, phase, correlation/resource IDs, and a stable fingerprint. High-cardinality IDs correlate occurrences; they should not define the root cause or grouping.

The service currently disables Sentry structured logs. Its operational state-transition log remains local in protected `logs/service.jsonl` and rotations. Sentry may still contain Node/Electron logs for the same hostname.

## Correlation workflow

Build a timeline in UTC and pivot in this order:

1. Exact event, issue, transaction, or trace ID supplied by the user.
2. A narrow symptom timestamp.
3. `run_id` and trace ID.
4. Update attempt/transaction ID or resource/correlation ID.
5. Hostname plus release/component as the broadest join.

Check whether a desktop/installer event preceded a service startup, update, termination, or heartbeat gap. Separate causal ordering from mere proximity.

Compare the event release and build commit with the checked-out repository. Relevant implementation areas include:

- `crates/lsb-seawork-service/src/telemetry/`
- `crates/lsb-seawork-service/src/scm.rs`
- `crates/lsb-seawork-service/src/logging.rs`
- `crates/lsb-seawork-service/src/update/`
- `crates/lsb-seawork-service/src/resource/`
- `crates/lsb-platform/src/windows_x86_64/qemu/`
- `docs/seawork-service-sentry-runbook.md`

Use `rg` for stable error codes, operations, phases, transaction names, and event messages. Follow construction and recovery paths, not only the capture call.

## Common failure interpretations

`UNCLEAN_PREVIOUS_EXIT` is emitted on the next start and describes the previous run. Its `previous_exit.kind` narrows interpretation:

- `returned_error`, `panic`, `explicit_abort`: inspect bounded previous-exit evidence and the prior run timeline.
- `unrecorded`: consistent with external termination, power loss, crash before persistence, or another uninstrumented exit; it does not identify which one occurred.

For QEMU hangs, distinguish guest-ready timeout, shutdown timeout, QMP failure, Hyper-V evidence, dump status, and whether serial/stderr activity was observed. A Sentry event can identify the incident while the process dump remains local.

For updates, pivot from the latest checkpoint to `update.attempt_id`, `update.transaction_id`, phase, outcome, retry count, failure boundary, and target/source releases. Journal timestamps are authoritative because the updater can replace and restart the service.

A heartbeat gap is evidence that telemetry was not observed, not proof that the service was stopped. Sleep, offline state, blocked transport, or sampling/retention can produce gaps.

Before requesting machine-local evidence, inspect every Sentry event attachment in the bundle. Current Native incident events can attach `service.jsonl`, Windows termination events, run/crash markers, incident JSON, incident ZIPs, and other binary artifacts. Attachments frequently contain the deciding evidence that the indexed event omits.

## Local fallback evidence

When remote evidence is insufficient, request only the relevant protected evidence:

- service log: `logs/service.jsonl` and bounded rotations
- Windows Event Log source: `LocalSandboxSeaWork`
- run marker and crash context under `runtime/telemetry`
- rejected incidents under `runtime/telemetry/incidents`
- update attempts/history and transaction journals under protected update state
- QEMU timeline and metadata for a hang incident

QEMU dumps normally remain on the affected machine. If a dump is attached to a matching Sentry event, the collector downloads it with every other attachment and the agent should inspect it with an appropriate debugger. If it was never attached, ask the user to inspect the machine-local dump with WinDbg.
