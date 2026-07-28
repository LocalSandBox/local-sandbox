# Service diagnostics contract

The service writes the same typed event identifier to two administrator-facing sinks:
the Windows Application Event Log source `LocalSandboxSeaWork` and protected JSON Lines
files under the fixed service `logs` directory. Event identifiers are append-only. The
message catalog and Rust catalog must remain in exact numeric order; host-neutral tests
reject drift.

## Bounded JSON records

`service.jsonl` and nine rotated files are each limited to 10 MiB. A process-wide writer
lock serializes size checks, rotation, and appends. Rotation deletes only the oldest
regular log, shifts regular generations, and refuses symlinks or non-file entries. Each
record is at most 8 KiB and contains schema, event/severity, timestamp, service and
bundle version, negotiated protocol version, ledger schema, phase, and stable code.
Optional context is limited to a 128-bit lowercase-hex correlation ID, a 256-bit
lowercase-hex identity hash, a paired safe resource type and opaque 128-bit resource ID,
duration, and a numeric Win32 code.

Phase, resource type, stable code, and opaque identifiers use closed character sets.
The API cannot accept arbitrary diagnostic text, paths, commands, arguments,
environment, output, content, credentials, tokens, certificate material, or cleanup
secrets. Disk or Event Log failures return an error; callers must not silently reinterpret
them as a successful diagnostic write.

## Event catalog

| ID | Symbol | Intended summary |
| ---: | --- | --- |
| 1 | `LSBSW_SERVICE_STARTED` | Service reached RUNNING |
| 2 | `LSBSW_SERVICE_STOPPED` | Service completed requested stop |
| 3 | `LSBSW_LEDGER_QUARANTINED` | Protected state requires repair |
| 4 | `LSBSW_SERVICE_START_PENDING` | SCM startup began |
| 5 | `LSBSW_SERVICE_STOP_PENDING` | STOP or preshutdown drain began |
| 6 | `LSBSW_SERVICE_FATAL_EXIT` | Runtime invariant failed |
| 7 | `LSBSW_BUNDLE_VERIFICATION_FAILED` | Installed bundle was rejected |
| 8 | `LSBSW_CLIENT_TRUST_FAILED` | Client authentication failed |
| 9 | `LSBSW_QUOTA_REJECTED` | Admission hit a bounded quota |
| 10 | `LSBSW_RESOURCE_CLEANUP_FAILED` | Durable cleanup remains |
| 11 | `LSBSW_UPDATE_STATE` | Update state changed |
| 12 | `LSBSW_ROLLBACK_STATE` | Rollback state changed |
| 13 | `LSBSW_UNINSTALL_STATE` | Uninstall state changed |
| 14 | `LSBSW_RUNTIME_CAPABILITY_UNAVAILABLE` | Required runtime capability is unavailable |
| 15 | `LSBSW_BUNDLE_VERIFIED` | Installed bundle was verified |
| 16 | `LSBSW_SESSIONS_DRAINED` | Active sessions were drained |
| 17 | `LSBSW_CONNECTION_FAILED` | Pipe connection was rejected or lost |
| 18 | `LSBSW_DIAGNOSTIC_CAPTURE_FAILED` | Bounded diagnostic capture was incomplete |

The release workflow resolves explicit `mc.exe` and `rc.exe` paths from the installed
Windows SDK. The service build fails if either path is absent, compilation fails, or the
`.res` output is missing, then passes that resource directly to the MSVC linker. It does
not search `PATH`. Before and after signing, the release runner loads the exact PE as a
data/image resource, formats IDs 1 through 18 in `0x0409`, and rejects any unexpected
message ID. The signed-binary SHA-256 and verified IDs are published as machine-readable release
evidence. Installed Event source registration and Application Event Log inspection still
require the Windows installer/runtime gate; macOS cannot supply that evidence.

## Live QEMU timeout diagnostics

Official Windows builds always capture a bounded live snapshot when QEMU is
still running at a guest-ready or QEMU-shutdown timeout. This is production
behavior, not a runtime option. Before the authoritative Job is terminated, the
platform records:

- native process CPU, memory, handle, thread, and I/O samples in
  `qemu-progress.jsonl`;
- the stable phase sequence in `qemu-timeline.jsonl`;
- four bounded, redacted queries over a private per-instance QMP pipe;
- bounded evidence from the Hyper-V Hypervisor Operational/Admin and VID Admin
  channels;
- the read-only authoritative Job snapshot; and
- one diagnostic minidump through the signed
  `localsandbox-qemu-dump-helper.exe`.

The dump helper has a parent-enforced 30-second deadline. Its reviewed flags
capture stacks, handles, unloaded modules, process/thread data, full memory-map
metadata, and indirectly referenced memory; they do not capture full process
memory. Diagnostic failure is fail-open for telemetry but never for lifecycle:
QEMU is eventually terminated even when QMP, Event Log, or dump collection
fails.

The local dump is retained below
`runtime/telemetry/qemu-dumps/<incident-id>/qemu-hang.dmp`. Only the newest
three completed incident directories remain. The sibling
`qemu-hang-dump.json` records the exact flags, size, SHA-256, timestamps,
Win32 outcome, correlation fields, and retention result. After Sentry accepts
the event, `sentry-receipt.json` records the event ID and redacted project
identity. Neither file weakens the inherited protected ACL.

Sentry receives exactly two manual incident attachments:
`incident.json` first and `incident.zip` second. The ZIP is built from a closed
15-name allowlist and deliberately excludes every `.dmp`. Missing files remain
represented in the manifest. Attachment, snapshot, archive, QMP, Hyper-V,
process-snapshot, dump, nil-event-UUID, and flush failures increment bounded
in-process telemetry counters and emit a reviewed local error without exposing
protected paths or command lines. The incident manifest, live artifacts, dump
manifest, boot status, preflight report, progress records, and timeline records
carry the same incident, correlation, and resource IDs. App-visible service
errors surface the correlation ID, and sandbox stop errors also surface the
resource ID for downstream support lookup.

The service-side stop watchdog allows 45 seconds so a dump still inside its
30-second deadline plus the termination margin is treated as progress.
Downstream callers must use a deadline of at least 45 seconds and preserve the
service correlation/resource IDs in `LOCAL_SANDBOX_STOP_TIMEOUT` and quarantine
events.

The focused `qemu-telemetry-smoke` Windows suite preserves digest-bound
evidence for a no-WHPX diagnostic child dump, normal WHPX boot, four forced
guest-ready timeouts, a forced platform shutdown timeout, and a service-owned
shutdown timeout. It verifies QMP responses, scheduled/final process samples,
three-entry dump retention, helper timeout, the authoritative service Job
reaching active-process-zero, bounded Hyper-V queries, the two-file incident
package, production hook exclusion, secret/private-pipe redaction, and WinDbg
execution of `!analyze -hang`, `~* k`, `!runaway`, and `lm`.
