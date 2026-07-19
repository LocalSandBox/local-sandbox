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

The release workflow resolves explicit `mc.exe` and `rc.exe` paths from the installed
Windows SDK. The service build fails if either path is absent, compilation fails, or the
`.res` output is missing, then passes that resource directly to the MSVC linker. It does
not search `PATH`. Before and after signing, the release runner loads the exact PE as a
data/image resource, formats IDs 1 through 16 in `0x0409`, and rejects an unexpected ID
17. The signed-binary SHA-256 and verified IDs are published as machine-readable release
evidence. Installed Event source registration and Application Event Log inspection still
require the Windows installer/runtime gate; macOS cannot supply that evidence.
