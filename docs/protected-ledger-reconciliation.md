# Protected ledger reconciliation envelope

Status: SEC-02 host-neutral persistence and admission envelope implemented; external
Windows ownership re-query and cleanup executors pending.

## Startup admission rules

The protected ledger directory is a closed set. Startup enumerates at most 1,024
entries without first collecting an unbounded directory, and every entry must be a
regular file named as exactly 32 lowercase hexadecimal sandbox-ID characters plus
`.json`. Unknown files, directories, symbolic links, malformed JSON, invalid schemas,
oversized documents, and interrupted atomic temporaries are never ignored. They are
moved without reading their contents into a bounded protected quarantine namespace and
close normal admissions.

If enumeration exceeds the bound, quarantine storage is exhausted, or an entry cannot
be moved, the service records unproven state and remains health-only. It does not delete
or interpret the ambiguous object. Document reads are independently capped at 256 KiB,
the accepted set is capped at 64 MiB total, and a file that grows during the bounded read
is rejected.

Valid documents require:

- the current ledger schema, bounded strings/resources, a monotonic timestamp pair, and
  an OS-derived owner shape;
- a unique random ownership ID across the entire accepted ledger set;
- unique stable resource identities inside each document;
- safe relative paths for protected/staging/image records;
- exact `lsbsw:` share ownership markers tied to the document ownership ID;
- service-specific account/share prefixes and SID/file identity proof fields; and
- intent/commit-specific staging and QEMU proof values (pending/zero before commit,
  externally queryable identity after commit).

These checks make protected bytes necessary but not sufficient cleanup authority. A
future Windows cleanup executor must still re-query the named Job/process, account,
right, share, ACE, staging identity, WFP object, port, or relay and compare every stable
proof before mutation. Prefix similarity alone never authorizes deletion.

The host-neutral recovery executor provides the ordering boundary for those Windows
adapters. It validates the document and durably enters `cleaning` before the first
external query, then processes resource records in reverse dependency order. An exact
removal or already-absent proof removes one record and durably checkpoints before the
next query. A mismatched identity preserves the record, persists `quarantined`, and
prevents automatic retry. Temporary query failure preserves `cleaning` for a later
retry. The ledger file is durably removed only after every record has an exact removed
or absent proof. A crash after external removal but before its checkpoint safely
re-queries the retained record and accepts only an already-absent/exact result.

## Durable writes

Each persistence attempt serializes before creating state, allocates a random
`create_new` sibling, flushes the complete bytes, atomically replaces the target, and
flushes the parent directory where the host supports it. Concurrent writers never share
or truncate one temporary. A failed write/replace removes only its own random temporary;
an interrupted leftover is quarantined at the next startup rather than silently
discarded.

## Verification boundary

macOS tests cover strict valid admission, corrupt/unknown/temp entries, symlinks without
target access, duplicate ownership, bounded enumeration, forged markers, duplicate
resources, intent/commit proof shapes, concurrent atomic writers, and failed-replace
cleanup. Fault injection covers every cleanup boundary, retry from each durable
checkpoint, identity mismatch, and the crash window between external removal and ledger
checkpoint. Windows verification must add protected-directory ACL/tamper cases, file-ID
re-query races, disk-full/power-cut snapshots, and idempotent resource-specific cleanup
before SEC-02 can be considered implementation complete.
