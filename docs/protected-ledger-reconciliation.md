# Protected ledger reconciliation envelope

Status: SEC-02 persistence/admission envelope, production QEMU transaction wiring,
and exact startup QEMU process recovery implemented; other Windows resource cleanup
executors and real crash/reboot evidence pending.

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

These checks make protected bytes necessary but not sufficient cleanup authority. Each
Windows cleanup executor must still re-query the process, account, right, share, ACE,
staging identity, WFP object, port, or relay and compare every stable proof before
mutation. Prefix similarity alone never authorizes deletion.

A well-formed document is an outstanding cleanup obligation, not a clean-start signal.
Startup therefore remains health-only whenever any valid document remains. The
production QEMU path reserves its sandbox ledger with create-new semantics, so an ID
collision cannot replace prior evidence. Immediately before the platform creates the
suspended child, the service persists a QEMU intent containing only the verified bundle
image path and random Job identity. After assignment to the authoritative service Job,
it queries the suspended process handle for PID and creation time, commits that exact
proof, and only then permits the primary thread to resume. Clean VM teardown persists
`cleaning`, clears the proven record, checkpoints again, and removes the document.
Ambiguous setup or teardown deliberately retains the document for startup recovery.
After verifying the adjacent bundle, startup reopens a committed QEMU PID once with
query, synchronize, and terminate rights; the retained handle must report the ledger's
creation time and exact verified-bundle image before termination. PID reuse or image
mismatch quarantines without mutation. An absent process is idempotent success, while
access, query, termination, or bounded-wait ambiguity retains the record for retry.
Intent-only records select no PID: the suspended child could not resume before commit
and the authoritative kill-on-close Job cannot survive the old service process. Any
non-QEMU record remains retry-required, so partial adapter coverage never reopens
admissions.

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

Initial reservation is stricter than an update: it opens the final ledger with
`create_new`, writes and flushes the complete initial document, and fails without
altering an existing file. Subsequent state transitions use the atomic replacement path.

## Verification boundary

Host-neutral tests cover strict valid admission, corrupt/unknown/temp entries, symlinks without
target access, duplicate ownership, bounded enumeration, forged markers, duplicate
resources, intent/commit proof shapes, concurrent atomic writers, and failed-replace
cleanup. Fault injection covers every cleanup boundary, retry from each durable
checkpoint, identity mismatch, and the crash window between external removal and ledger
checkpoint. Windows verification must add protected-directory ACL/tamper cases, file-ID
re-query races, disk-full/power-cut snapshots, real service-crash/reboot QEMU convergence,
and idempotent cleanup for every remaining resource before SEC-02 can be considered
implementation complete.
