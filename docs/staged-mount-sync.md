# Staged mount synchronization contract

This module is the host-neutral decision core for the non-admin staged-sync backend. It
does not authorize a caller path, impersonate a Windows token, publish an SMB share, or
claim that Windows propagation is active. Those operations remain behind the Windows
path worker and protected ledger.

## Fixed bounds

The shared protocol limits encode the production decision record: 100,000 entries,
20 GiB logical tree size, 4 GiB per file, 256 path components, 32,767 UTF-16 code units,
100 coalesced queued changes, and a 16 MiB small-copy threshold. The Windows authorized
walk and the protected-stage snapshot use these constants. A tree over a bound fails
before it can be advertised as an available mount.

Snapshots reject a symlink root, symlink entry, or other special entry without reading
its target. Files are content-hashed through a bounded reader; a length or modification
change during the read invalidates the snapshot. A Windows implementation must retain
the stronger handle/file-identity proof around these pure decisions because path-based
macOS tests cannot establish resistance to a Windows rename or reparse race.

The Windows path worker now performs an explicit `AccessCheck` against the held caller
impersonation token for every pinned ancestor, the mount root, and every opened tree
entry. Snapshot staging repeats the per-entry check, enforces the entry, per-file, and
tree-byte limits during the actual copy, caps each read at the authorized length plus
one byte, and re-queries volume/file identity, size, and last-write time on the held
source handle before accepting the copy. A current-token Windows regression exercises
the checked walk and staged snapshot. This is only a fail-closed authorization and
copying tranche: traversal is not yet handle-relative, active monitoring and
periodic/final synchronization are not wired, caller-token writeback is absent, and
mount requests remain `MOUNT_UNAVAILABLE` until service/SMB lifecycle integration and
the privileged NTFS/ReFS acceptance matrix are complete.

Protected-profile policy no longer relies only on the default profiles directory. The
path worker reads the protected 64-bit-machine `ProfileList` view with `KEY_READ`, caps
enumeration at 1,024 entries, bounds and expands each `ProfileImagePath`, requires an
absolute local-drive path, and adds every discovered root except the authenticated
caller's exact normalized profile to the deny set. Registry access, type/size/path, or
enumeration errors reject mount authorization. Current-machine and pure relocated-root
tests cover expansion, termination, caller exclusion, deduplication, and UNC rejection.
Canonical volume/file-identity comparison (including alias-resistant protection) is
still part of the handle-relative traversal backlog and is not claimed by this string
normalization tranche.

## Reconciliation

For each relative path, the baseline, current host, and current guest snapshots produce
one deterministic decision:

- host-only change: import the host version into the protected stage;
- guest-only change: export under the held caller token;
- identical two-sided change: record convergence;
- divergent two-sided change: stop propagation and return `MOUNT_CONFLICT`; or
- no change: perform no I/O.

Conflict names are exactly
`<filename>.lsb-conflict-<128-bit-lowercase-hex-session-id>-<decimal-sequence>` and must
fit both the component and full-path bounds. This function only constructs and validates
the name; caller-token publication, recovery metadata, and retained-stage teardown are
still Windows integration work.

Watcher notifications are hints. The queue coalesces duplicate relative paths and holds
at most 100 distinct changes. Boundary-plus-one clears the path set and produces one
`FullRescan` marker, so watcher overflow cannot create unbounded memory or silently omit
reconciliation.
