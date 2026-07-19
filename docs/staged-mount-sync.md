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
