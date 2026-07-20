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
the checked walk and staged snapshot. After one absolute local-volume bootstrap, every
ancestor, root, recursively walked entry, and staged-copy source is opened as one
validated component with `NtCreateFile` relative to the previously pinned directory
handle. Relative handles omit delete sharing, use open-reparse-point semantics, and are
revalidated by volume/file identity when a second rights-specific open is required.
Current-token tests prove the component chain resolves to the same identity as a direct
handle and exercise relative recursive copying. Caller-token writeback now consumes a
retained read-write `AuthorizedMountRoot` plus a bounded relative path; it rejects a
read-only capability, and no absolute caller destination crosses the path-worker
boundary. Every existing or newly created destination directory is opened with
`NtCreateFile` relative to the preceding pin, without delete sharing and without
following a reparse point. Authorization now pins every system,
service, ProfileList, profiles-directory, and caller-profile root without delete
sharing and compares its 64-bit volume serial plus 128-bit file ID against every pinned
mount ancestor and the mount root. This rejects protected-root drive-letter, short-name,
and other textual aliases while preserving only the caller-profile identity; an
identity collision never removes a system/service root. Unreadable, missing, reparse,
or non-directory protected roots fail authorization. Active monitoring, periodic/final
synchronization, conflict publication, integration of caller-token writeback with a
protected staged tree, and privileged alias/path-swap timing evidence remain incomplete;
mount requests therefore stay `MOUNT_UNAVAILABLE` until service/SMB lifecycle integration
and the NTFS/ReFS acceptance matrix are complete.

Protected-profile policy no longer relies only on the default profiles directory. The
path worker reads the protected 64-bit-machine `ProfileList` view with `KEY_READ`, caps
enumeration at 1,024 entries, bounds and expands each `ProfileImagePath`, requires an
absolute local-drive path, and adds every discovered root except the authenticated
caller's exact normalized profile to the deny set. Registry access, type/size/path, or
enumeration errors reject mount authorization. Current-machine and pure relocated-root
tests cover expansion, termination, caller exclusion, deduplication, and UNC rejection.
The canonical comparison described above now backs this string policy and canonically
excludes a ProfileList alias of the caller only from the profile-derived deny identities.
Real alternate-name and path-swap fixtures remain pending.

The caller-token export primitive bounds reads to the authorized source length plus one
byte and requires the same open source handle to retain its length and last-write time
through the copy. Under impersonation it traverses or creates each parent from the held
mount-root handle, creates a random sibling with create-new semantics, flushes it, and
commits that exact handle with `FileRenameInformationEx` relative to the pinned final
parent. The final component is a validated single name, so prefixes, traversal, path
separators, NUL, and ADS syntax cannot enter the rename record. Non-overwrite collision
leaves the existing destination intact; best-effort failure cleanup marks only the exact
temporary handle for deletion. A standard-token regression covers replacement,
collision, missing parents, over-length copy failure, traversal/absolute/ADS rejection,
and temporary cleanup. After the initial snapshot, `StagedMount` now opens the exact
service staging directory without following a reparse point, rejects unsafe attributes,
retains that no-delete-sharing handle, and commits the handle's identity to the protected
ledger before returning. Writeback accepts this unforgeable `ProtectedStagingRoot` plus
a bounded relative source; before impersonation, it opens every source component
handle-relatively without delete sharing and requires a regular non-reparse final file.
Thus neither side of the export worker boundary accepts a naked path. Standard-token
tests prove the staging directory stays pinned, its retained and ledger identities
match, and traversal, absolute, ADS, or empty protected-source names fail closed. The
ordered controller still lacks capability-bound snapshot/operation execution, conflict
publication, VM lifecycle wiring, and retained-stage teardown, so mount activation
remains unavailable.

## Reconciliation

For each relative path, the baseline, current host, and current guest snapshots produce
one deterministic decision:

- host-only change: import the host version into the protected stage;
- guest-only change: export under the held caller token;
- identical two-sided change: record convergence;
- divergent two-sided change: stop propagation and return `MOUNT_CONFLICT`; or
- no change: perform no I/O.

Each prepared `StagedMount` now owns the baseline through a fail-closed reconciliation
controller. A dirty hint becomes due after at most one second, an apparently idle mount
requires a full cycle every 30 seconds, and stop enters a mandatory final cycle with one
30-second deadline. Before exposing any operation, the controller finds every conflict;
one conflict fails the controller without returning a partial I/O plan. A conflict-free
plan orders deletions deepest-first, then directories parent-first, then files, so type
transitions cannot remove a parent before its children or create a child before its
directory. The baseline advances only when the caller explicitly reports the entire
plan complete. Any I/O ambiguity marks the controller failed. A random controller
identity plus monotonic epochs rejects foreign or stale plans, and a watcher hint
received during an in-flight cycle retains a newer dirty generation.
In particular, a final cycle with such a hint remains `Finalizing` and must catch up
within the original deadline rather than reporting successful teardown.

This controller does not activate mounts or perform privileged I/O. Production still
must obtain fresh host and protected-stage snapshots, execute each import/export through
the pinned capabilities, publish conflict artifacts and durable recovery metadata, and
bind the controller to VM stop/cleanup. Until that integration and its Windows evidence
exist, the service continues to advertise no mount capability.

Conflict names are exactly
`<filename>.lsb-conflict-<128-bit-lowercase-hex-session-id>-<decimal-sequence>` and must
fit both the component and full-path bounds. This function only constructs and validates
the name; caller-token publication, recovery metadata, and retained-stage teardown are
still Windows integration work.

Watcher notifications are hints. The queue coalesces duplicate relative paths and holds
at most 100 distinct changes. Boundary-plus-one clears the path set and produces one
`FullRescan` marker, so watcher overflow cannot create unbounded memory or silently omit
reconciliation.
