# Windows Overlay Mount Optimization Plan

## Objective

Reduce Windows overlay-mount startup time for the primary workload of roughly 2,000 small files. The current end-to-end time on the target Windows hardware is approximately 40 seconds, and the same unchanged tree may be mounted many times.

Implement the requested options `(1)`, `(2)`, `(4)`, and `(5)` in this order:

- **Option (1):** Reuse one mux `File` session for the complete mount initialization.
- **Option (2):** Remove per-file/per-chunk durability barriers from internal mount import and use one final filesystem barrier.
- **Option (4):** Replace the two full source-tree plans with one just-in-time secure snapshot walk.
- **Option (5):** Reuse content-addressed, read-only ext4 mount images across unchanged runs.

The coding agent will run this plan from the repository root on the affected Windows x86_64/WHPX machine.

## Required Semantics

The optimized implementation must preserve the existing Windows overlay contract documented in `README.md` and asserted by `windows_qemu_mount_smoke` in `crates/lsb-vm/src/sandbox.rs`.

- The mounted tree is a startup snapshot, not a live host share.
- Guest writes must never modify the host source.
- Guest writes must remain visible through overlayfs for the current VM and disappear with the VM unless explicitly exported through an existing API.
- Host changes made after successful startup must not appear in that running VM.
- Regular files, directories, and empty directories must be preserved.
- Reparse points, junctions, symlinks, hardlinks, special files, unsafe paths, and case-fold collisions must retain their current fail-closed behavior.
- Source mutation during snapshotting or cache construction must fail or produce one internally consistent snapshot. It must never publish an image under the wrong key.
- Public `write_file` and public copy-in durability semantics must not be weakened. Deferred durability is internal to mount initialization.
- Older guests without new capabilities must remain correct through the optimized non-cache copy-import fallback, even if they are slower.

## Out Of Scope

- Do not add VirtioFS support on Windows.
- Do not add a tar/bulk-import protocol in this work.
- Do not change default overlay semantics to SMB, 9p, vvfat, or a live share.
- Do not add automatic `.git`, `node_modules`, or build-output exclusions.
- Do not tune QEMU block cache, mux window sizes, compression, or parallel transfers until the required phase metrics show that one of them is still a bottleneck.
- Do not use timestamps or file sizes alone as the reusable image cache key.

## Current Bottlenecks

The implementation currently performs the following work:

- `VmConfigBuilder::build()` calls `plan_windows_mounts()`, which recursively creates a `CopyInPlan` for every overlay source.
- `Sandbox::initialize_windows_mounts()` calls `replan_windows_mount_import()`, recursively walking the same tree again.
- `copy_from_host_plan()` calls public-style `mkdir` and ranged-write helpers for every entry and every 512 KiB chunk.
- Each helper enters `with_guest_control_session()`, opening a new mux session and waiting for the mux OPEN/OPEN_OK handshake.
- Each ranged guest write calls `File::sync_all()`, after which `handle_write_file()` calls global `libc::sync()`.
- Imported lower data is currently stored under `/tmp/lsb/mounts`, and `/tmp` is tmpfs. Overlay upper/work are a second tmpfs mount.

Relevant starting points:

| Area | File |
| --- | --- |
| Windows mount planning | `crates/lsb-platform/src/windows_x86_64/fs/mount_plan.rs` |
| Windows source validation/copy planning | `crates/lsb-platform/src/windows_x86_64/fs/copy.rs` |
| Host import and mount initialization | `crates/lsb-vm/src/sandbox.rs` |
| Guest ranged writes and overlay mounting | `crates/lsb-guest/src/main.rs` |
| File protocol and capabilities | `crates/lsb-proto/src/lib.rs`, `crates/lsb-proto/src/frame.rs` |
| Windows mux | `crates/lsb-platform/src/windows_x86_64/control/mux.rs` |
| Windows QEMU config/argv/boot | `crates/lsb-platform/src/windows_x86_64/qemu/` |
| Runtime asset construction | `xtask/src/rootfs.rs` |

## Delivery Rules

- Complete the phases in order and benchmark after every phase.
- Keep every phase independently reviewable and covered by tests.
- Capture the original baseline before changing runtime behavior.
- Do not delete or weaken security checks to meet a timing target.
- Prefer explicit state machines and typed protocol messages over path or filename conventions.
- Keep cache failures non-fatal, but keep unsafe source validation fatal.
- Record raw benchmark data. Do not report only rounded summaries.

## Phase 0: Baseline And Instrumentation

### Benchmark Harness

Add `scripts/benchmark-windows-overlay.ps1` before changing the importer.

- [ ] Create a deterministic fixture outside timed regions under `target/windows-overlay-benchmark/fixture`.
- [ ] Create exactly 2,000 regular files in 100 directories, with 20 files per directory.
- [ ] Use deterministic 1 KiB payloads so file-count overhead, not bulk throughput, dominates.
- [ ] Create a separate correctness fixture containing empty files, empty directories, nested paths, and non-ASCII filenames that the current product accepts.
- [ ] Write a sorted canonical fixture manifest with relative path, entry kind, length, and SHA-256.
- [ ] Time `target\release\lsb.exe run --mount "<fixture>:/workspace" -- /bin/true`.
- [ ] Run a matching no-mount command as the VM startup floor.
- [ ] Give every measured overlay run an adjacent no-mount partner with a shared pair ID, and alternate which command runs first so overhead percentiles are calculated from per-pair differences rather than subtracted independent quantiles.
- [ ] Write one JSON record per run plus aggregate JSON/CSV under `target/windows-overlay-benchmark/results`.
- [ ] Support an isolated cache root through `LSB_WINDOWS_MOUNT_CACHE_DIR` so benchmark cleanup never touches a user's normal cache.
- [ ] Record git SHA and dirty state, Windows build, CPU, RAM, NTFS volume, active power plan, Defender real-time status, QEMU version, CLI hash, guest/runtime asset hash, and fixture digest.
- [ ] Copy aside and hash the complete pre-change `H0/G0` CLI/runtime set before installing any locally built assets; it is required for the final paired comparison and old-guest fallback test.
- [ ] Keep Defender enabled for acceptance runs. A Defender-disabled diagnostic run may be recorded separately but must not replace the primary result.

Capture one separate warm-up pair followed by at least 20 measured no-mount/legacy-overlay pairs. Calculate median and nearest-rank p95 only over the measured pairs. The expected legacy overlay total is approximately 40 seconds. If its median is outside 30-55 seconds, stop and explain the environmental difference before changing gates.

Initial command:

```powershell
cargo build -p lsb-cli --release

.\scripts\benchmark-windows-overlay.ps1 `
  -Binary .\target\release\lsb.exe `
  -PrepareFixture `
  -FixtureRoot .\target\windows-overlay-benchmark\fixture `
  -Mode Baseline `
  -WarmupIterations 1 `
  -Iterations 20
```

### Structured Metrics

Add a disabled-by-default, schema-versioned mount metrics JSON output. Use an explicit path from `LSB_WINDOWS_MOUNT_METRICS_PATH`; do not make the benchmark parse human tracing output. The PowerShell harness owns `external_total_ms`, pair ID, and run order, then merges them with the process-emitted phase metrics. Never include host source paths or file contents.

Required durations:

| Field | Boundary |
| --- | --- |
| `external_total_ms` | Benchmark harness immediately before CLI process creation through process exit; this is the canonical before/after comparison scope |
| `total_start_ms` | `Sandbox::start` entry through successful mount initialization; diagnostic only because the legacy builder walk begins earlier |
| `initial_plan_ms` | Existing eager plan, until Phase 3 removes it |
| `guest_ready_ms` | QEMU launch through guest-ready |
| `replan_ms` | Existing post-boot replan, until Phase 3 removes it |
| `snapshot_walk_ms` | Secure walk plus content-key calculation |
| `cache_lookup_ms` | Completed key through hit/miss/bypass decision |
| `cache_image_create_ms` | Host staging-file creation and sizing only |
| `cache_disk_config_ms` | Host data-disk configuration before QEMU launch |
| `cache_device_discovery_ms` | Post-guest-ready request through exact device discovery and validation |
| `cache_format_ms` | Guest format and initial read-write mount on a miss |
| `mux_session_open_ms` | Host File-session acquisition through OPEN_OK and usable reader/writer; sum all opens on legacy runs |
| `transfer_ms` | First directory/write request through final data response |
| `barrier_ms` | The single final filesystem barrier |
| `cache_validate_ms` | Guest tree validation and, for a miss, sealed raw-device digest calculation |
| `overlay_mount_ms` | First overlay request through final mount response |
| `cache_publish_ms` | QEMU file release through host raw-image verification and atomic manifest publication |

Make the phase fields above non-overlapping and measure them with a monotonic clock. Define `mount_work_ms` as the sum of `initial_plan_ms`, `replan_ms`, `snapshot_walk_ms`, `cache_lookup_ms`, `cache_image_create_ms`, `cache_disk_config_ms`, `cache_device_discovery_ms`, `cache_format_ms`, `mux_session_open_ms`, `transfer_ms`, `barrier_ms`, `cache_validate_ms`, and `overlay_mount_ms`; omit inapplicable phases as zero. `mount_work_ms` deliberately excludes `guest_ready_ms` and post-command `cache_publish_ms`. Use `external_total_ms`, not `total_start_ms`, for all old-versus-new performance gates.

Where one guest request spans several phases, return guest-measured subphase durations/counters in its typed response. Do not assign the same host round-trip duration to multiple fields or infer overlapping values.

Required counters and state:

- [ ] Record file count, directory count, logical source bytes, snapshot bytes hashed, transfer-verification bytes hashed, guest-validation bytes hashed, raw-image bytes hashed, bytes transferred, and chunk count.
- [ ] Record full source-tree walk count and entries visited per walk.
- [ ] Record mux `File` sessions, filesystem requests, responses, `sync_all` calls, global `sync` calls, and final barriers.
- [ ] Record per-mount `cache_decision`, `terminal_outcome`, and nullable `fallback_reason` enums. They must distinguish at least disabled, hit selected, build selected, busy bypass, unsupported bypass, invalid/corrupt bypass, hit used, fallback used, build published, build not published, and startup failed.
- [ ] Finalize the metrics record after QEMU stops so publication outcome is represented rather than collapsing `miss -> sealed -> published` into one value.
- [ ] Record cache schema/key version, image logical size, object count before/after, and eviction count.
- [ ] Record lowerdir tmpfs bytes. This should approach zero once image caching is active.
- [ ] Write metrics on both success and failure, including the failed phase and a sanitized error category.

## Phase 1: One Persistent Mux Session

No mux protocol changes are required for this phase. `handle_mux_virtual_session()` in `crates/lsb-guest/src/main.rs` already loops over multiple simple filesystem frames on one virtual session.

### Host Refactor

- [ ] Add stream-level helpers in `crates/lsb-vm/src/sandbox.rs` that accept an existing writer and reader instead of calling `with_guest_control_session()` themselves.
- [ ] Add equivalents of `void_fs_op`, `send_write_file_request`, `write_guest_file_range`, `copy_host_file_to_guest`, and `copy_from_host_plan` that operate on the supplied session.
- [ ] Keep public wrappers for ordinary filesystem APIs.
- [ ] Refactor `initialize_windows_mounts()` to enter `with_guest_control_session("mount init", ...)` exactly once.
- [ ] Perform every post-boot guest operation for mount initialization inside that one closure: directory creation, file writes, the Phase 2 barrier, Phase 4 cache prepare/seal/abort requests, validation, and exactly-once routing of each pending mount.
- [ ] Refactor public Windows `copy_from_host()` to use one session for its complete copy plan while retaining public durability behavior.
- [ ] Do not reconnect or resume after transport loss, a protocol violation, or source mutation during import. Drop/reset the session, stop the VM, and retry only through a fresh startup snapshot.
- [ ] Preserve pending mount descriptors until every import and mount request succeeds.

`"mount init"` already maps to `PlatformControlSessionKind::File`. Avoid nested acquisition of the Windows `control_session` mutex.

Pre-boot snapshot/cache lookup and data-disk configuration happen before the closure because the VM is not running. Cache publication and cleanup happen after QEMU stops. They are part of the lifecycle but are not mux operations and must not be forced into the guest session.

### Compatibility

- [ ] Use the persistent path whenever the guest advertises `CAP_SESSION_MUX`.
- [ ] Retain a correct legacy fallback for guests without mux support.
- [ ] Do not send new frame types until their specific capability is advertised.

### Phase 1 Exit Criteria

- [ ] The 2,000-file startup opens exactly one optimized mux `File` session for import plus mount initialization.
- [ ] The guest creates one virtual-session worker for the complete import, not one per file.
- [ ] Contents and overlay isolation remain unchanged.
- [ ] Record median and p95 after this phase before beginning Phase 2.
- [ ] Target at least a 2x improvement from the approximately 40-second legacy median. If not achieved, use the phase metrics before changing transport internals.

## Phase 2: Deferred Import Durability

### Additive Protocol

Update `lsb-proto` without breaking legacy JSON decoding.

- [ ] Add `CAP_DEFERRED_FILE_SYNC`.
- [ ] Add optional `WriteFileRequest.defer_sync: Option<bool>` with omitted/false preserving current behavior.
- [ ] Add `SyncFsRequest { path: String }`.
- [ ] Allocate an unused `SYNC_FS_REQ` frame and use existing `FS_OK_RESP`/`ERROR` for the response.
- [ ] Keep `PROTOCOL_VERSION` unchanged because the behavior is additive and capability-gated.
- [ ] Advertise the capability from the guest and update Windows guest-ready capability validation/tests.

### Guest Behavior

- [ ] Deferred ranged writes must write and close without `File::sync_all()` and without global `libc::sync()`.
- [ ] Non-deferred ranged writes must retain the current `File::sync_all()` plus subsequent global `libc::sync()` behavior in this work.
- [ ] Non-range public writes must retain their current durability semantics.
- [ ] Do not optimize the public path unless a separate change first defines and proves an equivalent file-data and parent-directory durability contract.
- [ ] Implement `SYNC_FS_REQ` with Linux `syncfs(fd)` on a securely opened path.
- [ ] Return success only after the filesystem-scoped barrier completes.

### Host Behavior

- [ ] Set `defer_sync=true` only for internal mount-image or tmpfs import writes and only when the capability is advertised.
- [ ] Never set it for public `write_file` or public copy-in.
- [ ] For legacy tmpfs fallback import, send one `SYNC_FS_REQ` for `/tmp/lsb/mounts` after all writes and before any overlay mount request.
- [ ] For ext4 cache-image construction, let the cache seal operation perform one `syncfs` per newly built image before it is remounted read-only.
- [ ] If the guest lacks `CAP_DEFERRED_FILE_SYNC`, retain durable writes and omit `SYNC_FS_REQ`. Continue using one session only when `CAP_SESSION_MUX` is present; a guest lacking both capabilities uses the Phase 1 legacy non-mux fallback.
- [ ] Abort before mounting when the final barrier fails.

### Phase 2 Exit Criteria

- [ ] A successful capability-enabled one-mount cache miss or fallback import records zero per-file global syncs.
- [ ] A capability-enabled import records zero per-file `sync_all` calls and exactly one final filesystem barrier.
- [ ] Public filesystem API tests prove unchanged durability behavior.
- [ ] Record median and p95 after this phase before beginning Phase 3.

## Phase 3: One Just-In-Time Secure Snapshot Walk

The reusable image key must be known before QEMU starts so the matching data disk can be configured. Perform the one full walk immediately inside `Sandbox::start()`, before `vm.start()`. This defines the snapshot point as the start operation, not `VmConfigBuilder::build()`.

### Separate Mount Description From Snapshot

- [ ] Remove `CopyInPlan` from `WindowsMountImport` in `mount_plan.rs`.
- [ ] Make builder-time mount planning validate only the mount tag, guest target, reserved paths, duplicate targets, and the source root itself.
- [ ] Add a root-only no-follow directory validator for Windows drive paths.
- [ ] Delete `replan_windows_mount_import()` and its exports/callers.
- [ ] Keep `plan_copy_in()` and `CopyInPlan` for public copy-in behavior.

Suggested types:

```rust
struct WindowsMountDescriptor {
    tag: String,
    host_root: PathBuf,
    guest_target: String,
}

struct WindowsMountSnapshot {
    descriptor: WindowsMountDescriptor,
    entries: Vec<WindowsMountSnapshotEntry>,
    key: MountSnapshotKey,
    file_count: u64,
    directory_count: u64,
    logical_bytes: u64,
}
```

### Deterministic Snapshot Key

Use BLAKE3 with a versioned/domain-separated encoding. Put the canonical encoder in shared code used by both host and guest cache validation, rather than implementing two subtly different encodings.

Canonical records must include:

| Record | Included data |
| --- | --- |
| Header | Cache key ABI/version and import-semantics version |
| Directory | Entry type, UTF-8 relative path length/path, and normalized directory mode |
| File | Entry type, UTF-8 relative path length/path, normalized mode, file length, and full file bytes |

- [ ] Include empty directories.
- [ ] Sort sibling names deterministically and emit parent directories before children.
- [ ] Exclude host absolute root, guest target, timestamps, ACLs, and other metadata not preserved by the current importer.
- [ ] Reject filenames that cannot round-trip through the guest protocol. Do not use lossy strings in a cache key.
- [ ] Bump the key ABI whenever imported metadata or path semantics change.
- [ ] Permit identical trees at different host paths or guest targets to share one cache object.

Define mount-import modes as protocol constants, initially directory `0o755` and regular file `0o644`, matching the shipped guest's effective current behavior. Apply those modes explicitly in both tmpfs fallback and ext4-image imports before mounting, and hash the constants rather than Windows source permissions. Public copy-in remains unchanged. Add a current-runtime integration assertion before locking these values; if the shipped guest produces different modes, use the observed values and document them instead of silently changing behavior.

### Secure Walk And Mutation Handling

- [ ] Preserve lexical path validation, per-directory case-fold checks, reparse rejection, hardlink rejection, and regular-file/directory-only rules.
- [ ] Immediately before each hash or transfer open, run the existing `validate_existing_prefixes` ancestor check unless the implementation instead walks through pinned directory handles.
- [ ] Refactor the checked Windows opener used by this path to open without following the final reparse point and with `FILE_SHARE_READ` only, not its current `FILE_SHARE_READ | FILE_SHARE_DELETE`; use it for both snapshot hashing and miss transfer reopens.
- [ ] Immediately after each open and before reading, rerun `validate_existing_prefixes` unless pinned directory handles make ancestor replacement impossible. A no-follow final-component open does not protect against ancestor junction traversal.
- [ ] Record Windows file identity, length, per-file digest, relative guest path, and expected normalized mode.
- [ ] Compare stable handle metadata before and after hashing; fail if a file changes during hashing.
- [ ] On a cache miss, apply the same pre-open ancestor check, checked open, post-open ancestor check, identity/length checks, and sharing policy when reopening each planned file. Hash bytes while transferring and compare with the planned digest without re-enumerating directories.
- [ ] Fail the startup and discard the pending cache build if transferred bytes do not match the planned snapshot.
- [ ] Do not automatically perform a second walk after mutation; a retry must begin a fresh `Sandbox::start()` snapshot.

This phase deliberately prioritizes the repeated-hit path: close planning handles after hashing rather than retaining roughly 2,000 file locks across QEMU boot and the user command. A cache miss therefore reads file bytes once to calculate the key and again through verified reopen-and-transfer; a hit reads the host bytes only for the key. `full_tree_walks = 1` means one recursive directory enumeration, not one open or one content read per file. A miss may reopen files, but it must not enumerate the tree again.

### Configure Data Disks Before Start

Add an internal platform abstraction for cache disks.

```rust
struct PlatformDataDisk {
    id: String,
    path: PathBuf,
    format: PlatformDiskFormat,
    read_only: bool,
    serial: String,
    virtual_size_bytes: u64,
}
```

- [ ] Add a hidden `PlatformVm::configure_data_disks(Vec<PlatformDataDisk>)` hook.
- [ ] Allow the Windows backend to replace its data-disk list only while stopped and before QEMU launch.
- [ ] Reject non-empty data disks on unsupported backends.
- [ ] Make configuration retry-safe after a failed Windows start.
- [ ] Store Windows VM configuration behind appropriate synchronization rather than mutating it unsafely.

### Phase 3 Exit Criteria

- [ ] `VmConfigBuilder::build()` no longer recursively scans overlay sources.
- [ ] Every startup records exactly one full source walk.
- [ ] Same-length source mutation during the walk or transfer is detected.
- [ ] Case collision and reparse race tests remain fail-closed.
- [ ] Record median and p95 after this phase before enabling image reuse.

## Phase 4: Reusable Read-Only Mount Images

### Cache Format And Layout

Use one raw ext4 image per unique content digest. The Windows kernel configuration already enables virtio-blk and ext4. Do not add squashfs in this implementation.

Default layout:

```text
<data_dir>/mount-cache/v1/
  locks/<digest>.lock
  objects/<digest>/image.ext4
  objects/<digest>/manifest.json
  access/<digest>
  staging/<digest>.<pid>.<nonce>/image.ext4
```

The manifest is the sole host-side ready marker. Required manifest fields are schema version, cache-key ABI, source-tree content digest, sealed raw-image BLAKE3 digest, image format, virtual size, source bytes, file count, directory count, inode count, and creation timestamp. Derive all paths from a validated lowercase digest; never trust a path loaded from the manifest.

- [ ] Implement Windows cache management in a focused module such as `crates/lsb-platform/src/windows_x86_64/fs/mount_cache.rs`.
- [ ] Resolve `data_dir` through the existing platform data-directory rules.
- [ ] Reject reparse points in the cache root, lock paths, staging paths, object directories, images, manifests, and access markers.
- [ ] Validate schema, digest, no-follow regular-file type, single-link identity, exact virtual size, and manifest/image pairing before attachment.
- [ ] Use unique staging directories and atomic rename of the complete directory on publication.
- [ ] Publish `manifest.json` last if directory-level atomic publication cannot be used.
- [ ] Set the published image's Windows read-only attribute as defense in depth; QEMU `readonly=on` remains the enforcement mechanism on hits.
- [ ] After QEMU releases a staging image, open it as a no-follow regular-file handle with write/delete sharing denied, revalidate its identity and exact virtual size, and hash exactly that many bytes before comparing the sealed raw-image digest.

### Cache Key Lookup

- [ ] Use the Phase 3 full-content snapshot key for lookup on every startup.
- [ ] Do not use mtime/size shortcuts in the initial implementation.
- [ ] Treat timestamp-only changes with identical contents as a cache hit.
- [ ] Treat add, delete, rename, empty-directory changes, and same-size content changes as misses.
- [ ] Deduplicate identical digests within one VM and attach one disk for multiple targets. Keep one validated `image_id` per disk plus a separate collision-free `binding_id` per guest target.

### Locking And Concurrency

- [ ] Use Windows `LockFileEx` guards keyed by digest.
- [ ] Hold a shared lock for a hit until QEMU stops and releases the image.
- [ ] Hold an exclusive lock for a miss from staging creation through publication or cleanup.
- [ ] If another process is already building a missing key, bypass caching for the current VM and use the optimized tmpfs import rather than waiting for an arbitrarily long user command.
- [ ] Never evict or invalidate an object without obtaining its exclusive lock non-blockingly.
- [ ] Make two concurrent misses produce at most one published object and no partial ready entry.

### Sparse Image Creation And Sizing

- [ ] Create a sparse raw image on NTFS with `FSCTL_SET_SPARSE` and checked `set_len`.
- [ ] Fall back to a normal file only when the configured size is safe; otherwise bypass caching with diagnostics.
- [ ] Use at least 128 MiB, align sizes to 16 MiB, and include conservative data-block, directory, inode-table, and metadata headroom.
- [ ] Allocate at least `max(8192, 2 * (entry_count + 1024))` inodes.
- [ ] Use checked arithmetic and bypass caching above a configurable maximum virtual image size, initially 8 GiB.
- [ ] Retry through the non-cache importer rather than attempting to grow an attached full image in place.

### Runtime Asset Requirement

- [ ] Add `e2fsprogs` explicitly to both rootfs package-install scripts in `xtask/src/rootfs.rs`, and extend their script-content tests.
- [ ] Resolve and test the actual `mkfs.ext4` path in the built guest.
- [ ] Advertise cache-image capability only when the required formatter exists.
- [ ] Ensure released runtime assets and the CLI/guest capability tests are updated together.
- [ ] Build `G1` and its rootfs through the repository's supported Linux/WSL/Docker or release-CI asset pipeline, then copy the matching artifacts to the Windows benchmark machine. Native Windows `cargo build` only builds the CLI and native `cargo test -p lsb-guest` does not exercise the Linux guest module.
- [ ] Do not benchmark a new host against downloaded pre-change guest assets except in the explicit compatibility row. If no Linux asset builder is available, stop Phase 2 acceptance and report that prerequisite rather than claiming guest changes were tested.

### QEMU Secondary Disks

Extend `QemuBootConfig`, `WindowsQemuBootConfig`, Windows backend config, and `QemuArgvBuilder` to carry multiple typed data disks.

- [ ] Emit each disk after the root disk as `-drive if=none,id=<id>,file=<path>,format=raw,readonly=on|off` plus `-device virtio-blk-pci,drive=<id>,serial=<serial>`.
- [ ] Attach cache hits with `readonly=on`.
- [ ] Attach cache-miss staging images with a writable QEMU backend because construction requires it; after seal the guest exposes only a read-only mount, and post-stop digest verification protects publication.
- [ ] Generate deterministic collision-free QEMU IDs and serials without embedding host paths.
- [ ] Redact every cache image path in diagnostic argv.
- [ ] Validate all QEMU suboption characters through existing typed argv helpers.
- [ ] Test multiple mounts, duplicate digests, commas/spaces in data paths, and read-only golden argv.

### Guest Cache Protocol

Add `CAP_MOUNT_CACHE_V1` and capability-gated cache disk request/response frames. Use tagged actions rather than unrelated booleans.

Suggested operations:

```text
PrepareBuild { image_id, serial, expected_size, expected_key, inode_count }
PrepareHit   { image_id, serial, expected_size, expected_key }
SealBuild    { image_id, expected_key }
AbortBuild   { image_id }
MountOverlay { image_id, binding_id, target }
```

Return typed cache results that distinguish `Ready` from a recoverable `Rejected { reason }`. Reserve the generic protocol `ERROR` frame for malformed requests, impossible state transitions, or internal failures that make the session unsafe. `SealBuild::Ready` must return both the verified source-tree key and the sealed raw-device digest.

- [ ] Locate disks by exact QEMU serial through sysfs; do not assume `/dev/vdb` ordering.
- [ ] Reject the root disk, non-virtio devices, serial mismatches, size mismatches, unexpected read-only state, and already-mounted devices.
- [ ] On a miss, format with `mkfs.ext4 -F -q -m 0 -O ^has_journal -E lazy_itable_init=0 -N <inode_count>` and mount read-write at a private path.
- [ ] Invoke the formatter directly without a shell, enforce a bounded timeout, cap/sanitize captured diagnostics, and roll back to a recoverable rejection on formatter failure.
- [ ] Store imported content under `<private-mount>/source` and cache metadata outside `source`.
- [ ] On a hit, mount ext4 read-only with `nodev,nosuid`; do not use `noexec`, because mounted project files may need execution.
- [ ] Derive the fixed `<private-mount>/source` lowerdir from validated `image_id` state. Do not accept a host-controlled source subdirectory or append an untrusted path component.
- [ ] On seal, write the version/key sentinel, perform one `syncfs`, securely validate the source tree, unmount ext4, set the block device read-only, hash exactly the full advertised virtual device with BLAKE3, then remount ext4 read-only before exposing the overlay.
- [ ] Securely walk and hash `<private-mount>/source` on both a newly sealed image and every cache hit. Return the computed key to the host and reject unexpected entry types, paths, modes, or contents.
- [ ] Compare the guest-computed key with the host snapshot key before mounting overlayfs.
- [ ] Use the existing overlay helper with the image's `/source` directory as lowerdir and a fresh tmpfs upper/work directory.
- [ ] Never expose a cache image whose full guest-side validation failed.
- [ ] Prepare and seal once per unique `image_id`, but create a distinct tmpfs upper/work pair for every `binding_id`. Validate that each binding maps to exactly one already-validated target and cannot reuse another binding's overlay staging paths.
- [ ] Make `AbortBuild` idempotently unmount and forget all private state for the image and its bindings. Every recoverable cache rejection must complete the same rollback before permitting tmpfs fallback on the existing session.

Full guest-side tree validation proves the lowerdir matches the host key before it is exposed. It does not freeze a miss image: the sandbox command runs as root and QEMU still has a writable backend, so guest block-read-only state is only defense in depth. The host must hash the complete staging file after QEMU releases it and publish only when that digest exactly matches the raw-device digest returned by `SealBuild`. A mismatch discards the candidate without failing an already completed user command. Subsequent hits attach the published object with QEMU-enforced `readonly=on` and still perform full tree validation.

### Miss, Hit, And Fallback State Machines

Cache miss:

```text
single host snapshot walk and key
  -> exclusive key lock
  -> sparse staging image
  -> configure writable data disk
  -> QEMU boot
  -> PrepareBuild
  -> one-session deferred import into /source
  -> SealBuild with one syncfs, full tree verification, unmount, and raw-device digest
  -> every binding mounts the read-only image lowerdir with distinct tmpfs upper/work
  -> Sandbox::start succeeds and build becomes publish-eligible
  -> user command
  -> successful QEMU stop
  -> host hashes the released staging file and compares the sealed raw-device digest
  -> atomic object publication
```

Cache hit:

```text
single host snapshot walk and key
  -> validate manifest/image and take shared key lock
  -> configure read-only data disk
  -> QEMU boot
  -> PrepareHit and full guest key verification
  -> image lowerdir plus fresh tmpfs upper/work
  -> zero host file payload transfer
```

Cache failure:

```text
cache/config/format/validation rejection
  -> guest transactionally rolls back private cache mounts/state
  -> return structured Rejected while keeping the File session synchronized
  -> mark sanitized decision, terminal outcome, and fallback reason
  -> optimized tmpfs import continues on the same session when possible
  -> remove/quarantine invalid object after QEMU releases it
  -> never use stale content
```

- [ ] Route every Windows overlay descriptor to exactly one path: `CacheBinding` or `TmpfsFallback`. A successful cache `MountOverlay` consumes and suppresses its corresponding legacy overlay `MountRequest`; fallback targets and unrelated mount types continue through the existing `send_mount_requests()` path.
- [ ] Clear pending state for a target only after its selected route succeeds. If a cache route returns recoverable `Rejected`, mark that binding for fallback before importing and sending its one legacy request; never send both cache and legacy overlay requests for one target.
- [ ] Track cache publication as an explicit monotonic host state such as `BuildSelected -> Sealed -> AllBindingsMounted -> StartupSucceeded -> PublishEligible`. Any cache abort/rejection, fallback selection, mount-initialization error, startup cleanup, or failed overlay response permanently transitions the staging candidate to discard-only.
- [ ] Retry QEMU boot at most once without data disks if attaching a cache disk prevents QEMU startup.
- [ ] Treat unsafe source validation or source mutation as fatal rather than falling back with a different snapshot.
- [ ] Treat cache infrastructure failures as non-fatal when a correct copy-import fallback remains possible.
- [ ] Treat transport loss, malformed protocol, failed rollback, or an impossible guest cache state as fatal to the current VM rather than attempting to reuse a desynchronized session.
- [ ] Publish only a `PublishEligible` build that completed guest seal/key verification, mounted every binding, returned successfully from `Sandbox::start()`, stopped/released QEMU normally, and whose post-stop host raw-image digest exactly matches the digest returned before the user command. User-command exit status alone does not affect eligibility.
- [ ] If a user command modifies a writable build candidate after seal, discard it after the post-stop digest mismatch. Never publish it and defer detection to the next hit.

### Eviction And Recovery

- [ ] Use default limits of 4 GiB logical image size, 64 objects, and 30 days since access.
- [ ] Make limits internally configurable for tests and optionally configurable through documented environment variables later.
- [ ] Update a separate access marker without modifying immutable object metadata.
- [ ] Evict least-recently-used inactive objects only after acquiring an exclusive lock.
- [ ] Remove the ready manifest before deleting an object image.
- [ ] Under the exclusive digest lock, clear the image's Windows read-only attribute before deletion, replacement, or quarantine; restore it if an operation that keeps the object fails.
- [ ] Sweep unlocked staging directories older than one hour.
- [ ] Sweep manifest-less objects when their exclusive lock can be acquired.
- [ ] Extend `lsb prune` or add an equivalent explicit cache-prune path; never mix cache deletion with unrelated instance cleanup silently.
- [ ] Report maintenance failures as diagnostics without failing a sandbox run.

### Phase 4 Exit Criteria

- [ ] First run of a new key builds, seals, uses, and publishes exactly one object.
- [ ] Thirty unchanged sequential runs produce thirty hits, zero payload writes, no object growth, and no fallback imports.
- [ ] Every hit attaches QEMU's cache disk read-only.
- [ ] Every run uses a fresh overlay upper/work directory, so prior guest writes never reappear.
- [ ] Same-length, same-timestamp content mutation misses and produces the changed content.
- [ ] Cache corruption is rejected and falls back correctly.
- [ ] A miss candidate modified after seal is discarded after QEMU stop and never receives a ready manifest.
- [ ] Interrupted and concurrent builds leave no ready partial image.

## Test Plan

### Protocol Tests

- [ ] Legacy `WriteFileRequest` JSON remains unchanged when `defer_sync` is absent.
- [ ] Deferred write and `SyncFsRequest` round-trip tests pass.
- [ ] Cache capability and tagged request/response types reject invalid states and values.
- [ ] Unknown capabilities/frames are never sent to an older guest.

### Guest Unit Tests

- [ ] Non-deferred range writes exercise the existing file sync plus global sync path; deferred writes exercise neither.
- [ ] `syncfs` succeeds for a valid path and returns `ERROR` for invalid paths.
- [ ] One virtual session processes mkdir, multiple writes, syncfs, cache prepare/seal/abort, fallback import, and mount requests sequentially.
- [ ] Cache device discovery rejects root, wrong serial, wrong size, wrong read-only state, and non-virtio devices.
- [ ] Cache tree hashing detects extra, missing, renamed, changed, special, symlink, and wrong-mode entries.
- [ ] Seal occurs before overlay mount and a failed seal never exposes the target.
- [ ] Seal returns a deterministic full raw-device digest only after sync, unmount, block read-only transition, and tree validation.

### Host Unit Tests

- [ ] Builder planning no longer visits descendants.
- [ ] Snapshot ordering and content keys are deterministic.
- [ ] Empty-directory and non-ASCII path behavior is deterministic.
- [ ] Mount import applies the defined directory/file modes identically on tmpfs fallback and ext4 images.
- [ ] Same content at different roots/targets deduplicates.
- [ ] Same-size/same-timestamp content changes invalidate.
- [ ] Root and descendant reparse points remain rejected.
- [ ] Checked snapshot/transfer opens assert `FILE_SHARE_READ` only and deterministically block concurrent write, delete, and rename handles while each read is active.
- [ ] Deterministic hooks cover source replacement during walk and transfer.
- [ ] Cache sizing covers 2,000 empty files, 2,000 1 KiB files, and metadata-heavy nested directories.
- [ ] Manifest validation, lock contention, orphan cleanup, atomic publication, corruption, and eviction are covered, including clearing read-only attributes under lock before cleanup.
- [ ] Post-stop raw-image verification rejects a one-byte mutation and never creates a ready manifest.
- [ ] A sealed build followed by any binding/startup failure remains discard-only even though QEMU cleanup releases the image normally.
- [ ] QEMU argv proves hit images are read-only and all host paths are redacted.
- [ ] Duplicate-digest mounts prepare one image but use distinct binding IDs and distinct upper/work directories for every target.
- [ ] A scripted mount transcript proves 2,000 writes plus barrier plus mount use one session and preserve request ordering.

### Windows WHPX Integration Tests

Extend the ignored Windows mount smoke test or add a focused companion test with disposable matching assets.

- [ ] Run one cache miss and a subsequent hit against the same 2,000-file fixture.
- [ ] Run the new host against a preserved pre-change guest/runtime asset and prove the capability-gated single-session copy fallback mounts the complete fixture.
- [ ] Compare the guest tree to the canonical fixture manifest.
- [ ] Verify ordinary guest writes through the overlay target do not change host source or lower image content.
- [ ] Verify guest writes disappear on the next run.
- [ ] Verify post-start host changes remain invisible in the current run.
- [ ] Verify mutation, add, delete, rename, and empty-directory invalidation.
- [ ] Verify a killed builder and two concurrent builders recover safely.
- [ ] Verify a truncated image, invalid manifest, and mismatched sentinel/key fall back and rebuild.
- [ ] Let a root guest command modify the writable miss block device after seal; prove post-stop verification discards the candidate and the next run cannot hit it.
- [ ] Verify eviction under a test-only small quota skips attached images.

Use deterministic synchronization hooks for TOCTOU tests. Do not use timing sleeps as the security assertion.

## Performance Acceptance Matrix

Use matching host/guest pairs: `H0/G0` is the preserved pre-change CLI plus its matching guest/runtime assets, and `H1/G1` is the post-change CLI plus its matching assets. Keep the machine, release profile, QEMU version, kernel where compatible, QEMU machine settings, power plan, and Defender state fixed; record every binary, initramfs, and rootfs hash because Phases 2 and 4 necessarily change guest assets. Use the same fixture digest for no-mount, legacy, miss, and hit performance rows. For invalidation rows, record the expected digest both before and after each mutation.

| Scenario | Samples | Cache state |
| --- | ---: | --- |
| No mount plus legacy overlay, `H0/G0` | 1 warm-up pair + 20 measured pairs | N/A |
| No mount plus cache miss, `H1/G1` | 1 warm-up pair + 20 measured pairs | Clear only the isolated benchmark cache before every mount run |
| No mount plus cache hit, `H1/G1` | 1 excluded seed miss + 30 measured pairs | Leave fixture and cache unchanged |
| Same-size mutation miss | 3 independent trials | Mutate to a new deterministic digest before every trial while preserving length and timestamp |
| Post-mutation hit | 10 measured | Leave the final changed tree unchanged |
| Concurrent miss | 2 processes | Empty isolated cache |
| Interrupted miss | 1 killed process plus retry | Empty isolated cache |

Within every performance pair, run the no-mount and overlay commands adjacent to each other and alternate pair order. Definitions below all use the harness's identical `external_total_ms` scope:

| Symbol | Meaning |
| --- | --- |
| `B_i`, `N0_i` | Legacy overlay and adjacent original no-mount total for measured pair `i` |
| `C_i`, `N1C_i` | Cache-miss and adjacent post-change no-mount total for pair `i` |
| `W_i`, `N1W_i` | Cache-hit and adjacent post-change no-mount total for pair `i` |
| `B`, `C`, `W` | Medians of the corresponding overlay totals |
| `N0`, `N1` | Median of original no-mount totals and median of all post-change paired no-mount totals |
| `L`, `L95` | Median and p95 of the per-pair values `B_i - N0_i` |
| `M`, `M95` | Median and p95 of the per-pair values `C_i - N1C_i` |
| `H`, `H95` | Median and p95 of the per-pair values `W_i - N1W_i` |

Required gates:

- [ ] No-mount regression satisfies `N1 - N0 <= max(500 ms, 0.10 * N0)`.
- [ ] Cache-miss `mount_work_ms` is at most 15 seconds median.
- [ ] Cache-miss overhead satisfies `M <= 0.50 * L`.
- [ ] Cache-miss p95 overhead satisfies `M95 <= 0.70 * L95`.
- [ ] Cache-hit `mount_work_ms`, including host key calculation, lookup/configuration, guest discovery/validation, and mount, is at most 2 seconds median and 4 seconds p95.
- [ ] Cache-hit overhead satisfies `H <= 0.10 * L`.
- [ ] Cache-hit paired external overhead satisfies `H <= 2 seconds`.
- [ ] The expected cache-hit external median on the reported machine is roughly 10 seconds or less instead of 40 seconds. If the no-mount floor itself makes this impossible, report that floor and retain the relative gate.
- [ ] Host snapshot walk/hash for 2,000 files is at most 1 second median and 2 seconds p95.
- [ ] All 30 unchanged measured runs are hits with stable cache bytes/object count and `terminal_outcome = hit_used`.
- [ ] Cache hits transfer zero host file payload bytes and consume no lowerdir tmpfs data.
- [ ] A normal one-mount miss records one mux session, one final barrier, and one full source walk.

Do not loosen a gate without retaining the failing raw results and identifying the measured phase that makes it impossible.

## Verification Commands

Run focused checks during development:

```powershell
cargo fmt --all -- --check
cargo check --workspace --locked --target x86_64-pc-windows-msvc
cargo test -p lsb-proto --locked
cargo test -p lsb-platform --locked windows_x86_64::fs
cargo test -p lsb-platform --locked windows_x86_64::control::mux
cargo test -p lsb-platform --locked windows_x86_64::qemu::argv
cargo test -p lsb-vm --locked windows_
```

Run Linux guest and rootfs checks in the same Linux/WSL/Docker builder used for `G1`; a native Windows guest test is not a substitute:

```sh
cargo test -p lsb-guest --locked
cargo test -p xtask --locked rootfs
cargo clippy -p lsb-guest --all-targets
```

Run full repository checks before acceptance:

```powershell
cargo fmt --all -- --check
cargo check --workspace --locked --target x86_64-pc-windows-msvc
cargo test --workspace --locked
cargo clippy --workspace
```

Run the WHPX smoke test with disposable matching assets:

```powershell
$env:LSB_WINDOWS_BOOT_KERNEL = "<disposable-kernel>"
$env:LSB_WINDOWS_BOOT_INITRD = "<matching-initramfs>"
$env:LSB_WINDOWS_BOOT_ROOTFS = "<disposable-rootfs>"

cargo test -p lsb-vm --release windows_qemu_mount_smoke -- --ignored --nocapture
```

Run the final benchmark and retain raw output:

```powershell
.\scripts\benchmark-windows-overlay.ps1 `
  -Binary .\target\release\lsb.exe `
  -FixtureRoot .\target\windows-overlay-benchmark\fixture `
  -CacheRoot .\target\windows-overlay-benchmark\cache `
  -Mode Acceptance `
  -WarmupIterations 1 `
  -MissIterations 20 `
  -HitIterations 30
```

## Completion Checklist

- [ ] Original approximately 40-second baseline and no-mount floor are preserved as raw artifacts.
- [ ] Phase-by-phase benchmarks attribute gains to session reuse, durability, one walk, and cache reuse.
- [ ] Cache-hit and cache-miss correctness/security tests pass on actual Windows hardware.
- [ ] All performance gates pass without weakening source validation.
- [ ] Old-guest fallback remains correct.
- [ ] Cache objects are content-addressed, atomically published, read-only on hits, bounded, and recoverable.
- [ ] Runtime assets include and verify the ext4 formatter.
- [ ] README and changelog document the Windows cache behavior, location, invalidation, fallback, and prune procedure.
- [ ] Full workspace format, check, test, and clippy commands pass.
