# Windows Session Mux, Spawn Streaming, and Watch Design

## Problem Statement

Windows currently supports LocalSandbox boot, non-interactive exec, file transfer,
overlay imports, SMB/CIFS direct mounts, port forwarding, proxy networking, and
checkpoints, but it does not have a general control-session model. Streaming
`sandbox.spawn()`, kill/stdin, concurrent spawn/watch, and `sandbox.watch()` need
multiple logical operations over the existing Windows virtio-serial control
transport without changing public CLI, Rust SDK, or Node API shape.

This design keeps Windows on QEMU/WHPX plus virtio-serial, adds an
LSB-owned session mux below existing `lsb-proto` operation frames, enables
Windows `spawn()` first, then `watch()`, and gives SMB/CIFS direct mounts
deterministic live host-backed watch semantics.

## Current Architecture Summary

- Windows backend status and constraints are documented in
  `docs/windows-port/README.md`, `docs/windows-port/mvp-handoff.md`, and
  `docs/windows-port/future-work.md`. The explicit current gaps are no mux,
  no Windows streaming `spawn()`, no interactive shells, and no `watch()`.
- `AGENTS.md` defines repo working agreements, standard build/test commands,
  Windows hardware validation commands, and the requirement to clarify
  underspecified architectural decisions instead of guessing.
- Accepted Windows decisions require QEMU/WHPX, virtio-serial LocalSandbox
  control, stable public APIs, no default guest NIC, no QEMU user networking,
  no `hostfwd`, and SMB/CIFS for explicit Windows direct mounts:
  `docs/windows-port/decisions.md` D005, D007, D008, D012, D015, D019, D024.
- `docs/windows-port/rfc-qemu-whpx.md` already anticipated a
  transport-internal virtio-serial mux with existing `lsb-proto` payloads
  nested unchanged. This design narrows that idea to spawn/watch and leaves
  port forwarding on its current dedicated channel.
- `lsb-proto` frames are transport-neutral. `crates/lsb-proto/src/frame.rs`
  defines the existing frame header and operation types, including `EXEC_REQ`,
  `STDOUT`, `STDERR`, `STDIN`, `EXIT`, `KILL`, `WATCH_REQ`, and `WATCH_EVENT`.
  `crates/lsb-proto/src/lib.rs` defines `GuestReady`, current capabilities, and
  virtio-serial port names.
- Windows QEMU boot creates private virtio-serial pipe chardevs for
  `org.localsandbox.control` and `org.localsandbox.forward` in
  `crates/lsb-platform/src/windows_x86_64/qemu/argv.rs` and
  `crates/lsb-platform/src/windows_x86_64/qemu/config.rs`.
- `crates/lsb-platform/src/windows_x86_64/qemu/boot.rs` opens the control pipe
  during boot, reads a raw `GUEST_READY` frame, stores the established stream,
  and later clones that stream for `connect_control()`. This was required by
  D021 because QEMU pipe chardev startup can block until the host connects.
- `crates/lsb-platform/src/windows_x86_64/control/virtio_serial.rs` generates
  private per-instance named pipe names and opens QEMU-created Windows pipes.
  Error messages intentionally avoid leaking full pipe paths.
- `crates/lsb-vm/src/sandbox.rs` serializes current Windows control operations
  behind `control_session: Mutex<()>`. Non-interactive exec and file operations
  use `with_guest_control_session()`. `open_exec()` returns an unsupported
  Windows capability error for streaming exec, and `open_watch()` assumes the
  macOS vsock path.
- `crates/lsb-sdk/src/process.rs`, `crates/lsb-sdk/src/watch.rs`, and
  `crates/lsb-sdk/src/runtime.rs` currently type streaming internals as
  `TcpStream`. `bindings/nodejs/README.md` documents that `spawn()` streaming
  and `watch()` are macOS-only today, while
  `bindings/nodejs/test/streaming.spec.ts` already describes the desired public
  Node behavior.
- `crates/lsb-guest/src/main.rs` selects virtio-serial via the kernel command
  line, sends `GUEST_READY` on virtio-serial, then handles one operation per
  physical stream. `handle_piped_exec()` and `handle_watch()` consume the
  physical stream and return. `handle_watch()` uses Linux inotify.
- Windows overlay mounts are snapshot imports. Direct mounts are planned as
  SMB/CIFS mounts in
  `crates/lsb-platform/src/windows_x86_64/fs/mount_plan.rs`, with live SMB
  lifecycle, credentials, shares, cleanup manifests, and redaction in
  `crates/lsb-platform/src/windows_x86_64/fs/smb/*`.
- `crates/lsb-sdk/src/runtime.rs` already attaches a mount-only SMB proxy for
  direct SMB mounts when `allow_net` is false, and smoke coverage verifies
  host-originated and guest-originated direct SMB file visibility plus arbitrary
  egress denial.

Platform semantics checked for this design:

- Microsoft documents `ReadDirectoryChangesW` as reporting changes inside a
  directory, optionally for the full subtree, with explicit overflow handling:
  https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-readdirectorychangesw
- Linux inotify does not catch remote changes on network filesystems, which is
  why CIFS direct mounts need host-side watch support for deterministic
  host-originated events:
  https://man7.org/linux/man-pages/man7/inotify.7.html
- QEMU documents Windows `-chardev pipe` as a single duplex pipe, matching the
  repo's current virtio-serial control pipe model:
  https://www.qemu.org/docs/master/system/qemu-manpage.html

## Chosen Design

### 1. Keep Windows on virtio-serial

Do not replace the control transport. The Windows backend remains QEMU/WHPX with
the existing `org.localsandbox.control` virtio-serial port backed by a private
QEMU Windows pipe. Port forwarding remains on the existing dedicated
`org.localsandbox.forward` virtio-serial channel and is not migrated to the mux
in this work.

### 2. Add `CAP_SESSION_MUX`

Add `CAP_SESSION_MUX` to `lsb-proto`. The guest advertises it in `GuestReady`
for virtio-serial only after it can run the mux accept loop. The host extends
Windows guest-ready validation to accept the new capability.

The initial Windows boot handshake stays a raw `GUEST_READY` frame so existing
readiness diagnostics remain stable. After the host validates `GUEST_READY` and
sees `CAP_SESSION_MUX`, both sides switch that physical control stream into mux
mode for all later control traffic.

If a Windows guest does not advertise `CAP_SESSION_MUX`, retain current
serialized non-streaming behavior where feasible, but keep streaming `spawn()`
and `watch()` unsupported with precise capability errors.

### 3. Add a mux below existing operation frames

The mux is transport-internal. Existing operation frames stay unchanged and are
carried as bytes inside virtual sessions:

- `EXEC_REQ`, `STDOUT`, `STDERR`, `STDIN`, `EXIT`, `KILL`, and `ERROR` are the
  process protocol on an exec session.
- `WATCH_REQ`, `WATCH_EVENT`, and `ERROR` are the watch protocol on a watch
  session.
- File and mount operations can use short-lived mux sessions so the physical
  pipe still has one owner after mux negotiation.

Recommended physical mux frames:

```text
Physical stream after GUEST_READY:
  existing frame header: [u32 be payload_len][u8 mux_type][payload]

New mux frame types:
  MUX_OPEN       host or guest requests a session
  MUX_OPEN_OK    peer accepted and grants initial receive credit
  MUX_OPEN_ERR   peer rejected before session establishment
  MUX_DATA       bytes for one virtual session
  MUX_WINDOW     additional receive credit for one session
  MUX_FIN        half-close for one session direction
  MUX_RST        abort one session with optional sanitized reason

Payload conventions:
  session_id: u64 be in every mux payload
  session_id 0: reserved for mux control only
  host-opened sessions: odd ids
  guest-opened sessions: even ids, reserved for future use
  MUX_DATA payload after session_id: virtual-stream bytes
```

Virtual-stream bytes are ordinary `lsb-proto` operation frames, including their
existing `[len][type][payload]` frame header. This avoids adding session IDs to
operation payloads and keeps macOS frame semantics untouched.

The mux data chunk size should be bounded below `MAX_FRAME_LEN`; use a small
constant such as 64 KiB per `MUX_DATA` frame unless benchmarks justify a change.

### 4. One physical reader and writer own the pipe

Once `CAP_SESSION_MUX` is active, no component may clone the Windows physical
control pipe and read from it independently. A Windows mux manager owns the
established `PlatformControlStream`, runs the only physical reader loop, and
runs the only physical writer loop. It exposes virtual session handles to
`lsb-vm` and `lsb-sdk` internals.

This means Windows non-streaming exec, file ops, mount init, streaming spawn,
and guest-side watch should all use virtual sessions after mux negotiation.
Keeping some operations on cloned physical handles would reintroduce frame
races and must be avoided.

### 5. Introduce an internal session abstraction

Add an internal `ControlSession` or equivalent boxed session type that is
`Read + Write + Send` and supports close/reset. Implement it for:

- macOS `TcpStream` or existing vsock transport.
- Windows mux virtual sessions.
- Test in-memory sessions.

Refactor streaming internals from `TcpStream` to this abstraction without
changing public Node, Rust SDK, or CLI API signatures. Do not require
`AsRawFd` for non-TTY exec or watch sessions; keep raw-fd requirements isolated
to interactive TTY code, which is out of scope.

### 6. Enable Windows `sandbox.spawn()` first

For Windows `spawn()`:

1. SDK asks `lsb-vm` for an exec session.
2. Windows `lsb-vm` opens a mux virtual session and writes the existing
   `EXEC_REQ` with `tty=false` and `stdin_closed=false`.
3. The guest mux accept loop dispatches the virtual session to the existing
   piped exec handler.
4. `STDOUT`, `STDERR`, `EXIT`, `ERROR`, `STDIN`, and `KILL` flow exactly as on
   macOS, but inside the virtual session.

Concurrent spawns must be supported before declaring the slice complete.

### 7. Enable Windows `sandbox.watch()` second

For normal guest paths and overlay/snapshot import paths, use guest-side
inotify over a mux virtual session with the existing `WATCH_REQ` and
`WATCH_EVENT` frames.

For paths inside Windows SMB/CIFS direct mounts, use a host-side Windows
watcher as the primary event source. Resolve the guest path against the
configured direct SMB mount registry, watch the canonical host source path
with `ReadDirectoryChangesW` or a crate that uses it correctly, and map emitted
host-relative paths back to guest paths. This is more deterministic than relying
only on Linux CIFS inotify because inotify does not catch remote network
filesystem events.

Required SMB watch semantics:

- Host-originated changes under the direct SMB source must be observed.
- Guest-originated writes through CIFS must also be tested and should be
  observed through the host watcher because they materialize on the host
  filesystem.
- Read-only direct SMB mounts should report host-originated changes while guest
  writes remain denied by existing SMB permissions.
- The first implementation may limit direct-SMB watch to paths at or below one
  direct SMB target. Recursive watches whose requested root is an ancestor of
  multiple mixed guest and SMB roots should either use a documented hybrid
  guest+host aggregator or return a precise unsupported error until hybrid
  semantics are implemented.

## Alternatives Considered and Rejected

- Replace virtio-serial with AF_VSOCK, Hyper-V sockets, QGA, QMP, hostfwd,
  QEMU user networking, TAP, bridge, or NAT: rejected by scope and by accepted
  Windows decisions. It would also reopen security and diagnostics work that is
  already settled for the current backend.
- Clone the Windows pipe handle for every stream: rejected because the physical
  byte stream has no operation-session boundaries. Multiple readers can consume
  each other's frames and corrupt concurrent operations.
- Add `session_id` fields to `EXEC_REQ`, `STDOUT`, `WATCH_EVENT`, and other
  operation frames: rejected as more invasive than necessary. Nesting existing
  operation frames inside mux virtual streams preserves current protocol
  semantics and macOS behavior.
- Rely solely on Linux inotify for CIFS direct mounts: rejected for live host
  changes because inotify does not catch remote network filesystem events.
  Host-side Windows watch is the deterministic path for SMB direct mounts.
- Migrate port forwarding onto the mux now: rejected by scope. Current Windows
  forwarding uses a separate virtio-serial channel and already preserves
  no-network semantics.
- Change public Node/Rust/CLI APIs: rejected because existing APIs can express
  the required behavior. Any later API change for explicit bounded public output
  streams needs separate approval.

## Data and Control Flow

### Mux Startup

```text
QEMU starts with existing control pipe
  -> host opens pipe during boot
  -> guest opens virtio-serial control port
  -> guest sends raw GUEST_READY with CAP_SESSION_MUX
  -> host validates protocol version, transport, and capabilities
  -> host creates WindowsMuxManager over the established pipe
  -> guest switches the same pipe to mux accept loop
```

No later code reads from the physical pipe directly. The mux manager is the only
owner of physical reads and writes.

### Spawn Flow

```text
Node/Rust public spawn()
  -> lsb-sdk AsyncSandbox::spawn()
  -> runtime actor requests OpenExec
  -> lsb-vm Sandbox::open_exec_session()
  -> Windows mux MUX_OPEN(kind=exec)
  -> guest accepts session
  -> host writes existing EXEC_REQ on virtual stream
  -> guest handle_piped_exec reads EXEC_REQ and starts child
  -> guest sends STDOUT/STDERR/EXIT frames on same virtual stream
  -> host SDK reader forwards chunks to existing ProcessHandle surfaces
  -> stdin writes and kill write existing STDIN/KILL frames on that session
```

### Guest Watch Flow

```text
public watch("/tmp" or overlay/import path)
  -> lsb-sdk AsyncSandbox::watch()
  -> lsb-vm resolves path as non-SMB
  -> Windows mux MUX_OPEN(kind=watch)
  -> host writes WATCH_REQ on virtual stream
  -> guest handle_watch uses inotify and emits WATCH_EVENT frames
  -> SDK WatchHandle yields existing event shape
  -> dropping WatchHandle closes/resets the virtual session
```

### SMB Direct-Mount Watch Flow

```text
public watch("/direct/subdir")
  -> lsb-vm resolves longest matching WindowsSmbMount target
  -> host maps guest path to canonical host source + relative path
  -> host starts Windows directory watcher on that host path
  -> watcher maps host relative event path back to guest path
  -> SDK WatchHandle yields existing WatchEvent values
  -> dropping WatchHandle cancels ReadDirectoryChangesW/worker and drains
```

The host watcher does not expose arbitrary host paths. It only watches sources
that were accepted by the Windows direct SMB mount planner and lifecycle.

## Error Handling, Cancellation, Shutdown, and Backpressure

### Mux Errors

- `MUX_OPEN_ERR` reports rejected sessions before establishment, using sanitized
  reason codes and short messages.
- In-session operation errors continue to use existing `ERROR` frames where the
  current protocol already does so.
- `MUX_RST` aborts established sessions. Use it for transport errors,
  cancellation, malformed virtual frames, and VM shutdown.
- Protocol violations on the physical mux stream are fatal to the mux manager:
  close the physical pipe, fail all sessions, and let higher-level VM shutdown
  or recovery handle the broken guest control transport.

### Cancellation

- `ProcessHandle::kill()` sends the existing `KILL` frame on the exec virtual
  session. Dropping stdin or explicit stdin close should send `FIN` or an
  existing stdin-closed signal if one is added internally.
- Dropping a watch handle closes or resets the watch session. Guest-side watch
  must stop on virtual-session close instead of polling a raw file descriptor.
- SMB host watchers should use overlapped I/O plus cancellation, `CancelIoEx`,
  or an equivalent crate abstraction that can be interrupted promptly.

### Shutdown

- `Sandbox::stop()` cancels all active sessions, stops the mux manager, then
  proceeds with existing QEMU and SMB cleanup ordering.
- Direct SMB watchers must stop before SMB shares, users, ACL grants, and
  cleanup manifests are removed.
- Guest mux loop treats physical EOF as VM shutdown or transport reset, aborts
  active sessions, and returns to the existing virtio-serial reopen loop.

### Backpressure and Fairness

- Each virtual session has a bounded inbound byte buffer and bounded outbound
  queue.
- Each side grants receive credit with `MUX_OPEN_OK` and `MUX_WINDOW`.
  `MUX_DATA` may be sent only when the peer has credit for that session.
- The physical writer loop schedules sessions fairly, for example round-robin
  over sessions with queued data and available credit.
- A single stdout-heavy process must not prevent `KILL`, another process, or a
  watch event from making progress.
- Guest stdout/stderr reader threads should block when their virtual-session
  credit is exhausted. That is intentional backpressure, not a deadlock.
- Keep current public SDK stream shape unless separately approved. If future
  agents want end-to-end bounded public stdout/stderr receivers, that is a
  public Rust API discussion and should not be folded into the Windows mux work
  silently.

## Security Considerations

- SMB credentials remain host-generated secrets. Do not write generated SMB
  passwords into cleanup manifests, QEMU argv, guest env, serial logs, proxy
  logs, mux traces, protocol dumps, or diagnostic bundles.
- Mux tracing must be allowlisted and redacted. Log frame/session metadata,
  counters, close reasons, and sanitized path labels; do not log arbitrary
  payload bytes.
- Control pipe privacy remains required. Continue using per-instance random
  QEMU pipe names and sanitized diagnostics from
  `windows_x86_64/control/virtio_serial.rs`.
- The mux must not add network reachability. It runs over the existing private
  virtio-serial pipe and must not add QEMU user networking, `hostfwd`, TAP,
  bridge, NAT, public sockets, or firewall policy as part of spawn/watch.
- Direct SMB watch path mapping must only use the configured mount registry.
  Never accept a raw guest path as a host path. Use longest-prefix matching with
  path-boundary checks so `/workspace2` cannot match `/workspace`.
- Keep direct SMB proxy behavior unchanged: when direct SMB is the only network
  need, use the existing mount-only SMB proxy and continue to deny arbitrary
  outbound network access.
- Host-side watchers must not keep SMB resources alive past sandbox teardown or
  prevent cleanup. Failure cleanup should still remove shares, ACL grants, local
  users, and manifests where possible.

## Testing Strategy

Unit and fake-transport coverage:

- `lsb-proto`: mux capability constant, mux frame encode/decode, malformed
  length/type handling, max chunk bounds, window accounting.
- Host mux manager: concurrent sessions over an in-memory duplex stream,
  fragmentation/reassembly, fair scheduling, window updates, reset/fin, EOF,
  physical protocol violation, and no independent physical readers.
- Guest mux loop: open session, dispatch exec/watch frames, reject malformed
  frames, cancellation while child/watch is active.
- SDK/VM abstraction: `TcpStream` compatibility for macOS and boxed/in-memory
  session tests for streaming process and watch internals.
- SMB path resolver: longest-prefix matching, path-boundary checks, recursive
  and non-recursive mapping, read-only/read-write mount metadata, no arbitrary
  host path access.
- Host watcher mapping: Windows temp-dir watcher events mapped to guest paths,
  rename/create/modify/delete, overflow/error reporting.

Windows self-hosted WHPX coverage:

- Two or more concurrent Windows `spawn()` processes complete without frame
  corruption.
- Windows `spawn()` supports stdout, stderr, non-zero exit, cwd, stdin writes,
  kill, and large output without starving another session.
- Guest-side `watch()` reports create/modify/rename/delete, recursive
  subdirectory events, and coexists with concurrent `spawn()`.
- Direct SMB `watch()` reports host-originated file changes.
- Direct SMB `watch()` reports guest-originated writes through CIFS, or records
  a blocking defect before release if Windows host notifications do not observe
  those writes on the runner.
- Direct SMB `watch()` on read-only mount reports host-originated changes and
  keeps guest writes denied.
- Network/security regression tests keep `-nic none` for default sandboxes, use
  only mount-only SMB proxy for direct SMB without `allow_net`, and verify
  arbitrary outbound traffic remains denied.

Node coverage:

- Reuse and extend `bindings/nodejs/test/streaming.spec.ts` so Windows no
  longer expects capability errors once the mux/spawn/watch slices land.
- Add Windows-specific direct SMB watch smoke where the runner can be elevated
  and has SMB policy prepared.

Validation commands for implementation agents:

```bash
cargo fmt --all -- --check
cargo test -p lsb-proto
cargo test -p lsb-platform
cargo test -p lsb-vm
cargo test -p lsb-sdk
cargo test --workspace
cd bindings/nodejs && corepack yarn test
./scripts/win-gh-test check
./scripts/win-gh-test unit
./scripts/win-gh-test smoke
```

Use `./scripts/win-gh-test smoke` after mux, spawn, watch, QEMU transport, SMB
watch, or guest-control changes. The helper requires a clean committed working
tree because GitHub Actions tests pushed commits.

## Implementation Slices

### Slice 1: Protocol and Session Mux Primitives

Goal:

Define mux capability and transport-internal frame primitives without changing
existing operation frames or public APIs.

Files likely touched:

- `crates/lsb-proto/src/lib.rs`
- `crates/lsb-proto/src/frame.rs`
- New internal mux module under `crates/lsb-proto/src/` if useful

Detailed tasks:

- Add `CAP_SESSION_MUX`.
- Add mux frame type constants or a mux envelope module.
- Define binary encode/decode for `OPEN`, `OPEN_OK`, `OPEN_ERR`, `DATA`,
  `WINDOW`, `FIN`, and `RST`.
- Enforce session id rules, payload length limits, and chunk size accounting.
- Keep existing operation frames unchanged and covered by existing tests.
- Add unit tests for valid/invalid mux envelopes, max size, and round trips.

Acceptance criteria:

- Existing `EXEC_REQ`, `STDOUT`, `STDERR`, `STDIN`, `EXIT`, `KILL`,
  `WATCH_REQ`, and `WATCH_EVENT` wire formats are unchanged.
- `CAP_SESSION_MUX` exists and can be advertised in `GuestReady`.
- Mux encode/decode rejects malformed, oversized, or reserved-session payloads.

Validation commands:

```bash
cargo fmt --all -- --check
cargo test -p lsb-proto mux
cargo test -p lsb-proto
```

Risks:

- Accidentally changing existing frame behavior would break macOS.
- Overly generic mux primitives can delay implementation; keep them minimal.

Copy-paste prompt:

```text
Implement only Slice 1 from PLAN.md: add `CAP_SESSION_MUX` and transport-internal mux primitive encode/decode in `lsb-proto`. Preserve all existing operation frame wire formats and public APIs. Add focused unit tests for mux frame round trips, invalid session ids, malformed payloads, and size limits. Do not touch Windows host/guest mux managers yet, and do not implement spawn/watch behavior in this slice.
```

### Slice 2: Host-Side Windows Mux Manager Over Virtio-Serial

Goal:

Create the Windows host mux manager that owns the established virtio-serial
control pipe and exposes virtual sessions internally.

Files likely touched:

- `crates/lsb-platform/src/windows_x86_64/qemu/boot.rs`
- `crates/lsb-platform/src/windows_x86_64/backend.rs`
- `crates/lsb-platform/src/windows_x86_64/control/virtio_serial.rs`
- New `crates/lsb-platform/src/windows_x86_64/control/mux.rs`
- `crates/lsb-platform/src/lib.rs` for internal session traits/enums if needed

Detailed tasks:

- Extend guest-ready capability validation to accept `CAP_SESSION_MUX`.
- After `GUEST_READY`, instantiate a mux manager when the capability is present.
- Ensure the mux manager has the only physical reader and writer for the
  control stream.
- Implement `open_session(kind)` with bounded queues, window credit, fair
  physical write scheduling, `FIN`, and `RST`.
- Fail all sessions cleanly on physical EOF or protocol violation.
- Keep legacy no-mux control path for non-streaming operations if capability is
  absent, but do not allow streaming `spawn()` or `watch()` without mux.
- Add fake-stream tests for concurrent sessions and backpressure.

Acceptance criteria:

- Two fake host sessions can exchange framed bytes concurrently without
  cross-session corruption.
- A stalled session cannot prevent a second session's small control frame from
  being delivered.
- There is no code path where mux mode and cloned physical-pipe readers are
  active at the same time.

Validation commands:

```bash
cargo fmt --all -- --check
cargo test -p lsb-platform mux
cargo test -p lsb-platform windows_x86_64
```

Risks:

- Boot currently stores cloneable control streams; future code must not keep
  exposing clones after mux activation.
- Deadlocks are possible if writer scheduling and window updates share locks
  incorrectly.

Copy-paste prompt:

```text
Implement only Slice 2 from PLAN.md: add the Windows host-side mux manager over the existing boot-established virtio-serial control stream. The mux manager must own the only physical reader/writer, expose internal virtual sessions, enforce bounded queues and flow-control credits, and accept `CAP_SESSION_MUX` in guest-ready validation. Do not refactor SDK spawn/watch yet and do not move port forwarding to this mux.
```

### Slice 3: Guest-Side Mux Accept Loop and Per-Session Dispatch

Goal:

Teach `lsb-guest` to advertise `CAP_SESSION_MUX` and dispatch mux virtual
sessions to existing operation handlers.

Files likely touched:

- `crates/lsb-guest/src/main.rs`
- `crates/lsb-proto/src/lib.rs`
- Guest tests in the same file/module

Detailed tasks:

- Advertise `CAP_SESSION_MUX` in virtio-serial `GuestReady`.
- Keep the raw `GUEST_READY` frame before switching to mux mode.
- Add a virtio-serial mux accept loop after ready.
- Dispatch each accepted virtual session to an operation handler based on its
  first existing operation frame.
- Split control handling so per-session handlers do not emit another
  `GUEST_READY`.
- Refactor non-TTY exec and watch handlers so they do not require `AsRawFd`;
  keep TTY/interactive shell out of scope.
- Implement guest-side per-session close/reset and physical EOF cleanup.

Acceptance criteria:

- Guest advertises `CAP_SESSION_MUX` only when the mux loop is active.
- Multiple virtual sessions can run handlers concurrently.
- Existing non-mux macOS/vsock behavior is unchanged.
- Interactive TTY requests are rejected or left on the existing unsupported path
  for Windows without implementing shell support.

Validation commands:

```bash
cargo fmt --all -- --check
cargo test -p lsb-guest mux
cargo test -p lsb-guest
```

Risks:

- Existing `handle_control_stream()` assumes one operation consumes one
  physical stream. The refactor must avoid changing macOS behavior.
- Raw-fd assumptions in watch cancellation need a clean virtual-session close
  path.

Copy-paste prompt:

```text
Implement only Slice 3 from PLAN.md: update `lsb-guest` to advertise `CAP_SESSION_MUX` on virtio-serial, send raw `GUEST_READY`, then switch to a mux accept loop that dispatches virtual sessions to existing exec/watch/file handlers. Refactor only what is needed so non-TTY exec and watch work over virtual sessions without `AsRawFd`. Do not implement interactive shells or port-forward mux migration.
```

### Slice 4: Refactor SDK/VM Streaming Internals to a Generic Session Abstraction

Goal:

Remove the internal `TcpStream` assumption from streaming process and watch
code while preserving public API shape.

Files likely touched:

- `crates/lsb-sdk/src/process.rs`
- `crates/lsb-sdk/src/watch.rs`
- `crates/lsb-sdk/src/runtime.rs`
- `crates/lsb-vm/src/sandbox.rs`
- `crates/lsb-platform/src/lib.rs` if the session trait belongs there

Detailed tasks:

- Define an internal session abstraction for `Read + Write + Send + close/reset`.
- Implement it for macOS `TcpStream` and Windows mux virtual sessions.
- Change `spawn_process_threads()` and `spawn_watch_thread()` to take the
  generic session type.
- Change runtime actor replies from `TcpStream` to the internal session type.
- Keep public `ProcessHandle`, `WatchHandle`, Node API, CLI behavior, and
  existing macOS behavior stable.
- Add in-memory session tests for process stdout/stderr/exit and watch events.

Acceptance criteria:

- No public API signatures change.
- Existing macOS streaming tests still use the same behavior.
- Windows code can return a mux virtual session without pretending it is a
  `TcpStream`.

Validation commands:

```bash
cargo fmt --all -- --check
cargo test -p lsb-sdk process
cargo test -p lsb-sdk watch
cargo test -p lsb-vm open_exec
```

Risks:

- Public Rust types may expose concrete receiver choices. Avoid end-to-end
  public stream changes in this slice.
- Session close semantics can diverge between `TcpStream` and mux sessions if
  not tested.

Copy-paste prompt:

```text
Implement only Slice 4 from PLAN.md: refactor internal SDK/VM streaming code from concrete `TcpStream` to a private generic control-session abstraction. Preserve public Rust, Node, and CLI APIs. Add in-memory tests for process and watch frame handling. Do not enable Windows spawn/watch behavior yet except where needed for compilation.
```

### Slice 5: Enable Windows `sandbox.spawn()`

Goal:

Turn on Windows streaming process support over mux virtual exec sessions.

Files likely touched:

- `crates/lsb-vm/src/sandbox.rs`
- `crates/lsb-sdk/src/runtime.rs`
- `crates/lsb-sdk/src/process.rs`
- `bindings/nodejs/src/*` only if existing platform gating needs adjustment
- `bindings/nodejs/test/streaming.spec.ts`

Detailed tasks:

- Change Windows `open_exec` to require `CAP_SESSION_MUX` and open a mux
  virtual exec session.
- Send the existing `EXEC_REQ` with `tty=false`.
- Support stdout, stderr, exit, stdin writes, and kill using existing frames.
- Add large-output and concurrent-spawn coverage to catch starvation and frame
  interleaving bugs.
- Update Node tests so Windows uses the positive spawn path when the runtime is
  available.
- Preserve precise capability errors when mux is absent.

Acceptance criteria:

- Windows `sandbox.spawn()` supports stdout, stderr, non-zero exit, cwd, stdin,
  kill, and concurrent processes.
- One large-output process does not starve kill or another process.
- Public API remains unchanged.

Validation commands:

```bash
cargo fmt --all -- --check
cargo test -p lsb-sdk spawn
cd bindings/nodejs && corepack yarn test
./scripts/win-gh-test unit
./scripts/win-gh-test smoke
```

Risks:

- Guest child stdout threads can block under backpressure; tests must prove kill
  and exit still make progress.
- Node tests may need runtime gating so hosted CI without WHPX still skips real
  VM paths cleanly.

Copy-paste prompt:

```text
Implement only Slice 5 from PLAN.md: enable Windows `sandbox.spawn()` over mux virtual exec sessions using existing `EXEC_REQ`, `STDOUT`, `STDERR`, `STDIN`, `EXIT`, and `KILL` frames. Preserve public APIs and keep interactive shells out of scope. Add/update Rust and Node tests for stdout/stderr/exit/cwd/stdin/kill/concurrent processes and large-output fairness.
```

### Slice 6: Enable Guest-Side `watch()` Over Mux for Normal Guest Paths

Goal:

Support Windows `sandbox.watch()` for non-SMB guest paths using guest inotify
over mux sessions.

Files likely touched:

- `crates/lsb-vm/src/sandbox.rs`
- `crates/lsb-sdk/src/watch.rs`
- `crates/lsb-sdk/src/runtime.rs`
- `crates/lsb-guest/src/main.rs`
- `bindings/nodejs/test/streaming.spec.ts`

Detailed tasks:

- Resolve watch paths that are not inside direct SMB mounts to guest-side watch.
- Open a mux watch session and send the existing `WATCH_REQ`.
- Ensure `handle_watch()` exits when the virtual session is closed/reset.
- Preserve event strings expected by Node tests: create, modify, rename,
  delete.
- Add tests for recursive subdirectories and watch coexisting with spawn.

Acceptance criteria:

- Windows watch on `/tmp` or an overlay/import path reports create, modify,
  rename, delete, and recursive events.
- A watch session and a spawn session can run concurrently without frame
  corruption or starvation.
- Dropping the watch handle stops guest resources.

Validation commands:

```bash
cargo fmt --all -- --check
cargo test -p lsb-sdk watch
cd bindings/nodejs && corepack yarn test
./scripts/win-gh-test smoke
```

Risks:

- Recursive inotify setup is racy for newly-created directories; preserve
  existing behavior and document limitations rather than expanding semantics.
- Watch cancellation previously used a raw fd poll; virtual sessions need a
  reliable close signal.

Copy-paste prompt:

```text
Implement only Slice 6 from PLAN.md: enable Windows `sandbox.watch()` for normal guest paths over mux virtual watch sessions using existing `WATCH_REQ` and `WATCH_EVENT` frames. Include recursive watch and spawn-coexistence tests. Do not implement SMB direct-mount host watcher in this slice, and do not change public APIs.
```

### Slice 7: Add SMB Direct-Mount Watch Semantics for Live Host-Backed Paths

Goal:

Make `sandbox.watch()` on Windows direct SMB/CIFS mounts observe live
host-backed changes deterministically.

Files likely touched:

- `crates/lsb-vm/src/sandbox.rs`
- `crates/lsb-platform/src/windows_x86_64/fs/mount_plan.rs`
- `crates/lsb-platform/src/windows_x86_64/fs/smb/*`
- New Windows host watcher module under `crates/lsb-platform/src/windows_x86_64/fs/`
- `crates/lsb-sdk/src/watch.rs`
- `crates/lsb-sdk/src/runtime.rs`
- `bindings/nodejs/test/streaming.spec.ts`

Detailed tasks:

- Preserve a runtime registry of direct SMB mounts: canonical host source,
  guest target, access mode, and share/resource identity needed for diagnostics.
- Resolve watch paths with longest-prefix guest target matching and strict path
  boundaries.
- For paths at or below one SMB target, watch the corresponding canonical host
  path with `ReadDirectoryChangesW` or an equivalent safe abstraction.
- Map Windows create/modify/delete/rename actions to existing `WatchEvent`
  strings and guest paths.
- Handle watcher overflow by emitting a sanitized error or resync signal through
  existing watch error handling.
- Stop host watchers before SMB cleanup.
- Add tests for host-originated and guest-originated changes, read-only direct
  mount behavior, path mapping, and no arbitrary host path exposure.

Acceptance criteria:

- Watching a direct SMB mount path reports host-created, host-modified,
  host-renamed, and host-deleted files.
- Watching a direct SMB mount path reports guest-originated writes made through
  CIFS, or the implementation is blocked with runner evidence and a documented
  fallback plan.
- Read-only direct SMB watch reports host-originated changes while guest writes
  remain denied.
- Direct SMB watch does not require arbitrary `allow_net` and does not leak SMB
  credentials or share names in diagnostics.

Validation commands:

```bash
cargo fmt --all -- --check
cargo test -p lsb-platform windows_smb watch
cargo test -p lsb-sdk windows_qemu_direct_smb_mount_smoke -- --ignored --nocapture
./scripts/win-gh-test smoke
```

Risks:

- `ReadDirectoryChangesW` buffers can overflow under high churn; implementation
  must surface this and avoid silent success.
- Guest-originated SMB writes should trigger host filesystem notifications, but
  this must be proven on the self-hosted runner.
- Recursive watches that span both guest-only and direct-SMB roots may need a
  hybrid aggregator. Do not silently return partial coverage.

Copy-paste prompt:

```text
Implement only Slice 7 from PLAN.md: add Windows direct SMB/CIFS watch semantics. Resolve guest watch paths under configured direct SMB mount targets to canonical host paths, use a host-side Windows directory watcher, map events back to guest paths, and test both host-originated and guest-originated changes. Preserve SMB credential redaction, mount-only proxy policy, and cleanup ordering. Do not replace SMB/CIFS or add new public APIs.
```

### Slice 8: Windows and Node Validation Coverage

Goal:

Broaden automated and self-hosted coverage so mux, spawn, watch, and SMB direct
watch regressions are caught.

Files likely touched:

- `crates/lsb-sdk/src/runtime.rs`
- `crates/lsb-vm/src/sandbox.rs` tests
- `bindings/nodejs/test/streaming.spec.ts`
- `.github/workflows/windows-lsb-hardware.yml` only if explicitly needed and
  without adding automatic pull request triggers
- `scripts/windows-smoke.ps1` if smoke orchestration needs new cases

Detailed tasks:

- Add Rust unit/fake tests for mux fairness and shutdown if not already covered
  by prior slices.
- Add ignored WHPX smoke tests for Windows spawn and watch.
- Extend direct SMB smoke to include watch events in both directions.
- Update Node streaming tests to run positive Windows spawn/watch paths when
  runtime assets and WHPX are available.
- Keep hosted Windows compile/unit/golden tests free of WHPX assumptions.
- Ensure diagnostics bundles include only redacted, allowlisted text artifacts.

Acceptance criteria:

- `./scripts/win-gh-test unit` exercises platform-independent coverage.
- `./scripts/win-gh-test smoke` exercises real Windows spawn, guest watch, SMB
  direct watch, and network-policy regression paths.
- Node tests clearly skip only when runtime prerequisites are absent, not
  because Windows lacks feature support.

Validation commands:

```bash
cargo fmt --all -- --check
cargo test --workspace
cd bindings/nodejs && corepack yarn test
./scripts/win-gh-test check
./scripts/win-gh-test unit
./scripts/win-gh-test smoke
```

Risks:

- The hardware workflow requires a clean committed branch; future agents must
  commit before dispatching it.
- Elevated SMB requirements can make local reproduction harder; diagnostics
  must stay actionable.

Copy-paste prompt:

```text
Implement only Slice 8 from PLAN.md: add and wire validation coverage for Windows mux, spawn, guest watch, and SMB direct watch. Keep hosted Windows tests WHPX-free, use self-hosted WHPX smoke for runtime behavior, and do not add automatic pull_request triggers for the Windows hardware runner. Do not implement feature logic beyond test orchestration gaps found while adding coverage.
```

### Slice 9: Docs and Diagnostics Update

Goal:

Update durable Windows docs and diagnostics after the implementation lands.

Files likely touched:

- `docs/windows-port/README.md`
- `docs/windows-port/mvp-handoff.md`
- `docs/windows-port/decisions.md` only if a new accepted decision is needed
- `docs/windows-port/future-work.md`
- `docs/windows-port/security-checklist.md`
- `docs/windows-port/diagnostics.md`
- `bindings/nodejs/README.md`

Detailed tasks:

- Document `CAP_SESSION_MUX`, single physical control owner, and Windows
  spawn/watch support.
- Move streaming spawn and watch out of the macOS-only limitation text in the
  Node README after tests pass.
- Document direct SMB watch semantics, including host-originated and
  guest-originated coverage results.
- Add diagnostics guidance for mux session hangs, backpressure, watcher
  overflow, and SMB watch failures.
- Preserve security checklist rules for SMB secrets, pipe privacy, no default
  NIC, no QEMU user networking, and redacted protocol traces.
- Add or update decisions only if implementation deviates from this plan or
  changes accepted architecture.

Acceptance criteria:

- Durable docs match implemented behavior and limitations.
- User-facing docs no longer claim Windows spawn/watch are unsupported once
  they pass validation.
- Diagnostics tell maintainers what evidence to collect without exposing
  secrets or raw payloads.

Validation commands:

```bash
cargo fmt --all -- --check
make docs
./scripts/win-gh-test smoke
```

Risks:

- Updating docs before validation can overpromise Windows support.
- Adding a decision without maintainer review violates `decisions.md` process.

Copy-paste prompt:

```text
Implement only Slice 9 from PLAN.md: update durable Windows and Node documentation after mux, spawn, watch, and SMB direct watch have landed and passed validation. Document the final behavior, limitations, diagnostics, and security notes. Do not change code behavior in this slice unless a docs test requires a small metadata fix, and do not add a new Windows decision unless the maintainer has accepted a design change.
```
