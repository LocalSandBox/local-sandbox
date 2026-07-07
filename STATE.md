# Future-Agent State: Windows Session Mux, Spawn Streaming, and Watch

## Current Status

Design-only. No Rust, TypeScript, TOML, lockfile, generated, test, or workflow
implementation changes have been made in this handoff.

Only `PLAN.md` and `STATE.md` were created for future implementation agents.

## Assumptions

- Windows remains QEMU/WHPX on Windows 11 x64.
- Windows control remains the existing virtio-serial control port backed by a
  private QEMU Windows pipe.
- Port forwarding remains on the existing dedicated virtio-serial forwarding
  channel and is not migrated to the new mux.
- Interactive shells remain out of scope.
- Public CLI, Rust SDK, and Node API shape should not change for this work.
- Existing operation frames are preserved where possible:
  `EXEC_REQ`, `STDOUT`, `STDERR`, `STDIN`, `EXIT`, `KILL`, `WATCH_REQ`,
  `WATCH_EVENT`, and `ERROR`.
- Direct Windows mounts continue to use the accepted SMB/CIFS implementation.
- Future implementation agents can modify code and tests per their assigned
  slice, but this design agent did not.

## Discovered Repo Facts

- `AGENTS.md` defines repo working agreements, standard Rust/Node commands,
  Windows hardware testing commands, and the instruction to ask for
  clarification when key architecture is underspecified.
- `docs/windows-port/README.md` says the current Windows MVP uses QEMU/WHPX,
  virtio-serial control, non-interactive exec, file transfer, staged mount
  imports, SMB/CIFS direct mounts, dedicated virtio-serial port forwarding,
  proxy networking, and checkpoints. It also says streaming `spawn()` and
  `watch()` are not yet Windows features.
- `docs/windows-port/rfc-qemu-whpx.md` anticipated a transport-internal
  virtio-serial mux with unchanged `lsb-proto` payloads nested inside sessions.
  It also listed backpressure, cancellation, and concurrent sessions as mux
  risks to validate.
- `docs/windows-port/mvp-handoff.md` lists intentional limitations: no
  streaming `spawn`/kill, no `watch`, and no general mux/session model. It says
  future work must define mux/session before enabling those features.
- `docs/windows-port/decisions.md` accepts QEMU/WHPX only, virtio-serial
  LocalSandbox control, stable public APIs, no default guest NIC, no QEMU user
  networking, strict egress policy, guest code as untrusted, and SMB/CIFS for
  Windows direct mounts.
- `docs/windows-port/future-work.md` explicitly calls for a mux/session model
  before streaming spawn, shell, kill, file watch, or concurrent port-forward
  sessions. This handoff intentionally excludes shell and port-forward mux
  migration.
- `docs/windows-port/security-checklist.md` requires private control endpoints,
  no secrets in logs/diagnostics, minimal host file exposure, no network
  expansion, and SMB direct-mount credential cleanup/redaction.
- `docs/windows-port/diagnostics.md` defines current boot readiness as a valid
  raw `GUEST_READY` frame over virtio-serial and records that port forwarding
  uses the dedicated `org.localsandbox.forward` virtio-serial port.
- `bindings/nodejs/README.md` exposes public `spawn()` and `watch()` examples,
  but currently documents both as macOS-only on Windows.
- `bindings/nodejs/test/streaming.spec.ts` already describes desired positive
  behavior for streaming stdout/stderr/exit, stdin writes, kill, concurrent
  processes, recursive watch events, and watch coexisting with spawn.
- `crates/lsb-proto/src/frame.rs` defines the current frame header, operation
  frame constants, `MAX_FRAME_LEN`, `write_frame`, `read_frame`, and
  `try_parse`.
- `crates/lsb-proto/src/lib.rs` defines `PROTOCOL_VERSION`, current
  capabilities (`file_range_io`, `port_forward`, `cifs_mount`), `GuestReady`,
  `ExecRequest`, `WatchRequest`, `WatchEvent`, and the virtio-serial control
  and forward port names.
- `crates/lsb-vm/src/sandbox.rs` serializes current Windows control operations
  with `control_session: Mutex<()>`, uses `with_guest_control_session()` for
  non-streaming operations, returns unsupported errors for Windows streaming
  exec, and assumes vsock for `open_watch()`.
- `crates/lsb-vm/src/sandbox.rs` also stores Windows SMB mount plan/resources,
  sends SMB mount requests with redaction, syncs before cleanup, and verifies
  direct SMB smoke behavior in ignored Windows tests.
- `crates/lsb-sdk/src/process.rs`, `crates/lsb-sdk/src/watch.rs`, and
  `crates/lsb-sdk/src/runtime.rs` use `TcpStream` for streaming process and
  watch internals today.
- `crates/lsb-guest/src/main.rs` sends `GUEST_READY` on virtio-serial, then
  handles one operation per physical stream. `handle_piped_exec()` and
  `handle_watch()` consume the stream and return. Guest watch uses Linux
  inotify.
- `crates/lsb-platform/src/windows_x86_64/qemu/boot.rs` opens the control pipe
  during QEMU boot and reads the raw `GUEST_READY` frame. Later
  `open_control()` clones the established stream, which is acceptable for the
  current serialized design but incompatible with concurrent independent
  readers after mux.
- `crates/lsb-platform/src/windows_x86_64/qemu/argv.rs` adds the
  `virtio-serial-pci` controller and private pipe chardevs when control or
  forwarding is configured. Tests assert no `hostfwd` and no default `-netdev`.
- `crates/lsb-platform/src/windows_x86_64/control/virtio_serial.rs` generates
  private pipe names and redacts pipe details in errors.
- `crates/lsb-platform/src/windows_x86_64/fs/mount_plan.rs` maps Windows
  overlay mounts to copy/import plans and direct mounts to SMB/CIFS
  `WindowsSmbMount` entries. Direct flags are limited to `0` and `MS_RDONLY`.
- `crates/lsb-platform/src/windows_x86_64/fs/smb/*` creates ephemeral SMB
  users, passwords, shares, ACL grants, mount requests, and non-secret cleanup
  manifests. Password display/debug formatting is redacted.
- `crates/lsb-sdk/src/runtime.rs` attaches a mount-only SMB proxy for direct SMB
  mounts when `allow_net` is false and tests that arbitrary outbound traffic is
  denied.

External platform facts used:

- Microsoft `ReadDirectoryChangesW` can watch a directory or subtree and
  returns detailed change records, with documented overflow/error cases.
- Linux inotify does not catch remote changes on network filesystems, so CIFS
  host-originated changes should not rely solely on guest inotify.
- QEMU documents Windows `-chardev pipe` as a single duplex pipe.

## Accepted Design Decisions

- Add `CAP_SESSION_MUX`.
- Keep the initial virtio-serial readiness handshake as a raw `GUEST_READY`
  frame. Switch the same physical stream to mux mode only after capability
  negotiation succeeds.
- Add an LSB-owned mux below existing operation frames. Mux `DATA` carries
  ordinary `lsb-proto` frame bytes for one virtual session.
- Reserve session id `0`; use odd host-opened session ids and reserve even
  guest-opened ids for future use.
- Use bounded per-session queues, receive credit, `WINDOW` updates, and fair
  physical write scheduling.
- Ensure exactly one physical reader and writer own the Windows virtio-serial
  control pipe in mux mode.
- Route Windows control operations through virtual sessions after mux
  negotiation. Do not mix mux mode with cloned physical-pipe readers.
- Refactor SDK/VM internals from `TcpStream` to a private session abstraction
  without changing public APIs.
- Enable Windows `spawn()` over mux before enabling Windows `watch()`.
- Use guest inotify over mux for normal guest paths and overlay/import paths.
- Use a host-side Windows watcher for direct SMB/CIFS mount paths, mapped from
  guest target to canonical host source, because this is more deterministic for
  host-originated changes than Linux CIFS inotify.
- Test and document both host-originated and guest-originated direct SMB watch
  behavior.
- Keep interactive shells, port-forward mux migration, alternative transports,
  and public API changes out of scope.

## Unresolved Questions

- Exact numeric values for new mux frame types should be chosen during Slice 1
  to avoid collisions and leave room for future protocol growth.
- Exact default flow-control constants need implementation benchmarking. The
  design recommends small `MUX_DATA` chunks such as 64 KiB and bounded
  per-session buffers, but does not mandate final byte counts.
- Whether to implement the Windows host watcher directly with
  `ReadDirectoryChangesW` or through a vetted Rust crate remains an
  implementation choice.
- Direct SMB guest-originated writes are expected to trigger host filesystem
  notifications because writes materialize on the host source, but this must be
  proven on the self-hosted Windows runner.
- Recursive watch requests whose root is an ancestor of one or more direct SMB
  mount targets need either a hybrid guest+host aggregator or a precise
  unsupported error. The first direct-SMB watch implementation may target paths
  at or below one SMB mount target.
- Existing public Rust process/watch receivers may remain unbounded. The mux
  must still have bounded internal queues and fair scheduling. Any public API
  change for fully end-to-end bounded streams needs separate approval.

## Slice Status

| Slice | Status | Notes |
|---|---|---|
| 1. Protocol and session mux primitives | Pending | Design only. |
| 2. Host-side Windows mux manager over virtio-serial | Pending | Design only. |
| 3. Guest-side mux accept loop and per-session dispatch | Pending | Design only. |
| 4. Refactor SDK/VM streaming internals from `TcpStream` | Pending | Design only. |
| 5. Enable Windows `sandbox.spawn()` | Pending | Design only. |
| 6. Enable guest-side `watch()` over mux for normal paths | Pending | Design only. |
| 7. Add SMB direct-mount watch semantics | Pending | Design only. |
| 8. Windows and Node validation coverage | Pending | Design only. |
| 9. Docs/diagnostics update | Pending | Design only. |

## Validation Not Yet Run

No validation commands were run for this handoff because it only creates design
documents.

Future implementation agents should run the commands listed in `PLAN.md` for
their slice. Runtime Windows behavior needs `./scripts/win-gh-test smoke` from
a clean committed branch.

## Do Not Redo

- Do not re-open the transport choice for this work. AF_VSOCK, Hyper-V sockets,
  QGA, QMP, hostfwd, QEMU user networking, TAP, bridge, NAT, and replacement
  transports are out of scope.
- Do not migrate port forwarding to the mux in these slices. It remains on the
  dedicated virtio-serial forward channel.
- Do not implement interactive shells as part of spawn/watch support.
- Do not add Windows-only public APIs unless a future design explicitly asks
  for approval and records why existing APIs are insufficient.
- Do not put session ids into existing operation frames unless the mux nesting
  design is proven impossible.
- Do not create multiple independent readers on the Windows physical control
  pipe after mux negotiation.
- Do not rely solely on Linux CIFS/inotify for direct SMB host-originated watch
  semantics.
- Do not log SMB passwords, proxy secrets, raw mux payloads, full guest env, or
  unredacted QEMU argv.
- Do not broaden network policy. Direct SMB watch must not imply arbitrary
  `allow_net`.
- Do not add automatic `pull_request` triggers for the self-hosted Windows
  hardware runner.
