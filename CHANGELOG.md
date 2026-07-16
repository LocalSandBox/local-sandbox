# Changelog

> Historical note: JavaScript and TypeScript support now ships from [`bindings/nodejs`](bindings/nodejs) as `@local-sandbox/lsb-nodejs`. Older `@superhq/lsb` entries below describe archived SDK releases.

## Unreleased

- Added opt-in HTTPS HTTP/1.1 request-header interception across `lsb.json`,
  the Rust SDK, and the Node.js binding, including caller-supplied User-Agent
  values and SNI-based allow/deny scopes. The feature remains off by default;
  non-applicable destinations retain blind TLS tunnelling.
- Replaced chunk-local secret substitution with a bounded framing-aware
  HTTP/1.1 transformer. Split placeholders, keep-alive and pipelined requests,
  fixed and chunked bodies, trailers, `100 Continue`, and accepted upgrades are
  handled without stale request lengths or chunk sizes.
- Added matched macOS and Windows User-Agent injection benchmark harnesses that
  retain JSONL samples, per-run logs, and schema-compatible summary JSON.
- Added optional per-invocation progress callbacks to the backward-compatible Node.js
  `initSandbox()` API, including initialization phases and throttled compressed-byte counters for
  runtime assets and Windows managed host tools.
- Added `lsb init --fix` and the Rust/Node initialization `fix` option to apply
  all available automatic host configuration repairs, including the Windows
  direct SMB mount policy repair.
- Added a bounded, content-addressed Windows overlay mount cache under
  `%LOCALAPPDATA%\lsb\mount-cache\v1`. Cache images are atomically published,
  validated before every read-only hit, invalidated by content rather than
  timestamps, and can be removed explicitly with `lsb prune --mount-cache`.

## 0.4.0

### Windows 11 x64 backend and Node package MVP

- Added a native Windows 11 x64 backend using QEMU with WHPX to boot the existing
  Linux guest model.
- Added Windows support for sandbox start/stop, non-interactive exec, guest file
  APIs, overlay mount import, SMB/CIFS direct mounts, loopback port forwarding,
  policy-mediated proxy networking, qcow2 checkpoint save/restore, streaming
  `spawn()` with stdin/kill, guest file `watch()`, and direct SMB host-backed
  `watch()`.
- Added the Windows virtio-serial session mux for concurrent exec, file,
  mount-init, streaming spawn, and guest watch control sessions.
- Added the `@local-sandbox/lsb-nodejs-win32-x64-msvc` native package target for
  `@local-sandbox/lsb-nodejs`.
- Windows production runs require WHPX. TCG fallback, QEMU user networking,
  `hostfwd`, TAP/bridge networking, interactive shells/PTTY, CAS/NBD checkpoint
  transport, and Windows ARM64 remain unsupported in this MVP. Windows users
  install managed QEMU host tools with `lsb init`.

### CLI (`lsb-cli` 0.4.0)

- Fixed `--allow-net` having no effect in `--stdio` mode. Proxy networking now works via the SDK.
- Secret environment variables are now injected into exec/spawn calls in stdio mode
- CA certificate installation for MITM proxying in stdio mode

### SDK (`@superhq/lsb` 0.3.1)

- `exec()` and `spawn()` now accept `string | string[]`. Array form passes argv directly with no shell interpretation.
- Added `shell` option to `ExecOptions` and `SpawnOptions` to override the default shell (e.g. `/bin/bash` instead of `sh`)
- New exported type: `ExecOptions`

### Streaming spawn, kill, and file watching

Full streaming I/O across the guest, CLI, and SDK - spawn long-running processes, stream stdout/stderr in real-time, kill processes, write to stdin, and watch files for changes.

#### Guest (`lsb-guest` 0.2.0)

- Streaming piped exec: dedicated threads for stdout, stderr, and stdin relay with mpsc channel for frame serialization (no interleaved writes)
- `cwd` support in both piped and TTY exec modes
- Guest-side file watching via raw `libc::inotify` with recursive directory traversal, auto-watching new subdirectories, and `poll(2)` for clean shutdown on vsock hangup
- New frame types: `KILL`, `WATCH_REQ`, `WATCH_EVENT`

#### CLI (`lsb-cli` 0.4.0)

- Rewrote `stdio.rs` from synchronous request-response to concurrent multiplexed architecture
- Main thread reads stdin JSON-RPC, dedicated event thread writes notifications to stdout
- Per-process std::threads relay vsock frames as JSON-RPC `output`/`exit` notifications
- New methods: `spawn` (returns pid, streams in background), `kill`, `input` (stdin forwarding), `watch` (file change events)
- `SharedWriter` (`Arc<Mutex<Stdout>>`) for thread-safe output from multiple process threads
- `ProcessHandle` with `mpsc::Sender<ProcessInput>` for stdin/kill forwarding to the correct vsock connection
- Backward-compatible: `exec`, `read_file`, `write_file`, `checkpoint` unchanged

#### Protocol (`lsb-proto` 0.2.0)

- Added `KILL` (0x07), `WATCH_REQ` (0x30), `WATCH_EVENT` (0x31) frame types
- Added `cwd` field to `ExecRequest` (backward-compatible `Option`)
- Added `WatchRequest` and `WatchEvent` types

#### VM (`lsb-vm` 0.2.0)

- `open_exec()`: connect vsock for streaming, returns raw `TcpStream` for caller-managed I/O
- `open_watch()`: connect vsock for file watching, returns stream emitting `WATCH_EVENT` frames

#### SDK (`@superhq/lsb` 0.3.0)

- `sandbox.spawn(command, opts?)` — real-time stdout/stderr streaming via `SandboxProcess` handle
- `sandbox.watch(path, handler, opts?)` — guest-side inotify file change events
- `SandboxProcess`: `.on("stdout" | "stderr" | "exit")`, `.write()`, `.kill()`, `.exited`, `.pid`
- `SpawnOptions` (`cwd`, `env`), `WatchOptions` (`recursive`), `FileChangeEvent` type
- JSON-RPC notification dispatch for `output`, `exit`, `file_change` in `lsbProcess`
- Unit tests (13) with mock lsb binary: spawn streaming, kill, watch, concurrent operations
- Integration tests (12) against real VM: streaming, stdin, kill, file creation/modification/deletion, recursive watch, concurrent watch+spawn

## 0.3.3

- Added `--secret` and `--allow-host` CLI flags for inline proxy config (no `lsb.json` required)
- Replaced `lsb.epoch` cmdline hack with proper PL031 RTC, now, the kernel sets wall clock at boot automatically
- Added `libatomic1` to rootfs
- SDK: `secrets` and `network` options now map to CLI flags directly (no temp config files)

## 0.3.2

- Fixed proxy corrupting large HTTP responses (e.g. `apt-get update`) due to dropped bytes when smoltcp TX buffer was full

## 0.3.1

- Fixed TLS certificate validation failures by syncing guest clock from host via kernel cmdline

## 0.3.0

### Custom minimal kernel, faster boot

Boot time reduced from ~5s to ~1s by replacing the Debian cloud kernel with a custom minimal Linux 6.12.x kernel.

- Custom kernel built from `kernel/lsb_defconfig` with all VirtIO drivers built-in (~8MB, no loadable modules)
- Simplified initramfs with no module loading, no DHCP, no /dev/vda polling
- Quiet boot by default, use `--verbose` to see kernel output

### Proxy-based networking

All guest network traffic now flows through a userspace proxy on the host. No NAT device, no direct internet access.

- Domain allowlists via `lsb.json`
- Secret injection: API keys stay on host, placeholder tokens swapped at proxy
- MITM TLS only when secrets need to be injected; blind-tunneled otherwise
- Fixed placeholder token collision with atomic counter
- Instance directory cleanup on error and PID reuse

**Note:** Existing checkpoints created with 0.2.x will continue to work.

## 0.2.0

### Breaking: Guest OS migrated from Alpine Linux to Debian

The guest VM now runs **Debian 13 (trixie)** instead of Alpine Linux 3.21. This is a breaking change for existing checkpoints and workflows that use `apk`.

**Why:** Alpine's musl libc is incompatible with many tools that assume glibc (e.g., Claude Code, VS Code server, many pre-built binaries). Debian's glibc resolves this and aligns with the standard environment developers expect.

**What changed:**

- **Package manager:** `apk add` -> `apt-get install -y`
- **Package names:** Some differ between Alpine and Debian (e.g., `build-base` → `build-essential`, `py3-pip` → `python3-pip`)
- **Kernel:** Alpine `linux-virt` -> Debian `linux-image-cloud-arm64`
- **Pre-installed tools:** `curl`, `git`, `jq`, `less`, `procps`, `openssh-client`, `iproute2`, `xz-utils`

**Migration guide:**

1. Run `lsb upgrade` to get the new CLI and OS image.
2. Recreate any checkpoints using `apt-get` instead of `apk`:

```bash
# Before (Alpine)
lsb checkpoint create myenv --allow-net -- apk add nodejs npm

# After (Debian)
lsb checkpoint create myenv --allow-net -- apt-get install -y nodejs npm
```

3. Existing Alpine checkpoints will continue to boot (same kernel architecture, same init path), but new VMs start from Debian.
