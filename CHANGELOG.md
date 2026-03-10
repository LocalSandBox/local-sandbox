# Changelog

## 0.4.0

### Streaming spawn, kill, and file watching

Full streaming I/O across the guest, CLI, and SDK - spawn long-running processes, stream stdout/stderr in real-time, kill processes, write to stdin, and watch files for changes.

#### Guest (`shuru-guest` 0.2.0)

- Streaming piped exec: dedicated threads for stdout, stderr, and stdin relay with mpsc channel for frame serialization (no interleaved writes)
- `cwd` support in both piped and TTY exec modes
- Guest-side file watching via raw `libc::inotify` with recursive directory traversal, auto-watching new subdirectories, and `poll(2)` for clean shutdown on vsock hangup
- New frame types: `KILL`, `WATCH_REQ`, `WATCH_EVENT`

#### CLI (`shuru-cli` 0.4.0)

- Rewrote `stdio.rs` from synchronous request-response to concurrent multiplexed architecture
- Main thread reads stdin JSON-RPC, dedicated event thread writes notifications to stdout
- Per-process std::threads relay vsock frames as JSON-RPC `output`/`exit` notifications
- New methods: `spawn` (returns pid, streams in background), `kill`, `input` (stdin forwarding), `watch` (file change events)
- `SharedWriter` (`Arc<Mutex<Stdout>>`) for thread-safe output from multiple process threads
- `ProcessHandle` with `mpsc::Sender<ProcessInput>` for stdin/kill forwarding to the correct vsock connection
- Backward-compatible: `exec`, `read_file`, `write_file`, `checkpoint` unchanged

#### Protocol (`shuru-proto` 0.2.0)

- Added `KILL` (0x07), `WATCH_REQ` (0x30), `WATCH_EVENT` (0x31) frame types
- Added `cwd` field to `ExecRequest` (backward-compatible `Option`)
- Added `WatchRequest` and `WatchEvent` types

#### VM (`shuru-vm` 0.2.0)

- `open_exec()`: connect vsock for streaming, returns raw `TcpStream` for caller-managed I/O
- `open_watch()`: connect vsock for file watching, returns stream emitting `WATCH_EVENT` frames

#### SDK (`@superhq/shuru` 0.3.0)

- `sandbox.spawn(command, opts?)` — real-time stdout/stderr streaming via `SandboxProcess` handle
- `sandbox.watch(path, handler, opts?)` — guest-side inotify file change events
- `SandboxProcess`: `.on("stdout" | "stderr" | "exit")`, `.write()`, `.kill()`, `.exited`, `.pid`
- `SpawnOptions` (`cwd`, `env`), `WatchOptions` (`recursive`), `FileChangeEvent` type
- JSON-RPC notification dispatch for `output`, `exit`, `file_change` in `ShuruProcess`
- Unit tests (13) with mock shuru binary: spawn streaming, kill, watch, concurrent operations
- Integration tests (12) against real VM: streaming, stdin, kill, file creation/modification/deletion, recursive watch, concurrent watch+spawn

## 0.3.3

- Added `--secret` and `--allow-host` CLI flags for inline proxy config (no `shuru.json` required)
- Replaced `shuru.epoch` cmdline hack with proper PL031 RTC, now, the kernel sets wall clock at boot automatically
- Added `libatomic1` to rootfs
- SDK: `secrets` and `network` options now map to CLI flags directly (no temp config files)

## 0.3.2

- Fixed proxy corrupting large HTTP responses (e.g. `apt-get update`) due to dropped bytes when smoltcp TX buffer was full

## 0.3.1

- Fixed TLS certificate validation failures by syncing guest clock from host via kernel cmdline

## 0.3.0

### Custom minimal kernel, faster boot

Boot time reduced from ~5s to ~1s by replacing the Debian cloud kernel with a custom minimal Linux 6.12.x kernel.

- Custom kernel built from `kernel/shuru_defconfig` with all VirtIO drivers built-in (~8MB, no loadable modules)
- Simplified initramfs with no module loading, no DHCP, no /dev/vda polling
- Quiet boot by default, use `--verbose` to see kernel output

### Proxy-based networking

All guest network traffic now flows through a userspace proxy on the host. No NAT device, no direct internet access.

- Domain allowlists via `shuru.json`
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

1. Run `shuru upgrade` to get the new CLI and OS image.
2. Recreate any checkpoints using `apt-get` instead of `apk`:

```bash
# Before (Alpine)
shuru checkpoint create myenv --allow-net -- apk add nodejs npm

# After (Debian)
shuru checkpoint create myenv --allow-net -- apt-get install -y nodejs npm
```

3. Existing Alpine checkpoints will continue to boot (same kernel architecture, same init path), but new VMs start from Debian.
