# Changelog

## 0.3.0 (2026-03-11)

### Added

- **`sandbox.spawn(command, opts?)`** — stream stdout/stderr in real-time from long-running processes. Returns a `SandboxProcess` handle with `.on("stdout" | "stderr" | "exit")`, `.write()`, `.kill()`, `.exited`, and `.pid`.
- **`sandbox.watch(path, handler, opts?)`** — watch directories for file changes inside the guest VM using guest-side inotify. Detects creates, modifications, deletions, and renames. Recursive by default.
- **`SandboxProcess.write(data)`** — write to a spawned process's stdin.
- **`SandboxProcess.kill()`** — terminate a spawned process.
- **`SpawnOptions`** — `cwd` and `env` options for `spawn()`.
- **`WatchOptions`** — `recursive` option for `watch()`.
- **`FileChangeEvent`** type — `{ path, event }` where event is `"create" | "modify" | "delete" | "rename"`.
- Concurrent operations — multiple `spawn()`, `exec()`, and `watch()` calls run in parallel within the same VM.
- Unit tests for spawn, kill, watch, and concurrent operations (mock-based).
- Integration tests for streaming exec, kill, stdin, and file watching against a real VM.

### Changed

- Internal `ShuruProcess` now dispatches JSON-RPC notifications (`output`, `exit`, `file_change`) to registered handlers, enabling multiplexed streaming from multiple processes.

## 0.2.0

### Added

- `secrets` option — inject secrets via MITM proxy with per-host scoping.
- `network.allow` option — restrict guest network access by domain.
- `ports` option — port forwarding (`"host:guest"`).
- `mounts` option — bind-mount host directories into the guest.

## 0.1.0

### Added

- Initial release.
- `Sandbox.start()` / `.stop()` — boot and teardown microVMs.
- `sandbox.exec(command)` — buffered command execution.
- `sandbox.readFile(path)` / `sandbox.writeFile(path, content)` — guest file I/O.
- `sandbox.checkpoint(name)` — save disk state for later restoration.
