---
name: lsb
description: Run commands in an isolated Linux microVM sandbox using the lsb CLI. Use when the user asks to execute untrusted code, install packages safely, test in a clean environment, or needs Linux-specific tooling on supported macOS or Windows hosts.
---

# Sandboxed Execution with lsb

lsb boots an ephemeral Debian Linux microVM on supported macOS hosts and Windows 11 x64. Each `lsb run` gets a fresh disk clone - all changes are discarded on exit. Use it whenever you need to run commands in isolation from the host.

## Core Workflow

The pattern is: **run in sandbox, mount to share files, checkpoint to persist state**.

```bash
# 1. Run a command in a fresh VM
lsb run -- echo "hello from the sandbox"

# 2. Mount the project directory so the VM can access host files
lsb run --mount ./src:/workspace -- ls /workspace

# 3. If the command needs network access (install packages, fetch data)
lsb run --allow-net -- sh -c 'apt-get install -y curl && curl https://example.com'

# 4. If setup is expensive, save a checkpoint and reuse it
lsb checkpoint create node-env --allow-net -- apt-get install -y nodejs npm
lsb run --from node-env --mount .:/workspace -- node /workspace/app.js
```

## Command Chaining

Chain commands with `sh -c` when you need multiple steps:

```bash
lsb run --allow-net -- sh -c 'apt-get install -y python3 python3-pip && python3 -c "print(1+1)"'

lsb run --mount .:/workspace -- sh -c 'cd /workspace && ls -la && cat README.md'
```

## Essential Commands

### Run

```bash
lsb run [flags] [-- command...]

# Interactive shell (macOS; on Windows prefer non-interactive command form)
lsb run

# Run a single command
lsb run -- whoami

# With resources
lsb run --cpus 4 --memory 4096 --disk-size 8192 -- make -j4

# With networking + port forwarding
lsb run --allow-net -p 8080:80 -- nginx -g 'daemon off;'

# Multiple mounts
lsb run --mount ./src:/src --mount ./data:/data -- ls /src /data

# From a checkpoint
lsb run --from myenv -- npm test
```

### Checkpoints

```bash
# Create: boots VM, runs command, saves disk on exit
lsb checkpoint create <name> [flags] [-- command...]

# Stack: create from an existing checkpoint
lsb checkpoint create with-deps --from base-env --allow-net -- npm install

# List all checkpoints (shows actual disk usage)
lsb checkpoint list

# Delete
lsb checkpoint delete <name>
```

Checkpoint names must be unique - delete the old one before re-creating with the same name.

### Other Commands

```bash
# Download/update OS image
lsb init
lsb init --force    # re-download even if up to date

# Upgrade CLI + OS image
lsb upgrade

# Clean up leftover data from crashed VMs
lsb prune
```

## Common Patterns

### Dev Environment Setup

Create a checkpoint with all dependencies pre-installed, then use it for fast runs:

```bash
# One-time setup
lsb checkpoint create python-dev --allow-net -- sh -c 'apt-get install -y python3 python3-pip && pip install pytest requests'

# Fast subsequent runs
lsb run --from python-dev --mount .:/workspace -- sh -c 'cd /workspace && pytest'
```

### Testing Untrusted Code

Run untrusted scripts with no network access and no host filesystem access:

```bash
# Fully isolated — no --allow-net, no --mount
lsb run -- sh -c 'echo "malicious script here" && rm -rf / 2>/dev/null; echo "host is safe"'
```

### Build and Test

Mount source read-only from the host perspective and build inside the VM:

```bash
lsb run --mount .:/workspace --cpus 4 --memory 4096 -- sh -c '
  cd /workspace
  apt-get install -y build-essential
  make -j4
  make test
'
```

### Port Forwarding for Web Servers

```bash
lsb run --allow-net --from node-env -p 3000:3000 --mount .:/app -- sh -c '
  cd /app && node server.js
'
# Access at http://localhost:3000 on the host
```

### Stacking Checkpoints

Build environments incrementally:

```bash
lsb checkpoint create base --allow-net -- apt-get install -y build-essential git curl
lsb checkpoint create node --from base --allow-net -- apt-get install -y nodejs npm
lsb checkpoint create project --from node --allow-net --mount .:/app -- sh -c 'cd /app && npm install'
# Now "project" has OS deps + Node + node_modules baked in
lsb run --from project --mount .:/app -- sh -c 'cd /app && npm test'
```

## Project Config (lsb.json)

Place `lsb.json` in the project root to avoid repeating flags:

```json
{
  "cpus": 2,
  "memory": 2048,
  "disk_size": 4096,
  "allow_net": true,
  "ports": ["8080:80"],
  "mounts": ["./src:/workspace"],
  "command": ["/bin/sh", "-c", "cd /workspace && sh"],
  "secrets": {
    "API_KEY": {
      "value": "sk-your-openai-key",
      "hosts": ["api.openai.com"]
    }
  },
  "network": {
    "allow": ["api.openai.com", "registry.npmjs.org"]
  }
}
```

CLI flags override config values. When `secrets` are configured, the guest receives placeholder tokens and the proxy substitutes real values on HTTPS requests to allowed hosts. See [references/config.md](references/config.md) for all fields.

## Important Constraints

- **Networking is off by default.** You must pass `--allow-net` to install packages or make HTTP requests.
- **The guest is Debian Linux.** Use `apt-get install` for packages.
- **Ephemeral by default.** Everything is discarded on exit unless you checkpoint.
- **CLI mounts default to overlay-style.** The host source is kept read-only from the product perspective; guest writes are isolated and discarded unless saved through a checkpoint or explicit copy/export path. On Windows, no-suffix and `:ro` CLI mounts are snapshot imports and do not provide live host sync. Explicit Windows `:rw` mounts use SMB/CIFS direct sharing, require `--allow-host-writes`, and must run from an elevated Administrator shell.
- **Supported hosts:** macOS 14+ on arm64/x64 and Windows 11 x64. macOS uses Apple Virtualization.framework. Windows uses QEMU with WHPX; `lsb init` installs managed `qemu-system-x86_64.exe` and `qemu-img.exe` host tools.
- **Windows feature limits:** use non-interactive CLI commands on Windows; interactive PTY shells, CAS/NBD checkpoints, and Windows ARM64 are not supported there yet. Rust and Node SDK streaming `spawn` plus file `watch` are supported on Windows x64 through the virtio-serial session mux. Windows explicit direct mounts are SMB/CIFS-backed and require Administrator privileges. Windows x64 CLI release/install artifacts are available, and Windows users should run `lsb init` to install managed QEMU host tools and runtime assets.
- **Default resources:** 2 CPUs, 2048 MB RAM, 4096 MB disk. Override with `--cpus`, `--memory`, `--disk-size`.

## Deep-Dive Documentation

- [references/checkpoints.md](references/checkpoints.md) — checkpoint lifecycle, stacking, disk usage
- [references/config.md](references/config.md) — lsb.json fields and resolution order
- [references/networking.md](references/networking.md) — allow-net, port forwarding, proxy behavior
