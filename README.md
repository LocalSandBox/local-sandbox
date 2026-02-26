# shuru

Local-first microVM sandbox for AI agents on macOS.

Shuru boots lightweight Linux VMs using Apple's Virtualization.framework. Each sandbox is ephemeral: the rootfs resets on every run, giving agents a disposable environment to execute code, install packages, and run tools without touching your host.

## Requirements

- macOS 14 (Sonoma) or later on Apple Silicon

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/superhq-ai/shuru/main/install.sh | sh
```

## Usage

```sh
# Interactive shell
shuru run

# Run a command
shuru run -- echo hello

# With network access
shuru run --allow-net

# Custom resources
shuru run --cpus 4 --memory 4096 --disk-size 8192 -- make -j4
```

### Directory mounts

Share host directories into the VM using VirtioFS. The host directory is read-only; guest writes go to a tmpfs overlay layer (discarded when the VM exits).

```sh
# Mount a directory (guest can write, host is untouched)
shuru run --mount ./src:/workspace -- ls /workspace

# Multiple mounts
shuru run --mount ./src:/workspace --mount ./data:/data -- sh
```

Mounts can also be set in `shuru.json` (see [Config file](#config-file)).

> **Note:** Directory mounts require checkpoints created on v0.1.11+. Existing checkpoints work normally for all other features. Run `shuru upgrade` to get the latest version.

### Port forwarding

Forward host ports to guest ports over vsock. Works without `--allow-net` — the guest needs no network device.

```sh
# Install python3 into a checkpoint, then serve with port forwarding
shuru checkpoint create py --allow-net -- apk add python3
shuru run --from py -p 8080:8000 -- python3 -m http.server 8000

# From the host (in another terminal)
curl http://127.0.0.1:8080/

# Multiple ports
shuru run -p 8080:80 -p 8443:443 -- nginx
```

Port forwards can also be set in `shuru.json` (see [Config file](#config-file)).

### Checkpoints

Checkpoints save the disk state so you can reuse an environment across runs.

```sh
# Set up an environment and save it
shuru checkpoint create myenv --allow-net -- sh -c 'apk add python3 gcc'

# Run from a checkpoint (ephemeral -- changes are discarded)
shuru run --from myenv -- python3 script.py

# Branch from an existing checkpoint
shuru checkpoint create myenv2 --from myenv --allow-net -- sh -c 'pip install numpy'

# List and delete
shuru checkpoint list
shuru checkpoint delete myenv
```

### Config file

Shuru loads `shuru.json` from the current directory (or `--config PATH`). All fields are optional; CLI flags take precedence.

```json
{
  "cpus": 4,
  "memory": 4096,
  "disk_size": 8192,
  "allow_net": true,
  "ports": ["8080:80"],
  "mounts": ["./src:/workspace", "./data:/data"],
  "command": ["python", "script.py"]
}
```

## Architecture

```
┌─────────────────────────────────────────────┐
│  macOS Host                                 │
│                                             │
│  shuru-cli ──► shuru-vm ──► shuru-darwin    │
│                   │      (Virtualization.framework)
│                   │                         │
│         ┌────────┼─────────┐                │
│         │ vsock :1024 exec │                │
│         │ vsock :1025 fwd  │                │
│         │ virtiofs  mounts │                │
│         └────────┼─────────┘                │
├──────────────────┼──────────────────────────┤
│  Linux Guest     │                          │
│         ┌────────┴─────────┐                │
│         │   shuru-guest    │                │
│         │   (PID 1 init)   │                │
│         └──────────────────┘                │
│  Alpine Linux 3.21 / linux-virt 6.12        │
└─────────────────────────────────────────────┘
```

## Bugs

File issues at [github.com/superhq-ai/shuru/issues](https://github.com/superhq-ai/shuru/issues).
