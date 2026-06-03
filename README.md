# lsb

lsb (Local SandBox) is a local-first microVM sandbox for AI agents on macOS.

lsb boots lightweight Linux VMs using Apple's Virtualization.framework. Each sandbox is ephemeral: the rootfs resets on every run, giving agents a disposable environment to execute code, install packages, and run tools without touching your host.

## Requirements

- macOS 14 (Sonoma) or later on Apple Silicon or Intel
- `cmake` is required when building from source because `lsb-proxy` now links BoringSSL for upstream TLS

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/LocalSandBox/local-sandbox/main/install.sh | sh
```

Or build from source:

```sh
cargo build -p lsb-cli --release
codesign --entitlements lsb.entitlements --force -s - target/release/lsb
```

## Usage

```sh
# Interactive shell
lsb run

# Run a command
lsb run -- echo hello

# With network access
lsb run --allow-net

# Restrict to specific hosts
lsb run --allow-net --allow-host api.openai.com --allow-host registry.npmjs.org

# Custom resources
lsb run --cpus 4 --memory 4096 --disk-size 8192 -- make -j4
```

With `--allow-net`, the guest resolves DNS through the host-side proxy at
`10.0.0.1`. Leave `/etc/resolv.conf` pointed at that proxy; the proxy performs
lookups with the host system resolver, including VPN or split-DNS rules.
Directly configuring corporate DNS servers inside the guest bypasses the proxy
and can fail because the guest has no general UDP or host VPN route access.

### Directory mounts

Share host directories into the VM using VirtioFS. The host directory is read-only; guest writes go to a tmpfs overlay layer (discarded when the VM exits).

```sh
# Mount a directory (guest can write, host is untouched)
lsb run --mount ./src:/workspace -- ls /workspace

# Multiple mounts
lsb run --mount ./src:/workspace --mount ./data:/data -- sh
```

Mounts can also be set in `lsb.json` (see [Config file](#config-file)).

> **Note:** Directory mounts require checkpoints created on v0.1.11+. Existing checkpoints work normally for all other features. Run `lsb upgrade` to get the latest version.

### Port forwarding

Forward host ports to guest ports over vsock. Works without `--allow-net` — the guest needs no network device.

```sh
# Install python3 into a checkpoint, then serve with port forwarding
lsb checkpoint create py --allow-net -- apt-get install -y python3
lsb run --from py -p 8080:8000 -- python3 -m http.server 8000

# From the host (in another terminal)
curl http://127.0.0.1:8080/

# Multiple ports
lsb run -p 8080:80 -p 8443:443 -- nginx
```

Port forwards can also be set in `lsb.json` (see [Config file](#config-file)).

### Checkpoints

Checkpoints save the disk state so you can reuse an environment across runs.
By default, checkpoints are CAS/NBD indexes that reference a pinned base rootfs
by runtime asset version. After `rootfs.ext4` is updated, new sandboxes use the
new base and existing checkpoints continue to use the base they were created
from.

```sh
# Initialize the current CLI version and boot from that current base
lsb init
lsb run -- sh

# Set up an environment and save it
lsb checkpoint create myenv --allow-net -- sh -c 'apt-get install -y python3 gcc'

# Run from a checkpoint (ephemeral -- changes are discarded)
lsb run --from myenv -- python3 script.py

# Branch from an existing checkpoint
lsb checkpoint create myenv2 --from myenv --allow-net -- sh -c 'pip install numpy'

# Optional: prepare and boot from a specific older pinned base version
lsb init --version 0.3.8
lsb run --base-version 0.3.8 -- sh

# List and delete
lsb checkpoint list
lsb checkpoint delete myenv
```

### Secrets

Secrets keep API keys on the host. The guest receives a random placeholder token; the proxy substitutes the real value only on HTTPS requests to the specified hosts. The real secret never enters the VM.

```sh
# Inject a secret via CLI
lsb run --allow-net --secret API_KEY=sk-your-openai-key@api.openai.com -- curl https://api.openai.com/v1/models

# Multiple secrets
lsb run --allow-net \
  --secret API_KEY=sk-your-openai-key@api.openai.com \
  --secret GH_TOKEN=github_pat_your_token@api.github.com \
  -- sh
```

Format: `NAME=VALUE@host1,host2` — `NAME` is the env var the guest sees, `VALUE` is the literal secret held on the host, and hosts are where the proxy substitutes it.

Secrets can also be set in `lsb.json` (see [Config file](#config-file)).

### Config file

lsb loads `lsb.json` from the current directory (or `--config PATH`). All fields are optional; CLI flags take precedence.

```json
{
  "cpus": 4,
  "memory": 4096,
  "disk_size": 8192,
  "allow_net": true,
  "ports": ["8080:80"],
  "mounts": ["./src:/workspace", "./data:/data"],
  "command": ["python", "script.py"],
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

The `network.allow` list restricts which hosts the guest can reach. Omit it to allow all hosts.

## Node.js Binding

Use lsb programmatically from Node.js or TypeScript with the [`@local-sandbox/lsb-nodejs`](https://www.npmjs.com/package/@local-sandbox/lsb-nodejs) package.

```sh
npm install @local-sandbox/lsb-nodejs
```

```ts
import { Sandbox } from "@local-sandbox/lsb-nodejs";

const sb = await Sandbox.start({ from: "python-env" });

const result = await sb.exec("python3 -c 'print(1+1)'");
console.log(result.stdout); // "2\n"

await sb.checkpoint("after-run"); // saves disk state and stops the VM
```

See the [Node.js binding README](bindings/nodejs/README.md) for full API docs and runtime requirements.

## Agent Skill

lsb ships as an [agent skill](https://agentskills.io) so AI agents (Claude Code, Cursor, Copilot, etc.) can use it automatically.

```sh
# Install via Vercel's skills CLI
npx skills add LocalSandBox/local-sandbox

# Or manually copy into your project
cp -r skills/lsb .claude/skills/lsb
```

Once installed, agents will use `lsb run` whenever they need sandboxed execution.

## Credits

This repository is a hard fork of [`superhq-ai/shuru`](https://github.com/superhq-ai/shuru).
Credit for the original architecture and implementation belongs to the Shuru project and its contributors.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release notes and breaking changes.

## Bugs

File issues at [github.com/LocalSandBox/local-sandbox/issues](https://github.com/LocalSandBox/local-sandbox/issues).
