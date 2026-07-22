# lsb

lsb (Local SandBox) is a local-first microVM sandbox for AI agents on macOS and
Windows 11 x64.

lsb boots lightweight Linux VMs using Apple's Virtualization.framework on macOS
and QEMU with WHPX on Windows. Each sandbox is ephemeral: the rootfs resets on
every run, giving agents a disposable environment to execute code, install
packages, and run tools without touching your host.

## Requirements

- macOS 14 (Sonoma) or later on Apple Silicon or Intel, or Windows 11 on x64.
- Windows requires Windows 11 x64 with Windows Hypervisor Platform enabled.
  `lsb init` installs LocalSandbox-managed QEMU host tools under the user data
  directory and production Windows runs require WHPX; they do not fall back to
  TCG. Run `lsb init --fix` from elevated PowerShell to also apply available
  automatic host configuration repairs. `LSB_QEMU` and `LSB_QEMU_IMG` remain
  supported override/debug paths.
- `cmake` is required when building from source because `lsb-proxy` links
  BoringSSL for upstream TLS.
- Windows source builds require the Rust MSVC toolchain and native build tools.

## Install

Install the latest CLI release on macOS:

```sh
curl -fsSL https://raw.githubusercontent.com/LocalSandBox/local-sandbox/main/install.sh | sh
```

Install the latest CLI release on Windows 11 x64 from PowerShell:

```powershell
irm https://raw.githubusercontent.com/LocalSandBox/local-sandbox/main/install.ps1 | iex
```

The shell installer also supports Windows x64 when run from Git Bash, MSYS2, or
Cygwin. After installation, run `lsb init` to download managed QEMU host tools
and runtime assets. To update a Windows CLI install, rerun the PowerShell
installer.

Build the macOS CLI from source:

```sh
cargo build -p lsb-cli --release
codesign --entitlements lsb.entitlements --force -s - target/release/lsb
```

Build the Windows CLI from source:

```powershell
cargo build -p lsb-cli --release
target\release\lsb.exe init
```

`cargo build` only builds the CLI. Runtime assets are downloaded separately by
`lsb init` and include `Image`, `initramfs.cpio.gz`, and `rootfs.ext4`. On
Windows, `lsb init` also installs managed QEMU host tools under
`%LOCALAPPDATA%\lsb\tools\qemu` without mutating global `PATH`. Windows uses its
own released runtime asset package because the QEMU/WHPX guest path requires
Windows-specific support such as virtio-serial. Building those assets from
source on Windows is more involved; developers should normally download the
released runtime assets instead of running the rootfs preparation pipeline
locally.

The machine-wide SeaWork Windows service is a separately signed, versioned
artifact rather than part of the CLI installer. Its release, verification, and
SeaWork installer contract is documented in
[docs/seawork-service-release.md](docs/seawork-service-release.md).

Developers who need matching local guest assets can use Podman without Docker
or host Linux filesystem tools. Use an empty data directory because `xtask`
preserves assets that already exist:

```powershell
$env:LSB_CONTAINER_ENGINE = "podman"
$env:LSB_FORCE_DOCKER_ROOTFS = "1"
$env:LSB_DATA_DIR = "$PWD\target\local-runtime"
cargo run -p xtask -- build-guest --platform windows-x86_64
cargo run -p xtask -- prepare-rootfs --platform windows-x86_64
```

The container rootfs path bootstraps into a normal directory and populates the
ext4 image with `mkfs.ext4 -d`; it does not require a loop device inside the
Podman VM.

## Usage

```sh
# Interactive shell (macOS)
lsb run

# Run a command (macOS and Windows)
lsb run -- echo hello

# With network access
lsb run --allow-net

# Restrict to specific hosts
lsb run --allow-net --allow-host api.openai.com --allow-host registry.npmjs.org

# Custom resources
lsb run --cpus 4 --memory 4096 --disk-size 8192 -- make -j4
```

## Platform Support

| Host | Runtime backend | Status |
| --- | --- | --- |
| macOS 14+ Apple Silicon | Apple Virtualization.framework | Supported |
| macOS 14+ Intel x64 | Apple Virtualization.framework | Supported |
| Windows 11 x64 | QEMU with WHPX | Supported backend and Node package |
| Windows ARM64 | Not available | Planned |

Windows support covers sandbox start/stop, non-interactive `exec`, streaming
`spawn` with stdin/kill, guest file APIs, file `watch`, overlay mounts,
explicit SMB/CIFS direct mounts, loopback port forwarding, policy-mediated
proxy networking, and qcow2 checkpoint save/restore. Interactive shells,
Windows ARM64, and CAS/NBD checkpoints are not part of the Windows support
surface yet.

With `--allow-net`, the guest resolves DNS through the host-side proxy at
`10.0.0.1`. Leave `/etc/resolv.conf` pointed at that proxy; the proxy performs
lookups with the host system resolver, including VPN or split-DNS rules.
Directly configuring corporate DNS servers inside the guest bypasses the proxy
and can fail because the guest has no general UDP or host VPN route access.

### Directory mounts

Mount host directories into the VM. On macOS, lsb uses VirtioFS with a guest
overlay. On Windows, CLI mounts without a suffix and CLI `:ro` mounts import a
snapshot into guest-owned staging storage; guest writes do not modify the host
source and are discarded when the VM exits unless you save or export them
through an explicit API.

Windows CLI `:rw` mounts use SMB/CIFS direct read-write sharing and require both
`--allow-host-writes` and an elevated Administrator shell. SDK and Node direct
mounts use the existing `Direct` API: `flags: 0` is SMB/CIFS read-write and
`flags: 1` (`MS_RDONLY`) is SMB/CIFS read-only. Direct SMB mounts use the
LocalSandbox-controlled proxy path and do not imply arbitrary outbound
`--allow-net`. If local Windows policy denies network logon to
`NT AUTHORITY\Local account`, direct SMB mounts fail before boot with an
actionable preflight error; diagnose or repair that policy with
`lsb doctor windows-smb-policy`, or apply all available automatic repairs with
`lsb init --fix` from elevated PowerShell.

On Windows, `watch()` on normal guest paths and overlay/import mounts observes
the guest filesystem view. `watch()` on SDK or Node direct SMB mount paths uses
a host-side Windows directory watcher so host-originated changes and
guest-originated CIFS writes are reported through the same event shape. A
recursive watch above a direct SMB mount target is rejected instead of returning
partial guest-only coverage; watch the SMB target directly or start separate
watches.

```sh
# Mount a directory (guest can write, host is untouched)
lsb run --mount ./src:/workspace -- ls /workspace

# Windows explicit direct read-write mount (requires Administrator)
lsb run --allow-host-writes --mount ./src:/workspace:rw -- sh

# Multiple mounts
lsb run --mount ./src:/workspace --mount ./data:/data -- sh
```

Mounts can also be set in `lsb.json` (see [Config file](#config-file)).

Windows overlay imports use a persistent content-addressed cache under
`%LOCALAPPDATA%\lsb\mount-cache\v1`. LocalSandbox securely walks and hashes the
complete source tree on every start, so timestamps alone do not change the key
and same-length content changes do. The first run for a key builds and seals an
ext4 lower image. Later runs attach the published image read-only, validate its
full raw digest on the host, and validate the source tree again in the guest
before creating a fresh tmpfs overlay. Guest writes therefore never change the
host or cached lower image and never reappear in a later run.

Cache failures are correctness-preserving: lock contention, image creation,
formatting, validation, or guest rejection routes that mount through the normal
copy importer instead of exposing stale content. Identical source digests in
one VM share one read-only disk but receive separate overlay upper/work
directories for each target. A build is published only after the VM stops and
the host verifies that its raw image still matches the digest returned by the
guest seal operation.

The default cache limits are 4 GiB of logical images, 64 objects, and 30 days
since access. Staging directories older than one hour and incomplete objects
are recovered during maintenance. Remove inactive cache objects explicitly;
this does not prune VM instances:

```powershell
lsb prune --mount-cache
```

For isolated tests and benchmarks, `LSB_WINDOWS_MOUNT_CACHE_DIR` changes the
cache data-directory base. `LSB_WINDOWS_MOUNT_METRICS_PATH` writes structured
startup metrics including cache decisions, fallbacks, transferred bytes, tree
and raw-image hashing, and terminal publication outcomes. Do not point either
variable at an untrusted or shared directory.

The ignored `lsb-vm` WHPX mount-cache tests use the direct backend and must be
given a disposable copy of `rootfs.ext4`; direct tests may modify that file.
The CLI-based recovery harness safely uses checkpoint overlays and verifies
synchronized concurrent builders plus forced interruption and retry:

```powershell
.\scripts\test-windows-mount-cache-recovery.ps1 `
  -Kernel <Image> -Initrd <initramfs.cpio.gz> -Rootfs <rootfs.ext4> `
  -FixtureRoot <2000-file-fixture> -Qemu <qemu-system-x86_64.exe> `
  -QemuImg <qemu-img.exe>
```

> **Note:** Directory mounts require checkpoints created on v0.1.11+. Existing checkpoints work normally for all other features. Run `lsb upgrade` to get the latest version.

### Port forwarding

Forward host ports to guest ports over a private host/guest channel. macOS uses
vsock; Windows uses a private virtio-serial channel. Port forwarding works
without `--allow-net`; the guest needs no general network device.

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
On macOS, checkpoints are CAS/NBD indexes that reference a pinned base rootfs by
runtime asset version. On Windows, checkpoints are flattened qcow2 disk
artifacts over immutable base images. After `rootfs.ext4` is updated, new
sandboxes use the new base and existing checkpoints continue to use the base
they were created from.

```sh
# Initialize the current CLI version and boot from that current base
lsb init
lsb run -- sh

# On Windows, also apply all available automatic host configuration repairs
lsb init --fix

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
    "allow": ["api.openai.com", "registry.npmjs.org"],
    "https_interception": {
      "enabled": true,
      "request_headers": [
        {
          "name": "User-Agent",
          "value": "my-sandbox-agent/1.0",
          "hosts": { "allow": ["api.openai.com"] }
        }
      ]
    }
  }
}
```

The `network.allow` list restricts which hosts the guest can reach. Omit it to allow all hosts.

### HTTPS request headers

`network.https_interception` is an opt-in HTTP/1.1 interceptor for HTTPS on TCP
port 443. It can set a caller-supplied `User-Agent` or other end-to-end request
headers. Existing instances are removed case-insensitively and one configured
value is inserted on every request, including keep-alive requests. Rules are
global unless `hosts.allow` or `hosts.deny` is present; both exact names and
`*.example.com` patterns are case-insensitive, trailing dots are ignored, and a
deny match always wins.

Global headers are sent to every intercepted destination and may disclose
sensitive data. Use an allow list for credentials or other private values.
Enabling interception installs an ephemeral proxy CA in the guest. It works
only for TCP port 443 with visible TLS SNI and HTTP/1.1. HTTP/2, HTTP/3/QUIC,
TLS without usable SNI, mutual TLS, pinned certificates, and private
application trust stores are not supported. Connections with no applicable
header or secret remain blind TLS tunnels.

Header names and values are validated before boot. Routing, framing, proxy,
and hop-by-hop fields such as `Host`, `Content-Length`, `Transfer-Encoding`,
`Connection`, `Upgrade`, and `Expect` cannot be configured. The limits are 64
rules, 128 bytes per name, 8 KiB per value, and 64 KiB across configured names
and values. Interception is off by default, and enabling it without a rule is
an error.

Secret substitution now follows HTTP/1.1 framing. A fixed-length request body
that must be scanned is streamed upstream with `Transfer-Encoding: chunked` so
length-changing replacement stays valid; origins that reject chunked HTTP/1.1
request bodies may therefore be incompatible with body-based substitution.

The same model is available from the Rust SDK:

```rust
use lsb_sdk::{HostScope, HttpsInterceptionConfig, RequestHeaderRule, SandboxConfig};

let config = SandboxConfig {
    allow_net: true,
    https_interception: HttpsInterceptionConfig {
        enabled: true,
        request_headers: vec![RequestHeaderRule {
            name: "User-Agent".into(),
            value: "my-sandbox-agent/1.0".into(),
            hosts: HostScope {
                allow: Some(vec!["api.example.com".into()]),
                deny: None,
            },
        }],
    },
    ..Default::default()
};
```

## Node.js Binding

Use lsb programmatically from Node.js or TypeScript with the
[`@local-sandbox/lsb-nodejs`](https://www.npmjs.com/package/@local-sandbox/lsb-nodejs)
package. The package supports macOS arm64/x64 and Windows x64.

```sh
npm install @local-sandbox/lsb-nodejs
```

```ts
import { Sandbox } from "@local-sandbox/lsb-nodejs";

const sb = await Sandbox.start({ from: "python-env" });

const result = await sb.exec("python3 -c 'print(1+1)'");
console.log(result.stdout); // "2\n"

await sb.checkpoint("after-run"); // saves disk state
await sb.stop();
```

See the [Node.js binding README](bindings/nodejs/README.md) for full API docs and runtime requirements.

## User-Agent injection benchmarks

Build the release CLI before benchmarking. Both harnesses generate matched
disabled/enabled configurations, execute an explicitly HTTP/1.1 curl workload,
alternate measured order, retain per-run logs, and emit `runs.jsonl` plus
`summary.json` with schema version 1.

```sh
cargo build --release -p lsb-cli
scripts/benchmark-macos-user-agent-injection.sh \
  --kernel /path/to/Image --rootfs /path/to/rootfs.ext4 \
  --initrd /path/to/initramfs.cpio.gz \
  --warmup-iterations 1 --iterations 5 \
  --results-root target/macos-user-agent-benchmark
```

```powershell
.\scripts\benchmark-windows-user-agent-injection.ps1 `
  -Binary .\target\release\lsb.exe `
  -WarmupIterations 1 -Iterations 5 `
  -ResultsRoot .\target\windows-user-agent-benchmark
```

Use `--url` / `-Url` and `--endpoint-kind` / `-EndpointKind` for a controlled
endpoint when available. Compare enabled-minus-disabled deltas within each host
before comparing platforms; virtualization backend, hardware, endpoint
latency, Defender, and host load can dominate absolute values. The macOS
harness reports private memory as `null` because RSS is the comparable
available metric. Windows execution and result collection must be performed on
a Windows 11 x64 host with WHPX/QEMU and initialized runtime assets; a macOS
parser check does not constitute Windows benchmark execution. PowerShell 7 is
required for argument-array process startup. Polling can miss very short-lived
descendants, so process-tree CPU and memory values are operational estimates;
each run records its scope, sample count, interval, and sampling errors.

## Agent Skill

lsb ships as an [agent skill](https://agentskills.io) so AI agents (Claude Code, Cursor, Copilot, etc.) can use it automatically.

```sh
# Install via Vercel's skills CLI
npx skills add LocalSandBox/local-sandbox

# Or manually copy into your project
cp -r skills/lsb .claude/skills/lsb
```

Once installed, agents will use `lsb run` whenever they need sandboxed execution.

## Releasing

Releases are prepared and published by the manually dispatched `Release`
workflow. The workflow creates the version-only release commit directly on
`main`, validates and builds that exact commit, tags it, optionally publishes
the Rust crates, publishes the Node.js package, and makes the staged GitHub
release public last.

```sh
# Defaults to the next patch release.
just release

# Other supported selectors.
just release minor
just release major
just release 0.5.2
```

Configure the `release` GitHub environment to require the desired approval and
allow the workflow token to push the release commit to protected `main`. The
repository must provide an `NPM_TOKEN` secret. Crates.io publishing is disabled
by default and becomes active when the optional `CARGO_REGISTRY_TOKEN`
repository secret is configured. To retry a partially completed release,
dispatch its exact version (for example, `just release 0.5.2`); already-created
tags, packages, and releases are checked and safely reused.

The canonical version is `workspace.package.version` in the root `Cargo.toml`.
For local diagnostics, `cargo run -p xtask -- release verify` checks every Rust
and Node.js manifest plus `Cargo.lock` for version drift.

## Credits

This repository is a hard fork of [`superhq-ai/shuru`](https://github.com/superhq-ai/shuru).
Credit for the original architecture and implementation belongs to the Shuru project and its contributors.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release notes and breaking changes.

## Bugs

File issues at [github.com/LocalSandBox/local-sandbox/issues](https://github.com/LocalSandBox/local-sandbox/issues).
