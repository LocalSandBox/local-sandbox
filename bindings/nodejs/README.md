# `@local-sandbox/lsb-nodejs`

Native Node.js bindings for [lsb](https://github.com/LocalSandBox/local-sandbox.git), built with
[`napi-rs`](https://napi.rs/).

This package is the canonical JavaScript and TypeScript entrypoint for lsb. It wraps the
Rust [`lsb-sdk`](../../crates/lsb-sdk) directly and exposes a Node-facing `Sandbox` API.

## Install

```sh
npm install @local-sandbox/lsb-nodejs
```

The published npm package is split into a root package plus a platform package. On supported hosts,
`npm` resolves and installs either `@local-sandbox/lsb-nodejs-darwin-arm64` or
`@local-sandbox/lsb-nodejs-darwin-x64` on macOS, or
`@local-sandbox/lsb-nodejs-win32-x64-msvc` on Windows x64, automatically.

For local development, use Corepack to run the Yarn version pinned in
[`package.json`](./package.json):

```sh
corepack yarn install
```

## Requirements

- Node.js 18+
- macOS 14+ on Apple Silicon or Intel x86_64, or Windows 11 on x86_64
- Runtime assets initialized with `initSandbox()` or `lsb init`. On Windows,
  that initialization also installs LocalSandbox-managed QEMU host tools.
  `Sandbox.start()` still expects the lsb runtime data directory to already
  contain `Image`, `rootfs.ext4`, and `initramfs.cpio.gz`; it does not download
  assets or host tools implicitly.
- On macOS, the `node` executable loading this SDK must be code signed with the
  `com.apple.security.virtualization` entitlement. For a project-local workflow, sign a copied
  Node binary with [`../../lsb.entitlements`](../../lsb.entitlements), or use
  [`test:signed-node`](./package.json) as a reference.
- On Windows, npm packages do not contain QEMU. Enable Windows Hypervisor
  Platform, then initialize host tools through `initSandbox()` or `lsb init`.
  The Windows backend requires WHPX and does not fall back to TCG for production
  Node users. `LSB_QEMU` and `LSB_QEMU_IMG` remain supported override/debug
  paths.
- Windows support covers sandbox start/stop, non-interactive `exec()` / `execShell()`, guest file
  APIs, overlay mounts, SMB/CIFS direct mounts, loopback port forwarding, policy-mediated proxy
  networking, and checkpoint restore/save. Streaming `spawn()`, interactive shells, and `watch()`
  remain macOS-only.

## Usage

### Start a sandbox and run commands

```ts
import { Sandbox, initSandbox } from '@local-sandbox/lsb-nodejs'

const init = await initSandbox()

const sandbox = await Sandbox.start({
  dataDir: init.dataDir,
  cpus: 2,
  memoryMb: 2048,
  mounts: [{ type: 'overlay', hostPath: './src', guestPath: '/workspace' }],
  network: { allow: ['registry.npmjs.org'] },
})

const result = await sandbox.exec('echo hello from lsb')
console.log(result.stdout)

await sandbox.writeFile('/tmp/demo.txt', 'hello')
const content = await sandbox.readFile('/tmp/demo.txt')
console.log(content.toString())

await sandbox.stop()
```

### Initialize runtime assets

```ts
import { initSandbox } from '@local-sandbox/lsb-nodejs'

const init = await initSandbox()
console.log(init.dataDir, init.version, init.downloaded)
```

`initSandbox()` defaults to this package version and pins that base rootfs.
`Sandbox.start()` defaults to the initialized `VERSION` in the runtime data directory. You only need
to pass a version when preparing or booting from an older pinned base.

```ts
await initSandbox({ version: '0.3.8' })

const sandbox = await Sandbox.start({ baseVersion: '0.3.8' })
```

### Pass argv directly or run through a shell

```ts
import { Sandbox } from '@local-sandbox/lsb-nodejs'

const sandbox = await Sandbox.start()

const argvResult = await sandbox.exec(['sh', '-lc', 'printf "%s" "$HOME"'])
console.log(argvResult.stdout)

const shellResult = await sandbox.execShell('uname -a')
console.log(shellResult.stdout)

await sandbox.stop()
```

### Inspect the guest filesystem

```ts
import { Sandbox } from '@local-sandbox/lsb-nodejs'

const sandbox = await Sandbox.start()

await sandbox.writeFile('/tmp/demo.txt', 'hello from lsb')

const entries = await sandbox.readDir('/tmp')
const stat = await sandbox.stat('/tmp/demo.txt')
const exists = await sandbox.exists('/tmp/demo.txt')

console.log(entries.map((entry) => `${entry.type}: ${entry.name}`))
console.log({ size: stat.size, mode: stat.mode, exists })

await sandbox.stop()
```

### Save and resume from a checkpoint

```ts
import { Sandbox } from '@local-sandbox/lsb-nodejs'

const base = await Sandbox.start()
await base.exec('mkdir -p /workspace && echo ready > /workspace/state.txt')
await base.checkpoint('my-env')

const resumed = await Sandbox.start({ from: 'my-env' })
const state = await resumed.readFile('/workspace/state.txt')
console.log(state.toString())

await resumed.stop()
```

### Configure mounts, ports, secrets, and network policy

```ts
import { Sandbox } from '@local-sandbox/lsb-nodejs'

const sandbox = await Sandbox.start({
  cpus: 4,
  memoryMb: 4096,
  diskSizeMb: 8192,
  ports: [{ host: 8080, guest: 80 }],
  mounts: [{ type: 'overlay', hostPath: './src', guestPath: '/workspace' }],
  network: {
    allow: ['api.openai.com', 'registry.npmjs.org'],
    exposeHost: [{ host: 3000, guest: 3000 }],
    secrets: {
      API_KEY: { value: 'sk-test', hosts: ['api.openai.com'] },
    },
  },
})

console.log(sandbox.instanceDir)

await sandbox.stop()
```

### Start options

| Option       | Type                                | Description                    |
| ------------ | ----------------------------------- | ------------------------------ |
| `instanceId` | `string`                            | Stable instance directory name |
| `from`       | `string`                            | Checkpoint name to start from  |
| `cpus`       | `number`                            | Number of vCPUs                |
| `memoryMb`   | `number`                            | Memory in MB                   |
| `diskSizeMb` | `number`                            | Disk size in MB                |
| `dataDir`    | `string`                            | lsb runtime data directory     |
| `ports`      | `{ host: number; guest: number }[]` | Host-to-guest port forwards    |
| `mounts`     | `MountConfig[]`                     | Directory mounts               |
| `network`    | `NetworkConfig`                     | Network access policy          |

`mounts` accepts discriminated entries:

| Type      | Shape                                                                    | Behavior                                      |
| --------- | ------------------------------------------------------------------------ | --------------------------------------------- |
| `overlay` | `{ type: 'overlay'; hostPath: string; guestPath: string }`               | Host is read-only; guest writes go to overlay |
| `direct`  | `{ type: 'direct'; hostPath: string; guestPath: string; flags: number }` | Direct mount with libc flags                  |

For direct mounts, `flags: 0` is read-write and `flags: 1` is `MS_RDONLY`. On Windows, direct mounts
use SMB/CIFS, require an elevated Administrator shell, and use LocalSandbox-controlled proxy
networking without enabling arbitrary outbound network access.

`network` enables proxy networking when present. It accepts:

| Option       | Type                                 | Description                        |
| ------------ | ------------------------------------ | ---------------------------------- |
| `allow`      | `string[]`                           | Allowed outbound host patterns     |
| `exposeHost` | `{ host: number; guest?: number }[]` | Host ports exposed to the guest    |
| `secrets`    | `Record<string, SecretConfig>`       | Secrets injected via the lsb proxy |

### Stream process output

```ts
import { Sandbox } from '@local-sandbox/lsb-nodejs'

const sandbox = await Sandbox.start()
const proc = await sandbox.spawn('echo out; echo err >&2')

for await (const chunk of proc.stdout) {
  process.stdout.write(chunk)
}

console.log(await proc.exited)

await sandbox.stop()
```

`spawn()` streaming is macOS-only in this release. On Windows, use `exec()` or `execShell()` for
non-interactive commands; streaming process I/O returns a backend capability error.

### Watch files

```ts
import { Sandbox } from '@local-sandbox/lsb-nodejs'

const sandbox = await Sandbox.start()
const events = await sandbox.watch('/tmp')

for await (const event of events) {
  console.log(event.path, event.event)
}
```

`watch()` is macOS-only in this release and returns a backend capability error on Windows.

## Scripts

```sh
corepack yarn build
corepack yarn test
corepack yarn test:signed-node
```

`corepack yarn test` always builds the native binding first, then runs AVA against the
generated root entrypoint. The positive VM smoke test only runs when both of these are true:

- lsb runtime assets already exist in the platform default lsb data directory
  (`~/.local/share/lsb` on macOS/Linux, `%LOCALAPPDATA%\lsb` on Windows) or in
  `LSB_NODEJS_TEST_DATA_DIR` (`Image` is expected there and usually needs to be provisioned
  manually)
- the current `node` executable has the `com.apple.security.virtualization` entitlement

To avoid modifying your global Node installation, use [`test:signed-node`](./package.json),
which copies the current `node` binary into `.signed-node/node`, signs that local copy with
[`../../lsb.entitlements`](../../lsb.entitlements), prepends it to `PATH`, and then runs
the local `napi build --platform` plus `ava` commands through that signed Node:

```sh
corepack yarn test:signed-node
```

If runtime assets are missing, provision them in the lsb data directory first. The generated build outputs
(`index.js`, `index.d.ts`, `lsb-nodejs.*.node`) are local artifacts and are ignored by git.
This explicit smoke-test entrypoint will attempt a real VM boot; if your host still refuses
virtualization after signing the local Node copy, the command will surface that underlying error.

## Platform Notes

- Supported targets: macOS on Apple Silicon (`aarch64-apple-darwin`), macOS Intel
  (`x86_64-apple-darwin`), and Windows 11 x64 (`x86_64-pc-windows-msvc` /
  `win32-x64-msvc`).
- Installation is limited to supported operating systems and CPU families where npm can express
  them. Unsupported platform packages should fail clearly instead of masking native-module load
  failures.
- npm cannot express supported OS/CPU pairs in the root package metadata, so Windows ARM64 may be
  accepted by the root package metadata even though no Windows ARM64 native package is published.
  The loader reports this as unsupported Windows architecture; only `win32-x64-msvc` is supported
  for Windows.
- The published native binaries live in the platform packages
  `@local-sandbox/lsb-nodejs-darwin-arm64`, `@local-sandbox/lsb-nodejs-darwin-x64`, and
  `@local-sandbox/lsb-nodejs-win32-x64-msvc`.
- If the Windows native package is missing, the load error should name
  `@local-sandbox/lsb-nodejs-win32-x64-msvc` or `lsb-nodejs.win32-x64-msvc.node`. If the native
  module loads but QEMU, WHPX, or runtime assets are not ready, `Sandbox.start()` surfaces the
  Rust backend preflight error with the relevant remediation.
