# `@superhq/shuru-nodejs`

Native Node.js bindings for [Shuru](https://github.com/superhq-ai/shuru), built with
[`napi-rs`](https://napi.rs/).

This package is the canonical JavaScript and TypeScript entrypoint for Shuru. It wraps the
Rust [`shuru-sdk`](../../crates/shuru-sdk) directly and exposes a Node-facing `Sandbox` API.

## Install

```sh
npm install @superhq/shuru-nodejs
```

For local development, use Corepack to run the Yarn version pinned in
[`package.json`](./package.json):

```sh
corepack yarn install
```

## Requirements

- Node.js 18+
- macOS 14+ on Apple Silicon
- [shuru CLI](https://github.com/superhq-ai/shuru) installed
- `Sandbox.start()` expects the Shuru runtime data directory to already exist. In the default
  location, `~/.local/share/shuru/Image` must be present before booting a sandbox. This VM image
  is not bundled with `@superhq/shuru-nodejs` and needs to be downloaded manually as part of your
  Shuru runtime setup.
- On macOS, the `node` executable loading this SDK must be code signed with the
  `com.apple.security.virtualization` entitlement. For a project-local workflow, sign a copied
  Node binary with [`../../shuru.entitlements`](../../shuru.entitlements), or use
  [`test:signed-node`](./package.json) as a reference.

## Usage

### Start a sandbox and run commands

```ts
import { Sandbox } from '@superhq/shuru-nodejs'

const dataDir = `${process.env.HOME}/.local/share/shuru`
const sandbox = await Sandbox.start({
  dataDir,
  cpus: 2,
  memory: 2048,
  allowNet: true,
  mounts: {
    './src': '/workspace',
  },
})

const result = await sandbox.exec('echo hello from shuru')
console.log(result.stdout)

await sandbox.writeFile('/tmp/demo.txt', 'hello')
const content = await sandbox.readFile('/tmp/demo.txt')
console.log(content.toString())

await sandbox.stop()
```

### Pass argv directly or run through a shell

```ts
import { Sandbox } from '@superhq/shuru-nodejs'

const sandbox = await Sandbox.start()

const argvResult = await sandbox.exec(['sh', '-lc', 'printf "%s" "$HOME"'])
console.log(argvResult.stdout)

const shellResult = await sandbox.execShell('uname -a')
console.log(shellResult.stdout)

await sandbox.stop()
```

### Inspect the guest filesystem

```ts
import { Sandbox } from '@superhq/shuru-nodejs'

const sandbox = await Sandbox.start()

await sandbox.writeFile('/tmp/demo.txt', 'hello from shuru')

const entries = await sandbox.readDir('/tmp')
const stat = await sandbox.stat('/tmp/demo.txt')
const exists = await sandbox.exists('/tmp/demo.txt')

console.log(entries.map((entry) => `${entry.type}: ${entry.name}`))
console.log({ size: stat.size, mode: stat.mode, exists })

await sandbox.stop()
```

### Save and resume from a checkpoint

```ts
import { Sandbox } from '@superhq/shuru-nodejs'

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
import { Sandbox } from '@superhq/shuru-nodejs'

const sandbox = await Sandbox.start({
  cpus: 4,
  memory: 4096,
  diskSize: 8192,
  allowNet: true,
  ports: ['8080:80'],
  mounts: { './src': '/workspace' },
  secrets: {
    API_KEY: { value: 'sk-test', hosts: ['api.openai.com'] },
  },
  network: { allow: ['api.openai.com', 'registry.npmjs.org'] },
})

console.log(sandbox.instanceDir)

await sandbox.stop()
```

### Start options

| Option | Type | Description |
|--------|------|-------------|
| `from` | `string` | Checkpoint name to start from |
| `cpus` | `number` | Number of vCPUs |
| `memory` | `number` | Memory in MB |
| `diskSize` | `number` | Disk size in MB |
| `dataDir` | `string` | Shuru runtime data directory |
| `allowNet` | `boolean` | Enable network access |
| `allowedHosts` | `string[]` | Additional allowlisted hosts |
| `ports` | `string[]` | Port forwards (`"host:guest"`) |
| `mounts` | `Record<string, string>` | Directory mounts (`{ hostPath: guestPath }`) |
| `secrets` | `Record<string, SecretConfig>` | Secrets injected via the Shuru proxy |
| `network` | `NetworkConfig` | Network access policy |

## Scripts

```sh
corepack yarn build
corepack yarn test
corepack yarn test:signed-node
```

`corepack yarn test` always builds the native binding first, then runs AVA against the
generated root entrypoint. The positive VM smoke test only runs when both of these are true:

- Shuru runtime assets already exist in `~/.local/share/shuru` or in `SHURU_NODEJS_TEST_DATA_DIR`
  (`Image` is expected there and usually needs to be provisioned manually)
- the current `node` executable has the `com.apple.security.virtualization` entitlement

To avoid modifying your global Node installation, use [`test:signed-node`](./package.json),
which copies the current `node` binary into `.signed-node/node`, signs that local copy with
[`../../shuru.entitlements`](../../shuru.entitlements), prepends it to `PATH`, and then runs
the local `napi build --platform` plus `ava` commands through that signed Node:

```sh
corepack yarn test:signed-node
```

If runtime assets are missing, provision them in the Shuru data directory first. The generated build outputs
(`index.js`, `index.d.ts`, `shuru-nodejs.*.node`) are local artifacts and are ignored by git.
This explicit smoke-test entrypoint will attempt a real VM boot; if your host still refuses
virtualization after signing the local Node copy, the command will surface that underlying error.

## Platform Notes

- Supported target: macOS on Apple Silicon (`aarch64-apple-darwin`).
- Other platforms and architectures are not supported by this binding at runtime.
