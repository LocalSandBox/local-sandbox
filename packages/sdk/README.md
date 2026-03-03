# @superhq/shuru

TypeScript SDK for [shuru](https://github.com/superhq-ai/shuru) — programmatic access to ephemeral Linux microVMs on macOS.

## Install

```sh
bun add @superhq/shuru
```

## Usage

```ts
import { Sandbox } from "@superhq/shuru";

const sb = await Sandbox.start();

const result = await sb.exec("echo hello");
console.log(result.stdout); // "hello\n"

await sb.writeFile("/tmp/app.ts", "console.log('hi')");
const content = await sb.readFile("/tmp/app.ts");

await sb.checkpoint("my-env");

await sb.stop();
```

### Start from a checkpoint

```ts
const sb = await Sandbox.start({ from: "my-env" });
```

### Options

```ts
const sb = await Sandbox.start({
  from: "my-env",
  cpus: 4,
  memory: 4096,
  diskSize: 8192,
  allowNet: true,
  ports: ["8080:80"],
  mounts: { "./src": "/workspace" },
});
```

| Option | Type | Description |
|--------|------|-------------|
| `from` | `string` | Checkpoint name to start from |
| `cpus` | `number` | Number of vCPUs |
| `memory` | `number` | Memory in MB |
| `diskSize` | `number` | Disk size in MB |
| `allowNet` | `boolean` | Enable network access |
| `ports` | `string[]` | Port forwards (`"host:guest"`) |
| `mounts` | `Record<string, string>` | Directory mounts (`{ hostPath: guestPath }`) |
| `shuruBin` | `string` | Path to shuru binary (default: `"shuru"`) |

## API

### `Sandbox.start(opts?): Promise<Sandbox>`

Boot a new microVM. Returns when the VM is ready.

### `sandbox.exec(command): Promise<ExecResult>`

Run a shell command in the VM. Returns `{ stdout, stderr, exitCode }`.

### `sandbox.readFile(path): Promise<string>`

Read a file from the VM.

### `sandbox.writeFile(path, content): Promise<void>`

Write a file to the VM.

### `sandbox.checkpoint(name): Promise<void>`

Snapshot the VM's disk. The VM keeps running.

### `sandbox.stop(): Promise<void>`

Stop the VM. Unsaved changes are discarded.

## Requirements

- macOS 14+ on Apple Silicon
- [shuru CLI](https://github.com/superhq-ai/shuru) installed
- Bun runtime
