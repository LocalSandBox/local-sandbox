import {
  copyFileSync,
  cpSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'

const require = createRequire(import.meta.url)
const scriptDir = dirname(fileURLToPath(import.meta.url))
const packageRoot = dirname(scriptDir)
const packageVersion = JSON.parse(readFileSync(join(packageRoot, 'package.json'), 'utf8')).version

function requireEnv(name) {
  const value = process.env[name]
  if (!value) {
    throw new Error(`${name} must point to a disposable Windows smoke boot asset`)
  }
  return value
}

function prepareDataDir(label) {
  const root = join(tmpdir(), `lsb-nodejs-windows-${label}-${process.pid}-${Date.now()}`)
  rmSync(root, { recursive: true, force: true })
  mkdirSync(join(root, 'checkpoints'), { recursive: true })
  mkdirSync(join(root, 'instances'), { recursive: true })

  copyFileSync(requireEnv('LSB_WINDOWS_BOOT_KERNEL'), join(root, 'Image'))
  copyFileSync(requireEnv('LSB_WINDOWS_BOOT_INITRD'), join(root, 'initramfs.cpio.gz'))
  copyFileSync(requireEnv('LSB_WINDOWS_BOOT_ROOTFS'), join(root, 'rootfs.ext4'))
  writeFileSync(join(root, 'VERSION'), `${packageVersion}\n`)

  return root
}

function errorMessage(error) {
  return error instanceof Error ? error.message : String(error)
}

async function withSmokeTimeout(label, dataDir, action, timeoutMs) {
  let timeout = null
  try {
    timeout = setTimeout(() => {
      console.error(`${label} timed out after ${Math.round(timeoutMs / 1000)} seconds`)
      stageInstanceDiagnostics(label, dataDir)
      process.exit(1)
    }, timeoutMs)
    return await action()
  } finally {
    if (timeout) {
      clearTimeout(timeout)
    }
  }
}

async function waitForWatchEvent(stream, predicate, timeoutMs) {
  const iterator = stream[Symbol.asyncIterator]()
  const seen = []
  const deadline = Date.now() + timeoutMs

  while (Date.now() < deadline) {
    const remaining = Math.max(1, deadline - Date.now())
    let timeout = null
    const next = await Promise.race([
      iterator.next(),
      new Promise((_, reject) => {
        timeout = setTimeout(() => {
          reject(new Error(`timed out waiting for watch event; seen ${JSON.stringify(seen)}`))
        }, remaining)
      }),
    ]).finally(() => {
      if (timeout) {
        clearTimeout(timeout)
      }
    })

    if (next.done) {
      throw new Error(`watch stream ended before expected event; seen ${JSON.stringify(seen)}`)
    }

    seen.push(next.value)
    if (predicate(next.value)) {
      return seen
    }
  }

  throw new Error(`timed out waiting for watch event; seen ${JSON.stringify(seen)}`)
}

function stageInstanceDiagnostics(label, dataDir) {
  const destinationRoot = process.env.LSB_WINDOWS_BOOT_ARTIFACT_DIR
  if (!destinationRoot) {
    return
  }

  const instancesDir = join(dataDir, 'instances')
  if (!existsSync(instancesDir)) {
    return
  }

  const stagedRoot = join(destinationRoot, `node-${label}`)
  let copied = 0

  try {
    mkdirSync(stagedRoot, { recursive: true })

    for (const entry of readdirSync(instancesDir, { withFileTypes: true })) {
      if (!entry.isDirectory()) {
        continue
      }

      const diagnosticsDir = join(instancesDir, entry.name, 'diagnostics')
      if (!existsSync(diagnosticsDir)) {
        continue
      }

      cpSync(diagnosticsDir, join(stagedRoot, entry.name), {
        errorOnExist: false,
        force: true,
        recursive: true,
      })
      copied += 1
    }

    if (copied > 0) {
      console.log(`staged Node ${label} diagnostic directory count: ${copied}`)
    }
  } catch (error) {
    console.warn(`failed to stage Node ${label} diagnostics: ${errorMessage(error)}`)
  }
}

function assertNotNativeLoadError(message) {
  if (
    /Failed to load native binding/i.test(message) ||
    /Cannot find module/i.test(message) ||
    /lsb-nodejs\.win32-x64-msvc\.node/i.test(message)
  ) {
    throw new Error(`Node smoke failed before reaching the Rust backend: ${message}`)
  }
}

function assertMissingQemuBackendError(message) {
  assertNotNativeLoadError(message)

  if (!/LSB_QEMU|qemu-system-x86_64|QEMU/i.test(message)) {
    throw new Error(`expected a Windows QEMU backend preflight error, got: ${message}`)
  }
  if (!/does not exist|not found|not a file|invalid/i.test(message)) {
    throw new Error(`expected a missing-QEMU path validation error, got: ${message}`)
  }
}

function loadBinding() {
  try {
    return require(join(packageRoot, 'index.js'))
  } catch (error) {
    throw new Error(
      `failed to load Windows Node binding before backend preflight: ${errorMessage(error)}`,
    )
  }
}

async function expectMissingQemuPreflight(Sandbox) {
  const dataDir = prepareDataDir('missing-qemu')
  const originalQemu = process.env.LSB_QEMU
  const originalStorage = process.env.LSB_STORAGE
  process.env.LSB_QEMU = join(dataDir, 'missing-qemu-system-x86_64.exe')
  process.env.LSB_STORAGE = 'direct'

  try {
    await Sandbox.start({
      dataDir,
      instanceId: `node-missing-qemu-${process.pid}`,
    })
    throw new Error('Sandbox.start unexpectedly succeeded with an invalid LSB_QEMU path')
  } catch (error) {
    const message = errorMessage(error)
    if (/unexpectedly succeeded/i.test(message)) {
      throw error
    }
    assertMissingQemuBackendError(message)
    console.log(`missing-QEMU preflight surfaced backend error: ${message}`)
  } finally {
    if (originalQemu === undefined) {
      delete process.env.LSB_QEMU
    } else {
      process.env.LSB_QEMU = originalQemu
    }
    if (originalStorage === undefined) {
      delete process.env.LSB_STORAGE
    } else {
      process.env.LSB_STORAGE = originalStorage
    }
    stageInstanceDiagnostics('missing-qemu', dataDir)
    rmSync(dataDir, { recursive: true, force: true })
  }
}

async function expectSandboxStart(Sandbox, initSandbox) {
  const dataDir = prepareDataDir('start')
  let sandbox = null

  try {
    await initSandbox({ dataDir })
    sandbox = await Sandbox.start({
      dataDir,
      instanceId: `node-start-${process.pid}`,
    })
    if (typeof sandbox.instanceDir !== 'string' || sandbox.instanceDir.length === 0) {
      throw new Error('Sandbox.start returned an instance without an instanceDir')
    }
    console.log(`Node sandbox started through Rust backend: ${sandbox.instanceDir}`)
  } catch (error) {
    const message = errorMessage(error)
    assertNotNativeLoadError(message)
    throw new Error(`Node Sandbox.start reached the Rust backend but did not start: ${message}`)
  } finally {
    if (sandbox) {
      console.log(`Stopping Node sandbox: ${sandbox.instanceDir}`)
      await sandbox.stop()
      console.log('Node sandbox stopped')
    }
    stageInstanceDiagnostics('start', dataDir)
    rmSync(dataDir, { recursive: true, force: true })
  }
}

async function expectDirectReadOnlyMount(Sandbox) {
  const dataDir = prepareDataDir('direct-ro')
  const source = join(dataDir, 'direct-ro-source')
  mkdirSync(source, { recursive: true })
  writeFileSync(join(source, 'input.txt'), 'node-direct-ro-host')
  const originalStorage = process.env.LSB_STORAGE
  let sandbox = null

  try {
    console.log('Starting Node direct read-only SMB mount smoke')
    process.env.LSB_STORAGE = 'direct'
    sandbox = await withSmokeTimeout(
      'direct-ro-start',
      dataDir,
      () =>
        Sandbox.start({
          dataDir,
          instanceId: `node-direct-ro-${process.pid}`,
          mounts: [{ type: 'direct', hostPath: source, guestPath: '/node-ro', flags: 1 }],
        }),
      180_000,
    )

    let result = await withSmokeTimeout(
      'direct-ro-read-initial',
      dataDir,
      () => sandbox.exec(['/bin/cat', '/node-ro/input.txt']),
      60_000,
    )
    if (result.exitCode !== 0 || result.stdout !== 'node-direct-ro-host') {
      throw new Error(
        `direct read-only mount did not expose host file: exit=${result.exitCode} stdout=${JSON.stringify(result.stdout)} stderr=${JSON.stringify(result.stderr)}`,
      )
    }

    writeFileSync(join(source, 'after-start.txt'), 'node-direct-ro-live-host')
    result = await withSmokeTimeout(
      'direct-ro-read-live-update',
      dataDir,
      () =>
        sandbox.exec([
          '/bin/sh',
          '-c',
          'i=0; while [ "$i" -lt 8 ]; do test "$(cat /node-ro/after-start.txt 2>/dev/null || true)" = "node-direct-ro-live-host" && exit 0; i=$((i + 1)); sleep 1; done; exit 1',
        ]),
      90_000,
    )
    if (result.exitCode !== 0) {
      throw new Error(`direct read-only mount did not expose live host update: ${result.stderr}`)
    }

    const directWatch = await withSmokeTimeout(
      'direct-ro-watch-open',
      dataDir,
      () => sandbox.watch('/node-ro'),
      60_000,
    )
    await new Promise((resolve) => setTimeout(resolve, 500))
    writeFileSync(join(source, 'host-watch.txt'), 'node-direct-ro-watch')
    await withSmokeTimeout(
      'direct-ro-watch-event',
      dataDir,
      () =>
        waitForWatchEvent(
          directWatch,
          (event) =>
            event.path === '/node-ro/host-watch.txt' &&
            (event.event === 'create' || event.event === 'modify'),
          60_000,
        ),
      70_000,
    )

    result = await withSmokeTimeout(
      'direct-ro-write-denial',
      dataDir,
      () =>
        sandbox.exec([
          '/bin/sh',
          '-c',
          'if printf guest-write > /node-ro/guest.txt 2>/tmp/node-ro-write.err; then exit 42; fi; printf ro-denied',
        ]),
      60_000,
    )
    if (result.exitCode !== 0 || result.stdout !== 'ro-denied') {
      throw new Error(
        `direct read-only mount allowed guest write or failed unexpectedly: exit=${result.exitCode} stdout=${JSON.stringify(result.stdout)} stderr=${JSON.stringify(result.stderr)}`,
      )
    }

    console.log('Node direct read-only SMB mount smoke passed')
  } catch (error) {
    const message = errorMessage(error)
    assertNotNativeLoadError(message)
    throw new Error(`Node direct read-only SMB mount smoke failed: ${message}`)
  } finally {
    if (originalStorage === undefined) {
      delete process.env.LSB_STORAGE
    } else {
      process.env.LSB_STORAGE = originalStorage
    }
    if (sandbox) {
      await withSmokeTimeout('direct-ro-stop', dataDir, () => sandbox.stop(), 60_000)
    }
    stageInstanceDiagnostics('direct-ro', dataDir)
    rmSync(dataDir, { recursive: true, force: true })
  }
}

if (process.platform !== 'win32' || process.arch !== 'x64') {
  throw new Error(`Windows Node smoke requires win32/x64, got ${process.platform}/${process.arch}`)
}

const { Sandbox, initSandbox } = loadBinding()
if (typeof Sandbox?.start !== 'function') {
  throw new Error('Windows Node binding did not export Sandbox.start')
}
if (typeof initSandbox !== 'function') {
  throw new Error('Windows Node binding did not export initSandbox')
}

await expectMissingQemuPreflight(Sandbox)
await expectSandboxStart(Sandbox, initSandbox)
await expectDirectReadOnlyMount(Sandbox)
