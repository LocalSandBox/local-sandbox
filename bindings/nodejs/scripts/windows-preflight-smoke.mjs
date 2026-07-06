import { copyFileSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
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
      await sandbox.stop()
    }
    rmSync(dataDir, { recursive: true, force: true })
  }
}

async function expectDirectReadOnlyMount(Sandbox) {
  const dataDir = prepareDataDir('direct-ro')
  const source = join(dataDir, 'direct-ro-source')
  mkdirSync(source, { recursive: true })
  writeFileSync(join(source, 'input.txt'), 'node-direct-ro-host')
  let sandbox = null

  try {
    sandbox = await Sandbox.start({
      dataDir,
      instanceId: `node-direct-ro-${process.pid}`,
      mounts: [{ type: 'direct', hostPath: source, guestPath: '/node-ro', flags: 1 }],
    })

    let result = await sandbox.exec(['/bin/cat', '/node-ro/input.txt'])
    if (result.exitCode !== 0 || result.stdout !== 'node-direct-ro-host') {
      throw new Error(
        `direct read-only mount did not expose host file: exit=${result.exitCode} stdout=${JSON.stringify(result.stdout)} stderr=${JSON.stringify(result.stderr)}`,
      )
    }

    writeFileSync(join(source, 'after-start.txt'), 'node-direct-ro-live-host')
    result = await sandbox.exec([
      '/bin/sh',
      '-c',
      'i=0; while [ "$i" -lt 8 ]; do test "$(cat /node-ro/after-start.txt 2>/dev/null || true)" = "node-direct-ro-live-host" && exit 0; i=$((i + 1)); sleep 1; done; exit 1',
    ])
    if (result.exitCode !== 0) {
      throw new Error(`direct read-only mount did not expose live host update: ${result.stderr}`)
    }

    result = await sandbox.exec([
      '/bin/sh',
      '-c',
      'if printf guest-write > /node-ro/guest.txt 2>/tmp/node-ro-write.err; then exit 42; fi; printf ro-denied',
    ])
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
    if (sandbox) {
      await sandbox.stop()
    }
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
