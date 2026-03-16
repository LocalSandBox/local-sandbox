import { spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, readdirSync, rmSync } from 'node:fs'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import test, { type ExecutionContext } from 'ava'

type NodejsBinding = typeof import('../index.js')
type SandboxInstance = InstanceType<NodejsBinding['Sandbox']>

const require = createRequire(import.meta.url)
const testDir = dirname(fileURLToPath(import.meta.url))
const projectRoot = join(testDir, '..')
const entrypointPath = join(projectRoot, 'index.js')
const defaultRuntimeDataDir = join(process.env.HOME ?? '/tmp', '.local', 'share', 'shuru')

const localBindingCandidatesByPlatform: Partial<
  Record<NodeJS.Platform, Partial<Record<string, string[]>>>
> = {
  darwin: {
    x64: ['shuru-nodejs.darwin-universal.node', 'shuru-nodejs.darwin-x64.node'],
    arm64: ['shuru-nodejs.darwin-universal.node', 'shuru-nodejs.darwin-arm64.node'],
  },
  linux: {
    x64: ['shuru-nodejs.linux-x64-musl.node', 'shuru-nodejs.linux-x64-gnu.node'],
    arm64: ['shuru-nodejs.linux-arm64-musl.node', 'shuru-nodejs.linux-arm64-gnu.node'],
    arm: ['shuru-nodejs.linux-arm-gnueabihf.node'],
    riscv64: ['shuru-nodejs.linux-riscv64-gnu.node'],
    ppc64: ['shuru-nodejs.linux-ppc64-gnu.node'],
    s390x: ['shuru-nodejs.linux-s390x-gnu.node'],
  },
  win32: {
    x64: ['shuru-nodejs.win32-x64-msvc.node'],
    ia32: ['shuru-nodejs.win32-ia32-msvc.node'],
    arm64: ['shuru-nodejs.win32-arm64-msvc.node'],
  },
}

function getBuiltNativeArtifacts() {
  return readdirSync(projectRoot)
    .filter((entry) => entry.startsWith('shuru-nodejs.') && entry.endsWith('.node'))
    .sort()
}

function getCurrentPlatformBindingCandidates() {
  if (!isSupportedRuntimePlatform()) {
    return []
  }

  return localBindingCandidatesByPlatform[process.platform]?.[process.arch] ?? []
}

function canLoadBuiltEntrypoint() {
  const currentPlatformCandidates =
    localBindingCandidatesByPlatform[process.platform]?.[process.arch] ?? []

  return currentPlatformCandidates.some((candidate) => existsSync(join(projectRoot, candidate)))
}

function resolveRuntimeDataDir() {
  return process.env.SHURU_NODEJS_TEST_DATA_DIR || defaultRuntimeDataDir
}

function hasRuntimeAssets(dataDir: string) {
  return existsSync(join(dataDir, 'Image')) && existsSync(join(dataDir, 'rootfs.ext4'))
}

function resolveNodeBinaryForEntitlementCheck() {
  return process.env.SHURU_NODEJS_TEST_NODE_BINARY || process.execPath
}

function hasVirtualizationEntitlement() {
  const nodeBinary = resolveNodeBinaryForEntitlementCheck()
  const result = spawnSync('codesign', ['-d', '--entitlements', ':-', nodeBinary], {
    encoding: 'utf8',
  })

  return `${result.stdout ?? ''}\n${result.stderr ?? ''}`.includes(
    'com.apple.security.virtualization',
  )
}

function loadBuiltEntrypoint(): NodejsBinding {
  return require(entrypointPath) as NodejsBinding
}

function isSupportedRuntimePlatform() {
  return process.platform === 'darwin' && process.arch === 'arm64'
}

function makeGuestPath(label: string) {
  return `/tmp/shuru-nodejs-${label}-${process.pid}-${Date.now()}`
}

function getRuntimeReadiness(options: { requireDefaultDataDir?: boolean } = {}) {
  if (!isSupportedRuntimePlatform()) {
    return {
      ok: false as const,
      message:
        'positive VM tests require macOS on Apple Silicon; non-darwin/arm64 coverage is limited to load and validation checks',
    }
  }

  const dataDir = options.requireDefaultDataDir ? defaultRuntimeDataDir : resolveRuntimeDataDir()
  if (!hasRuntimeAssets(dataDir)) {
    const qualifier = options.requireDefaultDataDir
      ? 'default runtime assets are required for checkpoint resume coverage'
      : 'runtime assets not found'

    return {
      ok: false as const,
      message: `${qualifier} in ${dataDir}; run "shuru init" or set SHURU_NODEJS_TEST_DATA_DIR to enable these VM tests`,
    }
  }

  if (!hasVirtualizationEntitlement()) {
    const nodeBinary = resolveNodeBinaryForEntitlementCheck()
    return {
      ok: false as const,
      message: `node executable at ${nodeBinary} does not have com.apple.security.virtualization; codesign it with shuru.entitlements to enable these VM tests`,
    }
  }

  return { ok: true as const, dataDir }
}

let sharedRuntimeSandbox: SandboxInstance | null = null
let sharedRuntimeSkipMessage: string | null = null

function useSharedRuntimeSandbox(t: ExecutionContext) {
  if (sharedRuntimeSandbox) {
    return sharedRuntimeSandbox
  }

  if (sharedRuntimeSkipMessage) {
    t.log(sharedRuntimeSkipMessage)
  }
  t.pass()
  return null
}

function useBuiltEntrypoint(t: ExecutionContext) {
  if (!canLoadBuiltEntrypoint()) {
    t.log(
      `no native binding artifact for ${process.platform}/${process.arch} is present in ${projectRoot}; skipping entrypoint load assertions`,
    )
    t.pass()
    return null
  }

  return loadBuiltEntrypoint()
}

test.serial.before(async () => {
  if (!canLoadBuiltEntrypoint()) {
    sharedRuntimeSkipMessage = `no native binding artifact for ${process.platform}/${process.arch} is present in ${projectRoot}; skipping VM-backed tests`
    return
  }

  const readiness = getRuntimeReadiness()
  if (!readiness.ok) {
    sharedRuntimeSkipMessage = readiness.message
    return
  }

  const { Sandbox } = loadBuiltEntrypoint()
  sharedRuntimeSandbox = await Sandbox.start({ dataDir: readiness.dataDir })
})

test.after.always(async () => {
  await sharedRuntimeSandbox?.stop()
})

test('build outputs exist for the root entrypoint', (t) => {
  t.true(existsSync(entrypointPath), `missing built entrypoint: ${entrypointPath}`)

  const builtNativeArtifacts = getBuiltNativeArtifacts()
  t.true(
    builtNativeArtifacts.length > 0,
    `expected at least one built native binding in ${projectRoot}, found none`,
  )

  const currentPlatformCandidates = getCurrentPlatformBindingCandidates()
  if (currentPlatformCandidates.length > 0) {
    t.true(
      currentPlatformCandidates.some((candidate) => builtNativeArtifacts.includes(candidate)),
      `expected one of ${currentPlatformCandidates.join(', ')}; found ${builtNativeArtifacts.join(', ')}`,
    )
  }
})

test('exports Sandbox class and the expected core methods from the built entrypoint', (t) => {
  const entrypoint = useBuiltEntrypoint(t)
  if (!entrypoint) {
    t.log('entrypoint not found')
    return
  }

  const { Sandbox } = entrypoint

  t.is(typeof Sandbox, 'function')
  t.is(typeof Sandbox.start, 'function')
  t.is(typeof Sandbox.prototype.exec, 'function')
  t.is(typeof Sandbox.prototype.execShell, 'function')
  t.is(typeof Sandbox.prototype.readFile, 'function')
  t.is(typeof Sandbox.prototype.writeFile, 'function')
  t.is(typeof Sandbox.prototype.spawn, 'function')
  t.is(typeof Sandbox.prototype.watch, 'function')
  t.is(typeof Sandbox.prototype.mkdir, 'function')
  t.is(typeof Sandbox.prototype.readDir, 'function')
  t.is(typeof Sandbox.prototype.stat, 'function')
  t.is(typeof Sandbox.prototype.remove, 'function')
  t.is(typeof Sandbox.prototype.rename, 'function')
  t.is(typeof Sandbox.prototype.copy, 'function')
  t.is(typeof Sandbox.prototype.chmod, 'function')
  t.is(typeof Sandbox.prototype.exists, 'function')
  t.is(typeof Sandbox.prototype.checkpoint, 'function')
  t.is(typeof Sandbox.prototype.stop, 'function')
})

test('unsupported platforms fail with a clear unsupported error', async (t) => {
  const entrypoint = useBuiltEntrypoint(t)
  if (!entrypoint) {
    t.log('entrypoint not found')
    return
  }

  const { Sandbox } = entrypoint

  if (isSupportedRuntimePlatform()) {
    t.log('supported runtime platform')
    t.pass()
    return
  }

  const error = await t.throwsAsync(() => Sandbox.start())
  t.regex(error?.message ?? '', /only macOS on Apple Silicon|darwin\/arm64/i)
})

test('supported builds validate startup inputs through the Rust SDK path', async (t) => {
  const entrypoint = useBuiltEntrypoint(t)
  if (!entrypoint) {
    t.log('entrypoint not found')
    return
  }

  const { Sandbox } = entrypoint

  if (!isSupportedRuntimePlatform()) {
    t.log('not supported runtime platform')
    t.pass()
    return
  }

  const missingDataDir = join(tmpdir(), 'shuru-nodejs-missing-assets')
  const error = await t.throwsAsync(() => Sandbox.start({ dataDir: missingDataDir }))

  t.truthy(error)
  t.true(
    /Kernel not found|Rootfs not found/.test(error?.message ?? ''),
    `unexpected error message: ${error?.message ?? '<empty>'}`,
  )
})

test('supported builds reject invalid port mappings before boot', async (t) => {
  const entrypoint = useBuiltEntrypoint(t)
  if (!entrypoint) {
    t.log('entrypoint not found')
    return
  }

  const { Sandbox } = entrypoint

  if (!isSupportedRuntimePlatform()) {
    t.log('not supported runtime platform')
    t.pass()
    return
  }

  const error = await t.throwsAsync(() => Sandbox.start({ ports: ['invalid'] }))

  t.truthy(error)
  t.regex(error?.message ?? '', /HOST:GUEST|invalid host port|invalid guest port/i)
})

test('supported builds reject relative guest mount paths before boot', async (t) => {
  const entrypoint = useBuiltEntrypoint(t)
  if (!entrypoint) {
    t.log('entrypoint not found')
    return
  }

  const { Sandbox } = entrypoint

  if (!isSupportedRuntimePlatform()) {
    t.log('not supported runtime platform')
    t.pass()
    return
  }

  const hostDir = mkdtempSync(join(tmpdir(), 'shuru-nodejs-mount-'))
  t.teardown(() => {
    rmSync(hostDir, { recursive: true, force: true })
  })

  const error = await t.throwsAsync(() =>
    Sandbox.start({
      mounts: {
        [hostDir]: 'workspace',
      },
    }),
  )

  t.truthy(error)
  t.regex(error?.message ?? '', /guest path must be absolute/i)
})

test('supported builds reject missing host mount paths before boot', async (t) => {
  const entrypoint = useBuiltEntrypoint(t)
  if (!entrypoint) {
    t.log('entrypoint not found')
    return
  }

  const { Sandbox } = entrypoint

  if (!isSupportedRuntimePlatform()) {
    t.log('not supported runtime platform')
    t.pass()
    return
  }

  const missingHostDir = join(tmpdir(), `shuru-nodejs-missing-mount-${process.pid}-${Date.now()}`)
  const error = await t.throwsAsync(() =>
    Sandbox.start({
      mounts: {
        [missingHostDir]: '/workspace',
      },
    }),
  )

  t.truthy(error)
  t.regex(error?.message ?? '', /host path does not exist/i)
})

test('supported builds reject secret definitions without a source env var', async (t) => {
  const entrypoint = useBuiltEntrypoint(t)
  if (!entrypoint) {
    t.log('entrypoint not found')
    return
  }

  const { Sandbox } = entrypoint

  if (!isSupportedRuntimePlatform()) {
    t.log('not supported runtime platform')
    t.pass()
    return
  }

  const error = await t.throwsAsync(() =>
    Sandbox.start({
      secrets: {
        API_KEY: { value: '', hosts: ['api.openai.com'] },
      },
    }),
  )

  t.truthy(error)
  t.regex(error?.message ?? '', /secret value must be non-empty/i)
})

test('supported builds reject secret definitions without allowed hosts', async (t) => {
  const entrypoint = useBuiltEntrypoint(t)
  if (!entrypoint) {
    t.log('entrypoint not found')
    return
  }

  const { Sandbox } = entrypoint

  if (!isSupportedRuntimePlatform()) {
    t.log('not supported runtime platform')
    t.pass()
    return
  }

  const error = await t.throwsAsync(() =>
    Sandbox.start({
      secrets: {
        API_KEY: { value: 'OPENAI_API_KEY', hosts: [] },
      },
    }),
  )

  t.truthy(error)
  t.regex(error?.message ?? '', /secret hosts must be non-empty/i)
})

test.serial('supported runtime exposes instanceDir and runs exec variants', async (t) => {
  const sandbox = useSharedRuntimeSandbox(t)
  if (!sandbox) {
    t.log('sandbox not found')
    return
  }

  t.true(sandbox.instanceDir.length > 0)

  const execResult = await sandbox.exec('echo hello-from-nodejs && echo stderr-line >&2')
  t.is(execResult.exitCode, 0)
  t.is(execResult.stdout.trim(), 'hello-from-nodejs')
  t.is(execResult.stderr.trim(), 'stderr-line')

  const argvResult = await sandbox.exec(['sh', '-lc', 'printf "%s" "argv-mode"'])
  t.is(argvResult.exitCode, 0)
  t.is(argvResult.stdout, 'argv-mode')
  t.is(argvResult.stderr, '')

  const shellResult = await sandbox.execShell('printf "%s" "exec-shell-mode"')
  t.is(shellResult.exitCode, 0)
  t.is(shellResult.stdout, 'exec-shell-mode')
  t.is(shellResult.stderr, '')

  const nonZeroResult = await sandbox.exec('exit 42')
  t.is(nonZeroResult.exitCode, 42)
})

test.serial(
  'supported runtime round-trips files through writeFile, readFile, and sequential execs',
  async (t) => {
    const sandbox = useSharedRuntimeSandbox(t)
    if (!sandbox) {
      t.log('sandbox not found')
      return
    }

    const textPath = makeGuestPath('roundtrip.txt')
    const binaryPath = makeGuestPath('roundtrip.bin')
    const sequentialPath = makeGuestPath('sequential.txt')

    const textContent = 'hello from shuru-nodejs\nline 2\n'
    await sandbox.writeFile(textPath, textContent)
    const textReadback = await sandbox.readFile(textPath)
    t.true(Buffer.isBuffer(textReadback))
    t.is(textReadback.toString('utf8'), textContent)

    const binaryContent = Buffer.from([0, 1, 2, 3, 254, 255])
    await sandbox.writeFile(binaryPath, binaryContent)
    const binaryReadback = await sandbox.readFile(binaryPath)
    t.deepEqual([...binaryReadback], [...binaryContent])

    await sandbox.exec(`printf "a\\n" > ${sequentialPath}`)
    await sandbox.exec(`printf "b\\n" >> ${sequentialPath}`)
    const sequentialReadback = await sandbox.readFile(sequentialPath)
    t.is(sequentialReadback.toString('utf8'), 'a\nb\n')
  },
)

test.serial(
  'supported runtime reports readDir, stat, and exists results like the SDK',
  async (t) => {
    const sandbox = useSharedRuntimeSandbox(t)
    if (!sandbox) {
      t.log('sandbox not found')
      return
    }

    const baseDir = makeGuestPath('filesystem')
    const textPath = `${baseDir}/hello.txt`
    const subdirPath = `${baseDir}/subdir`
    const missingPath = `${baseDir}/missing.txt`

    await sandbox.exec(`mkdir -p ${subdirPath}`)
    await sandbox.writeFile(textPath, 'hello')

    const entries = await sandbox.readDir(baseDir)
    const names = entries.map((entry) => entry.name).sort()
    t.deepEqual(names, ['hello.txt', 'subdir'])

    const fileEntry = entries.find((entry) => entry.name === 'hello.txt')
    t.is(fileEntry?.type, 'file')
    t.is(fileEntry?.size, 5)

    const dirEntry = entries.find((entry) => entry.name === 'subdir')
    t.is(dirEntry?.type, 'dir')

    const stat = await sandbox.stat(textPath)
    t.is(stat.size, 5)
    t.true(stat.isFile)
    t.false(stat.isDir)
    t.false(stat.isSymlink)
    t.true(stat.mtime > 0)
    t.true(stat.mode > 0)

    t.true(await sandbox.exists(textPath))
    t.false(await sandbox.exists(missingPath))
  },
)

test.serial('supported runtime checkpoints can be resumed through from', async (t) => {
  const readiness = getRuntimeReadiness({ requireDefaultDataDir: true })
  if (!readiness.ok) {
    t.log(readiness.message)
    t.pass()
    return
  }

  const entrypoint = useBuiltEntrypoint(t)
  if (!entrypoint) {
    return
  }

  const { Sandbox } = entrypoint
  const checkpointName = `nodejs-test-${process.pid}-${Date.now()}`
  const checkpointPath = join(defaultRuntimeDataDir, 'checkpoints', `${checkpointName}.ext4`)
  let base: SandboxInstance | null = null
  let resumed: SandboxInstance | null = null

  try {
    rmSync(checkpointPath, { force: true })

    base = await Sandbox.start({ dataDir: readiness.dataDir })
    await base.exec('mkdir -p /workspace && printf "%s" "checkpoint-ready" > /workspace/state.txt')
    await base.checkpoint(checkpointName)
    t.true(existsSync(checkpointPath))

    // Checkpoints are currently resolved from the default runtime data dir.
    resumed = await Sandbox.start({ dataDir: readiness.dataDir, from: checkpointName })
    const state = await resumed.readFile('/workspace/state.txt')
    t.is(state.toString('utf8'), 'checkpoint-ready')
  } finally {
    await resumed?.stop()
    await base?.stop()
    rmSync(checkpointPath, { force: true })
  }
})
