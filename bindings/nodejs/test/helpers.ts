import { spawnSync } from 'node:child_process'
import { existsSync, readdirSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import type { ExecutionContext } from 'ava'

export type NodejsBinding = typeof import('../index.js')
export type SandboxInstance = InstanceType<NodejsBinding['Sandbox']>

const require = createRequire(import.meta.url)
const testDir = dirname(fileURLToPath(import.meta.url))

export const projectRoot = join(testDir, '..')
export const entrypointPath = join(projectRoot, 'index.js')
export const defaultRuntimeDataDir = join(process.env.HOME ?? '/tmp', '.local', 'share', 'shuru')

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

export function getBuiltNativeArtifacts() {
  return readdirSync(projectRoot)
    .filter((entry) => entry.startsWith('shuru-nodejs.') && entry.endsWith('.node'))
    .sort()
}

export function getCurrentPlatformBindingCandidates() {
  return localBindingCandidatesByPlatform[process.platform]?.[process.arch] ?? []
}

export function canLoadBuiltEntrypoint() {
  const currentPlatformCandidates = getCurrentPlatformBindingCandidates()
  return currentPlatformCandidates.some((candidate) => existsSync(join(projectRoot, candidate)))
}

export function resolveRuntimeDataDir() {
  return process.env.SHURU_NODEJS_TEST_DATA_DIR || defaultRuntimeDataDir
}

export function hasRuntimeAssets(dataDir: string) {
  return existsSync(join(dataDir, 'Image')) && existsSync(join(dataDir, 'rootfs.ext4'))
}

export function resolveNodeBinaryForEntitlementCheck() {
  return process.env.SHURU_NODEJS_TEST_NODE_BINARY || process.execPath
}

export function hasVirtualizationEntitlement() {
  const nodeBinary = resolveNodeBinaryForEntitlementCheck()
  const result = spawnSync('codesign', ['-d', '--entitlements', ':-', nodeBinary], {
    encoding: 'utf8',
  })

  return `${result.stdout ?? ''}\n${result.stderr ?? ''}`.includes(
    'com.apple.security.virtualization',
  )
}

export function loadBuiltEntrypoint(): NodejsBinding {
  return require(entrypointPath) as NodejsBinding
}

export function isSupportedRuntimePlatform() {
  return process.platform === 'darwin' && process.arch === 'arm64'
}

export function makeGuestPath(label: string) {
  return `/tmp/shuru-nodejs-${label}-${process.pid}-${Date.now()}`
}

export function getRuntimeReadiness(options: { requireDefaultDataDir?: boolean } = {}) {
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

export function useBuiltEntrypoint(t: ExecutionContext) {
  if (!canLoadBuiltEntrypoint()) {
    t.log(
      `no native binding artifact for ${process.platform}/${process.arch} is present in ${projectRoot}; skipping entrypoint load assertions`,
    )
    t.pass()
    return null
  }

  return loadBuiltEntrypoint()
}

export function createSharedRuntimeHarness() {
  let sandbox: SandboxInstance | null = null
  let skipMessage: string | null = null

  return {
    async before() {
      if (!canLoadBuiltEntrypoint()) {
        skipMessage = `no native binding artifact for ${process.platform}/${process.arch} is present in ${projectRoot}; skipping VM-backed tests`
        return
      }

      const readiness = getRuntimeReadiness()
      if (!readiness.ok) {
        skipMessage = readiness.message
        return
      }

      const { Sandbox } = loadBuiltEntrypoint()
      sandbox = await Sandbox.start({ dataDir: readiness.dataDir })
    },

    async after() {
      await sandbox?.stop()
    },

    use(t: ExecutionContext) {
      if (sandbox) {
        return sandbox
      }

      if (skipMessage) {
        t.log(skipMessage)
      }
      t.pass()
      return null
    },
  }
}

export async function waitFor(
  predicate: () => boolean,
  options: { timeoutMs?: number; intervalMs?: number } = {},
) {
  const timeoutMs = options.timeoutMs ?? 5_000
  const intervalMs = options.intervalMs ?? 100
  const deadline = Date.now() + timeoutMs

  while (Date.now() < deadline) {
    if (predicate()) {
      return
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs))
  }

  throw new Error(`condition was not met within ${timeoutMs}ms`)
}
