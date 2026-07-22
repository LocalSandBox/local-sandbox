import { closeSync, mkdtempSync, openSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import test from 'ava'

import { getRuntimeReadiness, isSupportedRuntimePlatform, useBuiltEntrypoint } from './helpers'

test('exports the documented runtime methods from the built entrypoint', (t) => {
  const entrypoint = useBuiltEntrypoint(t)
  if (!entrypoint) {
    return
  }

  const { Sandbox, SeaWorkService, connectSeaWorkService } = entrypoint

  t.is(typeof Sandbox.prototype.spawn, 'function')
  t.is(typeof Sandbox.prototype.watch, 'function')
  t.is(typeof Sandbox.prototype.mkdir, 'function')
  t.is(typeof Sandbox.prototype.remove, 'function')
  t.is(typeof Sandbox.prototype.rename, 'function')
  t.is(typeof Sandbox.prototype.copy, 'function')
  t.is(typeof Sandbox.prototype.chmod, 'function')
  t.is(typeof connectSeaWorkService, 'function')
  t.is(typeof SeaWorkService.connect, 'function')
  t.is(typeof SeaWorkService.prototype.getServiceInfo, 'function')
  t.is(typeof SeaWorkService.prototype.healthCheck, 'function')
  t.is(typeof SeaWorkService.prototype.startSandbox, 'function')
})

test('supported builds reject mount host paths that do not exist before boot', async (t) => {
  const entrypoint = useBuiltEntrypoint(t)
  if (!entrypoint) {
    return
  }

  const { Sandbox } = entrypoint

  if (!isSupportedRuntimePlatform()) {
    t.pass()
    return
  }

  const parentDir = mkdtempSync(join(tmpdir(), 'lsb-nodejs-missing-mount-'))
  const missingHostPath = join(parentDir, 'does-not-exist')
  t.teardown(() => {
    rmSync(parentDir, { recursive: true, force: true })
  })

  const error = await t.throwsAsync(() =>
    Sandbox.start({
      mounts: [{ type: 'overlay', hostPath: missingHostPath, guestPath: '/workspace' }],
    }),
  )

  t.truthy(error)
  t.regex(error?.message ?? '', /host path does not exist/i)
})

test.serial(
  'macOS serial output cannot be redirected into a reused host file descriptor',
  async (t) => {
    const entrypoint = useBuiltEntrypoint(t)
    if (!entrypoint) {
      return
    }

    if (process.platform !== 'darwin') {
      t.pass()
      return
    }

    const readiness = getRuntimeReadiness()
    if (!readiness.ok) {
      t.log(readiness.message)
      t.pass()
      return
    }

    const testDir = mkdtempSync(join(tmpdir(), 'lsb-nodejs-serial-fd-'))
    const sentinelPath = join(testDir, 'sentinel')
    const sentinelContents = `sentinel-${process.pid}-${Date.now()}`
    writeFileSync(sentinelPath, sentinelContents)

    const { Sandbox } = entrypoint
    let sandbox: Awaited<ReturnType<typeof Sandbox.start>> | undefined
    let sentinelFd: number | undefined

    try {
      sandbox = await Sandbox.start({ dataDir: readiness.dataDir })

      // Open only after start() so this descriptor can reuse the number formerly
      // occupied by create_vm()'s local /dev/null File in the buggy implementation.
      sentinelFd = openSync(sentinelPath, 'r+')
      const result = await sandbox.exec(`printf '%s' 'lsb-nodejs-serial-probe' > /dev/hvc0`)
      t.is(result.exitCode, 0)

      await sandbox.stop()
      sandbox = undefined

      t.is(readFileSync(sentinelPath, 'utf8'), sentinelContents)
    } finally {
      if (sentinelFd !== undefined) {
        closeSync(sentinelFd)
      }
      await sandbox?.stop()
      rmSync(testDir, { recursive: true, force: true })
    }
  },
)
