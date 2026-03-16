import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import test from 'ava'

import { isSupportedRuntimePlatform, useBuiltEntrypoint } from './helpers'

test('exports the documented runtime methods from the built entrypoint', (t) => {
  const entrypoint = useBuiltEntrypoint(t)
  if (!entrypoint) {
    return
  }

  const { Sandbox } = entrypoint

  t.is(typeof Sandbox.prototype.spawn, 'function')
  t.is(typeof Sandbox.prototype.watch, 'function')
  t.is(typeof Sandbox.prototype.mkdir, 'function')
  t.is(typeof Sandbox.prototype.remove, 'function')
  t.is(typeof Sandbox.prototype.rename, 'function')
  t.is(typeof Sandbox.prototype.copy, 'function')
  t.is(typeof Sandbox.prototype.chmod, 'function')
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

  const parentDir = mkdtempSync(join(tmpdir(), 'shuru-nodejs-missing-mount-'))
  const missingHostPath = join(parentDir, 'does-not-exist')
  t.teardown(() => {
    rmSync(parentDir, { recursive: true, force: true })
  })

  const error = await t.throwsAsync(() =>
    Sandbox.start({
      mounts: {
        [missingHostPath]: '/workspace',
      },
    }),
  )

  t.truthy(error)
  t.regex(error?.message ?? '', /host path does not exist/i)
})
