import { readFileSync, writeFileSync } from 'node:fs'
import { pathToFileURL } from 'node:url'

const configPath = process.argv[2]
if (!configPath) throw new Error('acceptance config path is required')
const config = JSON.parse(readFileSync(configPath, 'utf8'))
const binding = await import(pathToFileURL(config.bindingEntry).href)

const checks = []
const check = (name, passed, detail = undefined) => {
  if (!passed) throw new Error(`acceptance check failed: ${name}`)
  checks.push(detail === undefined ? { name, passed: true } : { name, passed: true, detail })
}
const collect = async (next) => {
  const chunks = []
  for (;;) {
    const chunk = await next()
    if (chunk === null) return Buffer.concat(chunks).toString('utf8')
    chunks.push(Buffer.from(chunk))
  }
}

let service
let sandbox
try {
  service = await binding.connectSeaWorkService({ connectTimeoutMs: 15000 })
  const info = await service.getServiceInfo()
  const health = await service.healthCheck()
  check('service-health', health.ready && health.admissionsOpen && health.stableCode === 'READY')
  check(
    'direct-mount-capability',
    info.capabilities.directMount &&
      info.capabilities.directMountBackends.includes('compat-smb-direct') &&
      !info.capabilities.ports,
  )

  const start = {
    instanceId: config.instanceId,
    cpus: 2,
    memoryMb: 2048,
    diskSizeMb: 4096,
  }
  if (Array.isArray(config.mounts)) start.mounts = config.mounts
  if (config.network) start.network = config.network
  sandbox = await service.start(start)

  const unary = await sandbox.exec(['/bin/sh', '-c', 'printf unary-out; printf unary-err >&2'])
  check(
    'unary-exec',
    unary.exitCode === 0 && unary.stdout === 'unary-out' && unary.stderr === 'unary-err',
  )

  await sandbox.mkdir('/tmp/lsb-acceptance/nested', { recursive: true })
  await sandbox.writeFile('/tmp/lsb-acceptance/nested/value.txt', 'filesystem-ok')
  const file = await sandbox.readFile('/tmp/lsb-acceptance/nested/value.txt')
  check('filesystem', Buffer.from(file).toString('utf8') === 'filesystem-ok')

  const processHandle = await sandbox.spawn([
    '/bin/sh',
    '-c',
    'printf spawn-out; printf spawn-err >&2; exit 7',
  ])
  const [stdout, stderr, exitCode] = await Promise.all([
    collect(() => processHandle.nextStdout()),
    collect(() => processHandle.nextStderr()),
    processHandle.exited,
  ])
  check('spawn-stream-exit', stdout === 'spawn-out' && stderr === 'spawn-err' && exitCode === 7)

  const killed = await sandbox.spawn(['/bin/sh', '-c', 'sleep 60'])
  await new Promise((resolve) => setTimeout(resolve, 250))
  await killed.kill()
  const killedExit = await killed.exited
  check('spawn-kill', Number.isInteger(killedExit) && killedExit !== 0)

  const cancellable = await sandbox.beginExec(['/bin/sh', '-c', 'sleep 60'])
  await cancellable.cancel()
  let cancelled = false
  try {
    await cancellable.complete()
  } catch {
    cancelled = true
  }
  check('exec-cancellation', cancelled)

  if (config.mounts?.length) {
    const mountProbe = await sandbox.exec([
      '/bin/sh',
      '-c',
      [
        'set -eu',
        'test "$(cat /workspace/input.txt)" = workspace-input',
        'test "$(cat /skills/skill.txt)" = skill-input',
        'test "$(cat /uploaded_files/upload.txt)" = upload-input',
        'if printf denied > /workspace/forbidden.txt 2>/dev/null; then exit 21; fi',
        'if printf denied > /skills/forbidden.txt 2>/dev/null; then exit 22; fi',
        'if printf denied > /uploaded_files/forbidden.txt 2>/dev/null; then exit 23; fi',
        'printf nested-output > /workspace/output/result.txt',
      ].join('; '),
    ])
    check('direct-mount-layout', mountProbe.exitCode === 0, `exit-${mountProbe.exitCode}`)
  }

  await sandbox.stop()
  sandbox = undefined
  await service.close()
  service = undefined
  writeFileSync(
    config.resultPath,
    `${JSON.stringify({ schema_version: 1, status: 'passed', checks })}\n`,
    'utf8',
  )
} catch (error) {
  try {
    if (sandbox) await sandbox.stop()
  } catch {}
  try {
    if (service) await service.close()
  } catch {}
  writeFileSync(
    config.resultPath,
    `${JSON.stringify({
      schema_version: 1,
      status: 'failed',
      stable_error: error instanceof Error ? error.name : 'unknown',
      checks,
    })}\n`,
    'utf8',
  )
  process.exitCode = 1
}
