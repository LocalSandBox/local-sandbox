import { readFileSync, writeFileSync } from 'node:fs'
import { userInfo } from 'node:os'
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
let resultExtras = {}
let failedStage = 'identity'
try {
  check(
    'filtered-current-user-identity',
    userInfo().username.toLowerCase() === config.expectedUserName.toLowerCase(),
  )
  failedStage = 'connect-service'
  service = await binding.connectSeaWorkService({ connectTimeoutMs: 15000 })
  failedStage = 'service-info'
  const info = await service.getServiceInfo()
  failedStage = 'service-health'
  const health = await service.healthCheck()
  check('service-health', health.ready && health.admissionsOpen && health.stableCode === 'READY')
  check(
    'direct-mount-capability',
    info.capabilities.directMount &&
      info.capabilities.directMountBackends.includes('compat-smb-direct') &&
      !info.capabilities.ports,
  )

  if (config.scenario === 'update-check') {
    failedStage = 'update-check-trigger'
    await service.checkForUpdate()
    let sawChecking = false
    let finalStatus
    const observedPhases = new Set()
    const deadline = Date.now() + 120_000
    while (Date.now() < deadline) {
      failedStage = 'update-check-status'
      const status = await service.getUpdateStatus()
      observedPhases.add(status.phase)
      resultExtras = { updateStatus: status, observedUpdatePhases: [...observedPhases] }
      if (status.phase === 'update_checking') sawChecking = true
      if (status.phase === 'update_no_candidate') {
        finalStatus = status
        break
      }
      await new Promise((resolve) => setTimeout(resolve, 100))
    }
    check(
      'candidate-update-check-observed',
      sawChecking || finalStatus?.phase === 'update_no_candidate',
      { transientCheckingObserved: sawChecking },
    )
    check(
      'candidate-update-no-candidate',
      finalStatus?.phase === 'update_no_candidate' && finalStatus?.target == null,
    )
    resultExtras = { updateStatus: finalStatus }
  } else if (config.scenario === 'sequential') {
    for (let effect = 1; effect <= 10; effect += 1) {
      failedStage = `sequential-start-${effect}`
      sandbox = await service.start({
        instanceId: `${config.instanceId}-${effect}`,
        cpus: 2,
        memoryMb: 2048,
        diskSizeMb: 4096,
      })
      failedStage = `sequential-effect-${effect}`
      const result = await sandbox.exec(['/bin/sh', '-c', `printf effect-${effect}`])
      check(
        `sequential-effect-${effect}`,
        result.exitCode === 0 && result.stdout === `effect-${effect}` && result.stderr === '',
      )
      failedStage = `sequential-stop-${effect}`
      await sandbox.stop()
      sandbox = undefined
    }
    resultExtras = { effects: 10 }
  } else {
    const start = {
      instanceId: config.instanceId,
      cpus: 2,
      memoryMb: 2048,
      diskSizeMb: 4096,
    }
    if (Array.isArray(config.mounts)) start.mounts = config.mounts
    if (config.network) start.network = config.network
    failedStage = 'sandbox-start'
    sandbox = await service.start(start)

    if (config.scenario === 'network') {
      failedStage = 'public-dns'
      const dns = await sandbox.exec([
        '/bin/sh',
        '-c',
        'getent hosts example.com >/dev/null',
      ])
      check('public-dns', dns.exitCode === 0)

      failedStage = 'public-http'
      const http = await sandbox.exec([
        '/bin/sh',
        '-c',
        'curl -fsS --max-time 30 http://example.com/ >/dev/null',
      ])
      check('public-http', http.exitCode === 0)

      failedStage = 'public-https'
      const https = await sandbox.exec([
        '/bin/sh',
        '-c',
        'curl -fsS --max-time 30 https://example.com/ >/dev/null',
      ])
      check('public-https', https.exitCode === 0)

      failedStage = 'package-download'
      const metadata = await sandbox.exec([
        '/bin/sh',
        '-c',
        'curl -fsS --max-time 30 https://registry.npmjs.org/semver/latest',
      ])
      let packageMetadata
      try {
        packageMetadata = JSON.parse(metadata.stdout)
      } catch {}
      check(
        'package-download',
        metadata.exitCode === 0 &&
          packageMetadata?.name === 'semver' &&
          typeof packageMetadata?.version === 'string',
      )

      failedStage = 'scoped-secret-injection'
      const secret = await sandbox.exec([
        '/bin/sh',
        '-c',
        'curl -fsS --max-time 30 -H "X-LSB-Test: $LSB_TEST_SECRET" https://httpbingo.org/anything',
      ])
      check(
        'scoped-secret-injection',
        secret.exitCode === 0 &&
          typeof config.secretExpected === 'string' &&
          secret.stdout.includes(config.secretExpected),
      )

      failedStage = 'live-network-interception-rotate'
      await sandbox.updateNetworkInterception({
        secrets: {
          LSB_TEST_SECRET: {
            value: config.secretRotatedExpected,
            hosts: ['httpbingo.org'],
          },
        },
        httpsInterception: {
          enabled: true,
          requestHeaders: [
            {
              name: 'X-LSB-Live-Update',
              value: config.headerExpected,
              hosts: { allow: ['httpbingo.org'] },
            },
          ],
        },
      })
      const rotated = await sandbox.exec([
        '/bin/sh',
        '-c',
        'curl -fsS --max-time 30 -H "X-LSB-Test: $LSB_TEST_SECRET" https://httpbingo.org/anything',
      ])
      check(
        'live-network-interception-rotate',
        rotated.exitCode === 0 &&
          typeof config.secretRotatedExpected === 'string' &&
          typeof config.headerExpected === 'string' &&
          rotated.stdout.includes(config.secretRotatedExpected) &&
          rotated.stdout.includes(config.headerExpected) &&
          !rotated.stdout.includes(config.secretExpected),
      )

      failedStage = 'live-network-interception-clear'
      await sandbox.updateNetworkInterception({})
      const cleared = await sandbox.exec([
        '/bin/sh',
        '-c',
        'test -z "${LSB_TEST_SECRET+x}"',
      ])
      check('live-network-interception-clear', cleared.exitCode === 0)

      failedStage = 'private-target-denial'
      const denied = await sandbox.exec([
        '/bin/sh',
        '-c',
        'curl -fsS --max-time 8 http://169.254.169.254/latest/meta-data >/dev/null 2>&1',
      ])
      check('private-target-denied', denied.exitCode !== 0)
    } else {

      failedStage = 'unary-exec'
      const unary = await sandbox.exec(['/bin/sh', '-c', 'printf unary-out; printf unary-err >&2'])
      check(
        'unary-exec',
        unary.exitCode === 0 && unary.stdout === 'unary-out' && unary.stderr === 'unary-err',
      )

      failedStage = 'filesystem'
      await sandbox.mkdir('/tmp/lsb-acceptance/nested', { recursive: true })
      await sandbox.writeFile('/tmp/lsb-acceptance/nested/value.txt', 'filesystem-ok')
      const file = await sandbox.readFile('/tmp/lsb-acceptance/nested/value.txt')
      check('filesystem', Buffer.from(file).toString('utf8') === 'filesystem-ok')

      failedStage = 'spawn-stream-exit'
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
      check(
        'spawn-stream-exit',
        stdout === 'spawn-out' && stderr === 'spawn-err' && exitCode === 7,
      )

      failedStage = 'spawn-kill'
      const killed = await sandbox.spawn(['/bin/sh', '-c', 'sleep 60'])
      await new Promise((resolve) => setTimeout(resolve, 250))
      await killed.kill()
      const killedExit = await killed.exited
      check('spawn-kill', Number.isInteger(killedExit) && killedExit !== 0)

      failedStage = 'exec-cancellation'
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
        failedStage = 'nested-direct-mount-file-api'
        const nestedSkill = await sandbox.readFile('/skills/mis-it-center/SKILL.md')
        check(
          'nested-direct-mount-file-api',
          Buffer.from(nestedSkill).toString('utf8') === 'nested-skill-input',
        )
        failedStage = 'direct-mount-layout'
        const mountProbe = await sandbox.exec([
          '/bin/sh',
          '-c',
          [
            'set -eu',
            'test "$(cat /workspace/input.txt)" = workspace-input',
            'test "$(cat /skills/skill.txt)" = skill-input',
            'test "$(cat /skills/mis-it-center/SKILL.md)" = nested-skill-input',
            'test "$(cat /uploaded_files/upload.txt)" = upload-input',
            'if printf denied > /workspace/forbidden.txt 2>/dev/null; then exit 21; fi',
            'if printf denied > /skills/forbidden.txt 2>/dev/null; then exit 22; fi',
            'if printf denied > /skills/mis-it-center/forbidden.txt 2>/dev/null; then exit 24; fi',
            'if printf denied > /uploaded_files/forbidden.txt 2>/dev/null; then exit 23; fi',
            'printf nested-output > /workspace/output/result.txt',
          ].join('; '),
        ])
        check('direct-mount-layout', mountProbe.exitCode === 0, `exit-${mountProbe.exitCode}`)
      }
    }

    failedStage = 'sandbox-stop'
    await sandbox.stop()
    sandbox = undefined
  }

  failedStage = 'service-close'
  await service.close()
  service = undefined
  writeFileSync(
    config.resultPath,
    `${JSON.stringify({ schema_version: 1, status: 'passed', checks, ...resultExtras })}\n`,
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
      failed_stage: failedStage,
      stable_detail: error instanceof Error ? error.message : 'unknown',
      checks,
      ...resultExtras,
    })}\n`,
    'utf8',
  )
  process.exitCode = 1
}
