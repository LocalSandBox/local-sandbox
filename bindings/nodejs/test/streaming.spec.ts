import test from 'ava'

import { createSharedRuntimeHarness, makeGuestPath, waitFor } from './helpers'

const runtime = createSharedRuntimeHarness()

test.serial.before(async () => {
  await runtime.before()
})

test.after.always(async () => {
  await runtime.after()
})

test.serial(
  'supported runtime spawn streams stdout, stderr, exit, and non-zero exits',
  async (t) => {
    const sandbox = runtime.use(t)
    if (!sandbox) {
      t.log('sandbox not found')
      return
    }

    const stdoutChunks: string[] = []
    const stderrChunks: string[] = []
    const exitCodes: number[] = []
    const proc = await sandbox.spawn(
      'sleep 0.2; echo chunk1; sleep 0.05; echo warn >&2; sleep 0.05; echo chunk2; sleep 0.05; echo chunk3',
    )

    proc.on('stdout', (data) => {
      stdoutChunks.push(data.toString())
    })
    proc.on('stderr', (data) => {
      stderrChunks.push(data.toString())
    })
    proc.on('exit', (code) => {
      exitCodes.push(code)
    })

    const code = await proc.exited
    t.is(code, 0)
    t.deepEqual(exitCodes, [0])
    t.true(stdoutChunks.join('').includes('chunk1'))
    t.true(stdoutChunks.join('').includes('chunk2'))
    t.true(stdoutChunks.join('').includes('chunk3'))
    t.is(stderrChunks.join('').trim(), 'warn')

    const failing = await sandbox.spawn('sleep 0.2; exit 42')
    t.is(await failing.exited, 42)
  },
)

test.serial(
  'supported runtime spawn supports cwd, stdin writes, kill, and unique pids',
  async (t) => {
    const sandbox = runtime.use(t)
    if (!sandbox) {
      t.log('sandbox not found')
      return
    }

    const cwdProc = await sandbox.spawn('sleep 0.2; pwd', { cwd: '/tmp' })
    const cwdChunks: string[] = []
    cwdProc.on('stdout', (data) => {
      cwdChunks.push(data.toString())
    })
    t.is(await cwdProc.exited, 0)
    t.is(cwdChunks.join('').trim(), '/tmp')

    const echoProc = await sandbox.spawn(['sh', '-lc', 'sleep 0.2; cat'])
    const echoed: string[] = []
    echoProc.on('stdout', (data) => {
      echoed.push(data.toString())
    })
    await new Promise((resolve) => setTimeout(resolve, 300))
    echoProc.write('hello from stdin\n')
    await waitFor(() => echoed.join('').includes('hello from stdin'))
    await echoProc.kill()
    t.not(await echoProc.exited, 0)

    const proc1 = await sandbox.spawn('sleep 0.2; echo one')
    const proc2 = await sandbox.spawn('sleep 0.2; echo two')
    t.not(proc1.pid, proc2.pid)
    await Promise.all([proc1.exited, proc2.exited])
  },
)

test.serial(
  'supported runtime watch reports file changes, recurses into subdirectories, and coexists with spawn',
  async (t) => {
    const sandbox = runtime.use(t)
    if (!sandbox) {
      t.log('sandbox not found')
      return
    }

    const watchRoot = makeGuestPath('watch-root')
    const events: Array<{ path: string; event: string }> = []

    await sandbox.exec(`mkdir -p ${watchRoot}/sub`)
    await sandbox.watch(watchRoot, (event) => {
      events.push(event)
    })
    await new Promise((resolve) => setTimeout(resolve, 300))

    await sandbox.exec(
      `touch ${watchRoot}/new.txt && printf "x" >> ${watchRoot}/new.txt && mv ${watchRoot}/new.txt ${watchRoot}/renamed.txt && rm ${watchRoot}/renamed.txt && touch ${watchRoot}/sub/deep.txt`,
    )

    const concurrentStdout: string[] = []
    const concurrent = await sandbox.spawn(
      `sleep 0.2; echo started; touch ${watchRoot}/spawn-created.txt; echo done`,
    )
    concurrent.on('stdout', (data) => {
      concurrentStdout.push(data.toString())
    })
    t.is(await concurrent.exited, 0)

    await waitFor(() => {
      const eventKinds = new Set(events.map((event) => event.event))
      return (
        eventKinds.has('create') &&
        eventKinds.has('modify') &&
        eventKinds.has('rename') &&
        eventKinds.has('delete') &&
        events.some((event) => event.path.includes('/sub/deep.txt')) &&
        events.some((event) => event.path.includes('/spawn-created.txt'))
      )
    })

    t.true(concurrentStdout.join('').includes('started'))
    t.true(concurrentStdout.join('').includes('done'))
  },
)
