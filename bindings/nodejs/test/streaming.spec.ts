import test from 'ava'

import { createSharedRuntimeHarness, makeGuestPath, waitFor } from './helpers'

const runtime = createSharedRuntimeHarness()

async function collectByteChunks(stream: AsyncIterable<Uint8Array>, chunks: string[]) {
  for await (const chunk of stream) {
    chunks.push(Buffer.from(chunk).toString('utf8'))
  }
}

async function countBytes(stream: AsyncIterable<Uint8Array>) {
  let bytes = 0
  for await (const chunk of stream) {
    bytes += chunk.byteLength
  }
  return bytes
}

async function collectWatchEvents(
  stream: AsyncIterable<{ path: string; event: string }>,
  events: Array<{ path: string; event: string }>,
) {
  for await (const event of stream) {
    events.push(event)
  }
}

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

    const stdoutTask = collectByteChunks(proc.stdout, stdoutChunks)
    const stderrTask = collectByteChunks(proc.stderr, stderrChunks)
    const code = await proc.exited
    exitCodes.push(code)
    await Promise.all([stdoutTask, stderrTask])

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
  'supported runtime spawn supports cwd, stdin writes, kill, and concurrent processes',
  async (t) => {
    const sandbox = runtime.use(t)
    if (!sandbox) {
      t.log('sandbox not found')
      return
    }

    const cwdProc = await sandbox.spawn('sleep 0.2; pwd', { cwd: '/tmp' })
    const cwdChunks: string[] = []
    const cwdStdoutTask = collectByteChunks(cwdProc.stdout, cwdChunks)
    t.is(await cwdProc.exited, 0)
    await cwdStdoutTask
    t.is(cwdChunks.join('').trim(), '/tmp')

    const echoProc = await sandbox.spawn(['sh', '-lc', 'cat'])
    const echoed: string[] = []
    const echoStdoutTask = collectByteChunks(echoProc.stdout, echoed)
    await new Promise((resolve) => setTimeout(resolve, 300))
    echoProc.write('hello from stdin\n')
    await waitFor(() => echoed.join('').includes('hello from stdin'))
    await echoProc.kill()
    t.not(await echoProc.exited, 0)
    await echoStdoutTask

    const proc1 = await sandbox.spawn('sleep 0.2; echo one')
    const proc2 = await sandbox.spawn('sleep 0.2; echo two')
    const proc1Stdout: string[] = []
    const proc2Stdout: string[] = []
    const proc1StdoutTask = collectByteChunks(proc1.stdout, proc1Stdout)
    const proc2StdoutTask = collectByteChunks(proc2.stdout, proc2Stdout)
    await Promise.all([proc1.exited, proc2.exited, proc1StdoutTask, proc2StdoutTask])
    t.is(proc1Stdout.join('').trim(), 'one')
    t.is(proc2Stdout.join('').trim(), 'two')
  },
)

test.serial(
  'supported runtime spawn keeps a small process responsive during large output',
  async (t) => {
    const sandbox = runtime.use(t)
    if (!sandbox) {
      t.log('sandbox not found')
      return
    }

    const large = await sandbox.spawn(
      "i=0; while [ $i -lt 256 ]; do dd if=/dev/zero bs=4096 count=1 2>/dev/null | tr '\\0' L; i=$((i + 1)); done",
    )
    const largeBytesTask = countBytes(large.stdout)
    const small = await sandbox.spawn('sleep 0.1; echo small-ready')
    const smallStdout: string[] = []
    const smallStdoutTask = collectByteChunks(small.stdout, smallStdout)

    t.is(await small.exited, 0)
    await smallStdoutTask
    t.is(smallStdout.join('').trim(), 'small-ready')

    t.is(await large.exited, 0)
    t.true((await largeBytesTask) >= 1024 * 1024)
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
    let watchError: unknown = null
    void collectWatchEvents(await sandbox.watch(watchRoot), events).catch((error) => {
      watchError = error
    })
    await new Promise((resolve) => setTimeout(resolve, 300))

    await sandbox.exec(
      `touch ${watchRoot}/new.txt && printf "x" >> ${watchRoot}/new.txt && mv ${watchRoot}/new.txt ${watchRoot}/renamed.txt && rm ${watchRoot}/renamed.txt && touch ${watchRoot}/sub/deep.txt`,
    )

    const concurrentStdout: string[] = []
    const concurrent = await sandbox.spawn(
      `sleep 0.2; echo started; touch ${watchRoot}/spawn-created.txt; echo done`,
    )
    const concurrentStdoutTask = collectByteChunks(concurrent.stdout, concurrentStdout)
    t.is(await concurrent.exited, 0)
    await concurrentStdoutTask

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
    t.is(watchError, null)

    t.true(concurrentStdout.join('').includes('started'))
    t.true(concurrentStdout.join('').includes('done'))
  },
)
