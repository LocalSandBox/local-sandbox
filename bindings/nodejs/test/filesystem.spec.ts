import test from 'ava'

import { createSharedRuntimeHarness, makeGuestPath } from './helpers'

const runtime = createSharedRuntimeHarness()

test.serial.before(async () => {
  await runtime.before()
})

test.after.always(async () => {
  await runtime.after()
})

test.serial(
  'supported runtime mkdir creates directories with SDK-compatible defaults',
  async (t) => {
    const sandbox = runtime.use(t)
    if (!sandbox) {
      t.log('sandbox not found')
      return
    }

    const singleDir = makeGuestPath('mkdir-single')
    const nestedDir = `${makeGuestPath('mkdir-nested')}/a/b/c`

    await sandbox.mkdir(singleDir, { recursive: false })
    await sandbox.mkdir(nestedDir)

    const singleStat = await sandbox.stat(singleDir)
    const nestedStat = await sandbox.stat(nestedDir)

    t.true(singleStat.isDir)
    t.true(nestedStat.isDir)
  },
)

test.serial('supported runtime remove deletes files and recursive directory trees', async (t) => {
  const sandbox = runtime.use(t)
  if (!sandbox) {
    t.log('sandbox not found')
    return
  }

  const filePath = makeGuestPath('remove-file.txt')
  const dirPath = makeGuestPath('remove-dir')

  await sandbox.writeFile(filePath, 'delete me')
  await sandbox.exec(`mkdir -p ${dirPath}/nested && printf "data" > ${dirPath}/nested/file.txt`)

  await sandbox.remove(filePath)
  await sandbox.remove(dirPath, { recursive: true })

  t.false(await sandbox.exists(filePath))
  t.false(await sandbox.exists(dirPath))
})

test.serial('supported runtime rename moves files and removes the old path', async (t) => {
  const sandbox = runtime.use(t)
  if (!sandbox) {
    t.log('sandbox not found')
    return
  }

  const oldPath = makeGuestPath('rename-old.txt')
  const newPath = makeGuestPath('rename-new.txt')

  await sandbox.writeFile(oldPath, 'move me')
  await sandbox.rename(oldPath, newPath)

  const content = await sandbox.readFile(newPath)
  t.is(content.toString('utf8'), 'move me')
  t.false(await sandbox.exists(oldPath))
})

test.serial('supported runtime copy duplicates files and recursive directories', async (t) => {
  const sandbox = runtime.use(t)
  if (!sandbox) {
    t.log('sandbox not found')
    return
  }

  const srcFile = makeGuestPath('copy-src.txt')
  const dstFile = makeGuestPath('copy-dst.txt')
  const srcDir = makeGuestPath('copy-dir-src')
  const dstDir = makeGuestPath('copy-dir-dst')

  await sandbox.writeFile(srcFile, 'copy me')
  await sandbox.copy(srcFile, dstFile)
  t.is((await sandbox.readFile(dstFile)).toString('utf8'), 'copy me')

  await sandbox.exec(
    `mkdir -p ${srcDir}/sub && printf "aaa" > ${srcDir}/a.txt && printf "bbb" > ${srcDir}/sub/b.txt`,
  )
  await sandbox.copy(srcDir, dstDir, { recursive: true })

  t.is((await sandbox.readFile(`${dstDir}/a.txt`)).toString('utf8'), 'aaa')
  t.is((await sandbox.readFile(`${dstDir}/sub/b.txt`)).toString('utf8'), 'bbb')
})

test.serial(
  'supported runtime chmod updates permission bits and stat still rejects missing paths',
  async (t) => {
    const sandbox = runtime.use(t)
    if (!sandbox) {
      t.log('sandbox not found')
      return
    }

    const chmodPath = makeGuestPath('chmod.txt')
    const missingPath = makeGuestPath('missing.txt')

    await sandbox.writeFile(chmodPath, 'chmod me')
    await sandbox.chmod(chmodPath, 0o755)

    const stat = await sandbox.stat(chmodPath)
    t.is(stat.mode & 0o777, 0o755)

    const error = await t.throwsAsync(() => sandbox.stat(missingPath))
    t.truthy(error)
    t.regex(error?.message ?? '', /No such file or directory/i)
  },
)
