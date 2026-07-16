import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import test from 'ava'

const projectRoot = dirname(dirname(fileURLToPath(import.meta.url)))
const declarations = readFileSync(join(projectRoot, 'index.d.ts'), 'utf8')

const sandboxMethods = [
  'start',
  'exec',
  'execShell',
  'spawn',
  'watch',
  'readFile',
  'writeFile',
  'mkdir',
  'readDir',
  'stat',
  'remove',
  'rename',
  'copy',
  'chmod',
  'exists',
  'checkpoint',
  'stop',
]

test('TypeScript declarations preserve the public Sandbox API shape', (t) => {
  t.regex(declarations, /export declare class Sandbox/)
  t.regex(declarations, /export declare function initSandbox/)
  t.regex(declarations, /export interface SandboxFixResult/)
  t.regex(declarations, /export interface SandboxInitProgress/)
  t.regex(declarations, /SandboxInitProgressPhase/)
  t.regex(declarations, /fix\?: boolean/)
  t.regex(declarations, /fixes: Array<SandboxFixResult>/)
  t.regex(declarations, /onProgress\?: \(\(arg: SandboxInitProgress\) => void\)/)
  t.false(/onProgress\?:[^\n]*err:/i.test(declarations))

  for (const phase of [
    'checking',
    'applying-fixes',
    'downloading-host-tools',
    'verifying-host-tools',
    'extracting-host-tools',
    'validating-host-tools',
    'downloading-and-extracting-runtime-assets',
    'pinning-runtime-assets',
  ]) {
    t.true(declarations.includes(`'${phase}'`), `missing init progress phase: ${phase}`)
  }

  for (const method of sandboxMethods) {
    t.regex(declarations, new RegExp(`\\b${method}\\(`))
  }
})

test('TypeScript declarations do not expose platform-specific packaging details', (t) => {
  t.false(/win32-x64-msvc/i.test(declarations))
  t.false(/qemu/i.test(declarations))
  t.false(/whpx/i.test(declarations))
  t.false(/windows/i.test(declarations))
})

test('SeaWork service declarations expose only remote sandbox inputs', (t) => {
  t.regex(declarations, /export declare class SeaWorkService/)
  t.regex(declarations, /static connect\(\): Promise<SeaWorkService>/)
  t.regex(declarations, /start\(opts\?: SeaWorkStartOptions[^)]*\): Promise<SeaWorkSandbox>/)
  t.regex(declarations, /export declare class SeaWorkSandbox/)

  const options = declarations.match(/export interface SeaWorkStartOptions \{(?<body>[\s\S]*?)\n\}/)
    ?.groups?.body
  t.truthy(options)
  t.regex(options ?? '', /cpus\?: number/)
  t.regex(options ?? '', /memoryMb\?: number/)
  t.regex(options ?? '', /diskSizeMb\?: number/)
  for (const forbidden of ['dataDir', 'instanceId', 'baseVersion', 'from', 'qemu', 'identity']) {
    t.false((options ?? '').includes(forbidden), `forbidden service option: ${forbidden}`)
  }

  const execOptions = declarations.match(
    /export interface SeaWorkExecOptions \{(?<body>[\s\S]*?)\n\}/,
  )?.groups?.body
  t.truthy(execOptions)
  t.false((execOptions ?? '').includes('shell'), 'remote exec uses the fixed guest shell contract')
})
