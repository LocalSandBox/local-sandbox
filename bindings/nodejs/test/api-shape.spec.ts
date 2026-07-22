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
  t.regex(
    declarations,
    /connectSeaWorkService\(options\?: SeaWorkServiceConnectOptions[^)]*\): Promise<SeaWorkServiceClient>/,
  )
  t.regex(declarations, /export type SeaWorkServiceClient = SeaWorkService/)
  t.regex(declarations, /export type ServiceSandboxStartOptions = SeaWorkStartOptions/)
  t.regex(declarations, /export type RemoteSandbox = SeaWorkSandbox/)
  t.regex(declarations, /export type RemoteProcess = SeaWorkProcess/)
  t.regex(declarations, /getServiceInfo\(\): Promise<SeaWorkServiceInfo>/)
  t.regex(declarations, /healthCheck\(\): Promise<SeaWorkServiceHealth>/)
  t.regex(
    declarations,
    /startSandbox\(options: ServiceSandboxStartOptions\): Promise<RemoteSandbox>/,
  )
  t.regex(declarations, /prepareUpdate\(target: SeaWorkBundleIdentity\): Promise<string>/)
  t.regex(declarations, /getUpdateStatus\(\): Promise<SeaWorkUpdateStatus>/)
  t.regex(declarations, /checkForUpdate\(\): Promise<void>/)
  t.regex(declarations, /export interface SeaWorkBundleIdentity/)
  t.regex(declarations, /bundleManifestSha256: string/)
  t.regex(declarations, /archiveSha256: string/)
  t.regex(declarations, /serviceConfigurationRevision: number/)
  t.regex(declarations, /export interface SeaWorkLedgerCompatibility/)
  t.regex(declarations, /writerSchema: number/)
  t.regex(declarations, /export interface SeaWorkUpdateStatus/)
  t.regex(declarations, /activeUseCount: number/)
  t.regex(declarations, /export interface SeaWorkUpdateRetryState/)
  t.regex(declarations, /commitUpdate\(updateId: string\): Promise<void>/)
  t.regex(declarations, /abortUpdate\(updateId: string\): Promise<void>/)
  t.regex(declarations, /prepareUninstall\(\): Promise<SeaWorkUninstallPreparation>/)
  t.regex(declarations, /start\(opts\?: SeaWorkStartOptions[^)]*\): Promise<SeaWorkSandbox>/)
  t.regex(declarations, /export declare class SeaWorkSandbox/)
  t.regex(declarations, /readFile\(path: string\): Promise<Buffer>/)
  t.regex(declarations, /writeFile\(path: string, content: string \| Uint8Array\): Promise<void>/)
  t.regex(
    declarations,
    /spawn\(command: string \| Array<string>, opts\?: SeaWorkExecOptions[^)]*\): Promise<SeaWorkProcess>/,
  )
  t.regex(declarations, /export declare class SeaWorkProcess/)
  t.regex(
    declarations,
    /beginExec\(command: string \| Array<string>, opts\?: SeaWorkExecOptions[^)]*\): Promise<SeaWorkExecOperation>/,
  )
  t.regex(declarations, /export declare class SeaWorkExecOperation/)
  t.regex(declarations, /cancel\(\): Promise<void>/)
  t.regex(declarations, /complete\(\): Promise<ExecResult>/)
  t.regex(declarations, /watch\(path: string, opts\?: WatchOptions[^)]*\): Promise<SeaWorkWatch>/)
  t.regex(declarations, /export declare class SeaWorkWatch/)
  t.regex(declarations, /next\(\): Promise<FileChangeEvent \| null>/)
  t.regex(declarations, /nextStdout\(\): Promise<Buffer \| null>/)
  t.regex(declarations, /nextStderr\(\): Promise<Buffer \| null>/)
  t.regex(declarations, /kill\(\): Promise<void>/)
  t.regex(declarations, /get exited\(\): Promise<number>/)

  const options = declarations.match(/export interface SeaWorkStartOptions \{(?<body>[\s\S]*?)\n\}/)
    ?.groups?.body
  t.truthy(options)
  t.regex(options ?? '', /cpus\?: number/)
  t.regex(options ?? '', /memoryMb\?: number/)
  t.regex(options ?? '', /diskSizeMb\?: number/)
  t.regex(options ?? '', /instanceId\?: string/)
  t.regex(options ?? '', /from\?: string/)
  t.regex(options ?? '', /ports\?: Array<PortMappingConfig>/)
  t.regex(
    options ?? '',
    /mounts\?: Array<\{ type: 'overlay'; hostPath: string; guestPath: string \} \| \{ type: 'direct'; hostPath: string; guestPath: string; flags: number \}>/,
  )
  t.regex(options ?? '', /network\?: NetworkConfig/)
  for (const forbidden of ['dataDir', 'baseVersion', 'qemu', 'identity']) {
    t.false((options ?? '').includes(forbidden), `forbidden service option: ${forbidden}`)
  }

  const connectOptions = declarations.match(
    /export interface SeaWorkServiceConnectOptions \{(?<body>[\s\S]*?)\n\}/,
  )?.groups?.body
  t.truthy(connectOptions)
  t.regex(connectOptions ?? '', /connectTimeoutMs\?: number/)

  const capabilities = declarations.match(
    /export interface SeaWorkCapabilities \{(?<body>[\s\S]*?)\n\}/,
  )?.groups?.body
  t.truthy(capabilities)
  t.regex(
    capabilities ?? '',
    /directMountBackends: Array<'pinned-ro' \| 'staged-sync' \| 'compat-smb-direct'>/,
  )

  const execOptions = declarations.match(
    /export interface SeaWorkExecOptions \{(?<body>[\s\S]*?)\n\}/,
  )?.groups?.body
  t.truthy(execOptions)
  t.regex(execOptions ?? '', /shell\?: string/)
})
