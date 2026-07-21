import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const scriptDir = dirname(fileURLToPath(import.meta.url))
const loaderPath = join(scriptDir, '..', 'index.js')
const declarationsPath = join(scriptDir, '..', 'index.d.ts')

let source = readFileSync(loaderPath, 'utf8')

const windowsMissingMessage = [
  'Cannot find native binding for win32-x64-msvc.',
  'Install @local-sandbox/lsb-nodejs-win32-x64-msvc or make',
  'lsb-nodejs.win32-x64-msvc.node available next to the root package entrypoint.',
  'Run lsb init to install managed QEMU host tools.',
  'After the native module loads, Sandbox.start() reports',
  'Windows QEMU/WHPX preflight errors from the Rust backend.',
].join(' ')

const unsupportedWindowsMessage = [
  'Windows Node support is limited to win32-x64-msvc.',
  'Windows ARM64 and IA32 native packages are not published.',
  'Use Windows 11 x64, or install only the root package metadata on unsupported Windows hosts.',
].join(' ')

const helper = `function missingNativeBindingMessage() {
  if (process.platform === 'win32') {
    if (process.arch === 'x64') {
      return ${JSON.stringify(windowsMissingMessage)}
    }

    return (
      ${JSON.stringify(unsupportedWindowsMessage)} +
      ' Current host is win32-' +
      process.arch +
      '.'
    )
  }

  return (
    'Cannot find native binding. ' +
    'npm has a bug related to optional dependencies (https://github.com/npm/cli/issues/4828). ' +
    'Please try \`npm i\` again after removing both package-lock.json and node_modules directory.'
  )
}

`

const insertionPoint = '\nif (!nativeBinding) {\n'
const helperPattern =
  /function missingNativeBindingMessage\(\) \{[\s\S]*?\n\}\n\nif \(!nativeBinding\) \{\n/

if (source.includes('function missingNativeBindingMessage()')) {
  if (!helperPattern.test(source)) {
    throw new Error('could not replace existing native binding message helper')
  }
  source = source.replace(helperPattern, `${helper}if (!nativeBinding) {\n`)
} else {
  if (!source.includes(insertionPoint)) {
    throw new Error('could not find native binding failure block in generated index.js')
  }
  source = source.replace(insertionPoint, `\n${helper}if (!nativeBinding) {\n`)
}

const genericMessage = `      \`Cannot find native binding. \` +
        \`npm has a bug related to optional dependencies (https://github.com/npm/cli/issues/4828). \` +
        'Please try \`npm i\` again after removing both package-lock.json and node_modules directory.',`

if (source.includes(genericMessage)) {
  source = source.replace(genericMessage, '      missingNativeBindingMessage(),')
}

if (!source.includes('missingNativeBindingMessage(),')) {
  throw new Error('could not patch native binding failure message in generated index.js')
}

writeFileSync(loaderPath, source)

let declarations = readFileSync(declarationsPath, 'utf8')

function patchAsyncIterator(className, yieldType) {
  const generated = `export declare class ${className} {\n\n}`
  const patched = `export declare class ${className} implements AsyncIterable<${yieldType}> {\n  [Symbol.asyncIterator](): AsyncIterator<${yieldType}>\n}`

  if (declarations.includes(generated)) {
    declarations = declarations.replace(generated, patched)
  } else if (!declarations.includes(patched)) {
    throw new Error(`could not patch ${className} async iterator declaration`)
  }
}

patchAsyncIterator('ByteStream', 'Uint8Array')
patchAsyncIterator('WatchStream', 'FileChangeEvent')

const generatedConnect =
  /export declare function connectSeaWorkService\(([^)]*)\): Promise<SeaWorkService>/
const patchedConnect =
  /export declare function connectSeaWorkService\(([^)]*)\): Promise<SeaWorkServiceClient>/
if (generatedConnect.test(declarations)) {
  declarations = declarations.replace(
    generatedConnect,
    'export declare function connectSeaWorkService($1): Promise<SeaWorkServiceClient>',
  )
} else if (!patchedConnect.test(declarations)) {
  throw new Error('could not patch connectSeaWorkService return type')
}

const serviceAliases = `
export type SeaWorkServiceClient = SeaWorkService
export type ServiceSandboxStartOptions = SeaWorkStartOptions
export type RemoteSandbox = SeaWorkSandbox
export type RemoteProcess = SeaWorkProcess
`
if (!declarations.includes('export type SeaWorkServiceClient = SeaWorkService')) {
  declarations += serviceAliases
} else if (!declarations.includes(serviceAliases.trim())) {
  throw new Error('incomplete SeaWork service compatibility aliases')
}

const generatedStartSandbox =
  /startSandbox\(options: SeaWorkStartOptions\): Promise<SeaWorkSandbox>/
const patchedStartSandbox =
  /startSandbox\(options: ServiceSandboxStartOptions\): Promise<RemoteSandbox>/
if (generatedStartSandbox.test(declarations)) {
  declarations = declarations.replace(
    generatedStartSandbox,
    'startSandbox(options: ServiceSandboxStartOptions): Promise<RemoteSandbox>',
  )
} else if (!patchedStartSandbox.test(declarations)) {
  throw new Error('could not patch startSandbox compatibility types')
}

const generatedMountBackends = 'directMountBackends: Array<string>'
const patchedMountBackends =
  "directMountBackends: Array<'pinned-ro' | 'staged-sync' | 'compat-smb-direct'>"
if (declarations.includes(generatedMountBackends)) {
  declarations = declarations.replace(generatedMountBackends, patchedMountBackends)
} else if (!declarations.includes(patchedMountBackends)) {
  throw new Error('could not patch direct mount backend union')
}
writeFileSync(declarationsPath, declarations)
