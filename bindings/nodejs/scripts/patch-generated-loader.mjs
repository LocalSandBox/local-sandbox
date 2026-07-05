import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const scriptDir = dirname(fileURLToPath(import.meta.url))
const loaderPath = join(scriptDir, '..', 'index.js')

let source = readFileSync(loaderPath, 'utf8')

const windowsMissingMessage = [
  'Cannot find native binding for win32-x64-msvc.',
  'Install @local-sandbox/lsb-nodejs-win32-x64-msvc or make',
  'lsb-nodejs.win32-x64-msvc.node available next to the root package entrypoint.',
  'QEMU is not bundled; after the native module loads, Sandbox.start() reports',
  'Windows QEMU/WHPX preflight errors from the Rust backend.',
].join(' ')

const helper = `function missingNativeBindingMessage() {
  if (process.platform === 'win32' && process.arch === 'x64') {
    return ${JSON.stringify(windowsMissingMessage)}
  }

  return (
    'Cannot find native binding. ' +
    'npm has a bug related to optional dependencies (https://github.com/npm/cli/issues/4828). ' +
    'Please try \`npm i\` again after removing both package-lock.json and node_modules directory.'
  )
}

`

if (!source.includes('function missingNativeBindingMessage()')) {
  const insertionPoint = '\nif (!nativeBinding) {\n'
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
