import { readFileSync, readdirSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import test from 'ava'

type RootPackageJson = {
  os: string[]
  cpu: string[]
  napi: {
    targets: string[]
  }
}

type PlatformPackageJson = {
  name: string
  os: string[]
  cpu: string[]
  main: string
  files: string[]
}

const require = createRequire(import.meta.url)
const projectRoot = dirname(dirname(fileURLToPath(import.meta.url)))
const npmDir = join(projectRoot, 'npm')
const rootPackage = require(join(projectRoot, 'package.json')) as RootPackageJson

const expectedTargets = [
  'aarch64-apple-darwin',
  'x86_64-apple-darwin',
  'x86_64-pc-windows-msvc',
]

const expectedPlatformPackages: Record<
  string,
  {
    packageName: string
    os: string[]
    cpu: string[]
    artifact: string
  }
> = {
  'darwin-arm64': {
    packageName: '@local-sandbox/lsb-nodejs-darwin-arm64',
    os: ['darwin'],
    cpu: ['arm64'],
    artifact: 'lsb-nodejs.darwin-arm64.node',
  },
  'darwin-x64': {
    packageName: '@local-sandbox/lsb-nodejs-darwin-x64',
    os: ['darwin'],
    cpu: ['x64'],
    artifact: 'lsb-nodejs.darwin-x64.node',
  },
  'win32-x64-msvc': {
    packageName: '@local-sandbox/lsb-nodejs-win32-x64-msvc',
    os: ['win32'],
    cpu: ['x64'],
    artifact: 'lsb-nodejs.win32-x64-msvc.node',
  },
}

test('root package metadata advertises supported native targets', (t) => {
  t.deepEqual(rootPackage.napi.targets, expectedTargets)
  t.true(rootPackage.os.includes('darwin'))
  t.true(rootPackage.os.includes('win32'))
  t.true(rootPackage.cpu.includes('arm64'))
  t.true(rootPackage.cpu.includes('x64'))
})

test('platform package metadata matches supported native artifacts', (t) => {
  const packageDirs = readdirSync(npmDir).sort()
  t.deepEqual(packageDirs, Object.keys(expectedPlatformPackages).sort())

  for (const [dirName, expected] of Object.entries(expectedPlatformPackages)) {
    const packageJson = require(join(npmDir, dirName, 'package.json')) as PlatformPackageJson

    t.is(packageJson.name, expected.packageName)
    t.deepEqual(packageJson.os, expected.os)
    t.deepEqual(packageJson.cpu, expected.cpu)
    t.is(packageJson.main, expected.artifact)
    t.deepEqual(packageJson.files, [expected.artifact])
  }
})

test('Windows packaging remains x64-only for the MVP', (t) => {
  const packageDirs = readdirSync(npmDir)

  t.true(packageDirs.includes('win32-x64-msvc'))
  t.false(packageDirs.includes('win32-arm64-msvc'))
  t.false(packageDirs.includes('win32-ia32-msvc'))
  t.false(rootPackage.napi.targets.includes('aarch64-pc-windows-msvc'))
  t.false(rootPackage.napi.targets.includes('i686-pc-windows-msvc'))
})

test('generated loader names the missing Windows native package and artifact', (t) => {
  const generatedLoader = readFileSync(join(projectRoot, 'index.js'), 'utf8')

  t.true(generatedLoader.includes('@local-sandbox/lsb-nodejs-win32-x64-msvc'))
  t.true(generatedLoader.includes('lsb-nodejs.win32-x64-msvc.node'))
  t.true(generatedLoader.includes('Cannot find native binding for win32-x64-msvc'))
})
