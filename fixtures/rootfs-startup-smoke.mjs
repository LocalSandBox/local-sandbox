import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'

const started = performance.now()
const diskSectorsWritten = () => {
  const row = readFileSync('/proc/diskstats', 'utf8')
    .split('\n')
    .map((line) => line.trim().split(/\s+/))
    .find((fields) => fields[2] === 'vda')
  return row ? Number(row[9]) : null
}
const diskSectorsAtStart = diskSectorsWritten()
const rootMount = readFileSync('/proc/mounts', 'utf8')
  .split('\n')
  .map((line) => line.split(' '))
  .find((fields) => fields[1] === '/')
assert.ok(rootMount, 'root mount was not present in /proc/mounts')

const response = await fetch('https://registry.npmjs.org/semver/latest')
assert.equal(response.ok, true)
assert.equal((await response.json()).name, 'semver')

const scratch = '/tmp/task-tools/npm-startup-smoke'
mkdirSync(scratch, { recursive: true })
writeFileSync(`${scratch}/package.json`, '{"private":true}')
const installStarted = performance.now()
execFileSync('npm', ['install', '--prefix', scratch, '--save-exact', 'is-number@7.0.0'], {
  stdio: ['ignore', 'ignore', 'pipe'],
  timeout: 60_000,
})
const npmInstallMs = performance.now() - installStarted
writeFileSync('/tmp/rootfs-startup-write.bin', Buffer.alloc(1024 * 1024, 0x5a))
execFileSync('sync', { stdio: 'ignore', timeout: 60_000 })

const diskSectorsAtEnd = diskSectorsWritten()
console.log(JSON.stringify({
  schema_version: 1,
  status: 'passed',
  architecture: process.arch,
  node: process.version,
  npm: execFileSync('npm', ['--version'], { encoding: 'utf8' }).trim(),
  root_mount_options: rootMount[3].split(','),
  noatime: rootMount[3].split(',').includes('noatime'),
  npm_install_ms: Math.round(npmInstallMs * 1000) / 1000,
  duration_ms: Math.round((performance.now() - started) * 1000) / 1000,
  disk_write_bytes:
    diskSectorsAtStart === null || diskSectorsAtEnd === null
      ? null
      : (diskSectorsAtEnd - diskSectorsAtStart) * 512,
}))
