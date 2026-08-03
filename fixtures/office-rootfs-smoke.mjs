import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createRequire } from 'node:module'
import { mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs'

const require = createRequire(import.meta.url)
const started = performance.now()
const outputDir = '/tmp/lsb-office-smoke'
mkdirSync(outputDir, { recursive: true })
const diskSectorsWritten = () => {
  const row = readFileSync('/proc/diskstats', 'utf8')
    .split('\n')
    .map((line) => line.trim().split(/\s+/))
    .find((fields) => fields[2] === 'vda')
  return row ? Number(row[9]) : null
}
const diskSectorsAtStart = diskSectorsWritten()

const run = (command, args = [], options = {}) =>
  execFileSync(command, args, {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 60_000,
    ...options,
  }).trim()

assert.equal(process.env.HOME, '/root')
assert.ok(process.env.PATH?.startsWith('/root/.bun/bin:'))
assert.equal(process.env.NODE_PATH, '/usr/local/lib/node_modules')
assert.ok(readFileSync('/proc/mounts', 'utf8').split('\n')[0].split(' ')[3].split(',').includes('noatime'))

const versions = {
  node: process.version,
  npm: run('npm', ['--version']),
  bun: run('bun', ['--version']),
  tsx: run('tsx', ['--version']),
  typescript: run('tsc', ['--version']),
}
for (const [command, args] of [
  ['bunx', ['--version']],
  ['npx', ['--version']],
  ['gws', ['--help']],
  ['jira', ['--help']],
  ['confluence', ['--help']],
  ['officeparser', []],
  ['mjml', ['--version']],
  ['openapi-ts', ['--version']],
]) {
  run(command, args)
}

const XLSX = require('xlsx')
const { Document, Packer, Paragraph, TextRun } = require('docx')
const officeParser = require('officeparser')
const mjml2html = require('mjml')
require('youtube-transcript')
require('fractional-indexing')

if (process.env.LSB_SMOKE_NETWORK === '1') {
  const nodeResponse = await fetch('https://registry.npmjs.org/semver/latest')
  assert.equal(nodeResponse.ok, true)
  assert.equal((await nodeResponse.json()).name, 'semver')
  run('bun', [
    '-e',
    "const r=await fetch('https://registry.npmjs.org/semver/latest');if(!r.ok||(await r.json()).name!=='semver')process.exit(1)",
  ])

  const bunScratch = '/tmp/task-tools/bun-smoke'
  const npmScratch = '/tmp/task-tools/npm-smoke'
  mkdirSync(bunScratch, { recursive: true })
  mkdirSync(npmScratch, { recursive: true })
  writeFileSync(`${bunScratch}/package.json`, '{"private":true}')
  writeFileSync(`${npmScratch}/package.json`, '{"private":true}')
  run('bun', ['add', '--cwd', bunScratch, '--exact', 'is-number@7.0.0'])
  run('npm', ['install', '--prefix', npmScratch, '--save-exact', 'is-number@7.0.0'])
  for (const name of ['node_modules', 'bun.lock', 'package-lock.json']) {
    assert.equal(readdirSync('/workspace').includes(name), false)
  }
}

const xlsxPath = `${outputDir}/representative.xlsx`
const workbook = XLSX.utils.book_new()
XLSX.utils.book_append_sheet(
  workbook,
  XLSX.utils.aoa_to_sheet([
    ['Task', 'Duration ms'],
    ['boot', 1],
    ['artifact', 2],
  ]),
  'Metrics',
)
XLSX.writeFile(workbook, xlsxPath)
assert.equal(XLSX.readFile(xlsxPath).Sheets.Metrics.B3.v, 2)

const docxPath = `${outputDir}/representative.docx`
const document = new Document({
  sections: [
    {
      children: [
        new Paragraph({ children: [new TextRun('LocalSandbox office document smoke')] }),
      ],
    },
  ],
})
writeFileSync(docxPath, await Packer.toBuffer(document))
const parsedDocument = await officeParser.parseOffice(docxPath)
assert.ok(JSON.stringify(parsedDocument).includes('LocalSandbox office document smoke'))

const emailPath = `${outputDir}/representative.html`
const email = await mjml2html(`
  <mjml><mj-body><mj-section><mj-column>
    <mj-text>LocalSandbox email smoke</mj-text>
  </mj-column></mj-section></mj-body></mjml>
`)
assert.equal(email.errors.length, 0)
writeFileSync(emailPath, email.html)
assert.ok(readFileSync(emailPath, 'utf8').includes('LocalSandbox email smoke'))

const crcTable = Array.from({ length: 256 }, (_, value) => {
  let crc = value
  for (let bit = 0; bit < 8; bit += 1) crc = (crc & 1) ? 0xedb88320 ^ (crc >>> 1) : crc >>> 1
  return crc >>> 0
})
const crc32 = (buffer) => {
  let crc = 0xffffffff
  for (const byte of buffer) crc = crcTable[(crc ^ byte) & 0xff] ^ (crc >>> 8)
  return (crc ^ 0xffffffff) >>> 0
}
const createStoredZip = (entries) => {
  const localParts = []
  const centralParts = []
  let offset = 0
  for (const [name, value] of entries) {
    const nameBuffer = Buffer.from(name)
    const data = Buffer.from(value)
    const crc = crc32(data)
    const local = Buffer.alloc(30)
    local.writeUInt32LE(0x04034b50, 0)
    local.writeUInt16LE(20, 4)
    local.writeUInt32LE(crc, 14)
    local.writeUInt32LE(data.length, 18)
    local.writeUInt32LE(data.length, 22)
    local.writeUInt16LE(nameBuffer.length, 26)
    localParts.push(local, nameBuffer, data)

    const central = Buffer.alloc(46)
    central.writeUInt32LE(0x02014b50, 0)
    central.writeUInt16LE(20, 4)
    central.writeUInt16LE(20, 6)
    central.writeUInt32LE(crc, 16)
    central.writeUInt32LE(data.length, 20)
    central.writeUInt32LE(data.length, 24)
    central.writeUInt16LE(nameBuffer.length, 28)
    central.writeUInt32LE(offset, 42)
    centralParts.push(central, nameBuffer)
    offset += local.length + nameBuffer.length + data.length
  }
  const centralData = Buffer.concat(centralParts)
  const end = Buffer.alloc(22)
  end.writeUInt32LE(0x06054b50, 0)
  end.writeUInt16LE(entries.length, 8)
  end.writeUInt16LE(entries.length, 10)
  end.writeUInt32LE(centralData.length, 12)
  end.writeUInt32LE(offset, 16)
  return Buffer.concat([...localParts, centralData, end])
}
const readStoredZip = (archive) => {
  const entries = new Map()
  let offset = 0
  while (archive.readUInt32LE(offset) === 0x04034b50) {
    const size = archive.readUInt32LE(offset + 18)
    const nameLength = archive.readUInt16LE(offset + 26)
    const extraLength = archive.readUInt16LE(offset + 28)
    const nameStart = offset + 30
    const dataStart = nameStart + nameLength + extraLength
    entries.set(archive.subarray(nameStart, dataStart - extraLength).toString(), archive.subarray(dataStart, dataStart + size))
    offset = dataStart + size
  }
  return entries
}
const slideText = 'LocalSandbox slide smoke'
const pptxPath = `${outputDir}/representative.pptx`
const slideEntries = [
  ['[Content_Types].xml', '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/><Override PartName="/ppt/slides/slide1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/></Types>'],
  ['_rels/.rels', '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/></Relationships>'],
  ['ppt/presentation.xml', '<?xml version="1.0"?><p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><p:sldIdLst><p:sldId id="256" r:id="rId1"/></p:sldIdLst></p:presentation>'],
  ['ppt/_rels/presentation.xml.rels', '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="slides/slide1.xml"/></Relationships>'],
  ['ppt/slides/slide1.xml', `<?xml version="1.0"?><p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><p:cSld><p:spTree><p:sp><p:txBody><a:bodyPr/><a:lstStyle/><a:p><a:r><a:t>${slideText}</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>`],
]
writeFileSync(pptxPath, createStoredZip(slideEntries))
const reopenedSlide = readStoredZip(readFileSync(pptxPath))
assert.equal(reopenedSlide.size, slideEntries.length)
assert.ok(reopenedSlide.get('ppt/slides/slide1.xml').toString().includes(slideText))

const artifacts = Object.fromEntries(
  readdirSync(outputDir).sort().map((name) => [name, statSync(`${outputDir}/${name}`).size]),
)
run('sync')
const diskSectorsAtEnd = diskSectorsWritten()
console.log(JSON.stringify({
  schema_version: 1,
  status: 'passed',
  architecture: process.arch,
  versions,
  duration_ms: Math.round((performance.now() - started) * 1000) / 1000,
  disk_write_bytes:
    diskSectorsAtStart === null || diskSectorsAtEnd === null
      ? null
      : (diskSectorsAtEnd - diskSectorsAtStart) * 512,
  artifacts,
}))
