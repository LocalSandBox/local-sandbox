[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d+\.\d+\.\d+-[0-9A-Za-z.-]+$')]
    [string] $Version,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string] $PublisherSha256,

    [Parameter(Mandatory = $true)]
    [string] $OutputDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Invoke-Native {
    param([string] $Executable, [string[]] $Arguments, [string] $Label)
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE"
    }
}

function Resolve-RegularFile {
    param([string] $Path, [string] $Label)
    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction Stop
    $item = Get-Item -LiteralPath $resolved.Path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "$Label must be a regular non-reparse file"
    }
    return $resolved.Path
}

function Invoke-NpmPack {
    param([string] $PackageRoot, [string] $ArtifactsRoot, [string] $Label)
    Push-Location $PackageRoot
    try {
        $output = @(& npm.cmd pack --pack-destination $ArtifactsRoot --json)
        if ($LASTEXITCODE -ne 0) {
            throw "$Label npm pack failed with exit code $LASTEXITCODE"
        }
    }
    finally {
        Pop-Location
    }
    $records = @(($output -join "`n") | ConvertFrom-Json)
    if ($records.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$records[0].filename)) {
        throw "$Label npm pack returned unexpected metadata"
    }
    return Resolve-RegularFile (Join-Path $ArtifactsRoot $records[0].filename) "$Label tarball"
}

$repoRoot = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$bindingRoot = Join-Path $repoRoot 'bindings\nodejs'
$output = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $output) {
    throw 'Node release output directory already exists'
}
$stageRoot = Join-Path $output 'stage'
$mainStage = Join-Path $stageRoot 'main'
$platformStage = Join-Path $stageRoot 'win32-x64-msvc'
$artifactsRoot = Join-Path $output 'artifacts'
$installRoot = Join-Path $output 'install-test'
New-Item -ItemType Directory -Path $mainStage, $platformStage, $artifactsRoot, $installRoot | Out-Null

$sourceMainPackage = Get-Content -LiteralPath (Join-Path $bindingRoot 'package.json') -Raw |
    ConvertFrom-Json -AsHashtable
$sourcePlatformPackage = Get-Content `
    -LiteralPath (Join-Path $bindingRoot 'npm\win32-x64-msvc\package.json') -Raw |
    ConvertFrom-Json -AsHashtable
if ($sourceMainPackage['name'] -cne '@local-sandbox/lsb-nodejs' -or
    $sourcePlatformPackage['name'] -cne '@local-sandbox/lsb-nodejs-win32-x64-msvc' -or
    $sourceMainPackage['version'] -cne $Version -or
    $sourcePlatformPackage['version'] -cne $Version) {
    throw 'Node source package identity/version does not match the candidate'
}

$priorPublisher = $env:SEAWORK_PUBLISHER_SHA256
$priorPreviousPublisher = $env:SEAWORK_PUBLISHER_SHA256_PREVIOUS
try {
    $env:SEAWORK_PUBLISHER_SHA256 = $PublisherSha256.ToLowerInvariant()
    $env:SEAWORK_PUBLISHER_SHA256_PREVIOUS = $null
    Push-Location $bindingRoot
    try {
        $nativeOutput = Join-Path $bindingRoot 'lsb-nodejs.win32-x64-msvc.node'
        if (Test-Path -LiteralPath $nativeOutput) {
            Resolve-RegularFile $nativeOutput 'cached Node native output' | Out-Null
            Remove-Item -LiteralPath $nativeOutput -Force
        }
        Invoke-Native corepack @('yarn', 'install', '--immutable') 'Node dependency install'
        Invoke-Native corepack @(
            'yarn', 'napi', 'build',
            '--target', 'x86_64-pc-windows-msvc',
            '--platform', '--release', '--js', 'index.js', '--dts', 'index.d.ts'
        ) 'publisher-pinned Windows Node build'
        Invoke-Native corepack @('yarn', 'patch-loader') 'generated Node loader patch'
        Invoke-Native corepack @(
            'yarn', 'ava',
            'test/api-shape.spec.ts',
            'test/package-metadata.spec.ts',
            'test/startup.spec.ts'
        ) 'Windows Node API/package/startup tests'
        Invoke-Native corepack @(
            'yarn', 'tsc', '--noEmit', '--project', 'test/tsconfig.json'
        ) 'Windows Node declaration typecheck'
    }
    finally {
        Pop-Location
    }
}
finally {
    $env:SEAWORK_PUBLISHER_SHA256 = $priorPublisher
    $env:SEAWORK_PUBLISHER_SHA256_PREVIOUS = $priorPreviousPublisher
}

foreach ($name in @('README.md', 'LICENSE', 'index.js', 'index.d.ts')) {
    Copy-Item -LiteralPath (Resolve-RegularFile (Join-Path $bindingRoot $name) "Node main $name") `
        -Destination (Join-Path $mainStage $name)
}
$mainPackage = $sourceMainPackage
$mainPackage['optionalDependencies'] = [ordered]@{
    '@local-sandbox/lsb-nodejs-win32-x64-msvc' = $Version
}
$mainPackage | ConvertTo-Json -Depth 20 | Set-Content `
    -LiteralPath (Join-Path $mainStage 'package.json') -Encoding utf8NoBOM

foreach ($name in @('README.md', 'package.json')) {
    Copy-Item -LiteralPath (Resolve-RegularFile `
        (Join-Path $bindingRoot "npm\win32-x64-msvc\$name") "Node platform $name") `
        -Destination (Join-Path $platformStage $name)
}
Copy-Item -LiteralPath (Resolve-RegularFile (Join-Path $bindingRoot 'LICENSE') 'Node license') `
    -Destination (Join-Path $platformStage 'LICENSE')
$nativeName = 'lsb-nodejs.win32-x64-msvc.node'
Copy-Item -LiteralPath (Resolve-RegularFile (Join-Path $bindingRoot $nativeName) 'Node native binding') `
    -Destination (Join-Path $platformStage $nativeName)

$platformTarball = Invoke-NpmPack $platformStage $artifactsRoot 'Node platform package'
$mainTarball = Invoke-NpmPack $mainStage $artifactsRoot 'Node main package'

[ordered]@{
    name = 'seawork-node-package-install-test'
    private = $true
    version = '1.0.0'
} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $installRoot 'package.json') -Encoding utf8NoBOM
Push-Location $installRoot
try {
    Invoke-Native npm.cmd @(
        'install', '--ignore-scripts', '--no-audit', '--no-fund', '--package-lock=false',
        $platformTarball, $mainTarball
    ) 'exact Node tarball install'
    $probe = @'
const binding = require('@local-sandbox/lsb-nodejs')
if (typeof binding.connectSeaWorkService !== 'function') throw new Error('missing service API')
if (typeof binding.Sandbox !== 'function') throw new Error('missing legacy Sandbox API')
const main = require('@local-sandbox/lsb-nodejs/package.json')
const platform = require('@local-sandbox/lsb-nodejs-win32-x64-msvc/package.json')
if (main.version !== platform.version) throw new Error('package version mismatch')
'@
    Invoke-Native node.exe @('-e', $probe) 'installed Node package API smoke'
}
finally {
    Pop-Location
}

$packages = @(
    [ordered]@{
        role = 'main'
        name = '@local-sandbox/lsb-nodejs'
        version = $Version
        file = Split-Path -Leaf $mainTarball
        sha256 = (Get-FileHash -LiteralPath $mainTarball -Algorithm SHA256).Hash.ToLowerInvariant()
        size = (Get-Item -LiteralPath $mainTarball).Length
    },
    [ordered]@{
        role = 'platform'
        name = '@local-sandbox/lsb-nodejs-win32-x64-msvc'
        version = $Version
        file = Split-Path -Leaf $platformTarball
        sha256 = (Get-FileHash -LiteralPath $platformTarball -Algorithm SHA256).Hash.ToLowerInvariant()
        size = (Get-Item -LiteralPath $platformTarball).Length
    }
)
[ordered]@{
    schema_version = 1
    status = 'passed'
    version = $Version
    publisher_sha256 = $PublisherSha256.ToLowerInvariant()
    packages = $packages
    checks = @('api-shape', 'declarations', 'metadata', 'startup', 'exact-tarball-install')
} | ConvertTo-Json -Depth 8 | Set-Content `
    -LiteralPath (Join-Path $output 'evidence-node-packages.json') -Encoding utf8NoBOM

$packages | ConvertTo-Json -Depth 6 -Compress
