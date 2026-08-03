[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Normal', 'BeforeReboot', 'AfterReboot')]
    [string] $Phase,

    [Parameter(Mandatory = $true)]
    [string] $RunRoot,

    [Parameter(Mandatory = $true)]
    [string] $SnapshotSha
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($Phase -ne 'Normal') {
    throw 'The service-fast suite does not support reboot phases.'
}

function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)][string] $Executable,
        [Parameter(Mandatory = $true)][string[]] $Arguments,
        [Parameter(Mandatory = $true)][string] $Label
    )

    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE"
    }
}

Invoke-Native cargo @(
    'test',
    '-p', 'lsb-service-proto',
    '-p', 'lsb-service-client',
    '-p', 'lsb-seawork-service',
    '-p', 'lsb-proxy',
    '-p', 'lsb-vm',
    '--locked'
) 'focused Rust tests'

Invoke-Native cargo @(
    'clippy',
    '-p', 'lsb-service-proto',
    '-p', 'lsb-service-client',
    '-p', 'lsb-seawork-service',
    '--locked',
    '--no-deps',
    '--',
    '-D', 'warnings',
    '-A', 'dead-code',
    '-A', 'clippy::too-many-arguments',
    '-A', 'clippy::field-reassign-with-default'
) 'scoped Clippy gate'

Invoke-Native cargo @(
    'check',
    '--manifest-path', 'bindings/nodejs/Cargo.toml',
    '--tests'
) 'Node binding Rust check'

Push-Location 'bindings/nodejs'
try {
    Invoke-Native corepack @('yarn', 'install', '--immutable') 'Node dependency install'
    Invoke-Native corepack @('yarn', 'napi', 'build', '--platform') 'Node binding build'
    Invoke-Native corepack @('yarn', 'patch-loader') 'Node declaration patch'
    Invoke-Native corepack @(
        'yarn', 'ava',
        'test/api-shape.spec.ts',
        'test/package-metadata.spec.ts',
        'test/startup.spec.ts'
    ) 'Node API-shape tests'
    Invoke-Native corepack @(
        'yarn', 'tsc', '--noEmit', '--project', 'test/tsconfig.json'
    ) 'Node declaration typecheck'
}
finally {
    Pop-Location
}

[ordered]@{
    schema_version = 1
    suite = 'service-fast'
    snapshot_sha = $SnapshotSha
    status = 'passed'
    production_profile = $true
    development_service_feature = $false
} | ConvertTo-Json -Depth 4 | Set-Content `
    -LiteralPath (Join-Path $RunRoot 'evidence-service-fast.json') `
    -Encoding utf8NoBOM
