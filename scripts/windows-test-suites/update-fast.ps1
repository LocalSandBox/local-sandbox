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
    throw 'The update-fast suite does not support reboot phases.'
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

& (Join-Path $PSScriptRoot 'service-fast.ps1') `
    -Phase Normal -RunRoot $RunRoot -SnapshotSha $SnapshotSha

Invoke-Native cargo @(
    'test',
    '-p', 'lsb-seawork-update',
    '-p', 'lsb-seawork-updater',
    '-p', 'xtask',
    '--locked',
    '--no-fail-fast'
) 'controlled-update Rust tests'

Invoke-Native cargo @(
    'clippy',
    '-p', 'lsb-seawork-update',
    '-p', 'lsb-seawork-updater',
    '-p', 'xtask',
    '--locked',
    '--all-targets',
    '--no-deps',
    '--',
    '-D', 'warnings'
) 'controlled-update Clippy gate'

$evidenceName = 'evidence-update-fast.json'
$evidencePath = Join-Path $RunRoot $evidenceName
[ordered]@{
    schema_version = 1
    suite = 'update-fast'
    snapshot_sha = $SnapshotSha
    status = 'passed'
    native_windows = $true
    signed_installation_exercised = $false
    controlled_update_exercised = $false
    exhaustive_failure_matrix_exercised = $false
} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $evidencePath -Encoding utf8NoBOM

$serviceEvidenceName = 'evidence-service-fast.json'
$artifacts = foreach ($name in @($serviceEvidenceName, $evidenceName)) {
    $path = Join-Path $RunRoot $name
    [ordered]@{
        name = $name
        sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        size = (Get-Item -LiteralPath $path).Length
    }
}
[ordered]@{
    schema_version = 1
    run_id = Split-Path -Leaf ([IO.Path]::GetFullPath($RunRoot).TrimEnd('\'))
    artifacts = @($artifacts)
} | ConvertTo-Json -Depth 6 | Set-Content `
    -LiteralPath (Join-Path $RunRoot 'fetch-manifest.json') `
    -Encoding utf8NoBOM
