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

Invoke-Native cargo @(
    'build',
    '-p', 'lsb-seawork-updater',
    '--locked'
) 'updater binary build'

$targetRoot = if ([string]::IsNullOrWhiteSpace($env:CARGO_TARGET_DIR)) {
    Join-Path $PWD 'target'
}
else {
    [IO.Path]::GetFullPath($env:CARGO_TARGET_DIR)
}
$updater = Join-Path $targetRoot 'debug\localsandbox-seawork-updater.exe'
if (-not (Test-Path -LiteralPath $updater -PathType Leaf)) {
    throw 'The updater build did not produce the expected Windows executable.'
}

$versionText = (& $updater --version --json | Out-String).Trim()
if ($LASTEXITCODE -ne 0) {
    throw "updater version query failed with exit code $LASTEXITCODE"
}
$version = $versionText | ConvertFrom-Json
if ($version.service_name -cne 'LocalSandboxSeaWorkUpdater' -or
    [string]::IsNullOrWhiteSpace([string]$version.helper_version) -or
    [int]$version.helper_protocol_major -ne 1 -or
    [int]$version.helper_protocol_minor -lt 1) {
    throw 'The updater version query returned an invalid identity or protocol.'
}

$installText = (& $updater --verify-install --json 2>$null | Out-String).Trim()
$installExitCode = $LASTEXITCODE
if ([string]::IsNullOrWhiteSpace($installText)) {
    throw 'The updater invalid-install check did not emit bounded JSON evidence.'
}
$install = $installText | ConvertFrom-Json
if ($installExitCode -eq 0 -or $install.valid -ne $false -or
    $install.service_name -cne 'LocalSandboxSeaWorkUpdater' -or
    $install.error -cne 'INSTALL_INVALID') {
    throw 'The disposable updater unexpectedly passed its installed-helper self-check.'
}

$evidenceName = 'evidence-update-fast.json'
$evidencePath = Join-Path $RunRoot $evidenceName
[ordered]@{
    schema_version = 1
    suite = 'update-fast'
    snapshot_sha = $SnapshotSha
    status = 'passed'
    native_windows = $true
    helper_version_mode_exercised = $true
    invalid_install_rejection_exercised = $true
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
