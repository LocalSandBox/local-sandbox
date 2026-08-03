[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Normal', 'BeforeReboot', 'AfterReboot')]
    [string] $Phase,
    [Parameter(Mandatory = $true)][string] $RunRoot,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string] $SnapshotSha
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($Phase -ne 'Normal') { throw 'qemu-package-tests does not support reboot phases.' }

function Invoke-CargoTest {
    param([string[]] $Arguments)
    & cargo test @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "cargo test failed with exit code $LASTEXITCODE`: cargo test $($Arguments -join ' ')"
    }
}

$env:CARGO_TARGET_DIR = Join-Path $RunRoot 'cargo-target'
Invoke-CargoTest @('-p', 'lsb-qemu-dump-helper', '--locked')
Invoke-CargoTest @('-p', 'lsb-platform', '--features', 'qemu-hang-test-hooks', '--locked')

$dependencyJson = Join-Path $RunRoot 'sentry-native-prepared.json'
& pwsh -NoProfile -NonInteractive -File scripts/prepare-sentry-native.ps1 `
    -OutputJson $dependencyJson | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Sentry Native preparation failed with exit code $LASTEXITCODE"
}
$dependency = Get-Content -LiteralPath $dependencyJson -Raw | ConvertFrom-Json
$env:RUSTFLAGS = '-C target-feature=+crt-static'
$env:LSB_SENTRY_DSN = 'http://public@127.0.0.1:9/1'
$env:LSB_SENTRY_ENVIRONMENT = 'qemu-package-tests'
$env:LSB_SENTRY_TRACES_SAMPLE_RATE = '1'
$env:LSB_SENTRY_NATIVE_INCLUDE_DIR = [string]$dependency.include_dir
$env:LSB_SENTRY_NATIVE_LIBRARY = [string]$dependency.library
$env:LSB_SENTRY_CRASHPAD_HANDLER = [string]$dependency.crashpad_handler
$env:LSB_SENTRY_CRASHPAD_WER = [string]$dependency.crashpad_wer
Invoke-CargoTest @(
    '-p', 'lsb-seawork-service',
    '--features', 'sentry-telemetry,qemu-hang-test-hooks',
    '--locked'
)

[ordered]@{
    schema_version = 1
    status = 'passed'
    snapshot_sha = $SnapshotSha
    packages = @(
        'lsb-qemu-dump-helper',
        'lsb-platform[qemu-hang-test-hooks]',
        'lsb-seawork-service[sentry-telemetry,qemu-hang-test-hooks]'
    )
} | ConvertTo-Json -Depth 4 | Set-Content `
    -LiteralPath (Join-Path $RunRoot 'evidence-qemu-package-tests.json') -Encoding utf8NoBOM
