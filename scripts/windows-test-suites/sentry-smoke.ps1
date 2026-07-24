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
    throw 'The sentry-smoke suite does not support reboot phases.'
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

$dependencyJson = Join-Path $RunRoot 'sentry-native-prepared.json'
& pwsh -NoProfile -NonInteractive -File scripts/prepare-sentry-native.ps1 `
    -OutputJson $dependencyJson | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Sentry Native preparation failed with exit code $LASTEXITCODE"
}
$dependency = Get-Content -LiteralPath $dependencyJson -Raw | ConvertFrom-Json

$env:LSB_SENTRY_DSN = 'http://public@127.0.0.1:9/1'
$env:LSB_SENTRY_ENVIRONMENT = 'windows-smoke'
$env:LSB_SENTRY_TRACES_SAMPLE_RATE = '1'
$env:LSB_SENTRY_NATIVE_INCLUDE_DIR = [string]$dependency.include_dir
$env:LSB_SENTRY_NATIVE_LIBRARY = [string]$dependency.library
$env:LSB_SENTRY_CRASHPAD_HANDLER = [string]$dependency.crashpad_handler
$env:LSB_SENTRY_CRASHPAD_WER = [string]$dependency.crashpad_wer

$priorRustFlags = $env:RUSTFLAGS
try {
    $env:RUSTFLAGS = '-C target-feature=+crt-static'
    Invoke-Native cargo @(
        'build',
        '-p', 'lsb-seawork-service',
        '--features', 'sentry-telemetry',
        '--locked'
    ) 'telemetry-enabled service build'
}
finally {
    $env:RUSTFLAGS = $priorRustFlags
}

$fixtureRoot = Join-Path $RunRoot 'fixture path with spaces'
$fixtureBuild = Join-Path $fixtureRoot 'build'
$fixtureDatabase = Join-Path $fixtureRoot 'database'
$crashDatabase = Join-Path $fixtureRoot 'crash database'
$fixtureEnvelope = Join-Path $fixtureRoot 'captured-envelope.txt'
$fixtureAttachment = Join-Path $fixtureRoot 'representative diagnostic ünicode.txt'
New-Item -ItemType Directory -Path $fixtureRoot, $fixtureDatabase, $crashDatabase | Out-Null
[IO.File]::WriteAllText(
    $fixtureAttachment,
    "bounded representative diagnostic`n",
    [Text.UTF8Encoding]::new($false)
)
Copy-Item -LiteralPath ([string]$dependency.crashpad_handler) `
    -Destination (Join-Path $fixtureRoot 'crashpad_handler.exe')
Copy-Item -LiteralPath ([string]$dependency.crashpad_wer) `
    -Destination (Join-Path $fixtureRoot 'crashpad_wer.dll')
$fixtureHandler = Join-Path $fixtureRoot 'crashpad_handler.exe'

Invoke-Native cmake.exe @(
    '-S', (Join-Path $PWD 'crates\lsb-seawork-service\tests\fixtures\sentry-smoke'),
    '-B', $fixtureBuild,
    '-G', 'Visual Studio 18 2026',
    '-A', 'x64',
    "-DSENTRY_INCLUDE_DIR=$($dependency.include_dir)",
    "-DSENTRY_LIBRARY_DIR=$($dependency.library_dir)"
) 'Sentry smoke fixture configuration'
Invoke-Native cmake.exe @(
    '--build', $fixtureBuild, '--config', 'Release', '--parallel'
) 'Sentry smoke fixture build'
$fixture = Join-Path $fixtureBuild 'Release\lsb-sentry-smoke.exe'
if (-not (Test-Path -LiteralPath $fixture -PathType Leaf)) {
    throw 'The Sentry smoke fixture executable is missing.'
}

Invoke-Native $fixture @(
    'capture', $fixtureDatabase, $fixtureHandler, $fixtureAttachment, $fixtureEnvelope
) 'local Sentry event and trace capture'
$envelopeText = Get-Content -LiteralPath $fixtureEnvelope -Raw
foreach ($expected in @(
    'representative sandbox failure',
    'representative diagnostic',
    '"transaction":"sandbox.start"',
    '"op":"sandbox.preflight"',
    '"component":"local-sandbox-service"',
    'smoke-correlation',
    '"release":"local-sandbox-service@smoke"'
)) {
    if (-not $envelopeText.Contains($expected, [StringComparison]::Ordinal)) {
        throw "Captured envelope does not contain expected value: $expected"
    }
}

$crash = Start-Process -FilePath $fixture -ArgumentList @(
    'crash',
    "`"$crashDatabase`"",
    "`"$fixtureHandler`"",
    "`"$fixtureAttachment`"",
    "`"$fixtureEnvelope`""
) -Wait -PassThru
if ($crash.ExitCode -eq 0) {
    throw 'The aborting Sentry fixture unexpectedly exited successfully.'
}
$minidumps = @(Get-ChildItem -LiteralPath $crashDatabase -File -Recurse | Where-Object {
    if ($_.Length -lt 4) { return $false }
    $stream = [IO.File]::OpenRead($_.FullName)
    try {
        $magic = [byte[]]::new(4)
        $null = $stream.Read($magic, 0, 4)
        return [Text.Encoding]::ASCII.GetString($magic) -ceq 'MDMP'
    }
    finally {
        $stream.Dispose()
    }
})
if ($minidumps.Count -lt 1) {
    throw 'Crashpad did not produce a non-empty minidump in its local database.'
}

$fixturePdb = Join-Path $fixtureBuild 'Release\lsb-sentry-smoke.pdb'
Invoke-Native ([string]$dependency.sentry_cli) @(
    'debug-files', 'check', $fixture, $fixturePdb
) 'offline Sentry debug-file check'

[ordered]@{
    schema_version = 1
    suite = 'sentry-smoke'
    snapshot_sha = $SnapshotSha
    status = 'passed'
    sentry_native_tag = [string]$dependency.sentry_native_tag
    sentry_native_commit = [string]$dependency.sentry_native_commit
    sentry_cli_version = [string]$dependency.sentry_cli_version
    static_link_check = 'passed'
    local_envelope_check = 'passed'
    wide_attachment_check = 'passed'
    transaction_child_span_check = 'passed'
    abort_minidump_check = 'passed'
    handler_space_path_check = 'passed'
    offline_debug_file_check = 'passed'
    network_transport = 'local_only'
    minidump_count = $minidumps.Count
} | ConvertTo-Json -Depth 5 | Set-Content `
    -LiteralPath (Join-Path $RunRoot 'evidence-sentry-smoke.json') `
    -Encoding utf8NoBOM
