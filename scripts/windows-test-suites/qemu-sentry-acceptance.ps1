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
if ($Phase -ne 'Normal') { throw 'qemu-sentry-acceptance does not support reboot phases.' }

function Assert-RegularFile {
    param([string] $Path, [long] $MaximumBytes = 16GB)
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $item.Length -le 0 -or $item.Length -gt $MaximumBytes) {
        throw "Expected a bounded regular file: $Path"
    }
    return $item
}

$dsnFile = 'C:\dev\local-sandbox-agent-state\sentry-acceptance-dsn.txt'
$dsn = [string](Get-Content -LiteralPath (Assert-RegularFile $dsnFile 4KB).FullName -Raw)
$dsn = $dsn.Trim()
if ($dsn -notmatch '^https?://\S{1,2048}$') {
    throw 'The provisioned Sentry acceptance DSN is invalid.'
}

$assets = [IO.Path]::GetFullPath($env:LSB_WINDOWS_TEST_ASSETS_ROOT)
foreach ($path in @(
    (Join-Path $assets 'qemu\qemu-system-x86_64.exe'),
    (Join-Path $assets 'runtime\Image'),
    (Join-Path $assets 'runtime\initramfs.cpio.gz'),
    (Join-Path $assets 'runtime\rootfs.ext4')
)) {
    Assert-RegularFile $path | Out-Null
}

$dependencyJson = Join-Path $RunRoot 'sentry-native-prepared.json'
& pwsh -NoProfile -NonInteractive -File scripts/prepare-sentry-native.ps1 `
    -OutputJson $dependencyJson | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Sentry Native preparation failed with exit code $LASTEXITCODE"
}
$dependency = Get-Content -LiteralPath $dependencyJson -Raw | ConvertFrom-Json

$env:CARGO_TARGET_DIR = Join-Path $RunRoot 'cargo-target'
$env:RUSTFLAGS = '-C target-feature=+crt-static'
$env:LSB_SENTRY_DSN = $dsn
$env:LSB_SENTRY_ENVIRONMENT = 'qemu-sentry-acceptance'
$env:LSB_SENTRY_TRACES_SAMPLE_RATE = '1'
$env:LSB_SENTRY_NATIVE_INCLUDE_DIR = [string]$dependency.include_dir
$env:LSB_SENTRY_NATIVE_LIBRARY = [string]$dependency.library
$env:LSB_SENTRY_CRASHPAD_HANDLER = [string]$dependency.crashpad_handler
$env:LSB_SENTRY_CRASHPAD_WER = [string]$dependency.crashpad_wer
$env:LSB_QEMU_HANG_TEST_CRASHPAD_HANDLER = [string]$dependency.crashpad_handler
$env:LSB_QEMU_HANG_TEST_REAL_SENTRY = '1'
$env:LSB_QEMU_HANG_TEST_REAL_SENTRY_RESULT = Join-Path $RunRoot 'qemu-sentry-result.json'
$env:LSB_QEMU_HANG_TEST_SERVICE_ROOT = Join-Path $RunRoot 'service-programdata'
$env:LSB_QEMU_HANG_TEST_FORCE_GUEST_READY_TIMEOUT = '1'
$env:LSB_QEMU_HANG_TEST_FORCE_SHUTDOWN_TIMEOUT = '0'
$env:LSB_QEMU_HANG_TEST_DUMP_DEADLINE_MS = '5000'
$env:LSB_QEMU_HANG_TEST_SECRET_CANARY = "qemu-sentry-secret-$([Guid]::NewGuid().ToString('N'))"

& cargo build -p lsb-qemu-dump-helper --locked
if ($LASTEXITCODE -ne 0) {
    throw "Dump helper build failed with exit code $LASTEXITCODE"
}
$env:LSB_QEMU_HANG_TEST_HELPER = Join-Path $env:CARGO_TARGET_DIR `
    'debug\localsandbox-qemu-dump-helper.exe'
Assert-RegularFile $env:LSB_QEMU_HANG_TEST_HELPER 64MB | Out-Null

& cargo test -p lsb-seawork-service `
    --features 'sentry-telemetry,qemu-hang-test-hooks' --locked `
    'resource::vm::tests::windows_service_owned_qemu_hang_smoke' `
    -- --ignored --exact --nocapture
if ($LASTEXITCODE -ne 0) {
    throw "Real Sentry QEMU acceptance test failed with exit code $LASTEXITCODE"
}
if (Get-Process -Name 'qemu-system-x86_64', 'localsandbox-qemu-dump-helper' `
    -ErrorAction SilentlyContinue) {
    throw 'Real Sentry acceptance left QEMU or its dump helper alive.'
}

$acceptance = Get-Content -LiteralPath `
    (Assert-RegularFile $env:LSB_QEMU_HANG_TEST_REAL_SENTRY_RESULT 64KB).FullName -Raw |
    ConvertFrom-Json
$evidenceName = 'evidence-qemu-sentry-acceptance.json'
$evidencePath = Join-Path $RunRoot $evidenceName
[ordered]@{
    schema_version = 1
    status = 'passed'
    snapshot_sha = $SnapshotSha
    incident_id = [string]$acceptance.incident_id
    sentry_event_id = [string]$acceptance.sentry_event_id
    dump_relative_path = [string]$acceptance.dump_relative_path
    dump_size = [long]$acceptance.dump_size
    dump_sha256 = [string]$acceptance.dump_sha256
    correlation_id = [string]$acceptance.correlation_id
    resource_id = [string]$acceptance.resource_id
    qemu_processes_remaining = 0
} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $evidencePath -Encoding utf8NoBOM

$evidenceFile = Assert-RegularFile $evidencePath 64KB
[ordered]@{
    schema_version = 1
    run_id = Split-Path -Leaf $RunRoot
    artifacts = @(
        [ordered]@{
            name = $evidenceName
            sha256 = (Get-FileHash -LiteralPath $evidenceFile.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            size = $evidenceFile.Length
        }
    )
} | ConvertTo-Json -Depth 8 | Set-Content `
    -LiteralPath (Join-Path $RunRoot 'fetch-manifest.json') -Encoding utf8NoBOM
