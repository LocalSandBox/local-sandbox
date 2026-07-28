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
if ($Phase -ne 'Normal') { throw 'qemu-telemetry-smoke does not support reboot phases.' }

function Invoke-Cargo {
    param([string[]] $Arguments)
    & cargo @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "cargo failed with exit code $LASTEXITCODE`: cargo $($Arguments -join ' ')"
    }
}

function Assert-RegularFile {
    param([string] $Path, [long] $MaximumBytes = 16GB)
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $item.Length -le 0 -or $item.Length -gt $MaximumBytes) {
        throw "Expected a bounded regular file: $Path"
    }
    return $item
}

$assets = [IO.Path]::GetFullPath($env:LSB_WINDOWS_TEST_ASSETS_ROOT)
$runtime = Join-Path $assets 'runtime'
$qemu = Join-Path $assets 'qemu\qemu-system-x86_64.exe'
$kernel = Join-Path $runtime 'Image'
$initrd = Join-Path $runtime 'initramfs.cpio.gz'
$rootfs = Join-Path $runtime 'rootfs.ext4'
foreach ($path in @($qemu, $kernel, $initrd, $rootfs)) {
    Assert-RegularFile $path | Out-Null
}

$testTarget = Join-Path $RunRoot 'cargo-test-target'
$productionTarget = Join-Path $RunRoot 'cargo-production-target'
$env:CARGO_TARGET_DIR = $testTarget
Invoke-Cargo @('build', '-p', 'lsb-qemu-dump-helper', '--locked')
$helper = Join-Path $testTarget 'debug\localsandbox-qemu-dump-helper.exe'
Assert-RegularFile $helper 64MB | Out-Null

$env:LSB_WINDOWS_BOOT_KERNEL = $kernel
$env:LSB_WINDOWS_BOOT_INITRD = $initrd
$env:LSB_WINDOWS_BOOT_ROOTFS = $rootfs
$env:LSB_WINDOWS_BOOT_QEMU = $qemu
$env:LSB_QEMU_HANG_TEST_HELPER = $helper
$env:LSB_QEMU_HANG_TEST_FORCE_GUEST_READY_TIMEOUT = '0'
$normalArtifacts = Join-Path $RunRoot 'normal-boot'
$env:LSB_WINDOWS_BOOT_ARTIFACT_DIR = $normalArtifacts
Invoke-Cargo @(
    'test', '-p', 'lsb-platform', '--features', 'qemu-hang-test-hooks', '--locked',
    'windows_x86_64::qemu::boot::tests::windows_qemu_boot_smoke',
    '--', '--ignored', '--exact', '--nocapture'
)

$telemetryRoot = Join-Path $RunRoot 'telemetry'
$env:LSB_QEMU_HANG_TEST_TELEMETRY_ROOT = $telemetryRoot
$env:LSB_QEMU_HANG_TEST_FORCE_GUEST_READY_TIMEOUT = '1'
$env:LSB_QEMU_HANG_TEST_GUEST_READY_TIMEOUT_MS = '1500'
$env:LSB_QEMU_HANG_TEST_DUMP_DEADLINE_MS = '5000'
$incidents = @()
foreach ($index in 1..4) {
    $artifact = Join-Path $RunRoot "hang-$index"
    $env:LSB_WINDOWS_BOOT_ARTIFACT_DIR = $artifact
    Invoke-Cargo @(
        'test', '-p', 'lsb-platform', '--features', 'qemu-hang-test-hooks', '--locked',
        'windows_x86_64::qemu::boot::tests::windows_qemu_hang_telemetry_smoke',
        '--', '--ignored', '--exact', '--nocapture'
    )
    $hang = Get-Content -LiteralPath (Join-Path $artifact 'qemu-hang.json') -Raw |
        ConvertFrom-Json
    $dump = Get-Content -LiteralPath (Join-Path $artifact 'qemu-hang-dump.json') -Raw |
        ConvertFrom-Json
    if (-not $hang.qmp.connected -or -not $hang.qmp.responsive -or
        @($hang.qmp.queries).Count -ne 4 -or -not $dump.success) {
        throw "Incident $index did not capture responsive QMP and a diagnostic dump."
    }
    $dumpPath = Join-Path $telemetryRoot ([string]$dump.relative_local_path)
    $dumpItem = Assert-RegularFile $dumpPath
    $hash = (Get-FileHash -LiteralPath $dumpPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hash -cne [string]$dump.sha256 -or $dumpItem.Length -ne [long]$dump.dump_byte_size) {
        throw "Incident $index dump size/hash did not match its manifest."
    }
    $incidents += [ordered]@{
        incident_id = [string]$dump.incident_id
        dump_size = $dumpItem.Length
        dump_sha256 = $hash
        qmp_queries = @($hang.qmp.queries | ForEach-Object request_name)
    }
}
$retained = @(Get-ChildItem -LiteralPath (Join-Path $telemetryRoot 'qemu-dumps') -Directory -Force)
if ($retained.Count -ne 3) {
    throw "Dump retention kept $($retained.Count) directories instead of exactly three."
}

$blockedHelper = Join-Path $RunRoot 'blocked-dump-helper.exe'
$source = @'
using System;
using System.Threading;
public static class BlockedDumpHelper {
    public static int Main(string[] args) { Thread.Sleep(60000); return 0; }
}
'@
Add-Type -TypeDefinition $source -OutputAssembly $blockedHelper -OutputType ConsoleApplication
Assert-RegularFile $blockedHelper 8MB | Out-Null
$env:LSB_QEMU_HANG_TEST_HELPER = $blockedHelper
$env:LSB_QEMU_HANG_TEST_DUMP_DEADLINE_MS = '250'
$env:LSB_QEMU_HANG_TEST_EXPECT_DUMP_TIMEOUT = '1'
$env:LSB_WINDOWS_BOOT_ARTIFACT_DIR = Join-Path $RunRoot 'helper-timeout'
Invoke-Cargo @(
    'test', '-p', 'lsb-platform', '--features', 'qemu-hang-test-hooks', '--locked',
    'windows_x86_64::qemu::boot::tests::windows_qemu_hang_telemetry_smoke',
    '--', '--ignored', '--exact', '--nocapture'
)
if (Get-Process -Name 'blocked-dump-helper', 'qemu-system-x86_64' -ErrorAction SilentlyContinue) {
    throw 'The helper-timeout path left a helper or QEMU process alive.'
}

Remove-Item Env:LSB_QEMU_HANG_TEST_EXPECT_DUMP_TIMEOUT -ErrorAction SilentlyContinue
Invoke-Cargo @(
    'test', '-p', 'lsb-seawork-service', '--features',
    'sentry-telemetry,qemu-hang-test-hooks', '--locked',
    'telemetry::windows_events::tests::captures_all_bounded_hyperv_channels_for_live_incident_window',
    '--', '--exact'
)
Invoke-Cargo @(
    'test', '-p', 'lsb-seawork-service', '--features',
    'sentry-telemetry,qemu-hang-test-hooks', '--locked',
    'telemetry::diagnostics::tests::collects_allowlist_and_records_missing_files'
)

$env:CARGO_TARGET_DIR = $productionTarget
Invoke-Cargo @('build', '-p', 'lsb-seawork-service', '--features', 'sentry-telemetry', '--locked')
$productionService = Join-Path $productionTarget 'debug\localsandbox-seawork-service.exe'
$binaryText = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($productionService))
if ($binaryText.Contains('LSB_QEMU_HANG_TEST_FORCE_GUEST_READY_TIMEOUT') -or
    $binaryText.Contains('LSB_QEMU_HANG_TEST_HELPER')) {
    throw 'Production service unexpectedly contains qemu-hang-test-hooks strings.'
}

$qemuVersion = (& $qemu --version | Select-Object -First 1).Trim()
$os = Get-CimInstance Win32_OperatingSystem
$evidencePath = Join-Path $RunRoot 'evidence-qemu-telemetry-smoke.json'
[ordered]@{
    schema_version = 1
    status = 'passed'
    snapshot_sha = $SnapshotSha
    windows_build = [string]$os.BuildNumber
    qemu_version = $qemuVersion
    test_features = @('qemu-hang-test-hooks', 'sentry-telemetry')
    production_test_hooks_absent = $true
    normal_guest_ready = $true
    incidents = $incidents
    retained_incident_count = $retained.Count
    helper_timeout_bounded = $true
    qemu_processes_remaining = 0
} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $evidencePath -Encoding utf8NoBOM
$evidence = Assert-RegularFile $evidencePath 1MB
[ordered]@{
    schema_version = 1
    run_id = Split-Path -Leaf ([IO.Path]::GetFullPath($RunRoot).TrimEnd('\'))
    artifacts = @([ordered]@{
        name = $evidence.Name
        sha256 = (Get-FileHash -LiteralPath $evidence.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        size = $evidence.Length
    })
} | ConvertTo-Json -Depth 5 | Set-Content `
    -LiteralPath (Join-Path $RunRoot 'fetch-manifest.json') -Encoding utf8NoBOM
