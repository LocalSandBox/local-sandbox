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

function Invoke-CdbHangAnalysis {
    param(
        [Parameter(Mandatory = $true)][string] $DumpPath,
        [Parameter(Mandatory = $true)][string] $OutputStem,
        [Parameter(Mandatory = $true)][string] $ExpectedModule
    )
    $debugger = Get-Command cdb.exe -ErrorAction SilentlyContinue
    if ($null -ne $debugger) {
        $debuggerPath = $debugger.Source
    } else {
        $debuggerPath = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\Debuggers\x64\cdb.exe'
        Assert-RegularFile $debuggerPath 64MB | Out-Null
    }
    $output = Join-Path $RunRoot "$OutputStem.txt"
    $errorOutput = Join-Path $RunRoot "$OutputStem.stderr.txt"
    $process = Start-Process -FilePath $debuggerPath -ArgumentList @(
        '-z', "`"$DumpPath`"",
        '-c', '".symfix;.reload;!analyze -hang;~* k;!runaway;lm;q"'
    ) -PassThru -RedirectStandardOutput $output -RedirectStandardError $errorOutput
    if (-not $process.WaitForExit(120000)) {
        $process.Kill($true)
        throw "WinDbg did not finish bounded analysis for $DumpPath."
    }
    if ($process.ExitCode -ne 0) {
        throw "WinDbg rejected $DumpPath with exit code $($process.ExitCode)."
    }
    $result = Assert-RegularFile $output 16MB
    $text = [string](Get-Content -LiteralPath $result.FullName -Raw)
    foreach ($expected in @('Child-SP', 'module name', 'User Mode Time', $ExpectedModule)) {
        if (-not $text.Contains($expected, [StringComparison]::OrdinalIgnoreCase)) {
            throw "WinDbg output omitted requested evidence '$expected' for $DumpPath."
        }
    }
    return $result
}

$assets = [IO.Path]::GetFullPath($env:LSB_WINDOWS_TEST_ASSETS_ROOT)
$runtime = Join-Path $assets 'runtime'
$qemu = Join-Path $assets 'qemu\qemu-system-x86_64.exe'
$kernel = Join-Path $runtime 'Image'
$initrd = Join-Path $runtime 'initramfs.cpio.gz'
$rootfsSource = Join-Path $runtime 'rootfs.ext4'
foreach ($path in @($qemu, $kernel, $initrd, $rootfsSource)) {
    Assert-RegularFile $path | Out-Null
}
$rootfs = Join-Path $RunRoot 'runtime-rootfs.ext4'
Copy-Item -LiteralPath $rootfsSource -Destination $rootfs
Assert-RegularFile $rootfs | Out-Null

$testTarget = Join-Path $RunRoot 'cargo-test-target'
$productionTarget = Join-Path $RunRoot 'cargo-production-target'
$env:CARGO_TARGET_DIR = $testTarget
Invoke-Cargo @('build', '-p', 'lsb-qemu-dump-helper', '--locked')
$helper = Join-Path $testTarget 'debug\localsandbox-qemu-dump-helper.exe'
Assert-RegularFile $helper 64MB | Out-Null

$dependencyJson = Join-Path $RunRoot 'sentry-native-prepared.json'
& pwsh -NoProfile -NonInteractive -File scripts/prepare-sentry-native.ps1 `
    -OutputJson $dependencyJson | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Sentry Native preparation failed with exit code $LASTEXITCODE"
}
$dependency = Get-Content -LiteralPath $dependencyJson -Raw | ConvertFrom-Json
$env:LSB_SENTRY_DSN = 'http://public@127.0.0.1:9/1'
$env:LSB_SENTRY_ENVIRONMENT = 'qemu-telemetry-smoke'
$env:LSB_SENTRY_TRACES_SAMPLE_RATE = '1'
$env:LSB_SENTRY_NATIVE_INCLUDE_DIR = [string]$dependency.include_dir
$env:LSB_SENTRY_NATIVE_LIBRARY = [string]$dependency.library
$env:LSB_SENTRY_CRASHPAD_HANDLER = [string]$dependency.crashpad_handler
$env:LSB_SENTRY_CRASHPAD_WER = [string]$dependency.crashpad_wer

$env:LSB_WINDOWS_BOOT_KERNEL = $kernel
$env:LSB_WINDOWS_BOOT_INITRD = $initrd
$env:LSB_WINDOWS_BOOT_ROOTFS = $rootfs
$env:LSB_WINDOWS_BOOT_QEMU = $qemu
$env:LSB_QEMU_HANG_TEST_HELPER = $helper
$secretCanary = "qemu-telemetry-secret-$([Guid]::NewGuid().ToString('N'))"
$rawQmpEndpointPattern = 'socket,id=lsbqmp,host=127\.0\.0\.1,port=\d+'
$env:LSB_QEMU_HANG_TEST_SECRET_CANARY = $secretCanary
$env:LSB_QEMU_HANG_TEST_FORCE_GUEST_READY_TIMEOUT = '0'
$env:LSB_QEMU_HANG_TEST_FORCE_SHUTDOWN_TIMEOUT = '0'
$normalArtifacts = Join-Path $RunRoot 'normal-boot'
$env:LSB_WINDOWS_BOOT_ARTIFACT_DIR = $normalArtifacts
Invoke-Cargo @(
    'test', '-p', 'lsb-platform', '--features', 'qemu-hang-test-hooks', '--locked',
    'windows_x86_64::qemu::boot::tests::windows_qemu_boot_smoke',
    '--', '--ignored', '--exact', '--nocapture'
)
# WHPX teardown can outlive process exit briefly on the shared hardware host.
# Pace distinct VM incidents without weakening any per-incident assertion.
Start-Sleep -Milliseconds 1000

$telemetryRoot = Join-Path $RunRoot 'telemetry'
$env:LSB_QEMU_HANG_TEST_TELEMETRY_ROOT = $telemetryRoot
$env:LSB_QEMU_HANG_TEST_FORCE_GUEST_READY_TIMEOUT = '1'
$env:LSB_QEMU_HANG_TEST_GUEST_READY_TIMEOUT_MS = '1500'
$env:LSB_QEMU_HANG_TEST_DUMP_DEADLINE_MS = '5000'
$incidents = @()
$lastDumpPath = $null
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
    $status = Get-Content -LiteralPath (Join-Path $artifact 'qemu.status.json') -Raw |
        ConvertFrom-Json
    $bootStatus = Get-Content -LiteralPath (Join-Path $artifact 'boot.status.json') -Raw |
        ConvertFrom-Json
    $preflight = Get-Content -LiteralPath (Join-Path $artifact 'preflight.json') -Raw |
        ConvertFrom-Json
    $expectedCorrelationId = 'windows-qemu-hang-smoke'
    $expectedResourceId = 'windows-qemu-hang-smoke'
    if (-not $hang.qmp.connected -or -not $hang.qmp.responsive -or
        @($hang.qmp.queries).Count -ne 4 -or -not $dump.success -or
        [string]$status.state -cne 'exited' -or
        -not [bool]$status.exit_status.success -or
        [string]$hang.correlation_id -cne $expectedCorrelationId -or
        [string]$hang.resource_id -cne $expectedResourceId -or
        [string]$dump.incident_id -cne [string]$hang.incident_id -or
        [string]$dump.correlation_id -cne $expectedCorrelationId -or
        [string]$dump.resource_id -cne $expectedResourceId) {
        throw "Incident $index did not capture responsive QMP and a diagnostic dump."
    }
    foreach ($evidence in @($status, $bootStatus, $preflight)) {
        if ([string]$evidence.incident_id -cne [string]$hang.incident_id -or
            [string]$evidence.correlation_id -cne $expectedCorrelationId -or
            [string]$evidence.resource_id -cne $expectedResourceId) {
            throw "Incident $index boot/teardown identity fields diverged."
        }
    }
    $timelineRecords = @(Get-Content -LiteralPath (Join-Path $artifact 'qemu-timeline.jsonl') |
        ForEach-Object { $_ | ConvertFrom-Json })
    $timelinePhases = @($timelineRecords | ForEach-Object phase)
    $progressRecords = @(Get-Content -LiteralPath (Join-Path $artifact 'qemu-progress.jsonl') |
        ForEach-Object { $_ | ConvertFrom-Json })
    foreach ($record in @($timelineRecords) + @($progressRecords)) {
        if ([string]$record.incident_id -cne [string]$hang.incident_id -or
            [string]$record.correlation_id -cne $expectedCorrelationId -or
            [string]$record.resource_id -cne $expectedResourceId) {
            throw "Incident $index progress/timeline identity fields diverged."
        }
    }
    foreach ($textArtifact in Get-ChildItem -LiteralPath $artifact -File -Force |
        Where-Object { $_.Extension -in @('.json', '.jsonl', '.txt', '.log') }) {
        $text = Get-Content -LiteralPath $textArtifact.FullName -Raw
        if ($null -eq $text) { $text = [string]::Empty }
        if ($text -match $rawQmpEndpointPattern -or
            $text.Contains($secretCanary, [StringComparison]::Ordinal)) {
            throw "Incident $index leaked its QMP endpoint or parent secret into diagnostics."
        }
    }
    $lastPhaseIndex = -1
    foreach ($requiredPhase in @(
        'preflight_started',
        'preflight_completed',
        'qemu_spawn_requested',
        'qemu_spawned_suspended',
        'qemu_job_assigned',
        'qemu_primary_thread_resumed',
        'control_pipe_open_started',
        'control_pipe_opened',
        'guest_ready_wait_started',
        'guest_ready_timeout',
        'hang_snapshot_started',
        'qmp_snapshot_started',
        'qmp_snapshot_completed',
        'hyperv_snapshot_started',
        'hyperv_snapshot_completed',
        'dump_started',
        'dump_completed',
        'hang_snapshot_completed',
        'wait_exit_started',
        'qemu_process_exited'
    )) {
        $phaseIndex = [Array]::IndexOf($timelinePhases, $requiredPhase)
        if ($phaseIndex -lt 0) {
            throw "Incident $index timeline omitted $requiredPhase."
        }
        if ($phaseIndex -le $lastPhaseIndex) {
            throw "Incident $index timeline recorded $requiredPhase out of causal order."
        }
        $lastPhaseIndex = $phaseIndex
    }
    if ($progressRecords.Count -lt 2) {
        throw "Incident $index did not retain scheduled and final progress samples."
    }
    $dumpPath = Join-Path $telemetryRoot ([string]$dump.relative_local_path)
    $dumpItem = Assert-RegularFile $dumpPath
    $hash = (Get-FileHash -LiteralPath $dumpPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hash -cne [string]$dump.sha256 -or $dumpItem.Length -ne [long]$dump.dump_byte_size) {
        throw "Incident $index dump size/hash did not match its manifest."
    }
    $lastDumpPath = $dumpPath
    $incidents += [ordered]@{
        incident_id = [string]$dump.incident_id
        dump_path = [string]$dump.relative_local_path
        dump_size = $dumpItem.Length
        dump_sha256 = $hash
        qmp_queries = @($hang.qmp.queries | ForEach-Object request_name)
    }
    if ($index -lt 4) { Start-Sleep -Milliseconds 1000 }
}
$retained = @(Get-ChildItem -LiteralPath (Join-Path $telemetryRoot 'qemu-dumps') -Directory -Force)
if ($retained.Count -ne 3) {
    throw "Dump retention kept $($retained.Count) directories instead of exactly three."
}

$env:LSB_QEMU_HANG_TEST_FORCE_GUEST_READY_TIMEOUT = '0'
$env:LSB_QEMU_HANG_TEST_FORCE_SHUTDOWN_TIMEOUT = '1'
$env:LSB_QEMU_HANG_TEST_SHUTDOWN_TIMEOUT_MS = '1500'
$shutdownArtifacts = Join-Path $RunRoot 'shutdown-hang'
$env:LSB_WINDOWS_BOOT_ARTIFACT_DIR = $shutdownArtifacts
Invoke-Cargo @(
    'test', '-p', 'lsb-platform', '--features', 'qemu-hang-test-hooks', '--locked',
    'windows_x86_64::qemu::boot::tests::windows_qemu_shutdown_hang_telemetry_smoke',
    '--', '--ignored', '--exact', '--nocapture'
)
$shutdownHang = Get-Content -LiteralPath (Join-Path $shutdownArtifacts 'qemu-hang.json') -Raw |
    ConvertFrom-Json
$shutdownDump = Get-Content `
    -LiteralPath (Join-Path $shutdownArtifacts 'qemu-hang-dump.json') -Raw |
    ConvertFrom-Json
$shutdownStatus = Get-Content `
    -LiteralPath (Join-Path $shutdownArtifacts 'qemu.status.json') -Raw |
    ConvertFrom-Json
$shutdownDumpPath = Join-Path $telemetryRoot ([string]$shutdownDump.relative_local_path)
$shutdownDumpItem = Assert-RegularFile $shutdownDumpPath
$shutdownDumpHash = (
    Get-FileHash -LiteralPath $shutdownDumpItem.FullName -Algorithm SHA256
).Hash.ToLowerInvariant()
if ([string]$shutdownHang.failure_kind -cne 'qemu_shutdown_timeout' -or
    -not $shutdownHang.qmp.connected -or -not $shutdownHang.qmp.responsive -or
    -not $shutdownDump.success -or
    $shutdownDumpHash -cne [string]$shutdownDump.sha256 -or
    $shutdownDumpItem.Length -ne [long]$shutdownDump.dump_byte_size -or
    [string]$shutdownStatus.state -cne 'exited' -or
    -not [bool]$shutdownStatus.exit_status.success) {
    throw 'The QEMU shutdown-timeout path did not retain complete live diagnostics.'
}
$shutdownTimelinePhases = @(
    Get-Content -LiteralPath (Join-Path $shutdownArtifacts 'qemu-timeline.jsonl') |
        ForEach-Object { ($_ | ConvertFrom-Json).phase }
)
$lastShutdownPhaseIndex = -1
foreach ($requiredPhase in @(
    'instance_cleanup_started',
    'wait_exit_started',
    'wait_exit_timed_out',
    'qemu_shutdown_timeout',
    'hang_snapshot_started',
    'dump_completed',
    'hang_snapshot_completed',
    'qemu_process_exited'
)) {
    $phaseIndex = [Array]::IndexOf($shutdownTimelinePhases, $requiredPhase)
    if ($phaseIndex -le $lastShutdownPhaseIndex) {
        throw "QEMU shutdown-timeout timeline omitted or misordered $requiredPhase."
    }
    $lastShutdownPhaseIndex = $phaseIndex
}
foreach ($textArtifact in Get-ChildItem -LiteralPath $shutdownArtifacts -File -Force |
    Where-Object { $_.Extension -in @('.json', '.jsonl', '.txt', '.log') }) {
    $text = Get-Content -LiteralPath $textArtifact.FullName -Raw
    if ($null -eq $text) { $text = [string]::Empty }
    if ($text -match $rawQmpEndpointPattern -or
        $text.Contains($secretCanary, [StringComparison]::Ordinal)) {
        throw 'The QEMU shutdown-timeout diagnostics leaked private parent state.'
    }
}
if (Get-Process -Name 'qemu-system-x86_64' -ErrorAction SilentlyContinue) {
    throw 'The QEMU shutdown-timeout path left QEMU alive.'
}
$env:LSB_QEMU_HANG_TEST_FORCE_SHUTDOWN_TIMEOUT = '0'

$blockedHelper = Join-Path $RunRoot 'blocked-dump-helper.exe'
$blockedHelperSource = Join-Path $RunRoot 'blocked-dump-helper.rs'
Set-Content -LiteralPath $blockedHelperSource -Encoding utf8NoBOM -Value @'
fn main() {
    std::thread::sleep(std::time::Duration::from_secs(60));
}
'@
& rustc --edition=2021 $blockedHelperSource -o $blockedHelper
if ($LASTEXITCODE -ne 0) {
    throw "rustc failed to build the blocked dump helper with exit code $LASTEXITCODE"
}
Assert-RegularFile $blockedHelper 8MB | Out-Null
$env:LSB_QEMU_HANG_TEST_HELPER = $blockedHelper
$env:LSB_QEMU_HANG_TEST_FORCE_GUEST_READY_TIMEOUT = '1'
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
$env:LSB_QEMU_HANG_TEST_HELPER = $helper
$env:LSB_QEMU_HANG_TEST_DUMP_DEADLINE_MS = '5000'
$priorRustFlags = $env:RUSTFLAGS
$env:RUSTFLAGS = '-C target-feature=+crt-static'
$env:LSB_QEMU_HANG_TEST_FORCE_GUEST_READY_TIMEOUT = '1'
$env:LSB_QEMU_HANG_TEST_FORCE_SHUTDOWN_TIMEOUT = '0'
$env:LSB_QEMU_HANG_TEST_SERVICE_ROOT = Join-Path $RunRoot 'service-programdata'
Invoke-Cargo @(
    'test', '-p', 'lsb-seawork-service', '--features',
    'sentry-telemetry,qemu-hang-test-hooks', '--locked',
    'resource::vm::tests::windows_service_owned_qemu_hang_smoke',
    '--', '--ignored', '--exact', '--nocapture'
)
if (Get-Process -Name 'qemu-system-x86_64' -ErrorAction SilentlyContinue) {
    throw 'The service-owned QEMU hang path left QEMU alive.'
}
$serviceArchives = @(Get-ChildItem -LiteralPath $env:LSB_QEMU_HANG_TEST_SERVICE_ROOT `
    -Filter 'incident.zip' -File -Recurse -Force)
if ($serviceArchives.Count -ne 1) {
    throw "Service-owned QEMU hang retained $($serviceArchives.Count) incident archives."
}
$packaged = $serviceArchives[0].DirectoryName
$incidentManifest = Assert-RegularFile (Join-Path $packaged 'incident.json') 1MB
$incidentArchive = Assert-RegularFile (Join-Path $packaged 'incident.zip') 10MB
$archiveInspection = Join-Path $RunRoot 'service-archive-inspection'
Expand-Archive -LiteralPath $incidentArchive.FullName -DestinationPath $archiveInspection
foreach ($textArtifact in Get-ChildItem -LiteralPath $archiveInspection -File -Recurse -Force) {
    $text = Get-Content -LiteralPath $textArtifact.FullName -Raw
    if ($null -eq $text) { $text = [string]::Empty }
    if ($text.Contains($secretCanary, [StringComparison]::Ordinal) -or
        $text -match $rawQmpEndpointPattern) {
        throw 'Service incident archive leaked its QMP endpoint or parent secret.'
    }
}
$serviceHang = Get-Content -LiteralPath (Join-Path $packaged 'qemu-hang.json') -Raw |
    ConvertFrom-Json
if (-not $serviceHang.job.active_process_zero_observed -or
    $serviceHang.job.termination_requested -or
    $serviceHang.job.termination_succeeded -or
    @($serviceHang.job.active_pids).Count -ne 0) {
    throw 'Service-owned QEMU Job did not retain authoritative active-process-zero evidence.'
}
$hyperv = Get-Content -LiteralPath (Join-Path $packaged 'hyperv-events.json') -Raw |
    ConvertFrom-Json
if (@($hyperv.channels).Count -ne 3 -or @($hyperv.events).Count -gt 64 -or
    [long]$hyperv.lookback_ms -lt ([long]$serviceHang.elapsed_ms + 30000)) {
    throw 'Hyper-V evidence did not preserve the three-channel bounded query contract.'
}

$env:LSB_QEMU_HANG_TEST_FORCE_GUEST_READY_TIMEOUT = '0'
$env:LSB_QEMU_HANG_TEST_FORCE_SHUTDOWN_TIMEOUT = '1'
$env:LSB_QEMU_HANG_TEST_SERVICE_STOP_ROOT = Join-Path $RunRoot 'service-stop-programdata'
Invoke-Cargo @(
    'test', '-p', 'lsb-seawork-service', '--features',
    'sentry-telemetry,qemu-hang-test-hooks', '--locked',
    'resource::vm::tests::windows_service_owned_qemu_shutdown_hang_smoke',
    '--', '--ignored', '--exact', '--nocapture'
)
if (Get-Process -Name 'qemu-system-x86_64' -ErrorAction SilentlyContinue) {
    throw 'The service-owned QEMU shutdown-timeout path left QEMU alive.'
}
$serviceStopArchives = @(Get-ChildItem `
    -LiteralPath $env:LSB_QEMU_HANG_TEST_SERVICE_STOP_ROOT `
    -Filter 'incident.zip' -File -Recurse -Force)
if ($serviceStopArchives.Count -ne 1) {
    throw "Service stop retained $($serviceStopArchives.Count) incident archives."
}
$serviceStopPackaged = $serviceStopArchives[0].DirectoryName
$serviceStopHang = Get-Content `
    -LiteralPath (Join-Path $serviceStopPackaged 'qemu-hang.json') -Raw |
    ConvertFrom-Json
$serviceStopManifest = Get-Content `
    -LiteralPath (Join-Path $serviceStopPackaged 'incident.json') -Raw |
    ConvertFrom-Json
$serviceStopHyperv = Get-Content `
    -LiteralPath (Join-Path $serviceStopPackaged 'hyperv-events.json') -Raw |
    ConvertFrom-Json
if ([string]$serviceStopHang.failure_kind -cne 'qemu_shutdown_timeout' -or
    -not $serviceStopHang.job.active_process_zero_observed -or
    $serviceStopHang.job.termination_requested -or
    $serviceStopHang.job.termination_succeeded -or
    [long]$serviceStopHyperv.lookback_ms -lt ([long]$serviceStopHang.elapsed_ms + 30000) -or
    [string]$serviceStopManifest.stable_error_code -cne 'SANDBOX_STOP_FAILED' -or
    [string]$serviceStopManifest.failure_phase -cne 'stop') {
    throw 'Service stop did not preserve its shutdown-timeout incident contract.'
}
$serviceStopArchiveInspection = Join-Path $RunRoot 'service-stop-archive-inspection'
Expand-Archive -LiteralPath $serviceStopArchives[0].FullName `
    -DestinationPath $serviceStopArchiveInspection
foreach ($textArtifact in Get-ChildItem -LiteralPath $serviceStopArchiveInspection `
    -File -Recurse -Force) {
    $text = Get-Content -LiteralPath $textArtifact.FullName -Raw
    if ($null -eq $text) { $text = [string]::Empty }
    if ($text.Contains($secretCanary, [StringComparison]::Ordinal) -or
        $text -match $rawQmpEndpointPattern) {
        throw 'Service stop incident archive leaked its QMP endpoint or parent secret.'
    }
}
$env:LSB_QEMU_HANG_TEST_FORCE_SHUTDOWN_TIMEOUT = '0'

$env:CARGO_TARGET_DIR = $productionTarget
$productionFeatureTreePath = Join-Path $RunRoot 'production-feature-tree.txt'
$productionFeatureTree = & cargo tree -p lsb-seawork-service -e features `
    --features sentry-telemetry --locked
if ($LASTEXITCODE -ne 0) {
    throw "Production feature metadata failed with exit code $LASTEXITCODE."
}
$productionFeatureTree | Set-Content -LiteralPath $productionFeatureTreePath -Encoding utf8NoBOM
if (($productionFeatureTree -join "`n").Contains('qemu-hang-test-hooks')) {
    throw 'Production service feature metadata unexpectedly contains qemu-hang-test-hooks.'
}
$productionFeatureEvidence = Assert-RegularFile $productionFeatureTreePath 1MB
Invoke-Cargo @('build', '-p', 'lsb-seawork-service', '--features', 'sentry-telemetry', '--locked')
$productionService = Join-Path $productionTarget 'debug\localsandbox-seawork-service.exe'
$binaryText = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($productionService))
if ($binaryText.Contains('LSB_QEMU_HANG_TEST_FORCE_GUEST_READY_TIMEOUT') -or
    $binaryText.Contains('LSB_QEMU_HANG_TEST_FORCE_SHUTDOWN_TIMEOUT') -or
    $binaryText.Contains('LSB_QEMU_HANG_TEST_SHUTDOWN_TIMEOUT_MS') -or
    $binaryText.Contains('LSB_QEMU_HANG_TEST_HELPER')) {
    throw 'Production service unexpectedly contains qemu-hang-test-hooks strings.'
}
$env:RUSTFLAGS = $priorRustFlags

$childArtifacts = Join-Path $RunRoot 'diagnostic-child'
$childTelemetry = Join-Path $RunRoot 'diagnostic-child-telemetry'
$env:LSB_QEMU_HANG_TEST_CHILD_ARTIFACT_DIR = $childArtifacts
$env:LSB_QEMU_HANG_TEST_CHILD_TELEMETRY_ROOT = $childTelemetry
Invoke-Cargo @(
    'test', '-p', 'lsb-platform', '--features', 'qemu-hang-test-hooks', '--locked',
    'windows_x86_64::qemu::boot::tests::windows_dump_helper_diagnostic_child_smoke',
    '--', '--ignored', '--exact', '--nocapture'
)
$childManifest = Get-Content -LiteralPath (Join-Path $childArtifacts 'qemu-hang-dump.json') -Raw |
    ConvertFrom-Json
$childDumpPath = Join-Path $childTelemetry ([string]$childManifest.relative_local_path)
$childDump = Assert-RegularFile $childDumpPath
$childHash = (Get-FileHash -LiteralPath $childDump.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
if (-not $childManifest.success -or $childHash -cne [string]$childManifest.sha256 -or
    $childDump.Length -ne [long]$childManifest.dump_byte_size) {
    throw 'The no-WHPX diagnostic child dump did not match its manifest.'
}
$childWindbgResult = Invoke-CdbHangAnalysis -DumpPath $childDump.FullName `
    -OutputStem 'windbg-diagnostic-child' -ExpectedModule 'lsb_platform'
$windbgResult = Invoke-CdbHangAnalysis -DumpPath $lastDumpPath `
    -OutputStem 'windbg-qemu-hang' -ExpectedModule 'qemu'
$shutdownWindbgResult = Invoke-CdbHangAnalysis -DumpPath $shutdownDumpItem.FullName `
    -OutputStem 'windbg-qemu-shutdown-hang' -ExpectedModule 'qemu'

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
    production_feature_tree_sha256 = (
        Get-FileHash -LiteralPath $productionFeatureEvidence.FullName -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    normal_guest_ready = $true
    diagnostic_child = [ordered]@{
        dump_path = [string]$childManifest.relative_local_path
        dump_size = $childDump.Length
        dump_sha256 = $childHash
        windbg_output_sha256 = (
            Get-FileHash -LiteralPath $childWindbgResult.FullName -Algorithm SHA256
        ).Hash.ToLowerInvariant()
    }
    incidents = $incidents
    retained_incident_count = $retained.Count
    shutdown_timeout = [ordered]@{
        dump_path = [string]$shutdownDump.relative_local_path
        dump_size = $shutdownDumpItem.Length
        dump_sha256 = $shutdownDumpHash
        qmp_responsive = [bool]$shutdownHang.qmp.responsive
        windbg_output_sha256 = (
            Get-FileHash -LiteralPath $shutdownWindbgResult.FullName -Algorithm SHA256
        ).Hash.ToLowerInvariant()
    }
    helper_timeout_bounded = $true
    qemu_processes_remaining = 0
    hyperv_channels = @($hyperv.channels)
    hyperv_event_count = @($hyperv.events).Count
    incident_manifest_sha256 = (
        Get-FileHash -LiteralPath $incidentManifest.FullName -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    incident_archive_sha256 = (
        Get-FileHash -LiteralPath $incidentArchive.FullName -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    service_job_active_process_zero = $true
    service_stop_rpc_deadline_ms = 45000
    service_stop_failure_kind = [string]$serviceStopHang.failure_kind
    downstream_app_stop_quarantine_exercised = $false
    windbg_opened = $true
    windbg_output_sha256 = (
        Get-FileHash -LiteralPath $windbgResult.FullName -Algorithm SHA256
    ).Hash.ToLowerInvariant()
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
