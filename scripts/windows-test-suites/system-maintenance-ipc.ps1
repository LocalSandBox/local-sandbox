[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Normal', 'BeforeReboot', 'AfterReboot')]
    [string] $Phase,

    [Parameter(Mandatory = $true)]
    [string] $RunRoot,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string] $SnapshotSha
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($Phase -ne 'Normal') {
    throw 'The system-maintenance-ipc suite does not support reboot phases.'
}

$testName = 'security::token::tests::local_system_named_pipe_identity_is_accepted_for_maintenance'
$taskName = "LocalSandboxAgent-SystemIpc-$($SnapshotSha.Substring(0, 12))"
$targetRoot = if ([string]::IsNullOrWhiteSpace($env:CARGO_TARGET_DIR)) {
    Join-Path $PWD 'target'
}
else {
    [IO.Path]::GetFullPath($env:CARGO_TARGET_DIR)
}
$outputPath = Join-Path $RunRoot 'system-maintenance-ipc-output.txt'
$identityPath = Join-Path $RunRoot 'system-maintenance-ipc-identity.csv'
$exitPath = Join-Path $RunRoot 'system-maintenance-ipc-exit.txt'
$batchPath = Join-Path $RunRoot 'system-maintenance-ipc.cmd'

if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    throw "Refusing to adopt an existing LocalSystem IPC test task: $taskName"
}

& cargo test -p lsb-seawork-service --locked --no-run
if ($LASTEXITCODE -ne 0) {
    throw "LocalSystem IPC test build failed with exit code $LASTEXITCODE"
}

$testBinaries = @(
    Get-ChildItem -LiteralPath (Join-Path $targetRoot 'debug\deps') `
        -Filter 'localsandbox_seawork_service-*.exe' -File |
        Sort-Object LastWriteTimeUtc -Descending
)
if ($testBinaries.Count -lt 1) {
    throw 'The LocalSystem IPC test build did not produce a test executable.'
}
$testBinary = $testBinaries[0].FullName

@(
    '@echo off',
    "whoami.exe /user /fo csv /nh > `"$identityPath`"",
    "if errorlevel 1 exit /b %errorlevel%",
    "`"$testBinary`" `"$testName`" --ignored --exact --nocapture > `"$outputPath`" 2>&1",
    'set "test_exit=%errorlevel%"',
    "> `"$exitPath`" echo %test_exit%",
    'exit /b 0'
) | Set-Content -LiteralPath $batchPath -Encoding ascii

$action = New-ScheduledTaskAction -Execute $env:ComSpec `
    -Argument ('/d /c call "{0}"' -f $batchPath)
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(10)
$principal = New-ScheduledTaskPrincipal `
    -UserId 'SYSTEM' `
    -LogonType ServiceAccount `
    -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 5) `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -MultipleInstances IgnoreNew

try {
    $registered = Register-ScheduledTask -TaskName $taskName -Action $action `
        -Trigger $trigger -Principal $principal -Settings $settings
    if ([string]$registered.Principal.UserId -notin @('SYSTEM', 'S-1-5-18') -or
        [string]$registered.Principal.LogonType -ne 'ServiceAccount' -or
        [string]$registered.Principal.RunLevel -ne 'Highest') {
        throw 'The LocalSystem IPC test task principal is inconsistent.'
    }

    $startedAfter = [datetime]::Now.AddSeconds(-2)
    Start-ScheduledTask -TaskName $taskName
    $deadline = [datetime]::UtcNow.AddMinutes(5)
    do {
        $task = Get-ScheduledTask -TaskName $taskName
        $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName
        if ($task.State -eq 'Ready' -and $taskInfo.LastRunTime -ge $startedAfter) {
            break
        }
        Start-Sleep -Milliseconds 250
    } while ([datetime]::UtcNow -lt $deadline)
    if ($task.State -ne 'Ready' -or $taskInfo.LastRunTime -lt $startedAfter) {
        throw 'The LocalSystem IPC test task exceeded its execution deadline.'
    }
    if ([uint32]$taskInfo.LastTaskResult -ne 0) {
        throw "The LocalSystem IPC test task failed with result $($taskInfo.LastTaskResult)."
    }
    if (-not (Test-Path -LiteralPath $identityPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $exitPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $outputPath -PathType Leaf)) {
        throw 'The LocalSystem IPC test task did not produce its bounded outputs.'
    }

    $identity = @(Get-Content -LiteralPath $identityPath |
        ConvertFrom-Csv -Header UserName, Sid)
    if ($identity.Count -ne 1 -or [string]$identity[0].Sid -cne 'S-1-5-18') {
        throw 'The IPC regression did not execute as LocalSystem.'
    }
    [int]$testExit = -1
    if (-not [int]::TryParse(
        (Get-Content -LiteralPath $exitPath -Raw).Trim(),
        [ref]$testExit
    ) -or $testExit -ne 0) {
        $output = (Get-Content -LiteralPath $outputPath -Raw).Trim()
        throw "The LocalSystem IPC regression failed with exit $testExit`: $output"
    }
    $testOutput = Get-Content -LiteralPath $outputPath -Raw
    if ($testOutput -notmatch 'test result: ok\.' -or
        $testOutput -notmatch [regex]::Escape($testName)) {
        throw 'The LocalSystem IPC regression output is incomplete.'
    }

    [ordered]@{
        schema_version = 1
        suite = 'system-maintenance-ipc'
        status = 'passed'
        snapshot_sha = $SnapshotSha
        user_sid = [string]$identity[0].Sid
        session = 0
        token_class = 'LocalSystemMaintenance'
        real_named_pipe_impersonation = $true
    } | ConvertTo-Json -Depth 4 | Set-Content `
        -LiteralPath (Join-Path $RunRoot 'evidence-system-maintenance-ipc.json') `
        -Encoding utf8NoBOM
}
finally {
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $batchPath -Force -ErrorAction SilentlyContinue
}

Get-Content -LiteralPath (Join-Path $RunRoot 'evidence-system-maintenance-ipc.json') -Raw
