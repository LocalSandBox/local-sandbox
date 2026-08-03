[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string] $Root = 'C:\dev\local-sandbox-agent',
    [string] $StateRoot = 'C:\dev\local-sandbox-agent-state',
    [switch] $Full
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'lib\common.ps1')

$installOwner = 'local-sandbox-agent-install-smoke'
$serviceNames = @('LocalSandboxSeaWorkUpdater', 'LocalSandboxSeaWork', 'LocalSandboxSeaWorkSpike')
$processNames = @(
    'localsandbox-seawork-service', 'localsandbox-seawork-updater',
    'lsb-service-spike', 'qemu-system-x86_64', 'qemu-img'
)
$taskPrefixes = @('LocalSandboxAgent-')
$sharePrefix = '^lsb-[a-z0-9-]+$'
$userPrefix = '^lsb_[0-9a-f]+$'

function Invoke-Sc {
    param([Parameter(Mandatory = $true)][string[]] $Arguments)
    & sc.exe @Arguments | Out-Null
    return $LASTEXITCODE
}

function Test-InstallOwnerMarker {
    param([string] $Path, [string] $MarkerName)
    $markerPath = Join-Path $Path $MarkerName
    if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) { return $false }
    try {
        $marker = Read-WindowsTestJson -Path $markerPath -MaximumBytes 16KB
        return $marker.schema_version -eq 1 -and $marker.owner -ceq $installOwner
    }
    catch { return $false }
}

function Remove-PlainTree {
    param([Parameter(Mandatory = $true)][string] $Path, [switch] $RequireMarker, [string] $MarkerName)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Reset target is not a plain directory: $Path"
    }
    if ($RequireMarker -and -not (Test-InstallOwnerMarker -Path $Path -MarkerName $MarkerName)) {
        throw "Reset target lacks its required ownership marker: $Path"
    }
    if ($PSCmdlet.ShouldProcess($item.FullName, 'Remove owned Windows test tree')) {
        Remove-Item -LiteralPath $item.FullName -Recurse -Force -ErrorAction Stop
    }
}

Assert-WindowsTestAdministrator
$rootPath = Resolve-WindowsTestOwnedRoot -Path $Root -ExpectedLeaf 'local-sandbox-agent'
$statePath = Resolve-WindowsTestOwnedRoot -Path $StateRoot -ExpectedLeaf 'local-sandbox-agent-state'
$lockPath = Join-Path $statePath 'locks\runner.lock'
$lock = $null
try {
    $lock = [IO.File]::Open(
        $lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None
    )
}
catch [IO.IOException] {
    throw 'Refusing to reset while a Windows test run owns the exclusive host lock.'
}

try {
    $fullTargets = @(
        (Assert-WindowsTestDescendant -Path (Join-Path $rootPath 'cache') -Root $rootPath),
        (Assert-WindowsTestDescendant -Path (Join-Path $statePath 'runs') -Root $statePath)
    )
    if ($Full) {
        Write-Output 'Full reset additional targets:'
        foreach ($target in $fullTargets) { Write-Output "  $target" }
    }

    $importsRoot = Assert-WindowsTestDescendant -Path (Join-Path $statePath 'imports') `
        -Root $statePath
    if (Test-Path -LiteralPath $importsRoot -PathType Container) {
        foreach ($stage in @(Get-ChildItem -LiteralPath $importsRoot -Directory -Force)) {
            $stageOwner = Join-Path $stage.FullName 'owner.json'
            $owned = $false
            if (Test-Path -LiteralPath $stageOwner -PathType Leaf) {
                try {
                    $marker = Read-WindowsTestJson -Path $stageOwner -MaximumBytes 16KB
                    $owned = $marker.owner -ceq 'local-sandbox-release-artifact-import'
                }
                catch { $owned = $false }
            }
            if (-not $owned) { throw "Refusing to remove an unowned artifact import stage: $($stage.FullName)" }
            Remove-PlainTree -Path $stage.FullName
        }
    }

    foreach ($name in $serviceNames) {
        $service = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($null -ne $service) {
            if ($service.Status -ne 'Stopped') {
                if ($PSCmdlet.ShouldProcess("service:$name", 'Stop')) {
                    Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
                    $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(45))
                }
            }
            if ($PSCmdlet.ShouldProcess("service:$name", 'Delete')) {
                $exit = Invoke-Sc -Arguments @('delete', $name)
                if ($exit -notin @(0, 1060)) { throw "sc.exe delete $name failed with exit code $exit" }
            }
        }
    }

    foreach ($name in $processNames) {
        foreach ($process in @(Get-Process -Name $name -ErrorAction SilentlyContinue)) {
            if ($PSCmdlet.ShouldProcess("process:$name/$($process.Id)", 'Stop exact-name process')) {
                Stop-Process -Id $process.Id -Force -ErrorAction Stop
            }
        }
    }

    $eventSource = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\LocalSandboxSeaWork'
    if (Test-Path -LiteralPath $eventSource) {
        if ($PSCmdlet.ShouldProcess($eventSource, 'Remove LocalSandbox Event Log source')) {
            Remove-Item -LiteralPath $eventSource -Recurse -Force -ErrorAction Stop
        }
    }

    foreach ($task in @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
        $candidate = $_.TaskName
        @($taskPrefixes | Where-Object { $candidate.StartsWith($_, [StringComparison]::Ordinal) }).Count -gt 0
    })) {
        if ($PSCmdlet.ShouldProcess("scheduled-task:$($task.TaskName)", 'Stop and unregister')) {
            Stop-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath `
                -Confirm:$false -ErrorAction Stop
        }
    }

    foreach ($mapping in @(Get-SmbMapping -ErrorAction SilentlyContinue | Where-Object {
        ($_.RemotePath -split '\\')[-1] -match $sharePrefix
    })) {
        if ($PSCmdlet.ShouldProcess("SMB mapping:$($mapping.RemotePath)", 'Remove')) {
            Remove-SmbMapping -RemotePath $mapping.RemotePath -Force -UpdateProfile:$false `
                -ErrorAction Stop
        }
    }
    foreach ($share in @(Get-SmbShare -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match $sharePrefix
    })) {
        if ($PSCmdlet.ShouldProcess("SMB share:$($share.Name)", 'Remove')) {
            Remove-SmbShare -Name $share.Name -Force -Confirm:$false -ErrorAction Stop
        }
    }
    foreach ($user in @(Get-LocalUser -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match $userPrefix
    })) {
        if ($PSCmdlet.ShouldProcess("local user:$($user.Name)", 'Remove')) {
            Remove-LocalUser -Name $user.Name -Confirm:$false -ErrorAction Stop
        }
    }

    $canonicalPaths = @(
        (Join-Path $env:ProgramFiles 'SeaWork\LocalSandbox'),
        (Join-Path $env:ProgramData 'LocalSandbox\SeaWork'),
        (Join-Path $env:ProgramData 'LocalSandbox\SeaWorkSpike'),
        (Join-Path $env:ProgramData 'SeaWork\Installer')
    )
    foreach ($path in $canonicalPaths) { Remove-PlainTree -Path $path }

    $auxiliaryTargets = [Collections.Generic.List[string]]::new()
    $signingHarness = Join-Path $env:ProgramFiles 'SeaWork\LocalSandboxTestHarness'
    if (Test-Path -LiteralPath $signingHarness) {
        $auxiliaryTargets.Add($signingHarness)
        Remove-PlainTree -Path $signingHarness -RequireMarker `
            -MarkerName '.local-sandbox-agent-client.json'
    }
    foreach ($profile in @(Get-ChildItem -LiteralPath 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue)) {
        $programs = Join-Path $profile.FullName 'AppData\Local\Programs'
        if (-not (Test-Path -LiteralPath $programs -PathType Container)) { continue }
        foreach ($client in @(Get-ChildItem -LiteralPath $programs -Directory -Force | Where-Object {
            $_.Name -in @('SeaWork', 'SeaWork Test') -or $_.Name -match '^SeaWork-copy-[0-9a-f]{12}$'
        })) {
            $auxiliaryTargets.Add($client.FullName)
            Remove-PlainTree -Path $client.FullName -RequireMarker `
                -MarkerName '.local-sandbox-agent-client.json'
        }
    }

    if ($Full) {
        foreach ($target in $fullTargets) {
            Remove-PlainTree -Path $target
            if ($PSCmdlet.ShouldProcess($target, 'Recreate empty owned directory')) {
                New-Item -ItemType Directory -Path $target | Out-Null
            }
        }
    }

    Start-Sleep -Milliseconds 500
    $remaining = [Collections.Generic.List[string]]::new()
    foreach ($name in $serviceNames) {
        if (Get-Service -Name $name -ErrorAction SilentlyContinue) { $remaining.Add("service:$name") }
    }
    foreach ($name in $processNames) {
        if (Get-Process -Name $name -ErrorAction SilentlyContinue) { $remaining.Add("process:$name") }
    }
    if (Test-Path -LiteralPath $eventSource) { $remaining.Add("event-source:$eventSource") }
    foreach ($path in $canonicalPaths) {
        if (Test-Path -LiteralPath $path) { $remaining.Add("path:$path") }
    }
    foreach ($task in @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
        $_.TaskName -like 'LocalSandboxAgent-*'
    })) { $remaining.Add("task:$($task.TaskName)") }
    foreach ($share in @(Get-SmbShare -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match $sharePrefix
    })) { $remaining.Add("share:$($share.Name)") }
    foreach ($user in @(Get-LocalUser -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match $userPrefix
    })) { $remaining.Add("user:$($user.Name)") }
    foreach ($mapping in @(Get-SmbMapping -ErrorAction SilentlyContinue | Where-Object {
        ($_.RemotePath -split '\\')[-1] -match $sharePrefix
    })) { $remaining.Add("mapping:$($mapping.RemotePath)") }
    foreach ($path in $auxiliaryTargets) {
        if (Test-Path -LiteralPath $path) { $remaining.Add("path:$path") }
    }
    foreach ($stage in @(Get-ChildItem -LiteralPath $importsRoot -Directory -Force `
        -ErrorAction SilentlyContinue)) { $remaining.Add("artifact-import:$($stage.Name)") }
    if ($remaining.Count -gt 0) {
        throw "Windows test reset verification failed; resources remain: $($remaining -join ', ')"
    }
    [ordered]@{
        schema_version = 1
        status = 'reset'
        full = [bool]$Full
        preserved = @('mirror.git', 'repo', 'assets', 'locks')
        cleared_full_targets = if ($Full) { $fullTargets } else { @() }
    } | ConvertTo-Json -Depth 5
}
finally {
    if ($null -ne $lock) { $lock.Dispose() }
}
