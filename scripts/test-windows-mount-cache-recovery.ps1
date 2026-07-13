[CmdletBinding()]
param(
    [string]$Binary = ".\target\release\lsb.exe",
    [Parameter(Mandatory = $true)][string]$Kernel,
    [Parameter(Mandatory = $true)][string]$Initrd,
    [Parameter(Mandatory = $true)][string]$Rootfs,
    [Parameter(Mandatory = $true)][string]$FixtureRoot,
    [string]$WorkRoot = ".\target\windows-mount-cache-recovery",
    [string]$Qemu,
    [string]$QemuImg,
    [Parameter(DontShow = $true)][string]$ChildName,
    [Parameter(DontShow = $true)][string]$GateDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-FullPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }
    return [System.IO.Path]::GetFullPath((Join-Path (Get-Location) $Path))
}

function Get-RunArguments {
    return @(
        "run",
        "--kernel", $env:LSB_TEST_CACHE_KERNEL,
        "--initrd", $env:LSB_TEST_CACHE_INITRD,
        "--rootfs", $env:LSB_TEST_CACHE_ROOTFS,
        "--mount", "$($env:LSB_TEST_CACHE_FIXTURE):/workspace",
        "--", "/bin/true"
    )
}

function Restore-EnvironmentVariable {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowNull()][string]$Value
    )

    if ($null -eq $Value) {
        Remove-Item -Path "Env:$Name" -ErrorAction SilentlyContinue
    }
    else {
        Set-Item -Path "Env:$Name" -Value $Value
    }
}

if (-not [string]::IsNullOrWhiteSpace($ChildName)) {
    if ([string]::IsNullOrWhiteSpace($GateDirectory)) {
        throw "GateDirectory is required in child mode"
    }
    $env:LSB_WINDOWS_MOUNT_METRICS_PATH = Join-Path $GateDirectory "$ChildName-metrics.json"
    [System.IO.File]::WriteAllText((Join-Path $GateDirectory "$ChildName-ready"), "ready")
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    while (-not (Test-Path -LiteralPath (Join-Path $GateDirectory "go"))) {
        if ([DateTime]::UtcNow -ge $deadline) {
            throw "timed out waiting for the concurrent start gate"
        }
        Start-Sleep -Milliseconds 10
    }
    & $env:LSB_TEST_CACHE_BINARY @(Get-RunArguments)
    exit $LASTEXITCODE
}

$repoRoot = Resolve-FullPath (Join-Path $PSScriptRoot "..")
$binaryPath = Resolve-FullPath $Binary
$kernelPath = Resolve-FullPath $Kernel
$initrdPath = Resolve-FullPath $Initrd
$rootfsPath = Resolve-FullPath $Rootfs
$fixturePath = Resolve-FullPath $FixtureRoot
$workPath = Resolve-FullPath $WorkRoot
foreach ($path in @($binaryPath, $kernelPath, $initrdPath, $rootfsPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "required test file does not exist: $path"
    }
}
if (-not (Test-Path -LiteralPath $fixturePath -PathType Container)) {
    throw "fixture directory does not exist: $fixturePath"
}
$fixtureFiles = @(Get-ChildItem -LiteralPath $fixturePath -File -Recurse)
if ($fixtureFiles.Count -ne 2000) {
    throw "recovery fixture must contain exactly 2,000 files, found $($fixtureFiles.Count)"
}
$workRootWithSeparator = $workPath.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
$repoRootWithSeparator = $repoRoot.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
if (-not $workRootWithSeparator.StartsWith($repoRootWithSeparator, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "WorkRoot must stay inside the repository: $workPath"
}
if ($workPath.TrimEnd('\', '/') -eq $repoRoot.TrimEnd('\', '/')) {
    throw "WorkRoot cannot be the repository root"
}

$savedEnvironment = @{}
foreach ($name in @(
        "LOCALAPPDATA",
        "LSB_QEMU",
        "LSB_QEMU_IMG",
        "LSB_WINDOWS_MOUNT_CACHE_DIR",
        "LSB_WINDOWS_MOUNT_METRICS_PATH",
        "LSB_TEST_CACHE_BINARY",
        "LSB_TEST_CACHE_KERNEL",
        "LSB_TEST_CACHE_INITRD",
        "LSB_TEST_CACHE_ROOTFS",
        "LSB_TEST_CACHE_FIXTURE"
    )) {
    $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name)
}

try {
    if (Test-Path -LiteralPath $workPath) {
        Remove-Item -LiteralPath $workPath -Recurse -Force
    }
    $cacheRoot = Join-Path $workPath "cache"
    $gate = Join-Path $workPath "concurrent"
    $interruptedLogs = Join-Path $workPath "interrupted"
    $dataParent = Join-Path $workPath "localappdata"
    foreach ($path in @($cacheRoot, $gate, $interruptedLogs, $dataParent)) {
        [System.IO.Directory]::CreateDirectory($path) | Out-Null
    }

    $env:LOCALAPPDATA = $dataParent
    $env:LSB_WINDOWS_MOUNT_CACHE_DIR = $cacheRoot
    $env:LSB_TEST_CACHE_BINARY = $binaryPath
    $env:LSB_TEST_CACHE_KERNEL = $kernelPath
    $env:LSB_TEST_CACHE_INITRD = $initrdPath
    $env:LSB_TEST_CACHE_ROOTFS = $rootfsPath
    $env:LSB_TEST_CACHE_FIXTURE = $fixturePath
    if (-not [string]::IsNullOrWhiteSpace($Qemu)) {
        $env:LSB_QEMU = Resolve-FullPath $Qemu
    }
    if (-not [string]::IsNullOrWhiteSpace($QemuImg)) {
        $env:LSB_QEMU_IMG = Resolve-FullPath $QemuImg
    }

    $powershell = Join-Path $PSHOME "pwsh.exe"
    $children = foreach ($name in @("first", "second")) {
        Start-Process -FilePath $powershell `
            -ArgumentList @(
                "-NoProfile",
                "-File", $PSCommandPath,
                "-Kernel", $kernelPath,
                "-Initrd", $initrdPath,
                "-Rootfs", $rootfsPath,
                "-FixtureRoot", $fixturePath,
                "-ChildName", $name,
                "-GateDirectory", $gate
            ) `
            -RedirectStandardOutput (Join-Path $gate "$name.stdout.log") `
            -RedirectStandardError (Join-Path $gate "$name.stderr.log") `
            -WindowStyle Hidden `
            -PassThru
    }
    $gateDeadline = [DateTime]::UtcNow.AddSeconds(30)
    while (-not ((Test-Path -LiteralPath (Join-Path $gate "first-ready")) -and
            (Test-Path -LiteralPath (Join-Path $gate "second-ready")))) {
        if ($children.Where({ $_.HasExited }).Count -ne 0) {
            throw "a concurrent child exited before reaching the synchronization gate"
        }
        if ([DateTime]::UtcNow -ge $gateDeadline) {
            throw "timed out waiting for concurrent children"
        }
        Start-Sleep -Milliseconds 10
    }
    [System.IO.File]::WriteAllText((Join-Path $gate "go"), "go")
    foreach ($child in $children) {
        if (-not $child.WaitForExit(120000)) {
            $child.Kill($true)
            throw "a concurrent cache child timed out"
        }
        if ($child.ExitCode -ne 0) {
            throw "concurrent cache child $($child.Id) failed with exit code $($child.ExitCode)"
        }
    }

    $metrics = @(
        Get-Content -LiteralPath (Join-Path $gate "first-metrics.json") -Raw | ConvertFrom-Json
        Get-Content -LiteralPath (Join-Path $gate "second-metrics.json") -Raw | ConvertFrom-Json
    )
    $decisions = @($metrics | ForEach-Object { $_.mounts[0].cache_decision })
    if (@($decisions | Where-Object { $_ -eq "build_selected" }).Count -ne 1 -or
        @($decisions | Where-Object { $_ -eq "busy_bypass" }).Count -ne 1) {
        throw "expected one builder and one busy bypass, found: $($decisions -join ', ')"
    }
    $readyManifests = @(Get-ChildItem -LiteralPath $cacheRoot -Filter manifest.json -File -Recurse)
    if ($readyManifests.Count -ne 1) {
        throw "concurrent run published $($readyManifests.Count) ready objects instead of one"
    }

    Remove-Item -LiteralPath $cacheRoot -Recurse -Force
    [System.IO.Directory]::CreateDirectory($cacheRoot) | Out-Null
    $env:LSB_WINDOWS_MOUNT_METRICS_PATH = Join-Path $interruptedLogs "killed-metrics.json"
    $interrupted = Start-Process -FilePath $binaryPath `
        -ArgumentList (Get-RunArguments) `
        -RedirectStandardOutput (Join-Path $interruptedLogs "killed.stdout.log") `
        -RedirectStandardError (Join-Path $interruptedLogs "killed.stderr.log") `
        -WindowStyle Hidden `
        -PassThru
    $stagingRoot = Join-Path $cacheRoot "mount-cache\v1\staging"
    $stagingDeadline = [DateTime]::UtcNow.AddSeconds(30)
    while (-not (Test-Path -LiteralPath $stagingRoot) -or
        @(Get-ChildItem -LiteralPath $stagingRoot -Directory -ErrorAction SilentlyContinue).Count -eq 0) {
        if ($interrupted.HasExited) {
            throw "builder exited before staging became observable"
        }
        if ([DateTime]::UtcNow -ge $stagingDeadline) {
            $interrupted.Kill($true)
            throw "timed out waiting for an interruptible staging directory"
        }
        Start-Sleep -Milliseconds 10
    }
    $interrupted.Kill($true)
    $interrupted.WaitForExit()
    if (@(Get-ChildItem -LiteralPath $cacheRoot -Filter manifest.json -File -Recurse).Count -ne 0) {
        throw "interrupted builder left a ready manifest"
    }

    $env:LSB_WINDOWS_MOUNT_METRICS_PATH = Join-Path $interruptedLogs "retry-metrics.json"
    & $binaryPath @(Get-RunArguments)
    if ($LASTEXITCODE -ne 0) {
        throw "retry after interruption failed with exit code $LASTEXITCODE"
    }
    $readyAfterRetry = @(Get-ChildItem -LiteralPath $cacheRoot -Filter manifest.json -File -Recurse)
    if ($readyAfterRetry.Count -ne 1) {
        throw "retry after interruption published $($readyAfterRetry.Count) ready objects instead of one"
    }

    [ordered]@{
        concurrent_decisions = $decisions
        concurrent_objects   = $readyManifests.Count
        interrupted_ready    = 0
        retry_objects        = $readyAfterRetry.Count
    } | ConvertTo-Json
}
finally {
    foreach ($entry in $savedEnvironment.GetEnumerator()) {
        Restore-EnvironmentVariable -Name $entry.Key -Value $entry.Value
    }
}
