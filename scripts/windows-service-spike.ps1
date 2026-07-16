[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $DataDir,
    [string] $OutputDirectory = (Join-Path $env:ProgramData 'LocalSandbox\SeaWorkSpike'),
    [switch] $TestMounts,
    [switch] $TestWatches,
    [switch] $TestNetwork,
    [switch] $KeepService
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$serviceName = 'LocalSandboxSeaWorkSpike'
$repoRoot = Split-Path -Parent $PSScriptRoot
$dataDirPath = [System.IO.Path]::GetFullPath($DataDir)
$outputPath = [System.IO.Path]::GetFullPath($OutputDirectory)
$runId = '{0}-{1}' -f (Get-Date -Format 'yyyyMMddHHmmss'), $PID
$configPath = Join-Path $outputPath ("config-$runId.json")
$resultPath = Join-Path $outputPath ("result-$runId.json")
$workingRoot = Join-Path $outputPath ("work-$runId")
$binaryPath = Join-Path $repoRoot 'target\release\lsb-service-spike.exe'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script from an elevated PowerShell on a disposable Windows 11 x64 machine.'
    }
}

function Remove-SpikeService {
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($null -ne $service) {
        if ($service.Status -ne 'Stopped') {
            Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
            $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
        }
        & sc.exe delete $serviceName | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "sc.exe delete failed with exit code $LASTEXITCODE"
        }
    }
}

Assert-Administrator
if (-not [Environment]::Is64BitOperatingSystem) {
    throw 'The Phase 0 spike requires x86-64 Windows.'
}
if (-not (Test-Path -LiteralPath $dataDirPath -PathType Container)) {
    throw "Runtime data directory does not exist: $dataDirPath"
}

New-Item -ItemType Directory -Force -Path $outputPath, $workingRoot | Out-Null
Push-Location $repoRoot
try {
    cargo build --release -p lsb-service-spike --features windows-session0-spike
    if ($LASTEXITCODE -ne 0) {
        throw "cargo build failed with exit code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}

$config = [ordered]@{
    schema_version = 1
    run_id = $runId
    data_dir = $dataDirPath
    working_root = $workingRoot
    result_path = $resultPath
    test_mounts = [bool]$TestMounts
    test_watches = [bool]$TestWatches
    test_network = [bool]$TestNetwork
}
$config | ConvertTo-Json | Set-Content -LiteralPath $configPath -Encoding utf8NoBOM

Remove-SpikeService
$quotedBinary = '"{0}" --service "{1}"' -f $binaryPath, $configPath
$createArgs = @(
    'create', $serviceName,
    'binPath=', $quotedBinary,
    'start=', 'demand',
    'obj=', 'LocalSystem'
)
& sc.exe @createArgs | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "sc.exe create failed with exit code $LASTEXITCODE"
}

try {
    & sc.exe start $serviceName | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe start failed with exit code $LASTEXITCODE"
    }
    $deadline = [DateTime]::UtcNow.AddMinutes(8)
    do {
        Start-Sleep -Seconds 2
        $service = Get-Service -Name $serviceName
        if ((Test-Path -LiteralPath $resultPath -PathType Leaf) -or $service.Status -eq 'Stopped') {
            break
        }
    } while ([DateTime]::UtcNow -lt $deadline)

    if (-not (Test-Path -LiteralPath $resultPath -PathType Leaf)) {
        $query = (& sc.exe queryex $serviceName | Out-String).Trim()
        throw "Spike did not produce a result within the deadline.`n$query"
    }
    $result = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
    if (-not $result.complete) {
        throw "Spike result is incomplete: $resultPath"
    }
    Write-Output "Phase 0 result: $resultPath"
    $result.checks | Format-Table name, status, duration_ms, detail -AutoSize
}
finally {
    if (-not $KeepService) {
        Remove-SpikeService
    }
}
