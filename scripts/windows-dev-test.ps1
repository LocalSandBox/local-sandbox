[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-z0-9][a-z0-9._-]{0,95}$')]
    [string] $RunId,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string] $SnapshotSha,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-z0-9][a-z0-9._-]{0,63}$')]
    [string] $Suite,

    [Parameter(Mandatory = $true)]
    [ValidateSet('Normal', 'BeforeReboot', 'AfterReboot')]
    [string] $Phase,

    [Parameter(Mandatory = $true)]
    [string] $RunRoot,

    [string] $CommandSpecBase64 = '',

    [ValidatePattern('^$|^[a-z0-9][a-z0-9._-]{0,95}$')]
    [string] $ReuseRunId = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-JsonAtomic {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][object] $Value
    )

    $pending = "$Path.pending-$PID"
    $Value | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $pending -Encoding utf8NoBOM
    Move-Item -LiteralPath $pending -Destination $Path -Force
}

function Get-CommandParts {
    param([Parameter(Mandatory = $true)][string] $Encoded)

    if ([string]::IsNullOrWhiteSpace($Encoded)) {
        throw 'The command suite requires an encoded command specification.'
    }
    try {
        $text = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Encoded))
    }
    catch {
        throw 'The command specification is not valid base64-encoded UTF-8.'
    }
    $parts = @($text.Split([char]0))
    if ($parts.Count -lt 2 -or $parts[-1] -ne '') {
        throw 'The command specification must be a trailing-NUL argument vector.'
    }
    $parts = @($parts[0..($parts.Count - 2)])
    if ($parts.Count -eq 0 -or [string]::IsNullOrWhiteSpace($parts[0])) {
        throw 'The command specification has no executable.'
    }
    return $parts
}

function Get-WhpxState {
    $output = @(& dism.exe /English /Online /Get-FeatureInfo /FeatureName:HypervisorPlatform)
    if ($LASTEXITCODE -ne 0) {
        throw "DISM failed to query Windows Hypervisor Platform with exit code $LASTEXITCODE."
    }
    $stateLine = $output | Where-Object { $_ -match '^State\s*:' } | Select-Object -First 1
    if ($null -eq $stateLine) {
        throw 'DISM returned no Windows Hypervisor Platform state.'
    }
    return (($stateLine -split ':', 2)[1]).Trim()
}

function Invoke-Preflight {
    $os = Get-CimInstance Win32_OperatingSystem
    $computer = Get-CimInstance Win32_ComputerSystem
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $whpx = Get-WhpxState
    $sshd = Get-Service -Name sshd
    $head = (& git rev-parse HEAD).Trim().ToLowerInvariant()
    if ($LASTEXITCODE -ne 0 -or $head -ne $SnapshotSha) {
        throw "Preflight checkout mismatch: expected $SnapshotSha, observed $head"
    }
    if ([int]$os.BuildNumber -lt 22000 -or -not [Environment]::Is64BitOperatingSystem) {
        throw "Unsupported Windows host: $($os.Caption) build $($os.BuildNumber) $($os.OSArchitecture)"
    }
    if (-not $computer.HypervisorPresent -or $whpx -ne 'Enabled') {
        throw "Windows virtualization is unavailable: hypervisor=$($computer.HypervisorPresent), WHPX=$whpx"
    }
    if ($sshd.Status.ToString() -ne 'Running' -or
        $sshd.StartType.ToString() -ne 'Automatic') {
        throw "sshd is not reboot-safe: $($sshd.Status)/$($sshd.StartType)"
    }
    foreach ($command in @('git', 'cargo', 'rustc', 'cmake', 'pwsh')) {
        if ($null -eq (Get-Command $command -ErrorAction SilentlyContinue)) {
            throw "Required command is unavailable: $command"
        }
    }

    [ordered]@{
        status = 'ready'
        os = $os.Caption
        build = $os.BuildNumber
        architecture = $os.OSArchitecture
        elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        hypervisor_present = [bool]$computer.HypervisorPresent
        whpx = $whpx
        sshd = $sshd.Status.ToString()
        sshd_start = $sshd.StartType.ToString()
        snapshot_sha = $head
        git = (& git --version).Trim()
        cargo = (& cargo --version).Trim()
        rustc = (& rustc --version).Trim()
    } | ConvertTo-Json -Depth 5
}

$runPath = [IO.Path]::GetFullPath($RunRoot)
New-Item -ItemType Directory -Force -Path $runPath | Out-Null
$phaseToken = $Phase.ToLowerInvariant()
$logPath = Join-Path $runPath "output-$phaseToken.log"
$resultPath = Join-Path $runPath "result-$phaseToken.json"
$started = [DateTime]::UtcNow
$exitCode = 1
$status = 'failed'
$failureCode = $null

Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    try {
        if ($Suite -eq 'preflight') {
            Invoke-Preflight 2>&1 | Tee-Object -FilePath $logPath
            $exitCode = 0
        }
        elseif ($Suite -eq 'command') {
            if ($Phase -ne 'Normal') {
                throw 'The command suite cannot span a reboot; use a repository suite script.'
            }
            $parts = @(Get-CommandParts -Encoded $CommandSpecBase64)
            $executable = $parts[0]
            $arguments = @()
            if ($parts.Count -gt 1) {
                $arguments = @($parts[1..($parts.Count - 1)])
            }
            & $executable @arguments 2>&1 | Tee-Object -FilePath $logPath
            $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { $LASTEXITCODE }
            if ($exitCode -ne 0) {
                $failureCode = 'COMMAND_FAILED'
            }
        }
        else {
            $suitePath = Join-Path $PSScriptRoot "windows-test-suites\$Suite.ps1"
            if (-not (Test-Path -LiteralPath $suitePath -PathType Leaf)) {
                throw "Unknown Windows test suite '$Suite'; expected $suitePath"
            }
            $suiteArguments = @{
                Phase = $Phase
                RunRoot = $runPath
                SnapshotSha = $SnapshotSha
            }
            if (-not [string]::IsNullOrWhiteSpace($ReuseRunId)) {
                $suiteArguments['ReuseRunId'] = $ReuseRunId
            }
            & $suitePath @suiteArguments 2>&1 | Tee-Object -FilePath $logPath
            $exitCode = 0
        }
        if ($exitCode -eq 0) {
            $status = 'passed'
        }
    }
    catch {
        $_ | Out-String | Tee-Object -FilePath $logPath -Append | Write-Error
        $failureCode = if ($null -eq $failureCode) { 'RUNNER_ERROR' } else { $failureCode }
        $exitCode = 1
    }
}
finally {
    Pop-Location
    $finished = [DateTime]::UtcNow
    $result = [ordered]@{
        schema_version = 1
        run_id = $RunId
        snapshot_sha = $SnapshotSha
        suite = $Suite
        phase = $Phase
        status = $status
        exit_code = $exitCode
        failure_code = $failureCode
        started_utc = $started.ToString('o')
        finished_utc = $finished.ToString('o')
        duration_ms = [math]::Round(($finished - $started).TotalMilliseconds)
        boot_id = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().Ticks.ToString()
        output_file = Split-Path -Leaf $logPath
    }
    Write-JsonAtomic -Path $resultPath -Value $result
    Write-Output "WINDOWS_TEST_RESULT $resultPath"
}

exit $exitCode
