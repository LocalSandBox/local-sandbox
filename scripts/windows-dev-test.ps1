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

function Resolve-CatalogSuite {
    param([Parameter(Mandatory = $true)][string] $Name)
    $catalogPath = Join-Path $PSScriptRoot 'windows-test\catalog.json'
    $catalog = Get-Content -LiteralPath $catalogPath -Raw | ConvertFrom-Json
    if ($catalog.schema_version -ne 1) { throw 'Unsupported Windows test catalog schema.' }
    $property = $catalog.suites.PSObject.Properties[$Name]
    if ($null -eq $property) { throw "Unknown Windows test suite '$Name'." }
    return $property.Value
}

function Assert-FreeDisk {
    param([Parameter(Mandatory = $true)][int] $MinimumGiB)
    $driveName = [IO.Path]::GetPathRoot([IO.Path]::GetFullPath($RunRoot)).Substring(0, 1)
    $freeBytes = (Get-PSDrive -Name $driveName).Free
    if ($freeBytes -lt ([int64]$MinimumGiB * 1GB)) {
        throw "DISK_PRESSURE: suite requires $MinimumGiB GiB free; observed $([math]::Round($freeBytes / 1GB, 2)) GiB."
    }
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
$repositoryRoot = Split-Path -Parent $PSScriptRoot
New-Item -ItemType Directory -Force -Path $runPath | Out-Null
$phaseToken = $Phase.ToLowerInvariant()
$logPath = Join-Path $runPath "output-$Suite-$phaseToken.log"
$resultPath = Join-Path $runPath "result-$Suite-$phaseToken.json"
$started = [DateTime]::UtcNow
$exitCode = 1
$status = 'failed'
$failureCode = $null
$suiteMetadata = $null
$requiredCapabilities = @()
$mutations = @('arbitrary command selected by the operator')
$expectedArtifacts = @($resultPath | Split-Path -Leaf)
$acceptanceChecks = @()
$category = 'native'

if ($Suite -notin @('preflight', 'command')) {
    $suiteMetadata = Resolve-CatalogSuite -Name $Suite
    $requiredCapabilities = @($suiteMetadata.required_capabilities)
    $mutations = @($suiteMetadata.mutations)
    $expectedArtifacts = @($suiteMetadata.expected_artifacts)
    $acceptanceChecks = @($suiteMetadata.acceptance_checks)
    $category = [string]$suiteMetadata.category
}

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
            Assert-FreeDisk -MinimumGiB ([int]$suiteMetadata.minimum_free_gib)
            if ($suiteMetadata.reboot_mode -eq 'required' -and $Phase -eq 'Normal') {
                throw "Suite '$Suite' requires the reboot runner."
            }
            if ($suiteMetadata.reboot_mode -eq 'none' -and $Phase -ne 'Normal') {
                throw "Suite '$Suite' does not support reboot phases."
            }
            $repoRoot = Split-Path -Parent $PSScriptRoot
            $suitePath = [IO.Path]::GetFullPath((Join-Path $repoRoot ([string]$suiteMetadata.file)))
            if (-not $suitePath.StartsWith(
                ([IO.Path]::GetFullPath($repoRoot).TrimEnd('\') + '\'),
                [StringComparison]::OrdinalIgnoreCase
            ) -or -not (Test-Path -LiteralPath $suitePath -PathType Leaf)) {
                throw "Catalog suite path is missing or unsafe: $($suiteMetadata.file)"
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
        $failureCode = if ($null -ne $failureCode) { $failureCode }
            elseif ($_.Exception.Message -like 'DISK_PRESSURE:*') { 'DISK_PRESSURE' }
            else { 'RUNNER_ERROR' }
        $exitCode = 1
    }
}
finally {
    Pop-Location
    $finished = [DateTime]::UtcNow
    $releaseArtifact = @(
        Get-ChildItem -LiteralPath $runPath -File `
            -Filter 'lsb-seawork-service-v*-windows-x86_64.zip' -ErrorAction SilentlyContinue |
            Where-Object Name -NotMatch '-symbols\.zip$'
    )
    $releaseArtifactSha = if ($releaseArtifact.Count -eq 1) {
        (Get-FileHash -LiteralPath $releaseArtifact[0].FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    } else { $null }
    . (Join-Path $PSScriptRoot 'windows-test\lib\evidence.ps1')
    $sourceTreeSha = (& git -C $repositoryRoot rev-parse "${SnapshotSha}^{tree}").Trim().ToLowerInvariant()
    $baseCommitSha = (& git -C $repositoryRoot rev-parse "${SnapshotSha}^").Trim().ToLowerInvariant()
    if ($LASTEXITCODE -ne 0 -or $sourceTreeSha -notmatch '^[0-9a-f]{40}$' -or
        $baseCommitSha -notmatch '^[0-9a-f]{40}$') {
        throw 'Could not resolve result source-tree provenance.'
    }
    $result = [ordered]@{
        schema_version = 2
        run_id = $RunId
        snapshot_sha = $SnapshotSha
        source_tree_sha = $sourceTreeSha
        base_commit_sha = $baseCommitSha
        suite = $Suite
        category = $category
        phase = $Phase
        status = $status
        exit_code = $exitCode
        failure_code = $failureCode
        started_utc = $started.ToString('o')
        finished_utc = $finished.ToString('o')
        duration_ms = [math]::Round(($finished - $started).TotalMilliseconds)
        boot_id = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().Ticks.ToString()
        output_file = Split-Path -Leaf $logPath
        required_capabilities = $requiredCapabilities
        mutations = $mutations
        expected_artifacts = $expectedArtifacts
        acceptance_checks = $acceptanceChecks
        bindings = [ordered]@{
            runtime_assets_sha256 = Get-WindowsTestRuntimeAssetDigest `
                -AssetsRoot $env:LSB_WINDOWS_TEST_ASSETS_ROOT
            release_artifact_sha256 = $releaseArtifactSha
        }
    }
    Write-JsonAtomic -Path $resultPath -Value $result
    try {
        if (-not (Test-Json -LiteralPath $resultPath -SchemaFile `
            (Join-Path $PSScriptRoot 'windows-test\schemas\result.schema.json'))) {
            throw 'Generated suite result does not satisfy result.schema.json.'
        }
        $requireExpected = $status -eq 'passed' -and $Phase -ne 'BeforeReboot'
        Write-WindowsTestFetchManifest -RunRoot $runPath -RunId $RunId `
            -ResultPath $resultPath -ExpectedArtifacts $expectedArtifacts `
            -RequireExpected:$requireExpected | Out-Null
    }
    catch {
        $status = 'failed'
        $exitCode = 1
        $failureCode = 'EVIDENCE_WRITER_ERROR'
        $result.status = $status
        $result.exit_code = $exitCode
        $result.failure_code = $failureCode
        Write-JsonAtomic -Path $resultPath -Value $result
        Write-Error $_
        Write-WindowsTestFetchManifest -RunRoot $runPath -RunId $RunId `
            -ResultPath $resultPath -ExpectedArtifacts @() | Out-Null
    }
    Write-Output "WINDOWS_TEST_RESULT $resultPath"
}

exit $exitCode
