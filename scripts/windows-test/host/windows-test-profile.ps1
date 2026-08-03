[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet('runtime', 'diagnostics', 'service', 'release')]
    [string] $Profile,
    [Parameter(Mandatory = $true)][ValidatePattern('^[a-z0-9][a-z0-9._-]{0,95}$')]
    [string] $RunId,
    [string] $StateRoot = 'C:\dev\local-sandbox-agent-state',
    [string] $CatalogPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'catalog.json'),
    [switch] $IncludeOptional
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'lib\common.ps1')
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'lib\evidence.ps1')

$state = Resolve-WindowsTestOwnedRoot -Path $StateRoot -ExpectedLeaf 'local-sandbox-agent-state'
$runsRoot = Assert-WindowsTestDescendant -Path (Join-Path $state 'runs') -Root $state
$runRoot = Assert-WindowsTestDescendant -Path (Join-Path $runsRoot $RunId) -Root $runsRoot
$runItem = Get-Item -LiteralPath $runRoot -Force -ErrorAction Stop
if (-not $runItem.PSIsContainer -or ($runItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'Profile run root is not a plain directory.'
}
$lock = [IO.File]::Open(
    (Join-Path $state 'locks\runner.lock'), [IO.FileMode]::OpenOrCreate,
    [IO.FileAccess]::ReadWrite, [IO.FileShare]::None
)
try {
    $catalog = Get-WindowsTestCatalog -Path $CatalogPath
    $profileEntry = $catalog.profiles.PSObject.Properties[$Profile].Value
    $profileNames = [Collections.Generic.List[string]]::new()
    if ($null -ne $profileEntry.PSObject.Properties['includes']) {
        foreach ($included in @($profileEntry.includes)) { $profileNames.Add([string]$included) }
    }
    $profileNames.Add($Profile)
    $suiteRefs = [Collections.Generic.List[object]]::new()
    foreach ($profileName in $profileNames) {
        foreach ($suiteRef in @($catalog.profiles.PSObject.Properties[$profileName].Value.suites)) {
            if ($suiteRef.required -or $IncludeOptional) { $suiteRefs.Add($suiteRef) }
        }
    }

    $metadata = Read-WindowsTestJson -Path (Join-Path $runRoot 'run-metadata.json') `
        -MaximumBytes 256KB
    $resultRecords = [Collections.Generic.List[object]]::new()
    $observedChecks = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $artifactDigests = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $runtimeDigests = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $profilePassed = $true
    foreach ($suiteRef in $suiteRefs) {
        $suiteName = [string]$suiteRef.name
        $suite = $catalog.suites.PSObject.Properties[$suiteName].Value
        $phases = if ($suite.reboot_mode -eq 'required') {
            @('beforereboot', 'afterreboot')
        } else { @('normal') }
        foreach ($phase in $phases) {
            $name = "result-$suiteName-$phase.json"
            $path = Join-Path $runRoot $name
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
                $profilePassed = $false
                $resultRecords.Add([ordered]@{
                    suite = $suiteName; phase = $phase; status = 'not_run'
                    failure_code = 'RESULT_MISSING'; result_file = $name
                })
                continue
            }
            if (-not (Test-Json -LiteralPath $path -SchemaFile `
                (Join-Path (Split-Path -Parent $PSScriptRoot) 'schemas\result.schema.json'))) {
                throw "Suite result does not satisfy result.schema.json: $name"
            }
            $result = Read-WindowsTestJson -Path $path -MaximumBytes 256KB
            if ($result.run_id -cne $RunId -or $result.snapshot_sha -cne $metadata.snapshot_sha -or
                $result.suite -cne $suiteName) { throw "Suite result identity mismatch: $name" }
            if ($result.status -ne 'passed' -or $result.exit_code -ne 0) { $profilePassed = $false }
            foreach ($check in @($result.acceptance_checks)) { $observedChecks.Add([string]$check) | Out-Null }
            if ([string]$result.bindings.release_artifact_sha256 -match '^[0-9a-f]{64}$') {
                $artifactDigests.Add([string]$result.bindings.release_artifact_sha256) | Out-Null
            }
            if ([string]$result.bindings.runtime_assets_sha256 -match '^[0-9a-f]{64}$') {
                $runtimeDigests.Add([string]$result.bindings.runtime_assets_sha256) | Out-Null
            }
            $resultRecords.Add([ordered]@{
                suite = $suiteName; phase = $phase; status = [string]$result.status
                failure_code = $result.failure_code; result_file = $name
            })
        }
    }
    $declaredChecks = @($profileEntry.acceptance_checks | Sort-Object -Unique)
    $missingChecks = @($declaredChecks | Where-Object { -not $observedChecks.Contains([string]$_) })
    if ($missingChecks.Count -gt 0) { $profilePassed = $false }
    if ($artifactDigests.Count -gt 1 -or $runtimeDigests.Count -gt 1) {
        throw 'Profile results disagree on runtime or release artifact digest binding.'
    }
    if ($Profile -eq 'release' -and $artifactDigests.Count -ne 1) {
        $profilePassed = $false
        $missingChecks += 'release-artifact-digest'
    }
    $profileResultPath = Join-Path $runRoot 'profile-result.json'
    $profileResult = [ordered]@{
        schema_version = 1
        run_id = $RunId
        snapshot_sha = [string]$metadata.snapshot_sha
        profile = $Profile
        status = if ($profilePassed) { 'passed' } else { 'failed' }
        failure_code = if ($profilePassed) { $null } else { 'PROFILE_INCOMPLETE' }
        generated_utc = [DateTime]::UtcNow.ToString('o')
        candidate_run_id = if ([string]::IsNullOrWhiteSpace([string]$metadata.reuse_run_id)) {
            if ($Profile -in @('service', 'release')) { $RunId } else { $null }
        } else { [string]$metadata.reuse_run_id }
        bindings = [ordered]@{
            runtime_assets_sha256 = if ($runtimeDigests.Count -eq 1) { @($runtimeDigests)[0] } else { $null }
            release_artifact_sha256 = if ($artifactDigests.Count -eq 1) { @($artifactDigests)[0] } else { $null }
        }
        acceptance_checks = $declaredChecks
        missing_acceptance_checks = @($missingChecks | Sort-Object -Unique)
        suites = @($resultRecords)
    }
    Write-WindowsTestJsonAtomic -Path $profileResultPath -Value $profileResult
    Write-WindowsTestFetchManifest -RunRoot $runRoot -RunId $RunId `
        -ResultPath $profileResultPath -ExpectedArtifacts @() | Out-Null
    $profileResult | ConvertTo-Json -Depth 12
    if (-not $profilePassed) { exit 1 }
}
finally { $lock.Dispose() }
