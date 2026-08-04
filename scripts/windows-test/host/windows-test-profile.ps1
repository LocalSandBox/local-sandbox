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
    $resultDocuments = [Collections.Generic.List[object]]::new()
    $observedChecks = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $artifactDigests = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $runtimeDigests = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $sourceTrees = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $baseCommits = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
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
            $resultDocuments.Add([pscustomobject]@{ name = $name; value = $result })
            $sourceTrees.Add([string]$result.source_tree_sha) | Out-Null
            $baseCommits.Add([string]$result.base_commit_sha) | Out-Null
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
    if ($artifactDigests.Count -gt 1 -or $runtimeDigests.Count -gt 1 -or
        $sourceTrees.Count -gt 1 -or $baseCommits.Count -gt 1) {
        throw 'Profile results disagree on source, runtime, or release artifact binding.'
    }
    if ($sourceTrees.Count -ne 1 -or $baseCommits.Count -ne 1) { $profilePassed = $false }
    if ($Profile -eq 'release' -and $artifactDigests.Count -ne 1) {
        $profilePassed = $false
        $missingChecks += 'release-artifact-digest'
    }
    $profileResultPath = Join-Path $runRoot 'profile-result.json'
    $profileResult = [ordered]@{
        schema_version = 1
        run_id = $RunId
        snapshot_sha = [string]$metadata.snapshot_sha
        source_tree_sha = if ($sourceTrees.Count -eq 1) { @($sourceTrees)[0] } else { $null }
        base_commit_sha = if ($baseCommits.Count -eq 1) { @($baseCommits)[0] } else { $null }
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
    $fetch = Read-WindowsTestJson -Path (Join-Path $runRoot 'fetch-manifest.json') `
        -MaximumBytes 256KB
    $evidenceFiles = @($fetch.artifacts | Where-Object {
        $_.redacted -and ($_.name -eq 'profile-result.json' -or $_.name -match '^result-' -or
            $_.name -match '^evidence-.*\.redacted\.json$')
    } | ForEach-Object {
        [ordered]@{
            name = [string]$_.name; sha256 = [string]$_.sha256
            size = [int64]$_.size; redacted = $true
        }
    } | Sort-Object name)
    $checkResults = foreach ($checkId in $declaredChecks) {
        $mapped = @($resultDocuments | Where-Object {
            @($_.value.acceptance_checks) -contains $checkId
        })
        if ($mapped.Count -eq 0) {
            [ordered]@{
                id = $checkId; status = 'not_run'; duration_ms = 0
                stable_code = 'CHECK_MAPPING_MISSING'; evidence = @('profile-result.json')
            }
            continue
        }
        $duration = [int64](($mapped | ForEach-Object { [int64]$_.value.duration_ms } |
            Measure-Object -Sum).Sum)
        $passed = @($mapped | Where-Object { $_.value.status -ne 'passed' }).Count -eq 0
        [ordered]@{
            id = $checkId
            status = if ($passed) { 'passed' } else { 'failed' }
            duration_ms = $duration
            stable_code = if ($passed) { $null } else { 'SUITE_FAILED' }
            evidence = @($mapped | ForEach-Object name | Sort-Object -Unique)
        }
    }
    $expectedArtifactDigest = if ($artifactDigests.Count -eq 1) {
        [string](@($artifactDigests)[0])
    } else { $null }
    $candidate = @(Get-WindowsTestReleaseArtifact -RunRoot $runRoot `
        -ExpectedSha256 $expectedArtifactDigest)
    $releaseArtifact = if ($candidate.Count -eq 1) {
        [ordered]@{
            name = $candidate[0].Name
            sha256 = (Get-FileHash -LiteralPath $candidate[0].FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            size = [int64]$candidate[0].Length
        }
    } else { $null }
    $evidenceManifestPath = Join-Path $runRoot 'acceptance-evidence-manifest.json'
    Write-WindowsTestJsonAtomic -Path $evidenceManifestPath -Value ([ordered]@{
        schema_version = 1
        run_id = $RunId
        snapshot_sha = [string]$metadata.snapshot_sha
        source_tree_sha = $profileResult.source_tree_sha
        base_commit_sha = $profileResult.base_commit_sha
        profile = $Profile
        status = if ($profilePassed) { 'passed' } else { 'failed' }
        generated_utc = [DateTime]::UtcNow.ToString('o')
        bindings = $profileResult.bindings
        release_artifact = $releaseArtifact
        checks = @($checkResults)
        files = $evidenceFiles
    })
    Assert-WindowsTestProfileEvidenceManifest -RunRoot $runRoot `
        -ManifestPath $evidenceManifestPath `
        -SchemaPath (Join-Path (Split-Path -Parent $PSScriptRoot) `
            'schemas\profile-evidence.schema.json') | Out-Null
    Write-WindowsTestFetchManifest -RunRoot $runRoot -RunId $RunId `
        -ResultPath $profileResultPath `
        -ExpectedArtifacts @('acceptance-evidence-manifest.json') -RequireExpected | Out-Null
    $profileResult | ConvertTo-Json -Depth 12
    if (-not $profilePassed) { exit 1 }
}
finally { $lock.Dispose() }
