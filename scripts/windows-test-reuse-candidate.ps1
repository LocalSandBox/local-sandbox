[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $RunRoot,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string] $SnapshotSha,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-z0-9][a-z0-9._-]{0,95}$')]
    [string] $SourceRunId,

    [string] $StateRoot = (Join-Path $env:ProgramData 'LocalSandbox\DevTest')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Resolve-RegularFile {
    param([string] $Path, [string] $Label, [long] $MaximumSize = 8GB)

    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $item.Length -le 0 -or $item.Length -gt $MaximumSize) {
        throw "$Label must be a bounded regular non-reparse file"
    }
    return $item
}

function Resolve-RegularDirectory {
    param([string] $Path, [string] $Label)

    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "$Label must be a regular non-reparse directory"
    }
    return $item
}

function Read-JsonFile {
    param([string] $Path, [string] $Label, [long] $MaximumSize = 4MB)

    $item = Resolve-RegularFile $Path $Label $MaximumSize
    return Get-Content -LiteralPath $item.FullName -Raw | ConvertFrom-Json
}

function Get-GitObject {
    param([string] $Specification, [string] $Label)

    $value = (& git rev-parse $Specification).Trim().ToLowerInvariant()
    if ($LASTEXITCODE -ne 0 -or $value -notmatch '^[0-9a-f]{40}$') {
        throw "Could not resolve $Label."
    }
    return $value
}

function Get-FileRecord {
    param([string] $Path, [string] $Label)

    $item = Resolve-RegularFile $Path $Label
    return [pscustomobject]@{
        file = $item.Name
        sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        size = $item.Length
    }
}

function Assert-Record {
    param([object] $Expected, [string] $Path, [string] $Label)

    $observed = Get-FileRecord $Path $Label
    if ([string]$Expected.sha256 -cne $observed.sha256 -or
        [long]$Expected.size -ne $observed.size) {
        throw "$Label does not match its recorded hash and size."
    }
    return $observed
}

function Assert-SafeTree {
    param([string] $Path, [string] $Label)

    $root = Resolve-RegularDirectory $Path $Label
    foreach ($item in Get-ChildItem -LiteralPath $root.FullName -Recurse -Force) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "$Label contains a reparse point: $($item.FullName)"
        }
    }
    return $root
}

function Assert-FetchManifest {
    param([string] $Root, [string] $ExpectedRunId, [string[]] $RequiredNames)

    $fetch = Read-JsonFile (Join-Path $Root 'fetch-manifest.json') `
        'source fetch manifest' 256KB
    if ($fetch.schema_version -ne 1 -or $fetch.run_id -cne $ExpectedRunId) {
        throw 'Source fetch manifest identity is invalid.'
    }
    $entries = @($fetch.artifacts)
    if ($entries.Count -eq 0 -or $entries.Count -gt 32) {
        throw 'Source fetch manifest artifact count is outside the supported bound.'
    }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $entries) {
        $name = [string]$entry.name
        if ($name -notmatch '^[A-Za-z0-9][A-Za-z0-9._+-]{0,159}$' -or
            -not $seen.Add($name)) {
            throw 'Source fetch manifest contains an unsafe or duplicate name.'
        }
        Assert-Record $entry (Join-Path $Root $name) "source fetch artifact $name" | Out-Null
    }
    foreach ($name in $RequiredNames) {
        if (-not $seen.Contains($name)) {
            throw "Source fetch manifest omits required candidate artifact $name."
        }
    }
    return $fetch
}

function Get-CandidateConstructionProof {
    param([string] $Root, [string] $ExpectedSnapshot)

    $results = @('result-normal.json', 'result-beforereboot.json')
    $runtimeFailureResult = $null
    foreach ($name in $results) {
        $path = Join-Path $Root $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
        $result = Read-JsonFile $path "source $name" 1MB
        if ($result.snapshot_sha -ceq $ExpectedSnapshot -and
            [string]$result.suite -in @(
                'release-candidate', 'installed-service-smoke', 'service-reboot'
            )) {
            if ($result.status -eq 'passed' -and $result.exit_code -eq 0) {
                return $name
            }
            $runtimeFailureResult = $name
        }
    }
    if ($null -ne $runtimeFailureResult) {
        # The caller independently validates the passed release evidence, every
        # artifact hash, and both signature/bundle verification paths. A later
        # runtime failure does not invalidate completed candidate construction.
        return "$runtimeFailureResult+passed-release-evidence"
    }
    throw 'Source run has no result tied to its passed release-candidate evidence.'
}

function Assert-Sha256Sums {
    param([string] $Root, [object] $ReleaseEvidence)

    $records = @{}
    foreach ($line in Get-Content -LiteralPath (Join-Path $Root 'SHA256SUMS')) {
        if ($line -notmatch '^([0-9a-f]{64})\s+\*?([^\\/]+)$') {
            throw 'SHA256SUMS contains an invalid record.'
        }
        $records[$Matches[2]] = $Matches[1]
    }
    foreach ($artifact in @($ReleaseEvidence.payload, $ReleaseEvidence.symbols)) {
        $name = [string]$artifact.name
        if (-not $records.ContainsKey($name) -or
            $records[$name] -cne [string]$artifact.sha256) {
            throw "SHA256SUMS does not bind $name to its release evidence hash."
        }
    }
}

function Assert-Bundle {
    param(
        [string] $Root,
        [object] $ReleaseEvidence,
        [object] $ReleaseManifest,
        [object] $NodeEvidence,
        [string] $SigningScript
    )

    $version = [string]$ReleaseEvidence.version
    $bundle = Join-Path $Root `
        "release-work\out\lsb-seawork-service-v$version-windows-x86_64-stage\LocalSandbox"
    Assert-SafeTree $bundle 'candidate bundle' | Out-Null
    $hashes = $ReleaseManifest.artifact_hashes
    Assert-Record $hashes.service_zip `
        (Join-Path $Root ([string]$ReleaseEvidence.payload.name)) 'service archive' | Out-Null
    Assert-Record $hashes.symbols_zip `
        (Join-Path $Root ([string]$ReleaseEvidence.symbols.name)) 'symbols archive' | Out-Null
    Assert-Record $hashes.sha256sums (Join-Path $Root 'SHA256SUMS') 'SHA256SUMS' | Out-Null
    Assert-Record $hashes.bundle_manifest `
        (Join-Path $bundle 'manifests\bundle.json') 'bundle manifest' | Out-Null
    Assert-Record $hashes.service_contract `
        (Join-Path $bundle 'manifests\service-contract.json') 'service contract' | Out-Null
    Assert-Record $hashes.runtime_dependencies `
        (Join-Path $bundle 'manifests\runtime-dependencies.json') 'runtime dependencies' | Out-Null
    Assert-Record $hashes.sbom `
        (Join-Path $bundle 'manifests\sbom.spdx.json') 'SBOM' | Out-Null
    Assert-Record $hashes.licenses_notice `
        (Join-Path $bundle 'licenses\THIRD-PARTY-NOTICES.json') 'license notice' | Out-Null

    foreach ($package in @($NodeEvidence.packages)) {
        $record = @($hashes.node_packages | Where-Object file -CEQ ([string]$package.file))
        if ($record.Count -ne 1) {
            throw "Release manifest does not identify Node package $($package.file)."
        }
        Assert-Record $record[0] (Join-Path $Root ([string]$package.file)) `
            "Node package $($package.file)" | Out-Null
    }
    Assert-Sha256Sums $Root $ReleaseEvidence

    & $SigningScript `
        -Mode Verify `
        -BundleRoot $bundle `
        -ExpectedPublisherSubject ([string]$ReleaseEvidence.publisher_subject) `
        -ExpectedPublisherSha256 ([string]$ReleaseEvidence.publisher_sha256)
    & (Join-Path $bundle 'bin\localsandbox-seawork-service.exe') --verify-bundle --json
    if ($LASTEXITCODE -ne 0) {
        throw 'Installed-layout bundle verification failed.'
    }
    return $bundle
}

function Write-FetchManifest {
    param([string] $Root, [string[]] $Names)

    $artifacts = foreach ($name in $Names) {
        $record = Get-FileRecord (Join-Path $Root $name) "fetch artifact $name"
        [ordered]@{ name = $name; sha256 = $record.sha256; size = $record.size }
    }
    [ordered]@{
        schema_version = 1
        run_id = Split-Path -Leaf $Root
        artifacts = @($artifacts)
    } | ConvertTo-Json -Depth 8 | Set-Content `
        -LiteralPath (Join-Path $Root 'fetch-manifest.json') -Encoding utf8NoBOM
}

$state = [IO.Path]::GetFullPath($StateRoot).TrimEnd('\')
$runsRoot = Join-Path $state 'runs'
$destination = [IO.Path]::GetFullPath($RunRoot).TrimEnd('\')
$source = [IO.Path]::GetFullPath((Join-Path $runsRoot $SourceRunId)).TrimEnd('\')
$resolvedRuns = [IO.Path]::GetFullPath($runsRoot).TrimEnd('\')
if ((Split-Path -Parent $destination) -cne $resolvedRuns -or
    (Split-Path -Parent $source) -cne $resolvedRuns -or $source -ceq $destination) {
    throw 'Candidate reuse is restricted to two distinct direct children of the owned runs root.'
}
$stateMarker = Resolve-RegularFile `
    (Join-Path $state '.local-sandbox-agent-test-root.json') 'test-state owner marker' 1MB
$sourceItem = Resolve-RegularDirectory $source 'source run root'
$destinationItem = Resolve-RegularDirectory $destination 'destination run root'
$sourceOwner = (Get-Acl -LiteralPath $sourceItem.FullName).Owner
$destinationOwner = (Get-Acl -LiteralPath $destinationItem.FullName).Owner
if ([string]::IsNullOrWhiteSpace($sourceOwner) -or $sourceOwner -cne $destinationOwner) {
    throw 'Source and destination run ownership does not match.'
}
if (Test-Path -LiteralPath (Join-Path $destination 'release-work')) {
    throw 'Destination run already contains release work.'
}

$sourceEvidencePath = Join-Path $source 'evidence-release-candidate.json'
$sourceEvidenceItem = Resolve-RegularFile $sourceEvidencePath 'source release evidence' 4MB
$releaseEvidence = Get-Content -LiteralPath $sourceEvidenceItem.FullName -Raw | ConvertFrom-Json
$nodeEvidence = Read-JsonFile (Join-Path $source 'evidence-node-packages.json') `
    'source Node package evidence'
$releaseManifest = Read-JsonFile (Join-Path $source 'seawork-test-release-manifest.json') `
    'source test-release manifest'
if ($releaseEvidence.schema_version -ne 1 -or $releaseEvidence.status -ne 'passed' -or
    $releaseEvidence.service_profile -ne 'production' -or
    $releaseEvidence.snapshot_sha -notmatch '^[0-9a-f]{40}$' -or
    $releaseManifest.local_sandbox_commit -notmatch '^[0-9a-f]{40}$' -or
    $releaseManifest.synthetic_snapshot_sha -cne [string]$releaseEvidence.snapshot_sha -or
    $releaseManifest.candidate_version -cne [string]$releaseEvidence.version -or
    $nodeEvidence.status -ne 'passed' -or
    $nodeEvidence.version -cne [string]$releaseEvidence.version -or
    $nodeEvidence.publisher_sha256 -cne [string]$releaseEvidence.publisher_sha256) {
    throw 'Source evidence does not identify one production candidate.'
}

$currentTree = Get-GitObject "${SnapshotSha}^{tree}" 'current snapshot tree'
$currentBase = Get-GitObject "${SnapshotSha}^" 'current base commit'
$sourceTree = if ($null -ne $releaseEvidence.PSObject.Properties['snapshot_tree_sha']) {
    [string]$releaseEvidence.snapshot_tree_sha
}
else {
    Get-GitObject "$($releaseEvidence.snapshot_sha)^{tree}" 'source snapshot tree'
}
$sourceBase = if ($null -ne $releaseEvidence.PSObject.Properties['base_commit']) {
    [string]$releaseEvidence.base_commit
}
else {
    [string]$releaseManifest.local_sandbox_commit
}
$stateText = Get-Content -LiteralPath 'state.md' -Raw
$versionMatch = [regex]::Match($stateText, '(?m)^- Candidate version: `([^`]+)`$')
if (-not $versionMatch.Success -or $sourceTree -cne $currentTree -or
    $sourceBase -cne $currentBase -or
    $releaseManifest.local_sandbox_commit -cne $currentBase -or
    [string]$releaseEvidence.version -cne $versionMatch.Groups[1].Value) {
    throw 'Source candidate tree, base commit, or version does not exactly match this run.'
}

$signingVerifier = Join-Path $PSScriptRoot 'windows-test-signing-assets.ps1'
$signingScript = Join-Path $PSScriptRoot 'sign-seawork-service.ps1'
$certificateInfo = (& $signingVerifier -Mode Verify | Out-String | ConvertFrom-Json)
if ($certificateInfo.status -ne 'ready' -or
    [string]$certificateInfo.subject -cne [string]$releaseEvidence.publisher_subject -or
    [string]$certificateInfo.sha256_thumbprint -cne [string]$releaseEvidence.publisher_sha256 -or
    [string]$releaseManifest.publisher_subject -cne [string]$releaseEvidence.publisher_subject -or
    [string]$releaseManifest.publisher_sha256 -cne [string]$releaseEvidence.publisher_sha256) {
    throw 'Source candidate publisher does not match the protected production signing identity.'
}

$payloadName = [string]$releaseEvidence.payload.name
$symbolsName = [string]$releaseEvidence.symbols.name
$nodeNames = @($nodeEvidence.packages | ForEach-Object { [string]$_.file })
$sourceRequired = @(
    $payloadName, $symbolsName, 'SHA256SUMS', 'seawork-test-release-manifest.json',
    'evidence-release-candidate.json', 'evidence-node-packages.json',
    'evidence-event-messages.json'
) + $nodeNames
Assert-FetchManifest $source $SourceRunId $sourceRequired | Out-Null
$sourceResult = Get-CandidateConstructionProof $source ([string]$releaseEvidence.snapshot_sha)
Assert-SafeTree (Join-Path $source 'release-work') 'source release work' | Out-Null
Assert-Bundle $source $releaseEvidence $releaseManifest $nodeEvidence $signingScript | Out-Null

Copy-Item -LiteralPath (Join-Path $source 'release-work') `
    -Destination (Join-Path $destination 'release-work') -Recurse
$copiedNames = @(
    $payloadName, $symbolsName, 'SHA256SUMS', 'evidence-node-packages.json',
    'evidence-event-messages.json'
) + $nodeNames
foreach ($name in $copiedNames) {
    Copy-Item -LiteralPath (Join-Path $source $name) -Destination (Join-Path $destination $name)
    $sourceRecord = Get-FileRecord (Join-Path $source $name) "source $name"
    Assert-Record $sourceRecord (Join-Path $destination $name) "copied $name" | Out-Null
}
Assert-SafeTree (Join-Path $destination 'release-work') 'copied release work' | Out-Null
Assert-Bundle $destination $releaseEvidence $releaseManifest $nodeEvidence $signingScript | Out-Null

$sourceEvidenceHash = (Get-FileHash -LiteralPath $sourceEvidenceItem.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
$reuseEvidence = [ordered]@{
    schema_version = 1
    status = 'passed'
    source_run_id = $SourceRunId
    source_result = $sourceResult
    source_snapshot_sha = [string]$releaseEvidence.snapshot_sha
    source_snapshot_tree_sha = $sourceTree
    source_base_commit = $sourceBase
    source_release_evidence_sha256 = $sourceEvidenceHash
    destination_snapshot_sha = $SnapshotSha
    destination_snapshot_tree_sha = $currentTree
    destination_base_commit = $currentBase
    version = [string]$releaseEvidence.version
    publisher_subject = [string]$releaseEvidence.publisher_subject
    publisher_sha256 = [string]$releaseEvidence.publisher_sha256
    source_owner = $sourceOwner
    destination_owner = $destinationOwner
    checks = @(
        'exact-tree', 'exact-base-commit', 'exact-version', 'protected-publisher',
        'source-owner', 'no-reparse-points', 'source-fetch-hashes',
        'source-manifest-hashes', 'source-signature-and-catalog',
        'source-installed-layout', 'destination-copy-hashes',
        'destination-signature-and-catalog', 'destination-installed-layout'
    )
}
$reuseEvidence | ConvertTo-Json -Depth 8 | Set-Content `
    -LiteralPath (Join-Path $destination 'evidence-artifact-reuse.json') -Encoding utf8NoBOM

$releaseEvidence.snapshot_sha = $SnapshotSha
$releaseEvidence | Add-Member -NotePropertyName snapshot_tree_sha -NotePropertyValue $currentTree -Force
$releaseEvidence | Add-Member -NotePropertyName base_commit -NotePropertyValue $currentBase -Force
$releaseEvidence | Add-Member -NotePropertyName artifact_reuse -NotePropertyValue ([ordered]@{
    source_run_id = $SourceRunId
    source_snapshot_sha = [string]$reuseEvidence.source_snapshot_sha
    source_snapshot_tree_sha = $sourceTree
    source_release_evidence_sha256 = $sourceEvidenceHash
}) -Force
$releaseEvidence | ConvertTo-Json -Depth 10 | Set-Content `
    -LiteralPath (Join-Path $destination 'evidence-release-candidate.json') -Encoding utf8NoBOM

& (Join-Path $PSScriptRoot 'write-seawork-test-release-manifest.ps1') `
    -RunRoot $destination -SnapshotSha $SnapshotSha | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw 'Reused candidate manifest generation failed.'
}
$fetchNames = @(
    $payloadName, $symbolsName, 'SHA256SUMS', 'seawork-test-release-manifest.json',
    'evidence-event-messages.json', 'evidence-node-packages.json',
    'evidence-release-candidate.json', 'evidence-artifact-reuse.json'
) + $nodeNames
Write-FetchManifest $destination $fetchNames
Assert-FetchManifest $destination (Split-Path -Leaf $destination) $fetchNames | Out-Null

[ordered]@{
    status = 'reused'
    source_run_id = $SourceRunId
    snapshot_sha = $SnapshotSha
    snapshot_tree_sha = $currentTree
    version = [string]$releaseEvidence.version
} | ConvertTo-Json -Compress | Write-Output
