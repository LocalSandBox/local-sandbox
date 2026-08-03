[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet('Normal', 'BeforeReboot', 'AfterReboot')]
    [string] $Phase,
    [Parameter(Mandatory = $true)][string] $RunRoot,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')]
    [string] $SnapshotSha,
    [ValidatePattern('^$|^[a-z0-9][a-z0-9._-]{0,95}$')]
    [string] $ReuseRunId = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($Phase -ne 'Normal') { throw 'release-artifact-import does not support reboot phases.' }

function Resolve-RegularFile {
    param([string] $Path, [string] $Label, [int64] $MaximumBytes = 8GB)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $item.Length -le 0 -or $item.Length -gt $MaximumBytes) {
        throw "$Label is not a bounded regular file."
    }
    return $item
}

function Get-Record {
    param([string] $Path, [string] $Label)
    $item = Resolve-RegularFile $Path $Label
    return [ordered]@{
        file = $item.Name
        sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        size = [int64]$item.Length
    }
}

function Assert-SafeZip {
    param([string] $Path)
    $zip = [IO.Compression.ZipFile]::OpenRead($Path)
    try {
        $entries = @($zip.Entries)
        if ($entries.Count -lt 1 -or $entries.Count -gt 5000) {
            throw 'Imported service archive entry count is outside bounds.'
        }
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        [int64]$expanded = 0
        foreach ($entry in $entries) {
            $name = [string]$entry.FullName
            if ($name.Length -gt 512 -or $name.Contains('\') -or
                -not $name.StartsWith('LocalSandbox/', [StringComparison]::Ordinal) -or
                $name -match '(^|/)\.\.(/|$)' -or -not $seen.Add($name)) {
                throw "Imported archive contains an unsafe or duplicate path: $name"
            }
            if ([int64]$entry.Length -gt (4GB - $expanded)) {
                throw 'Imported archive expanded size exceeds 4 GiB.'
            }
            $expanded += [int64]$entry.Length
        }
    }
    finally { $zip.Dispose() }
}

$importPath = Join-Path $RunRoot 'imported-release-artifact.json'
$import = Get-Content -LiteralPath (Resolve-RegularFile $importPath 'import record' 64KB).FullName `
    -Raw | ConvertFrom-Json
if ($import.schema_version -ne 1 -or $import.snapshot_sha -cne $SnapshotSha -or
    [string]$import.name -notmatch '^lsb-seawork-service-v([0-9A-Za-z.+-]+)-windows-x86_64\.zip$' -or
    [string]$import.sha256 -notmatch '^[0-9a-f]{64}$') {
    throw 'Imported release artifact record is invalid or belongs to another snapshot.'
}
$version = $Matches[1]
$archivePath = Join-Path $RunRoot ([string]$import.name)
$archive = Get-Record $archivePath 'imported service archive'
if ($archive.sha256 -cne [string]$import.sha256 -or $archive.size -ne [int64]$import.size) {
    throw 'Imported service archive no longer matches its transfer digest.'
}
Assert-SafeZip -Path $archivePath

$metadata = (& cargo metadata --locked --format-version 1 --no-deps | Out-String | ConvertFrom-Json)
if ($LASTEXITCODE -ne 0) { throw 'cargo metadata failed while binding the imported artifact.' }
$package = @($metadata.packages | Where-Object name -CEQ 'lsb-seawork-service')
if ($package.Count -ne 1 -or [string]$package[0].version -cne $version) {
    throw 'Imported service artifact version does not match the snapshot workspace.'
}

$releaseWork = Join-Path $RunRoot 'release-work'
$stageParent = Join-Path $releaseWork "out\lsb-seawork-service-v$version-windows-x86_64-stage"
if (Test-Path -LiteralPath $releaseWork) { throw 'Release work already exists.' }
New-Item -ItemType Directory -Path $stageParent -Force | Out-Null
Expand-Archive -LiteralPath $archivePath -DestinationPath $stageParent
$bundle = Join-Path $stageParent 'LocalSandbox'
foreach ($item in @(Get-ChildItem -LiteralPath $bundle -Recurse -Force)) {
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "Imported archive expanded to a reparse point: $($item.FullName)"
    }
}
$bundleManifestPath = Join-Path $bundle 'manifests\bundle.json'
$serviceContractPath = Join-Path $bundle 'manifests\service-contract.json'
$dependencyPath = Join-Path $bundle 'manifests\runtime-dependencies.json'
$sbomPath = Join-Path $bundle 'manifests\sbom.spdx.json'
$licensesPath = Join-Path $bundle 'licenses\THIRD-PARTY-NOTICES.json'
$bundleManifest = Get-Content -LiteralPath `
    (Resolve-RegularFile $bundleManifestPath 'bundle manifest' 1MB).FullName -Raw | ConvertFrom-Json
if ($bundleManifest.schema_version -ne 1 -or $bundleManifest.local_sandbox_version -cne $version -or
    $bundleManifest.architecture -cne 'x86_64' -or
    $bundleManifest.target -cne 'x86_64-pc-windows-msvc') {
    throw 'Imported bundle manifest identity is invalid.'
}
$certificate = (& scripts\windows-test-signing-assets.ps1 -Mode Verify | Out-String | ConvertFrom-Json)
if ($certificate.status -ne 'ready' -or
    [string]$bundleManifest.publisher.subject -cne [string]$certificate.subject -or
    [string]$bundleManifest.publisher.sha256_thumbprint -cne [string]$certificate.sha256_thumbprint) {
    throw 'Imported artifact publisher does not match the protected acceptance identity.'
}
& scripts\sign-seawork-service.ps1 -Mode Verify -BundleRoot $bundle `
    -ExpectedPublisherSubject ([string]$certificate.subject) `
    -ExpectedPublisherSha256 ([string]$certificate.sha256_thumbprint)
& (Join-Path $bundle 'bin\localsandbox-seawork-service.exe') --verify-bundle --json
if ($LASTEXITCODE -ne 0) { throw 'Imported artifact installed-layout validation failed.' }

$tree = (& git rev-parse "${SnapshotSha}^{tree}").Trim().ToLowerInvariant()
$base = (& git rev-parse "${SnapshotSha}^").Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $tree -notmatch '^[0-9a-f]{40}$' -or $base -notmatch '^[0-9a-f]{40}$') {
    throw 'Could not resolve imported artifact snapshot provenance.'
}
$releaseEvidencePath = Join-Path $RunRoot 'evidence-release-candidate.json'
[ordered]@{
    schema_version = 1; suite = 'release-artifact-import'; status = 'passed'
    snapshot_sha = $SnapshotSha; snapshot_tree_sha = $tree; base_commit = $base
    version = $version; service_profile = 'production'
    publisher_subject = [string]$certificate.subject
    publisher_sha256 = [string]$certificate.sha256_thumbprint
    payload = [ordered]@{ name = $archive.file; sha256 = $archive.sha256; size = $archive.size }
    artifact_import = [ordered]@{ mode = 'exact-ci-artifact'; transferred_sha256 = $archive.sha256 }
    trusted_signature_required = $true; timestamp_required = $true
} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $releaseEvidencePath -Encoding utf8NoBOM

$artifactHashes = [ordered]@{
    service_zip = $archive
    bundle_manifest = Get-Record $bundleManifestPath 'bundle manifest'
    service_contract = Get-Record $serviceContractPath 'service contract'
    runtime_dependencies = Get-Record $dependencyPath 'runtime dependencies'
    sbom = Get-Record $sbomPath 'SBOM'
    licenses_notice = Get-Record $licensesPath 'license notice'
}
[ordered]@{
    schema_version = 1; status = 'imported'; local_sandbox_commit = $base
    candidate_version = $version; synthetic_snapshot_sha = $SnapshotSha
    windows_run_ids = @((Split-Path -Leaf ([IO.Path]::GetFullPath($RunRoot).TrimEnd('\'))))
    artifact_provenance = [ordered]@{ mode = 'exact-ci-artifact'; sha256 = $archive.sha256 }
    artifact_hashes = $artifactHashes
    publisher_subject = [string]$certificate.subject
    publisher_sha256 = [string]$certificate.sha256_thumbprint
} | ConvertTo-Json -Depth 10 | Set-Content `
    -LiteralPath (Join-Path $RunRoot 'seawork-test-release-manifest.json') -Encoding utf8NoBOM

$records = foreach ($name in @(
    $archive.file, 'evidence-release-candidate.json', 'seawork-test-release-manifest.json'
)) {
    $record = Get-Record (Join-Path $RunRoot $name) "import output $name"
    [ordered]@{ name = $name; sha256 = $record.sha256; size = $record.size }
}
[ordered]@{
    schema_version = 1
    run_id = Split-Path -Leaf ([IO.Path]::GetFullPath($RunRoot).TrimEnd('\'))
    artifacts = @($records)
} | ConvertTo-Json -Depth 6 | Set-Content `
    -LiteralPath (Join-Path $RunRoot 'fetch-manifest.json') -Encoding utf8NoBOM
