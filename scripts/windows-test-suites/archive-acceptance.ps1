[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Normal', 'BeforeReboot', 'AfterReboot')]
    [string] $Phase,
    [Parameter(Mandatory = $true)][string] $RunRoot,
    [Parameter(Mandatory = $true)][string] $SnapshotSha,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-z0-9][a-z0-9._-]{0,95}$')]
    [string] $ReuseRunId
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($Phase -ne 'Normal') { throw 'archive-acceptance does not support reboot phases.' }

function Read-JsonFile {
    param([string] $Path, [string] $Label, [long] $MaximumSize = 4MB)

    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $item.Length -le 0 -or $item.Length -gt $MaximumSize) {
        throw "$Label must be a bounded regular non-reparse file."
    }
    return Get-Content -LiteralPath $item.FullName -Raw | ConvertFrom-Json
}

function Get-FileRecord {
    param([string] $Path, [string] $Label)

    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "$Label must be a regular non-reparse file."
    }
    return [pscustomobject]@{
        name = $item.Name
        sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        size = $item.Length
    }
}

function Assert-Record {
    param([object] $Expected, [string] $Path, [string] $Label)

    $actual = Get-FileRecord $Path $Label
    if ([string]$Expected.sha256 -cne $actual.sha256 -or
        [long]$Expected.size -ne $actual.size) {
        throw "$Label does not match its recorded hash and size."
    }
    return $actual
}

function Assert-SafeZip {
    param([string] $Path)

    $archive = [IO.Compression.ZipFile]::OpenRead($Path)
    try {
        $entries = @($archive.Entries)
        if ($entries.Count -lt 1 -or $entries.Count -gt 5000) {
            throw 'Service archive entry count is outside the supported bound.'
        }
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        [long]$total = 0
        foreach ($entry in $entries) {
            $name = [string]$entry.FullName
            if ($name.Length -gt 512 -or $name.Contains('\') -or
                -not $name.StartsWith('LocalSandbox/', [StringComparison]::Ordinal) -or
                $name.StartsWith('/', [StringComparison]::Ordinal) -or
                $name -match '(^|/)\.\.(/|$)' -or -not $seen.Add($name)) {
                throw "Service archive contains an unsafe or duplicate path: $name"
            }
            if ([long]$entry.Length -gt (4GB - $total)) {
                throw 'Service archive expanded size exceeds the supported bound.'
            }
            $total += [long]$entry.Length
        }
    }
    finally {
        $archive.Dispose()
    }
}

$stateRoot = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'LocalSandbox\DevTest'))
$runsRoot = Join-Path $stateRoot 'runs'
$sourceRoot = [IO.Path]::GetFullPath((Join-Path $runsRoot $ReuseRunId)).TrimEnd('\')
if ((Split-Path -Parent $sourceRoot) -cne [IO.Path]::GetFullPath($runsRoot).TrimEnd('\')) {
    throw 'Source run escaped the owned Windows runs root.'
}
$sourceItem = Get-Item -LiteralPath $sourceRoot -Force
if (-not $sourceItem.PSIsContainer -or
    ($sourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'Source run must be a regular non-reparse directory.'
}
$release = Read-JsonFile (Join-Path $sourceRoot 'evidence-release-candidate.json') `
    'release evidence'
$manifest = Read-JsonFile (Join-Path $sourceRoot 'seawork-test-release-manifest.json') `
    'test-release manifest'
$fetch = Read-JsonFile (Join-Path $sourceRoot 'fetch-manifest.json') 'fetch manifest' 256KB
if ($release.status -ne 'passed' -or $release.service_profile -ne 'production' -or
    $manifest.local_sandbox_commit -notmatch '^[0-9a-f]{40}$' -or
    $manifest.synthetic_snapshot_sha -cne [string]$release.snapshot_sha -or
    $fetch.run_id -cne $ReuseRunId) {
    throw 'Source run does not identify one production release candidate.'
}
$payloadName = [string]$release.payload.name
$payloadRecord = @($fetch.artifacts | Where-Object name -CEQ $payloadName)
if ($payloadRecord.Count -ne 1) {
    throw 'Fetch manifest does not contain exactly one service archive record.'
}
$payload = Join-Path $sourceRoot $payloadName
$archiveRecord = Assert-Record $payloadRecord[0] $payload 'service archive'
if ($archiveRecord.sha256 -cne [string]$release.payload.sha256 -or
    $archiveRecord.sha256 -cne [string]$manifest.artifact_hashes.service_zip.sha256) {
    throw 'Service archive hashes disagree across release evidence and manifests.'
}
Assert-SafeZip $payload

$extractRoot = Join-Path $RunRoot 'archive-acceptance-work'
if (Test-Path -LiteralPath $extractRoot) {
    throw 'Archive acceptance work root already exists.'
}
try {
    Expand-Archive -LiteralPath $payload -DestinationPath $extractRoot
    foreach ($item in Get-ChildItem -LiteralPath $extractRoot -Recurse -Force) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Expanded archive contains a reparse point: $($item.FullName)"
        }
    }
    $bundle = Join-Path $extractRoot 'LocalSandbox'
    $signingScript = Join-Path (Split-Path -Parent $PSScriptRoot) 'sign-seawork-service.ps1'
    & $signingScript `
        -Mode Verify `
        -BundleRoot $bundle `
        -ExpectedPublisherSubject ([string]$release.publisher_subject) `
        -ExpectedPublisherSha256 ([string]$release.publisher_sha256)
    & (Join-Path $bundle 'bin\localsandbox-seawork-service.exe') --verify-bundle --json
    if ($LASTEXITCODE -ne 0) {
        throw 'Exact archive installed-layout verification failed.'
    }
    foreach ($check in @(
        [pscustomobject]@{ record = $manifest.artifact_hashes.bundle_manifest; path = 'manifests\bundle.json'; label = 'bundle manifest' },
        [pscustomobject]@{ record = $manifest.artifact_hashes.service_contract; path = 'manifests\service-contract.json'; label = 'service contract' },
        [pscustomobject]@{ record = $manifest.artifact_hashes.runtime_dependencies; path = 'manifests\runtime-dependencies.json'; label = 'runtime dependencies' },
        [pscustomobject]@{ record = $manifest.artifact_hashes.sbom; path = 'manifests\sbom.spdx.json'; label = 'SBOM' },
        [pscustomobject]@{ record = $manifest.artifact_hashes.licenses_notice; path = 'licenses\THIRD-PARTY-NOTICES.json'; label = 'license notice' }
    )) {
        Assert-Record $check.record (Join-Path $bundle $check.path) $check.label | Out-Null
    }
}
finally {
    Remove-Item -LiteralPath $extractRoot -Recurse -Force -ErrorAction SilentlyContinue
}

$evidenceName = 'evidence-archive-acceptance.json'
$evidencePath = Join-Path $RunRoot $evidenceName
[ordered]@{
    schema_version = 1
    status = 'passed'
    source_run_id = $ReuseRunId
    source_snapshot_sha = [string]$release.snapshot_sha
    source_base_commit = [string]$manifest.local_sandbox_commit
    validation_snapshot_sha = $SnapshotSha
    archive = $archiveRecord
    publisher_subject = [string]$release.publisher_subject
    publisher_sha256 = [string]$release.publisher_sha256
    checks = @(
        'bounded-safe-zip-paths', 'zip-expanded-successfully',
        'trusted-pe-and-catalog-closure', 'installed-layout',
        'embedded-release-manifest-hashes'
    )
} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $evidencePath -Encoding utf8NoBOM
$evidenceRecord = Get-FileRecord $evidencePath 'archive acceptance evidence'
[ordered]@{
    schema_version = 1
    run_id = Split-Path -Leaf ([IO.Path]::GetFullPath($RunRoot).TrimEnd('\'))
    artifacts = @([ordered]@{
        name = $evidenceName
        sha256 = $evidenceRecord.sha256
        size = $evidenceRecord.size
    })
} | ConvertTo-Json -Depth 6 | Set-Content `
    -LiteralPath (Join-Path $RunRoot 'fetch-manifest.json') -Encoding utf8NoBOM
