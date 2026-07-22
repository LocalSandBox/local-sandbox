[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $ServiceArchivePath,
    [Parameter(Mandatory = $true)][string] $HelperBinaryPath,
    [Parameter(Mandatory = $true)][string] $ResultsPath,
    [Parameter(Mandatory = $true)][string] $PreviousBundleIdentityPath,
    [Parameter(Mandatory = $true)][string] $CandidateBundleIdentityPath,
    [Parameter(Mandatory = $true)][uint64] $ReleaseId,
    [Parameter(Mandatory = $true)][ValidatePattern('^v[0-9A-Za-z.+-]{1,127}$')]
    [string] $ReleaseTag,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{64}$')]
    [string] $PublisherSha256,
    [Parameter(Mandatory = $true)][string] $RunnerIdentity,
    [Parameter(Mandatory = $true)][string] $PolicyFingerprint,
    [string[]] $EvidenceFiles = @(),
    [string] $OutputRoot = (Join-Path (Get-Location) 'artifacts\windows-update-evidence'),
    [string] $GitSha,
    [switch] $RequireComplete
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-Sha256Text {
    param([Parameter(Mandatory = $true)][string] $Value)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return [Convert]::ToHexString(
            $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value))
        ).ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Assert-RedactedText {
    param([Parameter(Mandatory = $true)][string] $Path)
    $text = Get-Content -LiteralPath $Path -Raw
    if ($null -eq $text) { $text = '' }
    $forbidden = [ordered]@{
        'domain or local account SID' = '(?i)S-1-5-21-(?:\d+-){2,}\d+'
        'absolute drive path' = '(?i)(?:^|[\s"''])(?:[A-Z]:\\)'
        'UNC path' = '(?:^|[\s"''])\\\\[^\\\s"'']+\\'
        'private key material' = '-----BEGIN [^-]*PRIVATE KEY-----'
        'credential-like JSON field' = '(?i)"(?:password|passwd|token|secret|authorization|cookie|private[_-]?key)"\s*:'
        'raw machine or user field' = '(?i)"(?:machine_name|computer_name|user_name|username|runner_name|user_sid|logon_sid)"\s*:'
    }
    foreach ($entry in $forbidden.GetEnumerator()) {
        if ($text -match $entry.Value) {
            throw "Evidence file is not redacted ($($entry.Key)): $Path"
        }
    }
}

function Read-JsonFile {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $Description
    )
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "$Description is not a file: $resolved"
    }
    return Get-Content -LiteralPath $resolved -Raw | ConvertFrom-Json
}

$serviceArchive = (Resolve-Path -LiteralPath $ServiceArchivePath).Path
$helperBinary = (Resolve-Path -LiteralPath $HelperBinaryPath).Path
$results = (Resolve-Path -LiteralPath $ResultsPath).Path
foreach ($artifact in @($serviceArchive, $helperBinary, $results)) {
    if (-not (Test-Path -LiteralPath $artifact -PathType Leaf)) {
        throw "Required update evidence input is not a file: $artifact"
    }
}
if ((Split-Path -Leaf $helperBinary) -cne 'localsandbox-seawork-updater.exe') {
    throw 'HelperBinaryPath must identify localsandbox-seawork-updater.exe'
}
if ((Split-Path -Leaf $serviceArchive) -cne
    "lsb-seawork-service-$ReleaseTag-windows-x86_64.zip") {
    throw 'ServiceArchivePath does not match the canonical release tag'
}
if ((Split-Path -Leaf $results) -notmatch '\.redacted(?:\.|$)') {
    throw 'ResultsPath must declare redaction with a .redacted filename component'
}
Assert-RedactedText -Path $results
$resultDocument = Read-JsonFile -Path $results -Description 'update result document'
if ($null -eq $resultDocument.cases -or $null -eq $resultDocument.phase_coverage) {
    throw 'ResultsPath must contain cases and phase_coverage arrays'
}
$previousBundle = Read-JsonFile -Path $PreviousBundleIdentityPath `
    -Description 'previous bundle identity'
$candidateBundle = Read-JsonFile -Path $CandidateBundleIdentityPath `
    -Description 'candidate bundle identity'

if ([string]::IsNullOrWhiteSpace($GitSha)) {
    $GitSha = (& git rev-parse HEAD).Trim().ToLowerInvariant()
    if ($LASTEXITCODE -ne 0) { throw 'git rev-parse HEAD failed' }
}
if ($GitSha -notmatch '^[0-9a-f]{40}$') {
    throw 'GitSha must be exactly 40 lowercase hexadecimal characters'
}

$serviceItem = Get-Item -LiteralPath $serviceArchive
$helperItem = Get-Item -LiteralPath $helperBinary
$helperVersion = & $helperBinary --version --json | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or
    $helperVersion.service_name -ne 'LocalSandboxSeaWorkUpdater' -or
    [uint16]$helperVersion.helper_protocol_major -ne 1 -or
    [uint16]$helperVersion.helper_protocol_minor -lt 1) {
    throw 'Installed helper version/protocol query is incompatible'
}
$serviceSha = (Get-FileHash -LiteralPath $serviceArchive -Algorithm SHA256).Hash.ToLowerInvariant()
$helperSha = (Get-FileHash -LiteralPath $helperBinary -Algorithm SHA256).Hash.ToLowerInvariant()
$root = [IO.Path]::GetFullPath($OutputRoot)
$rootVolume = [IO.Path]::GetPathRoot($root)
if ($root.TrimEnd('\', '/') -eq $rootVolume.TrimEnd('\', '/')) {
    throw 'OutputRoot cannot be a filesystem root'
}
$target = Join-Path (Join-Path (Join-Path $root $GitSha) $serviceSha) $helperSha
if (Test-Path -LiteralPath $target) {
    throw "Update evidence directory already exists; refusing to overwrite: $target"
}

$sources = @($results) + @($EvidenceFiles)
$resolvedEvidence = [Collections.Generic.List[IO.FileInfo]]::new()
$seenLeaves = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($source in $sources) {
    $resolved = Get-Item -LiteralPath (Resolve-Path -LiteralPath $source).Path
    if ($resolved.PSIsContainer) { throw "Evidence input is not a file: $source" }
    if ($resolved.Name -notmatch '\.redacted(?:\.|$)') {
        throw "Evidence filename must declare redaction with '.redacted': $($resolved.Name)"
    }
    if (-not $seenLeaves.Add($resolved.Name)) {
        throw "Evidence filenames collide case-insensitively: $($resolved.Name)"
    }
    Assert-RedactedText -Path $resolved.FullName
    $resolvedEvidence.Add($resolved)
}
if ($resolvedEvidence.Count -lt 1 -or $resolvedEvidence.Count -gt 256) {
    throw 'Evidence file count must be between 1 and 256'
}

New-Item -ItemType Directory -Path (Join-Path $target 'evidence') -Force | Out-Null
$fileRecords = [Collections.Generic.List[object]]::new()
foreach ($source in $resolvedEvidence) {
    $relative = "evidence/$($source.Name)"
    $destination = Join-Path $target ($relative.Replace('/', [IO.Path]::DirectorySeparatorChar))
    Copy-Item -LiteralPath $source.FullName -Destination $destination
    $copied = Get-Item -LiteralPath $destination
    $fileRecords.Add([ordered]@{
        relative_path = $relative
        sha256 = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
        size_bytes = [uint64]$copied.Length
        redacted = $true
    })
}

$manifest = [ordered]@{
    schema_version = 1
    source_git_sha = $GitSha
    release_id = $ReleaseId
    release_tag = $ReleaseTag
    generated_utc = [DateTime]::UtcNow.ToString('o')
    service_archive = [ordered]@{
        name = $serviceItem.Name
        sha256 = $serviceSha
        size_bytes = [uint64]$serviceItem.Length
    }
    helper_binary = [ordered]@{
        name = $helperItem.Name
        sha256 = $helperSha
        size_bytes = [uint64]$helperItem.Length
    }
    helper_protocol = [ordered]@{
        major = [uint16]$helperVersion.helper_protocol_major
        minor = [uint16]$helperVersion.helper_protocol_minor
    }
    publisher_sha256 = $PublisherSha256
    previous_bundle = $previousBundle
    candidate_bundle = $candidateBundle
    environment = [ordered]@{
        os_build = [Environment]::OSVersion.Version.ToString()
        architecture = 'x86_64'
        runner_identity_sha256 = Get-Sha256Text -Value $RunnerIdentity
        policy_sha256 = Get-Sha256Text -Value $PolicyFingerprint
    }
    cases = @($resultDocument.cases)
    phase_coverage = @($resultDocument.phase_coverage)
    files = @($fileRecords)
}
$manifestPath = Join-Path $target 'manifest.json'
$manifest | ConvertTo-Json -Depth 16 |
    Set-Content -LiteralPath $manifestPath -Encoding utf8NoBOM

$repoRoot = Split-Path -Parent $PSScriptRoot
$arguments = @(
    'run', '-p', 'xtask', '--locked', '--', 'verify-seawork-update-evidence',
    '--manifest', $manifestPath,
    '--service-archive', $serviceArchive,
    '--helper', $helperBinary
)
if ($RequireComplete) { $arguments += '--require-complete' }
Push-Location $repoRoot
try {
    & cargo @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "SeaWork update evidence validation failed with exit code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}
Write-Output $manifestPath
