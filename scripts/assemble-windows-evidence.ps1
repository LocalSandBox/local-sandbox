[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('win01', 'security', 'full')]
    [string] $Profile,

    [Parameter(Mandatory = $true)]
    [string] $ArtifactPath,

    [Parameter(Mandatory = $true)]
    [string] $CheckResultsPath,

    [Parameter(Mandatory = $true)]
    [string[]] $EvidenceFiles,

    [Parameter(Mandatory = $true)]
    [string] $ServiceVersion,

    [Parameter(Mandatory = $true)]
    [string] $BundleVersion,

    [Parameter(Mandatory = $true)]
    [string] $QemuVersion,

    [Parameter(Mandatory = $true)]
    [string] $RunnerIdentity,

    [Parameter(Mandatory = $true)]
    [string] $PolicyFingerprint,

    [string] $OutputRoot = (Join-Path (Get-Location) 'artifacts\windows-evidence'),

    [string] $GitSha,

    [switch] $RequireComplete
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-Sha256Text {
    param([Parameter(Mandatory = $true)][string] $Value)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
        return [Convert]::ToHexString($sha.ComputeHash($bytes)).ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Assert-SafeToken {
    param(
        [Parameter(Mandatory = $true)][string] $Name,
        [Parameter(Mandatory = $true)][string] $Value
    )
    if ($Value.Length -lt 1 -or $Value.Length -gt 128 -or $Value -notmatch '^[A-Za-z0-9._+-]+$') {
        throw "$Name must be a bounded safe token"
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
        'certificate identifier field' = '(?i)"(?:certificate|cert|publisher|thumbprint)[^"]*"\s*:'
        'raw machine or user field' = '(?i)"(?:machine_name|computer_name|user_name|username|runner_name|user_sid|logon_sid)"\s*:'
    }
    foreach ($entry in $forbidden.GetEnumerator()) {
        if ($text -match $entry.Value) {
            throw "Evidence file is not redacted ($($entry.Key)): $Path"
        }
    }
}

$artifact = (Resolve-Path -LiteralPath $ArtifactPath).Path
$checksPath = (Resolve-Path -LiteralPath $CheckResultsPath).Path
if (-not (Test-Path -LiteralPath $artifact -PathType Leaf)) {
    throw "ArtifactPath is not a file: $artifact"
}
if (-not (Test-Path -LiteralPath $checksPath -PathType Leaf)) {
    throw "CheckResultsPath is not a file: $checksPath"
}
foreach ($pair in @(
    @('ServiceVersion', $ServiceVersion),
    @('BundleVersion', $BundleVersion),
    @('QemuVersion', $QemuVersion)
)) {
    Assert-SafeToken -Name $pair[0] -Value $pair[1]
}

if ([string]::IsNullOrWhiteSpace($GitSha)) {
    $GitSha = (& git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'git rev-parse HEAD failed' }
}
$GitSha = $GitSha.ToLowerInvariant()
if ($GitSha -notmatch '^[0-9a-f]{40}$') {
    throw 'GitSha must be exactly 40 lowercase hexadecimal characters'
}

$artifactItem = Get-Item -LiteralPath $artifact
$artifactSha = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
$root = [IO.Path]::GetFullPath($OutputRoot)
$rootVolume = [IO.Path]::GetPathRoot($root)
if ($root.TrimEnd('\', '/') -eq $rootVolume.TrimEnd('\', '/')) {
    throw 'OutputRoot cannot be a filesystem root'
}
$target = Join-Path (Join-Path $root $GitSha) $artifactSha
if (Test-Path -LiteralPath $target) {
    throw "Evidence directory already exists; refusing to overwrite: $target"
}

Assert-RedactedText -Path $checksPath
$checkDocument = Get-Content -LiteralPath $checksPath -Raw | ConvertFrom-Json
$checks = if ($checkDocument -is [Array]) { @($checkDocument) } else { @($checkDocument.checks) }
if ($checks.Count -eq 0) {
    throw 'CheckResultsPath contains no checks'
}

$resolvedEvidence = [Collections.Generic.List[IO.FileInfo]]::new()
$seenLeaves = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($source in $EvidenceFiles) {
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
if ($resolvedEvidence.Count -eq 0 -or $resolvedEvidence.Count -gt 256) {
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
    git_sha = $GitSha
    artifact_sha256 = $artifactSha
    artifact_size_bytes = [uint64]$artifactItem.Length
    profile = $Profile
    generated_utc = [DateTime]::UtcNow.ToString('o')
    environment = [ordered]@{
        os_build = [Environment]::OSVersion.Version.ToString()
        architecture = 'x86_64'
        service_version = $ServiceVersion
        bundle_version = $BundleVersion
        qemu_version = $QemuVersion
        runner_identity_sha256 = Get-Sha256Text -Value $RunnerIdentity
        policy_sha256 = Get-Sha256Text -Value $PolicyFingerprint
    }
    checks = $checks
    files = @($fileRecords)
}
$manifestPath = Join-Path $target 'manifest.json'
$manifest | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $manifestPath -Encoding utf8NoBOM

$repoRoot = Split-Path -Parent $PSScriptRoot
$arguments = @('run', '-p', 'xtask', '--locked', '--', 'verify-windows-evidence', '--manifest', $manifestPath)
if ($RequireComplete) { $arguments += '--require-complete' }
& cargo @arguments
if ($LASTEXITCODE -ne 0) {
    throw "Windows evidence validation failed with exit code $LASTEXITCODE"
}
Write-Output $manifestPath
