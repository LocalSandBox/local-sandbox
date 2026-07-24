[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$MetadataPath,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,

    [Parameter(Mandatory = $true)]
    [string]$Version,

    [Parameter(Mandatory = $true)]
    [string]$CommitSha,

    [Parameter(Mandatory = $true)]
    [string]$CreatedUtc,

    [string]$SentryNativeLockPath,
    [string]$SentryNativeSourceDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Utf8NoBom = [Text.UTF8Encoding]::new($false)
$script:MaxPackages = 5000
$script:MaxMetadataBytes = 64MB
$script:MaxLicenseFileBytes = 4MB
$script:MaxLicenseTotalBytes = 128MB

function Resolve-ExistingFile {
    param([string]$Path, [string]$Label)
    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction Stop
    $item = Get-Item -LiteralPath $resolved.Path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "$Label must be a regular non-reparse file"
    }
    return $resolved.Path
}

function Write-DeterministicJson {
    param([string]$Path, [object]$Value)
    $json = $Value | ConvertTo-Json -Depth 30
    [IO.File]::WriteAllText($Path, $json + "`n", $script:Utf8NoBom)
}

function Get-Sha256Text {
    param([string]$Value)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        return ([Convert]::ToHexString($sha256.ComputeHash($script:Utf8NoBom.GetBytes($Value)))).ToLowerInvariant()
    } finally {
        $sha256.Dispose()
    }
}

function Get-SafeName {
    param([string]$Value)
    $safe = [Text.RegularExpressions.Regex]::Replace($Value, '[^A-Za-z0-9._-]', '_')
    if ([string]::IsNullOrWhiteSpace($safe) -or $safe.Length -gt 128) {
        throw 'package name or version is unsafe for license inventory paths'
    }
    return $safe
}

function Get-SpdxId {
    param([object]$Package)
    $name = Get-SafeName $Package.name
    $version = Get-SafeName $Package.version
    $digest = (Get-Sha256Text $Package.id).Substring(0, 12)
    return "SPDXRef-Package-$name-$version-$digest"
}

function Copy-LicenseInventory {
    param([object[]]$Packages, [string]$LicensesDirectory, [string]$WorkspaceRoot)
    $localDirectory = Join-Path $LicensesDirectory 'LocalSandbox'
    [void](New-Item -ItemType Directory -Path $localDirectory)
    $rootLicense = Resolve-ExistingFile (Join-Path $WorkspaceRoot 'LICENSE') 'workspace LICENSE'
    Copy-Item -LiteralPath $rootLicense -Destination (Join-Path $localDirectory 'LICENSE')

    $thirdPartyDirectory = Join-Path $LicensesDirectory 'third-party'
    [void](New-Item -ItemType Directory -Path $thirdPartyDirectory)
    $totalBytes = (Get-Item -LiteralPath $rootLicense).Length
    $notices = [Collections.Generic.List[object]]::new()
    foreach ($package in $Packages) {
        $packageKey = "$(Get-SafeName $package.name)-$(Get-SafeName $package.version)-$((Get-Sha256Text $package.id).Substring(0, 12))"
        $destination = Join-Path $thirdPartyDirectory $packageKey
        [void](New-Item -ItemType Directory -Path $destination)
        $manifest = Resolve-ExistingFile $package.manifest_path "manifest for $($package.name)"
        $manifestDirectory = Split-Path -Parent $manifest
        $candidates = @(Get-ChildItem -LiteralPath $manifestDirectory -Force -File | Where-Object {
            $_.Name -match '^(LICENSE|LICENCE|COPYING|NOTICE)(\..*|-.*)?$'
        } | Sort-Object Name)
        $copied = [Collections.Generic.List[string]]::new()
        foreach ($candidate in $candidates) {
            if ($candidate.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "license input is a reparse point: $($candidate.FullName)"
            }
            if ($candidate.Length -gt $script:MaxLicenseFileBytes) {
                throw "license input exceeds the per-file limit: $($candidate.FullName)"
            }
            $totalBytes += $candidate.Length
            if ($totalBytes -gt $script:MaxLicenseTotalBytes) {
                throw 'license inventory exceeds the total size limit'
            }
            $target = Join-Path $destination $candidate.Name
            if (Test-Path -LiteralPath $target) {
                throw "case-insensitive license filename collision: $target"
            }
            Copy-Item -LiteralPath $candidate.FullName -Destination $target
            $copied.Add($candidate.Name)
        }
        $license = if ([string]::IsNullOrWhiteSpace($package.license)) { 'NOASSERTION' } else { $package.license }
        if ($copied.Count -eq 0) {
            $fallback = "Declared Cargo license expression: $license`nNo package-local license file was present in the resolved source tree.`n"
            [IO.File]::WriteAllText((Join-Path $destination 'LICENSE-EXPRESSION.txt'), $fallback, $script:Utf8NoBom)
            $copied.Add('LICENSE-EXPRESSION.txt')
        }
        $notices.Add([ordered]@{
            name = $package.name
            version = $package.version
            license = $license
            source = if ($null -eq $package.source) { 'workspace' } else { $package.source }
            files = @($copied)
        })
    }
    Write-DeterministicJson (Join-Path $LicensesDirectory 'THIRD-PARTY-NOTICES.json') @($notices)
}

$metadataFile = Resolve-ExistingFile $MetadataPath 'MetadataPath'
$metadataSize = (Get-Item -LiteralPath $metadataFile).Length
if ($metadataSize -eq 0 -or $metadataSize -gt $script:MaxMetadataBytes) {
    throw 'Cargo metadata size is outside the supported range'
}
if ($Version -notmatch '^\d+\.\d+\.\d+([+-][0-9A-Za-z.-]+)?$') {
    throw 'Version must be a bounded SemVer value without a v prefix'
}
if ($CommitSha -notmatch '^[0-9a-fA-F]{40}$') {
    throw 'CommitSha must be a full Git SHA-1'
}
$created = [DateTimeOffset]::Parse($CreatedUtc, [Globalization.CultureInfo]::InvariantCulture)
$created = $created.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

$output = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $output) {
    throw "refusing to overwrite metadata output directory: $output"
}
[void](New-Item -ItemType Directory -Path $output)
$licensesDirectory = Join-Path $output 'licenses'
[void](New-Item -ItemType Directory -Path $licensesDirectory)

$metadata = Get-Content -LiteralPath $metadataFile -Raw | ConvertFrom-Json
$packages = @($metadata.packages | Sort-Object name, version, id)
if ($packages.Count -eq 0 -or $packages.Count -gt $script:MaxPackages) {
    throw 'Cargo package count is outside the supported range'
}
$workspaceRoot = Resolve-ExistingFile (Join-Path $metadata.workspace_root 'Cargo.toml') 'workspace Cargo.toml'
$workspaceRoot = Split-Path -Parent $workspaceRoot
Copy-LicenseInventory $packages $licensesDirectory $workspaceRoot

$nativePackages = @()
if (-not [string]::IsNullOrWhiteSpace($SentryNativeLockPath) -or
    -not [string]::IsNullOrWhiteSpace($SentryNativeSourceDirectory)) {
    if ([string]::IsNullOrWhiteSpace($SentryNativeLockPath) -or
        [string]::IsNullOrWhiteSpace($SentryNativeSourceDirectory)) {
        throw 'SentryNativeLockPath and SentryNativeSourceDirectory must be supplied together'
    }
    $nativeLockFile = Resolve-ExistingFile $SentryNativeLockPath 'Sentry Native lock'
    $nativeLock = Get-Content -LiteralPath $nativeLockFile -Raw | ConvertFrom-Json
    $nativeSource = (Resolve-Path -LiteralPath $SentryNativeSourceDirectory -ErrorAction Stop).Path
    $nativePackages = @(
        [ordered]@{
            name = 'sentry-native'; version = [string]$nativeLock.sentry_native.tag
            license = 'MIT'; revision = [string]$nativeLock.sentry_native.commit
            license_path = Join-Path $nativeSource 'LICENSE'
        },
        [ordered]@{
            name = 'crashpad'; version = [string]$nativeLock.sentry_native.recursive_revisions.'external/crashpad'
            license = 'Apache-2.0'; revision = [string]$nativeLock.sentry_native.recursive_revisions.'external/crashpad'
            license_path = Join-Path $nativeSource 'external\crashpad\LICENSE'
        },
        [ordered]@{
            name = 'mini-chromium'; version = [string]$nativeLock.sentry_native.recursive_revisions.'external/crashpad/third_party/mini_chromium/mini_chromium'
            license = 'BSD-3-Clause'; revision = [string]$nativeLock.sentry_native.recursive_revisions.'external/crashpad/third_party/mini_chromium/mini_chromium'
            license_path = Join-Path $nativeSource 'external\crashpad\third_party\mini_chromium\mini_chromium\LICENSE'
        },
        [ordered]@{
            name = 'zlib'; version = [string]$nativeLock.sentry_native.recursive_revisions.'external/crashpad/third_party/zlib/zlib'
            license = 'Zlib'; revision = [string]$nativeLock.sentry_native.recursive_revisions.'external/crashpad/third_party/zlib/zlib'
            license_path = Join-Path $nativeSource 'external\crashpad\third_party\zlib\zlib\LICENSE'
        }
    )
    foreach ($nativePackage in $nativePackages) {
        $license = Resolve-ExistingFile $nativePackage.license_path "$($nativePackage.name) license"
        $destination = Join-Path $licensesDirectory "third-party\$($nativePackage.name)-$($nativePackage.revision)"
        [void](New-Item -ItemType Directory -Path $destination)
        Copy-Item -LiteralPath $license -Destination (Join-Path $destination 'LICENSE')
    }
    $noticesPath = Join-Path $licensesDirectory 'THIRD-PARTY-NOTICES.json'
    $notices = @((Get-Content -LiteralPath $noticesPath -Raw | ConvertFrom-Json))
    $notices += @($nativePackages | ForEach-Object {
        [ordered]@{
            name = $_.name
            version = $_.version
            revision = $_.revision
            license = $_.license
            source = 'sentry-native.lock.json'
            files = @('LICENSE')
        }
    })
    Write-DeterministicJson $noticesPath @($notices | Sort-Object name, version)
}

$spdxPackages = [Collections.Generic.List[object]]::new()
$relationships = [Collections.Generic.List[object]]::new()
foreach ($package in $packages) {
    $spdxId = Get-SpdxId $package
    $license = if ([string]::IsNullOrWhiteSpace($package.license)) { 'NOASSERTION' } else { $package.license }
    $download = if ($null -eq $package.source) { 'NOASSERTION' } else { $package.source }
    $spdxPackages.Add([ordered]@{
        SPDXID = $spdxId
        name = $package.name
        versionInfo = $package.version
        downloadLocation = $download
        filesAnalyzed = $false
        licenseConcluded = 'NOASSERTION'
        licenseDeclared = $license
        copyrightText = 'NOASSERTION'
        externalRefs = @([ordered]@{
            referenceCategory = 'PACKAGE-MANAGER'
            referenceType = 'purl'
            referenceLocator = "pkg:cargo/$($package.name)@$($package.version)"
        })
    })
    $relationships.Add([ordered]@{
        spdxElementId = 'SPDXRef-DOCUMENT'
        relationshipType = 'DESCRIBES'
        relatedSpdxElement = $spdxId
    })
}
foreach ($package in $nativePackages) {
    $spdxId = "SPDXRef-Package-$($package.name)-$($package.revision)"
    $spdxPackages.Add([ordered]@{
        SPDXID = $spdxId
        name = $package.name
        versionInfo = $package.version
        downloadLocation = 'NOASSERTION'
        filesAnalyzed = $false
        licenseConcluded = 'NOASSERTION'
        licenseDeclared = $package.license
        copyrightText = 'NOASSERTION'
        externalRefs = @()
    })
    $relationships.Add([ordered]@{
        spdxElementId = 'SPDXRef-DOCUMENT'
        relationshipType = 'DESCRIBES'
        relatedSpdxElement = $spdxId
    })
}

$document = [ordered]@{
    spdxVersion = 'SPDX-2.3'
    dataLicense = 'CC0-1.0'
    SPDXID = 'SPDXRef-DOCUMENT'
    name = "lsb-seawork-service-v$Version-windows-x86_64"
    documentNamespace = "https://github.com/LocalSandBox/local-sandbox/releases/download/v$Version/lsb-seawork-service-$CommitSha"
    creationInfo = [ordered]@{
        created = $created
        creators = @('Tool: LocalSandbox prepare-seawork-release-metadata.ps1')
    }
    packages = @($spdxPackages)
    relationships = @($relationships)
}
Write-DeterministicJson (Join-Path $output 'sbom.spdx.json') $document

[pscustomobject]@{
    output = $output
    packages = $packages.Count
    created = $created
} | ConvertTo-Json -Compress
