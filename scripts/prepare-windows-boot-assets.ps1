[CmdletBinding()]
param(
  [string]$ArtifactDir,

  [string]$AssetKey,

  [switch]$UseCachedOnly,

  [switch]$ProbeOnly,

  [string]$CacheRoot = "C:\lsb-assets"
)

$ErrorActionPreference = "Stop"
$RequiredAssets = @("Image", "initramfs.cpio.gz", "rootfs.ext4")

function Get-Sha256Hex {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path
  )

  return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Assert-SafeAssetKey {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Value
  )

  if (-not $Value) {
    throw "Boot asset key must not be empty."
  }

  if ($Value -notmatch '^[A-Za-z0-9._-]+$') {
    throw "Boot asset key contains characters that are unsafe for a Windows cache path: $Value"
  }
}

function Assert-AssetFile {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [Parameter(Mandatory = $true)]
    [object]$Entry
  )

  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw "Boot asset is missing: $Path"
  }

  $actualSize = (Get-Item -LiteralPath $Path).Length
  $expectedSize = [Int64]($Entry.size_bytes)
  if ($actualSize -ne $expectedSize) {
    throw "Boot asset size mismatch for $Path. Expected $expectedSize bytes, got $actualSize bytes."
  }

  $actualHash = Get-Sha256Hex -Path $Path
  $expectedHash = ([string]$Entry.sha256).ToLowerInvariant()
  if ($actualHash -ne $expectedHash) {
    throw "Boot asset SHA256 mismatch for $Path. Expected $expectedHash, got $actualHash."
  }
}

function Get-ManifestEntry {
  param(
    [Parameter(Mandatory = $true)]
    [object[]]$Entries,

    [Parameter(Mandatory = $true)]
    [string]$Name
  )

  $matches = @($Entries | Where-Object { $_.name -eq $Name })
  if ($matches.Count -ne 1) {
    throw "asset-manifest.json must contain exactly one file entry for $Name."
  }

  return $matches[0]
}

function Read-AssetManifest {
  param(
    [Parameter(Mandatory = $true)]
    [string]$ManifestPath
  )

  if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
    throw "Boot asset manifest is missing: $ManifestPath"
  }

  return Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
}

function Assert-AssetManifest {
  param(
    [Parameter(Mandatory = $true)]
    [object]$Manifest,

    [string]$ExpectedAssetKey
  )

  $schemaVersion = [int]($Manifest.schema_version)
  if ($schemaVersion -ne 1) {
    throw "Unsupported boot asset manifest schema version: $($Manifest.schema_version)"
  }

  $manifestAssetKey = [string]$Manifest.asset_key
  Assert-SafeAssetKey -Value $manifestAssetKey

  if ($ExpectedAssetKey -and $manifestAssetKey -ne $ExpectedAssetKey) {
    throw "Boot asset manifest key mismatch. Expected $ExpectedAssetKey, got $manifestAssetKey."
  }

  $platform = [string]$Manifest.platform
  if ($platform -ne "windows-x86_64") {
    throw "Boot asset platform must be windows-x86_64, got $($Manifest.platform)."
  }

  $manifestFiles = @($Manifest.files)
  $entriesByName = @{}

  foreach ($assetName in $RequiredAssets) {
    $entry = Get-ManifestEntry -Entries $manifestFiles -Name $assetName
    $entryName = [string]$entry.name
    if ($entryName -match '[\\/]') {
      throw "Boot asset file entry must be a file name, got $($entry.name)."
    }

    $entriesByName[$assetName] = $entry
  }

  return $entriesByName
}

function Assert-AssetFiles {
  param(
    [Parameter(Mandatory = $true)]
    [string]$AssetRoot,

    [Parameter(Mandatory = $true)]
    [hashtable]$EntriesByName
  )

  foreach ($assetName in $RequiredAssets) {
    $assetPath = Join-Path $AssetRoot $assetName
    Assert-AssetFile -Path $assetPath -Entry $EntriesByName[$assetName]
  }
}

function Export-GitHubEnv {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Name,

    [Parameter(Mandatory = $true)]
    [string]$Value
  )

  if (-not $env:GITHUB_ENV) {
    throw "GITHUB_ENV is not set; this script must run inside GitHub Actions."
  }

  "$Name=$Value" | Out-File -FilePath $env:GITHUB_ENV -Encoding utf8 -Append
}

function New-DisposableRootfs {
  param(
    [Parameter(Mandatory = $true)]
    [string]$CacheDir,

    [Parameter(Mandatory = $true)]
    [hashtable]$EntriesByName
  )

  $runId = if ($env:GITHUB_RUN_ID) { $env:GITHUB_RUN_ID } else { "local" }
  $attempt = if ($env:GITHUB_RUN_ATTEMPT) { $env:GITHUB_RUN_ATTEMPT } else { "0" }
  $workDir = Join-Path (Join-Path $CacheRoot "work") "$runId-$attempt"
  $diagnosticDir = Join-Path $workDir "diagnostics"
  New-Item -ItemType Directory -Force -Path $diagnosticDir | Out-Null

  $disposableRootfs = Join-Path $workDir "rootfs.ext4"
  if (Test-Path -LiteralPath $disposableRootfs) {
    Remove-Item -LiteralPath $disposableRootfs -Force
  }

  $cachedRootfs = Join-Path $CacheDir "rootfs.ext4"
  Copy-Item -LiteralPath $cachedRootfs -Destination $disposableRootfs -Force
  Assert-AssetFile -Path $disposableRootfs -Entry ($EntriesByName["rootfs.ext4"])

  Export-GitHubEnv -Name "LSB_WINDOWS_BOOT_KERNEL" -Value (Join-Path $CacheDir "Image")
  Export-GitHubEnv -Name "LSB_WINDOWS_BOOT_INITRD" -Value (Join-Path $CacheDir "initramfs.cpio.gz")
  Export-GitHubEnv -Name "LSB_WINDOWS_BOOT_ROOTFS" -Value $disposableRootfs
  Export-GitHubEnv -Name "LSB_WINDOWS_BOOT_ARTIFACT_DIR" -Value $diagnosticDir

  Write-Host "Disposable rootfs: $disposableRootfs"
  Write-Host "Diagnostics: $diagnosticDir"
}

if ($ArtifactDir -and $AssetKey) {
  throw "Pass either -ArtifactDir or -AssetKey, not both."
}

if (-not $ArtifactDir -and -not $AssetKey) {
  throw "Pass -ArtifactDir for an artifact miss path or -AssetKey -UseCachedOnly for a local cache hit path."
}

if ($AssetKey -and -not $UseCachedOnly) {
  throw "Pass -UseCachedOnly when preparing assets by -AssetKey."
}

if ($ArtifactDir -and ($UseCachedOnly -or $ProbeOnly)) {
  throw "-UseCachedOnly and -ProbeOnly are only valid with -AssetKey."
}

if ($ProbeOnly -and -not $UseCachedOnly) {
  throw "-ProbeOnly requires -UseCachedOnly."
}

$cacheRootByKey = Join-Path $CacheRoot "by-key"

if ($ArtifactDir) {
  $artifactRoot = (Resolve-Path -LiteralPath $ArtifactDir).Path
  $manifestPath = Join-Path $artifactRoot "asset-manifest.json"
  $manifest = Read-AssetManifest -ManifestPath $manifestPath
  $entriesByName = Assert-AssetManifest -Manifest $manifest
  $assetKey = [string]$manifest.asset_key

  Assert-AssetFiles -AssetRoot $artifactRoot -EntriesByName $entriesByName

  $cacheDir = Join-Path $cacheRootByKey $assetKey
  New-Item -ItemType Directory -Force -Path $cacheDir | Out-Null

  foreach ($assetName in $RequiredAssets) {
    $entry = $entriesByName[$assetName]
    $sourcePath = Join-Path $artifactRoot $assetName
    $cachedPath = Join-Path $cacheDir $assetName
    $cacheValid = $false

    if (Test-Path -LiteralPath $cachedPath -PathType Leaf) {
      try {
        Assert-AssetFile -Path $cachedPath -Entry $entry
        $cacheValid = $true
      } catch {
        Write-Warning "Replacing invalid cached boot asset $cachedPath. $($_.Exception.Message)"
      }
    }

    if ($cacheValid) {
      Write-Host "Boot asset cache hit: $cachedPath"
    } else {
      Copy-Item -LiteralPath $sourcePath -Destination $cachedPath -Force
      Assert-AssetFile -Path $cachedPath -Entry $entry
      Write-Host "Cached boot asset: $cachedPath"
    }
  }

  Copy-Item -LiteralPath $manifestPath -Destination (Join-Path $cacheDir "asset-manifest.json") -Force
} else {
  Assert-SafeAssetKey -Value $AssetKey
  $assetKey = $AssetKey
  $cacheDir = Join-Path $cacheRootByKey $assetKey
  $manifestPath = Join-Path $cacheDir "asset-manifest.json"
  $manifest = Read-AssetManifest -ManifestPath $manifestPath
  $entriesByName = Assert-AssetManifest -Manifest $manifest -ExpectedAssetKey $assetKey
  Assert-AssetFiles -AssetRoot $cacheDir -EntriesByName $entriesByName
}

if ($ProbeOnly) {
  Write-Host "Boot asset cache probe hit: $cacheDir"
  return
}

New-DisposableRootfs -CacheDir $cacheDir -EntriesByName $entriesByName

Write-Host "Prepared Windows boot assets for $assetKey"
