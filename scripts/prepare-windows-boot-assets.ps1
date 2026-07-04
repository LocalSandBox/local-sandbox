[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$ArtifactDir,

  [string]$CacheRoot = "C:\lsb-assets"
)

$ErrorActionPreference = "Stop"

function Get-Sha256Hex {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path
  )

  return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
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

$artifactRoot = (Resolve-Path -LiteralPath $ArtifactDir).Path
$manifestPath = Join-Path $artifactRoot "asset-manifest.json"
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
  throw "Boot asset manifest is missing: $manifestPath"
}

$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$schemaVersion = [int]($manifest.schema_version)
if ($schemaVersion -ne 1) {
  throw "Unsupported boot asset manifest schema version: $($manifest.schema_version)"
}

$assetKey = [string]$manifest.asset_key
if (-not $assetKey) {
  throw "Boot asset manifest is missing asset_key."
}

if ($assetKey -notmatch '^[A-Za-z0-9._-]+$') {
  throw "Boot asset key contains characters that are unsafe for a Windows cache path: $assetKey"
}

$platform = [string]$manifest.platform
if ($platform -ne "windows-x86_64") {
  throw "Boot asset platform must be windows-x86_64, got $($manifest.platform)."
}

$manifestFiles = @($manifest.files)
$requiredAssets = @("Image", "initramfs.cpio.gz", "rootfs.ext4")
$entriesByName = @{}

foreach ($assetName in $requiredAssets) {
  $entry = Get-ManifestEntry -Entries $manifestFiles -Name $assetName
  $entryName = [string]$entry.name
  if ($entryName -match '[\\/]') {
    throw "Boot asset file entry must be a file name, got $($entry.name)."
  }

  $sourcePath = Join-Path $artifactRoot $assetName
  Assert-AssetFile -Path $sourcePath -Entry $entry
  $entriesByName[$assetName] = $entry
}

$cacheDir = Join-Path (Join-Path $CacheRoot "by-key") $assetKey
New-Item -ItemType Directory -Force -Path $cacheDir | Out-Null

foreach ($assetName in $requiredAssets) {
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

$runId = if ($env:GITHUB_RUN_ID) { $env:GITHUB_RUN_ID } else { "local" }
$attempt = if ($env:GITHUB_RUN_ATTEMPT) { $env:GITHUB_RUN_ATTEMPT } else { "0" }
$workDir = Join-Path (Join-Path $CacheRoot "work") "$runId-$attempt"
$diagnosticDir = Join-Path $workDir "diagnostics"
New-Item -ItemType Directory -Force -Path $diagnosticDir | Out-Null

$disposableRootfs = Join-Path $workDir "rootfs.ext4"
if (Test-Path -LiteralPath $disposableRootfs) {
  Remove-Item -LiteralPath $disposableRootfs -Force
}

$cachedRootfs = Join-Path $cacheDir "rootfs.ext4"
Copy-Item -LiteralPath $cachedRootfs -Destination $disposableRootfs -Force
Assert-AssetFile -Path $disposableRootfs -Entry ($entriesByName["rootfs.ext4"])

Export-GitHubEnv -Name "LSB_WINDOWS_BOOT_KERNEL" -Value (Join-Path $cacheDir "Image")
Export-GitHubEnv -Name "LSB_WINDOWS_BOOT_INITRD" -Value (Join-Path $cacheDir "initramfs.cpio.gz")
Export-GitHubEnv -Name "LSB_WINDOWS_BOOT_ROOTFS" -Value $disposableRootfs
Export-GitHubEnv -Name "LSB_WINDOWS_BOOT_ARTIFACT_DIR" -Value $diagnosticDir

Write-Host "Prepared Windows boot assets for $assetKey"
Write-Host "Disposable rootfs: $disposableRootfs"
Write-Host "Diagnostics: $diagnosticDir"
