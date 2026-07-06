[CmdletBinding()]
param(
  [string]$StageRoot = (Join-Path (Get-Location) "target\windows-lsb-diagnostics"),

  [string]$AssetWorkRoot = "C:\lsb-assets\work",

  [string]$RunnerDiagRoot = "C:\actions-runner\_diag",

  [string]$RunnerDiagSinceUtc = $env:LSB_DIAGNOSTICS_RUN_STARTED_UTC,

  [switch]$IncludeRunnerLogs,

  [switch]$SkipCargoLogs
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = "Stop"

$AllowedDiagnosticExtensions = @(".json", ".log", ".redacted", ".txt")
$SecretNamePattern = "(?i)(TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE|KEY|CREDENTIAL|AUTH|COOKIE)"
$EnvAllowlist = @(
  "RUNNER_ENVIRONMENT",
  "RUNNER_OS",
  "RUNNER_ARCH",
  "RUNNER_NAME",
  "GITHUB_ACTION",
  "GITHUB_JOB",
  "GITHUB_RUN_ID",
  "GITHUB_RUN_ATTEMPT",
  "GITHUB_REF_NAME",
  "LSB_QEMU",
  "LSB_TEST_REAL_QEMU",
  "LSB_WINDOWS_INTEGRATION",
  "LSB_WINDOWS_BOOT_KERNEL",
  "LSB_WINDOWS_BOOT_INITRD",
  "LSB_WINDOWS_BOOT_ROOTFS",
  "LSB_WINDOWS_BOOT_ARTIFACT_DIR",
  "LSB_DIAGNOSTICS_RUN_STARTED_UTC",
  "LSB_WINDOWS_GUEST_READY_SECS",
  "CARGO_HOME",
  "CARGO_TARGET_DIR",
  "LIBCLANG_PATH",
  "RUSTFLAGS"
)

$script:CollectedFiles = [System.Collections.Generic.List[string]]::new()
$script:SkippedFiles = [System.Collections.Generic.List[string]]::new()
$script:SecretValues = @()
$script:StageRootResolved = $null
$script:PathTrimChars = [char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)

function Get-RedactionSecretValues {
  $values = [System.Collections.Generic.List[string]]::new()

  Get-ChildItem Env: | ForEach-Object {
    $name = [string]$_.Name
    $value = [string]$_.Value
    if ($name -match $SecretNamePattern -and $value.Length -ge 8) {
      $values.Add($value)
    }
  }

  return @($values | Sort-Object -Unique)
}

function Redact-Text {
  param(
    [Parameter(Mandatory = $true)]
    [AllowEmptyString()]
    [string]$Text
  )

  $redacted = $Text

  foreach ($secret in $script:SecretValues) {
    if ($secret) {
      $redacted = $redacted.Replace($secret, "<redacted>")
    }
  }

  $redacted = [regex]::Replace(
    $redacted,
    "-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
    "<redacted-private-key>",
    [System.Text.RegularExpressions.RegexOptions]::Singleline
  )
  $redacted = [regex]::Replace($redacted, "github_pat_[A-Za-z0-9_]{20,}", "<redacted-github-token>")
  $redacted = [regex]::Replace($redacted, "gh[opsu]_[A-Za-z0-9_]{20,}", "<redacted-github-token>")
  $redacted = [regex]::Replace($redacted, "AKIA[0-9A-Z]{16}", "<redacted-aws-access-key>")
  $redacted = [regex]::Replace(
    $redacted,
    '(?i)\b(authorization|token|secret|password|passwd|cookie|private[_-]?key)(\s*[:=]\s*)("?[^\s,;"]+"?)',
    '$1$2<redacted>'
  )

  return $redacted
}

function Add-CollectedFile {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path
  )

  $resolved = (Resolve-Path -LiteralPath $Path).Path
  $relative = [System.IO.Path]::GetRelativePath($script:StageRootResolved, $resolved)
  $script:CollectedFiles.Add($relative)
}

function Write-RedactedTextFile {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Source,

    [Parameter(Mandatory = $true)]
    [string]$Destination
  )

  $parent = Split-Path -Parent $Destination
  New-Item -ItemType Directory -Force -Path $parent | Out-Null

  try {
    $text = Get-Content -LiteralPath $Source -Raw -ErrorAction Stop
  } catch {
    $script:SkippedFiles.Add("$Source (not readable as text: $($_.Exception.Message))")
    return
  }

  if ($null -eq $text) {
    $text = ""
  }

  $redacted = Redact-Text -Text $text
  $redacted | Out-File -FilePath $Destination -Encoding utf8
  Add-CollectedFile -Path $Destination
}

function Write-RedactedTextLines {
  param(
    [Parameter(Mandatory = $true)]
    [string[]]$Lines,

    [Parameter(Mandatory = $true)]
    [string]$Destination
  )

  $parent = Split-Path -Parent $Destination
  New-Item -ItemType Directory -Force -Path $parent | Out-Null
  $text = $Lines -join [Environment]::NewLine
  $redacted = Redact-Text -Text $text
  $redacted | Out-File -FilePath $Destination -Encoding utf8
  Add-CollectedFile -Path $Destination
}

function Test-AllowedDiagnosticFile {
  param(
    [Parameter(Mandatory = $true)]
    [System.IO.FileInfo]$File,

    [string[]]$AllowedExtensions = $AllowedDiagnosticExtensions
  )

  return $AllowedExtensions -contains $File.Extension.ToLowerInvariant()
}

function Get-SafePathName {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Name
  )

  return $Name -replace '[^A-Za-z0-9._-]', '_'
}

function Initialize-StageRoot {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path
  )

  $fullPath = [System.IO.Path]::GetFullPath($Path)
  $root = [System.IO.Path]::GetPathRoot($fullPath)
  $trimmedFullPath = $fullPath.TrimEnd($script:PathTrimChars)
  $trimmedRoot = $root.TrimEnd($script:PathTrimChars)
  if ($trimmedFullPath -eq $trimmedRoot) {
    throw "Refusing to use filesystem root as diagnostics StageRoot: $fullPath"
  }

  $parent = Split-Path -Parent $fullPath
  if (-not $parent) {
    throw "Diagnostics StageRoot must have a parent directory: $fullPath"
  }

  New-Item -ItemType Directory -Force -Path $parent | Out-Null

  if (Test-Path -LiteralPath $fullPath) {
    $item = Get-Item -LiteralPath $fullPath -Force
    if (-not $item.PSIsContainer) {
      throw "Diagnostics StageRoot exists and is not a directory: $fullPath"
    }

    Remove-Item -LiteralPath $fullPath -Recurse -Force
  }

  New-Item -ItemType Directory -Force -Path $fullPath | Out-Null
  return (Resolve-Path -LiteralPath $fullPath).Path
}

function Get-RunScopedArtifactDirectories {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Root
  )

  $directories = [System.Collections.Generic.List[string]]::new()
  $explicitArtifactDir = [Environment]::GetEnvironmentVariable("LSB_WINDOWS_BOOT_ARTIFACT_DIR")
  if ($explicitArtifactDir) {
    $directories.Add($explicitArtifactDir)
  }

  $runId = [Environment]::GetEnvironmentVariable("GITHUB_RUN_ID")
  $runAttempt = [Environment]::GetEnvironmentVariable("GITHUB_RUN_ATTEMPT")
  if ($runId -and $runAttempt) {
    $directories.Add((Join-Path (Join-Path $Root "$runId-$runAttempt") "diagnostics"))
  }

  return @($directories | Sort-Object -Unique)
}

function Get-ArtifactDestinationRoot {
  param(
    [Parameter(Mandatory = $true)]
    [string]$ArtifactDir,

    [Parameter(Mandatory = $true)]
    [string]$Root
  )

  $resolvedArtifactDir = (Resolve-Path -LiteralPath $ArtifactDir).Path
  $assetRootExists = Test-Path -LiteralPath $Root
  if ($assetRootExists) {
    $resolvedAssetRoot = (Resolve-Path -LiteralPath $Root).Path.TrimEnd($script:PathTrimChars)
    $artifactParent = Split-Path -Parent $resolvedArtifactDir
    $artifactParentTrimmed = $artifactParent.TrimEnd($script:PathTrimChars)
    $assetRootPrefix = "$resolvedAssetRoot$([System.IO.Path]::DirectorySeparatorChar)"
    if ($artifactParentTrimmed.StartsWith($assetRootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
      $safeName = Get-SafePathName -Name (Split-Path -Leaf $artifactParentTrimmed)
      return Join-Path (Join-Path $script:StageRootResolved "lsb-assets-work") $safeName
    }
  }

  return Join-Path $script:StageRootResolved "explicit-boot-artifact-dir"
}

function Get-RunnerDiagSince {
  if (-not $RunnerDiagSinceUtc) {
    return $null
  }

  try {
    return ([datetime]::Parse(
      $RunnerDiagSinceUtc,
      [System.Globalization.CultureInfo]::InvariantCulture,
      [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    )).ToUniversalTime()
  } catch {
    throw "Invalid RunnerDiagSinceUtc value '$RunnerDiagSinceUtc'. Use an ISO-8601 UTC timestamp."
  }
}

function Get-LogLineTimestampUtc {
  param(
    [Parameter(Mandatory = $true)]
    [AllowEmptyString()]
    [string]$Line
  )

  $patterns = @(
    '^\[(?<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)',
    '^(?<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)'
  )

  foreach ($pattern in $patterns) {
    if ($Line -match $pattern) {
      try {
        return ([datetime]::Parse(
          $Matches.timestamp,
          [System.Globalization.CultureInfo]::InvariantCulture,
          [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
        )).ToUniversalTime()
      } catch {
        return $null
      }
    }
  }

  return $null
}

function Copy-DiagnosticTree {
  param(
    [Parameter(Mandatory = $true)]
    [string]$SourceRoot,

    [Parameter(Mandatory = $true)]
    [string]$DestinationRoot,

    [string[]]$AllowedExtensions = $AllowedDiagnosticExtensions,

    [Nullable[datetime]]$ModifiedSinceUtc = $null
  )

  if (-not (Test-Path -LiteralPath $SourceRoot)) {
    return
  }

  $resolvedSource = (Resolve-Path -LiteralPath $SourceRoot).Path
  New-Item -ItemType Directory -Force -Path $DestinationRoot | Out-Null

  Get-ChildItem -LiteralPath $resolvedSource -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
    $file = $_
    if ($file.FullName.StartsWith($script:StageRootResolved, [System.StringComparison]::OrdinalIgnoreCase)) {
      return
    }

    if (-not (Test-AllowedDiagnosticFile -File $file -AllowedExtensions $AllowedExtensions)) {
      $script:SkippedFiles.Add("$($file.FullName) (extension not allowlisted)")
      return
    }

    if ($null -ne $ModifiedSinceUtc -and $file.LastWriteTimeUtc -lt $ModifiedSinceUtc) {
      $script:SkippedFiles.Add("$($file.FullName) (older than diagnostics run scope)")
      return
    }

    $relative = [System.IO.Path]::GetRelativePath($resolvedSource, $file.FullName)
    $destination = Join-Path $DestinationRoot $relative
    Write-RedactedTextFile -Source $file.FullName -Destination $destination
  }
}

function Copy-RunnerDiagnosticLogs {
  param(
    [Parameter(Mandatory = $true)]
    [string]$SourceRoot,

    [Parameter(Mandatory = $true)]
    [string]$DestinationRoot,

    [Parameter(Mandatory = $true)]
    [datetime]$SinceUtc
  )

  if (-not (Test-Path -LiteralPath $SourceRoot)) {
    return
  }

  $resolvedSource = (Resolve-Path -LiteralPath $SourceRoot).Path
  New-Item -ItemType Directory -Force -Path $DestinationRoot | Out-Null

  Get-ChildItem -LiteralPath $resolvedSource -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
    $file = $_
    if ($file.FullName.StartsWith($script:StageRootResolved, [System.StringComparison]::OrdinalIgnoreCase)) {
      return
    }

    if ($file.Extension.ToLowerInvariant() -ne ".log") {
      $script:SkippedFiles.Add("$($file.FullName) (extension not allowlisted)")
      return
    }

    if ($file.LastWriteTimeUtc -lt $SinceUtc) {
      $script:SkippedFiles.Add("$($file.FullName) (older than diagnostics run scope)")
      return
    }

    try {
      $sourceLines = Get-Content -LiteralPath $file.FullName -ErrorAction Stop
    } catch {
      $script:SkippedFiles.Add("$($file.FullName) (not readable as text: $($_.Exception.Message))")
      return
    }

    $includedLines = [System.Collections.Generic.List[string]]::new()
    $includeContinuation = $false
    foreach ($line in $sourceLines) {
      $timestamp = Get-LogLineTimestampUtc -Line ([string]$line)
      if ($null -ne $timestamp) {
        $includeContinuation = $timestamp -ge $SinceUtc
      }

      if ($includeContinuation) {
        $includedLines.Add([string]$line)
      }
    }

    if ($includedLines.Count -eq 0) {
      $script:SkippedFiles.Add("$($file.FullName) (no timestamped lines inside diagnostics run scope)")
      return
    }

    $relative = [System.IO.Path]::GetRelativePath($resolvedSource, $file.FullName)
    $destination = Join-Path $DestinationRoot $relative
    $includedLineArray = $includedLines.ToArray()
    Write-RedactedTextLines -Lines $includedLineArray -Destination $destination
  }
}

function Invoke-SummaryCommand {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Command,

    [string[]]$Arguments = @()
  )

  $found = Get-Command $Command -ErrorAction SilentlyContinue
  if (-not $found) {
    return [ordered]@{
      available = $false
    }
  }

  try {
    $output = & $found.Source @Arguments 2>&1 | Out-String
    return [ordered]@{
      available = $true
      path = Redact-Text -Text ([string]$found.Source)
      output = (Redact-Text -Text $output).Trim()
      exit_code = $LASTEXITCODE
    }
  } catch {
    return [ordered]@{
      available = $true
      path = Redact-Text -Text ([string]$found.Source)
      error = Redact-Text -Text $_.Exception.Message
    }
  }
}

function Get-AllowlistedEnvironment {
  $summary = [ordered]@{}

  foreach ($name in $EnvAllowlist) {
    $value = [Environment]::GetEnvironmentVariable($name)
    if ($null -ne $value -and $value -ne "") {
      $summary[$name] = Redact-Text -Text $value
    }
  }

  return $summary
}

function Write-JsonArtifact {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [Parameter(Mandatory = $true)]
    [object]$Value
  )

  $parent = Split-Path -Parent $Path
  New-Item -ItemType Directory -Force -Path $parent | Out-Null
  $json = $Value | ConvertTo-Json -Depth 8
  (Redact-Text -Text $json) | Out-File -FilePath $Path -Encoding utf8
  Add-CollectedFile -Path $Path
}

function Write-EnvironmentSummary {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path
  )

  $summary = [ordered]@{
    schema_version = 1
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    host = [ordered]@{
      computer_name = Redact-Text -Text ([Environment]::MachineName)
      os_version = [Environment]::OSVersion.VersionString
      process_architecture = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
      os_architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
      processor_count = [Environment]::ProcessorCount
      powershell = $PSVersionTable.PSVersion.ToString()
    }
    environment = Get-AllowlistedEnvironment
    tools = [ordered]@{
      rustc = Invoke-SummaryCommand -Command "rustc" -Arguments @("--version")
      cargo = Invoke-SummaryCommand -Command "cargo" -Arguments @("--version")
      rustup = Invoke-SummaryCommand -Command "rustup" -Arguments @("show")
      qemu_system_x86_64 = Invoke-SummaryCommand -Command "qemu-system-x86_64" -Arguments @("--version")
      qemu_img = Invoke-SummaryCommand -Command "qemu-img" -Arguments @("--version")
      node = Invoke-SummaryCommand -Command "node" -Arguments @("--version")
      npm = Invoke-SummaryCommand -Command "npm" -Arguments @("--version")
      cmake = Invoke-SummaryCommand -Command "cmake" -Arguments @("--version")
      nasm = Invoke-SummaryCommand -Command "nasm" -Arguments @("-v")
    }
  }

  Write-JsonArtifact -Path $Path -Value $summary
}

$script:StageRootResolved = Initialize-StageRoot -Path $StageRoot
$script:SecretValues = Get-RedactionSecretValues

Write-EnvironmentSummary -Path (Join-Path $script:StageRootResolved "environment.summary.json")

$artifactDirectories = @(Get-RunScopedArtifactDirectories -Root $AssetWorkRoot)
foreach ($artifactDir in $artifactDirectories) {
  if (-not (Test-Path -LiteralPath $artifactDir)) {
    $script:SkippedFiles.Add("$artifactDir (run-scoped diagnostics directory not found)")
    continue
  }

  Copy-DiagnosticTree `
    -SourceRoot $artifactDir `
    -DestinationRoot (Get-ArtifactDestinationRoot -ArtifactDir $artifactDir -Root $AssetWorkRoot)
}

if ($artifactDirectories.Count -eq 0) {
  $script:SkippedFiles.Add("no run-scoped boot diagnostics requested; set LSB_WINDOWS_BOOT_ARTIFACT_DIR for local reproduction")
}

if (-not $SkipCargoLogs) {
  $workspaceTarget = Join-Path (Get-Location) "target"
  Copy-DiagnosticTree `
    -SourceRoot $workspaceTarget `
    -DestinationRoot (Join-Path $script:StageRootResolved "workspace-target-logs") `
    -AllowedExtensions @(".log")

  if ($env:CARGO_TARGET_DIR -and (Test-Path -LiteralPath $env:CARGO_TARGET_DIR)) {
    Copy-DiagnosticTree `
      -SourceRoot $env:CARGO_TARGET_DIR `
      -DestinationRoot (Join-Path $script:StageRootResolved "cargo-target-logs") `
      -AllowedExtensions @(".log")
  }
}

if ($IncludeRunnerLogs -and (Test-Path -LiteralPath $RunnerDiagRoot)) {
  $runnerDiagSince = Get-RunnerDiagSince
  if ($null -eq $runnerDiagSince) {
    $script:SkippedFiles.Add("runner _diag logs skipped; set LSB_DIAGNOSTICS_RUN_STARTED_UTC or -RunnerDiagSinceUtc to bound collection")
  } else {
    Copy-RunnerDiagnosticLogs `
      -SourceRoot $RunnerDiagRoot `
      -DestinationRoot (Join-Path $script:StageRootResolved "actions-runner") `
      -SinceUtc $runnerDiagSince
  }
} elseif ($IncludeRunnerLogs) {
  $script:SkippedFiles.Add("$RunnerDiagRoot (runner diagnostics root not found)")
}

$manifest = [ordered]@{
  schema_version = 1
  generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
  stage_root = Redact-Text -Text $script:StageRootResolved
  collected_files = @($script:CollectedFiles | Sort-Object -Unique)
  skipped_files = @($script:SkippedFiles | Sort-Object -Unique)
}

Write-JsonArtifact -Path (Join-Path $script:StageRootResolved "diagnostics-manifest.json") -Value $manifest

Write-Host "Windows diagnostics staged at $script:StageRootResolved"
Write-Host "Collected $($script:CollectedFiles.Count) file(s); skipped $($script:SkippedFiles.Count) file(s)."
