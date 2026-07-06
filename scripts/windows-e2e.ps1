$ErrorActionPreference = "Stop"

Write-Host "== Windows LSB e2e test =="

function Invoke-NativeCommand {
  param(
    [Parameter(Mandatory = $true)]
    [string]$FilePath,

    [Parameter(Mandatory = $true)]
    [string[]]$Arguments
  )

  & $FilePath @Arguments
  if ($LASTEXITCODE -ne 0) {
    throw "$FilePath $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
  }
}

function Invoke-NativeCommandOutput {
  param(
    [Parameter(Mandatory = $true)]
    [string]$FilePath,

    [Parameter(Mandatory = $true)]
    [string[]]$Arguments
  )

  $output = & $FilePath @Arguments 2>&1
  if ($LASTEXITCODE -ne 0) {
    throw "$FilePath $($Arguments -join ' ') failed with exit code $LASTEXITCODE. Output: $($output -join "`n")"
  }

  return @($output)
}

function Get-CargoPackageVersion {
  param(
    [Parameter(Mandatory = $true)]
    [string]$PackageName
  )

  $metadataJson = (& cargo metadata --locked --no-deps --format-version 1) -join "`n"
  if ($LASTEXITCODE -ne 0) {
    throw "cargo metadata failed with exit code $LASTEXITCODE"
  }

  $metadata = $metadataJson | ConvertFrom-Json
  $package = @($metadata.packages | Where-Object { $_.name -eq $PackageName } | Select-Object -First 1)
  if ($package.Count -eq 0) {
    throw "cargo metadata did not include package '$PackageName'"
  }

  return $package[0].version
}

function Require-EnvFile {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Name
  )

  $value = [Environment]::GetEnvironmentVariable($Name)
  if (-not $value) {
    throw "$Name must point to a workflow-provisioned Windows boot asset"
  }
  if (-not (Test-Path -LiteralPath $value -PathType Leaf)) {
    throw "$Name points to '$value', which is not an existing file"
  }

  return $value
}

function Invoke-WindowsCliE2E {
  Write-Host "== Windows lsb CLI run e2e =="

  $kernel = Require-EnvFile "LSB_WINDOWS_BOOT_KERNEL"
  $initrd = Require-EnvFile "LSB_WINDOWS_BOOT_INITRD"
  $rootfs = Require-EnvFile "LSB_WINDOWS_BOOT_ROOTFS"

  $homeRoot = Join-Path ([System.IO.Path]::GetTempPath()) "lsb-cli-e2e-home-$PID"
  $workspaceRoot = Join-Path ([System.IO.Path]::GetTempPath()) "lsb-cli-e2e-workspace-$PID"
  Remove-Item -LiteralPath $homeRoot -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $workspaceRoot -Recurse -Force -ErrorAction SilentlyContinue

  $oldHome = [Environment]::GetEnvironmentVariable("HOME")
  try {
    $dataDir = Join-Path $homeRoot "AppData\Local\lsb"
    New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $dataDir "checkpoints") | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $dataDir "instances") | Out-Null
    New-Item -ItemType Directory -Force -Path $workspaceRoot | Out-Null

    Copy-Item -LiteralPath $kernel -Destination (Join-Path $dataDir "Image") -Force
    Copy-Item -LiteralPath $initrd -Destination (Join-Path $dataDir "initramfs.cpio.gz") -Force
    Copy-Item -LiteralPath $rootfs -Destination (Join-Path $dataDir "rootfs.ext4") -Force

    $version = Get-CargoPackageVersion "lsb-sdk"
    Set-Content -LiteralPath (Join-Path $dataDir "VERSION") -Value "$version"
    Set-Content -LiteralPath (Join-Path $workspaceRoot "lsb.json") -Value "{}"

    [Environment]::SetEnvironmentVariable("HOME", $homeRoot, "Process")

    $guestScript = "set -eu; printf 'lsb-windows-e2e-ok\n'; uname -s; test -d /tmp"
    $output = Invoke-NativeCommandOutput "cargo" @(
      "run",
      "-p",
      "lsb-cli",
      "--locked",
      "--",
      "run",
      "--config",
      (Join-Path $workspaceRoot "lsb.json"),
      "--cpus",
      "2",
      "--memory",
      "2048",
      "--disk-size",
      "4096",
      "--",
      "/bin/sh",
      "-c",
      $guestScript
    )
    $combinedOutput = $output -join "`n"
    if ($combinedOutput -notmatch "lsb-windows-e2e-ok") {
      throw "lsb CLI e2e output did not include the sentinel. Output: $combinedOutput"
    }
    if ($combinedOutput -notmatch "Linux") {
      throw "lsb CLI e2e output did not include the guest kernel name. Output: $combinedOutput"
    }
  } finally {
    if ($null -eq $oldHome) {
      [Environment]::SetEnvironmentVariable("HOME", $null, "Process")
    } else {
      [Environment]::SetEnvironmentVariable("HOME", $oldHome, "Process")
    }
    Remove-Item -LiteralPath $homeRoot -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $workspaceRoot -Recurse -Force -ErrorAction SilentlyContinue
  }
}

Invoke-WindowsCliE2E

# Future full suite:
# - stream stdout/stderr
# - read/write files
# - mount source tree
# - port forwarding
# - no-network egress test
# - allow-net/proxy test
# - checkpoint save/restore
