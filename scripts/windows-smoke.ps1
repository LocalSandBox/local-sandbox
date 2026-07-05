$ErrorActionPreference = "Stop"

Write-Host "== Windows LSB smoke test =="

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

Invoke-NativeCommand "cargo" @("run", "-p", "lsb-cli", "--", "--help")

function Invoke-YarnCommand {
  param(
    [Parameter(Mandatory = $true)]
    [string[]]$YarnArgs
  )

  $corepack = Get-Command corepack -ErrorAction SilentlyContinue
  if ($corepack) {
    Invoke-NativeCommand "corepack" (@("yarn") + $YarnArgs)
  } else {
    Write-Warning "corepack was not found on PATH; falling back to npx corepack."
    Invoke-NativeCommand "npx" (@("--yes", "corepack@latest", "yarn") + $YarnArgs)
  }
}

function Invoke-NodeCommand {
  param(
    [Parameter(Mandatory = $true)]
    [string[]]$NodeArgs
  )

  Invoke-NativeCommand "node" $NodeArgs
}

function Invoke-NpmCommand {
  param(
    [Parameter(Mandatory = $true)]
    [string[]]$NpmArgs
  )

  Invoke-NativeCommand "npm" $NpmArgs
}

function Invoke-NpmPack {
  param(
    [Parameter(Mandatory = $true)]
    [string]$PackageDir,

    [Parameter(Mandatory = $true)]
    [string]$PackDir
  )

  Push-Location $PackageDir
  try {
    $packOutput = & npm pack --silent --pack-destination $PackDir 2>&1
    if ($LASTEXITCODE -ne 0) {
      throw "npm pack failed with exit code $LASTEXITCODE. Output: $($packOutput -join "`n")"
    }

    $packLines = @($packOutput | Where-Object { $_ } | ForEach-Object { $_.ToString().Trim() })
    if ($packLines.Count -eq 0) {
      throw "npm pack did not print a tarball name for $PackageDir"
    }

    $tarballName = $packLines[-1]
    if (-not $tarballName) {
      throw "npm pack did not print a tarball name for $PackageDir"
    }

    $tarball = Join-Path $PackDir $tarballName
    if (-not (Test-Path -LiteralPath $tarball -PathType Leaf)) {
      throw "npm pack reported $tarballName but $tarball does not exist"
    }

    return $tarball
  } finally {
    Pop-Location
  }
}

function Invoke-WindowsNodePackedInstallSmoke {
  Write-Host "== Windows Node packed package install/import smoke =="

  $packRoot = Join-Path ([System.IO.Path]::GetTempPath()) "lsb-nodejs-pack-$PID"
  $installRoot = Join-Path ([System.IO.Path]::GetTempPath()) "lsb-nodejs-install-$PID"
  Remove-Item -LiteralPath $packRoot -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $installRoot -Recurse -Force -ErrorAction SilentlyContinue
  New-Item -ItemType Directory -Force -Path $packRoot | Out-Null
  New-Item -ItemType Directory -Force -Path $installRoot | Out-Null

  try {
    Invoke-YarnCommand @("napi", "prepublish", "-t", "npm", "--no-gh-release", "--skip-optional-publish")

    $packageRoot = (Get-Location).Path
    $platformPackageRoot = Join-Path $packageRoot "npm\win32-x64-msvc"
    $nativeArtifact = Join-Path $packageRoot "lsb-nodejs.win32-x64-msvc.node"
    $platformNativeArtifact = Join-Path $platformPackageRoot "lsb-nodejs.win32-x64-msvc.node"

    if (-not (Test-Path -LiteralPath $nativeArtifact -PathType Leaf)) {
      throw "Windows native binding was not produced at $nativeArtifact"
    }

    Copy-Item -LiteralPath $nativeArtifact -Destination $platformNativeArtifact -Force
    if (-not (Test-Path -LiteralPath $platformNativeArtifact -PathType Leaf)) {
      throw "Windows platform package is missing $platformNativeArtifact"
    }

    $rootTarball = Invoke-NpmPack -PackageDir $packageRoot -PackDir $packRoot
    $platformTarball = Invoke-NpmPack -PackageDir $platformPackageRoot -PackDir $packRoot

    Push-Location $installRoot
    try {
      Invoke-NpmCommand @("init", "-y")
      Invoke-NpmCommand @(
        "install",
        "--ignore-scripts",
        "--no-audit",
        "--fund=false",
        $rootTarball,
        $platformTarball
      )
      Invoke-NodeCommand @(
        "-e",
        "const binding = require('@local-sandbox/lsb-nodejs'); if (typeof binding.Sandbox?.start !== 'function') throw new Error('Sandbox.start missing from packed install'); console.log('packed install loaded @local-sandbox/lsb-nodejs');"
      )
    } finally {
      Pop-Location
    }
  } finally {
    Remove-Item -LiteralPath $packRoot -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $installRoot -Recurse -Force -ErrorAction SilentlyContinue
  }
}

function Invoke-WindowsNodeSmoke {
  Write-Host "== Windows Node binding sandbox creation/preflight smoke =="

  Push-Location "bindings/nodejs"
  try {
    Invoke-YarnCommand @("install", "--immutable")
    Invoke-YarnCommand @(
      "napi",
      "build",
      "--platform",
      "--release",
      "--js",
      "index.js",
      "--dts",
      "index.d.ts"
    )
    Invoke-YarnCommand @("patch-loader")
    Invoke-WindowsNodePackedInstallSmoke
    Invoke-NodeCommand @("scripts/windows-preflight-smoke.mjs")
  } finally {
    Pop-Location
  }
}

Write-Host "== Windows QEMU preflight smoke =="
$env:LSB_TEST_REAL_QEMU = "1"
Invoke-NativeCommand "cargo" @(
  "test",
  "-p",
  "lsb-platform",
  "real_qemu_preflight_when_explicitly_enabled",
  "--",
  "--ignored",
  "--nocapture"
)

$bootVars = @(
  "LSB_WINDOWS_BOOT_KERNEL",
  "LSB_WINDOWS_BOOT_INITRD",
  "LSB_WINDOWS_BOOT_ROOTFS"
)
$missingBootVars = @($bootVars | Where-Object { -not [Environment]::GetEnvironmentVariable($_) })
if ($missingBootVars.Count -eq 0) {
  Invoke-WindowsNodeSmoke
  Write-Host "== Windows QEMU direct boot smoke =="
  Invoke-NativeCommand "cargo" @("test", "-p", "lsb-platform", "windows_qemu_boot_smoke", "--", "--ignored", "--nocapture")
  Write-Host "== Windows guest exec smoke =="
  Invoke-NativeCommand "cargo" @("test", "-p", "lsb-vm", "windows_qemu_exec_smoke", "--", "--ignored", "--nocapture")
  Write-Host "== Windows guest copy transfer smoke =="
  Invoke-NativeCommand "cargo" @("test", "-p", "lsb-vm", "windows_qemu_copy_transfer_smoke", "--", "--ignored", "--nocapture")
  Write-Host "== Windows mount MVP smoke =="
  Invoke-NativeCommand "cargo" @("test", "-p", "lsb-vm", "windows_qemu_mount_mvp_smoke", "--", "--ignored", "--nocapture")
  Write-Host "== Windows port-forward smoke =="
  Invoke-NativeCommand "cargo" @("test", "-p", "lsb-vm", "windows_qemu_port_forward_smoke", "--", "--ignored", "--nocapture")
  Write-Host "== Windows checkpoint/store smoke =="
  Invoke-NativeCommand "cargo" @("test", "-p", "lsb-sdk", "windows_qemu_checkpoint_store_smoke", "--", "--ignored", "--nocapture")
  Write-Host "== Windows network policy/proxy smoke =="
  Invoke-NativeCommand "cargo" @("test", "-p", "lsb-sdk", "windows_qemu_network_policy_proxy_smoke", "--", "--ignored", "--nocapture")
} else {
  Write-Warning "Skipping Windows Node binding, QEMU direct boot, guest exec, guest copy transfer, mount MVP, port-forward, checkpoint/store, and network policy/proxy smokes. Set $($missingBootVars -join ', ') to disposable LocalSandbox boot asset paths."
}

# Later:
# cargo run -p lsb-cli -- run --port 8080:8080 -- your-network-policy-test
