$ErrorActionPreference = "Stop"

Write-Host "== Windows LSB smoke test =="

if (-not ("LsbSmoke.ProcessOutputCollector" -as [type])) {
  Add-Type -TypeDefinition @'
namespace LsbSmoke {
  using System;
  using System.Diagnostics;
  using System.Text;

  public sealed class ProcessOutputCollector {
    private readonly object gate = new object();
    private readonly StringBuilder stdout = new StringBuilder();
    private readonly StringBuilder stderr = new StringBuilder();

    public void OnOutput(object sender, DataReceivedEventArgs args) {
      if (args.Data == null) {
        return;
      }
      lock (gate) {
        stdout.AppendLine(args.Data);
      }
    }

    public void OnError(object sender, DataReceivedEventArgs args) {
      if (args.Data == null) {
        return;
      }
      lock (gate) {
        stderr.AppendLine(args.Data);
      }
    }

    public string GetText() {
      lock (gate) {
        string outText = stdout.ToString();
        string errText = stderr.ToString();
        if (outText.Length == 0) {
          return errText;
        }
        if (errText.Length == 0) {
          return outText;
        }
        return outText + Environment.NewLine + errText;
      }
    }
  }
}
'@
}

function Invoke-NativeCommand {
  param(
    [Parameter(Mandatory = $true)]
    [string]$FilePath,

    [Parameter(Mandatory = $true)]
    [string[]]$Arguments
  )

  $timeoutSeconds = 1200
  $configuredTimeout = [Environment]::GetEnvironmentVariable("LSB_WINDOWS_SMOKE_COMMAND_TIMEOUT_SECS")
  if ($configuredTimeout) {
    $parsedTimeout = 0
    if ([int]::TryParse($configuredTimeout, [ref]$parsedTimeout) -and $parsedTimeout -gt 0) {
      $timeoutSeconds = $parsedTimeout
    }
  }

  $started = Start-NativeCommandOutput -FilePath $FilePath -Arguments $Arguments
  $printedLength = 0
  $deadline = [DateTime]::UtcNow.AddSeconds($timeoutSeconds)
  $stoppedForTimeout = $false

  try {
    while (-not $started.Process.WaitForExit(1000)) {
      $text = Get-StartedCommandText $started
      if ($text.Length -gt $printedLength) {
        Write-Host -NoNewline $text.Substring($printedLength)
        $printedLength = $text.Length
      }

      if ([DateTime]::UtcNow -ge $deadline) {
        $text = Get-StartedCommandText $started
        if ($text.Length -gt $printedLength) {
          Write-Host -NoNewline $text.Substring($printedLength)
          $printedLength = $text.Length
        }
        Stop-StartedCommand $started
        $stoppedForTimeout = $true
        throw "$($started.Command) timed out after $timeoutSeconds seconds. Output: $text"
      }
    }

    [void]$started.Process.WaitForExit(30000)
    $text = Get-StartedCommandText $started
    if ($text.Length -gt $printedLength) {
      Write-Host -NoNewline $text.Substring($printedLength)
    }

    if ($started.Process.ExitCode -ne 0) {
      throw "$($started.Command) failed with exit code $($started.Process.ExitCode)"
    }
  } finally {
    if (-not $stoppedForTimeout) {
      $started.Process.remove_OutputDataReceived($started.OutputHandler)
      $started.Process.remove_ErrorDataReceived($started.ErrorHandler)
    }
  }
}

function Resolve-NativeCommandPath {
  param(
    [Parameter(Mandatory = $true)]
    [string]$FilePath
  )

  if ([System.IO.Path]::IsPathRooted($FilePath) -or $FilePath.Contains("\") -or $FilePath.Contains("/")) {
    return $FilePath
  }

  $commands = @(Get-Command $FilePath -All -ErrorAction SilentlyContinue)
  $application = @($commands | Where-Object { $_.CommandType -eq "Application" } | Select-Object -First 1)
  if ($application.Count -gt 0 -and $application[0].Source) {
    return $application[0].Source
  }

  $externalScript = @($commands | Where-Object { $_.CommandType -eq "ExternalScript" } | Select-Object -First 1)
  if ($externalScript.Count -gt 0 -and $externalScript[0].Source) {
    return $externalScript[0].Source
  }

  return $FilePath
}

function Set-NativeCommandStartInfo {
  param(
    [Parameter(Mandatory = $true)]
    [System.Diagnostics.ProcessStartInfo]$StartInfo,

    [Parameter(Mandatory = $true)]
    [string]$ResolvedFilePath,

    [Parameter(Mandatory = $true)]
    [string[]]$Arguments
  )

  $extension = [System.IO.Path]::GetExtension($ResolvedFilePath).ToLowerInvariant()
  if ($extension -eq ".ps1") {
    $pwsh = Get-Command pwsh -CommandType Application -ErrorAction SilentlyContinue
    if (-not $pwsh -or -not $pwsh.Source) {
      throw "Cannot execute PowerShell script shim $ResolvedFilePath because pwsh was not found on PATH"
    }

    $StartInfo.FileName = $pwsh.Source
    foreach ($argument in @("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $ResolvedFilePath)) {
      [void]$StartInfo.ArgumentList.Add($argument)
    }
    foreach ($argument in $Arguments) {
      [void]$StartInfo.ArgumentList.Add($argument)
    }
    return "$($pwsh.Source) -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $ResolvedFilePath $($Arguments -join ' ')"
  }

  $StartInfo.FileName = $ResolvedFilePath
  foreach ($argument in $Arguments) {
    [void]$StartInfo.ArgumentList.Add($argument)
  }
  return "$ResolvedFilePath $($Arguments -join ' ')"
}

function Start-NativeCommandOutput {
  param(
    [Parameter(Mandatory = $true)]
    [string]$FilePath,

    [Parameter(Mandatory = $true)]
    [string[]]$Arguments
  )

  $collector = [LsbSmoke.ProcessOutputCollector]::new()
  $resolvedFilePath = Resolve-NativeCommandPath $FilePath
  $psi = [System.Diagnostics.ProcessStartInfo]::new()
  $psi.WorkingDirectory = (Get-Location).Path
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $command = Set-NativeCommandStartInfo -StartInfo $psi -ResolvedFilePath $resolvedFilePath -Arguments $Arguments

  $process = [System.Diagnostics.Process]::new()
  $process.StartInfo = $psi
  $outputHandler = [System.Diagnostics.DataReceivedEventHandler]$collector.OnOutput
  $errorHandler = [System.Diagnostics.DataReceivedEventHandler]$collector.OnError
  $process.add_OutputDataReceived($outputHandler)
  $process.add_ErrorDataReceived($errorHandler)

  [void]$process.Start()
  $process.BeginOutputReadLine()
  $process.BeginErrorReadLine()

  return [pscustomobject]@{
    Process = $process
    Collector = $collector
    OutputHandler = $outputHandler
    ErrorHandler = $errorHandler
    Command = $command
  }
}

function Get-StartedCommandText {
  param(
    [Parameter(Mandatory = $true)]
    [object]$Started
  )

  return $Started.Collector.GetText()
}

function Stop-StartedCommand {
  param(
    [Parameter(Mandatory = $true)]
    [object]$Started
  )

  if (-not $Started.Process.HasExited) {
    try {
      $Started.Process.Kill($true)
    } catch {
      try {
        $Started.Process.Kill()
      } catch {
      }
    }
  }

  [void]$Started.Process.WaitForExit(30000)
  $Started.Process.remove_OutputDataReceived($Started.OutputHandler)
  $Started.Process.remove_ErrorDataReceived($Started.ErrorHandler)
}

function Wait-StartedCommandOutputContains {
  param(
    [Parameter(Mandatory = $true)]
    [object]$Started,

    [Parameter(Mandatory = $true)]
    [string]$Needle,

    [int]$TimeoutSeconds = 120
  )

  $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
  while ([DateTime]::UtcNow -lt $deadline) {
    $text = Get-StartedCommandText $Started
    if ($text.Contains($Needle)) {
      return
    }
    if ($Started.Process.HasExited) {
      throw "process exited before output contained '$Needle'. Exit code: $($Started.Process.ExitCode). Output: $text"
    }
    Start-Sleep -Milliseconds 200
  }

  throw "timed out waiting for output '$Needle'. Output: $(Get-StartedCommandText $Started)"
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

function Write-Utf8NoBomText {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [Parameter(Mandatory = $true)]
    [string]$Value
  )

  $encoding = [System.Text.UTF8Encoding]::new($false)
  [System.IO.File]::WriteAllText($Path, $Value, $encoding)
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
    Invoke-WindowsNodeStreamingSmoke
  } finally {
    Pop-Location
  }
}

function Invoke-WindowsNodeStreamingSmoke {
  Write-Host "== Windows Node binding spawn/watch streaming smoke =="

  $dataDir = Join-Path ([System.IO.Path]::GetTempPath()) "lsb-nodejs-streaming-$PID"
  Remove-Item -LiteralPath $dataDir -Recurse -Force -ErrorAction SilentlyContinue
  New-Item -ItemType Directory -Force -Path (Join-Path $dataDir "checkpoints") | Out-Null
  New-Item -ItemType Directory -Force -Path (Join-Path $dataDir "instances") | Out-Null

  $oldDataDir = $env:LSB_NODEJS_TEST_DATA_DIR
  $oldStorage = $env:LSB_STORAGE

  try {
    Copy-Item -LiteralPath $env:LSB_WINDOWS_BOOT_KERNEL -Destination (Join-Path $dataDir "Image") -Force
    Copy-Item -LiteralPath $env:LSB_WINDOWS_BOOT_INITRD -Destination (Join-Path $dataDir "initramfs.cpio.gz") -Force
    Copy-Item -LiteralPath $env:LSB_WINDOWS_BOOT_ROOTFS -Destination (Join-Path $dataDir "rootfs.ext4") -Force

    $packageVersion = (Get-Content -Raw -LiteralPath "package.json" | ConvertFrom-Json).version
    Write-Utf8NoBomText -Path (Join-Path $dataDir "VERSION") -Value "$packageVersion`n"

    $env:LSB_NODEJS_TEST_DATA_DIR = $dataDir
    $env:LSB_STORAGE = "direct"
    Invoke-YarnCommand @("ava", "test/streaming.spec.ts", "--timeout=3m")
  } finally {
    if ($null -eq $oldDataDir) {
      Remove-Item Env:\LSB_NODEJS_TEST_DATA_DIR -ErrorAction SilentlyContinue
    } else {
      $env:LSB_NODEJS_TEST_DATA_DIR = $oldDataDir
    }
    if ($null -eq $oldStorage) {
      Remove-Item Env:\LSB_STORAGE -ErrorAction SilentlyContinue
    } else {
      $env:LSB_STORAGE = $oldStorage
    }
    Remove-Item -LiteralPath $dataDir -Recurse -Force -ErrorAction SilentlyContinue
  }
}

function Invoke-WindowsCliRoOverlaySmoke {
  Write-Host "== Windows CLI :ro overlay compatibility smoke =="

  $source = Join-Path (Get-Location).Path "target\windows-smoke-cli-ro"
  Remove-Item -LiteralPath $source -Recurse -Force -ErrorAction SilentlyContinue
  New-Item -ItemType Directory -Force -Path (Join-Path $source "src") | Out-Null
  Write-Utf8NoBomText -Path (Join-Path $source "input.txt") -Value "cli-ro-host"
  Write-Utf8NoBomText -Path (Join-Path $source "src\nested.txt") -Value "cli-ro-nested"

  try {
    $mountSpec = "${source}:/workspace:ro"
    $guestScript = 'set -u; dump_workspace() { echo "cli-ro: workspace listing" >&2; ls -la /workspace >&2 || true; echo "cli-ro: workspace files" >&2; find /workspace -maxdepth 3 -type f -print >&2 || true; }; input="$(cat /workspace/input.txt 2>/tmp/cli-ro-input.err)"; input_status=$?; if [ "$input_status" -ne 0 ] || [ "$input" != "cli-ro-host" ]; then echo "cli-ro: expected /workspace/input.txt to be cli-ro-host, got: [$input]" >&2; cat /tmp/cli-ro-input.err >&2 || true; dump_workspace; exit 11; fi; nested="$(cat /workspace/src/nested.txt 2>/tmp/cli-ro-nested.err)"; nested_status=$?; if [ "$nested_status" -ne 0 ] || [ "$nested" != "cli-ro-nested" ]; then echo "cli-ro: expected /workspace/src/nested.txt to be cli-ro-nested, got: [$nested]" >&2; cat /tmp/cli-ro-nested.err >&2 || true; dump_workspace; exit 12; fi; if ! printf "guest-output" > /workspace/guest.txt; then echo "cli-ro: failed to write overlay-only guest file" >&2; dump_workspace; exit 13; fi; printf "cli-ro-overlay-ok\n"'
    Invoke-NativeCommand "cargo" @(
      "run",
      "-p",
      "lsb-cli",
      "--",
      "run",
      "--kernel",
      $env:LSB_WINDOWS_BOOT_KERNEL,
      "--initrd",
      $env:LSB_WINDOWS_BOOT_INITRD,
      "--rootfs",
      $env:LSB_WINDOWS_BOOT_ROOTFS,
      "--memory",
      "2048",
      "--disk-size",
      "4096",
      "--mount",
      $mountSpec,
      "--",
      "/bin/sh",
      "-c",
      $guestScript
    )

    $hostGuestWrite = Join-Path $source "guest.txt"
    if (Test-Path -LiteralPath $hostGuestWrite) {
      throw "CLI :ro overlay mount leaked guest write to host path $hostGuestWrite"
    }
  } finally {
    Remove-Item -LiteralPath $source -Recurse -Force -ErrorAction SilentlyContinue
  }
}

function Invoke-WindowsCliConsoleDirectSmbSmoke {
  Write-Host "== Windows CLI console direct SMB proxy smoke =="

  $source = Join-Path (Get-Location).Path "target\windows-smoke-cli-console-rw"
  Remove-Item -LiteralPath $source -Recurse -Force -ErrorAction SilentlyContinue
  New-Item -ItemType Directory -Force -Path $source | Out-Null
  Write-Utf8NoBomText -Path (Join-Path $source "input.txt") -Value "cli-console-rw-host"

  $started = $null
  try {
    $mountSpec = "${source}:/workspace:rw"
    $started = Start-NativeCommandOutput "cargo" @(
      "run",
      "-p",
      "lsb-cli",
      "--",
      "run",
      "--console",
      "--kernel",
      $env:LSB_WINDOWS_BOOT_KERNEL,
      "--initrd",
      $env:LSB_WINDOWS_BOOT_INITRD,
      "--rootfs",
      $env:LSB_WINDOWS_BOOT_ROOTFS,
      "--memory",
      "2048",
      "--disk-size",
      "4096",
      "--allow-host-writes",
      "--mount",
      $mountSpec
    )

    Wait-StartedCommandOutputContains -Started $started -Needle "lsb: VM started" -TimeoutSeconds 180
  } finally {
    if ($null -ne $started) {
      Stop-StartedCommand $started
    }
    try {
      Invoke-NativeCommand "cargo" @(
        "run",
        "-p",
        "lsb-cli",
        "--",
        "run",
        "--kernel",
        $env:LSB_WINDOWS_BOOT_KERNEL,
        "--initrd",
        $env:LSB_WINDOWS_BOOT_INITRD,
        "--rootfs",
        $env:LSB_WINDOWS_BOOT_ROOTFS,
        "--memory",
        "2048",
        "--disk-size",
        "4096",
        "--",
        "/bin/true"
      )
    } catch {
      Write-Warning "Best-effort stale cleanup trigger after CLI console smoke failed: $($_.Exception.Message)"
    }
    Remove-Item -LiteralPath $source -Recurse -Force -ErrorAction SilentlyContinue
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
  Write-Host "== Windows SMB policy doctor =="
  Invoke-NativeCommand "cargo" @("run", "-p", "lsb-cli", "--", "doctor", "windows-smb-policy", "--fix", "--yes")
  Invoke-WindowsNodeSmoke
  Invoke-WindowsCliRoOverlaySmoke
  Invoke-WindowsCliConsoleDirectSmbSmoke
  Write-Host "== Windows QEMU direct boot smoke =="
  Invoke-NativeCommand "cargo" @("test", "-p", "lsb-platform", "windows_qemu_boot_smoke", "--", "--ignored", "--nocapture")
  Write-Host "== Windows guest exec smoke =="
  Invoke-NativeCommand "cargo" @("test", "-p", "lsb-vm", "windows_qemu_exec_smoke", "--", "--ignored", "--nocapture")
  Write-Host "== Windows mux spawn/guest watch smoke =="
  Invoke-NativeCommand "cargo" @("test", "-p", "lsb-vm", "windows_qemu_spawn_guest_watch_smoke", "--", "--ignored", "--nocapture")
  Write-Host "== Windows guest copy transfer smoke =="
  Invoke-NativeCommand "cargo" @("test", "-p", "lsb-vm", "windows_qemu_copy_transfer_smoke", "--", "--ignored", "--nocapture")
  Write-Host "== Windows mount smoke =="
  Invoke-NativeCommand "cargo" @("test", "-p", "lsb-vm", "windows_qemu_mount_smoke", "--", "--ignored", "--nocapture")
  Write-Host "== Windows direct SMB failure cleanup smoke =="
  Invoke-NativeCommand "cargo" @("test", "-p", "lsb-vm", "windows_qemu_direct_smb_failure_cleanup_smoke", "--", "--ignored", "--nocapture")
  Write-Host "== Windows port-forward smoke =="
  Invoke-NativeCommand "cargo" @("test", "-p", "lsb-vm", "windows_qemu_port_forward_smoke", "--", "--ignored", "--nocapture")
  Write-Host "== Windows checkpoint/store smoke =="
  Invoke-NativeCommand "cargo" @("test", "-p", "lsb-sdk", "windows_qemu_checkpoint_store_smoke", "--", "--ignored", "--nocapture")
  Write-Host "== Windows direct SMB mount smoke =="
  Invoke-NativeCommand "cargo" @("test", "-p", "lsb-sdk", "windows_qemu_direct_smb_mount_smoke", "--", "--ignored", "--nocapture")
  Write-Host "== Windows network policy/proxy smoke =="
  Invoke-NativeCommand "cargo" @("test", "-p", "lsb-sdk", "windows_qemu_network_policy_proxy_smoke", "--", "--ignored", "--nocapture")
} else {
  Write-Warning "Skipping Windows Node binding, QEMU direct boot, guest exec, mux spawn/watch, guest copy transfer, mount, port-forward, checkpoint/store, direct SMB watch, and network policy/proxy smokes. Set $($missingBootVars -join ', ') to disposable LocalSandbox boot asset paths."
}
