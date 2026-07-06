$ErrorActionPreference = "Stop"

Write-Host "== Windows LSB e2e test =="

if (-not ("LsbE2E.ProcessOutputCollector" -as [type])) {
  Add-Type -TypeDefinition @'
namespace LsbE2E {
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

$script:RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$script:CargoManifest = Join-Path $script:RepoRoot "Cargo.toml"

function New-CommandResult {
  param(
    [Parameter(Mandatory = $true)]
    [int]$ExitCode,

    [object[]]$Output = @()
  )

  $lines = @($Output | ForEach-Object { $_.ToString() })
  return [pscustomobject]@{
    ExitCode = $ExitCode
    Output = $lines
    Text = ($lines -join "`n")
  }
}

function Invoke-NativeCommandOutput {
  param(
    [Parameter(Mandatory = $true)]
    [string]$FilePath,

    [Parameter(Mandatory = $true)]
    [string[]]$Arguments,

    [string]$WorkingDirectory = (Get-Location).Path,

    [int[]]$AllowedExitCodes = @(0)
  )

  Push-Location $WorkingDirectory
  try {
    $output = @(& $FilePath @Arguments 2>&1)
    $exitCode = $LASTEXITCODE
  } finally {
    Pop-Location
  }

  $result = New-CommandResult -ExitCode $exitCode -Output $output
  if ($AllowedExitCodes -notcontains $exitCode) {
    throw "$FilePath $($Arguments -join ' ') failed with exit code $exitCode. Output: $($result.Text)"
  }

  return $result
}

function Start-NativeCommandOutput {
  param(
    [Parameter(Mandatory = $true)]
    [string]$FilePath,

    [Parameter(Mandatory = $true)]
    [string[]]$Arguments,

    [Parameter(Mandatory = $true)]
    [string]$WorkingDirectory
  )

  $collector = [LsbE2E.ProcessOutputCollector]::new()
  $psi = [System.Diagnostics.ProcessStartInfo]::new()
  $psi.FileName = $FilePath
  $psi.WorkingDirectory = $WorkingDirectory
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  foreach ($argument in $Arguments) {
    [void]$psi.ArgumentList.Add($argument)
  }

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
    Command = "$FilePath $($Arguments -join ' ')"
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
}

function Wait-StartedCommand {
  param(
    [Parameter(Mandatory = $true)]
    [object]$Started,

    [int]$TimeoutSeconds = 180,

    [int[]]$AllowedExitCodes = @(0)
  )

  if (-not $Started.Process.WaitForExit($TimeoutSeconds * 1000)) {
    Stop-StartedCommand $Started
    throw "$($Started.Command) timed out after ${TimeoutSeconds}s. Output: $(Get-StartedCommandText $Started)"
  }

  $Started.Process.WaitForExit()
  $Started.Process.remove_OutputDataReceived($Started.OutputHandler)
  $Started.Process.remove_ErrorDataReceived($Started.ErrorHandler)

  $text = Get-StartedCommandText $Started
  if ($text.Length -gt 0) {
    $lines = @($text.TrimEnd("`r", "`n") -split "\r?\n")
  } else {
    $lines = @()
  }
  $result = New-CommandResult -ExitCode $Started.Process.ExitCode -Output $lines
  if ($AllowedExitCodes -notcontains $result.ExitCode) {
    throw "$($Started.Command) failed with exit code $($result.ExitCode). Output: $($result.Text)"
  }

  return $result
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
      $result = Wait-StartedCommand -Started $Started -AllowedExitCodes @(0..255)
      throw "process exited before output contained '$Needle'. Exit code: $($result.ExitCode). Output: $($result.Text)"
    }
    Start-Sleep -Milliseconds 200
  }

  throw "timed out waiting for output '$Needle'. Output: $(Get-StartedCommandText $Started)"
}

function Get-CargoPackageVersion {
  param(
    [Parameter(Mandatory = $true)]
    [string]$PackageName
  )

  Push-Location $script:RepoRoot
  try {
    $metadataJson = (& cargo metadata --locked --no-deps --format-version 1) -join "`n"
    if ($LASTEXITCODE -ne 0) {
      throw "cargo metadata failed with exit code $LASTEXITCODE"
    }
  } finally {
    Pop-Location
  }

  $metadataObject = $metadataJson | ConvertFrom-Json
  $package = @($metadataObject.packages | Where-Object { $_.name -eq $PackageName } | Select-Object -First 1)
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

function Get-CommonVmArgs {
  return @(
    "--config",
    $script:ConfigPath,
    "--cpus",
    "2",
    "--memory",
    "2048",
    "--disk-size",
    "4096"
  )
}

function Get-LsbCargoArgs {
  param(
    [Parameter(Mandatory = $true)]
    [string[]]$LsbArgs
  )

  return @(
    "run",
    "--manifest-path",
    $script:CargoManifest,
    "-p",
    "lsb-cli",
    "--locked",
    "--"
  ) + $LsbArgs
}

function Invoke-LsbCli {
  param(
    [Parameter(Mandatory = $true)]
    [string[]]$Arguments,

    [string]$WorkingDirectory = $script:WorkspaceRoot,

    [int[]]$AllowedExitCodes = @(0)
  )

  return Invoke-NativeCommandOutput `
    -FilePath "cargo" `
    -Arguments (Get-LsbCargoArgs $Arguments) `
    -WorkingDirectory $WorkingDirectory `
    -AllowedExitCodes $AllowedExitCodes
}

function Start-LsbCli {
  param(
    [Parameter(Mandatory = $true)]
    [string[]]$Arguments,

    [string]$WorkingDirectory = $script:WorkspaceRoot
  )

  return Start-NativeCommandOutput `
    -FilePath "cargo" `
    -Arguments (Get-LsbCargoArgs $Arguments) `
    -WorkingDirectory $WorkingDirectory
}

function Assert-Contains {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Text,

    [Parameter(Mandatory = $true)]
    [string]$Needle,

    [Parameter(Mandatory = $true)]
    [string]$Label
  )

  if (-not $Text.Contains($Needle)) {
    throw "$Label did not include '$Needle'. Output: $Text"
  }
}

function Assert-NotContains {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Text,

    [Parameter(Mandatory = $true)]
    [string]$Needle,

    [Parameter(Mandatory = $true)]
    [string]$Label
  )

  if ($Text.Contains($Needle)) {
    throw "$Label unexpectedly included '$Needle'. Output: $Text"
  }
}

function Set-Utf8NoBomText {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [Parameter(Mandatory = $true)]
    [string]$Value
  )

  $encoding = [System.Text.UTF8Encoding]::new($false)
  [System.IO.File]::WriteAllText($Path, $Value, $encoding)
}

function Get-FreeLoopbackPort {
  $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse("127.0.0.1"), 0)
  $listener.Start()
  try {
    return ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
  } finally {
    $listener.Stop()
  }
}

function Read-LoopbackTcpText {
  param(
    [Parameter(Mandatory = $true)]
    [int]$Port,

    [int]$TimeoutSeconds = 60,

    [object]$StartedCommand = $null
  )

  $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
  while ([DateTime]::UtcNow -lt $deadline) {
    if ($null -ne $StartedCommand -and $StartedCommand.Process.HasExited) {
      $result = Wait-StartedCommand -Started $StartedCommand -AllowedExitCodes @(0..255)
      throw "process exited before loopback port $Port responded. Exit code: $($result.ExitCode). Output: $($result.Text)"
    }

    $client = [System.Net.Sockets.TcpClient]::new()
    try {
      $connect = $client.BeginConnect("127.0.0.1", $Port, $null, $null)
      if (-not $connect.AsyncWaitHandle.WaitOne(500)) {
        $client.Close()
        Start-Sleep -Milliseconds 200
        continue
      }

      $client.EndConnect($connect)
      $stream = $client.GetStream()
      $stream.ReadTimeout = 5000
      $reader = [System.IO.StreamReader]::new($stream, [System.Text.Encoding]::UTF8)
      return $reader.ReadToEnd()
    } catch {
      Start-Sleep -Milliseconds 200
    } finally {
      $client.Close()
    }
  }

  throw "timed out connecting to 127.0.0.1:$Port"
}

function Invoke-LoopbackHttpText {
  param(
    [Parameter(Mandatory = $true)]
    [int]$Port,

    [Parameter(Mandatory = $true)]
    [object]$StartedCommand,

    [int]$TimeoutSeconds = 30
  )

  $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
  $lastError = $null
  while ([DateTime]::UtcNow -lt $deadline) {
    if ($StartedCommand.Process.HasExited) {
      $result = Wait-StartedCommand -Started $StartedCommand -AllowedExitCodes @(0..255)
      throw "process exited before loopback HTTP port $Port responded. Exit code: $($result.ExitCode). Output: $($result.Text)"
    }

    try {
      $curl = Invoke-NativeCommandOutput `
        -FilePath "curl.exe" `
        -Arguments @("-fsS", "--connect-timeout", "1", "--max-time", "5", "http://127.0.0.1:$Port/") `
        -WorkingDirectory $script:WorkspaceRoot
      return $curl.Text.Trim()
    } catch {
      $lastError = $_.Exception.Message
      Start-Sleep -Milliseconds 200
    }
  }

  throw "timed out fetching http://127.0.0.1:$Port/. Last error: $lastError. Process output: $(Get-StartedCommandText $StartedCommand)"
}

function Wait-ForFile {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [int]$TimeoutSeconds = 30
  )

  $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
  while ([DateTime]::UtcNow -lt $deadline) {
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
      return
    }
    Start-Sleep -Milliseconds 100
  }

  throw "timed out waiting for file: $Path"
}

function Start-HostHttpServerOnce {
  param(
    [Parameter(Mandatory = $true)]
    [int]$Port,

    [Parameter(Mandatory = $true)]
    [string]$ReadyFile,

    [Parameter(Mandatory = $true)]
    [string]$RequestFile,

    [Parameter(Mandatory = $true)]
    [string]$ResponseText
  )

  $job = Start-Job -ScriptBlock {
    param($Port, $ReadyFile, $RequestFile, $ResponseText)

    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse("127.0.0.1"), $Port)
    $listener.Start()
    Set-Content -LiteralPath $ReadyFile -Value "ready"
    try {
      $client = $listener.AcceptTcpClient()
      try {
        $stream = $client.GetStream()
        $stream.ReadTimeout = 10000
        $buffer = New-Object byte[] 8192
        $bytes = New-Object System.Collections.Generic.List[byte]
        while ($true) {
          $count = $stream.Read($buffer, 0, $buffer.Length)
          if ($count -le 0) {
            break
          }
          for ($i = 0; $i -lt $count; $i++) {
            $bytes.Add($buffer[$i])
          }
          $request = [System.Text.Encoding]::ASCII.GetString($bytes.ToArray())
          if ($request.Contains("`r`n`r`n")) {
            break
          }
        }

        Set-Content -LiteralPath $RequestFile -Value $request
        $body = [System.Text.Encoding]::UTF8.GetBytes($ResponseText)
        $headers = "HTTP/1.1 200 OK`r`nContent-Type: text/plain`r`nContent-Length: $($body.Length)`r`nConnection: close`r`n`r`n"
        $headerBytes = [System.Text.Encoding]::ASCII.GetBytes($headers)
        $stream.Write($headerBytes, 0, $headerBytes.Length)
        $stream.Write($body, 0, $body.Length)
        $stream.Flush()
      } finally {
        $client.Close()
      }
    } finally {
      $listener.Stop()
    }
  } -ArgumentList $Port, $ReadyFile, $RequestFile, $ResponseText

  Wait-ForFile -Path $ReadyFile -TimeoutSeconds 30
  return $job
}

function Complete-HostHttpServerOnce {
  param(
    [Parameter(Mandatory = $true)]
    [System.Management.Automation.Job]$Job,

    [Parameter(Mandatory = $true)]
    [string]$RequestFile
  )

  $completed = Wait-Job -Job $Job -Timeout 30
  if ($null -eq $completed) {
    Stop-Job -Job $Job -ErrorAction SilentlyContinue
    Remove-Job -Job $Job -Force -ErrorAction SilentlyContinue
    throw "host HTTP fixture did not receive a request"
  }

  $jobOutput = Receive-Job -Job $Job 2>&1
  $state = $Job.State
  Remove-Job -Job $Job -Force
  if ($state -ne "Completed") {
    throw "host HTTP fixture failed with state ${state}: $($jobOutput -join "`n")"
  }

  return Get-Content -Raw -LiteralPath $RequestFile
}

function Initialize-E2EWorkspace {
  param(
    [Parameter(Mandatory = $true)]
    [string]$HomeRoot,

    [Parameter(Mandatory = $true)]
    [string]$WorkspaceRoot,

    [Parameter(Mandatory = $true)]
    [string]$Kernel,

    [Parameter(Mandatory = $true)]
    [string]$Initrd,

    [Parameter(Mandatory = $true)]
    [string]$Rootfs
  )

  $dataDir = Join-Path $HomeRoot "AppData\Local\lsb"
  New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
  New-Item -ItemType Directory -Force -Path (Join-Path $dataDir "checkpoints") | Out-Null
  New-Item -ItemType Directory -Force -Path (Join-Path $dataDir "instances") | Out-Null
  New-Item -ItemType Directory -Force -Path $WorkspaceRoot | Out-Null

  Copy-Item -LiteralPath $Kernel -Destination (Join-Path $dataDir "Image") -Force
  Copy-Item -LiteralPath $Initrd -Destination (Join-Path $dataDir "initramfs.cpio.gz") -Force
  Copy-Item -LiteralPath $Rootfs -Destination (Join-Path $dataDir "rootfs.ext4") -Force

  $version = Get-CargoPackageVersion "lsb-sdk"
  Set-Content -LiteralPath (Join-Path $dataDir "VERSION") -Value "$version"
  $script:ConfigPath = Join-Path $WorkspaceRoot "lsb.json"
  Set-Content -LiteralPath $script:ConfigPath -Value "{}"
}

function Test-BasicRunAndNoNetwork {
  Write-Host "== E2E: boot, exec, stdout, and no-network default =="

  $bootScript = 'set -eu; printf "boot-ok\n"; uname -s; test -d /tmp; command -v curl >/dev/null'
  $boot = Invoke-LsbCli (@("run") + (Get-CommonVmArgs) + @("--", "/bin/sh", "-c", $bootScript))
  Assert-Contains -Text $boot.Text -Needle "boot-ok" -Label "boot run"
  Assert-Contains -Text $boot.Text -Needle "Linux" -Label "boot run"

  $noNetworkScript = 'set -eu; command -v curl >/dev/null; if curl -fsS --max-time 5 http://example.com/ >/tmp/e2e-egress.out 2>/tmp/e2e-egress.err; then echo unexpected-network-egress >&2; cat /tmp/e2e-egress.out >&2; exit 42; fi; printf "no-network-denied\n"'
  $noNetwork = Invoke-LsbCli (@("run") + (Get-CommonVmArgs) + @("--", "/bin/sh", "-c", $noNetworkScript))
  Assert-Contains -Text $noNetwork.Text -Needle "no-network-denied" -Label "no-network run"
}

function Test-MountWorkflow {
  Write-Host "== E2E: mounted project read with isolated guest writes =="

  $projectDir = Join-Path $script:WorkspaceRoot "project"
  New-Item -ItemType Directory -Force -Path (Join-Path $projectDir "src") | Out-Null
  Set-Utf8NoBomText -Path (Join-Path $projectDir "input.txt") -Value "host-input"
  Set-Utf8NoBomText -Path (Join-Path $projectDir "src\module.txt") -Value "nested-host-input"

  $mountSpec = "${projectDir}:/workspace"
  $mountScript = 'set -eu; test "$(cat /workspace/input.txt)" = "host-input"; test "$(cat /workspace/src/module.txt)" = "nested-host-input"; mkdir -p /workspace/out; printf "guest-output" > /workspace/out/result.txt; printf "mount-isolated-ok\n"'
  $result = Invoke-LsbCli (@("run") + (Get-CommonVmArgs) + @("--mount", $mountSpec, "--", "/bin/sh", "-c", $mountScript))
  Assert-Contains -Text $result.Text -Needle "mount-isolated-ok" -Label "mount run"

  $hostOutput = Join-Path $projectDir "out\result.txt"
  if (Test-Path -LiteralPath $hostOutput) {
    throw "guest write under /workspace escaped to host path $hostOutput"
  }
  $hostInput = (Get-Content -Raw -LiteralPath (Join-Path $projectDir "input.txt")).Trim()
  if ($hostInput -ne "host-input") {
    throw "host input was modified by mounted guest workflow: $hostInput"
  }
}

function Test-PortForwardWorkflow {
  Write-Host "== E2E: host-to-guest port forwarding without allow-net =="

  $hostPort = Get-FreeLoopbackPort
  $guestPort = 18180
  $responseBody = "lsb-e2e-port-ok"
  $responseLength = [System.Text.Encoding]::ASCII.GetByteCount($responseBody)
  $portScript = @'
set -eu
ready=/tmp/lsb-e2e-port-ready
rm -f "$ready"
response="$(printf 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: __RESPONSE_LENGTH__\r\nConnection: close\r\n\r\n__RESPONSE_BODY__')"
/usr/bin/lsb-init --lsb-test-tcp-server __GUEST_PORT__ "$response" "$ready" >/tmp/lsb-e2e-port.log 2>&1 &
server=$!
for i in $(seq 1 100); do
  if [ -f "$ready" ]; then
    printf "port-server-ready\n"
    break
  fi
  sleep 0.1
done
if [ ! -f "$ready" ]; then
  cat /tmp/lsb-e2e-port.log >&2 || true
  exit 1
fi
wait "$server"
'@.
    Replace("__GUEST_PORT__", $guestPort.ToString()).
    Replace("__RESPONSE_BODY__", $responseBody).
    Replace("__RESPONSE_LENGTH__", $responseLength.ToString())

  $started = Start-LsbCli (@("run") + (Get-CommonVmArgs) + @("-p", "${hostPort}:$guestPort", "--", "/bin/sh", "-c", $portScript))
  try {
    Wait-StartedCommandOutputContains `
      -Started $started `
      -Needle "lsb: forwarding 127.0.0.1:$hostPort -> guest:$guestPort" `
      -TimeoutSeconds 120
    Wait-StartedCommandOutputContains -Started $started -Needle "port-server-ready" -TimeoutSeconds 120
    $response = Invoke-LoopbackHttpText -Port $hostPort -StartedCommand $started -TimeoutSeconds 30
    if ($response -ne $responseBody) {
      throw "unexpected forwarded response: '$response'"
    }
    [void](Wait-StartedCommand -Started $started -TimeoutSeconds 120)
  } catch {
    Stop-StartedCommand $started
    throw
  }
}

function Test-ProxyExposeHostWorkflow {
  Write-Host "== E2E: scoped allow-net proxy to host.lsb.internal =="

  $hostPort = Get-FreeLoopbackPort
  $guestPort = 18181
  $readyFile = Join-Path $script:WorkspaceRoot "host-http.ready"
  $requestFile = Join-Path $script:WorkspaceRoot "host-http.request"
  Remove-Item -LiteralPath $readyFile, $requestFile -Force -ErrorAction SilentlyContinue

  $job = Start-HostHttpServerOnce `
    -Port $hostPort `
    -ReadyFile $readyFile `
    -RequestFile $requestFile `
    -ResponseText "host-expose-ok"

  try {
    $proxyScript = @'
set -eu
command -v curl >/dev/null
body="$(curl -fsS --max-time 20 "http://host.lsb.internal:__GUEST_PORT__/e2e")"
test "$body" = "host-expose-ok"
printf "proxy-expose-ok\n"
'@.Replace("__GUEST_PORT__", $guestPort.ToString())

    $result = Invoke-LsbCli (@("run") + (Get-CommonVmArgs) + @(
      "--allow-net",
      "--allow-host",
      "host.lsb.internal",
      "--expose-host",
      "${hostPort}:$guestPort",
      "--",
      "/bin/sh",
      "-c",
      $proxyScript
    ))
    Assert-Contains -Text $result.Text -Needle "proxy-expose-ok" -Label "proxy expose-host run"
    $request = Complete-HostHttpServerOnce -Job $job -RequestFile $requestFile
    Assert-Contains -Text $request -Needle "GET /e2e HTTP/" -Label "host HTTP request"
  } catch {
    Stop-Job -Job $job -ErrorAction SilentlyContinue
    Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    throw
  }
}

function Test-CheckpointWorkflow {
  Write-Host "== E2E: checkpoint create, resume, branch, and delete =="

  $baseName = "e2e-base-$PID"
  $branchName = "e2e-branch-$PID"

  $createBaseScript = 'set -eu; mkdir -p /workspace; printf "base-state" > /workspace/state.txt; sync; printf "checkpoint-base-created\n"'
  $baseCreate = Invoke-LsbCli (@("checkpoint", "create", $baseName) + (Get-CommonVmArgs) + @("--", "/bin/sh", "-c", $createBaseScript))
  Assert-Contains -Text $baseCreate.Text -Needle "checkpoint-base-created" -Label "checkpoint create"

  $list = Invoke-LsbCli @("checkpoint", "list")
  Assert-Contains -Text $list.Text -Needle $baseName -Label "checkpoint list"

  $resumeScript = 'set -eu; test "$(cat /workspace/state.txt)" = "base-state"; printf "ephemeral-state" > /workspace/ephemeral.txt; printf "checkpoint-resume-ok\n"'
  $resume = Invoke-LsbCli (@("run") + (Get-CommonVmArgs) + @("--from", $baseName, "--", "/bin/sh", "-c", $resumeScript))
  Assert-Contains -Text $resume.Text -Needle "checkpoint-resume-ok" -Label "checkpoint resume"

  $isolationScript = 'set -eu; test "$(cat /workspace/state.txt)" = "base-state"; test ! -e /workspace/ephemeral.txt; printf "checkpoint-ephemeral-isolated-ok\n"'
  $isolation = Invoke-LsbCli (@("run") + (Get-CommonVmArgs) + @("--from", $baseName, "--", "/bin/sh", "-c", $isolationScript))
  Assert-Contains -Text $isolation.Text -Needle "checkpoint-ephemeral-isolated-ok" -Label "checkpoint isolation"

  $createBranchScript = 'set -eu; test "$(cat /workspace/state.txt)" = "base-state"; printf "branch-state" > /workspace/branch.txt; sync; printf "checkpoint-branch-created\n"'
  $branchCreate = Invoke-LsbCli (@("checkpoint", "create", $branchName) + (Get-CommonVmArgs) + @("--from", $baseName, "--", "/bin/sh", "-c", $createBranchScript))
  Assert-Contains -Text $branchCreate.Text -Needle "checkpoint-branch-created" -Label "checkpoint branch create"

  $branchScript = 'set -eu; test "$(cat /workspace/state.txt)" = "base-state"; test "$(cat /workspace/branch.txt)" = "branch-state"; printf "checkpoint-branch-ok\n"'
  $branch = Invoke-LsbCli (@("run") + (Get-CommonVmArgs) + @("--from", $branchName, "--", "/bin/sh", "-c", $branchScript))
  Assert-Contains -Text $branch.Text -Needle "checkpoint-branch-ok" -Label "checkpoint branch resume"

  [void](Invoke-LsbCli @("checkpoint", "delete", $branchName))
  [void](Invoke-LsbCli @("checkpoint", "delete", $baseName))
  $afterDelete = Invoke-LsbCli @("checkpoint", "list")
  Assert-NotContains -Text $afterDelete.Text -Needle $branchName -Label "checkpoint list after delete"
  Assert-NotContains -Text $afterDelete.Text -Needle $baseName -Label "checkpoint list after delete"
}

function Invoke-WindowsCliE2E {
  Write-Host "== Windows lsb CLI user workflow e2e =="

  $kernel = Require-EnvFile "LSB_WINDOWS_BOOT_KERNEL"
  $initrd = Require-EnvFile "LSB_WINDOWS_BOOT_INITRD"
  $rootfs = Require-EnvFile "LSB_WINDOWS_BOOT_ROOTFS"

  $homeRoot = Join-Path ([System.IO.Path]::GetTempPath()) "lsb-cli-e2e-home-$PID"
  $workspaceRoot = Join-Path ([System.IO.Path]::GetTempPath()) "lsb-cli-e2e-workspace-$PID"
  Remove-Item -LiteralPath $homeRoot -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $workspaceRoot -Recurse -Force -ErrorAction SilentlyContinue

  $oldHome = [Environment]::GetEnvironmentVariable("HOME")
  try {
    $script:WorkspaceRoot = $workspaceRoot
    Initialize-E2EWorkspace `
      -HomeRoot $homeRoot `
      -WorkspaceRoot $workspaceRoot `
      -Kernel $kernel `
      -Initrd $initrd `
      -Rootfs $rootfs
    [Environment]::SetEnvironmentVariable("HOME", $homeRoot, "Process")

    Test-BasicRunAndNoNetwork
    Test-MountWorkflow
    Test-PortForwardWorkflow
    Test-ProxyExposeHostWorkflow
    Test-CheckpointWorkflow
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
