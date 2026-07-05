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

Invoke-NativeCommand "cargo" @("test", "--workspace", "--locked")

# Future full suite:
# - boot VM
# - exec command
# - stream stdout/stderr
# - read/write files
# - mount source tree
# - port forwarding
# - no-network egress test
# - allow-net/proxy test
# - checkpoint save/restore
