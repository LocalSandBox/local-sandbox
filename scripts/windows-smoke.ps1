$ErrorActionPreference = "Stop"

Write-Host "== Windows LSB smoke test =="

cargo run -p lsb-cli -- --help

function Invoke-YarnCommand {
  param(
    [Parameter(Mandatory = $true)]
    [string[]]$YarnArgs
  )

  $corepack = Get-Command corepack -ErrorAction SilentlyContinue
  if ($corepack) {
    & corepack yarn @YarnArgs
  } else {
    Write-Warning "corepack was not found on PATH; falling back to npx corepack."
    & npx --yes corepack@latest yarn @YarnArgs
  }

  if ($LASTEXITCODE -ne 0) {
    throw "yarn $($YarnArgs -join ' ') failed with exit code $LASTEXITCODE"
  }
}

function Invoke-NodeCommand {
  param(
    [Parameter(Mandatory = $true)]
    [string[]]$NodeArgs
  )

  & node @NodeArgs
  if ($LASTEXITCODE -ne 0) {
    throw "node $($NodeArgs -join ' ') failed with exit code $LASTEXITCODE"
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
    Invoke-NodeCommand @("scripts/windows-preflight-smoke.mjs")
  } finally {
    Pop-Location
  }
}

Write-Host "== Windows QEMU preflight smoke =="
$env:LSB_TEST_REAL_QEMU = "1"
cargo test -p lsb-platform real_qemu_preflight_when_explicitly_enabled -- --ignored --nocapture

$bootVars = @(
  "LSB_WINDOWS_BOOT_KERNEL",
  "LSB_WINDOWS_BOOT_INITRD",
  "LSB_WINDOWS_BOOT_ROOTFS"
)
$missingBootVars = @($bootVars | Where-Object { -not [Environment]::GetEnvironmentVariable($_) })
if ($missingBootVars.Count -eq 0) {
  Invoke-WindowsNodeSmoke
  Write-Host "== Windows QEMU direct boot smoke =="
  cargo test -p lsb-platform windows_qemu_boot_smoke -- --ignored --nocapture
  Write-Host "== Windows guest exec smoke =="
  cargo test -p lsb-vm windows_qemu_exec_smoke -- --ignored --nocapture
  Write-Host "== Windows guest copy transfer smoke =="
  cargo test -p lsb-vm windows_qemu_copy_transfer_smoke -- --ignored --nocapture
  Write-Host "== Windows mount MVP smoke =="
  cargo test -p lsb-vm windows_qemu_mount_mvp_smoke -- --ignored --nocapture
  Write-Host "== Windows port-forward smoke =="
  cargo test -p lsb-vm windows_qemu_port_forward_smoke -- --ignored --nocapture
  Write-Host "== Windows checkpoint/store smoke =="
  cargo test -p lsb-sdk windows_qemu_checkpoint_store_smoke -- --ignored --nocapture
  Write-Host "== Windows network policy/proxy smoke =="
  cargo test -p lsb-sdk windows_qemu_network_policy_proxy_smoke -- --ignored --nocapture
} else {
  Write-Warning "Skipping Windows Node binding, QEMU direct boot, guest exec, guest copy transfer, mount MVP, port-forward, checkpoint/store, and network policy/proxy smokes. Set $($missingBootVars -join ', ') to disposable LocalSandbox boot asset paths."
}

# Later:
# cargo run -p lsb-cli -- run --port 8080:8080 -- your-network-policy-test
