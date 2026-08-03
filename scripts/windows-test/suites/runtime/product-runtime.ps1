[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Normal', 'BeforeReboot', 'AfterReboot')]
    [string] $Phase,
    [Parameter(Mandatory = $true)][string] $RunRoot,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')]
    [string] $SnapshotSha
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($Phase -ne 'Normal') { throw 'product-runtime does not support reboot phases.' }

function Resolve-RegularFile {
    param([Parameter(Mandatory = $true)][string] $Path)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $item.Length -le 0) { throw "Runtime asset is not a regular non-empty file: $Path" }
    return $item.FullName
}

function Get-OwnedNetworkResources {
    return [ordered]@{
        users = @(Get-LocalUser -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -match '^lsb_[0-9a-f]+$'
        } | ForEach-Object Name | Sort-Object)
        shares = @(Get-SmbShare -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -match '^lsb-[a-z0-9-]+$'
        } | ForEach-Object Name | Sort-Object)
    }
}

function Invoke-FocusedTest {
    param(
        [Parameter(Mandatory = $true)][string] $Package,
        [Parameter(Mandatory = $true)][string] $Name,
        [string[]] $Features = @()
    )
    $arguments = @('test', '-p', $Package, '--locked')
    if ($Features.Count -gt 0) { $arguments += @('--features', ($Features -join ',')) }
    $arguments += @($Name, '--', '--ignored', '--exact', '--nocapture')
    $watch = [Diagnostics.Stopwatch]::StartNew()
    & cargo @arguments
    $exitCode = $LASTEXITCODE
    $watch.Stop()
    if ($exitCode -ne 0) { throw "Focused runtime test failed ($exitCode): $Name" }
    return [pscustomobject]@{
        name = $Name
        package = $Package
        duration_ms = [math]::Round($watch.Elapsed.TotalMilliseconds)
        status = 'passed'
    }
}

if ([string]::IsNullOrWhiteSpace($env:LSB_WINDOWS_TEST_ASSETS_ROOT)) {
    throw 'LSB_WINDOWS_TEST_ASSETS_ROOT is not configured by the Windows runner.'
}
$assets = [IO.Path]::GetFullPath($env:LSB_WINDOWS_TEST_ASSETS_ROOT)
$runtime = Join-Path $assets 'runtime'
$qemu = Join-Path $assets 'qemu'
$env:LSB_WINDOWS_BOOT_KERNEL = Resolve-RegularFile (Join-Path $runtime 'Image')
$env:LSB_WINDOWS_BOOT_INITRD = Resolve-RegularFile (Join-Path $runtime 'initramfs.cpio.gz')
$env:LSB_WINDOWS_BOOT_ROOTFS = Resolve-RegularFile (Join-Path $runtime 'rootfs.ext4')
$env:LSB_WINDOWS_BOOT_QEMU = Resolve-RegularFile (Join-Path $qemu 'qemu-system-x86_64.exe')
$env:LSB_QEMU = $env:LSB_WINDOWS_BOOT_QEMU
$env:LSB_QEMU_IMG = Resolve-RegularFile (Join-Path $qemu 'qemu-img.exe')
$env:LSB_WINDOWS_BOOT_ARTIFACT_DIR = Join-Path $RunRoot 'product-runtime-boot'

$before = Get-OwnedNetworkResources
$tests = [Collections.Generic.List[object]]::new()
$definitions = @(
    @('lsb-platform', 'windows_x86_64::qemu::boot::tests::windows_qemu_boot_smoke'),
    @('lsb-vm', 'sandbox::tests::windows_qemu_exec_smoke'),
    @('lsb-vm', 'sandbox::tests::windows_qemu_spawn_guest_watch_smoke'),
    @('lsb-vm', 'sandbox::tests::windows_qemu_copy_transfer_smoke'),
    @('lsb-vm', 'sandbox::tests::windows_qemu_mount_smoke'),
    @('lsb-vm', 'sandbox::tests::windows_qemu_direct_smb_failure_cleanup_smoke'),
    @('lsb-vm', 'sandbox::tests::windows_qemu_port_forward_smoke'),
    @('lsb-sdk', 'runtime::tests::windows_qemu_direct_smb_mount_smoke'),
    @('lsb-sdk', 'runtime::tests::windows_qemu_network_policy_proxy_smoke'),
    @('lsb-sdk', 'runtime::tests::windows_qemu_checkpoint_store_smoke')
)

try {
    foreach ($definition in $definitions) {
        $tests.Add((Invoke-FocusedTest -Package $definition[0] -Name $definition[1]))
        # WHPX teardown can remain briefly active after a process exits on the dedicated host.
        Start-Sleep -Milliseconds 750
    }
}
finally {
    $remainingQemu = @(Get-Process -Name 'qemu-system-x86_64' -ErrorAction SilentlyContinue)
    if ($remainingQemu.Count -gt 0) {
        throw "Product runtime left QEMU processes alive: $($remainingQemu.Id -join ',')"
    }
    $after = Get-OwnedNetworkResources
    if (Compare-Object @($before.users) @($after.users)) {
        throw 'Product runtime did not restore its test-owned local users.'
    }
    if (Compare-Object @($before.shares) @($after.shares)) {
        throw 'Product runtime did not restore its test-owned SMB shares.'
    }
}

[ordered]@{
    schema_version = 1
    status = 'passed'
    snapshot_sha = $SnapshotSha
    suite = 'product-runtime'
    tests = @($tests)
    acceptance_checks = @(
        'win01.whpx_qemu_boot_exec_stop', 'mnt01.admin_live', 'mnt01.nonadmin_staged',
        'net02.host_relay', 'net02.ports_wfp', 'sec02.reconciliation'
    )
    assets = [ordered]@{
        kernel_sha256 = (Get-FileHash $env:LSB_WINDOWS_BOOT_KERNEL -Algorithm SHA256).Hash.ToLowerInvariant()
        initrd_sha256 = (Get-FileHash $env:LSB_WINDOWS_BOOT_INITRD -Algorithm SHA256).Hash.ToLowerInvariant()
        rootfs_sha256 = (Get-FileHash $env:LSB_WINDOWS_BOOT_ROOTFS -Algorithm SHA256).Hash.ToLowerInvariant()
        qemu_sha256 = (Get-FileHash $env:LSB_WINDOWS_BOOT_QEMU -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    cleanup = [ordered]@{ qemu_processes = 0; users_restored = $true; shares_restored = $true }
} | ConvertTo-Json -Depth 10 | Set-Content `
    -LiteralPath (Join-Path $RunRoot 'evidence-product-runtime.json') -Encoding utf8NoBOM
