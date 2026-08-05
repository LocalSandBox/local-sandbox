[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Normal', 'BeforeReboot', 'AfterReboot')]
    [string] $Phase,

    [Parameter(Mandatory = $true)]
    [string] $RunRoot,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string] $SnapshotSha
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($Phase -ne 'Normal') { throw 'office-rootfs-smoke does not support reboot phases.' }

function Resolve-RegularFile {
    param([string] $Path, [string] $Label)
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "$Label must be a regular non-reparse file: $Path"
    }
    return $item.FullName
}

$assets = [IO.Path]::GetFullPath($env:LSB_WINDOWS_TEST_ASSETS_ROOT)
$runtime = Join-Path $assets 'runtime'
$qemu = Join-Path $assets 'qemu'
$kernel = Resolve-RegularFile (Join-Path $runtime 'Image') 'kernel image'
$initrd = Resolve-RegularFile (Join-Path $runtime 'initramfs.cpio.gz') 'initramfs'
$rootfs = Resolve-RegularFile (Join-Path $runtime 'rootfs.ext4') 'root filesystem'
$env:LSB_QEMU = Resolve-RegularFile (Join-Path $qemu 'qemu-system-x86_64.exe') 'QEMU executable'
$env:LSB_QEMU_IMG = Resolve-RegularFile (Join-Path $qemu 'qemu-img.exe') 'QEMU image executable'
$metricsPath = Join-Path $RunRoot 'office-rootfs-mount-metrics.json'
$env:LSB_WINDOWS_MOUNT_METRICS_PATH = $metricsPath

& cargo build -p lsb-cli --release --locked
if ($LASTEXITCODE -ne 0) { throw "lsb-cli release build failed with exit code $LASTEXITCODE" }
$binary = Resolve-RegularFile (Join-Path $env:CARGO_TARGET_DIR 'release\lsb.exe') 'lsb CLI'
$fixtureRoot = [IO.Path]::GetFullPath((Join-Path (Get-Location) 'fixtures'))
$mount = "${fixtureRoot}:/workspace:ro"
$arguments = @(
    'run',
    '--kernel', $kernel,
    '--initrd', $initrd,
    '--rootfs', $rootfs,
    '--allow-net',
    '--allow-host', 'registry.npmjs.org',
    '--mount', $mount,
    '--', '/usr/bin/env', 'LSB_SMOKE_NETWORK=1', 'node',
    '/workspace/office-rootfs-smoke.mjs'
)

$stopwatch = [Diagnostics.Stopwatch]::StartNew()
$output = @(& $binary @arguments)
$exitCode = $LASTEXITCODE
$stopwatch.Stop()
if ($exitCode -ne 0) { throw "office rootfs smoke failed with exit code $exitCode" }
$guest = ($output -join "`n") | ConvertFrom-Json
if ($guest.status -ne 'passed' -or $guest.architecture -ne 'x64' -or
    $guest.versions.bun -notmatch '^1\.' -or $guest.versions.node -notmatch '^v24\.' -or
    $guest.versions.python -notmatch '^Python 3\.' -or
    $guest.versions.uv -notmatch '^uv 0\.11\.32$' -or
    $guest.versions.uvx -notmatch '^uvx 0\.11\.32$') {
    throw 'office rootfs smoke returned invalid runtime evidence.'
}
if (-not (Test-Path -LiteralPath $metricsPath -PathType Leaf)) {
    throw 'office rootfs smoke did not write Windows boot and mount metrics.'
}
$metrics = Get-Content -LiteralPath $metricsPath -Raw | ConvertFrom-Json

[ordered]@{
    schema_version = 1
    status = 'passed'
    snapshot_sha = $SnapshotSha
    external_duration_ms = [math]::Round($stopwatch.Elapsed.TotalMilliseconds, 3)
    rootfs_size_bytes = (Get-Item -LiteralPath $rootfs).Length
    rootfs_sha256 = (Get-FileHash -LiteralPath $rootfs -Algorithm SHA256).Hash.ToLowerInvariant()
    guest = $guest
    startup_metrics = $metrics
} | ConvertTo-Json -Depth 20 | Set-Content `
    -LiteralPath (Join-Path $RunRoot 'evidence-office-rootfs-smoke.json') -Encoding utf8NoBOM
