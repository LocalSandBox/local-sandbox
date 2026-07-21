[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Prepare', 'Commit', 'Verify', 'Abort', 'Remove')]
    [string] $Mode,

    [ValidatePattern('^[a-z0-9][a-z0-9._-]{0,95}$')]
    [string] $StageName,

    [string] $StateRoot = (Join-Path $env:ProgramData 'LocalSandbox\DevTest')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$owner = 'local-sandbox-agent-runtime-flow'
$rootMarkerName = '.local-sandbox-runtime-assets.json'
$stageMarkerName = '.local-sandbox-runtime-stage.json'
$qemuUrl = 'https://github.com/LocalSandBox/local-sandbox/releases/download/qemu-windows-x86_64-v11.0.50-lsb0.4.0/lsb-qemu-windows-x86_64-qemu-11.0.50-lsb0.4.0.tar.gz'
$qemuSha256 = '49021ed8481ad8bc3e2d71ab3d088e60414ec2bb78654c96f6da33b2dd0c6251'
$qemuTopLevel = 'qemu-11.0.50-lsb0.4.0'

function Assert-PlainDirectory {
    param([string] $Path, [string] $Label)
    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "$Label must be a regular non-reparse directory"
    }
    return $item
}

function Assert-PlainFile {
    param([string] $Path, [string] $Label, [long] $MaximumBytes)
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $item.Length -le 0 -or $item.Length -gt $MaximumBytes) {
        throw "$Label must be a bounded regular non-reparse file"
    }
    return $item
}

function Assert-X86KernelImage {
    param([string] $Path)
    $bytes = [byte[]]::new(0x206)
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $read = $stream.Read($bytes, 0, $bytes.Length)
    }
    finally {
        $stream.Dispose()
    }
    if ($read -ne $bytes.Length -or
        $bytes[0x1fe] -ne 0x55 -or $bytes[0x1ff] -ne 0xaa -or
        $bytes[0x202] -ne 0x48 -or $bytes[0x203] -ne 0x64 -or
        $bytes[0x204] -ne 0x72 -or $bytes[0x205] -ne 0x53) {
        throw 'Kernel Image is not an x86_64 Linux boot-protocol image.'
    }
}

function Write-Marker {
    param([string] $Path, [string] $Kind)
    [ordered]@{ schema_version = 1; owner = $owner; kind = $Kind } |
        ConvertTo-Json | Set-Content -LiteralPath $Path -Encoding utf8NoBOM
}

function Assert-Marker {
    param([string] $Path, [string] $Kind)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw 'Runtime asset ownership marker is missing.' }
    $marker = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ($marker.schema_version -ne 1 -or $marker.owner -ne $owner -or $marker.kind -ne $Kind) {
        throw 'Runtime asset ownership marker is invalid.'
    }
}

function Get-RuntimeInfo {
    param([string] $AssetsRoot)
    $runtime = Assert-PlainDirectory (Join-Path $AssetsRoot 'runtime') 'runtime asset root'
    $qemu = Assert-PlainDirectory (Join-Path $AssetsRoot 'qemu') 'QEMU asset root'
    $files = [ordered]@{}
    foreach ($name in @('Image', 'initramfs.cpio.gz', 'rootfs.ext4')) {
        $path = Join-Path $runtime.FullName $name
        Assert-PlainFile $path "runtime asset $name" 16GB | Out-Null
        $files[$name] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    Assert-X86KernelImage (Join-Path $runtime.FullName 'Image')
    foreach ($name in @('qemu-system-x86_64.exe', 'qemu-img.exe')) {
        Assert-PlainFile (Join-Path $qemu.FullName $name) "QEMU asset $name" 1GB | Out-Null
    }
    return [ordered]@{
        schema_version = 1
        status = 'ready'
        runtime_hashes = $files
        qemu_package_sha256 = $qemuSha256
        qemu_package = $qemuTopLevel
    }
}

$state = [IO.Path]::GetFullPath($StateRoot).TrimEnd('\', '/')
if ((Split-Path -Leaf $state) -cne 'DevTest' -or
    -not (Test-Path -LiteralPath (Join-Path $state '.local-sandbox-agent-test-root.json') -PathType Leaf)) {
    throw 'The Windows test state root is not initialized.'
}
$assets = Join-Path $state 'assets'
Assert-PlainDirectory $assets 'test asset root' | Out-Null
$runtimeRoot = Join-Path $assets 'runtime'
$qemuRoot = Join-Path $assets 'qemu'
$rootMarker = Join-Path $assets $rootMarkerName
if ($Mode -in @('Prepare', 'Commit', 'Abort') -and [string]::IsNullOrWhiteSpace($StageName)) {
    throw 'StageName is required for Prepare, Commit, and Abort.'
}
$stage = if ([string]::IsNullOrWhiteSpace($StageName)) { $null } else { Join-Path $assets ".runtime-stage-$StageName" }
$stageMarker = if ($null -eq $stage) { $null } else { Join-Path $stage $stageMarkerName }

switch ($Mode) {
    'Prepare' {
        if ((Test-Path -LiteralPath $runtimeRoot) -or (Test-Path -LiteralPath $qemuRoot) -or
            (Test-Path -LiteralPath $rootMarker)) {
            throw 'Runtime assets are already provisioned; use Verify instead.'
        }
        if (Test-Path -LiteralPath $stage) { throw 'The runtime staging directory already exists.' }
        New-Item -ItemType Directory -Path $stage | Out-Null
        Write-Marker $stageMarker 'stage'
        [ordered]@{ status = 'prepared' } | ConvertTo-Json -Compress
    }
    'Commit' {
        Assert-PlainDirectory $stage 'runtime staging root' | Out-Null
        Assert-Marker $stageMarker 'stage'
        $expected = @($stageMarkerName, 'runtime-assets.tar.gz')
        $entries = @(Get-ChildItem -LiteralPath $stage -Force)
        if ($entries.Count -ne $expected.Count -or
            @($entries | Where-Object { $expected -notcontains $_.Name }).Count -ne 0) {
            throw 'The runtime staging directory contains an unexpected entry.'
        }
        $runtimeArchive = Join-Path $stage 'runtime-assets.tar.gz'
        Assert-PlainFile $runtimeArchive 'runtime asset archive' 16GB | Out-Null
        $runtimeEntries = @(& tar.exe -tzf $runtimeArchive | ForEach-Object {
            ([string]$_).Trim().Replace('\', '/')
        })
        $expectedRuntimeEntries = @('Image', 'initramfs.cpio.gz', 'rootfs.ext4')
        if ($LASTEXITCODE -ne 0 -or $runtimeEntries.Count -ne $expectedRuntimeEntries.Count -or
            @($runtimeEntries | Where-Object { $expectedRuntimeEntries -cnotcontains $_ }).Count -ne 0) {
            $observedNames = @($runtimeEntries | ForEach-Object {
                if ($_ -match '^[A-Za-z0-9._-]{1,64}$') { $_ } else { '<invalid>' }
            }) -join ','
            throw "The runtime archive does not contain the exact closed asset set (observed: $observedNames)."
        }
        $runtimeExtract = Join-Path $stage 'runtime-extract'
        New-Item -ItemType Directory -Path $runtimeExtract | Out-Null
        & tar.exe -xzf $runtimeArchive -C $runtimeExtract
        if ($LASTEXITCODE -ne 0) { throw "Extracting runtime assets failed with exit code $LASTEXITCODE" }
        Assert-PlainFile (Join-Path $runtimeExtract 'Image') 'kernel image' 1GB | Out-Null
        Assert-X86KernelImage (Join-Path $runtimeExtract 'Image')
        Assert-PlainFile (Join-Path $runtimeExtract 'initramfs.cpio.gz') 'initramfs' 2GB | Out-Null
        Assert-PlainFile (Join-Path $runtimeExtract 'rootfs.ext4') 'root filesystem' 16GB | Out-Null
        $archive = Join-Path $stage 'qemu.tar.gz'
        Invoke-WebRequest -Uri $qemuUrl -OutFile $archive
        if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -cne $qemuSha256) {
            throw 'The managed QEMU archive hash does not match the pinned package.'
        }
        $extract = Join-Path $stage 'qemu-extract'
        New-Item -ItemType Directory -Path $extract | Out-Null
        & tar.exe -xzf $archive -C $extract
        if ($LASTEXITCODE -ne 0) { throw "Extracting managed QEMU failed with exit code $LASTEXITCODE" }
        $qemuSource = Join-Path $extract $qemuTopLevel
        Assert-PlainDirectory $qemuSource 'extracted QEMU package' | Out-Null
        Assert-PlainFile (Join-Path $qemuSource 'qemu-system-x86_64.exe') 'QEMU executable' 1GB | Out-Null
        Assert-PlainFile (Join-Path $qemuSource 'qemu-img.exe') 'QEMU image tool' 1GB | Out-Null
        if ((Test-Path -LiteralPath $runtimeRoot) -or (Test-Path -LiteralPath $qemuRoot) -or
            (Test-Path -LiteralPath $rootMarker)) {
            throw 'Refusing to overwrite a runtime asset destination created after staging.'
        }
        $runtimeCreated = $false
        $qemuMoved = $false
        try {
            New-Item -ItemType Directory -Path $runtimeRoot | Out-Null
            $runtimeCreated = $true
            foreach ($name in @('Image', 'initramfs.cpio.gz', 'rootfs.ext4')) {
                Move-Item -LiteralPath (Join-Path $runtimeExtract $name) -Destination (Join-Path $runtimeRoot $name)
            }
            Move-Item -LiteralPath $qemuSource -Destination $qemuRoot
            $qemuMoved = $true
            Write-Marker $rootMarker 'installed'
            Remove-Item -LiteralPath $stage -Recurse -Force
        }
        catch {
            if (Test-Path -LiteralPath $rootMarker) {
                Remove-Item -LiteralPath $rootMarker -Force
            }
            if ($qemuMoved -and (Test-Path -LiteralPath $qemuRoot)) {
                Remove-Item -LiteralPath $qemuRoot -Recurse -Force
            }
            if ($runtimeCreated -and (Test-Path -LiteralPath $runtimeRoot)) {
                Remove-Item -LiteralPath $runtimeRoot -Recurse -Force
            }
            throw
        }
        Get-RuntimeInfo $assets | ConvertTo-Json -Depth 5 -Compress
    }
    'Verify' {
        Assert-Marker $rootMarker 'installed'
        Get-RuntimeInfo $assets | ConvertTo-Json -Depth 5 -Compress
    }
    'Abort' {
        if (Test-Path -LiteralPath $stage) {
            Assert-PlainDirectory $stage 'runtime staging root' | Out-Null
            Assert-Marker $stageMarker 'stage'
            Remove-Item -LiteralPath $stage -Recurse -Force
        }
        [ordered]@{ status = 'aborted' } | ConvertTo-Json -Compress
    }
    'Remove' {
        Assert-Marker $rootMarker 'installed'
        Assert-PlainDirectory $runtimeRoot 'runtime asset root' | Out-Null
        Assert-PlainDirectory $qemuRoot 'QEMU asset root' | Out-Null
        Remove-Item -LiteralPath $runtimeRoot -Recurse -Force
        Remove-Item -LiteralPath $qemuRoot -Recurse -Force
        Remove-Item -LiteralPath $rootMarker -Force
        [ordered]@{ status = 'removed' } | ConvertTo-Json -Compress
    }
}
