Set-StrictMode -Version Latest

$script:WindowsTestOwner = 'local-sandbox-agent-test-flow'
$script:WindowsTestMarkerName = '.local-sandbox-agent-test-root.json'

function Read-WindowsTestJson {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [int64] $MaximumBytes = 1MB
    )
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $item.Length -le 0 -or $item.Length -gt $MaximumBytes) {
        throw "JSON input is not a bounded regular file: $Path"
    }
    try { return Get-Content -LiteralPath $item.FullName -Raw | ConvertFrom-Json }
    catch { throw "JSON input is invalid: $Path`: $($_.Exception.Message)" }
}

function Write-WindowsTestJsonAtomic {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][object] $Value
    )
    $pending = "$Path.pending-$PID"
    $Value | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $pending -Encoding utf8NoBOM
    Move-Item -LiteralPath $pending -Destination $Path -Force
}

function Resolve-WindowsTestOwnedRoot {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][ValidateSet('local-sandbox-agent', 'local-sandbox-agent-state')]
        [string] $ExpectedLeaf
    )
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
    $volume = [IO.Path]::GetPathRoot($full).TrimEnd('\', '/')
    if ($full.Equals($volume, [StringComparison]::OrdinalIgnoreCase) -or
        (Split-Path -Leaf $full) -cne $ExpectedLeaf) {
        throw "Owned root must end in '$ExpectedLeaf' and cannot be a volume root: $full"
    }
    $markerPath = Join-Path $full $script:WindowsTestMarkerName
    $marker = Read-WindowsTestJson -Path $markerPath -MaximumBytes 16KB
    if ($marker.schema_version -ne 1 -or $marker.owner -cne $script:WindowsTestOwner) {
        throw "Owned root marker is invalid: $markerPath"
    }
    return $full
}

function Assert-WindowsTestDescendant {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $Root
    )
    $resolvedRoot = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    $resolvedPath = [IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
    if (-not $resolvedPath.StartsWith("$resolvedRoot\", [StringComparison]::OrdinalIgnoreCase)) {
        throw "Path escapes its owned root: $resolvedPath"
    }
    return $resolvedPath
}

function Assert-WindowsTestAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'This Windows test-host operation requires an elevated administrator token.'
    }
}

function Get-WindowsTestCatalog {
    param([string] $Path = (Join-Path (Split-Path -Parent $PSScriptRoot) 'catalog.json'))
    $catalog = Read-WindowsTestJson -Path $Path
    if ($catalog.schema_version -ne 1) { throw 'Unsupported Windows test catalog schema.' }
    return $catalog
}

function Get-WindowsTestDirectorySize {
    param([Parameter(Mandatory = $true)][string] $Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return [int64]0 }
    $sum = [int64]0
    foreach ($file in @(Get-ChildItem -LiteralPath $Path -File -Recurse -Force -ErrorAction Stop)) {
        if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Owned tree contains a reparse-point file: $($file.FullName)"
        }
        $sum += $file.Length
    }
    return $sum
}
