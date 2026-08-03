[CmdletBinding()]
param(
    [string] $Root = 'C:\dev\local-sandbox-agent',
    [string] $StateRoot = 'C:\dev\local-sandbox-agent-state',
    [switch] $DryRun,
    [ValidatePattern('^[1-9][0-9]*d$')][string] $OlderThan = '14d',
    [ValidateRange(1, 1000)][int] $Keep = 20,
    [ValidateRange(1, 4096)][int] $CacheMaxGiB = 80,
    [ValidateRange(1, 4096)][int] $MinimumFreeGiB = 25
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'lib\common.ps1')

function Assert-PlainDirectory {
    param([Parameter(Mandatory = $true)][string] $Path)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Prune target is not a plain directory: $Path"
    }
    return $item
}

function Remove-PruneTarget {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $AllowedRoot,
        [Parameter(Mandatory = $true)][string] $Kind
    )
    $resolved = Assert-WindowsTestDescendant -Path $Path -Root $AllowedRoot
    $item = Assert-PlainDirectory -Path $resolved
    $bytes = Get-WindowsTestDirectorySize -Path $item.FullName
    $script:actions.Add([pscustomobject]@{
        kind = $Kind; path = $item.FullName; bytes = $bytes; dry_run = [bool]$DryRun
    })
    if (-not $DryRun) { Remove-Item -LiteralPath $item.FullName -Recurse -Force -ErrorAction Stop }
    return $bytes
}

$rootPath = Resolve-WindowsTestOwnedRoot -Path $Root -ExpectedLeaf 'local-sandbox-agent'
$statePath = Resolve-WindowsTestOwnedRoot -Path $StateRoot -ExpectedLeaf 'local-sandbox-agent-state'
$runsRoot = Assert-WindowsTestDescendant -Path (Join-Path $statePath 'runs') -Root $statePath
$cacheRoot = Assert-WindowsTestDescendant -Path (Join-Path $rootPath 'cache') -Root $rootPath
Assert-PlainDirectory -Path $runsRoot | Out-Null
Assert-PlainDirectory -Path $cacheRoot | Out-Null

$lockPath = Join-Path $statePath 'locks\runner.lock'
$lock = $null
try {
    $lock = [IO.File]::Open(
        $lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None
    )
}
catch [IO.IOException] {
    throw 'Refusing to prune while a Windows test run owns the exclusive host lock.'
}

$actions = [Collections.Generic.List[object]]::new()
$protected = [Collections.Generic.List[object]]::new()
$releasedBytes = [int64]0
try {
    $runs = @(Get-ChildItem -LiteralPath $runsRoot -Directory -Force | Sort-Object LastWriteTimeUtc -Descending)
    $newest = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($run in @($runs | Select-Object -First $Keep)) { $newest.Add($run.Name) | Out-Null }
    $referencedCandidates = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($run in $runs) {
        foreach ($name in @('continuation.json', 'profile-result.json', 'run-metadata.json')) {
            $path = Join-Path $run.FullName $name
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
            try {
                $value = Read-WindowsTestJson -Path $path -MaximumBytes 256KB
                foreach ($property in @('reuse_run_id', 'candidate_run_id', 'source_run_id')) {
                    $member = $value.PSObject.Properties[$property]
                    if ($null -ne $member -and [string]$member.Value -match '^[a-z0-9][a-z0-9._-]{0,95}$') {
                        $referencedCandidates.Add([string]$member.Value) | Out-Null
                    }
                }
            }
            catch {
                $protected.Add([pscustomobject]@{ run_id = $run.Name; reason = "invalid-$name" })
            }
        }
    }

    $days = [int]$OlderThan.Substring(0, $OlderThan.Length - 1)
    $cutoff = [DateTime]::UtcNow.AddDays(-$days)
    foreach ($run in $runs) {
        if ($run.Name -notmatch '^[a-z0-9][a-z0-9._-]{0,95}$') {
            $protected.Add([pscustomobject]@{ run_id = $run.Name; reason = 'unsafe-name' })
            continue
        }
        $reason = $null
        if ($newest.Contains($run.Name)) { $reason = 'newest-retention' }
        elseif ($run.LastWriteTimeUtc -ge $cutoff) { $reason = 'age-retention' }
        elseif (Test-Path -LiteralPath (Join-Path $run.FullName 'active.json') -PathType Leaf) {
            $reason = 'active'
        }
        elseif (Test-Path -LiteralPath (Join-Path $run.FullName 'pinned.json') -PathType Leaf) {
            $reason = 'pinned'
        }
        elseif ($referencedCandidates.Contains($run.Name)) { $reason = 'referenced-candidate' }
        else {
            $continuationPath = Join-Path $run.FullName 'continuation.json'
            if (Test-Path -LiteralPath $continuationPath -PathType Leaf) {
                try {
                    $continuation = Read-WindowsTestJson -Path $continuationPath -MaximumBytes 64KB
                    if ($continuation.status -eq 'awaiting_reboot') { $reason = 'pending-reboot' }
                }
                catch { $reason = 'invalid-continuation' }
            }
        }
        if ($null -ne $reason) {
            $protected.Add([pscustomobject]@{ run_id = $run.Name; reason = $reason })
            continue
        }

        # Remove large, reproducible build trees before the evidence envelope and summaries.
        foreach ($relative in @('release-work', 'archive-acceptance-work', 'build', 'target')) {
            $large = Join-Path $run.FullName $relative
            if (Test-Path -LiteralPath $large -PathType Container) {
                $largeBytes = Remove-PruneTarget -Path $large -AllowedRoot $runsRoot -Kind 'run-build'
                if (-not $DryRun) { $releasedBytes += $largeBytes }
            }
        }
        if (-not $DryRun -and -not (Test-Path -LiteralPath $run.FullName)) { continue }
        $releasedBytes += Remove-PruneTarget -Path $run.FullName -AllowedRoot $runsRoot -Kind 'run-envelope'
    }

    $cacheBytes = Get-WindowsTestDirectorySize -Path $cacheRoot
    $driveName = [IO.Path]::GetPathRoot($cacheRoot).Substring(0, 1)
    $freeBytes = (Get-PSDrive -Name $driveName).Free
    $cacheThresholdCrossed = $cacheBytes -gt ([int64]$CacheMaxGiB * 1GB) -or
        $freeBytes -lt ([int64]$MinimumFreeGiB * 1GB)
    if ($cacheThresholdCrossed) {
        foreach ($entry in @(Get-ChildItem -LiteralPath $cacheRoot -Directory -Force |
            Sort-Object LastWriteTimeUtc)) {
            $releasedBytes += Remove-PruneTarget -Path $entry.FullName -AllowedRoot $cacheRoot `
                -Kind 'shared-cache'
            if (-not $DryRun) {
                $freeBytes = (Get-PSDrive -Name $driveName).Free
                $cacheBytes = Get-WindowsTestDirectorySize -Path $cacheRoot
                if ($freeBytes -ge ([int64]$MinimumFreeGiB * 1GB) -and
                    $cacheBytes -le ([int64]$CacheMaxGiB * 1GB)) { break }
            }
        }
    }

    [ordered]@{
        schema_version = 1
        dry_run = [bool]$DryRun
        policy = [ordered]@{
            older_than = $OlderThan
            keep = $Keep
            cache_max_gib = $CacheMaxGiB
            minimum_free_gib = $MinimumFreeGiB
        }
        deletion_count = $actions.Count
        reclaimable_bytes = $releasedBytes
        cache_threshold_crossed = $cacheThresholdCrossed
        protected_count = $protected.Count
        deletions = @($actions)
        protected = @($protected)
    } | ConvertTo-Json -Depth 8
}
finally {
    if ($null -ne $lock) { $lock.Dispose() }
}
