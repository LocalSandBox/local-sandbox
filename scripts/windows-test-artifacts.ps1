[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-z0-9][a-z0-9._-]{0,95}$')]
    [string] $RunId,

    [string] $StateRoot = (Join-Path $env:ProgramData 'LocalSandbox\DevTest')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-RegularFile {
    param([Parameter(Mandatory = $true)][string] $Path)

    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Fetchable artifact must be a regular non-reparse file: $Path"
    }
    return $item
}

function Test-AllowlistedName {
    param([Parameter(Mandatory = $true)][string] $Name)

    return $Name -eq 'fetch-manifest.json' -or
        $Name -eq 'seawork-test-release-manifest.json' -or
        $Name -eq 'SHA256SUMS' -or
        $Name -match '^lsb-seawork-service-v[0-9A-Za-z.+-]+-windows-x86_64(-symbols)?\.zip$' -or
        $Name -match '^lsb-seawork-updater-v[0-9A-Za-z.+-]+-windows-x86_64\.zip$' -or
        $Name -match '^lsb-seawork-updater-v[0-9A-Za-z.+-]+-windows-x86_64-manifest\.json$' -or
        $Name -match '^lsb-seawork-updater-v[0-9A-Za-z.+-]+-SHA256SUMS$' -or
        $Name -match '^[A-Za-z0-9][A-Za-z0-9._+-]{0,120}\.tgz$' -or
        $Name -match '^evidence-[a-z0-9][a-z0-9._-]{0,80}\.json$' -or
        $Name -match '^result-(normal|beforereboot|afterreboot)\.json$'
}

$state = [IO.Path]::GetFullPath($StateRoot).TrimEnd('\', '/')
if ((Split-Path -Leaf $state) -cne 'DevTest') {
    throw 'StateRoot must end in the dedicated DevTest directory.'
}
$stateMarker = Join-Path $state '.local-sandbox-agent-test-root.json'
if (-not (Test-Path -LiteralPath $stateMarker -PathType Leaf)) {
    throw 'The Windows test state root is not initialized.'
}
$runsRoot = Join-Path $state 'runs'
$runRoot = Join-Path $runsRoot $RunId
$resolvedRuns = [IO.Path]::GetFullPath($runsRoot).TrimEnd('\') + '\'
$resolvedRun = [IO.Path]::GetFullPath($runRoot).TrimEnd('\')
if (-not $resolvedRun.StartsWith($resolvedRuns, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'The requested run escaped the dedicated runs root.'
}
$runItem = Get-Item -LiteralPath $resolvedRun -Force
if (-not $runItem.PSIsContainer -or ($runItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'The requested run root is not a regular directory.'
}
$manifestPath = Join-Path $resolvedRun 'fetch-manifest.json'
$manifestItem = Assert-RegularFile -Path $manifestPath
if ($manifestItem.Length -le 0 -or $manifestItem.Length -gt 256KB) {
    throw 'The fetch manifest size is outside the supported bound.'
}
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.schema_version -ne 1 -or $manifest.run_id -ne $RunId) {
    throw 'The fetch manifest identity is invalid.'
}
$artifacts = @($manifest.artifacts)
if ($artifacts.Count -eq 0 -or $artifacts.Count -gt 32) {
    throw 'The fetch manifest artifact count is outside the supported bound.'
}
$seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$records = [Collections.Generic.List[object]]::new()
$manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
$records.Add([pscustomobject]@{
    name = 'fetch-manifest.json'
    sha256 = $manifestHash
    size = $manifestItem.Length
})
foreach ($artifact in $artifacts) {
    $name = [string]$artifact.name
    $expectedHash = ([string]$artifact.sha256).ToLowerInvariant()
    $expectedSize = [long]$artifact.size
    if (-not (Test-AllowlistedName -Name $name) -or $name -eq 'fetch-manifest.json' -or
        -not $seen.Add($name)) {
        throw 'The fetch manifest contains an unsafe, reserved, or duplicate artifact name.'
    }
    if ($expectedHash -notmatch '^[0-9a-f]{64}$' -or $expectedSize -lt 0 -or
        $expectedSize -gt 8GB) {
        throw "The fetch manifest metadata is invalid for $name."
    }
    $path = Join-Path $resolvedRun $name
    $item = Assert-RegularFile -Path $path
    if ($item.Length -ne $expectedSize) {
        throw "The fetchable artifact size does not match the manifest: $name"
    }
    $observedHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($observedHash -cne $expectedHash) {
        throw "The fetchable artifact hash does not match the manifest: $name"
    }
    $records.Add([pscustomobject]@{
        name = $name
        sha256 = $observedHash
        size = $item.Length
    })
}

foreach ($record in $records) {
    Write-Output "$($record.name)`t$($record.sha256)`t$($record.size)"
}
