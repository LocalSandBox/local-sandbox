[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet('List', 'Show')][string] $Mode,
    [ValidatePattern('^$|^[a-z0-9][a-z0-9._-]{0,95}$')][string] $RunId = '',
    [string] $StateRoot = 'C:\dev\local-sandbox-agent-state'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'lib\common.ps1')

$statePath = Resolve-WindowsTestOwnedRoot -Path $StateRoot `
    -ExpectedLeaf 'local-sandbox-agent-state'
$runsRoot = Assert-WindowsTestDescendant -Path (Join-Path $statePath 'runs') -Root $statePath

if ($Mode -eq 'List') {
    $rows = foreach ($run in @(Get-ChildItem -LiteralPath $runsRoot -Directory -Force |
        Sort-Object LastWriteTimeUtc -Descending)) {
        if ($run.Name -notmatch '^[a-z0-9][a-z0-9._-]{0,95}$') { continue }
        $statuses = [Collections.Generic.List[string]]::new()
        foreach ($result in @(Get-ChildItem -LiteralPath $run.FullName -Filter 'result-*.json' `
            -File -ErrorAction SilentlyContinue)) {
            try {
                $value = Read-WindowsTestJson -Path $result.FullName -MaximumBytes 256KB
                $statuses.Add("$($value.suite):$($value.status)")
            }
            catch { $statuses.Add("$($result.BaseName):invalid") }
        }
        $continuation = 'none'
        $continuationPath = Join-Path $run.FullName 'continuation.json'
        if (Test-Path -LiteralPath $continuationPath -PathType Leaf) {
            try { $continuation = [string](Read-WindowsTestJson $continuationPath).status }
            catch { $continuation = 'invalid' }
        }
        [pscustomobject]@{
            run_id = $run.Name
            updated_utc = $run.LastWriteTimeUtc.ToString('o')
            status = if ($statuses.Count) { $statuses -join ',' } else { 'no-results' }
            continuation = $continuation
            pinned = Test-Path -LiteralPath (Join-Path $run.FullName 'pinned.json') -PathType Leaf
        }
    }
    $rows | Format-Table -AutoSize | Out-String -Width 240 | Write-Output
    exit 0
}

if ([string]::IsNullOrWhiteSpace($RunId)) { throw 'Show mode requires RunId.' }
$runPath = Assert-WindowsTestDescendant -Path (Join-Path $runsRoot $RunId) -Root $runsRoot
$item = Get-Item -LiteralPath $runPath -Force -ErrorAction Stop
if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'Requested run is not a plain directory.'
}
$documents = [ordered]@{}
foreach ($name in @('run-metadata.json', 'profile-result.json', 'continuation.json', 'fetch-manifest.json')) {
    $path = Join-Path $runPath $name
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        $documents[$name] = Read-WindowsTestJson -Path $path -MaximumBytes 1MB
    }
}
foreach ($result in @(Get-ChildItem -LiteralPath $runPath -Filter 'result-*.json' -File |
    Sort-Object Name)) {
    $documents[$result.Name] = Read-WindowsTestJson -Path $result.FullName -MaximumBytes 256KB
}
[ordered]@{
    schema_version = 1
    run_id = $RunId
    updated_utc = $item.LastWriteTimeUtc.ToString('o')
    documents = $documents
    fetchable = if ($documents.Contains('fetch-manifest.json')) {
        @($documents['fetch-manifest.json'].artifacts | ForEach-Object name)
    } else { @() }
} | ConvertTo-Json -Depth 20
