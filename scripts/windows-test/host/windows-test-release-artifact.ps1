[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet('Prepare', 'Commit', 'Abort')][string] $Mode,
    [Parameter(Mandatory = $true)][ValidatePattern('^[a-z0-9][a-z0-9._-]{0,95}$')]
    [string] $RunId,
    [Parameter(Mandatory = $true)]
    [ValidateScript({
        $_ -match '^lsb-seawork-service-v[0-9A-Za-z.+-]+-windows-x86_64\.zip$' -or
        $_ -match '^lsb-seawork-updater-v[0-9A-Za-z.+-]+-windows-x86_64\.zip$' -or
        $_ -match '^lsb-seawork-updater-v[0-9A-Za-z.+-]+-windows-x86_64-manifest\.json$'
    })]
    [string] $FileName,
    [ValidatePattern('^$|^[0-9a-f]{64}$')][string] $ExpectedSha256 = '',
    [ValidateRange(0, 8589934592)][int64] $ExpectedSize = 0,
    [ValidatePattern('^$|^[0-9a-f]{40}$')][string] $SnapshotSha = '',
    [string] $StateRoot = 'C:\dev\local-sandbox-agent-state'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'lib\common.ps1')

$state = Resolve-WindowsTestOwnedRoot -Path $StateRoot -ExpectedLeaf 'local-sandbox-agent-state'
$imports = Assert-WindowsTestDescendant -Path (Join-Path $state 'imports') -Root $state
if (-not (Test-Path -LiteralPath $imports -PathType Container)) {
    New-Item -ItemType Directory -Path $imports | Out-Null
}
$stage = Assert-WindowsTestDescendant -Path (Join-Path $imports $RunId) -Root $imports
$stageFile = Join-Path $stage $FileName

if ($Mode -eq 'Prepare') {
    if ([string]::IsNullOrWhiteSpace($SnapshotSha)) { throw 'Prepare requires SnapshotSha.' }
    if (Test-Path -LiteralPath $stage) { throw 'Release artifact import stage already exists.' }
    New-Item -ItemType Directory -Path $stage | Out-Null
    Write-WindowsTestJsonAtomic -Path (Join-Path $stage 'owner.json') -Value ([ordered]@{
        schema_version = 1; owner = 'local-sandbox-release-artifact-import'
        run_id = $RunId; snapshot_sha = $SnapshotSha; file_name = $FileName
    })
    Write-Output $stage.Replace('\', '/')
    exit 0
}

if (-not (Test-Path -LiteralPath $stage -PathType Container)) {
    if ($Mode -eq 'Abort') { exit 0 }
    throw 'Release artifact import stage does not exist.'
}
$owner = Read-WindowsTestJson -Path (Join-Path $stage 'owner.json') -MaximumBytes 16KB
if ($owner.schema_version -ne 1 -or $owner.owner -cne 'local-sandbox-release-artifact-import' -or
    $owner.run_id -cne $RunId -or $owner.file_name -cne $FileName) {
    throw 'Release artifact import ownership marker is invalid.'
}
if ($Mode -eq 'Abort') {
    Remove-Item -LiteralPath $stage -Recurse -Force
    exit 0
}
if ([string]::IsNullOrWhiteSpace($ExpectedSha256) -or $ExpectedSize -le 0) {
    throw 'Commit requires the expected SHA-256 and nonzero size.'
}
$item = Get-Item -LiteralPath $stageFile -Force -ErrorAction Stop
if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
    $item.Length -ne $ExpectedSize) { throw 'Imported release artifact type or size is invalid.' }
$observed = (Get-FileHash -LiteralPath $stageFile -Algorithm SHA256).Hash.ToLowerInvariant()
if ($observed -cne $ExpectedSha256) { throw 'Imported release artifact SHA-256 mismatch.' }
$runs = Assert-WindowsTestDescendant -Path (Join-Path $state 'runs') -Root $state
$run = Assert-WindowsTestDescendant -Path (Join-Path $runs $RunId) -Root $runs
if (-not (Test-Path -LiteralPath $run -PathType Container)) {
    New-Item -ItemType Directory -Path $run | Out-Null
}
$destination = Join-Path $run $FileName
if (Test-Path -LiteralPath $destination) { throw 'Destination run already contains the release artifact.' }
Move-Item -LiteralPath $stageFile -Destination $destination
Write-WindowsTestJsonAtomic -Path (Join-Path $run 'imported-release-artifact.json') `
    -Value ([ordered]@{
        schema_version = 1; run_id = $RunId; snapshot_sha = [string]$owner.snapshot_sha
        name = $FileName; sha256 = $observed; size = [int64]$item.Length
        imported_utc = [DateTime]::UtcNow.ToString('o')
    })
Remove-Item -LiteralPath $stage -Recurse -Force
Write-Output $destination
