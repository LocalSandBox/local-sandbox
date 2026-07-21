[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Normal', 'BeforeReboot', 'AfterReboot')]
    [string] $Phase,
    [Parameter(Mandatory = $true)][string] $RunRoot,
    [Parameter(Mandatory = $true)][string] $SnapshotSha,
    [ValidatePattern('^$|^[a-z0-9][a-z0-9._-]{0,95}$')]
    [string] $ReuseRunId = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($Phase -ne 'Normal') { throw 'The installed-service-smoke suite does not support reboot phases.' }

$releaseSuite = Join-Path $PSScriptRoot 'release-candidate.ps1'
$reuseCandidate = Join-Path (Split-Path -Parent $PSScriptRoot) `
    'windows-test-reuse-candidate.ps1'
$harness = Join-Path (Split-Path -Parent $PSScriptRoot) 'windows-test-service-harness.ps1'
if ([string]::IsNullOrWhiteSpace($ReuseRunId)) {
    & $releaseSuite -Phase Normal -RunRoot $RunRoot -SnapshotSha $SnapshotSha
}
else {
    & $reuseCandidate `
        -RunRoot $RunRoot `
        -SnapshotSha $SnapshotSha `
        -SourceRunId $ReuseRunId
}
try {
    & $harness -Mode InstallAndSmoke -RunRoot $RunRoot -SnapshotSha $SnapshotSha
}
finally {
    if (Test-Path -LiteralPath (Join-Path $RunRoot 'installed-service-state.json')) {
        & $harness -Mode Uninstall -RunRoot $RunRoot -SnapshotSha $SnapshotSha
        [ordered]@{ schema_version = 1; status = 'passed'; owned_resources_removed = $true } |
            ConvertTo-Json | Set-Content -LiteralPath (Join-Path $RunRoot 'evidence-uninstall.json') -Encoding utf8NoBOM
    }
}

$manifestPath = Join-Path $RunRoot 'fetch-manifest.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
foreach ($name in @(
    'evidence-installed-smoke.json',
    'evidence-node-mount-free.json',
    'evidence-node-direct-mounts.json',
    'evidence-node-network.json',
    'evidence-node-sequential.json',
    'evidence-uninstall.json'
)) {
    $path = Join-Path $RunRoot $name
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        $manifest.artifacts += [pscustomobject]@{
            name = $name
            sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            size = (Get-Item -LiteralPath $path).Length
        }
    }
}
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding utf8NoBOM
$manifestWriter = Join-Path (Split-Path -Parent $PSScriptRoot) `
    'write-seawork-test-release-manifest.ps1'
& $manifestWriter -RunRoot $RunRoot -SnapshotSha $SnapshotSha | Out-Null
