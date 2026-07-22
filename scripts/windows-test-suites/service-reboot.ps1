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
if ($Phase -eq 'Normal') { throw 'The service-reboot suite must be run through scripts/win-test reboot.' }

$releaseSuite = Join-Path $PSScriptRoot 'release-candidate.ps1'
$reuseCandidate = Join-Path (Split-Path -Parent $PSScriptRoot) `
    'windows-test-reuse-candidate.ps1'
$harness = Join-Path (Split-Path -Parent $PSScriptRoot) 'windows-test-service-harness.ps1'
if ($Phase -eq 'BeforeReboot') {
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
    catch {
        $installError = $_
        if (Test-Path -LiteralPath (Join-Path $RunRoot 'installed-service-state.json')) {
            try {
                & $harness -Mode Uninstall -RunRoot $RunRoot -SnapshotSha $SnapshotSha
                [ordered]@{
                    schema_version = 1
                    status = 'passed'
                    owned_resources_removed = $true
                    after_failed_pre_reboot = $true
                } | ConvertTo-Json | Set-Content -LiteralPath `
                    (Join-Path $RunRoot 'evidence-uninstall.json') -Encoding utf8NoBOM
            }
            catch {
                throw "Pre-reboot validation failed: $installError; owned cleanup also failed: $_"
            }
        }
        throw $installError
    }
    exit 0
}

try {
    & $harness -Mode SmokeInstalled -RunRoot $RunRoot -SnapshotSha $SnapshotSha
}
finally {
    & $harness -Mode Uninstall -RunRoot $RunRoot -SnapshotSha $SnapshotSha
    [ordered]@{ schema_version = 1; status = 'passed'; owned_resources_removed = $true } |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $RunRoot 'evidence-uninstall.json') -Encoding utf8NoBOM
}
$manifestPath = Join-Path $RunRoot 'fetch-manifest.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
foreach ($name in @(
    'evidence-installed-smoke.json',
    'evidence-node-mount-free.json',
    'evidence-node-direct-mounts.json',
    'evidence-node-network.json',
    'evidence-node-sequential.json',
    'evidence-post-reboot.json',
    'evidence-node-post-reboot.json',
    'evidence-uninstall.json'
)) {
    $path = Join-Path $RunRoot $name
    $manifest.artifacts += [pscustomobject]@{
        name = $name
        sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        size = (Get-Item -LiteralPath $path).Length
    }
}
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding utf8NoBOM
$manifestWriter = Join-Path (Split-Path -Parent $PSScriptRoot) `
    'write-seawork-test-release-manifest.ps1'
& $manifestWriter -RunRoot $RunRoot -SnapshotSha $SnapshotSha -RequireComplete | Out-Null
