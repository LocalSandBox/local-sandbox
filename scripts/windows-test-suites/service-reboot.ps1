[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Normal', 'BeforeReboot', 'AfterReboot')]
    [string] $Phase,
    [Parameter(Mandatory = $true)][string] $RunRoot,
    [Parameter(Mandatory = $true)][string] $SnapshotSha
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($Phase -eq 'Normal') { throw 'The service-reboot suite must be run through scripts/win-test reboot.' }

$releaseSuite = Join-Path $PSScriptRoot 'release-candidate.ps1'
$harness = Join-Path (Split-Path -Parent $PSScriptRoot) 'windows-test-service-harness.ps1'
if ($Phase -eq 'BeforeReboot') {
    & $releaseSuite -Phase Normal -RunRoot $RunRoot -SnapshotSha $SnapshotSha
    & $harness -Mode InstallAndSmoke -RunRoot $RunRoot -SnapshotSha $SnapshotSha
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
foreach ($name in @('evidence-post-reboot.json', 'evidence-node-post-reboot.json', 'evidence-uninstall.json')) {
    $path = Join-Path $RunRoot $name
    $manifest.artifacts += [pscustomobject]@{
        name = $name
        sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        size = (Get-Item -LiteralPath $path).Length
    }
}
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding utf8NoBOM
