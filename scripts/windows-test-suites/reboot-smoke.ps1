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

function Get-BootId {
    return (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().Ticks.ToString()
}

function Write-JsonAtomic {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][object] $Value
    )

    $pending = "$Path.pending-$PID"
    $Value | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $pending -Encoding utf8NoBOM
    Move-Item -LiteralPath $pending -Destination $Path -Force
}

if ($Phase -eq 'Normal') {
    throw 'reboot-smoke must be invoked with scripts/win-test reboot reboot-smoke'
}

$statePath = Join-Path $RunRoot 'reboot-smoke.json'
$head = (& git rev-parse HEAD).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $head -ne $SnapshotSha) {
    throw "Reboot smoke checkout mismatch: expected $SnapshotSha, observed $head"
}

if ($Phase -eq 'BeforeReboot') {
    Write-JsonAtomic -Path $statePath -Value ([ordered]@{
        schema_version = 1
        snapshot_sha = $SnapshotSha
        boot_id_before = Get-BootId
        status = 'awaiting_reboot'
    })
    Write-Output 'Reboot smoke pre-phase is armed.'
    return
}

if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
    throw "Reboot smoke state is missing: $statePath"
}
$state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
if ($state.schema_version -ne 1 -or $state.snapshot_sha -ne $SnapshotSha -or
    $state.status -ne 'awaiting_reboot') {
    throw 'Reboot smoke state is invalid.'
}
$bootAfter = Get-BootId
if ($bootAfter -eq [string]$state.boot_id_before) {
    throw 'Windows boot identity did not change.'
}
$state.status = 'passed'
$state | Add-Member -NotePropertyName boot_id_after -NotePropertyValue $bootAfter -Force
$state | Add-Member -NotePropertyName completed_utc `
    -NotePropertyValue ([DateTime]::UtcNow.ToString('o')) -Force
Write-JsonAtomic -Path $statePath -Value $state
Write-Output 'Reboot smoke post-phase passed.'
