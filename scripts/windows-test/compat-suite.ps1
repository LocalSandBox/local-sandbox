[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet('runtime', 'diagnostics', 'service', 'native', 'release')]
    [string] $Category,
    [Parameter(Mandatory = $true)][ValidatePattern('^[a-z0-9][a-z0-9-]{0,63}$')]
    [string] $Suite,
    [Parameter(Mandatory = $true)][ValidateSet('Normal', 'BeforeReboot', 'AfterReboot')]
    [string] $Phase,
    [Parameter(Mandatory = $true)][string] $RunRoot,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')]
    [string] $SnapshotSha,
    [ValidatePattern('^$|^[a-z0-9][a-z0-9._-]{0,95}$')]
    [string] $ReuseRunId = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$target = Join-Path $PSScriptRoot "suites\$Category\$Suite.ps1"
if (-not (Test-Path -LiteralPath $target -PathType Leaf)) {
    throw "Deprecated suite shim target is missing: $target"
}
$arguments = @{
    Phase = $Phase; RunRoot = $RunRoot; SnapshotSha = $SnapshotSha
}
if (-not [string]::IsNullOrWhiteSpace($ReuseRunId)) { $arguments.ReuseRunId = $ReuseRunId }
& $target @arguments
