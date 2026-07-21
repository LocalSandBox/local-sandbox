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
if ($Phase -ne 'Normal') { throw 'The filtered-client-token suite does not support reboot phases.' }

$harness = Join-Path (Split-Path -Parent $PSScriptRoot) 'windows-test-service-harness.ps1'
. $harness -Mode InstallAndSmoke -RunRoot $RunRoot -SnapshotSha $SnapshotSha
Assert-Administrator
$identity = Get-InteractiveClientIdentity
$probeRoot = Join-Path $RunRoot 'filtered-client-token-probe'
New-Item -ItemType Directory -Path $probeRoot | Out-Null
Set-Sddl $probeRoot ("O:BAG:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{0})" -f $identity.sid)
$proofPath = Join-Path $probeRoot 'proof.json'
$state = [pscustomobject]@{
    client_harness_root = Split-Path -Parent $harness
    client_task_prefix = "LocalSandboxAgent-$($SnapshotSha.Substring(0, 8))"
    client_user_identity = $identity.identity
    client_user_sid = $identity.sid
}
try {
    $result = Invoke-FilteredUserProcess `
        -State $state `
        -Executable (Join-Path $env:SystemRoot 'System32\where.exe') `
        -Arguments @('cmd.exe') `
        -WorkingDirectory $env:SystemRoot `
        -ProofPath $proofPath `
        -TaskSuffix 'probe' `
        -TimeoutSeconds 30
}
finally {
    Remove-Item -LiteralPath $probeRoot -Recurse -Force -ErrorAction SilentlyContinue
}

[ordered]@{
    schema_version = 1
    status = 'passed'
    snapshot_sha = $SnapshotSha
    mode = 'filtered-current-user'
    source = [string]$result.source
    user_name = [string]$result.user_name
    user_sid = [string]$result.user_sid
    integrity_level = 'medium'
    integrity_rid = [int]$result.integrity_rid
    elevated = [bool]$result.elevated
    administrator = [bool]$result.administrator
    privilege_behavior_validated = $true
    separate_account_profile_validated = $false
} | ConvertTo-Json -Depth 5 | Set-Content `
    -LiteralPath (Join-Path $RunRoot 'evidence-filtered-client-token.json') `
    -Encoding utf8NoBOM

Get-Content -LiteralPath (Join-Path $RunRoot 'evidence-filtered-client-token.json') -Raw
