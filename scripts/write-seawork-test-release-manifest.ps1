[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $RunRoot,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string] $SnapshotSha,

    [switch] $RequireComplete
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Read-JsonFile {
    param([string] $Path, [string] $Label)
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $item.Length -le 0 -or $item.Length -gt 4MB) {
        throw "$Label is not a bounded regular file"
    }
    return Get-Content -LiteralPath $item.FullName -Raw | ConvertFrom-Json
}

function Get-ArtifactRecord {
    param([string] $Path)
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "release artifact must be a regular non-reparse file: $Path"
    }
    return [ordered]@{
        file = $item.Name
        sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        size = $item.Length
    }
}

function Read-PassedEvidence {
    param([string] $Name)
    $path = Join-Path $run $Name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        return $null
    }
    $value = Read-JsonFile $path $Name
    if ($value.schema_version -ne 1 -or $value.status -ne 'passed') {
        return $null
    }
    return $value
}

function Test-NodeChecks {
    param([object] $Evidence, [string[]] $Names)
    if ($null -eq $Evidence) { return $false }
    $observed = @($Evidence.checks | ForEach-Object { [string]$_.name })
    foreach ($name in $Names) {
        if ($name -cnotin $observed) { return $false }
    }
    return $true
}

function Test-FilteredTokenEvidence {
    param([object] $Evidence)
    if ($null -eq $Evidence -or $null -eq $Evidence.client_token) { return $false }
    $token = $Evidence.client_token
    return $token.mode -eq 'filtered-current-user' -and
        $token.integrity_level -eq 'medium' -and
        -not [bool]$token.elevated -and
        -not [bool]$token.administrator -and
        [bool]$token.privilege_behavior_validated -and
        -not [bool]$token.separate_account_profile_validated
}

$repoRoot = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$run = [IO.Path]::GetFullPath($RunRoot).TrimEnd('\')
$releaseEvidence = Read-JsonFile (Join-Path $run 'evidence-release-candidate.json') `
    'release-candidate evidence'
$nodePackagesEvidence = Read-JsonFile (Join-Path $run 'evidence-node-packages.json') `
    'Node package evidence'
if ($releaseEvidence.status -ne 'passed' -or $releaseEvidence.snapshot_sha -ne $SnapshotSha -or
    $releaseEvidence.service_profile -ne 'production' -or
    $nodePackagesEvidence.status -ne 'passed' -or
    $nodePackagesEvidence.version -ne $releaseEvidence.version -or
    $nodePackagesEvidence.publisher_sha256 -cne $releaseEvidence.publisher_sha256) {
    throw 'release and Node evidence do not identify one production candidate'
}

$version = [string]$releaseEvidence.version
$stage = Join-Path $run "release-work\out\lsb-seawork-service-v$version-windows-x86_64-stage\LocalSandbox"
$serviceContractPath = Join-Path $stage 'manifests\service-contract.json'
$bundleManifestPath = Join-Path $stage 'manifests\bundle.json'
$dependencyPath = Join-Path $stage 'manifests\runtime-dependencies.json'
$sbomPath = Join-Path $stage 'manifests\sbom.spdx.json'
$licensesNoticePath = Join-Path $stage 'licenses\THIRD-PARTY-NOTICES.json'
$serviceContract = Read-JsonFile $serviceContractPath 'service contract'
$testContract = Read-JsonFile (Join-Path $repoRoot 'contracts\seawork-test-release-v1.json') `
    'test-release contract'
if ($serviceContract.service.name -cne 'LocalSandboxSeaWork' -or
    $serviceContract.service.account -cne 'LocalSystem' -or
    $serviceContract.ipc.pipe_name -cne '\\.\pipe\LocalSandbox.SeaWork.v1' -or
    $serviceContract.filesystem.state_root -cne '%ProgramData%\LocalSandbox\SeaWork') {
    throw 'generated service contract does not contain the production identities'
}

$localSandboxCommit = (& git rev-parse "$SnapshotSha^").Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $localSandboxCommit -notmatch '^[0-9a-f]{40}$') {
    throw 'could not resolve the LocalSandbox commit below the synthetic snapshot'
}
$runId = Split-Path -Leaf $run
$os = Get-CimInstance Win32_OperatingSystem

$artifactHashes = [ordered]@{
    service_zip = Get-ArtifactRecord (Join-Path $run ([string]$releaseEvidence.payload.name))
    symbols_zip = Get-ArtifactRecord (Join-Path $run ([string]$releaseEvidence.symbols.name))
    sha256sums = Get-ArtifactRecord (Join-Path $run 'SHA256SUMS')
    node_packages = @($nodePackagesEvidence.packages | ForEach-Object {
        $record = Get-ArtifactRecord (Join-Path $run ([string]$_.file))
        if ($record.sha256 -cne [string]$_.sha256 -or $record.size -ne [long]$_.size) {
            throw "Node package evidence does not match $($_.file)"
        }
        [ordered]@{
            role = [string]$_.role
            name = [string]$_.name
            version = [string]$_.version
            file = $record.file
            sha256 = $record.sha256
            size = $record.size
        }
    })
    bundle_manifest = Get-ArtifactRecord $bundleManifestPath
    service_contract = Get-ArtifactRecord $serviceContractPath
    runtime_dependencies = Get-ArtifactRecord $dependencyPath
    sbom = Get-ArtifactRecord $sbomPath
    licenses_notice = Get-ArtifactRecord $licensesNoticePath
}
if ($artifactHashes.service_zip.sha256 -cne [string]$releaseEvidence.payload.sha256 -or
    $artifactHashes.symbols_zip.sha256 -cne [string]$releaseEvidence.symbols.sha256) {
    throw 'release evidence does not match the candidate archives'
}

$mountFree = Read-PassedEvidence 'evidence-node-mount-free.json'
$directMounts = Read-PassedEvidence 'evidence-node-direct-mounts.json'
$network = Read-PassedEvidence 'evidence-node-network.json'
$sequential = Read-PassedEvidence 'evidence-node-sequential.json'
$installed = Read-PassedEvidence 'evidence-installed-smoke.json'
$postReboot = Read-PassedEvidence 'evidence-post-reboot.json'
$uninstall = Read-PassedEvidence 'evidence-uninstall.json'

$caseProof = [ordered]@{
    'signed-install' = ($null -ne $installed -and [bool]$installed.production_identity)
    'service-health' = (Test-NodeChecks $mountFree @('service-health'))
    'mount-free-lifecycle' = (Test-NodeChecks $mountFree @('unary-exec', 'filesystem'))
    'four-mount-standard-user' = (
        (Test-NodeChecks $directMounts @('direct-mount-layout')) -and
        (Test-FilteredTokenEvidence $directMounts)
    )
    'exec-and-files' = (Test-NodeChecks $mountFree @('unary-exec', 'filesystem'))
    'spawn-stream-kill' = (Test-NodeChecks $mountFree @('spawn-stream-exit', 'spawn-kill'))
    'cancellation-cleanup' = (Test-NodeChecks $mountFree @('exec-cancellation'))
    'public-network-and-secret' = (Test-NodeChecks $network @(
        'public-dns', 'public-http', 'public-https', 'package-download', 'scoped-secret-redacted'
    ))
    'private-target-denial' = (Test-NodeChecks $network @('private-target-denied'))
    'ten-sequential-effects' = ($null -ne $sequential -and [int]$sequential.effects -eq 10)
    'reboot-continuation' = ($null -ne $postReboot -and [bool]$postReboot.post_reboot)
    'normal-stop-cleanup' = ($null -ne $installed -and [bool]$installed.compatibility_resources_restored)
    'uninstall' = ($null -ne $uninstall -and [bool]$uninstall.owned_resources_removed)
}
$caseResults = @($testContract.evidence.required_cases | ForEach-Object {
    $id = [string]$_
    [ordered]@{
        id = $id
        status = if ($caseProof[$id]) { 'passed' } else { 'pending' }
    }
})
$pending = @($caseResults | Where-Object { $_.status -ne 'passed' })
if ($RequireComplete -and $pending.Count -ne 0) {
    throw "test-release evidence is incomplete: $(($pending.id) -join ', ')"
}

$redactedLogs = @(Get-ChildItem -LiteralPath $run -File -Filter 'output-*.log' |
    Sort-Object Name | ForEach-Object { $_.Name })
$manifestPath = Join-Path $run 'seawork-test-release-manifest.json'
[ordered]@{
    schema_version = 1
    status = if ($pending.Count -eq 0) { 'complete' } else { 'incomplete' }
    local_sandbox_commit = $localSandboxCommit
    candidate_version = $version
    synthetic_snapshot_sha = $SnapshotSha
    windows_run_ids = @($runId)
    artifact_provenance = if (
        $null -ne $releaseEvidence.PSObject.Properties['artifact_reuse']
    ) {
        [ordered]@{
            mode = 'verified-reuse'
            source_run_id = [string]$releaseEvidence.artifact_reuse.source_run_id
            source_snapshot_sha = [string]$releaseEvidence.artifact_reuse.source_snapshot_sha
            source_snapshot_tree_sha = `
                [string]$releaseEvidence.artifact_reuse.source_snapshot_tree_sha
            source_release_evidence_sha256 = `
                [string]$releaseEvidence.artifact_reuse.source_release_evidence_sha256
        }
    }
    else {
        [ordered]@{ mode = 'built-in-run' }
    }
    windows_build = [ordered]@{
        caption = [string]$os.Caption
        build = [string]$os.BuildNumber
        architecture = [string]$os.OSArchitecture
    }
    artifact_hashes = $artifactHashes
    publisher_subject = [string]$releaseEvidence.publisher_subject
    publisher_sha256 = [string]$releaseEvidence.publisher_sha256
    protocol = $serviceContract.ipc.protocol
    capabilities = [ordered]@{
        operations = @($testContract.operations | Where-Object { $_.scope -eq 'required' } |
            ForEach-Object { $_.id })
        direct_mount = $true
        direct_mount_backends = @('compat-smb-direct')
        network = @($testContract.network_capabilities | ForEach-Object { $_.id })
        ports = $false
        checkpoints = $false
        overlay_mount = $false
    }
    production_identities = $testContract.identities
    validation_scope = [ordered]@{
        standard_user_privilege_behavior = 'filtered-medium-integrity-non-admin-current-user-token'
        separate_account_profile_behavior = 'not-validated'
    }
    case_results = $caseResults
    redacted_log_locations = $redactedLogs
} | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $manifestPath -Encoding utf8NoBOM

$fetchManifestPath = Join-Path $run 'fetch-manifest.json'
if (Test-Path -LiteralPath $fetchManifestPath -PathType Leaf) {
    $fetch = Read-JsonFile $fetchManifestPath 'fetch manifest'
    $manifestRecord = Get-ArtifactRecord $manifestPath
    $manifestRecord = [pscustomobject]@{
        name = $manifestRecord.file
        sha256 = $manifestRecord.sha256
        size = $manifestRecord.size
    }
    $others = @($fetch.artifacts | Where-Object { $_.name -cne $manifestRecord.name })
    $fetch.artifacts = @($others + $manifestRecord)
    $fetch | ConvertTo-Json -Depth 10 | Set-Content `
        -LiteralPath $fetchManifestPath -Encoding utf8NoBOM
}

Get-Content -LiteralPath $manifestPath -Raw
