[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Normal', 'BeforeReboot', 'AfterReboot')]
    [string] $Phase,
    [Parameter(Mandatory = $true)][string] $RunRoot,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')]
    [string] $SnapshotSha,
    [ValidatePattern('^$|^[a-z0-9][a-z0-9._-]{0,95}$')]
    [string] $ReuseRunId = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($Phase -eq 'Normal') {
    throw 'release-service-core-update-reboot must run through scripts/win-test reboot.'
}

$scriptsRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
$harness = Join-Path $scriptsRoot 'windows-test-service-harness.ps1'
$signing = Join-Path $scriptsRoot 'sign-seawork-service.ps1'
$serviceName = 'LocalSandboxSeaWork'
$updaterServiceName = 'LocalSandboxSeaWorkUpdater'
$installedStatePath = Join-Path $RunRoot 'installed-service-state.json'

function Invoke-Native {
    param([string] $Executable, [string[]] $Arguments, [string] $Label)
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Label failed with exit code $LASTEXITCODE" }
}

function Resolve-OneFile {
    param([string] $Pattern, [string] $Label)
    $items = @(Get-ChildItem -LiteralPath $RunRoot -File -Filter $Pattern)
    if ($items.Count -ne 1 -or
        ($items[0].Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "$Label must resolve to exactly one regular non-reparse file."
    }
    return $items[0]
}

function Get-Record {
    param([IO.FileInfo] $Item)
    return [ordered]@{
        name = $Item.Name
        sha256 = (Get-FileHash -LiteralPath $Item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        size = [int64]$Item.Length
    }
}

function Expand-ServiceTuple {
    param([IO.FileInfo] $Archive, [string] $Version, [string] $PublisherSubject,
        [string] $PublisherSha256, [string] $Label)
    $root = Join-Path $RunRoot "$Label-service"
    if (Test-Path -LiteralPath $root) { throw "$Label service extraction already exists." }
    Expand-Archive -LiteralPath $Archive.FullName -DestinationPath $root
    $bundle = Join-Path $root 'LocalSandbox'
    & $signing -Mode Verify -BundleRoot $bundle `
        -ExpectedPublisherSubject $PublisherSubject `
        -ExpectedPublisherSha256 $PublisherSha256
    Invoke-Native (Join-Path $bundle 'bin\localsandbox-seawork-service.exe') `
        @('--verify-bundle', '--json') "$Label installed-layout verification"
    $manifest = Get-Content -LiteralPath (Join-Path $bundle 'manifests\bundle.json') `
        -Raw | ConvertFrom-Json
    if ([string]$manifest.service_version -cne $Version -or
        [string]$manifest.publisher.subject -cne $PublisherSubject -or
        [string]$manifest.publisher.sha256_thumbprint -cne $PublisherSha256) {
        throw "$Label service bundle identity differs from its tuple."
    }
    return $bundle
}

function Expand-UpdaterTuple {
    param([IO.FileInfo] $Archive, [IO.FileInfo] $Manifest, [string] $Version,
        [string] $PublisherSubject, [string] $PublisherSha256, [string] $Label)
    $manifestValue = Get-Content -LiteralPath $Manifest.FullName -Raw | ConvertFrom-Json
    if ($manifestValue.schema_version -ne 2 -or
        [string]$manifestValue.version -cne $Version -or
        [string]$manifestValue.publisher_subject -cne $PublisherSubject -or
        [string]$manifestValue.publisher_sha256_thumbprint -cne $PublisherSha256 -or
        [string]$manifestValue.service_name -cne $updaterServiceName) {
        throw "$Label updater manifest identity is invalid."
    }
    $root = Join-Path $RunRoot "$Label-updater"
    if (Test-Path -LiteralPath $root) { throw "$Label updater extraction already exists." }
    Expand-Archive -LiteralPath $Archive.FullName -DestinationPath $root
    $entries = @(Get-ChildItem -LiteralPath $root -Recurse -File)
    if ($entries.Count -ne 2) { throw "$Label updater archive is not a closed two-file tuple." }
    $binary = Get-Item -LiteralPath (Join-Path $root 'localsandbox-seawork-updater.exe')
    if ((Get-FileHash -LiteralPath $binary.FullName -Algorithm SHA256).Hash.ToLowerInvariant() `
        -cne [string]$manifestValue.binary_sha256) {
        throw "$Label updater binary digest differs from its manifest."
    }
    & $signing -Mode VerifyUpdaterPe -UpdaterBinary $binary.FullName `
        -ExpectedPublisherSubject $PublisherSubject `
        -ExpectedPublisherSha256 $PublisherSha256
    return [pscustomobject]@{ binary = $binary; manifest = $manifestValue }
}

function Install-UpdaterService {
    param([string] $Binary)
    $state = Get-Content -LiteralPath $installedStatePath -Raw | ConvertFrom-Json
    $updaterRoot = Join-Path ([string]$state.install_root) 'updater'
    New-Item -ItemType Directory -Path $updaterRoot | Out-Null
    $installed = Join-Path $updaterRoot 'localsandbox-seawork-updater.exe'
    Copy-Item -LiteralPath $Binary -Destination $installed
    $command = '"{0}" --service' -f $installed
    Invoke-Native sc.exe @('create', $updaterServiceName, 'binPath=', $command,
        'start=', 'auto', 'obj=', 'LocalSystem', 'DisplayName=',
        'LocalSandbox for SeaWork Updater') 'updater service creation'
    Invoke-Native sc.exe @('sidtype', $updaterServiceName, 'unrestricted') `
        'updater service SID configuration'
    Invoke-Native sc.exe @('failure', $updaterServiceName, 'reset=', '86400',
        'actions=', 'restart/5000/restart/30000/restart/120000') `
        'updater service failure actions'
    Invoke-Native sc.exe @('failureflag', $updaterServiceName, '1') `
        'updater service failure flag'
    Invoke-Native sc.exe @('sdset', $updaterServiceName,
        'O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00000005;;;IU)') `
        'updater service ACL'
    Invoke-Native $installed @('--verify-install', '--json') 'baseline updater install verification'
    $state | Add-Member -NotePropertyName updater_service_binary `
        -NotePropertyValue $installed -Force
    $state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $installedStatePath `
        -Encoding utf8NoBOM
    return $installed
}

function Replace-UpdaterBinary {
    param([string] $Source)
    $state = Get-Content -LiteralPath $installedStatePath -Raw | ConvertFrom-Json
    $installed = Join-Path ([string]$state.install_root) `
        'updater\localsandbox-seawork-updater.exe'
    $service = Get-Service -Name $updaterServiceName
    if ($service.Status -ne 'Stopped') {
        Stop-Service -Name $updaterServiceName
        $service.WaitForStatus('Stopped', [TimeSpan]::FromMinutes(2))
    }
    Copy-Item -LiteralPath $Source -Destination $installed -Force
    Invoke-Native $installed @('--verify-install', '--json') 'candidate updater install verification'
    return $installed
}

function Invoke-SeedUtility {
    param([string[]] $Arguments, [string] $Label)
    Invoke-Native cargo.exe (@('run', '-p', 'xtask', '--locked', '--',
        'seed-update-candidate') + $Arguments) $Label
}

function Wait-CandidateCommit {
    param([string] $CommittedPath, [string] $BaselineVersion,
        [string] $CandidateVersion, [string] $CandidateSha256)
    $deadline = [DateTime]::UtcNow.AddMinutes(15)
    do {
        Start-Sleep -Milliseconds 500
        if (Test-Path -LiteralPath $CommittedPath -PathType Leaf) {
            $committed = Get-Content -LiteralPath $CommittedPath -Raw | ConvertFrom-Json
            if ([string]$committed.committed.current.version -ceq $CandidateVersion -and
                [string]$committed.committed.current.archive_sha256 -ceq $CandidateSha256) {
                if ([string]$committed.committed.previous_last_known_good.version -cne
                    $BaselineVersion) {
                    throw 'Committed candidate did not retain the baseline as last-known-good.'
                }
                return $committed
            }
        }
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Candidate service did not reach committed state within 15 minutes.'
}

if ($Phase -eq 'BeforeReboot') {
    try {
        $candidateEvidence = Get-Content -LiteralPath `
            (Join-Path $RunRoot 'evidence-release-candidate.json') -Raw | ConvertFrom-Json
        if ($candidateEvidence.status -ne 'passed' -or
            $candidateEvidence.snapshot_sha -ne $SnapshotSha -or
            $candidateEvidence.service_profile -ne 'production') {
            throw 'Candidate evidence does not bind this release run.'
        }
        $candidateVersion = [string]$candidateEvidence.version
        $publisherSubject = [string]$candidateEvidence.publisher_subject
        $publisherSha256 = [string]$candidateEvidence.publisher_sha256
        $candidateService = Resolve-OneFile `
            "lsb-seawork-service-v$candidateVersion-windows-x86_64.zip" 'candidate service'
        $candidateUpdater = Resolve-OneFile `
            "lsb-seawork-updater-v$candidateVersion-windows-x86_64.zip" 'candidate updater'
        $candidateUpdaterManifest = Resolve-OneFile `
            "lsb-seawork-updater-v$candidateVersion-windows-x86_64-manifest.json" `
            'candidate updater manifest'

        $baselineServices = @(Get-ChildItem -LiteralPath $RunRoot -File `
            -Filter 'lsb-seawork-service-v*-windows-x86_64.zip' |
            Where-Object Name -CNE $candidateService.Name)
        if ($baselineServices.Count -ne 1 -or
            $baselineServices[0].BaseName -notmatch '^lsb-seawork-service-v(.+)-windows-x86_64$') {
            throw 'Run does not contain exactly one descriptor-bound baseline service.'
        }
        $baselineVersion = $Matches[1]
        if ([version]$baselineVersion -ge [version]$candidateVersion) {
            throw 'Baseline version is not lower than the candidate.'
        }
        $baselineService = $baselineServices[0]
        $baselineUpdater = Resolve-OneFile `
            "lsb-seawork-updater-v$baselineVersion-windows-x86_64.zip" 'baseline updater'
        $baselineUpdaterManifest = Resolve-OneFile `
            "lsb-seawork-updater-v$baselineVersion-windows-x86_64-manifest.json" `
            'baseline updater manifest'
        $baselineUpdaterTuple = @(Expand-UpdaterTuple $baselineUpdater `
            $baselineUpdaterManifest $baselineVersion $publisherSubject $publisherSha256 'baseline')[-1]
        $candidateUpdaterTuple = @(Expand-UpdaterTuple $candidateUpdater `
            $candidateUpdaterManifest $candidateVersion $publisherSubject $publisherSha256 'candidate')[-1]
        $baselineBundle = [string](@(Expand-ServiceTuple $baselineService $baselineVersion `
            $publisherSubject $publisherSha256 'baseline')[-1])
        $candidateBundle = [string](@(Expand-ServiceTuple $candidateService $candidateVersion `
            $publisherSubject $publisherSha256 'candidate')[-1])
        $baselineEvidencePath = Join-Path $RunRoot 'baseline-release-evidence.json'
        [ordered]@{
            schema_version = 1; status = 'passed'; service_profile = 'production'
            snapshot_sha = $SnapshotSha
            version = $baselineVersion; publisher_subject = $publisherSubject
            publisher_sha256 = $publisherSha256; payload = Get-Record $baselineService
            updater = [ordered]@{
                archive = Get-Record $baselineUpdater
                manifest = Get-Record $baselineUpdaterManifest
            }
        } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $baselineEvidencePath `
            -Encoding utf8NoBOM

        & $harness -Mode InstallOnly -Scope Core -RunRoot $RunRoot `
            -SnapshotSha $SnapshotSha -InstallBundleRoot $baselineBundle `
            -InstallEvidencePath $baselineEvidencePath
        $installedUpdater = [string](@(Install-UpdaterService `
            $baselineUpdaterTuple.binary.FullName)[-1])
        $installState = Get-Content -LiteralPath $installedStatePath -Raw | ConvertFrom-Json
        $committedPath = Join-Path ([string]$installState.state_root) 'updates\committed.json'
        $baselineInstalledBundle = Join-Path ([string]$installState.install_root) `
            "versions\$baselineVersion"
        $initialId = ('0' * 24) + $SnapshotSha.Substring(0, 8)
        Invoke-SeedUtility @(
            'initialize-baseline', '--archive', $baselineService.FullName,
            '--bundle', $baselineInstalledBundle, '--committed', $committedPath,
            '--publisher-subject', $publisherSubject, '--publisher-sha256', $publisherSha256,
            '--transaction-id', $initialId
        ) 'baseline committed-state initialization'
        Restart-Service -Name $serviceName
        (Get-Service -Name $serviceName).WaitForStatus('Running', [TimeSpan]::FromMinutes(2))

        $installedUpdater = [string](@(Replace-UpdaterBinary `
            $candidateUpdaterTuple.binary.FullName)[-1])
        $transactionId = ([Guid]::NewGuid().ToString('N')).ToLowerInvariant()
        $stagingParent = Join-Path ([string]$installState.state_root) `
            "updates\staging\$transactionId"
        New-Item -ItemType Directory -Path $stagingParent | Out-Null
        Copy-Item -LiteralPath $candidateBundle -Destination `
            (Join-Path $stagingParent 'LocalSandbox') -Recurse
        $stagedBundle = Join-Path $stagingParent 'LocalSandbox'
        $requestPath = Join-Path ([string]$installState.state_root) `
            'updates\transactions\preinstall-request.json'
        $finalVersionRoot = Join-Path ([string]$installState.install_root) `
            "versions\$candidateVersion"
        Invoke-SeedUtility @(
            'seed-candidate', '--archive', $candidateService.FullName,
            '--bundle', $stagedBundle, '--committed', $committedPath,
            '--publisher-subject', $publisherSubject, '--publisher-sha256', $publisherSha256,
            '--transaction-id', $transactionId, '--request', $requestPath,
            '--helper', $installedUpdater,
            '--final-version-root', $finalVersionRoot,
            '--created-utc', [DateTime]::UtcNow.ToString('o'), '--release-id', '1',
            '--asset-url', "https://github.com/LocalSandBox/local-sandbox/releases/download/v$candidateVersion/$($candidateService.Name)"
        ) 'protected candidate preinstall seeding'

        $candidateRecord = Get-Record $candidateService
        $committed = Wait-CandidateCommit $committedPath $baselineVersion `
            $candidateVersion $candidateRecord.sha256
        $mainService = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
        $expectedBinary = Join-Path $finalVersionRoot 'bin\localsandbox-seawork-service.exe'
        # The committed identity proves SCM now belongs to the candidate. Persist that
        # ownership before later assertions so failure cleanup cannot mistake the
        # production-switched service for an unrelated installation.
        $installState.version = $candidateVersion
        $installState.service_binary = $expectedBinary
        $installState | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $installedStatePath `
            -Encoding utf8NoBOM
        if ($mainService.State -cne 'Running' -or
            -not $mainService.PathName.Contains($expectedBinary,
                [StringComparison]::OrdinalIgnoreCase) -or
            (Test-Path -LiteralPath (Join-Path ([string]$installState.state_root) `
                'updates\transactions\current.json'))) {
            throw 'Committed candidate service, SCM path, or transaction cleanup is invalid.'
        }
        & $harness -Mode SmokeCore -Scope Core -RunRoot $RunRoot -SnapshotSha $SnapshotSha
        [ordered]@{
            schema_version = 1; contract = 'release-core-update-reboot-v1'
            check = 'upd01.activation_smoke'; status = 'passed'
            snapshot_sha = $SnapshotSha
            baseline = [ordered]@{
                version = $baselineVersion; service = Get-Record $baselineService
                updater = Get-Record $baselineUpdater
            }
            candidate = [ordered]@{
                version = $candidateVersion; service = $candidateRecord
                updater = Get-Record $candidateUpdater
            }
            helper_first_replacement = $true
            transaction_id = $transactionId
            committed = $committed.committed
            candidate_manual_no_candidate = $true
            updater_binary_sha256 = (Get-FileHash -LiteralPath $installedUpdater `
                -Algorithm SHA256).Hash.ToLowerInvariant()
        } | ConvertTo-Json -Depth 14 | Set-Content -LiteralPath `
            (Join-Path $RunRoot 'evidence-release-core-update.json') -Encoding utf8NoBOM
    }
    catch {
        $failure = $_
        if (Test-Path -LiteralPath $installedStatePath) {
            try { & $harness -Mode Uninstall -RunRoot $RunRoot -SnapshotSha $SnapshotSha }
            catch { throw "Core update failed: $failure; cleanup also failed: $_" }
        }
        throw $failure
    }
    exit 0
}

try {
    & $harness -Mode SmokeInstalled -Scope Core -RunRoot $RunRoot -SnapshotSha $SnapshotSha
}
finally {
    if (Test-Path -LiteralPath $installedStatePath) {
        & $harness -Mode Uninstall -RunRoot $RunRoot -SnapshotSha $SnapshotSha
    }
}
$mainRemaining = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
$updaterRemaining = Get-Service -Name $updaterServiceName -ErrorAction SilentlyContinue
$stateRemaining = Test-Path -LiteralPath (Join-Path $env:ProgramData 'LocalSandbox\SeaWork')
$productRemaining = Test-Path -LiteralPath (Join-Path `
    ([Environment]::GetFolderPath('ProgramFiles')) 'SeaWork\LocalSandbox')
if ($null -ne $mainRemaining -or $null -ne $updaterRemaining -or
    $stateRemaining -or $productRemaining) {
    throw 'Final release cleanup left a production service or product root behind.'
}
[ordered]@{
    schema_version = 1; status = 'passed'; final_cleanup = $true
    service_removed = $true; updater_removed = $true; product_roots_removed = $true
} | ConvertTo-Json | Set-Content -LiteralPath `
    (Join-Path $RunRoot 'evidence-release-final-cleanup.json') -Encoding utf8NoBOM
