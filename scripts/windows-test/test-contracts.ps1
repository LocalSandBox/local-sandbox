[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'lib\common.ps1')
. (Join-Path $PSScriptRoot 'lib\evidence.ps1')
. (Join-Path $PSScriptRoot 'lib\failure-diagnostics.ps1')

$testRoot = Join-Path ([IO.Path]::GetTempPath()) "windows-test-contract-$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $testRoot | Out-Null
try {
    $resultPath = Join-Path $testRoot 'result-sample-suite-normal.json'
    [ordered]@{
        schema_version = 2; run_id = 'sample-run'; snapshot_sha = '1' * 40
        source_tree_sha = '1' * 40; base_commit_sha = '1' * 40
        suite = 'sample-suite'; category = 'runtime'; phase = 'Normal'; status = 'passed'
        exit_code = 0; failure_code = $null; started_utc = '2026-01-01T00:00:00Z'
        finished_utc = '2026-01-01T00:00:01Z'; duration_ms = 1000; boot_id = '1234'
        output_file = 'output-sample-suite-normal.log'; required_capabilities = @('whpx')
        mutations = @('WHPX VM'); expected_artifacts = @('evidence-sample.json')
        acceptance_checks = @('win01.whpx_qemu_boot_exec_stop')
        bindings = [ordered]@{ runtime_assets_sha256 = '2' * 64; release_artifact_sha256 = $null }
    } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $resultPath -Encoding utf8NoBOM
    $rawEvidence = Join-Path $testRoot 'evidence-sample.json'
    [ordered]@{
        schema_version = 1; status = 'passed'; safe = 'retained'
        absolute_path = 'C:\Users\raw\secret.txt'; user_sid = 'S-1-5-21-1-2-3-4'
        publisher_sha256 = '3' * 64; nested = [ordered]@{ value = 7 }
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $rawEvidence -Encoding utf8NoBOM

    Write-WindowsTestFetchManifest -RunRoot $testRoot -RunId 'sample-run' `
        -ResultPath $resultPath -ExpectedArtifacts @('evidence-sample.json') `
        -RequireExpected | Out-Null
    $redactedPath = Join-Path $testRoot 'evidence-sample.redacted.json'
    $redactedText = Get-Content -LiteralPath $redactedPath -Raw
    if ($redactedText -match 'S-1-5-21|publisher_sha256|C:\\Users' -or
        $redactedText -notmatch 'retained') { throw 'Shared evidence redaction test failed.' }
    if ((Get-Content -LiteralPath $rawEvidence -Raw) -notmatch 'publisher_sha256') {
        throw 'Shared evidence writer modified raw host evidence.'
    }
    $manifest = Read-WindowsTestJson -Path (Join-Path $testRoot 'fetch-manifest.json')
    if ($manifest.schema_version -ne 2 -or @($manifest.artifacts).Count -ne 2 -or
        @($manifest.artifacts | ForEach-Object name) -notcontains 'evidence-sample.redacted.json') {
        throw 'Shared fetch manifest test failed.'
    }
    $resultItem = Get-Item -LiteralPath $resultPath
    $profileEvidencePath = Join-Path $testRoot 'acceptance-evidence-manifest.json'
    Write-WindowsTestJsonAtomic -Path $profileEvidencePath -Value ([ordered]@{
        schema_version = 1; run_id = 'sample-run'; snapshot_sha = '1' * 40
        source_tree_sha = '1' * 40; base_commit_sha = '1' * 40
        profile = 'runtime'; status = 'passed'; generated_utc = '2026-01-01T00:00:01Z'
        bindings = [ordered]@{ runtime_assets_sha256 = '2' * 64; release_artifact_sha256 = $null }
        release_artifact = $null
        checks = @([ordered]@{
            id = 'win01.whpx_qemu_boot_exec_stop'; status = 'passed'; duration_ms = 1000
            stable_code = $null; evidence = @($resultItem.Name)
        })
        files = @([ordered]@{
            name = $resultItem.Name
            sha256 = (Get-FileHash -LiteralPath $resultItem.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            size = [int64]$resultItem.Length; redacted = $true
        })
    })
    $profileSchema = Join-Path $PSScriptRoot 'schemas\profile-evidence.schema.json'
    Assert-WindowsTestProfileEvidenceManifest -RunRoot $testRoot `
        -ManifestPath $profileEvidencePath -SchemaPath $profileSchema | Out-Null
    Add-Content -LiteralPath $resultPath -Value ' ' -Encoding utf8NoBOM
    $tamperRejected = $false
    try {
        Assert-WindowsTestProfileEvidenceManifest -RunRoot $testRoot `
            -ManifestPath $profileEvidencePath -SchemaPath $profileSchema | Out-Null
    }
    catch { $tamperRejected = $true }
    if (-not $tamperRejected) { throw 'Profile evidence digest verifier accepted a modified file.' }
    $profilePlan = Join-Path $PSScriptRoot 'profile-plan.ps1'
    $releasePlan = @(& $profilePlan -Profile release)
    if (($releasePlan -join "`n") -cne (@(
        "release-artifact-import`tnone",
        "archive-acceptance`tnone",
        "release-service-core-update-reboot`trequired"
    ) -join "`n")) { throw 'Release profile plan does not match the catalog expansion.' }
    $diagnosticsPlan = @(& $profilePlan -Profile diagnostics -IncludeOptional)
    if ($diagnosticsPlan[-1] -cne "qemu-sentry-acceptance`tnone") {
        throw 'Optional diagnostics suite is absent from the catalog-derived plan.'
    }
    $candidateArchive = Join-Path $testRoot `
        'lsb-seawork-service-v2.0.0-windows-x86_64.zip'
    $baselineArchive = Join-Path $testRoot `
        'lsb-seawork-service-v1.0.0-windows-x86_64.zip'
    Set-Content -LiteralPath $candidateArchive -Value 'candidate' -Encoding utf8NoBOM
    Set-Content -LiteralPath $baselineArchive -Value 'baseline' -Encoding utf8NoBOM
    Write-WindowsTestJsonAtomic -Path (Join-Path $testRoot `
        'evidence-release-candidate.json') -Value ([ordered]@{
            payload = [ordered]@{ name = Split-Path -Leaf $candidateArchive }
        })
    $selectedRelease = @(Get-WindowsTestReleaseArtifact -RunRoot $testRoot)
    if ($selectedRelease.Count -ne 1 -or
        $selectedRelease[0].Name -cne (Split-Path -Leaf $candidateArchive)) {
        throw 'Candidate evidence did not disambiguate the release archive from its baseline.'
    }
    Remove-Item -LiteralPath (Join-Path $testRoot 'evidence-release-candidate.json') -Force
    $candidateDigest = (Get-FileHash -LiteralPath $candidateArchive `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $selectedByDigest = @(Get-WindowsTestReleaseArtifact -RunRoot $testRoot `
        -ExpectedSha256 $candidateDigest)
    if ($selectedByDigest.Count -ne 1 -or
        $selectedByDigest[0].Name -cne (Split-Path -Leaf $candidateArchive)) {
        throw 'Release binding did not disambiguate the candidate archive from its baseline.'
    }

    $failureRun = Join-Path $testRoot 'forced-smoke-failure'
    $failureState = Join-Path $failureRun 'state-root'
    $failureInstall = Join-Path $failureRun 'install-root'
    $failureService = Join-Path $failureRun 'owned-service.registered'
    $failureArchive = Join-Path $failureRun 'failure-diagnostics'
    New-Item -ItemType Directory -Path `
        (Join-Path $failureState 'logs'),
        (Join-Path $failureState 'runtime\telemetry\incidents\incident-1'),
        (Join-Path $failureState 'config'),
        $failureInstall | Out-Null
    Set-Content -LiteralPath (Join-Path $failureState 'logs\service.jsonl') `
        -Value '{"operation":"sandbox.start","code":"INTERNAL_ERROR"}' -Encoding utf8NoBOM
    Set-Content -LiteralPath `
        (Join-Path $failureState 'runtime\telemetry\incidents\incident-1\incident.json') `
        -Value '{"stable_error_code":"INTERNAL_ERROR"}' -Encoding utf8NoBOM
    Set-Content -LiteralPath (Join-Path $failureState 'config\service.json') `
        -Value '{"credential":"must-not-copy"}' -Encoding utf8NoBOM
    Set-Content -LiteralPath (Join-Path $failureState 'rootfs.ext4') `
        -Value 'disk-must-not-copy' -Encoding utf8NoBOM
    Set-Content -LiteralPath $failureService -Value 'owned' -Encoding utf8NoBOM
    [IO.File]::WriteAllBytes(
        (Join-Path $failureState 'logs\bounded.log'),
        [byte[]]::new($script:FailureDiagnosticMaxFileBytes + 4096)
    )
    $forcedFailure = $null
    try { throw 'forced installed-service smoke failure' }
    catch {
        $forcedFailure = $_
        New-FailureDiagnosticArchive -StateRoot $failureState `
            -DestinationRoot $failureArchive
    }
    finally {
        Remove-Item -LiteralPath $failureService -Force
        Remove-Item -LiteralPath $failureInstall, $failureState -Recurse -Force
    }
    if ($null -eq $forcedFailure -or -not (Test-Path -LiteralPath $failureArchive) -or
        (Test-Path -LiteralPath $failureService) -or (Test-Path -LiteralPath $failureInstall) -or
        (Test-Path -LiteralPath $failureState)) {
        throw 'Forced-smoke diagnostic retention did not survive owned cleanup.'
    }
    $failureManifest = Get-Content -LiteralPath (Join-Path $failureArchive 'manifest.json') `
        -Raw | ConvertFrom-Json
    if (@($failureManifest.files).Count -ne 3 -or
        $failureManifest.total_bytes -gt $failureManifest.bounds.max_total_bytes -or
        @($failureManifest.files | Where-Object truncated).Count -ne 1 -or
        @($failureManifest.files | Where-Object {
            $_.size -gt $failureManifest.bounds.max_file_bytes
        }).Count -ne 0 -or
        (@($failureManifest.files.source_path) -join "`n") -match `
            '(?i)(config|credential|rootfs|\.ext4)') {
        throw 'Failure diagnostic allowlist or bounds were not enforced.'
    }
    foreach ($record in @($failureManifest.files)) {
        $retained = Join-Path $failureArchive ([string]$record.path)
        if ((Get-Item -LiteralPath $retained).Length -ne [long]$record.size -or
            (Get-FileHash -LiteralPath $retained -Algorithm SHA256).Hash.ToLowerInvariant() `
                -cne [string]$record.sha256) {
            throw 'Failure diagnostic manifest hash or size does not match retained evidence.'
        }
    }
    $successRun = Join-Path $testRoot 'successful-smoke'
    New-Item -ItemType Directory -Path $successRun | Out-Null
    if (Test-Path -LiteralPath (Join-Path $successRun 'failure-diagnostics')) {
        throw 'Successful smoke unexpectedly created a failure diagnostic archive.'
    }
    Write-Output 'Validated shared Windows results, evidence fetching, and profile planning.'
}
finally { Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue }
