[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'lib\common.ps1')
. (Join-Path $PSScriptRoot 'lib\evidence.ps1')

$testRoot = Join-Path ([IO.Path]::GetTempPath()) "windows-test-contract-$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $testRoot | Out-Null
try {
    $resultPath = Join-Path $testRoot 'result-sample-suite-normal.json'
    [ordered]@{
        schema_version = 2; run_id = 'sample-run'; snapshot_sha = '1' * 40
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
    Write-Output 'Validated shared Windows result redaction and fetch manifest behavior.'
}
finally { Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue }
