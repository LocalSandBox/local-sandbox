[CmdletBinding()]
param([string] $WindowsTestRoot = $PSScriptRoot)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$schemaRoot = Join-Path $WindowsTestRoot 'schemas'
foreach ($schema in @(Get-ChildItem -LiteralPath $schemaRoot -Filter '*.schema.json' -File)) {
    Get-Content -LiteralPath $schema.FullName -Raw | ConvertFrom-Json | Out-Null
}
if (-not (Test-Json -LiteralPath (Join-Path $WindowsTestRoot 'catalog.json') `
    -SchemaFile (Join-Path $schemaRoot 'catalog.schema.json'))) {
    throw 'catalog.json does not satisfy catalog.schema.json'
}

$sha40 = '1' * 40
$sha64 = '2' * 64
$result = [ordered]@{
    schema_version = 2; run_id = 'sample-run'; snapshot_sha = $sha40
    suite = 'sample-suite'; category = 'runtime'; phase = 'Normal'; status = 'passed'
    exit_code = 0; failure_code = $null; started_utc = '2026-01-01T00:00:00Z'
    finished_utc = '2026-01-01T00:00:01Z'; duration_ms = 1000; boot_id = '1234'
    output_file = 'output-sample-suite-normal.log'; required_capabilities = @('whpx')
    mutations = @('WHPX VM'); expected_artifacts = @('evidence-sample.json')
    acceptance_checks = @('win01.whpx_qemu_boot_exec_stop')
    bindings = [ordered]@{ runtime_assets_sha256 = $sha64; release_artifact_sha256 = $null }
} | ConvertTo-Json -Depth 10
if (-not (Test-Json -Json $result -SchemaFile (Join-Path $schemaRoot 'result.schema.json'))) {
    throw 'result schema rejected its canonical sample'
}

$fetch = [ordered]@{
    schema_version = 2; run_id = 'sample-run'; generated_utc = '2026-01-01T00:00:01Z'
    artifacts = @([ordered]@{
        name = 'evidence-sample.json'; sha256 = $sha64; size = 10
        kind = 'evidence'; redacted = $true
    })
} | ConvertTo-Json -Depth 10
if (-not (Test-Json -Json $fetch -SchemaFile (Join-Path $schemaRoot 'fetch.schema.json'))) {
    throw 'fetch schema rejected its canonical sample'
}

$evidence = [ordered]@{
    schema_version = 1; git_sha = $sha40; artifact_sha256 = $sha64
    artifact_size_bytes = 10; profile = 'full'; generated_utc = '2026-01-01T00:00:01Z'
    environment = [ordered]@{
        os_build = '10.0.26100'; architecture = 'x86_64'; service_version = '1.0.0'
        bundle_version = '1.0.0'; qemu_version = '11.0.50'
        runner_identity_sha256 = $sha64; policy_sha256 = $sha64
    }
    checks = @([ordered]@{
        id = 'rel01.artifact_trust'; status = 'passed'; duration_ms = 10
        evidence = @('evidence/sample.redacted.json')
    })
    files = @([ordered]@{
        relative_path = 'evidence/sample.redacted.json'; sha256 = $sha64
        size_bytes = 10; redacted = $true
    })
} | ConvertTo-Json -Depth 10
if (-not (Test-Json -Json $evidence -SchemaFile (Join-Path $schemaRoot 'evidence.schema.json'))) {
    throw 'evidence schema rejected its canonical sample'
}
$profileEvidence = [ordered]@{
    schema_version = 1; run_id = 'sample-run'; snapshot_sha = $sha40; profile = 'release'
    status = 'passed'; generated_utc = '2026-01-01T00:00:01Z'
    bindings = [ordered]@{ runtime_assets_sha256 = $sha64; release_artifact_sha256 = $sha64 }
    release_artifact = [ordered]@{
        name = 'lsb-seawork-service-v1.0.0-windows-x86_64.zip'; sha256 = $sha64; size = 10
    }
    checks = @([ordered]@{
        id = 'rel01.artifact_trust'; status = 'passed'; duration_ms = 10
        stable_code = $null; evidence = @('result-archive-acceptance-normal.json')
    })
    files = @([ordered]@{
        name = 'result-archive-acceptance-normal.json'; sha256 = $sha64
        size = 10; redacted = $true
    })
} | ConvertTo-Json -Depth 10
if (-not (Test-Json -Json $profileEvidence `
    -SchemaFile (Join-Path $schemaRoot 'profile-evidence.schema.json'))) {
    throw 'profile evidence schema rejected its canonical sample'
}
Write-Output 'Validated catalog, result, fetch, and evidence JSON schemas.'
