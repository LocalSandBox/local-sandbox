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
$scriptsRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
if ($Phase -ne 'Normal') { throw 'The installed-service-smoke suite does not support reboot phases.' }

$releaseSuite = Join-Path $PSScriptRoot '..\release\release-candidate.ps1'
$reuseCandidate = Join-Path $scriptsRoot 'windows-test-reuse-candidate.ps1'
$harness = Join-Path $scriptsRoot 'windows-test-service-harness.ps1'
$heartbeatEvidenceName = 'evidence-service-heartbeats.json'

function Start-HeartbeatCollector {
    param([Parameter(Mandatory = $true)][string] $CaptureRoot)
    New-Item -ItemType Directory -Path $CaptureRoot | Out-Null
    $readyPath = Join-Path $CaptureRoot 'ready'
    $job = Start-Job -ScriptBlock {
        param($Root, $Ready)
        $ErrorActionPreference = 'Stop'
        $listener = [Net.HttpListener]::new()
        $listener.Prefixes.Add('http://127.0.0.1:9/')
        try {
            $listener.Start()
            [IO.File]::WriteAllText($Ready, 'ready', [Text.UTF8Encoding]::new($false))
            $sequence = 0
            while ($listener.IsListening) {
                $context = $listener.GetContext()
                $sequence++
                $path = Join-Path $Root ('envelope-{0:d4}.bin' -f $sequence)
                $stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
                try { $context.Request.InputStream.CopyTo($stream) }
                finally { $stream.Dispose() }
                $context.Response.StatusCode = 200
                $context.Response.ContentLength64 = 0
                $context.Response.Close()
            }
        }
        finally {
            if ($listener.IsListening) { $listener.Stop() }
            $listener.Close()
        }
    } -ArgumentList $CaptureRoot, $readyPath
    for ($attempt = 0; $attempt -lt 100 -and -not (Test-Path -LiteralPath $readyPath); $attempt++) {
        if ($job.State -in @('Failed', 'Stopped', 'Completed')) {
            $failure = Receive-Job -Job $job -ErrorAction SilentlyContinue | Out-String
            Remove-Job -Job $job -Force
            throw "Heartbeat collector failed before readiness: $failure"
        }
        Start-Sleep -Milliseconds 100
    }
    if (-not (Test-Path -LiteralPath $readyPath -PathType Leaf)) {
        Stop-Job -Job $job -ErrorAction SilentlyContinue
        Remove-Job -Job $job -Force
        throw 'Heartbeat collector did not become ready.'
    }
    return $job
}

function Wait-ServiceHeartbeats {
    param(
        [Parameter(Mandatory = $true)][string] $CaptureRoot,
        [Parameter(Mandatory = $true)][string] $ExpectedNativeTag,
        [Parameter(Mandatory = $true)][string] $ExpectedNativeCommit
    )
    $deadline = [DateTime]::UtcNow.AddMinutes(16)
    do {
        $heartbeats = @()
        foreach ($file in Get-ChildItem -LiteralPath $CaptureRoot -Filter 'envelope-*.bin' -File) {
            $text = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($file.FullName))
            if ($text.Contains('"transaction":"service.heartbeat"', [StringComparison]::Ordinal)) {
                $trace = [regex]::Match($text, '"trace_id":"([0-9a-f]{32})"')
                if (-not $trace.Success) { throw 'Captured service heartbeat has no valid trace ID.' }
                $heartbeats += [pscustomobject]@{ path = $file.FullName; trace_id = $trace.Groups[1].Value }
            }
        }
        if ($heartbeats.Count -ge 2) {
            $observed = @($heartbeats | Select-Object -First 2)
            if ($observed[0].trace_id -ceq $observed[1].trace_id) {
                throw 'Consecutive service heartbeats reused one trace boundary.'
            }
            [ordered]@{
                schema_version = 1
                suite = 'installed-service-smoke'
                status = 'passed'
                snapshot_sha = $SnapshotSha
                sentry_native_tag = $ExpectedNativeTag
                sentry_native_commit = $ExpectedNativeCommit
                service_state = 'Running'
                heartbeat_count = 2
                distinct_trace_boundaries = $true
                first_trace_id = [string]$observed[0].trace_id
                second_trace_id = [string]$observed[1].trace_id
            } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath `
                (Join-Path $RunRoot $heartbeatEvidenceName) -Encoding utf8NoBOM
            return
        }
        Start-Sleep -Seconds 2
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Did not observe two consecutive service heartbeat envelopes within 16 minutes.'
}
if ([string]::IsNullOrWhiteSpace($ReuseRunId)) {
    if (-not (Test-Path -LiteralPath (Join-Path $RunRoot 'evidence-release-candidate.json') `
        -PathType Leaf)) {
        & $releaseSuite -Phase Normal -RunRoot $RunRoot -SnapshotSha $SnapshotSha
    }
}
else {
    & $reuseCandidate `
        -RunRoot $RunRoot `
        -SnapshotSha $SnapshotSha `
        -SourceRunId $ReuseRunId
}
$collector = $null
$captureRoot = Join-Path $RunRoot 'raw-service-heartbeats'
try {
    $candidateEvidence = Get-Content -LiteralPath `
        (Join-Path $RunRoot 'evidence-release-candidate.json') -Raw | ConvertFrom-Json
    $lock = Get-Content -LiteralPath (Join-Path $PWD 'sentry-native.lock.json') -Raw |
        ConvertFrom-Json
    if ([string]$candidateEvidence.sentry.native_tag -cne [string]$lock.sentry_native.tag -or
        [string]$candidateEvidence.sentry.native_commit -cne [string]$lock.sentry_native.commit) {
        throw 'Release candidate Sentry Native provenance does not match the dependency lock.'
    }
    $collector = Start-HeartbeatCollector -CaptureRoot $captureRoot
    & $harness `
        -Mode InstallAndSmoke `
        -RunRoot $RunRoot `
        -SnapshotSha $SnapshotSha `
        -ClientHarnessLeaf 'SeaWork LocalSandbox Acceptance'
    Wait-ServiceHeartbeats `
        -CaptureRoot $captureRoot `
        -ExpectedNativeTag ([string]$candidateEvidence.sentry.native_tag) `
        -ExpectedNativeCommit ([string]$candidateEvidence.sentry.native_commit)
}
finally {
    if (Test-Path -LiteralPath (Join-Path $RunRoot 'installed-service-state.json')) {
        & $harness -Mode Uninstall -RunRoot $RunRoot -SnapshotSha $SnapshotSha
        [ordered]@{ schema_version = 1; status = 'passed'; owned_resources_removed = $true } |
            ConvertTo-Json | Set-Content -LiteralPath (Join-Path $RunRoot 'evidence-uninstall.json') -Encoding utf8NoBOM
    }
    if ($null -ne $collector) {
        Stop-Job -Job $collector -ErrorAction SilentlyContinue
        Remove-Job -Job $collector -Force -ErrorAction SilentlyContinue
    }
}

$manifestPath = Join-Path $RunRoot 'fetch-manifest.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
foreach ($name in @(
    'evidence-installed-smoke.json',
    'evidence-node-mount-free.json',
    'evidence-node-caller-test-root.json',
    'evidence-node-caller-prefix-collision.json',
    'evidence-node-caller-wrong-publisher.json',
    'evidence-node-caller-wrong-owner.json',
    'evidence-node-direct-mounts.json',
    'evidence-node-direct-mounts-repeat.json',
    'evidence-node-network.json',
    'evidence-node-sequential.json',
    'evidence-uninstall.json',
    $heartbeatEvidenceName
)) {
    $path = Join-Path $RunRoot $name
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        $manifest.artifacts += [pscustomobject]@{
            name = $name
            sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            size = (Get-Item -LiteralPath $path).Length
        }
    }
}
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding utf8NoBOM
$manifestWriter = Join-Path $scriptsRoot 'write-seawork-test-release-manifest.ps1'
& $manifestWriter -RunRoot $RunRoot -SnapshotSha $SnapshotSha | Out-Null
