[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string]$BaselineBinary,
    [string]$CandidateBinary = ".\target\release\lsb.exe",
    [string]$Url = "https://example.com/",
    [string]$UserAgent = "lsb-user-agent-benchmark/1.0",
    [string]$SecretValue = "lsb-secret-substitution-benchmark-value",
    [ValidateRange(0, 100)] [int]$WarmupIterations = 1,
    [ValidateRange(1, 1000)] [int]$Iterations = 5,
    [ValidateRange(25, 5000)] [int]$SampleIntervalMs = 100,
    [ValidateRange(1, 3600)] [int]$TimeoutSeconds = 300,
    [ValidateSet("local", "controlled", "public")] [string]$EndpointKind = "public",
    [string]$RuntimeDataDir,
    [string]$ResultsRoot = ".\target\windows-secret-substitution-vs-user-agent-benchmark"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw "this benchmark requires PowerShell 7 or newer for argument-array process startup"
}
if ([string]::IsNullOrEmpty($SecretValue)) {
    throw "SecretValue must not be empty"
}
try { $parsedUrl = [Uri]$Url }
catch { throw "Url must be an absolute HTTPS URL: $Url" }
if (-not $parsedUrl.IsAbsoluteUri -or $parsedUrl.Scheme -ne "https" -or [string]::IsNullOrWhiteSpace($parsedUrl.DnsSafeHost)) {
    throw "Url must be an absolute HTTPS URL: $Url"
}
if ($parsedUrl.Port -ne 443) {
    throw "Url must use port 443 because HTTPS interception is port-scoped"
}

$script:Utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$script:SchemaVersion = 2
$script:SecretName = "LSB_BENCHMARK_SECRET"
$script:SecretHost = $parsedUrl.DnsSafeHost
$script:Scenarios = @("secret_substitution", "secret_plus_user_agent")
$script:RequestCounts = @(1, 10)
$script:RunSequence = 0
$script:Records = [System.Collections.Generic.List[object]]::new()

function Resolve-FullPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }
    return [System.IO.Path]::GetFullPath((Join-Path (Get-Location) $Path))
}

function Assert-SafePath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $full = Resolve-FullPath $Path
    $root = [System.IO.Path]::GetPathRoot($full)
    if ([string]::IsNullOrWhiteSpace($root) -or $full.TrimEnd('\', '/') -eq $root.TrimEnd('\', '/')) {
        throw "refusing to use filesystem root as results directory: $full"
    }
    if ($full.TrimEnd('\', '/') -eq $script:RepoRoot.TrimEnd('\', '/')) {
        throw "refusing to use repository root as results directory: $full"
    }
}

function Write-JsonFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Value,
        [int]$Depth = 20
    )
    $json = $Value | ConvertTo-Json -Depth $Depth
    [System.IO.File]::WriteAllText($Path, $json + [Environment]::NewLine, $script:Utf8NoBom)
}

function Get-CommandOutput {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [string[]]$Arguments = @()
    )
    try {
        $output = & $Command @Arguments 2>&1
        if ($LASTEXITCODE -ne 0) { return $null }
        return (($output | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine).Trim()
    }
    catch { return $null }
}

function Get-TextSha256 {
    param([Parameter(Mandatory = $true)][string]$Value)
    $hash = [System.Security.Cryptography.SHA256]::HashData($script:Utf8NoBom.GetBytes($Value))
    return ([System.BitConverter]::ToString($hash)).Replace("-", "").ToLowerInvariant()
}

function Get-Architecture {
    $value = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
    if ($value -eq "x64") { return "x86_64" }
    if ($value -eq "arm64") { return "aarch64" }
    return $value
}

function New-ScenarioConfig {
    param(
        [Parameter(Mandatory = $true)][bool]$IncludeUserAgent,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $secrets = [ordered]@{}
    $secrets[$script:SecretName] = [ordered]@{
        value = $SecretValue
        hosts = @($script:SecretHost)
    }
    $config = [ordered]@{
        allow_net = $true
        secrets = $secrets
    }
    if ($IncludeUserAgent) {
        $config.network = [ordered]@{
            https_interception = [ordered]@{
                enabled = $true
                request_headers = @(
                    [ordered]@{ name = "User-Agent"; value = $UserAgent }
                )
            }
        }
    }
    Write-JsonFile -Path $Path -Value $config
    $null = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Get-ProcessTreeSnapshot {
    param([Parameter(Mandatory = $true)][int]$RootPid)
    $discoverySucceeded = $true
    $samplingError = $null
    $selected = [System.Collections.Generic.HashSet[int]]::new()
    $pending = [System.Collections.Generic.Queue[int]]::new()
    $pending.Enqueue($RootPid)
    try {
        $children = @{}
        foreach ($item in Get-CimInstance Win32_Process -Property ProcessId, ParentProcessId -ErrorAction Stop) {
            $parent = [int]$item.ParentProcessId
            if (-not $children.ContainsKey($parent)) {
                $children[$parent] = [System.Collections.Generic.List[int]]::new()
            }
            $children[$parent].Add([int]$item.ProcessId)
        }
        while ($pending.Count -gt 0) {
            $processId = $pending.Dequeue()
            if (-not $selected.Add($processId)) { continue }
            if ($children.ContainsKey($processId)) {
                foreach ($child in $children[$processId]) { $pending.Enqueue($child) }
            }
        }
    }
    catch {
        $discoverySucceeded = $false
        $samplingError = $_.Exception.Message
        $selected.Clear()
        $null = $selected.Add($RootPid)
    }

    $samples = [System.Collections.Generic.List[object]]::new()
    foreach ($processId in $selected) {
        try {
            $process = Get-Process -Id $processId -ErrorAction Stop
            $samples.Add([ordered]@{
                    pid = $processId
                    start_ticks = $process.StartTime.ToUniversalTime().Ticks
                    cpu_seconds = [double]$process.TotalProcessorTime.TotalSeconds
                    working_set_bytes = [uint64]$process.WorkingSet64
                    private_memory_bytes = [uint64]$process.PrivateMemorySize64
                })
        }
        catch { }
    }
    return [ordered]@{
        samples = $samples
        discovery_succeeded = $discoverySucceeded
        error = $samplingError
    }
}

function Get-RequestArguments {
    param([Parameter(Mandatory = $true)][int]$RequestCount)
    $arguments = [System.Collections.Generic.List[string]]::new()
    foreach ($argument in @(
            "sh",
            "-ceu",
            'exec curl --http1.1 -fsS -H "Authorization: Bearer $LSB_BENCHMARK_SECRET" "$@"',
            "sh"
        )) {
        $arguments.Add($argument)
    }
    for ($request = 0; $request -lt $RequestCount; $request++) {
        $arguments.Add("-o")
        $arguments.Add("/dev/null")
        $arguments.Add($Url)
    }
    return $arguments
}

function Invoke-BenchmarkRun {
    param(
        [Parameter(Mandatory = $true)][ValidateSet("secret_substitution", "secret_plus_user_agent")][string]$Scenario,
        [Parameter(Mandatory = $true)][ValidateSet(1, 10)][int]$RequestCount,
        [Parameter(Mandatory = $true)][bool]$IsWarmup,
        [Parameter(Mandatory = $true)][int]$Iteration,
        [Parameter(Mandatory = $true)][int]$OrderIndex,
        [Parameter(Mandatory = $true)][string]$RunId
    )
    [Console]::Error.WriteLine("running $RunId")
    $stdoutPath = Join-Path $script:StdoutDir "$RunId.log"
    $stderrPath = Join-Path $script:StderrDir "$RunId.log"
    $arguments = [System.Collections.Generic.List[string]]::new()
    foreach ($argument in @("run", "--config", $script:Configs[$Scenario], "--")) {
        $arguments.Add($argument)
    }
    foreach ($argument in (Get-RequestArguments -RequestCount $RequestCount)) {
        $arguments.Add($argument)
    }
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $script:Binaries[$Scenario]
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in $arguments) { $null = $startInfo.ArgumentList.Add($argument) }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $timestamp = [DateTime]::UtcNow.ToString("o")
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    if (-not $process.Start()) { throw "failed to start $($script:Binaries[$Scenario])" }
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $lastCpu = @{}
    [double]$totalCpu = 0
    [uint64]$peakWorkingSet = 0
    [uint64]$peakPrivateMemory = 0
    [int]$sampleCount = 0
    $discoverySucceeded = $true
    $samplingError = $null
    $timedOut = $false

    while (-not $process.HasExited) {
        $snapshot = Get-ProcessTreeSnapshot -RootPid $process.Id
        $sampleCount++
        if (-not $snapshot.discovery_succeeded) {
            $discoverySucceeded = $false
            $samplingError = $snapshot.error
        }
        [uint64]$workingSet = 0
        [uint64]$privateMemory = 0
        foreach ($sample in $snapshot.samples) {
            $key = "$($sample.pid):$($sample.start_ticks)"
            $previous = if ($lastCpu.ContainsKey($key)) { [double]$lastCpu[$key] } else { 0.0 }
            $totalCpu += [Math]::Max(0.0, [double]$sample.cpu_seconds - $previous)
            $lastCpu[$key] = [double]$sample.cpu_seconds
            $workingSet += [uint64]$sample.working_set_bytes
            $privateMemory += [uint64]$sample.private_memory_bytes
        }
        if ($workingSet -gt $peakWorkingSet) { $peakWorkingSet = $workingSet }
        if ($privateMemory -gt $peakPrivateMemory) { $peakPrivateMemory = $privateMemory }
        if ($stopwatch.Elapsed.TotalSeconds -gt $TimeoutSeconds) {
            $timedOut = $true
            try { $process.Kill($true) } catch { try { $process.Kill() } catch { } }
            break
        }
        Start-Sleep -Milliseconds $SampleIntervalMs
    }
    $process.WaitForExit()
    $stopwatch.Stop()
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    [System.IO.File]::WriteAllText($stdoutPath, $stdout, $script:Utf8NoBom)
    [System.IO.File]::WriteAllText($stderrPath, $stderr, $script:Utf8NoBom)
    $exitCode = $process.ExitCode
    $succeeded = -not $timedOut -and $exitCode -eq 0
    $process.Dispose()

    return [ordered]@{
        schema_version = $script:SchemaVersion
        run_id = $RunId
        timestamp_utc = $timestamp
        platform = "windows"
        platform_version = [Environment]::OSVersion.VersionString
        architecture = Get-Architecture
        scenario = $Scenario
        request_count = $RequestCount
        iteration = $Iteration
        is_warmup = $IsWarmup
        order_index = $OrderIndex
        binary_path = $script:Binaries[$Scenario]
        exit_code = $exitCode
        timed_out = $timedOut
        succeeded = $succeeded
        wall_time_ms = [double]$stopwatch.Elapsed.TotalMilliseconds
        cpu_time_seconds = $totalCpu
        peak_working_set_bytes = $peakWorkingSet
        peak_private_memory_bytes = $peakPrivateMemory
        measurement_scope = if ($discoverySucceeded) { "process_tree" } else { "root_only" }
        descendant_discovery_succeeded = $discoverySucceeded
        sample_interval_ms = $SampleIntervalMs
        sample_count = $sampleCount
        sampling_error = $samplingError
        stdout_path = $stdoutPath
        stderr_path = $stderrPath
    }
}

function Add-Run {
    param(
        [Parameter(Mandatory = $true)][string]$Scenario,
        [Parameter(Mandatory = $true)][int]$RequestCount,
        [Parameter(Mandatory = $true)][bool]$IsWarmup,
        [Parameter(Mandatory = $true)][int]$Iteration
    )
    $script:RunSequence++
    $kind = if ($IsWarmup) { "warmup" } else { "measured" }
    $runId = "{0:d4}-{1}-{2}-{3:d2}req-{4:d3}" -f $script:RunSequence, $kind, $Scenario, $RequestCount, $Iteration
    try {
        $record = Invoke-BenchmarkRun -Scenario $Scenario -RequestCount $RequestCount -IsWarmup $IsWarmup -Iteration $Iteration -OrderIndex $script:RunSequence -RunId $runId
    }
    catch {
        $stdoutPath = Join-Path $script:StdoutDir "$runId.log"
        $stderrPath = Join-Path $script:StderrDir "$runId.log"
        [System.IO.File]::WriteAllText($stdoutPath, "", $script:Utf8NoBom)
        [System.IO.File]::WriteAllText($stderrPath, $_.Exception.Message + [Environment]::NewLine, $script:Utf8NoBom)
        $record = [ordered]@{
            schema_version = $script:SchemaVersion
            run_id = $runId
            timestamp_utc = [DateTime]::UtcNow.ToString("o")
            platform = "windows"
            platform_version = [Environment]::OSVersion.VersionString
            architecture = Get-Architecture
            scenario = $Scenario
            request_count = $RequestCount
            iteration = $Iteration
            is_warmup = $IsWarmup
            order_index = $script:RunSequence
            binary_path = $script:Binaries[$Scenario]
            exit_code = -1
            timed_out = $false
            succeeded = $false
            wall_time_ms = 0.0
            cpu_time_seconds = 0.0
            peak_working_set_bytes = 0
            peak_private_memory_bytes = 0
            measurement_scope = "root_only"
            descendant_discovery_succeeded = $false
            sample_interval_ms = $SampleIntervalMs
            sample_count = 0
            sampling_error = $_.Exception.Message
            stdout_path = $stdoutPath
            stderr_path = $stderrPath
        }
    }
    $script:Records.Add($record)
    $line = $record | ConvertTo-Json -Depth 10 -Compress
    [System.IO.File]::AppendAllText($script:RunsPath, $line + [Environment]::NewLine, $script:Utf8NoBom)
    return $record
}

function Get-MetricSummary {
    param([double[]]$Values)
    if ($Values.Count -eq 0) { return $null }
    [Array]::Sort($Values)
    $count = $Values.Count
    $sum = ($Values | Measure-Object -Sum).Sum
    $mean = [double]$sum / $count
    $median = if ($count % 2 -eq 1) {
        $Values[[int][Math]::Floor($count / 2)]
    }
    else {
        ($Values[$count / 2 - 1] + $Values[$count / 2]) / 2.0
    }
    $variance = 0.0
    foreach ($value in $Values) { $variance += [Math]::Pow($value - $mean, 2) }
    $p95Index = [Math]::Max(0, [Math]::Ceiling(0.95 * $count) - 1)
    return [ordered]@{
        successful_run_count = $count
        minimum = $Values[0]
        maximum = $Values[$count - 1]
        mean = $mean
        median = $median
        standard_deviation = [Math]::Sqrt($variance / $count)
        p95 = $Values[$p95Index]
    }
}

function Get-ScenarioSummary {
    param(
        [Parameter(Mandatory = $true)][string]$Scenario,
        [Parameter(Mandatory = $true)][int]$RequestCount
    )
    $runs = @($script:Records | Where-Object {
            $_.scenario -eq $Scenario -and
            $_.request_count -eq $RequestCount -and
            -not $_.is_warmup -and
            $_.succeeded
        })
    return [ordered]@{
        wall_time_ms = Get-MetricSummary ([double[]]@($runs | ForEach-Object { $_.wall_time_ms }))
        cpu_time_seconds = Get-MetricSummary ([double[]]@($runs | ForEach-Object { $_.cpu_time_seconds }))
        peak_working_set_bytes = Get-MetricSummary ([double[]]@($runs | ForEach-Object { $_.peak_working_set_bytes }))
        peak_private_memory_bytes = Get-MetricSummary ([double[]]@($runs | ForEach-Object { $_.peak_private_memory_bytes }))
    }
}

function Get-Delta {
    param($Baseline, $Candidate)
    if ($null -eq $Baseline -or $null -eq $Candidate) { return $null }
    $difference = [double]$Candidate.mean - [double]$Baseline.mean
    return [ordered]@{
        candidate_minus_baseline_mean = $difference
        candidate_minus_baseline_percent = if ([double]$Baseline.mean -eq 0) { $null } else { $difference / [double]$Baseline.mean * 100.0 }
    }
}

$script:RepoRoot = Resolve-FullPath (Join-Path $PSScriptRoot "..")
$script:Binaries = @{
    secret_substitution = Resolve-FullPath $BaselineBinary
    secret_plus_user_agent = Resolve-FullPath $CandidateBinary
}
foreach ($scenario in $script:Scenarios) {
    if (-not (Test-Path -LiteralPath $script:Binaries[$scenario] -PathType Leaf)) {
        throw "$scenario binary does not exist: $($script:Binaries[$scenario])"
    }
}
$runtimeRoot = if ([string]::IsNullOrWhiteSpace($RuntimeDataDir)) {
    Join-Path $env:LOCALAPPDATA "lsb"
}
else { Resolve-FullPath $RuntimeDataDir }
foreach ($asset in @("Image", "rootfs.ext4", "initramfs.cpio.gz")) {
    $assetPath = Join-Path $runtimeRoot $asset
    if (-not (Test-Path -LiteralPath $assetPath -PathType Leaf)) {
        throw "runtime asset is unavailable: $assetPath"
    }
}

$resultsBase = Resolve-FullPath $ResultsRoot
Assert-SafePath $resultsBase
$stamp = [DateTime]::Now.ToString("yyyyMMdd-HHmmss")
$script:RunDirectory = Join-Path $resultsBase $stamp
$suffix = 0
while (Test-Path -LiteralPath $script:RunDirectory) {
    $suffix++
    $script:RunDirectory = Join-Path $resultsBase "$stamp-$suffix"
}
$script:StdoutDir = Join-Path $script:RunDirectory "stdout"
$script:StderrDir = Join-Path $script:RunDirectory "stderr"
$configDir = Join-Path $script:RunDirectory "configs"
foreach ($directory in @($script:RunDirectory, $script:StdoutDir, $script:StderrDir, $configDir)) {
    [System.IO.Directory]::CreateDirectory($directory) | Out-Null
}
$script:RunsPath = Join-Path $script:RunDirectory "runs.jsonl"
$script:Configs = @{
    secret_substitution = Join-Path $configDir "secret_substitution.json"
    secret_plus_user_agent = Join-Path $configDir "secret_plus_user_agent.json"
}
New-ScenarioConfig -IncludeUserAgent $false -Path $script:Configs.secret_substitution
New-ScenarioConfig -IncludeUserAgent $true -Path $script:Configs.secret_plus_user_agent
$startedAt = [DateTime]::UtcNow.ToString("o")

foreach ($requestCount in $script:RequestCounts) {
    foreach ($scenario in $script:Scenarios) {
        $preflight = Add-Run -Scenario $scenario -RequestCount $requestCount -IsWarmup $true -Iteration 0
        if (-not $preflight.succeeded) {
            throw "preflight failed for $scenario/$requestCount requests; artifacts retained at $script:RunDirectory"
        }
    }
}
for ($warmup = 1; $warmup -le $WarmupIterations; $warmup++) {
    foreach ($requestCount in $script:RequestCounts) {
        foreach ($scenario in $script:Scenarios) {
            $null = Add-Run -Scenario $scenario -RequestCount $requestCount -IsWarmup $true -Iteration $warmup
        }
    }
}
for ($iteration = 1; $iteration -le $Iterations; $iteration++) {
    $requestOrder = if ($iteration % 2 -eq 1) { @(1, 10) } else { @(10, 1) }
    $scenarioOrder = if ($iteration % 2 -eq 1) {
        @("secret_substitution", "secret_plus_user_agent")
    }
    else { @("secret_plus_user_agent", "secret_substitution") }
    foreach ($requestCount in $requestOrder) {
        foreach ($scenario in $scenarioOrder) {
            $null = Add-Run -Scenario $scenario -RequestCount $requestCount -IsWarmup $false -Iteration $iteration
        }
    }
}

$supportedMetrics = @("wall_time_ms", "cpu_time_seconds", "peak_working_set_bytes", "peak_private_memory_bytes")
$workloads = [ordered]@{}
foreach ($requestCount in $script:RequestCounts) {
    $baseline = Get-ScenarioSummary -Scenario "secret_substitution" -RequestCount $requestCount
    $candidate = Get-ScenarioSummary -Scenario "secret_plus_user_agent" -RequestCount $requestCount
    $deltas = [ordered]@{}
    foreach ($metric in $supportedMetrics) { $deltas[$metric] = Get-Delta $baseline[$metric] $candidate[$metric] }
    $workloads["startup_plus_${requestCount}_requests"] = [ordered]@{
        request_count = $requestCount
        scenarios = [ordered]@{
            secret_substitution = $baseline
            secret_plus_user_agent = $candidate
        }
        candidate_vs_baseline = $deltas
    }
}
$requestScalingScenarios = [ordered]@{}
foreach ($scenario in $script:Scenarios) {
    $metricScaling = [ordered]@{}
    foreach ($metric in $supportedMetrics) {
        $oneMetric = $workloads.startup_plus_1_requests.scenarios[$scenario][$metric]
        $tenMetric = $workloads.startup_plus_10_requests.scenarios[$scenario][$metric]
        if ($null -eq $oneMetric -or $null -eq $tenMetric) {
            $metricScaling[$metric] = $null
            continue
        }
        $difference = [double]$tenMetric.mean - [double]$oneMetric.mean
        $metricScaling[$metric] = [ordered]@{
            ten_minus_one_mean = $difference
            per_additional_request_estimate = $difference / 9.0
        }
    }
    $requestScalingScenarios[$scenario] = $metricScaling
}
$requestScalingDeltas = [ordered]@{}
foreach ($metric in $supportedMetrics) {
    $baselineScaling = $requestScalingScenarios.secret_substitution[$metric]
    $candidateScaling = $requestScalingScenarios.secret_plus_user_agent[$metric]
    if ($null -eq $baselineScaling -or $null -eq $candidateScaling) {
        $requestScalingDeltas[$metric] = $null
        continue
    }
    $difference = [double]$candidateScaling.ten_minus_one_mean - [double]$baselineScaling.ten_minus_one_mean
    $requestScalingDeltas[$metric] = [ordered]@{
        candidate_minus_baseline_ten_minus_one = $difference
        candidate_minus_baseline_per_additional_request_estimate = $difference / 9.0
    }
}
$requestScaling = [ordered]@{
    method = "(startup_plus_10_requests mean - startup_plus_1_requests mean) / 9"
    scenarios = $requestScalingScenarios
    candidate_vs_baseline = $requestScalingDeltas
}
$binaryMetadata = [ordered]@{}
foreach ($scenario in $script:Scenarios) {
    $binary = $script:Binaries[$scenario]
    $binaryMetadata[$scenario] = [ordered]@{
        path = $binary
        sha256 = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
        lsb_version = Get-CommandOutput -Command $binary -Arguments @("--version")
    }
}
$os = $null
try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } catch { }
$summaryPath = Join-Path $script:RunDirectory "summary.json"
$summary = [ordered]@{
    schema_version = $script:SchemaVersion
    platform = "windows"
    platform_version = [Environment]::OSVersion.VersionString
    architecture = Get-Architecture
    benchmark = "secret_substitution_vs_user_agent_injection"
    started_at_utc = $startedAt
    ended_at_utc = [DateTime]::UtcNow.ToString("o")
    binaries = $binaryMetadata
    git_revision = Get-CommandOutput -Command "git" -Arguments @("rev-parse", "HEAD")
    url = $Url
    endpoint_kind = $EndpointKind
    secret_name = $script:SecretName
    secret_value = "<redacted>"
    secret_value_sha256 = Get-TextSha256 $SecretValue
    user_agent = "<redacted>"
    user_agent_sha256 = Get-TextSha256 $UserAgent
    request_counts = $script:RequestCounts
    curl_invocation = "one curl process per VM run; repeated URLs permit connection reuse"
    warmup_iterations = $WarmupIterations
    iterations = $Iterations
    sample_interval_ms = $SampleIntervalMs
    timeout_seconds = $TimeoutSeconds
    supported_metrics = $supportedMetrics
    aggregation = "successful measured runs; population standard deviation; nearest-rank p95"
    logical_processor_count = [Environment]::ProcessorCount
    total_physical_memory_bytes = if ($null -ne $os) { [uint64]$os.TotalVisibleMemorySize * 1024 } else { $null }
    windows_version = if ($null -ne $os) { [string]$os.Caption } else { [Environment]::OSVersion.VersionString }
    powershell_version = $PSVersionTable.PSVersion.ToString()
    artifacts = [ordered]@{
        runs_jsonl = $script:RunsPath
        summary_json = $summaryPath
        stdout_directory = $script:StdoutDir
        stderr_directory = $script:StderrDir
        configs = $script:Configs
    }
    workloads = $workloads
    request_scaling = $requestScaling
    overall_success = @($script:Records | Where-Object { -not $_.is_warmup -and -not $_.succeeded }).Count -eq 0
}
Write-JsonFile -Path $summaryPath -Value $summary
$result = [ordered]@{ overall_success = $summary.overall_success; runs_jsonl = $script:RunsPath; summary_json = $summaryPath }
[Console]::Out.WriteLine(($result | ConvertTo-Json -Compress))
if (-not $summary.overall_success) { exit 1 }
