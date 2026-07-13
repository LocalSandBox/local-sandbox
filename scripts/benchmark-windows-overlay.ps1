[CmdletBinding()]
param(
    [string]$Binary = ".\target\release\lsb.exe",
    [switch]$PrepareFixture,
    [switch]$FixtureOnly,
    [string]$FixtureRoot = ".\target\windows-overlay-benchmark\fixture",
    [string]$CacheRoot = ".\target\windows-overlay-benchmark\cache",
    [string]$ResultsRoot = ".\target\windows-overlay-benchmark\results",
    [string]$RuntimeKernel,
    [string]$RuntimeInitrd,
    [string]$RuntimeRootfs,
    [ValidateSet("Baseline", "Phase1", "Phase2", "Phase3", "Acceptance")]
    [string]$Mode = "Baseline",
    [ValidateRange(0, 1000)]
    [int]$WarmupIterations = 1,
    [ValidateRange(0, 1000)]
    [int]$Iterations = 5,
    [ValidateRange(0, 1000)]
    [int]$MissIterations = 5,
    [ValidateRange(0, 1000)]
    [int]$HitIterations = 5,
    [ValidateRange(0, 100)]
    [int]$MaxFailedPairs = 5,
    [switch]$DefenderDisabledDiagnostic,
    [switch]$SkipBaselineArtifactCopy
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:Utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$script:RunRecords = [System.Collections.Generic.List[object]]::new()
$script:RunSequence = 0

function Resolve-FullPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }
    return [System.IO.Path]::GetFullPath((Join-Path (Get-Location) $Path))
}

function Assert-SafeResetPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $fullPath = Resolve-FullPath $Path
    $root = [System.IO.Path]::GetPathRoot($fullPath)
    if ([string]::IsNullOrWhiteSpace($root) -or $fullPath.TrimEnd('\', '/') -eq $root.TrimEnd('\', '/')) {
        throw "refusing to reset filesystem root '$fullPath'"
    }
    if ($fullPath.TrimEnd('\', '/') -eq $script:RepoRoot.TrimEnd('\', '/')) {
        throw "refusing to reset repository root '$fullPath'"
    }
}

function Reset-Directory {
    param([Parameter(Mandatory = $true)][string]$Path)

    Assert-SafeResetPath $Path
    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Recurse -Force
    }
    [System.IO.Directory]::CreateDirectory($Path) | Out-Null
}

function Write-JsonFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Value,
        [int]$Depth = 20
    )

    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        [System.IO.Directory]::CreateDirectory($parent) | Out-Null
    }
    $json = $Value | ConvertTo-Json -Depth $Depth
    [System.IO.File]::WriteAllText($Path, $json + [Environment]::NewLine, $script:Utf8NoBom)
}

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-StringSha256 {
    param([Parameter(Mandatory = $true)][string]$Value)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $script:Utf8NoBom.GetBytes($Value)
        return ([System.BitConverter]::ToString($sha.ComputeHash($bytes))).Replace("-", "").ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Get-RelativeManifestPath {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $rootWithSeparator = $Root.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    if (-not $Path.StartsWith($rootWithSeparator, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "manifest path '$Path' is outside '$Root'"
    }
    return $Path.Substring($rootWithSeparator.Length).Replace('\', '/')
}

function Write-FixtureManifest {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$ManifestPath
    )

    if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
        throw "fixture root does not exist: $Root"
    }

    $paths = [System.Collections.Generic.List[string]]::new()
    foreach ($directory in [System.IO.Directory]::EnumerateDirectories(
            $Root,
            "*",
            [System.IO.SearchOption]::AllDirectories)) {
        $paths.Add($directory)
    }
    foreach ($file in [System.IO.Directory]::EnumerateFiles(
            $Root,
            "*",
            [System.IO.SearchOption]::AllDirectories)) {
        $paths.Add($file)
    }
    $paths.Sort([System.StringComparer]::Ordinal)

    $entries = [System.Collections.Generic.List[object]]::new()
    foreach ($path in $paths) {
        $relativePath = Get-RelativeManifestPath -Root $Root -Path $path
        if ([System.IO.Directory]::Exists($path)) {
            $entries.Add([ordered]@{
                    path   = $relativePath
                    kind   = "directory"
                    length = 0
                    sha256 = $null
                })
        }
        else {
            $fileInfo = [System.IO.FileInfo]::new($path)
            $entries.Add([ordered]@{
                    path   = $relativePath
                    kind   = "file"
                    length = $fileInfo.Length
                    sha256 = Get-Sha256 $path
                })
        }
    }

    Write-JsonFile -Path $ManifestPath -Value ([ordered]@{
            schema_version = 1
            entries        = $entries
        })
    return [ordered]@{
        path            = $ManifestPath
        sha256          = Get-Sha256 $ManifestPath
        entry_count     = $entries.Count
        file_count      = @($entries | Where-Object { $_.kind -eq "file" }).Count
        directory_count = @($entries | Where-Object { $_.kind -eq "directory" }).Count
    }
}

function New-BenchmarkFixtures {
    param(
        [Parameter(Mandatory = $true)][string]$FixturePath,
        [Parameter(Mandatory = $true)][string]$CorrectnessPath
    )

    Reset-Directory $FixturePath
    Reset-Directory $CorrectnessPath

    for ($directoryIndex = 0; $directoryIndex -lt 100; $directoryIndex++) {
        $directory = Join-Path $FixturePath ("dir-{0:d3}" -f $directoryIndex)
        [System.IO.Directory]::CreateDirectory($directory) | Out-Null
        for ($fileIndex = 0; $fileIndex -lt 20; $fileIndex++) {
            $payload = [byte[]]::new(1024)
            for ($byteIndex = 0; $byteIndex -lt $payload.Length; $byteIndex++) {
                $payload[$byteIndex] = ($directoryIndex * 31 + $fileIndex * 17 + $byteIndex) % 256
            }
            $file = Join-Path $directory ("file-{0:d3}.bin" -f $fileIndex)
            [System.IO.File]::WriteAllBytes($file, $payload)
        }
    }

    [System.IO.Directory]::CreateDirectory((Join-Path $CorrectnessPath "empty-directory")) | Out-Null
    [System.IO.Directory]::CreateDirectory((Join-Path $CorrectnessPath "nested\empty-directory")) | Out-Null
    [System.IO.File]::WriteAllBytes((Join-Path $CorrectnessPath "empty-file"), [byte[]]::new(0))
    [System.IO.File]::WriteAllText(
        (Join-Path $CorrectnessPath "nested\content.txt"),
        "deterministic correctness payload`n",
        $script:Utf8NoBom
    )
    $unicodeDirectory = "caf$([char]0x00e9)"
    $unicodeFilename = "$([char]0x6d4b)$([char]0x8bd5).txt"
    [System.IO.Directory]::CreateDirectory((Join-Path $CorrectnessPath $unicodeDirectory)) | Out-Null
    [System.IO.File]::WriteAllText(
        (Join-Path (Join-Path $CorrectnessPath $unicodeDirectory) $unicodeFilename),
        "utf-8 filename fixture`n",
        $script:Utf8NoBom
    )
}

function Get-CommandOutput {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [string[]]$Arguments = @()
    )

    try {
        $output = & $Command @Arguments 2>&1
        if ($LASTEXITCODE -ne 0) {
            return $null
        }
        return (($output | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine).Trim()
    }
    catch {
        return $null
    }
}

function Get-RuntimeAssets {
    param(
        [AllowNull()][string]$KernelPath,
        [AllowNull()][string]$InitrdPath,
        [AllowNull()][string]$RootfsPath
    )

    $dataDir = Join-Path $env:LOCALAPPDATA "lsb"
    $assets = [ordered]@{}
    $assetPaths = [ordered]@{
        VERSION             = Join-Path $dataDir "VERSION"
        Image               = if ($null -ne $KernelPath) { $KernelPath } else { Join-Path $dataDir "Image" }
        "initramfs.cpio.gz" = if ($null -ne $InitrdPath) { $InitrdPath } else { Join-Path $dataDir "initramfs.cpio.gz" }
        "rootfs.ext4"       = if ($null -ne $RootfsPath) { $RootfsPath } else { Join-Path $dataDir "rootfs.ext4" }
    }
    foreach ($entry in $assetPaths.GetEnumerator()) {
        $name = $entry.Key
        $path = $entry.Value
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $file = [System.IO.FileInfo]::new($path)
            $assets[$name] = [ordered]@{
                path   = $path
                length = $file.Length
                sha256 = Get-Sha256 $path
            }
        }
    }

    $qemu = $null
    $qemuOverride = [Environment]::GetEnvironmentVariable("LSB_QEMU")
    if (-not [string]::IsNullOrWhiteSpace($qemuOverride)) {
        $qemuExecutable = Resolve-FullPath $qemuOverride
        if (-not (Test-Path -LiteralPath $qemuExecutable -PathType Leaf)) {
            throw "LSB_QEMU does not identify a file: $qemuExecutable"
        }
        $qemuImgOverride = [Environment]::GetEnvironmentVariable("LSB_QEMU_IMG")
        $qemuImg = if (-not [string]::IsNullOrWhiteSpace($qemuImgOverride)) {
            Resolve-FullPath $qemuImgOverride
        }
        else {
            Join-Path (Split-Path -Parent $qemuExecutable) "qemu-img.exe"
        }
        $qemu = [ordered]@{
            source                  = "LSB_QEMU"
            current_manifest_path   = $null
            current_manifest_sha256 = $null
            package_version         = $null
            executable_sha256       = Get-Sha256 $qemuExecutable
            qemu_img_sha256         = if (Test-Path -LiteralPath $qemuImg -PathType Leaf) {
                Get-Sha256 $qemuImg
            }
            else {
                $null
            }
            version                 = Get-CommandOutput -Command $qemuExecutable -Arguments @("--version")
            executable_path         = $qemuExecutable
            qemu_img_path           = $qemuImg
            package_directory       = Split-Path -Parent $qemuExecutable
        }
    }
    $qemuCurrentPath = Join-Path $dataDir "tools\qemu\current.json"
    if ($null -eq $qemu -and (Test-Path -LiteralPath $qemuCurrentPath -PathType Leaf)) {
        $current = Get-Content -LiteralPath $qemuCurrentPath -Raw | ConvertFrom-Json
        $qemuExecutable = [string]$current.qemu_system_x86_64
        $qemuImg = [string]$current.qemu_img
        $qemu = [ordered]@{
            source                  = "managed"
            current_manifest_path   = $qemuCurrentPath
            current_manifest_sha256 = Get-Sha256 $qemuCurrentPath
            package_version         = [string]$current.package_version
            executable_sha256       = if (Test-Path -LiteralPath $qemuExecutable -PathType Leaf) {
                Get-Sha256 $qemuExecutable
            }
            else {
                $null
            }
            qemu_img_sha256         = if (Test-Path -LiteralPath $qemuImg -PathType Leaf) {
                Get-Sha256 $qemuImg
            }
            else {
                $null
            }
            version                 = if (Test-Path -LiteralPath $qemuExecutable -PathType Leaf) {
                Get-CommandOutput -Command $qemuExecutable -Arguments @("--version")
            }
            else {
                $null
            }
            executable_path         = $qemuExecutable
            qemu_img_path           = $qemuImg
            package_directory       = if (-not [string]::IsNullOrWhiteSpace($qemuExecutable)) {
                Split-Path -Parent $qemuExecutable
            }
            else {
                $null
            }
        }
    }

    $combinedLines = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in $assets.GetEnumerator()) {
        $combinedLines.Add("$($entry.Key)`t$($entry.Value.length)`t$($entry.Value.sha256)")
    }
    if ($null -ne $qemu) {
        $combinedLines.Add("qemu`t$($qemu.package_version)`t$($qemu.executable_sha256)")
    }
    $combinedLines.Sort([System.StringComparer]::Ordinal)

    return [ordered]@{
        data_dir        = $dataDir
        files           = $assets
        qemu            = $qemu
        combined_sha256 = Get-StringSha256 ($combinedLines -join "`n")
    }
}

function Copy-BaselineArtifacts {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)]$Runtime,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    $manifestPath = Join-Path $Destination "artifact-manifest.json"
    if (Test-Path -LiteralPath $manifestPath -PathType Leaf) {
        Write-Host "Using preserved baseline artifact set at $Destination"
        return Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    }
    if (Test-Path -LiteralPath $Destination) {
        throw "baseline artifact directory exists without a manifest: $Destination"
    }

    [System.IO.Directory]::CreateDirectory((Join-Path $Destination "cli")) | Out-Null
    [System.IO.Directory]::CreateDirectory((Join-Path $Destination "runtime")) | Out-Null
    Copy-Item -LiteralPath $Executable -Destination (Join-Path $Destination "cli\lsb.exe")

    foreach ($entry in $Runtime.files.GetEnumerator()) {
        Copy-Item -LiteralPath $entry.Value.path -Destination (Join-Path $Destination "runtime\$($entry.Key)")
    }

    if ($null -ne $Runtime.qemu) {
        $qemuDestination = Join-Path $Destination "runtime\qemu"
        Copy-Item -LiteralPath $Runtime.qemu.package_directory -Destination $qemuDestination -Recurse
        if (-not [string]::IsNullOrWhiteSpace($Runtime.qemu.current_manifest_path) -and
            (Test-Path -LiteralPath $Runtime.qemu.current_manifest_path -PathType Leaf)) {
            $currentDestination = Join-Path $Destination "runtime\qemu-current.json"
            Copy-Item -LiteralPath $Runtime.qemu.current_manifest_path -Destination $currentDestination
        }
    }

    $artifactManifest = Write-FixtureManifest -Root $Destination -ManifestPath ($manifestPath + ".pending")
    $pending = Get-Content -LiteralPath ($manifestPath + ".pending") -Raw | ConvertFrom-Json
    $manifest = [ordered]@{
        schema_version      = 1
        captured_at_utc     = [DateTime]::UtcNow.ToString("o")
        source_cli_sha256   = Get-Sha256 $Executable
        source_runtime_hash = $Runtime.combined_sha256
        entries             = $pending.entries | Where-Object { $_.path -ne "artifact-manifest.json.pending" }
    }
    Remove-Item -LiteralPath ($manifestPath + ".pending") -Force
    Write-JsonFile -Path $manifestPath -Value $manifest
    $manifest["manifest_sha256"] = Get-Sha256 $manifestPath
    return $manifest
}

function Get-EnvironmentMetadata {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string]$FixturePath,
        [Parameter(Mandatory = $true)][string]$FixtureDigest,
        [Parameter(Mandatory = $true)]$Runtime
    )

    $gitSha = Get-CommandOutput -Command "git" -Arguments @("rev-parse", "HEAD")
    $gitStatus = Get-CommandOutput -Command "git" -Arguments @("status", "--porcelain=v1", "--untracked-files=normal")
    $os = $null
    $cpu = $null
    try { $os = Get-CimInstance Win32_OperatingSystem } catch { }
    try { $cpu = @(Get-CimInstance Win32_Processor | Select-Object -First 1)[0] } catch { }

    $volume = $null
    try {
        $fixtureDrive = [System.IO.Path]::GetPathRoot($FixturePath).TrimEnd('\', '/').TrimEnd(':')
        $volumeInfo = Get-Volume -DriveLetter $fixtureDrive -ErrorAction Stop
        $volume = [ordered]@{
            drive_letter = $fixtureDrive
            filesystem   = [string]$volumeInfo.FileSystem
            size_bytes   = [uint64]$volumeInfo.Size
            free_bytes   = [uint64]$volumeInfo.SizeRemaining
        }
    }
    catch { }

    $defender = $null
    try {
        $status = Get-MpComputerStatus -ErrorAction Stop
        $defender = [ordered]@{
            real_time_protection_enabled = [bool]$status.RealTimeProtectionEnabled
            antivirus_enabled            = [bool]$status.AntivirusEnabled
            am_running_mode              = [string]$status.AMRunningMode
        }
    }
    catch { }

    return [ordered]@{
        captured_at_utc     = [DateTime]::UtcNow.ToString("o")
        git_sha             = $gitSha
        git_dirty           = -not [string]::IsNullOrWhiteSpace($gitStatus)
        windows             = [ordered]@{
            version_string = [Environment]::OSVersion.VersionString
            caption        = if ($null -ne $os) { [string]$os.Caption } else { $null }
            build_number   = if ($null -ne $os) { [string]$os.BuildNumber } else { $null }
        }
        cpu                 = [ordered]@{
            name              = if ($null -ne $cpu) { [string]$cpu.Name } else { $null }
            logical_processors = if ($null -ne $cpu) { [uint32]$cpu.NumberOfLogicalProcessors } else { $null }
        }
        ram_bytes           = if ($null -ne $os) { [uint64]$os.TotalVisibleMemorySize * 1024 } else { $null }
        ntfs_volume         = $volume
        active_power_plan   = Get-CommandOutput -Command "powercfg.exe" -Arguments @("/getactivescheme")
        defender            = $defender
        qemu                = $Runtime.qemu
        cli                 = [ordered]@{
            sha256 = Get-Sha256 $Executable
            length = ([System.IO.FileInfo]::new($Executable)).Length
        }
        runtime             = [ordered]@{
            combined_sha256 = $Runtime.combined_sha256
            files           = $Runtime.files
        }
        fixture_sha256      = $FixtureDigest
    }
}

function Add-ProcessMetrics {
    param(
        [Parameter(Mandatory = $true)][System.Collections.Specialized.OrderedDictionary]$Metrics,
        $ProcessMetrics
    )

    if ($null -eq $ProcessMetrics) {
        return
    }
    foreach ($property in $ProcessMetrics.PSObject.Properties) {
        $Metrics[$property.Name] = $property.Value
    }
}

function Restore-EnvironmentVariable {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowNull()][string]$Value
    )

    if ($null -eq $Value) {
        Remove-Item -Path "Env:$Name" -ErrorAction SilentlyContinue
    }
    else {
        Set-Item -Path "Env:$Name" -Value $Value
    }
}

function Invoke-BenchmarkCommand {
    param(
        [Parameter(Mandatory = $true)][ValidateSet("overlay", "no_mount")][string]$Kind,
        [Parameter(Mandatory = $true)][string]$Scenario,
        [AllowNull()][string]$PairId,
        [Parameter(Mandatory = $true)][int]$OrderInPair,
        [Parameter(Mandatory = $true)][bool]$Measured,
        [Parameter(Mandatory = $true)][bool]$ClearCacheBefore
    )

    if ($ClearCacheBefore) {
        Reset-Directory $script:CacheRoot
    }

    $script:RunSequence++
    $runId = "{0:d4}-{1}" -f $script:RunSequence, $Kind
    $processMetricsPath = Join-Path $script:RunDirectory "$runId.process-metrics.json"
    $stdoutPath = Join-Path $script:RunDirectory "$runId.stdout.log"
    $stderrPath = Join-Path $script:RunDirectory "$runId.stderr.log"

    $arguments = [System.Collections.Generic.List[string]]::new()
    $arguments.Add("run")
    if ($null -ne $script:RuntimeKernel) {
        $arguments.Add("--kernel")
        $arguments.Add($script:RuntimeKernel)
        $arguments.Add("--initrd")
        $arguments.Add($script:RuntimeInitrd)
        $arguments.Add("--rootfs")
        $arguments.Add($script:RuntimeRootfs)
    }
    if ($Kind -eq "overlay") {
        $arguments.Add("--mount")
        $arguments.Add("$($script:FixtureRoot):/workspace")
    }
    $arguments.Add("--")
    $arguments.Add("/bin/true")

    $oldMetricsPath = [Environment]::GetEnvironmentVariable("LSB_WINDOWS_MOUNT_METRICS_PATH")
    $oldCacheRoot = [Environment]::GetEnvironmentVariable("LSB_WINDOWS_MOUNT_CACHE_DIR")
    $exitCode = -1
    $startedAt = [DateTime]::UtcNow
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $env:LSB_WINDOWS_MOUNT_METRICS_PATH = $processMetricsPath
        $env:LSB_WINDOWS_MOUNT_CACHE_DIR = $script:CacheRoot
        & $script:Binary @arguments 1> $stdoutPath 2> $stderrPath
        $exitCode = $LASTEXITCODE
    }
    finally {
        $stopwatch.Stop()
        Restore-EnvironmentVariable -Name "LSB_WINDOWS_MOUNT_METRICS_PATH" -Value $oldMetricsPath
        Restore-EnvironmentVariable -Name "LSB_WINDOWS_MOUNT_CACHE_DIR" -Value $oldCacheRoot
    }

    $processMetrics = $null
    if (Test-Path -LiteralPath $processMetricsPath -PathType Leaf) {
        $processMetrics = Get-Content -LiteralPath $processMetricsPath -Raw | ConvertFrom-Json
    }
    $metrics = [ordered]@{}
    Add-ProcessMetrics -Metrics $metrics -ProcessMetrics $processMetrics
    $metrics["external_total_ms"] = [Math]::Round($stopwatch.Elapsed.TotalMilliseconds, 3)
    $metrics["pair_id"] = $PairId
    $metrics["run_order"] = $OrderInPair

    $record = [ordered]@{
        schema_version          = 1
        run_id                  = $runId
        benchmark_mode          = $Mode
        scenario                = $Scenario
        command_kind            = $Kind
        pair_id                 = $PairId
        order_in_pair           = $OrderInPair
        measured                = $Measured
        started_at_utc          = $startedAt.ToString("o")
        exit_code               = $exitCode
        process_metrics_present = $null -ne $processMetrics
        pair_successful         = $null
        metrics                 = $metrics
        environment             = $script:EnvironmentMetadata
    }
    $recordPath = Join-Path $script:RunDirectory "$runId.json"
    $record["record_path"] = $recordPath
    Write-JsonFile -Path $recordPath -Value $record
    $script:RunRecords.Add($record)
    return $record
}

function Invoke-BenchmarkPair {
    param(
        [Parameter(Mandatory = $true)][string]$Scenario,
        [Parameter(Mandatory = $true)][int]$Index,
        [Parameter(Mandatory = $true)][bool]$Measured,
        [Parameter(Mandatory = $true)][bool]$ClearCacheBeforeOverlay
    )

    $pairId = "{0}-{1}-{2:d3}" -f $Mode.ToLowerInvariant(), $Scenario, $Index
    $overlayFirst = ($Index % 2) -eq 1
    if ($overlayFirst) {
        $first = Invoke-BenchmarkCommand -Kind overlay -Scenario $Scenario -PairId $pairId -OrderInPair 1 -Measured $Measured -ClearCacheBefore $ClearCacheBeforeOverlay
        $second = Invoke-BenchmarkCommand -Kind no_mount -Scenario $Scenario -PairId $pairId -OrderInPair 2 -Measured $Measured -ClearCacheBefore $false
    }
    else {
        $first = Invoke-BenchmarkCommand -Kind no_mount -Scenario $Scenario -PairId $pairId -OrderInPair 1 -Measured $Measured -ClearCacheBefore $false
        $second = Invoke-BenchmarkCommand -Kind overlay -Scenario $Scenario -PairId $pairId -OrderInPair 2 -Measured $Measured -ClearCacheBefore $ClearCacheBeforeOverlay
    }

    $successful = $first.exit_code -eq 0 -and $second.exit_code -eq 0
    foreach ($record in @($first, $second)) {
        $record.pair_successful = $successful
        Write-JsonFile -Path $record.record_path -Value $record
    }
    if (-not $successful) {
        Write-Warning "pair '$pairId' failed and will be excluded from aggregates"
    }
    return $successful
}

function Invoke-SuccessfulPairs {
    param(
        [Parameter(Mandatory = $true)][string]$Scenario,
        [Parameter(Mandatory = $true)][int]$StartIndex,
        [Parameter(Mandatory = $true)][int]$RequiredCount,
        [Parameter(Mandatory = $true)][bool]$Measured,
        [Parameter(Mandatory = $true)][bool]$ClearCacheBeforeOverlay
    )

    $successfulCount = 0
    $attemptCount = 0
    while ($successfulCount -lt $RequiredCount) {
        if ($attemptCount -ge ($RequiredCount + $MaxFailedPairs)) {
            throw "unable to collect $RequiredCount successful '$Scenario' pairs after $attemptCount attempts"
        }
        $attemptCount++
        $successful = Invoke-BenchmarkPair `
            -Scenario $Scenario `
            -Index ($StartIndex + $attemptCount - 1) `
            -Measured $Measured `
            -ClearCacheBeforeOverlay $ClearCacheBeforeOverlay
        if ($successful) {
            $successfulCount++
        }
    }
    return $attemptCount
}

function Get-Median {
    param([double[]]$Values)

    if ($null -eq $Values -or $Values.Count -eq 0) { return $null }
    $sorted = @($Values | Sort-Object)
    $middle = [Math]::Floor($sorted.Count / 2)
    if (($sorted.Count % 2) -eq 1) {
        return [double]$sorted[$middle]
    }
    return ([double]$sorted[$middle - 1] + [double]$sorted[$middle]) / 2.0
}

function Get-NearestRankP95 {
    param([double[]]$Values)

    if ($null -eq $Values -or $Values.Count -eq 0) { return $null }
    $sorted = @($Values | Sort-Object)
    $rank = [Math]::Ceiling(0.95 * $sorted.Count)
    return [double]$sorted[[Math]::Max(0, $rank - 1)]
}

function Get-ScenarioAggregate {
    param([Parameter(Mandatory = $true)][string]$Scenario)

    $records = @($script:RunRecords | Where-Object {
            $_.scenario -eq $Scenario -and $_.measured -and $_.pair_successful -and $_.exit_code -eq 0
        })
    $overlay = @($records | Where-Object { $_.command_kind -eq "overlay" })
    $noMount = @($records | Where-Object { $_.command_kind -eq "no_mount" })
    $overheads = [System.Collections.Generic.List[double]]::new()
    foreach ($overlayRecord in $overlay) {
        $partner = @($noMount | Where-Object { $_.pair_id -eq $overlayRecord.pair_id })
        if ($partner.Count -eq 1) {
            $overheads.Add(
                [double]$overlayRecord.metrics.external_total_ms - [double]$partner[0].metrics.external_total_ms
            )
        }
    }

    $overlayValues = [double[]]@($overlay | ForEach-Object { [double]$_.metrics.external_total_ms })
    $noMountValues = [double[]]@($noMount | ForEach-Object { [double]$_.metrics.external_total_ms })
    $overheadValues = [double[]]$overheads.ToArray()
    return [ordered]@{
        scenario                = $Scenario
        measured_pairs          = $overheads.Count
        overlay_median_ms       = Get-Median $overlayValues
        overlay_p95_ms          = Get-NearestRankP95 $overlayValues
        no_mount_median_ms      = Get-Median $noMountValues
        no_mount_p95_ms         = Get-NearestRankP95 $noMountValues
        paired_overhead_median_ms = Get-Median $overheadValues
        paired_overhead_p95_ms  = Get-NearestRankP95 $overheadValues
    }
}

function Write-Aggregates {
    $scenarioNames = @($script:RunRecords | Where-Object { $_.measured } | ForEach-Object { $_.scenario } | Sort-Object -Unique)
    $scenarioAggregates = [System.Collections.Generic.List[object]]::new()
    foreach ($scenarioName in $scenarioNames) {
        $scenarioAggregates.Add((Get-ScenarioAggregate $scenarioName))
    }

    $aggregate = [ordered]@{
        schema_version        = 1
        benchmark_mode        = $Mode
        acceptance_classification = $script:AcceptanceClassification
        created_at_utc        = [DateTime]::UtcNow.ToString("o")
        fixture_manifest      = $script:FixtureManifest
        correctness_manifest  = $script:CorrectnessManifest
        environment           = $script:EnvironmentMetadata
        baseline_artifacts    = $script:BaselineArtifacts
        run_count             = $script:RunRecords.Count
        scenarios             = $scenarioAggregates
        records               = @($script:RunRecords | ForEach-Object { Split-Path -Leaf $_.record_path })
    }
    Write-JsonFile -Path (Join-Path $script:RunDirectory "aggregate.json") -Value $aggregate

    $csvRows = foreach ($record in $script:RunRecords) {
        [pscustomobject][ordered]@{
            run_id                  = $record.run_id
            benchmark_mode          = $record.benchmark_mode
            scenario                = $record.scenario
            command_kind            = $record.command_kind
            pair_id                 = $record.pair_id
            order_in_pair           = $record.order_in_pair
            measured                = $record.measured
            exit_code               = $record.exit_code
            pair_successful         = $record.pair_successful
            external_total_ms       = $record.metrics.external_total_ms
            mount_work_ms           = if ($record.metrics.Contains("mount_work_ms")) { $record.metrics.mount_work_ms } else { $null }
            cache_decision           = if ($record.metrics.Contains("cache_decision")) { $record.metrics.cache_decision } else { $null }
            terminal_outcome         = if ($record.metrics.Contains("terminal_outcome")) { $record.metrics.terminal_outcome } else { $null }
            process_metrics_present = $record.process_metrics_present
            process_metrics_json    = $record.metrics | ConvertTo-Json -Compress -Depth 20
        }
    }
    $csvRows | Export-Csv -LiteralPath (Join-Path $script:RunDirectory "runs.csv") -NoTypeInformation -Encoding utf8
}

$script:RepoRoot = Resolve-FullPath (Join-Path $PSScriptRoot "..")
$script:Binary = Resolve-FullPath $Binary
$script:FixtureRoot = Resolve-FullPath $FixtureRoot
$script:CacheRoot = Resolve-FullPath $CacheRoot
$script:ResultsRoot = Resolve-FullPath $ResultsRoot
$customRuntimeValues = @($RuntimeKernel, $RuntimeInitrd, $RuntimeRootfs)
$customRuntimeCount = @($customRuntimeValues | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count
if ($customRuntimeCount -ne 0 -and $customRuntimeCount -ne 3) {
    throw "RuntimeKernel, RuntimeInitrd, and RuntimeRootfs must be supplied together"
}
$script:RuntimeKernel = if ($customRuntimeCount -eq 3) { Resolve-FullPath $RuntimeKernel } else { $null }
$script:RuntimeInitrd = if ($customRuntimeCount -eq 3) { Resolve-FullPath $RuntimeInitrd } else { $null }
$script:RuntimeRootfs = if ($customRuntimeCount -eq 3) { Resolve-FullPath $RuntimeRootfs } else { $null }
$benchmarkRoot = Split-Path -Parent $script:FixtureRoot
$correctnessRoot = Join-Path $benchmarkRoot "correctness-fixture"
$fixtureManifestPath = Join-Path $benchmarkRoot "fixture-manifest.json"
$correctnessManifestPath = Join-Path $benchmarkRoot "correctness-manifest.json"

if ($PrepareFixture) {
    New-BenchmarkFixtures -FixturePath $script:FixtureRoot -CorrectnessPath $correctnessRoot
}
$script:FixtureManifest = Write-FixtureManifest -Root $script:FixtureRoot -ManifestPath $fixtureManifestPath
$script:CorrectnessManifest = Write-FixtureManifest -Root $correctnessRoot -ManifestPath $correctnessManifestPath

if ($script:FixtureManifest.file_count -ne 2000 -or $script:FixtureManifest.directory_count -ne 100) {
    throw "performance fixture must contain exactly 2,000 files in 100 directories"
}
foreach ($entry in (Get-Content -LiteralPath $fixtureManifestPath -Raw | ConvertFrom-Json).entries) {
    if ($entry.kind -eq "file" -and $entry.length -ne 1024) {
        throw "performance fixture file '$($entry.path)' is not exactly 1 KiB"
    }
}

Write-Host "Fixture digest: $($script:FixtureManifest.sha256)"
if ($FixtureOnly) {
    Write-Host "Fixture verification completed."
    exit 0
}

if (-not (Test-Path -LiteralPath $script:Binary -PathType Leaf)) {
    throw "benchmark binary does not exist: $($script:Binary)"
}
[System.IO.Directory]::CreateDirectory($script:ResultsRoot) | Out-Null
[System.IO.Directory]::CreateDirectory($script:CacheRoot) | Out-Null
$timestamp = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ")
$classificationSuffix = if ($DefenderDisabledDiagnostic) { "-defender-disabled-diagnostic" } else { "" }
$script:RunDirectory = Join-Path $script:ResultsRoot "$timestamp-$($Mode.ToLowerInvariant())$classificationSuffix"
[System.IO.Directory]::CreateDirectory($script:RunDirectory) | Out-Null

$runtime = Get-RuntimeAssets `
    -KernelPath $script:RuntimeKernel `
    -InitrdPath $script:RuntimeInitrd `
    -RootfsPath $script:RuntimeRootfs
$script:EnvironmentMetadata = Get-EnvironmentMetadata `
    -Executable $script:Binary `
    -FixturePath $script:FixtureRoot `
    -FixtureDigest $script:FixtureManifest.sha256 `
    -Runtime $runtime
$defenderEnabled = $null -ne $script:EnvironmentMetadata.defender -and `
    $script:EnvironmentMetadata.defender.real_time_protection_enabled
if ($Mode -in @("Baseline", "Acceptance") -and -not $defenderEnabled -and -not $DefenderDisabledDiagnostic) {
    throw "Defender real-time protection is disabled or could not be verified. Use -DefenderDisabledDiagnostic only for a non-acceptance diagnostic run."
}
$script:AcceptanceClassification = if ($DefenderDisabledDiagnostic) {
    "defender_disabled_diagnostic"
}
else {
    "primary"
}
$script:BaselineArtifacts = $null
if ($Mode -eq "Baseline" -and -not $SkipBaselineArtifactCopy) {
    $baselineDestination = Join-Path $benchmarkRoot "baseline-artifacts\h0-g0"
    $script:BaselineArtifacts = Copy-BaselineArtifacts `
        -Executable $script:Binary `
        -Runtime $runtime `
        -Destination $baselineDestination
}
Write-JsonFile -Path (Join-Path $script:RunDirectory "environment.json") -Value $script:EnvironmentMetadata

try {
    if ($Mode -eq "Acceptance") {
        $warmupAttempts = Invoke-SuccessfulPairs `
            -Scenario "cache_miss" `
            -StartIndex 1 `
            -RequiredCount $WarmupIterations `
            -Measured $false `
            -ClearCacheBeforeOverlay $true
        $missAttempts = Invoke-SuccessfulPairs `
            -Scenario "cache_miss" `
            -StartIndex ($warmupAttempts + 1) `
            -RequiredCount $MissIterations `
            -Measured $true `
            -ClearCacheBeforeOverlay $true

        Reset-Directory $script:CacheRoot
        $seed = Invoke-BenchmarkCommand `
            -Kind overlay `
            -Scenario "cache_hit_seed" `
            -PairId $null `
            -OrderInPair 0 `
            -Measured $false `
            -ClearCacheBefore $false
        if ($seed.exit_code -ne 0) {
            throw "cache-hit seed run failed with exit code $($seed.exit_code)"
        }
        Invoke-SuccessfulPairs `
            -Scenario "cache_hit" `
            -StartIndex 1 `
            -RequiredCount $HitIterations `
            -Measured $true `
            -ClearCacheBeforeOverlay $false | Out-Null
    }
    else {
        $scenario = if ($Mode -eq "Baseline") { "legacy_overlay" } else { "$($Mode.ToLowerInvariant())_overlay" }
        $warmupAttempts = Invoke-SuccessfulPairs `
            -Scenario $scenario `
            -StartIndex 1 `
            -RequiredCount $WarmupIterations `
            -Measured $false `
            -ClearCacheBeforeOverlay $false
        Invoke-SuccessfulPairs `
            -Scenario $scenario `
            -StartIndex ($warmupAttempts + 1) `
            -RequiredCount $Iterations `
            -Measured $true `
            -ClearCacheBeforeOverlay $false | Out-Null
    }
}
finally {
    Write-Aggregates
}

Write-Host "Benchmark results: $($script:RunDirectory)"
