[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Normal', 'BeforeReboot', 'AfterReboot')]
    [string] $Phase,

    [Parameter(Mandatory = $true)]
    [string] $RunRoot,

    [Parameter(Mandatory = $true)]
    [string] $SnapshotSha
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$scriptsRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))

if ($Phase -ne 'Normal') {
    throw 'The release-candidate suite does not support reboot phases.'
}

function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)][string] $Executable,
        [Parameter(Mandatory = $true)][string[]] $Arguments,
        [Parameter(Mandatory = $true)][string] $Label
    )

    if ([IO.Path]::GetExtension($Executable) -ieq '.ps1') {
        & pwsh.exe -NoProfile -NonInteractive -File $Executable @Arguments
    }
    else {
        & $Executable @Arguments
    }
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE"
    }
}

function Resolve-RegularFile {
    param([Parameter(Mandatory = $true)][string] $Path, [Parameter(Mandatory = $true)][string] $Label)

    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction Stop
    $item = Get-Item -LiteralPath $resolved.Path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "$Label must be a regular non-reparse file"
    }
    return $resolved.Path
}

function Resolve-RegularDirectory {
    param([Parameter(Mandatory = $true)][string] $Path, [Parameter(Mandatory = $true)][string] $Label)

    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction Stop
    $item = Get-Item -LiteralPath $resolved.Path -Force
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "$Label must be a regular non-reparse directory"
    }
    return $resolved.Path.TrimEnd('\')
}

function Resolve-EventMessageTools {
    $roots = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots'
    if ([string]::IsNullOrWhiteSpace([string]$roots.KitsRoot10)) {
        throw 'Windows SDK KitsRoot10 is unavailable.'
    }
    $toolset = Get-ChildItem -LiteralPath (Join-Path $roots.KitsRoot10 'bin') -Directory |
        Sort-Object Name -Descending |
        Where-Object {
            (Test-Path -LiteralPath (Join-Path $_.FullName 'x64\mc.exe') -PathType Leaf) -and
            (Test-Path -LiteralPath (Join-Path $_.FullName 'x64\rc.exe') -PathType Leaf)
        } |
        Select-Object -First 1
    if ($null -eq $toolset) {
        throw 'No complete x64 Windows SDK mc.exe/rc.exe toolset was found.'
    }
    return [pscustomobject]@{
        Mc = Join-Path $toolset.FullName 'x64\mc.exe'
        Rc = Join-Path $toolset.FullName 'x64\rc.exe'
    }
}

function Write-FetchManifest {
    param([Parameter(Mandatory = $true)][string[]] $Names)

    $artifacts = foreach ($name in $Names) {
        $path = Resolve-RegularFile (Join-Path $RunRoot $name) "fetch artifact $name"
        $item = Get-Item -LiteralPath $path
        [ordered]@{
            name = $name
            sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            size = $item.Length
        }
    }
    [ordered]@{
        schema_version = 1
        run_id = Split-Path -Leaf ([IO.Path]::GetFullPath($RunRoot).TrimEnd('\'))
        artifacts = @($artifacts)
    } | ConvertTo-Json -Depth 6 | Set-Content `
        -LiteralPath (Join-Path $RunRoot 'fetch-manifest.json') `
        -Encoding utf8NoBOM
}

if ([string]::IsNullOrWhiteSpace($env:LSB_WINDOWS_TEST_ASSETS_ROOT)) {
    throw 'LSB_WINDOWS_TEST_ASSETS_ROOT is not configured by the Windows test runner.'
}
$assetsRoot = Resolve-RegularDirectory $env:LSB_WINDOWS_TEST_ASSETS_ROOT 'test assets root'
$runtime = Resolve-RegularDirectory (Join-Path $assetsRoot 'runtime') 'runtime assets'
$qemu = Resolve-RegularDirectory (Join-Path $assetsRoot 'qemu') 'managed QEMU assets'
foreach ($asset in @('Image', 'initramfs.cpio.gz', 'rootfs.ext4')) {
    Resolve-RegularFile (Join-Path $runtime $asset) "runtime asset $asset" | Out-Null
}
foreach ($asset in @('qemu-system-x86_64.exe', 'qemu-img.exe')) {
    Resolve-RegularFile (Join-Path $qemu $asset) "managed QEMU asset $asset" | Out-Null
}
$pfx = Resolve-RegularFile $env:SEAWORK_WINDOWS_PFX_PATH 'signing PFX'
$passwordFile = Resolve-RegularFile $env:SEAWORK_WINDOWS_PFX_PASSWORD_FILE 'signing password file'
$signingScript = Resolve-RegularFile `
    (Join-Path $scriptsRoot 'windows-test-signing-assets.ps1') `
    'signing asset verifier'
$certificateInfo = (& $signingScript -Mode Verify | Out-String | ConvertFrom-Json)
if ($certificateInfo.status -ne 'ready' -or
    $certificateInfo.sha256_thumbprint -notmatch '^[0-9a-f]{64}$') {
    throw 'Protected signing assets did not produce valid public certificate metadata.'
}

$workspaceMetadata = (& cargo metadata --locked --no-deps --format-version 1 |
    Out-String | ConvertFrom-Json)
if ($LASTEXITCODE -ne 0) {
    throw 'cargo metadata could not resolve the release candidate version.'
}
$servicePackages = @($workspaceMetadata.packages | Where-Object {
    $_.name -ceq 'lsb-seawork-service'
})
if ($servicePackages.Count -ne 1 -or
    [string]$servicePackages[0].version -notmatch '^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$') {
    throw 'cargo metadata did not contain one bounded service package version.'
}
$version = [string]$servicePackages[0].version
$releaseRoot = Join-Path $RunRoot 'release-work'
if (Test-Path -LiteralPath $releaseRoot) {
    throw 'The release work directory already exists.'
}
$input = Join-Path $releaseRoot 'input'
$metadata = Join-Path $input 'metadata'
$out = Join-Path $releaseRoot 'out'
$catalogWork = Join-Path $releaseRoot 'catalog-work'
New-Item -ItemType Directory -Path $input, $out, $catalogWork | Out-Null

$sentryDependencyJson = Join-Path $releaseRoot 'sentry-native-prepared.json'
Invoke-Native (Join-Path $PWD 'scripts\prepare-sentry-native.ps1') @(
    '-OutputJson', $sentryDependencyJson
) 'Sentry Native preparation'
$sentryDependency = Get-Content -LiteralPath $sentryDependencyJson -Raw | ConvertFrom-Json
$env:LSB_SENTRY_DSN = 'http://public@127.0.0.1:9/1'
$env:LSB_SENTRY_ENVIRONMENT = 'windows-release-candidate'
$env:LSB_SENTRY_TRACES_SAMPLE_RATE = '1'
$env:LSB_SENTRY_NATIVE_INCLUDE_DIR = [string]$sentryDependency.include_dir
$env:LSB_SENTRY_NATIVE_LIBRARY = [string]$sentryDependency.library
$env:LSB_SENTRY_CRASHPAD_HANDLER = [string]$sentryDependency.crashpad_handler
$env:LSB_SENTRY_CRASHPAD_WER = [string]$sentryDependency.crashpad_wer
$crashpadHandler = Join-Path $input 'crashpad_handler.exe'
$crashpadWer = Join-Path $input 'crashpad_wer.dll'
$telemetryBinaries = @($crashpadHandler, $crashpadWer)
Copy-Item -LiteralPath $env:LSB_SENTRY_CRASHPAD_HANDLER -Destination $crashpadHandler
Copy-Item -LiteralPath $env:LSB_SENTRY_CRASHPAD_WER -Destination $crashpadWer

$targetRoot = if ([string]::IsNullOrWhiteSpace($env:CARGO_TARGET_DIR)) {
    Join-Path $PWD 'target'
}
else {
    [IO.Path]::GetFullPath($env:CARGO_TARGET_DIR)
}
$service = Join-Path $targetRoot 'x86_64-pc-windows-msvc\release\localsandbox-seawork-service.exe'
$dumpHelper = Join-Path $targetRoot 'x86_64-pc-windows-msvc\release\localsandbox-qemu-dump-helper.exe'
$pdb = Join-Path $targetRoot 'x86_64-pc-windows-msvc\release\localsandbox_seawork_service.pdb'
$eventTools = Resolve-EventMessageTools
$priorRustFlags = $env:RUSTFLAGS
$priorCompileEventMessages = $env:LSB_COMPILE_EVENT_MESSAGES
$priorMcPath = $env:LSB_WINDOWS_MC_PATH
$priorRcPath = $env:LSB_WINDOWS_RC_PATH
$priorPublisher = $env:SEAWORK_PUBLISHER_SHA256
$priorPreviousPublisher = $env:SEAWORK_PUBLISHER_SHA256_PREVIOUS
try {
    foreach ($outputPath in @($service, $dumpHelper, $pdb)) {
        if (Test-Path -LiteralPath $outputPath) {
            Resolve-RegularFile $outputPath 'cached release output' | Out-Null
            Remove-Item -LiteralPath $outputPath -Force
        }
    }
    $env:RUSTFLAGS = '-C target-feature=+crt-static'
    $env:LSB_COMPILE_EVENT_MESSAGES = '1'
    $env:LSB_WINDOWS_MC_PATH = $eventTools.Mc
    $env:LSB_WINDOWS_RC_PATH = $eventTools.Rc
    $env:SEAWORK_PUBLISHER_SHA256 = [string]$certificateInfo.sha256_thumbprint
    $env:SEAWORK_PUBLISHER_SHA256_PREVIOUS = ''
    Invoke-Native cargo @(
        'build', '-p', 'lsb-seawork-service', '-p', 'lsb-qemu-dump-helper', '--locked', '--release',
        '--target', 'x86_64-pc-windows-msvc', '--features', 'sentry-telemetry'
    ) 'production service build'
}
finally {
    $env:RUSTFLAGS = $priorRustFlags
    $env:LSB_COMPILE_EVENT_MESSAGES = $priorCompileEventMessages
    $env:LSB_WINDOWS_MC_PATH = $priorMcPath
    $env:LSB_WINDOWS_RC_PATH = $priorRcPath
    $env:SEAWORK_PUBLISHER_SHA256 = $priorPublisher
    $env:SEAWORK_PUBLISHER_SHA256_PREVIOUS = $priorPreviousPublisher
}
Resolve-RegularFile $service 'release service PE' | Out-Null
Resolve-RegularFile $dumpHelper 'release QEMU dump helper PE' | Out-Null
Resolve-RegularFile $pdb 'release service PDB' | Out-Null

$eventUnsigned = Join-Path $releaseRoot 'event-messages-unsigned.json'
Invoke-Native (Join-Path $PWD 'scripts\verify-seawork-event-messages.ps1') @(
    '-ServiceBinary', $service,
    '-OutputPath', $eventUnsigned
) 'unsigned Event Log resource verification'

Invoke-Native (Join-Path $PWD 'scripts\sign-seawork-service.ps1') @(
    '-Mode', 'SignPe',
    '-UseLocalMachineStore',
    '-ServiceBinary', $service,
    '-PfxPath', $pfx,
    '-PasswordFile', $passwordFile,
    '-ExpectedPublisherSubject', [string]$certificateInfo.subject,
    '-ExpectedPublisherSha256', [string]$certificateInfo.sha256_thumbprint
) 'service PE signing'
Invoke-Native (Join-Path $PWD 'scripts\sign-seawork-service.ps1') @(
    '-Mode', 'SignDumpHelperPe',
    '-UseLocalMachineStore',
    '-DumpHelperBinary', $dumpHelper,
    '-PfxPath', $pfx,
    '-PasswordFile', $passwordFile,
    '-ExpectedPublisherSubject', [string]$certificateInfo.subject,
    '-ExpectedPublisherSha256', [string]$certificateInfo.sha256_thumbprint
) 'QEMU dump helper PE signing'
& (Join-Path $PWD 'scripts\sign-seawork-service.ps1') `
    -Mode SignTelemetryPe `
    -UseLocalMachineStore `
    -TelemetryBinary $telemetryBinaries `
    -PfxPath $pfx `
    -PasswordFile $passwordFile `
    -ExpectedPublisherSubject ([string]$certificateInfo.subject) `
    -ExpectedPublisherSha256 ([string]$certificateInfo.sha256_thumbprint)

$eventSigned = Join-Path $releaseRoot 'event-messages-signed.json'
Invoke-Native (Join-Path $PWD 'scripts\verify-seawork-event-messages.ps1') @(
    '-ServiceBinary', $service,
    '-OutputPath', $eventSigned
) 'signed Event Log resource verification'

$dependencies = Join-Path $input 'runtime-dependencies.json'
& (Join-Path $PWD 'scripts\inspect-seawork-service-dependencies.ps1') `
    -ServiceBinary $service `
    -TelemetryBinary $telemetryBinaries `
    -OutputPath $dependencies
$cargoMetadata = Join-Path $input 'cargo-metadata.json'
$metadataProcess = Start-Process cargo.exe `
    -ArgumentList @('metadata', '--locked', '--format-version', '1') `
    -RedirectStandardOutput $cargoMetadata `
    -NoNewWindow -Wait -PassThru
if ($metadataProcess.ExitCode -ne 0) {
    throw "cargo metadata failed with exit code $($metadataProcess.ExitCode)"
}
$createdUtc = (& git show -s --format=%cI HEAD).Trim()
if ($LASTEXITCODE -ne 0) {
    throw 'git could not read the snapshot commit timestamp.'
}
Invoke-Native (Join-Path $PWD 'scripts\prepare-seawork-release-metadata.ps1') @(
    '-MetadataPath', $cargoMetadata,
    '-OutputDirectory', $metadata,
    '-Version', $version,
    '-CommitSha', $SnapshotSha,
    '-CreatedUtc', $createdUtc,
    '-SentryNativeLockPath', (Join-Path $PWD 'sentry-native.lock.json'),
    '-SentryNativeSourceDirectory', [string]$sentryDependency.source_dir
) 'release metadata generation'

Invoke-Native cargo @(
    'run', '-p', 'xtask', '--release', '--locked', '--', 'package-release',
    '--artifact', 'seawork-service',
    '--mode', 'stage',
    '--platform', 'windows-x86_64',
    '--version', $version,
    '--output-dir', $out,
    '--service-binary', $service,
    '--dump-helper', $dumpHelper,
    '--crashpad-handler', $crashpadHandler,
    '--crashpad-wer', $crashpadWer,
    '--runtime-dir', $runtime,
    '--qemu-dir', $qemu,
    '--sbom', (Join-Path $metadata 'sbom.spdx.json'),
    '--dependency-report', $dependencies,
    '--licenses', (Join-Path $metadata 'licenses'),
    '--publisher-subject', [string]$certificateInfo.subject,
    '--publisher-thumbprint', [string]$certificateInfo.sha256_thumbprint
) 'service bundle staging'
$stage = Join-Path $out "lsb-seawork-service-v$version-windows-x86_64-stage"
$bundle = Resolve-RegularDirectory (Join-Path $stage 'LocalSandbox') 'staged service bundle'

Invoke-Native (Join-Path $PWD 'scripts\sign-seawork-service.ps1') @(
    '-Mode', 'Catalog',
    '-UseLocalMachineStore',
    '-BundleRoot', $bundle,
    '-WorkDirectory', $catalogWork,
    '-PfxPath', $pfx,
    '-PasswordFile', $passwordFile,
    '-ExpectedPublisherSubject', [string]$certificateInfo.subject,
    '-ExpectedPublisherSha256', [string]$certificateInfo.sha256_thumbprint
) 'bundle catalog signing'

$sourceMap = Join-Path $input 'source-map.json'
[ordered]@{
    schema_version = 1
    version = $version
    snapshot_sha = $SnapshotSha
    sentry_native_commit = [string]$sentryDependency.sentry_native_commit
    service_sha256 = (Get-FileHash -LiteralPath $service -Algorithm SHA256).Hash.ToLowerInvariant()
    pdb_sha256 = (Get-FileHash -LiteralPath $pdb -Algorithm SHA256).Hash.ToLowerInvariant()
} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $sourceMap -Encoding utf8NoBOM

$serviceCheck = @(& $sentryDependency.sentry_cli debug-files check $service 2>&1)
if ($LASTEXITCODE -ne 0) {
    throw 'sentry-cli executable debug-file check failed'
}
$pdbCheck = @(& $sentryDependency.sentry_cli debug-files check $pdb 2>&1)
if ($LASTEXITCODE -ne 0) {
    throw 'sentry-cli PDB debug-file check failed'
}
$debugIds = @(($serviceCheck + $pdbCheck) | Select-String -AllMatches `
    -Pattern '(?i)\b(?:[0-9a-f]{32}|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})-[0-9a-f]+\b' |
    ForEach-Object { $_.Matches.Value.ToLowerInvariant() } | Sort-Object -Unique)
if ($debugIds.Count -ne 1) {
    throw 'service PE and PDB did not report one matching debug identifier'
}
$debugIdEvidence = Join-Path $input 'evidence-sentry-debug-ids.json'
[ordered]@{
    schema_version = 1
    release = "local-sandbox-service@$version"
    dist = 'windows-x86_64'
    debug_ids = $debugIds
    service_sha256 = (Get-FileHash -LiteralPath $service -Algorithm SHA256).Hash.ToLowerInvariant()
    pdb_sha256 = (Get-FileHash -LiteralPath $pdb -Algorithm SHA256).Hash.ToLowerInvariant()
} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $debugIdEvidence -Encoding utf8NoBOM

Invoke-Native cargo @(
    'run', '-p', 'xtask', '--release', '--locked', '--', 'package-release',
    '--artifact', 'seawork-service',
    '--mode', 'archive',
    '--platform', 'windows-x86_64',
    '--version', $version,
    '--output-dir', $out,
    '--stage-dir', $stage,
    '--catalog', (Join-Path $bundle 'manifests\LocalSandboxSeaWork.cat'),
    '--pdb', $pdb,
    '--source-map', $sourceMap,
    '--debug-id-evidence', $debugIdEvidence
) 'service archive construction'

$symbolsPath = Resolve-RegularFile `
    (Join-Path $out "lsb-seawork-service-v$version-windows-x86_64-symbols.zip") `
    'symbols archive'
$symbolEntries = @(& tar.exe -tf $symbolsPath | Sort-Object)
if ($LASTEXITCODE -ne 0) {
    throw 'listing the symbols archive failed'
}
$expectedSymbolEntries = @(
    'LocalSandbox/bin/localsandbox-seawork-service.exe',
    'LocalSandbox/bin/localsandbox-seawork-service.pdb',
    'LocalSandbox/manifests/source-map.json',
    'LocalSandbox/manifests/evidence-sentry-debug-ids.json'
) | Sort-Object
if (@(Compare-Object $expectedSymbolEntries $symbolEntries -CaseSensitive).Count -ne 0) {
    throw 'symbols archive does not have the exact required layout'
}
$archivedDebugIds = @((& tar.exe -xOf $symbolsPath `
    'LocalSandbox/manifests/evidence-sentry-debug-ids.json' |
    Out-String | ConvertFrom-Json).debug_ids | Sort-Object -Unique)
if ($LASTEXITCODE -ne 0 -or
    @(Compare-Object $debugIds $archivedDebugIds -CaseSensitive).Count -ne 0) {
    throw 'symbols archive debug-ID evidence does not match the PE/PDB checks'
}
$sentrySymbolsEvidence = Join-Path $RunRoot 'evidence-sentry-symbols.json'
[ordered]@{
    schema_version = 1
    release = "local-sandbox-service@$version"
    dist = 'windows-x86_64'
    sentry_cli_version = [string]$sentryDependency.sentry_cli_version
    debug_ids = $debugIds
    service_sha256 = (Get-FileHash -LiteralPath $service -Algorithm SHA256).Hash.ToLowerInvariant()
    pdb_sha256 = (Get-FileHash -LiteralPath $pdb -Algorithm SHA256).Hash.ToLowerInvariant()
    symbols_archive_sha256 = (Get-FileHash -LiteralPath $symbolsPath -Algorithm SHA256).Hash.ToLowerInvariant()
    upload_status = 'manual_required'
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $sentrySymbolsEvidence -Encoding utf8NoBOM

Invoke-Native (Join-Path $PWD 'scripts\sign-seawork-service.ps1') @(
    '-Mode', 'Verify',
    '-BundleRoot', $bundle,
    '-ExpectedPublisherSubject', [string]$certificateInfo.subject,
    '-ExpectedPublisherSha256', [string]$certificateInfo.sha256_thumbprint
) 'final signature and catalog verification'
Invoke-Native (Join-Path $bundle 'bin\localsandbox-seawork-service.exe') @(
    '--verify-bundle', '--json'
) 'installed-layout bundle verification'

$nodeRelease = Join-Path $releaseRoot 'node-release'
Invoke-Native (Join-Path $PWD 'scripts\package-seawork-node-release.ps1') @(
    '-Version', $version,
    '-PublisherSha256', [string]$certificateInfo.sha256_thumbprint,
    '-OutputDirectory', $nodeRelease
) 'Windows Node package construction'
$nodeEvidenceSource = Resolve-RegularFile `
    (Join-Path $nodeRelease 'evidence-node-packages.json') `
    'Node package evidence'
$nodeEvidence = Get-Content -LiteralPath $nodeEvidenceSource -Raw | ConvertFrom-Json
if ($nodeEvidence.status -ne 'passed' -or $nodeEvidence.version -ne $version -or
    $nodeEvidence.publisher_sha256 -cne [string]$certificateInfo.sha256_thumbprint -or
    @($nodeEvidence.packages).Count -ne 2) {
    throw 'Node package evidence does not match the signed candidate'
}
$nodePackageNames = [Collections.Generic.List[string]]::new()
foreach ($package in @($nodeEvidence.packages)) {
    $name = [string]$package.file
    if ($name -notmatch '^[A-Za-z0-9][A-Za-z0-9._+-]{0,120}\.tgz$' -or
        $nodePackageNames.Contains($name)) {
        throw 'Node package evidence contains an unsafe or duplicate filename'
    }
    $source = Resolve-RegularFile (Join-Path $nodeRelease "artifacts\$name") "Node package $name"
    $observedHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($observedHash -cne [string]$package.sha256 -or
        (Get-Item -LiteralPath $source).Length -ne [long]$package.size) {
        throw "Node package evidence hash/size mismatch: $name"
    }
    Copy-Item -LiteralPath $source -Destination (Join-Path $RunRoot $name)
    $nodePackageNames.Add($name)
}
Copy-Item -LiteralPath $nodeEvidenceSource `
    -Destination (Join-Path $RunRoot 'evidence-node-packages.json')

$payloadName = "lsb-seawork-service-v$version-windows-x86_64.zip"
$symbolsName = "lsb-seawork-service-v$version-windows-x86_64-symbols.zip"
$sumsName = "lsb-seawork-service-v$version-SHA256SUMS"
foreach ($name in @($payloadName, $symbolsName)) {
    Copy-Item -LiteralPath (Resolve-RegularFile (Join-Path $out $name) "release artifact $name") `
        -Destination (Join-Path $RunRoot $name)
}
Copy-Item -LiteralPath (Resolve-RegularFile (Join-Path $out $sumsName) 'release checksums') `
    -Destination (Join-Path $RunRoot 'SHA256SUMS')
Copy-Item -LiteralPath $eventSigned -Destination (Join-Path $RunRoot 'evidence-event-messages.json')
$evidenceName = 'evidence-release-candidate.json'
$snapshotTreeSha = (& git rev-parse "${SnapshotSha}^{tree}").Trim().ToLowerInvariant()
$baseCommit = (& git rev-parse "${SnapshotSha}^").Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $snapshotTreeSha -notmatch '^[0-9a-f]{40}$' -or
    $baseCommit -notmatch '^[0-9a-f]{40}$') {
    throw 'Could not resolve release-candidate snapshot provenance.'
}
[ordered]@{
    schema_version = 1
    suite = 'release-candidate'
    status = 'passed'
    snapshot_sha = $SnapshotSha
    snapshot_tree_sha = $snapshotTreeSha
    base_commit = $baseCommit
    version = $version
    service_profile = 'production'
    publisher_subject = [string]$certificateInfo.subject
    publisher_sha256 = [string]$certificateInfo.sha256_thumbprint
    payload = [ordered]@{
        name = $payloadName
        sha256 = (Get-FileHash -LiteralPath (Join-Path $RunRoot $payloadName) -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    symbols = [ordered]@{
        name = $symbolsName
        sha256 = (Get-FileHash -LiteralPath (Join-Path $RunRoot $symbolsName) -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    sentry = [ordered]@{
        native_tag = [string]$sentryDependency.sentry_native_tag
        native_commit = [string]$sentryDependency.sentry_native_commit
        cli_version = [string]$sentryDependency.sentry_cli_version
        debug_ids = $debugIds
        environment = $env:LSB_SENTRY_ENVIRONMENT
        traces_sample_rate = [double]$env:LSB_SENTRY_TRACES_SAMPLE_RATE
        handler_sha256 = (Get-FileHash -LiteralPath $crashpadHandler -Algorithm SHA256).Hash.ToLowerInvariant()
        wer_sha256 = (Get-FileHash -LiteralPath $crashpadWer -Algorithm SHA256).Hash.ToLowerInvariant()
        upload_status = 'manual_required'
    }
    node_packages = @($nodeEvidence.packages)
    trusted_signature_required = $true
    timestamp_required = $true
} | ConvertTo-Json -Depth 8 | Set-Content `
    -LiteralPath (Join-Path $RunRoot $evidenceName) `
    -Encoding utf8NoBOM

Invoke-Native (Join-Path $PWD 'scripts\write-seawork-test-release-manifest.ps1') @(
    '-RunRoot', $RunRoot,
    '-SnapshotSha', $SnapshotSha
) 'base test-release manifest generation'

$fetchNames = @(
    $payloadName,
    $symbolsName,
    'SHA256SUMS',
    'seawork-test-release-manifest.json',
    'evidence-event-messages.json',
    'evidence-node-packages.json',
    'evidence-sentry-symbols.json',
    $evidenceName
)
$fetchNames += @($nodePackageNames)
Write-FetchManifest $fetchNames
