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

if ($Phase -ne 'Normal') {
    throw 'The release-candidate suite does not support reboot phases.'
}

function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)][string] $Executable,
        [Parameter(Mandatory = $true)][string[]] $Arguments,
        [Parameter(Mandatory = $true)][string] $Label
    )

    & $Executable @Arguments
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
    (Join-Path (Split-Path -Parent $PSScriptRoot) 'windows-test-signing-assets.ps1') `
    'signing asset verifier'
$certificateInfo = (& $signingScript -Mode Verify | Out-String | ConvertFrom-Json)
if ($certificateInfo.status -ne 'ready' -or
    $certificateInfo.sha256_thumbprint -notmatch '^[0-9a-f]{64}$') {
    throw 'Protected signing assets did not produce valid public certificate metadata.'
}

$stateText = Get-Content -LiteralPath 'state.md' -Raw
$versionMatch = [regex]::Match($stateText, '(?m)^- Candidate version: `([^`]+)`$')
if (-not $versionMatch.Success -or
    $versionMatch.Groups[1].Value -notmatch '^\d+\.\d+\.\d+-[0-9A-Za-z.-]+$') {
    throw 'state.md does not contain the bounded prerelease candidate version.'
}
$version = $versionMatch.Groups[1].Value
$releaseRoot = Join-Path $RunRoot 'release-work'
if (Test-Path -LiteralPath $releaseRoot) {
    throw 'The release work directory already exists.'
}
$input = Join-Path $releaseRoot 'input'
$metadata = Join-Path $input 'metadata'
$out = Join-Path $releaseRoot 'out'
$catalogWork = Join-Path $releaseRoot 'catalog-work'
New-Item -ItemType Directory -Path $input, $out, $catalogWork | Out-Null

$targetRoot = if ([string]::IsNullOrWhiteSpace($env:CARGO_TARGET_DIR)) {
    Join-Path $PWD 'target'
}
else {
    [IO.Path]::GetFullPath($env:CARGO_TARGET_DIR)
}
$service = Join-Path $targetRoot 'x86_64-pc-windows-msvc\release\localsandbox-seawork-service.exe'
$pdb = Join-Path $targetRoot 'x86_64-pc-windows-msvc\release\localsandbox-seawork-service.pdb'
$priorRustFlags = $env:RUSTFLAGS
try {
    $env:RUSTFLAGS = '-C target-feature=+crt-static'
    Invoke-Native cargo @(
        'build', '-p', 'lsb-seawork-service', '--locked', '--release',
        '--target', 'x86_64-pc-windows-msvc'
    ) 'production service build'
}
finally {
    $env:RUSTFLAGS = $priorRustFlags
}
Resolve-RegularFile $service 'release service PE' | Out-Null
Resolve-RegularFile $pdb 'release service PDB' | Out-Null

$eventUnsigned = Join-Path $releaseRoot 'event-messages-unsigned.json'
Invoke-Native (Join-Path $PWD 'scripts\verify-seawork-event-messages.ps1') @(
    '-ServiceBinary', $service,
    '-OutputPath', $eventUnsigned
) 'unsigned Event Log resource verification'

Invoke-Native (Join-Path $PWD 'scripts\sign-seawork-service.ps1') @(
    '-Mode', 'SignPe',
    '-ServiceBinary', $service,
    '-PfxPath', $pfx,
    '-PasswordFile', $passwordFile,
    '-ExpectedPublisherSubject', [string]$certificateInfo.subject,
    '-ExpectedPublisherSha256', [string]$certificateInfo.sha256_thumbprint
) 'service PE signing'

$eventSigned = Join-Path $releaseRoot 'event-messages-signed.json'
Invoke-Native (Join-Path $PWD 'scripts\verify-seawork-event-messages.ps1') @(
    '-ServiceBinary', $service,
    '-OutputPath', $eventSigned
) 'signed Event Log resource verification'

$dependencies = Join-Path $input 'runtime-dependencies.json'
Invoke-Native (Join-Path $PWD 'scripts\inspect-seawork-service-dependencies.ps1') @(
    '-ServiceBinary', $service,
    '-OutputPath', $dependencies
) 'runtime dependency inspection'
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
    '-CreatedUtc', $createdUtc
) 'release metadata generation'

Invoke-Native cargo @(
    'run', '-p', 'xtask', '--locked', '--', 'package-release',
    '--artifact', 'seawork-service',
    '--mode', 'stage',
    '--platform', 'windows-x86_64',
    '--version', $version,
    '--output-dir', $out,
    '--service-binary', $service,
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
    service_sha256 = (Get-FileHash -LiteralPath $service -Algorithm SHA256).Hash.ToLowerInvariant()
    pdb_sha256 = (Get-FileHash -LiteralPath $pdb -Algorithm SHA256).Hash.ToLowerInvariant()
} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $sourceMap -Encoding utf8NoBOM

Invoke-Native cargo @(
    'run', '-p', 'xtask', '--locked', '--', 'package-release',
    '--artifact', 'seawork-service',
    '--mode', 'archive',
    '--platform', 'windows-x86_64',
    '--version', $version,
    '--output-dir', $out,
    '--stage-dir', $stage,
    '--catalog', (Join-Path $bundle 'manifests\LocalSandboxSeaWork.cat'),
    '--pdb', $pdb,
    '--source-map', $sourceMap
) 'service archive construction'

Invoke-Native (Join-Path $PWD 'scripts\sign-seawork-service.ps1') @(
    '-Mode', 'Verify',
    '-BundleRoot', $bundle,
    '-ExpectedPublisherSubject', [string]$certificateInfo.subject,
    '-ExpectedPublisherSha256', [string]$certificateInfo.sha256_thumbprint
) 'final signature and catalog verification'
Invoke-Native (Join-Path $bundle 'bin\localsandbox-seawork-service.exe') @(
    '--verify-bundle', '--json'
) 'installed-layout bundle verification'

$payloadName = "lsb-seawork-service-v$version-windows-x86_64.zip"
$symbolsName = "lsb-seawork-service-v$version-windows-x86_64-symbols.zip"
foreach ($name in @($payloadName, $symbolsName, 'SHA256SUMS')) {
    Copy-Item -LiteralPath (Resolve-RegularFile (Join-Path $out $name) "release artifact $name") `
        -Destination (Join-Path $RunRoot $name)
}
Copy-Item -LiteralPath $eventSigned -Destination (Join-Path $RunRoot 'evidence-event-messages.json')
$evidenceName = 'evidence-release-candidate.json'
[ordered]@{
    schema_version = 1
    suite = 'release-candidate'
    status = 'passed'
    snapshot_sha = $SnapshotSha
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
    trusted_signature_required = $true
    timestamp_required = $true
} | ConvertTo-Json -Depth 8 | Set-Content `
    -LiteralPath (Join-Path $RunRoot $evidenceName) `
    -Encoding utf8NoBOM

Write-FetchManifest @(
    $payloadName,
    $symbolsName,
    'SHA256SUMS',
    'evidence-event-messages.json',
    $evidenceName
)
