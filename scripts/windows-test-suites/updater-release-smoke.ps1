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
    throw 'The updater-release-smoke suite does not support reboot phases.'
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
    param([Parameter(Mandatory = $true)][string] $Path, [string] $Label = 'file')

    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $item = Get-Item -LiteralPath $resolved -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "$Label must be a regular non-reparse file."
    }
    return $resolved
}

if ([string]::IsNullOrWhiteSpace($env:LSB_WINDOWS_TEST_ASSETS_ROOT)) {
    throw 'LSB_WINDOWS_TEST_ASSETS_ROOT is not configured by the Windows test runner.'
}
$pfx = Resolve-RegularFile $env:SEAWORK_WINDOWS_PFX_PATH 'signing PFX'
$passwordFile = Resolve-RegularFile $env:SEAWORK_WINDOWS_PFX_PASSWORD_FILE 'signing password file'
$signingAssets = Resolve-RegularFile `
    (Join-Path (Split-Path -Parent $PSScriptRoot) 'windows-test-signing-assets.ps1') `
    'signing asset verifier'
$certificate = (& $signingAssets -Mode Verify | Out-String | ConvertFrom-Json)
if ($certificate.status -ne 'ready' -or
    [string]$certificate.sha256_thumbprint -notmatch '^[0-9a-f]{64}$' -or
    [string]::IsNullOrWhiteSpace([string]$certificate.subject)) {
    throw 'Protected signing assets did not produce valid public certificate metadata.'
}

$metadata = (& cargo metadata --locked --format-version 1 --no-deps | Out-String | ConvertFrom-Json)
if ($LASTEXITCODE -ne 0) {
    throw "cargo metadata failed with exit code $LASTEXITCODE"
}
$updaterPackage = @($metadata.packages | Where-Object { $_.name -ceq 'lsb-seawork-updater' })
if ($updaterPackage.Count -ne 1 -or
    [string]$updaterPackage[0].version -notmatch '^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$') {
    throw 'Cargo metadata did not contain one canonical updater package version.'
}
$version = [string]$updaterPackage[0].version

$targetRoot = if ([string]::IsNullOrWhiteSpace($env:CARGO_TARGET_DIR)) {
    Join-Path $PWD 'target'
}
else {
    [IO.Path]::GetFullPath($env:CARGO_TARGET_DIR)
}
$updater = Join-Path $targetRoot `
    'x86_64-pc-windows-msvc\release\localsandbox-seawork-updater.exe'
if (Test-Path -LiteralPath $updater) {
    Resolve-RegularFile $updater 'cached updater output' | Out-Null
    Remove-Item -LiteralPath $updater -Force
}

$priorRustFlags = $env:RUSTFLAGS
$priorPublisher = $env:SEAWORK_PUBLISHER_SHA256
try {
    $env:RUSTFLAGS = '-C target-feature=+crt-static'
    $env:SEAWORK_PUBLISHER_SHA256 = [string]$certificate.sha256_thumbprint
    Invoke-Native cargo @(
        'build', '-p', 'lsb-seawork-updater', '--locked', '--release',
        '--target', 'x86_64-pc-windows-msvc'
    ) 'production updater build'
}
finally {
    $env:RUSTFLAGS = $priorRustFlags
    $env:SEAWORK_PUBLISHER_SHA256 = $priorPublisher
}
$updater = Resolve-RegularFile $updater 'release updater PE'

$signingScript = Resolve-RegularFile `
    (Join-Path (Split-Path -Parent $PSScriptRoot) 'sign-seawork-service.ps1') `
    'updater signing script'
Invoke-Native $signingScript @(
    '-Mode', 'SignUpdaterPe',
    '-UseLocalMachineStore',
    '-UpdaterBinary', $updater,
    '-PfxPath', $pfx,
    '-PasswordFile', $passwordFile,
    '-ExpectedPublisherSubject', [string]$certificate.subject,
    '-ExpectedPublisherSha256', [string]$certificate.sha256_thumbprint
) 'updater PE signing'
Invoke-Native $signingScript @(
    '-Mode', 'VerifyUpdaterPe',
    '-UpdaterBinary', $updater,
    '-ExpectedPublisherSubject', [string]$certificate.subject,
    '-ExpectedPublisherSha256', [string]$certificate.sha256_thumbprint
) 'updater PE signature verification'

$versionResult = (& $updater --version --json | Out-String).Trim() | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or
    $versionResult.service_name -cne 'LocalSandboxSeaWorkUpdater' -or
    [string]$versionResult.helper_version -cne $version -or
    [int]$versionResult.helper_protocol_major -ne 1 -or
    [int]$versionResult.helper_protocol_minor -lt 1) {
    throw 'The signed updater version query returned an invalid identity or protocol.'
}

$installText = (& $updater --verify-install --json 2>$null | Out-String).Trim()
$installExitCode = $LASTEXITCODE
$installResult = $installText | ConvertFrom-Json
if ($installExitCode -eq 0 -or $installResult.valid -ne $false -or
    $installResult.error -cne 'INSTALL_INVALID') {
    throw 'The non-installed signed updater did not fail its self-check as expected.'
}

$out = Join-Path $RunRoot 'updater-release'
New-Item -ItemType Directory -Path $out | Out-Null
Invoke-Native cargo @(
    'run', '-p', 'xtask', '--locked', '--', 'package-release',
    '--artifact', 'seawork-updater',
    '--version', $version,
    '--platform', 'windows-x86_64',
    '--output-dir', $out,
    '--updater-binary', $updater,
    '--publisher-subject', [string]$certificate.subject,
    '--publisher-thumbprint', [string]$certificate.sha256_thumbprint
) 'signed updater packaging'

$archiveName = "lsb-seawork-updater-v$version-windows-x86_64.zip"
$manifestName = "lsb-seawork-updater-v$version-windows-x86_64-manifest.json"
$sumsName = "lsb-seawork-updater-v$version-SHA256SUMS"
foreach ($name in @($archiveName, $manifestName, $sumsName)) {
    $source = Resolve-RegularFile (Join-Path $out $name) "packaged updater artifact $name"
    Copy-Item -LiteralPath $source -Destination (Join-Path $RunRoot $name)
}
$manifest = Get-Content -LiteralPath (Join-Path $RunRoot $manifestName) -Raw | ConvertFrom-Json
$binarySha256 = (Get-FileHash -LiteralPath $updater -Algorithm SHA256).Hash.ToLowerInvariant()
if ([int]$manifest.schema_version -ne 2 -or [string]$manifest.version -cne $version -or
    [string]$manifest.binary_sha256 -cne $binarySha256 -or
    [string]$manifest.publisher_sha256_thumbprint -cne [string]$certificate.sha256_thumbprint) {
    throw 'The packaged updater manifest does not bind the signed updater tuple.'
}

$evidenceName = 'evidence-updater-release-smoke.json'
[ordered]@{
    schema_version = 1
    suite = 'updater-release-smoke'
    snapshot_sha = $SnapshotSha
    status = 'passed'
    version = $version
    publisher_sha256 = [string]$certificate.sha256_thumbprint
    updater_sha256 = $binarySha256
    timestamped_signature_verified = $true
    version_mode_exercised = $true
    invalid_install_rejection_exercised = $true
    scm_installation_exercised = $false
} | ConvertTo-Json -Depth 4 | Set-Content `
    -LiteralPath (Join-Path $RunRoot $evidenceName) -Encoding utf8NoBOM

$names = @($archiveName, $manifestName, $sumsName, $evidenceName)
$artifacts = foreach ($name in $names) {
    $path = Resolve-RegularFile (Join-Path $RunRoot $name) "fetch artifact $name"
    [ordered]@{
        name = $name
        sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        size = (Get-Item -LiteralPath $path).Length
    }
}
[ordered]@{
    schema_version = 1
    run_id = Split-Path -Leaf ([IO.Path]::GetFullPath($RunRoot).TrimEnd('\'))
    artifacts = @($artifacts)
} | ConvertTo-Json -Depth 6 | Set-Content `
    -LiteralPath (Join-Path $RunRoot 'fetch-manifest.json') -Encoding utf8NoBOM
