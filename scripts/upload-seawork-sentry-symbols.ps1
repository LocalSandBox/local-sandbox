[CmdletBinding()]
param(
    [string] $LockPath = (Join-Path $PSScriptRoot '../sentry-native.lock.json'),
    [string] $OutputRoot = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-NativeSuccess {
    param(
        [Parameter(Mandatory = $true)][string] $Program,
        [Parameter(Mandatory = $true)][int] $ExitCode,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]] $Output
    )

    if ($ExitCode -ne 0) {
        $detail = @($Output | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
        throw "$Program failed with exit code $ExitCode`n$detail"
    }
}

function Assert-Sha256 {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $Expected,
        [Parameter(Mandatory = $true)][string] $Label
    )

    if ($Expected -cnotmatch '^[0-9a-f]{64}$') {
        throw "$Label has an invalid expected SHA-256."
    }
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne $Expected) {
        throw "$Label SHA-256 mismatch: expected $Expected, observed $actual"
    }
    return $actual
}

function Assert-SameValues {
    param(
        [Parameter(Mandatory = $true)][string[]] $Expected,
        [Parameter(Mandatory = $true)][string[]] $Actual,
        [Parameter(Mandatory = $true)][string] $Label
    )

    $expectedSet = @($Expected | Sort-Object -Unique)
    $actualSet = @($Actual | Sort-Object -Unique)
    if (@(Compare-Object $expectedSet $actualSet -CaseSensitive).Count -ne 0) {
        throw "$Label mismatch: expected [$($expectedSet -join ', ')], observed [$($actualSet -join ', ')]"
    }
}

function Get-DebugIds {
    param([Parameter(Mandatory = $true)][object[]] $Output)

    return @(
        $Output |
            ForEach-Object { [string]$_ } |
            Select-String -AllMatches `
                -Pattern '(?i)\b(?:[0-9a-f]{32}|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})-[0-9a-f]+\b' |
            ForEach-Object { $_.Matches.Value.ToLowerInvariant() } |
            Sort-Object -Unique
    )
}

if (-not $IsMacOS) {
    throw 'SeaWork symbols must be uploaded from macOS by this recipe.'
}
$architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
$cliKey = switch ($architecture) {
    'Arm64' { 'darwin_arm64' }
    'X64' { 'darwin_x86_64' }
    default { throw "Unsupported macOS architecture: $architecture" }
}

foreach ($command in @('gh', 'pwsh')) {
    if ($null -eq (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "Required command is unavailable: $command"
    }
}

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$resolvedLock = (Resolve-Path -LiteralPath $LockPath).Path
$lock = Get-Content -LiteralPath $resolvedLock -Raw | ConvertFrom-Json
if ($lock.schema_version -ne 1) {
    throw 'Unsupported Sentry Native dependency lock schema.'
}

$cliVersion = [string]$lock.sentry_cli.version
$cliProperty = $lock.sentry_cli.psobject.Properties[$cliKey]
if ($null -eq $cliProperty) {
    throw "sentry-native.lock.json does not pin sentry-cli for $cliKey."
}
$cliAsset = $cliProperty.Value
$cliSha = ([string]$cliAsset.sha256).ToLowerInvariant()
if ($cliVersion -notmatch '^[0-9A-Za-z.+-]+$' -or
    $cliSha -notmatch '^[0-9a-f]{64}$' -or
    [string]::IsNullOrWhiteSpace([string]$cliAsset.url)) {
    throw 'The locked sentry-cli metadata is invalid.'
}

$releaseOutput = @(& gh release list --limit 1000 `
        --json tagName,publishedAt,isDraft 2>&1)
$releaseExit = $LASTEXITCODE
Assert-NativeSuccess 'gh release list' $releaseExit $releaseOutput
$releases = @(
    ($releaseOutput -join [Environment]::NewLine | ConvertFrom-Json) |
        Where-Object { -not $_.isDraft -and -not [string]::IsNullOrWhiteSpace([string]$_.publishedAt) } |
        Sort-Object publishedAt -Descending
)
if ($releases.Count -lt 1) {
    throw 'GitHub has no published release or prerelease.'
}
$release = $releases[0]
$tag = [string]$release.tagName
$publishedAt = ([DateTimeOffset]$release.publishedAt).ToUniversalTime().ToString('o')

$viewOutput = @(& gh release view $tag --json assets,url 2>&1)
$viewExit = $LASTEXITCODE
Assert-NativeSuccess "gh release view $tag" $viewExit $viewOutput
$releaseDetails = $viewOutput -join [Environment]::NewLine | ConvertFrom-Json
$assetNames = @($releaseDetails.assets | ForEach-Object { [string]$_.name })
$symbolAssets = @(
    $assetNames |
        Where-Object {
            $_ -cmatch '^lsb-seawork-service-v(?<version>[0-9A-Za-z.+-]+)-windows-x86_64-symbols\.zip$'
        }
)
if ($symbolAssets.Count -ne 1) {
    throw "Newest published GitHub release $tag must contain exactly one SeaWork service symbols ZIP."
}
$symbolsName = $symbolAssets[0]
$null = $symbolsName -cmatch '^lsb-seawork-service-v(?<version>[0-9A-Za-z.+-]+)-windows-x86_64-symbols\.zip$'
$version = $Matches.version
if ($tag -cne "v$version") {
    throw "Newest published GitHub release tag $tag does not match symbols version $version."
}
$sumsName = "lsb-seawork-service-v$version-SHA256SUMS"
$evidenceName = 'evidence-sentry-symbols.json'
foreach ($requiredName in @($sumsName, $evidenceName)) {
    if (@($assetNames | Where-Object { $_ -ceq $requiredName }).Count -ne 1) {
        throw "Newest published GitHub release $tag is missing required asset $requiredName."
    }
}

if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot = Join-Path $repoRoot 'target/seawork-sentry-symbol-upload'
}
$resolvedOutputRoot = [IO.Path]::GetFullPath($OutputRoot)
$receiptDirectory = Join-Path $resolvedOutputRoot $version
$workRoot = Join-Path ([IO.Path]::GetTempPath()) "lsb-sentry-symbol-upload-$([Guid]::NewGuid().ToString('N'))"
$downloadRoot = Join-Path $workRoot 'downloads'
$extractRoot = Join-Path $workRoot 'symbols'

New-Item -ItemType Directory -Path $downloadRoot | Out-Null
try {
    Write-Host "Selected newest published GitHub release: $tag ($publishedAt)"
    $downloadOutput = @(& gh release download $tag --dir $downloadRoot `
            --pattern $symbolsName --pattern $sumsName --pattern $evidenceName 2>&1)
    $downloadExit = $LASTEXITCODE
    Assert-NativeSuccess "gh release download $tag" $downloadExit $downloadOutput

    $symbolsPath = Join-Path $downloadRoot $symbolsName
    $sumsPath = Join-Path $downloadRoot $sumsName
    $evidencePath = Join-Path $downloadRoot $evidenceName
    foreach ($path in @($symbolsPath, $sumsPath, $evidencePath)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Downloaded release asset is missing: $path"
        }
    }

    $checksumRecords = @(
        Get-Content -LiteralPath $sumsPath |
            ForEach-Object {
                if ($_ -notmatch '^(?<sha>[0-9A-Fa-f]{64})[ \t]+\*?(?<name>.+)$') {
                    throw "$sumsName contains an invalid checksum record."
                }
                [pscustomobject]@{
                    sha = $Matches.sha.ToLowerInvariant()
                    name = $Matches.name
                }
            }
    )
    $symbolChecksumRecords = @(
        $checksumRecords | Where-Object { $_.name -ceq $symbolsName }
    )
    if ($symbolChecksumRecords.Count -ne 1) {
        throw "$sumsName must contain exactly one checksum for $symbolsName."
    }
    $archiveSha = Assert-Sha256 $symbolsPath $symbolChecksumRecords[0].sha $symbolsName

    $evidence = Get-Content -LiteralPath $evidencePath -Raw | ConvertFrom-Json
    $expectedRelease = "local-sandbox-service@$version"
    if ($evidence.schema_version -ne 1 -or
        [string]$evidence.release -cne $expectedRelease -or
        [string]$evidence.dist -cne 'windows-x86_64' -or
        [string]$evidence.sentry_cli_version -cne $cliVersion -or
        [string]$evidence.upload_status -cne 'manual_required') {
        throw "$evidenceName does not match release $tag and the locked sentry-cli."
    }
    if ($archiveSha -cne ([string]$evidence.symbols_archive_sha256).ToLowerInvariant()) {
        throw "$symbolsName SHA-256 does not match $evidenceName."
    }
    $expectedDebugIds = @(
        $evidence.debug_ids |
            ForEach-Object { ([string]$_).ToLowerInvariant() } |
            Sort-Object -Unique
    )
    if ($expectedDebugIds.Count -lt 1 -or
        @($expectedDebugIds | Where-Object {
                $_ -cnotmatch '^(?:[0-9a-f]{32}|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})-[0-9a-f]+$'
            }).Count -ne 0) {
        throw "$evidenceName contains invalid debug identifiers."
    }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($symbolsPath)
    try {
        $archiveEntries = @($zip.Entries | ForEach-Object { $_.FullName } | Sort-Object)
    }
    finally {
        $zip.Dispose()
    }
    $expectedEntries = @(
        'LocalSandbox/bin/localsandbox-seawork-service.exe',
        'LocalSandbox/bin/localsandbox-seawork-service.pdb',
        'LocalSandbox/manifests/evidence-sentry-debug-ids.json',
        'LocalSandbox/manifests/source-map.json'
    ) | Sort-Object
    if ($archiveEntries.Count -ne $expectedEntries.Count) {
        throw "$symbolsName contains missing, extra, or duplicate entries."
    }
    Assert-SameValues $expectedEntries $archiveEntries "$symbolsName contents"
    [IO.Compression.ZipFile]::ExtractToDirectory($symbolsPath, $extractRoot)

    $servicePath = Join-Path $extractRoot 'LocalSandbox/bin/localsandbox-seawork-service.exe'
    $pdbPath = Join-Path $extractRoot 'LocalSandbox/bin/localsandbox-seawork-service.pdb'
    $archivedEvidencePath = Join-Path $extractRoot `
        'LocalSandbox/manifests/evidence-sentry-debug-ids.json'
    Assert-Sha256 $servicePath ([string]$evidence.service_sha256).ToLowerInvariant() `
        'service executable' | Out-Null
    Assert-Sha256 $pdbPath ([string]$evidence.pdb_sha256).ToLowerInvariant() `
        'service PDB' | Out-Null
    $archivedEvidence = Get-Content -LiteralPath $archivedEvidencePath -Raw | ConvertFrom-Json
    $archivedDebugIds = @(
        $archivedEvidence.debug_ids |
            ForEach-Object { ([string]$_).ToLowerInvariant() } |
            Sort-Object -Unique
    )
    Assert-SameValues $expectedDebugIds $archivedDebugIds `
        'archived and release debug-ID evidence'

    $userRoot = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
    $cacheRoot = Join-Path $userRoot 'Library/Caches/LocalSandbox/SentryCli'
    New-Item -ItemType Directory -Force -Path $cacheRoot | Out-Null
    $cliPath = Join-Path $cacheRoot "sentry-cli-$cliVersion-$cliKey-$cliSha"
    if (-not (Test-Path -LiteralPath $cliPath -PathType Leaf)) {
        $pendingCli = "$cliPath.pending-$PID"
        try {
            Invoke-WebRequest -Uri ([string]$cliAsset.url) -OutFile $pendingCli
            Assert-Sha256 $pendingCli $cliSha 'downloaded sentry-cli' | Out-Null
            Move-Item -LiteralPath $pendingCli -Destination $cliPath
        }
        finally {
            if (Test-Path -LiteralPath $pendingCli) {
                Remove-Item -LiteralPath $pendingCli -Force
            }
        }
    }
    Assert-Sha256 $cliPath $cliSha 'cached sentry-cli' | Out-Null
    & /bin/chmod +x $cliPath
    if ($LASTEXITCODE -ne 0) {
        throw 'Failed to mark the cached sentry-cli executable.'
    }

    $serviceCheck = @(& $cliPath debug-files check $servicePath 2>&1)
    $serviceCheckExit = $LASTEXITCODE
    Assert-NativeSuccess 'sentry-cli debug-files check (service executable)' `
        $serviceCheckExit $serviceCheck
    $pdbCheck = @(& $cliPath debug-files check $pdbPath 2>&1)
    $pdbCheckExit = $LASTEXITCODE
    Assert-NativeSuccess 'sentry-cli debug-files check (service PDB)' $pdbCheckExit $pdbCheck
    $checkedDebugIds = Get-DebugIds @($serviceCheck + $pdbCheck)
    Assert-SameValues $expectedDebugIds $checkedDebugIds `
        'checked and expected debug identifiers'

    $uploadArguments = @(
        'debug-files', 'upload',
        '--include-sources',
        '--wait',
        '--require-all'
    )
    foreach ($debugId in $expectedDebugIds) {
        $uploadArguments += @('--id', $debugId)
    }
    $uploadArguments += $extractRoot
    $uploadOutput = @(& $cliPath @uploadArguments 2>&1)
    $uploadExit = $LASTEXITCODE
    Assert-NativeSuccess 'sentry-cli debug-files upload' $uploadExit $uploadOutput
    Write-Host ($uploadOutput -join [Environment]::NewLine)

    $confirmedUtc = [DateTimeOffset]::UtcNow.ToString('o')
    $receipt = [ordered]@{
        schema_version = 1
        release = $expectedRelease
        dist = 'windows-x86_64'
        github_release = [ordered]@{
            tag = $tag
            published_at = $publishedAt
            url = [string]$releaseDetails.url
        }
        symbols = [ordered]@{
            archive = $symbolsName
            sha256 = $archiveSha
        }
        sentry_cli_version = $cliVersion
        debug_ids = $expectedDebugIds
        checks = [ordered]@{
            sha256sums = 'passed'
            release_evidence = 'passed'
            archive_layout = 'passed'
            debug_files = 'passed'
            upload_require_all = 'passed'
            server_processing = 'passed'
        }
        upload_result = 'success'
        upload_status = 'confirmed'
        confirmed_utc = $confirmedUtc
    }
    New-Item -ItemType Directory -Force -Path $receiptDirectory | Out-Null
    $receiptPath = Join-Path $receiptDirectory 'evidence-sentry-symbol-upload.json'
    $pendingReceipt = "$receiptPath.pending-$PID"
    $receipt | ConvertTo-Json -Depth 6 |
        Set-Content -LiteralPath $pendingReceipt -Encoding utf8NoBOM
    Move-Item -LiteralPath $pendingReceipt -Destination $receiptPath -Force

    Write-Host "Confirmed Sentry symbols for $expectedRelease."
    Write-Host "Debug IDs: $($expectedDebugIds -join ', ')"
    Write-Host "Redacted receipt: $receiptPath"
}
finally {
    if (Test-Path -LiteralPath $workRoot) {
        Remove-Item -LiteralPath $workRoot -Recurse -Force
    }
}
