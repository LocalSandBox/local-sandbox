[CmdletBinding()]
param(
    [string] $LockPath = (Join-Path $PSScriptRoot '..\sentry-native.lock.json'),
    [string] $CacheRoot = (Join-Path $env:LOCALAPPDATA 'LocalSandbox\BuildCache\SentryNative'),
    [string] $OutputJson = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-Sha256 {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $Expected,
        [Parameter(Mandatory = $true)][string] $Label
    )

    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne $Expected) {
        throw "$Label SHA-256 mismatch: expected $Expected, observed $actual"
    }
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string] $Program,
        [Parameter(Mandatory = $true)][string[]] $Arguments
    )

    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Program failed with exit code $LASTEXITCODE"
    }
}

function Assert-PlainFile {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $Label
    )

    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $item.Length -le 0) {
        throw "$Label must be a non-empty regular non-reparse file"
    }
    return $item
}

$resolvedLock = (Resolve-Path -LiteralPath $LockPath).Path
$lock = Get-Content -LiteralPath $resolvedLock -Raw | ConvertFrom-Json
if ($lock.schema_version -ne 1) {
    throw 'Unsupported Sentry Native dependency lock schema.'
}

$native = $lock.sentry_native
$archiveSha = [string]$native.release_archive.sha256
if ($archiveSha -notmatch '^[0-9a-f]{64}$') {
    throw 'The locked Sentry Native archive SHA-256 is invalid.'
}

$cache = [IO.Path]::GetFullPath($CacheRoot)
$versionRoot = Join-Path $cache ([string]$native.commit)
$downloads = Join-Path $cache 'downloads'
$archive = Join-Path $downloads "sentry-native-$($native.tag)-$archiveSha.zip"
$source = Join-Path $versionRoot 'source'
$build = Join-Path $versionRoot 'build'
$install = Join-Path $versionRoot 'install'
$complete = Join-Path $versionRoot 'prepared.json'

if (-not (Test-Path -LiteralPath $complete -PathType Leaf)) {
    New-Item -ItemType Directory -Force -Path $downloads | Out-Null
    if (-not (Test-Path -LiteralPath $archive -PathType Leaf)) {
        $pendingArchive = "$archive.pending-$PID"
        try {
            Invoke-WebRequest -Uri ([string]$native.release_archive.url) -OutFile $pendingArchive
            Assert-Sha256 $pendingArchive $archiveSha 'Sentry Native release archive'
            Move-Item -LiteralPath $pendingArchive -Destination $archive
        }
        finally {
            if (Test-Path -LiteralPath $pendingArchive) {
                Remove-Item -LiteralPath $pendingArchive -Force
            }
        }
    }
    Assert-Sha256 $archive $archiveSha 'cached Sentry Native release archive'

    $staging = "$versionRoot.pending-$PID"
    if (Test-Path -LiteralPath $staging) {
        Remove-Item -LiteralPath $staging -Recurse -Force
    }
    New-Item -ItemType Directory -Path $staging | Out-Null
    try {
        $stagingSource = Join-Path $staging 'source'
        Expand-Archive -LiteralPath $archive -DestinationPath $stagingSource
        $entries = @(Get-ChildItem -LiteralPath $stagingSource -Force)
        if ($entries.Count -eq 1 -and $entries[0].PSIsContainer) {
            $stagingSource = $entries[0].FullName
        }
        Assert-PlainFile (Join-Path $stagingSource 'include\sentry.h') 'Sentry Native header' |
            Out-Null
        $versionMatches = @(Select-String `
                -LiteralPath (Join-Path $stagingSource 'include\sentry.h') `
                -Pattern "#define SENTRY_SDK_VERSION `"$($native.tag)`"" -SimpleMatch)
        if ($versionMatches.Count -ne 1) {
            throw 'The extracted Sentry Native version does not match the dependency lock.'
        }

        $stagingBuild = Join-Path $staging 'build'
        $stagingInstall = Join-Path $staging 'install'
        $options = $native.cmake_options
        $configure = @(
            '-S', $stagingSource,
            '-B', $stagingBuild,
            '-G', [string]$options.generator,
            '-A', [string]$options.architecture,
            "-DCMAKE_INSTALL_PREFIX=$stagingInstall",
            "-DSENTRY_BACKEND=$($options.SENTRY_BACKEND)",
            "-DSENTRY_TRANSPORT=$($options.SENTRY_TRANSPORT)",
            "-DSENTRY_BUILD_SHARED_LIBS=$($options.SENTRY_BUILD_SHARED_LIBS)",
            "-DSENTRY_BUILD_RUNTIMESTATIC=$($options.SENTRY_BUILD_RUNTIMESTATIC)",
            "-DSENTRY_BUILD_TESTS=$($options.SENTRY_BUILD_TESTS)",
            "-DSENTRY_BUILD_EXAMPLES=$($options.SENTRY_BUILD_EXAMPLES)",
            "-DSENTRY_BUILD_BENCHMARKS=$($options.SENTRY_BUILD_BENCHMARKS)"
        )
        Invoke-Checked 'cmake.exe' $configure
        Invoke-Checked 'cmake.exe' @(
            '--build', $stagingBuild,
            '--config', [string]$options.configuration,
            '--target', 'install',
            '--parallel'
        )

        Assert-PlainFile (Join-Path $stagingInstall 'include\sentry.h') `
            'installed Sentry Native header' | Out-Null
        Assert-PlainFile (Join-Path $stagingInstall 'lib\sentry.lib') `
            'installed static Sentry Native library' | Out-Null
        Assert-PlainFile (Join-Path $stagingInstall 'bin\crashpad_handler.exe') `
            'installed Crashpad handler' | Out-Null
        Assert-PlainFile (Join-Path $stagingInstall 'bin\crashpad_wer.dll') `
            'installed Crashpad WER module' | Out-Null

        [ordered]@{
            schema_version = 1
            sentry_native_tag = [string]$native.tag
            sentry_native_commit = [string]$native.commit
            archive_sha256 = $archiveSha
            prepared_utc = [DateTime]::UtcNow.ToString('o')
        } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $staging 'prepared.json') `
            -Encoding utf8NoBOM

        if (Test-Path -LiteralPath $versionRoot) {
            Remove-Item -LiteralPath $versionRoot -Recurse -Force
        }
        Move-Item -LiteralPath $staging -Destination $versionRoot
    }
    finally {
        if (Test-Path -LiteralPath $staging) {
            Remove-Item -LiteralPath $staging -Recurse -Force
        }
    }
}

$prepared = Get-Content -LiteralPath $complete -Raw | ConvertFrom-Json
if ($prepared.sentry_native_commit -cne [string]$native.commit -or
    $prepared.archive_sha256 -cne $archiveSha) {
    throw 'The prepared Sentry Native cache does not match the dependency lock.'
}

$cli = $lock.sentry_cli.windows_x86_64
$cliSha = [string]$cli.sha256
if ($cliSha -notmatch '^[0-9a-f]{64}$') {
    throw 'The locked sentry-cli SHA-256 is invalid.'
}
$cliPath = Join-Path $downloads "sentry-cli-$($lock.sentry_cli.version)-windows-x86_64-$cliSha.exe"
if (-not (Test-Path -LiteralPath $cliPath -PathType Leaf)) {
    $pendingCli = "$cliPath.pending-$PID"
    try {
        Invoke-WebRequest -Uri ([string]$cli.url) -OutFile $pendingCli
        Assert-Sha256 $pendingCli $cliSha 'sentry-cli'
        Move-Item -LiteralPath $pendingCli -Destination $cliPath
    }
    finally {
        if (Test-Path -LiteralPath $pendingCli) {
            Remove-Item -LiteralPath $pendingCli -Force
        }
    }
}
Assert-Sha256 $cliPath $cliSha 'cached sentry-cli'

$result = [ordered]@{
    schema_version = 1
    sentry_native_tag = [string]$native.tag
    sentry_native_commit = [string]$native.commit
    include_dir = (Resolve-Path -LiteralPath (Join-Path $install 'include')).Path
    library_dir = (Resolve-Path -LiteralPath (Join-Path $install 'lib')).Path
    library = (Resolve-Path -LiteralPath (Join-Path $install 'lib\sentry.lib')).Path
    crashpad_handler = (Resolve-Path -LiteralPath `
        (Join-Path $install 'bin\crashpad_handler.exe')).Path
    crashpad_wer = (Resolve-Path -LiteralPath `
        (Join-Path $install 'bin\crashpad_wer.dll')).Path
    sentry_cli_version = [string]$lock.sentry_cli.version
    sentry_cli = (Resolve-Path -LiteralPath $cliPath).Path
    source_dir = (Resolve-Path -LiteralPath $source).Path
    build_dir = (Resolve-Path -LiteralPath $build).Path
}
$json = $result | ConvertTo-Json -Depth 4
if (-not [string]::IsNullOrWhiteSpace($OutputJson)) {
    $output = [IO.Path]::GetFullPath($OutputJson)
    $parent = Split-Path -Parent $output
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    $pending = "$output.pending-$PID"
    $json | Set-Content -LiteralPath $pending -Encoding utf8NoBOM
    Move-Item -LiteralPath $pending -Destination $output -Force
}
$json
