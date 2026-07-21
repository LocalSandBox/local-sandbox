[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Run', 'Reboot', 'Resume')]
    [string] $Mode,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-z0-9][a-z0-9._-]{0,95}$')]
    [string] $RunId,

    [ValidatePattern('^[0-9a-f]{40}$')]
    [string] $SnapshotSha,

    [ValidatePattern('^refs/heads/snapshots/[a-z0-9][a-z0-9._-]{0,95}$')]
    [string] $SnapshotRef,

    [ValidatePattern('^[a-z0-9][a-z0-9._-]{0,63}$')]
    [string] $Suite = 'preflight',

    [string] $CommandSpecBase64 = '',
    [ValidatePattern('^$|^[a-z0-9][a-z0-9._-]{0,95}$')]
    [string] $ReuseRunId = '',
    [string] $Root = 'C:\dev\local-sandbox-agent',
    [string] $StateRoot = (Join-Path $env:ProgramData 'LocalSandbox\DevTest'),
    [int] $LockTimeoutSeconds = 120
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Invoke-Git {
    param([Parameter(Mandatory = $true)][string[]] $Arguments)

    & git @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "git failed with exit code ${LASTEXITCODE}: git $($Arguments -join ' ')"
    }
}

function Initialize-RustupEnvironment {
    if (-not [string]::IsNullOrWhiteSpace($env:RUSTUP_HOME)) {
        return
    }
    $command = Get-Command rustup -ErrorAction Stop
    $rustup = (Resolve-Path -LiteralPath $command.Source).Path
    $bin = Split-Path -Parent $rustup
    $cargoHome = Split-Path -Parent $bin
    if ((Split-Path -Leaf $bin) -cne 'bin' -or (Split-Path -Leaf $cargoHome) -cne '.cargo') {
        throw 'RUSTUP_HOME is unset and rustup is not in a standard .cargo\bin directory.'
    }
    $rustupHome = Join-Path (Split-Path -Parent $cargoHome) '.rustup'
    if (-not (Test-Path -LiteralPath $rustupHome -PathType Container)) {
        throw "RUSTUP_HOME is unset and the toolchain directory is missing: $rustupHome"
    }
    $env:CARGO_HOME = $cargoHome
    $env:RUSTUP_HOME = $rustupHome
}

function Write-JsonAtomic {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][object] $Value
    )

    $pending = "$Path.pending-$PID"
    $Value | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $pending -Encoding utf8NoBOM
    Move-Item -LiteralPath $pending -Destination $Path -Force
}

function Open-RunnerLock {
    param([Parameter(Mandatory = $true)][string] $Path)

    $deadline = [DateTime]::UtcNow.AddSeconds($LockTimeoutSeconds)
    do {
        try {
            return [IO.File]::Open(
                $Path,
                [IO.FileMode]::OpenOrCreate,
                [IO.FileAccess]::ReadWrite,
                [IO.FileShare]::None
            )
        }
        catch [IO.IOException] {
            if ([DateTime]::UtcNow -ge $deadline) {
                throw "Timed out waiting for the exclusive Windows test-host lock: $Path"
            }
            Start-Sleep -Milliseconds 500
        }
    } while ($true)
}

function Get-BootId {
    return (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().Ticks.ToString()
}

function Sync-Checkout {
    param(
        [Parameter(Mandatory = $true)][string] $RepoPath,
        [Parameter(Mandatory = $true)][string] $MirrorPath,
        [Parameter(Mandatory = $true)][string] $Ref,
        [Parameter(Mandatory = $true)][string] $Sha
    )

    Invoke-Git -Arguments @('-C', $RepoPath, 'fetch', '--force', $MirrorPath, $Ref)
    $fetched = (& git -C $RepoPath rev-parse FETCH_HEAD).Trim().ToLowerInvariant()
    if ($LASTEXITCODE -ne 0 -or $fetched -ne $Sha) {
        throw "Fetched snapshot mismatch: expected $Sha, observed $fetched"
    }
    Invoke-Git -Arguments @('-C', $RepoPath, 'reset', '--hard', $Sha)
    Invoke-Git -Arguments @('-C', $RepoPath, 'clean', '-ffd')
    $checkedOut = (& git -C $RepoPath rev-parse HEAD).Trim().ToLowerInvariant()
    if ($LASTEXITCODE -ne 0 -or $checkedOut -ne $Sha) {
        throw "Checkout mismatch: expected $Sha, observed $checkedOut"
    }
}

Initialize-RustupEnvironment
$rootPath = [IO.Path]::GetFullPath($Root)
$statePath = [IO.Path]::GetFullPath($StateRoot)
$marker = Join-Path $rootPath '.local-sandbox-agent-test-root.json'
if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) {
    throw "The Windows test host is not initialized: $marker"
}

$mirrorPath = Join-Path $rootPath 'mirror.git'
$repoPath = Join-Path $rootPath 'repo'
$lockPath = Join-Path $statePath 'locks\runner.lock'
$runPath = Join-Path (Join-Path $statePath 'runs') $RunId
$continuationPath = Join-Path $runPath 'continuation.json'
New-Item -ItemType Directory -Force -Path $runPath | Out-Null

$lock = Open-RunnerLock -Path $lockPath
try {
    if ($Mode -eq 'Resume') {
        if (-not (Test-Path -LiteralPath $continuationPath -PathType Leaf)) {
            throw "No reboot continuation exists for run '$RunId'."
        }
        $continuation = Get-Content -LiteralPath $continuationPath -Raw | ConvertFrom-Json
        if ($continuation.schema_version -ne 1 -or $continuation.run_id -ne $RunId -or
            $continuation.status -ne 'awaiting_reboot') {
            throw "Reboot continuation is invalid or not resumable: $continuationPath"
        }
        $SnapshotSha = [string]$continuation.snapshot_sha
        $SnapshotRef = [string]$continuation.snapshot_ref
        $Suite = [string]$continuation.suite
        $CommandSpecBase64 = [string]$continuation.command_spec_base64
        $ReuseRunId = if ($null -eq $continuation.PSObject.Properties['reuse_run_id']) {
            ''
        }
        else {
            [string]$continuation.reuse_run_id
        }
        if ((Get-BootId) -eq [string]$continuation.boot_id_before) {
            throw "Windows has not rebooted since run '$RunId' was armed."
        }
    }
    elseif ([string]::IsNullOrWhiteSpace($SnapshotSha) -or
        [string]::IsNullOrWhiteSpace($SnapshotRef)) {
        throw 'SnapshotSha and SnapshotRef are required for Run and Reboot modes.'
    }

    Sync-Checkout -RepoPath $repoPath -MirrorPath $mirrorPath -Ref $SnapshotRef -Sha $SnapshotSha
    $runner = Join-Path $repoPath 'scripts\windows-dev-test.ps1'
    if (-not (Test-Path -LiteralPath $runner -PathType Leaf)) {
        throw "The snapshot does not contain the Windows test runner: $runner"
    }

    $env:CARGO_TARGET_DIR = Join-Path $rootPath 'cache\cargo-target'
    $env:CARGO_INCREMENTAL = '1'
    $env:RUST_BACKTRACE = '1'
    $env:LSB_WINDOWS_TEST_RUN_ROOT = $runPath
    $env:LSB_WINDOWS_TEST_ASSETS_ROOT = Join-Path $statePath 'assets'
    $env:SEAWORK_WINDOWS_PFX_PATH = Join-Path $statePath 'assets\signing\SeaWork-CodeSign.pfx'
    $env:SEAWORK_WINDOWS_PFX_PASSWORD_FILE = Join-Path $statePath 'assets\signing\win_csc_key_password.txt'

    $phase = switch ($Mode) {
        'Run' { 'Normal' }
        'Reboot' { 'BeforeReboot' }
        'Resume' { 'AfterReboot' }
    }
    & pwsh -NoProfile -NonInteractive -File $runner `
        -RunId $RunId `
        -SnapshotSha $SnapshotSha `
        -Suite $Suite `
        -Phase $phase `
        -RunRoot $runPath `
        -CommandSpecBase64 $CommandSpecBase64 `
        -ReuseRunId $ReuseRunId
    $runnerExit = $LASTEXITCODE
    if ($runnerExit -ne 0) {
        exit $runnerExit
    }

    if ($Mode -eq 'Reboot') {
        $continuation = [ordered]@{
            schema_version = 1
            run_id = $RunId
            status = 'awaiting_reboot'
            snapshot_sha = $SnapshotSha
            snapshot_ref = $SnapshotRef
            suite = $Suite
            command_spec_base64 = $CommandSpecBase64
            reuse_run_id = $ReuseRunId
            boot_id_before = Get-BootId
            armed_utc = [DateTime]::UtcNow.ToString('o')
        }
        Write-JsonAtomic -Path $continuationPath -Value $continuation
        Write-Output "REBOOT_ARMED $RunId"
        & shutdown.exe /r /t 5 /f /c "LocalSandbox agent test $RunId"
        if ($LASTEXITCODE -ne 0) {
            throw "shutdown.exe failed with exit code $LASTEXITCODE"
        }
    }
    elseif ($Mode -eq 'Resume') {
        $continuation.status = 'completed'
        $continuation | Add-Member -NotePropertyName completed_utc `
            -NotePropertyValue ([DateTime]::UtcNow.ToString('o')) -Force
        $continuation | Add-Member -NotePropertyName boot_id_after `
            -NotePropertyValue (Get-BootId) -Force
        Write-JsonAtomic -Path $continuationPath -Value $continuation
    }
}
finally {
    $lock.Dispose()
}
