[CmdletBinding()]
param(
    [string] $Root = 'C:\dev\local-sandbox-agent',
    [string] $StateRoot = (Join-Path $env:ProgramData 'LocalSandbox\DevTest'),
    [string] $BootstrapSource = (Join-Path $PSScriptRoot 'windows-test-bootstrap.ps1'),
    [string] $SigningAssetsSource = (Join-Path $PSScriptRoot 'windows-test-signing-assets.ps1'),
    [string] $ArtifactFetchSource = (Join-Path $PSScriptRoot 'windows-test-artifacts.ps1'),
    [switch] $VerifyOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$schemaVersion = 1
$markerName = '.local-sandbox-agent-test-root.json'

function Resolve-SafeRoot {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $ExpectedLeaf,
        [Parameter(Mandatory = $true)][string] $Label
    )

    $fullPath = [IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
    $volumeRoot = [IO.Path]::GetPathRoot($fullPath).TrimEnd('\', '/')
    if ($fullPath -eq $volumeRoot -or (Split-Path -Leaf $fullPath) -ne $ExpectedLeaf) {
        throw "$Label must end in the dedicated '$ExpectedLeaf' directory and cannot be a filesystem root: $fullPath"
    }
    return $fullPath
}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Windows test-host setup requires an elevated administrator token.'
    }
    return $identity.User
}

function Assert-OwnedOrEmptyDirectory {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $MarkerPath
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path | Out-Null
        return
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "Dedicated root exists but is not a directory: $Path"
    }
    if (-not (Test-Path -LiteralPath $MarkerPath -PathType Leaf)) {
        $existing = Get-ChildItem -LiteralPath $Path -Force | Select-Object -First 1
        if ($null -ne $existing) {
            throw "Refusing to adopt a non-empty directory without the agent-owned marker: $Path"
        }
        return
    }
    try {
        $marker = Get-Content -LiteralPath $MarkerPath -Raw | ConvertFrom-Json
    }
    catch {
        throw "Agent-owned directory marker is unreadable: $MarkerPath"
    }
    if ($marker.schema_version -ne 1 -or $marker.owner -ne 'local-sandbox-agent-test-flow') {
        throw "Agent-owned directory marker is invalid: $MarkerPath"
    }
}

function Assert-ValidMarker {
    param([Parameter(Mandatory = $true)][string] $Path)

    try {
        $marker = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    }
    catch {
        throw "Agent-owned directory marker is unreadable: $Path"
    }
    if ($marker.schema_version -ne 1 -or $marker.owner -ne 'local-sandbox-agent-test-flow') {
        throw "Agent-owned directory marker is invalid: $Path"
    }
}

function Set-ProtectedDirectoryAcl {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier] $CurrentUserSid
    )

    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propagation = [Security.AccessControl.PropagationFlags]::None
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $fullControl = [Security.AccessControl.FileSystemRights]::FullControl
    $sids = @(
        [Security.Principal.SecurityIdentifier]::new('S-1-5-18'),
        [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'),
        $CurrentUserSid
    )
    foreach ($sid in $sids) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            $fullControl,
            $inheritance,
            $propagation,
            $allow
        )
        $acl.AddAccessRule($rule) | Out-Null
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Assert-ProtectedDirectoryAcl {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier] $CurrentUserSid
    )

    $acl = Get-Acl -LiteralPath $Path
    if (-not $acl.AreAccessRulesProtected) {
        throw "Dedicated root still inherits access rules: $Path"
    }
    $expected = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544', $CurrentUserSid.Value)) {
        $expected.Add($sid) | Out-Null
    }
    $observed = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $rules = $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
    foreach ($rule in $rules) {
        $sid = $rule.IdentityReference.Value
        if (-not $expected.Contains($sid) -or
            $rule.AccessControlType.ToString() -ne 'Allow' -or
            ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne
                [Security.AccessControl.FileSystemRights]::FullControl) {
            throw "Dedicated root has an unexpected access rule for ${sid}: $Path"
        }
        $observed.Add($sid) | Out-Null
    }
    foreach ($sid in $expected) {
        if (-not $observed.Contains($sid)) {
            throw "Dedicated root is missing the required full-control rule for ${sid}: $Path"
        }
    }
}

function Invoke-Git {
    param([Parameter(Mandatory = $true)][string[]] $Arguments)

    & git @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "git failed with exit code ${LASTEXITCODE}: git $($Arguments -join ' ')"
    }
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

function Get-WhpxState {
    $output = @(& dism.exe /English /Online /Get-FeatureInfo /FeatureName:HypervisorPlatform)
    if ($LASTEXITCODE -ne 0) {
        throw "DISM failed to query Windows Hypervisor Platform with exit code $LASTEXITCODE."
    }
    $stateLine = $output | Where-Object { $_ -match '^State\s*:' } | Select-Object -First 1
    if ($null -eq $stateLine) {
        throw 'DISM returned no Windows Hypervisor Platform state.'
    }
    return (($stateLine -split ':', 2)[1]).Trim()
}

function Test-HostConfiguration {
    param(
        [Parameter(Mandatory = $true)][string] $RootPath,
        [Parameter(Mandatory = $true)][string] $StatePath,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier] $CurrentUserSid
    )

    $os = Get-CimInstance Win32_OperatingSystem
    $computer = Get-CimInstance Win32_ComputerSystem
    if (-not [Environment]::Is64BitOperatingSystem -or $os.OSArchitecture -notmatch '64') {
        throw 'The test host must run x86-64 Windows.'
    }
    if ([int]$os.BuildNumber -lt 22000) {
        throw "The test host must run Windows 11 or later; observed build $($os.BuildNumber)."
    }
    if (-not $computer.HypervisorPresent) {
        throw 'No active Windows hypervisor was detected.'
    }
    $whpx = Get-WhpxState
    if ($whpx -ne 'Enabled') {
        throw "Windows Hypervisor Platform must be enabled; observed $whpx."
    }
    $sshd = Get-Service -Name sshd
    if ($sshd.Status.ToString() -ne 'Running' -or
        $sshd.StartType.ToString() -ne 'Automatic') {
        throw "sshd must be running with Automatic startup; observed $($sshd.Status)/$($sshd.StartType)."
    }
    foreach ($command in @('git', 'cargo', 'rustc', 'cmake', 'pwsh')) {
        if ($null -eq (Get-Command $command -ErrorAction SilentlyContinue)) {
            throw "Required command is unavailable: $command"
        }
    }
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) {
        throw 'Visual Studio Build Tools discovery is unavailable (vswhere.exe is missing).'
    }
    $buildTools = @(& $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath)
    if ($LASTEXITCODE -ne 0 -or $buildTools.Count -ne 1 -or [string]::IsNullOrWhiteSpace($buildTools[0])) {
        throw 'Visual Studio C++ x86/x64 Build Tools are not installed.'
    }
    $installedTargets = @(& rustup target list --installed)
    if ($LASTEXITCODE -ne 0 -or $installedTargets -notcontains 'x86_64-pc-windows-msvc') {
        throw 'The x86_64-pc-windows-msvc Rust target is not installed.'
    }
    foreach ($path in @(
        $RootPath,
        (Join-Path $RootPath 'mirror.git'),
        (Join-Path $RootPath 'repo'),
        (Join-Path $RootPath 'bootstrap.ps1'),
        (Join-Path $RootPath 'windows-test-signing-assets.ps1'),
        (Join-Path $RootPath 'windows-test-artifacts.ps1'),
        (Join-Path $RootPath 'setup-windows-test-host.ps1'),
        $StatePath,
        (Join-Path $StatePath 'locks'),
        (Join-Path $StatePath 'runs'),
        (Join-Path $StatePath 'assets')
    )) {
        if (-not (Test-Path -LiteralPath $path)) {
            throw "Required test-host path is missing: $path"
        }
    }
    $isBare = (& git -C (Join-Path $RootPath 'mirror.git') rev-parse --is-bare-repository).Trim()
    if ($LASTEXITCODE -ne 0 -or $isBare -ne 'true') {
        throw 'The agent source mirror is not a valid bare Git repository.'
    }
    & git -C (Join-Path $RootPath 'repo') rev-parse --git-dir | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'The agent checkout is not a valid Git repository.'
    }
    Assert-ProtectedDirectoryAcl -Path $RootPath -CurrentUserSid $CurrentUserSid
    Assert-ProtectedDirectoryAcl -Path $StatePath -CurrentUserSid $CurrentUserSid

    return [ordered]@{
        schema_version = $schemaVersion
        status = 'ready'
        os_caption = $os.Caption
        os_build = $os.BuildNumber
        architecture = $os.OSArchitecture
        hypervisor_present = [bool]$computer.HypervisorPresent
        whpx = $whpx
        sshd = $sshd.Status.ToString()
        sshd_start = $sshd.StartType.ToString()
        root = $RootPath
        state_root = $StatePath
        git = (& git --version).Trim()
        cargo = (& cargo --version).Trim()
        rustc = (& rustc --version).Trim()
    }
}

$currentUserSid = Assert-Administrator
$rootPath = Resolve-SafeRoot -Path $Root -ExpectedLeaf 'local-sandbox-agent' -Label 'Root'
$statePath = Resolve-SafeRoot -Path $StateRoot -ExpectedLeaf 'DevTest' -Label 'StateRoot'
$rootMarker = Join-Path $rootPath $markerName
$stateMarker = Join-Path $statePath $markerName

if ($VerifyOnly) {
    if (-not (Test-Path -LiteralPath $rootMarker -PathType Leaf) -or
        -not (Test-Path -LiteralPath $stateMarker -PathType Leaf)) {
        throw 'The Windows test host has not been initialized by this setup script.'
    }
    Assert-ValidMarker -Path $rootMarker
    Assert-ValidMarker -Path $stateMarker
    Test-HostConfiguration -RootPath $rootPath -StatePath $statePath -CurrentUserSid $currentUserSid |
        ConvertTo-Json -Depth 8 -Compress
    exit 0
}

Assert-OwnedOrEmptyDirectory -Path $rootPath -MarkerPath $rootMarker
Assert-OwnedOrEmptyDirectory -Path $statePath -MarkerPath $stateMarker
Set-ProtectedDirectoryAcl -Path $rootPath -CurrentUserSid $currentUserSid
Set-ProtectedDirectoryAcl -Path $statePath -CurrentUserSid $currentUserSid

$mirrorPath = Join-Path $rootPath 'mirror.git'
$repoPath = Join-Path $rootPath 'repo'
$cachePath = Join-Path $rootPath 'cache\cargo-target'
$lockPath = Join-Path $statePath 'locks'
$runsPath = Join-Path $statePath 'runs'
$assetsPath = Join-Path $statePath 'assets'
New-Item -ItemType Directory -Force -Path $cachePath, $lockPath, $runsPath, $assetsPath | Out-Null

if (-not (Test-Path -LiteralPath $mirrorPath)) {
    Invoke-Git -Arguments @('init', '--bare', $mirrorPath)
}
if (-not (Test-Path -LiteralPath $repoPath)) {
    New-Item -ItemType Directory -Path $repoPath | Out-Null
}
if (-not (Test-Path -LiteralPath (Join-Path $repoPath '.git'))) {
    $existingRepoFiles = Get-ChildItem -LiteralPath $repoPath -Force | Select-Object -First 1
    if ($null -ne $existingRepoFiles) {
        throw "Refusing to initialize a non-empty checkout directory: $repoPath"
    }
    Invoke-Git -Arguments @('init', $repoPath)
}

Invoke-Git -Arguments @('-C', $mirrorPath, 'config', 'receive.denyNonFastForwards', 'false')
Invoke-Git -Arguments @('-C', $repoPath, 'config', 'core.autocrlf', 'false')
Invoke-Git -Arguments @('-C', $repoPath, 'config', 'core.longpaths', 'true')
$existingRemote = & git -C $repoPath remote get-url snapshot 2>$null
if ($LASTEXITCODE -eq 0) {
    Invoke-Git -Arguments @('-C', $repoPath, 'remote', 'set-url', 'snapshot', $mirrorPath)
}
else {
    Invoke-Git -Arguments @('-C', $repoPath, 'remote', 'add', 'snapshot', $mirrorPath)
}

$resolvedBootstrap = (Resolve-Path -LiteralPath $BootstrapSource).Path
$resolvedSigningAssets = (Resolve-Path -LiteralPath $SigningAssetsSource).Path
$resolvedArtifactFetch = (Resolve-Path -LiteralPath $ArtifactFetchSource).Path
$installedBootstrap = Join-Path $rootPath 'bootstrap.ps1'
$installedSigningAssets = Join-Path $rootPath 'windows-test-signing-assets.ps1'
$installedArtifactFetch = Join-Path $rootPath 'windows-test-artifacts.ps1'
$installedSetup = Join-Path $rootPath 'setup-windows-test-host.ps1'
if (-not [IO.Path]::GetFullPath($resolvedBootstrap).Equals(
    [IO.Path]::GetFullPath($installedBootstrap),
    [StringComparison]::OrdinalIgnoreCase
)) {
    Copy-Item -LiteralPath $resolvedBootstrap -Destination $installedBootstrap -Force
}
if (-not [IO.Path]::GetFullPath($resolvedSigningAssets).Equals(
    [IO.Path]::GetFullPath($installedSigningAssets),
    [StringComparison]::OrdinalIgnoreCase
)) {
    Copy-Item -LiteralPath $resolvedSigningAssets -Destination $installedSigningAssets -Force
}
if (-not [IO.Path]::GetFullPath($resolvedArtifactFetch).Equals(
    [IO.Path]::GetFullPath($installedArtifactFetch),
    [StringComparison]::OrdinalIgnoreCase
)) {
    Copy-Item -LiteralPath $resolvedArtifactFetch -Destination $installedArtifactFetch -Force
}
if (-not [IO.Path]::GetFullPath($PSCommandPath).Equals(
    [IO.Path]::GetFullPath($installedSetup),
    [StringComparison]::OrdinalIgnoreCase
)) {
    Copy-Item -LiteralPath $PSCommandPath -Destination $installedSetup -Force
}

$marker = [ordered]@{
    schema_version = $schemaVersion
    owner = 'local-sandbox-agent-test-flow'
    current_user_sid = $currentUserSid.Value
    created_or_verified_utc = [DateTime]::UtcNow.ToString('o')
}
Write-JsonAtomic -Path $rootMarker -Value $marker
Write-JsonAtomic -Path $stateMarker -Value $marker

Test-HostConfiguration -RootPath $rootPath -StatePath $statePath -CurrentUserSid $currentUserSid |
    ConvertTo-Json -Depth 8 -Compress
