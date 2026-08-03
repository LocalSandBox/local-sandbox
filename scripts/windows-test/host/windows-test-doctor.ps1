[CmdletBinding()]
param(
    [ValidateSet('', 'runtime', 'diagnostics', 'service', 'release')]
    [string] $Profile = '',
    [string] $Root = 'C:\dev\local-sandbox-agent',
    [string] $StateRoot = 'C:\dev\local-sandbox-agent-state',
    [string] $CatalogPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'catalog.json'),
    [switch] $Json
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'lib\common.ps1')

function Get-WhpxState {
    try {
        $output = @(& dism.exe /English /Online /Get-FeatureInfo /FeatureName:HypervisorPlatform)
        if ($LASTEXITCODE -ne 0) { return 'unavailable' }
        $line = $output | Where-Object { $_ -match '^State\s*:' } | Select-Object -First 1
        if ($null -eq $line) { return 'unknown' }
        return (($line -split ':', 2)[1]).Trim()
    }
    catch { return 'unavailable' }
}

function Test-IsAdministrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        return [Security.Principal.WindowsPrincipal]::new($identity).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator
        )
    }
    catch { return $false }
}

function Test-RegularFile {
    param([string] $Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    $item = Get-Item -LiteralPath $Path -Force
    return -not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)
}

function Get-StaleResources {
    $resources = [Collections.Generic.List[string]]::new()
    foreach ($name in @('LocalSandboxSeaWorkUpdater', 'LocalSandboxSeaWork', 'LocalSandboxSeaWorkSpike')) {
        if (Get-Service -Name $name -ErrorAction SilentlyContinue) { $resources.Add("service:$name") }
    }
    foreach ($path in @(
        (Join-Path $env:ProgramFiles 'SeaWork\LocalSandbox'),
        (Join-Path $env:ProgramData 'LocalSandbox\SeaWork'),
        (Join-Path $env:ProgramData 'SeaWork\Installer')
    )) {
        if (Test-Path -LiteralPath $path) { $resources.Add("path:$path") }
    }
    foreach ($task in @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
        $_.TaskName -like 'LocalSandboxAgent-*'
    })) { $resources.Add("task:$($task.TaskName)") }
    foreach ($user in @(Get-LocalUser -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match '^lsb-[a-z0-9-]+$'
    })) { $resources.Add("user:$($user.Name)") }
    foreach ($share in @(Get-SmbShare -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match '^lsb-[a-z0-9-]+$'
    })) { $resources.Add("share:$($share.Name)") }
    foreach ($name in @(
        'localsandbox-seawork-service', 'localsandbox-seawork-updater',
        'lsb-service-spike', 'qemu-system-x86_64', 'qemu-img'
    )) {
        foreach ($process in @(Get-Process -Name $name -ErrorAction SilentlyContinue)) {
            $resources.Add("process:$name/$($process.Id)")
        }
    }
    $imports = Join-Path $StateRoot 'imports'
    if (Test-Path -LiteralPath $imports -PathType Container) {
        foreach ($stage in @(Get-ChildItem -LiteralPath $imports -Directory -Force)) {
            $resources.Add("artifact-import:$($stage.Name)")
        }
    }
    return @($resources | Sort-Object -Unique)
}

function Get-PendingRebootReasons {
    $reasons = [Collections.Generic.List[string]]::new()
    foreach ($path in @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    )) {
        if (Test-Path -LiteralPath $path) { $reasons.Add($path) }
    }
    try {
        $pendingRename = (Get-ItemProperty -LiteralPath `
            'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
            -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
        if ($null -ne $pendingRename) { $reasons.Add('PendingFileRenameOperations') }
    }
    catch {}
    $runs = Join-Path $StateRoot 'runs'
    if (Test-Path -LiteralPath $runs -PathType Container) {
        foreach ($continuation in @(Get-ChildItem -LiteralPath $runs -Filter continuation.json `
            -File -Recurse -ErrorAction SilentlyContinue)) {
            try {
                $value = Read-WindowsTestJson -Path $continuation.FullName -MaximumBytes 64KB
                if ($value.status -eq 'awaiting_reboot') {
                    $reasons.Add("runner:$($value.run_id)")
                }
            }
            catch { $reasons.Add("invalid-continuation:$($continuation.Directory.Name)") }
        }
    }
    return @($reasons)
}

$catalog = Get-WindowsTestCatalog -Path $CatalogPath
$required = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($name in @('administrator', 'windows11_x86_64', 'sshd', 'build_tools')) {
    $required.Add($name) | Out-Null
}
$minimumFreeGiB = 10
if (-not [string]::IsNullOrWhiteSpace($Profile)) {
    $profileEntry = $catalog.profiles.PSObject.Properties[$Profile].Value
    $minimumFreeGiB = [int]$profileEntry.minimum_free_gib
    $profileNames = [Collections.Generic.List[string]]::new()
    if ($null -ne $profileEntry.PSObject.Properties['includes']) {
        foreach ($included in @($profileEntry.includes)) { $profileNames.Add([string]$included) }
    }
    $profileNames.Add($Profile)
    foreach ($profileName in $profileNames) {
        $entry = $catalog.profiles.PSObject.Properties[$profileName].Value
        foreach ($suiteRef in @($entry.suites | Where-Object required)) {
            $suite = $catalog.suites.PSObject.Properties[[string]$suiteRef.name].Value
            foreach ($capability in @($suite.required_capabilities)) {
                $required.Add([string]$capability) | Out-Null
            }
        }
    }
}

$os = Get-CimInstance Win32_OperatingSystem
$computer = Get-CimInstance Win32_ComputerSystem
$sshd = Get-Service -Name sshd -ErrorAction SilentlyContinue
$assets = Join-Path $StateRoot 'assets'
$runtime = Join-Path $assets 'runtime'
$qemu = Join-Path $assets 'qemu'
$signing = Join-Path $assets 'signing'
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$buildCommands = @('git', 'cargo', 'rustc', 'cmake', 'pwsh')
$buildReady = ($buildCommands | Where-Object {
    $null -eq (Get-Command $_ -ErrorAction SilentlyContinue)
}).Count -eq 0 -and (Test-RegularFile $vswhere)

$capabilityState = [ordered]@{
    administrator = Test-IsAdministrator
    windows11_x86_64 = ([Environment]::Is64BitOperatingSystem -and [int]$os.BuildNumber -ge 22000)
    whpx = ([bool]$computer.HypervisorPresent -and (Get-WhpxState) -eq 'Enabled')
    sshd = ($null -ne $sshd -and $sshd.Status -eq 'Running' -and $sshd.StartType -eq 'Automatic')
    build_tools = $buildReady
    runtime_assets = (@('Image', 'initramfs.cpio.gz', 'rootfs.ext4') | Where-Object {
        -not (Test-RegularFile (Join-Path $runtime $_))
    }).Count -eq 0
    qemu_assets = (@('qemu-system-x86_64.exe', 'qemu-img.exe') | Where-Object {
        -not (Test-RegularFile (Join-Path $qemu $_))
    }).Count -eq 0
    signing_assets = (@('SeaWork-CodeSign.pfx', 'win_csc_key_password.txt') | Where-Object {
        -not (Test-RegularFile (Join-Path $signing $_))
    }).Count -eq 0
    interactive_user = -not [string]::IsNullOrWhiteSpace([string]$computer.UserName)
    outbound_network = $true
    sentry_dsn = Test-RegularFile (Join-Path $StateRoot 'sentry-acceptance-dsn.txt')
}

$stateDrive = Get-PSDrive -Name ([IO.Path]::GetPathRoot([IO.Path]::GetFullPath($StateRoot)).Substring(0, 1))
$freeGiB = [math]::Round($stateDrive.Free / 1GB, 2)
$missing = @($required | Where-Object { -not [bool]$capabilityState[$_] } | Sort-Object)
$pendingReboot = @(Get-PendingRebootReasons)
$stale = @(Get-StaleResources)
$report = [ordered]@{
    schema_version = 1
    status = if ($missing.Count -eq 0 -and $freeGiB -ge $minimumFreeGiB -and
        $pendingReboot.Count -eq 0 -and $stale.Count -eq 0) { 'ready' } else { 'not_ready' }
    profile = if ([string]::IsNullOrWhiteSpace($Profile)) { $null } else { $Profile }
    required_capabilities = @($required | Sort-Object)
    capabilities = $capabilityState
    missing_capabilities = $missing
    disk = [ordered]@{
        free_gib = $freeGiB
        minimum_free_gib = $minimumFreeGiB
        pressure = $freeGiB -lt $minimumFreeGiB
    }
    pending_reboot = $pendingReboot
    stale_resources = $stale
}

if ($Json) {
    $report | ConvertTo-Json -Depth 10
}
else {
    Write-Output "Windows test host: $($report.status)"
    Write-Output "Profile: $(if ($null -eq $report.profile) { 'baseline' } else { $report.profile })"
    Write-Output "Disk: $freeGiB GiB free; $minimumFreeGiB GiB required"
    Write-Output "Missing capabilities: $(if ($missing.Count) { $missing -join ', ' } else { 'none' })"
    Write-Output "Pending reboot: $(if ($pendingReboot.Count) { $pendingReboot -join ', ' } else { 'none' })"
    Write-Output "Stale product/test resources: $(if ($stale.Count) { $stale -join ', ' } else { 'none' })"
}
if ($report.status -ne 'ready') { exit 1 }
