$ErrorActionPreference = "Stop"

$Repo = "LocalSandBox/local-sandbox"
$InstallDir = Join-Path $HOME ".local\bin"

##### Platform checks

function ConvertTo-LsbWindowsArchitecture {
    param([AllowNull()][object] $Value)

    if ($null -eq $Value) {
        return $null
    }

    $Text = "$Value".Trim()
    if (-not $Text) {
        return $null
    }

    switch -Regex ($Text.ToUpperInvariant()) {
        "^(X64|AMD64|X86_64|9)$" { return "x64" }
        "^(ARM64|AARCH64|12)$" { return "arm64" }
        "^(X86|I386|I686|0)$" { return "x86" }
        "^(ARM|5)$" { return "arm" }
        default { return $Text }
    }
}

function Get-LsbWindowsArchitecture {
    $Candidates = @()

    try {
        $Candidates += [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
    } catch {
    }

    try {
        $Processor = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1
        if ($Processor) {
            $Candidates += $Processor.Architecture
        }
    } catch {
    }

    try {
        $MachineEnvironment = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -ErrorAction Stop
        $Candidates += $MachineEnvironment.PROCESSOR_ARCHITECTURE
    } catch {
    }

    $Candidates += $env:PROCESSOR_ARCHITEW6432
    $Candidates += $env:PROCESSOR_ARCHITECTURE

    foreach ($Candidate in $Candidates) {
        $Architecture = ConvertTo-LsbWindowsArchitecture $Candidate
        if ($Architecture) {
            return $Architecture
        }
    }

    if ([System.Environment]::Is64BitOperatingSystem) {
        return "unknown-64-bit"
    }

    return "unknown"
}

function Get-LsbWindowsBuildNumber {
    try {
        $OperatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        if ($OperatingSystem.BuildNumber) {
            return [int]$OperatingSystem.BuildNumber
        }
    } catch {
    }

    try {
        $CurrentVersion = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction Stop
        if ($CurrentVersion.CurrentBuildNumber) {
            return [int]$CurrentVersion.CurrentBuildNumber
        }
    } catch {
    }

    return $null
}

function Format-LsbWindowsPlatform {
    param(
        [string]$Architecture,
        [AllowNull()][object]$BuildNumber
    )

    $BuildNumberValue = $null
    if ($null -ne $BuildNumber) {
        $BuildNumberValue = [int]$BuildNumber
    }

    if ($null -ne $BuildNumberValue -and $BuildNumberValue -ge 22000) {
        $Version = "Windows 11 build $BuildNumberValue"
    } elseif ($null -ne $BuildNumberValue) {
        $Version = "Windows build $BuildNumberValue"
    } else {
        $Version = "Windows version unknown"
    }

    if (-not $Architecture) {
        $Architecture = "unknown architecture"
    }

    return "$Version, $Architecture"
}

if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    throw "This installer is for Windows. Use install.sh on macOS."
}

$Arch = Get-LsbWindowsArchitecture
$BuildNumber = Get-LsbWindowsBuildNumber
$DetectedPlatform = Format-LsbWindowsPlatform -Architecture $Arch -BuildNumber $BuildNumber
if ($Arch -ne "x64" -or ($null -ne $BuildNumber -and $BuildNumber -lt 22000)) {
    throw "lsb Windows CLI releases currently support Windows 11 x64 only. Detected: $DetectedPlatform"
}

if ($null -eq $BuildNumber) {
    Write-Warning "Could not determine the Windows build number. Continuing because the detected architecture is x64."
}

if (-not (Get-Command tar -ErrorAction SilentlyContinue)) {
    throw "tar.exe is required to extract the lsb release archive."
}

##### Fetch latest release tag

Write-Host "Fetching latest release..."
$Release = Invoke-RestMethod `
    -Headers @{ "User-Agent" = "lsb-installer" } `
    -Uri "https://api.github.com/repos/$Repo/releases/latest"

$Tag = $Release.tag_name
if (-not $Tag) {
    throw "Could not determine latest release."
}

$Version = $Tag -replace "^v", ""
Write-Host "Latest version: $Version"

##### Download and extract

$Tarball = "lsb-v$Version-windows-x86_64.tar.gz"
$Url = "https://github.com/$Repo/releases/download/$Tag/$Tarball"
$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) "lsb-install-$([System.Guid]::NewGuid())"
$TarballPath = Join-Path $TempDir $Tarball

New-Item -ItemType Directory -Path $TempDir | Out-Null

try {
    Write-Host "Downloading $Tarball..."
    Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $TarballPath

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    tar -xzf $TarballPath -C $InstallDir

    $BinaryPath = Join-Path $InstallDir "lsb.exe"
    if (-not (Test-Path $BinaryPath)) {
        throw "lsb.exe was not found in the release archive."
    }

    Write-Host ""
    Write-Host "Installed lsb $Version to $BinaryPath"

    $ResolvedInstallDir = (Resolve-Path $InstallDir).Path
    $PathEntries = $env:PATH -split ";" | Where-Object { $_ }
    $OnPath = $PathEntries | Where-Object { $_.TrimEnd("\") -ieq $ResolvedInstallDir.TrimEnd("\") }

    if (-not $OnPath) {
        Write-Host ""
        Write-Host "Add $ResolvedInstallDir to your PATH. For the current user:"
        Write-Host ""
        Write-Host "  [Environment]::SetEnvironmentVariable('Path', `"$ResolvedInstallDir;`$([Environment]::GetEnvironmentVariable('Path', 'User'))`", 'User')"
        Write-Host ""
        Write-Host "Open a new terminal after updating PATH."
    }
} finally {
    Remove-Item -Recurse -Force $TempDir -ErrorAction SilentlyContinue
}
