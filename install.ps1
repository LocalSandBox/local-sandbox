$ErrorActionPreference = "Stop"

$Repo = "LocalSandBox/local-sandbox"
$InstallDir = Join-Path $HOME ".local\bin"

##### Platform checks

if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    throw "This installer is for Windows. Use install.sh on macOS."
}

$Arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
if ($Arch -ne [System.Runtime.InteropServices.Architecture]::X64) {
    throw "lsb Windows CLI releases currently support Windows 11 x64 only. Detected: $Arch"
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
