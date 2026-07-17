[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ServiceBinary,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath,

    [string]$DumpbinPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-Dumpbin {
    if (-not [string]::IsNullOrWhiteSpace($DumpbinPath)) {
        return (Resolve-Path -LiteralPath $DumpbinPath -ErrorAction Stop).Path
    }
    $command = Get-Command dumpbin.exe -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        return $command.Source
    }
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) {
        throw 'dumpbin.exe and vswhere.exe were not found'
    }
    $installation = (& $vswhere -latest -products * `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -property installationPath | Select-Object -First 1)
    if ([string]::IsNullOrWhiteSpace($installation)) {
        throw 'a Visual Studio C++ tools installation was not found'
    }
    $toolsRoot = Join-Path $installation 'VC\Tools\MSVC'
    $candidate = Get-ChildItem -LiteralPath $toolsRoot -Directory |
        Sort-Object { [version]$_.Name } -Descending |
        ForEach-Object { Join-Path $_.FullName 'bin\Hostx64\x64\dumpbin.exe' } |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
        Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($candidate)) {
        throw 'x64 dumpbin.exe was not found in the Visual Studio C++ tools'
    }
    return $candidate
}

$service = (Resolve-Path -LiteralPath $ServiceBinary -ErrorAction Stop).Path
if (-not (Test-Path -LiteralPath $service -PathType Leaf)) {
    throw 'ServiceBinary must be a file'
}
if ((Get-Item -LiteralPath $service -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw 'ServiceBinary must not be a reparse point'
}

$output = [IO.Path]::GetFullPath($OutputPath)
if (Test-Path -LiteralPath $output) {
    throw 'OutputPath already exists'
}
$parent = Split-Path -Parent $output
if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
    throw 'OutputPath parent directory does not exist'
}
if ((Get-Item -LiteralPath $parent -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw 'OutputPath parent must not be a reparse point'
}

$dumpbin = Resolve-Dumpbin
$lines = @(& $dumpbin /NOLOGO /DEPENDENTS $service 2>&1)
if ($LASTEXITCODE -ne 0) {
    throw "dumpbin /DEPENDENTS failed with exit code $LASTEXITCODE"
}
$dependencies = @($lines |
    ForEach-Object { $_.ToString().Trim() } |
    Where-Object { $_ -match '^[A-Za-z0-9_.-]+\.dll$' } |
    ForEach-Object { $_.ToLowerInvariant() } |
    Sort-Object -Unique)
if ($dependencies.Count -eq 0) {
    throw 'dumpbin reported no service DLL dependencies'
}

$systemDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::System)
$entries = foreach ($dependency in $dependencies) {
    $isApiSet = $dependency.StartsWith('api-ms-win-', [StringComparison]::OrdinalIgnoreCase) -or
        $dependency.StartsWith('ext-ms-win-', [StringComparison]::OrdinalIgnoreCase)
    $isRedistributable = $dependency -match '^(vcruntime|msvcp|concrt|mfc)[0-9].*\.dll$'
    if ($isRedistributable) {
        throw "Visual C++ runtime dependency must be statically linked: $dependency"
    }
    if (-not $isApiSet -and
        -not (Test-Path -LiteralPath (Join-Path $systemDirectory $dependency) -PathType Leaf)) {
        throw "non-system runtime dependency is not bundled: $dependency"
    }
    [ordered]@{
        name = $dependency
        source = 'windows_system'
    }
}

$report = [ordered]@{
    schema_version = 1
    architecture = 'x86_64'
    service_binary = [IO.Path]::GetFileName($service)
    service_sha256 = (Get-FileHash -LiteralPath $service -Algorithm SHA256).Hash.ToLowerInvariant()
    dependencies = @($entries)
}
$json = $report | ConvertTo-Json -Depth 5
[IO.File]::WriteAllText($output, $json + "`n", [Text.UTF8Encoding]::new($false))
Write-Output "wrote runtime dependency report for $($dependencies.Count) DLLs to $output"
