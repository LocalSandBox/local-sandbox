[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('runtime', 'diagnostics', 'service', 'release')]
    [string] $Profile,
    [string] $CatalogPath = (Join-Path $PSScriptRoot 'catalog.json'),
    [switch] $IncludeOptional
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'lib\common.ps1')

$catalog = Get-WindowsTestCatalog -Path $CatalogPath
$profileEntry = $catalog.profiles.PSObject.Properties[$Profile].Value
$profileNames = [Collections.Generic.List[string]]::new()
if ($null -ne $profileEntry.PSObject.Properties['includes']) {
    foreach ($included in @($profileEntry.includes)) { $profileNames.Add([string]$included) }
}
$profileNames.Add($Profile)

$seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($profileName in $profileNames) {
    $entry = $catalog.profiles.PSObject.Properties[$profileName].Value
    foreach ($suiteRef in @($entry.suites)) {
        if (-not $suiteRef.required -and -not $IncludeOptional) { continue }
        $suiteName = [string]$suiteRef.name
        if (-not $seen.Add($suiteName)) {
            throw "Profile '$Profile' resolves suite '$suiteName' more than once."
        }
        $suite = $catalog.suites.PSObject.Properties[$suiteName].Value
        Write-Output "$suiteName`t$($suite.reboot_mode)"
    }
}
