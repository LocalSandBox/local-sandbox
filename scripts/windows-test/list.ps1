[CmdletBinding()]
param([string] $CatalogPath = (Join-Path $PSScriptRoot 'catalog.json'))

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'lib\common.ps1')
$catalog = Get-WindowsTestCatalog -Path $CatalogPath

Write-Output 'Acceptance profiles:'
foreach ($property in $catalog.profiles.PSObject.Properties) {
    $profile = $property.Value
    $suites = @($profile.suites | ForEach-Object {
        if ($_.required) { $_.name } else { "$($_.name) (optional)" }
    })
    $includes = @(if ($null -ne $profile.PSObject.Properties['includes']) { $profile.includes })
    if ($includes.Count) { $suites = @($includes | ForEach-Object { "@$_" }) + $suites }
    Write-Output ("  {0,-12} {1} [{2}]" -f $property.Name, $profile.description, ($suites -join ', '))
}
Write-Output ''
Write-Output 'Focused suites:'
foreach ($property in @($catalog.suites.PSObject.Properties | Sort-Object Name)) {
    $suite = $property.Value
    $hardware = if ($suite.category -eq 'native') { 'native/non-acceptance' } else { $suite.category }
    Write-Output ("  {0,-28} {1,-21} {2,4}m  {3}" -f `
        $property.Name, $hardware, $suite.timeout_minutes, $suite.description)
}
