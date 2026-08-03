[CmdletBinding()]
param(
    [string] $RepositoryRoot = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),
    [string] $CatalogPath = (Join-Path $PSScriptRoot 'catalog.json')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'lib\common.ps1')

$root = [IO.Path]::GetFullPath($RepositoryRoot)
$catalog = Get-WindowsTestCatalog -Path $CatalogPath
$errors = [Collections.Generic.List[string]]::new()
$knownCategories = @('native', 'runtime', 'diagnostics', 'service', 'release')
$knownRebootModes = @('none', 'required')
$knownChecks = @(
    'con01.job_containment', 'ent01.managed_policy', 'mnt01.admin_live',
    'mnt01.nonadmin_staged', 'net01.managed_network', 'net02.host_relay',
    'net02.ports_wfp', 'obs01.event_log', 'rel01.artifact_trust',
    'sec01.endpoint_auth', 'sec02.reconciliation', 'tst01.adversarial',
    'tst02.lifecycle', 'win01.scm_lifecycle', 'win01.service_identity_session0',
    'win01.standard_user_no_uac', 'win01.two_users_two_logons',
    'win01.whpx_qemu_boot_exec_stop'
)

$catalogFiles = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($property in $catalog.suites.PSObject.Properties) {
    $name = $property.Name
    $suite = $property.Value
    if ($name -notmatch '^[a-z0-9][a-z0-9-]{0,63}$') { $errors.Add("invalid suite name: $name") }
    foreach ($field in @(
        'description', 'category', 'file', 'timeout_minutes', 'reboot_mode',
        'minimum_free_gib', 'required_capabilities', 'mutations', 'expected_artifacts',
        'acceptance_checks'
    )) {
        if ($null -eq $suite.PSObject.Properties[$field]) {
            $errors.Add("suite $name lacks $field")
        }
    }
    if ($suite.category -notin $knownCategories) { $errors.Add("suite $name has invalid category") }
    if ($suite.reboot_mode -notin $knownRebootModes) { $errors.Add("suite $name has invalid reboot_mode") }
    if ([int]$suite.timeout_minutes -lt 1 -or [int]$suite.timeout_minutes -gt 1440) {
        $errors.Add("suite $name has invalid timeout_minutes")
    }
    if (@($suite.required_capabilities).Count -eq 0) {
        $errors.Add("suite $name has no required capabilities")
    }
    if (@($suite.mutations).Count -eq 0) { $errors.Add("suite $name has no mutation declaration") }
    if (@($suite.expected_artifacts).Count -eq 0) {
        $errors.Add("suite $name has no expected artifacts")
    }
    foreach ($capability in @($suite.required_capabilities)) {
        if ($null -eq $catalog.capabilities.PSObject.Properties[[string]$capability]) {
            $errors.Add("suite $name references unknown capability $capability")
        }
    }
    foreach ($check in @($suite.acceptance_checks)) {
        if ([string]$check -notin $knownChecks) { $errors.Add("suite $name references unknown check $check") }
    }
    $relative = ([string]$suite.file).Replace('/', [IO.Path]::DirectorySeparatorChar)
    $full = [IO.Path]::GetFullPath((Join-Path $root $relative))
    if (-not $full.StartsWith("$root$([IO.Path]::DirectorySeparatorChar)", [StringComparison]::OrdinalIgnoreCase)) {
        $errors.Add("suite $name file escapes the repository")
    }
    elseif (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        $errors.Add("suite $name file is missing: $($suite.file)")
    }
    $catalogFiles.Add($full) | Out-Null
}

$suiteRoots = @((Join-Path $root 'scripts\windows-test\suites'))
foreach ($suiteRoot in $suiteRoots) {
    if (-not (Test-Path -LiteralPath $suiteRoot -PathType Container)) { continue }
    foreach ($file in @(Get-ChildItem -LiteralPath $suiteRoot -Filter '*.ps1' -File -Recurse)) {
        if (-not $catalogFiles.Contains($file.FullName)) {
            $errors.Add("suite file has no catalog entry: $($file.FullName.Substring($root.Length + 1))")
        }
    }
}

foreach ($property in $catalog.profiles.PSObject.Properties) {
    $name = $property.Name
    $profile = $property.Value
    foreach ($field in @('description', 'minimum_free_gib', 'reset', 'acceptance_checks', 'suites')) {
        if ($null -eq $profile.PSObject.Properties[$field]) { $errors.Add("profile $name lacks $field") }
    }
    $mapped = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $includes = @(if ($null -ne $profile.PSObject.Properties['includes']) { $profile.includes })
    $expanded = @($name) + $includes
    foreach ($expandedName in $expanded) {
        $expandedProperty = $catalog.profiles.PSObject.Properties[[string]$expandedName]
        if ($null -eq $expandedProperty) {
            $errors.Add("profile $name includes unknown profile $expandedName")
            continue
        }
        foreach ($suiteRef in @($expandedProperty.Value.suites)) {
            if ($null -eq $suiteRef.PSObject.Properties['name'] -or
                $null -eq $suiteRef.PSObject.Properties['required']) {
                $errors.Add("profile $expandedName has an invalid suite reference")
                continue
            }
            $suiteProperty = $catalog.suites.PSObject.Properties[[string]$suiteRef.name]
            if ($null -eq $suiteProperty) {
                $errors.Add("profile $expandedName references unknown suite $($suiteRef.name)")
                continue
            }
            foreach ($check in @($suiteProperty.Value.acceptance_checks)) { $mapped.Add([string]$check) | Out-Null }
        }
    }
    $declared = @($profile.acceptance_checks | Sort-Object -Unique)
    $missing = @($declared | Where-Object { -not $mapped.Contains([string]$_) })
    $extra = @($mapped | Where-Object { $_ -notin $declared })
    if ($missing.Count -or $extra.Count) {
        $errors.Add("profile $name acceptance mapping differs: missing=[$($missing -join ',')] extra=[$($extra -join ',')]")
    }
}

foreach ($path in @(Get-ChildItem -LiteralPath $root -Filter '*.ps1' -File -Recurse | Where-Object {
    $_.FullName -notmatch '[\\/]target[\\/]'
})) {
    $parseErrors = $null
    [void][Management.Automation.Language.Parser]::ParseFile(
        $path.FullName, [ref]$null, [ref]$parseErrors
    )
    foreach ($parseError in @($parseErrors)) {
        $errors.Add("$($path.FullName.Substring($root.Length + 1)): $parseError")
    }
}

if ($errors.Count -gt 0) {
    $errors | ForEach-Object { Write-Error $_ }
    throw "Windows test catalog validation failed with $($errors.Count) error(s)."
}
Write-Output "Validated $(@($catalog.suites.PSObject.Properties).Count) suites, $(@($catalog.profiles.PSObject.Properties).Count) profiles, and all PowerShell syntax."
