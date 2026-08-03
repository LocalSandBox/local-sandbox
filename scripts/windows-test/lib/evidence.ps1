Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'common.ps1')

function Test-WindowsTestFetchName {
    param([Parameter(Mandatory = $true)][string] $Name)
    return $Name -eq 'profile-result.json' -or
        $Name -eq 'acceptance-evidence-manifest.json' -or
        $Name -eq 'seawork-test-release-manifest.json' -or
        $Name -eq 'SHA256SUMS' -or
        $Name -match '^result-[a-z0-9][a-z0-9-]{0,63}-(normal|beforereboot|afterreboot)\.json$' -or
        $Name -match '^evidence-[a-z0-9][a-z0-9._-]{0,80}\.redacted\.json$' -or
        $Name -match '^lsb-seawork-service-v[0-9A-Za-z.+-]+-windows-x86_64(-symbols)?\.zip$' -or
        $Name -match '^lsb-seawork-updater-v[0-9A-Za-z.+-]+-windows-x86_64\.zip$' -or
        $Name -match '^lsb-seawork-updater-v[0-9A-Za-z.+-]+-windows-x86_64-manifest\.json$' -or
        $Name -match '^lsb-seawork-updater-v[0-9A-Za-z.+-]+-SHA256SUMS$' -or
        $Name -match '^[A-Za-z0-9][A-Za-z0-9._+-]{0,120}\.tgz$'
}

function ConvertTo-WindowsTestRedactedValue {
    param([AllowNull()][object] $Value, [string] $PropertyName = '')
    $forbiddenProperty = '(?i)^(?:password|passwd|token|secret|authorization|cookie|private[_-]?key|certificate|cert|publisher|thumbprint|machine_name|computer_name|user_name|username|runner_name|user_sid|logon_sid)(?:$|_)'
    if (-not [string]::IsNullOrWhiteSpace($PropertyName) -and $PropertyName -match $forbiddenProperty) {
        return $null
    }
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) {
        if ($Value -match '(?i)S-1-5-21-(?:\d+-){2,}\d+') { return '[redacted-sid]' }
        if ($Value -match '(?i)(?:^|[\s"''])(?:[A-Z]:\\)' -or
            $Value -match '(?:^|[\s"''])\\\\[^\\\s"'']+\\') { return '[redacted-path]' }
        if ($Value -match '-----BEGIN [^-]*PRIVATE KEY-----') { return '[redacted-key]' }
        return $Value
    }
    if ($Value -is [ValueType]) { return $Value }
    if ($Value -is [Collections.IDictionary]) {
        $result = [ordered]@{}
        foreach ($key in $Value.Keys) {
            if ([string]$key -match $forbiddenProperty) { continue }
            $result[[string]$key] = ConvertTo-WindowsTestRedactedValue -Value $Value[$key] `
                -PropertyName ([string]$key)
        }
        return $result
    }
    if ($Value -is [Collections.IEnumerable] -and $Value -isnot [string]) {
        return @($Value | ForEach-Object { ConvertTo-WindowsTestRedactedValue -Value $_ })
    }
    $object = [ordered]@{}
    foreach ($property in $Value.PSObject.Properties) {
        if ($property.Name -match $forbiddenProperty) { continue }
        $object[$property.Name] = ConvertTo-WindowsTestRedactedValue -Value $property.Value `
            -PropertyName $property.Name
    }
    return $object
}

function Write-WindowsTestRedactedEvidence {
    param(
        [Parameter(Mandatory = $true)][string] $Source,
        [Parameter(Mandatory = $true)][string] $Destination
    )
    $document = Read-WindowsTestJson -Path $Source -MaximumBytes 16MB
    $redacted = ConvertTo-WindowsTestRedactedValue -Value $document
    Write-WindowsTestJsonAtomic -Path $Destination -Value $redacted
    $text = Get-Content -LiteralPath $Destination -Raw
    foreach ($pattern in @(
        '(?i)S-1-5-21-(?:\d+-){2,}\d+', '(?i)(?:^|[\s"''])(?:[A-Z]:\\)',
        '(?:^|[\s"''])\\\\[^\\\s"'']+\\', '-----BEGIN [^-]*PRIVATE KEY-----',
        '(?i)"(?:password|passwd|token|secret|authorization|cookie|private[_-]?key)"\s*:',
        '(?i)"(?:certificate|cert|publisher|thumbprint)[^"]*"\s*:',
        '(?i)"(?:machine_name|computer_name|user_name|username|runner_name|user_sid|logon_sid)"\s*:'
    )) {
        if ($text -match $pattern) { throw "Shared redaction verification failed: $Destination" }
    }
}

function Get-WindowsTestArtifactKind {
    param([string] $Name)
    if ($Name -match '^result-' -or $Name -eq 'profile-result.json') { return 'result' }
    if ($Name -match '^evidence-' -or $Name -eq 'acceptance-evidence-manifest.json') {
        return 'evidence'
    }
    if ($Name -match '\.(zip|tgz)$') { return 'release-artifact' }
    return 'manifest'
}

function Write-WindowsTestFetchManifest {
    param(
        [Parameter(Mandatory = $true)][string] $RunRoot,
        [Parameter(Mandatory = $true)][string] $RunId,
        [Parameter(Mandatory = $true)][string] $ResultPath,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]] $ExpectedArtifacts,
        [switch] $RequireExpected
    )
    $run = [IO.Path]::GetFullPath($RunRoot).TrimEnd('\', '/')
    $manifestPath = Join-Path $run 'fetch-manifest.json'
    $indexPath = Join-Path $run 'fetch-index.json'
    $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $sourceNames = [Collections.Generic.List[string]]::new()
    $sourceNames.Add((Split-Path -Leaf $ResultPath))
    foreach ($name in $ExpectedArtifacts) { $sourceNames.Add($name) }
    if (Test-Path -LiteralPath $indexPath -PathType Leaf) {
        $index = Read-WindowsTestJson -Path $indexPath -MaximumBytes 256KB
        if ($index.schema_version -ne 1 -or $index.run_id -cne $RunId) {
            throw "Fetch index identity is invalid: $indexPath"
        }
        foreach ($name in @($index.names)) { $sourceNames.Add([string]$name) }
    }
    if (Test-Path -LiteralPath $manifestPath -PathType Leaf) {
        try {
            $prior = Read-WindowsTestJson -Path $manifestPath -MaximumBytes 256KB
            foreach ($artifact in @($prior.artifacts)) { $sourceNames.Add([string]$artifact.name) }
        }
        catch { throw "Existing fetch manifest is invalid: $manifestPath" }
    }

    $records = [Collections.Generic.List[object]]::new()
    foreach ($sourceName in $sourceNames) {
        if ([string]::IsNullOrWhiteSpace($sourceName) -or $sourceName -eq 'fetch-manifest.json') {
            continue
        }
        if ($sourceName -notmatch '^[A-Za-z0-9][A-Za-z0-9._+-]{0,159}$') {
            throw "Declared artifact name is unsafe: $sourceName"
        }
        $sourcePath = Join-Path $run $sourceName
        $fetchName = $sourceName
        if ($sourceName -match '^evidence-.+\.json$' -and
            $sourceName -notmatch '\.redacted\.json$') {
            $fetchName = $sourceName -replace '\.json$', '.redacted.json'
            if (Test-Path -LiteralPath $sourcePath -PathType Leaf) {
                Write-WindowsTestRedactedEvidence -Source $sourcePath `
                    -Destination (Join-Path $run $fetchName)
            }
        }
        $fetchPath = Join-Path $run $fetchName
        if (-not (Test-Path -LiteralPath $fetchPath -PathType Leaf)) {
            if ($RequireExpected -and $sourceName -in $ExpectedArtifacts) {
                throw "Passed suite omitted declared artifact: $sourceName"
            }
            continue
        }
        if (-not (Test-WindowsTestFetchName -Name $fetchName)) {
            throw "Artifact is outside the closed fetch allowlist: $fetchName"
        }
        if (-not $names.Add($fetchName)) { continue }
        $item = Get-Item -LiteralPath $fetchPath -Force
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            $item.Length -gt 8GB) { throw "Fetch artifact is not a bounded regular file: $fetchName" }
        $records.Add([ordered]@{
            name = $fetchName
            sha256 = (Get-FileHash -LiteralPath $fetchPath -Algorithm SHA256).Hash.ToLowerInvariant()
            size = [int64]$item.Length
            kind = Get-WindowsTestArtifactKind -Name $fetchName
            redacted = $fetchName -match '\.redacted\.json$' -or $fetchName -match '^result-' -or
                $fetchName -eq 'profile-result.json'
        })
    }
    if ($records.Count -eq 0 -or $records.Count -gt 128) {
        throw 'Fetch manifest artifact count is outside the supported bound.'
    }
    Write-WindowsTestJsonAtomic -Path $indexPath -Value ([ordered]@{
        schema_version = 1
        run_id = $RunId
        names = @($records | ForEach-Object name | Sort-Object -Unique)
    })
    Write-WindowsTestJsonAtomic -Path $manifestPath -Value ([ordered]@{
        schema_version = 2
        run_id = $RunId
        generated_utc = [DateTime]::UtcNow.ToString('o')
        artifacts = @($records | Sort-Object name)
    })
    $fetchSchema = Join-Path (Split-Path -Parent $PSScriptRoot) 'schemas\fetch.schema.json'
    if (-not (Test-Json -LiteralPath $manifestPath -SchemaFile $fetchSchema)) {
        throw 'Generated fetch manifest does not satisfy fetch.schema.json.'
    }
    return $manifestPath
}

function Get-WindowsTestRuntimeAssetDigest {
    param([string] $AssetsRoot)
    if ([string]::IsNullOrWhiteSpace($AssetsRoot)) { return $null }
    $paths = @(
        (Join-Path $AssetsRoot 'runtime\Image'),
        (Join-Path $AssetsRoot 'runtime\initramfs.cpio.gz'),
        (Join-Path $AssetsRoot 'runtime\rootfs.ext4'),
        (Join-Path $AssetsRoot 'qemu\qemu-system-x86_64.exe'),
        (Join-Path $AssetsRoot 'qemu\qemu-img.exe')
    )
    if (@($paths | Where-Object { -not (Test-Path -LiteralPath $_ -PathType Leaf) }).Count) {
        return $null
    }
    $text = ($paths | ForEach-Object {
        (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLowerInvariant()
    }) -join "`n"
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return [Convert]::ToHexString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text))).ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Assert-WindowsTestProfileEvidenceManifest {
    param(
        [Parameter(Mandatory = $true)][string] $RunRoot,
        [Parameter(Mandatory = $true)][string] $ManifestPath,
        [Parameter(Mandatory = $true)][string] $SchemaPath
    )
    if (-not (Test-Json -LiteralPath $ManifestPath -SchemaFile $SchemaPath)) {
        throw 'Generated acceptance evidence does not satisfy profile-evidence.schema.json.'
    }
    $run = [IO.Path]::GetFullPath($RunRoot).TrimEnd('\', '/')
    $manifest = Read-WindowsTestJson -Path $ManifestPath -MaximumBytes 1MB
    $fileNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($record in @($manifest.files)) {
        $name = [string]$record.name
        if (-not $fileNames.Add($name) -or -not (Test-WindowsTestFetchName -Name $name)) {
            throw "Acceptance evidence contains a duplicate or unsafe file: $name"
        }
        $path = Join-Path $run $name
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            $item.Length -ne [int64]$record.size) {
            throw "Acceptance evidence file type or size mismatch: $name"
        }
        $digest = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($digest -cne [string]$record.sha256) {
            throw "Acceptance evidence file digest mismatch: $name"
        }
    }
    foreach ($check in @($manifest.checks)) {
        foreach ($name in @($check.evidence)) {
            if (-not $fileNames.Contains([string]$name)) {
                throw "Acceptance check '$($check.id)' references unbound evidence: $name"
            }
        }
    }
    $artifactBinding = [string]$manifest.bindings.release_artifact_sha256
    if ($null -eq $manifest.release_artifact) {
        if (-not [string]::IsNullOrWhiteSpace($artifactBinding)) {
            throw 'Release artifact binding exists without a release artifact record.'
        }
    }
    else {
        $artifact = $manifest.release_artifact
        $artifactPath = Join-Path $run ([string]$artifact.name)
        $item = Get-Item -LiteralPath $artifactPath -Force -ErrorAction Stop
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            $item.Length -ne [int64]$artifact.size) {
            throw 'Release artifact type or size does not match acceptance evidence.'
        }
        $digest = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($digest -cne [string]$artifact.sha256 -or $digest -cne $artifactBinding) {
            throw 'Release artifact digest does not match acceptance evidence bindings.'
        }
    }
    if ($manifest.profile -eq 'release' -and $manifest.status -eq 'passed' -and
        $null -eq $manifest.release_artifact) {
        throw 'Passed release evidence must bind an exact release artifact.'
    }
    return $manifest
}
