Set-StrictMode -Version Latest

$script:FailureDiagnosticMaxFiles = 256
$script:FailureDiagnosticMaxFileBytes = 4MB
$script:FailureDiagnosticMaxTotalBytes = 20MB
$script:FailureDiagnosticExtensions = @('.json', '.jsonl', '.log', '.txt', '.zip')
$script:FailureDiagnosticDeniedExtensions = @(
    '.crt', '.der', '.ext4', '.img', '.key', '.p12', '.pem', '.pfx', '.qcow2', '.vhd', '.vhdx'
)

function Test-FailureDiagnosticFileAllowed {
    param([Parameter(Mandatory = $true)][IO.FileInfo] $File)

    $name = $File.Name.ToLowerInvariant()
    $extension = $File.Extension.ToLowerInvariant()
    if ($extension -in $script:FailureDiagnosticDeniedExtensions -or
        $extension -notin $script:FailureDiagnosticExtensions) {
        return $false
    }
    if ($name -match '(credential|password|secret|token|private[-_.]?key)' -or
        $name -in @('service.json', 'product-ca.pem')) {
        return $false
    }
    return -not ($File.Attributes -band [IO.FileAttributes]::ReparsePoint)
}

function Get-FailureDiagnosticCandidates {
    param([Parameter(Mandatory = $true)][string] $StateRoot)

    $candidates = [Collections.Generic.List[IO.FileInfo]]::new()
    foreach ($relativeRoot in @(
        'logs',
        'runtime\telemetry\incidents',
        'runtime\telemetry\qemu-dumps'
    )) {
        $root = Join-Path $StateRoot $relativeRoot
        if (Test-Path -LiteralPath $root -PathType Container) {
            foreach ($file in @(Get-ChildItem -LiteralPath $root -Recurse -Force -File)) {
                if (Test-FailureDiagnosticFileAllowed $file) { $candidates.Add($file) }
            }
        }
    }

    foreach ($name in @(
        'run-marker.json',
        'crash-context.json',
        'last-exit.json',
        'previous-exit.json',
        'termination-intent.json'
    )) {
        $path = Join-Path (Join-Path $StateRoot 'runtime') $name
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $file = Get-Item -LiteralPath $path -Force
            if (Test-FailureDiagnosticFileAllowed $file) { $candidates.Add($file) }
        }
    }

    $usersRoot = Join-Path $StateRoot 'state\users'
    if (Test-Path -LiteralPath $usersRoot -PathType Container) {
        foreach ($file in @(Get-ChildItem -LiteralPath $usersRoot -Recurse -Force -File)) {
            $relative = [IO.Path]::GetRelativePath($usersRoot, $file.FullName)
            if ($relative -match '(^|\\)instances\\[^\\]+\\diagnostics\\' -and
                (Test-FailureDiagnosticFileAllowed $file)) {
                $candidates.Add($file)
            }
        }
    }

    return @($candidates | Sort-Object FullName -Unique)
}

function Copy-FailureDiagnosticFile {
    param(
        [Parameter(Mandatory = $true)][IO.FileInfo] $Source,
        [Parameter(Mandatory = $true)][string] $Destination,
        [Parameter(Mandatory = $true)][long] $Limit
    )

    $sourceSize = [long]$Source.Length
    $copySize = [Math]::Min($sourceSize, $Limit)
    $truncated = $copySize -lt $sourceSize
    if ($truncated -and $Source.Extension.ToLowerInvariant() -notin @('.log', '.jsonl', '.txt')) {
        return $null
    }
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Destination) | Out-Null
    $input = [IO.File]::Open($Source.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    $output = $null
    try {
        if ($truncated) { $input.Seek(-$copySize, [IO.SeekOrigin]::End) | Out-Null }
        $output = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
        $buffer = [byte[]]::new(64KB)
        $remaining = $copySize
        while ($remaining -gt 0) {
            $read = $input.Read($buffer, 0, [int][Math]::Min($buffer.Length, $remaining))
            if ($read -le 0) { throw "Diagnostic source ended before its recorded size: $($Source.FullName)" }
            $output.Write($buffer, 0, $read)
            $remaining -= $read
        }
        $output.Flush($true)
    }
    finally {
        if ($null -ne $output) { $output.Dispose() }
        $input.Dispose()
    }
    return [pscustomobject]@{ size = $copySize; source_size = $sourceSize; truncated = $truncated }
}

function New-FailureDiagnosticArchive {
    param(
        [Parameter(Mandatory = $true)][string] $StateRoot,
        [Parameter(Mandatory = $true)][string] $DestinationRoot
    )

    $state = [IO.Path]::GetFullPath($StateRoot).TrimEnd('\')
    $destination = [IO.Path]::GetFullPath($DestinationRoot)
    if (-not (Test-Path -LiteralPath $state -PathType Container)) {
        throw 'Failure diagnostic state root is absent.'
    }
    if (Test-Path -LiteralPath $destination) {
        throw 'Refusing to overwrite an existing failure diagnostic archive.'
    }
    New-Item -ItemType Directory -Path $destination | Out-Null
    $records = [Collections.Generic.List[object]]::new()
    $total = 0L
    try {
        foreach ($source in @(Get-FailureDiagnosticCandidates $state)) {
            if ($records.Count -ge $script:FailureDiagnosticMaxFiles -or
                $total -ge $script:FailureDiagnosticMaxTotalBytes) { break }
            $remaining = $script:FailureDiagnosticMaxTotalBytes - $total
            $limit = [Math]::Min($script:FailureDiagnosticMaxFileBytes, $remaining)
            if ($limit -le 0) { break }
            $relative = [IO.Path]::GetRelativePath($state, $source.FullName)
            if ($relative.StartsWith('..') -or [IO.Path]::IsPathRooted($relative)) {
                throw "Diagnostic source escaped the state root: $($source.FullName)"
            }
            $archiveRelative = ('files/' + $relative.Replace('\', '/'))
            $target = Join-Path $destination $archiveRelative
            $copied = Copy-FailureDiagnosticFile $source $target $limit
            if ($null -eq $copied) { continue }
            $hash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
            $records.Add([ordered]@{
                path = $archiveRelative
                source_path = $relative.Replace('\', '/')
                size = [long]$copied.size
                source_size = [long]$copied.source_size
                sha256 = $hash
                truncated = [bool]$copied.truncated
            })
            $total += [long]$copied.size
        }
        [ordered]@{
            schema_version = 1
            created_utc = [DateTime]::UtcNow.ToString('o')
            bounds = [ordered]@{
                max_files = $script:FailureDiagnosticMaxFiles
                max_file_bytes = $script:FailureDiagnosticMaxFileBytes
                max_total_bytes = $script:FailureDiagnosticMaxTotalBytes
            }
            total_bytes = $total
            files = @($records)
        } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath `
            (Join-Path $destination 'manifest.json') -Encoding utf8NoBOM
    }
    catch {
        Remove-Item -LiteralPath $destination -Recurse -Force -ErrorAction SilentlyContinue
        throw
    }
}
