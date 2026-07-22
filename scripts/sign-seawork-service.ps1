[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('SignPe', 'SignTestNode', 'Catalog', 'Verify')]
    [string]$Mode,

    [string]$ServiceBinary,
    [string]$ClientBinary,
    [string]$BundleRoot,
    [string]$PfxPath,
    [string]$PasswordFile,
    [string]$WorkDirectory,
    [string]$SdkBin,
    [string]$TimestampUrl = 'http://timestamp.digicert.com',
    [string]$ExpectedPublisherSubject,
    [string]$ExpectedPublisherSha256,
    [switch]$AllowUntrustedTestCertificate,
    [switch]$SkipTrustVerification,
    [switch]$UseLocalMachineStore,
    [switch]$SkipTimestamp
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:MaxBundleFiles = 10000
$script:MaxBundleBytes = 16GB

if ($SkipTimestamp -and -not $AllowUntrustedTestCertificate) {
    throw 'SkipTimestamp is allowed only with AllowUntrustedTestCertificate'
}

function Resolve-ExistingFile {
    param([string]$Path, [string]$Label)
    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw "$Label is required"
    }
    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction Stop
    if (-not (Test-Path -LiteralPath $resolved.Path -PathType Leaf)) {
        throw "$Label must be a file"
    }
    return $resolved.Path
}

function Resolve-ExistingDirectory {
    param([string]$Path, [string]$Label)
    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw "$Label is required"
    }
    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction Stop
    if (-not (Test-Path -LiteralPath $resolved.Path -PathType Container)) {
        throw "$Label must be a directory"
    }
    if ((Get-Item -LiteralPath $resolved.Path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "$Label must not be a reparse point"
    }
    return $resolved.Path.TrimEnd('\')
}

function Resolve-SdkTool {
    param([string]$Name)
    if (-not [string]::IsNullOrWhiteSpace($SdkBin)) {
        return Resolve-ExistingFile (Join-Path $SdkBin $Name) $Name
    }
    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        return $command.Source
    }
    $kit = 'C:\Program Files (x86)\Windows Kits\10\bin'
    if (-not (Test-Path -LiteralPath $kit -PathType Container)) {
        throw "$Name was not found; install the Windows SDK signing tools"
    }
    $candidate = Get-ChildItem -LiteralPath $kit -Directory |
        Where-Object { $_.Name -match '^\d+(?:\.\d+){1,3}$' } |
        Sort-Object { [version]$_.Name } -Descending |
        ForEach-Object { Join-Path $_.FullName "x64\$Name" } |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
        Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($candidate)) {
        throw "$Name was not found in an x64 Windows SDK bin directory"
    }
    return $candidate
}

function Invoke-Native {
    param([string]$Executable, [string[]]$Arguments, [string]$Action)
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Action failed with exit code $LASTEXITCODE"
    }
}

function Invoke-SignTool {
    param([string]$Executable, [string[]]$Arguments, [string]$Action)
    $attempts = if ($SkipTimestamp) { 1 } else { 3 }
    for ($attempt = 1; $attempt -le $attempts; $attempt++) {
        & $Executable @Arguments
        if ($LASTEXITCODE -eq 0) {
            return
        }
        $exitCode = $LASTEXITCODE
        if ($attempt -lt $attempts) {
            Write-Warning "$Action failed on attempt $attempt of $attempts; retrying timestamped signing."
            Start-Sleep -Seconds 5
            continue
        }
        throw "$Action failed after $attempts attempts with exit code $exitCode"
    }
}

function Get-PfxPassword {
    $path = Resolve-ExistingFile $PasswordFile 'PasswordFile'
    $password = (Get-Content -LiteralPath $path -Raw).TrimEnd("`r", "`n")
    if ([string]::IsNullOrEmpty($password)) {
        throw 'PFX password file is empty'
    }
    return $password
}

function Get-CertificateSha256 {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([Convert]::ToHexString($sha256.ComputeHash($Certificate.RawData))).ToLowerInvariant()
    } finally {
        $sha256.Dispose()
    }
}

function Assert-Signer {
    param([string]$Path, [switch]$RequireTimestamp)
    try {
        $legacyCertificate = [Security.Cryptography.X509Certificates.X509Certificate]::CreateFromSignedFile($Path)
        $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($legacyCertificate)
    } catch {
        throw "file has no Authenticode signer: $Path"
    }
    $subject = $certificate.Subject
    $sha256 = Get-CertificateSha256 $certificate
    if (-not [string]::IsNullOrWhiteSpace($ExpectedPublisherSubject) -and
        $subject -cne $ExpectedPublisherSubject) {
        throw "signature publisher subject mismatch for $Path"
    }
    if (-not [string]::IsNullOrWhiteSpace($ExpectedPublisherSha256)) {
        $expected = $ExpectedPublisherSha256.Replace(':', '').Replace(' ', '').ToLowerInvariant()
        if ($expected.Length -ne 64 -or $expected -notmatch '^[0-9a-f]{64}$' -or $sha256 -cne $expected) {
            throw "signature publisher SHA-256 mismatch for $Path"
        }
    }
    if (-not $AllowUntrustedTestCertificate -and -not $SkipTrustVerification) {
        $arguments = @('verify', '/v', '/pa', '/all')
        if ($RequireTimestamp) {
            $arguments += '/tw'
        }
        $arguments += $Path
        Invoke-Native (Resolve-SdkTool 'signtool.exe') $arguments "verify signature $Path"
    }
    [pscustomobject]@{
        Subject = $subject
        Sha256 = $sha256
        Status = if ($AllowUntrustedTestCertificate) {
            'UntrustedTest'
        } elseif ($SkipTrustVerification) {
            'TrustNotVerified'
        } else {
            'Valid'
        }
        TimestampRequired = [bool]$RequireTimestamp
    }
}

function Invoke-Sign {
    param([string]$Path)
    $signTool = Resolve-SdkTool 'signtool.exe'
    $pfx = Resolve-ExistingFile $PfxPath 'PfxPath'
    $password = Get-PfxPassword
    $securePassword = $null
    $collection = @()
    $arguments = @()
    $importedThumbprints = [Collections.Generic.List[string]]::new()
    $storeLocation = if ($UseLocalMachineStore) {
        'Cert:\LocalMachine\My'
    }
    else {
        'Cert:\CurrentUser\My'
    }
    try {
        $collection = [Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
        $collection.Import(
            $pfx,
            $password,
            [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
        )
        $signers = @($collection | Where-Object { $_.HasPrivateKey })
        if ($signers.Count -ne 1) {
            throw 'PFX must contain exactly one certificate with a private key'
        }
        $signerThumbprint = $signers[0].Thumbprint
        if ($signerThumbprint -notmatch '^[0-9A-Fa-f]{40}$') {
            throw 'PFX signer has an invalid SHA-1 certificate identifier'
        }
        foreach ($certificate in $collection) {
            $certificatePath = "$storeLocation\$($certificate.Thumbprint)"
            if (Test-Path -LiteralPath $certificatePath) {
                throw 'Refusing to replace a certificate already present in the signing user store'
            }
        }
        $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
        $imported = @(Import-PfxCertificate `
            -FilePath $pfx `
            -CertStoreLocation $storeLocation `
            -Password $securePassword `
            -Exportable:$false)
        foreach ($certificate in $imported) {
            $importedThumbprints.Add($certificate.Thumbprint)
        }
        if ($importedThumbprints -notcontains $signerThumbprint) {
            throw 'The imported certificate set did not contain the PFX signer'
        }
        $arguments = @('sign', '/fd', 'SHA256', '/s', 'My', '/sha1', $signerThumbprint)
        if ($UseLocalMachineStore) {
            $arguments = @('sign', '/fd', 'SHA256', '/sm', '/s', 'My', '/sha1', $signerThumbprint)
        }
        if (-not $SkipTimestamp) {
            if ([string]::IsNullOrWhiteSpace($TimestampUrl)) {
                throw 'TimestampUrl is required unless SkipTimestamp is explicitly set'
            }
            $arguments += @('/tr', $TimestampUrl, '/td', 'SHA256')
        }
        $arguments += $Path
        Invoke-SignTool $signTool $arguments "sign $Path" | Out-Host
        Assert-Signer $Path -RequireTimestamp:(-not $SkipTimestamp)
    }
    finally {
        foreach ($thumbprint in $importedThumbprints) {
            $certificatePath = "$storeLocation\$thumbprint"
            if (Test-Path -LiteralPath $certificatePath) {
                Remove-Item -Path $certificatePath -DeleteKey -Force
            }
        }
        foreach ($certificate in $collection) {
            $certificate.Dispose()
        }
        $securePassword = $null
        $password = $null
        $arguments = $null
    }
}

function Get-BundleFiles {
    param([string]$Root, [switch]$ExcludeCatalog)
    $rootPrefix = $Root.TrimEnd('\') + '\'
    $allEntries = Get-ChildItem -LiteralPath $Root -Force -Recurse
    if ($allEntries | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }) {
        throw 'bundle contains a reparse entry'
    }
    $files = @($allEntries | Where-Object { -not $_.PSIsContainer })
    if ($ExcludeCatalog) {
        $files = @($files | Where-Object { $_.FullName -cne (Join-Path $Root 'manifests\LocalSandboxSeaWork.cat') })
    }
    if ($files.Count -eq 0 -or $files.Count -gt $script:MaxBundleFiles) {
        throw 'bundle file count is outside the supported range'
    }
    $totalBytes = 0L
    $folded = @{}
    $result = foreach ($file in $files) {
        if (-not $file.FullName.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'bundle file escaped the bundle root'
        }
        $relative = $file.FullName.Substring($rootPrefix.Length).Replace('\', '/')
        $unsafeSegments = @($relative.Split('/') | Where-Object { $_ -eq '' -or $_ -eq '.' -or $_ -eq '..' })
        if ($relative.StartsWith('/') -or $relative.Contains(':') -or $unsafeSegments.Count -ne 0) {
            throw "unsafe bundle path: $relative"
        }
        $key = $relative.ToLowerInvariant()
        if ($folded.ContainsKey($key)) {
            throw "case-insensitive bundle path collision: $relative"
        }
        $folded[$key] = $true
        if ($file.Length -gt ([long]::MaxValue - $totalBytes)) {
            throw 'bundle expanded size overflow'
        }
        $totalBytes += $file.Length
        if ($totalBytes -gt $script:MaxBundleBytes) {
            throw 'bundle expanded size exceeds the supported limit'
        }
        [pscustomobject]@{ FullName = $file.FullName; Relative = $relative }
    }
    return @($result | Sort-Object Relative)
}

function Get-TemporaryCatalogDrive {
    $driveLetter = @('Z', 'Y', 'X', 'W', 'V') |
        Where-Object { -not (Test-Path -LiteralPath "${_}:\") } |
        Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($driveLetter)) {
        throw 'no temporary drive letter is available for bounded catalog paths'
    }
    return "${driveLetter}:"
}

function Assert-FileCatalogClosure {
    param(
        [string]$Root,
        [string]$Catalog,
        [object[]]$ExpectedFiles,
        [switch]$CatalogInsideRoot
    )

    $arguments = @{
        Path = $Root
        CatalogFilePath = $Catalog
        Detailed = $true
        ErrorAction = 'Stop'
    }
    if ($CatalogInsideRoot) {
        $arguments.FilesToSkip = 'manifests\LocalSandboxSeaWork.cat'
    }
    $validation = Test-FileCatalog @arguments
    if ($validation.Status.ToString() -cne 'Valid') {
        throw "file catalog validation failed with status $($validation.Status)"
    }
    if ($validation.HashAlgorithm.ToString() -cne 'SHA256') {
        throw "file catalog uses unexpected hash algorithm $($validation.HashAlgorithm)"
    }
    $expected = @($ExpectedFiles | ForEach-Object { $_.Relative.Replace('\', '/') } | Sort-Object)
    $observed = @($validation.PathItems.Keys | ForEach-Object {
        ([string]$_).Replace('\', '/')
    } | Sort-Object)
    $differences = @(Compare-Object -ReferenceObject $expected -DifferenceObject $observed -CaseSensitive)
    if ($differences.Count -ne 0 -or $observed.Count -ne $expected.Count) {
        throw 'file catalog membership does not match the closed bundle file set'
    }
}

function New-BundleCatalog {
    $root = Resolve-ExistingDirectory $BundleRoot 'BundleRoot'
    if ((Split-Path -Leaf $root) -cne 'LocalSandbox') {
        throw 'BundleRoot must name the LocalSandbox directory'
    }
    $work = Resolve-ExistingDirectory $WorkDirectory 'WorkDirectory'
    $catalogDestination = Join-Path $root 'manifests\LocalSandboxSeaWork.cat'
    if (Test-Path -LiteralPath $catalogDestination) {
        throw 'bundle already contains a catalog'
    }
    $files = Get-BundleFiles $root -ExcludeCatalog
    $catalog = Join-Path $work 'LocalSandboxSeaWork.cat'
    if (Test-Path -LiteralPath $catalog) {
        throw 'catalog work directory is not clean'
    }
    $drive = Get-TemporaryCatalogDrive
    Invoke-Native subst.exe @($drive, $root) 'map temporary bundle catalog drive'
    try {
        $mappedRoot = "$drive\"
        if (-not (Test-Path -LiteralPath $mappedRoot -PathType Container)) {
            throw 'temporary bundle catalog drive did not resolve'
        }
        New-FileCatalog `
            -Path $mappedRoot `
            -CatalogFilePath $catalog `
            -CatalogVersion 2.0 `
            -ErrorAction Stop | Out-Null
        $catalog = Resolve-ExistingFile $catalog 'generated catalog'
        Invoke-Sign $catalog | Out-Null
        Assert-FileCatalogClosure -Root $mappedRoot -Catalog $catalog -ExpectedFiles $files
        Copy-Item -LiteralPath $catalog -Destination $catalogDestination
        Verify-BundleSignatures $mappedRoot
    }
    finally {
        Invoke-Native subst.exe @($drive, '/d') 'remove temporary bundle catalog drive'
    }
}

function Verify-BundleSignatures {
    param([string]$Root)
    $root = Resolve-ExistingDirectory $Root 'BundleRoot'
    $mapped = $false
    $drive = $null
    if ($root.Length -gt 3) {
        $drive = Get-TemporaryCatalogDrive
        Invoke-Native subst.exe @($drive, $root) 'map temporary bundle verification drive'
        $root = "$drive\"
        $mapped = $true
    }
    try {
        $catalog = Resolve-ExistingFile (Join-Path $root 'manifests\LocalSandboxSeaWork.cat') 'catalog'
        $service = Resolve-ExistingFile (Join-Path $root 'bin\localsandbox-seawork-service.exe') 'service binary'
        $files = Get-BundleFiles $root -ExcludeCatalog
        Assert-Signer $service -RequireTimestamp:(-not $SkipTimestamp) | Out-Null
        Assert-Signer $catalog -RequireTimestamp:(-not $SkipTimestamp) | Out-Null
        Assert-FileCatalogClosure `
            -Root $root `
            -Catalog $catalog `
            -ExpectedFiles $files `
            -CatalogInsideRoot
        if (-not $AllowUntrustedTestCertificate -and -not $SkipTrustVerification) {
            $signTool = Resolve-SdkTool 'signtool.exe'
            $zeroMemberRelative = 'tools/qemu/lib/gdk-pixbuf-2.0/2.10.0/loaders.cache'
            $zeroMember = @($files | Where-Object { $_.Relative -ceq $zeroMemberRelative })
            if ($zeroMember.Count -ne 1) {
                throw "expected exactly one zero-byte catalog member at $zeroMemberRelative"
            }
            if ((Get-Item -LiteralPath $zeroMember[0].FullName -Force).Length -ne 0) {
                throw 'representative QEMU cache file is no longer zero bytes'
            }
            $representativeMembers = @(
                'bin/localsandbox-seawork-service.exe'
                'manifests/bundle.json'
                'tools/qemu/qemu-system-x86_64.exe'
            )
            foreach ($relative in $representativeMembers) {
                $file = @($files | Where-Object { $_.Relative -ceq $relative })
                if ($file.Count -ne 1) {
                    throw "expected exactly one representative catalog member at $relative"
                }
                Invoke-Native $signTool @(
                    'verify', '/v', '/pa', '/c', $catalog, $file[0].FullName
                ) "verify representative catalog member $relative"
            }
        }
    }
    finally {
        if ($mapped) {
            Invoke-Native subst.exe @($drive, '/d') 'remove temporary bundle verification drive'
        }
    }
}

switch ($Mode) {
    'SignPe' {
        $service = Resolve-ExistingFile $ServiceBinary 'ServiceBinary'
        if ((Split-Path -Leaf $service) -cne 'localsandbox-seawork-service.exe') {
            throw 'ServiceBinary has an unexpected filename'
        }
        $result = Invoke-Sign $service
        $result | ConvertTo-Json -Compress
    }
    'SignTestNode' {
        $client = Resolve-ExistingFile $ClientBinary 'ClientBinary'
        if ((Split-Path -Leaf $client) -cne 'node.exe') {
            throw 'ClientBinary must name node.exe'
        }
        $programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
        $allowedRoot = Join-Path $programFiles 'SeaWork\LocalSandboxTestHarness'
        $allowedPrefix = [IO.Path]::GetFullPath($allowedRoot).TrimEnd('\') + '\'
        if (-not [IO.Path]::GetFullPath($client).StartsWith(
            $allowedPrefix,
            [StringComparison]::OrdinalIgnoreCase
        )) {
            throw 'ClientBinary must be below the protected LocalSandbox test-harness root'
        }
        $clientItem = Get-Item -LiteralPath $client -Force
        if ($clientItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'ClientBinary must not be a reparse point'
        }
        $cursor = $clientItem.Directory
        while ($true) {
            if ($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw 'ClientBinary and its test-harness ancestors must not be reparse points'
            }
            if ($cursor.FullName.Equals(
                $allowedRoot,
                [StringComparison]::OrdinalIgnoreCase
            )) {
                break
            }
            $cursor = $cursor.Parent
            if ($null -eq $cursor) {
                throw 'ClientBinary did not resolve below the test-harness root'
            }
        }
        $result = Invoke-Sign $client
        $result | ConvertTo-Json -Compress
    }
    'Catalog' {
        New-BundleCatalog
    }
    'Verify' {
        Verify-BundleSignatures $BundleRoot
    }
}
