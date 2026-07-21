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
    if (-not $AllowUntrustedTestCertificate) {
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
        Status = if ($AllowUntrustedTestCertificate) { 'UntrustedTest' } else { 'Valid' }
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
            $certificatePath = "Cert:\CurrentUser\My\$($certificate.Thumbprint)"
            if (Test-Path -LiteralPath $certificatePath) {
                throw 'Refusing to replace a certificate already present in the signing user store'
            }
        }
        $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
        $imported = @(Import-PfxCertificate `
            -FilePath $pfx `
            -CertStoreLocation 'Cert:\CurrentUser\My' `
            -Password $securePassword `
            -Exportable:$false)
        foreach ($certificate in $imported) {
            $importedThumbprints.Add($certificate.Thumbprint)
        }
        if ($importedThumbprints -notcontains $signerThumbprint) {
            throw 'The imported certificate set did not contain the PFX signer'
        }
        $arguments = @('sign', '/fd', 'SHA256', '/s', 'My', '/sha1', $signerThumbprint)
        if (-not $SkipTimestamp) {
            if ([string]::IsNullOrWhiteSpace($TimestampUrl)) {
                throw 'TimestampUrl is required unless SkipTimestamp is explicitly set'
            }
            $arguments += @('/tr', $TimestampUrl, '/td', 'SHA256')
        }
        $arguments += $Path
        Invoke-Native $signTool $arguments "sign $Path" | Out-Host
        Assert-Signer $Path -RequireTimestamp:(-not $SkipTimestamp)
    }
    finally {
        foreach ($thumbprint in $importedThumbprints) {
            $certificatePath = "Cert:\CurrentUser\My\$thumbprint"
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
    $cdf = Join-Path $work 'LocalSandboxSeaWork.cdf'
    $catalog = Join-Path $work 'LocalSandboxSeaWork.cat'
    if ((Test-Path -LiteralPath $cdf) -or (Test-Path -LiteralPath $catalog)) {
        throw 'catalog work directory is not clean'
    }
    $lines = [Collections.Generic.List[string]]::new()
    $lines.Add('[CatalogHeader]')
    $lines.Add('Name=LocalSandboxSeaWork.cat')
    $lines.Add('ResultDir=.')
    $lines.Add('PublicVersion=0x00000001')
    $lines.Add('CatalogVersion=2')
    $lines.Add('EncodingType=0x00010001')
    $lines.Add('HashAlgorithms=SHA256')
    $lines.Add('')
    $lines.Add('[CatalogFiles]')
    for ($index = 0; $index -lt $files.Count; $index++) {
        $lines.Add(('<HASH>member{0:D5}={1}' -f $index, $files[$index].FullName))
    }
    [IO.File]::WriteAllText($cdf, ($lines -join "`r`n") + "`r`n", [Text.Encoding]::ASCII)
    $makeCat = Resolve-SdkTool 'makecat.exe'
    Push-Location $work
    try {
        Invoke-Native $makeCat @('-r', '-v', $cdf) 'generate bundle catalog'
    } finally {
        Pop-Location
    }
    $catalog = Resolve-ExistingFile $catalog 'generated catalog'
    Invoke-Sign $catalog | Out-Null
    Copy-Item -LiteralPath $catalog -Destination $catalogDestination
    Verify-BundleSignatures $root
}

function Verify-BundleSignatures {
    param([string]$Root)
    $root = Resolve-ExistingDirectory $Root 'BundleRoot'
    $catalog = Resolve-ExistingFile (Join-Path $root 'manifests\LocalSandboxSeaWork.cat') 'catalog'
    $service = Resolve-ExistingFile (Join-Path $root 'bin\localsandbox-seawork-service.exe') 'service binary'
    Assert-Signer $service -RequireTimestamp:(-not $SkipTimestamp) | Out-Null
    Assert-Signer $catalog -RequireTimestamp:(-not $SkipTimestamp) | Out-Null
    if ($AllowUntrustedTestCertificate) {
        return
    }
    $signTool = Resolve-SdkTool 'signtool.exe'
    foreach ($file in Get-BundleFiles $root -ExcludeCatalog) {
        Invoke-Native $signTool @('verify', '/v', '/pa', '/c', $catalog, $file.FullName) "verify catalog member $($file.Relative)"
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
