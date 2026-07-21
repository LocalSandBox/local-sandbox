[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Prepare', 'Commit', 'Verify', 'Abort', 'ImportLocal')]
    [string] $Mode,

    [ValidatePattern('^[a-z0-9][a-z0-9._-]{0,95}$')]
    [string] $StageName,

    [string] $SourceRoot,

    [string] $StateRoot = (Join-Path $env:ProgramData 'LocalSandbox\DevTest')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$markerName = '.local-sandbox-signing-assets.json'
$stageMarkerName = '.local-sandbox-signing-stage.json'
$owner = 'local-sandbox-agent-signing-flow'

function Resolve-StateRoot {
    $full = [IO.Path]::GetFullPath($StateRoot).TrimEnd('\', '/')
    if ((Split-Path -Leaf $full) -cne 'DevTest') {
        throw "StateRoot must end in the dedicated DevTest directory: $full"
    }
    $marker = Join-Path $full '.local-sandbox-agent-test-root.json'
    if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) {
        throw 'The Windows test state root is not owned by the agent test flow.'
    }
    $stateMarker = Get-Content -LiteralPath $marker -Raw | ConvertFrom-Json
    if ($stateMarker.schema_version -ne 1 -or
        $stateMarker.owner -ne 'local-sandbox-agent-test-flow' -or
        [string]::IsNullOrWhiteSpace([string]$stateMarker.current_user_sid)) {
        throw 'The Windows test state marker is invalid.'
    }
    return [pscustomobject]@{
        Path = $full
        CurrentUserSid = [Security.Principal.SecurityIdentifier]::new(
            [string]$stateMarker.current_user_sid
        )
    }
}

function Assert-NotReparsePoint {
    param([Parameter(Mandatory = $true)][string] $Path)

    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "Signing asset path must not be a reparse point: $Path"
    }
    return $item
}

function Set-ProtectedAcl {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier] $CurrentUserSid
    )

    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($sid in @(
        [Security.Principal.SecurityIdentifier]::new('S-1-5-18'),
        [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'),
        $CurrentUserSid
    )) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )) | Out-Null
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Set-ProtectedFileAcl {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier] $CurrentUserSid
    )

    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @(
        [Security.Principal.SecurityIdentifier]::new('S-1-5-18'),
        [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'),
        $CurrentUserSid
    )) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow
        )) | Out-Null
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Assert-ProtectedAcl {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier] $CurrentUserSid
    )

    $acl = Get-Acl -LiteralPath $Path
    if (-not $acl.AreAccessRulesProtected) {
        throw "Signing asset directory inherits access rules: $Path"
    }
    $expected = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544', $CurrentUserSid.Value)) {
        $expected.Add($sid) | Out-Null
    }
    $observed = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($rule in $acl.GetAccessRules(
        $true,
        $true,
        [Security.Principal.SecurityIdentifier]
    )) {
        $sid = $rule.IdentityReference.Value
        if (-not $expected.Contains($sid) -or
            $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne
                [Security.AccessControl.FileSystemRights]::FullControl) {
            throw "Signing asset directory has an unexpected access rule: $Path"
        }
        $observed.Add($sid) | Out-Null
    }
    foreach ($sid in $expected) {
        if (-not $observed.Contains($sid)) {
            throw "Signing asset directory is missing a required access rule: $Path"
        }
    }
}

function Get-ProtectedAclOwnerSid {
    param([Parameter(Mandatory = $true)][string] $Path)

    $acl = Get-Acl -LiteralPath $Path
    if (-not $acl.AreAccessRulesProtected) {
        throw "Signing asset directory inherits access rules: $Path"
    }
    $privileged = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $privileged.Add('S-1-5-18') | Out-Null
    $privileged.Add('S-1-5-32-544') | Out-Null
    $owners = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($rule in $acl.GetAccessRules(
        $true,
        $true,
        [Security.Principal.SecurityIdentifier]
    )) {
        $sid = $rule.IdentityReference.Value
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne
                [Security.AccessControl.FileSystemRights]::FullControl) {
            throw "Signing asset directory has an unexpected access rule: $Path"
        }
        if (-not $privileged.Contains($sid)) {
            $owners.Add($sid) | Out-Null
        }
    }
    if ($owners.Count -ne 1) {
        throw "Signing asset directory must have exactly one designated owner SID: $Path"
    }
    $ownerSid = [Security.Principal.SecurityIdentifier]::new(@($owners)[0])
    Assert-ProtectedAcl -Path $Path -CurrentUserSid $ownerSid
    return $ownerSid
}

function Write-Marker {
    param([Parameter(Mandatory = $true)][string] $Path, [Parameter(Mandatory = $true)][string] $Kind)

    [ordered]@{
        schema_version = 1
        owner = $owner
        kind = $Kind
        updated_utc = [DateTime]::UtcNow.ToString('o')
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $Path -Encoding utf8NoBOM
}

function Assert-Marker {
    param([Parameter(Mandatory = $true)][string] $Path, [Parameter(Mandatory = $true)][string] $Kind)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Signing asset ownership marker is missing: $Path"
    }
    $marker = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ($marker.schema_version -ne 1 -or $marker.owner -ne $owner -or $marker.kind -ne $Kind) {
        throw "Signing asset ownership marker is invalid: $Path"
    }
}

function Get-PublicCertificateInfo {
    param(
        [Parameter(Mandatory = $true)][string] $Directory,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier] $CurrentUserSid
    )

    $pfx = Join-Path $Directory 'SeaWork-CodeSign.pfx'
    $passwordFile = Join-Path $Directory 'win_csc_key_password.txt'
    foreach ($path in @($pfx, $passwordFile)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw 'Signing asset set is incomplete.'
        }
        $item = Assert-NotReparsePoint -Path $path
        if ($item.Length -le 0) {
            throw 'Signing asset files must not be empty.'
        }
        Assert-ProtectedAcl -Path $path -CurrentUserSid $CurrentUserSid
    }
    if ((Get-Item -LiteralPath $pfx).Length -gt 16MB -or
        (Get-Item -LiteralPath $passwordFile).Length -gt 16KB) {
        throw 'Signing asset file size is outside the supported bound.'
    }
    $password = (Get-Content -LiteralPath $passwordFile -Raw).TrimEnd("`r", "`n")
    if ([string]::IsNullOrEmpty($password)) {
        throw 'The signing password file is empty.'
    }
    $certificate = $null
    try {
        $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new(
            $pfx,
            $password,
            [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
        )
        if (-not $certificate.HasPrivateKey) {
            throw 'The signing PFX does not contain a private key.'
        }
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            $thumbprint = ([Convert]::ToHexString(
                $sha.ComputeHash($certificate.RawData)
            )).ToLowerInvariant()
        }
        finally {
            $sha.Dispose()
        }
        return [ordered]@{
            schema_version = 1
            status = 'ready'
            subject = $certificate.Subject
            sha256_thumbprint = $thumbprint
            pfx_present = $true
            password_file_present = $true
            acl_status = 'protected'
        }
    }
    finally {
        if ($null -ne $certificate) {
            $certificate.Dispose()
        }
        $password = $null
    }
}

$state = Resolve-StateRoot
$assetsRoot = Join-Path $state.Path 'assets'
Assert-NotReparsePoint -Path $assetsRoot | Out-Null
$signingRoot = Join-Path $assetsRoot 'signing'
$signingMarker = Join-Path $signingRoot $markerName

if ($Mode -in @('Prepare', 'Commit', 'Abort', 'ImportLocal') -and
    [string]::IsNullOrWhiteSpace($StageName)) {
    throw 'StageName is required for Prepare, Commit, Abort, and ImportLocal.'
}
$stageRoot = if ([string]::IsNullOrWhiteSpace($StageName)) {
    $null
}
else {
    Join-Path $assetsRoot ".signing-stage-$StageName"
}
$stageMarker = if ($null -eq $stageRoot) { $null } else { Join-Path $stageRoot $stageMarkerName }

switch ($Mode) {
    'Prepare' {
        if (Test-Path -LiteralPath $stageRoot) {
            throw 'The signing staging directory already exists.'
        }
        if (Test-Path -LiteralPath $signingRoot) {
            Assert-NotReparsePoint -Path $signingRoot | Out-Null
            Assert-Marker -Path $signingMarker -Kind 'installed'
            Get-ProtectedAclOwnerSid -Path $signingRoot | Out-Null
            throw 'Protected signing assets are already provisioned; use Verify instead of replacing them.'
        }
        New-Item -ItemType Directory -Path $stageRoot | Out-Null
        Set-ProtectedAcl -Path $stageRoot -CurrentUserSid $state.CurrentUserSid
        Write-Marker -Path $stageMarker -Kind 'stage'
        [ordered]@{ status = 'prepared'; acl_status = 'protected' } |
            ConvertTo-Json -Compress
    }
    'Commit' {
        Assert-NotReparsePoint -Path $stageRoot | Out-Null
        Assert-Marker -Path $stageMarker -Kind 'stage'
        Assert-ProtectedAcl -Path $stageRoot -CurrentUserSid $state.CurrentUserSid
        $entries = @(Get-ChildItem -LiteralPath $stageRoot -Force)
        $expectedNames = @($stageMarkerName, 'SeaWork-CodeSign.pfx', 'win_csc_key_password.txt')
        if ($entries.Count -ne $expectedNames.Count -or
            @($entries | Where-Object { $expectedNames -notcontains $_.Name }).Count -ne 0) {
            throw 'The signing staging directory contains an unexpected entry.'
        }
        foreach ($name in @('SeaWork-CodeSign.pfx', 'win_csc_key_password.txt')) {
            Set-ProtectedFileAcl -Path (Join-Path $stageRoot $name) -CurrentUserSid $state.CurrentUserSid
        }
        $publicInfo = Get-PublicCertificateInfo -Directory $stageRoot -CurrentUserSid $state.CurrentUserSid
        Remove-Item -LiteralPath $stageMarker -Force
        Write-Marker -Path (Join-Path $stageRoot $markerName) -Kind 'installed'
        if (Test-Path -LiteralPath $signingRoot) {
            throw 'Refusing to overwrite the existing signing asset destination.'
        }
        try {
            Move-Item -LiteralPath $stageRoot -Destination $signingRoot
            Assert-ProtectedAcl -Path $signingRoot -CurrentUserSid $state.CurrentUserSid
        }
        catch {
            if (Test-Path -LiteralPath $signingRoot) {
                Move-Item -LiteralPath $signingRoot -Destination $stageRoot
                Remove-Item -LiteralPath (Join-Path $stageRoot $markerName) -Force
                Write-Marker -Path $stageMarker -Kind 'stage'
            }
            throw
        }
        $publicInfo | ConvertTo-Json -Compress
    }
    'Verify' {
        if (-not (Test-Path -LiteralPath $signingRoot -PathType Container)) {
            throw 'Protected signing assets have not been provisioned.'
        }
        Assert-NotReparsePoint -Path $signingRoot | Out-Null
        Assert-Marker -Path $signingMarker -Kind 'installed'
        $ownerSid = Get-ProtectedAclOwnerSid -Path $signingRoot
        Get-PublicCertificateInfo -Directory $signingRoot -CurrentUserSid $ownerSid |
            ConvertTo-Json -Compress
    }
    'Abort' {
        if (Test-Path -LiteralPath $stageRoot) {
            Assert-NotReparsePoint -Path $stageRoot | Out-Null
            Assert-Marker -Path $stageMarker -Kind 'stage'
            Assert-ProtectedAcl -Path $stageRoot -CurrentUserSid $state.CurrentUserSid
            Remove-Item -LiteralPath $stageRoot -Recurse -Force
        }
        [ordered]@{ status = 'aborted' } | ConvertTo-Json -Compress
    }
    'ImportLocal' {
        if ([string]::IsNullOrWhiteSpace($SourceRoot)) {
            throw 'SourceRoot is required for ImportLocal.'
        }
        $source = [IO.Path]::GetFullPath($SourceRoot).TrimEnd('\', '/')
        if (-not (Test-Path -LiteralPath $source -PathType Container)) {
            throw 'The Windows-local signing source directory does not exist.'
        }
        Assert-NotReparsePoint -Path $source | Out-Null
        $sourceFiles = @(
            Join-Path $source 'SeaWork-CodeSign.pfx'
            Join-Path $source 'win_csc_key_password.txt'
        )
        foreach ($path in $sourceFiles) {
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
                throw 'The Windows-local signing asset set is incomplete.'
            }
            $item = Assert-NotReparsePoint -Path $path
            if ($item.Length -le 0) {
                throw 'A Windows-local signing asset is empty.'
            }
        }
        & $PSCommandPath -Mode Prepare -StageName $StageName -StateRoot $state.Path
        try {
            Copy-Item -LiteralPath $sourceFiles[0] -Destination (Join-Path $stageRoot 'SeaWork-CodeSign.pfx')
            Copy-Item -LiteralPath $sourceFiles[1] -Destination (Join-Path $stageRoot 'win_csc_key_password.txt')
            & $PSCommandPath -Mode Commit -StageName $StageName -StateRoot $state.Path
        }
        catch {
            & $PSCommandPath -Mode Abort -StageName $StageName -StateRoot $state.Path
            throw
        }
    }
}
