[CmdletBinding()]
param(
    [string] $EvidencePath = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Windows SMB ACL reproduction requires an elevated process.'
    }
}

function Test-ExplicitSidAce {
    param([string] $Path, [string] $Sid)
    $acl = Get-Acl -LiteralPath $Path
    foreach ($rule in $acl.Access) {
        if ($rule.IsInherited) { continue }
        try {
            $ruleSid = $rule.IdentityReference.
                Translate([Security.Principal.SecurityIdentifier]).Value
            if ($ruleSid -ceq $Sid) { return $true }
        }
        catch [Security.Principal.IdentityNotMappedException] {
            if ($rule.IdentityReference.Value -ceq $Sid) { return $true }
        }
    }
    return $false
}

function Remove-ExactSidRules {
    param([string] $Path, [Security.Principal.SecurityIdentifier] $Sid)
    $acl = Get-Acl -LiteralPath $Path
    $acl.PurgeAccessRules($Sid)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

Assert-Administrator

if ($null -eq ('LocalSandbox.SmbAclReproduction' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace LocalSandbox
{
public static class SmbAclReproduction
{
    private const int LOGON32_LOGON_INTERACTIVE = 2;
    private const int LOGON32_PROVIDER_DEFAULT = 0;

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool LogonUser(
        string username,
        string domain,
        string password,
        int logonType,
        int logonProvider,
        out SafeAccessTokenHandle token);

    public static bool CanRead(string username, string password, string path)
    {
        SafeAccessTokenHandle token;
        if (!LogonUser(
            username,
            Environment.MachineName,
            password,
            LOGON32_LOGON_INTERACTIVE,
            LOGON32_PROVIDER_DEFAULT,
            out token))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "LogonUser failed");
        }
        using (token)
        {
            try
            {
                return WindowsIdentity.RunImpersonated(
                    token,
                    () => File.ReadAllText(path) == "protected-skill-input");
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }
        }
    }
}
}
'@
}

$nonce = [Convert]::ToHexString(
    [Security.Cryptography.RandomNumberGenerator]::GetBytes(4)
).ToLowerInvariant()
$userName = "lsb_repro_$nonce"
$password = "R!$([guid]::NewGuid().ToString('N'))a9"
$root = Join-Path $env:TEMP "lsb-smb-acl-repro-$nonce"
$protected = Join-Path $root 'mis-it-center'
$skill = Join-Path $protected 'SKILL.md'
$userCreated = $false
$sid = $null
$evidence = [ordered]@{
    schema_version = 1
    protected_acl_boundary_reproduced = $false
    root_only_grant_read_denied = $false
    orphan_sid_bug_reproduced = $false
    account_deleted_before_acl_cleanup = $false
    name_lookup_unavailable = $false
    orphan_sid_ace_observed = $false
    exact_sid_cleanup_succeeded = $false
    residual_user = $true
}

try {
    New-Item -ItemType Directory -Path $protected -Force | Out-Null
    Set-Content -LiteralPath $skill -Value 'protected-skill-input' -NoNewline

    $protectedAcl = Get-Acl -LiteralPath $protected
    $protectedAcl.SetAccessRuleProtection($true, $true)
    Set-Acl -LiteralPath $protected -AclObject $protectedAcl
    if (-not (Get-Acl -LiteralPath $protected).AreAccessRulesProtected) {
        throw 'Failed to create the protected ACL boundary.'
    }

    $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
    New-LocalUser `
        -Name $userName `
        -Password $securePassword `
        -AccountNeverExpires `
        -PasswordNeverExpires `
        -UserMayNotChangePassword | Out-Null
    $userCreated = $true
    $principal = "$env:COMPUTERNAME\$userName"
    $sid = ([Security.Principal.NTAccount]::new($principal)).
        Translate([Security.Principal.SecurityIdentifier])
    $sidValue = [string]$sid.Value

    # Reproduce the old implementation: one inheritable grant at the mount root.
    # Because the child DACL is protected, the generated user receives no child/file ACE.
    $rootAcl = Get-Acl -LiteralPath $root
    $rootRule = [Security.AccessControl.FileSystemAccessRule]::new(
        $sid,
        [Security.AccessControl.FileSystemRights]::ReadAndExecute,
        [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow
    )
    [void]$rootAcl.AddAccessRule($rootRule)
    Set-Acl -LiteralPath $root -AclObject $rootAcl

    $canRead = [LocalSandbox.SmbAclReproduction]::CanRead(
        $userName,
        $password,
        $skill
    )
    $evidence.protected_acl_boundary_reproduced = $true
    $evidence.root_only_grant_read_denied = -not $canRead
    if ($canRead) {
        throw 'Root-only inheritable grant unexpectedly crossed the protected ACL boundary.'
    }

    # Put an explicit generated-user ACE below the boundary, then remove the account
    # before ACL cleanup. The ACE is now rendered only as an unresolved SID.
    $fileAcl = Get-Acl -LiteralPath $skill
    $fileRule = [Security.AccessControl.FileSystemAccessRule]::new(
        $sid,
        [Security.AccessControl.FileSystemRights]::ReadAndExecute,
        [Security.AccessControl.AccessControlType]::Allow
    )
    [void]$fileAcl.AddAccessRule($fileRule)
    Set-Acl -LiteralPath $skill -AclObject $fileAcl
    if (-not (Test-ExplicitSidAce $skill $sidValue)) {
        throw 'Failed to create the disposable SID ACE.'
    }

    Remove-LocalUser -Name $userName
    $userCreated = $false
    $evidence.account_deleted_before_acl_cleanup = $true

    try {
        [void]([Security.Principal.NTAccount]::new($principal)).
            Translate([Security.Principal.SecurityIdentifier])
    }
    catch [Security.Principal.IdentityNotMappedException] {
        $evidence.name_lookup_unavailable = $true
    }
    $evidence.orphan_sid_ace_observed = Test-ExplicitSidAce $skill $sidValue
    $evidence.orphan_sid_bug_reproduced =
        $evidence.name_lookup_unavailable -and $evidence.orphan_sid_ace_observed
    if (-not $evidence.orphan_sid_bug_reproduced) {
        throw 'Failed to reproduce the unresolved SID ACE after account deletion.'
    }

    Remove-ExactSidRules $skill $sid
    Remove-ExactSidRules $root $sid
    $evidence.exact_sid_cleanup_succeeded =
        -not (Test-ExplicitSidAce $skill $sidValue) -and
        -not (Test-ExplicitSidAce $root $sidValue)
    if (-not $evidence.exact_sid_cleanup_succeeded) {
        throw 'Exact SID cleanup did not remove the disposable reproduction ACEs.'
    }
}
finally {
    if ($userCreated) {
        Remove-LocalUser -Name $userName -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    }
    $evidence.residual_user =
        $null -ne (Get-LocalUser -Name $userName -ErrorAction SilentlyContinue)
    if (-not [string]::IsNullOrWhiteSpace($EvidencePath)) {
        $parent = Split-Path -Parent $EvidencePath
        if (-not [string]::IsNullOrWhiteSpace($parent)) {
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
        }
        $evidence | ConvertTo-Json -Depth 4 |
            Set-Content -LiteralPath $EvidencePath -Encoding utf8NoBOM
    }
}

$evidence | ConvertTo-Json -Depth 4
if (-not $evidence.protected_acl_boundary_reproduced -or
    -not $evidence.root_only_grant_read_denied -or
    -not $evidence.orphan_sid_bug_reproduced -or
    -not $evidence.exact_sid_cleanup_succeeded -or
    $evidence.residual_user) {
    throw 'Windows SMB ACL bug reproduction evidence is incomplete.'
}
