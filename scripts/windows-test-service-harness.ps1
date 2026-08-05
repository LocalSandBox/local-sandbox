[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('InstallAndSmoke', 'InstallOnly', 'SmokeCore', 'SmokeInstalled', 'CaptureFailureDiagnostics', 'Uninstall')]
    [string] $Mode,

    [Parameter(Mandatory = $true)]
    [string] $RunRoot,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string] $SnapshotSha,

    [ValidateSet('Broad', 'Core')]
    [string] $Scope = 'Broad',

    [string] $InstallBundleRoot = '',

    [string] $InstallArchivePath = '',

    [string] $InstallEvidencePath = '',

    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$')]
    [string] $ClientHarnessLeaf = 'SeaWork Test'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$serviceName = 'LocalSandboxSeaWork'
$owner = 'local-sandbox-agent-install-smoke'
$installStatePath = Join-Path $RunRoot 'installed-service-state.json'
$clientSigningHarnessSddl = 'O:BAG:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)'
$postRebootServiceWaitSeconds = 300
$failureDiagnostics = Join-Path $PSScriptRoot 'windows-test\lib\failure-diagnostics.ps1'
. $failureDiagnostics

function Invoke-Native {
    param([string] $Executable, [string[]] $Arguments, [string] $Label)
    if ([IO.Path]::GetExtension($Executable) -ieq '.ps1') {
        & pwsh.exe -NoProfile -NonInteractive -File $Executable @Arguments
    }
    else {
        & $Executable @Arguments
    }
    if ($LASTEXITCODE -ne 0) { throw "$Label failed with exit code $LASTEXITCODE" }
}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'The installed service smoke requires an elevated test-harness process.'
    }
}

function Get-InteractiveClientIdentity {
    $computer = Get-CimInstance Win32_ComputerSystem
    $accountName = [string]$computer.UserName
    if ([string]::IsNullOrWhiteSpace($accountName) -or $accountName -notmatch '\\') {
        throw 'No supported interactive console user is logged on for filtered-token validation.'
    }
    try {
        $account = [Security.Principal.NTAccount]::new($accountName)
        $sid = $account.Translate([Security.Principal.SecurityIdentifier])
    }
    catch {
        throw "The interactive console user '$accountName' could not be resolved: $($_.Exception.Message)"
    }
    if ($sid.Value -notmatch '^S-1-5-21-(?:\d+-){3}\d+$') {
        throw "The interactive console user '$accountName' does not have a supported user SID."
    }
    $profiles = @(Get-CimInstance Win32_UserProfile | Where-Object SID -eq $sid.Value)
    if ($profiles.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$profiles[0].LocalPath)) {
        throw "The interactive console user '$accountName' does not have one loaded local profile."
    }
    $localAppData = Join-Path ([string]$profiles[0].LocalPath) 'AppData\Local'
    if (-not (Test-Path -LiteralPath $localAppData -PathType Container) -or
        (Get-Item -LiteralPath $localAppData -Force).Attributes -band
            [IO.FileAttributes]::ReparsePoint) {
        throw "The interactive console user's LocalAppData is absent or a reparse point."
    }
    return [pscustomobject]@{
        identity = $accountName
        name = $accountName.Substring($accountName.LastIndexOf('\') + 1)
        sid = [string]$sid.Value
        local_app_data = $localAppData
    }
}

function Assert-PlainDirectory {
    param([string] $Path, [string] $Label)
    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "$Label must be a regular non-reparse directory"
    }
    return $item
}

function Write-OwnerMarker {
    param([string] $Path, [string] $Kind)
    [ordered]@{
        schema_version = 1
        owner = $owner
        kind = $Kind
        snapshot_sha = $SnapshotSha
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $Path -Encoding utf8NoBOM
}

function Assert-OwnerMarker {
    param([string] $Path, [string] $Kind)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Test-harness ownership marker is missing: $Path"
    }
    $marker = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ($marker.schema_version -ne 1 -or $marker.owner -ne $owner -or
        $marker.kind -ne $Kind -or $marker.snapshot_sha -ne $SnapshotSha) {
        throw "Test-harness ownership marker is invalid: $Path"
    }
}

function Assert-Sddl {
    param([string] $Sddl, [string] $Label)
    try {
        return [Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
    }
    catch {
        throw "$Label SDDL is invalid: $($_.Exception.Message)"
    }
}

function Set-Sddl {
    param([string] $Path, [string] $Sddl)
    $raw = Assert-Sddl $Sddl "ACL for $Path"
    $bytes = [byte[]]::new($raw.BinaryLength)
    $raw.GetBinaryForm($bytes, 0)
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetSecurityDescriptorBinaryForm($bytes)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Set-PathOwner {
    param([string] $Path, [string] $Sid)
    $ownerSid = [Security.Principal.SecurityIdentifier]::new($Sid)
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetOwner($ownerSid)
    Set-Acl -LiteralPath $Path -AclObject $acl
    $observed = (Get-Acl -LiteralPath $Path).Owner
    if ($observed -notin @($Sid, $ownerSid.Translate([Security.Principal.NTAccount]).Value)) {
        throw "Owner verification failed for $Path"
    }
}

function Set-ServicePreshutdownTimeout {
    param([string] $Name, [uint32] $Milliseconds)
    if ($null -eq ('LocalSandbox.Agent.ServiceConfigNative' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace LocalSandbox.Agent
{
public static class ServiceConfigNative
{
    private const uint SC_MANAGER_CONNECT = 0x0001;
    private const uint SERVICE_CHANGE_CONFIG = 0x0002;
    private const uint SERVICE_CONFIG_PRESHUTDOWN_INFO = 7;

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_PRESHUTDOWN_INFO
    {
        public uint TimeoutMilliseconds;
    }

    [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenSCManager(
        string machineName,
        string databaseName,
        uint desiredAccess);

    [DllImport("advapi32.dll", EntryPoint = "OpenServiceW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenService(
        IntPtr serviceManager,
        string serviceName,
        uint desiredAccess);

    [DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfig2W", SetLastError = true)]
    private static extern bool ChangeServiceConfig2(
        IntPtr service,
        uint infoLevel,
        ref SERVICE_PRESHUTDOWN_INFO info);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr handle);

    public static void SetPreshutdownTimeout(string serviceName, uint milliseconds)
    {
        IntPtr manager = OpenSCManager(null, null, SC_MANAGER_CONNECT);
        if (manager == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenSCManager failed");
        }
        try
        {
            IntPtr service = OpenService(manager, serviceName, SERVICE_CHANGE_CONFIG);
            if (service == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenService failed");
            }
            try
            {
                var info = new SERVICE_PRESHUTDOWN_INFO { TimeoutMilliseconds = milliseconds };
                if (!ChangeServiceConfig2(service, SERVICE_CONFIG_PRESHUTDOWN_INFO, ref info))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "ChangeServiceConfig2 preshutdown configuration failed");
                }
            }
            finally
            {
                CloseServiceHandle(service);
            }
        }
        finally
        {
            CloseServiceHandle(manager);
        }
    }
}
}
'@
    }
    [LocalSandbox.Agent.ServiceConfigNative]::SetPreshutdownTimeout($Name, $Milliseconds)
    $serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    $observed = Get-ItemPropertyValue -LiteralPath $serviceKey -Name PreshutdownTimeout
    if ([uint32]$observed -ne $Milliseconds) {
        throw 'SCM preshutdown timeout verification failed'
    }
}

function Invoke-FilteredUserProcess {
    param(
        [object] $State,
        [string] $Executable,
        [string[]] $Arguments,
        [string] $WorkingDirectory,
        [string] $ProofPath,
        [string] $TaskSuffix,
        [switch] $Elevated,
        [int] $TimeoutSeconds = 1800
    )
    if ($TaskSuffix -notmatch '^[a-z0-9][a-z0-9-]{0,31}$') {
        throw 'filtered client task suffix is invalid'
    }
    foreach ($value in @($Executable, $WorkingDirectory, $ProofPath) + @($Arguments)) {
        if ($value -match '["%\r\n]') { throw 'filtered client task value is unsafe for cmd.exe' }
    }
    $taskName = "$($State.client_task_prefix)-$TaskSuffix"
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        throw "Refusing to adopt an existing filtered client task: $taskName"
    }
    $batchPath = "$ProofPath.cmd"
    $groupsPath = "$ProofPath.groups.csv"
    $userPath = "$ProofPath.user.csv"
    $tracePath = "$ProofPath.trace.txt"
    $exitPath = "$ProofPath.exit.txt"
    $quotedArguments = @($Arguments | ForEach-Object { '"{0}"' -f $_ }) -join ' '
    @(
        '@echo off',
        "> `"$tracePath`" echo started",
        "whoami.exe /groups /fo csv /nh > `"$groupsPath`"",
        "if errorlevel 1 (echo groups-failed:%errorlevel%>> `"$tracePath`" & exit /b %errorlevel%)",
        ">> `"$tracePath`" echo groups-passed",
        "whoami.exe /user /fo csv /nh > `"$userPath`"",
        "if errorlevel 1 (echo user-failed:%errorlevel%>> `"$tracePath`" & exit /b %errorlevel%)",
        ">> `"$tracePath`" echo user-passed",
        "pushd `"$WorkingDirectory`"",
        "if errorlevel 1 (echo pushd-failed:%errorlevel%>> `"$tracePath`" & exit /b %errorlevel%)",
        ">> `"$tracePath`" echo pushd-passed",
        "`"$Executable`" $quotedArguments",
        'set "lsb_exit=%errorlevel%"',
        ">> `"$tracePath`" echo executable-result:%lsb_exit%",
        "> `"$exitPath`" echo %lsb_exit%",
        'popd',
        'exit /b 0'
    ) | Set-Content -LiteralPath $batchPath -Encoding ascii
    $action = New-ScheduledTaskAction -Execute $env:ComSpec `
        -Argument ('/d /c call "{0}"' -f $batchPath)
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(10)
    $runLevel = if ($Elevated) { 'Highest' } else { 'Limited' }
    $principal = New-ScheduledTaskPrincipal `
        -UserId $State.client_user_sid `
        -LogonType Interactive `
        -RunLevel $runLevel
    $settings = New-ScheduledTaskSettingsSet `
        -ExecutionTimeLimit (New-TimeSpan -Seconds ($TimeoutSeconds + 60)) `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -MultipleInstances IgnoreNew
    try {
        $registered = Register-ScheduledTask -TaskName $taskName -Action $action `
            -Trigger $trigger -Principal $principal -Settings $settings
        $registeredUserId = [string]$registered.Principal.UserId
        $expectedUserIds = @(
            [string]$State.client_user_sid,
            [string]$State.client_user_identity,
            [string]$State.client_user_name
        )
        if ([string]$registered.Principal.RunLevel -ne $runLevel -or
            [string]$registered.Principal.LogonType -notin @('Interactive', 'InteractiveToken') -or
            $registeredUserId -notin $expectedUserIds) {
            throw "Filtered client task principal mismatch: " +
                "userId=$registeredUserId, " +
                "logonType=$($registered.Principal.LogonType), " +
                "runLevel=$($registered.Principal.RunLevel)."
        }
        $startedAfter = [datetime]::Now.AddSeconds(-2)
        Start-ScheduledTask -TaskName $taskName
        $deadline = [datetime]::UtcNow.AddSeconds($TimeoutSeconds)
        do {
            $task = Get-ScheduledTask -TaskName $taskName
            $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName
            if ($task.State -eq 'Ready' -and $taskInfo.LastRunTime -ge $startedAfter) {
                break
            }
            Start-Sleep -Milliseconds 250
        } while ([datetime]::UtcNow -lt $deadline)
        if ($task.State -ne 'Ready' -or $taskInfo.LastRunTime -lt $startedAfter) {
            throw "Filtered client task exceeded its $TimeoutSeconds second execution limit."
        }
        if ([uint32]$taskInfo.LastTaskResult -ne 0) {
            $trace = if (Test-Path -LiteralPath $tracePath -PathType Leaf) {
                (Get-Content -LiteralPath $tracePath -Raw).Trim()
            }
            else { 'trace-not-written' }
            throw "Filtered client task failed with result $($taskInfo.LastTaskResult): $trace"
        }
        if (-not (Test-Path -LiteralPath $groupsPath -PathType Leaf) -or
            -not (Test-Path -LiteralPath $userPath -PathType Leaf) -or
            -not (Test-Path -LiteralPath $exitPath -PathType Leaf)) {
            throw 'Filtered client task did not write token proof inputs.'
        }
        [int]$processExitCode = 0
        if (-not [int]::TryParse(
            (Get-Content -LiteralPath $exitPath -Raw).Trim(),
            [ref]$processExitCode
        )) {
            throw 'Filtered client task wrote an invalid process exit code.'
        }
        $groups = @(Get-Content -LiteralPath $groupsPath |
            ConvertFrom-Csv -Header GroupName, Type, Sid, Attributes)
        $users = @(Get-Content -LiteralPath $userPath |
            ConvertFrom-Csv -Header UserName, Sid)
        $medium = @($groups | Where-Object Sid -eq 'S-1-16-8192')
        $high = @($groups | Where-Object Sid -eq 'S-1-16-12288')
        $administrators = @($groups | Where-Object Sid -eq 'S-1-5-32-544')
        if ($users.Count -ne 1 -or $users[0].Sid -cne [string]$State.client_user_sid -or
            $administrators.Count -ne 1) {
            throw 'Interactive client task identity proof inputs are invalid.'
        }
        if ($Elevated) {
            if ($medium.Count -ne 0 -or $high.Count -ne 1 -or
                $administrators[0].Attributes -match '(?i)deny') {
                throw 'Elevated maintenance task token proof inputs are invalid.'
            }
        }
        elseif ($medium.Count -ne 1 -or $high.Count -ne 0 -or
            $administrators[0].Attributes -notmatch '(?i)deny') {
            throw 'Filtered client task token proof inputs are invalid.'
        }
        $mode = if ($Elevated) { 'elevated-maintenance' } else { 'filtered-current-user' }
        $integrityLevel = if ($Elevated) { 'high' } else { 'medium' }
        $integrityRid = if ($Elevated) { 12288 } else { 8192 }
        $proof = [ordered]@{
            schema_version = 1
            status = 'passed'
            mode = $mode
            source = if ($Elevated) {
                'interactive-highest-scheduled-task'
            } else { 'interactive-limited-scheduled-task' }
            user_name = [string]$users[0].UserName
            user_sid = [string]$users[0].Sid
            integrity_level = $integrityLevel
            integrity_rid = $integrityRid
            elevated = [bool]$Elevated
            administrator = [bool]$Elevated
            administrator_group_attributes = [string]$administrators[0].Attributes
            elevation_proof = if ($Elevated) {
                'highest-task-plus-high-integrity'
            } else { 'limited-task-plus-medium-integrity' }
            process_exit_code = $processExitCode
            privilege_behavior_validated = $true
            separate_account_profile_validated = $false
        }
        $proof | ConvertTo-Json -Depth 5 |
            Set-Content -LiteralPath $ProofPath -Encoding utf8NoBOM
        $proof = Get-Content -LiteralPath $ProofPath -Raw | ConvertFrom-Json
        return $proof
    }
    finally {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $batchPath, $groupsPath, $userPath, $tracePath, $exitPath `
            -Force -ErrorAction SilentlyContinue
    }
}

function Get-CompatibilityResources {
    $shares = @(& net.exe share | Where-Object { $_ -match '^lsb-' } | ForEach-Object {
        ($_ -split '\s+', 2)[0].ToLowerInvariant()
    })
    $users = @(& net.exe user | Select-String -Pattern '\blsb_[0-9A-Za-z_]+' -AllMatches |
        ForEach-Object { $_.Matches.Value.ToLowerInvariant() })
    return [ordered]@{ shares = @($shares | Sort-Object -Unique); users = @($users | Sort-Object -Unique) }
}

function Assert-CompatibleResourcesRestored {
    param([object] $Before, [string] $StateRoot)
    $after = Get-CompatibilityResources
    if ((Compare-Object @($Before.shares) @($after.shares)) -or
        (Compare-Object @($Before.users) @($after.users))) {
        throw 'The direct-mount smoke left a temporary SMB share or local account.'
    }
    $cleanupManifests = @(Get-ChildItem -LiteralPath $StateRoot -Recurse -Force -File `
        -Filter 'windows-smb-cleanup.json' -ErrorAction SilentlyContinue)
    if ($cleanupManifests.Count -ne 0) {
        throw 'The direct-mount smoke left a compatibility cleanup manifest.'
    }
}

function Assert-SecretAbsentFromLogs {
    param([object] $State, [string] $Secret)
    $files = [Collections.Generic.List[IO.FileInfo]]::new()
    $stateFiles = @(Get-ChildItem -LiteralPath $State.state_root -Recurse -Force -File `
        -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in @('.json', '.log') })
    foreach ($file in $stateFiles) { $files.Add($file) }
    foreach ($file in @(Get-ChildItem -LiteralPath $RunRoot -Force -File -Filter 'output-*.log' `
        -ErrorAction SilentlyContinue)) {
        $files.Add($file)
    }
    foreach ($file in $files) {
        if (Select-String -LiteralPath $file.FullName -SimpleMatch -Quiet -Pattern $Secret) {
            throw "The scoped test secret appeared in a protected log: $($file.Name)"
        }
    }
}

function Wait-ServiceState {
    param([string] $State, [int] $Seconds)
    $deadline = [datetime]::UtcNow.AddSeconds($Seconds)
    do {
        $service = Get-Service -Name $serviceName
        if ([string]$service.Status -eq $State) {
            return
        }
        if ($State -ne 'Stopped' -and [string]$service.Status -eq 'Stopped') {
            $details = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
            # A delayed-auto service remains Stopped with ERROR_SERVICE_NEVER_STARTED
            # while SCM's post-boot delay is still active. Keep waiting within the
            # caller's existing bound so the test proves automatic startup.
            if ([int]$details.ExitCode -eq 1077) {
                Start-Sleep -Milliseconds 250
                continue
            }
            throw "Owned service stopped before reaching $State " +
                "(Win32ExitCode=$($details.ExitCode), " +
                "ServiceSpecificExitCode=$($details.ServiceSpecificExitCode))."
        }
        Start-Sleep -Milliseconds 250
    } while ([datetime]::UtcNow -lt $deadline)
    throw "Owned service did not reach $State within $Seconds seconds."
}

function Wait-OwnedProcessExit {
    param([uint32] $ProcessId, [string] $ExecutablePath, [int] $Seconds)
    if ($ProcessId -eq 0) { return }
    $deadline = [datetime]::UtcNow.AddSeconds($Seconds)
    while ([datetime]::UtcNow -lt $deadline) {
        $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if ($null -eq $process) { return }
        if (-not [string]::IsNullOrWhiteSpace($process.Path) -and
            -not $process.Path.Equals($ExecutablePath, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing to wait on a process whose executable is not owned by this run.'
        }
        Start-Sleep -Milliseconds 250
    }
    throw "Owned service process $ProcessId did not exit within $Seconds seconds."
}

function Stop-OwnedService {
    param([int] $Seconds)
    $deadline = [datetime]::UtcNow.AddSeconds($Seconds)
    while ([datetime]::UtcNow -lt $deadline) {
        $status = (Get-Service -Name $serviceName).Status
        if ($status -eq 'Stopped') { return }
        if ($status -eq 'Running') {
            try { Stop-Service -Name $serviceName -ErrorAction Stop }
            catch {
                # SCM recovery can race a stop request after an unexpected exit.
                # Re-read the bounded state until it is running or stopped.
            }
        }
        elseif ($status -notin @('StartPending', 'StopPending')) {
            throw "Owned service entered unsupported state '$status' during removal."
        }
        Start-Sleep -Milliseconds 250
    }
    throw "Owned service did not stop within $Seconds seconds."
}

function Read-InstallState {
    if (-not (Test-Path -LiteralPath $installStatePath -PathType Leaf)) {
        throw 'The run has no installed service ownership state.'
    }
    $state = Get-Content -LiteralPath $installStatePath -Raw | ConvertFrom-Json
    if ($state.schema_version -ne 1 -or $state.owner -ne $owner -or
        $state.snapshot_sha -ne $SnapshotSha) {
        throw 'The installed service ownership state is invalid.'
    }
    return $state
}

function Invoke-ClientSmoke {
    param(
        [object] $State,
        [switch] $Mounts,
        [switch] $Network,
        [switch] $Sequential,
        [switch] $UpdateCheck,
        [switch] $Maintenance,
        [switch] $AdmissionRejected,
        [string] $ClientHarnessRoot = '',
        [string] $ClientExecutableName = 'node.exe',
        [string] $Suffix
    )
    $scenarioCount = [int]$Mounts.IsPresent + [int]$Network.IsPresent + `
        [int]$Sequential.IsPresent + [int]$UpdateCheck.IsPresent
    if ($scenarioCount -gt 1) {
        throw 'Only one specialized client smoke scenario may be selected.'
    }
    $harnessRoot = if ([string]::IsNullOrWhiteSpace($ClientHarnessRoot)) {
        [string]$State.client_harness_root
    } else { $ClientHarnessRoot }
    $clientData = Join-Path $State.client_data_root $Suffix
    New-Item -ItemType Directory -Path $clientData | Out-Null
    Set-Sddl $clientData ("O:BAG:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{0})" -f $State.client_user_sid)
    $workspace = Join-Path $clientData 'workspace'
    $output = Join-Path $workspace 'output'
    $skills = Join-Path $clientData 'skills'
    $uploads = Join-Path $clientData 'uploads'
    New-Item -ItemType Directory -Path $output, $skills, $uploads | Out-Null
    $protectedSkill = Join-Path $skills 'mis-it-center'
    New-Item -ItemType Directory -Path $protectedSkill | Out-Null
    Set-Sddl $protectedSkill (
        "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;{0})" -f
        $State.client_user_sid
    )
    $protectedSkillFile = Join-Path $protectedSkill 'SKILL.md'
    Set-Content -LiteralPath (Join-Path $workspace 'input.txt') -Value 'workspace-input' -NoNewline
    Set-Content -LiteralPath (Join-Path $skills 'skill.txt') -Value 'skill-input' -NoNewline
    Set-Content -LiteralPath $protectedSkillFile -Value 'protected-skill-input' -NoNewline
    Set-Content -LiteralPath (Join-Path $uploads 'upload.txt') -Value 'upload-input' -NoNewline
    $aclBefore = [ordered]@{
        root = (Get-Acl -LiteralPath $skills).Sddl
        protected_child = (Get-Acl -LiteralPath $protectedSkill).Sddl
        protected_file = (Get-Acl -LiteralPath $protectedSkillFile).Sddl
    }
    $resultPath = Join-Path $clientData 'result.json'
    $mountList = if ($Mounts) {
        @(
            [ordered]@{ type = 'direct'; hostPath = $workspace; guestPath = '/workspace'; flags = 1 },
            [ordered]@{ type = 'direct'; hostPath = $output; guestPath = '/workspace/output'; flags = 0 },
            [ordered]@{ type = 'direct'; hostPath = $skills; guestPath = '/skills'; flags = 1 },
            [ordered]@{ type = 'direct'; hostPath = $uploads; guestPath = '/uploaded_files'; flags = 1 }
        )
    } else { @() }
    $configPath = Join-Path $clientData 'client-config.json'
    $clientConfig = [ordered]@{
        bindingEntry = Join-Path $harnessRoot 'index.js'
        instanceId = "acceptance-$Suffix"
        mounts = $mountList
        resultPath = $resultPath
        expectedUserName = [string]$State.client_user_name
    }
    $secretValue = $null
    $rotatedSecretValue = $null
    $headerValue = $null
    if ($Network) {
        $secretValue = [Convert]::ToHexString(
            [Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
        ).ToLowerInvariant()
        $rotatedSecretValue = [Convert]::ToHexString(
            [Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
        ).ToLowerInvariant()
        $headerValue = [Convert]::ToHexString(
            [Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
        ).ToLowerInvariant()
        $clientConfig['scenario'] = 'network'
        $clientConfig['secretExpected'] = $secretValue
        $clientConfig['secretRotatedExpected'] = $rotatedSecretValue
        $clientConfig['headerExpected'] = $headerValue
        $clientConfig['network'] = [ordered]@{
            allow = @('example.com', 'registry.npmjs.org', 'httpbingo.org')
            secrets = [ordered]@{
                LSB_TEST_SECRET = [ordered]@{
                    value = $secretValue
                    hosts = @('httpbingo.org')
                }
            }
        }
    }
    elseif ($Sequential) {
        $clientConfig['scenario'] = 'sequential'
    }
    elseif ($UpdateCheck) {
        $clientConfig['scenario'] = 'update-check'
    }
    $clientConfig | ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath $configPath -Encoding utf8NoBOM

    $clientExecutable = Join-Path $harnessRoot $ClientExecutableName
    $clientArguments = @(
        (Join-Path $harnessRoot 'service-acceptance.mjs'),
        $configPath
    )
    $tokenProofPath = Join-Path $clientData 'client-token-proof.json'
    $smokeKind = if ($Maintenance) { 'maintenance' } else { 'filtered-token' }
    try {
        if ($Maintenance) {
            $tokenProof = Invoke-FilteredUserProcess `
                -State $State `
                -Executable $clientExecutable `
                -Arguments $clientArguments `
                -WorkingDirectory $harnessRoot `
                -ProofPath $tokenProofPath `
                -TaskSuffix $Suffix `
                -Elevated `
                -TimeoutSeconds 1800
        }
        else {
            $tokenProof = Invoke-FilteredUserProcess `
                -State $State `
                -Executable $clientExecutable `
                -Arguments $clientArguments `
                -WorkingDirectory $harnessRoot `
                -ProofPath $tokenProofPath `
                -TaskSuffix $Suffix `
                -TimeoutSeconds 1800
        }
        if ([int]$tokenProof.process_exit_code -ne 0) {
            if (Test-Path -LiteralPath $resultPath -PathType Leaf) {
                $failedResult = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
                $failedEvidence = Join-Path $RunRoot "evidence-node-$Suffix-failed.json"
                Copy-Item -LiteralPath $resultPath -Destination $failedEvidence
                if ($AdmissionRejected) {
                    if ($failedResult.status -ne 'failed' -or
                        $failedResult.failed_stage -ne 'connect-service') {
                        throw "The rejected client '$Suffix' failed outside service admission."
                    }
                    [ordered]@{
                        schema_version = 1
                        status = 'passed'
                        admission_rejected = $true
                        client_root = $harnessRoot
                        executable_name = $ClientExecutableName
                        client_token = $tokenProof
                        observed_failure = $failedResult
                    } | ConvertTo-Json -Depth 8 |
                        Set-Content -LiteralPath (Join-Path $RunRoot "evidence-node-$Suffix.json") `
                            -Encoding utf8NoBOM
                    return
                }
                $stableDetail = if ($null -ne $failedResult.PSObject.Properties['stable_detail']) {
                    [string]$failedResult.stable_detail
                }
                else { 'no stable detail' }
                throw "The $smokeKind Node smoke '$Suffix' failed at stage " +
                    "'$($failedResult.failed_stage)' after $(@($failedResult.checks).Count) checks: " +
                    $stableDetail
            }
            throw "The $smokeKind Node smoke '$Suffix' exited " +
                "$($tokenProof.process_exit_code) without a result."
        }
        if ($AdmissionRejected) {
            throw "The client '$Suffix' unexpectedly passed service admission."
        }
        if (-not (Test-Path -LiteralPath $resultPath -PathType Leaf)) {
            throw "The $smokeKind Node smoke did not produce a result."
        }
        $result = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
        if ($result.status -ne 'passed') { throw "The $smokeKind Node smoke reported failure." }
        $result | Add-Member -NotePropertyName client_token -NotePropertyValue ([ordered]@{
            mode = [string]$tokenProof.mode
            source = [string]$tokenProof.source
            user_name = [string]$tokenProof.user_name
            user_sid = [string]$tokenProof.user_sid
            integrity_level = [string]$tokenProof.integrity_level
            integrity_rid = [int]$tokenProof.integrity_rid
            elevated = [bool]$tokenProof.elevated
            administrator = [bool]$tokenProof.administrator
            privilege_behavior_validated = [bool]$tokenProof.privilege_behavior_validated
            separate_account_profile_validated = `
                [bool]$tokenProof.separate_account_profile_validated
        })
        if ($Network) {
            $observedChecks = @($result.checks | ForEach-Object { [string]$_.name })
            foreach ($requiredCheck in @(
                'scoped-secret-injection',
                'live-network-interception-rotate',
                'live-network-interception-clear'
            )) {
                if ($requiredCheck -cnotin $observedChecks) {
                    throw "The network smoke did not prove $requiredCheck."
                }
            }
            Assert-SecretAbsentFromLogs $State $secretValue
            Assert-SecretAbsentFromLogs $State $rotatedSecretValue
            Assert-SecretAbsentFromLogs $State $headerValue
            $result.checks += [pscustomobject]@{
                name = 'scoped-secret-redacted'; passed = $true
            }
            $result.checks += [pscustomobject]@{
                name = 'network-interception-values-redacted'; passed = $true
            }
        }
        if ($Sequential -and [int]$result.effects -ne 10) {
            throw 'The sequential smoke did not complete ten effects.'
        }
        if ($Mounts) {
            if ((Get-Content -LiteralPath (Join-Path $output 'result.txt') -Raw) -cne 'nested-output' -or
                (Test-Path -LiteralPath (Join-Path $workspace 'forbidden.txt')) -or
                (Test-Path -LiteralPath (Join-Path $skills 'forbidden.txt')) -or
                (Test-Path -LiteralPath (Join-Path $protectedSkill 'forbidden.txt')) -or
                (Test-Path -LiteralPath (Join-Path $uploads 'forbidden.txt'))) {
                throw 'The direct-mount host visibility or access-mode proof failed.'
            }
            $aclAfter = [ordered]@{
                root = (Get-Acl -LiteralPath $skills).Sddl
                protected_child = (Get-Acl -LiteralPath $protectedSkill).Sddl
                protected_file = (Get-Acl -LiteralPath $protectedSkillFile).Sddl
            }
            foreach ($name in @('root', 'protected_child', 'protected_file')) {
                if ($aclBefore[$name] -cne $aclAfter[$name]) {
                    throw "The direct-mount smoke did not exactly restore the $name SDDL."
                }
            }
            $result | Add-Member -NotePropertyName protected_acl -NotePropertyValue ([ordered]@{
                subtree_read_via_file_api = $true
                subtree_read_via_guest_shell = $true
                exact_sddl_restored = $true
                paths = @('skills', 'skills/mis-it-center', 'skills/mis-it-center/SKILL.md')
            })
        }
        $result | ConvertTo-Json -Depth 8 |
            Set-Content -LiteralPath $resultPath -Encoding utf8NoBOM
        Copy-Item -LiteralPath $resultPath -Destination (Join-Path $RunRoot "evidence-node-$Suffix.json")
    }
    finally {
        Remove-Item -LiteralPath $configPath -Force -ErrorAction SilentlyContinue
        $secretValue = $null
        $rotatedSecretValue = $null
        $headerValue = $null
    }
}

function Install-And-Smoke {
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        throw 'Refusing to touch an existing LocalSandboxSeaWork service.'
    }
    $evidencePath = if ([string]::IsNullOrWhiteSpace($InstallEvidencePath)) {
        Join-Path $RunRoot 'evidence-release-candidate.json'
    } else { [IO.Path]::GetFullPath($InstallEvidencePath) }
    $expectedRunPrefix = [IO.Path]::GetFullPath($RunRoot).TrimEnd('\') + '\'
    if (-not $evidencePath.StartsWith($expectedRunPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Install evidence must remain beneath the run root.'
    }
    $evidence = Get-Content -LiteralPath $evidencePath -Raw | ConvertFrom-Json
    if ($null -eq $evidence.PSObject.Properties['snapshot_sha'] -or
        $evidence.snapshot_sha -ne $SnapshotSha -or
        $evidence.service_profile -ne 'production') {
        throw 'The release-candidate evidence does not match this production snapshot.'
    }
    $version = [string]$evidence.version
    $programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
    $installRoot = Join-Path $programFiles 'SeaWork\LocalSandbox'
    $installMarker = Join-Path $installRoot '.local-sandbox-agent-install.json'
    if (Test-Path -LiteralPath $installRoot) {
        throw 'Refusing to adopt an existing LocalSandbox install root.'
    }
    $stateRoot = Join-Path $env:ProgramData 'LocalSandbox\SeaWork'
    if (Test-Path -LiteralPath $stateRoot) {
        throw 'Refusing to adopt an existing LocalSandboxSeaWork state root.'
    }
    $clientDataRoot = Join-Path $RunRoot "client-data-$($evidence.snapshot_sha.Substring(0, 12))"
    if (Test-Path -LiteralPath $clientDataRoot) {
        throw 'Refusing to adopt an existing standard-user smoke root.'
    }
    $versionRoot = Join-Path $installRoot "versions\$version"
    $bundle = if ([string]::IsNullOrWhiteSpace($InstallBundleRoot)) {
        Join-Path $RunRoot "release-work\out\lsb-seawork-service-v$version-windows-x86_64-stage\LocalSandbox"
    } else { [IO.Path]::GetFullPath($InstallBundleRoot) }
    if (-not $bundle.StartsWith($expectedRunPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Install bundle must remain beneath the run root.'
    }
    $serviceBinary = Join-Path $versionRoot 'bin\localsandbox-seawork-service.exe'
    $eventKey = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\$serviceName"
    $clientIdentity = Get-InteractiveClientIdentity
    $clientUserIdentity = [string]$clientIdentity.identity
    $clientUserName = [string]$clientIdentity.name
    $clientUserSid = [string]$clientIdentity.sid
    $clientLocalAppData = [string]$clientIdentity.local_app_data
    $clientPrograms = Join-Path $clientLocalAppData 'Programs'
    $clientHarnessBase = Join-Path $clientPrograms $ClientHarnessLeaf
    $clientHarness = Join-Path $clientHarnessBase 'Primary'
    $clientTestHarness = Join-Path $clientHarnessBase 'Untrusted'
    $clientCollisionHarness = Join-Path $clientPrograms "SeaWork-copy-$($evidence.snapshot_sha.Substring(0, 12))"
    $clientSigningHarness = Join-Path $programFiles `
        "SeaWork\LocalSandboxTestHarness\$($evidence.snapshot_sha.Substring(0, 12))"
    $clientSigningHarnessBase = Split-Path -Parent $clientSigningHarness
    foreach ($path in @($clientHarnessBase, $clientCollisionHarness)) {
        if (Test-Path -LiteralPath $path) {
            throw "Refusing to adopt an existing LocalAppData test-client root: $path"
        }
    }
    if (Test-Path -LiteralPath $clientSigningHarnessBase) {
        throw 'Refusing to adopt an existing LocalSandbox signing-fixture root.'
    }
    New-Item -ItemType Directory -Force -Path $clientPrograms | Out-Null
    New-Item -ItemType Directory -Path `
        (Join-Path $installRoot 'versions'), $clientHarnessBase, $clientHarness,
        $clientTestHarness,
        $clientCollisionHarness, $clientSigningHarness, $stateRoot, $clientDataRoot |
        Out-Null
    Write-OwnerMarker (Join-Path $clientHarnessBase '.local-sandbox-agent-client.json') `
        'client-harness-base'
    Write-OwnerMarker $installMarker 'install-root'
    Write-OwnerMarker (Join-Path $clientHarness '.local-sandbox-agent-client.json') `
        'client-root'
    Write-OwnerMarker (Join-Path $clientTestHarness '.local-sandbox-agent-client.json') `
        'test-client-root'
    Write-OwnerMarker (Join-Path $clientCollisionHarness '.local-sandbox-agent-client.json') `
        'collision-client-root'
    Write-OwnerMarker (Join-Path $clientSigningHarnessBase '.local-sandbox-agent-client.json') `
        'signing-client-root'
    Write-OwnerMarker (Join-Path $stateRoot '.local-sandbox-agent-state.json') 'state-root'
    Write-OwnerMarker (Join-Path $clientDataRoot '.local-sandbox-agent-client-data.json') 'client-data-root'
    $clientTaskPrefix = "LocalSandboxAgent-$($SnapshotSha.Substring(0, 8))"
    if (Get-ScheduledTask | Where-Object TaskName -like "$clientTaskPrefix-*") {
        throw 'Refusing to adopt an existing filtered client task.'
    }
    $runId = Split-Path -Leaf ([IO.Path]::GetFullPath($RunRoot).TrimEnd('\'))
    [ordered]@{
        schema_version = 1; owner = $owner; snapshot_sha = $SnapshotSha; run_id = $runId
        version = $version; service_binary = $serviceBinary; install_root = $installRoot
        install_marker = $installMarker; state_root = $stateRoot; event_key = $eventKey
        client_harness_base = $clientHarnessBase
        client_harness_root = $clientHarness
        client_test_harness_root = $clientTestHarness
        client_collision_harness_root = $clientCollisionHarness
        client_signing_harness_root = $clientSigningHarness
        client_signing_harness_base = $clientSigningHarnessBase
        client_local_app_data = $clientLocalAppData
        client_data_root = $clientDataRoot
        client_user_identity = $clientUserIdentity
        client_user_name = $clientUserName
        client_user_sid = $clientUserSid
        client_token_mode = 'filtered-current-user'
        client_task_prefix = $clientTaskPrefix
        separate_account_profile_validated = $false
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $installStatePath -Encoding utf8NoBOM

    Assert-PlainDirectory $bundle 'signed staged bundle' | Out-Null
    New-Item -ItemType Directory -Path $versionRoot | Out-Null
    foreach ($entry in Get-ChildItem -LiteralPath $bundle -Force) {
        Copy-Item -LiteralPath $entry.FullName -Destination $versionRoot -Recurse
    }
    Invoke-Native $serviceBinary @('--verify-bundle', '--json') 'copied installed-layout verification'

    $priorPublisher = $env:SEAWORK_PUBLISHER_SHA256
    try {
        $env:SEAWORK_PUBLISHER_SHA256 = [string]$evidence.publisher_sha256
        Push-Location 'bindings/nodejs'
        try {
            Invoke-Native corepack @('yarn', 'install', '--immutable') 'Node dependency install'
            Invoke-Native corepack @('yarn', 'napi', 'build', '--target', 'x86_64-pc-windows-msvc', '--platform', '--release', '--js', 'index.js', '--dts', 'index.d.ts') 'pinned Node binding build'
            Invoke-Native corepack @('yarn', 'patch-loader') 'Node loader patch'
        } finally { Pop-Location }
    } finally { $env:SEAWORK_PUBLISHER_SHA256 = $priorPublisher }
    Copy-Item -LiteralPath (Get-Command node.exe).Source `
        -Destination (Join-Path $clientSigningHarness 'node.exe')
    Copy-Item -LiteralPath 'bindings\nodejs\index.js' -Destination $clientSigningHarness
    Copy-Item -LiteralPath 'bindings\nodejs\lsb-nodejs.win32-x64-msvc.node' `
        -Destination $clientSigningHarness
    Copy-Item -LiteralPath 'fixtures\windows\guest\service-acceptance.mjs' `
        -Destination $clientSigningHarness
    Set-Sddl $clientSigningHarnessBase $clientSigningHarnessSddl
    Invoke-Native 'scripts\sign-seawork-service.ps1' @(
        '-Mode', 'SignTestNode',
        '-ClientBinary', (Join-Path $clientSigningHarness 'node.exe'),
        '-UseLocalMachineStore',
        '-PfxPath', $env:SEAWORK_WINDOWS_PFX_PATH,
        '-PasswordFile', $env:SEAWORK_WINDOWS_PFX_PASSWORD_FILE,
        '-ExpectedPublisherSubject', [string]$evidence.publisher_subject,
        '-ExpectedPublisherSha256', [string]$evidence.publisher_sha256
    ) 'test Node executable signing'
    foreach ($root in @($clientHarness, $clientTestHarness, $clientCollisionHarness)) {
        Copy-Item -Path (Join-Path $clientSigningHarness '*') -Destination $root `
            -Recurse -Force
    }
    Copy-Item -LiteralPath (Get-Command node.exe).Source `
        -Destination (Join-Path $clientTestHarness 'node-untrusted.exe')
    Write-OwnerMarker (Join-Path $clientHarness '.local-sandbox-agent-client.json') `
        'client-root'
    Write-OwnerMarker (Join-Path $clientTestHarness '.local-sandbox-agent-client.json') `
        'test-client-root'
    Write-OwnerMarker (Join-Path $clientCollisionHarness '.local-sandbox-agent-client.json') `
        'collision-client-root'
    $clientRootSddl = "O:$clientUserSid" +
        "G:$clientUserSid" +
        "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;$clientUserSid)"
    foreach ($root in @($clientHarness, $clientTestHarness, $clientCollisionHarness)) {
        Set-Sddl $root $clientRootSddl
        Set-PathOwner (Join-Path $root 'node.exe') $clientUserSid
    }
    Set-PathOwner (Join-Path $clientTestHarness 'node-untrusted.exe') $clientUserSid

    $binaryPath = '"{0}" --service' -f $serviceBinary
    Invoke-Native sc.exe @('create', $serviceName, 'binPath=', $binaryPath, 'start=', 'auto', 'obj=', 'LocalSystem', 'DisplayName=', 'LocalSandbox for SeaWork') 'service creation'
    Invoke-Native sc.exe @('description', $serviceName, 'Runs LocalSandbox virtual machines for locally signed SeaWork desktop clients.') 'service description'
    Invoke-Native sc.exe @('sidtype', $serviceName, 'unrestricted') 'service SID configuration'
    Invoke-Native sc.exe @('failure', $serviceName, 'reset=', '86400', 'actions=', 'restart/5000/restart/30000/restart/120000') 'service failure actions'
    Invoke-Native sc.exe @('failureflag', $serviceName, '1') 'service failure flag'
    Set-ServicePreshutdownTimeout $serviceName 60000
    Invoke-Native sc.exe @('sdset', $serviceName, 'O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00000005;;;IU)') 'service object ACL'
    Invoke-Native sc.exe @('config', $serviceName, 'start=', 'delayed-auto') 'delayed automatic start'
    $serviceSid = ([Security.Principal.NTAccount]::new("NT SERVICE\$serviceName")).Translate([Security.Principal.SecurityIdentifier]).Value
    Set-Sddl $versionRoot ("O:BAG:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;{0})(A;OICI;FRFX;;;BU)" -f $serviceSid)
    Set-Sddl $stateRoot 'O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
    New-Item -ItemType Directory -Path (Join-Path $stateRoot 'config') | Out-Null
    [ordered]@{
        schema_version = 1; config_revision = 3
        quotas = [ordered]@{ connections_global = 32; connections_per_user = 4; sandboxes_global = 8; sandboxes_per_user = 4; sandboxes_per_connection = 2; memory_mib_global = 24576 }
        publisher_thumbprints = @([string]$evidence.publisher_sha256)
        client_roots = @(
            '%CALLER_LOCALAPPDATA%\Programs\SeaWork',
            "%CALLER_LOCALAPPDATA%\Programs\$ClientHarnessLeaf"
        )
        maintenance_roots = @(Join-Path $programFiles 'SeaWork')
        egress_allow = @(); upstream_proxy = $null; ports_enabled = $false
    } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $stateRoot 'config\service.json') -Encoding utf8NoBOM
    $expectedArchiveName = "lsb-seawork-service-v$version-windows-x86_64.zip"
    $serviceArchive = if ([string]::IsNullOrWhiteSpace($InstallArchivePath)) {
        [IO.Path]::GetFullPath((Join-Path $RunRoot "release-work\out\$expectedArchiveName"))
    } else { [IO.Path]::GetFullPath($InstallArchivePath) }
    if (-not $serviceArchive.StartsWith($expectedRunPrefix, [StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-Path -LiteralPath $serviceArchive -PathType Leaf) -or
        (Split-Path -Leaf $serviceArchive) -cne $expectedArchiveName -or
        ((Get-Item -LiteralPath $serviceArchive -Force).Attributes -band
            [IO.FileAttributes]::ReparsePoint)) {
        throw 'The install service archive is missing, invalid, or outside the run root.'
    }
    $updatesRoot = Join-Path $stateRoot 'updates'
    New-Item -ItemType Directory -Path $updatesRoot | Out-Null
    $initialTransactionId = ('0' * 24) + $SnapshotSha.Substring(0, 8)
    Invoke-Native cargo.exe @(
        'run', '-p', 'xtask', '--locked', '--', 'seed-update-candidate',
        'initialize-baseline', '--archive', $serviceArchive,
        '--bundle', $versionRoot,
        '--committed', (Join-Path $updatesRoot 'committed.json'),
        '--publisher-subject', [string]$evidence.publisher_subject,
        '--publisher-sha256', [string]$evidence.publisher_sha256,
        '--transaction-id', $initialTransactionId
    ) 'baseline committed-state initialization'
    Set-Sddl $stateRoot 'O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
    if (Test-Path -LiteralPath $eventKey) { throw 'Refusing to adopt an existing Event Log source.' }
    New-Item -Path $eventKey | Out-Null
    New-ItemProperty -Path $eventKey -Name LocalSandboxAgentOwner -Value $owner -PropertyType String | Out-Null
    New-ItemProperty -Path $eventKey -Name EventMessageFile -Value $serviceBinary -PropertyType ExpandString | Out-Null
    New-ItemProperty -Path $eventKey -Name TypesSupported -Value 7 -PropertyType DWord | Out-Null

    Set-Sddl $clientDataRoot ("O:BAG:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{0})" -f $clientUserSid)
    Invoke-Native sc.exe @('start', $serviceName) 'service start'
    Wait-ServiceState 'Running' 120
    $state = Read-InstallState
    $before = Get-CompatibilityResources
    Invoke-ClientSmoke $state -Suffix 'mount-free'
    if ($Mode -eq 'InstallOnly') {
        Assert-CompatibleResourcesRestored $before $stateRoot
        [ordered]@{
            schema_version = 1
            status = 'passed'
            snapshot_sha = $SnapshotSha
            version = $version
            production_identity = $true
            service_healthy = $true
            admissions_open = $true
            standard_user_mount_free = $true
        } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath `
            (Join-Path $RunRoot 'evidence-baseline-installed.json') -Encoding utf8NoBOM
        return
    }
    if ($Scope -eq 'Broad') {
        Invoke-ClientSmoke $state -ClientHarnessRoot $clientTestHarness -Suffix 'caller-test-root'
        Invoke-ClientSmoke $state -AdmissionRejected `
            -ClientHarnessRoot $clientCollisionHarness -Suffix 'caller-prefix-collision'
    }
    Invoke-ClientSmoke $state -AdmissionRejected `
        -ClientHarnessRoot $clientTestHarness -ClientExecutableName 'node-untrusted.exe' `
        -Suffix 'caller-wrong-publisher'
    if ($Scope -eq 'Broad') {
        Set-PathOwner (Join-Path $clientTestHarness 'node.exe') 'S-1-5-32-544'
        Invoke-ClientSmoke $state -AdmissionRejected `
            -ClientHarnessRoot $clientTestHarness -Suffix 'caller-wrong-owner'
        Set-PathOwner (Join-Path $clientTestHarness 'node.exe') $clientUserSid
    }
    Invoke-ClientSmoke $state -Mounts -Suffix 'direct-mounts'
    Invoke-ClientSmoke $state -Network -Suffix 'network'
    Invoke-ClientSmoke $state -UpdateCheck -Maintenance `
        -ClientHarnessRoot ([string]$state.client_signing_harness_root) `
        -Suffix 'update-check'
    if ($Scope -eq 'Broad') {
        Invoke-ClientSmoke $state -Mounts -Suffix 'direct-mounts-repeat'
        Invoke-ClientSmoke $state -Sequential -Suffix 'sequential'
    }
    Assert-CompatibleResourcesRestored $before $stateRoot
    [ordered]@{
        schema_version = 1
        status = 'passed'
        snapshot_sha = $SnapshotSha
        production_identity = $true
        client_validation = [ordered]@{
            mode = 'filtered-current-user'
            privilege_behavior_validated = $true
            medium_integrity = $true
            non_admin = $true
            caller_relative_production_root = $true
            caller_relative_test_root = $true
            prefix_collision_rejected = $true
            wrong_publisher_client_rejected = $true
            wrong_owner_rejected = $true
            separate_account_profile_validated = $false
        }
        uac_after_install = $false
        compatibility_resources_restored = $true
        protected_acl_cycles = 2
        protected_subtree_reads = $true
        exact_acl_restoration = $true
    } |
        ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $RunRoot 'evidence-installed-smoke.json') -Encoding utf8NoBOM
}

function Smoke-Core {
    $state = Read-InstallState
    if ((Get-Service -Name $serviceName).Status -ne 'Running') {
        Wait-ServiceState 'Running' $postRebootServiceWaitSeconds
    }
    $before = Get-CompatibilityResources
    Invoke-ClientSmoke $state -Suffix 'core-mount-free'
    Invoke-ClientSmoke $state -AdmissionRejected `
        -ClientHarnessRoot ([string]$state.client_test_harness_root) `
        -ClientExecutableName 'node-untrusted.exe' -Suffix 'core-caller-wrong-publisher'
    Invoke-ClientSmoke $state -Mounts -Suffix 'core-direct-mounts'
    Invoke-ClientSmoke $state -Network -Suffix 'core-network'
    Invoke-ClientSmoke $state -UpdateCheck -Maintenance `
        -ClientHarnessRoot ([string]$state.client_signing_harness_root) `
        -Suffix 'core-update-check'
    Assert-CompatibleResourcesRestored $before $state.state_root
    [ordered]@{
        schema_version = 1
        status = 'passed'
        snapshot_sha = $SnapshotSha
        scope = 'core'
        mount_free = $true
        seawork_mounts = $true
        managed_network = $true
        candidate_manual_no_candidate = $true
        wrong_publisher_rejected = $true
    } | ConvertTo-Json | Set-Content -LiteralPath `
        (Join-Path $RunRoot 'evidence-service-core.json') -Encoding utf8NoBOM
}

function Smoke-Installed {
    $state = Read-InstallState
    if ((Get-Service -Name $serviceName).Status -ne 'Running') {
        Wait-ServiceState 'Running' $postRebootServiceWaitSeconds
    }
    $before = Get-CompatibilityResources
    if ($Scope -eq 'Core') {
        Invoke-ClientSmoke $state -Suffix 'post-reboot'
    } else {
        Invoke-ClientSmoke $state -Mounts -Suffix 'post-reboot'
    }
    Assert-CompatibleResourcesRestored $before $state.state_root
    [ordered]@{
        schema_version = 1
        status = 'passed'
        snapshot_sha = $SnapshotSha
        post_reboot = $true
        client_validation = [ordered]@{
            mode = 'filtered-current-user'
            privilege_behavior_validated = $true
            separate_account_profile_validated = $false
        }
    } |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $RunRoot 'evidence-post-reboot.json') -Encoding utf8NoBOM
}

function Capture-FailureDiagnostics {
    $state = Read-InstallState
    Assert-OwnerMarker $state.install_marker 'install-root'
    Assert-OwnerMarker (Join-Path $state.state_root '.local-sandbox-agent-state.json') 'state-root'
    $service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" `
        -ErrorAction SilentlyContinue
    if ($null -ne $service) {
        if (-not $service.PathName.Contains(
            [string]$state.service_binary, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing to capture diagnostics from a service not owned by this run.'
        }
        $serviceProcessId = [uint32]$service.ProcessId
        if ((Get-Service -Name $serviceName).Status -ne 'Stopped') {
            Stop-OwnedService 120
        }
        Wait-OwnedProcessExit $serviceProcessId ([string]$state.service_binary) 60
    }
    New-FailureDiagnosticArchive `
        -StateRoot ([string]$state.state_root) `
        -DestinationRoot (Join-Path $RunRoot 'failure-diagnostics')
}

function Uninstall-Owned {
    $state = Read-InstallState
    if ($null -ne $state.PSObject.Properties['updater_service_binary']) {
        $updaterService = Get-CimInstance Win32_Service `
            -Filter "Name='LocalSandboxSeaWorkUpdater'" -ErrorAction SilentlyContinue
        if ($null -ne $updaterService) {
            if (-not $updaterService.PathName.Contains(
                [string]$state.updater_service_binary,
                [StringComparison]::OrdinalIgnoreCase)) {
                throw 'Refusing to remove an updater service whose ImagePath is not owned by this run.'
            }
            if ((Get-Service -Name 'LocalSandboxSeaWorkUpdater').Status -ne 'Stopped') {
                Stop-Service -Name 'LocalSandboxSeaWorkUpdater'
                (Get-Service -Name 'LocalSandboxSeaWorkUpdater').WaitForStatus(
                    'Stopped', [TimeSpan]::FromMinutes(2))
            }
            Invoke-Native sc.exe @('delete', 'LocalSandboxSeaWorkUpdater') `
                'updater service deletion'
        }
    }
    $service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
    if ($null -ne $service) {
        if (-not $service.PathName.Contains([string]$state.service_binary, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing to remove a service whose ImagePath is not owned by this run.'
        }
        $serviceProcessId = [uint32]$service.ProcessId
        if ((Get-Service -Name $serviceName).Status -ne 'Stopped') {
            Stop-OwnedService 120
        }
        Wait-OwnedProcessExit $serviceProcessId ([string]$state.service_binary) 60
        Invoke-Native sc.exe @('delete', $serviceName) 'service deletion'
    }
    if (Test-Path -LiteralPath $state.event_key) {
        if ((Get-ItemPropertyValue -LiteralPath $state.event_key -Name LocalSandboxAgentOwner) -ne $owner) { throw 'Event source ownership mismatch.' }
        Remove-Item -LiteralPath $state.event_key -Recurse -Force
    }
    foreach ($task in @(Get-ScheduledTask | Where-Object TaskName -like "$($state.client_task_prefix)-*")) {
        Stop-ScheduledTask -TaskName $task.TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false
    }
    Assert-OwnerMarker $state.install_marker 'install-root'
    Assert-OwnerMarker (Join-Path $state.client_harness_base '.local-sandbox-agent-client.json') `
        'client-harness-base'
    Assert-OwnerMarker (Join-Path $state.client_test_harness_root '.local-sandbox-agent-client.json') `
        'test-client-root'
    Assert-OwnerMarker (Join-Path $state.client_collision_harness_root '.local-sandbox-agent-client.json') `
        'collision-client-root'
    Assert-OwnerMarker (Join-Path $state.client_signing_harness_base '.local-sandbox-agent-client.json') `
        'signing-client-root'
    Assert-OwnerMarker (Join-Path $state.state_root '.local-sandbox-agent-state.json') 'state-root'
    Assert-OwnerMarker (Join-Path $state.client_data_root '.local-sandbox-agent-client-data.json') 'client-data-root'
    Remove-Item -LiteralPath $state.install_root -Recurse -Force -ErrorAction Stop
    Remove-Item -LiteralPath $state.client_harness_base -Recurse -Force -ErrorAction Stop
    Remove-Item -LiteralPath $state.client_collision_harness_root -Recurse -Force `
        -ErrorAction Stop
    Remove-Item -LiteralPath $state.client_signing_harness_base -Recurse -Force `
        -ErrorAction Stop
    Remove-Item -LiteralPath $state.state_root -Recurse -Force -ErrorAction Stop
    Remove-Item -LiteralPath $state.client_data_root -Recurse -Force -ErrorAction Stop
    Remove-Item -LiteralPath $installStatePath -Force -ErrorAction Stop
}

if ($MyInvocation.InvocationName -ne '.') {
    Assert-Administrator
    switch ($Mode) {
        'InstallAndSmoke' { Install-And-Smoke }
        'InstallOnly' { Install-And-Smoke }
        'SmokeCore' { Smoke-Core }
        'SmokeInstalled' { Smoke-Installed }
        'CaptureFailureDiagnostics' { Capture-FailureDiagnostics }
        'Uninstall' { Uninstall-Owned }
    }
}
