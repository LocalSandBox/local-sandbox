[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('InstallAndSmoke', 'SmokeInstalled', 'Uninstall')]
    [string] $Mode,

    [Parameter(Mandatory = $true)]
    [string] $RunRoot,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string] $SnapshotSha
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$serviceName = 'LocalSandboxSeaWork'
$owner = 'local-sandbox-agent-install-smoke'
$installStatePath = Join-Path $RunRoot 'installed-service-state.json'
$clientHarnessSddl = 'O:BAG:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)'

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
    $principal = New-ScheduledTaskPrincipal `
        -UserId $State.client_user_identity `
        -LogonType Interactive `
        -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet `
        -ExecutionTimeLimit (New-TimeSpan -Seconds ($TimeoutSeconds + 60)) `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -MultipleInstances IgnoreNew
    try {
        $registered = Register-ScheduledTask -TaskName $taskName -Action $action `
            -Trigger $trigger -Principal $principal -Settings $settings
        if ([string]$registered.Principal.RunLevel -ne 'Limited' -or
            [string]$registered.Principal.LogonType -notin @('Interactive', 'InteractiveToken')) {
            throw "Filtered client task principal mismatch: " +
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
            $medium.Count -ne 1 -or $high.Count -ne 0 -or
            $administrators.Count -ne 1 -or
            $administrators[0].Attributes -notmatch '(?i)deny') {
            throw 'Filtered client task token proof inputs are invalid.'
        }
        $proof = [ordered]@{
            schema_version = 1
            status = 'passed'
            mode = 'filtered-current-user'
            source = 'interactive-limited-scheduled-task'
            user_name = [string]$users[0].UserName
            user_sid = [string]$users[0].Sid
            integrity_level = 'medium'
            integrity_rid = 8192
            elevated = $false
            administrator = $false
            administrator_group_attributes = [string]$administrators[0].Attributes
            elevation_proof = 'limited-task-plus-medium-integrity'
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
    $service = Get-Service -Name $serviceName
    $service.WaitForStatus($State, [TimeSpan]::FromSeconds($Seconds))
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
        [string] $Suffix
    )
    $scenarioCount = [int]$Mounts.IsPresent + [int]$Network.IsPresent + [int]$Sequential.IsPresent
    if ($scenarioCount -gt 1) {
        throw 'Only one specialized client smoke scenario may be selected.'
    }
    $clientData = Join-Path $State.client_data_root $Suffix
    New-Item -ItemType Directory -Path $clientData | Out-Null
    Set-Sddl $clientData ("O:BAG:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{0})" -f $State.client_user_sid)
    $workspace = Join-Path $clientData 'workspace'
    $output = Join-Path $workspace 'output'
    $skills = Join-Path $clientData 'skills'
    $uploads = Join-Path $clientData 'uploads'
    New-Item -ItemType Directory -Path $output, $skills, $uploads | Out-Null
    Set-Content -LiteralPath (Join-Path $workspace 'input.txt') -Value 'workspace-input' -NoNewline
    Set-Content -LiteralPath (Join-Path $skills 'skill.txt') -Value 'skill-input' -NoNewline
    Set-Content -LiteralPath (Join-Path $uploads 'upload.txt') -Value 'upload-input' -NoNewline
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
        bindingEntry = Join-Path $State.client_harness_root 'index.js'
        instanceId = "acceptance-$Suffix"
        mounts = $mountList
        resultPath = $resultPath
        expectedUserName = [string]$State.client_user_name
    }
    $secretValue = $null
    if ($Network) {
        $secretValue = [Convert]::ToHexString(
            [Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
        ).ToLowerInvariant()
        $clientConfig['scenario'] = 'network'
        $clientConfig['secretExpected'] = $secretValue
        $clientConfig['network'] = [ordered]@{
            allow = @('example.com', 'registry.npmjs.org', 'httpbin.org')
            secrets = [ordered]@{
                LSB_TEST_SECRET = [ordered]@{
                    value = $secretValue
                    hosts = @('httpbin.org')
                }
            }
            httpsInterception = [ordered]@{ enabled = $true; requestHeaders = @() }
        }
    }
    elseif ($Sequential) {
        $clientConfig['scenario'] = 'sequential'
    }
    $clientConfig | ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath $configPath -Encoding utf8NoBOM

    $clientExecutable = Join-Path $State.client_harness_root 'node.exe'
    $clientArguments = @(
        (Join-Path $State.client_harness_root 'service-acceptance.mjs'),
        $configPath
    )
    $tokenProofPath = Join-Path $clientData 'client-token-proof.json'
    try {
        $tokenProof = Invoke-FilteredUserProcess `
            -State $State `
            -Executable $clientExecutable `
            -Arguments $clientArguments `
            -WorkingDirectory $State.client_harness_root `
            -ProofPath $tokenProofPath `
            -TaskSuffix $Suffix `
            -TimeoutSeconds 1800
        if ([int]$tokenProof.process_exit_code -ne 0) {
            if (Test-Path -LiteralPath $resultPath -PathType Leaf) {
                $failedResult = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
                Copy-Item -LiteralPath $resultPath `
                    -Destination (Join-Path $RunRoot "evidence-node-$Suffix-failed.json")
                throw "The filtered-token Node smoke '$Suffix' failed at stage " +
                    "'$($failedResult.failed_stage)' after $(@($failedResult.checks).Count) checks: " +
                    "$($failedResult.stable_detail)"
            }
            throw "The filtered-token Node smoke '$Suffix' exited " +
                "$($tokenProof.process_exit_code) without a result."
        }
        if (-not (Test-Path -LiteralPath $resultPath -PathType Leaf)) {
            throw 'The filtered-token Node smoke did not produce a result.'
        }
        $result = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
        if ($result.status -ne 'passed') { throw 'The filtered-token Node smoke reported failure.' }
        $result | Add-Member -NotePropertyName client_token -NotePropertyValue ([ordered]@{
            mode = 'filtered-current-user'
            source = [string]$tokenProof.source
            user_name = [string]$tokenProof.user_name
            user_sid = [string]$tokenProof.user_sid
            integrity_level = 'medium'
            integrity_rid = [int]$tokenProof.integrity_rid
            elevated = [bool]$tokenProof.elevated
            administrator = [bool]$tokenProof.administrator
            privilege_behavior_validated = $true
            separate_account_profile_validated = $false
        })
        if ($Network) {
            $observedChecks = @($result.checks | ForEach-Object { [string]$_.name })
            if ('scoped-secret-injection' -cnotin $observedChecks) {
                throw 'The network smoke did not prove scoped secret injection.'
            }
            Assert-SecretAbsentFromLogs $State $secretValue
            $result.checks += [pscustomobject]@{ name = 'scoped-secret-redacted'; passed = $true }
        }
        if ($Sequential -and [int]$result.effects -ne 10) {
            throw 'The sequential smoke did not complete ten effects.'
        }
        if ($Mounts) {
            if ((Get-Content -LiteralPath (Join-Path $output 'result.txt') -Raw) -cne 'nested-output' -or
                (Test-Path -LiteralPath (Join-Path $workspace 'forbidden.txt')) -or
                (Test-Path -LiteralPath (Join-Path $skills 'forbidden.txt')) -or
                (Test-Path -LiteralPath (Join-Path $uploads 'forbidden.txt'))) {
                throw 'The direct-mount host visibility or access-mode proof failed.'
            }
        }
        $result | ConvertTo-Json -Depth 8 |
            Set-Content -LiteralPath $resultPath -Encoding utf8NoBOM
        Copy-Item -LiteralPath $resultPath -Destination (Join-Path $RunRoot "evidence-node-$Suffix.json")
    }
    finally {
        Remove-Item -LiteralPath $configPath -Force -ErrorAction SilentlyContinue
        $secretValue = $null
    }
}

function Install-And-Smoke {
    Assert-Sddl $clientHarnessSddl 'test client harness ACL' | Out-Null
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        throw 'Refusing to touch an existing LocalSandboxSeaWork service.'
    }
    $evidence = Get-Content -LiteralPath (Join-Path $RunRoot 'evidence-release-candidate.json') -Raw | ConvertFrom-Json
    if ($evidence.snapshot_sha -ne $SnapshotSha -or $evidence.service_profile -ne 'production') {
        throw 'The release-candidate evidence does not match this production snapshot.'
    }
    $version = [string]$evidence.version
    $programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
    $installRoot = Join-Path $programFiles 'SeaWork\LocalSandbox'
    $installMarker = Join-Path $installRoot '.local-sandbox-agent-install.json'
    if (Test-Path -LiteralPath $installRoot) {
        throw 'Refusing to adopt an existing LocalSandbox install root.'
    }
    $clientHarness = Join-Path $programFiles "SeaWork\LocalSandboxTestHarness\$($evidence.snapshot_sha.Substring(0, 12))"
    $clientHarnessBase = Split-Path -Parent $clientHarness
    if (Test-Path -LiteralPath $clientHarnessBase) {
        throw 'Refusing to adopt an existing LocalSandbox test-client root.'
    }
    $stateRoot = Join-Path $env:ProgramData 'LocalSandbox\SeaWork'
    if (Test-Path -LiteralPath $stateRoot) {
        throw 'Refusing to adopt an existing LocalSandboxSeaWork state root.'
    }
    $clientDataRoot = Join-Path $env:ProgramData "LocalSandbox\DevTest\client-runs\$($evidence.snapshot_sha.Substring(0, 12))"
    if (Test-Path -LiteralPath $clientDataRoot) {
        throw 'Refusing to adopt an existing standard-user smoke root.'
    }
    New-Item -ItemType Directory -Path (Join-Path $installRoot 'versions'), $clientHarness, $stateRoot, $clientDataRoot | Out-Null
    Write-OwnerMarker $installMarker 'install-root'
    Write-OwnerMarker (Join-Path $clientHarnessBase '.local-sandbox-agent-client.json') 'client-root'
    Write-OwnerMarker (Join-Path $stateRoot '.local-sandbox-agent-state.json') 'state-root'
    Write-OwnerMarker (Join-Path $clientDataRoot '.local-sandbox-agent-client-data.json') 'client-data-root'

    $versionRoot = Join-Path $installRoot "versions\$version"
    $bundle = Join-Path $RunRoot "release-work\out\lsb-seawork-service-v$version-windows-x86_64-stage\LocalSandbox"
    $serviceBinary = Join-Path $versionRoot 'bin\localsandbox-seawork-service.exe'
    $eventKey = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\$serviceName"
    $clientIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $clientUserIdentity = [string]$clientIdentity.Name
    $clientUserName = [string]$env:USERNAME
    $clientUserSid = [string]$clientIdentity.User.Value
    if ([string]::IsNullOrWhiteSpace($clientUserIdentity) -or
        [string]::IsNullOrWhiteSpace($clientUserName) -or
        $clientUserSid -notmatch '^S-1-5-21-(?:\d+-){3}\d+$') {
        throw 'The elevated harness does not have a supported local/domain user identity.'
    }
    $clientTaskPrefix = "LocalSandboxAgent-$($SnapshotSha.Substring(0, 8))"
    if (Get-ScheduledTask | Where-Object TaskName -like "$clientTaskPrefix-*") {
        throw 'Refusing to adopt an existing filtered client task.'
    }
    $runId = Split-Path -Leaf ([IO.Path]::GetFullPath($RunRoot).TrimEnd('\'))
    [ordered]@{
        schema_version = 1; owner = $owner; snapshot_sha = $SnapshotSha; run_id = $runId
        version = $version; service_binary = $serviceBinary; install_root = $installRoot
        install_marker = $installMarker; state_root = $stateRoot; event_key = $eventKey
        client_harness_root = $clientHarness; client_harness_base = $clientHarnessBase
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
    Copy-Item -LiteralPath (Get-Command node.exe).Source -Destination (Join-Path $clientHarness 'node.exe')
    Copy-Item -LiteralPath 'bindings\nodejs\index.js' -Destination $clientHarness
    Copy-Item -LiteralPath 'bindings\nodejs\lsb-nodejs.win32-x64-msvc.node' -Destination $clientHarness
    Copy-Item -LiteralPath 'scripts\windows-test-suites\service-acceptance.mjs' -Destination $clientHarness
    Set-Sddl $clientHarnessBase $clientHarnessSddl
    Invoke-Native 'scripts\sign-seawork-service.ps1' @(
        '-Mode', 'SignTestNode', '-ClientBinary', (Join-Path $clientHarness 'node.exe'),
        '-UseLocalMachineStore',
        '-PfxPath', $env:SEAWORK_WINDOWS_PFX_PATH,
        '-PasswordFile', $env:SEAWORK_WINDOWS_PFX_PASSWORD_FILE,
        '-ExpectedPublisherSubject', [string]$evidence.publisher_subject,
        '-ExpectedPublisherSha256', [string]$evidence.publisher_sha256
    ) 'test Node executable signing'

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
    Set-Sddl $stateRoot ("O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{0})" -f $serviceSid)
    New-Item -ItemType Directory -Path (Join-Path $stateRoot 'config') | Out-Null
    [ordered]@{
        schema_version = 1; config_revision = 1
        quotas = [ordered]@{ connections_global = 32; connections_per_user = 4; sandboxes_global = 8; sandboxes_per_user = 4; sandboxes_per_connection = 2; memory_mib_global = 24576 }
        publisher_thumbprints = @([string]$evidence.publisher_sha256)
        client_roots = @(Join-Path $programFiles 'SeaWork')
        maintenance_roots = @(Join-Path $programFiles 'SeaWork')
        egress_allow = @(); upstream_proxy = $null; ports_enabled = $false
    } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $stateRoot 'config\service.json') -Encoding utf8NoBOM
    Set-Sddl $stateRoot ("O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{0})" -f $serviceSid)
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
    Invoke-ClientSmoke $state -Mounts -Suffix 'direct-mounts'
    Invoke-ClientSmoke $state -Network -Suffix 'network'
    Invoke-ClientSmoke $state -Sequential -Suffix 'sequential'
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
            separate_account_profile_validated = $false
        }
        uac_after_install = $false
        compatibility_resources_restored = $true
    } |
        ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $RunRoot 'evidence-installed-smoke.json') -Encoding utf8NoBOM
}

function Smoke-Installed {
    $state = Read-InstallState
    if ((Get-Service -Name $serviceName).Status -ne 'Running') { Wait-ServiceState 'Running' 120 }
    $before = Get-CompatibilityResources
    Invoke-ClientSmoke $state -Mounts -Suffix 'post-reboot'
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

function Uninstall-Owned {
    $state = Read-InstallState
    $service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
    if ($null -ne $service) {
        if (-not $service.PathName.Contains([string]$state.service_binary, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing to remove a service whose ImagePath is not owned by this run.'
        }
        $serviceProcessId = [uint32]$service.ProcessId
        if ((Get-Service -Name $serviceName).Status -ne 'Stopped') {
            Stop-Service -Name $serviceName
            Wait-ServiceState 'Stopped' 60
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
    Assert-OwnerMarker (Join-Path $state.client_harness_base '.local-sandbox-agent-client.json') 'client-root'
    Assert-OwnerMarker (Join-Path $state.state_root '.local-sandbox-agent-state.json') 'state-root'
    Assert-OwnerMarker (Join-Path $state.client_data_root '.local-sandbox-agent-client-data.json') 'client-data-root'
    Remove-Item -LiteralPath $state.install_root -Recurse -Force -ErrorAction Stop
    Remove-Item -LiteralPath $state.client_harness_base -Recurse -Force -ErrorAction Stop
    Remove-Item -LiteralPath $state.state_root -Recurse -Force -ErrorAction Stop
    Remove-Item -LiteralPath $state.client_data_root -Recurse -Force -ErrorAction Stop
    Remove-Item -LiteralPath $installStatePath -Force -ErrorAction Stop
}

if ($MyInvocation.InvocationName -ne '.') {
    Assert-Administrator
    switch ($Mode) {
        'InstallAndSmoke' { Install-And-Smoke }
        'SmokeInstalled' { Smoke-Installed }
        'Uninstall' { Uninstall-Owned }
    }
}
