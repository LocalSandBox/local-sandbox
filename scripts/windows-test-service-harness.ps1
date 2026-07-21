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

function Invoke-Native {
    param([string] $Executable, [string[]] $Arguments, [string] $Label)
    & $Executable @Arguments
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

function Set-Sddl {
    param([string] $Path, [string] $Sddl)
    $raw = [Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
    $bytes = [byte[]]::new($raw.BinaryLength)
    $raw.GetBinaryForm($bytes, 0)
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetSecurityDescriptorBinaryForm($bytes)
    Set-Acl -LiteralPath $Path -AclObject $acl
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

function Wait-ServiceState {
    param([string] $State, [int] $Seconds)
    $service = Get-Service -Name $serviceName
    $service.WaitForStatus($State, [TimeSpan]::FromSeconds($Seconds))
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
    param([object] $State, [switch] $Mounts, [string] $Suffix)
    $clientData = Join-Path $State.client_data_root $Suffix
    New-Item -ItemType Directory -Path $clientData | Out-Null
    Set-Sddl $clientData ("O:BAG:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{0})" -f $State.test_user_sid)
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
    [ordered]@{
        bindingEntry = Join-Path $State.client_harness_root 'index.js'
        instanceId = "acceptance-$Suffix"
        mounts = $mountList
        resultPath = $resultPath
    } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $configPath -Encoding utf8NoBOM

    $taskName = "LocalSandboxAgent-$($State.run_id)-$Suffix"
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        throw 'The standard-user smoke task already exists.'
    }
    $action = New-ScheduledTaskAction `
        -Execute (Join-Path $State.client_harness_root 'node.exe') `
        -Argument ('"{0}" "{1}"' -f (Join-Path $State.client_harness_root 'service-acceptance.mjs'), $configPath) `
        -WorkingDirectory $State.client_harness_root
    $principal = New-ScheduledTaskPrincipal `
        -UserId "$env:COMPUTERNAME\$($State.test_user_name)" `
        -LogonType S4U `
        -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromMinutes(15))
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings | Out-Null
    try {
        Start-ScheduledTask -TaskName $taskName
        $deadline = [DateTime]::UtcNow.AddMinutes(12)
        do {
            Start-Sleep -Seconds 2
            if (Test-Path -LiteralPath $resultPath -PathType Leaf) { break }
        } while ([DateTime]::UtcNow -lt $deadline)
        if (-not (Test-Path -LiteralPath $resultPath -PathType Leaf)) {
            $info = Get-ScheduledTaskInfo -TaskName $taskName
            throw "The standard-user Node smoke did not produce a result (task code $($info.LastTaskResult))."
        }
        $result = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
        if ($result.status -ne 'passed') { throw 'The standard-user Node smoke reported failure.' }
        if ($Mounts) {
            if ((Get-Content -LiteralPath (Join-Path $output 'result.txt') -Raw) -cne 'nested-output' -or
                (Test-Path -LiteralPath (Join-Path $workspace 'forbidden.txt')) -or
                (Test-Path -LiteralPath (Join-Path $skills 'forbidden.txt')) -or
                (Test-Path -LiteralPath (Join-Path $uploads 'forbidden.txt'))) {
                throw 'The direct-mount host visibility or access-mode proof failed.'
            }
        }
        Copy-Item -LiteralPath $resultPath -Destination (Join-Path $RunRoot "evidence-node-$Suffix.json")
    }
    finally {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    }
}

function Install-And-Smoke {
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
    Assert-PlainDirectory $bundle 'signed staged bundle' | Out-Null
    New-Item -ItemType Directory -Path $versionRoot | Out-Null
    foreach ($entry in Get-ChildItem -LiteralPath $bundle -Force) {
        Copy-Item -LiteralPath $entry.FullName -Destination $versionRoot -Recurse
    }
    $serviceBinary = Join-Path $versionRoot 'bin\localsandbox-seawork-service.exe'
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
    Set-Sddl $clientHarnessBase 'O:BAG:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;RX;;;BU)'
    Invoke-Native 'scripts\sign-seawork-service.ps1' @(
        '-Mode', 'SignTestNode', '-ClientBinary', (Join-Path $clientHarness 'node.exe'),
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
    Invoke-Native sc.exe @('preshutdown', $serviceName, '60000') 'service preshutdown timeout'
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
    $eventKey = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\$serviceName"
    if (Test-Path -LiteralPath $eventKey) { throw 'Refusing to adopt an existing Event Log source.' }
    New-Item -Path $eventKey | Out-Null
    New-ItemProperty -Path $eventKey -Name EventMessageFile -Value $serviceBinary -PropertyType ExpandString | Out-Null
    New-ItemProperty -Path $eventKey -Name TypesSupported -Value 7 -PropertyType DWord | Out-Null
    New-ItemProperty -Path $eventKey -Name LocalSandboxAgentOwner -Value $owner -PropertyType String | Out-Null

    $userName = "LsbTr$($SnapshotSha.Substring(0, 8))"
    if (Get-LocalUser -Name $userName -ErrorAction SilentlyContinue) { throw 'The test standard user already exists.' }
    $random = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(24)) + 'aA1!'
    $secure = ConvertTo-SecureString $random -AsPlainText -Force
    $user = New-LocalUser -Name $userName -Password $secure -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword -Description "$owner $SnapshotSha"
    $random = $null; $secure = $null
    Set-Sddl $clientDataRoot ("O:BAG:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{0})" -f $user.SID.Value)
    $runId = Split-Path -Leaf ([IO.Path]::GetFullPath($RunRoot).TrimEnd('\'))
    [ordered]@{
        schema_version = 1; owner = $owner; snapshot_sha = $SnapshotSha; run_id = $runId
        version = $version; service_binary = $serviceBinary; install_root = $installRoot
        install_marker = $installMarker; state_root = $stateRoot; event_key = $eventKey
        client_harness_root = $clientHarness; client_harness_base = $clientHarnessBase
        client_data_root = $clientDataRoot; test_user_name = $userName; test_user_sid = $user.SID.Value
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $installStatePath -Encoding utf8NoBOM

    Invoke-Native sc.exe @('start', $serviceName) 'service start'
    Wait-ServiceState 'Running' 120
    $state = Read-InstallState
    $before = Get-CompatibilityResources
    Invoke-ClientSmoke $state -Suffix 'mount-free'
    Invoke-ClientSmoke $state -Mounts -Suffix 'direct-mounts'
    Assert-CompatibleResourcesRestored $before $stateRoot
    [ordered]@{ schema_version = 1; status = 'passed'; snapshot_sha = $SnapshotSha; production_identity = $true; standard_user = $true; uac_after_install = $false; compatibility_resources_restored = $true } |
        ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $RunRoot 'evidence-installed-smoke.json') -Encoding utf8NoBOM
}

function Smoke-Installed {
    $state = Read-InstallState
    if ((Get-Service -Name $serviceName).Status -ne 'Running') { Wait-ServiceState 'Running' 120 }
    $before = Get-CompatibilityResources
    Invoke-ClientSmoke $state -Mounts -Suffix 'post-reboot'
    Assert-CompatibleResourcesRestored $before $state.state_root
    [ordered]@{ schema_version = 1; status = 'passed'; snapshot_sha = $SnapshotSha; post_reboot = $true } |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $RunRoot 'evidence-post-reboot.json') -Encoding utf8NoBOM
}

function Uninstall-Owned {
    $state = Read-InstallState
    $service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
    if ($null -ne $service) {
        if (-not $service.PathName.Contains([string]$state.service_binary, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing to remove a service whose ImagePath is not owned by this run.'
        }
        if ((Get-Service -Name $serviceName).Status -ne 'Stopped') {
            Stop-Service -Name $serviceName
            Wait-ServiceState 'Stopped' 60
        }
        Invoke-Native sc.exe @('delete', $serviceName) 'service deletion'
    }
    if (Test-Path -LiteralPath $state.event_key) {
        if ((Get-ItemPropertyValue -LiteralPath $state.event_key -Name LocalSandboxAgentOwner) -ne $owner) { throw 'Event source ownership mismatch.' }
        Remove-Item -LiteralPath $state.event_key -Recurse -Force
    }
    $user = Get-LocalUser -Name $state.test_user_name -ErrorAction SilentlyContinue
    if ($null -ne $user) {
        if ($user.Description -ne "$owner $SnapshotSha") { throw 'Test user ownership mismatch.' }
        Remove-LocalUser -Name $state.test_user_name
    }
    Assert-OwnerMarker $state.install_marker 'install-root'
    Assert-OwnerMarker (Join-Path $state.client_harness_base '.local-sandbox-agent-client.json') 'client-root'
    Assert-OwnerMarker (Join-Path $state.state_root '.local-sandbox-agent-state.json') 'state-root'
    Assert-OwnerMarker (Join-Path $state.client_data_root '.local-sandbox-agent-client-data.json') 'client-data-root'
    Remove-Item -LiteralPath $state.install_root -Recurse -Force
    Remove-Item -LiteralPath $state.client_harness_base -Recurse -Force
    Remove-Item -LiteralPath $state.state_root -Recurse -Force
    Remove-Item -LiteralPath $state.client_data_root -Recurse -Force
}

Assert-Administrator
switch ($Mode) {
    'InstallAndSmoke' { Install-And-Smoke }
    'SmokeInstalled' { Smoke-Installed }
    'Uninstall' { Uninstall-Owned }
}
