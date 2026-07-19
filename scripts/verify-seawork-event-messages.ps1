[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ServiceBinary,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Utf8NoBom = [Text.UTF8Encoding]::new($false)
$script:ExpectedMessageIds = 1..16

if (-not $IsWindows) {
    throw 'event message verification requires Windows'
}

$binary = (Resolve-Path -LiteralPath $ServiceBinary -ErrorAction Stop).Path
$binaryItem = Get-Item -LiteralPath $binary -Force
if ($binaryItem.PSIsContainer -or ($binaryItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'ServiceBinary must be a regular non-reparse file'
}

$output = [IO.Path]::GetFullPath($OutputPath)
if (Test-Path -LiteralPath $output) {
    throw "refusing to overwrite event-message evidence: $output"
}
$outputParent = Split-Path -Parent $output
if ([string]::IsNullOrWhiteSpace($outputParent)) {
    throw 'OutputPath must have a parent directory'
}
[void](New-Item -ItemType Directory -Path $outputParent -Force)

if ($null -eq ('LocalSandbox.EventMessageNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace LocalSandbox {
    public static class EventMessageNative {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr LoadLibraryExW(string fileName, IntPtr file, uint flags);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern uint FormatMessageW(
            uint flags,
            IntPtr source,
            uint messageId,
            uint languageId,
            StringBuilder buffer,
            uint size,
            IntPtr arguments);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool FreeLibrary(IntPtr module);
    }
}
'@
}

$loadLibraryAsDataFile = 0x00000002
$loadLibraryAsImageResource = 0x00000020
$formatMessageFromHmodule = 0x00000800
$formatMessageIgnoreInserts = 0x00000200
$formatMessageMaxWidthMask = 0x000000FF
$module = [LocalSandbox.EventMessageNative]::LoadLibraryExW(
    $binary,
    [IntPtr]::Zero,
    $loadLibraryAsDataFile -bor $loadLibraryAsImageResource
)
if ($module -eq [IntPtr]::Zero) {
    throw "LoadLibraryExW failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
}

$verified = [Collections.Generic.List[uint32]]::new()
try {
    foreach ($messageId in $script:ExpectedMessageIds) {
        $buffer = [Text.StringBuilder]::new(2048)
        $length = [LocalSandbox.EventMessageNative]::FormatMessageW(
            $formatMessageFromHmodule -bor $formatMessageIgnoreInserts -bor $formatMessageMaxWidthMask,
            $module,
            [uint32]$messageId,
            0x0409,
            $buffer,
            [uint32]$buffer.Capacity,
            [IntPtr]::Zero
        )
        if ($length -eq 0 -or [string]::IsNullOrWhiteSpace($buffer.ToString())) {
            throw "embedded event message $messageId is unavailable"
        }
        $verified.Add([uint32]$messageId)
    }

    $unexpected = [Text.StringBuilder]::new(256)
    $unexpectedLength = [LocalSandbox.EventMessageNative]::FormatMessageW(
        $formatMessageFromHmodule -bor $formatMessageIgnoreInserts -bor $formatMessageMaxWidthMask,
        $module,
        17,
        0x0409,
        $unexpected,
        [uint32]$unexpected.Capacity,
        [IntPtr]::Zero
    )
    if ($unexpectedLength -ne 0) {
        throw 'the embedded event catalog contains an unreviewed message ID 17'
    }
} finally {
    if (-not [LocalSandbox.EventMessageNative]::FreeLibrary($module)) {
        throw "FreeLibrary failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
}

$evidence = [ordered]@{
    schema_version = 1
    service_sha256 = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
    language_id = '0x0409'
    message_ids = @($verified)
    first_unassigned_message_id = 17
}
[IO.File]::WriteAllText(
    $output,
    ($evidence | ConvertTo-Json -Depth 5) + "`n",
    $script:Utf8NoBom
)
$evidence | ConvertTo-Json -Compress
