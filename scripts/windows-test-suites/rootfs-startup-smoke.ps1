param([string]$Phase,[string]$RunRoot,[string]$SnapshotSha,[string]$ReuseRunId='')
& "$PSScriptRoot\..\windows-test\compat-suite.ps1" -Category runtime -Suite rootfs-startup-smoke @PSBoundParameters
