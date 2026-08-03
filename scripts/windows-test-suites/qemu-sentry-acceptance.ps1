param([string]$Phase,[string]$RunRoot,[string]$SnapshotSha,[string]$ReuseRunId='')
& "$PSScriptRoot\..\windows-test\compat-suite.ps1" -Category diagnostics -Suite qemu-sentry-acceptance @PSBoundParameters
