param([string]$Phase,[string]$RunRoot,[string]$SnapshotSha,[string]$ReuseRunId='')
& "$PSScriptRoot\..\windows-test\compat-suite.ps1" -Category release -Suite updater-release-smoke @PSBoundParameters
