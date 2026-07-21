# Windows agent testing over SSH

The macOS coding checkout remains authoritative. Tests run on the dedicated Windows 11
x64 host selected by the `win-test` SSH alias. The Windows directories below are owned
exclusively by the agent test flow and may be reset or cleaned by its scripts:

```text
C:\dev\local-sandbox-agent\
  mirror.git             private Git mirror populated directly over SSH
  repo                   disposable checkout of one exact test snapshot
  cache\cargo-target     persistent Cargo build cache

C:\ProgramData\LocalSandbox\DevTest\
  assets                 persistent, operator-provided runtime assets
  locks                  exclusive host-runner lock
  runs\<run-id>           logs, phase results, and reboot continuation state
```

`plan.md`, `state.md`, and `backlog.md` are not part of this testing setup.

## Ready-to-use commands

The host is already initialized. A subsequent agent can immediately run:

```bash
# Validate source sync, exact checkout, host tools, Windows 11, WHPX, and reboot-safe SSH.
scripts/win-test preflight

# Run any native command from the repository root on Windows.
scripts/win-test run -- cargo test -p lsb-service-proto --locked
scripts/win-test run -- cargo check -p lsb-seawork-service --locked

# Run a named repository suite.
scripts/win-test suite service-fast
```

Set `WIN_TEST_HOST` to use an SSH alias other than `win-test`. Commands and arguments are
transported as a base64-encoded, NUL-delimited argument vector; they are never evaluated
as a PowerShell expression.

## Source synchronization

Every invocation creates a synthetic Git commit from the complete current macOS working
tree, including tracked edits and non-ignored untracked files. It uses a temporary Git
index, so it does not modify the current branch, the real index, or the working tree.
Ignored build products and local assets are deliberately excluded.

The synthetic commit is pushed directly over SSH to a run-specific ref in the private
Windows bare mirror. A stable base ref lets later pushes negotiate incremental object
transfers. Nothing is pushed to `origin`. The Windows bootstrap serializes runs with an
exclusive file lock, fetches that exact ref, verifies its 40-character SHA, then
hard-resets and cleans only the dedicated checkout. The persistent Cargo cache and test
results are outside that checkout.

Each invocation prints its run ID and snapshot SHA. Windows records are retained under
`C:\ProgramData\LocalSandbox\DevTest\runs\<run-id>`. These are developer diagnostics,
not automatically release-qualified evidence; inspect and redact them before using the
separate Windows acceptance-evidence flow.

## Adding focused suites

Focused test selection belongs to the agent implementing a feature. Add a script named
`scripts/windows-test-suites/<suite-name>.ps1` with this contract:

```powershell
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Normal', 'BeforeReboot', 'AfterReboot')]
    [string] $Phase,

    [Parameter(Mandatory = $true)]
    [string] $RunRoot,

    [Parameter(Mandatory = $true)]
    [string] $SnapshotSha
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($Phase -ne 'Normal') {
    throw 'This suite does not support reboot phases.'
}

& cargo test -p example-crate --locked
if ($LASTEXITCODE -ne 0) {
    throw "cargo test failed with exit code $LASTEXITCODE"
}
```

Run it with `scripts/win-test suite <suite-name>`. Suite scripts must throw when a
PowerShell operation fails and must explicitly check native process exit codes.

## Reboot-spanning suites

A reboot suite uses the same script contract and handles `BeforeReboot` and
`AfterReboot` separately:

```bash
scripts/win-test reboot service-recovery
```

An infrastructure-only smoke suite is included for an intentional end-to-end reboot
check: `scripts/win-test reboot reboot-smoke`. Running it really reboots the laptop.

The bootstrap runs the pre-reboot phase, atomically writes an `awaiting_reboot`
continuation containing the run ID, snapshot SHA/ref, suite, and old Windows boot
identity, and only then schedules `shutdown.exe`. The macOS wrapper waits up to 15
minutes for SSH and requires the Windows boot identity to change before invoking the
post-reboot phase. Merely restarting `sshd` cannot satisfy this check.

If the macOS agent or terminal is interrupted, resume without creating a new snapshot:

```bash
scripts/win-test resume <run-id>
```

The installed bootstrap re-reads protected continuation state, verifies that a reboot
occurred, restores the exact snapshot, and runs `AfterReboot`. This flow assumes the
test does not disable automatic `sshd`; tests that intentionally break SSH need an
external scheduled-task or console orchestrator.

If Windows has not returned within 10 minutes, the coding agent must stop polling,
preserve the run ID and continuation state, pause any active goal, end its turn, and wait
for human intervention. It must not attempt another reboot, power-cycle the laptop, or
otherwise broaden recovery actions without explicit direction.

## Host setup and verification

Setup is idempotent and refuses to adopt non-empty directories that lack its ownership
marker. It requires elevated SSH, Windows 11 x64, an active hypervisor, WHPX, automatic
and running `sshd`, Git, Rust with the MSVC target, CMake, and PowerShell 7. It protects
the roots so only the connected setup user, Administrators, and LocalSystem have access.

Re-run setup or its non-mutating verification when host configuration changes:

```bash
scripts/win-test setup
scripts/win-test verify
```

The setup command stages only the setup/bootstrap files in a unique Windows temporary
directory, installs them into the dedicated root, verifies the complete installation,
then removes that exact staging directory.
