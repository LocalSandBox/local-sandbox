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

# Provision the two external signing inputs without adding them to a snapshot.
SEAWORK_WINDOWS_PFX_PATH=/absolute/private/SeaWork-CodeSign.pfx \
SEAWORK_WINDOWS_PFX_PASSWORD_FILE=/absolute/private/win_csc_key_password.txt \
scripts/win-test provision-signing
scripts/win-test verify-signing

# If the same two files already exist on the Windows test host, copy them locally into
# the protected asset transaction instead of transferring them over SSH.
SEAWORK_WINDOWS_SIGNING_SOURCE_ROOT='C:/Users/Public/code/private' \
  scripts/win-test provision-signing-windows
scripts/win-test verify-signing

# Provision source-built guest assets plus the pinned, hash-verified QEMU package.
LSB_WINDOWS_RUNTIME_ROOT=/absolute/path/to/runtime scripts/win-test provision-runtime
scripts/win-test verify-runtime

# Build a signed candidate, or build/install/exercise/uninstall it in one bounded run.
scripts/win-test suite release-candidate
scripts/win-test suite installed-service-smoke

# Fetch only manifest-listed release artifacts and redacted JSON evidence.
scripts/win-test fetch <run-id> <new-local-directory>
```

Set `WIN_TEST_HOST` to use an SSH alias other than `win-test`. Commands and arguments are
transported as a base64-encoded, NUL-delimited argument vector; they are never evaluated
as a PowerShell expression.

Signing provisioning creates a unique protected staging directory below
`C:\ProgramData\LocalSandbox\DevTest\assets`, transfers the PFX and password directly
over SSH, validates their bounded shape and certificate, and atomically installs them at
`assets\signing`. It refuses reparse points, loose ACLs, an existing destination, and
unowned roots. Output contains only presence/ACL status plus the public certificate
subject and SHA-256 thumbprint. The signing path temporarily imports the certificate
into the invoking user's certificate store so the password is never placed on the
SignTool command line, then removes the imported certificate and private key.

Runtime provisioning is independent of signing. It transfers only `Image`,
`initramfs.cpio.gz`, and `rootfs.ext4`, downloads the repository-pinned managed QEMU
archive on Windows, verifies its SHA-256, and installs the closed runtime/QEMU roots
under the protected test asset directory. It refuses existing or unowned destinations.

Artifact fetch reads `fetch-manifest.json` from one exact run and accepts only the
release manifest/checksums, service ZIPs, Node package tarballs, and redacted JSON
evidence named by its closed filename allowlist. Every file is size- and SHA-256-checked
after transfer. Logs, arbitrary run files, and the persistent asset tree are not
fetchable through this command.

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

The test-release suites are:

- `service-fast`: focused Rust tests, scoped Clippy, Node compilation, API-shape tests,
  and declaration typechecking;
- `release-candidate`: production-profile static-CRT build, trusted timestamped PE and
  catalog signing, closed archives, and a fetch manifest;
- `installed-service-smoke`: candidate construction plus an owned production-identity
  install, signed Node binding execution as a temporary standard user, mount-free and
  four-mount smoke, compatibility-resource proof, and uninstall; and
- `service-reboot`: the same owned install before reboot, delayed automatic startup and
  a post-reboot signed standard-user smoke, followed by uninstall.

The install harness refuses an existing service, Event Log source, install/state/client
root, test user, or scheduled task that it cannot prove belongs to its exact run. It is
dedicated-laptop test infrastructure, not a replacement for SeaWork's NSIS transaction.

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
