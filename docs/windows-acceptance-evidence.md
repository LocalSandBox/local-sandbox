# Windows acceptance evidence contract

Windows runtime results are retained under the exact digest-bound layout
`artifacts/windows-evidence/<git-sha>/<artifact-sha256>/`. Each directory contains one
`manifest.json` and one or more files below `evidence/`. The manifest records only safe
version/build fields, hashes of runner/policy identity, closed check identifiers, stable
statuses/codes, durations, and hashes/sizes of files that are explicitly declared
redacted. It never records raw user or logon SIDs, usernames, machine/runner names, full
paths, certificate identifiers, corporate-network names, credentials, commands,
arguments, environment, guest output, or file content.

The assembler refuses to overwrite an existing digest directory and rejects evidence
that contains common raw SID, absolute/UNC path, credential, certificate, machine, or
user fields. Evidence inputs must use a `.redacted` filename component so redaction is
an explicit producer contract rather than an assumption made during upload.

Create and validate an incomplete WIN-01 handoff (blocked checks remain visible):

```powershell
.\scripts\assemble-windows-evidence.ps1 `
  -Profile win01 `
  -ArtifactPath C:\protected\lsb-seawork-service-v0.4.6-windows-x86_64.zip `
  -CheckResultsPath C:\evidence\checks.redacted.json `
  -EvidenceFiles C:\evidence\session0.redacted.json `
  -ServiceVersion 0.4.6 -BundleVersion 0.4.6 -QemuVersion 11.0.50 `
  -RunnerIdentity '<operator-supplied runner identity>' `
  -PolicyFingerprint '<operator-supplied policy description>'
```

For a release gate, add `-RequireComplete`. The validator then requires every check in
the selected `win01`, `security`, or `full` profile—and every additional listed
check—to be `passed`. `failed`, `blocked`, and `not_run` results require a bounded stable
code and are valid only for an incomplete handoff. Every check must reference at least
one listed evidence file, and every evidence file's type, size, SHA-256, relative path,
case uniqueness, and redaction declaration are revalidated.

The standalone validation command is:

```powershell
cargo run -p xtask --locked -- verify-windows-evidence `
  --manifest artifacts\windows-evidence\<git-sha>\<artifact-sha256>\manifest.json `
  --require-complete
```

This validator proves schema closure, artifact/commit layout binding, result coverage,
and retained-file integrity. It does not prove that the signed artifact actually ran,
that a claimed pass is truthful, or that a runner is disposable/managed. CI must pair
it with protected runner provenance and artifact attestations before publication.
