# Controlled SeaWork update evidence contract

Controlled self-upgrade evidence is retained separately from the existing service
acceptance evidence under:

```text
artifacts/windows-update-evidence/
  <source-git-sha>/<service-archive-sha256>/<helper-binary-sha256>/
    manifest.json
    evidence/*.redacted.*
```

This is a source and operator contract only. It does not change
`.github/workflows/release.yml`, and an unsigned local or cross-compiled run is not
Windows acceptance evidence.

Manifest schema 2 binds one immutable GitHub release ID/tag, the exact service archive and
preinstalled helper binary and queried helper protocol, the exact accepted publisher SHA-256 identity, the source
commit, the previous and candidate bundle identities, and hashed runner/policy
identities. The validator rehashes every retained evidence file and, when supplied,
both artifacts.

## Required result matrix

The `cases` array must contain exactly these IDs:

- `update.stable_channel`
- `update.prerelease_channel`
- `update.indefinite_busy_wait`
- `update.idle_admission_race`
- `update.activation_success`
- `update.health_rollback`
- `update.untrusted_and_incompatible_rejection`
- `update.failed_target_suppression`
- `update.seawork_repair`
- `update.seawork_uninstall`

The `phase_coverage` array must contain every nonterminal durable helper phase from
`prepared` through `old_service_restarted`. Each row independently records
`helper_crash` and `reboot` status, so one happy-path result cannot stand in for the
crash/power-loss matrix. Every case and phase row references one or more retained,
explicitly redacted files.

Statuses are `passed`, `failed`, `blocked`, or `not_run`. A non-passing result requires
a stable bounded code. Incomplete manifests are valid handoff records; only
`--require-complete` requires every case and both recovery modes at every phase to have
passed.

## Assemble on the authorized Windows host

The result document contains top-level `cases` and `phase_coverage` arrays. Evidence
references use the final form `evidence/<filename>`, and the result filename itself
must include `.redacted`.

```powershell
.\scripts\assemble-seawork-update-evidence.ps1 `
  -ServiceArchivePath C:\protected\lsb-seawork-service-v0.5.1-windows-x86_64.zip `
  -HelperBinaryPath 'C:\Program Files\SeaWork\LocalSandbox\updater\localsandbox-seawork-updater.exe' `
  -ResultsPath C:\evidence\update-results.redacted.json `
  -PreviousBundleIdentityPath C:\evidence\previous-bundle.json `
  -CandidateBundleIdentityPath C:\evidence\candidate-bundle.json `
  -ReleaseId 123456 -ReleaseTag v0.5.1 `
  -PublisherSha256 <64-lowercase-hex> `
  -RunnerIdentity '<operator-supplied runner identity>' `
  -PolicyFingerprint '<operator-supplied policy description>' `
  -EvidenceFiles C:\evidence\event-log.redacted.json,C:\evidence\journal-phases.redacted.json `
  -RequireComplete
```

Standalone validation is:

```powershell
cargo run -p xtask --locked -- verify-seawork-update-evidence `
  --manifest <manifest-path> `
  --service-archive <exact-service-zip> `
  --helper <exact-installed-helper-exe> `
  --require-complete
```

Before assembly, the script requires the helper's complete `--verify-install --json`
self-check, a valid timestamped Authenticode signature, and an exact signer-certificate
SHA-256 match with `-PublisherSha256`; a version-only helper query is not evidence.

The Windows operator must obtain the cases using the exact signed production-profile
tuple and the SeaWork-installed SCM entries. Helper termination is injected only after
the named journal phase has been durably observed; reboot coverage uses an actual boot
identity change. The retained records must show exact ImagePath/EventMessageFile,
restricted health/commit or rollback, admissions, last-known-good preservation, and
standard-user no-UAC outcomes without retaining raw usernames, SIDs, machine names,
paths, command lines, environments, credentials, or response bodies.
