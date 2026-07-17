# SeaWork Windows service release and installation contract

This document is the operational contract for the LocalSandbox-owned Windows
service artifact and the SeaWork-owned installer. `plan.md` remains the design
source of truth. The generated `service-contract.json` is authoritative for
machine-consumed SCM, IPC, filesystem, health, and schema values.

## Release assets

Every enabled service release publishes these files under the same SemVer as
the LocalSandbox tag and Node packages:

```text
lsb-seawork-service-v<VERSION>-windows-x86_64.zip
  LocalSandbox/
    bin/localsandbox-seawork-service.exe
    runtime/{Image,initramfs.cpio.gz,rootfs.ext4,VERSION}
    tools/qemu/<complete pinned managed QEMU distribution>
    manifests/{bundle.json,service-contract.json,sbom.spdx.json}
    manifests/{runtime-dependencies.json,LocalSandboxSeaWork.cat}
    licenses/<LocalSandbox and third-party license/notice inventory>

lsb-seawork-service-v<VERSION>-windows-x86_64-symbols.zip
  LocalSandbox/bin/localsandbox-seawork-service.pdb
  LocalSandbox/manifests/source-map.json

SHA256SUMS
```

The payload ZIP is deterministic after signing. `bundle.json` is a sorted,
closed SHA-256 and size inventory; it excludes itself and the catalog to avoid
a hash cycle. The signed catalog covers both manifests and every other payload
file. The symbols ZIP is not installed. `runtime-dependencies.json` records the
signed service PE's `dumpbin /DEPENDENTS` result; releases fail if the service
imports a Visual C++ redistributable or any DLL not supplied by Windows.

## Release workflow

The service jobs in `.github/workflows/release.yml` run only when the repository
variable `SEAWORK_SERVICE_SIGNING_ENABLED` is exactly `true`. When disabled,
the existing CLI and OS-image release remains independent and no unsigned
service artifact is published.

Configure these repository variables:

| Name | Value |
| --- | --- |
| `SEAWORK_SERVICE_SIGNING_ENABLED` | `true` only after production signing and clean-machine gates are ready |
| `SEAWORK_PUBLISHER_SUBJECT` | Exact Authenticode certificate subject |
| `SEAWORK_PUBLISHER_SHA256` | Lowercase SHA-256 certificate thumbprint |
| `SEAWORK_TIMESTAMP_URL` | Organization-approved RFC 3161 timestamp URL |

Configure these repository secrets:

| Name | Value |
| --- | --- |
| `SEAWORK_CODESIGN_PFX_BASE64` | Base64 of the organization-controlled PFX |
| `SEAWORK_CODESIGN_PASSWORD` | PFX password |

The workflow builds the x64 service with a statically linked CRT and preserved
PDB, signs and timestamps the PE, records runtime and Cargo dependencies,
generates the SPDX/license inventory, stages the closed bundle, creates and
signs the catalog, builds deterministic payload/symbol ZIPs, verifies the
installed-layout bundle, emits checksums, creates GitHub artifact attestations,
and publishes the assets. Signing secrets exist only below `RUNNER_TEMP`.

Local manual signing may use
`scripts/sign-seawork-service.ps1 -AllowUntrustedTestCertificate -SkipTimestamp`
to test mechanics. Such output is test-only and must never be published. The
certificate currently available on this development machine was exercised only
in that test mode; it is not evidence of a production-trusted chain or timestamp.

## Consumer verification

SeaWork pins an exact tuple: Node package version, archive SHA-256, expected
publisher subject, and expected SHA-256 certificate thumbprint. Before copying,
its elevated installer must:

1. Verify the pinned archive digest and, where policy permits, GitHub attestation.
2. Reject absolute, drive, UNC, parent, ADS, duplicate, case-colliding, symlink,
   reparse, nonregular, excess-count, excess-expanded-size, and unlisted ZIP entries.
3. Verify the catalog trust chain, RFC 3161 timestamp, exact publisher, and every
   catalog member; verify the service's embedded signature independently.
4. Verify `bundle.json` closure, every listed size/hash, architecture, protocol,
   ledger/config compatibility, dependency report, and absence of unlisted EXEs
   or DLLs.
5. Extract only into a newly created administrator-only staging directory, copy
   to the final protected version directory, and repeat verification there.

The service provides a second installed-layout check:

```powershell
& "$VersionRoot\bin\localsandbox-seawork-service.exe" --verify-bundle --json
if ($LASTEXITCODE -ne 0) { throw 'installed bundle verification failed' }
```

This command verifies manifest closure and hashes. It does not replace SeaWork's
WinVerifyTrust/catalog-membership/archive checks.

## Install contract

SeaWork installs immutable versions below
`%ProgramFiles%\SeaWork\LocalSandbox\versions\<VERSION>` and keeps protected
state below `%ProgramData%\LocalSandbox\SeaWork`. It must not use a `current`
junction or a user-writable path. The stable service name is
`LocalSandboxSeaWork`; the pipe is `\\.\pipe\LocalSandbox.SeaWork.v1`.

Initial installation is one elevated transaction:

1. Verify and copy the immutable version, then apply the exact protected ACLs
   from `service-contract.json`.
2. Create the SCM service with every generated contract field, including quoted
   absolute ImagePath plus `--service`, LocalSystem, delayed automatic start,
   unrestricted service SID, service DACL, preshutdown timeout, failure actions,
   and Event Log source.
3. Create protected configuration/state and configure the signed maintenance
   client roots and publisher allowlist. Ordinary users never own or write them.
4. Start the service and use the upstream maintenance client for service info and
   health. Require publisher, bundle, protocol, ledger, ACL, WHPX, guest asset,
   and managed-QEMU checks. Record `reboot-required` rather than claiming success
   if the Windows virtualization prerequisite needs a reboot.
5. Record the installed bundle/client compatibility in protected SeaWork state.
   Normal app startup then connects without UAC and has no helper fallback.

The installer must atomically create
`%ProgramData%\LocalSandbox\SeaWork\config\service.json` before the first
service start. The directory and file use the protected state ACL from
`service-contract.json`; standard users receive no write access. A minimal
production configuration is:

```json
{
  "schema_version": 1,
  "config_revision": 1,
  "quotas": {
    "connections_global": 32,
    "connections_per_user": 4,
    "sandboxes_global": 8,
    "sandboxes_per_user": 4,
    "sandboxes_per_connection": 2,
    "memory_mib_global": 24576
  },
  "publisher_thumbprints": ["<40-or-64-hex-signer-thumbprint>"],
  "client_roots": ["C:\\Program Files\\SeaWork"],
  "maintenance_roots": ["C:\\Program Files\\SeaWork"],
  "ports_enabled": false
}
```

`client_roots` must contain the protected installed app binary that opens
normal sandbox sessions. `maintenance_roots` must contain only protected,
elevated installer/repair entry points. Every accepted binary must have a valid
Authenticode chain whose embedded signer matches `publisher_thumbprints`.
Empty roots or publishers intentionally keep normal admissions closed; an
empty maintenance root denies all maintenance calls. Host ports remain
compiled fail-closed, so setting `ports_enabled` to `true` is rejected.

NSIS must not implement the pipe protocol. It launches a narrow, protected,
signed SeaWork maintenance entry under the installer token; that entry calls the
upstream Node client, returns bounded JSON, and exits.

## Maintenance recipes

**Update.** Verify and stage the new immutable version. Call `PrepareUpdate` with
the exact target bundle and protocol range, drain, stop SCM, change the existing
service ImagePath, start the new version, require restricted health, then call
`CommitUpdate` with the opaque update ID. Keep the previous version until health
and commit succeed.

**Interrupted update and rollback.** Before ImagePath changes, call `AbortUpdate`.
After it changes but before commit, stop the health-only new service, restore the
old ImagePath, and restart it; the pending record keeps the old writer schema.
Rollback or downgrade is allowed only when the target ledger reader range covers
the on-disk schema. Never delete state to force compatibility.

**Repair.** Reverify the final catalog/files, restore exact ACLs and SCM/Event Log
configuration, reconcile protected state, restart, and health-check. Repair must
not import caller cleanup metadata or weaken authorization.

**Uninstall.** Call administrator-only `PrepareUninstall` and require a clean
drain/reconciliation result. Then stop and delete the SCM service, close handles,
remove the Event source and owned WFP configuration, and delete only verified
owned version/state paths. If ownership is ambiguous, retain the signed service
and protected state in health-only repair mode and report the exact quarantine;
never delete the cleanup authority first.

## Publisher rotation

Publisher rotation is an overlap, not an in-place pin bypass:

1. Ship a signed SeaWork installer/client that trusts both old and new publisher
   thumbprints and updates the protected maintenance allowlist.
2. Publish a release signed and timestamped by the new identity; its manifest
   names only that exact publisher.
3. Upgrade and health-verify the service using the normal update transaction.
4. Remove the old pin only after all supported rollback targets and deployed
   clients no longer require it. A compromised identity is handled by a new
   trusted installer release and explicit fleet remediation, never by disabling
   signature checks.

## Release checklist

- The tag, Rust service/client crates, Node packages, runtime `VERSION`, guest
  assets, and archive names use the same SemVer.
- The managed QEMU URL, package metadata, and SHA-256 match compiled metadata.
- CI tests, strict release Clippy, PowerShell parsing, deterministic archive test,
  installed bundle verification, dependency gate, SignTool PE/catalog trust and
  membership checks, checksums, and attestations pass.
- The production certificate chain and RFC 3161 timestamp verify on a clean
  Windows 11 x64 machine; publisher subject/thumbprint match repository config.
- SeaWork pins the archive/package tuple, rejects malicious ZIP structures, and
  repeats verification after final copy.
- Elevated install/update/rollback/repair/uninstall and unelevated standard-user
  use pass on a clean machine; the old helper is absent from production paths.
- Session 0 WHPX/QEMU boot/exec/stop, crash/reboot reconciliation, and enterprise
  Defender/EDR/GPO/proxy/VPN policy evidence are signed off. Mounts and host
  ports remain disabled; SMB and WFP evidence is required before enabling them.

## External release blockers

This repository cannot manufacture the following evidence in an unelevated
developer shell. They remain hard release blockers and are tracked in `state.md`
and `docs/windows-service-feasibility.md`:

- Production-trusted organization signing identity, RFC 3161 timestamp, and
  clean-machine chain/thumbprint verification.
- Real LocalSystem Session 0 WHPX/QEMU and prepared runtime/QEMU asset execution.
- Elevated two-user/two-logon SCM, Job, crash/reboot, update, rollback, repair,
  and uninstall acceptance. SMB/ACL/LSA acceptance additionally gates enabling
  the currently unavailable mount capability.
- Managed-fleet Defender/EDR, enterprise GPO, proxy/VPN, and certificate-policy
  review. Release is blocked on an incompatibility; controls are not bypassed.
