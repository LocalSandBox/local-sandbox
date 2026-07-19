# Windows service feasibility evidence

This document records the reproducible Phase 0 gate for the SeaWork Windows service. An ordinary elevated console run is not evidence: the harness must run through SCM as `LocalSystem` in Session 0.

## Harness

Prerequisites:

- Disposable x86-64 Windows 11 machine with virtualization enabled and WHPX available.
- Elevated PowerShell, Rust MSVC toolchain, LocalSandbox runtime assets, QEMU bundle, and running `BFE`/`LanmanServer` services.
- At least 8 GiB free RAM and 20 GiB free disk.
- For the full matrix, two standard users plus a second logon session of the owner, IPv4/IPv6 loopback, and a managed SeaWork machine with its normal proxy/VPN/EDR policy.

Run the core Session 0 probe:

```powershell
.\scripts\windows-service-spike.ps1 `
  -DataDir C:\path\to\prepared\localsandbox `
  -TestMounts -TestWatches -TestNetwork
```

The script builds the ignored nonshipping service, registers `LocalSandboxSeaWorkSpike` as `LocalSystem`, waits for a typed JSON result under `%ProgramData%\LocalSandbox\SeaWorkSpike`, prints the checks, and deletes the SCM registration. Machine-specific configs, results, and binaries are not committed.

Validate a retained result against the integration contract:

```powershell
$env:LSB_SESSION0_SPIKE_RESULT = 'C:\ProgramData\LocalSandbox\SeaWorkSpike\result-<run>.json'
cargo test -p lsb-service-spike --features windows-session0-spike --test windows_session0 -- --ignored
```

Release-candidate results must additionally be assembled and validated with the
digest-bound contract in `docs/windows-acceptance-evidence.md`. The Phase 0 spike JSON
alone is not release evidence: the final `win01` or `full` profile must be tied to the
exact production artifact SHA-256, contain only explicitly redacted retained files, and
pass `verify-windows-evidence --require-complete`.

The manual `Windows service self-hosted acceptance` workflow runs the same
harness on an elevated disposable runner labeled `self-hosted`, `Windows`,
`X64`, and `seawork-service`. Its required `data_dir` input must name prepared,
protected runtime assets on that machine. The workflow uploads the typed result
as evidence but does not convert a blocked managed-fleet check into a pass.

## Result schema

Schema version 1 records service/process identity, Session ID, token SID, explicit runtime path usage, SDK version, duration and status for each probe, plus the fail-closed host-port capability decision. Status is one of `passed`, `failed`, `blocked`, or `not_run`. Generate an example with:

```powershell
cargo run -p lsb-service-spike --features windows-session0-spike -- --schema
```

## Current evidence

No real SCM run has been completed in this repository yet. On 2026-07-20 the effective tool token was rechecked with `whoami /all`: it is a medium-integrity standard-user token in `BUILTIN\\Users`, not Administrators, and has only `SeChangeNotifyPrivilege` enabled. The surrounding PowerShell session's elevation is therefore not evidence for the tool process, and no SCM registration, LocalSystem, disposable-user, SMB/LSA, WFP, installer, destructive-lifecycle, or reboot test was attempted without a separate explicit elevation approval.

The following decisions unblock implementation without claiming evidence that does not exist:

- Host ports remain disabled for v1 because logon-SID WFP isolation is not implemented or proven.
- The production platform QEMU supervisor now starts the child suspended, assigns its kill-on-close Job, and resumes only afterward. A separately approved standard-token development run proved that the fake child's first instruction observes Job containment and that dropping the Job terminates a spawned grandchild tree. This is source-level CON-01 evidence, not SCM/LocalSystem, nested-enterprise-Job, service-deadline, or production-artifact evidence; the service still does not hold the external Job handle required to force-close a stuck VM thread.
- Managed proxy/VPN/Defender/EDR compatibility remains a downstream fleet validation item.
- Direct RW in the spike exercises existing SMB behavior only. Production direct RW remains disallowed; Phase 3 must use staged-sync.

## Sign-off matrix

| Evidence | Status | Result/run | Owner notes |
| --- | --- | --- | --- |
| LocalSystem SID and Session 0 | Pending real-machine run | | |
| WHPX/QEMU boot, exec, stop | Pending real-machine run | | |
| Direct RO/RW SMB and watches | Pending real-machine run | | Spike-only existing behavior; production RW stays staged-sync |
| Full user/share/right/ACE teardown | Pending real-machine inspection | | |
| Crash/forced-stop/reboot cleanup | Pending Phase 3 ledger/reconciliation | | Existing caller-owned manifests are not production authority |
| Suspended-start kill-on-close QEMU Job | Development test passed | Current source test binary; 2026-07-20 | 14/14 QEMU process tests; child entrypoint was already contained and Job drop terminated its grandchild |
| Nested/service-authoritative QEMU Job | Pending privileged SCM/LocalSystem run | | External service Job handle, nested enterprise Job, forced-stop deadline, crash, reboot, and exact production artifact remain required |
| IPv4/IPv6 WFP logon isolation | Disabled for v1 | | `PORT_ISOLATION_UNAVAILABLE` |
| Proxy/VPN/certificate behavior | Pending managed-machine run | | |
| Defender/EDR behavior | Pending managed-machine run | | |

Phase 0 is not signed off until a Windows owner attaches a result and records the environment/build/policy identifiers above. Per the implementation guidelines, unavailable hardware/elevation checks are tracked here rather than preventing source progress.
