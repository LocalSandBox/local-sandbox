# Windows Risk Register

Track Windows backend risks here. Update this file when evidence changes a risk.

| ID | Risk | Impact | Likelihood | Mitigation | Status | Owner |
|---|---|---:|---:|---|---|---|
| R001 | QEMU + WHPX availability varies across Windows machines | High | Medium | Strict preflight; actionable diagnostics; Windows 11 x64 support boundary | Open | TBD |
| R002 | Virtio-serial named pipe behavior differs across QEMU versions | High | Medium | Self-hosted WHPX smoke proved current pipe ordering; host connects during boot and keeps established stream | Mitigating | TBD |
| R003 | Guest transport regression from adding virtio-serial beside vsock | High | Low | Guest keeps macOS vsock path; Windows readiness/exec smokes validate virtio-serial | Retired | TBD |
| R004 | Windows filesystem semantics differ from macOS VirtioFS overlay semantics | High | High | Snapshot import/export MVP; conservative reparse/hardlink/case-collision policy; document no live sync | Open | TBD |
| R005 | Windows proxy attachment could bypass LocalSandbox policy | High | Medium | Windows uses LocalSandbox-owned loopback stream netdev, rejects legacy fd/socketpair/non-loopback paths, and tests direct-IP/forged-host denial | Mitigating | TBD |
| R006 | Windows checkpoint store lacks CAS/NBD parity | Medium | High | MVP uses flattened qcow2 artifacts; future storage work must choose CAS/NBD, qcow2 chains, or another deduplicated format | Accepted | TBD |
| R007 | Hosted CI cannot run WHPX | Medium | High | Hosted CI is compile/unit/golden only; manual self-hosted Windows 11 runner covers WHPX runtime | Accepted | Maintainer |
| R008 | QEMU binary provenance/security if user-installed | Medium | Medium | Discovery diagnostics record path/version; decide bundling/signing or a stronger provenance policy before broader release hardening | Open | TBD |
| R009 | Process cleanup leaves QEMU running after host crash/test timeout | High | Medium | Windows Job Object cleanup; fake process tests; periodic runner process checks | Mitigating | TBD |
| R010 | Network policy bypass through accidental NIC/user networking | High | Medium | Golden/unit/smoke coverage asserts `-nic none` by default, stream proxy only for allow-net, no QEMU user networking/hostfwd/TAP/bridge | Mitigating | TBD |
| R011 | Public API drift while adding Windows capability errors | Medium | Medium | API-shape tests; keep platform-specific detail below SDK/CLI/Node surfaces | Open | TBD |
| R012 | Boot asset compatibility differs between QEMU and Apple VZ | High | Medium | Self-hosted boot smoke; x86_64 serial console config; preserve guest asset invariants | Mitigating | TBD |
| R013 | Default self-hosted Windows labels can route cache probe and smoke jobs to different machines if runner pool grows | Medium | Medium | Current docs record the single-runner assumption, keep the workflow off pull requests, and limit automatic hardware execution to trusted `main` e2e runs. Add a dedicated label or disable local-cache skip path before adding runners. | Open | Maintainer |
| R014 | Missing mux/session model blocks streaming spawn, shell, watch, and concurrent forwarding | Medium | High | Keep unsupported errors precise; design mux/session model before enabling those APIs | Open | TBD |
| R015 | Final QEMU minimum version is not pinned | Medium | Medium | Test supported QEMU versions on self-hosted WHPX; document minimum before public release | Open | Release owner |

## Status values

- `Open`: active risk.
- `Mitigating`: implementation reduces but does not eliminate the risk.
- `Accepted`: known tradeoff accepted for the current support level.
- `Retired`: validation or implementation materially removed the risk.

## Adding risks

Add a risk when implementation or review discovers uncertainty that affects
security, product semantics, CI reliability, release readiness, or user-visible
support boundaries.
