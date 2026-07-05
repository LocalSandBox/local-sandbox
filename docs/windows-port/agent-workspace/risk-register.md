# Windows Port Risk Register

Track implementation risks here. Update as evidence arrives.

| ID | Risk | Impact | Likelihood | Mitigation | Status | Owner |
|---|---|---:|---:|---|---|---|
| R001 | QEMU + WHPX availability varies across Windows machines | High | Medium | Strict M02 preflight; clear diagnostics; Windows 11 MVP only | Open | TBD |
| R002 | Virtio-serial named pipe behavior differs from expectation on Windows | High | Medium | M06 self-hosted WHPX smoke showed QEMU `-chardev pipe` blocks boot until a host client connects; LocalSandbox now connects during boot and keeps the established stream. Keep validating across QEMU versions. | Mitigating | TBD |
| R003 | Current guest assumes vsock-only control | High | High | M06 added `lsb-guest` transport selection and virtio-serial port discovery while preserving vsock; WHPX smoke proved the guest selects virtio-serial and opens `/dev/vport1p1`. Retire after M07 proves framed ready/control exchange over the opened stream. | Mitigating | TBD |
| R004 | Windows filesystem semantics differ from current VirtioFS overlay semantics | High | High | MVP copy-in/copy-out; document limits; conformance tests | Open | TBD |
| R005 | Existing `lsb-proxy` depends on Unix socketpair/file-handle network attachment | High | High | M12 adds a Windows QEMU stream attachment backed by a LocalSandbox-owned loopback listener and rejects legacy fd/socketpair attachments on Windows. No QEMU NAT is enabled by default. | Mitigating | TBD |
| R006 | CAS/NBD store depends on Unix domain sockets | Medium | High | Implement simple Windows checkpoint artifacts first; port CAS/NBD later | Open | TBD |
| R007 | CI cannot run WHPX on hosted runners | Medium | High | Use self-hosted Windows 11 runner for boot/integration | Accepted | Maintainer |
| R008 | QEMU binary provenance/security if user-installed | Medium | Medium | Discovery diagnostics; warn on suspicious paths; consider bundling later | Open | TBD |
| R009 | Process cleanup leaves QEMU running after host crash/test timeout | High | Medium | Windows Job Object cleanup in M04; tests with fake child processes | Open | TBD |
| R010 | Network policy bypass through accidental NIC/user networking | High | Medium | M12 golden/unit tests assert default `-nic none`, policy-mediated `-netdev stream` only when allow-net/proxy is configured, no QEMU user networking/hostfwd/TAP/bridge, DNS-answer binding for explicit allowlists, forged Host/SNI denial to arbitrary IPs, direct-IP and missing-domain denial, and fail-closed unsupported Windows attachment modes. | Mitigating | TBD |
| R011 | Public API drift while adding Windows capability errors | Medium | Medium | Compile/API compatibility tests; keep errors structured below API boundary | Open | TBD |
| R012 | Boot asset compatibility with QEMU differs from Apple VZ | High | Medium | M05 minimal direct boot smoke; update kernel/initramfs only behind preserved semantics | Open | TBD |

## Risk status values

- `Open`: active risk.
- `Mitigating`: work in progress.
- `Accepted`: known and accepted by decision.
- `Retired`: validation removed or materially reduced the risk.

## Adding risks

Add a risk when an implementation issue discovers uncertainty that affects security, product semantics, CI, or milestone ordering. Include the milestone where it was discovered in the mitigation notes.
