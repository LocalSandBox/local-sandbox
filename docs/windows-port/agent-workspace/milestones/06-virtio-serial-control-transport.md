# M06: Virtio-Serial Control Transport

Status: Done
Depends on: See `00-index.md`
RFC sections: See `traceability.md`

## Objective

Connect host and guest using the existing `lsb-proto` frames over virtio-serial.

## Scope

- Add guest transport abstraction: vsock for macOS remains, virtio-serial for Windows added.
- Configure QEMU virtio-serial device and port.
- Use private Windows named pipe or chosen QEMU chardev backend.
- Implement host-side async stream wrapper.
- Add simple ping/echo or protocol-level smoke if available.

## Out of scope

- Do not replace `lsb-proto`.
- Do not adopt QGA for LocalSandbox guest APIs.
- Do not use hostfwd TCP as production control path.
- Do not break macOS vsock transport.

## Likely files / crates

- `crates/lsb-guest/src/main.rs` or transport modules
- `crates/lsb-platform/src/windows_x86_64/control/virtio_serial.rs`
- `crates/lsb-proto` only for transport-neutral helpers if needed

## Design notes

- Preserve existing macOS behavior unless the milestone explicitly states otherwise.
- Keep Windows-specific implementation behind platform/backend boundaries.
- Prefer precise capability errors over silent degradation.
- Update `state.md` when implementation reveals a better file layout or dependency.

## Tests to add or update

The specific tests should match the implementation, but this milestone must include enough validation to satisfy the acceptance criteria below. Prefer unit/golden/fake tests before requiring self-hosted integration tests.

## Acceptance criteria

- [x] Guest builds with both macOS/vsock and Windows/virtio-serial support.
- [x] Host opens control transport reliably during boot and exposes the established stream after boot. Self-hosted WHPX smoke showed QEMU `-chardev pipe` blocks boot until a host client connects, so LocalSandbox connects immediately after QEMU process start and clones the stored stream for later control callers.
- [x] Protocol framing tests pass over in-memory and Windows transport where possible.
- [x] Timeouts produce clear diagnostics.

## Coding-agent prompt

```text
You are implementing M06: Virtio-Serial Control Transport for the LocalSandbox Windows QEMU + WHPX port.

Read first:
- docs/windows-port/rfc-qemu-whpx.md
- docs/windows-port/AGENTS.md
- docs/windows-port/agent-workspace/state.md
- docs/windows-port/agent-workspace/decisions.md
- docs/windows-port/agent-workspace/milestones/06-virtio-serial-control-transport.md

Implement only this milestone. Preserve public CLI/SDK/Node APIs and existing macOS behavior. Add tests required by the milestone. Do not implement later milestones opportunistically. Update state.md and this milestone handoff before finishing.
```

## Security checklist

Complete the checklist in `../security-checklist.md`. Record any new risk in `../risk-register.md`.

## Handoff

- Branch/PR: `codex/windows-m06-virtio-serial-control`
- Summary: Added a platform-neutral host control stream boundary, Windows QEMU virtio-serial endpoint naming/opening, QEMU control chardev lifecycle wiring, guest virtio-serial transport selection/discovery, and focused protocol/endpoint/discovery tests. Self-hosted WHPX smoke proved the Windows QEMU pipe chardev must be connected during boot; the boot lifecycle now opens the pipe immediately after QEMU starts and keeps the established stream. No ready handshake, exec/file API parity, mux, mount, networking, checkpoint, or Node work was added.
- Tests run: `cargo fmt --all -- --check`; `cargo check --workspace`; `cargo test --workspace`; `cargo check --workspace --target x86_64-pc-windows-msvc` (blocked by known macOS-host MSVC tooling gaps); `cargo check -p lsb-platform --target x86_64-pc-windows-msvc`; `cargo check -p lsb-platform --tests --target x86_64-pc-windows-msvc`; focused `lsb-platform`, `lsb-guest`, and `lsb-proto` tests; `./scripts/win-gh-test smoke`.
- Debug artifacts: Passing smoke run `28701999114`, Windows job `85121503319`, artifact `windows-lsb-diagnostics` ID `8080445128`. `qemu.argv.redacted.txt` contains `virtio-serial-pci`, `virtserialport`, `lsb.transport=virtio-serial`, and `-nic none`; `serial.log` shows `lsb-guest` using virtio-serial and opening `/dev/vport1p1`.
- New decisions: D021 records the QEMU pipe connection ordering decision. D007 still selects virtio-serial over private Windows named pipe/QEMU chardev.
- New risks: No new risk record. R002 was moved to `Mitigating` with the observed connect-during-boot behavior; R003 remains `Mitigating` until M07 proves framed ready/control exchange over the opened virtio-serial stream.
- Next milestone: M07 guest ready handshake.

Security review:
- No-network default preserved: yes
- Secret redaction verified: yes, no protocol payload logging was added and QEMU argv diagnostics keep control pipe names redacted
- Host file exposure reviewed: yes, no new host file sharing was added
- Control/QMP endpoint privacy reviewed: partial, per-instance random pipe names are generated and self-hosted smoke validated same-user pipe connection ordering; QEMU-created named-pipe ACL behavior still needs hardening review before public runtime support
- Process cleanup reviewed: yes, endpoint lifetime is tied to the running boot object and QEMU cleanup remains under the existing supervisor/Job Object path
- New risks added to risk-register.md: no; existing R003 status updated
