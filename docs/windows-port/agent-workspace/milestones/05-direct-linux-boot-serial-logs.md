# M05: Direct Linux Boot and Serial Logs

Status: Done
Depends on: See `00-index.md`
RFC sections: See `traceability.md`

## Objective

Boot the Linux guest under QEMU + WHPX and capture enough logs to diagnose boot/init failures.

## Scope

- Use existing kernel/initramfs/rootfs assets.
- Boot with `-accel whpx` in production path.
- Pass direct Linux boot args compatible with rootfs virtio-blk.
- Capture serial console to file and/or host stream.
- Define boot timeout and artifact preservation.

## Out of scope

- Do not implement LocalSandbox exec.
- Do not enable guest NIC.
- Do not implement mounts/checkpoints.
- Do not mask boot failures as success.

## Likely files / crates

- `QEMU backend boot config`
- `kernel` config only if validation requires it
- `diagnostics artifacts`

## Design notes

- Preserve existing macOS behavior unless the milestone explicitly states otherwise.
- Keep Windows-specific implementation behind platform/backend boundaries.
- Prefer precise capability errors over silent degradation.
- Update `state.md` when implementation reveals a better file layout or dependency.

## Tests to add or update

The specific tests should match the implementation, but this milestone must include enough validation to satisfy the acceptance criteria below. Prefer unit/golden/fake tests before requiring self-hosted integration tests.

## Acceptance criteria

- [x] Self-hosted Windows boot smoke uses provisioned disposable boot assets, captures diagnostics, and observes QEMU alive through the M05 boot observation window. Guest readiness remains M06/M07.
- [x] WHPX missing fails before QEMU production launch.
- [x] Serial logs are captured in a known debug artifact location.
- [x] macOS boot path unchanged.

## Coding-agent prompt

```text
You are implementing M05: Direct Linux Boot and Serial Logs for the LocalSandbox Windows QEMU + WHPX port.

Read first:
- docs/windows-port/rfc-qemu-whpx.md
- docs/windows-port/AGENTS.md
- docs/windows-port/agent-workspace/state.md
- docs/windows-port/agent-workspace/decisions.md
- docs/windows-port/agent-workspace/milestones/05-direct-linux-boot-serial-logs.md

Implement only this milestone. Preserve public CLI/SDK/Node APIs and existing macOS behavior. Add tests required by the milestone. Do not implement later milestones opportunistically. Update state.md and this milestone handoff before finishing.
```

## Security checklist

Complete the checklist in `../security-checklist.md`. Record any new risk in `../risk-register.md`.

## Handoff

- Branch/PR: `codex/windows-m05-direct-linux-boot-serial-logs`
- Summary: Added a private Windows QEMU direct boot orchestration module and wired `PlatformVm::start()` to run QEMU discovery/preflight, build direct Linux boot argv through the existing builder, launch through the existing supervisor/Job Object path, capture stdout/stderr/serial/preflight/status artifacts, and treat QEMU staying alive through the observation window as the M05-only boot result. The provisioned smoke path now uses `-cpu Westmere` for WHPX compatibility after `-cpu max` failed on the self-hosted runner. Later control, readiness, exec, mounts, networking, and checkpoints remain unsupported with explicit errors.
- Tests run: See `../state.md` for the final validation log. Local validation passed `cargo fmt --all -- --check`, targeted QEMU argv/boot tests, `cargo check --workspace`, `cargo test --workspace`, `cargo check -p lsb-platform --target x86_64-pc-windows-msvc`, `git diff --check`, and YAML parsing for `.github/workflows/windows-lsb-hardware.yml`. Full macOS-hosted workspace Windows target check remains blocked by external MSVC C/assembler tooling. Windows self-hosted `./scripts/win-gh-test smoke` passed in run `28697374629`; it ran real QEMU/WHPX preflight and `windows_qemu_boot_smoke`, observing QEMU alive for 10000 ms with provisioned kernel/initrd/rootfs assets.
- Debug artifacts: M05 writes `qemu.argv.redacted.txt`, `qemu.stdout.log`, `qemu.stderr.log`, `qemu.status.json`, `serial.log`, `preflight.json`, and `boot.status.json` under `<instance-dir>/diagnostics`, or under `LSB_WINDOWS_BOOT_ARTIFACT_DIR` for the ignored smoke test. The successful hardware smoke wrote `C:\lsb-assets\work\28697374629-1\diagnostics` and uploaded staged diagnostics in `windows-lsb-diagnostics` artifact ID `8079059489`.
- New decisions: D020 records the WHPX direct boot CPU model choice.
- New risks: None.
- Security review: no-network default preserved: yes, QEMU argv still includes `-nic none` and no network device is added; secret redaction verified: yes, argv/status artifacts are redacted and QEMU does not inherit parent env by default; host file exposure reviewed: yes, M05 uses only kernel/initrd/rootfs asset paths and diagnostics, with rootfs documented as a disposable writable raw image; control/QMP endpoint privacy reviewed: yes, no new QMP or control endpoint is created by the wired boot path; process cleanup reviewed: yes, start/stop use the existing supervisor and Windows Job Object cleanup; new risks added to risk-register.md: no.
- Next milestone: M06 virtio-serial control transport. M05 does not prove guest readiness or LocalSandbox command execution.
