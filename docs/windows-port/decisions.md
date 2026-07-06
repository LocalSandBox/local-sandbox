# Windows Port Decisions

This file records accepted decisions for the Windows QEMU + WHPX backend.
Treat accepted decisions as fixed unless implementation is blocked and a new
decision is reviewed.

## Decision change process

A decision may be changed only when all are true:

1. The current implementation is blocked without the change.
2. The agent records evidence and failed alternatives.
3. The change is reviewed by the maintainer.
4. The RFC and durable Windows docs are updated if the change affects
   architecture or user-visible behavior.

Use this format for new records:

```markdown
### DXXX: Short decision title

- Status: Accepted
- Date: YYYY-MM-DD
- Owner: TBD
- Related area: boot | transport | network | storage | packaging | CI

#### Context

What forced this decision?

#### Decision

State the decision precisely.

#### Consequences

- Positive consequence.
- Tradeoff or follow-up.

#### Alternatives considered

- Alternative: reason rejected.
```

## Accepted decisions

### D001: MVP host is Windows 11 x86_64

- Status: Accepted
- Date: 2026-07-02
- Decision: The MVP targets Windows 11 on x86_64 hosts.
- Consequence: Do not spend MVP effort on Windows 10, Windows Server, or compatibility shims unless needed for a compile/test path.

### D002: Windows ARM64 is planned, not MVP

- Status: Accepted
- Date: 2026-07-02
- Decision: Implement x86_64 first. Keep architecture boundaries clean enough that Windows ARM64 can be added later.
- Consequence: Do not add ARM64-specific QEMU/WHPX work to MVP work.

### D003: Guest/kernel/initramfs changes are allowed

- Status: Accepted
- Date: 2026-07-02
- Decision: The Windows port may modify the Linux guest agent, initramfs, and kernel config when needed.
- Consequence: Prefer preserving `lsb-proto` and product semantics over preserving an unchanged guest binary.

### D004: QEMU is discovered for MVP

- Status: Accepted
- Date: 2026-07-02
- Decision: MVP discovers an installed `qemu-system-x86_64.exe` through explicit configuration/env/PATH. Bundling may be considered after the backend is stable.
- Consequence: Preflight diagnostics must be strong enough for env/config/PATH
  override QEMU binaries.
- Update: D023 changes the standard post-MVP path to a managed QEMU host-tool
  package installed by `lsb init`; env/config/PATH discovery remains supported
  as override and fallback behavior.

### D005: Production requires WHPX

- Status: Accepted
- Date: 2026-07-02
- Decision: Production Windows runs use `-accel whpx` only.
- Consequence: TCG fallback may exist only as a hidden/debug diagnostic path. Normal CLI/API paths must fail if WHPX is unavailable.

### D006: MVP is QEMU + WHPX only

- Status: Accepted
- Date: 2026-07-02
- Decision: HCS, Hyper-V Manager VMs, WSL2, Docker, and raw WHP VMM implementations are out of MVP scope.
- Consequence: Alternative backend work belongs in later RFCs or experiments.

### D007: MVP control transport is virtio-serial

- Status: Accepted
- Date: 2026-07-02
- Decision: Use virtio-serial over a private Windows named pipe/QEMU chardev for LocalSandbox control messages. Preserve the existing `lsb-proto` framing and semantics.
- Consequence: QMP is for QEMU management only. QGA is not the LocalSandbox guest API. Vsock/Hyper-V sockets are future validation experiments.

### D008: Public CLI/SDK/Node APIs remain stable

- Status: Accepted
- Date: 2026-07-02
- Decision: Preserve public API shape and semantics. Unsupported Windows MVP features should return precise capability errors.
- Consequence: Do not introduce Windows-only public APIs unless separately approved.

### D009: Copy-in/copy-out is allowed for Windows mount MVP

- Status: Accepted
- Date: 2026-07-02
- Decision: MVP may implement filesystem semantics using copy-in/copy-out/import/export before live shared mounts.
- Consequence: Live VirtioFS/9p/custom sync are future improvements after validation.

### D010: Mount fidelity is product-level, not POSIX-perfect, for MVP

- Status: Accepted
- Date: 2026-07-02
- Decision: Preserve product semantics: host source read-only from product perspective, guest writes isolated, explicit export. Do not require perfect POSIX live sharing in MVP.
- Consequence: Windows case, symlink, ACL, special-file, and file-watch differences must be documented and tested where supported.

### D011: Direct `:rw` host mounts are not in Windows MVP

- Status: Accepted
- Date: 2026-07-02
- Decision: Windows MVP does not support direct host-write mounts.
- Consequence: Requests for `:rw` mounts on Windows must fail with a capability error unless a later decision enables them.

### D012: No QEMU user networking by default

- Status: Accepted
- Date: 2026-07-02
- Decision: The default Windows VM has no guest NIC and no arbitrary outbound network.
- Consequence: Do not use QEMU user networking as a convenience default.

### D013: Allowlisted egress must be strict

- Status: Accepted
- Date: 2026-07-02
- Decision: Allowlisted networking must block arbitrary outbound egress, direct IP bypass, and non-proxied traffic unless explicitly allowed by policy.
- Consequence: QEMU NAT alone is insufficient. Egress policy lives in LocalSandbox-controlled code.

### D014: Windows Firewall is defense-in-depth, not MVP primary policy

- Status: Accepted
- Date: 2026-07-02
- Decision: MVP should not rely on Windows Firewall as the primary enforcement mechanism. Firewall integration may be added later for defense-in-depth or for specific network backends.
- Consequence: Avoid admin-permission design assumptions in MVP.

### D015: Port forwarding should preserve no-network semantics

- Status: Accepted
- Date: 2026-07-02
- Decision: Host-to-guest port forwarding should work without giving the guest arbitrary outbound networking.
- Consequence: Prefer a LocalSandbox control/data channel over QEMU `hostfwd`; treat QEMU `hostfwd` as debug/temporary only.

### D016: Checkpoint MVP uses simple disk artifacts first

- Status: Accepted
- Date: 2026-07-02
- Decision: Preserve product-level checkpoint semantics, but implement Windows MVP with immutable base plus per-sandbox writable disk/checkpoint artifacts before porting CAS/NBD.
- Consequence: Unix-socket NBD/CAS is not required for first Windows checkpoint support.

### D017: Rust CLI/backend ships before Node Windows package

- Status: Accepted
- Date: 2026-07-02
- Decision: Implement and validate the Rust backend first. Add Windows Node packaging after core CLI smoke tests pass.
- Consequence: Node package changes should not block early backend work.

### D018: Self-hosted Windows 11 WHPX runner will be available

- Status: Accepted
- Date: 2026-07-02
- Decision: Use GitHub-hosted Windows runners for compile/unit/golden tests and a self-hosted Windows 11 x86_64 runner for WHPX boot/network/mount/checkpoint smoke tests.
- Consequence: CI must split hosted compile/unit/golden coverage from manual WHPX runtime coverage.

### D019: Guest code is untrusted

- Status: Accepted
- Date: 2026-07-02
- Decision: Treat guest code as untrusted. Host secrets are high-value. QEMU is part of the attack surface. Host filesystem and local sockets/pipes must be private and minimized.
- Consequence: Windows backend work must pass the security checklist before completion.

### D020: Windows WHPX direct boot uses a conservative CPU model

- Status: Accepted
- Date: 2026-07-04
- Decision: Use explicit `-cpu Westmere` for the Windows QEMU + WHPX direct boot path instead of `-cpu max`.
- Evidence: Self-hosted smoke run `28696602575` on QEMU 11.0.50 exited before serial output with APX/MPX feature conflicts and `WHPX: Unexpected VP exit code 4`. QEMU issue 1043 records the same `-cpu max` + WHPX failure shape and a `Westmere` workaround.
- Consequence: Keep production execution WHPX-only; this is not a TCG fallback. Revisit the CPU model only with self-hosted WHPX boot smoke evidence and updated argv golden tests.

### D021: Windows virtio-serial pipe is connected during boot

- Status: Accepted
- Date: 2026-07-04
- Related area: transport

#### Context

The first self-hosted WHPX smoke run with `-device virtio-serial-pci`,
`-chardev pipe`, and `virtserialport` in argv produced an empty `serial.log`.
Diagnostics from run `28701861357` showed the expected redacted argv and no
QEMU stderr, but Linux never emitted serial output. This validated that QEMU
11.0.50 on the Windows runner blocks guest startup until a host client connects
to the named pipe chardev.

#### Decision

LocalSandbox connects to the QEMU-created control pipe immediately after the
QEMU process starts and before boot observation. The established stream is owned
by the running boot object, and later `PlatformVm::connect_control()` returns a
clone of that stream instead of opening a second pipe client.

#### Consequences

- Guest boot is unblocked while preserving the private virtio-serial/QEMU pipe
  transport.
- Control transport lifecycle is tied to the QEMU boot object; dropping/stopping
  the boot drops the pipe handle.
- Guest-ready handshake and later control operations use the already-established
  stream.

#### Alternatives considered

- Open the pipe only after boot: rejected because QEMU did not produce serial
  output until a host client connected.
- Make LocalSandbox create the named-pipe server: rejected for the MVP because
  QEMU `-chardev pipe` creates the endpoint and the validated path uses QEMU's
  server side.
- Use hostfwd TCP/QGA/QMP for control: rejected by D007.

### D022: Windows checkpoint artifacts are flattened qcow2 files for M13

- Status: Accepted
- Date: 2026-07-05
- Related area: storage

#### Context

D016 allows the Windows checkpoint MVP to use simple disk artifacts before
porting Unix-socket NBD/CAS. The implementation still needed to choose between
persistent qcow2 backing chains, flat checkpoint copies, or QEMU internal
snapshots.

#### Decision

Each running Windows sandbox uses a private qcow2 writable overlay over the
immutable base image or a source checkpoint. Creating a product checkpoint
converts the active overlay into a standalone flattened qcow2 artifact and
registers versioned JSON metadata only after conversion succeeds.

#### Consequences

- Restoring from a checkpoint does not depend on mutable backing-chain paths and
  does not mutate the base rootfs.
- Deleting a checkpoint is local to its `.qcow2` and `.json` artifacts; it does
  not invalidate other checkpoint files through shared backing chains.
- Checkpoints may be larger than overlay-chain artifacts and are not CAS/NBD
  parity.
- The Windows SDK `checkpoint()` path stops the VM before conversion for the
  MVP; live checkpointing requires later QMP/block-layer work or another
  approved design.

#### Alternatives considered

- Persistent qcow2 overlay chains: deferred because durable backing paths across
  Windows data-dir moves, deletes, and future CAS migration need more design.
- QEMU internal snapshots as the product checkpoint abstraction: rejected
  because product checkpoints are explicit saved-disk-state artifacts.
- Port Unix-socket NBD/CAS first: rejected by D016.

### D023: `lsb init` installs a managed Windows QEMU host tool package

- Status: Accepted
- Date: 2026-07-07
- Owner: TBD
- Related area: packaging | CI

#### Context

The original MVP discovery model relied on env/config/PATH-provisioned QEMU.
That kept the first Windows backend small, but made fresh installs, support
diagnostics, and CI less reproducible.

#### Decision

On Windows x86_64, `lsb init` installs and validates a pinned LocalSandbox
managed QEMU package under `%LOCALAPPDATA%\lsb\tools\qemu`. The package is a
host tool, not part of CLI archives, runtime OS assets, or npm packages. QEMU
discovery order is `LSB_QEMU`, internal config, managed QEMU, then `PATH`.
`qemu-img.exe` uses `LSB_QEMU_IMG`, sibling override/config paths, managed QEMU,
then `PATH`.

#### Consequences

- Fresh Windows users no longer need manual QEMU setup for the standard path.
- Diagnostics can distinguish managed QEMU from env/config/PATH overrides.
- The maintained QEMU artifact must be published and hash-verifiable before
  product releases.
- User override QEMU builds remain possible but are no longer the default.

#### Alternatives considered

- Bundle QEMU in CLI/npm/runtime assets: rejected to avoid large artifacts and
  mixing host tools with guest runtime assets.
- Continue env/config/PATH-only QEMU discovery: rejected for standard UX and CI
  reproducibility.
- Add TCG fallback: rejected by D005.
