# Windows Future Work

This file tracks post-MVP Windows work that should not be rediscovered from the
deleted sprint workspace.

## Release readiness

- Rerun `./scripts/win-gh-test smoke` at final branch head after diagnostics
  collector scoping changes.
- Decide and document the minimum supported QEMU version.
- Evaluate whether a later Windows release should bundle/sign a known QEMU
  distribution instead of continuing with user-installed QEMU.
- Add a user-facing Windows diagnostics command such as `lsb doctor windows`.
- Decide whether to keep default self-hosted labels or add a dedicated WHPX
  runner label before growing the runner pool.

## Runtime capabilities

- Design a mux/session model for virtio-serial before enabling streaming
  `spawn`, shell, kill, file watch, or concurrent port-forward sessions.
- Decide whether Windows file watch should observe only guest-imported copies or
  wait for live sharing support.
- Add live checkpointing only after a QMP/block-layer design is accepted.
- Add native Windows build-number probing through Windows API, registry query,
  or the future diagnostics command.

## Storage

- Decide whether to migrate Windows checkpoints from flattened qcow2 artifacts
  to CAS/NBD, persistent qcow2 overlay chains, or another deduplicated format.
- Validate data-dir move/delete behavior for any backing-chain design.
- Keep product checkpoint semantics explicit; do not replace them with QEMU
  internal snapshots.

## Filesystem sharing experiments

### VirtioFS on Windows

Question: can QEMU on Windows provide a production-suitable VirtioFS path with
acceptable packaging, performance, security, and file semantics?

Validate:

- required `virtiofsd` binary and Windows support status,
- read-only Windows directory exposure into Linux guest,
- case sensitivity, symlinks/junctions, permissions, file watching, large
  directories, and concurrent behavior,
- guest overlay behavior preserving LocalSandbox semantics,
- no admin requirement for normal use.

If it fails, keep snapshot import/export and consider custom sync.

### 9p/virtfs on Windows

Question: can QEMU 9p/virtfs provide a simpler live sharing path than VirtioFS?

Validate read-only behavior, metadata fidelity, large-tree performance,
symlink/junction behavior, and path escape resistance.

## Transport experiments

### QEMU virtio-vsock on Windows host

Question: can QEMU on Windows WHPX provide a reliable host-side virtio-vsock
endpoint compatible with LocalSandbox's existing `lsb-proto` transport?

Validate:

- Linux guest sees the vsock device,
- Windows host can open a guest vsock connection without TCP host networking,
- framed ping/ready exchange works repeatedly,
- security properties match or exceed the virtio-serial MVP.

Keep virtio-serial as supported transport unless evidence justifies a new
accepted decision.

### Hyper-V sockets

Potential future transport only if virtio-serial proves inadequate. This likely
requires additional Windows-specific registration and guest kernel work.

## Networking/security

- Evaluate Windows Firewall only as defense-in-depth, not the primary policy
  mechanism.
- Continue testing direct-IP, forged Host/SNI, missing-domain, and secret
  redaction paths as proxy code evolves.
- Revisit QEMU binary provenance and path trust before public release.

## Platform expansion

### Windows ARM64

Windows ARM64 is planned but out of MVP.

Validate:

- QEMU binary and WHPX ARM64 requirements,
- guest architecture strategy,
- asset build and packaging path,
- Node package target naming,
- no disruption to Windows x64 backend.
