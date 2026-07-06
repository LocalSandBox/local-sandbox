# Checkpoints

Checkpoints save the full disk state after a command finishes. On macOS they use APFS copy-on-write clones/CAS indexes, so a checkpoint only consumes disk space for blocks that differ from the base image. On Windows they are stored as qcow2 checkpoint artifacts over immutable base images.

## Creating a Checkpoint

```bash
lsb checkpoint create <name> [--allow-net] [--from <existing>] [-- command...]
```

This boots a VM, runs the command (or drops to `/bin/sh` if none given), and saves the disk state when the command exits. The checkpoint is saved regardless of the exit code.

If `--from` is specified, the VM boots from that checkpoint instead of the base image.

## Stacking

Checkpoints can branch from existing checkpoints:

```bash
lsb checkpoint create base --allow-net -- apt-get install -y build-essential git
lsb checkpoint create node --from base --allow-net -- apt-get install -y nodejs npm
lsb checkpoint create deps --from node --allow-net --mount .:/app -- sh -c 'cd /app && npm ci'
```

`lsb checkpoint list` shows actual disk usage per checkpoint where the host backend can report it.

## Booting from a Checkpoint

```bash
lsb run --from <name> [flags] [-- command...]
```

The VM gets a fresh clone of the checkpoint — changes during the run are discarded on exit.

## Lifecycle

- `checkpoint create` — save disk state
- `checkpoint list` — show all checkpoints with size and age
- `checkpoint delete <name>` — permanently remove a checkpoint
- Names must be unique. Delete before re-creating with the same name.

## Disk Usage

On macOS, checkpoints use APFS clonefile/CAS behavior. A fresh checkpoint from a 512MB base image might only use 10-50MB of actual disk space depending on what changed. On Windows, checkpoints are qcow2 artifacts and may have different apparent and allocated sizes. Use `checkpoint list` to see reported usage.

If you're running low on disk, delete unused checkpoints with `checkpoint delete`.
