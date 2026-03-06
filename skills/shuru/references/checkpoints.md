# Checkpoints

Checkpoints save the full ext4 disk state after a command finishes. They use APFS copy-on-write clones, so a checkpoint only consumes disk space for blocks that differ from the base image.

## Creating a Checkpoint

```bash
shuru checkpoint create <name> [--allow-net] [--from <existing>] [-- command...]
```

This boots a VM, runs the command (or drops to `/bin/sh` if none given), and saves the disk state when the command exits. The checkpoint is saved regardless of the exit code.

If `--from` is specified, the VM boots from that checkpoint instead of the base image.

## Stacking

Checkpoints can be layered. Each layer only stores its diff from the parent:

```bash
shuru checkpoint create base --allow-net -- apt-get install -y build-essential git
shuru checkpoint create node --from base --allow-net -- apt-get install -y nodejs npm
shuru checkpoint create deps --from node --allow-net --mount .:/app -- sh -c 'cd /app && npm ci'
```

`shuru checkpoint list` shows actual disk usage per checkpoint (allocated blocks, not apparent size).

## Booting from a Checkpoint

```bash
shuru run --from <name> [flags] [-- command...]
```

The VM gets a fresh clone of the checkpoint — changes during the run are discarded on exit.

## Lifecycle

- `checkpoint create` — save disk state
- `checkpoint list` — show all checkpoints with size and age
- `checkpoint delete <name>` — permanently remove a checkpoint
- Names must be unique. Delete before re-creating with the same name.

## Disk Usage

Checkpoints use APFS clonefile. A fresh checkpoint from a 512MB base image might only use 10-50MB of actual disk space depending on what changed. Use `checkpoint list` to see real usage.

If you're running low on disk, delete unused checkpoints with `checkpoint delete`.
