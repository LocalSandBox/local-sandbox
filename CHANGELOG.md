# Changelog

## 0.2.0

### Breaking: Guest OS migrated from Alpine Linux to Debian

The guest VM now runs **Debian 13 (trixie)** instead of Alpine Linux 3.21. This is a breaking change for existing checkpoints and workflows that use `apk`.

**Why:** Alpine's musl libc is incompatible with many tools that assume glibc (e.g., Claude Code, VS Code server, many pre-built binaries). Debian's glibc resolves this and aligns with the standard environment developers expect.

**What changed:**

- **Package manager:** `apk add` -> `apt-get install -y`
- **Package names:** Some differ between Alpine and Debian (e.g., `build-base` → `build-essential`, `py3-pip` → `python3-pip`)
- **Kernel:** Alpine `linux-virt` -> Debian `linux-image-cloud-arm64`
- **Pre-installed tools:** `curl`, `git`, `jq`, `less`, `procps`, `openssh-client`, `iproute2`, `xz-utils`

**Migration guide:**

1. Run `shuru upgrade` to get the new CLI and OS image.
2. Recreate any checkpoints using `apt-get` instead of `apk`:

```bash
# Before (Alpine)
shuru checkpoint create myenv --allow-net -- apk add nodejs npm

# After (Debian)
shuru checkpoint create myenv --allow-net -- apt-get install -y nodejs npm
```

3. Existing Alpine checkpoints will continue to boot (same kernel architecture, same init path), but new VMs start from Debian.
