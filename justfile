guest_target := `cargo run -q -p xtask -- platform-meta --platform macos-aarch64 --format env | sed -n 's/^SHURU_GUEST_TARGET=//p'`
codesign_entitlements := `cargo run -q -p xtask -- platform-meta --platform macos-aarch64 --format env | sed -n 's/^SHURU_CODESIGN_ENTITLEMENTS=//p'`
binary := "target/debug/shuru"

# List available recipes
default:
    @just --list

# Build the guest init binary (cross-compiled to aarch64 musl)
build-guest:
    cargo build -p shuru-guest --target {{ guest_target }} --release

# Build the guest kernel image via xtask
build-kernel:
    cargo run -p xtask -- build-kernel --platform macos-aarch64

# Build the CLI binary (debug)
build-cli:
    cargo build -p shuru-cli

# Codesign the CLI binary with virtualization entitlement
codesign:
    codesign --entitlements {{ codesign_entitlements }} --force -s - {{ binary }}

# Build everything: guest + CLI + codesign
build: build-guest build-cli codesign

# Prepare the rootfs, kernel, and initramfs (requires Docker)
prepare-rootfs:
    cargo run -p xtask -- prepare-rootfs --platform macos-aarch64

# Run a command inside the VM
run *args:
    {{ binary }} run -- {{ args }}

# Open an interactive shell in the VM
shell:
    {{ binary }} run -- sh

# Full setup from scratch: rootfs + build
setup: prepare-rootfs build

# Check all crates compile (host targets only)
check:
    cargo check --workspace

# Run clippy on all crates
clippy:
    cargo clippy --workspace

# Install the binary to ~/.local/bin with codesign
install: build-guest
    cargo build -p shuru-cli --release
    codesign --entitlements {{ codesign_entitlements }} --force -s - target/release/shuru
    mkdir -p ~/.local/bin
    cp target/release/shuru ~/.local/bin/shuru

# Tag and push a release (triggers GitHub Actions)
release version:
    git tag -a "v{{ version }}" -m "Release v{{ version }}"
    git push origin "v{{ version }}"
