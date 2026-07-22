# List available recipes
default:
    @just --list

# Build the guest init binary for the host platform by default.
# Set LSB_PLATFORM=<platform-id> to cross-build.
build-guest:
    LSB_PLATFORM="${LSB_PLATFORM:-}" cargo run -p xtask -- build-guest

# Build the guest kernel image via xtask.
# Set LSB_PLATFORM=<platform-id> to override the host default.
build-kernel:
    LSB_PLATFORM="${LSB_PLATFORM:-}" cargo run -p xtask -- build-kernel

# Build the CLI binary (debug)
build-cli:
    cargo build -p lsb-cli

# Codesign the CLI binary when the selected platform requires it.
codesign:
    @meta="$(LSB_PLATFORM="${LSB_PLATFORM:-}" cargo run -q -p xtask -- platform-meta --format env)"; \
    entitlements="$(printf '%s\n' "$meta" | sed -n 's/^LSB_CODESIGN_ENTITLEMENTS=//p')"; \
    binary_name="$(printf '%s\n' "$meta" | sed -n 's/^LSB_CLI_BINARY=//p')"; \
    if [ -n "$entitlements" ]; then \
        codesign --entitlements "$entitlements" --force -s - "target/debug/$binary_name"; \
    else \
        echo "No codesign entitlements for selected platform; skipping codesign"; \
    fi

# Build everything: guest + CLI + platform signing when needed
build: build-guest build-cli codesign

# Prepare the rootfs, kernel, and initramfs (requires Docker).
# Set LSB_PLATFORM=<platform-id> to override the host default.
# Advanced source-build path. On Windows, prefer `just init-runtime-assets`.
prepare-rootfs:
    LSB_PLATFORM="${LSB_PLATFORM:-}" cargo run -p xtask -- prepare-rootfs

# Pass extra init flags directly, for example:
#   just init-runtime-assets --version 0.3.8 --force
#
# Download released runtime assets for the local CLI/platform.
init-runtime-assets *args:
    cargo run -p lsb-cli -- init {{ args }}

# Run a command inside the VM
run *args:
    @binary_name="$(LSB_PLATFORM="${LSB_PLATFORM:-}" cargo run -q -p xtask -- platform-meta --format env | sed -n 's/^LSB_CLI_BINARY=//p')"; \
    "target/debug/$binary_name" run -- {{ args }}

# Open an interactive shell in the VM
shell:
    @binary_name="$(LSB_PLATFORM="${LSB_PLATFORM:-}" cargo run -q -p xtask -- platform-meta --format env | sed -n 's/^LSB_CLI_BINARY=//p')"; \
    "target/debug/$binary_name" run -- sh

# On Windows, building runtime assets locally is complicated; prefer
# `just build-cli` followed by `just init-runtime-assets`.
#
# Full source setup from scratch: rootfs + build
setup: prepare-rootfs build

# Check all crates compile (host targets only)
check:
    cargo check --workspace

# Run clippy on all crates
clippy:
    cargo clippy --workspace

# Install the binary to ~/.local/bin with platform signing when needed
install:
    cargo build -p lsb-cli --release
    @meta="$(LSB_PLATFORM="${LSB_PLATFORM:-}" cargo run -q -p xtask -- platform-meta --format env)"; \
    entitlements="$(printf '%s\n' "$meta" | sed -n 's/^LSB_CODESIGN_ENTITLEMENTS=//p')"; \
    binary_name="$(printf '%s\n' "$meta" | sed -n 's/^LSB_CLI_BINARY=//p')"; \
    if [ -n "$entitlements" ]; then \
        codesign --entitlements "$entitlements" --force -s - "target/release/$binary_name"; \
    else \
        echo "No codesign entitlements for selected platform; skipping codesign"; \
    fi; \
    mkdir -p ~/.local/bin; \
    cp "target/release/$binary_name" "$HOME/.local/bin/$binary_name"

# Dispatch a release; prereleases skip evidence by default, stable releases require it.
release version service_evidence="":
    @evidence="{{ service_evidence }}"; \
    if [ -z "$evidence" ]; then \
        case "{{ version }}" in \
            *-*) evidence="skip" ;; \
            *) evidence="required" ;; \
        esac; \
    fi; \
    case "$evidence" in \
        skip|required) ;; \
        *) echo "service_evidence must be skip or required" >&2; exit 2 ;; \
    esac; \
    gh workflow run release.yml --ref main -f version="{{ version }}" -f service_evidence="$evidence"
