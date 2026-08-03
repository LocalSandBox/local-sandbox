#!/usr/bin/env bash
set -euo pipefail

iterations=3
lsb_binary="${LSB_BINARY:-target/release/lsb}"
results_path="${LSB_STARTUP_SMOKE_RESULTS:-target/rootfs-startup-smoke.jsonl}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

usage() {
    cat <<'EOF'
Usage: scripts/validate-rootfs-startup.sh [--iterations N] [--lsb PATH] [--results PATH]

Measures boot, npm scratch-install, image-size, and disk-write behavior in ephemeral VMs.
Set LSB_KERNEL, LSB_INITRD, and LSB_ROOTFS to compare unpublished runtime assets.
EOF
}

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --iterations)
            [[ "$#" -ge 2 && "$2" =~ ^[1-9][0-9]*$ ]] || { usage >&2; exit 2; }
            iterations="$2"
            shift 2
            ;;
        --lsb)
            [[ "$#" -ge 2 ]] || { usage >&2; exit 2; }
            lsb_binary="$2"
            shift 2
            ;;
        --results)
            [[ "$#" -ge 2 ]] || { usage >&2; exit 2; }
            results_path="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            exit 2
            ;;
    esac
done

[[ -x "$lsb_binary" ]] || { printf 'lsb binary is not executable: %s\n' "$lsb_binary" >&2; exit 2; }
mkdir -p "$(dirname "$results_path")"
: > "$results_path"

rootfs_size='null'
if [[ -n "${LSB_ROOTFS:-}" && -f "${LSB_ROOTFS}" ]]; then
    rootfs_size="$(wc -c < "${LSB_ROOTFS}" | tr -d ' ')"
fi

for ((iteration = 1; iteration <= iterations; iteration += 1)); do
    started_ms="$(node -e 'console.log(Date.now())')"
    guest_result="$(
        "$lsb_binary" run \
            --allow-net \
            --allow-host registry.npmjs.org \
            --mount "$repo_root/fixtures:/workspace:ro" \
            -- node /workspace/rootfs-startup-smoke.mjs
    )"
    finished_ms="$(node -e 'console.log(Date.now())')"
    node -e '
const [iteration, externalMs, rootfsSize, guest] = process.argv.slice(1)
process.stdout.write(JSON.stringify({
  iteration: Number(iteration),
  external_duration_ms: Number(externalMs),
  rootfs_size_bytes: rootfsSize === "null" ? null : Number(rootfsSize),
  ...JSON.parse(guest),
}) + "\n")
' "$iteration" "$((finished_ms - started_ms))" "$rootfs_size" "$guest_result" >> "$results_path"
done

node -e '
const fs = require("fs")
const runs = fs.readFileSync(process.argv[1], "utf8").trim().split("\n").map(JSON.parse)
const median = (values) => [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)]
console.log(JSON.stringify({
  status: "passed",
  iterations: runs.length,
  median_external_duration_ms: median(runs.map((run) => run.external_duration_ms)),
  median_guest_duration_ms: median(runs.map((run) => run.duration_ms)),
  median_npm_install_ms: median(runs.map((run) => run.npm_install_ms)),
  median_disk_write_bytes: median(runs.map((run) => run.disk_write_bytes).filter(Number.isFinite)),
  rootfs_size_bytes: runs[0].rootfs_size_bytes,
  noatime: runs.every((run) => run.noatime),
  results: process.argv[1],
}, null, 2))
' "$results_path"
