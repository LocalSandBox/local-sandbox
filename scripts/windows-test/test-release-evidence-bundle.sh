#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture="$(mktemp -d "${TMPDIR:-/tmp}/lsb-evidence-test.XXXXXX")"
trap 'rm -rf -- "$fixture"' EXIT
source_dir="$fixture/source"
mkdir -p "$source_dir"
printf '%s\n' '{"schema_version":1,"status":"passed"}' > "$source_dir/evidence-core.redacted.json"
sha="$(shasum -a 256 "$source_dir/evidence-core.redacted.json" | awk '{print $1}')"
size="$(wc -c < "$source_dir/evidence-core.redacted.json" | tr -d ' ')"
jq -n --arg sha "$sha" --argjson size "$size" '{
  schema_version: 1,
  run_id: "run-1",
  snapshot_sha: ("a" * 40),
  source_tree_sha: ("b" * 40),
  base_commit_sha: ("c" * 40),
  profile: "release",
  status: "passed",
  generated_utc: "2026-08-04T00:00:00Z",
  bindings: {runtime_assets_sha256: null, release_artifact_sha256: ("d" * 64)},
  release_artifact: {name: "lsb-seawork-service-v1.2.3-windows-x86_64.zip", sha256: ("d" * 64), size: 1},
  checks: [{id: "upd01.activation_smoke", status: "passed", duration_ms: 1, stable_code: null, evidence: ["evidence-core.redacted.json"]}],
  files: [{name: "evidence-core.redacted.json", sha256: $sha, size: $size, redacted: true}]
}' > "$source_dir/acceptance-evidence-manifest.json"

"$repo_root/scripts/package-windows-release-evidence.sh" "$source_dir" "$fixture/evidence.tgz" >/dev/null
[[ "$(tar -tzf "$fixture/evidence.tgz" | sort | tr '\n' ' ')" == './ ./acceptance-evidence-manifest.json ./evidence-core.redacted.json ' ]]

printf 'tamper\n' >> "$source_dir/evidence-core.redacted.json"
if "$repo_root/scripts/package-windows-release-evidence.sh" "$source_dir" "$fixture/tampered.tgz" >/dev/null 2>&1; then
    echo 'tampered evidence was accepted' >&2
    exit 1
fi

jq '.status = "failed"' "$source_dir/acceptance-evidence-manifest.json" > "$fixture/failed.json"
mv "$fixture/failed.json" "$source_dir/acceptance-evidence-manifest.json"
if "$repo_root/scripts/package-windows-release-evidence.sh" "$source_dir" "$fixture/failed.tgz" >/dev/null 2>&1; then
    echo 'failed evidence was accepted' >&2
    exit 1
fi
