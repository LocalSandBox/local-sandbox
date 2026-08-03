#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: $0 <fetched-evidence-directory> <output.tgz>" >&2
    exit 2
}

[[ $# -eq 2 ]] || usage
source_dir="$1"
output="$2"
manifest="$source_dir/acceptance-evidence-manifest.json"
[[ -d "$source_dir" && -f "$manifest" ]] || {
    echo 'release evidence directory or manifest is missing' >&2
    exit 1
}
command -v jq >/dev/null || { echo 'jq is required' >&2; exit 1; }

jq -e '
  .schema_version == 1 and .profile == "release" and .status == "passed" and
  (.run_id | test("^[a-z0-9][a-z0-9._-]{0,95}$")) and
  (.snapshot_sha | test("^[0-9a-f]{40}$")) and
  (.base_commit_sha | test("^[0-9a-f]{40}$")) and
  (.release_artifact.sha256 == .bindings.release_artifact_sha256) and
  ([.checks[].status] | all(. == "passed")) and
  (.files | length > 0 and length <= 256)
' "$manifest" >/dev/null || {
    echo 'release evidence manifest is incomplete or failed' >&2
    exit 1
}

stage="$(mktemp -d "${TMPDIR:-/tmp}/lsb-windows-evidence.XXXXXX")"
trap 'rm -rf -- "$stage"' EXIT
cp "$manifest" "$stage/acceptance-evidence-manifest.json"

while IFS=$'\t' read -r name expected_sha expected_size; do
    [[ "$name" =~ ^(profile-result|result-[a-z0-9-]+-(normal|beforereboot|afterreboot)|evidence-[a-z0-9._-]+\.redacted)\.json$ ]] || {
        echo "unsafe evidence name: $name" >&2
        exit 1
    }
    path="$source_dir/$name"
    [[ -f "$path" && ! -L "$path" ]] || { echo "missing evidence file: $name" >&2; exit 1; }
    observed_size="$(wc -c < "$path" | tr -d ' ')"
    observed_sha="$(shasum -a 256 "$path" | awk '{print $1}')"
    [[ "$observed_size" == "$expected_size" && "$observed_sha" == "$expected_sha" ]] || {
        echo "evidence binding mismatch: $name" >&2
        exit 1
    }
    cp "$path" "$stage/$name"
done < <(jq -r '.files[] | [.name, .sha256, (.size | tostring)] | @tsv' "$manifest")

mkdir -p -- "$(dirname "$output")"
tar -czf "$output" -C "$stage" .
size="$(wc -c < "$output" | tr -d ' ')"
if (( size > 46080 )); then
    echo "compressed release evidence exceeds 45 KiB: $size bytes" >&2
    exit 1
fi
echo "$output"
