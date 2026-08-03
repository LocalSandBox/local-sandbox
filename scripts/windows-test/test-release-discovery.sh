#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
root="$(mktemp -d "${TMPDIR:-/tmp}/lsb-release-discovery-test.XXXXXX")"
trap 'rm -rf -- "$root"' EXIT

: > "$root/zero.jsonl"
if "$repo_root/scripts/select-windows-release-candidate.sh" "$root/zero.jsonl" >/dev/null 2>&1; then
    echo 'zero eligible runs were accepted' >&2; exit 1
fi
printf '%s\n' '{"run_id":1,"url":"https://example.invalid/1"}' > "$root/one.jsonl"
[[ "$("$repo_root/scripts/select-windows-release-candidate.sh" "$root/one.jsonl")" == *'"run_id":1'* ]]
printf '%s\n' '{"run_id":2,"url":"https://example.invalid/2"}' >> "$root/one.jsonl"
if "$repo_root/scripts/select-windows-release-candidate.sh" "$root/one.jsonl" >/dev/null 2>&1; then
    echo 'multiple eligible runs were accepted' >&2; exit 1
fi

jq -n '{
  schema_version:1, workflow:"release.yml", release_workflow_run_id:42,
  release_sha:("a"*40), version:"1.2.3", service_evidence:"required",
  publisher:{subject:"CN=SeaWork",sha256:("b"*64)},
  candidate:{
    service:{name:"lsb-seawork-service-v1.2.3-windows-x86_64.zip",sha256:("c"*64),size:1},
    updater:{name:"lsb-seawork-updater-v1.2.3-windows-x86_64.zip",sha256:("d"*64),size:1},
    updater_manifest:{name:"lsb-seawork-updater-v1.2.3-windows-x86_64-manifest.json",sha256:("e"*64),size:1}},
  baseline:{mode:"release",release_id:1,tag:"v1.2.2",assets:[
    {name:"lsb-seawork-service-v1.2.2-windows-x86_64.zip",sha256:("1"*64),size:1,api_url:"https://api.example/1"},
    {name:"lsb-seawork-updater-v1.2.2-windows-x86_64.zip",sha256:("2"*64),size:1,api_url:"https://api.example/2"},
    {name:"lsb-seawork-updater-v1.2.2-windows-x86_64-manifest.json",sha256:("3"*64),size:1,api_url:"https://api.example/3"}]}
}' > "$root/descriptor.json"
jq -e --argjson run 42 --arg sha "$(printf 'a%.0s' {1..40})" \
    -f "$repo_root/scripts/windows-release-descriptor.jq" "$root/descriptor.json" >/dev/null
for mutation in '.service_evidence="skip"' '.release_sha=("f"*40)' '.baseline.assets=[]'; do
    jq "$mutation" "$root/descriptor.json" > "$root/bad.json"
    if jq -e --argjson run 42 --arg sha "$(printf 'a%.0s' {1..40})" \
        -f "$repo_root/scripts/windows-release-descriptor.jq" "$root/bad.json" >/dev/null; then
        echo "invalid descriptor was accepted: $mutation" >&2; exit 1
    fi
done
