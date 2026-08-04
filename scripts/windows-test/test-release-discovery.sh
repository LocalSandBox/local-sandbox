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
  baseline:{
    mode:"release",release_id:1,tag:"v1.2.2",version:"1.2.2",
    publisher:{subject:"CN=SeaWork",sha256:("b"*64)},assets:[
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

git_root="$root/repository"
mkdir -p "$git_root"
git -C "$git_root" init -q -b main
git -C "$git_root" config user.name fixture
git -C "$git_root" config user.email fixture@example.invalid
printf 'fixture\n' > "$git_root/README.md"
git -C "$git_root" add README.md
git -C "$git_root" commit -qm base
dispatch_sha="$(git -C "$git_root" rev-parse HEAD)"

mkdir -p "$git_root/bindings/nodejs/npm/win32-x64-msvc"
printf '[workspace]\n' > "$git_root/Cargo.toml"
printf 'lock\n' > "$git_root/Cargo.lock"
printf '{"version":"1.2.3"}\n' > "$git_root/bindings/nodejs/npm/win32-x64-msvc/package.json"
git -C "$git_root" add Cargo.toml Cargo.lock bindings
git -C "$git_root" commit -qm 'chore(release): prepare v1.2.3'
release_sha="$(git -C "$git_root" rev-parse HEAD)"
validator="$repo_root/scripts/validate-windows-release-commit.sh"
(cd "$git_root" && "$validator" "$dispatch_sha" "$release_sha" 1.2.3 refs/heads/main)
(cd "$git_root" && "$validator" "$release_sha" "$release_sha" 1.2.3 refs/heads/main)

git -C "$git_root" switch -q -c unexpected "$dispatch_sha"
printf 'unexpected\n' > "$git_root/README.md"
git -C "$git_root" add README.md
git -C "$git_root" commit -qm 'chore(release): prepare v1.2.3'
unexpected_sha="$(git -C "$git_root" rev-parse HEAD)"
if (cd "$git_root" && "$validator" "$dispatch_sha" "$unexpected_sha" 1.2.3 refs/heads/unexpected) >/dev/null 2>&1; then
    echo 'release commit with unexpected changes was accepted' >&2; exit 1
fi

git -C "$git_root" switch -q -c wrong-message "$dispatch_sha"
printf '[workspace]\n' > "$git_root/Cargo.toml"
git -C "$git_root" add Cargo.toml
git -C "$git_root" commit -qm 'prepare release'
wrong_message_sha="$(git -C "$git_root" rev-parse HEAD)"
if (cd "$git_root" && "$validator" "$dispatch_sha" "$wrong_message_sha" 1.2.3 refs/heads/wrong-message) >/dev/null 2>&1; then
    echo 'release commit with the wrong subject was accepted' >&2; exit 1
fi

if (cd "$git_root" && "$validator" "$dispatch_sha" "$unexpected_sha" 1.2.3 refs/heads/main) >/dev/null 2>&1; then
    echo 'release commit outside the trusted branch was accepted' >&2; exit 1
fi

linked_worktree="$root/linked-worktree"
git -C "$git_root" worktree add -q "$linked_worktree" main
expected_objects="$(git -C "$git_root" rev-parse --path-format=absolute --git-common-dir)/objects"
observed_objects="$("$repo_root/scripts/git-common-objects-dir.sh" "$linked_worktree")"
[[ "$observed_objects" == "$expected_objects" ]] || {
    echo 'linked worktree did not resolve the shared Git object directory' >&2; exit 1
}
