#!/usr/bin/env bash
set -euo pipefail
[[ $# -eq 2 ]] || { echo "usage: $0 <bundle.tgz> <destination>" >&2; exit 2; }
bundle="$1" destination="$2"
[[ -f "$bundle" && ! -e "$destination" ]] || { echo 'bundle is missing or destination exists' >&2; exit 1; }
size="$(wc -c < "$bundle" | tr -d ' ')"
(( size <= 46080 )) || { echo 'compressed evidence exceeds 45 KiB' >&2; exit 1; }
count=0
declare -A seen=()
while IFS= read -r name; do
    ((count += 1))
    [[ "$name" == ./ || "$name" =~ ^\./(acceptance-evidence-manifest|profile-result|result-[a-z0-9-]+-(normal|beforereboot|afterreboot)|evidence-[a-z0-9._-]+\.redacted)\.json$ ]] || {
        echo "unsafe bundle path: $name" >&2; exit 1;
    }
    [[ -z "${seen[$name]:-}" ]] || { echo "duplicate bundle path: $name" >&2; exit 1; }
    seen[$name]=1
done < <(tar -tzf "$bundle")
(( count > 1 && count <= 258 )) || { echo 'evidence bundle entry count is invalid' >&2; exit 1; }
if tar -tvzf "$bundle" | awk 'substr($1,1,1) != "-" && substr($1,1,1) != "d" { exit 1 }'; then :; else
    echo 'evidence bundle contains a non-regular entry' >&2; exit 1
fi
mkdir -p "$destination"
tar -xzf "$bundle" --no-same-owner --no-same-permissions -C "$destination"
