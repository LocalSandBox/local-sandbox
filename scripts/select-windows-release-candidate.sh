#!/usr/bin/env bash
set -euo pipefail
[[ $# -eq 1 ]] || { echo "usage: $0 <eligible.jsonl>" >&2; exit 2; }
input="$1"
[[ -f "$input" ]] || { echo 'eligible-run input is missing' >&2; exit 1; }
count="$(wc -l < "$input" | tr -d ' ')"
if [[ "$count" != 1 ]]; then
    echo "expected exactly one eligible release run; found $count" >&2
    jq -r '"  " + .url' "$input" >&2 || true
    exit 1
fi
head -n 1 "$input"
