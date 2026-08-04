#!/usr/bin/env bash
set -euo pipefail

[[ $# -le 1 ]] || { echo "usage: $0 [repository]" >&2; exit 2; }
repository="${1:-.}"
common_dir="$(git -C "$repository" rev-parse --path-format=absolute --git-common-dir)"
objects_dir="$common_dir/objects"
[[ -d "$objects_dir" ]] || {
    echo "Git common object directory does not exist: $objects_dir" >&2
    exit 1
}
printf '%s\n' "$objects_dir"
