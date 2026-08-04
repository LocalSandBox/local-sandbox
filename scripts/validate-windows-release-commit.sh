#!/usr/bin/env bash
set -euo pipefail

[[ $# -eq 4 ]] || {
    echo "usage: $0 <dispatch-sha> <release-sha> <version> <trusted-ref>" >&2
    exit 2
}
dispatch_sha="$1" release_sha="$2" version="$3" trusted_ref="$4"

fail() { echo "invalid Windows release commit: $*" >&2; exit 1; }
[[ "$dispatch_sha" =~ ^[0-9a-f]{40}$ ]] || fail 'dispatch SHA is malformed'
[[ "$release_sha" =~ ^[0-9a-f]{40}$ ]] || fail 'release SHA is malformed'
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || \
    fail 'release version is malformed'

git cat-file -e "$dispatch_sha^{commit}" 2>/dev/null || fail 'dispatch commit is unavailable'
git cat-file -e "$release_sha^{commit}" 2>/dev/null || fail 'release commit is unavailable'
git rev-parse --verify --quiet "$trusted_ref^{commit}" >/dev/null || fail 'trusted ref is unavailable'
git merge-base --is-ancestor "$release_sha" "$trusted_ref" || \
    fail 'release commit is not reachable from the remote default branch'

# An exact-version rerun starts at the already-prepared release commit.
[[ "$release_sha" != "$dispatch_sha" ]] || exit 0

# A new release is prepared by the workflow as one tightly constrained child commit.
[[ "$(git show -s --format=%P "$release_sha")" == "$dispatch_sha" ]] || \
    fail 'release commit is not the direct child of the dispatch commit'
[[ "$(git show -s --format=%s "$release_sha")" == "chore(release): prepare v$version" ]] || \
    fail 'release preparation commit subject is invalid'

unexpected="$(git diff-tree --no-commit-id --name-only -r "$release_sha" | \
    grep -Ev '^(Cargo\.toml|Cargo\.lock|bindings/nodejs/Cargo\.toml|bindings/nodejs/package\.json|bindings/nodejs/npm/[^/]+/package\.json)$' || true)"
[[ -z "$unexpected" ]] || {
    echo 'invalid Windows release commit: release preparation changed files outside the allowlist:' >&2
    echo "$unexpected" >&2
    exit 1
}
