#!/usr/bin/env bash
set -euo pipefail

[[ $# -eq 6 ]] || {
    echo "usage: $0 <descriptor> <evidence-dir> <candidate-dir> <baseline-dir> <release-run-id> <release-sha>" >&2
    exit 2
}
descriptor="$1" evidence_dir="$2" candidate_dir="$3" baseline_dir="$4"
release_run_id="$5" release_sha="$6"
manifest="$evidence_dir/acceptance-evidence-manifest.json"
[[ -f "$descriptor" && -f "$manifest" ]] || { echo 'descriptor or evidence manifest is missing' >&2; exit 1; }
jq -e --argjson run "$release_run_id" --arg sha "$release_sha" \
    -f "$(dirname "$0")/windows-release-descriptor.jq" "$descriptor" >/dev/null

hash_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}
locate_file() {
    local directory="$1" name="$2" matches=()
    while IFS= read -r match; do matches[${#matches[@]}]="$match"; done \
        < <(find "$directory" -type f -name "$name" -print)
    (( ${#matches[@]} == 1 )) || return 1
    printf '%s\n' "${matches[0]}"
}
verify_record() {
    local directory="$1" record="$2" name sha size path
    name="$(jq -r .name <<< "$record")"; sha="$(jq -r .sha256 <<< "$record")"
    size="$(jq -r .size <<< "$record")"
    [[ "$name" != */* && "$name" != *\\* && "$name" != .* ]] || return 1
    path="$(locate_file "$directory" "$name")" || return 1
    [[ -f "$path" && ! -L "$path" ]] || return 1
    [[ "$(wc -c < "$path" | tr -d ' ')" == "$size" && "$(hash_file "$path")" == "$sha" ]]
}
for key in service updater updater_manifest; do
    verify_record "$candidate_dir" "$(jq -c ".candidate.$key" "$descriptor")" || {
        echo "candidate tuple mismatch: $key" >&2; exit 1;
    }
done
while IFS= read -r record; do
    verify_record "$baseline_dir" "$record" || { echo 'baseline tuple mismatch' >&2; exit 1; }
done < <(jq -c '.baseline.assets[]' "$descriptor")

candidate_manifest="$(locate_file "$candidate_dir" "$(jq -r .candidate.updater_manifest.name "$descriptor")")"
baseline_manifest_name="$(jq -r '.baseline.assets[] | select(.name | endswith("-manifest.json")) | .name' "$descriptor")"
baseline_manifest="$(locate_file "$baseline_dir" "$baseline_manifest_name")"
jq -e --arg subject "$(jq -r .publisher.subject "$descriptor")" \
  --arg sha "$(jq -r .publisher.sha256 "$descriptor")" --arg version "$(jq -r .version "$descriptor")" \
  '.version == $version and .publisher_subject == $subject and .publisher_sha256_thumbprint == $sha' \
  "$candidate_manifest" >/dev/null || { echo 'candidate publisher binding is invalid' >&2; exit 1; }
jq -e --arg subject "$(jq -r .baseline.publisher.subject "$descriptor")" \
  --arg sha "$(jq -r .baseline.publisher.sha256 "$descriptor")" --arg version "$(jq -r .baseline.version "$descriptor")" \
  '.version == $version and .publisher_subject == $subject and .publisher_sha256_thumbprint == $sha' \
  "$baseline_manifest" >/dev/null || { echo 'baseline publisher binding is invalid' >&2; exit 1; }

jq -e --arg sha "$release_sha" --arg service_sha "$(jq -r .candidate.service.sha256 "$descriptor")" '
  .schema_version == 1 and .profile == "release" and .status == "passed" and
  .base_commit_sha == $sha and .bindings.release_artifact_sha256 == $service_sha and
  .release_artifact.sha256 == $service_sha and
  ([.checks[].status] | all(. == "passed")) and
  ([.checks[].id] | contains([
    "mnt01.admin_live", "net01.managed_network", "rel01.artifact_trust",
    "sec01.endpoint_auth", "tst02.lifecycle", "upd01.activation_smoke",
    "win01.scm_lifecycle", "win01.service_identity_session0",
    "win01.standard_user_no_uac"
  ]))
' "$manifest" >/dev/null || { echo 'release evidence contract is incomplete' >&2; exit 1; }

while IFS=$'\t' read -r name sha size; do
    [[ "$name" =~ ^(profile-result|result-[a-z0-9-]+-(normal|beforereboot|afterreboot)|evidence-[a-z0-9._-]+\.redacted)\.json$ ]] || exit 1
    path="$evidence_dir/$name"
    [[ -f "$path" && ! -L "$path" ]] || exit 1
    [[ "$(wc -c < "$path" | tr -d ' ')" == "$size" && "$(hash_file "$path")" == "$sha" ]] || exit 1
done < <(jq -r '.files[] | [.name,.sha256,(.size|tostring)] | @tsv' "$manifest")

before="$evidence_dir/result-release-service-core-update-reboot-beforereboot.json"
after="$evidence_dir/result-release-service-core-update-reboot-afterreboot.json"
core="$evidence_dir/evidence-release-core-update.redacted.json"
service_core="$evidence_dir/evidence-service-core.redacted.json"
post="$evidence_dir/evidence-post-reboot.redacted.json"
cleanup="$evidence_dir/evidence-release-final-cleanup.redacted.json"
for path in "$before" "$after" "$core" "$service_core" "$post" "$cleanup"; do
    [[ -f "$path" ]] || { echo "required evidence is missing: $(basename "$path")" >&2; exit 1; }
done
before_boot="$(jq -er '.boot_id | select(test("^[0-9]{1,32}$"))' "$before")"
after_boot="$(jq -er '.boot_id | select(test("^[0-9]{1,32}$"))' "$after")"
[[ "$before_boot" != "$after_boot" ]] || { echo 'Windows boot identity did not change' >&2; exit 1; }

jq -e \
  --arg baseline_version "$(jq -r .baseline.version "$descriptor")" \
  --arg baseline_service "$(jq -r '.baseline.assets[] | select(.name|startswith("lsb-seawork-service-")) | .sha256' "$descriptor")" \
  --arg candidate_version "$(jq -r .version "$descriptor")" \
  --arg candidate_service "$(jq -r .candidate.service.sha256 "$descriptor")" \
  --arg candidate_updater "$(jq -r .candidate.updater.sha256 "$descriptor")" '
    .schema_version == 1 and .contract == "release-core-update-reboot-v1" and
    .check == "upd01.activation_smoke" and .status == "passed" and
    .helper_first_replacement == true and .candidate_manual_no_candidate == true and
    .baseline.version == $baseline_version and .baseline.service.sha256 == $baseline_service and
    .candidate.version == $candidate_version and .candidate.service.sha256 == $candidate_service and
    .candidate.updater.sha256 == $candidate_updater and
    .committed.current.version == $candidate_version and
    .committed.previous_last_known_good.version == $baseline_version
  ' "$core" >/dev/null || { echo 'update activation evidence is invalid' >&2; exit 1; }
jq -e '.status == "passed" and .scope == "core" and .mount_free and .seawork_mounts and .managed_network and .candidate_manual_no_candidate and .wrong_publisher_rejected' "$service_core" >/dev/null
jq -e '.status == "passed" and .post_reboot == true' "$post" >/dev/null
jq -e '.status == "passed" and .final_cleanup and .service_removed and .updater_removed and .product_roots_removed' "$cleanup" >/dev/null
echo 'release-core-update-validated'
