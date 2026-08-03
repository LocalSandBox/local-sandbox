#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture="$(mktemp -d "${TMPDIR:-/tmp}/lsb-submission-test.XXXXXX")"
trap 'rm -rf -- "$fixture"' EXIT
descriptor="$fixture/descriptor.json"
evidence="$fixture/evidence"
candidate="$fixture/candidate/out"
baseline="$fixture/baseline"
mkdir -p "$evidence" "$candidate" "$baseline"
run_id=42
release_sha="$(printf 'a%.0s' {1..40})"
publisher_sha="$(printf 'b%.0s' {1..64})"

hash_file() { shasum -a 256 "$1" | awk '{print $1}'; }
record() {
    jq -cn --arg name "$(basename "$1")" --arg sha256 "$(hash_file "$1")" \
        --argjson size "$(wc -c < "$1" | tr -d ' ')" \
        '{name:$name,sha256:$sha256,size:$size}'
}
printf 'candidate-service\n' > "$candidate/lsb-seawork-service-v1.2.3-windows-x86_64.zip"
printf 'candidate-updater\n' > "$candidate/lsb-seawork-updater-v1.2.3-windows-x86_64.zip"
jq -n --arg publisher "$publisher_sha" '{version:"1.2.3",publisher_subject:"CN=Fixture",publisher_sha256_thumbprint:$publisher}' \
    > "$candidate/lsb-seawork-updater-v1.2.3-windows-x86_64-manifest.json"
printf 'baseline-service\n' > "$baseline/lsb-seawork-service-v1.2.2-windows-x86_64.zip"
printf 'baseline-updater\n' > "$baseline/lsb-seawork-updater-v1.2.2-windows-x86_64.zip"
jq -n --arg publisher "$publisher_sha" '{version:"1.2.2",publisher_subject:"CN=Fixture",publisher_sha256_thumbprint:$publisher}' \
    > "$baseline/lsb-seawork-updater-v1.2.2-windows-x86_64-manifest.json"

candidate_service="$(record "$candidate/lsb-seawork-service-v1.2.3-windows-x86_64.zip")"
candidate_updater="$(record "$candidate/lsb-seawork-updater-v1.2.3-windows-x86_64.zip")"
candidate_manifest="$(record "$candidate/lsb-seawork-updater-v1.2.3-windows-x86_64-manifest.json")"
baseline_assets="$(for path in "$baseline"/*; do
    record "$path" | jq --arg url 'https://api.github.test/releases/assets/1' '. + {api_url:$url}'
done | jq -s .)"
jq -n --argjson run "$run_id" --arg sha "$release_sha" --arg publisher "$publisher_sha" \
  --argjson service "$candidate_service" --argjson updater "$candidate_updater" \
  --argjson updater_manifest "$candidate_manifest" --argjson assets "$baseline_assets" '{
    schema_version:1, workflow:"release.yml", release_workflow_run_id:$run,
    release_workflow_run_attempt:1, release_sha:$sha, version:"1.2.3", service_evidence:"required",
    publisher:{subject:"CN=Fixture",sha256:$publisher},
    candidate:{service:$service,updater:$updater,updater_manifest:$updater_manifest},
    baseline:{mode:"release",release_id:7,tag:"v1.2.2",version:"1.2.2",
      qualification:"bootstrap-skipped-release",publisher:{subject:"CN=Fixture",sha256:$publisher},assets:$assets}
  }' > "$descriptor"

candidate_sha="$(jq -r .candidate.service.sha256 "$descriptor")"
baseline_service_sha="$(jq -r '.baseline.assets[] | select(.name|startswith("lsb-seawork-service-")) | .sha256' "$descriptor")"
candidate_updater_sha="$(jq -r .candidate.updater.sha256 "$descriptor")"
jq -n --arg baseline_service "$baseline_service_sha" --arg candidate_service "$candidate_sha" \
  --arg candidate_updater "$candidate_updater_sha" '{
    schema_version:1,contract:"release-core-update-reboot-v1",check:"upd01.activation_smoke",status:"passed",
    baseline:{version:"1.2.2",service:{sha256:$baseline_service}},
    candidate:{version:"1.2.3",service:{sha256:$candidate_service},updater:{sha256:$candidate_updater}},
    helper_first_replacement:true,candidate_manual_no_candidate:true,
    committed:{current:{version:"1.2.3"},previous_last_known_good:{version:"1.2.2"}}
  }' > "$evidence/evidence-release-core-update.redacted.json"
jq -n '{status:"passed",scope:"core",mount_free:true,seawork_mounts:true,managed_network:true,candidate_manual_no_candidate:true,wrong_publisher_rejected:true}' \
  > "$evidence/evidence-service-core.redacted.json"
jq -n '{status:"passed",post_reboot:true}' > "$evidence/evidence-post-reboot.redacted.json"
jq -n '{status:"passed",final_cleanup:true,service_removed:true,updater_removed:true,product_roots_removed:true}' \
  > "$evidence/evidence-release-final-cleanup.redacted.json"
jq -n '{boot_id:"100"}' > "$evidence/result-release-service-core-update-reboot-beforereboot.json"
jq -n '{boot_id:"101"}' > "$evidence/result-release-service-core-update-reboot-afterreboot.json"
files="$(for path in "$evidence"/*.json; do record "$path"; done | jq -s .)"
checks='["mnt01.admin_live","net01.managed_network","rel01.artifact_trust","sec01.endpoint_auth","tst02.lifecycle","upd01.activation_smoke","win01.scm_lifecycle","win01.service_identity_session0","win01.standard_user_no_uac"]'
jq -n --arg sha "$release_sha" --arg service_sha "$candidate_sha" --argjson files "$files" \
  --argjson checks "$checks" '{
    schema_version:1,run_id:"fixture",snapshot_sha:$sha,source_tree_sha:$sha,base_commit_sha:$sha,
    profile:"release",status:"passed",bindings:{release_artifact_sha256:$service_sha},
    release_artifact:{sha256:$service_sha},checks:[$checks[]|{id:.,status:"passed"}],files:$files
  }' > "$evidence/acceptance-evidence-manifest.json"

verify=("$repo_root/scripts/verify-windows-release-submission.sh" "$descriptor" "$evidence" \
    "$fixture/candidate" "$baseline" "$run_id" "$release_sha")
"${verify[@]}" | grep -qx release-core-update-validated
expect_rejected() { if "$@" >/dev/null 2>&1; then echo "rejection case passed unexpectedly" >&2; exit 1; fi; }

cp -R "$evidence" "$fixture/missing"
rm "$fixture/missing/evidence-post-reboot.redacted.json"
expect_rejected "$repo_root/scripts/verify-windows-release-submission.sh" "$descriptor" "$fixture/missing" "$fixture/candidate" "$baseline" "$run_id" "$release_sha"
cp -R "$evidence" "$fixture/malformed"
printf '{' > "$fixture/malformed/acceptance-evidence-manifest.json"
expect_rejected "$repo_root/scripts/verify-windows-release-submission.sh" "$descriptor" "$fixture/malformed" "$fixture/candidate" "$baseline" "$run_id" "$release_sha"
cp -R "$evidence" "$fixture/tampered"
printf 'tamper\n' >> "$fixture/tampered/evidence-service-core.redacted.json"
expect_rejected "$repo_root/scripts/verify-windows-release-submission.sh" "$descriptor" "$fixture/tampered" "$fixture/candidate" "$baseline" "$run_id" "$release_sha"
expect_rejected "${verify[@]:0:5}" 43 "$release_sha"
expect_rejected "${verify[@]:0:5}" "$run_id" "$(printf 'c%.0s' {1..40})"
cp -R "$evidence" "$fixture/incomplete"
jq 'del(.checks[0])' "$fixture/incomplete/acceptance-evidence-manifest.json" > "$fixture/incomplete/manifest.tmp"
mv "$fixture/incomplete/manifest.tmp" "$fixture/incomplete/acceptance-evidence-manifest.json"
expect_rejected "$repo_root/scripts/verify-windows-release-submission.sh" "$descriptor" "$fixture/incomplete" "$fixture/candidate" "$baseline" "$run_id" "$release_sha"
cp -R "$evidence" "$fixture/failed"
jq '.status="failed"' "$fixture/failed/acceptance-evidence-manifest.json" > "$fixture/failed/manifest.tmp"
mv "$fixture/failed/manifest.tmp" "$fixture/failed/acceptance-evidence-manifest.json"
expect_rejected "$repo_root/scripts/verify-windows-release-submission.sh" "$descriptor" "$fixture/failed" "$fixture/candidate" "$baseline" "$run_id" "$release_sha"

mkdir "$fixture/unsafe-source"
printf 'unsafe\n' > "$fixture/unsafe-source/secret"
tar -czf "$fixture/unsafe.tgz" -C "$fixture/unsafe-source" .
expect_rejected "$repo_root/scripts/extract-windows-release-evidence.sh" "$fixture/unsafe.tgz" "$fixture/unsafe-output"
head -c 46081 /dev/urandom > "$fixture/oversized.tgz"
expect_rejected "$repo_root/scripts/extract-windows-release-evidence.sh" "$fixture/oversized.tgz" "$fixture/oversized-output"
mkdir "$fixture/expanded-source"
dd if=/dev/zero of="$fixture/expanded-source/evidence-large.redacted.json" bs=1048576 count=9 2>/dev/null
tar -czf "$fixture/expanded.tgz" -C "$fixture/expanded-source" .
expect_rejected "$repo_root/scripts/extract-windows-release-evidence.sh" "$fixture/expanded.tgz" "$fixture/expanded-output"
