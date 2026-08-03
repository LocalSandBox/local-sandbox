.schema_version == 1 and
.workflow == "release.yml" and
.release_workflow_run_id == $run and
.release_sha == $sha and
.service_evidence == "required" and
(.version | test("^[0-9]+\\.[0-9]+\\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")) and
(.publisher.subject | type == "string" and length > 0) and
(.publisher.sha256 | test("^[0-9a-f]{64}$")) and
.baseline.mode == "release" and
(.baseline.release_id | type == "number" and . > 0) and
(.baseline.tag | test("^v[0-9]+\\.[0-9]+\\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")) and
(.baseline.tag == ("v" + .baseline.version)) and
(.baseline.publisher.subject | type == "string" and length > 0) and
(.baseline.publisher.sha256 | test("^[0-9a-f]{64}$")) and
(.baseline.assets | length == 3) and
([.candidate.service, .candidate.updater, .candidate.updater_manifest, .baseline.assets[]] |
  all(
    (.name | test("^lsb-seawork-(?:service|updater)-v[0-9A-Za-z.-]+-windows-x86_64(?:-manifest\\.json|\\.zip)$")) and
    (.sha256 | test("^[0-9a-f]{64}$")) and
    (.size | type == "number" and . > 0)
  ))
and .candidate.service.name == ("lsb-seawork-service-v" + .version + "-windows-x86_64.zip")
and .candidate.updater.name == ("lsb-seawork-updater-v" + .version + "-windows-x86_64.zip")
and .candidate.updater_manifest.name == ("lsb-seawork-updater-v" + .version + "-windows-x86_64-manifest.json")
and ([.baseline.assets[].name] | sort) == ([
  "lsb-seawork-service-v" + .baseline.version + "-windows-x86_64.zip",
  "lsb-seawork-updater-v" + .baseline.version + "-windows-x86_64-manifest.json",
  "lsb-seawork-updater-v" + .baseline.version + "-windows-x86_64.zip"
] | sort)
