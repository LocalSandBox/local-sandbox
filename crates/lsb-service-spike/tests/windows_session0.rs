#![cfg(windows)]

use std::path::PathBuf;

use serde_json::Value;

#[test]
fn result_schema_example_is_machine_readable() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_lsb-service-spike"))
        .arg("--schema")
        .output()
        .expect("run schema command");
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).expect("parse schema JSON");
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["service_name"], "LocalSandboxSeaWorkSpike");
    assert_eq!(report["capability_decisions"]["ports_enabled"], false);
    assert!(report["checks"].is_array());
}

#[test]
#[ignore = "requires scripts/windows-service-spike.ps1 on disposable elevated Windows 11 x64"]
fn scm_local_system_result_satisfies_phase0_contract() {
    let path = std::env::var_os("LSB_SESSION0_SPIKE_RESULT")
        .map(PathBuf::from)
        .expect("LSB_SESSION0_SPIKE_RESULT must name a completed result JSON file");
    let report: Value = serde_json::from_slice(&std::fs::read(path).expect("read result"))
        .expect("parse result JSON");
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["complete"], true);
    assert_eq!(report["host"]["session_id"], 0);
    assert_eq!(report["host"]["token_sid"], "S-1-5-18");
    assert!(report["checks"]
        .as_array()
        .expect("checks array")
        .iter()
        .any(|check| check["name"] == "sandbox_boot_exec" && check["status"] == "passed"));
}
