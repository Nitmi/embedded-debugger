use std::fs;

use assert_cmd::Command;
use serde_json::Value;
use tempfile::tempdir;

fn fixture() -> &'static str {
    "examples/replay/stm32g4.json"
}

#[test]
fn doctor_json_uses_versioned_envelope() {
    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args(["doctor", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(result["schema_version"], "1.0");
    assert_eq!(result["ok"], true);
    assert_eq!(result["operation"], "doctor");
    assert_eq!(result["data"]["replay_available"], true);
    assert_eq!(result["data"]["probe_rs_discovery_available"], true);
    assert_eq!(result["data"]["probe_rs_guarded_flash_available"], true);
    assert_eq!(result["data"]["tools"][0]["name"], "probe-rs-cli");
    assert_eq!(result["data"]["tools"][0]["required"], false);
    assert!(result["operation_id"].as_str().unwrap().starts_with("op_"));
}

#[test]
fn replay_fixture_lists_one_probe() {
    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args(["--fixture", fixture(), "probes", "list", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(result["data"]["probes"].as_array().unwrap().len(), 1);
    assert_eq!(result["data"]["backend"], "replay");
}

#[test]
fn replay_probe_test_reports_a_complete_session_lifecycle() {
    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "--fixture",
            fixture(),
            "probes",
            "test",
            "--probe",
            "replay:stlink-v3:0039002A3432510433343034",
            "--target",
            "STM32G431CBTx",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["operation"], "probes.test");
    assert_eq!(result["data"]["risk"], "R1_REVERSIBLE_CONTROL");
    assert_eq!(result["data"]["complete"], true);
    assert_eq!(
        result["data"]["effects"]["flash_operation_requested"],
        false
    );
    assert_eq!(
        result["data"]["effects"]["backend_may_modify_volatile_target_state"],
        false
    );
    assert_eq!(
        result["data"]["effects"]["volatile_target_state_notes"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        result["data"]["operations"][0]["operation"],
        "session.attach"
    );
    assert_eq!(
        result["data"]["operations"][1]["operation"],
        "session.disconnect"
    );
}

#[test]
fn replay_snapshot_capture_reports_named_cores_and_restoration() {
    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "--fixture",
            fixture(),
            "snapshot",
            "capture",
            "--probe",
            "replay:stlink-v3:0039002A3432510433343034",
            "--target",
            "STM32G431CBTx",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["operation"], "snapshot.capture");
    assert_eq!(result["data"]["risk"], "R1_REVERSIBLE_CONTROL");
    assert_eq!(result["data"]["complete"], true);
    assert_eq!(
        result["data"]["effects"]["core_execution_state_restoration_verified"],
        true
    );
    assert_eq!(result["data"]["cores"].as_array().unwrap().len(), 1);
    assert_eq!(result["data"]["cores"][0]["index"], 0);
    assert_eq!(result["data"]["cores"][0]["name"], "core0");
    assert_eq!(result["data"]["cores"][0]["original_state"], "halted");
    assert_eq!(
        result["data"]["cores"][0]["snapshot"]["captured_state"],
        "halted"
    );
    assert_eq!(
        result["data"]["operations"][5]["operation"],
        "session.disconnect"
    );
}

#[test]
fn wrong_confirmation_returns_stable_error() {
    let directory = tempdir().unwrap();
    let evidence = directory.path().join("run.evidence.json");
    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "--fixture",
            fixture(),
            "flash",
            "execute",
            "examples/firmware/demo.bin",
            "--confirm",
            "wrong",
            "--evidence",
            evidence.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(result["ok"], false);
    assert_eq!(result["error"]["code"], "CONFIRMATION_MISMATCH");
    assert!(!evidence.exists());
}

#[test]
fn plan_then_execute_completes_replay_journey() {
    let directory = tempdir().unwrap();
    let firmware = directory.path().join("firmware.bin");
    let evidence = directory.path().join("run.evidence.json");
    fs::write(&firmware, b"cli replay firmware").unwrap();

    let plan_output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "--fixture",
            fixture(),
            "flash",
            "plan",
            firmware.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let plan: Value = serde_json::from_slice(&plan_output).unwrap();
    let confirmation = plan["data"]["confirm_digest"].as_str().unwrap();
    assert_eq!(plan["data"]["ranges"][0]["start"], "0x08000000");
    assert_eq!(plan["data"]["ranges"][0]["length"], 19);
    assert_eq!(plan["data"]["firmware"]["base_address"], "0x08000000");
    assert_eq!(plan["data"]["erase_ranges"][0]["start"], "0x08000000");
    assert_eq!(plan["data"]["erase_ranges"][0]["length"], 2048);
    assert_eq!(
        plan["data"]["policy"]["erase_mode"],
        "affected_sectors_only"
    );
    assert_eq!(plan["data"]["policy"]["preserve_unwritten_bytes"], true);

    let execute_output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "--fixture",
            fixture(),
            "flash",
            "execute",
            firmware.to_str().unwrap(),
            "--confirm",
            confirmation,
            "--evidence",
            evidence.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let execute: Value = serde_json::from_slice(&execute_output).unwrap();
    assert_eq!(execute["data"]["flash"]["verified"], true);
    assert_eq!(execute["data"]["snapshot"]["captured_state"], "halted");
    assert_eq!(execute["data"]["snapshot"]["state"], "running");
    assert!(evidence.exists());

    let evidence_data: Value = serde_json::from_slice(&fs::read(&evidence).unwrap()).unwrap();
    assert_eq!(evidence_data["plan_id"], plan["data"]["plan_id"]);
    assert_eq!(
        evidence_data["confirm_digest"],
        plan["data"]["confirm_digest"]
    );
    assert_eq!(evidence_data["flash"]["verified"], true);
    assert_eq!(evidence_data["erase_ranges"][0]["length"], 2048);
    assert_eq!(evidence_data["operations"].as_array().unwrap().len(), 8);
    assert_eq!(
        evidence_data["operations"][7]["operation"],
        "session.disconnect"
    );
}

#[test]
fn native_raw_bin_requires_base_address_before_probe_discovery() {
    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "--backend",
            "probe-rs",
            "flash",
            "plan",
            "examples/firmware/demo.bin",
            "--target",
            "STM32G431CBTx",
            "--json",
        ])
        .assert()
        .code(7)
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["error"]["code"], "CONFIG_INVALID");
    assert!(
        result["error"]["message"]
            .as_str()
            .unwrap()
            .contains("--base-address")
    );
}

#[test]
fn native_unknown_target_is_a_stable_error() {
    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "--backend",
            "probe-rs",
            "flash",
            "plan",
            "examples/firmware/demo.bin",
            "--target",
            "definitely-not-a-real-target",
            "--base-address",
            "0x08000000",
            "--json",
        ])
        .assert()
        .code(4)
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["error"]["code"], "TARGET_UNAVAILABLE");
}
