use std::fs;

use assert_cmd::Command;
use serde_json::Value;
use tempfile::tempdir;

mod support;

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
fn replay_reset_capture_reports_per_core_reset_policy() {
    let directory = tempdir().unwrap();
    let fixture = esp32s3_executable_fixture(directory.path());
    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "--fixture",
            fixture.to_str().unwrap(),
            "snapshot",
            "reset-capture",
            "--probe",
            "replay:stlink-v3:0039002A3432510433343034",
            "--target",
            "esp32s3",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["operation"], "snapshot.reset_capture");
    assert_eq!(result["data"]["complete"], true);
    assert_eq!(result["data"]["effects"]["reset_requested"], true);
    assert_eq!(
        result["data"]["effects"]["flash_operation_requested"],
        false
    );
    assert_eq!(result["data"]["cores"].as_array().unwrap().len(), 2);
    assert_eq!(
        result["data"]["cores"][0]["expected_final_state"],
        "running"
    );
    assert_eq!(result["data"]["cores"][0]["snapshot"]["state"], "running");
    assert_eq!(result["data"]["cores"][1]["expected_final_state"], "halted");
    assert_eq!(result["data"]["cores"][1]["snapshot"]["state"], "halted");
    assert_eq!(
        result["data"]["operations"][4]["operation"],
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
    assert_eq!(
        execute["data"]["flash"]["segments"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(execute["data"]["flash"]["segments"][0]["verified"], true);
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

#[test]
fn idf_plan_exposes_normalized_segments_and_execution_blockers() {
    let directory = tempdir().unwrap();
    let firmware = directory.path().join("firmware.elf");
    let fixture = esp32s3_fixture(directory.path(), true);
    fs::write(&firmware, support::minimal_esp32s3_idf_elf()).unwrap();

    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "--fixture",
            fixture.to_str().unwrap(),
            "flash",
            "plan",
            firmware.to_str().unwrap(),
            "--format",
            "idf",
            "--flash-size",
            "8MB",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["data"]["firmware"]["format"], "idf");
    assert_eq!(
        result["data"]["firmware"]["segments"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert_eq!(
        result["data"]["firmware"]["segments"][0]["kind"],
        "bootloader"
    );
    assert_eq!(
        result["data"]["firmware"]["segments"][0]["start"],
        "0x00000000"
    );
    assert_eq!(
        result["data"]["firmware"]["segments"][1]["kind"],
        "partition_table"
    );
    assert_eq!(
        result["data"]["firmware"]["segments"][1]["start"],
        "0x00008000"
    );
    assert_eq!(
        result["data"]["firmware"]["segments"][2]["kind"],
        "application"
    );
    assert_eq!(
        result["data"]["firmware"]["segments"][2]["start"],
        "0x00010000"
    );
    assert_eq!(result["data"]["ranges"].as_array().unwrap().len(), 3);
    assert_eq!(result["data"]["execution"]["supported"], false);
    assert_eq!(
        result["data"]["execution"]["blockers"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        result["data"]["execution"]["blockers"][0]["code"],
        "SEGMENTED_FLASH_ACCEPTANCE_REQUIRED"
    );
    assert_eq!(
        result["data"]["execution"]["blockers"][1]["code"],
        "MULTI_CORE_POST_FLASH_POLICY_UNVERIFIED"
    );
    assert_eq!(
        result["data"]["firmware"]["image_options"]["flash_size"],
        8 * 1024 * 1024
    );
}

#[test]
fn idf_execute_is_blocked_before_hardware_or_evidence() {
    let directory = tempdir().unwrap();
    let firmware = directory.path().join("firmware.elf");
    let evidence = directory.path().join("run.evidence.json");
    let fixture = esp32s3_fixture(directory.path(), true);
    fs::write(&firmware, support::minimal_esp32s3_idf_elf()).unwrap();

    let common = [
        "--fixture",
        fixture.to_str().unwrap(),
        "flash",
        "plan",
        firmware.to_str().unwrap(),
        "--format",
        "idf",
        "--flash-size",
        "8MB",
        "--json",
    ];
    let plan_output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args(common)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let plan: Value = serde_json::from_slice(&plan_output).unwrap();
    let confirmation = plan["data"]["confirm_digest"].as_str().unwrap();

    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "--fixture",
            fixture.to_str().unwrap(),
            "flash",
            "execute",
            firmware.to_str().unwrap(),
            "--format",
            "idf",
            "--flash-size",
            "8MB",
            "--confirm",
            confirmation,
            "--evidence",
            evidence.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .code(6)
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["error"]["code"], "CAPABILITY_UNAVAILABLE");
    assert_eq!(
        result["error"]["details"]["probe_enumeration_performed"],
        true
    );
    assert_eq!(result["error"]["details"]["target_session_attached"], false);
    assert_eq!(
        result["error"]["details"]["flash_operation_requested"],
        false
    );
    assert_eq!(result["error"]["details"]["reset_requested"], false);
    assert!(!evidence.exists());
}

#[test]
fn idf_segmented_replay_execution_reports_verified_segments() {
    let directory = tempdir().unwrap();
    let firmware = directory.path().join("firmware.elf");
    let evidence = directory.path().join("run.evidence.json");
    let fixture = esp32c3_fixture(directory.path());
    fs::write(&firmware, support::minimal_esp32c3_idf_elf()).unwrap();

    let plan_output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "--fixture",
            fixture.to_str().unwrap(),
            "flash",
            "plan",
            firmware.to_str().unwrap(),
            "--format",
            "idf",
            "--flash-size",
            "8MB",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let plan: Value = serde_json::from_slice(&plan_output).unwrap();
    let confirmation = plan["data"]["confirm_digest"].as_str().unwrap();
    assert_eq!(plan["data"]["execution"]["supported"], true);

    let execute_output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "--fixture",
            fixture.to_str().unwrap(),
            "flash",
            "execute",
            firmware.to_str().unwrap(),
            "--format",
            "idf",
            "--flash-size",
            "8MB",
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
    assert_eq!(
        execute["data"]["flash"]["segments"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert!(
        execute["data"]["flash"]["segments"]
            .as_array()
            .unwrap()
            .iter()
            .all(|segment| segment["verified"] == true)
    );
    assert!(evidence.exists());
}

#[test]
fn idf_multi_core_replay_execution_reports_post_flash_inventory() {
    let directory = tempdir().unwrap();
    let firmware = directory.path().join("firmware.elf");
    let evidence = directory.path().join("run.evidence.json");
    let fixture = esp32s3_executable_fixture(directory.path());
    fs::write(&firmware, support::minimal_esp32s3_idf_elf()).unwrap();

    let plan_output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "--fixture",
            fixture.to_str().unwrap(),
            "flash",
            "plan",
            firmware.to_str().unwrap(),
            "--format",
            "idf",
            "--flash-size",
            "8MB",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let plan: Value = serde_json::from_slice(&plan_output).unwrap();
    let confirmation = plan["data"]["confirm_digest"].as_str().unwrap();
    assert_eq!(plan["data"]["execution"]["supported"], true);

    let execute_output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "--fixture",
            fixture.to_str().unwrap(),
            "flash",
            "execute",
            firmware.to_str().unwrap(),
            "--format",
            "idf",
            "--flash-size",
            "8MB",
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

    assert_eq!(
        execute["data"]["flash"]["segments"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert_eq!(
        execute["data"]["post_flash_cores"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(execute["data"]["post_flash_cores"][0]["available"], true);
    assert_eq!(execute["data"]["post_flash_cores"][1]["available"], true);
    assert_eq!(
        execute["data"]["post_flash_cores"][1]["expected_final_state"],
        "halted"
    );
    assert_eq!(
        execute["data"]["snapshot"],
        execute["data"]["post_flash_cores"][0]["snapshot"]
    );

    let bundle: Value = serde_json::from_slice(&fs::read(&evidence).unwrap()).unwrap();
    assert_eq!(
        bundle["post_flash_cores"],
        execute["data"]["post_flash_cores"]
    );
    assert_eq!(bundle["core"], execute["data"]["snapshot"]);
    assert_eq!(bundle["complete"], true);
}

fn esp32s3_fixture(directory: &std::path::Path, reset: bool) -> std::path::PathBuf {
    let mut value: Value =
        serde_json::from_slice(&fs::read("examples/replay/stm32g4.json").unwrap()).unwrap();
    value["target"]["name"] = "esp32s3".into();
    value["target"]["architecture"] = "xtensa".into();
    value["target"]["core_count"] = 2.into();
    value["capabilities"]["reset"] = reset.into();
    value["live_cores"] = serde_json::json!([
        {
            "index": 0,
            "name": "cpu0",
            "architecture": "xtensa",
            "available": true,
            "original_state": "running",
            "snapshot": {
                "captured_state": "halted",
                "state": "running",
                "pc": "0x42000000",
                "sp": "0x3fcf0000",
                "registers": {"lr": "0x42000004"},
                "halt_reason": "request"
            },
            "unavailable_reason": null
        },
        {
            "index": 1,
            "name": "cpu1",
            "architecture": "xtensa",
            "available": false,
            "original_state": null,
            "snapshot": null,
            "unavailable_reason": "core is not enabled"
        }
    ]);
    value["flash"]["base_address"] = "0x00000000".into();
    value["flash"]["erase_ranges"] = serde_json::json!([{
        "start": "0x00000000",
        "length": 131072,
    }]);
    let path = directory.join("esp32s3.json");
    fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    path
}

fn esp32s3_executable_fixture(directory: &std::path::Path) -> std::path::PathBuf {
    let path = esp32s3_fixture(directory, true);
    let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    value["capabilities"]["segmented_flash"] = true.into();
    value["capabilities"]["multi_core_post_flash"] = true.into();
    value["post_flash_cores"] = serde_json::json!([
        {
            "index": 0,
            "name": "cpu0",
            "architecture": "xtensa",
            "available": true,
            "expected_final_state": "running",
            "snapshot": {
                "captured_state": "halted",
                "state": "running",
                "pc": "0x42010000",
                "sp": "0x3fcf0000",
                "registers": {"lr": "0x42010004"},
                "halt_reason": "request"
            },
            "unavailable_reason": null
        },
        {
            "index": 1,
            "name": "cpu1",
            "architecture": "xtensa",
            "available": true,
            "expected_final_state": "halted",
            "snapshot": {
                "captured_state": "halted",
                "state": "halted",
                "pc": "0x400003c0",
                "sp": "0x00000000",
                "registers": {"lr": "0x00000000"},
                "halt_reason": "breakpoint"
            },
            "unavailable_reason": null
        }
    ]);
    fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    path
}

fn esp32c3_fixture(directory: &std::path::Path) -> std::path::PathBuf {
    let mut value: Value =
        serde_json::from_slice(&fs::read("examples/replay/stm32g4.json").unwrap()).unwrap();
    value["target"]["name"] = "esp32c3".into();
    value["target"]["architecture"] = "riscv".into();
    value["target"]["core_count"] = 1.into();
    value["capabilities"]["segmented_flash"] = true.into();
    value["flash"]["base_address"] = "0x00000000".into();
    value["flash"]["erase_ranges"] = serde_json::json!([{
        "start": "0x00000000",
        "length": 131072,
    }]);
    let path = directory.join("esp32c3.json");
    fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    path
}
