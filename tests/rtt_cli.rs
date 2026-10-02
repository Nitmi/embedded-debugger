//! CLI checks use Replay or pure built-in target planning, never connected hardware.
use std::fs;

use assert_cmd::Command;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::tempdir;

fn replay_arguments() -> Vec<&'static str> {
    vec![
        "--json",
        "--backend",
        "replay",
        "--fixture",
        "examples/replay/stm32g4.json",
    ]
}

fn selection() -> Vec<&'static str> {
    vec![
        "--probe",
        "replay:stlink-v3:0039002A3432510433343034",
        "--target",
        "STM32G431CBTx",
        "--control-block",
        "0x20000100",
        "--duration-ms",
        "20",
        "--poll-interval-ms",
        "1",
        "--max-bytes",
        "5",
    ]
}

fn plan() -> Value {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("embedded-debugger"))
        .args(replay_arguments())
        .args(["rtt", "plan"])
        .args(selection())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice(&output).unwrap()
}

#[test]
fn replay_capture_returns_a_small_summary_and_lossless_external_evidence() {
    let plan = plan();
    let dir = tempdir().unwrap();
    let file = dir.path().join("rtt.jsonl");
    let output = Command::new(assert_cmd::cargo::cargo_bin!("embedded-debugger"))
        .args(replay_arguments())
        .args(["rtt", "capture"])
        .args(selection())
        .args([
            "--confirm",
            plan["data"]["confirm_digest"].as_str().unwrap(),
            "--evidence",
        ])
        .arg(&file)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(report["operation"], "rtt.capture");
    assert_eq!(report["data"]["bytes_captured"], 5);
    assert_eq!(report["data"]["hardware_access"], false);
    assert_eq!(report["data"]["disconnected"], true);
    assert!(report["data"].get("chunks").is_none());
    let bytes = fs::read(&file).unwrap();
    assert_eq!(
        report["data"]["evidence"]["sha256"],
        hex::encode(Sha256::digest(&bytes))
    );
    let events = String::from_utf8(bytes)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        events
            .iter()
            .find(|event| event["event"] == "rtt.chunk")
            .unwrap()["data"],
        hex::encode(b"EAT_R")
    );
}

#[test]
fn bad_confirmation_does_not_create_evidence_or_open_a_session() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("must-not-exist.jsonl");
    let output = Command::new(assert_cmd::cargo::cargo_bin!("embedded-debugger"))
        .args(replay_arguments())
        .args(["rtt", "capture"])
        .args(selection())
        .args(["--confirm", "wrong", "--evidence"])
        .arg(&file)
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();
    let report: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(report["error"]["code"], "CONFIRMATION_MISMATCH");
    assert!(!file.exists());
}

#[test]
fn native_planning_does_not_require_a_real_probe_and_reports_cursor_effect() {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("embedded-debugger"))
        .args([
            "--json",
            "--backend",
            "probe-rs",
            "rtt",
            "plan",
            "--probe",
            "1366:1061:not-a-connected-serial",
            "--target",
            "nRF52840_xxAA",
            "--control-block",
            "0x20000100",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(report["operation"], "rtt.plan");
    assert_eq!(report["data"]["hardware_access"], false);
    assert_eq!(report["data"]["hardware_acceptance_verified"], false);
    assert_eq!(
        report["data"]["effects"]["target_rtt_read_cursor_write"],
        true
    );
    assert_eq!(report["data"]["effects"]["reset_requested"], false);
    assert_eq!(report["data"]["effects"]["halt_requested"], false);
    assert_eq!(report["data"]["memory_scope"]["start"], "0x20000000");
}

#[test]
fn unsupported_openocd_and_invalid_limits_fail_explicitly() {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("embedded-debugger"))
        .args(["--json", "--backend", "openocd", "rtt", "plan"])
        .args(selection())
        .assert()
        .code(6)
        .get_output()
        .stdout
        .clone();
    let report: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(report["error"]["code"], "CAPABILITY_UNAVAILABLE");
    Command::new(assert_cmd::cargo::cargo_bin!("embedded-debugger"))
        .args(replay_arguments())
        .args([
            "rtt",
            "plan",
            "--probe",
            "exact",
            "--target",
            "STM32G431CBTx",
            "--control-block",
            "0x20000100",
            "--max-bytes",
            "1048577",
        ])
        .assert()
        .code(7);
}
