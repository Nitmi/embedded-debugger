use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    process::{Command as ProcessCommand, Stdio},
    thread,
    time::{Duration, Instant},
};

use assert_cmd::Command;
use serde_json::Value;
use tempfile::tempdir;

mod support;

fn fixture() -> &'static str {
    "examples/replay/stm32g4.json"
}

#[test]
fn replay_session_server_supports_an_interactive_jsonl_lifecycle() {
    let mut child = ProcessCommand::new(assert_cmd::cargo::cargo_bin!("embedded-debugger"))
        .args([
            "--fixture",
            fixture(),
            "session",
            "serve",
            "--target",
            "STM32G431CBTx",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    writeln!(
        stdin,
        "{}",
        serde_json::json!({
            "schema_version": "1.0",
            "request_id": "open",
            "operation": "session.open",
            "probe": "replay:stlink-v3:0039002A3432510433343034",
            "target": "STM32G431CBTx",
        })
    )
    .unwrap();
    stdin.flush().unwrap();
    let opened = read_jsonl_response(&mut stdout);
    let session_id = opened["data"]["session"]["session_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(opened["request_id"], "open");
    assert_eq!(opened["data"]["state"], "open");
    assert_eq!(opened["data"]["lease_policy"]["idle_timeout_ms"], 300000);
    assert_eq!(
        opened["data"]["lease_policy"]["idle_timeout_action"],
        "close_and_exit"
    );

    writeln!(
        stdin,
        "{}",
        serde_json::json!({
            "schema_version": "1.0",
            "request_id": "premature-shutdown",
            "operation": "server.shutdown",
        })
    )
    .unwrap();
    stdin.flush().unwrap();
    let premature_shutdown = read_jsonl_response(&mut stdout);
    assert_eq!(premature_shutdown["ok"], false);
    assert_eq!(
        premature_shutdown["error"]["details"]["required_operation"],
        "session.close"
    );

    for (request_id, operation, expected_state) in [
        ("run", "core.run", "running"),
        ("halt", "core.halt", "halted"),
        ("status", "core.status", "halted"),
    ] {
        writeln!(
            stdin,
            "{}",
            serde_json::json!({
                "schema_version": "1.0",
                "request_id": request_id,
                "operation": operation,
                "session_id": session_id,
                "core": 0,
            })
        )
        .unwrap();
        stdin.flush().unwrap();
        let response = read_jsonl_response(&mut stdout);
        assert_eq!(response["request_id"], request_id);
        assert_eq!(response["data"]["state_scope"], "active_session");
        assert_eq!(response["data"]["core"]["state"], expected_state);
    }

    writeln!(
        stdin,
        "{}",
        serde_json::json!({
            "schema_version": "1.0",
            "request_id": "step",
            "operation": "core.step",
            "session_id": session_id,
            "core": 0,
        })
    )
    .unwrap();
    stdin.flush().unwrap();
    let step = read_jsonl_response(&mut stdout);
    assert_eq!(step["operation"], "core.step");
    assert_eq!(step["data"]["state_scope"], "active_session");
    assert_eq!(step["data"]["core"]["original_state"], "halted");
    assert_eq!(step["data"]["core"]["state"], "halted");
    assert_eq!(step["data"]["core"]["halt_reason"], "step");
    assert_eq!(step["data"]["core"]["pc_before"], "0x08001234");
    assert_eq!(step["data"]["core"]["pc_after"], "0x08001236");
    assert_eq!(step["data"]["effects"]["instruction_step_requested"], true);

    writeln!(
        stdin,
        "{}",
        serde_json::json!({
            "schema_version": "1.0",
            "request_id": "continue-until-halt",
            "operation": "core.continue_until_halt",
            "session_id": session_id,
            "core": 0,
            "timeout_ms": 100,
            "poll_interval_ms": 25,
        })
    )
    .unwrap();
    stdin.flush().unwrap();
    let waited = read_jsonl_response(&mut stdout);
    assert_eq!(waited["ok"], true);
    assert_eq!(waited["operation"], "core.continue_until_halt");
    assert_eq!(waited["data"]["wait"]["outcome"], "halted");
    assert_eq!(waited["data"]["wait"]["state"], "halted");
    assert_eq!(waited["data"]["wait"]["halt_reason"], "breakpoint");
    assert_eq!(waited["data"]["wait"]["elapsed_ms"], 75);
    assert_eq!(waited["data"]["wait"]["poll_count"], 3);

    writeln!(
        stdin,
        "{}",
        serde_json::json!({
            "schema_version": "1.0",
            "request_id": "continue-until-timeout",
            "operation": "core.continue_until_halt",
            "session_id": session_id,
            "core": 0,
            "timeout_ms": 100,
            "poll_interval_ms": 25,
        })
    )
    .unwrap();
    stdin.flush().unwrap();
    let timed_out = read_jsonl_response(&mut stdout);
    assert_eq!(timed_out["ok"], true);
    assert_eq!(timed_out["data"]["wait"]["outcome"], "timed_out");
    assert_eq!(timed_out["data"]["wait"]["state"], "running");
    assert_eq!(timed_out["data"]["wait"]["halt_reason"], Value::Null);
    assert_eq!(timed_out["data"]["wait"]["elapsed_ms"], 100);
    assert_eq!(timed_out["data"]["wait"]["poll_count"], 4);
    assert_eq!(timed_out["data"]["complete"], true);
    assert!(
        timed_out["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning
                .as_str()
                .unwrap()
                .contains("single-request JSONL server"))
    );

    for (request_id, operation, expected_state) in [
        ("status-after-timeout", "core.status", "running"),
        ("halt-after-timeout", "core.halt", "halted"),
    ] {
        writeln!(
            stdin,
            "{}",
            serde_json::json!({
                "schema_version": "1.0",
                "request_id": request_id,
                "operation": operation,
                "session_id": session_id,
                "core": 0,
            })
        )
        .unwrap();
        stdin.flush().unwrap();
        let response = read_jsonl_response(&mut stdout);
        assert_eq!(response["ok"], true);
        assert_eq!(response["data"]["core"]["state"], expected_state);
    }

    writeln!(
        stdin,
        "{}",
        serde_json::json!({
            "schema_version": "1.0",
            "request_id": "breakpoints-list",
            "operation": "breakpoints.list",
            "session_id": session_id,
            "core": 0,
        })
    )
    .unwrap();
    stdin.flush().unwrap();
    let listed_breakpoints = read_jsonl_response(&mut stdout);
    assert_eq!(listed_breakpoints["data"]["core"]["capacity"], 6);
    assert_eq!(listed_breakpoints["data"]["core"]["changed"], false);
    assert!(
        listed_breakpoints["data"]["core"]["after"]
            .as_array()
            .unwrap()
            .iter()
            .all(|slot| slot["address"].is_null())
    );

    writeln!(
        stdin,
        "{}",
        serde_json::json!({
            "schema_version": "1.0",
            "request_id": "breakpoints-set",
            "operation": "breakpoints.set",
            "session_id": session_id,
            "core": 0,
            "address": "0x08001234",
        })
    )
    .unwrap();
    stdin.flush().unwrap();
    let set_breakpoint = read_jsonl_response(&mut stdout);
    assert_eq!(set_breakpoint["data"]["core"]["affected_slot"], 0);
    assert_eq!(
        set_breakpoint["data"]["core"]["after"][0]["address"],
        "0x08001234"
    );
    assert_eq!(
        set_breakpoint["data"]["effects"]["hardware_breakpoint_configuration_requested"],
        true
    );
    assert_eq!(
        set_breakpoint["data"]["effects"]["hardware_breakpoint_state_verified"],
        true
    );

    writeln!(
        stdin,
        "{}",
        serde_json::json!({
            "schema_version": "1.0",
            "request_id": "breakpoints-clear",
            "operation": "breakpoints.clear",
            "session_id": session_id,
            "core": 0,
            "slot": 0,
        })
    )
    .unwrap();
    stdin.flush().unwrap();
    let cleared_breakpoint = read_jsonl_response(&mut stdout);
    assert_eq!(cleared_breakpoint["data"]["core"]["affected_slot"], 0);
    assert!(cleared_breakpoint["data"]["core"]["after"][0]["address"].is_null());

    writeln!(
        stdin,
        "{}",
        serde_json::json!({
            "schema_version": "1.0",
            "request_id": "breakpoints-set-for-close",
            "operation": "breakpoints.set",
            "session_id": session_id,
            "core": 0,
            "address": "0x08002000",
            "slot": 2,
        })
    )
    .unwrap();
    stdin.flush().unwrap();
    assert_eq!(
        read_jsonl_response(&mut stdout)["data"]["core"]["affected_slot"],
        2
    );

    writeln!(
        stdin,
        "{}",
        serde_json::json!({
            "schema_version": "1.0",
            "request_id": "breakpoints-clear-all",
            "operation": "breakpoints.clear_all",
            "session_id": session_id,
            "core": 0,
        })
    )
    .unwrap();
    stdin.flush().unwrap();
    let cleared_all = read_jsonl_response(&mut stdout);
    assert!(
        cleared_all["data"]["core"]["after"]
            .as_array()
            .unwrap()
            .iter()
            .all(|slot| slot["address"].is_null())
    );

    writeln!(
        stdin,
        "{}",
        serde_json::json!({
            "schema_version": "1.0",
            "request_id": "breakpoints-set-for-close-again",
            "operation": "breakpoints.set",
            "session_id": session_id,
            "core": 0,
            "address": "0x08002000",
            "slot": 2,
        })
    )
    .unwrap();
    stdin.flush().unwrap();
    assert_eq!(
        read_jsonl_response(&mut stdout)["data"]["core"]["affected_slot"],
        2
    );

    writeln!(
        stdin,
        "{}",
        serde_json::json!({
            "schema_version": "1.0",
            "request_id": "registers",
            "operation": "registers.read",
            "session_id": session_id,
            "core": 0,
            "names": ["pc", "sp"],
        })
    )
    .unwrap();
    stdin.flush().unwrap();
    let registers = read_jsonl_response(&mut stdout);
    assert_eq!(registers["operation"], "registers.read");
    assert_eq!(registers["data"]["state_scope"], "active_session");
    assert_eq!(registers["data"]["core"]["original_state"], "halted");
    assert_eq!(registers["data"]["core"]["state"], "halted");
    assert_eq!(
        registers["data"]["effects"]["core_execution_state_restoration_verified"],
        true
    );
    assert_eq!(
        registers["data"]["core"]["registers"]
            .as_array()
            .unwrap()
            .len(),
        2
    );

    writeln!(
        stdin,
        "{}",
        serde_json::json!({
            "schema_version": "1.0",
            "request_id": "memory",
            "operation": "memory.read",
            "session_id": session_id,
            "core": 0,
            "address": "0x20007F04",
            "length": 8,
        })
    )
    .unwrap();
    stdin.flush().unwrap();
    let memory = read_jsonl_response(&mut stdout);
    assert_eq!(memory["operation"], "memory.read");
    assert_eq!(memory["data"]["core"]["original_state"], "halted");
    assert_eq!(memory["data"]["core"]["state"], "halted");
    assert_eq!(memory["data"]["data"], "0405060708090a0b");
    assert_eq!(memory["data"]["effects"]["memory_read_requested"], true);

    writeln!(
        stdin,
        "{}",
        serde_json::json!({
            "schema_version": "1.0",
            "request_id": "session-status",
            "operation": "session.status",
            "session_id": session_id,
        })
    )
    .unwrap();
    stdin.flush().unwrap();
    let status = read_jsonl_response(&mut stdout);
    assert_eq!(status["data"]["state"], "open");
    assert_eq!(status["data"]["observed_core_indexes"][0], 0);
    assert_eq!(status["data"]["hardware_breakpoint_core_indexes"][0], 0);

    writeln!(
        stdin,
        "{}",
        serde_json::json!({
            "schema_version": "1.0",
            "request_id": "close",
            "operation": "session.close",
            "session_id": session_id,
        })
    )
    .unwrap();
    stdin.flush().unwrap();
    let closed = read_jsonl_response(&mut stdout);
    assert_eq!(closed["data"]["state"], "closed");
    assert_eq!(
        closed["data"]["final_core_observations"][0]["state"],
        "running"
    );
    assert_eq!(
        closed["data"]["hardware_breakpoint_cleanup"][0]["after"][2]["address"],
        Value::Null
    );
    assert_eq!(
        closed["data"]["effects"]["hardware_breakpoint_state_verified"],
        true
    );

    writeln!(
        stdin,
        "{}",
        serde_json::json!({
            "schema_version": "1.0",
            "request_id": "shutdown",
            "operation": "server.shutdown",
        })
    )
    .unwrap();
    stdin.flush().unwrap();
    let shutdown = read_jsonl_response(&mut stdout);
    assert_eq!(shutdown["data"]["shutdown"], true);
    drop(stdin);

    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
}

#[test]
fn replay_mcp_server_supports_initialize_and_persistent_session_tool_calls() {
    let mut child = ProcessCommand::new(assert_cmd::cargo::cargo_bin!("embedded-debugger"))
        .args([
            "--fixture",
            fixture(),
            "mcp",
            "serve",
            "--idle-timeout-ms",
            "0",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    writeln!(
        stdin,
        "{}",
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        })
    )
    .unwrap();
    stdin.flush().unwrap();
    let initialize = read_jsonl_response(&mut stdout);
    assert_eq!(initialize["result"]["protocolVersion"], "2025-06-18");

    writeln!(
        stdin,
        "{}",
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        })
    )
    .unwrap();
    stdin.flush().unwrap();
    let tools = read_jsonl_response(&mut stdout);
    assert_eq!(
        tools["result"]["tools"][0]["name"],
        "embedded_debugger_request"
    );

    writeln!(
        stdin,
        "{}",
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "embedded_debugger_request",
                "arguments": {
                    "operation": "session.open",
                    "probe": "replay:stlink-v3:0039002A3432510433343034",
                    "target": "STM32G431CBTx"
                }
            }
        })
    )
    .unwrap();
    stdin.flush().unwrap();
    let open = read_jsonl_response(&mut stdout);
    assert_eq!(open["result"]["isError"], false);
    let open_envelope: Value =
        serde_json::from_str(open["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    let session_id = open_envelope["data"]["session"]["session_id"]
        .as_str()
        .unwrap()
        .to_string();

    writeln!(
        stdin,
        "{}",
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "embedded_debugger_request",
                "arguments": {"operation": "session.close", "session_id": session_id}
            }
        })
    )
    .unwrap();
    stdin.flush().unwrap();
    let close = read_jsonl_response(&mut stdout);
    assert_eq!(
        close["result"]["structuredContent"]["data"]["state"],
        "closed"
    );

    writeln!(
        stdin,
        "{}",
        serde_json::json!({"jsonrpc": "2.0", "id": 5, "method": "shutdown"})
    )
    .unwrap();
    stdin.flush().unwrap();
    assert_eq!(
        read_jsonl_response(&mut stdout)["result"],
        serde_json::json!({})
    );

    drop(stdin);
    drop(stdout);
    let status = child.wait().unwrap();
    assert!(status.success());
}

#[test]
fn replay_session_halted_only_mutations_reject_running_core_and_keep_serving() {
    let mut child = ProcessCommand::new(assert_cmd::cargo::cargo_bin!("embedded-debugger"))
        .args([
            "--fixture",
            fixture(),
            "session",
            "serve",
            "--target",
            "STM32G431CBTx",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    writeln!(
        stdin,
        "{}",
        serde_json::json!({
            "schema_version": "1.0",
            "request_id": "open",
            "operation": "session.open",
            "probe": "replay:stlink-v3:0039002A3432510433343034",
            "target": "STM32G431CBTx",
        })
    )
    .unwrap();
    stdin.flush().unwrap();
    let opened = read_jsonl_response(&mut stdout);
    let session_id = opened["data"]["session"]["session_id"]
        .as_str()
        .unwrap()
        .to_string();

    for (request_id, operation) in [("run", "core.run"), ("step", "core.step")] {
        writeln!(
            stdin,
            "{}",
            serde_json::json!({
                "schema_version": "1.0",
                "request_id": request_id,
                "operation": operation,
                "session_id": session_id,
                "core": 0,
            })
        )
        .unwrap();
        stdin.flush().unwrap();
        let response = read_jsonl_response(&mut stdout);
        if operation == "core.step" {
            assert_eq!(response["ok"], false);
            assert_eq!(response["error"]["code"], "CONFIG_INVALID");
            assert_eq!(response["error"]["details"]["original_state"], "running");
        }
    }

    writeln!(
        stdin,
        "{}",
        serde_json::json!({
            "schema_version": "1.0",
            "request_id": "breakpoint",
            "operation": "breakpoints.set",
            "session_id": session_id,
            "core": 0,
            "address": "0x08001234",
        })
    )
    .unwrap();
    stdin.flush().unwrap();
    let breakpoint = read_jsonl_response(&mut stdout);
    assert_eq!(breakpoint["ok"], false);
    assert_eq!(breakpoint["error"]["code"], "CONFIG_INVALID");
    assert_eq!(breakpoint["error"]["details"]["original_state"], "running");

    writeln!(
        stdin,
        "{}",
        serde_json::json!({
            "schema_version": "1.0",
            "request_id": "status",
            "operation": "core.status",
            "session_id": session_id,
            "core": 0,
        })
    )
    .unwrap();
    stdin.flush().unwrap();
    let status = read_jsonl_response(&mut stdout);
    assert_eq!(status["data"]["core"]["state"], "running");

    writeln!(
        stdin,
        "{}",
        serde_json::json!({
            "schema_version": "1.0",
            "request_id": "halt-before-continue",
            "operation": "core.halt",
            "session_id": session_id,
            "core": 0,
        })
    )
    .unwrap();
    stdin.flush().unwrap();
    let halted = read_jsonl_response(&mut stdout);
    assert_eq!(halted["ok"], true);
    assert_eq!(halted["data"]["core"]["state"], "halted");

    writeln!(
        stdin,
        "{}",
        serde_json::json!({
            "schema_version": "1.0",
            "request_id": "continue",
            "operation": "core.continue",
            "session_id": session_id,
            "core": 0,
        })
    )
    .unwrap();
    stdin.flush().unwrap();
    let continued = read_jsonl_response(&mut stdout);
    assert_eq!(continued["ok"], true);
    assert_eq!(continued["operation"], "core.continue");
    assert_eq!(continued["data"]["core"]["original_state"], "halted");
    assert_eq!(continued["data"]["core"]["state"], "running");
    assert_eq!(
        continued["data"]["effects"]["execution_continue_requested"],
        true
    );
    assert!(
        continued["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning
                .as_str()
                .unwrap()
                .contains("immediately hit a breakpoint"))
    );

    writeln!(
        stdin,
        "{}",
        serde_json::json!({
            "schema_version": "1.0",
            "request_id": "close",
            "operation": "session.close",
            "session_id": session_id,
        })
    )
    .unwrap();
    stdin.flush().unwrap();
    assert_eq!(read_jsonl_response(&mut stdout)["ok"], true);

    writeln!(
        stdin,
        "{}",
        serde_json::json!({
            "schema_version": "1.0",
            "request_id": "shutdown",
            "operation": "server.shutdown",
        })
    )
    .unwrap();
    stdin.flush().unwrap();
    assert_eq!(read_jsonl_response(&mut stdout)["ok"], true);
    drop(stdin);
    assert!(child.wait().unwrap().success());
}

#[test]
fn replay_session_server_safely_closes_an_active_session_on_eof() {
    let mut child = ProcessCommand::new(assert_cmd::cargo::cargo_bin!("embedded-debugger"))
        .args([
            "--fixture",
            fixture(),
            "session",
            "serve",
            "--target",
            "STM32G431CBTx",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    writeln!(
        stdin,
        "{}",
        serde_json::json!({
            "schema_version": "1.0",
            "request_id": "open",
            "operation": "session.open",
            "probe": "replay:stlink-v3:0039002A3432510433343034",
            "target": "STM32G431CBTx",
        })
    )
    .unwrap();
    stdin.flush().unwrap();
    let opened = read_jsonl_response(&mut stdout);
    let session_id = opened["data"]["session"]["session_id"].as_str().unwrap();

    writeln!(
        stdin,
        "{}",
        serde_json::json!({
            "schema_version": "1.0",
            "request_id": "halt",
            "operation": "core.halt",
            "session_id": session_id,
            "core": 0,
        })
    )
    .unwrap();
    stdin.flush().unwrap();
    let halted = read_jsonl_response(&mut stdout);
    assert_eq!(halted["data"]["core"]["state"], "halted");

    drop(stdin);
    let output = child.wait_with_output().unwrap();

    assert!(output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("session transport ended; safely closed"));
    assert!(stderr.contains("run_observed_cores_before_disconnect"));
}

#[test]
fn replay_session_idle_timeout_cleans_up_and_exits_with_structured_evidence() {
    let mut child = ProcessCommand::new(assert_cmd::cargo::cargo_bin!("embedded-debugger"))
        .args([
            "--fixture",
            fixture(),
            "session",
            "serve",
            "--target",
            "STM32G431CBTx",
            "--idle-timeout-ms",
            "200",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    writeln!(
        stdin,
        "{}",
        serde_json::json!({
            "schema_version": "1.0",
            "request_id": "open",
            "operation": "session.open",
            "probe": "replay:stlink-v3:0039002A3432510433343034",
            "target": "STM32G431CBTx",
        })
    )
    .unwrap();
    stdin.flush().unwrap();
    let opened = read_jsonl_response(&mut stdout);
    let session_id = opened["data"]["session"]["session_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(opened["data"]["lease_policy"]["idle_timeout_ms"], 200);

    writeln!(
        stdin,
        "{}",
        serde_json::json!({
            "schema_version": "1.0",
            "request_id": "breakpoint",
            "operation": "breakpoints.set",
            "session_id": session_id,
            "core": 0,
            "address": "0x08001234",
            "slot": 0,
        })
    )
    .unwrap();
    stdin.flush().unwrap();
    assert_eq!(read_jsonl_response(&mut stdout)["ok"], true);

    let idle_started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if idle_started.elapsed() > Duration::from_secs(5) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("session server did not exit after its idle timeout");
        }
        thread::sleep(Duration::from_millis(20));
    };
    assert!(idle_started.elapsed() >= Duration::from_millis(150));
    assert!(status.success());
    drop(stdin);
    drop(stdout);

    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    let event = stderr
        .lines()
        .find_map(|line| serde_json::from_str::<Value>(line).ok())
        .expect("idle expiry writes a structured stderr event");
    assert_eq!(event["event"], "session.idle_expired");
    assert_eq!(event["idle_timeout_ms"], 200);
    assert_eq!(event["action"], "close_and_exit");
    assert_eq!(event["close"]["state"], "closed");
    assert_eq!(event["close"]["disconnected"], true);
    assert_eq!(
        event["close"]["final_core_observations"][0]["state"],
        "running"
    );
    assert!(
        event["close"]["hardware_breakpoint_cleanup"][0]["after"]
            .as_array()
            .unwrap()
            .iter()
            .all(|slot| slot["address"].is_null())
    );
}

#[test]
fn session_idle_timeout_is_validated_before_backend_loading() {
    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "--fixture",
            "deliberately-missing.json",
            "session",
            "serve",
            "--target",
            "STM32G431CBTx",
            "--idle-timeout-ms",
            "99",
        ])
        .assert()
        .code(7)
        .get_output()
        .stderr
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["ok"], false);
    assert_eq!(result["operation"], "session.serve");
    assert_eq!(result["error"]["code"], "CONFIG_INVALID");
    assert_eq!(result["error"]["details"]["idle_timeout_ms"], 99);
}

fn read_jsonl_response(reader: &mut impl BufRead) -> Value {
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert!(
        !line.is_empty(),
        "session server closed stdout unexpectedly"
    );
    serde_json::from_str(&line).unwrap()
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
        "session.disconnect_preserving_core_state"
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
fn replay_register_read_reports_metadata_and_restored_state() {
    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "--fixture",
            fixture(),
            "registers",
            "read",
            "r15",
            "xpsr",
            "--probe",
            "replay:stlink-v3:0039002A3432510433343034",
            "--target",
            "STM32G431CBTx",
            "--core",
            "0",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["operation"], "registers.read");
    assert_eq!(result["data"]["risk"], "R1_REVERSIBLE_CONTROL");
    assert_eq!(result["data"]["complete"], true);
    assert_eq!(result["data"]["core"]["index"], 0);
    assert_eq!(result["data"]["core"]["original_state"], "halted");
    assert_eq!(result["data"]["core"]["captured_state"], "halted");
    assert_eq!(result["data"]["core"]["state"], "halted");
    assert_eq!(result["data"]["core"]["registers"][0]["name"], "pc");
    assert_eq!(
        result["data"]["core"]["registers"][0]["value"],
        "0x08001234"
    );
    assert_eq!(result["data"]["core"]["registers"][1]["name"], "xpsr");
    assert_eq!(
        result["data"]["effects"]["core_execution_state_restoration_verified"],
        true
    );
    assert_eq!(
        result["data"]["operations"][5]["operation"],
        "session.disconnect_preserving_core_state"
    );
}

#[test]
fn replay_register_read_returns_a_stable_unknown_name_error() {
    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "--fixture",
            fixture(),
            "registers",
            "read",
            "missing",
            "--probe",
            "replay:stlink-v3:0039002A3432510433343034",
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

    assert_eq!(result["ok"], false);
    assert_eq!(result["operation"], "registers.read");
    assert_eq!(result["error"]["code"], "CONFIG_INVALID");
    assert_eq!(result["error"]["details"]["requested"], "missing");
}

#[test]
fn replay_memory_read_reports_exact_bytes_region_hash_and_restored_state() {
    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "--fixture",
            fixture(),
            "memory",
            "read",
            "0x20007F04",
            "0x8",
            "--probe",
            "replay:stlink-v3:0039002A3432510433343034",
            "--target",
            "STM32G431CBTx",
            "--core",
            "0",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["operation"], "memory.read");
    assert_eq!(result["data"]["risk"], "R1_REVERSIBLE_CONTROL");
    assert_eq!(result["data"]["complete"], true);
    assert_eq!(result["data"]["core"]["index"], 0);
    assert_eq!(result["data"]["core"]["original_state"], "halted");
    assert_eq!(result["data"]["core"]["captured_state"], "halted");
    assert_eq!(result["data"]["core"]["state"], "halted");
    assert_eq!(result["data"]["range"]["start"], "0x20007F04");
    assert_eq!(result["data"]["range"]["length"], 8);
    assert_eq!(result["data"]["range"]["region"]["kind"], "ram");
    assert_eq!(result["data"]["encoding"], "hex");
    assert_eq!(result["data"]["data"], "0405060708090a0b");
    assert_eq!(result["data"]["sha256"].as_str().unwrap().len(), 64);
    assert_eq!(result["data"]["effects"]["memory_read_requested"], true);
    assert_eq!(
        result["data"]["effects"]["arbitrary_memory_write_requested"],
        false
    );
    assert_eq!(
        result["data"]["operations"][6]["operation"],
        "session.disconnect_preserving_core_state"
    );
}

#[test]
fn replay_memory_read_returns_a_stable_boundary_error() {
    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "--fixture",
            fixture(),
            "memory",
            "read",
            "0x20007F18",
            "16",
            "--probe",
            "replay:stlink-v3:0039002A3432510433343034",
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

    assert_eq!(result["ok"], false);
    assert_eq!(result["operation"], "memory.read");
    assert_eq!(result["error"]["code"], "CONFIG_INVALID");
    assert_eq!(result["error"]["details"]["start"], "0x20007F18");
}

#[test]
fn replay_core_status_reports_state_without_requesting_a_final_change() {
    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "--fixture",
            fixture(),
            "core",
            "status",
            "--probe",
            "replay:stlink-v3:0039002A3432510433343034",
            "--target",
            "STM32G431CBTx",
            "--core",
            "0",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["operation"], "core.status");
    assert_eq!(result["data"]["risk"], "R1_REVERSIBLE_CONTROL");
    assert_eq!(result["data"]["core"]["action"], "status");
    assert_eq!(result["data"]["core"]["original_state"], "halted");
    assert_eq!(result["data"]["core"]["state"], "halted");
    assert_eq!(result["data"]["core"]["state_changed"], false);
    assert_eq!(
        result["data"]["effects"]["intentional_final_core_state_change_requested"],
        false
    );
    assert_eq!(
        result["data"]["operations"][2]["operation"],
        "session.disconnect_preserving_core_state"
    );
}

#[test]
fn replay_core_run_reports_an_intentional_verified_state_change() {
    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "--fixture",
            fixture(),
            "core",
            "run",
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

    assert_eq!(result["operation"], "core.run");
    assert_eq!(result["data"]["core"]["action"], "run");
    assert_eq!(result["data"]["core"]["original_state"], "halted");
    assert_eq!(result["data"]["core"]["state"], "running");
    assert_eq!(result["data"]["core"]["state_changed"], true);
    assert_eq!(result["data"]["core"]["halt_reason"], Value::Null);
    assert_eq!(
        result["data"]["effects"]["intentional_final_core_state_change_requested"],
        true
    );
    assert_eq!(
        result["data"]["effects"]["core_execution_state_restoration_verified"],
        false
    );
    assert_eq!(
        result["data"]["operations"][4]["operation"],
        "session.disconnect_preserving_core_state"
    );
}

#[test]
fn replay_core_step_reports_a_halted_instruction_boundary() {
    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "--fixture",
            fixture(),
            "core",
            "step",
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

    assert_eq!(result["operation"], "core.step");
    assert_eq!(result["data"]["core"]["action"], "step");
    assert_eq!(result["data"]["core"]["original_state"], "halted");
    assert_eq!(result["data"]["core"]["state"], "halted");
    assert_eq!(result["data"]["core"]["state_changed"], false);
    assert_eq!(result["data"]["core"]["halt_reason"], "step");
    assert_eq!(result["data"]["core"]["pc_before"], "0x08001234");
    assert_eq!(result["data"]["core"]["pc_after"], "0x08001236");
    assert_eq!(
        result["data"]["effects"]["instruction_step_requested"],
        true
    );
    assert_eq!(
        result["data"]["effects"]["intentional_final_core_state_change_requested"],
        false
    );
    assert_eq!(
        result["data"]["operations"][2]["operation"],
        "core.step_one_instruction"
    );
}

#[test]
fn replay_core_continue_reports_the_observed_immediate_result() {
    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "--fixture",
            fixture(),
            "core",
            "continue",
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

    assert_eq!(result["operation"], "core.continue");
    assert_eq!(result["data"]["core"]["original_state"], "halted");
    assert_eq!(result["data"]["core"]["state"], "running");
    assert_eq!(
        result["data"]["effects"]["execution_continue_requested"],
        true
    );
    assert_eq!(
        result["data"]["effects"]["intentional_final_core_state_change_requested"],
        false
    );
}

#[test]
fn replay_core_continue_until_halt_reports_a_bounded_halt_event() {
    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "--fixture",
            fixture(),
            "core",
            "continue-until-halt",
            "--probe",
            "replay:stlink-v3:0039002A3432510433343034",
            "--target",
            "STM32G431CBTx",
            "--timeout-ms",
            "100",
            "--poll-interval-ms",
            "25",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["operation"], "core.continue_until_halt");
    assert_eq!(result["data"]["wait"]["outcome"], "halted");
    assert_eq!(result["data"]["wait"]["state"], "halted");
    assert_eq!(result["data"]["wait"]["halt_reason"], "breakpoint");
    assert_eq!(result["data"]["wait"]["timeout_ms"], 100);
    assert_eq!(result["data"]["wait"]["poll_interval_ms"], 25);
    assert_eq!(result["data"]["wait"]["elapsed_ms"], 75);
    assert_eq!(result["data"]["wait"]["poll_count"], 3);
    assert_eq!(
        result["data"]["effects"]["execution_continue_requested"],
        true
    );
    assert_eq!(
        result["data"]["effects"]["intentional_final_core_state_change_requested"],
        false
    );
    assert_eq!(
        result["data"]["operations"][3]["operation"],
        "core.poll_until_halted_or_timeout"
    );
    assert_eq!(
        result["data"]["operations"][5]["operation"],
        "session.disconnect_preserving_core_state"
    );
}

#[test]
fn core_continue_until_halt_rejects_invalid_timing_before_probe_selection() {
    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "--fixture",
            fixture(),
            "core",
            "continue-until-halt",
            "--probe",
            "deliberately-invalid",
            "--target",
            "STM32G431CBTx",
            "--timeout-ms",
            "5",
            "--poll-interval-ms",
            "10",
            "--json",
        ])
        .assert()
        .code(7)
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["ok"], false);
    assert_eq!(result["operation"], "core.continue_until_halt");
    assert_eq!(result["error"]["code"], "CONFIG_INVALID");
    assert_eq!(result["error"]["details"]["options"]["timeout_ms"], 5);
}

#[test]
fn core_control_rejects_an_invalid_index_before_probe_selection() {
    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "--fixture",
            fixture(),
            "core",
            "status",
            "--probe",
            "deliberately-invalid",
            "--target",
            "STM32G431CBTx",
            "--core",
            "1",
            "--json",
        ])
        .assert()
        .code(7)
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["ok"], false);
    assert_eq!(result["operation"], "core.status");
    assert_eq!(result["error"]["code"], "CONFIG_INVALID");
    assert_eq!(result["error"]["details"]["core_count"], 1);
}

#[test]
fn native_one_shot_core_state_is_gated_before_probe_selection() {
    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "--backend",
            "probe-rs",
            "core",
            "status",
            "--probe",
            "deliberately-invalid",
            "--target",
            "esp32s3",
            "--core",
            "0",
            "--json",
        ])
        .assert()
        .code(6)
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["ok"], false);
    assert_eq!(result["operation"], "core.status");
    assert_eq!(result["error"]["code"], "CAPABILITY_UNAVAILABLE");
    assert_eq!(
        result["error"]["details"]["capability"],
        "post_disconnect_core_state"
    );
    assert_eq!(result["error"]["details"]["backend"], "probe-rs");
}

#[test]
fn native_one_shot_continue_until_halt_is_gated_before_probe_selection() {
    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "--backend",
            "probe-rs",
            "core",
            "continue-until-halt",
            "--probe",
            "deliberately-invalid",
            "--target",
            "esp32s3",
            "--core",
            "0",
            "--timeout-ms",
            "100",
            "--poll-interval-ms",
            "25",
            "--json",
        ])
        .assert()
        .code(6)
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["ok"], false);
    assert_eq!(result["operation"], "core.continue_until_halt");
    assert_eq!(result["error"]["code"], "CAPABILITY_UNAVAILABLE");
    assert_eq!(
        result["error"]["details"]["capability"],
        "post_disconnect_core_state"
    );
    assert_eq!(result["error"]["details"]["backend"], "probe-rs");
}

#[test]
fn native_state_preserving_snapshot_is_gated_before_probe_selection() {
    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "--backend",
            "probe-rs",
            "snapshot",
            "capture",
            "--probe",
            "deliberately-invalid",
            "--target",
            "esp32s3",
            "--json",
        ])
        .assert()
        .code(6)
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["ok"], false);
    assert_eq!(result["operation"], "snapshot.capture");
    assert_eq!(result["error"]["code"], "CAPABILITY_UNAVAILABLE");
    assert_eq!(
        result["error"]["details"]["capability"],
        "post_disconnect_core_state"
    );
    assert_eq!(result["error"]["details"]["backend"], "probe-rs");
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
