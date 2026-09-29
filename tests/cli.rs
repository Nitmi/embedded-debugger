use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
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

fn write_fake_openocd(directory: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        let executable = directory.join("fake-openocd.cmd");
        fs::write(
            &executable,
            "@echo off\r\necho Open On-Chip Debugger 0.12.0-test\r\n",
        )
        .unwrap();
        executable
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let executable = directory.join("fake-openocd");
        fs::write(
            &executable,
            "#!/bin/sh\nprintf '%s\\n' 'Open On-Chip Debugger 0.12.0-test'\n",
        )
        .unwrap();
        let mut permissions = fs::metadata(&executable).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&executable, permissions).unwrap();
        executable
    }
}

fn write_fake_gdb(directory: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        let executable = directory.join("fake-gdb.cmd");
        fs::write(
            &executable,
            "@echo off\r\nif \"%1\"==\"--version\" goto version\r\necho =thread-group-added,id=\"i1\"\r\necho ^(gdb^)\r\nset /p first=\r\nif not \"%first%\"==\"1-gdb-version\" exit /b 3\r\necho ~\"GNU gdb (esp-gdb) 17.1-test\\n\"\r\necho 1^^done\r\necho ^(gdb^)\r\nset /p second=\r\nif not \"%second%\"==\"2-gdb-exit\" exit /b 4\r\necho 2^^exit\r\nexit /b 0\r\n:version\r\necho GNU gdb ^(esp-gdb^) 17.1-test\r\nexit /b 0\r\n",
        )
        .unwrap();
        executable
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let executable = directory.join("fake-gdb");
        fs::write(
            &executable,
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  printf '%s\\n' 'GNU gdb (esp-gdb) 17.1-test'\n  exit 0\nfi\nprintf '%s\\n' '=thread-group-added,id=\"i1\"' '(gdb)'\nIFS= read -r first\n[ \"$first\" = '1-gdb-version' ] || exit 3\nprintf '%s\\n' '~\"GNU gdb (esp-gdb) 17.1-test\\n\"' '1^done' '(gdb)'\nIFS= read -r second\n[ \"$second\" = '2-gdb-exit' ] || exit 4\nprintf '%s\\n' '2^exit'\n",
        )
        .unwrap();
        let mut permissions = fs::metadata(&executable).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&executable, permissions).unwrap();
        executable
    }
}

fn write_fake_gdb_with_wrong_token(directory: &Path) -> PathBuf {
    let executable = write_fake_gdb(directory);
    let script = fs::read_to_string(&executable).unwrap();
    let script = if cfg!(windows) {
        script.replace("echo 1^^done", "echo 9^^done")
    } else {
        script.replace("'1^done'", "'9^done'")
    };
    fs::write(&executable, script).unwrap();
    executable
}

fn write_stack_annotation_elf(directory: &Path, name: &str, marker: u8) -> PathBuf {
    use object::{Endianness, build, elf};

    let mut builder = build::elf::Builder::new(Endianness::Little, false);
    builder.header.e_type = elf::ET_EXEC;
    builder.header.e_machine = elf::EM_XTENSA;
    builder.header.e_entry = 0x4037_0000;
    builder.header.e_phoff = 0x34;

    let section = builder.sections.add();
    section.name = b".shstrtab"[..].into();
    section.sh_type = elf::SHT_STRTAB;
    section.data = build::elf::SectionData::SectionString;

    let section = builder.sections.add();
    section.name = b".text"[..].into();
    section.sh_type = elf::SHT_PROGBITS;
    section.sh_flags = u64::from(elf::SHF_ALLOC | elf::SHF_EXECINSTR);
    section.sh_addr = 0x4037_0000;
    section.sh_offset = 0x1000;
    section.sh_addralign = 4;
    section.data = build::elf::SectionData::Data(vec![marker; 0x40].into());
    let text_id = section.id();

    let section = builder.sections.add();
    section.name = b".symtab"[..].into();
    section.sh_type = elf::SHT_SYMTAB;
    section.sh_addralign = 4;
    section.data = build::elf::SectionData::Symbol;

    let section = builder.sections.add();
    section.name = b".strtab"[..].into();
    section.sh_type = elf::SHT_STRTAB;
    section.sh_addralign = 1;
    section.data = build::elf::SectionData::String;

    let symbol = builder.symbols.add();
    symbol.name = b"fixture_app_main"[..].into();
    symbol.section = Some(text_id);
    symbol.set_st_info(elf::STB_GLOBAL, elf::STT_FUNC);
    symbol.st_value = 0x4037_0000;
    symbol.st_size = 0x20;

    builder.set_section_sizes();
    let segment = builder.segments.add();
    segment.p_type = elf::PT_LOAD;
    segment.p_flags = elf::PF_R | elf::PF_X;
    segment.p_offset = 0x1000;
    segment.p_vaddr = 0x4037_0000;
    segment.p_paddr = 0x4037_0000;
    segment.p_filesz = 0x40;
    segment.p_memsz = 0x40;
    segment.p_align = 0x1000;
    segment.sections.push(text_id);

    let mut bytes = Vec::new();
    builder.write(&mut bytes).unwrap();
    let path = directory.join(name);
    fs::write(&path, bytes).unwrap();
    path
}

fn spawn_replay_supervisor(idle_timeout_ms: u64, max_restarts: u32) -> std::process::Child {
    ProcessCommand::new(assert_cmd::cargo::cargo_bin!("embedded-debugger"))
        .args([
            "--fixture",
            fixture(),
            "supervisor",
            "mcp",
            "--idle-timeout-ms",
            &idle_timeout_ms.to_string(),
            "--max-restarts",
            &max_restarts.to_string(),
            "--restart-delay-ms",
            "0",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn send_mcp_request(stdin: &mut impl Write, stdout: &mut impl BufRead, request: Value) -> Value {
    writeln!(stdin, "{request}").unwrap();
    stdin.flush().unwrap();
    read_jsonl_response(stdout)
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
fn replay_supervisor_transparently_proxies_mcp_and_exits_after_shutdown() {
    let mut child = spawn_replay_supervisor(0, 1);
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    let initialize = send_mcp_request(
        &mut stdin,
        &mut stdout,
        serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
    );
    assert_eq!(initialize["result"]["protocolVersion"], "2025-06-18");
    let tools = send_mcp_request(
        &mut stdin,
        &mut stdout,
        serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    );
    assert_eq!(
        tools["result"]["tools"][0]["name"],
        "embedded_debugger_request"
    );
    let shutdown = send_mcp_request(
        &mut stdin,
        &mut stdout,
        serde_json::json!({"jsonrpc": "2.0", "id": 3, "method": "shutdown"}),
    );
    assert_eq!(shutdown["result"], serde_json::json!({}));

    drop(stdin);
    drop(stdout);
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
}

#[test]
fn replay_supervisor_restores_the_mcp_handshake_after_an_idle_child_restart() {
    let mut child = spawn_replay_supervisor(200, 1);
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    assert_eq!(
        send_mcp_request(
            &mut stdin,
            &mut stdout,
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
        )["result"]["protocolVersion"],
        "2025-06-18"
    );
    writeln!(
        stdin,
        "{}",
        serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        })
    )
    .unwrap();
    stdin.flush().unwrap();
    let open = send_mcp_request(
        &mut stdin,
        &mut stdout,
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "embedded_debugger_request",
                "arguments": {
                    "operation": "session.open",
                    "probe": "replay:stlink-v3:0039002A3432510433343034",
                    "target": "STM32G431CBTx"
                }
            }
        }),
    );
    let old_session_id = open["result"]["structuredContent"]["data"]["session"]["session_id"]
        .as_str()
        .unwrap()
        .to_string();

    thread::sleep(Duration::from_millis(800));
    let ping = send_mcp_request(
        &mut stdin,
        &mut stdout,
        serde_json::json!({"jsonrpc": "2.0", "id": 3, "method": "ping"}),
    );
    assert_eq!(ping["result"], serde_json::json!({}));
    let stale = send_mcp_request(
        &mut stdin,
        &mut stdout,
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "embedded_debugger_request",
                "arguments": {"operation": "session.status", "session_id": old_session_id}
            }
        }),
    );
    assert_eq!(stale["result"]["isError"], true);
    assert_eq!(
        stale["result"]["structuredContent"]["error"]["code"],
        "PROTOCOL_ERROR"
    );
    assert_eq!(
        send_mcp_request(
            &mut stdin,
            &mut stdout,
            serde_json::json!({"jsonrpc": "2.0", "id": 5, "method": "shutdown"}),
        )["result"],
        serde_json::json!({})
    );

    drop(stdin);
    drop(stdout);
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("session.idle_expired"));
    assert!(stderr.contains("supervisor.child_exited"));
    assert!(stderr.contains("supervisor.child_restarted"));
    assert!(stderr.contains("supervisor.child_ready"));
    assert!(stderr.contains("\"initialized_notification_replayed\":true"));
}

#[test]
fn replay_supervisor_stops_when_the_restart_budget_is_exhausted() {
    let mut child = spawn_replay_supervisor(200, 0);
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    send_mcp_request(
        &mut stdin,
        &mut stdout,
        serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
    );
    let open = send_mcp_request(
        &mut stdin,
        &mut stdout,
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "embedded_debugger_request",
                "arguments": {
                    "operation": "session.open",
                    "probe": "replay:stlink-v3:0039002A3432510433343034",
                    "target": "STM32G431CBTx"
                }
            }
        }),
    );
    assert_eq!(open["result"]["isError"], false);

    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if started.elapsed() > Duration::from_secs(5) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("supervisor did not stop after exhausting its restart budget");
        }
        thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(status.code(), Some(10));
    drop(stdin);
    drop(stdout);
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(stderr.contains("\"restart\":false"));
    assert!(stderr.contains("supervisor restart limit was reached"));
}

#[test]
fn supervisor_options_are_validated_before_fixture_loading() {
    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "--fixture",
            "missing-supervisor-fixture.json",
            "supervisor",
            "mcp",
            "--max-restarts",
            "33",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(7));
    let stderr = String::from_utf8(output.stderr).unwrap();
    let result: Value = serde_json::from_str(stderr.lines().last().unwrap()).unwrap();
    assert_eq!(result["operation"], "supervisor.mcp");
    assert_eq!(result["error"]["code"], "CONFIG_INVALID");
    assert_eq!(result["error"]["details"]["max_restarts"], 33);
}

#[test]
fn supervisor_validates_the_replay_fixture_before_spawning_a_child() {
    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "--fixture",
            "missing-supervisor-fixture.json",
            "supervisor",
            "mcp",
            "--max-restarts",
            "2",
            "--restart-delay-ms",
            "0",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(10));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!stderr.contains("supervisor.child_exited"));
    assert!(!stderr.contains("supervisor.child_restarted"));
    let result: Value = serde_json::from_str(stderr.lines().last().unwrap()).unwrap();
    assert_eq!(result["operation"], "supervisor.mcp");
    assert_eq!(
        result["error"]["details"]["operation"],
        "read replay fixture"
    );
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
    assert_eq!(result["data"]["openocd_host_inspection_available"], true);
    assert_eq!(result["data"]["tools"][0]["name"], "probe-rs-cli");
    assert_eq!(result["data"]["tools"][0]["required"], false);
    assert!(result["operation_id"].as_str().unwrap().starts_with("op_"));
}

#[test]
fn openocd_inspect_returns_a_host_only_versioned_contract() {
    let directory = tempdir().unwrap();
    let executable = write_fake_openocd(directory.path());
    let config = directory.path().join("board.cfg");
    fs::write(&config, b"adapter speed 1000\n").unwrap();

    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .arg("openocd")
        .arg("inspect")
        .arg("--executable")
        .arg(&executable)
        .arg("--config")
        .arg(&config)
        .arg("--search")
        .arg(directory.path())
        .arg("--json")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["schema_version"], "1.0");
    assert_eq!(result["operation"], "openocd.inspect");
    assert_eq!(result["data"]["backend"], "openocd");
    assert_eq!(result["data"]["scope"], "host_only");
    assert_eq!(result["data"]["risk"], "R0_READ_ONLY");
    assert_eq!(result["data"]["complete"], true);
    assert_eq!(
        result["data"]["executable"]["version_line"],
        "Open On-Chip Debugger 0.12.0-test"
    );
    assert_eq!(
        result["data"]["configuration"]["top_level_files"][0]["bytes"],
        19
    );
    assert_eq!(
        result["data"]["configuration"]["top_level_files"][0]["sha256"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    assert_eq!(
        result["data"]["configuration"]["semantic_validation"],
        false
    );
    assert_eq!(
        result["data"]["server_enablement_requirements"]["implemented"],
        true
    );
    assert_eq!(
        result["data"]["server_enablement_requirements"]["bind_address"],
        "127.0.0.1"
    );
    assert_eq!(
        result["data"]["server_enablement_requirements"]["tcl_message_terminator"],
        "0x1a"
    );
    assert_eq!(
        result["data"]["server_enablement_requirements"]["graceful_shutdown"],
        "shutdown"
    );
    assert_eq!(result["data"]["capabilities"]["server_launch"], false);
    assert_eq!(result["data"]["capabilities"]["tcl_rpc"], false);
    assert_eq!(result["data"]["capabilities"]["gdb_mi"], false);
    assert_eq!(result["data"]["capabilities"]["target_operations"], false);
    assert_eq!(result["data"]["capabilities"]["flash"], false);
}

#[test]
fn openocd_gdb_inspect_returns_a_host_only_versioned_contract() {
    let directory = tempdir().unwrap();
    let executable = write_fake_gdb(directory.path());

    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .arg("openocd")
        .arg("gdb")
        .arg("inspect")
        .arg("--executable")
        .arg(&executable)
        .arg("--json")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["schema_version"], "1.0");
    assert_eq!(result["operation"], "openocd.gdb.inspect");
    assert_eq!(result["data"]["backend"], "openocd");
    assert_eq!(result["data"]["component"], "gdb");
    assert_eq!(result["data"]["scope"], "host_only");
    assert_eq!(result["data"]["risk"], "R0_READ_ONLY");
    assert_eq!(result["data"]["complete"], true);
    assert_eq!(
        result["data"]["executable"]["version_line"],
        "GNU gdb (esp-gdb) 17.1-test"
    );
    assert_eq!(result["data"]["executable"]["vendor"], "espressif");
    assert_eq!(
        result["data"]["executable_file"]["sha256"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    assert_eq!(result["data"]["capabilities"]["gdb_mi_host_process"], false);
    assert_eq!(
        result["data"]["capabilities"]["remote_target_connection"],
        false
    );
    assert_eq!(result["data"]["capabilities"]["target_operations"], false);
    assert_eq!(result["data"]["capabilities"]["flash"], false);
}

#[test]
fn openocd_gdb_test_proves_a_bounded_token_correlated_mi2_lifecycle() {
    let directory = tempdir().unwrap();
    let executable = write_fake_gdb(directory.path());

    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .arg("openocd")
        .arg("gdb")
        .arg("test")
        .arg("--executable")
        .arg(&executable)
        .arg("--json")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["schema_version"], "1.0");
    assert_eq!(result["operation"], "openocd.gdb.test");
    assert_eq!(result["data"]["scope"], "managed_gdb_mi_lifecycle");
    assert_eq!(result["data"]["risk"], "R0_READ_ONLY");
    assert_eq!(result["data"]["protocol"]["interpreter"], "mi2");
    assert_eq!(
        result["data"]["protocol"]["initialization_files_enabled"],
        false
    );
    assert_eq!(
        result["data"]["protocol"]["token_correlation_required"],
        true
    );
    assert_eq!(
        result["data"]["protocol"]["process_isolation"],
        if cfg!(windows) {
            "windows_job_object"
        } else {
            "unix_process_group"
        }
    );
    assert_eq!(result["data"]["protocol"]["commands"][0]["token"], 1);
    assert_eq!(
        result["data"]["protocol"]["commands"][0]["command"],
        "-gdb-version"
    );
    assert_eq!(
        result["data"]["handshake"]["version_command"]["result_class"],
        "done"
    );
    assert_eq!(result["data"]["handshake"]["version_stream_records"], 1);
    assert_eq!(result["data"]["shutdown"]["result_class"], "exit");
    assert_eq!(result["data"]["shutdown"]["graceful"], true);
    assert_eq!(
        result["data"]["shutdown"]["forced_process_tree_kill"],
        false
    );
    assert_eq!(
        result["data"]["shutdown"]["process_tree_cleanup_complete"],
        true
    );
    assert_eq!(result["data"]["capabilities"]["gdb_mi_host_process"], true);
    assert_eq!(
        result["data"]["capabilities"]["remote_target_connection"],
        false
    );
    assert_eq!(result["data"]["capabilities"]["register_read"], false);
    assert_eq!(result["data"]["capabilities"]["memory_read"], false);
    assert_eq!(result["data"]["capabilities"]["breakpoints"], false);
    assert_eq!(result["data"]["capabilities"]["execution_control"], false);
    assert_eq!(result["data"]["capabilities"]["flash"], false);
    assert_eq!(result["data"]["output"]["stdout"]["truncated"], false);
    assert_eq!(result["data"]["output"]["stdout"]["drain_complete"], true);
    assert_eq!(
        result["data"]["output"]["stdout"]["sha256"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
}

#[test]
fn openocd_gdb_test_validates_timeouts_before_executable_lookup() {
    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "openocd",
            "gdb",
            "test",
            "--executable",
            "deliberately-missing-gdb",
            "--startup-timeout-ms",
            "99",
            "--json",
        ])
        .assert()
        .code(7)
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["operation"], "openocd.gdb.test");
    assert_eq!(result["error"]["code"], "CONFIG_INVALID");
    assert_eq!(result["error"]["details"]["timeout_kind"], "startup");
}

#[test]
fn openocd_gdb_test_rejects_an_unmatched_result_token_and_cleans_up() {
    let directory = tempdir().unwrap();
    let executable = write_fake_gdb_with_wrong_token(directory.path());

    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .arg("openocd")
        .arg("gdb")
        .arg("test")
        .arg("--executable")
        .arg(&executable)
        .arg("--json")
        .assert()
        .code(6)
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["operation"], "openocd.gdb.test");
    assert_eq!(result["error"]["code"], "PROTOCOL_ERROR");
    assert_eq!(result["error"]["details"]["expected_token"], 1);
    assert_eq!(result["error"]["details"]["observed_token"], 9);
    assert_eq!(
        result["error"]["details"]["shutdown"]["process_tree_cleanup_complete"],
        true
    );
    assert_eq!(
        result["error"]["details"]["output"]["stdout"]["drain_complete"],
        true
    );
}

#[test]
fn openocd_server_plan_returns_a_guarded_versioned_contract() {
    let directory = tempdir().unwrap();
    let executable = write_fake_openocd(directory.path());
    let config = directory.path().join("board.cfg");
    fs::write(&config, b"adapter speed 1000\n").unwrap();

    let make_plan = || {
        let output = Command::cargo_bin("embedded-debugger")
            .unwrap()
            .arg("openocd")
            .arg("server")
            .arg("plan")
            .arg("--executable")
            .arg(&executable)
            .arg("--config")
            .arg(&config)
            .arg("--search")
            .arg(directory.path())
            .arg("--json")
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        serde_json::from_slice::<Value>(&output).unwrap()
    };
    let first = make_plan();
    let second = make_plan();

    assert_eq!(first["schema_version"], "1.0");
    assert_eq!(first["operation"], "openocd.server.plan");
    assert_eq!(first["data"]["backend"], "openocd");
    assert_eq!(first["data"]["operation"], "openocd.server.test");
    assert_eq!(first["data"]["risk"], "R2_DEVICE_WRITE");
    assert_eq!(first["data"]["complete"], true);
    assert_eq!(
        first["data"]["lifecycle"]["process_isolation"],
        if cfg!(windows) {
            "windows_job_object"
        } else {
            "unix_process_group"
        }
    );
    assert_eq!(
        first["data"]["effects"]["configuration_tcl_execution_required"],
        true
    );
    assert_eq!(
        first["data"]["effects"]["device_write_possible_from_configuration"],
        true
    );
    assert_eq!(
        first["data"]["confirmation_boundary"]["top_level_configuration_hashes_bound"],
        true
    );
    assert_eq!(
        first["data"]["confirmation_boundary"]["transitive_sources_bound"],
        false
    );
    assert_eq!(
        first["data"]["executable_file"]["sha256"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    assert_eq!(
        first["data"]["confirm_digest"],
        second["data"]["confirm_digest"]
    );
}

#[test]
fn openocd_server_test_rejects_a_stale_digest_before_configuration_execution() {
    let directory = tempdir().unwrap();
    let executable = write_fake_openocd(directory.path());
    let config = directory.path().join("board.cfg");
    fs::write(&config, b"adapter speed 1000\n").unwrap();

    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .arg("openocd")
        .arg("server")
        .arg("test")
        .arg("--executable")
        .arg(&executable)
        .arg("--config")
        .arg(&config)
        .arg("--confirm")
        .arg("00".repeat(32))
        .arg("--json")
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["operation"], "openocd.server.test");
    assert_eq!(result["error"]["code"], "CONFIRMATION_MISMATCH");
    assert_eq!(
        result["error"]["suggested_actions"][0]["action"],
        "review_openocd_server_plan"
    );
}

#[test]
fn openocd_server_validates_timeouts_before_filesystem_inputs() {
    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "openocd",
            "server",
            "plan",
            "--executable",
            "deliberately-missing-openocd",
            "--config",
            "deliberately-missing.cfg",
            "--startup-timeout-ms",
            "99",
            "--json",
        ])
        .assert()
        .code(7)
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["operation"], "openocd.server.plan");
    assert_eq!(result["error"]["code"], "CONFIG_INVALID");
    assert_eq!(result["error"]["details"]["timeout_kind"], "startup");
    assert_eq!(result["error"]["details"]["timeout_ms"], 99);
}

#[test]
fn openocd_server_requires_an_explicit_top_level_config() {
    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args(["openocd", "server", "plan", "--json"])
        .assert()
        .code(7)
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["operation"], "openocd.server.plan");
    assert_eq!(result["error"]["code"], "CONFIG_INVALID");
    assert_eq!(
        result["error"]["details"]["required_argument"],
        "--config <FILE>"
    );
}

#[test]
fn openocd_session_plan_binds_both_tools_and_the_fixed_restoration_policy() {
    let directory = tempdir().unwrap();
    let openocd = write_fake_openocd(directory.path());
    let gdb = write_fake_gdb(directory.path());
    let config = directory.path().join("board.cfg");
    let gdb_xtensa_config = directory.path().join("xtensa_fake.so");
    fs::write(&config, b"adapter speed 1000\n").unwrap();
    fs::write(&gdb_xtensa_config, b"target-profile").unwrap();

    let make_plan = || {
        let output = Command::cargo_bin("embedded-debugger")
            .unwrap()
            .arg("openocd")
            .arg("session")
            .arg("plan")
            .arg("--openocd-executable")
            .arg(&openocd)
            .arg("--gdb-executable")
            .arg(&gdb)
            .arg("--gdb-xtensa-config")
            .arg(&gdb_xtensa_config)
            .arg("--expected-target")
            .arg("fake.cpu0")
            .arg("--config")
            .arg(&config)
            .arg("--search")
            .arg(directory.path())
            .arg("--json")
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        serde_json::from_slice::<Value>(&output).unwrap()
    };
    let first = make_plan();
    let second = make_plan();

    assert_eq!(first["schema_version"], "1.0");
    assert_eq!(first["operation"], "openocd.session.plan");
    assert_eq!(first["data"]["operation"], "openocd.session.test");
    assert_eq!(first["data"]["risk"], "R2_DEVICE_WRITE");
    assert!(first["data"]["openocd"]["confirm_digest"].is_null());
    assert_eq!(
        first["data"]["openocd"]["configuration_effects"]["configuration_tcl_execution_required"],
        true
    );
    assert_eq!(
        first["data"]["protocol"]["commands"][1]["command"],
        "-target-select remote 127.0.0.1:<dynamic_openocd_gdb_port>"
    );
    assert_eq!(
        first["data"]["protocol"]["commands"][1]["expected_result_class"],
        "connected"
    );
    assert_eq!(
        first["data"]["target_state_policy"]["initial_state_required"],
        "running"
    );
    assert_eq!(
        first["data"]["target_state_policy"]["expected_current_target"],
        "fake.cpu0"
    );
    assert_eq!(
        first["data"]["target_state_policy"]["final_state_required"],
        "running"
    );
    assert_eq!(
        first["data"]["effects"]["fixed_resume_fallback_possible"],
        true
    );
    assert_eq!(
        first["data"]["effects"]["remote_negotiation_target_description_or_memory_map_possible"],
        true
    );
    assert_eq!(
        first["data"]["effects"]["openocd_attach_handler_reset_possible"],
        true
    );
    assert_eq!(
        first["data"]["effects"]["symbol_or_executable_loading_requested"],
        false
    );
    assert_eq!(
        first["data"]["effects"]["explicit_register_or_memory_command_requested"],
        false
    );
    assert_eq!(
        first["data"]["confirmation_boundary"]["gdb_executable_file_hash_bound"],
        true
    );
    assert_eq!(
        first["data"]["gdb"]["xtensa_config"]["environment_variable"],
        "XTENSA_GNU_CONFIG"
    );
    assert_eq!(
        first["data"]["gdb"]["ambient_xtensa_config_inherited"],
        false
    );
    assert_eq!(
        first["data"]["effects"]["gdb_xtensa_target_configuration_requested"],
        true
    );
    assert_eq!(
        first["data"]["confirmation_boundary"]["gdb_xtensa_config_file_hash_bound"],
        true
    );
    assert_eq!(
        first["data"]["confirmation_boundary"]["runtime_port_number_bound"],
        false
    );
    assert_eq!(
        first["data"]["confirmation_boundary"]["runtime_adapter_identity_bound"],
        false
    );
    assert_eq!(
        first["data"]["confirm_digest"],
        second["data"]["confirm_digest"]
    );
}

#[test]
fn openocd_session_test_rejects_a_stale_digest_before_tcl_execution() {
    let directory = tempdir().unwrap();
    let openocd = write_fake_openocd(directory.path());
    let gdb = write_fake_gdb(directory.path());
    let config = directory.path().join("board.cfg");
    fs::write(&config, b"adapter speed 1000\n").unwrap();

    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .arg("openocd")
        .arg("session")
        .arg("test")
        .arg("--openocd-executable")
        .arg(&openocd)
        .arg("--gdb-executable")
        .arg(&gdb)
        .arg("--expected-target")
        .arg("fake.cpu0")
        .arg("--config")
        .arg(&config)
        .arg("--confirm")
        .arg("00".repeat(32))
        .arg("--json")
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["operation"], "openocd.session.test");
    assert_eq!(result["error"]["code"], "CONFIRMATION_MISMATCH");
    assert_eq!(
        result["error"]["suggested_actions"][0]["action"],
        "review_openocd_session_plan"
    );
}

#[test]
fn openocd_session_validates_its_timeouts_before_filesystem_inputs() {
    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "openocd",
            "session",
            "plan",
            "--openocd-executable",
            "deliberately-missing-openocd",
            "--gdb-executable",
            "deliberately-missing-gdb",
            "--expected-target",
            "fake.cpu0",
            "--config",
            "deliberately-missing.cfg",
            "--gdb-command-timeout-ms",
            "99",
            "--json",
        ])
        .assert()
        .code(7)
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["operation"], "openocd.session.plan");
    assert_eq!(result["error"]["code"], "CONFIG_INVALID");
    assert_eq!(result["error"]["details"]["timeout_kind"], "gdb_command");
}

#[test]
fn openocd_registers_plan_binds_selection_protocol_and_restoration() {
    let directory = tempdir().unwrap();
    let openocd = write_fake_openocd(directory.path());
    let gdb = write_fake_gdb(directory.path());
    let config = directory.path().join("board.cfg");
    fs::write(&config, b"adapter speed 1000\n").unwrap();

    let make_plan = || {
        let output = Command::cargo_bin("embedded-debugger")
            .unwrap()
            .arg("openocd")
            .arg("registers")
            .arg("plan")
            .arg("--openocd-executable")
            .arg(&openocd)
            .arg("--gdb-executable")
            .arg(&gdb)
            .arg("--expected-target")
            .arg("fake.cpu0")
            .arg("--config")
            .arg(&config)
            .arg("--search")
            .arg(directory.path())
            .arg("--register")
            .arg("PC")
            .arg("--register")
            .arg("a0")
            .arg("--json")
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        serde_json::from_slice::<Value>(&output).unwrap()
    };
    let first = make_plan();
    let second = make_plan();

    assert_eq!(first["operation"], "openocd.registers.plan");
    assert_eq!(first["data"]["operation"], "openocd.registers.test");
    assert_eq!(first["data"]["risk"], "R2_DEVICE_WRITE");
    assert_eq!(
        first["data"]["register_policy"]["requested_names"],
        serde_json::json!(["pc", "a0"])
    );
    assert_eq!(
        first["data"]["protocol"]["commands"][2]["command"],
        "-data-list-register-names"
    );
    assert_eq!(
        first["data"]["protocol"]["commands"][3]["command"],
        "-data-list-register-values --skip-unavailable x <resolved_register_numbers>"
    );
    assert_eq!(
        first["data"]["target_state_policy"]["normal_restoration_command"],
        "5-target-detach"
    );
    assert_eq!(
        first["data"]["effects"]["explicit_selected_register_read_requested"],
        true
    );
    assert_eq!(
        first["data"]["effects"]["openocd_attach_handler_reset_possible"],
        true
    );
    assert_eq!(
        first["data"]["capabilities"]["selected_register_read"],
        Value::Null
    );
    assert_eq!(
        first["data"]["confirm_digest"],
        second["data"]["confirm_digest"]
    );
}

#[test]
fn openocd_registers_test_rejects_a_stale_digest_before_tcl_execution() {
    let directory = tempdir().unwrap();
    let openocd = write_fake_openocd(directory.path());
    let gdb = write_fake_gdb(directory.path());
    let config = directory.path().join("board.cfg");
    fs::write(&config, b"adapter speed 1000\n").unwrap();

    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .arg("openocd")
        .arg("registers")
        .arg("test")
        .arg("--openocd-executable")
        .arg(&openocd)
        .arg("--gdb-executable")
        .arg(&gdb)
        .arg("--expected-target")
        .arg("fake.cpu0")
        .arg("--config")
        .arg(&config)
        .arg("--register")
        .arg("pc")
        .arg("--confirm")
        .arg("00".repeat(32))
        .arg("--json")
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["operation"], "openocd.registers.test");
    assert_eq!(result["error"]["code"], "CONFIRMATION_MISMATCH");
    assert_eq!(
        result["error"]["suggested_actions"][0]["action"],
        "review_openocd_register_snapshot_plan"
    );
    assert!(result["error"]["details"]["openocd_readiness"].is_null());
}

#[test]
fn openocd_registers_validate_selection_before_filesystem_inputs() {
    for registers in [Vec::<&str>::new(), vec!["pc; reset"]] {
        let mut command = Command::cargo_bin("embedded-debugger").unwrap();
        command.args([
            "openocd",
            "registers",
            "plan",
            "--openocd-executable",
            "deliberately-missing-openocd",
            "--gdb-executable",
            "deliberately-missing-gdb",
            "--expected-target",
            "fake.cpu0",
            "--config",
            "deliberately-missing.cfg",
        ]);
        for register in registers {
            command.arg("--register").arg(register);
        }
        let output = command
            .arg("--json")
            .assert()
            .code(7)
            .get_output()
            .stdout
            .clone();
        let result: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(result["operation"], "openocd.registers.plan");
        assert_eq!(result["error"]["code"], "CONFIG_INVALID");
    }
}

#[test]
fn openocd_breakpoint_plan_binds_exact_hardware_only_roundtrip() {
    let directory = tempdir().unwrap();
    let openocd = write_fake_openocd(directory.path());
    let gdb = write_fake_gdb(directory.path());
    let config = directory.path().join("board.cfg");
    fs::write(&config, b"adapter speed 1000\n").unwrap();

    let make_plan = |address: &str| {
        let output = Command::cargo_bin("embedded-debugger")
            .unwrap()
            .args(["openocd", "breakpoint", "plan"])
            .arg("--openocd-executable")
            .arg(&openocd)
            .arg("--gdb-executable")
            .arg(&gdb)
            .arg("--expected-target")
            .arg("fake.cpu0")
            .arg("--config")
            .arg(&config)
            .arg("--search")
            .arg(directory.path())
            .arg("--address")
            .arg(address)
            .arg("--json")
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        serde_json::from_slice::<Value>(&output).unwrap()
    };
    let first = make_plan("0x420129e4");
    let second = make_plan("0x420129e4");
    let changed = make_plan("0x420129e8");

    assert_eq!(first["operation"], "openocd.breakpoint.plan");
    assert_eq!(first["data"]["operation"], "openocd.breakpoint.test");
    assert_eq!(first["data"]["risk"], "R2_DEVICE_WRITE");
    assert_eq!(
        first["data"]["breakpoint_policy"]["requested_address"],
        "0x420129E4"
    );
    assert_eq!(
        first["data"]["protocol"]["commands"][2]["command"],
        "-break-insert -h *0x420129e4"
    );
    assert_eq!(
        first["data"]["target_state_policy"]["normal_restoration_command"],
        "6-target-detach"
    );
    assert_eq!(
        first["data"]["breakpoint_policy"]["breakpoint_hit_requested"],
        false
    );
    assert_eq!(
        first["data"]["breakpoint_policy"]["symbols_or_expressions_allowed"],
        false
    );
    assert_eq!(
        first["data"]["breakpoint_policy"]["explicit_openocd_resume_after_gdb_failure"],
        false
    );
    assert_eq!(
        first["data"]["breakpoint_policy"]["target_resume_possible_during_failure_cleanup"],
        true
    );
    assert_eq!(
        first["data"]["breakpoint_policy"]["failure_cleanup_commands"][0]["token"],
        8
    );
    assert_eq!(
        first["data"]["confirmation_boundary"]["runtime_adapter_identity_bound"],
        false
    );
    assert_eq!(
        first["data"]["confirm_digest"],
        second["data"]["confirm_digest"]
    );
    assert_ne!(
        first["data"]["confirm_digest"],
        changed["data"]["confirm_digest"]
    );
}

#[test]
fn openocd_breakpoint_test_rejects_stale_digest_before_tcl_execution() {
    let directory = tempdir().unwrap();
    let openocd = write_fake_openocd(directory.path());
    let gdb = write_fake_gdb(directory.path());
    let config = directory.path().join("board.cfg");
    fs::write(&config, b"adapter speed 1000\n").unwrap();

    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args(["openocd", "breakpoint", "test"])
        .arg("--openocd-executable")
        .arg(&openocd)
        .arg("--gdb-executable")
        .arg(&gdb)
        .arg("--expected-target")
        .arg("fake.cpu0")
        .arg("--config")
        .arg(&config)
        .arg("--address")
        .arg("0x420129e4")
        .arg("--confirm")
        .arg("00".repeat(32))
        .arg("--json")
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["operation"], "openocd.breakpoint.test");
    assert_eq!(result["error"]["code"], "CONFIRMATION_MISMATCH");
    assert_eq!(
        result["error"]["suggested_actions"][0]["action"],
        "review_openocd_hardware_breakpoint_plan"
    );
    assert_eq!(result["error"]["details"]["hardware_access_started"], false);
    assert!(result["error"]["details"]["openocd_readiness"].is_null());
}

#[test]
fn openocd_breakpoint_rejects_zero_before_filesystem_inputs() {
    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "openocd",
            "breakpoint",
            "plan",
            "--openocd-executable",
            "deliberately-missing-openocd",
            "--gdb-executable",
            "deliberately-missing-gdb",
            "--expected-target",
            "fake.cpu0",
            "--config",
            "deliberately-missing.cfg",
            "--address",
            "0",
            "--json",
        ])
        .assert()
        .code(7)
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["operation"], "openocd.breakpoint.plan");
    assert_eq!(result["error"]["code"], "CONFIG_INVALID");
    assert_eq!(result["error"]["details"]["address"], "0x00000000");
}

#[test]
fn openocd_watchpoint_plan_binds_range_mode_classification_and_read_effect() {
    let directory = tempdir().unwrap();
    let openocd = write_fake_openocd(directory.path());
    let gdb = write_fake_gdb(directory.path());
    let config = directory.path().join("board.cfg");
    fs::write(&config, b"adapter speed 1000\n").unwrap();

    let make_plan = |mode: &str| {
        let output = Command::cargo_bin("embedded-debugger")
            .unwrap()
            .args(["openocd", "watchpoint", "plan"])
            .arg("--openocd-executable")
            .arg(&openocd)
            .arg("--gdb-executable")
            .arg(&gdb)
            .arg("--expected-target")
            .arg("fake.cpu0")
            .arg("--config")
            .arg(&config)
            .arg("--search")
            .arg(directory.path())
            .args([
                "--address",
                "0x3fcdb550",
                "--length",
                "4",
                "--region-start",
                "0x3fcd0000",
                "--region-length",
                "65536",
                "--region-kind",
                "ram",
                "--mode",
                mode,
                "--json",
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        serde_json::from_slice::<Value>(&output).unwrap()
    };
    let first = make_plan("access");
    let second = make_plan("access");
    let changed = make_plan("read");

    assert_eq!(first["operation"], "openocd.watchpoint.plan");
    assert_eq!(first["data"]["operation"], "openocd.watchpoint.test");
    assert_eq!(first["data"]["risk"], "R2_DEVICE_WRITE");
    assert_eq!(
        first["data"]["watchpoint_policy"]["requested_address"],
        "0x3FCDB550"
    );
    assert_eq!(
        first["data"]["watchpoint_policy"]["requested_length_bytes"],
        4
    );
    assert_eq!(first["data"]["watchpoint_policy"]["mode"], "access");
    assert_eq!(
        first["data"]["watchpoint_policy"]["expression"],
        "*((char*)0x3fcdb550)@4"
    );
    assert_eq!(
        first["data"]["protocol"]["commands"][2]["command"],
        "-gdb-set language c"
    );
    assert_eq!(
        first["data"]["protocol"]["commands"][3]["command"],
        "-break-watch -a *((char*)0x3fcdb550)@4"
    );
    assert_eq!(
        first["data"]["target_state_policy"]["normal_restoration_command"],
        "8-target-detach"
    );
    assert_eq!(
        first["data"]["effects"]["expression_evaluation_memory_read_possible"],
        true
    );
    assert_eq!(
        first["data"]["watchpoint_policy"]["write_only_mode_supported"],
        false
    );
    assert_eq!(
        first["data"]["watchpoint_policy"]["watchpoint_hit_requested"],
        false
    );
    assert_eq!(
        first["data"]["watchpoint_policy"]["failure_cleanup_commands"][0]["token"],
        10
    );
    assert_eq!(
        first["data"]["confirmation_boundary"]["target_ram_semantics_bound"],
        false
    );
    assert_eq!(
        first["data"]["confirmation_boundary"]["physical_comparator_allocation_bound"],
        false
    );
    assert_eq!(
        first["data"]["confirm_digest"],
        second["data"]["confirm_digest"]
    );
    assert_ne!(
        first["data"]["confirm_digest"],
        changed["data"]["confirm_digest"]
    );
}

#[test]
fn openocd_watchpoint_test_rejects_stale_digest_before_tcl_execution() {
    let directory = tempdir().unwrap();
    let openocd = write_fake_openocd(directory.path());
    let gdb = write_fake_gdb(directory.path());
    let config = directory.path().join("board.cfg");
    fs::write(&config, b"adapter speed 1000\n").unwrap();

    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args(["openocd", "watchpoint", "test"])
        .arg("--openocd-executable")
        .arg(&openocd)
        .arg("--gdb-executable")
        .arg(&gdb)
        .arg("--expected-target")
        .arg("fake.cpu0")
        .arg("--config")
        .arg(&config)
        .args([
            "--address",
            "0x3fcdb550",
            "--length",
            "4",
            "--region-start",
            "0x3fcd0000",
            "--region-length",
            "65536",
            "--region-kind",
            "ram",
            "--mode",
            "access",
            "--confirm",
        ])
        .arg("00".repeat(32))
        .arg("--json")
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["operation"], "openocd.watchpoint.test");
    assert_eq!(result["error"]["code"], "CONFIRMATION_MISMATCH");
    assert_eq!(
        result["error"]["suggested_actions"][0]["action"],
        "review_openocd_hardware_watchpoint_plan"
    );
    assert_eq!(result["error"]["details"]["hardware_access_started"], false);
    assert!(result["error"]["details"]["openocd_readiness"].is_null());
}

#[test]
fn openocd_watchpoint_rejects_unsafe_range_before_filesystem_inputs() {
    for (length, region_kind) in [("3", "ram"), ("4", "nvm")] {
        let output = Command::cargo_bin("embedded-debugger")
            .unwrap()
            .args([
                "openocd",
                "watchpoint",
                "plan",
                "--openocd-executable",
                "deliberately-missing-openocd",
                "--gdb-executable",
                "deliberately-missing-gdb",
                "--expected-target",
                "fake.cpu0",
                "--config",
                "deliberately-missing.cfg",
                "--address",
                "0x3fcdb550",
                "--length",
                length,
                "--region-start",
                "0x3fcd0000",
                "--region-length",
                "65536",
                "--region-kind",
                region_kind,
                "--mode",
                "access",
                "--json",
            ])
            .assert()
            .code(7)
            .get_output()
            .stdout
            .clone();
        let result: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(result["operation"], "openocd.watchpoint.plan");
        assert_eq!(result["error"]["code"], "CONFIG_INVALID");
    }
}

#[test]
fn openocd_watchpoint_hit_plan_binds_async_stop_pc_timeout_and_cleanup() {
    let directory = tempdir().unwrap();
    let openocd = write_fake_openocd(directory.path());
    let gdb = write_fake_gdb(directory.path());
    let config = directory.path().join("board.cfg");
    fs::write(&config, b"adapter speed 1000\n").unwrap();

    let make_plan = |hit_timeout: &str| {
        let output = Command::cargo_bin("embedded-debugger")
            .unwrap()
            .args(["openocd", "watchpoint", "hit", "plan"])
            .arg("--openocd-executable")
            .arg(&openocd)
            .arg("--gdb-executable")
            .arg(&gdb)
            .arg("--expected-target")
            .arg("fake.cpu0")
            .arg("--config")
            .arg(&config)
            .arg("--search")
            .arg(directory.path())
            .args([
                "--address",
                "0x3fcdb550",
                "--length",
                "4",
                "--region-start",
                "0x3fcd0000",
                "--region-length",
                "65536",
                "--region-kind",
                "ram",
                "--mode",
                "access",
                "--expected-pc-start",
                "0x420128c5",
                "--expected-pc-length",
                "11",
                "--hit-timeout-ms",
                hit_timeout,
                "--json",
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        serde_json::from_slice::<Value>(&output).unwrap()
    };
    let first = make_plan("5000");
    let second = make_plan("5000");
    let changed = make_plan("5001");

    assert_eq!(first["operation"], "openocd.watchpoint.hit.plan");
    assert_eq!(first["data"]["operation"], "openocd.watchpoint.hit.test");
    assert_eq!(first["data"]["risk"], "R2_DEVICE_WRITE");
    assert_eq!(
        first["data"]["protocol"]["commands"]
            .as_array()
            .unwrap()
            .len(),
        13
    );
    assert_eq!(
        first["data"]["protocol"]["commands"][1]["command"],
        "-gdb-set mi-async on"
    );
    assert_eq!(
        first["data"]["protocol"]["commands"][2]["command"],
        "-gdb-set non-stop off"
    );
    assert_eq!(
        first["data"]["protocol"]["commands"][7]["command"],
        "-exec-continue --all"
    );
    assert_eq!(
        first["data"]["hit_policy"]["expected_pc_start"],
        "0x420128C5"
    );
    assert_eq!(
        first["data"]["hit_policy"]["expected_pc_end_exclusive"],
        "0x420128D0"
    );
    assert_eq!(first["data"]["hit_policy"]["hit_timeout_ms"], 5000);
    assert_eq!(
        first["data"]["hit_policy"]["expected_stop_reason"],
        "access-watchpoint-trigger"
    );
    assert_eq!(
        first["data"]["hit_policy"]["expected_stop_tuple"],
        "hw-awpt"
    );
    assert_eq!(
        first["data"]["hit_policy"]["automatic_retry_allowed"],
        false
    );
    assert_eq!(
        first["data"]["hit_policy"]["failure_cleanup_commands"][0]["command"],
        "-exec-interrupt --all"
    );
    assert_eq!(
        first["data"]["hit_policy"]["failure_cleanup_commands"][0]["expected_result_class"],
        "done_then_tokenless_or_matching_continue_token_sigint_stop_when_running"
    );
    assert!(
        first["data"]["hit_policy"]["stop_requirements"]
            .as_array()
            .unwrap()
            .iter()
            .any(|requirement| requirement.as_str().unwrap().contains("stop token absent"))
    );
    assert_eq!(
        first["data"]["effects"]["target_execution_while_watchpoint_installed_requested"],
        true
    );
    assert_eq!(
        first["data"]["confirmation_boundary"]["runtime_firmware_identity_bound"],
        false
    );
    assert_eq!(
        first["data"]["confirm_digest"],
        second["data"]["confirm_digest"]
    );
    assert_ne!(
        first["data"]["confirm_digest"],
        changed["data"]["confirm_digest"]
    );
}

#[test]
fn openocd_watchpoint_hit_test_rejects_stale_digest_before_tcl_execution() {
    let directory = tempdir().unwrap();
    let openocd = write_fake_openocd(directory.path());
    let gdb = write_fake_gdb(directory.path());
    let config = directory.path().join("board.cfg");
    fs::write(&config, b"adapter speed 1000\n").unwrap();

    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args(["openocd", "watchpoint", "hit", "test"])
        .arg("--openocd-executable")
        .arg(&openocd)
        .arg("--gdb-executable")
        .arg(&gdb)
        .arg("--expected-target")
        .arg("fake.cpu0")
        .arg("--config")
        .arg(&config)
        .args([
            "--address",
            "0x3fcdb550",
            "--length",
            "4",
            "--region-start",
            "0x3fcd0000",
            "--region-length",
            "65536",
            "--region-kind",
            "ram",
            "--mode",
            "access",
            "--expected-pc-start",
            "0x420128c5",
            "--expected-pc-length",
            "11",
            "--hit-timeout-ms",
            "5000",
            "--confirm",
        ])
        .arg("00".repeat(32))
        .arg("--json")
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["operation"], "openocd.watchpoint.hit.test");
    assert_eq!(result["error"]["code"], "CONFIRMATION_MISMATCH");
    assert_eq!(
        result["error"]["suggested_actions"][0]["action"],
        "review_openocd_hardware_watchpoint_hit_plan"
    );
    assert_eq!(result["error"]["details"]["hardware_access_started"], false);
    assert!(result["error"]["details"]["openocd_readiness"].is_null());
}

#[test]
fn openocd_stack_plan_binds_limit_protocol_unwind_risk_and_restoration() {
    let directory = tempdir().unwrap();
    let openocd = write_fake_openocd(directory.path());
    let gdb = write_fake_gdb(directory.path());
    let config = directory.path().join("board.cfg");
    fs::write(&config, b"adapter speed 1000\n").unwrap();

    let make_plan = |maximum_frames: &str| {
        let output = Command::cargo_bin("embedded-debugger")
            .unwrap()
            .arg("openocd")
            .arg("stack")
            .arg("plan")
            .arg("--openocd-executable")
            .arg(&openocd)
            .arg("--gdb-executable")
            .arg(&gdb)
            .arg("--expected-target")
            .arg("fake.cpu0")
            .arg("--config")
            .arg(&config)
            .arg("--search")
            .arg(directory.path())
            .arg("--max-frames")
            .arg(maximum_frames)
            .arg("--json")
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        serde_json::from_slice::<Value>(&output).unwrap()
    };
    let first = make_plan("8");
    let second = make_plan("8");
    let changed = make_plan("9");

    assert_eq!(first["operation"], "openocd.stack.plan");
    assert_eq!(first["data"]["operation"], "openocd.stack.test");
    assert_eq!(first["data"]["risk"], "R2_DEVICE_WRITE");
    assert_eq!(first["data"]["stack_policy"]["maximum_frames_requested"], 8);
    assert_eq!(
        first["data"]["protocol"]["commands"][2]["command"],
        "-stack-list-frames --no-frame-filters 0 7"
    );
    assert_eq!(
        first["data"]["target_state_policy"]["normal_restoration_command"],
        "4-target-detach"
    );
    assert_eq!(
        first["data"]["effects"]["explicit_bounded_stack_unwind_requested"],
        true
    );
    assert_eq!(
        first["data"]["effects"]["unwinder_target_memory_addresses_bound"],
        false
    );
    assert_eq!(
        first["data"]["confirmation_boundary"]["implicit_unwinder_target_access_addresses_bound"],
        false
    );
    assert_eq!(
        first["data"]["confirm_digest"],
        second["data"]["confirm_digest"]
    );
    assert_ne!(
        first["data"]["confirm_digest"],
        changed["data"]["confirm_digest"]
    );
}

#[test]
fn openocd_stack_test_rejects_a_stale_digest_before_tcl_execution() {
    let directory = tempdir().unwrap();
    let openocd = write_fake_openocd(directory.path());
    let gdb = write_fake_gdb(directory.path());
    let config = directory.path().join("board.cfg");
    fs::write(&config, b"adapter speed 1000\n").unwrap();

    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .arg("openocd")
        .arg("stack")
        .arg("test")
        .arg("--openocd-executable")
        .arg(&openocd)
        .arg("--gdb-executable")
        .arg(&gdb)
        .arg("--expected-target")
        .arg("fake.cpu0")
        .arg("--config")
        .arg(&config)
        .arg("--max-frames")
        .arg("8")
        .arg("--confirm")
        .arg("00".repeat(32))
        .arg("--json")
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["operation"], "openocd.stack.test");
    assert_eq!(result["error"]["code"], "CONFIRMATION_MISMATCH");
    assert_eq!(
        result["error"]["suggested_actions"][0]["action"],
        "review_openocd_stack_snapshot_plan"
    );
    assert!(result["error"]["details"]["openocd_readiness"].is_null());
}

#[test]
fn openocd_stack_validates_limit_before_filesystem_inputs() {
    for maximum_frames in ["0", "33"] {
        let output = Command::cargo_bin("embedded-debugger")
            .unwrap()
            .args([
                "openocd",
                "stack",
                "plan",
                "--openocd-executable",
                "deliberately-missing-openocd",
                "--gdb-executable",
                "deliberately-missing-gdb",
                "--expected-target",
                "fake.cpu0",
                "--config",
                "deliberately-missing.cfg",
                "--max-frames",
                maximum_frames,
                "--json",
            ])
            .assert()
            .code(7)
            .get_output()
            .stdout
            .clone();
        let result: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(result["operation"], "openocd.stack.plan");
        assert_eq!(result["error"]["code"], "CONFIG_INVALID");
    }
}

#[test]
fn openocd_annotated_stack_plan_binds_elf_identity_without_changing_gdb_protocol() {
    let directory = tempdir().unwrap();
    let openocd = write_fake_openocd(directory.path());
    let gdb = write_fake_gdb(directory.path());
    let config = directory.path().join("board.cfg");
    fs::write(&config, b"adapter speed 1000\n").unwrap();
    let elf = write_stack_annotation_elf(directory.path(), "firmware.elf", 0);

    let make_plan = |elf: &Path| {
        let output = Command::cargo_bin("embedded-debugger")
            .unwrap()
            .arg("openocd")
            .arg("stack")
            .arg("plan")
            .arg("--openocd-executable")
            .arg(&openocd)
            .arg("--gdb-executable")
            .arg(&gdb)
            .arg("--expected-target")
            .arg("fake.cpu0")
            .arg("--config")
            .arg(&config)
            .arg("--search")
            .arg(directory.path())
            .arg("--max-frames")
            .arg("8")
            .arg("--elf")
            .arg(elf)
            .arg("--json")
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        serde_json::from_slice::<Value>(&output).unwrap()
    };

    let first = make_plan(&elf);
    let second = make_plan(&elf);
    let alias = directory.path().join("same-bytes.elf");
    fs::copy(&elf, &alias).unwrap();
    let changed_path = make_plan(&alias);
    write_stack_annotation_elf(directory.path(), "firmware.elf", 1);
    let changed_bytes = make_plan(&elf);

    assert_eq!(first["operation"], "openocd.stack.annotated.plan");
    assert_eq!(first["data"]["operation"], "openocd.stack.annotated.test");
    assert_eq!(first["data"]["stack"]["operation"], "openocd.stack.test");
    assert_eq!(first["data"]["elf"]["format"], "elf");
    assert_eq!(first["data"]["elf"]["kind"], "executable");
    assert_eq!(first["data"]["elf"]["architecture"], "xtensa");
    assert_eq!(first["data"]["elf"]["address_size_bits"], 32);
    assert_eq!(first["data"]["elf"]["text_symbol_count"], 1);
    assert_eq!(first["data"]["elf"]["nonzero_sized_text_symbol_count"], 1);
    assert_eq!(first["data"]["elf"]["zero_sized_text_symbol_count"], 0);
    assert_eq!(first["data"]["elf"]["external_files_loaded"], false);
    assert_eq!(
        first["data"]["annotation_policy"]["maximum_elf_bytes"],
        64 * 1024 * 1024
    );
    assert_eq!(
        first["data"]["annotation_policy"]["maximum_sections"],
        65_536
    );
    assert_eq!(
        first["data"]["annotation_policy"]["maximum_symbols"],
        262_144
    );
    assert_eq!(
        first["data"]["annotation_policy"]["maximum_build_id_bytes"],
        64
    );
    assert_eq!(
        first["data"]["annotation_policy"]["maximum_dwarf_frames_examined_per_frame"],
        17
    );
    assert_eq!(
        first["data"]["annotation_policy"]["maximum_inline_annotations_per_frame"],
        16
    );
    assert_eq!(
        first["data"]["annotation_policy"]["maximum_split_dwarf_requests_per_frame"],
        8
    );
    assert_eq!(
        first["data"]["annotation_policy"]["maximum_inferred_zero_size_symbol_bytes"],
        65_536
    );
    assert_eq!(
        first["data"]["annotation_policy"]["gdb_symbol_or_executable_loading"],
        false
    );
    assert_eq!(
        first["data"]["effects"]["gdb_symbol_or_executable_loading_requested"],
        false
    );
    assert_eq!(
        first["data"]["confirmation_boundary"]["runtime_firmware_identity_bound"],
        false
    );
    assert_eq!(
        first["data"]["confirmation_boundary"]["parser_resource_limits_bound"],
        true
    );
    assert_eq!(
        first["data"]["confirmation_boundary"]["zero_size_symbol_inference_policy_bound"],
        true
    );
    assert_eq!(
        first["data"]["stack"]["protocol"]["commands"][2]["command"],
        "-stack-list-frames --no-frame-filters 0 7"
    );
    assert_eq!(
        first["data"]["stack"]["effects"]["symbol_or_executable_loading_requested"],
        false
    );
    assert_eq!(
        first["data"]["confirm_digest"],
        second["data"]["confirm_digest"]
    );
    assert_eq!(
        first["data"]["elf"]["sha256"],
        changed_path["data"]["elf"]["sha256"]
    );
    assert_ne!(
        first["data"]["confirm_digest"],
        changed_path["data"]["confirm_digest"]
    );
    assert_eq!(
        first["data"]["elf"]["resolved"],
        changed_bytes["data"]["elf"]["resolved"]
    );
    assert_ne!(
        first["data"]["elf"]["sha256"],
        changed_bytes["data"]["elf"]["sha256"]
    );
    assert_ne!(
        first["data"]["confirm_digest"],
        changed_bytes["data"]["confirm_digest"]
    );
}

#[test]
fn openocd_annotated_stack_test_rejects_stale_digest_before_tcl_execution() {
    let directory = tempdir().unwrap();
    let openocd = write_fake_openocd(directory.path());
    let gdb = write_fake_gdb(directory.path());
    let config = directory.path().join("board.cfg");
    fs::write(&config, b"adapter speed 1000\n").unwrap();
    let elf = write_stack_annotation_elf(directory.path(), "firmware.elf", 0);

    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .arg("openocd")
        .arg("stack")
        .arg("test")
        .arg("--openocd-executable")
        .arg(&openocd)
        .arg("--gdb-executable")
        .arg(&gdb)
        .arg("--expected-target")
        .arg("fake.cpu0")
        .arg("--config")
        .arg(&config)
        .arg("--max-frames")
        .arg("8")
        .arg("--elf")
        .arg(&elf)
        .arg("--confirm")
        .arg("00".repeat(32))
        .arg("--json")
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["operation"], "openocd.stack.annotated.test");
    assert_eq!(result["error"]["code"], "CONFIRMATION_MISMATCH");
    assert_eq!(
        result["error"]["suggested_actions"][0]["action"],
        "review_openocd_annotated_stack_plan"
    );
    assert!(result["error"]["details"]["openocd_readiness"].is_null());
}

#[test]
fn openocd_annotated_stack_validates_limit_before_elf_or_tool_inputs() {
    for maximum_frames in ["0", "33"] {
        let output = Command::cargo_bin("embedded-debugger")
            .unwrap()
            .args([
                "openocd",
                "stack",
                "plan",
                "--openocd-executable",
                "deliberately-missing-openocd",
                "--gdb-executable",
                "deliberately-missing-gdb",
                "--expected-target",
                "fake.cpu0",
                "--config",
                "deliberately-missing.cfg",
                "--max-frames",
                maximum_frames,
                "--elf",
                "deliberately-missing.elf",
                "--json",
            ])
            .assert()
            .code(7)
            .get_output()
            .stdout
            .clone();
        let result: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(result["operation"], "openocd.stack.annotated.plan");
        assert_eq!(result["error"]["code"], "CONFIG_INVALID");
        assert_eq!(
            result["error"]["details"]["maximum_frames"],
            maximum_frames.parse::<u64>().unwrap()
        );
    }
}

#[test]
fn openocd_annotated_stack_validates_session_and_server_before_elf_inputs() {
    for (arguments, timeout_kind) in [
        (vec!["--gdb-command-timeout-ms", "99"], "gdb_command"),
        (vec!["--openocd-startup-timeout-ms", "99"], "startup"),
    ] {
        let mut command = Command::cargo_bin("embedded-debugger").unwrap();
        command.args([
            "openocd",
            "stack",
            "plan",
            "--openocd-executable",
            "deliberately-missing-openocd",
            "--gdb-executable",
            "deliberately-missing-gdb",
            "--expected-target",
            "fake.cpu0",
            "--config",
            "deliberately-missing.cfg",
            "--max-frames",
            "8",
            "--elf",
            "deliberately-missing.elf",
            "--json",
        ]);
        let output = command
            .args(arguments)
            .assert()
            .code(7)
            .get_output()
            .stdout
            .clone();
        let result: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(result["operation"], "openocd.stack.annotated.plan");
        assert_eq!(result["error"]["code"], "CONFIG_INVALID");
        assert_eq!(result["error"]["details"]["timeout_kind"], timeout_kind);
        assert_eq!(result["error"]["details"]["timeout_ms"], 99);
    }
}

#[test]
fn openocd_memory_plan_binds_range_region_protocol_and_restoration() {
    let directory = tempdir().unwrap();
    let openocd = write_fake_openocd(directory.path());
    let gdb = write_fake_gdb(directory.path());
    let config = directory.path().join("board.cfg");
    fs::write(&config, b"adapter speed 1000\n").unwrap();

    let make_plan = || {
        let output = Command::cargo_bin("embedded-debugger")
            .unwrap()
            .arg("openocd")
            .arg("memory")
            .arg("plan")
            .arg("--openocd-executable")
            .arg(&openocd)
            .arg("--gdb-executable")
            .arg(&gdb)
            .arg("--expected-target")
            .arg("fake.cpu0")
            .arg("--config")
            .arg(&config)
            .arg("--search")
            .arg(directory.path())
            .arg("--address")
            .arg("0x20000004")
            .arg("--length")
            .arg("8")
            .arg("--region-start")
            .arg("0x20000000")
            .arg("--region-length")
            .arg("0x1000")
            .arg("--region-kind")
            .arg("ram")
            .arg("--json")
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        serde_json::from_slice::<Value>(&output).unwrap()
    };
    let first = make_plan();
    let second = make_plan();

    assert_eq!(first["operation"], "openocd.memory.plan");
    assert_eq!(first["data"]["operation"], "openocd.memory.test");
    assert_eq!(first["data"]["risk"], "R2_DEVICE_WRITE");
    assert_eq!(
        first["data"]["memory_policy"]["requested_address"],
        "0x20000004"
    );
    assert_eq!(
        first["data"]["memory_policy"]["requested_end_exclusive"],
        "0x2000000C"
    );
    assert_eq!(
        first["data"]["memory_policy"]["declared_region"]["kind"],
        "ram"
    );
    assert_eq!(
        first["data"]["protocol"]["commands"][2]["command"],
        "-data-read-memory-bytes 0x20000004 8"
    );
    assert_eq!(
        first["data"]["target_state_policy"]["normal_restoration_command"],
        "4-target-detach"
    );
    assert_eq!(
        first["data"]["effects"]["explicit_bounded_memory_read_requested"],
        true
    );
    assert_eq!(
        first["data"]["effects"]["target_memory_map_semantics_verified"],
        false
    );
    assert_eq!(
        first["data"]["capabilities"]["bounded_memory_read"],
        Value::Null
    );
    assert_eq!(
        first["data"]["confirm_digest"],
        second["data"]["confirm_digest"]
    );
}

#[test]
fn openocd_memory_test_rejects_a_stale_digest_before_tcl_execution() {
    let directory = tempdir().unwrap();
    let openocd = write_fake_openocd(directory.path());
    let gdb = write_fake_gdb(directory.path());
    let config = directory.path().join("board.cfg");
    fs::write(&config, b"adapter speed 1000\n").unwrap();

    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .arg("openocd")
        .arg("memory")
        .arg("test")
        .arg("--openocd-executable")
        .arg(&openocd)
        .arg("--gdb-executable")
        .arg(&gdb)
        .arg("--expected-target")
        .arg("fake.cpu0")
        .arg("--config")
        .arg(&config)
        .arg("--address")
        .arg("0x20000004")
        .arg("--length")
        .arg("8")
        .arg("--region-start")
        .arg("0x20000000")
        .arg("--region-length")
        .arg("0x1000")
        .arg("--region-kind")
        .arg("ram")
        .arg("--confirm")
        .arg("00".repeat(32))
        .arg("--json")
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["operation"], "openocd.memory.test");
    assert_eq!(result["error"]["code"], "CONFIRMATION_MISMATCH");
    assert_eq!(
        result["error"]["suggested_actions"][0]["action"],
        "review_openocd_memory_snapshot_plan"
    );
    assert!(result["error"]["details"]["openocd_readiness"].is_null());
}

#[test]
fn openocd_memory_validates_range_before_filesystem_inputs() {
    for (address, length) in [("0x20000004", "0"), ("0x30000000", "8")] {
        let output = Command::cargo_bin("embedded-debugger")
            .unwrap()
            .args([
                "openocd",
                "memory",
                "plan",
                "--openocd-executable",
                "deliberately-missing-openocd",
                "--gdb-executable",
                "deliberately-missing-gdb",
                "--expected-target",
                "fake.cpu0",
                "--config",
                "deliberately-missing.cfg",
                "--address",
                address,
                "--length",
                length,
                "--region-start",
                "0x20000000",
                "--region-length",
                "0x1000",
                "--region-kind",
                "ram",
                "--json",
            ])
            .assert()
            .code(7)
            .get_output()
            .stdout
            .clone();
        let result: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(result["operation"], "openocd.memory.plan");
        assert_eq!(result["error"]["code"], "CONFIG_INVALID");
    }
}

#[test]
fn openocd_esp_app_identity_plan_binds_elf_descriptor_and_nvm_read() {
    let directory = tempdir().unwrap();
    let openocd = write_fake_openocd(directory.path());
    let gdb = write_fake_gdb(directory.path());
    let config = directory.path().join("board.cfg");
    let elf = directory.path().join("app.elf");
    fs::write(&config, b"adapter speed 1000\n").unwrap();
    fs::write(&elf, support::minimal_esp32s3_idf_elf()).unwrap();

    let make_plan = || {
        let output = Command::cargo_bin("embedded-debugger")
            .unwrap()
            .arg("openocd")
            .arg("esp-app-identity")
            .arg("plan")
            .arg("--openocd-executable")
            .arg(&openocd)
            .arg("--gdb-executable")
            .arg(&gdb)
            .arg("--expected-target")
            .arg("esp32s3.cpu0")
            .arg("--config")
            .arg(&config)
            .arg("--search")
            .arg(directory.path())
            .arg("--elf")
            .arg(&elf)
            .arg("--region-start")
            .arg("0x3c000000")
            .arg("--region-length")
            .arg("0x10000")
            .arg("--region-kind")
            .arg("nvm")
            .arg("--json")
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        serde_json::from_slice::<Value>(&output).unwrap()
    };
    let first = make_plan();
    let second = make_plan();

    assert_eq!(first["operation"], "openocd.esp_app_identity.plan");
    assert_eq!(first["data"]["operation"], "openocd.esp_app_identity.test");
    assert_eq!(first["data"]["risk"], "R2_DEVICE_WRITE");
    assert_eq!(first["data"]["elf"]["architecture"], "xtensa");
    assert_eq!(first["data"]["elf"]["section_address"], "0x3C000020");
    assert_eq!(first["data"]["elf"]["section_length_bytes"], 256);
    assert_eq!(
        first["data"]["elf"]["expected_descriptor"]["app_elf_sha256"],
        first["data"]["elf"]["sha256"]
    );
    assert_eq!(
        first["data"]["memory"]["protocol"]["commands"][2]["command"],
        "-data-read-memory-bytes 0x3c000020 256"
    );
    assert_eq!(
        first["data"]["memory"]["memory_policy"]["declared_region"]["kind"],
        "nvm"
    );
    assert_eq!(
        first["data"]["identity_policy"]["cryptographic_authenticity_claimed"],
        false
    );
    assert_eq!(
        first["data"]["confirm_digest"],
        second["data"]["confirm_digest"]
    );
}

#[test]
fn openocd_esp_app_identity_rejects_stale_digest_before_tcl_execution() {
    let directory = tempdir().unwrap();
    let openocd = write_fake_openocd(directory.path());
    let gdb = write_fake_gdb(directory.path());
    let config = directory.path().join("board.cfg");
    let elf = directory.path().join("app.elf");
    fs::write(&config, b"adapter speed 1000\n").unwrap();
    fs::write(&elf, support::minimal_esp32s3_idf_elf()).unwrap();

    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .arg("openocd")
        .arg("esp-app-identity")
        .arg("test")
        .arg("--openocd-executable")
        .arg(&openocd)
        .arg("--gdb-executable")
        .arg(&gdb)
        .arg("--expected-target")
        .arg("esp32s3.cpu0")
        .arg("--config")
        .arg(&config)
        .arg("--elf")
        .arg(&elf)
        .arg("--region-start")
        .arg("0x3c000000")
        .arg("--region-length")
        .arg("0x10000")
        .arg("--region-kind")
        .arg("nvm")
        .arg("--confirm")
        .arg("00".repeat(32))
        .arg("--json")
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["operation"], "openocd.esp_app_identity.test");
    assert_eq!(result["error"]["code"], "CONFIRMATION_MISMATCH");
    assert_eq!(
        result["error"]["suggested_actions"][0]["action"],
        "review_openocd_esp_app_identity_plan"
    );
    assert!(result["error"]["details"]["openocd_readiness"].is_null());
}

#[test]
fn openocd_reset_plan_binds_global_reset_and_selected_target_recovery() {
    let directory = tempdir().unwrap();
    let openocd = write_fake_openocd(directory.path());
    let config = directory.path().join("board.cfg");
    fs::write(&config, b"adapter speed 1000\n").unwrap();

    let make_plan = || {
        let output = Command::cargo_bin("embedded-debugger")
            .unwrap()
            .arg("openocd")
            .arg("reset")
            .arg("plan")
            .arg("--executable")
            .arg(&openocd)
            .arg("--expected-target")
            .arg("fake.cpu0")
            .arg("--config")
            .arg(&config)
            .arg("--search")
            .arg(directory.path())
            .arg("--json")
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        serde_json::from_slice::<Value>(&output).unwrap()
    };
    let first = make_plan();
    let second = make_plan();

    assert_eq!(first["schema_version"], "1.0");
    assert_eq!(first["operation"], "openocd.reset.plan");
    assert_eq!(first["data"]["operation"], "openocd.reset.test");
    assert_eq!(first["data"]["risk"], "R2_DEVICE_WRITE");
    assert_eq!(
        first["data"]["protocol"]["commands"][2]["command"],
        "format {__EMBEDDED_DEBUGGER_RESET_V1__%d} [catch {reset halt}]"
    );
    assert_eq!(
        first["data"]["protocol"]["commands"][3]["command"],
        "format {__EMBEDDED_DEBUGGER_RECOVERY_V1__%d} [catch {targets <validated_current_target>; resume}]"
    );
    assert_eq!(
        first["data"]["reset_policy"]["expected_current_target"],
        "fake.cpu0"
    );
    assert_eq!(
        first["data"]["reset_policy"]["reset_scope"],
        "all_defined_targets_per_openocd_reset_semantics"
    );
    assert_eq!(
        first["data"]["reset_policy"]["initial_state_required"],
        "running"
    );
    assert_eq!(
        first["data"]["reset_policy"]["selected_target_post_reset_state_required"],
        "halted"
    );
    assert_eq!(
        first["data"]["reset_policy"]["selected_target_final_state_required"],
        "running"
    );
    assert_eq!(
        first["data"]["effects"]["reset_scope_all_defined_targets"],
        true
    );
    assert_eq!(
        first["data"]["effects"]["reset_event_handlers_execute"],
        true
    );
    assert_eq!(
        first["data"]["effects"]["non_selected_target_final_states_verified"],
        false
    );
    assert_eq!(
        first["data"]["confirmation_boundary"]["fixed_reset_mode_bound"],
        true
    );
    assert_eq!(
        first["data"]["confirmation_boundary"]["non_selected_target_inventory_bound"],
        false
    );
    assert_eq!(
        first["data"]["confirmation_boundary"]["runtime_adapter_identity_bound"],
        false
    );
    assert_eq!(
        first["data"]["confirm_digest"],
        second["data"]["confirm_digest"]
    );
}

#[test]
fn openocd_reset_test_rejects_a_stale_digest_before_tcl_execution() {
    let directory = tempdir().unwrap();
    let openocd = write_fake_openocd(directory.path());
    let config = directory.path().join("board.cfg");
    fs::write(&config, b"adapter speed 1000\n").unwrap();

    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .arg("openocd")
        .arg("reset")
        .arg("test")
        .arg("--executable")
        .arg(&openocd)
        .arg("--expected-target")
        .arg("fake.cpu0")
        .arg("--config")
        .arg(&config)
        .arg("--confirm")
        .arg("00".repeat(32))
        .arg("--json")
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["operation"], "openocd.reset.test");
    assert_eq!(result["error"]["code"], "CONFIRMATION_MISMATCH");
    assert_eq!(
        result["error"]["suggested_actions"][0]["action"],
        "review_openocd_reset_plan"
    );
}

#[test]
fn openocd_reset_validates_timeout_before_filesystem_inputs() {
    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "openocd",
            "reset",
            "plan",
            "--executable",
            "deliberately-missing-openocd",
            "--expected-target",
            "fake.cpu0",
            "--config",
            "deliberately-missing.cfg",
            "--target-state-timeout-ms",
            "99",
            "--json",
        ])
        .assert()
        .code(7)
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["operation"], "openocd.reset.plan");
    assert_eq!(result["error"]["code"], "CONFIG_INVALID");
    assert_eq!(result["error"]["details"]["timeout_kind"], "target_state");
    assert_eq!(result["error"]["details"]["timeout_ms"], 99);
}

#[test]
fn openocd_resume_plan_binds_one_conditional_resume_and_no_retry() {
    let directory = tempdir().unwrap();
    let openocd = write_fake_openocd(directory.path());
    let config = directory.path().join("board.cfg");
    fs::write(&config, b"adapter speed 1000\n").unwrap();

    let make_plan = || {
        let output = Command::cargo_bin("embedded-debugger")
            .unwrap()
            .arg("openocd")
            .arg("resume")
            .arg("plan")
            .arg("--executable")
            .arg(&openocd)
            .arg("--expected-target")
            .arg("fake.cpu0")
            .arg("--config")
            .arg(&config)
            .arg("--search")
            .arg(directory.path())
            .arg("--json")
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        serde_json::from_slice::<Value>(&output).unwrap()
    };
    let first = make_plan();
    let second = make_plan();

    assert_eq!(first["schema_version"], "1.0");
    assert_eq!(first["operation"], "openocd.resume.plan");
    assert_eq!(first["data"]["operation"], "openocd.resume.test");
    assert_eq!(first["data"]["risk"], "R2_DEVICE_WRITE");
    assert_eq!(
        first["data"]["protocol"]["commands"][2]["command"],
        "format {__EMBEDDED_DEBUGGER_RESUME_ONLY_V1__%d} [catch {targets <validated_current_target>; resume}]"
    );
    assert_eq!(
        first["data"]["resume_policy"]["expected_current_target"],
        "fake.cpu0"
    );
    assert_eq!(
        first["data"]["resume_policy"]["accepted_initial_states"],
        serde_json::json!(["halted", "running"])
    );
    assert_eq!(
        first["data"]["resume_policy"]["maximum_resume_command_count"],
        1
    );
    assert_eq!(
        first["data"]["resume_policy"]["automatic_retry_allowed"],
        false
    );
    assert_eq!(
        first["data"]["effects"]["explicit_selected_target_halt_requested"],
        false
    );
    assert_eq!(first["data"]["effects"]["reset_requested_by_tool"], false);
    assert_eq!(
        first["data"]["effects"]["breakpoint_or_watchpoint_command_requested"],
        false
    );
    assert_eq!(
        first["data"]["confirmation_boundary"]["maximum_resume_command_count_bound"],
        true
    );
    assert_eq!(
        first["data"]["confirmation_boundary"]["runtime_adapter_identity_bound"],
        false
    );
    assert_eq!(
        first["data"]["confirm_digest"],
        second["data"]["confirm_digest"]
    );
}

#[test]
fn openocd_resume_test_rejects_a_stale_digest_before_tcl_execution() {
    let directory = tempdir().unwrap();
    let openocd = write_fake_openocd(directory.path());
    let config = directory.path().join("board.cfg");
    fs::write(&config, b"adapter speed 1000\n").unwrap();

    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .arg("openocd")
        .arg("resume")
        .arg("test")
        .arg("--executable")
        .arg(&openocd)
        .arg("--expected-target")
        .arg("fake.cpu0")
        .arg("--config")
        .arg(&config)
        .arg("--confirm")
        .arg("00".repeat(32))
        .arg("--json")
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["operation"], "openocd.resume.test");
    assert_eq!(result["error"]["code"], "CONFIRMATION_MISMATCH");
    assert_eq!(
        result["error"]["suggested_actions"][0]["action"],
        "review_openocd_resume_plan"
    );
}

#[test]
fn openocd_resume_validates_timeout_before_filesystem_inputs() {
    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "openocd",
            "resume",
            "plan",
            "--executable",
            "deliberately-missing-openocd",
            "--expected-target",
            "fake.cpu0",
            "--config",
            "deliberately-missing.cfg",
            "--target-state-timeout-ms",
            "99",
            "--json",
        ])
        .assert()
        .code(7)
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["operation"], "openocd.resume.plan");
    assert_eq!(result["error"]["code"], "CONFIG_INVALID");
    assert_eq!(result["error"]["details"]["timeout_kind"], "target_state");
    assert_eq!(result["error"]["details"]["timeout_ms"], 99);
}

#[test]
fn openocd_target_plan_binds_the_fixed_halt_resume_roundtrip() {
    let directory = tempdir().unwrap();
    let openocd = write_fake_openocd(directory.path());
    let config = directory.path().join("board.cfg");
    fs::write(&config, b"adapter speed 1000\n").unwrap();

    let make_plan = || {
        let output = Command::cargo_bin("embedded-debugger")
            .unwrap()
            .arg("openocd")
            .arg("target")
            .arg("plan")
            .arg("--executable")
            .arg(&openocd)
            .arg("--expected-target")
            .arg("fake.cpu0")
            .arg("--config")
            .arg(&config)
            .arg("--search")
            .arg(directory.path())
            .arg("--json")
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        serde_json::from_slice::<Value>(&output).unwrap()
    };
    let first = make_plan();
    let second = make_plan();

    assert_eq!(first["schema_version"], "1.0");
    assert_eq!(first["operation"], "openocd.target.plan");
    assert_eq!(first["data"]["operation"], "openocd.target.test");
    assert_eq!(first["data"]["risk"], "R2_DEVICE_WRITE");
    assert_eq!(
        first["data"]["protocol"]["commands"][2]["command"],
        "targets <validated_current_target>; halt"
    );
    assert_eq!(
        first["data"]["protocol"]["commands"][3]["command"],
        "targets <validated_current_target>; resume"
    );
    assert_eq!(
        first["data"]["target_policy"]["expected_current_target"],
        "fake.cpu0"
    );
    assert_eq!(
        first["data"]["target_policy"]["initial_state_required"],
        "running"
    );
    assert_eq!(
        first["data"]["target_policy"]["halted_state_required"],
        "halted"
    );
    assert_eq!(
        first["data"]["target_policy"]["final_state_required"],
        "running"
    );
    assert_eq!(
        first["data"]["effects"]["explicit_target_halt_requested"],
        true
    );
    assert_eq!(
        first["data"]["effects"]["explicit_target_resume_requested"],
        true
    );
    assert_eq!(first["data"]["effects"]["reset_requested_by_tool"], false);
    assert_eq!(first["data"]["effects"]["flash_command_requested"], false);
    assert_eq!(
        first["data"]["confirmation_boundary"]["fixed_tcl_protocol_bound"],
        true
    );
    assert_eq!(
        first["data"]["confirmation_boundary"]["runtime_port_number_bound"],
        false
    );
    assert_eq!(
        first["data"]["confirmation_boundary"]["runtime_adapter_identity_bound"],
        false
    );
    assert_eq!(
        first["data"]["confirm_digest"],
        second["data"]["confirm_digest"]
    );
}

#[test]
fn openocd_target_test_rejects_a_stale_digest_before_tcl_execution() {
    let directory = tempdir().unwrap();
    let openocd = write_fake_openocd(directory.path());
    let config = directory.path().join("board.cfg");
    fs::write(&config, b"adapter speed 1000\n").unwrap();

    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .arg("openocd")
        .arg("target")
        .arg("test")
        .arg("--executable")
        .arg(&openocd)
        .arg("--expected-target")
        .arg("fake.cpu0")
        .arg("--config")
        .arg(&config)
        .arg("--confirm")
        .arg("00".repeat(32))
        .arg("--json")
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["operation"], "openocd.target.test");
    assert_eq!(result["error"]["code"], "CONFIRMATION_MISMATCH");
    assert_eq!(
        result["error"]["suggested_actions"][0]["action"],
        "review_openocd_target_plan"
    );
}

#[test]
fn openocd_target_validates_timeout_before_filesystem_inputs() {
    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "openocd",
            "target",
            "plan",
            "--executable",
            "deliberately-missing-openocd",
            "--expected-target",
            "fake.cpu0",
            "--config",
            "deliberately-missing.cfg",
            "--target-state-timeout-ms",
            "99",
            "--json",
        ])
        .assert()
        .code(7)
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["operation"], "openocd.target.plan");
    assert_eq!(result["error"]["code"], "CONFIG_INVALID");
    assert_eq!(result["error"]["details"]["timeout_kind"], "target_state");
    assert_eq!(result["error"]["details"]["timeout_ms"], 99);
}

#[test]
fn openocd_inspect_rejects_bad_timeout_before_filesystem_or_path_lookup() {
    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "openocd",
            "inspect",
            "--executable",
            "deliberately-missing-openocd",
            "--config",
            "deliberately-missing.cfg",
            "--timeout-ms",
            "99",
            "--json",
        ])
        .assert()
        .code(7)
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["operation"], "openocd.inspect");
    assert_eq!(result["error"]["code"], "CONFIG_INVALID");
    assert_eq!(result["error"]["details"]["timeout_ms"], 99);
}

#[test]
fn openocd_inspect_reports_a_missing_host_tool_without_backend_fallback() {
    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "openocd",
            "inspect",
            "--executable",
            "deliberately-missing-openocd-for-contract-test",
            "--json",
        ])
        .assert()
        .code(4)
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["error"]["code"], "CAPABILITY_UNAVAILABLE");
    assert_eq!(
        result["error"]["details"]["capability"],
        "host_tool_discovery"
    );
    assert_eq!(
        result["error"]["suggested_actions"][0]["action"],
        "install_or_select_openocd"
    );
}

#[test]
fn openocd_inspect_rejects_an_executable_with_the_wrong_identity() {
    let executable = assert_cmd::cargo::cargo_bin!("embedded-debugger");
    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .arg("openocd")
        .arg("inspect")
        .arg("--executable")
        .arg(executable)
        .arg("--json")
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
            .contains("did not identify itself")
    );
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
fn runtime_init_and_inspect_are_offline_for_every_backend() {
    for backend in ["replay", "probe-rs", "openocd"] {
        let directory = tempdir().unwrap();
        let contract = directory.path().join("project/runtime.json");
        let output = Command::cargo_bin("embedded-debugger")
            .unwrap()
            .current_dir(directory.path())
            .env("PATH", "")
            .args([
                "--backend",
                backend,
                "--fixture",
                "missing-fixture.json",
                "runtime",
                "init",
                "--name",
                "project-smoke",
                "--board",
                "Project board",
                "--probe",
                "not-a-connected-probe",
                "--target",
                "not-a-real-target",
                "--port",
                "not-a-real-port",
                "--vid",
                "1234",
                "--pid",
                "aBcD",
                "--serial-number",
                "project-fixture",
                "--baud",
                "57600",
                "--dtr",
                "true",
                "--rts",
                "false",
                "--duration",
                "8",
                "--ready-line",
                "READY v1",
                "--build-id-line",
                "BUILD v1 test",
                "--heartbeat-line",
                "HEARTBEAT",
                "--minimum-heartbeats",
                "4",
                "--forbid-line",
                "FAULT",
                "--output",
                contract.to_str().unwrap(),
                "--json",
            ])
            .assert()
            .success()
            .get_output()
            .clone();
        assert!(output.stderr.is_empty());
        let created: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(created["operation"], "runtime.init");
        assert_eq!(created["data"]["scope"], "host_only_no_hardware_access");
        assert_eq!(created["data"]["hardware_identity_verified"], false);
        let document: Value = serde_json::from_slice(&fs::read(&contract).unwrap()).unwrap();
        assert_eq!(document["serial"]["usb_product_id"], "ABCD");
        assert_eq!(document["serial"]["baud"], 57600);
        assert_eq!(document["serial"]["dtr"], true);
        assert_eq!(document["serial"]["rts"], false);
        assert_eq!(document["serial"]["observe_duration_seconds"], 8);
        assert_eq!(document["serial"]["minimum_complete_heartbeats"], 4);
        assert_eq!(document["serial"]["build_id_line"], "BUILD v1 test");
        assert_eq!(document["serial"]["forbidden_complete_lines"][0], "FAULT");
        let inspected_output = Command::cargo_bin("embedded-debugger")
            .unwrap()
            .current_dir(directory.path())
            .env("PATH", "")
            .args([
                "--backend",
                backend,
                "--fixture",
                "missing-fixture.json",
                "runtime",
                "inspect",
                contract.to_str().unwrap(),
                "--json",
            ])
            .assert()
            .success()
            .get_output()
            .clone();
        assert!(inspected_output.stderr.is_empty());
        let inspected: Value = serde_json::from_slice(&inspected_output.stdout).unwrap();
        assert_eq!(inspected["operation"], "runtime.inspect");
        assert_eq!(inspected["data"], created["data"]);
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
        assert_eq!(fs::read_dir(contract.parent().unwrap()).unwrap().count(), 1);
    }
}

#[test]
fn runtime_init_requires_identity_and_preserves_existing_files() {
    let directory = tempdir().unwrap();
    let output_path = directory.path().join("runtime.json");
    let missing = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "runtime",
            "init",
            "--name",
            "smoke",
            "--board",
            "Board",
            "--output",
            output_path.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .code(7)
        .get_output()
        .stdout
        .clone();
    let missing: Value = serde_json::from_slice(&missing).unwrap();
    assert_eq!(missing["operation"], "runtime.init");
    assert_eq!(missing["error"]["details"]["missing"], "--probe");
    assert!(!output_path.exists());
    fs::write(&output_path, b"keep existing project config").unwrap();
    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "runtime",
            "init",
            "--name",
            "smoke",
            "--board",
            "Board",
            "--probe",
            "probe",
            "--target",
            "target",
            "--port",
            "port",
            "--vid",
            "1234",
            "--pid",
            "5678",
            "--serial-number",
            "serial",
            "--ready-line",
            "READY",
            "--heartbeat-line",
            "HEARTBEAT",
            "--output",
            output_path.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(result["error"]["code"], "OUTPUT_EXISTS");
    assert_eq!(
        fs::read(output_path).unwrap(),
        b"keep existing project config"
    );
}

#[test]
fn runtime_inspect_reports_invalid_contract_without_creating_evidence() {
    let directory = tempdir().unwrap();
    let contract = directory.path().join("contract.json");
    fs::write(&contract, b"{}").unwrap();
    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .current_dir(directory.path())
        .args(["runtime", "inspect", contract.to_str().unwrap(), "--json"])
        .assert()
        .code(7)
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(result["operation"], "runtime.inspect");
    assert_eq!(result["error"]["code"], "CONFIG_INVALID");
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
}

#[test]
fn runtime_accept_rejects_non_exact_usb_ids_during_cli_parsing() {
    let stderr = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "runtime",
            "accept",
            "--probe",
            "replay:stlink-v3:0039002A3432510433343034",
            "--target",
            "STM32G431CBTx",
            "--port",
            "COM11",
            "--vid",
            "136",
            "--pid",
            "1061",
            "--serial-number",
            "001050275757",
            "--ready-line",
            "READY v1",
            "--heartbeat-line",
            "HEARTBEAT",
            "--evidence",
            "runtime.evidence.json",
        ])
        .assert()
        .code(2)
        .get_output()
        .stderr
        .clone();
    assert!(
        String::from_utf8_lossy(&stderr)
            .contains("USB VID/PID must be exactly four hexadecimal digits")
    );
}

#[test]
fn runtime_accept_rejects_unbounded_duration_before_starting_baud() {
    let directory = tempdir().unwrap();
    let evidence = directory.path().join("runtime.evidence.json");
    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "--fixture",
            fixture(),
            "runtime",
            "accept",
            "--baud-executable",
            "definitely-missing-baud",
            "--probe",
            "replay:stlink-v3:0039002A3432510433343034",
            "--target",
            "STM32G431CBTx",
            "--port",
            "COM11",
            "--vid",
            "1366",
            "--pid",
            "1061",
            "--serial-number",
            "001050275757",
            "--duration",
            "121",
            "--ready-line",
            "READY v1",
            "--heartbeat-line",
            "HEARTBEAT",
            "--evidence",
            evidence.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .code(7)
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["operation"], "runtime.accept");
    assert_eq!(result["error"]["code"], "CONFIG_INVALID");
    assert_eq!(result["error"]["details"]["duration_seconds"], 121);
    assert!(!evidence.exists());
}

#[test]
fn runtime_accept_rejects_contract_and_direct_field_mixing() {
    let directory = tempdir().unwrap();
    let evidence = directory.path().join("runtime.evidence.json");
    let missing_contract = directory.path().join("missing-contract.json");
    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "runtime",
            "accept",
            "--contract",
            missing_contract.to_str().unwrap(),
            "--probe",
            "unexpected-override",
            "--evidence",
            evidence.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .code(7)
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["error"]["code"], "CONFIG_INVALID");
    assert_eq!(result["error"]["details"]["conflicts"][0], "--probe");
    assert!(!evidence.exists());
}

#[test]
fn runtime_accept_requires_direct_identity_without_a_contract() {
    let directory = tempdir().unwrap();
    let evidence = directory.path().join("runtime.evidence.json");
    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "runtime",
            "accept",
            "--evidence",
            evidence.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .code(7)
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(result["error"]["code"], "CONFIG_INVALID");
    assert_eq!(result["error"]["details"]["missing"], "--probe");
    assert!(!evidence.exists());
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
fn flash_session_cli_runs_two_builds_and_cannot_reuse_scope() {
    let directory = tempdir().unwrap();
    let build = directory.path().join("build");
    fs::create_dir(&build).unwrap();
    let transcript = directory.path().join("transcript");
    fs::create_dir(&transcript).unwrap();
    let firmware_a = build.join("a.bin");
    let firmware_b = build.join("b.bin");
    fs::write(&firmware_a, b"first CLI build").unwrap();
    fs::write(&firmware_b, b"second CLI build").unwrap();
    let scope = directory.path().join("scope.json");
    let first_evidence = directory.path().join("first.evidence.json");
    let second_evidence = directory.path().join("second.evidence.json");
    let planned = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "flash",
            "session",
            "plan",
            "--probe",
            "replay:stlink-v3:0039002A3432510433343034",
            "--target",
            "STM32G431CBTx",
            "--firmware-directory",
            build.to_str().unwrap(),
            "--format",
            "bin",
            "--base-address",
            "0x08000000",
            "--write-start",
            "0x08000000",
            "--write-length",
            "64",
            "--erase-start",
            "0x08000000",
            "--erase-length",
            "2048",
            "--max-flashes",
            "2",
            "--duration-seconds",
            "120",
            "--output",
            scope.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let planned: Value = serde_json::from_slice(&planned).unwrap();
    assert_eq!(planned["data"]["hardware_access"], false);
    let digest = planned["data"]["confirm_digest"].as_str().unwrap();
    let mut child = ProcessCommand::new(assert_cmd::cargo::cargo_bin!("embedded-debugger"))
        .args([
            "--fixture",
            fixture(),
            "flash",
            "session",
            "serve",
            scope.to_str().unwrap(),
            "--confirm",
            digest,
            "--transcript-dir",
            transcript.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    writeln!(
        stdin,
        "{}",
        serde_json::json!({"operation":"flash","firmware":firmware_a,"evidence":first_evidence})
    )
    .unwrap();
    writeln!(
        stdin,
        "{}",
        serde_json::json!({"operation":"flash","firmware":firmware_b,"evidence":second_evidence})
    )
    .unwrap();
    let output = child.wait_with_output().unwrap();
    drop(stdin);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(transcript.join("responses.jsonl")).unwrap(),
        output.stdout
    );
    let requests: Vec<Value> = fs::read_to_string(transcript.join("requests.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0]["firmware"], firmware_a.to_str().unwrap());
    assert_eq!(requests[1]["firmware"], firmware_b.to_str().unwrap());
    let messages: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(messages.len(), 3);
    assert_eq!(messages[0]["operation"], "flash.session.ready");
    assert_eq!(messages[1]["operation"], "flash.session.flash");
    assert_eq!(messages[2]["data"]["remaining"], 0);
    assert!(first_evidence.exists());
    assert!(second_evidence.exists());

    let restarted = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "--fixture",
            fixture(),
            "flash",
            "session",
            "serve",
            scope.to_str().unwrap(),
            "--confirm",
            digest,
        ])
        .assert()
        .code(8)
        .get_output()
        .clone();
    assert!(restarted.stdout.is_empty());
    assert!(String::from_utf8_lossy(&restarted.stderr).contains("PERMISSION_DENIED"));
}

#[test]
fn flash_session_cli_transcribes_failure_without_flashing() {
    let directory = tempdir().unwrap();
    let build = directory.path().join("build");
    let transcript = directory.path().join("transcript");
    fs::create_dir(&build).unwrap();
    fs::create_dir(&transcript).unwrap();
    let scope = directory.path().join("scope.json");
    let planned = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "flash",
            "session",
            "plan",
            "--probe",
            "replay:stlink-v3:0039002A3432510433343034",
            "--target",
            "STM32G431CBTx",
            "--firmware-directory",
            build.to_str().unwrap(),
            "--format",
            "bin",
            "--base-address",
            "0x08000000",
            "--write-start",
            "0x08000000",
            "--write-length",
            "64",
            "--erase-start",
            "0x08000000",
            "--erase-length",
            "2048",
            "--max-flashes",
            "2",
            "--duration-seconds",
            "120",
            "--output",
            scope.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let planned: Value = serde_json::from_slice(&planned).unwrap();
    let digest = planned["data"]["confirm_digest"].as_str().unwrap();
    Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "--fixture",
            fixture(),
            "flash",
            "session",
            "serve",
            scope.to_str().unwrap(),
            "--confirm",
            &"0".repeat(64),
            "--transcript-dir",
            transcript.to_str().unwrap(),
        ])
        .assert()
        .code(2);
    assert!(fs::read_dir(&transcript).unwrap().next().is_none());
    assert!(!scope.with_file_name("scope.json.active").exists());
    let mut child = ProcessCommand::new(assert_cmd::cargo::cargo_bin!("embedded-debugger"))
        .args([
            "--fixture",
            fixture(),
            "flash",
            "session",
            "serve",
            scope.to_str().unwrap(),
            "--confirm",
            digest,
            "--transcript-dir",
            transcript.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(b"not-json\n").unwrap();
    let output = child.wait_with_output().unwrap();
    drop(stdin);
    assert!(!output.status.success());
    assert_eq!(
        fs::read(transcript.join("requests.jsonl")).unwrap(),
        b"not-json\n"
    );
    assert_eq!(
        fs::read(transcript.join("responses.jsonl")).unwrap(),
        output.stdout
    );
    let messages: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0]["operation"], "flash.session.ready");
    assert_eq!(messages[1]["error"]["code"], "CONFIG_INVALID");
    assert!(fs::read_dir(&build).unwrap().next().is_none());
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
fn intel_hex_plan_is_normalized_and_execute_remains_blocked() {
    let directory = tempdir().unwrap();
    let firmware = directory.path().join("firmware.hex");
    let evidence = directory.path().join("run.evidence.json");
    fs::write(
        &firmware,
        ":020000040800F2\n:0400000001020304F2\n:00000001FF\n",
    )
    .unwrap();

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

    assert_eq!(plan["data"]["firmware"]["format"], "hex");
    assert_eq!(plan["data"]["firmware"]["program_size"], 4);
    assert_eq!(plan["data"]["firmware"]["segments"][0]["kind"], "data");
    assert_eq!(
        plan["data"]["firmware"]["segments"][0]["start"],
        "0x08000000"
    );
    assert_eq!(plan["data"]["execution"]["supported"], false);
    assert_eq!(
        plan["data"]["execution"]["blockers"][0]["code"],
        "INTEL_HEX_EXECUTION_ACCEPTANCE_REQUIRED"
    );

    let confirmation = plan["data"]["confirm_digest"].as_str().unwrap();
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
        .code(6)
        .get_output()
        .stdout
        .clone();
    let execute: Value = serde_json::from_slice(&execute_output).unwrap();

    assert_eq!(execute["error"]["code"], "CAPABILITY_UNAVAILABLE");
    assert_eq!(
        execute["error"]["details"]["target_session_attached"],
        false
    );
    assert_eq!(
        execute["error"]["details"]["flash_operation_requested"],
        false
    );
    assert_eq!(execute["error"]["details"]["reset_requested"], false);
    assert!(!evidence.exists());
}

#[test]
fn intel_hex_execution_uses_independent_format_segment_and_non_boot_nvm_gates() {
    let directory = tempdir().unwrap();
    let firmware = directory.path().join("uicr.hex");
    let fixture_path = directory.path().join("nrf52840.json");
    fs::write(
        &firmware,
        ":020000041000EA\n:041000001122334442\n:00000001FF\n",
    )
    .unwrap();

    let mut value: Value = serde_json::from_slice(&fs::read(fixture()).unwrap()).unwrap();
    value["target"]["name"] = "nRF52840_xxAA".into();
    value["target"]["architecture"] = "armv7em".into();
    value["capabilities"]["intel_hex_flash"] = true.into();
    value["capabilities"]["segmented_flash"] = true.into();
    value["capabilities"]["non_boot_nvm_flash"] = false.into();
    value["flash"]["base_address"] = "0x10001000".into();
    value["flash"]["erase_ranges"] = serde_json::json!([{
        "start": "0x10001000",
        "length": 4096
    }]);
    fs::write(&fixture_path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();

    let output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "--fixture",
            fixture_path.to_str().unwrap(),
            "flash",
            "plan",
            firmware.to_str().unwrap(),
            "--target",
            "nRF52840_xxAA",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let plan: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(plan["data"]["firmware"]["segments"][0]["kind"], "uicr");
    assert_eq!(plan["data"]["execution"]["supported"], false);
    assert_eq!(
        plan["data"]["execution"]["blockers"][0]["code"],
        "NON_BOOT_NVM_EXECUTION_ACCEPTANCE_REQUIRED"
    );
}

#[test]
fn nrf52840_development_debug_flag_accepts_only_the_digest_bound_approtect_policy() {
    let directory = tempdir().unwrap();
    let firmware = directory.path().join("development-debug.hex");
    let fixture_path = directory.path().join("nrf52840.json");
    fs::write(
        &firmware,
        ":020000040000FA\n:0400000001020304F2\n:020000041000EA\n:041208005A00000088\n:00000001FF\n",
    )
    .unwrap();

    let mut value: Value = serde_json::from_slice(&fs::read(fixture()).unwrap()).unwrap();
    value["target"]["name"] = "nRF52840_xxAA".into();
    value["target"]["architecture"] = "armv7em".into();
    value["capabilities"]["intel_hex_flash"] = true.into();
    value["capabilities"]["segmented_flash"] = true.into();
    value["capabilities"]["non_boot_nvm_flash"] = false.into();
    value["flash"]["base_address"] = "0x00000000".into();
    value["flash"]["erase_ranges"] = serde_json::json!([
        {"start": "0x00000000", "length": 4096},
        {"start": "0x10001000", "length": 4096}
    ]);
    fs::write(&fixture_path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();

    let default_output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "--fixture",
            fixture_path.to_str().unwrap(),
            "flash",
            "plan",
            firmware.to_str().unwrap(),
            "--target",
            "nRF52840_xxAA",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let default_plan: Value = serde_json::from_slice(&default_output).unwrap();

    let accepted_output = Command::cargo_bin("embedded-debugger")
        .unwrap()
        .args([
            "--fixture",
            fixture_path.to_str().unwrap(),
            "flash",
            "plan",
            firmware.to_str().unwrap(),
            "--target",
            "nRF52840_xxAA",
            "--allow-nrf52840-development-debug",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let accepted_plan: Value = serde_json::from_slice(&accepted_output).unwrap();

    assert_eq!(default_plan["data"]["execution"]["supported"], false);
    assert_eq!(accepted_plan["data"]["execution"]["supported"], true);
    assert_ne!(
        default_plan["data"]["confirm_digest"],
        accepted_plan["data"]["confirm_digest"]
    );
    assert_eq!(
        accepted_plan["data"]["policy"]["nrf52840_development_debug"]["uicr_address"],
        "0x10001208"
    );
    assert_eq!(
        accepted_plan["data"]["policy"]["nrf52840_development_debug"]["little_endian_bytes"],
        "5a000000"
    );
    assert!(
        accepted_plan["data"]["actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|action| action["action"] == "program_nrf52840_uicr_approtect_hw_disabled")
    );
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
