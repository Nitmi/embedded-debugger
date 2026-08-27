use std::{
    collections::{HashMap, HashSet},
    env,
    ffi::OsString,
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{ChildStdin, Command, ExitStatus, Stdio},
    sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

#[cfg(windows)]
use process_wrap::std::JobObject;
#[cfg(unix)]
use process_wrap::std::ProcessGroup;
use process_wrap::std::{ChildWrapper, CommandWrap};
use serde::Serialize;
use serde_gdbmi::{
    lexer::{self, Token as MiToken},
    parser::{DataSymbol, ResponseBody as StructuredResponseBody, Value as MiValue},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    error::{DebugError, ErrorCode, Result, SuggestedAction},
    model::{Address, MAX_INLINE_MEMORY_READ_BYTES},
};

pub const DEFAULT_GDB_VERSION_TIMEOUT_MS: u64 = 10_000;
pub const MIN_GDB_VERSION_TIMEOUT_MS: u64 = 100;
pub const MAX_GDB_VERSION_TIMEOUT_MS: u64 = 30_000;
pub const DEFAULT_GDB_MI_STARTUP_TIMEOUT_MS: u64 = 10_000;
pub const MIN_GDB_MI_STARTUP_TIMEOUT_MS: u64 = 100;
pub const MAX_GDB_MI_STARTUP_TIMEOUT_MS: u64 = 60_000;
pub const DEFAULT_GDB_MI_SHUTDOWN_TIMEOUT_MS: u64 = 3_000;
pub const MIN_GDB_MI_SHUTDOWN_TIMEOUT_MS: u64 = 100;
pub const MAX_GDB_MI_SHUTDOWN_TIMEOUT_MS: u64 = 30_000;
pub const DEFAULT_GDB_MI_COMMAND_TIMEOUT_MS: u64 = 10_000;
pub const MIN_GDB_MI_COMMAND_TIMEOUT_MS: u64 = 100;
pub const MAX_GDB_MI_COMMAND_TIMEOUT_MS: u64 = 60_000;

const MAX_GDB_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_MI_OUTPUT_BYTES_PER_STREAM: usize = 256 * 1024;
const MAX_MI_OUTPUT_LINE_BYTES: usize = 16 * 1024;
const MI_OUTPUT_EVENT_QUEUE_CAPACITY: usize = 256;
const MI_OUTPUT_SNIPPET_CHARS: usize = 4 * 1024;
const MI_POLL_INTERVAL: Duration = Duration::from_millis(10);
const MI_STREAM_DRAIN_GRACE: Duration = Duration::from_secs(1);
const VERSION_TOKEN: u64 = 1;
const EXIT_TOKEN: u64 = 2;
const VERSION_COMMAND: &str = "-gdb-version";
const EXIT_COMMAND: &str = "-gdb-exit";
const REMOTE_SELECT_TOKEN: u64 = 2;
const REMOTE_DETACH_TOKEN: u64 = 3;
const REMOTE_EXIT_TOKEN: u64 = 4;
const REMOTE_SELECT_COMMAND_PLACEHOLDER: &str =
    "-target-select remote 127.0.0.1:<dynamic_openocd_gdb_port>";
const REMOTE_DETACH_COMMAND: &str = "-target-detach";
const REGISTER_NAMES_TOKEN: u64 = 3;
const REGISTER_VALUES_TOKEN: u64 = 4;
const REGISTER_DETACH_TOKEN: u64 = 5;
const REGISTER_EXIT_TOKEN: u64 = 6;
const REGISTER_NAMES_COMMAND: &str = "-data-list-register-names";
const REGISTER_VALUES_COMMAND_PLACEHOLDER: &str =
    "-data-list-register-values --skip-unavailable x <resolved_register_numbers>";
const MEMORY_READ_TOKEN: u64 = 3;
const MEMORY_DETACH_TOKEN: u64 = 4;
const MEMORY_EXIT_TOKEN: u64 = 5;
const STACK_LIST_TOKEN: u64 = 3;
const STACK_DETACH_TOKEN: u64 = 4;
const STACK_EXIT_TOKEN: u64 = 5;
const MI_LAUNCH_ARGUMENTS: [&str; 4] = ["--nx", "--nh", "--quiet", "--interpreter=mi2"];
pub(super) const XTENSA_GNU_CONFIG_ENV: &str = "XTENSA_GNU_CONFIG";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GdbInspectOptions {
    pub executable: PathBuf,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GdbMiTestOptions {
    pub executable: PathBuf,
    pub version_timeout_ms: u64,
    pub startup_timeout_ms: u64,
    pub shutdown_timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GdbInspection {
    pub backend: String,
    pub component: String,
    pub scope: String,
    pub risk: String,
    pub complete: bool,
    pub executable: GdbExecutableInspection,
    pub executable_file: GdbExecutableFileIdentity,
    pub capabilities: GdbInspectionCapabilities,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GdbExecutableInspection {
    pub requested: String,
    pub resolved: String,
    pub version_line: String,
    pub version_source: GdbVersionSource,
    pub vendor: String,
    pub timeout_ms: u64,
    pub elapsed_ms: u64,
    pub exit_code: i32,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub output_limit_bytes_per_stream: u64,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GdbVersionSource {
    Stdout,
    Stderr,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GdbExecutableFileIdentity {
    pub bytes: u64,
    pub sha256: String,
    pub maximum_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GdbInspectionCapabilities {
    pub executable_discovery: bool,
    pub bounded_version_probe: bool,
    pub gdb_mi_host_process: bool,
    pub remote_target_connection: bool,
    pub target_operations: bool,
    pub flash: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GdbMiTestReport {
    pub backend: String,
    pub component: String,
    pub scope: String,
    pub risk: String,
    pub complete: bool,
    pub executable: GdbExecutableInspection,
    pub executable_file: GdbExecutableFileIdentity,
    pub protocol: GdbMiProtocol,
    pub handshake: GdbMiHandshake,
    pub shutdown: GdbMiShutdown,
    pub capabilities: GdbMiCapabilities,
    pub output: GdbMiOutput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GdbMiProtocol {
    pub interpreter: String,
    pub launch_arguments: Vec<String>,
    pub initialization_files_enabled: bool,
    pub input_encoding: String,
    pub line_terminator: String,
    pub token_correlation_required: bool,
    pub process_isolation: String,
    pub commands: Vec<GdbMiPlannedCommand>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GdbMiPlannedCommand {
    pub token: u64,
    pub command: String,
    pub expected_result_class: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GdbMiHandshake {
    pub startup_prompt_observed: bool,
    pub startup_elapsed_ms: u64,
    pub startup_timeout_ms: u64,
    pub version_command: GdbMiCommandResult,
    pub version_stream_records: u64,
    pub record_counts: GdbMiRecordCounts,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GdbMiCommandResult {
    pub token: u64,
    pub command: String,
    pub result_class: String,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GdbMiShutdown {
    pub token: u64,
    pub command: String,
    pub expected_result_class: String,
    pub command_sent: bool,
    pub result_observed: bool,
    pub result_class: Option<String>,
    pub graceful: bool,
    pub exit_code: Option<i32>,
    pub exit_success: bool,
    pub elapsed_ms: u64,
    pub timeout_ms: u64,
    pub forced_process_tree_kill: bool,
    pub process_tree_termination_enforced: bool,
    pub process_tree_cleanup_complete: bool,
    pub command_error: Option<String>,
    pub termination_error: Option<String>,
    pub wait_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GdbMiCapabilities {
    pub gdb_mi_host_process: bool,
    pub token_correlated_commands: bool,
    pub remote_target_connection: bool,
    pub symbol_loading: bool,
    pub register_read: bool,
    pub memory_read: bool,
    pub stack_read: bool,
    pub breakpoints: bool,
    pub execution_control: bool,
    pub flash: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GdbMiOutput {
    pub output_limit_bytes_per_stream: u64,
    pub line_limit_bytes: u64,
    pub event_queue_capacity: u64,
    pub stdout: GdbMiOutputSummary,
    pub stderr: GdbMiOutputSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GdbMiOutputSummary {
    pub total_bytes: u64,
    pub retained_bytes: u64,
    pub sha256: String,
    pub truncated: bool,
    pub line_limit_exceeded: bool,
    pub events_dropped: u64,
    pub drain_complete: bool,
    pub read_error: Option<String>,
    pub snippet: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct GdbMiRecordCounts {
    pub prompts: u64,
    pub results: u64,
    pub exec_async: u64,
    pub status_async: u64,
    pub notify_async: u64,
    pub console_stream: u64,
    pub target_stream: u64,
    pub log_stream: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GdbMiRegisterInventory {
    pub total_entries: u64,
    pub named_entries: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GdbMiRegisterValue {
    pub requested_name: String,
    pub canonical_name: String,
    pub number: u64,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GdbMiMemoryBlock {
    pub begin: Address,
    pub offset_bytes: u64,
    pub end_exclusive: Address,
    pub length_bytes: u64,
    pub contents: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GdbMiMemorySnapshot {
    pub address: Address,
    pub length_bytes: u64,
    pub end_exclusive: Address,
    pub encoding: String,
    pub data: String,
    pub sha256: String,
    pub complete_coverage: bool,
    pub blocks: Vec<GdbMiMemoryBlock>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GdbMiStackFrame {
    pub level: u64,
    pub address: Address,
    pub function: Option<String>,
    pub file: Option<String>,
    pub fullname: Option<String>,
    pub line: Option<u64>,
    pub module: Option<String>,
    pub architecture: Option<String>,
    pub address_flags: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GdbMiStackSnapshot {
    pub maximum_frames: u64,
    pub returned_frames: u64,
    pub frame_limit_reached: bool,
    pub additional_gdb_frames_possible: bool,
    pub physical_call_stack_completeness_proven: bool,
    pub frames: Vec<GdbMiStackFrame>,
}

pub(super) struct RemoteGdbExecution {
    pub endpoint: String,
    pub startup_elapsed: Duration,
    pub version_elapsed: Duration,
    pub version_result_class: String,
    pub version_stream_records: u64,
    pub connect_elapsed: Duration,
    pub connect_result_class: String,
    pub detach_elapsed: Duration,
    pub detach_result_class: String,
    pub record_counts: GdbMiRecordCounts,
    pub shutdown: GdbMiShutdown,
    pub output: GdbMiOutput,
}

pub(super) struct RemoteRegisterExecution {
    pub endpoint: String,
    pub startup_elapsed: Duration,
    pub version_elapsed: Duration,
    pub version_result_class: String,
    pub version_stream_records: u64,
    pub connect_elapsed: Duration,
    pub connect_result_class: String,
    pub names_elapsed: Duration,
    pub names_result_class: String,
    pub values_elapsed: Duration,
    pub values_result_class: String,
    pub values_command: String,
    pub inventory: GdbMiRegisterInventory,
    pub values: Vec<GdbMiRegisterValue>,
    pub detach_elapsed: Duration,
    pub detach_result_class: String,
    pub record_counts: GdbMiRecordCounts,
    pub shutdown: GdbMiShutdown,
    pub output: GdbMiOutput,
}

pub(super) struct RemoteMemoryExecution {
    pub endpoint: String,
    pub startup_elapsed: Duration,
    pub version_elapsed: Duration,
    pub version_result_class: String,
    pub version_stream_records: u64,
    pub connect_elapsed: Duration,
    pub connect_result_class: String,
    pub read_elapsed: Duration,
    pub read_result_class: String,
    pub read_command: String,
    pub snapshot: GdbMiMemorySnapshot,
    pub detach_elapsed: Duration,
    pub detach_result_class: String,
    pub record_counts: GdbMiRecordCounts,
    pub shutdown: GdbMiShutdown,
    pub output: GdbMiOutput,
}

pub(super) struct RemoteStackExecution {
    pub endpoint: String,
    pub startup_elapsed: Duration,
    pub version_elapsed: Duration,
    pub version_result_class: String,
    pub version_stream_records: u64,
    pub connect_elapsed: Duration,
    pub connect_result_class: String,
    pub list_elapsed: Duration,
    pub list_result_class: String,
    pub list_command: String,
    pub snapshot: GdbMiStackSnapshot,
    pub detach_elapsed: Duration,
    pub detach_result_class: String,
    pub record_counts: GdbMiRecordCounts,
    pub shutdown: GdbMiShutdown,
    pub output: GdbMiOutput,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct RemoteMemoryRequest {
    pub address: Address,
    pub length_bytes: u64,
}

pub fn inspect_gdb(options: &GdbInspectOptions) -> Result<GdbInspection> {
    validate_version_timeout(options.timeout_ms)?;
    validate_executable_request(&options.executable)?;
    let executable = inspect_gdb_executable(&options.executable, options.timeout_ms)?;
    let executable_file = inspect_executable_file(Path::new(&executable.resolved))?;

    Ok(GdbInspection {
        backend: "openocd".to_string(),
        component: "gdb".to_string(),
        scope: "host_only".to_string(),
        risk: "R0_READ_ONLY".to_string(),
        complete: true,
        executable,
        executable_file,
        capabilities: GdbInspectionCapabilities {
            executable_discovery: true,
            bounded_version_probe: true,
            gdb_mi_host_process: false,
            remote_target_connection: false,
            target_operations: false,
            flash: false,
        },
    })
}

pub fn test_gdb_mi(options: &GdbMiTestOptions) -> Result<GdbMiTestReport> {
    validate_test_options(options)?;
    let inspection = inspect_gdb(&GdbInspectOptions {
        executable: options.executable.clone(),
        timeout_ms: options.version_timeout_ms,
    })?;

    let mut command = Command::new(&inspection.executable.resolved);
    command
        .args(MI_LAUNCH_ARGUMENTS)
        .env_remove(XTENSA_GNU_CONFIG_ENV);
    let mut gdb = ManagedGdb::spawn(command, &inspection.executable.resolved, EXIT_TOKEN)?;
    let lifecycle = match gdb.run_lifecycle(
        Duration::from_millis(options.startup_timeout_ms),
        Duration::from_millis(options.shutdown_timeout_ms),
    ) {
        Ok(lifecycle) => lifecycle,
        Err(failure) => {
            return Err(finalize_failure(gdb, failure, options.shutdown_timeout_ms));
        }
    };

    let mut shutdown = gdb.cleanup(Duration::from_millis(options.shutdown_timeout_ms));
    let record_counts = gdb.record_counts.clone();
    let output = gdb.finish_output();
    shutdown.process_tree_cleanup_complete &= output_streams_closed(&output);

    if !shutdown.command_sent
        || !shutdown.result_observed
        || !shutdown.graceful
        || !shutdown.exit_success
        || !shutdown.process_tree_cleanup_complete
    {
        return Err(protocol_error_with_lifecycle(
            "managed GDB/MI process did not complete a graceful shutdown",
            json!({}),
            &shutdown,
            &output,
        ));
    }
    validate_complete_output(&output)
        .map_err(|message| protocol_error_with_lifecycle(message, json!({}), &shutdown, &output))?;

    Ok(GdbMiTestReport {
        backend: "openocd".to_string(),
        component: "gdb".to_string(),
        scope: "managed_gdb_mi_lifecycle".to_string(),
        risk: "R0_READ_ONLY".to_string(),
        complete: true,
        executable: inspection.executable,
        executable_file: inspection.executable_file,
        protocol: protocol_contract(),
        handshake: GdbMiHandshake {
            startup_prompt_observed: true,
            startup_elapsed_ms: duration_ms(lifecycle.startup_elapsed),
            startup_timeout_ms: options.startup_timeout_ms,
            version_command: GdbMiCommandResult {
                token: VERSION_TOKEN,
                command: VERSION_COMMAND.to_string(),
                result_class: lifecycle.version_result_class,
                elapsed_ms: duration_ms(lifecycle.version_elapsed),
            },
            version_stream_records: lifecycle.version_stream_records,
            record_counts,
        },
        shutdown,
        capabilities: GdbMiCapabilities {
            gdb_mi_host_process: true,
            token_correlated_commands: true,
            remote_target_connection: false,
            symbol_loading: false,
            register_read: false,
            memory_read: false,
            stack_read: false,
            breakpoints: false,
            execution_control: false,
            flash: false,
        },
        output,
    })
}

pub(super) fn execute_remote_gdb(
    executable: &str,
    xtensa_config: Option<&str>,
    gdb_port: u16,
    startup_timeout_ms: u64,
    command_timeout_ms: u64,
    shutdown_timeout_ms: u64,
) -> Result<RemoteGdbExecution> {
    let endpoint = format!("127.0.0.1:{gdb_port}");
    let mut command = Command::new(executable);
    command
        .args(MI_LAUNCH_ARGUMENTS)
        .env_remove(XTENSA_GNU_CONFIG_ENV);
    if let Some(config) = xtensa_config {
        command.env(XTENSA_GNU_CONFIG_ENV, config);
    }
    let mut gdb = ManagedGdb::spawn(command, executable, REMOTE_EXIT_TOKEN)?;
    let lifecycle = match gdb.run_remote_lifecycle(
        &endpoint,
        Duration::from_millis(startup_timeout_ms),
        Duration::from_millis(command_timeout_ms),
        Duration::from_millis(shutdown_timeout_ms),
    ) {
        Ok(lifecycle) => lifecycle,
        Err(failure) => {
            return Err(finalize_failure(gdb, failure, shutdown_timeout_ms));
        }
    };

    let mut shutdown = gdb.cleanup(Duration::from_millis(shutdown_timeout_ms));
    let record_counts = gdb.record_counts.clone();
    let output = gdb.finish_output();
    shutdown.process_tree_cleanup_complete &= output_streams_closed(&output);
    if !shutdown.command_sent
        || !shutdown.result_observed
        || !shutdown.graceful
        || !shutdown.exit_success
        || !shutdown.process_tree_cleanup_complete
    {
        return Err(protocol_error_with_lifecycle(
            "remote GDB/MI process did not complete a graceful shutdown",
            json!({"endpoint": endpoint}),
            &shutdown,
            &output,
        ));
    }
    validate_complete_output(&output).map_err(|message| {
        protocol_error_with_lifecycle(message, json!({"endpoint": endpoint}), &shutdown, &output)
    })?;

    Ok(RemoteGdbExecution {
        endpoint,
        startup_elapsed: lifecycle.startup_elapsed,
        version_elapsed: lifecycle.version_elapsed,
        version_result_class: lifecycle.version_result_class,
        version_stream_records: lifecycle.version_stream_records,
        connect_elapsed: lifecycle.connect_elapsed,
        connect_result_class: lifecycle.connect_result_class,
        detach_elapsed: lifecycle.detach_elapsed,
        detach_result_class: lifecycle.detach_result_class,
        record_counts,
        shutdown,
        output,
    })
}

pub(super) fn execute_remote_register_snapshot(
    executable: &str,
    xtensa_config: Option<&str>,
    gdb_port: u16,
    requested_names: &[String],
    startup_timeout_ms: u64,
    command_timeout_ms: u64,
    shutdown_timeout_ms: u64,
) -> Result<RemoteRegisterExecution> {
    let endpoint = format!("127.0.0.1:{gdb_port}");
    let mut command = Command::new(executable);
    command
        .args(MI_LAUNCH_ARGUMENTS)
        .env_remove(XTENSA_GNU_CONFIG_ENV);
    if let Some(config) = xtensa_config {
        command.env(XTENSA_GNU_CONFIG_ENV, config);
    }
    let mut gdb = ManagedGdb::spawn(command, executable, REGISTER_EXIT_TOKEN)?;
    let lifecycle = match gdb.run_register_lifecycle(
        &endpoint,
        requested_names,
        Duration::from_millis(startup_timeout_ms),
        Duration::from_millis(command_timeout_ms),
        Duration::from_millis(shutdown_timeout_ms),
    ) {
        Ok(lifecycle) => lifecycle,
        Err(failure) => {
            return Err(finalize_failure(gdb, failure, shutdown_timeout_ms));
        }
    };

    let mut shutdown = gdb.cleanup(Duration::from_millis(shutdown_timeout_ms));
    let record_counts = gdb.record_counts.clone();
    let output = gdb.finish_output();
    shutdown.process_tree_cleanup_complete &= output_streams_closed(&output);
    if !shutdown.command_sent
        || !shutdown.result_observed
        || !shutdown.graceful
        || !shutdown.exit_success
        || !shutdown.process_tree_cleanup_complete
    {
        return Err(protocol_error_with_lifecycle(
            "register-snapshot GDB/MI process did not complete a graceful shutdown",
            json!({"endpoint": endpoint}),
            &shutdown,
            &output,
        ));
    }
    validate_complete_output(&output).map_err(|message| {
        protocol_error_with_lifecycle(message, json!({"endpoint": endpoint}), &shutdown, &output)
    })?;

    Ok(RemoteRegisterExecution {
        endpoint,
        startup_elapsed: lifecycle.startup_elapsed,
        version_elapsed: lifecycle.version_elapsed,
        version_result_class: lifecycle.version_result_class,
        version_stream_records: lifecycle.version_stream_records,
        connect_elapsed: lifecycle.connect_elapsed,
        connect_result_class: lifecycle.connect_result_class,
        names_elapsed: lifecycle.names_elapsed,
        names_result_class: lifecycle.names_result_class,
        values_elapsed: lifecycle.values_elapsed,
        values_result_class: lifecycle.values_result_class,
        values_command: lifecycle.values_command,
        inventory: lifecycle.inventory,
        values: lifecycle.values,
        detach_elapsed: lifecycle.detach_elapsed,
        detach_result_class: lifecycle.detach_result_class,
        record_counts,
        shutdown,
        output,
    })
}

pub(super) fn execute_remote_memory_snapshot(
    executable: &str,
    xtensa_config: Option<&str>,
    gdb_port: u16,
    request: RemoteMemoryRequest,
    startup_timeout_ms: u64,
    command_timeout_ms: u64,
    shutdown_timeout_ms: u64,
) -> Result<RemoteMemoryExecution> {
    let endpoint = format!("127.0.0.1:{gdb_port}");
    let mut command = Command::new(executable);
    command
        .args(MI_LAUNCH_ARGUMENTS)
        .env_remove(XTENSA_GNU_CONFIG_ENV);
    if let Some(config) = xtensa_config {
        command.env(XTENSA_GNU_CONFIG_ENV, config);
    }
    let mut gdb = ManagedGdb::spawn(command, executable, MEMORY_EXIT_TOKEN)?;
    let lifecycle = match gdb.run_memory_lifecycle(
        &endpoint,
        request.address,
        request.length_bytes,
        Duration::from_millis(startup_timeout_ms),
        Duration::from_millis(command_timeout_ms),
        Duration::from_millis(shutdown_timeout_ms),
    ) {
        Ok(lifecycle) => lifecycle,
        Err(failure) => {
            return Err(finalize_failure(gdb, failure, shutdown_timeout_ms));
        }
    };

    let mut shutdown = gdb.cleanup(Duration::from_millis(shutdown_timeout_ms));
    let record_counts = gdb.record_counts.clone();
    let output = gdb.finish_output();
    shutdown.process_tree_cleanup_complete &= output_streams_closed(&output);
    if !shutdown.command_sent
        || !shutdown.result_observed
        || !shutdown.graceful
        || !shutdown.exit_success
        || !shutdown.process_tree_cleanup_complete
    {
        return Err(protocol_error_with_lifecycle(
            "memory-snapshot GDB/MI process did not complete a graceful shutdown",
            json!({"endpoint": endpoint}),
            &shutdown,
            &output,
        ));
    }
    validate_complete_output(&output).map_err(|message| {
        protocol_error_with_lifecycle(message, json!({"endpoint": endpoint}), &shutdown, &output)
    })?;

    Ok(RemoteMemoryExecution {
        endpoint,
        startup_elapsed: lifecycle.startup_elapsed,
        version_elapsed: lifecycle.version_elapsed,
        version_result_class: lifecycle.version_result_class,
        version_stream_records: lifecycle.version_stream_records,
        connect_elapsed: lifecycle.connect_elapsed,
        connect_result_class: lifecycle.connect_result_class,
        read_elapsed: lifecycle.read_elapsed,
        read_result_class: lifecycle.read_result_class,
        read_command: lifecycle.read_command,
        snapshot: lifecycle.snapshot,
        detach_elapsed: lifecycle.detach_elapsed,
        detach_result_class: lifecycle.detach_result_class,
        record_counts,
        shutdown,
        output,
    })
}

pub(super) fn execute_remote_stack_snapshot(
    executable: &str,
    xtensa_config: Option<&str>,
    gdb_port: u16,
    maximum_frames: u64,
    startup_timeout_ms: u64,
    command_timeout_ms: u64,
    shutdown_timeout_ms: u64,
) -> Result<RemoteStackExecution> {
    let endpoint = format!("127.0.0.1:{gdb_port}");
    let mut command = Command::new(executable);
    command
        .args(MI_LAUNCH_ARGUMENTS)
        .env_remove(XTENSA_GNU_CONFIG_ENV);
    if let Some(config) = xtensa_config {
        command.env(XTENSA_GNU_CONFIG_ENV, config);
    }
    let mut gdb = ManagedGdb::spawn(command, executable, STACK_EXIT_TOKEN)?;
    let lifecycle = match gdb.run_stack_lifecycle(
        &endpoint,
        maximum_frames,
        Duration::from_millis(startup_timeout_ms),
        Duration::from_millis(command_timeout_ms),
        Duration::from_millis(shutdown_timeout_ms),
    ) {
        Ok(lifecycle) => lifecycle,
        Err(failure) => {
            return Err(finalize_failure(gdb, failure, shutdown_timeout_ms));
        }
    };

    let mut shutdown = gdb.cleanup(Duration::from_millis(shutdown_timeout_ms));
    let record_counts = gdb.record_counts.clone();
    let output = gdb.finish_output();
    shutdown.process_tree_cleanup_complete &= output_streams_closed(&output);
    if !shutdown.command_sent
        || !shutdown.result_observed
        || !shutdown.graceful
        || !shutdown.exit_success
        || !shutdown.process_tree_cleanup_complete
    {
        return Err(protocol_error_with_lifecycle(
            "stack-snapshot GDB/MI process did not complete a graceful shutdown",
            json!({"endpoint": endpoint}),
            &shutdown,
            &output,
        ));
    }
    validate_complete_output(&output).map_err(|message| {
        protocol_error_with_lifecycle(message, json!({"endpoint": endpoint}), &shutdown, &output)
    })?;

    Ok(RemoteStackExecution {
        endpoint,
        startup_elapsed: lifecycle.startup_elapsed,
        version_elapsed: lifecycle.version_elapsed,
        version_result_class: lifecycle.version_result_class,
        version_stream_records: lifecycle.version_stream_records,
        connect_elapsed: lifecycle.connect_elapsed,
        connect_result_class: lifecycle.connect_result_class,
        list_elapsed: lifecycle.list_elapsed,
        list_result_class: lifecycle.list_result_class,
        list_command: lifecycle.list_command,
        snapshot: lifecycle.snapshot,
        detach_elapsed: lifecycle.detach_elapsed,
        detach_result_class: lifecycle.detach_result_class,
        record_counts,
        shutdown,
        output,
    })
}

fn protocol_contract() -> GdbMiProtocol {
    GdbMiProtocol {
        interpreter: "mi2".to_string(),
        launch_arguments: MI_LAUNCH_ARGUMENTS
            .into_iter()
            .map(str::to_string)
            .collect(),
        initialization_files_enabled: false,
        input_encoding: "ascii".to_string(),
        line_terminator: "lf".to_string(),
        token_correlation_required: true,
        process_isolation: process_isolation().to_string(),
        commands: vec![
            GdbMiPlannedCommand {
                token: VERSION_TOKEN,
                command: VERSION_COMMAND.to_string(),
                expected_result_class: "done".to_string(),
            },
            GdbMiPlannedCommand {
                token: EXIT_TOKEN,
                command: EXIT_COMMAND.to_string(),
                expected_result_class: "exit".to_string(),
            },
        ],
    }
}

pub(super) fn remote_protocol_contract() -> GdbMiProtocol {
    GdbMiProtocol {
        interpreter: "mi2".to_string(),
        launch_arguments: MI_LAUNCH_ARGUMENTS
            .into_iter()
            .map(str::to_string)
            .collect(),
        initialization_files_enabled: false,
        input_encoding: "ascii".to_string(),
        line_terminator: "lf".to_string(),
        token_correlation_required: true,
        process_isolation: process_isolation().to_string(),
        commands: vec![
            GdbMiPlannedCommand {
                token: VERSION_TOKEN,
                command: VERSION_COMMAND.to_string(),
                expected_result_class: "done".to_string(),
            },
            GdbMiPlannedCommand {
                token: REMOTE_SELECT_TOKEN,
                command: REMOTE_SELECT_COMMAND_PLACEHOLDER.to_string(),
                expected_result_class: "connected".to_string(),
            },
            GdbMiPlannedCommand {
                token: REMOTE_DETACH_TOKEN,
                command: REMOTE_DETACH_COMMAND.to_string(),
                expected_result_class: "done".to_string(),
            },
            GdbMiPlannedCommand {
                token: REMOTE_EXIT_TOKEN,
                command: EXIT_COMMAND.to_string(),
                expected_result_class: "exit".to_string(),
            },
        ],
    }
}

pub(super) fn register_protocol_contract() -> GdbMiProtocol {
    GdbMiProtocol {
        interpreter: "mi2".to_string(),
        launch_arguments: MI_LAUNCH_ARGUMENTS
            .into_iter()
            .map(str::to_string)
            .collect(),
        initialization_files_enabled: false,
        input_encoding: "ascii".to_string(),
        line_terminator: "lf".to_string(),
        token_correlation_required: true,
        process_isolation: process_isolation().to_string(),
        commands: vec![
            GdbMiPlannedCommand {
                token: VERSION_TOKEN,
                command: VERSION_COMMAND.to_string(),
                expected_result_class: "done".to_string(),
            },
            GdbMiPlannedCommand {
                token: REMOTE_SELECT_TOKEN,
                command: REMOTE_SELECT_COMMAND_PLACEHOLDER.to_string(),
                expected_result_class: "connected".to_string(),
            },
            GdbMiPlannedCommand {
                token: REGISTER_NAMES_TOKEN,
                command: REGISTER_NAMES_COMMAND.to_string(),
                expected_result_class: "done".to_string(),
            },
            GdbMiPlannedCommand {
                token: REGISTER_VALUES_TOKEN,
                command: REGISTER_VALUES_COMMAND_PLACEHOLDER.to_string(),
                expected_result_class: "done".to_string(),
            },
            GdbMiPlannedCommand {
                token: REGISTER_DETACH_TOKEN,
                command: REMOTE_DETACH_COMMAND.to_string(),
                expected_result_class: "done".to_string(),
            },
            GdbMiPlannedCommand {
                token: REGISTER_EXIT_TOKEN,
                command: EXIT_COMMAND.to_string(),
                expected_result_class: "exit".to_string(),
            },
        ],
    }
}

pub(super) fn memory_protocol_contract(address: Address, length_bytes: u64) -> GdbMiProtocol {
    GdbMiProtocol {
        interpreter: "mi2".to_string(),
        launch_arguments: MI_LAUNCH_ARGUMENTS
            .into_iter()
            .map(str::to_string)
            .collect(),
        initialization_files_enabled: false,
        input_encoding: "ascii".to_string(),
        line_terminator: "lf".to_string(),
        token_correlation_required: true,
        process_isolation: process_isolation().to_string(),
        commands: vec![
            GdbMiPlannedCommand {
                token: VERSION_TOKEN,
                command: VERSION_COMMAND.to_string(),
                expected_result_class: "done".to_string(),
            },
            GdbMiPlannedCommand {
                token: REMOTE_SELECT_TOKEN,
                command: REMOTE_SELECT_COMMAND_PLACEHOLDER.to_string(),
                expected_result_class: "connected".to_string(),
            },
            GdbMiPlannedCommand {
                token: MEMORY_READ_TOKEN,
                command: memory_read_command(address, length_bytes),
                expected_result_class: "done".to_string(),
            },
            GdbMiPlannedCommand {
                token: MEMORY_DETACH_TOKEN,
                command: REMOTE_DETACH_COMMAND.to_string(),
                expected_result_class: "done".to_string(),
            },
            GdbMiPlannedCommand {
                token: MEMORY_EXIT_TOKEN,
                command: EXIT_COMMAND.to_string(),
                expected_result_class: "exit".to_string(),
            },
        ],
    }
}

pub(super) fn stack_protocol_contract(maximum_frames: u64) -> GdbMiProtocol {
    GdbMiProtocol {
        interpreter: "mi2".to_string(),
        launch_arguments: MI_LAUNCH_ARGUMENTS
            .into_iter()
            .map(str::to_string)
            .collect(),
        initialization_files_enabled: false,
        input_encoding: "ascii".to_string(),
        line_terminator: "lf".to_string(),
        token_correlation_required: true,
        process_isolation: process_isolation().to_string(),
        commands: vec![
            GdbMiPlannedCommand {
                token: VERSION_TOKEN,
                command: VERSION_COMMAND.to_string(),
                expected_result_class: "done".to_string(),
            },
            GdbMiPlannedCommand {
                token: REMOTE_SELECT_TOKEN,
                command: REMOTE_SELECT_COMMAND_PLACEHOLDER.to_string(),
                expected_result_class: "connected".to_string(),
            },
            GdbMiPlannedCommand {
                token: STACK_LIST_TOKEN,
                command: stack_list_command(maximum_frames),
                expected_result_class: "done".to_string(),
            },
            GdbMiPlannedCommand {
                token: STACK_DETACH_TOKEN,
                command: REMOTE_DETACH_COMMAND.to_string(),
                expected_result_class: "done".to_string(),
            },
            GdbMiPlannedCommand {
                token: STACK_EXIT_TOKEN,
                command: EXIT_COMMAND.to_string(),
                expected_result_class: "exit".to_string(),
            },
        ],
    }
}

fn validate_test_options(options: &GdbMiTestOptions) -> Result<()> {
    validate_version_timeout(options.version_timeout_ms)?;
    validate_timeout(
        options.startup_timeout_ms,
        "startup",
        MIN_GDB_MI_STARTUP_TIMEOUT_MS,
        MAX_GDB_MI_STARTUP_TIMEOUT_MS,
    )?;
    validate_timeout(
        options.shutdown_timeout_ms,
        "shutdown",
        MIN_GDB_MI_SHUTDOWN_TIMEOUT_MS,
        MAX_GDB_MI_SHUTDOWN_TIMEOUT_MS,
    )?;
    validate_executable_request(&options.executable)
}

fn validate_version_timeout(timeout_ms: u64) -> Result<()> {
    validate_timeout(
        timeout_ms,
        "version",
        MIN_GDB_VERSION_TIMEOUT_MS,
        MAX_GDB_VERSION_TIMEOUT_MS,
    )
}

fn validate_timeout(timeout_ms: u64, kind: &str, minimum: u64, maximum: u64) -> Result<()> {
    if !(minimum..=maximum).contains(&timeout_ms) {
        return Err(DebugError::config(
            "GDB timeout is outside the supported range",
            json!({
                "timeout_kind": kind,
                "timeout_ms": timeout_ms,
                "minimum": minimum,
                "maximum": maximum,
            }),
        ));
    }
    Ok(())
}

fn inspect_gdb_executable(requested: &Path, timeout_ms: u64) -> Result<GdbExecutableInspection> {
    let requested_display = stable_path(requested, "executable")?;
    let resolved = resolve_executable(requested)?;
    let resolved_display = stable_path(&resolved, "resolved executable")?;
    let mut command = Command::new(&resolved);
    command
        .arg("--version")
        .env_remove(XTENSA_GNU_CONFIG_ENV)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = super::run_bounded_command(
        command,
        &resolved_display,
        Duration::from_millis(timeout_ms),
        "GDB",
        "openocd",
        "gdb_version_probe",
    )?;
    executable_inspection_from_output(requested_display, resolved_display, timeout_ms, output)
}

fn executable_inspection_from_output(
    requested: String,
    resolved: String,
    timeout_ms: u64,
    output: super::BoundedProcessOutput,
) -> Result<GdbExecutableInspection> {
    for (stream_name, stream) in [("stdout", &output.stdout), ("stderr", &output.stderr)] {
        if let Some(read_error) = &stream.read_error {
            return Err(DebugError::new(
                ErrorCode::ProtocolError,
                "GDB version output could not be drained completely",
                6,
                json!({
                    "executable": resolved,
                    "stream": stream_name,
                    "cause": read_error,
                    "drain_complete": stream.drain_complete,
                }),
            ));
        }
        if stream.truncated {
            return Err(DebugError::new(
                ErrorCode::ProtocolError,
                "GDB version output exceeded the bounded capture limit",
                6,
                json!({
                    "executable": resolved,
                    "stream": stream_name,
                    "bytes": stream.total_bytes,
                    "maximum": super::MAX_CAPTURED_VERSION_OUTPUT_BYTES,
                }),
            ));
        }
    }
    if !output.success {
        return Err(DebugError::unavailable(
            ErrorCode::CapabilityUnavailable,
            "GDB version probe exited unsuccessfully",
            json!({
                "backend": "openocd",
                "capability": "gdb_version_probe",
                "executable": resolved,
                "exit_code": output.exit_code,
                "stdout": super::output_snippet(&output.stdout),
                "stderr": super::output_snippet(&output.stderr),
            }),
        ));
    }

    let (version_source, version_line) = find_gdb_version_line(&output.stdout, &output.stderr)
        .ok_or_else(|| {
            DebugError::config(
                "selected executable did not identify itself as GNU GDB",
                json!({
                    "requested_executable": requested,
                    "resolved_executable": resolved,
                    "stdout": super::output_snippet(&output.stdout),
                    "stderr": super::output_snippet(&output.stderr),
                }),
            )
        })?;
    let vendor = if version_line.contains("(esp-gdb)") {
        "espressif"
    } else {
        "gnu_or_other"
    };

    Ok(GdbExecutableInspection {
        requested,
        resolved,
        version_line,
        version_source,
        vendor: vendor.to_string(),
        timeout_ms,
        elapsed_ms: duration_ms(output.elapsed),
        exit_code: output.exit_code.unwrap_or(0),
        stdout_bytes: output.stdout.total_bytes,
        stderr_bytes: output.stderr.total_bytes,
        output_limit_bytes_per_stream: super::MAX_CAPTURED_VERSION_OUTPUT_BYTES as u64,
        stdout_truncated: output.stdout.truncated,
        stderr_truncated: output.stderr.truncated,
    })
}

fn find_gdb_version_line(
    stdout: &super::CapturedStream,
    stderr: &super::CapturedStream,
) -> Option<(GdbVersionSource, String)> {
    [
        (GdbVersionSource::Stdout, &stdout.retained),
        (GdbVersionSource::Stderr, &stderr.retained),
    ]
    .into_iter()
    .find_map(|(source, bytes)| {
        String::from_utf8_lossy(bytes)
            .lines()
            .map(str::trim)
            .find(|line| line.starts_with("GNU gdb"))
            .map(|line| (source, line.to_string()))
    })
}

fn inspect_executable_file(path: &Path) -> Result<GdbExecutableFileIdentity> {
    let display = stable_path(path, "resolved executable")?;
    let metadata = fs::metadata(path).map_err(|source| {
        DebugError::config(
            "read GDB executable metadata failed",
            json!({"path": display, "cause": source.to_string()}),
        )
    })?;
    if !metadata.is_file() {
        return Err(DebugError::config(
            "resolved GDB executable is not a regular file",
            json!({"path": display}),
        ));
    }
    if metadata.len() > MAX_GDB_EXECUTABLE_BYTES {
        return Err(DebugError::config(
            "GDB executable exceeds the hashing size limit",
            json!({
                "path": display,
                "bytes": metadata.len(),
                "maximum": MAX_GDB_EXECUTABLE_BYTES,
            }),
        ));
    }

    let mut file = File::open(path).map_err(|source| {
        DebugError::config(
            "open GDB executable for hashing failed",
            json!({"path": display, "cause": source.to_string()}),
        )
    })?;
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|source| {
            DebugError::config(
                "read GDB executable for hashing failed",
                json!({"path": display, "cause": source.to_string()}),
            )
        })?;
        if count == 0 {
            break;
        }
        total = total.saturating_add(count as u64);
        if total > MAX_GDB_EXECUTABLE_BYTES {
            return Err(DebugError::config(
                "GDB executable grew beyond the hashing size limit",
                json!({"path": display, "maximum": MAX_GDB_EXECUTABLE_BYTES}),
            ));
        }
        hasher.update(&buffer[..count]);
    }

    Ok(GdbExecutableFileIdentity {
        bytes: total,
        sha256: hex::encode(hasher.finalize()),
        maximum_bytes: MAX_GDB_EXECUTABLE_BYTES,
    })
}

fn validate_executable_request(requested: &Path) -> Result<()> {
    if requested.as_os_str().is_empty() {
        return Err(DebugError::config(
            "GDB executable name must not be empty",
            json!({"requested_executable": ""}),
        ));
    }
    stable_path(requested, "executable")?;
    Ok(())
}

fn resolve_executable(requested: &Path) -> Result<PathBuf> {
    if is_explicit_path(requested) {
        return canonicalize_executable(requested);
    }

    let path_value = env::var_os("PATH").unwrap_or_default();
    let extensions = executable_extensions(requested);
    for directory in env::split_paths(&path_value) {
        if let Some(found) = executable_candidate(&directory.join(requested)) {
            return Ok(found);
        }
        for extension in &extensions {
            let mut file_name = requested.as_os_str().to_os_string();
            file_name.push(extension);
            if let Some(found) = executable_candidate(&directory.join(file_name)) {
                return Ok(found);
            }
        }
    }

    let requested_display = stable_path(requested, "executable")?;
    let mut error = DebugError::unavailable(
        ErrorCode::CapabilityUnavailable,
        "GDB executable was not found on PATH",
        json!({
            "backend": "openocd",
            "capability": "gdb_host_tool_discovery",
            "requested_executable": requested_display,
        }),
    );
    error.suggested_actions.push(SuggestedAction::new(
        "install_or_select_gdb",
        json!({"argument": "--executable <PATH>"}),
    ));
    Err(error)
}

fn canonicalize_executable(path: &Path) -> Result<PathBuf> {
    let canonical = fs::canonicalize(path).map_err(|source| {
        DebugError::config(
            "resolve GDB executable failed",
            json!({"path": path.to_string_lossy(), "cause": source.to_string()}),
        )
    })?;
    if !canonical.is_file() {
        return Err(DebugError::config(
            "GDB executable has the wrong filesystem type",
            json!({"path": path.to_string_lossy(), "expected": "regular_file"}),
        ));
    }
    Ok(canonical)
}

fn executable_candidate(path: &Path) -> Option<PathBuf> {
    path.is_file()
        .then(|| fs::canonicalize(path).ok())
        .flatten()
}

fn executable_extensions(requested: &Path) -> Vec<OsString> {
    if !cfg!(windows) || requested.extension().is_some() {
        return Vec::new();
    }
    env::var_os("PATHEXT")
        .map(|value| {
            value
                .to_string_lossy()
                .split(';')
                .filter(|extension| !extension.is_empty())
                .map(OsString::from)
                .collect()
        })
        .unwrap_or_else(|| {
            [".COM", ".EXE", ".BAT", ".CMD"]
                .into_iter()
                .map(OsString::from)
                .collect()
        })
}

fn is_explicit_path(path: &Path) -> bool {
    path.is_absolute()
        || path.components().count() > 1
        || path.to_string_lossy().contains(['/', '\\'])
}

fn stable_path(path: &Path, label: &str) -> Result<String> {
    let path = path.to_str().ok_or_else(|| {
        DebugError::config(
            format!("GDB {label} is not valid Unicode"),
            json!({"path_kind": label}),
        )
    })?;
    #[cfg(windows)]
    {
        if let Some(path) = path.strip_prefix(r"\\?\UNC\") {
            return Ok(format!(r"\\{path}"));
        }
        if let Some(path) = path.strip_prefix(r"\\?\") {
            return Ok(path.to_string());
        }
    }
    Ok(path.to_string())
}

fn process_isolation() -> &'static str {
    if cfg!(windows) {
        "windows_job_object"
    } else {
        "unix_process_group"
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputStream {
    Stdout,
    Stderr,
}

impl OutputStream {
    fn name(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}

#[derive(Debug)]
struct OutputEvent {
    stream: OutputStream,
    line: String,
}

#[derive(Debug)]
struct StreamCapture {
    retained: Vec<u8>,
    total_bytes: u64,
    sha256: String,
    truncated: bool,
    line_limit_exceeded: bool,
    events_dropped: u64,
    drain_complete: bool,
    read_error: Option<String>,
}

impl StreamCapture {
    fn incomplete(message: &str) -> Self {
        Self {
            retained: Vec::new(),
            total_bytes: 0,
            sha256: hex::encode(Sha256::digest([])),
            truncated: true,
            line_limit_exceeded: false,
            events_dropped: 0,
            drain_complete: false,
            read_error: Some(message.to_string()),
        }
    }

    fn summary(self) -> GdbMiOutputSummary {
        GdbMiOutputSummary {
            total_bytes: self.total_bytes,
            retained_bytes: self.retained.len() as u64,
            sha256: self.sha256,
            truncated: self.truncated,
            line_limit_exceeded: self.line_limit_exceeded,
            events_dropped: self.events_dropped,
            drain_complete: self.drain_complete,
            read_error: self.read_error,
            snippet: String::from_utf8_lossy(&self.retained)
                .chars()
                .take(MI_OUTPUT_SNIPPET_CHARS)
                .collect(),
        }
    }
}

struct ManagedGdb {
    child: Option<Box<dyn ChildWrapper>>,
    stdin: Option<ChildStdin>,
    events: Receiver<OutputEvent>,
    stdout_reader: Option<JoinHandle<StreamCapture>>,
    stderr_reader: Option<JoinHandle<StreamCapture>>,
    started: Instant,
    observed_status: Option<ExitStatus>,
    record_counts: GdbMiRecordCounts,
    exit_token: u64,
    exit_command_sent: bool,
    exit_command_started: Option<Instant>,
    exit_result_class: Option<String>,
}

impl ManagedGdb {
    fn spawn(mut command: Command, executable: &str, exit_token: u64) -> Result<Self> {
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut wrapped = CommandWrap::from(command);
        #[cfg(windows)]
        wrapped.wrap(JobObject);
        #[cfg(unix)]
        wrapped.wrap(ProcessGroup::leader());

        let mut child = wrapped.spawn().map_err(|source| {
            DebugError::unavailable(
                ErrorCode::CapabilityUnavailable,
                "managed GDB/MI process could not be started",
                json!({
                    "backend": "openocd",
                    "capability": "gdb_mi_host_process",
                    "executable": executable,
                    "cause": source.to_string(),
                    "process_isolation": process_isolation(),
                }),
            )
        })?;
        let stdin = child.stdin().take();
        let stdout = child.stdout().take();
        let stderr = child.stderr().take();
        let (Some(stdin), Some(stdout), Some(stderr)) = (stdin, stdout, stderr) else {
            let _ = child.start_kill();
            let _ = child.wait();
            return Err(DebugError::new(
                ErrorCode::Internal,
                "managed GDB/MI process did not provide its requested pipes",
                10,
                json!({"executable": executable}),
            ));
        };

        let (sender, events) = mpsc::sync_channel(MI_OUTPUT_EVENT_QUEUE_CAPACITY);
        let stdout_reader = capture_stream(stdout, OutputStream::Stdout, sender.clone());
        let stderr_reader = capture_stream(stderr, OutputStream::Stderr, sender);

        Ok(Self {
            child: Some(child),
            stdin: Some(stdin),
            events,
            stdout_reader: Some(stdout_reader),
            stderr_reader: Some(stderr_reader),
            started: Instant::now(),
            observed_status: None,
            record_counts: GdbMiRecordCounts::default(),
            exit_token,
            exit_command_sent: false,
            exit_command_started: None,
            exit_result_class: None,
        })
    }

    fn run_lifecycle(
        &mut self,
        startup_timeout: Duration,
        shutdown_timeout: Duration,
    ) -> std::result::Result<LifecycleSuccess, LifecycleFailure> {
        let startup_deadline = self.started + startup_timeout;
        self.wait_for_prompt(startup_deadline)?;
        let startup_elapsed = self.started.elapsed();
        let streams_before_version = stream_record_count(&self.record_counts);
        let version_started = Instant::now();
        self.send_command(VERSION_TOKEN, VERSION_COMMAND)?;
        let version_result_class = self.wait_for_result(VERSION_TOKEN, "done", startup_deadline)?;
        let version_elapsed = version_started.elapsed();
        let version_stream_records =
            stream_record_count(&self.record_counts).saturating_sub(streams_before_version);

        self.send_command(EXIT_TOKEN, EXIT_COMMAND)?;
        let shutdown_deadline = Instant::now() + shutdown_timeout;
        self.wait_for_result(EXIT_TOKEN, "exit", shutdown_deadline)?;
        self.wait_for_exit(shutdown_deadline)?;

        Ok(LifecycleSuccess {
            startup_elapsed,
            version_elapsed,
            version_result_class,
            version_stream_records,
        })
    }

    fn run_remote_lifecycle(
        &mut self,
        endpoint: &str,
        startup_timeout: Duration,
        command_timeout: Duration,
        shutdown_timeout: Duration,
    ) -> std::result::Result<RemoteLifecycleSuccess, LifecycleFailure> {
        let startup_deadline = self.started + startup_timeout;
        self.wait_for_prompt(startup_deadline)?;
        let startup_elapsed = self.started.elapsed();

        let streams_before_version = stream_record_count(&self.record_counts);
        let version_started = Instant::now();
        self.send_command(VERSION_TOKEN, VERSION_COMMAND)?;
        let version_result_class = self.wait_for_result(VERSION_TOKEN, "done", startup_deadline)?;
        let version_elapsed = version_started.elapsed();
        let version_stream_records =
            stream_record_count(&self.record_counts).saturating_sub(streams_before_version);

        let connect_command = format!("-target-select remote {endpoint}");
        let connect_started = Instant::now();
        self.send_command(REMOTE_SELECT_TOKEN, &connect_command)?;
        let connect_result_class = self.wait_for_result(
            REMOTE_SELECT_TOKEN,
            "connected",
            connect_started + command_timeout,
        )?;
        let connect_elapsed = connect_started.elapsed();

        let detach_started = Instant::now();
        self.send_command(REMOTE_DETACH_TOKEN, REMOTE_DETACH_COMMAND)?;
        let detach_result_class = self.wait_for_result(
            REMOTE_DETACH_TOKEN,
            "done",
            detach_started + command_timeout,
        )?;
        let detach_elapsed = detach_started.elapsed();

        self.send_command(REMOTE_EXIT_TOKEN, EXIT_COMMAND)?;
        let shutdown_deadline = Instant::now() + shutdown_timeout;
        self.wait_for_result(REMOTE_EXIT_TOKEN, "exit", shutdown_deadline)?;
        self.wait_for_exit(shutdown_deadline)?;

        Ok(RemoteLifecycleSuccess {
            startup_elapsed,
            version_elapsed,
            version_result_class,
            version_stream_records,
            connect_elapsed,
            connect_result_class,
            detach_elapsed,
            detach_result_class,
        })
    }

    fn run_register_lifecycle(
        &mut self,
        endpoint: &str,
        requested_names: &[String],
        startup_timeout: Duration,
        command_timeout: Duration,
        shutdown_timeout: Duration,
    ) -> std::result::Result<RegisterLifecycleSuccess, LifecycleFailure> {
        let startup_deadline = self.started + startup_timeout;
        self.wait_for_prompt(startup_deadline)?;
        let startup_elapsed = self.started.elapsed();

        let streams_before_version = stream_record_count(&self.record_counts);
        let version_started = Instant::now();
        self.send_command(VERSION_TOKEN, VERSION_COMMAND)?;
        let version_result_class = self.wait_for_result(VERSION_TOKEN, "done", startup_deadline)?;
        let version_elapsed = version_started.elapsed();
        let version_stream_records =
            stream_record_count(&self.record_counts).saturating_sub(streams_before_version);

        let connect_command = format!("-target-select remote {endpoint}");
        let connect_started = Instant::now();
        self.send_command(REMOTE_SELECT_TOKEN, &connect_command)?;
        let connect_result_class = self.wait_for_result(
            REMOTE_SELECT_TOKEN,
            "connected",
            connect_started + command_timeout,
        )?;
        let connect_elapsed = connect_started.elapsed();

        let snapshot = match self.run_register_snapshot(requested_names, command_timeout) {
            Ok(snapshot) => snapshot,
            Err(failure) => return Err(self.with_register_detach_attempt(failure, command_timeout)),
        };

        let detach_started = Instant::now();
        self.send_command(REGISTER_DETACH_TOKEN, REMOTE_DETACH_COMMAND)?;
        let detach_result_class = self.wait_for_result(
            REGISTER_DETACH_TOKEN,
            "done",
            detach_started + command_timeout,
        )?;
        let detach_elapsed = detach_started.elapsed();

        self.send_command(REGISTER_EXIT_TOKEN, EXIT_COMMAND)?;
        let shutdown_deadline = Instant::now() + shutdown_timeout;
        self.wait_for_result(REGISTER_EXIT_TOKEN, "exit", shutdown_deadline)?;
        self.wait_for_exit(shutdown_deadline)?;

        Ok(RegisterLifecycleSuccess {
            startup_elapsed,
            version_elapsed,
            version_result_class,
            version_stream_records,
            connect_elapsed,
            connect_result_class,
            names_elapsed: snapshot.names_elapsed,
            names_result_class: snapshot.names_result_class,
            values_elapsed: snapshot.values_elapsed,
            values_result_class: snapshot.values_result_class,
            values_command: snapshot.values_command,
            inventory: snapshot.inventory,
            values: snapshot.values,
            detach_elapsed,
            detach_result_class,
        })
    }

    fn run_register_snapshot(
        &mut self,
        requested_names: &[String],
        command_timeout: Duration,
    ) -> std::result::Result<RegisterSnapshotSuccess, LifecycleFailure> {
        let names_started = Instant::now();
        self.send_command(REGISTER_NAMES_TOKEN, REGISTER_NAMES_COMMAND)?;
        let names_result = self.wait_for_result_record(
            REGISTER_NAMES_TOKEN,
            "done",
            names_started + command_timeout,
        )?;
        let names_elapsed = names_started.elapsed();
        let selection = resolve_register_selection(&names_result.variables, requested_names)?;

        let values_command = register_values_command(&selection.registers);
        let values_started = Instant::now();
        self.send_command(REGISTER_VALUES_TOKEN, &values_command)?;
        let values_result = self.wait_for_result_record(
            REGISTER_VALUES_TOKEN,
            "done",
            values_started + command_timeout,
        )?;
        let values_elapsed = values_started.elapsed();
        let values = parse_register_values(&values_result.variables, &selection.registers)?;

        Ok(RegisterSnapshotSuccess {
            names_elapsed,
            names_result_class: names_result.class,
            values_elapsed,
            values_result_class: values_result.class,
            values_command,
            inventory: selection.inventory,
            values,
        })
    }

    fn with_register_detach_attempt(
        &mut self,
        mut failure: LifecycleFailure,
        command_timeout: Duration,
    ) -> LifecycleFailure {
        let started = Instant::now();
        let attempt = self
            .send_command(REGISTER_DETACH_TOKEN, REMOTE_DETACH_COMMAND)
            .and_then(|()| {
                self.wait_for_result(REGISTER_DETACH_TOKEN, "done", started + command_timeout)
            });
        let evidence = match attempt {
            Ok(result_class) => json!({
                "attempted": true,
                "complete": true,
                "token": REGISTER_DETACH_TOKEN,
                "command": REMOTE_DETACH_COMMAND,
                "result_class": result_class,
                "elapsed_ms": duration_ms(started.elapsed()),
            }),
            Err(detach_failure) => json!({
                "attempted": true,
                "complete": false,
                "token": REGISTER_DETACH_TOKEN,
                "command": REMOTE_DETACH_COMMAND,
                "elapsed_ms": duration_ms(started.elapsed()),
                "failure": lifecycle_failure_value(&detach_failure),
            }),
        };
        let mut details = failure.details.as_object().cloned().unwrap_or_default();
        details.insert("cleanup_detach".to_string(), evidence);
        failure.details = Value::Object(details);
        failure
    }

    fn run_memory_lifecycle(
        &mut self,
        endpoint: &str,
        address: Address,
        length_bytes: u64,
        startup_timeout: Duration,
        command_timeout: Duration,
        shutdown_timeout: Duration,
    ) -> std::result::Result<MemoryLifecycleSuccess, LifecycleFailure> {
        let startup_deadline = self.started + startup_timeout;
        self.wait_for_prompt(startup_deadline)?;
        let startup_elapsed = self.started.elapsed();

        let streams_before_version = stream_record_count(&self.record_counts);
        let version_started = Instant::now();
        self.send_command(VERSION_TOKEN, VERSION_COMMAND)?;
        let version_result_class = self.wait_for_result(VERSION_TOKEN, "done", startup_deadline)?;
        let version_elapsed = version_started.elapsed();
        let version_stream_records =
            stream_record_count(&self.record_counts).saturating_sub(streams_before_version);

        let connect_command = format!("-target-select remote {endpoint}");
        let connect_started = Instant::now();
        self.send_command(REMOTE_SELECT_TOKEN, &connect_command)?;
        let connect_result_class = self.wait_for_result(
            REMOTE_SELECT_TOKEN,
            "connected",
            connect_started + command_timeout,
        )?;
        let connect_elapsed = connect_started.elapsed();

        let snapshot = match self.run_memory_snapshot(address, length_bytes, command_timeout) {
            Ok(snapshot) => snapshot,
            Err(failure) => return Err(self.with_memory_detach_attempt(failure, command_timeout)),
        };

        let detach_started = Instant::now();
        self.send_command(MEMORY_DETACH_TOKEN, REMOTE_DETACH_COMMAND)?;
        let detach_result_class = self.wait_for_result(
            MEMORY_DETACH_TOKEN,
            "done",
            detach_started + command_timeout,
        )?;
        let detach_elapsed = detach_started.elapsed();

        self.send_command(MEMORY_EXIT_TOKEN, EXIT_COMMAND)?;
        let shutdown_deadline = Instant::now() + shutdown_timeout;
        self.wait_for_result(MEMORY_EXIT_TOKEN, "exit", shutdown_deadline)?;
        self.wait_for_exit(shutdown_deadline)?;

        Ok(MemoryLifecycleSuccess {
            startup_elapsed,
            version_elapsed,
            version_result_class,
            version_stream_records,
            connect_elapsed,
            connect_result_class,
            read_elapsed: snapshot.read_elapsed,
            read_result_class: snapshot.read_result_class,
            read_command: snapshot.read_command,
            snapshot: snapshot.snapshot,
            detach_elapsed,
            detach_result_class,
        })
    }

    fn run_memory_snapshot(
        &mut self,
        address: Address,
        length_bytes: u64,
        command_timeout: Duration,
    ) -> std::result::Result<MemorySnapshotSuccess, LifecycleFailure> {
        let read_command = memory_read_command(address, length_bytes);
        let read_started = Instant::now();
        self.send_command(MEMORY_READ_TOKEN, &read_command)?;
        let read_result =
            self.wait_for_result_record(MEMORY_READ_TOKEN, "done", read_started + command_timeout)?;
        let read_elapsed = read_started.elapsed();
        let snapshot = parse_memory_snapshot(&read_result.variables, address, length_bytes)?;

        Ok(MemorySnapshotSuccess {
            read_elapsed,
            read_result_class: read_result.class,
            read_command,
            snapshot,
        })
    }

    fn with_memory_detach_attempt(
        &mut self,
        mut failure: LifecycleFailure,
        command_timeout: Duration,
    ) -> LifecycleFailure {
        let started = Instant::now();
        let attempt = self
            .send_command(MEMORY_DETACH_TOKEN, REMOTE_DETACH_COMMAND)
            .and_then(|()| {
                self.wait_for_result(MEMORY_DETACH_TOKEN, "done", started + command_timeout)
            });
        let evidence = match attempt {
            Ok(result_class) => json!({
                "attempted": true,
                "complete": true,
                "token": MEMORY_DETACH_TOKEN,
                "command": REMOTE_DETACH_COMMAND,
                "result_class": result_class,
                "elapsed_ms": duration_ms(started.elapsed()),
            }),
            Err(detach_failure) => json!({
                "attempted": true,
                "complete": false,
                "token": MEMORY_DETACH_TOKEN,
                "command": REMOTE_DETACH_COMMAND,
                "elapsed_ms": duration_ms(started.elapsed()),
                "failure": lifecycle_failure_value(&detach_failure),
            }),
        };
        let mut details = failure.details.as_object().cloned().unwrap_or_default();
        details.insert("cleanup_detach".to_string(), evidence);
        failure.details = Value::Object(details);
        failure
    }

    fn run_stack_lifecycle(
        &mut self,
        endpoint: &str,
        maximum_frames: u64,
        startup_timeout: Duration,
        command_timeout: Duration,
        shutdown_timeout: Duration,
    ) -> std::result::Result<StackLifecycleSuccess, LifecycleFailure> {
        let startup_deadline = self.started + startup_timeout;
        self.wait_for_prompt(startup_deadline)?;
        let startup_elapsed = self.started.elapsed();

        let streams_before_version = stream_record_count(&self.record_counts);
        let version_started = Instant::now();
        self.send_command(VERSION_TOKEN, VERSION_COMMAND)?;
        let version_result_class = self.wait_for_result(VERSION_TOKEN, "done", startup_deadline)?;
        let version_elapsed = version_started.elapsed();
        let version_stream_records =
            stream_record_count(&self.record_counts).saturating_sub(streams_before_version);

        let connect_command = format!("-target-select remote {endpoint}");
        let connect_started = Instant::now();
        self.send_command(REMOTE_SELECT_TOKEN, &connect_command)?;
        let connect_result_class = self.wait_for_result(
            REMOTE_SELECT_TOKEN,
            "connected",
            connect_started + command_timeout,
        )?;
        let connect_elapsed = connect_started.elapsed();

        let snapshot = match self.run_stack_snapshot(maximum_frames, command_timeout) {
            Ok(snapshot) => snapshot,
            Err(failure) => return Err(self.with_stack_detach_attempt(failure, command_timeout)),
        };

        let detach_started = Instant::now();
        self.send_command(STACK_DETACH_TOKEN, REMOTE_DETACH_COMMAND)?;
        let detach_result_class =
            self.wait_for_result(STACK_DETACH_TOKEN, "done", detach_started + command_timeout)?;
        let detach_elapsed = detach_started.elapsed();

        self.send_command(STACK_EXIT_TOKEN, EXIT_COMMAND)?;
        let shutdown_deadline = Instant::now() + shutdown_timeout;
        self.wait_for_result(STACK_EXIT_TOKEN, "exit", shutdown_deadline)?;
        self.wait_for_exit(shutdown_deadline)?;

        Ok(StackLifecycleSuccess {
            startup_elapsed,
            version_elapsed,
            version_result_class,
            version_stream_records,
            connect_elapsed,
            connect_result_class,
            list_elapsed: snapshot.list_elapsed,
            list_result_class: snapshot.list_result_class,
            list_command: snapshot.list_command,
            snapshot: snapshot.snapshot,
            detach_elapsed,
            detach_result_class,
        })
    }

    fn run_stack_snapshot(
        &mut self,
        maximum_frames: u64,
        command_timeout: Duration,
    ) -> std::result::Result<StackSnapshotSuccess, LifecycleFailure> {
        let list_command = stack_list_command(maximum_frames);
        let list_started = Instant::now();
        self.send_command(STACK_LIST_TOKEN, &list_command)?;
        let list_result =
            self.wait_for_result_record(STACK_LIST_TOKEN, "done", list_started + command_timeout)?;
        let list_elapsed = list_started.elapsed();
        let snapshot = parse_stack_snapshot(&list_result.variables, maximum_frames)?;

        Ok(StackSnapshotSuccess {
            list_elapsed,
            list_result_class: list_result.class,
            list_command,
            snapshot,
        })
    }

    fn with_stack_detach_attempt(
        &mut self,
        mut failure: LifecycleFailure,
        command_timeout: Duration,
    ) -> LifecycleFailure {
        let started = Instant::now();
        let attempt = self
            .send_command(STACK_DETACH_TOKEN, REMOTE_DETACH_COMMAND)
            .and_then(|()| {
                self.wait_for_result(STACK_DETACH_TOKEN, "done", started + command_timeout)
            });
        let evidence = match attempt {
            Ok(result_class) => json!({
                "attempted": true,
                "complete": true,
                "token": STACK_DETACH_TOKEN,
                "command": REMOTE_DETACH_COMMAND,
                "result_class": result_class,
                "elapsed_ms": duration_ms(started.elapsed()),
            }),
            Err(detach_failure) => json!({
                "attempted": true,
                "complete": false,
                "token": STACK_DETACH_TOKEN,
                "command": REMOTE_DETACH_COMMAND,
                "elapsed_ms": duration_ms(started.elapsed()),
                "failure": lifecycle_failure_value(&detach_failure),
            }),
        };
        let mut details = failure.details.as_object().cloned().unwrap_or_default();
        details.insert("cleanup_detach".to_string(), evidence);
        failure.details = Value::Object(details);
        failure
    }

    fn wait_for_prompt(&mut self, deadline: Instant) -> std::result::Result<(), LifecycleFailure> {
        loop {
            match self.next_record(deadline, "startup prompt")? {
                ParsedRecord::Prompt => return Ok(()),
                ParsedRecord::Result { token, class, .. } => {
                    return Err(protocol_failure(
                        "GDB/MI emitted a result before its startup prompt",
                        json!({"token": token, "result_class": class}),
                    ));
                }
                _ => {}
            }
        }
    }

    fn wait_for_result(
        &mut self,
        expected_token: u64,
        expected_class: &str,
        deadline: Instant,
    ) -> std::result::Result<String, LifecycleFailure> {
        self.wait_for_result_record(expected_token, expected_class, deadline)
            .map(|result| result.class)
    }

    fn wait_for_result_record(
        &mut self,
        expected_token: u64,
        expected_class: &str,
        deadline: Instant,
    ) -> std::result::Result<MiResultRecord, LifecycleFailure> {
        loop {
            if let ParsedRecord::Result {
                token,
                class,
                variables,
            } = self.next_record(deadline, "result")?
            {
                if token != Some(expected_token) {
                    return Err(protocol_failure(
                        "GDB/MI result token did not match the outstanding command",
                        json!({
                            "expected_token": expected_token,
                            "observed_token": token,
                            "observed_result_class": class,
                        }),
                    ));
                }
                if class != expected_class {
                    return Err(protocol_failure(
                        "GDB/MI command returned an unexpected result class",
                        json!({
                            "token": expected_token,
                            "expected_result_class": expected_class,
                            "observed_result_class": class,
                        }),
                    ));
                }
                return Ok(MiResultRecord { class, variables });
            }
        }
    }

    fn next_record(
        &mut self,
        deadline: Instant,
        phase: &str,
    ) -> std::result::Result<ParsedRecord, LifecycleFailure> {
        loop {
            match self.events.try_recv() {
                Ok(event) => {
                    if let Some(record) = self.observe_event(event)? {
                        return Ok(record);
                    }
                    continue;
                }
                Err(TryRecvError::Disconnected) => {
                    return Err(self.output_closed_failure(phase));
                }
                Err(TryRecvError::Empty) => {}
            }

            self.poll_status().map_err(|source| LifecycleFailure {
                code: ErrorCode::Internal,
                message: "poll managed GDB/MI process failed".to_string(),
                exit_code: 10,
                retryable: false,
                details: json!({"phase": phase, "cause": source.to_string()}),
            })?;
            if Instant::now() >= deadline {
                return Err(LifecycleFailure {
                    code: ErrorCode::Timeout,
                    message: format!("managed GDB/MI {phase} exceeded its deadline"),
                    exit_code: 5,
                    retryable: true,
                    details: json!({
                        "phase": phase,
                        "elapsed_ms": duration_ms(self.started.elapsed()),
                    }),
                });
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            match self.events.recv_timeout(MI_POLL_INTERVAL.min(remaining)) {
                Ok(event) => {
                    if let Some(record) = self.observe_event(event)? {
                        return Ok(record);
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(self.output_closed_failure(phase));
                }
            }
        }
    }

    fn output_closed_failure(&self, phase: &str) -> LifecycleFailure {
        LifecycleFailure {
            code: ErrorCode::CapabilityUnavailable,
            message: "managed GDB/MI process exited before the protocol exchange completed"
                .to_string(),
            exit_code: 4,
            retryable: false,
            details: json!({
                "phase": phase,
                "exit_code": self.observed_status.and_then(|status| status.code()),
            }),
        }
    }

    fn observe_event(
        &mut self,
        event: OutputEvent,
    ) -> std::result::Result<Option<ParsedRecord>, LifecycleFailure> {
        eprintln!("[gdb:{}] {}", event.stream.name(), event.line);
        if event.stream == OutputStream::Stderr {
            return Ok(None);
        }
        let record = parse_record(&event.line).map_err(|cause| {
            protocol_failure(
                "GDB/MI stdout contained an invalid record",
                json!({"cause": cause, "line": bounded_line(&event.line)}),
            )
        })?;
        self.record_counts.observe(&record);
        if let ParsedRecord::Result { token, class, .. } = &record
            && *token == Some(self.exit_token)
        {
            self.exit_result_class = Some(class.clone());
        }
        Ok(Some(record))
    }

    fn send_command(
        &mut self,
        token: u64,
        command: &str,
    ) -> std::result::Result<(), LifecycleFailure> {
        let Some(stdin) = self.stdin.as_mut() else {
            return Err(protocol_failure(
                "managed GDB/MI stdin was unavailable",
                json!({"token": token, "command": command}),
            ));
        };
        let request = format!("{token}{command}\n");
        stdin
            .write_all(request.as_bytes())
            .and_then(|()| stdin.flush())
            .map_err(|source| {
                protocol_failure(
                    "write GDB/MI command failed",
                    json!({
                        "token": token,
                        "command": command,
                        "cause": source.to_string(),
                    }),
                )
            })?;
        if token == self.exit_token && command == EXIT_COMMAND {
            self.exit_command_sent = true;
            self.exit_command_started = Some(Instant::now());
        }
        Ok(())
    }

    fn wait_for_exit(
        &mut self,
        deadline: Instant,
    ) -> std::result::Result<ExitStatus, LifecycleFailure> {
        loop {
            self.drain_events()?;
            if let Some(status) = self.poll_status().map_err(|source| LifecycleFailure {
                code: ErrorCode::Internal,
                message: "poll managed GDB/MI exit failed".to_string(),
                exit_code: 10,
                retryable: false,
                details: json!({"cause": source.to_string()}),
            })? {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(LifecycleFailure {
                    code: ErrorCode::Timeout,
                    message: "managed GDB/MI process did not exit before its deadline".to_string(),
                    exit_code: 5,
                    retryable: true,
                    details: json!({"phase": "process_exit"}),
                });
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            match self.events.recv_timeout(MI_POLL_INTERVAL.min(remaining)) {
                Ok(event) => {
                    self.observe_event(event)?;
                }
                Err(mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected) => {}
            }
        }
    }

    fn poll_status(&mut self) -> std::io::Result<Option<ExitStatus>> {
        if let Some(status) = self.observed_status {
            return Ok(Some(status));
        }
        let status = self
            .child
            .as_mut()
            .expect("managed GDB child exists until cleanup")
            .try_wait()?;
        if let Some(status) = status {
            self.observed_status = Some(status);
        }
        Ok(status)
    }

    fn drain_events(&mut self) -> std::result::Result<(), LifecycleFailure> {
        loop {
            match self.events.try_recv() {
                Ok(event) => {
                    self.observe_event(event)?;
                }
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => return Ok(()),
            }
        }
    }

    fn cleanup(&mut self, timeout: Duration) -> GdbMiShutdown {
        let cleanup_started = Instant::now();
        let mut command_error = None;
        if !self.exit_command_sent
            && self.observed_status.is_none()
            && let Err(failure) = self.send_command(self.exit_token, EXIT_COMMAND)
        {
            command_error = Some(failure.message);
        }

        let deadline = Instant::now() + timeout;
        while self.observed_status.is_none() && Instant::now() < deadline {
            if let Err(failure) = self.drain_events() {
                command_error.get_or_insert(failure.message);
            }
            match self.poll_status() {
                Ok(Some(_)) => break,
                Ok(None) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    thread::sleep(MI_POLL_INTERVAL.min(remaining));
                }
                Err(source) => {
                    command_error.get_or_insert_with(|| format!("poll GDB exit: {source}"));
                    break;
                }
            }
        }

        let forced_process_tree_kill = self.observed_status.is_none();
        self.stdin.take();
        let mut termination_error = None;
        let mut wait_error = None;
        let mut final_status = self.observed_status;
        if let Some(mut child) = self.child.take() {
            if let Err(source) = child.start_kill()
                && source.kind() != std::io::ErrorKind::NotFound
            {
                termination_error = Some(source.to_string());
            }
            if final_status.is_none() {
                match child.wait() {
                    Ok(status) => final_status = Some(status),
                    Err(source) => wait_error = Some(source.to_string()),
                }
            }
        }
        self.observed_status = final_status;
        if let Err(failure) = self.drain_events() {
            command_error.get_or_insert(failure.message);
        }

        let exit_success = final_status.is_some_and(|status| status.success());
        let result_observed = self.exit_result_class.as_deref() == Some("exit");
        let graceful = self.exit_command_sent
            && result_observed
            && !forced_process_tree_kill
            && exit_success
            && termination_error.is_none()
            && wait_error.is_none();
        let elapsed = self
            .exit_command_started
            .map_or_else(|| cleanup_started.elapsed(), |started| started.elapsed());
        GdbMiShutdown {
            token: self.exit_token,
            command: EXIT_COMMAND.to_string(),
            expected_result_class: "exit".to_string(),
            command_sent: self.exit_command_sent,
            result_observed,
            result_class: self.exit_result_class.clone(),
            graceful,
            exit_code: final_status.and_then(|status| status.code()),
            exit_success,
            elapsed_ms: duration_ms(elapsed),
            timeout_ms: duration_ms(timeout),
            forced_process_tree_kill,
            process_tree_termination_enforced: true,
            process_tree_cleanup_complete: termination_error.is_none() && wait_error.is_none(),
            command_error,
            termination_error,
            wait_error,
        }
    }

    fn finish_output(&mut self) -> GdbMiOutput {
        let deadline = Instant::now() + MI_STREAM_DRAIN_GRACE;
        let stdout = finish_stream(self.stdout_reader.take(), deadline).summary();
        let stderr = finish_stream(self.stderr_reader.take(), deadline).summary();
        GdbMiOutput {
            output_limit_bytes_per_stream: MAX_MI_OUTPUT_BYTES_PER_STREAM as u64,
            line_limit_bytes: MAX_MI_OUTPUT_LINE_BYTES as u64,
            event_queue_capacity: MI_OUTPUT_EVENT_QUEUE_CAPACITY as u64,
            stdout,
            stderr,
        }
    }
}

impl Drop for ManagedGdb {
    fn drop(&mut self) {
        self.stdin.take();
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
            let _ = child.wait();
        }
    }
}

#[derive(Debug)]
struct LifecycleSuccess {
    startup_elapsed: Duration,
    version_elapsed: Duration,
    version_result_class: String,
    version_stream_records: u64,
}

#[derive(Debug)]
struct RemoteLifecycleSuccess {
    startup_elapsed: Duration,
    version_elapsed: Duration,
    version_result_class: String,
    version_stream_records: u64,
    connect_elapsed: Duration,
    connect_result_class: String,
    detach_elapsed: Duration,
    detach_result_class: String,
}

#[derive(Debug)]
struct RegisterLifecycleSuccess {
    startup_elapsed: Duration,
    version_elapsed: Duration,
    version_result_class: String,
    version_stream_records: u64,
    connect_elapsed: Duration,
    connect_result_class: String,
    names_elapsed: Duration,
    names_result_class: String,
    values_elapsed: Duration,
    values_result_class: String,
    values_command: String,
    inventory: GdbMiRegisterInventory,
    values: Vec<GdbMiRegisterValue>,
    detach_elapsed: Duration,
    detach_result_class: String,
}

#[derive(Debug)]
struct RegisterSnapshotSuccess {
    names_elapsed: Duration,
    names_result_class: String,
    values_elapsed: Duration,
    values_result_class: String,
    values_command: String,
    inventory: GdbMiRegisterInventory,
    values: Vec<GdbMiRegisterValue>,
}

#[derive(Debug)]
struct MemoryLifecycleSuccess {
    startup_elapsed: Duration,
    version_elapsed: Duration,
    version_result_class: String,
    version_stream_records: u64,
    connect_elapsed: Duration,
    connect_result_class: String,
    read_elapsed: Duration,
    read_result_class: String,
    read_command: String,
    snapshot: GdbMiMemorySnapshot,
    detach_elapsed: Duration,
    detach_result_class: String,
}

#[derive(Debug)]
struct MemorySnapshotSuccess {
    read_elapsed: Duration,
    read_result_class: String,
    read_command: String,
    snapshot: GdbMiMemorySnapshot,
}

#[derive(Debug)]
struct StackLifecycleSuccess {
    startup_elapsed: Duration,
    version_elapsed: Duration,
    version_result_class: String,
    version_stream_records: u64,
    connect_elapsed: Duration,
    connect_result_class: String,
    list_elapsed: Duration,
    list_result_class: String,
    list_command: String,
    snapshot: GdbMiStackSnapshot,
    detach_elapsed: Duration,
    detach_result_class: String,
}

#[derive(Debug)]
struct StackSnapshotSuccess {
    list_elapsed: Duration,
    list_result_class: String,
    list_command: String,
    snapshot: GdbMiStackSnapshot,
}

#[derive(Debug)]
struct MiResultRecord {
    class: String,
    variables: HashMap<String, MiValue>,
}

#[derive(Debug)]
struct ResolvedRegisterSelection {
    inventory: GdbMiRegisterInventory,
    registers: Vec<ResolvedRegister>,
}

#[derive(Debug, Clone)]
struct ResolvedRegister {
    requested_name: String,
    canonical_name: String,
    number: u64,
}

#[derive(Debug)]
struct LifecycleFailure {
    code: ErrorCode,
    message: String,
    exit_code: i32,
    retryable: bool,
    details: Value,
}

fn protocol_failure(message: impl Into<String>, details: Value) -> LifecycleFailure {
    LifecycleFailure {
        code: ErrorCode::ProtocolError,
        message: message.into(),
        exit_code: 6,
        retryable: false,
        details,
    }
}

fn lifecycle_failure_value(failure: &LifecycleFailure) -> Value {
    json!({
        "code": failure.code,
        "message": failure.message,
        "exit_code": failure.exit_code,
        "retryable": failure.retryable,
        "details": failure.details,
    })
}

fn resolve_register_selection(
    variables: &HashMap<String, MiValue>,
    requested_names: &[String],
) -> std::result::Result<ResolvedRegisterSelection, LifecycleFailure> {
    let names = exact_list_variable(variables, "register-names", "register-name inventory")?;
    let mut by_name: HashMap<String, Vec<ResolvedRegister>> = HashMap::new();
    let mut named_entries = 0_u64;
    for (index, value) in names.iter().enumerate() {
        let MiValue::String(canonical_name) = value else {
            return Err(protocol_failure(
                "GDB/MI register-name inventory contained a non-string entry",
                json!({"register_number": index}),
            ));
        };
        if canonical_name.is_empty() {
            continue;
        }
        if !is_safe_register_name(canonical_name) {
            return Err(protocol_failure(
                "GDB/MI register-name inventory contained an unsafe name",
                json!({
                    "register_number": index,
                    "register_name": bounded_line(canonical_name),
                }),
            ));
        }
        let number = u64::try_from(index).map_err(|_| {
            protocol_failure(
                "GDB/MI register inventory exceeded the supported index range",
                json!({"register_number": index}),
            )
        })?;
        named_entries = named_entries.saturating_add(1);
        by_name
            .entry(canonical_name.to_ascii_lowercase())
            .or_default()
            .push(ResolvedRegister {
                requested_name: String::new(),
                canonical_name: canonical_name.clone(),
                number,
            });
    }

    let mut registers = Vec::with_capacity(requested_names.len());
    for requested_name in requested_names {
        let key = requested_name.to_ascii_lowercase();
        let Some(candidates) = by_name.get(&key) else {
            return Err(protocol_failure(
                "requested register was not present in the GDB/MI register-name inventory",
                json!({
                    "requested_register": requested_name,
                    "inventory_entries": names.len(),
                    "named_registers": named_entries,
                }),
            ));
        };
        if candidates.len() != 1 {
            return Err(protocol_failure(
                "requested register name was ambiguous in the GDB/MI inventory",
                json!({
                    "requested_register": requested_name,
                    "matching_register_numbers": candidates.iter().map(|item| item.number).collect::<Vec<_>>(),
                }),
            ));
        }
        let mut register = candidates[0].clone();
        register.requested_name = requested_name.clone();
        registers.push(register);
    }

    Ok(ResolvedRegisterSelection {
        inventory: GdbMiRegisterInventory {
            total_entries: u64::try_from(names.len()).unwrap_or(u64::MAX),
            named_entries,
        },
        registers,
    })
}

fn register_values_command(registers: &[ResolvedRegister]) -> String {
    let numbers = registers
        .iter()
        .map(|register| register.number.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    format!("-data-list-register-values --skip-unavailable x {numbers}")
}

fn parse_register_values(
    variables: &HashMap<String, MiValue>,
    registers: &[ResolvedRegister],
) -> std::result::Result<Vec<GdbMiRegisterValue>, LifecycleFailure> {
    let values = exact_list_variable(variables, "register-values", "register values")?;
    let requested_numbers = registers
        .iter()
        .map(|register| register.number)
        .collect::<HashSet<_>>();
    let mut by_number = HashMap::new();
    for value in values {
        let MiValue::Dict(fields) = value else {
            return Err(protocol_failure(
                "GDB/MI register-values list contained a non-tuple entry",
                json!({}),
            ));
        };
        if fields.len() != 2 {
            return Err(protocol_failure(
                "GDB/MI register-value tuple did not contain exactly number and value",
                json!({"field_count": fields.len()}),
            ));
        }
        let number = exact_string_field(fields, "number", "register-value tuple")?;
        if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(protocol_failure(
                "GDB/MI register-value tuple contained an invalid register number",
                json!({"number": bounded_line(number)}),
            ));
        }
        let number = number.parse::<u64>().map_err(|_| {
            protocol_failure(
                "GDB/MI register number exceeded the supported integer range",
                json!({"number": bounded_line(number)}),
            )
        })?;
        if !requested_numbers.contains(&number) {
            return Err(protocol_failure(
                "GDB/MI returned a register number that was not requested",
                json!({"register_number": number}),
            ));
        }
        let raw_value = exact_string_field(fields, "value", "register-value tuple")?;
        let normalized_value = normalize_hex_register_value(raw_value)?;
        if by_number.insert(number, normalized_value).is_some() {
            return Err(protocol_failure(
                "GDB/MI returned a duplicate register number",
                json!({"register_number": number}),
            ));
        }
    }

    registers
        .iter()
        .map(|register| {
            let value = by_number.remove(&register.number).ok_or_else(|| {
                protocol_failure(
                    "GDB/MI did not return every requested register value",
                    json!({
                        "missing_register": register.requested_name,
                        "register_number": register.number,
                        "unavailable_policy": "fail",
                    }),
                )
            })?;
            Ok(GdbMiRegisterValue {
                requested_name: register.requested_name.clone(),
                canonical_name: register.canonical_name.clone(),
                number: register.number,
                value,
            })
        })
        .collect()
}

fn memory_read_command(address: Address, length_bytes: u64) -> String {
    format!("-data-read-memory-bytes 0x{:x} {length_bytes}", address.0)
}

fn parse_memory_snapshot(
    variables: &HashMap<String, MiValue>,
    address: Address,
    length_bytes: u64,
) -> std::result::Result<GdbMiMemorySnapshot, LifecycleFailure> {
    if length_bytes == 0 || length_bytes > MAX_INLINE_MEMORY_READ_BYTES {
        return Err(protocol_failure(
            "GDB/MI memory snapshot request exceeded the supported byte range",
            json!({
                "length_bytes": length_bytes,
                "minimum": 1,
                "maximum": MAX_INLINE_MEMORY_READ_BYTES,
            }),
        ));
    }
    let end_exclusive = address.0.checked_add(length_bytes).ok_or_else(|| {
        protocol_failure(
            "GDB/MI memory snapshot request overflowed the address space",
            json!({"address": address, "length_bytes": length_bytes}),
        )
    })?;
    let values = exact_list_variable(variables, "memory", "memory snapshot")?;
    if values.is_empty() {
        return Err(protocol_failure(
            "GDB/MI memory snapshot returned no readable blocks",
            json!({"address": address, "length_bytes": length_bytes}),
        ));
    }
    let maximum_blocks = usize::try_from(length_bytes).unwrap_or(usize::MAX);
    if values.len() > maximum_blocks {
        return Err(protocol_failure(
            "GDB/MI memory snapshot returned more blocks than requested bytes",
            json!({
                "block_count": values.len(),
                "length_bytes": length_bytes,
            }),
        ));
    }

    let mut expected_offset = 0_u64;
    let mut bytes = Vec::with_capacity(maximum_blocks);
    let mut blocks = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let MiValue::Dict(fields) = value else {
            return Err(protocol_failure(
                "GDB/MI memory list contained a non-tuple entry",
                json!({"block_index": index}),
            ));
        };
        if fields.len() != 4 {
            return Err(protocol_failure(
                "GDB/MI memory block did not contain exactly begin, offset, end, and contents",
                json!({"block_index": index, "field_count": fields.len()}),
            ));
        }
        let begin = parse_hex_u64_field(fields, "begin", index)?;
        let offset = parse_hex_u64_field(fields, "offset", index)?;
        let end = parse_hex_u64_field(fields, "end", index)?;
        if offset != expected_offset {
            return Err(protocol_failure(
                "GDB/MI memory blocks did not provide ordered gap-free coverage",
                json!({
                    "block_index": index,
                    "expected_offset_bytes": expected_offset,
                    "observed_offset_bytes": offset,
                }),
            ));
        }
        let expected_begin = address.0.checked_add(offset).ok_or_else(|| {
            protocol_failure(
                "GDB/MI memory block begin overflowed the requested address",
                json!({"block_index": index, "address": address, "offset_bytes": offset}),
            )
        })?;
        if begin != expected_begin {
            return Err(protocol_failure(
                "GDB/MI memory block begin did not match its requested-relative offset",
                json!({
                    "block_index": index,
                    "expected_begin": Address(expected_begin),
                    "observed_begin": Address(begin),
                }),
            ));
        }
        if end <= begin || end > end_exclusive {
            return Err(protocol_failure(
                "GDB/MI memory block end was outside the requested range",
                json!({
                    "block_index": index,
                    "begin": Address(begin),
                    "end_exclusive": Address(end),
                    "request_end_exclusive": Address(end_exclusive),
                }),
            ));
        }

        let contents = exact_string_field(fields, "contents", "memory block")?;
        if contents.is_empty()
            || contents.len() > (MAX_INLINE_MEMORY_READ_BYTES as usize) * 2
            || !contents.len().is_multiple_of(2)
            || !contents.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(protocol_failure(
                "GDB/MI memory block contained invalid bounded hexadecimal contents",
                json!({
                    "block_index": index,
                    "hex_digits": contents.len(),
                    "maximum_hex_digits": MAX_INLINE_MEMORY_READ_BYTES * 2,
                }),
            ));
        }
        let block_bytes = hex::decode(contents).map_err(|_| {
            protocol_failure(
                "GDB/MI memory block hexadecimal contents could not be decoded",
                json!({"block_index": index}),
            )
        })?;
        let block_length = u64::try_from(block_bytes.len()).map_err(|_| {
            protocol_failure(
                "GDB/MI memory block length exceeded the supported range",
                json!({"block_index": index}),
            )
        })?;
        if end - begin != block_length {
            return Err(protocol_failure(
                "GDB/MI memory block address span did not match its decoded contents",
                json!({
                    "block_index": index,
                    "address_span": end - begin,
                    "decoded_bytes": block_length,
                }),
            ));
        }
        expected_offset = expected_offset.checked_add(block_length).ok_or_else(|| {
            protocol_failure(
                "GDB/MI memory block coverage overflowed",
                json!({"block_index": index}),
            )
        })?;
        bytes.extend_from_slice(&block_bytes);
        blocks.push(GdbMiMemoryBlock {
            begin: Address(begin),
            offset_bytes: offset,
            end_exclusive: Address(end),
            length_bytes: block_length,
            contents: contents.to_ascii_lowercase(),
        });
    }

    if expected_offset != length_bytes {
        return Err(protocol_failure(
            "GDB/MI memory blocks did not cover every requested byte",
            json!({
                "requested_length_bytes": length_bytes,
                "covered_length_bytes": expected_offset,
                "unavailable_policy": "fail",
            }),
        ));
    }

    Ok(GdbMiMemorySnapshot {
        address,
        length_bytes,
        end_exclusive: Address(end_exclusive),
        encoding: "hex".to_string(),
        data: hex::encode(&bytes),
        sha256: hex::encode(Sha256::digest(&bytes)),
        complete_coverage: true,
        blocks,
    })
}

fn stack_list_command(maximum_frames: u64) -> String {
    let maximum_frame_index = maximum_frames.saturating_sub(1);
    format!("-stack-list-frames --no-frame-filters 0 {maximum_frame_index}")
}

fn parse_stack_snapshot(
    variables: &HashMap<String, MiValue>,
    maximum_frames: u64,
) -> std::result::Result<GdbMiStackSnapshot, LifecycleFailure> {
    const MAX_STACK_TEXT_FIELD_BYTES: usize = 4 * 1024;

    if maximum_frames == 0 {
        return Err(protocol_failure(
            "GDB/MI stack snapshot requires a non-zero frame limit",
            json!({"maximum_frames": maximum_frames}),
        ));
    }
    let values = exact_list_variable(variables, "stack", "stack snapshot")?;
    if values.is_empty() {
        return Err(protocol_failure(
            "GDB/MI stack snapshot returned no frames",
            json!({"maximum_frames": maximum_frames}),
        ));
    }
    let returned_frames = u64::try_from(values.len()).map_err(|_| {
        protocol_failure(
            "GDB/MI stack snapshot frame count exceeded the supported integer range",
            json!({}),
        )
    })?;
    if returned_frames > maximum_frames {
        return Err(protocol_failure(
            "GDB/MI stack snapshot returned more frames than requested",
            json!({
                "returned_frames": returned_frames,
                "maximum_frames": maximum_frames,
            }),
        ));
    }

    let mut frames = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let MiValue::Dict(fields) = value else {
            return Err(protocol_failure(
                "GDB/MI stack list contained a non-frame entry",
                json!({"frame_index": index}),
            ));
        };
        for field in fields.keys() {
            if !matches!(
                field.as_str(),
                "level"
                    | "addr"
                    | "func"
                    | "file"
                    | "fullname"
                    | "line"
                    | "from"
                    | "arch"
                    | "addr_flags"
            ) {
                return Err(protocol_failure(
                    "GDB/MI stack frame contained an unexpected field",
                    json!({"frame_index": index, "field": bounded_line(field)}),
                ));
            }
        }
        let level = parse_decimal_stack_field(fields, "level", index)?;
        let expected_level = u64::try_from(index).map_err(|_| {
            protocol_failure(
                "GDB/MI stack frame index exceeded the supported integer range",
                json!({"frame_index": index}),
            )
        })?;
        if level != expected_level {
            return Err(protocol_failure(
                "GDB/MI stack frames were not contiguous from level zero",
                json!({
                    "frame_index": index,
                    "expected_level": expected_level,
                    "observed_level": level,
                }),
            ));
        }
        let address = parse_stack_address(fields, index)?;
        let line = fields
            .contains_key("line")
            .then(|| parse_decimal_stack_field(fields, "line", index))
            .transpose()?;
        frames.push(GdbMiStackFrame {
            level,
            address: Address(address),
            function: optional_bounded_stack_field(
                fields,
                "func",
                index,
                MAX_STACK_TEXT_FIELD_BYTES,
            )?,
            file: optional_bounded_stack_field(fields, "file", index, MAX_STACK_TEXT_FIELD_BYTES)?,
            fullname: optional_bounded_stack_field(
                fields,
                "fullname",
                index,
                MAX_STACK_TEXT_FIELD_BYTES,
            )?,
            line,
            module: optional_bounded_stack_field(
                fields,
                "from",
                index,
                MAX_STACK_TEXT_FIELD_BYTES,
            )?,
            architecture: optional_bounded_stack_field(
                fields,
                "arch",
                index,
                MAX_STACK_TEXT_FIELD_BYTES,
            )?,
            address_flags: optional_bounded_stack_field(
                fields,
                "addr_flags",
                index,
                MAX_STACK_TEXT_FIELD_BYTES,
            )?,
        });
    }

    let frame_limit_reached = returned_frames == maximum_frames;
    Ok(GdbMiStackSnapshot {
        maximum_frames,
        returned_frames,
        frame_limit_reached,
        additional_gdb_frames_possible: frame_limit_reached,
        physical_call_stack_completeness_proven: false,
        frames,
    })
}

fn parse_decimal_stack_field(
    fields: &HashMap<String, MiValue>,
    key: &str,
    frame_index: usize,
) -> std::result::Result<u64, LifecycleFailure> {
    let value = exact_string_field(fields, key, "stack frame")?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(protocol_failure(
            "GDB/MI stack frame contained invalid decimal metadata",
            json!({"frame_index": frame_index, "field": key, "value": bounded_line(value)}),
        ));
    }
    value.parse::<u64>().map_err(|_| {
        protocol_failure(
            "GDB/MI stack frame decimal metadata exceeded 64 bits",
            json!({"frame_index": frame_index, "field": key, "value": bounded_line(value)}),
        )
    })
}

fn parse_stack_address(
    fields: &HashMap<String, MiValue>,
    frame_index: usize,
) -> std::result::Result<u64, LifecycleFailure> {
    let value = exact_string_field(fields, "addr", "stack frame")?;
    let Some(digits) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    else {
        return Err(protocol_failure(
            "GDB/MI stack frame address was not hexadecimal",
            json!({"frame_index": frame_index, "value": bounded_line(value)}),
        ));
    };
    if digits.is_empty()
        || digits.len() > 16
        || !digits.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(protocol_failure(
            "GDB/MI stack frame address had an invalid hexadecimal payload",
            json!({"frame_index": frame_index, "value": bounded_line(value)}),
        ));
    }
    u64::from_str_radix(digits, 16).map_err(|_| {
        protocol_failure(
            "GDB/MI stack frame address exceeded 64 bits",
            json!({"frame_index": frame_index, "value": bounded_line(value)}),
        )
    })
}

fn optional_bounded_stack_field(
    fields: &HashMap<String, MiValue>,
    key: &str,
    frame_index: usize,
    maximum_bytes: usize,
) -> std::result::Result<Option<String>, LifecycleFailure> {
    let Some(value) = fields.get(key) else {
        return Ok(None);
    };
    let MiValue::String(value) = value else {
        return Err(protocol_failure(
            "GDB/MI stack frame optional metadata was not a string",
            json!({"frame_index": frame_index, "field": key}),
        ));
    };
    if value.is_empty() || value.len() > maximum_bytes || value.chars().any(char::is_control) {
        return Err(protocol_failure(
            "GDB/MI stack frame optional metadata exceeded the safe text boundary",
            json!({
                "frame_index": frame_index,
                "field": key,
                "bytes": value.len(),
                "maximum_bytes": maximum_bytes,
            }),
        ));
    }
    Ok(Some(value.clone()))
}

fn parse_hex_u64_field(
    fields: &HashMap<String, MiValue>,
    key: &str,
    block_index: usize,
) -> std::result::Result<u64, LifecycleFailure> {
    let value = exact_string_field(fields, key, "memory block")?;
    let Some(digits) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    else {
        return Err(protocol_failure(
            "GDB/MI memory block address metadata was not hexadecimal",
            json!({"block_index": block_index, "field": key, "value": bounded_line(value)}),
        ));
    };
    if digits.is_empty()
        || digits.len() > 16
        || !digits.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(protocol_failure(
            "GDB/MI memory block address metadata had an invalid hexadecimal payload",
            json!({"block_index": block_index, "field": key, "value": bounded_line(value)}),
        ));
    }
    u64::from_str_radix(digits, 16).map_err(|_| {
        protocol_failure(
            "GDB/MI memory block address metadata exceeded 64 bits",
            json!({"block_index": block_index, "field": key, "value": bounded_line(value)}),
        )
    })
}

fn exact_list_variable<'a>(
    variables: &'a HashMap<String, MiValue>,
    expected_key: &str,
    label: &str,
) -> std::result::Result<&'a [MiValue], LifecycleFailure> {
    if variables.len() != 1 {
        return Err(protocol_failure(
            format!("GDB/MI {label} result contained unexpected fields"),
            json!({
                "expected_field": expected_key,
                "field_count": variables.len(),
            }),
        ));
    }
    let Some(MiValue::List(values)) = variables.get(expected_key) else {
        return Err(protocol_failure(
            format!("GDB/MI {label} result did not contain the expected list"),
            json!({"expected_field": expected_key}),
        ));
    };
    Ok(values)
}

fn exact_string_field<'a>(
    fields: &'a HashMap<String, MiValue>,
    key: &str,
    label: &str,
) -> std::result::Result<&'a str, LifecycleFailure> {
    let Some(MiValue::String(value)) = fields.get(key) else {
        return Err(protocol_failure(
            format!("GDB/MI {label} did not contain a string {key} field"),
            json!({"field": key}),
        ));
    };
    Ok(value)
}

fn normalize_hex_register_value(value: &str) -> std::result::Result<String, LifecycleFailure> {
    const MAX_REGISTER_HEX_DIGITS: usize = 1024;
    let Some(digits) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    else {
        return Err(protocol_failure(
            "GDB/MI register value was not hexadecimal",
            json!({"value": bounded_line(value)}),
        ));
    };
    if digits.is_empty()
        || digits.len() > MAX_REGISTER_HEX_DIGITS
        || !digits.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(protocol_failure(
            "GDB/MI register value had an invalid hexadecimal payload",
            json!({
                "value": bounded_line(value),
                "maximum_hex_digits": MAX_REGISTER_HEX_DIGITS,
            }),
        ));
    }
    Ok(format!("0x{}", digits.to_ascii_lowercase()))
}

fn is_safe_register_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
}

fn finalize_failure(
    mut gdb: ManagedGdb,
    failure: LifecycleFailure,
    shutdown_timeout_ms: u64,
) -> DebugError {
    let mut shutdown = gdb.cleanup(Duration::from_millis(shutdown_timeout_ms));
    let output = gdb.finish_output();
    shutdown.process_tree_cleanup_complete &= output_streams_closed(&output);
    let mut object = failure.details.as_object().cloned().unwrap_or_default();
    object.insert(
        "shutdown".to_string(),
        serde_json::to_value(shutdown).expect("GDB shutdown always serializes"),
    );
    object.insert(
        "output".to_string(),
        serde_json::to_value(output).expect("GDB output always serializes"),
    );
    let mut error = DebugError::new(
        failure.code,
        failure.message,
        failure.exit_code,
        Value::Object(object),
    );
    error.retryable = failure.retryable;
    error
}

fn protocol_error_with_lifecycle(
    message: impl Into<String>,
    details: Value,
    shutdown: &GdbMiShutdown,
    output: &GdbMiOutput,
) -> DebugError {
    let mut object = details.as_object().cloned().unwrap_or_default();
    object.insert(
        "shutdown".to_string(),
        serde_json::to_value(shutdown).expect("GDB shutdown always serializes"),
    );
    object.insert(
        "output".to_string(),
        serde_json::to_value(output).expect("GDB output always serializes"),
    );
    DebugError::new(ErrorCode::ProtocolError, message, 6, Value::Object(object))
}

fn validate_complete_output(output: &GdbMiOutput) -> std::result::Result<(), &'static str> {
    for stream in [&output.stdout, &output.stderr] {
        if !stream.drain_complete || stream.read_error.is_some() {
            return Err("managed GDB/MI output stream did not drain completely");
        }
        if stream.truncated {
            return Err("managed GDB/MI output exceeded the bounded capture limit");
        }
        if stream.line_limit_exceeded {
            return Err("managed GDB/MI emitted a line beyond the bounded line limit");
        }
        if stream.events_dropped != 0 {
            return Err("managed GDB/MI output event queue overflowed");
        }
    }
    Ok(())
}

fn output_streams_closed(output: &GdbMiOutput) -> bool {
    [&output.stdout, &output.stderr]
        .into_iter()
        .all(|stream| stream.drain_complete && stream.read_error.is_none())
}

fn capture_stream<R: Read + Send + 'static>(
    mut stream: R,
    stream_name: OutputStream,
    sender: SyncSender<OutputEvent>,
) -> JoinHandle<StreamCapture> {
    thread::spawn(move || {
        let mut retained = Vec::new();
        let mut total_bytes = 0_u64;
        let mut hasher = Sha256::new();
        let mut truncated = false;
        let mut line = Vec::new();
        let mut line_overflow = false;
        let mut line_limit_exceeded = false;
        let mut events_dropped = 0_u64;
        let mut buffer = [0_u8; 4096];

        loop {
            match stream.read(&mut buffer) {
                Ok(0) => {
                    if !line.is_empty() || line_overflow {
                        send_event(&sender, stream_name, &line, &mut events_dropped);
                    }
                    return StreamCapture {
                        retained,
                        total_bytes,
                        sha256: hex::encode(hasher.finalize()),
                        truncated,
                        line_limit_exceeded,
                        events_dropped,
                        drain_complete: true,
                        read_error: None,
                    };
                }
                Ok(count) => {
                    let bytes = &buffer[..count];
                    hasher.update(bytes);
                    total_bytes = total_bytes.saturating_add(count as u64);
                    let remaining = MAX_MI_OUTPUT_BYTES_PER_STREAM.saturating_sub(retained.len());
                    retained.extend_from_slice(&bytes[..bytes.len().min(remaining)]);
                    truncated = total_bytes > MAX_MI_OUTPUT_BYTES_PER_STREAM as u64;

                    for byte in bytes {
                        if *byte == b'\n' {
                            send_event(&sender, stream_name, &line, &mut events_dropped);
                            line.clear();
                            line_overflow = false;
                        } else if line.len() < MAX_MI_OUTPUT_LINE_BYTES {
                            line.push(*byte);
                        } else {
                            line_overflow = true;
                            line_limit_exceeded = true;
                        }
                    }
                }
                Err(source) => {
                    return StreamCapture {
                        retained,
                        total_bytes,
                        sha256: hex::encode(hasher.finalize()),
                        truncated,
                        line_limit_exceeded,
                        events_dropped,
                        drain_complete: false,
                        read_error: Some(source.to_string()),
                    };
                }
            }
        }
    })
}

fn send_event(
    sender: &SyncSender<OutputEvent>,
    stream: OutputStream,
    bytes: &[u8],
    events_dropped: &mut u64,
) {
    let line = String::from_utf8_lossy(bytes)
        .trim_end_matches('\r')
        .to_string();
    match sender.try_send(OutputEvent { stream, line }) {
        Ok(()) => {}
        Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
            *events_dropped = events_dropped.saturating_add(1);
        }
    }
}

fn finish_stream(handle: Option<JoinHandle<StreamCapture>>, deadline: Instant) -> StreamCapture {
    let Some(handle) = handle else {
        return StreamCapture::incomplete("GDB output reader was not available");
    };
    while !handle.is_finished() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(1));
    }
    if !handle.is_finished() {
        return StreamCapture::incomplete(
            "GDB output stream did not close after process-tree cleanup",
        );
    }
    handle
        .join()
        .unwrap_or_else(|_| StreamCapture::incomplete("GDB output reader thread panicked"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ParsedRecord {
    Prompt,
    Result {
        token: Option<u64>,
        class: String,
        variables: HashMap<String, MiValue>,
    },
    ExecAsync,
    StatusAsync,
    NotifyAsync,
    ConsoleStream,
    TargetStream,
    LogStream,
}

fn parse_record(line: &str) -> std::result::Result<ParsedRecord, String> {
    if line.trim() == "(gdb)" {
        return Ok(ParsedRecord::Prompt);
    }
    if line.is_empty() {
        return Err("empty stdout line".to_string());
    }

    let token_length = line.bytes().take_while(u8::is_ascii_digit).count();
    let (token, record) = if token_length == 0 {
        (None, line)
    } else {
        let token = line[..token_length]
            .parse::<u64>()
            .map_err(|_| "MI token is outside the supported integer range".to_string())?;
        (Some(token), &line[token_length..])
    };
    let Some(marker) = record.as_bytes().first().copied() else {
        return Err("MI record marker is missing".to_string());
    };
    let payload = &record[1..];
    match marker {
        b'^' => parse_result_record(line, token, payload),
        b'*' => {
            reject_token(token, "exec async")?;
            parse_class(payload, "exec async")?;
            Ok(ParsedRecord::ExecAsync)
        }
        b'+' => {
            reject_token(token, "status async")?;
            parse_class(payload, "status async")?;
            Ok(ParsedRecord::StatusAsync)
        }
        b'=' => {
            reject_token(token, "notify async")?;
            parse_class(payload, "notify async")?;
            Ok(ParsedRecord::NotifyAsync)
        }
        b'~' => {
            reject_token(token, "console stream")?;
            validate_stream_payload(payload)?;
            Ok(ParsedRecord::ConsoleStream)
        }
        b'@' => {
            reject_token(token, "target stream")?;
            validate_stream_payload(payload)?;
            Ok(ParsedRecord::TargetStream)
        }
        b'&' => {
            reject_token(token, "log stream")?;
            validate_stream_payload(payload)?;
            Ok(ParsedRecord::LogStream)
        }
        _ => Err(format!("unsupported MI record marker 0x{marker:02x}")),
    }
}

fn parse_result_record(
    line: &str,
    token: Option<u64>,
    payload: &str,
) -> std::result::Result<ParsedRecord, String> {
    let class = parse_class(payload, "result")?;
    if payload.starts_with("done,stack=") {
        return parse_stack_result_record(line, token, class);
    }
    let response = serde_gdbmi::parser::Response::try_from(line)
        .map_err(|error| format!("result record has invalid structured MI data: {error}"))?;
    let parsed_token = response
        .token
        .as_deref()
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| "MI token is outside the supported integer range".to_string())
        })
        .transpose()?;
    if parsed_token != token {
        return Err("structured MI parser returned an inconsistent result token".to_string());
    }
    let StructuredResponseBody::Data(data) = response.body else {
        return Err("result marker parsed as a stream record".to_string());
    };
    if data.symbol != DataSymbol::Result || data.class != class {
        return Err("structured MI parser returned an inconsistent result record".to_string());
    }
    Ok(ParsedRecord::Result {
        token,
        class,
        variables: data.variables,
    })
}

fn parse_stack_result_record(
    line: &str,
    token: Option<u64>,
    class: String,
) -> std::result::Result<ParsedRecord, String> {
    if class != "done" {
        return Err("stack result used an unexpected result class".to_string());
    }
    let tokens = lexer::lex(line)
        .map_err(|error| format!("stack result has invalid structured MI data: {error}"))?
        .into_iter()
        .collect::<Vec<_>>();
    let mut tokens = tokens.into_iter();

    if let Some(expected_token) = token {
        match tokens.next() {
            Some(MiToken::Text(value)) if value == expected_token.to_string() => {}
            _ => return Err("stack result token was not represented exactly once".to_string()),
        }
    }
    match tokens.next() {
        Some(MiToken::Punct('^')) => {}
        _ => return Err("stack result marker was missing".to_string()),
    }
    match tokens.next() {
        Some(MiToken::Text(value)) if value == "done" => {}
        _ => return Err("stack result class was not done".to_string()),
    }
    match tokens.next() {
        Some(MiToken::Punct(',')) => {}
        _ => return Err("stack result variable separator was missing".to_string()),
    }
    match tokens.next() {
        Some(MiToken::Text(value)) if value == "stack" => {}
        _ => return Err("stack result did not contain the exact stack variable".to_string()),
    }
    match tokens.next() {
        Some(MiToken::Punct('=')) => {}
        _ => return Err("stack result assignment was missing".to_string()),
    }
    let frames = match tokens.next() {
        Some(MiToken::Bracketed(frames)) => parse_named_stack_frame_list(frames)?,
        _ => return Err("stack result was not a result-list".to_string()),
    };
    if tokens.next().is_some() {
        return Err("stack result contained unexpected trailing variables".to_string());
    }

    Ok(ParsedRecord::Result {
        token,
        class,
        variables: HashMap::from([("stack".to_string(), MiValue::List(frames))]),
    })
}

fn parse_named_stack_frame_list(
    frames: lexer::TokenStream,
) -> std::result::Result<Vec<MiValue>, String> {
    let mut tokens = frames.into_iter().peekable();
    let mut parsed = Vec::new();
    while tokens.peek().is_some() {
        match tokens.next() {
            Some(MiToken::Text(value)) if value == "frame" => {}
            _ => return Err("stack result-list entry was not named frame".to_string()),
        }
        match tokens.next() {
            Some(MiToken::Punct('=')) => {}
            _ => return Err("stack frame result assignment was missing".to_string()),
        }
        let fields = match tokens.next() {
            Some(MiToken::Braced(fields)) => parse_stack_frame_fields(fields)?,
            _ => return Err("stack frame result was not a tuple".to_string()),
        };
        parsed.push(MiValue::Dict(fields));
        if tokens.peek().is_none() {
            break;
        }
        match tokens.next() {
            Some(MiToken::Punct(',')) if tokens.peek().is_some() => {}
            _ => return Err("stack result-list separator was malformed".to_string()),
        }
    }
    Ok(parsed)
}

fn parse_stack_frame_fields(
    fields: lexer::TokenStream,
) -> std::result::Result<HashMap<String, MiValue>, String> {
    let mut tokens = fields.into_iter().peekable();
    let mut parsed = HashMap::new();
    while tokens.peek().is_some() {
        let key = match tokens.next() {
            Some(MiToken::Text(key)) => key,
            _ => return Err("stack frame field name was malformed".to_string()),
        };
        match tokens.next() {
            Some(MiToken::Punct('=')) => {}
            _ => return Err("stack frame field assignment was missing".to_string()),
        }
        let value = match tokens.next() {
            Some(MiToken::Text(value)) => MiValue::String(value),
            _ => return Err("stack frame field was not a scalar string".to_string()),
        };
        if parsed.insert(key, value).is_some() {
            return Err("stack frame contained a duplicate field".to_string());
        }
        if tokens.peek().is_none() {
            break;
        }
        match tokens.next() {
            Some(MiToken::Punct(',')) if tokens.peek().is_some() => {}
            _ => return Err("stack frame field separator was malformed".to_string()),
        }
    }
    Ok(parsed)
}

fn reject_token(token: Option<u64>, kind: &str) -> std::result::Result<(), String> {
    if token.is_some() {
        return Err(format!("{kind} record unexpectedly carried a token"));
    }
    Ok(())
}

fn parse_class(payload: &str, kind: &str) -> std::result::Result<String, String> {
    let class = payload.split_once(',').map_or(payload, |(class, _)| class);
    if class.is_empty()
        || !class
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(format!("{kind} record has an invalid class"));
    }
    Ok(class.to_string())
}

fn validate_stream_payload(payload: &str) -> std::result::Result<(), String> {
    if payload.len() < 2 || !payload.starts_with('"') || !payload.ends_with('"') {
        return Err("MI stream record is not a quoted C string".to_string());
    }
    Ok(())
}

impl GdbMiRecordCounts {
    fn observe(&mut self, record: &ParsedRecord) {
        let counter = match record {
            ParsedRecord::Prompt => &mut self.prompts,
            ParsedRecord::Result { .. } => &mut self.results,
            ParsedRecord::ExecAsync => &mut self.exec_async,
            ParsedRecord::StatusAsync => &mut self.status_async,
            ParsedRecord::NotifyAsync => &mut self.notify_async,
            ParsedRecord::ConsoleStream => &mut self.console_stream,
            ParsedRecord::TargetStream => &mut self.target_stream,
            ParsedRecord::LogStream => &mut self.log_stream,
        };
        *counter = counter.saturating_add(1);
    }
}

fn stream_record_count(counts: &GdbMiRecordCounts) -> u64 {
    counts
        .console_stream
        .saturating_add(counts.target_stream)
        .saturating_add(counts.log_stream)
}

fn bounded_line(line: &str) -> String {
    line.chars().take(512).collect()
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_accepts_the_required_mi2_record_shapes() {
        assert_eq!(parse_record("(gdb) ").unwrap(), ParsedRecord::Prompt);
        assert_eq!(
            parse_record("1^done").unwrap(),
            ParsedRecord::Result {
                token: Some(1),
                class: "done".to_string(),
                variables: HashMap::new(),
            }
        );
        assert_eq!(
            parse_record("2^exit").unwrap(),
            ParsedRecord::Result {
                token: Some(2),
                class: "exit".to_string(),
                variables: HashMap::new(),
            }
        );
        assert_eq!(
            parse_record("=thread-group-added,id=\"i1\"").unwrap(),
            ParsedRecord::NotifyAsync
        );
        assert_eq!(
            parse_record("~\"GNU gdb (esp-gdb) 17.1\\n\"").unwrap(),
            ParsedRecord::ConsoleStream
        );
    }

    #[test]
    fn parser_rejects_unstructured_output_tokens_and_unquoted_streams() {
        assert!(parse_record("GNU gdb 17.1").is_err());
        assert!(parse_record("1").is_err());
        assert!(parse_record("9=thread-created,id=\"1\"").is_err());
        assert!(parse_record("~not-quoted").is_err());
        assert!(parse_record("3^done,register-names=[\"pc\"").is_err());
    }

    #[test]
    fn parser_preserves_structured_result_variables() {
        let record = parse_record("3^done,register-names=[\"pc\",\"\",\"a0\"]").unwrap();
        let ParsedRecord::Result {
            token,
            class,
            variables,
        } = record
        else {
            panic!("expected result record");
        };
        assert_eq!(token, Some(3));
        assert_eq!(class, "done");
        assert_eq!(
            variables["register-names"],
            MiValue::List(vec![
                MiValue::String("pc".to_string()),
                MiValue::String(String::new()),
                MiValue::String("a0".to_string()),
            ])
        );
    }

    #[test]
    fn register_results_are_resolved_and_returned_in_requested_order() {
        let names = parse_record("3^done,register-names=[\"pc\",\"a0\",\"\",\"ps\"]").unwrap();
        let ParsedRecord::Result {
            variables: name_variables,
            ..
        } = names
        else {
            panic!("expected result record");
        };
        let requested = vec!["ps".to_string(), "pc".to_string()];
        let selection = resolve_register_selection(&name_variables, &requested).unwrap();
        assert_eq!(selection.inventory.total_entries, 4);
        assert_eq!(selection.inventory.named_entries, 3);
        assert_eq!(
            register_values_command(&selection.registers),
            "-data-list-register-values --skip-unavailable x 3 0"
        );

        let values = parse_record(
            "4^done,register-values=[{number=\"0\",value=\"0X4200ABCD\"},{number=\"3\",value=\"0x20\"}]",
        )
        .unwrap();
        let ParsedRecord::Result {
            variables: value_variables,
            ..
        } = values
        else {
            panic!("expected result record");
        };
        let values = parse_register_values(&value_variables, &selection.registers).unwrap();
        assert_eq!(values[0].requested_name, "ps");
        assert_eq!(values[0].number, 3);
        assert_eq!(values[0].value, "0x20");
        assert_eq!(values[1].requested_name, "pc");
        assert_eq!(values[1].value, "0x4200abcd");
    }

    #[test]
    fn register_results_fail_closed_on_unknown_unavailable_or_duplicate_values() {
        let names = HashMap::from([(
            "register-names".to_string(),
            MiValue::List(vec![MiValue::String("pc".to_string())]),
        )]);
        let unknown = resolve_register_selection(&names, &["a0".to_string()]).unwrap_err();
        assert_eq!(unknown.code, ErrorCode::ProtocolError);

        let ambiguous_names = HashMap::from([(
            "register-names".to_string(),
            MiValue::List(vec![
                MiValue::String("pc".to_string()),
                MiValue::String("PC".to_string()),
            ]),
        )]);
        let ambiguous =
            resolve_register_selection(&ambiguous_names, &["pc".to_string()]).unwrap_err();
        assert_eq!(
            ambiguous.details["matching_register_numbers"],
            json!([0, 1])
        );

        let selection = resolve_register_selection(&names, &["pc".to_string()]).unwrap();
        let unavailable =
            HashMap::from([("register-values".to_string(), MiValue::List(Vec::new()))]);
        let error = parse_register_values(&unavailable, &selection.registers).unwrap_err();
        assert_eq!(error.details["unavailable_policy"], "fail");

        let tuple = MiValue::Dict(HashMap::from([
            ("number".to_string(), MiValue::String("0".to_string())),
            ("value".to_string(), MiValue::String("0x1".to_string())),
        ]));
        let duplicate = HashMap::from([(
            "register-values".to_string(),
            MiValue::List(vec![tuple.clone(), tuple]),
        )]);
        let error = parse_register_values(&duplicate, &selection.registers).unwrap_err();
        assert_eq!(error.details["register_number"], 0);

        let non_hex = HashMap::from([(
            "register-values".to_string(),
            MiValue::List(vec![MiValue::Dict(HashMap::from([
                ("number".to_string(), MiValue::String("0".to_string())),
                (
                    "value".to_string(),
                    MiValue::String("unavailable".to_string()),
                ),
            ]))]),
        )]);
        assert!(parse_register_values(&non_hex, &selection.registers).is_err());

        let extra = HashMap::from([(
            "register-values".to_string(),
            MiValue::List(vec![MiValue::Dict(HashMap::from([
                ("number".to_string(), MiValue::String("1".to_string())),
                ("value".to_string(), MiValue::String("0x1".to_string())),
            ]))]),
        )]);
        let error = parse_register_values(&extra, &selection.registers).unwrap_err();
        assert_eq!(error.details["register_number"], 1);
    }

    #[test]
    fn memory_results_require_complete_ordered_gap_free_coverage() {
        let record = parse_record(
            "3^done,memory=[{begin=\"0x20000004\",offset=\"0x0\",end=\"0x20000008\",contents=\"00010203\"},{begin=\"0x20000008\",offset=\"0x4\",end=\"0x2000000c\",contents=\"AABBCCDD\"}]",
        )
        .unwrap();
        let ParsedRecord::Result { variables, .. } = record else {
            panic!("expected result record");
        };
        let snapshot = parse_memory_snapshot(&variables, Address(0x2000_0004), 8).unwrap();
        assert_eq!(snapshot.address, Address(0x2000_0004));
        assert_eq!(snapshot.end_exclusive, Address(0x2000_000c));
        assert_eq!(snapshot.data, "00010203aabbccdd");
        assert_eq!(
            snapshot.sha256,
            hex::encode(Sha256::digest([0, 1, 2, 3, 0xaa, 0xbb, 0xcc, 0xdd]))
        );
        assert!(snapshot.complete_coverage);
        assert_eq!(snapshot.blocks.len(), 2);
        assert_eq!(snapshot.blocks[1].offset_bytes, 4);
        assert_eq!(snapshot.blocks[1].contents, "aabbccdd");
    }

    #[test]
    fn memory_results_fail_closed_on_partial_or_malformed_blocks() {
        let cases = [
            "3^done,memory=[]",
            "3^done,memory=[{begin=\"0x20000004\",offset=\"0x0\",end=\"0x20000008\",contents=\"00010203\"}]",
            "3^done,memory=[{begin=\"0x20000004\",offset=\"0x0\",end=\"0x20000008\",contents=\"00010203\"},{begin=\"0x20000009\",offset=\"0x5\",end=\"0x2000000c\",contents=\"aabbcc\"}]",
            "3^done,memory=[{begin=\"0x20000005\",offset=\"0x0\",end=\"0x2000000c\",contents=\"0001020304050607\"}]",
            "3^done,memory=[{begin=\"0x20000004\",offset=\"0x0\",end=\"0x2000000c\",contents=\"00010203\"}]",
            "3^done,memory=[{begin=\"0x20000004\",offset=\"0x0\",end=\"0x2000000c\",contents=\"not-hex!\"}]",
            "3^done,memory=[{begin=\"0x20000004\",offset=\"0x0\",end=\"0x2000000c\",contents=\"0001020304050607\",extra=\"x\"}]",
        ];
        for line in cases {
            let record = parse_record(line).unwrap();
            let ParsedRecord::Result { variables, .. } = record else {
                panic!("expected result record");
            };
            let error = parse_memory_snapshot(&variables, Address(0x2000_0004), 8).unwrap_err();
            assert_eq!(error.code, ErrorCode::ProtocolError, "{line}");
        }
    }

    #[test]
    fn stack_result_lists_are_parsed_and_bounded_structurally() {
        let record = parse_record(
            "3^done,stack=[frame={level=\"0\",addr=\"0X40370010\",func=\"app_main\",file=\"main.c\",fullname=\"D:/src/main.c\",line=\"42\",arch=\"xtensa\"},frame={level=\"1\",addr=\"0x40370020\",from=\"rom\",addr_flags=\"is-entry\"}]",
        )
        .unwrap();
        let ParsedRecord::Result { variables, .. } = record else {
            panic!("expected result record");
        };
        let snapshot = parse_stack_snapshot(&variables, 4).unwrap();

        assert_eq!(snapshot.maximum_frames, 4);
        assert_eq!(snapshot.returned_frames, 2);
        assert!(!snapshot.frame_limit_reached);
        assert!(!snapshot.additional_gdb_frames_possible);
        assert!(!snapshot.physical_call_stack_completeness_proven);
        assert_eq!(snapshot.frames[0].address, Address(0x4037_0010));
        assert_eq!(snapshot.frames[0].function.as_deref(), Some("app_main"));
        assert_eq!(snapshot.frames[0].line, Some(42));
        assert_eq!(snapshot.frames[1].module.as_deref(), Some("rom"));
        assert_eq!(
            snapshot.frames[1].address_flags.as_deref(),
            Some("is-entry")
        );
    }

    #[test]
    fn stack_results_fail_closed_on_shape_level_address_or_field_violations() {
        let malformed_records = [
            "3^done,stack=[{level=\"0\",addr=\"0x1\"}]",
            "3^done,stack=[frame={level=\"0\",level=\"0\",addr=\"0x1\"}]",
            "3^done,stack=[frame={level=\"0\",addr=\"0x1\",args=[]}]",
            "3^done,stack=[frame={level=\"0\",addr=\"0x1\"}],extra=\"x\"",
        ];
        for line in malformed_records {
            assert!(parse_record(line).is_err(), "{line}");
        }

        let invalid_snapshots = [
            "3^done,stack=[]",
            "3^done,stack=[frame={level=\"1\",addr=\"0x1\"}]",
            "3^done,stack=[frame={level=\"0\",addr=\"not-hex\"}]",
            "3^done,stack=[frame={level=\"0\",addr=\"0x1\",unexpected=\"x\"}]",
        ];
        for line in invalid_snapshots {
            let record = parse_record(line).unwrap();
            let ParsedRecord::Result { variables, .. } = record else {
                panic!("expected result record");
            };
            assert!(parse_stack_snapshot(&variables, 2).is_err(), "{line}");
        }

        let record = parse_record(
            "3^done,stack=[frame={level=\"0\",addr=\"0x1\"},frame={level=\"1\",addr=\"0x2\"}]",
        )
        .unwrap();
        let ParsedRecord::Result { variables, .. } = record else {
            panic!("expected result record");
        };
        assert!(parse_stack_snapshot(&variables, 1).is_err());
    }

    #[test]
    fn test_options_validate_scalar_bounds_before_executable_lookup() {
        let mut options = GdbMiTestOptions {
            executable: PathBuf::from("missing-gdb"),
            version_timeout_ms: DEFAULT_GDB_VERSION_TIMEOUT_MS,
            startup_timeout_ms: DEFAULT_GDB_MI_STARTUP_TIMEOUT_MS,
            shutdown_timeout_ms: DEFAULT_GDB_MI_SHUTDOWN_TIMEOUT_MS,
        };
        options.startup_timeout_ms = MIN_GDB_MI_STARTUP_TIMEOUT_MS - 1;
        let error = validate_test_options(&options).unwrap_err();
        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert_eq!(error.details["timeout_kind"], "startup");
    }

    #[test]
    fn protocol_contract_fixes_mi2_and_keeps_the_command_set_minimal() {
        let contract = protocol_contract();
        assert_eq!(contract.interpreter, "mi2");
        assert!(!contract.initialization_files_enabled);
        assert!(contract.token_correlation_required);
        assert_eq!(contract.commands.len(), 2);
        assert_eq!(contract.commands[0].command, VERSION_COMMAND);
        assert_eq!(contract.commands[1].command, EXIT_COMMAND);
    }

    #[test]
    fn register_protocol_contract_exposes_only_the_fixed_snapshot_exchange() {
        let contract = register_protocol_contract();
        assert_eq!(contract.commands.len(), 6);
        assert_eq!(contract.commands[2].command, REGISTER_NAMES_COMMAND);
        assert_eq!(
            contract.commands[3].command,
            REGISTER_VALUES_COMMAND_PLACEHOLDER
        );
        assert_eq!(contract.commands[4].command, REMOTE_DETACH_COMMAND);
        assert_eq!(contract.commands[5].command, EXIT_COMMAND);
    }

    #[test]
    fn memory_protocol_contract_binds_the_exact_bounded_read() {
        let contract = memory_protocol_contract(Address(0x2000_0004), 8);
        assert_eq!(contract.commands.len(), 5);
        assert_eq!(
            contract.commands[2].command,
            "-data-read-memory-bytes 0x20000004 8"
        );
        assert_eq!(contract.commands[3].command, REMOTE_DETACH_COMMAND);
        assert_eq!(contract.commands[4].command, EXIT_COMMAND);
    }

    #[test]
    fn stack_protocol_contract_binds_the_exact_bounded_unfiltered_range() {
        let contract = stack_protocol_contract(8);
        assert_eq!(contract.commands.len(), 5);
        assert_eq!(
            contract.commands[2].command,
            "-stack-list-frames --no-frame-filters 0 7"
        );
        assert_eq!(contract.commands[3].command, REMOTE_DETACH_COMMAND);
        assert_eq!(contract.commands[4].command, EXIT_COMMAND);
    }
}
