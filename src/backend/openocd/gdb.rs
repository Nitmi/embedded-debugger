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
const BREAKPOINT_INSERT_TOKEN: u64 = 3;
const BREAKPOINT_DELETE_TOKEN: u64 = 4;
const BREAKPOINT_LIST_TOKEN: u64 = 5;
const BREAKPOINT_DETACH_TOKEN: u64 = 6;
const BREAKPOINT_EXIT_TOKEN: u64 = 7;
const BREAKPOINT_CLEANUP_DELETE_TOKEN: u64 = 8;
const BREAKPOINT_CLEANUP_LIST_TOKEN: u64 = 9;
const BREAKPOINT_CLEANUP_DETACH_TOKEN: u64 = 10;
const BREAKPOINT_NUMBER: u64 = 1;
const BREAKPOINT_DELETE_COMMAND: &str = "-break-delete 1";
const BREAKPOINT_LIST_COMMAND: &str = "-break-list";
const WATCHPOINT_LANGUAGE_TOKEN: u64 = 3;
const WATCHPOINT_INSERT_TOKEN: u64 = 4;
const WATCHPOINT_LIST_TOKEN: u64 = 5;
const WATCHPOINT_DELETE_TOKEN: u64 = 6;
const WATCHPOINT_LIST_AFTER_DELETE_TOKEN: u64 = 7;
const WATCHPOINT_DETACH_TOKEN: u64 = 8;
const WATCHPOINT_EXIT_TOKEN: u64 = 9;
const WATCHPOINT_CLEANUP_DELETE_TOKEN: u64 = 10;
const WATCHPOINT_CLEANUP_LIST_TOKEN: u64 = 11;
const WATCHPOINT_CLEANUP_DETACH_TOKEN: u64 = 12;
const WATCHPOINT_LANGUAGE_COMMAND: &str = "-gdb-set language c";
const WATCHPOINT_HIT_ASYNC_TOKEN: u64 = 2;
const WATCHPOINT_HIT_ALL_STOP_TOKEN: u64 = 3;
const WATCHPOINT_HIT_SELECT_TOKEN: u64 = 4;
const WATCHPOINT_HIT_LANGUAGE_TOKEN: u64 = 5;
const WATCHPOINT_HIT_INSERT_TOKEN: u64 = 6;
const WATCHPOINT_HIT_LIST_BEFORE_TOKEN: u64 = 7;
const WATCHPOINT_HIT_CONTINUE_TOKEN: u64 = 8;
const WATCHPOINT_HIT_LIST_AFTER_TOKEN: u64 = 9;
const WATCHPOINT_HIT_DELETE_TOKEN: u64 = 10;
const WATCHPOINT_HIT_LIST_EMPTY_TOKEN: u64 = 11;
const WATCHPOINT_HIT_DETACH_TOKEN: u64 = 12;
const WATCHPOINT_HIT_EXIT_TOKEN: u64 = 13;
const WATCHPOINT_HIT_CLEANUP_INTERRUPT_TOKEN: u64 = 19;
const WATCHPOINT_HIT_CLEANUP_DELETE_TOKEN: u64 = 20;
const WATCHPOINT_HIT_CLEANUP_LIST_TOKEN: u64 = 21;
const WATCHPOINT_HIT_CLEANUP_DETACH_TOKEN: u64 = 22;
const WATCHPOINT_HIT_ASYNC_COMMAND: &str = "-gdb-set mi-async on";
const WATCHPOINT_HIT_ALL_STOP_COMMAND: &str = "-gdb-set non-stop off";
const WATCHPOINT_HIT_CONTINUE_COMMAND: &str = "-exec-continue --all";
const WATCHPOINT_HIT_INTERRUPT_COMMAND: &str = "-exec-interrupt --all";
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GdbMiHardwareBreakpoint {
    pub number: u64,
    pub breakpoint_type: String,
    pub disposition: String,
    pub enabled: bool,
    pub address: Address,
    pub hit_count: u64,
    pub thread_groups: Vec<String>,
    pub original_location: Option<String>,
    pub function: Option<String>,
    pub file: Option<String>,
    pub fullname: Option<String>,
    pub line: Option<u64>,
    pub address_flags: Option<String>,
    pub at: Option<String>,
    pub what: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GdbMiBreakpointTable {
    pub reported_rows: u64,
    pub reported_columns: u64,
    pub header_columns: Vec<String>,
    pub body_entries: u64,
    pub empty: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GdbMiHardwareBreakpointRoundtrip {
    pub inserted: GdbMiHardwareBreakpoint,
    pub table_after_delete: GdbMiBreakpointTable,
    pub gdb_breakpoint_table_empty: bool,
    pub physical_comparator_state_independently_verified: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenOcdHardwareWatchpointMode {
    Read,
    Access,
}

impl OpenOcdHardwareWatchpointMode {
    fn command_flag(self) -> &'static str {
        match self {
            Self::Read => "-r",
            Self::Access => "-a",
        }
    }

    fn insertion_result_field(self) -> &'static str {
        match self {
            Self::Read => "hw-rwpt",
            Self::Access => "hw-awpt",
        }
    }

    fn breakpoint_type(self) -> &'static str {
        match self {
            Self::Read => "read watchpoint",
            Self::Access => "acc watchpoint",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GdbMiHardwareWatchpointInsertion {
    pub result_field: String,
    pub number: u64,
    pub expression: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GdbMiHardwareWatchpoint {
    pub number: u64,
    pub mode: OpenOcdHardwareWatchpointMode,
    pub breakpoint_type: String,
    pub disposition: String,
    pub enabled: bool,
    pub expression: String,
    pub hit_count: u64,
    pub thread_groups: Vec<String>,
    pub original_location: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GdbMiHardwareWatchpointTable {
    pub reported_rows: u64,
    pub reported_columns: u64,
    pub header_columns: Vec<String>,
    pub body_entries: u64,
    pub watchpoint: GdbMiHardwareWatchpoint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GdbMiHardwareWatchpointRoundtrip {
    pub inserted: GdbMiHardwareWatchpointInsertion,
    pub table_before_delete: GdbMiHardwareWatchpointTable,
    pub table_after_delete: GdbMiBreakpointTable,
    pub gdb_hardware_classification_verified: bool,
    pub gdb_breakpoint_table_empty: bool,
    pub physical_comparator_allocation_independently_verified: bool,
    pub physical_comparator_state_independently_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GdbMiHardwareWatchpointHitValue {
    pub reported_fields: Vec<String>,
    pub read: Option<String>,
    pub old: Option<String>,
    pub new: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GdbMiAsyncStopCorrelation {
    TokenlessSingleContinue,
    MatchingContinueToken,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GdbMiHardwareWatchpointHit {
    pub continue_token: u64,
    pub observed_stop_token: Option<u64>,
    pub stop_correlation: GdbMiAsyncStopCorrelation,
    pub running_notifications: u64,
    pub stop_reason: String,
    pub result_field: String,
    pub number: u64,
    pub expression: String,
    pub value: GdbMiHardwareWatchpointHitValue,
    pub frame_address: Address,
    pub frame_function: Option<String>,
    pub frame_file: Option<String>,
    pub frame_fullname: Option<String>,
    pub frame_line: Option<u64>,
    pub frame_module: Option<String>,
    pub frame_architecture: Option<String>,
    pub frame_address_flags: Option<String>,
    pub thread_id: Option<String>,
    pub stopped_threads: Option<String>,
    pub core: Option<u64>,
    pub expected_pc_start: Address,
    pub expected_pc_end_exclusive: Address,
    pub expected_pc_range_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GdbMiHardwareWatchpointHitRoundtrip {
    pub inserted: GdbMiHardwareWatchpointInsertion,
    pub table_before_continue: GdbMiHardwareWatchpointTable,
    pub hit: GdbMiHardwareWatchpointHit,
    pub table_after_hit: GdbMiHardwareWatchpointTable,
    pub table_after_delete: GdbMiBreakpointTable,
    pub gdb_hardware_classification_verified: bool,
    pub one_correlated_hit_verified: bool,
    pub post_hit_count_verified: bool,
    pub gdb_breakpoint_table_empty: bool,
    pub physical_comparator_state_independently_verified: bool,
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

pub(super) struct RemoteBreakpointExecution {
    pub endpoint: String,
    pub startup_elapsed: Duration,
    pub version_elapsed: Duration,
    pub version_result_class: String,
    pub version_stream_records: u64,
    pub connect_elapsed: Duration,
    pub connect_result_class: String,
    pub insert_elapsed: Duration,
    pub insert_result_class: String,
    pub insert_command: String,
    pub delete_elapsed: Duration,
    pub delete_result_class: String,
    pub list_elapsed: Duration,
    pub list_result_class: String,
    pub roundtrip: GdbMiHardwareBreakpointRoundtrip,
    pub detach_elapsed: Duration,
    pub detach_result_class: String,
    pub record_counts: GdbMiRecordCounts,
    pub shutdown: GdbMiShutdown,
    pub output: GdbMiOutput,
}

pub(super) struct RemoteWatchpointExecution {
    pub endpoint: String,
    pub startup_elapsed: Duration,
    pub version_elapsed: Duration,
    pub version_result_class: String,
    pub version_stream_records: u64,
    pub connect_elapsed: Duration,
    pub connect_result_class: String,
    pub language_elapsed: Duration,
    pub language_result_class: String,
    pub insert_elapsed: Duration,
    pub insert_result_class: String,
    pub insert_command: String,
    pub list_before_delete_elapsed: Duration,
    pub list_before_delete_result_class: String,
    pub delete_elapsed: Duration,
    pub delete_result_class: String,
    pub list_after_delete_elapsed: Duration,
    pub list_after_delete_result_class: String,
    pub roundtrip: GdbMiHardwareWatchpointRoundtrip,
    pub detach_elapsed: Duration,
    pub detach_result_class: String,
    pub record_counts: GdbMiRecordCounts,
    pub shutdown: GdbMiShutdown,
    pub output: GdbMiOutput,
}

pub(super) struct RemoteWatchpointHitExecution {
    pub endpoint: String,
    pub startup_elapsed: Duration,
    pub version_elapsed: Duration,
    pub version_result_class: String,
    pub version_stream_records: u64,
    pub async_elapsed: Duration,
    pub async_result_class: String,
    pub all_stop_elapsed: Duration,
    pub all_stop_result_class: String,
    pub connect_elapsed: Duration,
    pub connect_result_class: String,
    pub language_elapsed: Duration,
    pub language_result_class: String,
    pub insert_elapsed: Duration,
    pub insert_result_class: String,
    pub insert_command: String,
    pub list_before_continue_elapsed: Duration,
    pub list_before_continue_result_class: String,
    pub continue_elapsed: Duration,
    pub continue_result_class: String,
    pub hit_wait_elapsed: Duration,
    pub list_after_hit_elapsed: Duration,
    pub list_after_hit_result_class: String,
    pub delete_elapsed: Duration,
    pub delete_result_class: String,
    pub list_after_delete_elapsed: Duration,
    pub list_after_delete_result_class: String,
    pub roundtrip: GdbMiHardwareWatchpointHitRoundtrip,
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

#[derive(Debug, Clone, Copy)]
pub(super) struct RemoteWatchpointRequest {
    pub address: Address,
    pub length_bytes: u64,
    pub mode: OpenOcdHardwareWatchpointMode,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct RemoteWatchpointHitRequest {
    pub address: Address,
    pub length_bytes: u64,
    pub mode: OpenOcdHardwareWatchpointMode,
    pub expected_pc_start: Address,
    pub expected_pc_end_exclusive: Address,
    pub hit_timeout_ms: u64,
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

pub(super) fn execute_remote_breakpoint_roundtrip(
    executable: &str,
    xtensa_config: Option<&str>,
    gdb_port: u16,
    address: Address,
    startup_timeout_ms: u64,
    command_timeout_ms: u64,
    shutdown_timeout_ms: u64,
) -> Result<RemoteBreakpointExecution> {
    let endpoint = format!("127.0.0.1:{gdb_port}");
    let mut command = Command::new(executable);
    command
        .args(MI_LAUNCH_ARGUMENTS)
        .env_remove(XTENSA_GNU_CONFIG_ENV);
    if let Some(config) = xtensa_config {
        command.env(XTENSA_GNU_CONFIG_ENV, config);
    }
    let mut gdb = ManagedGdb::spawn(command, executable, BREAKPOINT_EXIT_TOKEN)?;
    let lifecycle = match gdb.run_breakpoint_lifecycle(
        &endpoint,
        address,
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
            "hardware-breakpoint GDB/MI process did not complete a graceful shutdown",
            json!({"endpoint": endpoint}),
            &shutdown,
            &output,
        ));
    }
    validate_complete_output(&output).map_err(|message| {
        protocol_error_with_lifecycle(message, json!({"endpoint": endpoint}), &shutdown, &output)
    })?;

    Ok(RemoteBreakpointExecution {
        endpoint,
        startup_elapsed: lifecycle.startup_elapsed,
        version_elapsed: lifecycle.version_elapsed,
        version_result_class: lifecycle.version_result_class,
        version_stream_records: lifecycle.version_stream_records,
        connect_elapsed: lifecycle.connect_elapsed,
        connect_result_class: lifecycle.connect_result_class,
        insert_elapsed: lifecycle.insert_elapsed,
        insert_result_class: lifecycle.insert_result_class,
        insert_command: lifecycle.insert_command,
        delete_elapsed: lifecycle.delete_elapsed,
        delete_result_class: lifecycle.delete_result_class,
        list_elapsed: lifecycle.list_elapsed,
        list_result_class: lifecycle.list_result_class,
        roundtrip: lifecycle.roundtrip,
        detach_elapsed: lifecycle.detach_elapsed,
        detach_result_class: lifecycle.detach_result_class,
        record_counts,
        shutdown,
        output,
    })
}

pub(super) fn execute_remote_watchpoint_roundtrip(
    executable: &str,
    xtensa_config: Option<&str>,
    gdb_port: u16,
    request: RemoteWatchpointRequest,
    startup_timeout_ms: u64,
    command_timeout_ms: u64,
    shutdown_timeout_ms: u64,
) -> Result<RemoteWatchpointExecution> {
    let endpoint = format!("127.0.0.1:{gdb_port}");
    let mut command = Command::new(executable);
    command
        .args(MI_LAUNCH_ARGUMENTS)
        .env_remove(XTENSA_GNU_CONFIG_ENV);
    if let Some(config) = xtensa_config {
        command.env(XTENSA_GNU_CONFIG_ENV, config);
    }
    let mut gdb = ManagedGdb::spawn(command, executable, WATCHPOINT_EXIT_TOKEN)?;
    let lifecycle = match gdb.run_watchpoint_lifecycle(
        &endpoint,
        request,
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
            "hardware-watchpoint GDB/MI process did not complete a graceful shutdown",
            json!({"endpoint": endpoint}),
            &shutdown,
            &output,
        ));
    }
    validate_complete_output(&output).map_err(|message| {
        protocol_error_with_lifecycle(message, json!({"endpoint": endpoint}), &shutdown, &output)
    })?;

    Ok(RemoteWatchpointExecution {
        endpoint,
        startup_elapsed: lifecycle.startup_elapsed,
        version_elapsed: lifecycle.version_elapsed,
        version_result_class: lifecycle.version_result_class,
        version_stream_records: lifecycle.version_stream_records,
        connect_elapsed: lifecycle.connect_elapsed,
        connect_result_class: lifecycle.connect_result_class,
        language_elapsed: lifecycle.language_elapsed,
        language_result_class: lifecycle.language_result_class,
        insert_elapsed: lifecycle.insert_elapsed,
        insert_result_class: lifecycle.insert_result_class,
        insert_command: lifecycle.insert_command,
        list_before_delete_elapsed: lifecycle.list_before_delete_elapsed,
        list_before_delete_result_class: lifecycle.list_before_delete_result_class,
        delete_elapsed: lifecycle.delete_elapsed,
        delete_result_class: lifecycle.delete_result_class,
        list_after_delete_elapsed: lifecycle.list_after_delete_elapsed,
        list_after_delete_result_class: lifecycle.list_after_delete_result_class,
        roundtrip: lifecycle.roundtrip,
        detach_elapsed: lifecycle.detach_elapsed,
        detach_result_class: lifecycle.detach_result_class,
        record_counts,
        shutdown,
        output,
    })
}

pub(super) fn execute_remote_watchpoint_hit(
    executable: &str,
    xtensa_config: Option<&str>,
    gdb_port: u16,
    request: RemoteWatchpointHitRequest,
    startup_timeout_ms: u64,
    command_timeout_ms: u64,
    shutdown_timeout_ms: u64,
) -> Result<RemoteWatchpointHitExecution> {
    let endpoint = format!("127.0.0.1:{gdb_port}");
    let mut command = Command::new(executable);
    command
        .args(MI_LAUNCH_ARGUMENTS)
        .env_remove(XTENSA_GNU_CONFIG_ENV);
    if let Some(config) = xtensa_config {
        command.env(XTENSA_GNU_CONFIG_ENV, config);
    }
    let mut gdb = ManagedGdb::spawn(command, executable, WATCHPOINT_HIT_EXIT_TOKEN)?;
    let lifecycle = match gdb.run_watchpoint_hit_lifecycle(
        &endpoint,
        request,
        Duration::from_millis(startup_timeout_ms),
        Duration::from_millis(command_timeout_ms),
        Duration::from_millis(shutdown_timeout_ms),
    ) {
        Ok(lifecycle) => lifecycle,
        Err(failure) => return Err(finalize_failure(gdb, failure, shutdown_timeout_ms)),
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
            "hardware-watchpoint hit GDB/MI process did not complete a graceful shutdown",
            json!({"endpoint": endpoint}),
            &shutdown,
            &output,
        ));
    }
    validate_complete_output(&output).map_err(|message| {
        protocol_error_with_lifecycle(message, json!({"endpoint": endpoint}), &shutdown, &output)
    })?;

    Ok(RemoteWatchpointHitExecution {
        endpoint,
        startup_elapsed: lifecycle.startup_elapsed,
        version_elapsed: lifecycle.version_elapsed,
        version_result_class: lifecycle.version_result_class,
        version_stream_records: lifecycle.version_stream_records,
        async_elapsed: lifecycle.async_elapsed,
        async_result_class: lifecycle.async_result_class,
        all_stop_elapsed: lifecycle.all_stop_elapsed,
        all_stop_result_class: lifecycle.all_stop_result_class,
        connect_elapsed: lifecycle.connect_elapsed,
        connect_result_class: lifecycle.connect_result_class,
        language_elapsed: lifecycle.language_elapsed,
        language_result_class: lifecycle.language_result_class,
        insert_elapsed: lifecycle.insert_elapsed,
        insert_result_class: lifecycle.insert_result_class,
        insert_command: lifecycle.insert_command,
        list_before_continue_elapsed: lifecycle.list_before_continue_elapsed,
        list_before_continue_result_class: lifecycle.list_before_continue_result_class,
        continue_elapsed: lifecycle.continue_elapsed,
        continue_result_class: lifecycle.continue_result_class,
        hit_wait_elapsed: lifecycle.hit_wait_elapsed,
        list_after_hit_elapsed: lifecycle.list_after_hit_elapsed,
        list_after_hit_result_class: lifecycle.list_after_hit_result_class,
        delete_elapsed: lifecycle.delete_elapsed,
        delete_result_class: lifecycle.delete_result_class,
        list_after_delete_elapsed: lifecycle.list_after_delete_elapsed,
        list_after_delete_result_class: lifecycle.list_after_delete_result_class,
        roundtrip: lifecycle.roundtrip,
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

pub(super) fn breakpoint_protocol_contract(address: Address) -> GdbMiProtocol {
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
                token: BREAKPOINT_INSERT_TOKEN,
                command: breakpoint_insert_command(address),
                expected_result_class: "done".to_string(),
            },
            GdbMiPlannedCommand {
                token: BREAKPOINT_DELETE_TOKEN,
                command: BREAKPOINT_DELETE_COMMAND.to_string(),
                expected_result_class: "done".to_string(),
            },
            GdbMiPlannedCommand {
                token: BREAKPOINT_LIST_TOKEN,
                command: BREAKPOINT_LIST_COMMAND.to_string(),
                expected_result_class: "done".to_string(),
            },
            GdbMiPlannedCommand {
                token: BREAKPOINT_DETACH_TOKEN,
                command: REMOTE_DETACH_COMMAND.to_string(),
                expected_result_class: "done".to_string(),
            },
            GdbMiPlannedCommand {
                token: BREAKPOINT_EXIT_TOKEN,
                command: EXIT_COMMAND.to_string(),
                expected_result_class: "exit".to_string(),
            },
        ],
    }
}

pub(super) fn breakpoint_failure_cleanup_contract() -> Vec<GdbMiPlannedCommand> {
    vec![
        GdbMiPlannedCommand {
            token: BREAKPOINT_CLEANUP_DELETE_TOKEN,
            command: BREAKPOINT_DELETE_COMMAND.to_string(),
            expected_result_class: "done_or_error_then_verify_table".to_string(),
        },
        GdbMiPlannedCommand {
            token: BREAKPOINT_CLEANUP_LIST_TOKEN,
            command: BREAKPOINT_LIST_COMMAND.to_string(),
            expected_result_class: "done".to_string(),
        },
        GdbMiPlannedCommand {
            token: BREAKPOINT_CLEANUP_DETACH_TOKEN,
            command: REMOTE_DETACH_COMMAND.to_string(),
            expected_result_class: "done".to_string(),
        },
    ]
}

pub(super) fn watchpoint_protocol_contract(
    address: Address,
    length_bytes: u64,
    mode: OpenOcdHardwareWatchpointMode,
) -> GdbMiProtocol {
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
                token: WATCHPOINT_LANGUAGE_TOKEN,
                command: WATCHPOINT_LANGUAGE_COMMAND.to_string(),
                expected_result_class: "done".to_string(),
            },
            GdbMiPlannedCommand {
                token: WATCHPOINT_INSERT_TOKEN,
                command: watchpoint_insert_command(address, length_bytes, mode),
                expected_result_class: "done".to_string(),
            },
            GdbMiPlannedCommand {
                token: WATCHPOINT_LIST_TOKEN,
                command: BREAKPOINT_LIST_COMMAND.to_string(),
                expected_result_class: "done".to_string(),
            },
            GdbMiPlannedCommand {
                token: WATCHPOINT_DELETE_TOKEN,
                command: BREAKPOINT_DELETE_COMMAND.to_string(),
                expected_result_class: "done".to_string(),
            },
            GdbMiPlannedCommand {
                token: WATCHPOINT_LIST_AFTER_DELETE_TOKEN,
                command: BREAKPOINT_LIST_COMMAND.to_string(),
                expected_result_class: "done".to_string(),
            },
            GdbMiPlannedCommand {
                token: WATCHPOINT_DETACH_TOKEN,
                command: REMOTE_DETACH_COMMAND.to_string(),
                expected_result_class: "done".to_string(),
            },
            GdbMiPlannedCommand {
                token: WATCHPOINT_EXIT_TOKEN,
                command: EXIT_COMMAND.to_string(),
                expected_result_class: "exit".to_string(),
            },
        ],
    }
}

pub(super) fn watchpoint_failure_cleanup_contract() -> Vec<GdbMiPlannedCommand> {
    vec![
        GdbMiPlannedCommand {
            token: WATCHPOINT_CLEANUP_DELETE_TOKEN,
            command: BREAKPOINT_DELETE_COMMAND.to_string(),
            expected_result_class: "done_or_error_then_verify_table".to_string(),
        },
        GdbMiPlannedCommand {
            token: WATCHPOINT_CLEANUP_LIST_TOKEN,
            command: BREAKPOINT_LIST_COMMAND.to_string(),
            expected_result_class: "done".to_string(),
        },
        GdbMiPlannedCommand {
            token: WATCHPOINT_CLEANUP_DETACH_TOKEN,
            command: REMOTE_DETACH_COMMAND.to_string(),
            expected_result_class: "done".to_string(),
        },
    ]
}

pub(super) fn watchpoint_hit_protocol_contract(
    address: Address,
    length_bytes: u64,
    mode: OpenOcdHardwareWatchpointMode,
) -> GdbMiProtocol {
    let command = |token, command: &str, expected: &str| GdbMiPlannedCommand {
        token,
        command: command.to_string(),
        expected_result_class: expected.to_string(),
    };
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
            command(VERSION_TOKEN, VERSION_COMMAND, "done"),
            command(
                WATCHPOINT_HIT_ASYNC_TOKEN,
                WATCHPOINT_HIT_ASYNC_COMMAND,
                "done",
            ),
            command(
                WATCHPOINT_HIT_ALL_STOP_TOKEN,
                WATCHPOINT_HIT_ALL_STOP_COMMAND,
                "done",
            ),
            command(
                WATCHPOINT_HIT_SELECT_TOKEN,
                REMOTE_SELECT_COMMAND_PLACEHOLDER,
                "connected",
            ),
            command(
                WATCHPOINT_HIT_LANGUAGE_TOKEN,
                WATCHPOINT_LANGUAGE_COMMAND,
                "done",
            ),
            command(
                WATCHPOINT_HIT_INSERT_TOKEN,
                &watchpoint_insert_command(address, length_bytes, mode),
                "done",
            ),
            command(
                WATCHPOINT_HIT_LIST_BEFORE_TOKEN,
                BREAKPOINT_LIST_COMMAND,
                "done",
            ),
            command(
                WATCHPOINT_HIT_CONTINUE_TOKEN,
                WATCHPOINT_HIT_CONTINUE_COMMAND,
                "running_then_one_correlated_watchpoint_stop",
            ),
            command(
                WATCHPOINT_HIT_LIST_AFTER_TOKEN,
                BREAKPOINT_LIST_COMMAND,
                "done",
            ),
            command(
                WATCHPOINT_HIT_DELETE_TOKEN,
                BREAKPOINT_DELETE_COMMAND,
                "done",
            ),
            command(
                WATCHPOINT_HIT_LIST_EMPTY_TOKEN,
                BREAKPOINT_LIST_COMMAND,
                "done",
            ),
            command(WATCHPOINT_HIT_DETACH_TOKEN, REMOTE_DETACH_COMMAND, "done"),
            command(WATCHPOINT_HIT_EXIT_TOKEN, EXIT_COMMAND, "exit"),
        ],
    }
}

pub(super) fn watchpoint_hit_failure_cleanup_contract() -> Vec<GdbMiPlannedCommand> {
    vec![
        GdbMiPlannedCommand {
            token: WATCHPOINT_HIT_CLEANUP_INTERRUPT_TOKEN,
            command: WATCHPOINT_HIT_INTERRUPT_COMMAND.to_string(),
            expected_result_class:
                "done_then_tokenless_or_matching_continue_token_sigint_stop_when_running"
                    .to_string(),
        },
        GdbMiPlannedCommand {
            token: WATCHPOINT_HIT_CLEANUP_DELETE_TOKEN,
            command: BREAKPOINT_DELETE_COMMAND.to_string(),
            expected_result_class: "done_or_error_then_verify_table".to_string(),
        },
        GdbMiPlannedCommand {
            token: WATCHPOINT_HIT_CLEANUP_LIST_TOKEN,
            command: BREAKPOINT_LIST_COMMAND.to_string(),
            expected_result_class: "done".to_string(),
        },
        GdbMiPlannedCommand {
            token: WATCHPOINT_HIT_CLEANUP_DETACH_TOKEN,
            command: REMOTE_DETACH_COMMAND.to_string(),
            expected_result_class: "done".to_string(),
        },
    ]
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

    fn run_breakpoint_lifecycle(
        &mut self,
        endpoint: &str,
        address: Address,
        startup_timeout: Duration,
        command_timeout: Duration,
        shutdown_timeout: Duration,
    ) -> std::result::Result<BreakpointLifecycleSuccess, LifecycleFailure> {
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
        let connect_result_class = match self.wait_for_result(
            REMOTE_SELECT_TOKEN,
            "connected",
            connect_started + command_timeout,
        ) {
            Ok(class) => class,
            Err(failure) => {
                return Err(self.with_breakpoint_detach_attempt(failure, command_timeout));
            }
        };
        let connect_elapsed = connect_started.elapsed();

        let roundtrip = match self.run_breakpoint_roundtrip(address, command_timeout) {
            Ok(roundtrip) => roundtrip,
            Err(failure) => {
                return Err(
                    self.with_breakpoint_cleanup_and_detach_attempt(failure, command_timeout)
                );
            }
        };

        let detach_started = Instant::now();
        self.send_command(BREAKPOINT_DETACH_TOKEN, REMOTE_DETACH_COMMAND)?;
        let detach_result_class = self.wait_for_result(
            BREAKPOINT_DETACH_TOKEN,
            "done",
            detach_started + command_timeout,
        )?;
        let detach_elapsed = detach_started.elapsed();

        self.send_command(BREAKPOINT_EXIT_TOKEN, EXIT_COMMAND)?;
        let shutdown_deadline = Instant::now() + shutdown_timeout;
        self.wait_for_result(BREAKPOINT_EXIT_TOKEN, "exit", shutdown_deadline)?;
        self.wait_for_exit(shutdown_deadline)?;

        Ok(BreakpointLifecycleSuccess {
            startup_elapsed,
            version_elapsed,
            version_result_class,
            version_stream_records,
            connect_elapsed,
            connect_result_class,
            insert_elapsed: roundtrip.insert_elapsed,
            insert_result_class: roundtrip.insert_result_class,
            insert_command: roundtrip.insert_command,
            delete_elapsed: roundtrip.delete_elapsed,
            delete_result_class: roundtrip.delete_result_class,
            list_elapsed: roundtrip.list_elapsed,
            list_result_class: roundtrip.list_result_class,
            roundtrip: roundtrip.roundtrip,
            detach_elapsed,
            detach_result_class,
        })
    }

    fn run_breakpoint_roundtrip(
        &mut self,
        address: Address,
        command_timeout: Duration,
    ) -> std::result::Result<BreakpointRoundtripSuccess, LifecycleFailure> {
        let insert_command = breakpoint_insert_command(address);
        let insert_started = Instant::now();
        self.send_command(BREAKPOINT_INSERT_TOKEN, &insert_command)?;
        let insert_result = self.wait_for_result_record(
            BREAKPOINT_INSERT_TOKEN,
            "done",
            insert_started + command_timeout,
        )?;
        let insert_elapsed = insert_started.elapsed();
        let inserted = parse_hardware_breakpoint(&insert_result.variables, address)?;

        let delete_started = Instant::now();
        self.send_command(BREAKPOINT_DELETE_TOKEN, BREAKPOINT_DELETE_COMMAND)?;
        let delete_result_class = self.wait_for_result(
            BREAKPOINT_DELETE_TOKEN,
            "done",
            delete_started + command_timeout,
        )?;
        let delete_elapsed = delete_started.elapsed();

        let list_started = Instant::now();
        self.send_command(BREAKPOINT_LIST_TOKEN, BREAKPOINT_LIST_COMMAND)?;
        let list_result = self.wait_for_result_record(
            BREAKPOINT_LIST_TOKEN,
            "done",
            list_started + command_timeout,
        )?;
        let list_elapsed = list_started.elapsed();
        let table_after_delete = parse_empty_breakpoint_table(&list_result.variables)?;

        Ok(BreakpointRoundtripSuccess {
            insert_elapsed,
            insert_result_class: insert_result.class,
            insert_command,
            delete_elapsed,
            delete_result_class,
            list_elapsed,
            list_result_class: list_result.class,
            roundtrip: GdbMiHardwareBreakpointRoundtrip {
                inserted,
                table_after_delete,
                gdb_breakpoint_table_empty: true,
                physical_comparator_state_independently_verified: false,
            },
        })
    }

    fn with_breakpoint_cleanup_and_detach_attempt(
        &mut self,
        mut failure: LifecycleFailure,
        command_timeout: Duration,
    ) -> LifecycleFailure {
        let cleanup_started = Instant::now();
        let delete_started = Instant::now();
        let delete = self
            .send_command(BREAKPOINT_CLEANUP_DELETE_TOKEN, BREAKPOINT_DELETE_COMMAND)
            .and_then(|()| {
                self.wait_for_any_result_record(
                    BREAKPOINT_CLEANUP_DELETE_TOKEN,
                    delete_started + command_timeout,
                )
            });
        let delete_evidence = match delete {
            Ok(result) => json!({
                "attempted": true,
                "token": BREAKPOINT_CLEANUP_DELETE_TOKEN,
                "command": BREAKPOINT_DELETE_COMMAND,
                "result_class": result.class,
                "elapsed_ms": duration_ms(delete_started.elapsed()),
            }),
            Err(delete_failure) => json!({
                "attempted": true,
                "token": BREAKPOINT_CLEANUP_DELETE_TOKEN,
                "command": BREAKPOINT_DELETE_COMMAND,
                "elapsed_ms": duration_ms(delete_started.elapsed()),
                "failure": lifecycle_failure_value(&delete_failure),
            }),
        };

        let list_started = Instant::now();
        let list = self
            .send_command(BREAKPOINT_CLEANUP_LIST_TOKEN, BREAKPOINT_LIST_COMMAND)
            .and_then(|()| {
                self.wait_for_result_record(
                    BREAKPOINT_CLEANUP_LIST_TOKEN,
                    "done",
                    list_started + command_timeout,
                )
            })
            .and_then(|result| {
                parse_empty_breakpoint_table(&result.variables).map(|table| (result.class, table))
            });
        let (table_empty, list_evidence) = match list {
            Ok((result_class, table)) => (
                table.empty,
                json!({
                    "attempted": true,
                    "token": BREAKPOINT_CLEANUP_LIST_TOKEN,
                    "command": BREAKPOINT_LIST_COMMAND,
                    "result_class": result_class,
                    "table": table,
                    "elapsed_ms": duration_ms(list_started.elapsed()),
                }),
            ),
            Err(list_failure) => (
                false,
                json!({
                    "attempted": true,
                    "token": BREAKPOINT_CLEANUP_LIST_TOKEN,
                    "command": BREAKPOINT_LIST_COMMAND,
                    "elapsed_ms": duration_ms(list_started.elapsed()),
                    "failure": lifecycle_failure_value(&list_failure),
                }),
            ),
        };

        let detach_started = Instant::now();
        let detach = self
            .send_command(BREAKPOINT_CLEANUP_DETACH_TOKEN, REMOTE_DETACH_COMMAND)
            .and_then(|()| {
                self.wait_for_result(
                    BREAKPOINT_CLEANUP_DETACH_TOKEN,
                    "done",
                    detach_started + command_timeout,
                )
            });
        let (detach_complete, detach_evidence) = match detach {
            Ok(result_class) => (
                true,
                json!({
                    "attempted": true,
                    "complete": true,
                    "token": BREAKPOINT_CLEANUP_DETACH_TOKEN,
                    "command": REMOTE_DETACH_COMMAND,
                    "result_class": result_class,
                    "elapsed_ms": duration_ms(detach_started.elapsed()),
                }),
            ),
            Err(detach_failure) => (
                false,
                json!({
                    "attempted": true,
                    "complete": false,
                    "token": BREAKPOINT_CLEANUP_DETACH_TOKEN,
                    "command": REMOTE_DETACH_COMMAND,
                    "elapsed_ms": duration_ms(detach_started.elapsed()),
                    "failure": lifecycle_failure_value(&detach_failure),
                }),
            ),
        };

        let mut details = failure.details.as_object().cloned().unwrap_or_default();
        details.insert(
            "breakpoint_cleanup".to_string(),
            json!({
                "attempted": true,
                "delete": delete_evidence,
                "list": list_evidence,
                "gdb_breakpoint_table_empty": table_empty,
                "physical_comparator_state_independently_verified": false,
                "complete": table_empty && detach_complete,
                "elapsed_ms": duration_ms(cleanup_started.elapsed()),
            }),
        );
        details.insert("cleanup_detach".to_string(), detach_evidence);
        failure.details = Value::Object(details);
        failure
    }

    fn with_breakpoint_detach_attempt(
        &mut self,
        mut failure: LifecycleFailure,
        command_timeout: Duration,
    ) -> LifecycleFailure {
        let started = Instant::now();
        let attempt = self
            .send_command(BREAKPOINT_CLEANUP_DETACH_TOKEN, REMOTE_DETACH_COMMAND)
            .and_then(|()| {
                self.wait_for_result(
                    BREAKPOINT_CLEANUP_DETACH_TOKEN,
                    "done",
                    started + command_timeout,
                )
            });
        let evidence = match attempt {
            Ok(result_class) => json!({
                "attempted": true,
                "complete": true,
                "token": BREAKPOINT_CLEANUP_DETACH_TOKEN,
                "command": REMOTE_DETACH_COMMAND,
                "result_class": result_class,
                "elapsed_ms": duration_ms(started.elapsed()),
            }),
            Err(detach_failure) => json!({
                "attempted": true,
                "complete": false,
                "token": BREAKPOINT_CLEANUP_DETACH_TOKEN,
                "command": REMOTE_DETACH_COMMAND,
                "elapsed_ms": duration_ms(started.elapsed()),
                "failure": lifecycle_failure_value(&detach_failure),
            }),
        };
        let mut details = failure.details.as_object().cloned().unwrap_or_default();
        details.insert("cleanup_detach".to_string(), evidence);
        details.insert(
            "breakpoint_cleanup".to_string(),
            json!({
                "attempted": false,
                "required": false,
                "complete": true,
            }),
        );
        failure.details = Value::Object(details);
        failure
    }

    fn run_watchpoint_lifecycle(
        &mut self,
        endpoint: &str,
        request: RemoteWatchpointRequest,
        startup_timeout: Duration,
        command_timeout: Duration,
        shutdown_timeout: Duration,
    ) -> std::result::Result<WatchpointLifecycleSuccess, LifecycleFailure> {
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
        let connect_result_class = match self.wait_for_result(
            REMOTE_SELECT_TOKEN,
            "connected",
            connect_started + command_timeout,
        ) {
            Ok(class) => class,
            Err(failure) => {
                return Err(self.with_watchpoint_detach_attempt(failure, command_timeout));
            }
        };
        let connect_elapsed = connect_started.elapsed();

        let language_started = Instant::now();
        if let Err(failure) =
            self.send_command(WATCHPOINT_LANGUAGE_TOKEN, WATCHPOINT_LANGUAGE_COMMAND)
        {
            return Err(self.with_watchpoint_detach_attempt(failure, command_timeout));
        }
        let language_result_class = match self.wait_for_result(
            WATCHPOINT_LANGUAGE_TOKEN,
            "done",
            language_started + command_timeout,
        ) {
            Ok(class) => class,
            Err(failure) => {
                return Err(self.with_watchpoint_detach_attempt(failure, command_timeout));
            }
        };
        let language_elapsed = language_started.elapsed();

        let roundtrip = match self.run_watchpoint_roundtrip(
            request.address,
            request.length_bytes,
            request.mode,
            command_timeout,
        ) {
            Ok(roundtrip) => roundtrip,
            Err(failure) => {
                return Err(
                    self.with_watchpoint_cleanup_and_detach_attempt(failure, command_timeout)
                );
            }
        };

        let detach_started = Instant::now();
        self.send_command(WATCHPOINT_DETACH_TOKEN, REMOTE_DETACH_COMMAND)?;
        let detach_result_class = self.wait_for_result(
            WATCHPOINT_DETACH_TOKEN,
            "done",
            detach_started + command_timeout,
        )?;
        let detach_elapsed = detach_started.elapsed();

        self.send_command(WATCHPOINT_EXIT_TOKEN, EXIT_COMMAND)?;
        let shutdown_deadline = Instant::now() + shutdown_timeout;
        self.wait_for_result(WATCHPOINT_EXIT_TOKEN, "exit", shutdown_deadline)?;
        self.wait_for_exit(shutdown_deadline)?;

        Ok(WatchpointLifecycleSuccess {
            startup_elapsed,
            version_elapsed,
            version_result_class,
            version_stream_records,
            connect_elapsed,
            connect_result_class,
            language_elapsed,
            language_result_class,
            insert_elapsed: roundtrip.insert_elapsed,
            insert_result_class: roundtrip.insert_result_class,
            insert_command: roundtrip.insert_command,
            list_before_delete_elapsed: roundtrip.list_before_delete_elapsed,
            list_before_delete_result_class: roundtrip.list_before_delete_result_class,
            delete_elapsed: roundtrip.delete_elapsed,
            delete_result_class: roundtrip.delete_result_class,
            list_after_delete_elapsed: roundtrip.list_after_delete_elapsed,
            list_after_delete_result_class: roundtrip.list_after_delete_result_class,
            roundtrip: roundtrip.roundtrip,
            detach_elapsed,
            detach_result_class,
        })
    }

    fn run_watchpoint_hit_lifecycle(
        &mut self,
        endpoint: &str,
        request: RemoteWatchpointHitRequest,
        startup_timeout: Duration,
        command_timeout: Duration,
        shutdown_timeout: Duration,
    ) -> std::result::Result<WatchpointHitLifecycleSuccess, LifecycleFailure> {
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

        let async_started = Instant::now();
        self.send_command(WATCHPOINT_HIT_ASYNC_TOKEN, WATCHPOINT_HIT_ASYNC_COMMAND)?;
        let async_result_class = self.wait_for_result(
            WATCHPOINT_HIT_ASYNC_TOKEN,
            "done",
            async_started + command_timeout,
        )?;
        let async_elapsed = async_started.elapsed();

        let all_stop_started = Instant::now();
        self.send_command(
            WATCHPOINT_HIT_ALL_STOP_TOKEN,
            WATCHPOINT_HIT_ALL_STOP_COMMAND,
        )?;
        let all_stop_result_class = self.wait_for_result(
            WATCHPOINT_HIT_ALL_STOP_TOKEN,
            "done",
            all_stop_started + command_timeout,
        )?;
        let all_stop_elapsed = all_stop_started.elapsed();

        let connect_command = format!("-target-select remote {endpoint}");
        let connect_started = Instant::now();
        if let Err(failure) = self.send_command(WATCHPOINT_HIT_SELECT_TOKEN, &connect_command) {
            return Err(self.with_watchpoint_hit_detach_attempt(failure, command_timeout));
        }
        let connect_result_class = match self.wait_for_result(
            WATCHPOINT_HIT_SELECT_TOKEN,
            "connected",
            connect_started + command_timeout,
        ) {
            Ok(class) => class,
            Err(failure) => {
                return Err(self.with_watchpoint_hit_detach_attempt(failure, command_timeout));
            }
        };
        let connect_elapsed = connect_started.elapsed();

        let language_started = Instant::now();
        if let Err(failure) =
            self.send_command(WATCHPOINT_HIT_LANGUAGE_TOKEN, WATCHPOINT_LANGUAGE_COMMAND)
        {
            return Err(self.with_watchpoint_hit_detach_attempt(failure, command_timeout));
        }
        let language_result_class = match self.wait_for_result(
            WATCHPOINT_HIT_LANGUAGE_TOKEN,
            "done",
            language_started + command_timeout,
        ) {
            Ok(class) => class,
            Err(failure) => {
                return Err(self.with_watchpoint_hit_detach_attempt(failure, command_timeout));
            }
        };
        let language_elapsed = language_started.elapsed();

        let expression = watchpoint_expression(request.address, request.length_bytes);
        let insert_command =
            watchpoint_insert_command(request.address, request.length_bytes, request.mode);
        let insert_started = Instant::now();
        if let Err(failure) = self.send_command(WATCHPOINT_HIT_INSERT_TOKEN, &insert_command) {
            return Err(self.with_watchpoint_hit_cleanup(
                failure,
                WatchpointHitCleanupState::Stopped,
                command_timeout,
            ));
        }
        let insert_result = match self.wait_for_result_record(
            WATCHPOINT_HIT_INSERT_TOKEN,
            "done",
            insert_started + command_timeout,
        ) {
            Ok(result) => result,
            Err(failure) => {
                return Err(self.with_watchpoint_hit_cleanup(
                    failure,
                    WatchpointHitCleanupState::Stopped,
                    command_timeout,
                ));
            }
        };
        let insert_elapsed = insert_started.elapsed();
        let inserted = match parse_hardware_watchpoint_insertion(
            &insert_result.variables,
            &expression,
            request.mode,
        ) {
            Ok(inserted) => inserted,
            Err(failure) => {
                return Err(self.with_watchpoint_hit_cleanup(
                    failure,
                    WatchpointHitCleanupState::Stopped,
                    command_timeout,
                ));
            }
        };

        let list_before_continue_started = Instant::now();
        if let Err(failure) =
            self.send_command(WATCHPOINT_HIT_LIST_BEFORE_TOKEN, BREAKPOINT_LIST_COMMAND)
        {
            return Err(self.with_watchpoint_hit_cleanup(
                failure,
                WatchpointHitCleanupState::Stopped,
                command_timeout,
            ));
        }
        let list_before_continue_result = match self.wait_for_result_record(
            WATCHPOINT_HIT_LIST_BEFORE_TOKEN,
            "done",
            list_before_continue_started + command_timeout,
        ) {
            Ok(result) => result,
            Err(failure) => {
                return Err(self.with_watchpoint_hit_cleanup(
                    failure,
                    WatchpointHitCleanupState::Stopped,
                    command_timeout,
                ));
            }
        };
        let list_before_continue_elapsed = list_before_continue_started.elapsed();
        let table_before_continue = match parse_hardware_watchpoint_table(
            &list_before_continue_result.variables,
            &expression,
            request.mode,
        ) {
            Ok(table) => table,
            Err(failure) => {
                return Err(self.with_watchpoint_hit_cleanup(
                    failure,
                    WatchpointHitCleanupState::Stopped,
                    command_timeout,
                ));
            }
        };

        let hit = match self.run_watchpoint_hit_wait(
            &expression,
            request,
            command_timeout,
            Duration::from_millis(request.hit_timeout_ms),
        ) {
            Ok(hit) => hit,
            Err((failure, state)) => {
                return Err(self.with_watchpoint_hit_cleanup(failure, state, command_timeout));
            }
        };

        let list_after_hit_started = Instant::now();
        if let Err(failure) =
            self.send_command(WATCHPOINT_HIT_LIST_AFTER_TOKEN, BREAKPOINT_LIST_COMMAND)
        {
            return Err(self.with_watchpoint_hit_cleanup(
                failure,
                WatchpointHitCleanupState::Stopped,
                command_timeout,
            ));
        }
        let list_after_hit_result = match self.wait_for_result_record(
            WATCHPOINT_HIT_LIST_AFTER_TOKEN,
            "done",
            list_after_hit_started + command_timeout,
        ) {
            Ok(result) => result,
            Err(failure) => {
                return Err(self.with_watchpoint_hit_cleanup(
                    failure,
                    WatchpointHitCleanupState::Stopped,
                    command_timeout,
                ));
            }
        };
        let list_after_hit_elapsed = list_after_hit_started.elapsed();
        let table_after_hit = match parse_hardware_watchpoint_table_with_hit_count(
            &list_after_hit_result.variables,
            &expression,
            request.mode,
            1,
        ) {
            Ok(table) => table,
            Err(failure) => {
                return Err(self.with_watchpoint_hit_cleanup(
                    failure,
                    WatchpointHitCleanupState::Stopped,
                    command_timeout,
                ));
            }
        };

        let delete_started = Instant::now();
        if let Err(failure) =
            self.send_command(WATCHPOINT_HIT_DELETE_TOKEN, BREAKPOINT_DELETE_COMMAND)
        {
            return Err(self.with_watchpoint_hit_cleanup(
                failure,
                WatchpointHitCleanupState::Stopped,
                command_timeout,
            ));
        }
        let delete_result_class = match self.wait_for_result(
            WATCHPOINT_HIT_DELETE_TOKEN,
            "done",
            delete_started + command_timeout,
        ) {
            Ok(class) => class,
            Err(failure) => {
                return Err(self.with_watchpoint_hit_cleanup(
                    failure,
                    WatchpointHitCleanupState::Stopped,
                    command_timeout,
                ));
            }
        };
        let delete_elapsed = delete_started.elapsed();

        let list_after_delete_started = Instant::now();
        if let Err(failure) =
            self.send_command(WATCHPOINT_HIT_LIST_EMPTY_TOKEN, BREAKPOINT_LIST_COMMAND)
        {
            return Err(self.with_watchpoint_hit_cleanup(
                failure,
                WatchpointHitCleanupState::Stopped,
                command_timeout,
            ));
        }
        let list_after_delete_result = match self.wait_for_result_record(
            WATCHPOINT_HIT_LIST_EMPTY_TOKEN,
            "done",
            list_after_delete_started + command_timeout,
        ) {
            Ok(result) => result,
            Err(failure) => {
                return Err(self.with_watchpoint_hit_cleanup(
                    failure,
                    WatchpointHitCleanupState::Stopped,
                    command_timeout,
                ));
            }
        };
        let list_after_delete_elapsed = list_after_delete_started.elapsed();
        let table_after_delete =
            match parse_empty_breakpoint_table(&list_after_delete_result.variables) {
                Ok(table) => table,
                Err(failure) => {
                    return Err(self.with_watchpoint_hit_cleanup(
                        failure,
                        WatchpointHitCleanupState::Stopped,
                        command_timeout,
                    ));
                }
            };

        let detach_started = Instant::now();
        self.send_command(WATCHPOINT_HIT_DETACH_TOKEN, REMOTE_DETACH_COMMAND)?;
        let detach_result_class = self.wait_for_result(
            WATCHPOINT_HIT_DETACH_TOKEN,
            "done",
            detach_started + command_timeout,
        )?;
        let detach_elapsed = detach_started.elapsed();

        self.send_command(WATCHPOINT_HIT_EXIT_TOKEN, EXIT_COMMAND)?;
        let shutdown_deadline = Instant::now() + shutdown_timeout;
        self.wait_for_result(WATCHPOINT_HIT_EXIT_TOKEN, "exit", shutdown_deadline)?;
        self.wait_for_exit(shutdown_deadline)?;

        Ok(WatchpointHitLifecycleSuccess {
            startup_elapsed,
            version_elapsed,
            version_result_class,
            version_stream_records,
            async_elapsed,
            async_result_class,
            all_stop_elapsed,
            all_stop_result_class,
            connect_elapsed,
            connect_result_class,
            language_elapsed,
            language_result_class,
            insert_elapsed,
            insert_result_class: insert_result.class,
            insert_command,
            list_before_continue_elapsed,
            list_before_continue_result_class: list_before_continue_result.class,
            continue_elapsed: hit.continue_elapsed,
            continue_result_class: hit.continue_result_class,
            hit_wait_elapsed: hit.hit_wait_elapsed,
            list_after_hit_elapsed,
            list_after_hit_result_class: list_after_hit_result.class,
            delete_elapsed,
            delete_result_class,
            list_after_delete_elapsed,
            list_after_delete_result_class: list_after_delete_result.class,
            roundtrip: GdbMiHardwareWatchpointHitRoundtrip {
                inserted,
                table_before_continue,
                hit: hit.hit,
                table_after_hit,
                table_after_delete,
                gdb_hardware_classification_verified: true,
                one_correlated_hit_verified: true,
                post_hit_count_verified: true,
                gdb_breakpoint_table_empty: true,
                physical_comparator_state_independently_verified: false,
            },
            detach_elapsed,
            detach_result_class,
        })
    }

    fn run_watchpoint_hit_wait(
        &mut self,
        expected_expression: &str,
        request: RemoteWatchpointHitRequest,
        command_timeout: Duration,
        hit_timeout: Duration,
    ) -> std::result::Result<WatchpointHitWaitSuccess, (LifecycleFailure, WatchpointHitCleanupState)>
    {
        let continue_started = Instant::now();
        self.send_command(
            WATCHPOINT_HIT_CONTINUE_TOKEN,
            WATCHPOINT_HIT_CONTINUE_COMMAND,
        )
        .map_err(|failure| (failure, WatchpointHitCleanupState::RunningOrUnknown))?;

        let mut continue_result: Option<(String, Duration, Instant)> = None;
        let mut stopped: Option<GdbMiHardwareWatchpointHit> = None;
        let mut running_notifications = 0_u64;
        loop {
            if let Some((result_class, continue_elapsed, result_observed)) = &continue_result
                && let Some(hit) = stopped.take()
            {
                let hit_wait_elapsed = result_observed.elapsed();
                return Ok(WatchpointHitWaitSuccess {
                    continue_elapsed: *continue_elapsed,
                    continue_result_class: result_class.clone(),
                    hit_wait_elapsed,
                    hit,
                });
            }

            let deadline = continue_result.as_ref().map_or_else(
                || continue_started + command_timeout,
                |(_, _, observed)| *observed + hit_timeout,
            );
            let record = self
                .next_record(deadline, "watchpoint hit")
                .map_err(|failure| {
                    let state = if stopped.is_some() {
                        WatchpointHitCleanupState::Stopped
                    } else {
                        WatchpointHitCleanupState::RunningOrUnknown
                    };
                    (failure, state)
                })?;
            match record {
                ParsedRecord::Result {
                    token,
                    class,
                    variables: _,
                } => {
                    if token != Some(WATCHPOINT_HIT_CONTINUE_TOKEN) {
                        let state = if stopped.is_some() {
                            WatchpointHitCleanupState::Stopped
                        } else {
                            WatchpointHitCleanupState::RunningOrUnknown
                        };
                        return Err((
                            protocol_failure(
                                "GDB/MI result token did not match the fixed continue command",
                                json!({
                                    "expected_token": WATCHPOINT_HIT_CONTINUE_TOKEN,
                                    "observed_token": token,
                                    "observed_result_class": class,
                                }),
                            ),
                            state,
                        ));
                    }
                    if continue_result.is_some() {
                        return Err((
                            protocol_failure(
                                "GDB/MI emitted more than one result for the fixed continue command",
                                json!({"token": WATCHPOINT_HIT_CONTINUE_TOKEN}),
                            ),
                            if stopped.is_some() {
                                WatchpointHitCleanupState::Stopped
                            } else {
                                WatchpointHitCleanupState::RunningOrUnknown
                            },
                        ));
                    }
                    if class != "running" {
                        let state = if stopped.is_some() {
                            WatchpointHitCleanupState::Stopped
                        } else if class == "error" {
                            WatchpointHitCleanupState::NotRunning
                        } else {
                            WatchpointHitCleanupState::RunningOrUnknown
                        };
                        return Err((
                            protocol_failure(
                                "GDB/MI continue command did not enter the running state",
                                json!({
                                    "token": WATCHPOINT_HIT_CONTINUE_TOKEN,
                                    "expected_result_class": "running",
                                    "observed_result_class": class,
                                }),
                            ),
                            state,
                        ));
                    }
                    continue_result = Some((class, continue_started.elapsed(), Instant::now()));
                }
                ParsedRecord::ExecAsync {
                    token,
                    class,
                    variables,
                } if class == "running" => {
                    if stopped.is_some() {
                        return Err((
                            protocol_failure(
                                "GDB/MI emitted a running notification after the watchpoint stop",
                                json!({
                                    "expected_stop_token": WATCHPOINT_HIT_CONTINUE_TOKEN,
                                    "observed_running_token": token,
                                }),
                            ),
                            WatchpointHitCleanupState::RunningOrUnknown,
                        ));
                    }
                    if token.is_some() && token != Some(WATCHPOINT_HIT_CONTINUE_TOKEN) {
                        return Err((
                            protocol_failure(
                                "GDB/MI running notification carried an unrelated token",
                                json!({
                                    "expected_token": WATCHPOINT_HIT_CONTINUE_TOKEN,
                                    "observed_token": token,
                                }),
                            ),
                            WatchpointHitCleanupState::RunningOrUnknown,
                        ));
                    }
                    validate_running_notification(&variables).map_err(|failure| {
                        (failure, WatchpointHitCleanupState::RunningOrUnknown)
                    })?;
                    running_notifications = running_notifications.saturating_add(1);
                }
                ParsedRecord::ExecAsync {
                    token,
                    class,
                    variables,
                } if class == "stopped" => {
                    let correlation = correlate_only_async_stop_to_single_continue(
                        stopped.is_some(),
                        token,
                        "watchpoint hit",
                    )
                    .map_err(|failure| (failure, WatchpointHitCleanupState::Stopped))?;
                    let hit = parse_hardware_watchpoint_hit(
                        correlation,
                        &class,
                        &variables,
                        HardwareWatchpointHitParsePolicy {
                            expected_expression,
                            mode: request.mode,
                            expected_pc_start: request.expected_pc_start,
                            expected_pc_end_exclusive: request.expected_pc_end_exclusive,
                        },
                        running_notifications,
                    )
                    .map_err(|failure| (failure, WatchpointHitCleanupState::Stopped))?;
                    stopped = Some(hit);
                }
                ParsedRecord::ExecAsync { token, class, .. } => {
                    return Err((
                        protocol_failure(
                            "GDB/MI emitted an unsupported execution notification during the watchpoint wait",
                            json!({"token": token, "observed_class": class}),
                        ),
                        WatchpointHitCleanupState::RunningOrUnknown,
                    ));
                }
                _ => {}
            }
        }
    }

    fn run_watchpoint_roundtrip(
        &mut self,
        address: Address,
        length_bytes: u64,
        mode: OpenOcdHardwareWatchpointMode,
        command_timeout: Duration,
    ) -> std::result::Result<WatchpointRoundtripSuccess, LifecycleFailure> {
        let expression = watchpoint_expression(address, length_bytes);
        let insert_command = watchpoint_insert_command(address, length_bytes, mode);
        let insert_started = Instant::now();
        self.send_command(WATCHPOINT_INSERT_TOKEN, &insert_command)?;
        let insert_result = self.wait_for_result_record(
            WATCHPOINT_INSERT_TOKEN,
            "done",
            insert_started + command_timeout,
        )?;
        let insert_elapsed = insert_started.elapsed();
        let inserted =
            parse_hardware_watchpoint_insertion(&insert_result.variables, &expression, mode)?;

        let list_before_delete_started = Instant::now();
        self.send_command(WATCHPOINT_LIST_TOKEN, BREAKPOINT_LIST_COMMAND)?;
        let list_before_delete_result = self.wait_for_result_record(
            WATCHPOINT_LIST_TOKEN,
            "done",
            list_before_delete_started + command_timeout,
        )?;
        let list_before_delete_elapsed = list_before_delete_started.elapsed();
        let table_before_delete = parse_hardware_watchpoint_table(
            &list_before_delete_result.variables,
            &expression,
            mode,
        )?;

        let delete_started = Instant::now();
        self.send_command(WATCHPOINT_DELETE_TOKEN, BREAKPOINT_DELETE_COMMAND)?;
        let delete_result_class = self.wait_for_result(
            WATCHPOINT_DELETE_TOKEN,
            "done",
            delete_started + command_timeout,
        )?;
        let delete_elapsed = delete_started.elapsed();

        let list_after_delete_started = Instant::now();
        self.send_command(WATCHPOINT_LIST_AFTER_DELETE_TOKEN, BREAKPOINT_LIST_COMMAND)?;
        let list_after_delete_result = self.wait_for_result_record(
            WATCHPOINT_LIST_AFTER_DELETE_TOKEN,
            "done",
            list_after_delete_started + command_timeout,
        )?;
        let list_after_delete_elapsed = list_after_delete_started.elapsed();
        let table_after_delete = parse_empty_breakpoint_table(&list_after_delete_result.variables)?;

        Ok(WatchpointRoundtripSuccess {
            insert_elapsed,
            insert_result_class: insert_result.class,
            insert_command,
            list_before_delete_elapsed,
            list_before_delete_result_class: list_before_delete_result.class,
            delete_elapsed,
            delete_result_class,
            list_after_delete_elapsed,
            list_after_delete_result_class: list_after_delete_result.class,
            roundtrip: GdbMiHardwareWatchpointRoundtrip {
                inserted,
                table_before_delete,
                table_after_delete,
                gdb_hardware_classification_verified: true,
                gdb_breakpoint_table_empty: true,
                physical_comparator_allocation_independently_verified: false,
                physical_comparator_state_independently_verified: false,
            },
        })
    }

    fn with_watchpoint_hit_cleanup(
        &mut self,
        mut failure: LifecycleFailure,
        state: WatchpointHitCleanupState,
        command_timeout: Duration,
    ) -> LifecycleFailure {
        failure.retryable = false;
        let cleanup_started = Instant::now();
        let (interrupt_complete, interrupt_evidence) = match state {
            WatchpointHitCleanupState::RunningOrUnknown => {
                self.attempt_watchpoint_hit_interrupt(command_timeout)
            }
            WatchpointHitCleanupState::NotRunning | WatchpointHitCleanupState::Stopped => (
                true,
                json!({
                    "attempted": false,
                    "required": false,
                    "complete": true,
                    "reason": match state {
                        WatchpointHitCleanupState::NotRunning => "continue did not enter running state",
                        WatchpointHitCleanupState::Stopped => "a stop record was already observed",
                        WatchpointHitCleanupState::RunningOrUnknown => unreachable!(),
                    },
                }),
            ),
        };

        let delete_started = Instant::now();
        let delete = self
            .send_command(
                WATCHPOINT_HIT_CLEANUP_DELETE_TOKEN,
                BREAKPOINT_DELETE_COMMAND,
            )
            .and_then(|()| {
                self.wait_for_any_result_record(
                    WATCHPOINT_HIT_CLEANUP_DELETE_TOKEN,
                    delete_started + command_timeout,
                )
            });
        let delete_evidence = match delete {
            Ok(result) => json!({
                "attempted": true,
                "token": WATCHPOINT_HIT_CLEANUP_DELETE_TOKEN,
                "command": BREAKPOINT_DELETE_COMMAND,
                "result_class": result.class,
                "elapsed_ms": duration_ms(delete_started.elapsed()),
            }),
            Err(delete_failure) => json!({
                "attempted": true,
                "token": WATCHPOINT_HIT_CLEANUP_DELETE_TOKEN,
                "command": BREAKPOINT_DELETE_COMMAND,
                "elapsed_ms": duration_ms(delete_started.elapsed()),
                "failure": lifecycle_failure_value(&delete_failure),
            }),
        };

        let list_started = Instant::now();
        let list = self
            .send_command(WATCHPOINT_HIT_CLEANUP_LIST_TOKEN, BREAKPOINT_LIST_COMMAND)
            .and_then(|()| {
                self.wait_for_result_record(
                    WATCHPOINT_HIT_CLEANUP_LIST_TOKEN,
                    "done",
                    list_started + command_timeout,
                )
            })
            .and_then(|result| {
                parse_empty_breakpoint_table(&result.variables).map(|table| (result.class, table))
            });
        let (table_empty, list_evidence) = match list {
            Ok((result_class, table)) => (
                table.empty,
                json!({
                    "attempted": true,
                    "token": WATCHPOINT_HIT_CLEANUP_LIST_TOKEN,
                    "command": BREAKPOINT_LIST_COMMAND,
                    "result_class": result_class,
                    "table": table,
                    "elapsed_ms": duration_ms(list_started.elapsed()),
                }),
            ),
            Err(list_failure) => (
                false,
                json!({
                    "attempted": true,
                    "token": WATCHPOINT_HIT_CLEANUP_LIST_TOKEN,
                    "command": BREAKPOINT_LIST_COMMAND,
                    "elapsed_ms": duration_ms(list_started.elapsed()),
                    "failure": lifecycle_failure_value(&list_failure),
                }),
            ),
        };

        let detach_started = Instant::now();
        let detach = self
            .send_command(WATCHPOINT_HIT_CLEANUP_DETACH_TOKEN, REMOTE_DETACH_COMMAND)
            .and_then(|()| {
                self.wait_for_result(
                    WATCHPOINT_HIT_CLEANUP_DETACH_TOKEN,
                    "done",
                    detach_started + command_timeout,
                )
            });
        let (detach_complete, detach_evidence) = match detach {
            Ok(result_class) => (
                true,
                json!({
                    "attempted": true,
                    "complete": true,
                    "token": WATCHPOINT_HIT_CLEANUP_DETACH_TOKEN,
                    "command": REMOTE_DETACH_COMMAND,
                    "result_class": result_class,
                    "elapsed_ms": duration_ms(detach_started.elapsed()),
                }),
            ),
            Err(detach_failure) => (
                false,
                json!({
                    "attempted": true,
                    "complete": false,
                    "token": WATCHPOINT_HIT_CLEANUP_DETACH_TOKEN,
                    "command": REMOTE_DETACH_COMMAND,
                    "elapsed_ms": duration_ms(detach_started.elapsed()),
                    "failure": lifecycle_failure_value(&detach_failure),
                }),
            ),
        };

        let mut details = failure.details.as_object().cloned().unwrap_or_default();
        details.insert(
            "watchpoint_hit_cleanup".to_string(),
            json!({
                "attempted": true,
                "initial_execution_state": match state {
                    WatchpointHitCleanupState::NotRunning => "not_running",
                    WatchpointHitCleanupState::Stopped => "stopped",
                    WatchpointHitCleanupState::RunningOrUnknown => "running_or_unknown",
                },
                "interrupt": interrupt_evidence,
                "delete": delete_evidence,
                "list": list_evidence,
                "gdb_breakpoint_table_empty": table_empty,
                "physical_comparator_state_independently_verified": false,
                "complete": interrupt_complete && table_empty && detach_complete,
                "elapsed_ms": duration_ms(cleanup_started.elapsed()),
            }),
        );
        details.insert("cleanup_detach".to_string(), detach_evidence);
        failure.details = Value::Object(details);
        failure
    }

    fn attempt_watchpoint_hit_interrupt(&mut self, timeout: Duration) -> (bool, Value) {
        let started = Instant::now();
        if let Err(failure) = self.send_command(
            WATCHPOINT_HIT_CLEANUP_INTERRUPT_TOKEN,
            WATCHPOINT_HIT_INTERRUPT_COMMAND,
        ) {
            return (
                false,
                json!({
                    "attempted": true,
                    "complete": false,
                    "token": WATCHPOINT_HIT_CLEANUP_INTERRUPT_TOKEN,
                    "command": WATCHPOINT_HIT_INTERRUPT_COMMAND,
                    "failure": lifecycle_failure_value(&failure),
                    "elapsed_ms": duration_ms(started.elapsed()),
                }),
            );
        }

        let deadline = started + timeout;
        let mut result_class: Option<String> = None;
        let mut stop_correlation: Option<CorrelatedAsyncStop> = None;
        loop {
            if result_class.as_deref() == Some("done")
                && let Some(correlation) = stop_correlation
            {
                return (
                    true,
                    json!({
                        "attempted": true,
                        "complete": true,
                        "token": WATCHPOINT_HIT_CLEANUP_INTERRUPT_TOKEN,
                        "command": WATCHPOINT_HIT_INTERRUPT_COMMAND,
                        "result_class": "done",
                        "expected_stop_token": WATCHPOINT_HIT_CONTINUE_TOKEN,
                        "observed_stop_token": correlation.observed_token,
                        "stop_correlation": correlation.kind,
                        "stop_observed": true,
                        "elapsed_ms": duration_ms(started.elapsed()),
                    }),
                );
            }
            let record = match self.next_record(deadline, "watchpoint hit cleanup interrupt") {
                Ok(record) => record,
                Err(failure) => {
                    return (
                        false,
                        json!({
                            "attempted": true,
                            "complete": false,
                            "token": WATCHPOINT_HIT_CLEANUP_INTERRUPT_TOKEN,
                            "command": WATCHPOINT_HIT_INTERRUPT_COMMAND,
                            "result_class": result_class,
                            "stop_observed": stop_correlation.is_some(),
                            "failure": lifecycle_failure_value(&failure),
                            "elapsed_ms": duration_ms(started.elapsed()),
                        }),
                    );
                }
            };
            match record {
                ParsedRecord::Result { token, class, .. } => {
                    if token != Some(WATCHPOINT_HIT_CLEANUP_INTERRUPT_TOKEN) {
                        return (
                            false,
                            json!({
                                "attempted": true,
                                "complete": false,
                                "expected_result_token": WATCHPOINT_HIT_CLEANUP_INTERRUPT_TOKEN,
                                "observed_result_token": token,
                                "observed_result_class": class,
                                "stop_observed": stop_correlation.is_some(),
                            }),
                        );
                    }
                    if result_class.is_some() {
                        return (
                            false,
                            json!({
                                "attempted": true,
                                "complete": false,
                                "token": WATCHPOINT_HIT_CLEANUP_INTERRUPT_TOKEN,
                                "command": WATCHPOINT_HIT_INTERRUPT_COMMAND,
                                "duplicate_result": true,
                                "observed_result_class": class,
                                "stop_observed": stop_correlation.is_some(),
                            }),
                        );
                    }
                    if class != "done" {
                        return (
                            false,
                            json!({
                                "attempted": true,
                                "complete": false,
                                "token": WATCHPOINT_HIT_CLEANUP_INTERRUPT_TOKEN,
                                "command": WATCHPOINT_HIT_INTERRUPT_COMMAND,
                                "result_class": class,
                                "stop_observed": stop_correlation.is_some(),
                                "elapsed_ms": duration_ms(started.elapsed()),
                            }),
                        );
                    }
                    result_class = Some(class);
                }
                ParsedRecord::ExecAsync {
                    token,
                    class,
                    variables,
                } if class == "stopped" => {
                    let correlation = match correlate_only_async_stop_to_single_continue(
                        stop_correlation.is_some(),
                        token,
                        "watchpoint hit cleanup interrupt",
                    ) {
                        Ok(correlation) => correlation,
                        Err(failure) => {
                            return (
                                false,
                                json!({
                                    "attempted": true,
                                    "complete": false,
                                    "expected_stop_token": WATCHPOINT_HIT_CONTINUE_TOKEN,
                                    "observed_stop_token": token,
                                    "failure": lifecycle_failure_value(&failure),
                                }),
                            );
                        }
                    };
                    if let Err(failure) = validate_watchpoint_hit_interrupt_stop(&variables) {
                        return (
                            false,
                            json!({
                                "attempted": true,
                                "complete": false,
                                "expected_stop_reason": "signal-received",
                                "expected_signal_name": "SIGINT",
                                "observed_stop_token": token,
                                "failure": lifecycle_failure_value(&failure),
                            }),
                        );
                    }
                    stop_correlation = Some(correlation);
                }
                ParsedRecord::ExecAsync {
                    token,
                    class,
                    variables,
                } if class == "running" => {
                    if token.is_some() && token != Some(WATCHPOINT_HIT_CONTINUE_TOKEN) {
                        return (
                            false,
                            json!({
                                "attempted": true,
                                "complete": false,
                                "expected_running_token": WATCHPOINT_HIT_CONTINUE_TOKEN,
                                "observed_running_token": token,
                            }),
                        );
                    }
                    if let Err(failure) = validate_running_notification(&variables) {
                        return (
                            false,
                            json!({
                                "attempted": true,
                                "complete": false,
                                "observed_running_token": token,
                                "failure": lifecycle_failure_value(&failure),
                            }),
                        );
                    }
                }
                ParsedRecord::ExecAsync { token, class, .. } => {
                    return (
                        false,
                        json!({
                            "attempted": true,
                            "complete": false,
                            "observed_exec_token": token,
                            "observed_exec_class": class,
                        }),
                    );
                }
                _ => {}
            }
        }
    }

    fn with_watchpoint_hit_detach_attempt(
        &mut self,
        mut failure: LifecycleFailure,
        command_timeout: Duration,
    ) -> LifecycleFailure {
        failure.retryable = false;
        let started = Instant::now();
        let attempt = self
            .send_command(WATCHPOINT_HIT_CLEANUP_DETACH_TOKEN, REMOTE_DETACH_COMMAND)
            .and_then(|()| {
                self.wait_for_result(
                    WATCHPOINT_HIT_CLEANUP_DETACH_TOKEN,
                    "done",
                    started + command_timeout,
                )
            });
        let evidence = match attempt {
            Ok(result_class) => json!({
                "attempted": true,
                "complete": true,
                "token": WATCHPOINT_HIT_CLEANUP_DETACH_TOKEN,
                "command": REMOTE_DETACH_COMMAND,
                "result_class": result_class,
                "elapsed_ms": duration_ms(started.elapsed()),
            }),
            Err(detach_failure) => json!({
                "attempted": true,
                "complete": false,
                "token": WATCHPOINT_HIT_CLEANUP_DETACH_TOKEN,
                "command": REMOTE_DETACH_COMMAND,
                "elapsed_ms": duration_ms(started.elapsed()),
                "failure": lifecycle_failure_value(&detach_failure),
            }),
        };
        let mut details = failure.details.as_object().cloned().unwrap_or_default();
        details.insert("cleanup_detach".to_string(), evidence);
        details.insert(
            "watchpoint_hit_cleanup".to_string(),
            json!({
                "attempted": false,
                "required": false,
                "complete": true,
                "reason": "watchpoint insertion was not attempted",
            }),
        );
        failure.details = Value::Object(details);
        failure
    }

    fn with_watchpoint_cleanup_and_detach_attempt(
        &mut self,
        mut failure: LifecycleFailure,
        command_timeout: Duration,
    ) -> LifecycleFailure {
        let cleanup_started = Instant::now();
        let delete_started = Instant::now();
        let delete = self
            .send_command(WATCHPOINT_CLEANUP_DELETE_TOKEN, BREAKPOINT_DELETE_COMMAND)
            .and_then(|()| {
                self.wait_for_any_result_record(
                    WATCHPOINT_CLEANUP_DELETE_TOKEN,
                    delete_started + command_timeout,
                )
            });
        let delete_evidence = match delete {
            Ok(result) => json!({
                "attempted": true,
                "token": WATCHPOINT_CLEANUP_DELETE_TOKEN,
                "command": BREAKPOINT_DELETE_COMMAND,
                "result_class": result.class,
                "elapsed_ms": duration_ms(delete_started.elapsed()),
            }),
            Err(delete_failure) => json!({
                "attempted": true,
                "token": WATCHPOINT_CLEANUP_DELETE_TOKEN,
                "command": BREAKPOINT_DELETE_COMMAND,
                "elapsed_ms": duration_ms(delete_started.elapsed()),
                "failure": lifecycle_failure_value(&delete_failure),
            }),
        };

        let list_started = Instant::now();
        let list = self
            .send_command(WATCHPOINT_CLEANUP_LIST_TOKEN, BREAKPOINT_LIST_COMMAND)
            .and_then(|()| {
                self.wait_for_result_record(
                    WATCHPOINT_CLEANUP_LIST_TOKEN,
                    "done",
                    list_started + command_timeout,
                )
            })
            .and_then(|result| {
                parse_empty_breakpoint_table(&result.variables).map(|table| (result.class, table))
            });
        let (table_empty, list_evidence) = match list {
            Ok((result_class, table)) => (
                table.empty,
                json!({
                    "attempted": true,
                    "token": WATCHPOINT_CLEANUP_LIST_TOKEN,
                    "command": BREAKPOINT_LIST_COMMAND,
                    "result_class": result_class,
                    "table": table,
                    "elapsed_ms": duration_ms(list_started.elapsed()),
                }),
            ),
            Err(list_failure) => (
                false,
                json!({
                    "attempted": true,
                    "token": WATCHPOINT_CLEANUP_LIST_TOKEN,
                    "command": BREAKPOINT_LIST_COMMAND,
                    "elapsed_ms": duration_ms(list_started.elapsed()),
                    "failure": lifecycle_failure_value(&list_failure),
                }),
            ),
        };

        let detach_started = Instant::now();
        let detach = self
            .send_command(WATCHPOINT_CLEANUP_DETACH_TOKEN, REMOTE_DETACH_COMMAND)
            .and_then(|()| {
                self.wait_for_result(
                    WATCHPOINT_CLEANUP_DETACH_TOKEN,
                    "done",
                    detach_started + command_timeout,
                )
            });
        let (detach_complete, detach_evidence) = match detach {
            Ok(result_class) => (
                true,
                json!({
                    "attempted": true,
                    "complete": true,
                    "token": WATCHPOINT_CLEANUP_DETACH_TOKEN,
                    "command": REMOTE_DETACH_COMMAND,
                    "result_class": result_class,
                    "elapsed_ms": duration_ms(detach_started.elapsed()),
                }),
            ),
            Err(detach_failure) => (
                false,
                json!({
                    "attempted": true,
                    "complete": false,
                    "token": WATCHPOINT_CLEANUP_DETACH_TOKEN,
                    "command": REMOTE_DETACH_COMMAND,
                    "elapsed_ms": duration_ms(detach_started.elapsed()),
                    "failure": lifecycle_failure_value(&detach_failure),
                }),
            ),
        };

        let mut details = failure.details.as_object().cloned().unwrap_or_default();
        details.insert(
            "watchpoint_cleanup".to_string(),
            json!({
                "attempted": true,
                "delete": delete_evidence,
                "list": list_evidence,
                "gdb_breakpoint_table_empty": table_empty,
                "physical_comparator_state_independently_verified": false,
                "complete": table_empty && detach_complete,
                "elapsed_ms": duration_ms(cleanup_started.elapsed()),
            }),
        );
        details.insert("cleanup_detach".to_string(), detach_evidence);
        failure.details = Value::Object(details);
        failure
    }

    fn with_watchpoint_detach_attempt(
        &mut self,
        mut failure: LifecycleFailure,
        command_timeout: Duration,
    ) -> LifecycleFailure {
        let started = Instant::now();
        let attempt = self
            .send_command(WATCHPOINT_CLEANUP_DETACH_TOKEN, REMOTE_DETACH_COMMAND)
            .and_then(|()| {
                self.wait_for_result(
                    WATCHPOINT_CLEANUP_DETACH_TOKEN,
                    "done",
                    started + command_timeout,
                )
            });
        let evidence = match attempt {
            Ok(result_class) => json!({
                "attempted": true,
                "complete": true,
                "token": WATCHPOINT_CLEANUP_DETACH_TOKEN,
                "command": REMOTE_DETACH_COMMAND,
                "result_class": result_class,
                "elapsed_ms": duration_ms(started.elapsed()),
            }),
            Err(detach_failure) => json!({
                "attempted": true,
                "complete": false,
                "token": WATCHPOINT_CLEANUP_DETACH_TOKEN,
                "command": REMOTE_DETACH_COMMAND,
                "elapsed_ms": duration_ms(started.elapsed()),
                "failure": lifecycle_failure_value(&detach_failure),
            }),
        };
        let mut details = failure.details.as_object().cloned().unwrap_or_default();
        details.insert("cleanup_detach".to_string(), evidence);
        details.insert(
            "watchpoint_cleanup".to_string(),
            json!({
                "attempted": false,
                "required": false,
                "complete": true,
            }),
        );
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

    fn wait_for_any_result_record(
        &mut self,
        expected_token: u64,
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
                        "GDB/MI result token did not match the outstanding cleanup command",
                        json!({
                            "expected_token": expected_token,
                            "observed_token": token,
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
struct BreakpointLifecycleSuccess {
    startup_elapsed: Duration,
    version_elapsed: Duration,
    version_result_class: String,
    version_stream_records: u64,
    connect_elapsed: Duration,
    connect_result_class: String,
    insert_elapsed: Duration,
    insert_result_class: String,
    insert_command: String,
    delete_elapsed: Duration,
    delete_result_class: String,
    list_elapsed: Duration,
    list_result_class: String,
    roundtrip: GdbMiHardwareBreakpointRoundtrip,
    detach_elapsed: Duration,
    detach_result_class: String,
}

#[derive(Debug)]
struct BreakpointRoundtripSuccess {
    insert_elapsed: Duration,
    insert_result_class: String,
    insert_command: String,
    delete_elapsed: Duration,
    delete_result_class: String,
    list_elapsed: Duration,
    list_result_class: String,
    roundtrip: GdbMiHardwareBreakpointRoundtrip,
}

#[derive(Debug)]
struct WatchpointLifecycleSuccess {
    startup_elapsed: Duration,
    version_elapsed: Duration,
    version_result_class: String,
    version_stream_records: u64,
    connect_elapsed: Duration,
    connect_result_class: String,
    language_elapsed: Duration,
    language_result_class: String,
    insert_elapsed: Duration,
    insert_result_class: String,
    insert_command: String,
    list_before_delete_elapsed: Duration,
    list_before_delete_result_class: String,
    delete_elapsed: Duration,
    delete_result_class: String,
    list_after_delete_elapsed: Duration,
    list_after_delete_result_class: String,
    roundtrip: GdbMiHardwareWatchpointRoundtrip,
    detach_elapsed: Duration,
    detach_result_class: String,
}

#[derive(Debug)]
struct WatchpointRoundtripSuccess {
    insert_elapsed: Duration,
    insert_result_class: String,
    insert_command: String,
    list_before_delete_elapsed: Duration,
    list_before_delete_result_class: String,
    delete_elapsed: Duration,
    delete_result_class: String,
    list_after_delete_elapsed: Duration,
    list_after_delete_result_class: String,
    roundtrip: GdbMiHardwareWatchpointRoundtrip,
}

#[derive(Debug)]
struct WatchpointHitLifecycleSuccess {
    startup_elapsed: Duration,
    version_elapsed: Duration,
    version_result_class: String,
    version_stream_records: u64,
    async_elapsed: Duration,
    async_result_class: String,
    all_stop_elapsed: Duration,
    all_stop_result_class: String,
    connect_elapsed: Duration,
    connect_result_class: String,
    language_elapsed: Duration,
    language_result_class: String,
    insert_elapsed: Duration,
    insert_result_class: String,
    insert_command: String,
    list_before_continue_elapsed: Duration,
    list_before_continue_result_class: String,
    continue_elapsed: Duration,
    continue_result_class: String,
    hit_wait_elapsed: Duration,
    list_after_hit_elapsed: Duration,
    list_after_hit_result_class: String,
    delete_elapsed: Duration,
    delete_result_class: String,
    list_after_delete_elapsed: Duration,
    list_after_delete_result_class: String,
    roundtrip: GdbMiHardwareWatchpointHitRoundtrip,
    detach_elapsed: Duration,
    detach_result_class: String,
}

#[derive(Debug)]
struct WatchpointHitWaitSuccess {
    continue_elapsed: Duration,
    continue_result_class: String,
    hit_wait_elapsed: Duration,
    hit: GdbMiHardwareWatchpointHit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WatchpointHitCleanupState {
    NotRunning,
    Stopped,
    RunningOrUnknown,
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

fn breakpoint_insert_command(address: Address) -> String {
    format!("-break-insert -h *0x{:x}", address.0)
}

pub(super) fn watchpoint_expression(address: Address, length_bytes: u64) -> String {
    format!("*((char*)0x{:x})@{length_bytes}", address.0)
}

fn watchpoint_insert_command(
    address: Address,
    length_bytes: u64,
    mode: OpenOcdHardwareWatchpointMode,
) -> String {
    format!(
        "-break-watch {} {}",
        mode.command_flag(),
        watchpoint_expression(address, length_bytes)
    )
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

fn parse_hardware_watchpoint_insertion(
    variables: &HashMap<String, MiValue>,
    expected_expression: &str,
    mode: OpenOcdHardwareWatchpointMode,
) -> std::result::Result<GdbMiHardwareWatchpointInsertion, LifecycleFailure> {
    let expected_field = mode.insertion_result_field();
    if variables.len() != 1 {
        return Err(protocol_failure(
            "GDB/MI hardware-watchpoint insertion contained unexpected result fields",
            json!({"expected_field": expected_field, "field_count": variables.len()}),
        ));
    }
    let Some(MiValue::Dict(fields)) = variables.get(expected_field) else {
        return Err(protocol_failure(
            "GDB/MI hardware-watchpoint insertion did not return the required hardware tuple",
            json!({"expected_field": expected_field}),
        ));
    };
    const EXPECTED_FIELDS: [&str; 2] = ["number", "exp"];
    if fields.len() != EXPECTED_FIELDS.len()
        || fields
            .keys()
            .any(|field| !EXPECTED_FIELDS.contains(&field.as_str()))
    {
        let mut reported_fields = fields.keys().cloned().collect::<Vec<_>>();
        reported_fields.sort();
        return Err(protocol_failure(
            "GDB/MI hardware-watchpoint insertion tuple contained unexpected fields",
            json!({"expected_fields": EXPECTED_FIELDS, "reported_fields": reported_fields}),
        ));
    }
    let number = parse_decimal_text(
        exact_string_field(fields, "number", "hardware watchpoint insertion")?,
        "hardware watchpoint number",
    )?;
    if number != BREAKPOINT_NUMBER {
        return Err(protocol_failure(
            "GDB/MI hardware-watchpoint number did not match the fixed cleanup identifier",
            json!({"expected": BREAKPOINT_NUMBER, "observed": number}),
        ));
    }
    let expression = exact_string_field(fields, "exp", "hardware watchpoint insertion")?;
    if expression != expected_expression {
        return Err(protocol_failure(
            "GDB/MI hardware-watchpoint insertion expression did not match the fixed request",
            json!({"expected": expected_expression, "observed": bounded_line(expression)}),
        ));
    }

    Ok(GdbMiHardwareWatchpointInsertion {
        result_field: expected_field.to_string(),
        number,
        expression: expression.to_string(),
    })
}

fn parse_hardware_watchpoint_table(
    variables: &HashMap<String, MiValue>,
    expected_expression: &str,
    mode: OpenOcdHardwareWatchpointMode,
) -> std::result::Result<GdbMiHardwareWatchpointTable, LifecycleFailure> {
    parse_hardware_watchpoint_table_with_hit_count(variables, expected_expression, mode, 0)
}

fn parse_hardware_watchpoint_table_with_hit_count(
    variables: &HashMap<String, MiValue>,
    expected_expression: &str,
    mode: OpenOcdHardwareWatchpointMode,
    expected_hit_count: u64,
) -> std::result::Result<GdbMiHardwareWatchpointTable, LifecycleFailure> {
    const EXPECTED_COLUMNS: [&str; 6] = ["number", "type", "disp", "enabled", "addr", "what"];
    if variables.len() != 1 {
        return Err(protocol_failure(
            "GDB/MI hardware-watchpoint list contained unexpected result fields",
            json!({"expected_field": "BreakpointTable", "field_count": variables.len()}),
        ));
    }
    let Some(MiValue::Dict(table)) = variables.get("BreakpointTable") else {
        return Err(protocol_failure(
            "GDB/MI hardware-watchpoint list did not contain a table",
            json!({"expected_field": "BreakpointTable"}),
        ));
    };
    let expected_table_fields = ["nr_rows", "nr_cols", "hdr", "body"];
    if table.len() != expected_table_fields.len()
        || table
            .keys()
            .any(|field| !expected_table_fields.contains(&field.as_str()))
    {
        let mut reported_fields = table.keys().cloned().collect::<Vec<_>>();
        reported_fields.sort();
        return Err(protocol_failure(
            "GDB/MI hardware-watchpoint table contained unexpected fields",
            json!({
                "expected_fields": expected_table_fields,
                "reported_fields": reported_fields,
            }),
        ));
    }

    let reported_rows = parse_decimal_text(
        exact_string_field(table, "nr_rows", "hardware watchpoint table")?,
        "hardware watchpoint table row count",
    )?;
    let reported_columns = parse_decimal_text(
        exact_string_field(table, "nr_cols", "hardware watchpoint table")?,
        "hardware watchpoint table column count",
    )?;
    if reported_rows != 1 || reported_columns != EXPECTED_COLUMNS.len() as u64 {
        return Err(protocol_failure(
            "GDB/MI hardware-watchpoint table was not the expected one-row six-column table",
            json!({
                "reported_rows": reported_rows,
                "reported_columns": reported_columns,
                "expected_rows": 1,
                "expected_columns": EXPECTED_COLUMNS.len(),
            }),
        ));
    }

    let header_columns = parse_breakpoint_table_headers(table, &EXPECTED_COLUMNS)?;
    let Some(MiValue::List(body)) = table.get("body") else {
        return Err(protocol_failure(
            "GDB/MI hardware-watchpoint table body was not a list",
            json!({"field": "body"}),
        ));
    };
    if body.len() != 1 {
        return Err(protocol_failure(
            "GDB/MI hardware-watchpoint table did not contain exactly one body entry",
            json!({"body_entries": body.len(), "expected": 1}),
        ));
    }
    let MiValue::Dict(fields) = &body[0] else {
        return Err(protocol_failure(
            "GDB/MI hardware-watchpoint table body entry was not a tuple",
            json!({"index": 0}),
        ));
    };
    const REQUIRED_FIELDS: [&str; 7] = [
        "number",
        "type",
        "disp",
        "enabled",
        "what",
        "times",
        "original-location",
    ];
    const ALLOWED_FIELDS: [&str; 8] = [
        "number",
        "type",
        "disp",
        "enabled",
        "what",
        "times",
        "original-location",
        "thread-groups",
    ];
    if REQUIRED_FIELDS
        .iter()
        .any(|field| !fields.contains_key(*field))
        || fields
            .keys()
            .any(|field| !ALLOWED_FIELDS.contains(&field.as_str()))
    {
        let mut reported_fields = fields.keys().cloned().collect::<Vec<_>>();
        reported_fields.sort();
        return Err(protocol_failure(
            "GDB/MI hardware-watchpoint table entry contained missing or unsupported fields",
            json!({
                "required_fields": REQUIRED_FIELDS,
                "allowed_fields": ALLOWED_FIELDS,
                "reported_fields": reported_fields,
            }),
        ));
    }

    let number = parse_decimal_text(
        exact_string_field(fields, "number", "hardware watchpoint table entry")?,
        "hardware watchpoint table number",
    )?;
    if number != BREAKPOINT_NUMBER {
        return Err(protocol_failure(
            "GDB/MI hardware-watchpoint table number did not match the fixed cleanup identifier",
            json!({"expected": BREAKPOINT_NUMBER, "observed": number}),
        ));
    }
    let breakpoint_type = exact_string_field(fields, "type", "hardware watchpoint table entry")?;
    if breakpoint_type != mode.breakpoint_type() {
        return Err(protocol_failure(
            "GDB/MI did not classify the listed watchpoint as the requested hardware-only kind",
            json!({
                "expected": mode.breakpoint_type(),
                "observed": bounded_line(breakpoint_type),
            }),
        ));
    }
    let disposition = exact_string_field(fields, "disp", "hardware watchpoint table entry")?;
    if disposition != "keep" {
        return Err(protocol_failure(
            "GDB/MI hardware watchpoint had an unexpected disposition",
            json!({"expected": "keep", "observed": bounded_line(disposition)}),
        ));
    }
    let enabled = exact_string_field(fields, "enabled", "hardware watchpoint table entry")?;
    if enabled != "y" {
        return Err(protocol_failure(
            "GDB/MI hardware watchpoint was not enabled",
            json!({"expected": "y", "observed": bounded_line(enabled)}),
        ));
    }
    let expression = exact_string_field(fields, "what", "hardware watchpoint table entry")?;
    if expression != expected_expression {
        return Err(protocol_failure(
            "GDB/MI listed hardware-watchpoint expression did not match the fixed request",
            json!({"expected": expected_expression, "observed": bounded_line(expression)}),
        ));
    }
    let hit_count = parse_decimal_text(
        exact_string_field(fields, "times", "hardware watchpoint table entry")?,
        "hardware watchpoint hit count",
    )?;
    if hit_count != expected_hit_count {
        return Err(protocol_failure(
            "GDB/MI hardware watchpoint reported an unexpected hit count",
            json!({"expected": expected_hit_count, "observed": hit_count}),
        ));
    }
    let original_location = exact_string_field(
        fields,
        "original-location",
        "hardware watchpoint table entry",
    )?;
    if original_location != expected_expression {
        return Err(protocol_failure(
            "GDB/MI hardware-watchpoint original location did not match the fixed request",
            json!({
                "expected": expected_expression,
                "observed": bounded_line(original_location),
            }),
        ));
    }
    let thread_groups = parse_optional_breakpoint_thread_groups(fields, "hardware watchpoint")?;

    Ok(GdbMiHardwareWatchpointTable {
        reported_rows,
        reported_columns,
        header_columns,
        body_entries: 1,
        watchpoint: GdbMiHardwareWatchpoint {
            number,
            mode,
            breakpoint_type: breakpoint_type.to_string(),
            disposition: disposition.to_string(),
            enabled: true,
            expression: expression.to_string(),
            hit_count,
            thread_groups,
            original_location: original_location.to_string(),
        },
    })
}

#[derive(Clone, Copy)]
struct HardwareWatchpointHitParsePolicy<'a> {
    expected_expression: &'a str,
    mode: OpenOcdHardwareWatchpointMode,
    expected_pc_start: Address,
    expected_pc_end_exclusive: Address,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CorrelatedAsyncStop {
    observed_token: Option<u64>,
    kind: GdbMiAsyncStopCorrelation,
}

fn correlate_async_stop_to_single_continue(
    observed_token: Option<u64>,
    phase: &str,
) -> std::result::Result<CorrelatedAsyncStop, LifecycleFailure> {
    let kind = match observed_token {
        None => GdbMiAsyncStopCorrelation::TokenlessSingleContinue,
        Some(WATCHPOINT_HIT_CONTINUE_TOKEN) => GdbMiAsyncStopCorrelation::MatchingContinueToken,
        Some(_) => {
            return Err(protocol_failure(
                "GDB/MI asynchronous stop carried a nonmatching token",
                json!({
                    "phase": phase,
                    "expected_token_when_present": WATCHPOINT_HIT_CONTINUE_TOKEN,
                    "observed_token": observed_token,
                    "single_continue_outstanding": true,
                }),
            ));
        }
    };
    Ok(CorrelatedAsyncStop {
        observed_token,
        kind,
    })
}

fn correlate_only_async_stop_to_single_continue(
    stop_already_observed: bool,
    observed_token: Option<u64>,
    phase: &str,
) -> std::result::Result<CorrelatedAsyncStop, LifecycleFailure> {
    if stop_already_observed {
        return Err(protocol_failure(
            "GDB/MI emitted a competing stop while one continue was outstanding",
            json!({
                "phase": phase,
                "continue_token": WATCHPOINT_HIT_CONTINUE_TOKEN,
                "observed_token": observed_token,
                "competing_stop": true,
            }),
        ));
    }
    correlate_async_stop_to_single_continue(observed_token, phase)
}

fn parse_hardware_watchpoint_hit(
    correlation: CorrelatedAsyncStop,
    class: &str,
    variables: &HashMap<String, MiValue>,
    policy: HardwareWatchpointHitParsePolicy<'_>,
    running_notifications: u64,
) -> std::result::Result<GdbMiHardwareWatchpointHit, LifecycleFailure> {
    const MAX_HIT_TEXT_BYTES: usize = 4 * 1024;
    const MAX_THREAD_TEXT_BYTES: usize = 128;
    let expected_reason = match policy.mode {
        OpenOcdHardwareWatchpointMode::Read => "read-watchpoint-trigger",
        OpenOcdHardwareWatchpointMode::Access => "access-watchpoint-trigger",
    };
    let expected_tuple = policy.mode.insertion_result_field();
    if class != "stopped" {
        return Err(protocol_failure(
            "GDB/MI watchpoint hit parser received a non-stop async record",
            json!({"observed_class": class}),
        ));
    }

    let required_fields = ["reason", expected_tuple, "value", "frame"];
    let allowed_fields = [
        "reason",
        expected_tuple,
        "value",
        "frame",
        "thread-id",
        "stopped-threads",
        "core",
    ];
    if required_fields
        .iter()
        .any(|field| !variables.contains_key(*field))
        || variables
            .keys()
            .any(|field| !allowed_fields.contains(&field.as_str()))
    {
        let mut observed = variables.keys().cloned().collect::<Vec<_>>();
        observed.sort();
        return Err(protocol_failure(
            "GDB/MI watchpoint stop contained missing or unsupported fields",
            json!({
                "required_fields": required_fields,
                "allowed_fields": allowed_fields,
                "observed_fields": observed,
            }),
        ));
    }
    let reason = exact_string_field(variables, "reason", "watchpoint stop")?;
    if reason != expected_reason {
        return Err(protocol_failure(
            "GDB/MI stopped for a reason other than the confirmed hardware watchpoint",
            json!({"expected": expected_reason, "observed": bounded_line(reason)}),
        ));
    }

    let Some(MiValue::Dict(watchpoint)) = variables.get(expected_tuple) else {
        return Err(protocol_failure(
            "GDB/MI watchpoint stop did not contain the required hardware tuple",
            json!({"expected_field": expected_tuple}),
        ));
    };
    let tuple_fields = ["number", "exp"];
    if watchpoint.len() != tuple_fields.len()
        || watchpoint
            .keys()
            .any(|field| !tuple_fields.contains(&field.as_str()))
    {
        return Err(protocol_failure(
            "GDB/MI watchpoint stop hardware tuple contained unexpected fields",
            json!({"expected_fields": tuple_fields}),
        ));
    }
    let number = parse_decimal_text(
        exact_string_field(watchpoint, "number", "watchpoint stop tuple")?,
        "watchpoint stop number",
    )?;
    if number != BREAKPOINT_NUMBER {
        return Err(protocol_failure(
            "GDB/MI watchpoint stop number did not match the confirmed watchpoint",
            json!({"expected": BREAKPOINT_NUMBER, "observed": number}),
        ));
    }
    let expression = exact_string_field(watchpoint, "exp", "watchpoint stop tuple")?;
    if expression != policy.expected_expression {
        return Err(protocol_failure(
            "GDB/MI watchpoint stop expression did not match the confirmed expression",
            json!({"expected": policy.expected_expression, "observed": bounded_line(expression)}),
        ));
    }

    let Some(MiValue::Dict(value)) = variables.get("value") else {
        return Err(protocol_failure(
            "GDB/MI watchpoint stop value was not a tuple",
            json!({"field": "value"}),
        ));
    };
    let (read, old, new) = match policy.mode {
        OpenOcdHardwareWatchpointMode::Read => {
            if value.len() != 1 || !value.contains_key("value") {
                return Err(protocol_failure(
                    "GDB/MI read-watchpoint value tuple did not contain exactly value",
                    json!({"observed_fields": sorted_fields(value)}),
                ));
            }
            (
                Some(bounded_required_string(
                    value,
                    "value",
                    "read-watchpoint value",
                    MAX_HIT_TEXT_BYTES,
                )?),
                None,
                None,
            )
        }
        OpenOcdHardwareWatchpointMode::Access => {
            let fields = sorted_fields(value);
            if fields != ["new"] && fields != ["new", "old"] {
                return Err(protocol_failure(
                    "GDB/MI access-watchpoint value tuple had an unsupported shape",
                    json!({"allowed_shapes": [["new"], ["new", "old"]], "observed_fields": fields}),
                ));
            }
            (
                None,
                value
                    .contains_key("old")
                    .then(|| {
                        bounded_required_string(
                            value,
                            "old",
                            "access-watchpoint old value",
                            MAX_HIT_TEXT_BYTES,
                        )
                    })
                    .transpose()?,
                Some(bounded_required_string(
                    value,
                    "new",
                    "access-watchpoint new value",
                    MAX_HIT_TEXT_BYTES,
                )?),
            )
        }
    };

    let Some(MiValue::Dict(frame)) = variables.get("frame") else {
        return Err(protocol_failure(
            "GDB/MI watchpoint stop frame was not a tuple",
            json!({"field": "frame"}),
        ));
    };
    const REQUIRED_FRAME_FIELDS: [&str; 1] = ["addr"];
    const ALLOWED_FRAME_FIELDS: [&str; 10] = [
        "level",
        "addr",
        "func",
        "args",
        "file",
        "fullname",
        "line",
        "from",
        "arch",
        "addr_flags",
    ];
    if REQUIRED_FRAME_FIELDS
        .iter()
        .any(|field| !frame.contains_key(*field))
        || frame
            .keys()
            .any(|field| !ALLOWED_FRAME_FIELDS.contains(&field.as_str()))
    {
        return Err(protocol_failure(
            "GDB/MI watchpoint stop frame contained missing or unsupported fields",
            json!({
                "required_fields": REQUIRED_FRAME_FIELDS,
                "allowed_fields": ALLOWED_FRAME_FIELDS,
                "observed_fields": sorted_fields(frame),
            }),
        ));
    }
    if frame.contains_key("level") && parse_decimal_stack_field(frame, "level", 0)? != 0 {
        return Err(protocol_failure(
            "GDB/MI watchpoint stop frame was not the top frame",
            json!({"expected_level": 0}),
        ));
    }
    validate_hit_frame_args(frame, MAX_HIT_TEXT_BYTES)?;
    let frame_address = Address(parse_stack_address(frame, 0)?);
    if frame_address.0 < policy.expected_pc_start.0
        || frame_address.0 >= policy.expected_pc_end_exclusive.0
    {
        return Err(protocol_failure(
            "GDB/MI watchpoint stop frame was outside the confirmed PC interval",
            json!({
                "frame_address": frame_address,
                "expected_pc_start": policy.expected_pc_start,
                "expected_pc_end_exclusive": policy.expected_pc_end_exclusive,
            }),
        ));
    }

    let thread_id = optional_bounded_hit_string(
        variables,
        "thread-id",
        "watchpoint stop",
        MAX_THREAD_TEXT_BYTES,
    )?;
    let stopped_threads = optional_bounded_hit_string(
        variables,
        "stopped-threads",
        "watchpoint stop",
        MAX_THREAD_TEXT_BYTES,
    )?;
    if stopped_threads
        .as_deref()
        .is_some_and(|value| value != "all")
    {
        return Err(protocol_failure(
            "GDB/MI all-stop watchpoint event did not report all threads stopped",
            json!({"observed": stopped_threads}),
        ));
    }
    let core = variables
        .get("core")
        .map(|_| {
            parse_decimal_text(
                exact_string_field(variables, "core", "watchpoint stop")?,
                "watchpoint stop core",
            )
        })
        .transpose()?;

    Ok(GdbMiHardwareWatchpointHit {
        continue_token: WATCHPOINT_HIT_CONTINUE_TOKEN,
        observed_stop_token: correlation.observed_token,
        stop_correlation: correlation.kind,
        running_notifications,
        stop_reason: reason.to_string(),
        result_field: expected_tuple.to_string(),
        number,
        expression: expression.to_string(),
        value: GdbMiHardwareWatchpointHitValue {
            reported_fields: sorted_fields(value),
            read,
            old,
            new,
        },
        frame_address,
        frame_function: optional_bounded_stack_field(frame, "func", 0, MAX_HIT_TEXT_BYTES)?,
        frame_file: optional_bounded_stack_field(frame, "file", 0, MAX_HIT_TEXT_BYTES)?,
        frame_fullname: optional_bounded_stack_field(frame, "fullname", 0, MAX_HIT_TEXT_BYTES)?,
        frame_line: frame
            .get("line")
            .map(|_| parse_decimal_stack_field(frame, "line", 0))
            .transpose()?,
        frame_module: optional_bounded_stack_field(frame, "from", 0, MAX_HIT_TEXT_BYTES)?,
        frame_architecture: optional_bounded_stack_field(frame, "arch", 0, MAX_HIT_TEXT_BYTES)?,
        frame_address_flags: optional_bounded_stack_field(
            frame,
            "addr_flags",
            0,
            MAX_HIT_TEXT_BYTES,
        )?,
        thread_id,
        stopped_threads,
        core,
        expected_pc_start: policy.expected_pc_start,
        expected_pc_end_exclusive: policy.expected_pc_end_exclusive,
        expected_pc_range_verified: true,
    })
}

fn validate_watchpoint_hit_interrupt_stop(
    variables: &HashMap<String, MiValue>,
) -> std::result::Result<(), LifecycleFailure> {
    let reason = exact_string_field(variables, "reason", "watchpoint cleanup interrupt stop")?;
    if reason != "signal-received" {
        return Err(protocol_failure(
            "GDB/MI cleanup interrupt produced an unrelated stop reason",
            json!({"expected": "signal-received", "observed": bounded_line(reason)}),
        ));
    }
    let signal_name = exact_string_field(
        variables,
        "signal-name",
        "watchpoint cleanup interrupt stop",
    )?;
    if signal_name != "SIGINT" {
        return Err(protocol_failure(
            "GDB/MI cleanup interrupt produced an unexpected signal",
            json!({"expected": "SIGINT", "observed": bounded_line(signal_name)}),
        ));
    }
    if let Some(stopped_threads) = variables.get("stopped-threads") {
        let MiValue::String(stopped_threads) = stopped_threads else {
            return Err(protocol_failure(
                "GDB/MI cleanup interrupt stopped-threads field was not a string",
                json!({"field": "stopped-threads"}),
            ));
        };
        if stopped_threads != "all" {
            return Err(protocol_failure(
                "GDB/MI all-stop cleanup interrupt did not report all threads stopped",
                json!({"observed": bounded_line(stopped_threads)}),
            ));
        }
    }
    Ok(())
}

fn validate_running_notification(
    variables: &HashMap<String, MiValue>,
) -> std::result::Result<(), LifecycleFailure> {
    if variables.len() != 1 || !variables.contains_key("thread-id") {
        return Err(protocol_failure(
            "GDB/MI running notification did not contain exactly thread-id",
            json!({"observed_fields": sorted_fields(variables)}),
        ));
    }
    bounded_required_string(
        variables,
        "thread-id",
        "running notification thread id",
        128,
    )?;
    Ok(())
}

fn validate_hit_frame_args(
    frame: &HashMap<String, MiValue>,
    maximum_bytes: usize,
) -> std::result::Result<(), LifecycleFailure> {
    let Some(value) = frame.get("args") else {
        return Ok(());
    };
    let MiValue::List(arguments) = value else {
        return Err(protocol_failure(
            "GDB/MI watchpoint stop frame arguments were not a list",
            json!({"field": "args"}),
        ));
    };
    if arguments.len() > 64 {
        return Err(protocol_failure(
            "GDB/MI watchpoint stop frame argument count exceeded the bound",
            json!({"count": arguments.len(), "maximum": 64}),
        ));
    }
    for (index, argument) in arguments.iter().enumerate() {
        let MiValue::Dict(fields) = argument else {
            return Err(protocol_failure(
                "GDB/MI watchpoint stop frame argument was not a tuple",
                json!({"index": index}),
            ));
        };
        const ALLOWED_ARGUMENT_FIELDS: [&str; 2] = ["name", "value"];
        if fields.is_empty()
            || fields
                .keys()
                .any(|field| !ALLOWED_ARGUMENT_FIELDS.contains(&field.as_str()))
        {
            return Err(protocol_failure(
                "GDB/MI watchpoint stop frame argument contained unsupported fields",
                json!({"index": index, "observed_fields": sorted_fields(fields)}),
            ));
        }
        for field in fields.keys() {
            bounded_required_string(
                fields,
                field,
                "watchpoint stop frame argument",
                maximum_bytes,
            )?;
        }
    }
    Ok(())
}

fn sorted_fields(fields: &HashMap<String, MiValue>) -> Vec<String> {
    let mut fields = fields.keys().cloned().collect::<Vec<_>>();
    fields.sort_unstable();
    fields
}

fn bounded_required_string(
    fields: &HashMap<String, MiValue>,
    key: &str,
    label: &str,
    maximum_bytes: usize,
) -> std::result::Result<String, LifecycleFailure> {
    let value = exact_string_field(fields, key, label)?;
    if value.is_empty() || value.len() > maximum_bytes || value.chars().any(char::is_control) {
        return Err(protocol_failure(
            format!("GDB/MI {label} exceeded the safe text boundary"),
            json!({"field": key, "bytes": value.len(), "maximum_bytes": maximum_bytes}),
        ));
    }
    Ok(value.to_string())
}

fn optional_bounded_hit_string(
    fields: &HashMap<String, MiValue>,
    key: &str,
    label: &str,
    maximum_bytes: usize,
) -> std::result::Result<Option<String>, LifecycleFailure> {
    fields
        .contains_key(key)
        .then(|| bounded_required_string(fields, key, label, maximum_bytes))
        .transpose()
}

fn parse_breakpoint_table_headers(
    table: &HashMap<String, MiValue>,
    expected_columns: &[&str],
) -> std::result::Result<Vec<String>, LifecycleFailure> {
    let Some(MiValue::List(headers)) = table.get("hdr") else {
        return Err(protocol_failure(
            "GDB/MI breakpoint table header was not a list",
            json!({"field": "hdr"}),
        ));
    };
    if headers.len() != expected_columns.len() {
        return Err(protocol_failure(
            "GDB/MI breakpoint table header count did not match the declared columns",
            json!({
                "header_count": headers.len(),
                "expected_columns": expected_columns.len(),
            }),
        ));
    }
    let mut header_columns = Vec::with_capacity(headers.len());
    for (index, header) in headers.iter().enumerate() {
        let MiValue::Dict(fields) = header else {
            return Err(protocol_failure(
                "GDB/MI breakpoint table header entry was not a tuple",
                json!({"index": index}),
            ));
        };
        let expected_header_fields = ["width", "alignment", "col_name", "colhdr"];
        if fields.len() != expected_header_fields.len()
            || fields
                .keys()
                .any(|field| !expected_header_fields.contains(&field.as_str()))
        {
            return Err(protocol_failure(
                "GDB/MI breakpoint table header contained unexpected fields",
                json!({"index": index}),
            ));
        }
        parse_decimal_text(
            exact_string_field(fields, "width", "breakpoint table header")?,
            "breakpoint table header width",
        )?;
        let alignment = exact_string_field(fields, "alignment", "breakpoint table header")?;
        alignment.parse::<i64>().map_err(|_| {
            protocol_failure(
                "GDB/MI breakpoint table header alignment was not a signed integer",
                json!({"index": index, "alignment": bounded_line(alignment)}),
            )
        })?;
        let column = exact_string_field(fields, "col_name", "breakpoint table header")?;
        if column != expected_columns[index] {
            return Err(protocol_failure(
                "GDB/MI breakpoint table columns did not match the fixed schema",
                json!({
                    "index": index,
                    "expected": expected_columns[index],
                    "observed": bounded_line(column),
                }),
            ));
        }
        let label = exact_string_field(fields, "colhdr", "breakpoint table header")?;
        if label.is_empty() || label.len() > 128 || label.chars().any(char::is_control) {
            return Err(protocol_failure(
                "GDB/MI breakpoint table column label exceeded the safe boundary",
                json!({"index": index}),
            ));
        }
        header_columns.push(column.to_string());
    }
    Ok(header_columns)
}

fn parse_optional_breakpoint_thread_groups(
    fields: &HashMap<String, MiValue>,
    context: &str,
) -> std::result::Result<Vec<String>, LifecycleFailure> {
    match fields.get("thread-groups") {
        None => Ok(Vec::new()),
        Some(MiValue::List(groups)) if groups.len() <= 64 => groups
            .iter()
            .enumerate()
            .map(|(index, value)| match value {
                MiValue::String(group)
                    if !group.is_empty()
                        && group.len() <= 128
                        && !group.chars().any(char::is_control) =>
                {
                    Ok(group.clone())
                }
                _ => Err(protocol_failure(
                    format!("GDB/MI {context} thread group was not a bounded string"),
                    json!({"index": index}),
                )),
            })
            .collect(),
        Some(_) => Err(protocol_failure(
            format!("GDB/MI {context} thread groups exceeded the safe boundary"),
            json!({"maximum_entries": 64}),
        )),
    }
}

fn parse_hardware_breakpoint(
    variables: &HashMap<String, MiValue>,
    requested_address: Address,
) -> std::result::Result<GdbMiHardwareBreakpoint, LifecycleFailure> {
    const MAX_BREAKPOINT_TEXT_BYTES: usize = 4 * 1024;
    const ALLOWED_FIELDS: [&str; 16] = [
        "number",
        "type",
        "disp",
        "enabled",
        "addr",
        "addr_flags",
        "func",
        "file",
        "filename",
        "fullname",
        "line",
        "at",
        "original-location",
        "times",
        "thread-groups",
        "what",
    ];

    if variables.len() != 1 {
        return Err(protocol_failure(
            "GDB/MI hardware-breakpoint insertion contained unexpected result fields",
            json!({"expected_field": "bkpt", "field_count": variables.len()}),
        ));
    }
    let Some(MiValue::Dict(fields)) = variables.get("bkpt") else {
        return Err(protocol_failure(
            "GDB/MI hardware-breakpoint insertion did not return a breakpoint tuple",
            json!({"expected_field": "bkpt"}),
        ));
    };
    if fields
        .keys()
        .any(|field| !ALLOWED_FIELDS.contains(&field.as_str()))
    {
        let mut reported_fields = fields.keys().cloned().collect::<Vec<_>>();
        reported_fields.sort();
        return Err(protocol_failure(
            "GDB/MI hardware-breakpoint tuple contained unsupported fields",
            json!({"reported_fields": reported_fields, "allowed_fields": ALLOWED_FIELDS}),
        ));
    }
    if fields.contains_key("file") && fields.contains_key("filename") {
        return Err(protocol_failure(
            "GDB/MI hardware-breakpoint tuple contained duplicate file metadata",
            json!({"fields": ["file", "filename"]}),
        ));
    }

    let number = parse_decimal_text(
        exact_string_field(fields, "number", "hardware breakpoint")?,
        "hardware breakpoint number",
    )?;
    if number != BREAKPOINT_NUMBER {
        return Err(protocol_failure(
            "GDB/MI hardware-breakpoint number did not match the fixed cleanup identifier",
            json!({"expected": BREAKPOINT_NUMBER, "observed": number}),
        ));
    }
    let breakpoint_type = exact_string_field(fields, "type", "hardware breakpoint")?;
    if breakpoint_type != "hw breakpoint" {
        return Err(protocol_failure(
            "GDB/MI did not identify the inserted breakpoint as hardware-assisted",
            json!({"expected": "hw breakpoint", "observed": bounded_line(breakpoint_type)}),
        ));
    }
    let disposition = exact_string_field(fields, "disp", "hardware breakpoint")?;
    if disposition != "keep" {
        return Err(protocol_failure(
            "GDB/MI hardware breakpoint had an unexpected disposition",
            json!({"expected": "keep", "observed": bounded_line(disposition)}),
        ));
    }
    let enabled = exact_string_field(fields, "enabled", "hardware breakpoint")?;
    if enabled != "y" {
        return Err(protocol_failure(
            "GDB/MI hardware breakpoint was not enabled",
            json!({"expected": "y", "observed": bounded_line(enabled)}),
        ));
    }
    let address = parse_hex_address_text(
        exact_string_field(fields, "addr", "hardware breakpoint")?,
        "hardware breakpoint address",
    )?;
    if address != requested_address.0 {
        return Err(protocol_failure(
            "GDB/MI hardware-breakpoint address did not match the exact request",
            json!({"requested": requested_address, "observed": Address(address)}),
        ));
    }
    let hit_count = parse_decimal_text(
        exact_string_field(fields, "times", "hardware breakpoint")?,
        "hardware breakpoint hit count",
    )?;
    if hit_count != 0 {
        return Err(protocol_failure(
            "GDB/MI hardware breakpoint reported an unexpected hit count",
            json!({"expected": 0, "observed": hit_count}),
        ));
    }

    let thread_groups = match fields.get("thread-groups") {
        None => Vec::new(),
        Some(MiValue::List(groups)) if groups.len() <= 64 => groups
            .iter()
            .enumerate()
            .map(|(index, value)| match value {
                MiValue::String(group)
                    if !group.is_empty()
                        && group.len() <= 128
                        && !group.chars().any(char::is_control) =>
                {
                    Ok(group.clone())
                }
                _ => Err(protocol_failure(
                    "GDB/MI hardware-breakpoint thread group was not a bounded string",
                    json!({"index": index}),
                )),
            })
            .collect::<std::result::Result<Vec<_>, _>>()?,
        Some(_) => {
            return Err(protocol_failure(
                "GDB/MI hardware-breakpoint thread groups exceeded the safe boundary",
                json!({"maximum_entries": 64}),
            ));
        }
    };
    let original_location =
        optional_bounded_breakpoint_field(fields, "original-location", MAX_BREAKPOINT_TEXT_BYTES)?;
    let expected_location = format!("*0x{:x}", requested_address.0);
    if original_location
        .as_deref()
        .is_some_and(|location| location != expected_location)
    {
        return Err(protocol_failure(
            "GDB/MI hardware-breakpoint original location did not match the numeric request",
            json!({"expected": expected_location, "observed": original_location}),
        ));
    }
    let file = match (
        optional_bounded_breakpoint_field(fields, "file", MAX_BREAKPOINT_TEXT_BYTES)?,
        optional_bounded_breakpoint_field(fields, "filename", MAX_BREAKPOINT_TEXT_BYTES)?,
    ) {
        (Some(file), None) | (None, Some(file)) => Some(file),
        (None, None) => None,
        (Some(_), Some(_)) => unreachable!("duplicate file fields were rejected above"),
    };
    let line = fields
        .contains_key("line")
        .then(|| {
            parse_decimal_text(
                exact_string_field(fields, "line", "hardware breakpoint")?,
                "hardware breakpoint source line",
            )
        })
        .transpose()?;

    Ok(GdbMiHardwareBreakpoint {
        number,
        breakpoint_type: breakpoint_type.to_string(),
        disposition: disposition.to_string(),
        enabled: true,
        address: Address(address),
        hit_count,
        thread_groups,
        original_location,
        function: optional_bounded_breakpoint_field(fields, "func", MAX_BREAKPOINT_TEXT_BYTES)?,
        file,
        fullname: optional_bounded_breakpoint_field(fields, "fullname", MAX_BREAKPOINT_TEXT_BYTES)?,
        line,
        address_flags: optional_bounded_breakpoint_field(
            fields,
            "addr_flags",
            MAX_BREAKPOINT_TEXT_BYTES,
        )?,
        at: optional_bounded_breakpoint_field(fields, "at", MAX_BREAKPOINT_TEXT_BYTES)?,
        what: optional_bounded_breakpoint_field(fields, "what", MAX_BREAKPOINT_TEXT_BYTES)?,
    })
}

fn parse_empty_breakpoint_table(
    variables: &HashMap<String, MiValue>,
) -> std::result::Result<GdbMiBreakpointTable, LifecycleFailure> {
    const EXPECTED_COLUMNS: [&str; 6] = ["number", "type", "disp", "enabled", "addr", "what"];
    if variables.len() != 1 {
        return Err(protocol_failure(
            "GDB/MI breakpoint-list result contained unexpected fields",
            json!({"expected_field": "BreakpointTable", "field_count": variables.len()}),
        ));
    }
    let Some(MiValue::Dict(table)) = variables.get("BreakpointTable") else {
        return Err(protocol_failure(
            "GDB/MI breakpoint-list result did not contain a table",
            json!({"expected_field": "BreakpointTable"}),
        ));
    };
    let expected_fields = ["nr_rows", "nr_cols", "hdr", "body"];
    if table.len() != expected_fields.len()
        || table
            .keys()
            .any(|field| !expected_fields.contains(&field.as_str()))
    {
        let mut reported_fields = table.keys().cloned().collect::<Vec<_>>();
        reported_fields.sort();
        return Err(protocol_failure(
            "GDB/MI breakpoint table contained unexpected fields",
            json!({"expected_fields": expected_fields, "reported_fields": reported_fields}),
        ));
    }
    let reported_rows = parse_decimal_text(
        exact_string_field(table, "nr_rows", "breakpoint table")?,
        "breakpoint table row count",
    )?;
    let reported_columns = parse_decimal_text(
        exact_string_field(table, "nr_cols", "breakpoint table")?,
        "breakpoint table column count",
    )?;
    if reported_rows != 0 || reported_columns != EXPECTED_COLUMNS.len() as u64 {
        return Err(protocol_failure(
            "GDB/MI breakpoint table was not the expected empty six-column table",
            json!({
                "reported_rows": reported_rows,
                "reported_columns": reported_columns,
                "expected_rows": 0,
                "expected_columns": EXPECTED_COLUMNS.len(),
            }),
        ));
    }

    let Some(MiValue::List(headers)) = table.get("hdr") else {
        return Err(protocol_failure(
            "GDB/MI breakpoint table header was not a list",
            json!({"field": "hdr"}),
        ));
    };
    if headers.len() != EXPECTED_COLUMNS.len() {
        return Err(protocol_failure(
            "GDB/MI breakpoint table header count did not match the declared columns",
            json!({"header_count": headers.len(), "reported_columns": reported_columns}),
        ));
    }
    let mut header_columns = Vec::with_capacity(headers.len());
    for (index, header) in headers.iter().enumerate() {
        let MiValue::Dict(fields) = header else {
            return Err(protocol_failure(
                "GDB/MI breakpoint table header entry was not a tuple",
                json!({"index": index}),
            ));
        };
        let expected_header_fields = ["width", "alignment", "col_name", "colhdr"];
        if fields.len() != expected_header_fields.len()
            || fields
                .keys()
                .any(|field| !expected_header_fields.contains(&field.as_str()))
        {
            return Err(protocol_failure(
                "GDB/MI breakpoint table header contained unexpected fields",
                json!({"index": index}),
            ));
        }
        parse_decimal_text(
            exact_string_field(fields, "width", "breakpoint table header")?,
            "breakpoint table header width",
        )?;
        let alignment = exact_string_field(fields, "alignment", "breakpoint table header")?;
        alignment.parse::<i64>().map_err(|_| {
            protocol_failure(
                "GDB/MI breakpoint table header alignment was not a signed integer",
                json!({"index": index, "alignment": bounded_line(alignment)}),
            )
        })?;
        let column = exact_string_field(fields, "col_name", "breakpoint table header")?;
        if column != EXPECTED_COLUMNS[index] {
            return Err(protocol_failure(
                "GDB/MI breakpoint table columns did not match the fixed schema",
                json!({"index": index, "expected": EXPECTED_COLUMNS[index], "observed": bounded_line(column)}),
            ));
        }
        let label = exact_string_field(fields, "colhdr", "breakpoint table header")?;
        if label.is_empty() || label.len() > 128 || label.chars().any(char::is_control) {
            return Err(protocol_failure(
                "GDB/MI breakpoint table column label exceeded the safe boundary",
                json!({"index": index}),
            ));
        }
        header_columns.push(column.to_string());
    }
    let Some(MiValue::List(body)) = table.get("body") else {
        return Err(protocol_failure(
            "GDB/MI breakpoint table body was not a list",
            json!({"field": "body"}),
        ));
    };
    if !body.is_empty() {
        return Err(protocol_failure(
            "GDB/MI breakpoint table was not empty after fixed deletion",
            json!({"body_entries": body.len()}),
        ));
    }

    Ok(GdbMiBreakpointTable {
        reported_rows,
        reported_columns,
        header_columns,
        body_entries: 0,
        empty: true,
    })
}

fn optional_bounded_breakpoint_field(
    fields: &HashMap<String, MiValue>,
    key: &str,
    maximum_bytes: usize,
) -> std::result::Result<Option<String>, LifecycleFailure> {
    let Some(value) = fields.get(key) else {
        return Ok(None);
    };
    let MiValue::String(value) = value else {
        return Err(protocol_failure(
            "GDB/MI hardware-breakpoint optional metadata was not a string",
            json!({"field": key}),
        ));
    };
    if value.is_empty() || value.len() > maximum_bytes || value.chars().any(char::is_control) {
        return Err(protocol_failure(
            "GDB/MI hardware-breakpoint optional metadata exceeded the safe text boundary",
            json!({"field": key, "bytes": value.len(), "maximum_bytes": maximum_bytes}),
        ));
    }
    Ok(Some(value.clone()))
}

fn parse_decimal_text(value: &str, label: &str) -> std::result::Result<u64, LifecycleFailure> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(protocol_failure(
            format!("GDB/MI {label} was not an unsigned decimal integer"),
            json!({"value": bounded_line(value)}),
        ));
    }
    value.parse::<u64>().map_err(|_| {
        protocol_failure(
            format!("GDB/MI {label} exceeded 64 bits"),
            json!({"value": bounded_line(value)}),
        )
    })
}

fn parse_hex_address_text(value: &str, label: &str) -> std::result::Result<u64, LifecycleFailure> {
    let Some(digits) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    else {
        return Err(protocol_failure(
            format!("GDB/MI {label} was not hexadecimal"),
            json!({"value": bounded_line(value)}),
        ));
    };
    if digits.is_empty()
        || digits.len() > 16
        || !digits.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(protocol_failure(
            format!("GDB/MI {label} had an invalid hexadecimal payload"),
            json!({"value": bounded_line(value)}),
        ));
    }
    u64::from_str_radix(digits, 16).map_err(|_| {
        protocol_failure(
            format!("GDB/MI {label} exceeded 64 bits"),
            json!({"value": bounded_line(value)}),
        )
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
    ExecAsync {
        token: Option<u64>,
        class: String,
        variables: HashMap<String, MiValue>,
    },
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
        b'*' => parse_exec_async_record(line, token, payload),
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

fn parse_exec_async_record(
    line: &str,
    token: Option<u64>,
    payload: &str,
) -> std::result::Result<ParsedRecord, String> {
    let class = parse_class(payload, "exec async")?;
    let response = serde_gdbmi::parser::Response::try_from(line)
        .map_err(|error| format!("exec async record has invalid structured MI data: {error}"))?;
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
        return Err("structured MI parser returned an inconsistent exec async token".to_string());
    }
    let StructuredResponseBody::Data(data) = response.body else {
        return Err("exec async marker parsed as a stream record".to_string());
    };
    if data.symbol != DataSymbol::AsyncExec || data.class != class {
        return Err("structured MI parser returned an inconsistent exec async record".to_string());
    }
    Ok(ParsedRecord::ExecAsync {
        token,
        class,
        variables: data.variables,
    })
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
    if payload.starts_with("done,BreakpointTable=") {
        return parse_breakpoint_table_result_record(line, token, class);
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

fn parse_breakpoint_table_result_record(
    line: &str,
    token: Option<u64>,
    class: String,
) -> std::result::Result<ParsedRecord, String> {
    if class != "done" {
        return Err("breakpoint-table result used an unexpected result class".to_string());
    }
    let tokens = lexer::lex(line)
        .map_err(|error| format!("breakpoint-table result has invalid MI data: {error}"))?
        .into_iter()
        .collect::<Vec<_>>();
    let mut tokens = tokens.into_iter();

    if let Some(expected_token) = token {
        match tokens.next() {
            Some(MiToken::Text(value)) if value == expected_token.to_string() => {}
            _ => {
                return Err(
                    "breakpoint-table result token was not represented exactly once".to_string(),
                );
            }
        }
    }
    match tokens.next() {
        Some(MiToken::Punct('^')) => {}
        _ => return Err("breakpoint-table result marker was missing".to_string()),
    }
    match tokens.next() {
        Some(MiToken::Text(value)) if value == "done" => {}
        _ => return Err("breakpoint-table result class was not done".to_string()),
    }
    match tokens.next() {
        Some(MiToken::Punct(',')) => {}
        _ => return Err("breakpoint-table variable separator was missing".to_string()),
    }
    match tokens.next() {
        Some(MiToken::Text(value)) if value == "BreakpointTable" => {}
        _ => return Err("result did not contain the exact BreakpointTable variable".to_string()),
    }
    match tokens.next() {
        Some(MiToken::Punct('=')) => {}
        _ => return Err("breakpoint-table assignment was missing".to_string()),
    }
    let table = match tokens.next() {
        Some(MiToken::Braced(fields)) => parse_breakpoint_table_fields(fields)?,
        _ => return Err("BreakpointTable was not a tuple".to_string()),
    };
    if tokens.next().is_some() {
        return Err("breakpoint-table result contained trailing variables".to_string());
    }

    Ok(ParsedRecord::Result {
        token,
        class,
        variables: HashMap::from([("BreakpointTable".to_string(), MiValue::Dict(table))]),
    })
}

fn parse_breakpoint_table_fields(
    fields: lexer::TokenStream,
) -> std::result::Result<HashMap<String, MiValue>, String> {
    let mut tokens = fields.into_iter().peekable();
    let mut parsed = HashMap::new();
    while tokens.peek().is_some() {
        let key = match tokens.next() {
            Some(MiToken::Text(key)) => key,
            _ => return Err("breakpoint-table field name was malformed".to_string()),
        };
        match tokens.next() {
            Some(MiToken::Punct('=')) => {}
            _ => return Err("breakpoint-table field assignment was missing".to_string()),
        }
        let value = match (key.as_str(), tokens.next()) {
            ("hdr", Some(MiToken::Bracketed(headers))) => {
                MiValue::List(parse_breakpoint_header_list(headers)?)
            }
            ("body", Some(MiToken::Bracketed(body))) => {
                MiValue::List(parse_breakpoint_body_list(body)?)
            }
            (_, Some(MiToken::Text(value))) => MiValue::String(value),
            _ => return Err("breakpoint-table field had an unexpected value shape".to_string()),
        };
        if parsed.insert(key, value).is_some() {
            return Err("breakpoint table contained a duplicate field".to_string());
        }
        if tokens.peek().is_none() {
            break;
        }
        match tokens.next() {
            Some(MiToken::Punct(',')) if tokens.peek().is_some() => {}
            _ => return Err("breakpoint-table field separator was malformed".to_string()),
        }
    }
    Ok(parsed)
}

fn parse_breakpoint_header_list(
    headers: lexer::TokenStream,
) -> std::result::Result<Vec<MiValue>, String> {
    let mut tokens = headers.into_iter().peekable();
    let mut parsed = Vec::new();
    while tokens.peek().is_some() {
        let fields = match tokens.next() {
            Some(MiToken::Braced(fields)) => parse_breakpoint_header_fields(fields)?,
            _ => return Err("breakpoint-table header entry was not a tuple".to_string()),
        };
        parsed.push(MiValue::Dict(fields));
        if tokens.peek().is_none() {
            break;
        }
        match tokens.next() {
            Some(MiToken::Punct(',')) if tokens.peek().is_some() => {}
            _ => return Err("breakpoint-table header separator was malformed".to_string()),
        }
    }
    Ok(parsed)
}

fn parse_breakpoint_header_fields(
    fields: lexer::TokenStream,
) -> std::result::Result<HashMap<String, MiValue>, String> {
    let mut tokens = fields.into_iter().peekable();
    let mut parsed = HashMap::new();
    while tokens.peek().is_some() {
        let key = match tokens.next() {
            Some(MiToken::Text(key)) => key,
            _ => return Err("breakpoint-table header field name was malformed".to_string()),
        };
        match tokens.next() {
            Some(MiToken::Punct('=')) => {}
            _ => return Err("breakpoint-table header assignment was missing".to_string()),
        }
        let value = match tokens.next() {
            Some(MiToken::Text(value)) => MiValue::String(value),
            _ => return Err("breakpoint-table header field was not scalar".to_string()),
        };
        if parsed.insert(key, value).is_some() {
            return Err("breakpoint-table header contained a duplicate field".to_string());
        }
        if tokens.peek().is_none() {
            break;
        }
        match tokens.next() {
            Some(MiToken::Punct(',')) if tokens.peek().is_some() => {}
            _ => return Err("breakpoint-table header field separator was malformed".to_string()),
        }
    }
    Ok(parsed)
}

fn parse_breakpoint_body_list(
    body: lexer::TokenStream,
) -> std::result::Result<Vec<MiValue>, String> {
    let mut tokens = body.into_iter().peekable();
    let mut parsed = Vec::new();
    while tokens.peek().is_some() {
        match tokens.next() {
            Some(MiToken::Text(value)) if value == "bkpt" => {}
            _ => return Err("breakpoint-table body entry was not named bkpt".to_string()),
        }
        match tokens.next() {
            Some(MiToken::Punct('=')) => {}
            _ => return Err("breakpoint-table body assignment was missing".to_string()),
        }
        match tokens.next() {
            Some(MiToken::Braced(fields)) => {
                parsed.push(MiValue::Dict(parse_breakpoint_body_fields(fields)?))
            }
            _ => return Err("breakpoint-table body entry was not a tuple".to_string()),
        }
        if tokens.peek().is_none() {
            break;
        }
        match tokens.next() {
            Some(MiToken::Punct(',')) if tokens.peek().is_some() => {}
            _ => return Err("breakpoint-table body separator was malformed".to_string()),
        }
    }
    Ok(parsed)
}

fn parse_breakpoint_body_fields(
    fields: lexer::TokenStream,
) -> std::result::Result<HashMap<String, MiValue>, String> {
    let mut tokens = fields.into_iter().peekable();
    let mut parsed = HashMap::new();
    while tokens.peek().is_some() {
        let key = match tokens.next() {
            Some(MiToken::Text(key)) => key,
            _ => return Err("breakpoint-table body field name was malformed".to_string()),
        };
        match tokens.next() {
            Some(MiToken::Punct('=')) => {}
            _ => return Err("breakpoint-table body field assignment was missing".to_string()),
        }
        let value = match tokens.next() {
            Some(MiToken::Text(value)) => MiValue::String(value),
            Some(MiToken::Bracketed(values)) => {
                MiValue::List(parse_breakpoint_body_string_list(values)?)
            }
            _ => return Err("breakpoint-table body field had an unsupported shape".to_string()),
        };
        if parsed.insert(key, value).is_some() {
            return Err("breakpoint-table body contained a duplicate field".to_string());
        }
        if tokens.peek().is_none() {
            break;
        }
        match tokens.next() {
            Some(MiToken::Punct(',')) if tokens.peek().is_some() => {}
            _ => return Err("breakpoint-table body field separator was malformed".to_string()),
        }
    }
    Ok(parsed)
}

fn parse_breakpoint_body_string_list(
    values: lexer::TokenStream,
) -> std::result::Result<Vec<MiValue>, String> {
    let mut tokens = values.into_iter().peekable();
    let mut parsed = Vec::new();
    while tokens.peek().is_some() {
        match tokens.next() {
            Some(MiToken::Text(value)) => parsed.push(MiValue::String(value)),
            _ => return Err("breakpoint-table body list entry was not scalar".to_string()),
        }
        if tokens.peek().is_none() {
            break;
        }
        match tokens.next() {
            Some(MiToken::Punct(',')) if tokens.peek().is_some() => {}
            _ => return Err("breakpoint-table body list separator was malformed".to_string()),
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
            ParsedRecord::ExecAsync { .. } => &mut self.exec_async,
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
    fn parser_preserves_tokened_structured_exec_async_records() {
        let record = parse_record(concat!(
            "8*stopped,reason=\"access-watchpoint-trigger\",",
            "hw-awpt={number=\"1\",exp=\"*((char*)0x3fcdb550)@4\"},",
            "value={new=\"7\"},frame={addr=\"0x420128cd\",args=[]},",
            "thread-id=\"1\",stopped-threads=\"all\",core=\"0\""
        ))
        .unwrap();
        let ParsedRecord::ExecAsync {
            token,
            class,
            variables,
        } = record
        else {
            panic!("expected exec async record");
        };
        assert_eq!(token, Some(8));
        assert_eq!(class, "stopped");
        assert_eq!(
            variables["reason"],
            MiValue::String("access-watchpoint-trigger".to_string())
        );
        assert!(matches!(variables["hw-awpt"], MiValue::Dict(_)));
    }

    #[test]
    fn access_watchpoint_hit_requires_exact_tuple_value_shape_and_pc_interval() {
        let record = parse_record(concat!(
            "*stopped,reason=\"access-watchpoint-trigger\",",
            "hw-awpt={number=\"1\",exp=\"*((char*)0x3fcdb550)@4\"},",
            "value={old=\"6\",new=\"7\"},",
            "frame={addr=\"0x420128cd\",func=\"main\",args=[],",
            "file=\"src/bin/main.rs\",line=\"85\",arch=\"xtensa\"},",
            "thread-id=\"1\",stopped-threads=\"all\",core=\"0\""
        ))
        .unwrap();
        let ParsedRecord::ExecAsync {
            token,
            class,
            variables,
        } = record
        else {
            panic!("expected exec async record");
        };
        let correlation =
            correlate_async_stop_to_single_continue(token, "unit test watchpoint hit").unwrap();
        let hit = parse_hardware_watchpoint_hit(
            correlation,
            &class,
            &variables,
            HardwareWatchpointHitParsePolicy {
                expected_expression: "*((char*)0x3fcdb550)@4",
                mode: OpenOcdHardwareWatchpointMode::Access,
                expected_pc_start: Address(0x4201_28c5),
                expected_pc_end_exclusive: Address(0x4201_28d0),
            },
            2,
        )
        .unwrap();
        assert_eq!(hit.continue_token, 8);
        assert_eq!(hit.observed_stop_token, None);
        assert_eq!(
            hit.stop_correlation,
            GdbMiAsyncStopCorrelation::TokenlessSingleContinue
        );
        assert_eq!(hit.running_notifications, 2);
        assert_eq!(hit.result_field, "hw-awpt");
        assert_eq!(hit.value.old.as_deref(), Some("6"));
        assert_eq!(hit.value.new.as_deref(), Some("7"));
        assert_eq!(hit.frame_address, Address(0x4201_28cd));
        assert_eq!(hit.core, Some(0));

        let outside = parse_hardware_watchpoint_hit(
            correlation,
            &class,
            &variables,
            HardwareWatchpointHitParsePolicy {
                expected_expression: "*((char*)0x3fcdb550)@4",
                mode: OpenOcdHardwareWatchpointMode::Access,
                expected_pc_start: Address(0x4201_28d0),
                expected_pc_end_exclusive: Address(0x4201_28e0),
            },
            2,
        )
        .unwrap_err();
        assert_eq!(outside.code, ErrorCode::ProtocolError);
        assert_eq!(outside.details["frame_address"], "0x420128CD");
    }

    #[test]
    fn read_watchpoint_hit_rejects_access_or_unrelated_stop_shapes() {
        let read = parse_record(concat!(
            "8*stopped,reason=\"read-watchpoint-trigger\",",
            "hw-rwpt={number=\"1\",exp=\"*((char*)0x20000000)@4\"},",
            "value={value=\"9\"},frame={addr=\"0x08000100\",args=[]},",
            "stopped-threads=\"all\""
        ))
        .unwrap();
        let ParsedRecord::ExecAsync {
            token,
            class,
            variables,
        } = read
        else {
            panic!("expected exec async record");
        };
        let correlation =
            correlate_async_stop_to_single_continue(token, "unit test watchpoint hit").unwrap();
        let hit = parse_hardware_watchpoint_hit(
            correlation,
            &class,
            &variables,
            HardwareWatchpointHitParsePolicy {
                expected_expression: "*((char*)0x20000000)@4",
                mode: OpenOcdHardwareWatchpointMode::Read,
                expected_pc_start: Address(0x0800_0100),
                expected_pc_end_exclusive: Address(0x0800_0104),
            },
            0,
        )
        .unwrap();
        assert_eq!(hit.value.read.as_deref(), Some("9"));
        assert_eq!(hit.observed_stop_token, Some(8));
        assert_eq!(
            hit.stop_correlation,
            GdbMiAsyncStopCorrelation::MatchingContinueToken
        );

        let unrelated = parse_record(concat!(
            "8*stopped,reason=\"breakpoint-hit\",bkptno=\"1\",",
            "frame={addr=\"0x08000100\",args=[]}"
        ))
        .unwrap();
        let ParsedRecord::ExecAsync {
            token,
            class,
            variables,
        } = unrelated
        else {
            panic!("expected exec async record");
        };
        let correlation =
            correlate_async_stop_to_single_continue(token, "unit test watchpoint hit").unwrap();
        assert!(
            parse_hardware_watchpoint_hit(
                correlation,
                &class,
                &variables,
                HardwareWatchpointHitParsePolicy {
                    expected_expression: "*((char*)0x20000000)@4",
                    mode: OpenOcdHardwareWatchpointMode::Read,
                    expected_pc_start: Address(0x0800_0100),
                    expected_pc_end_exclusive: Address(0x0800_0104),
                },
                0,
            )
            .is_err()
        );
    }

    #[test]
    fn async_stop_correlation_accepts_only_tokenless_or_matching_continue_token() {
        let tokenless =
            correlate_async_stop_to_single_continue(None, "unit test watchpoint hit").unwrap();
        assert_eq!(tokenless.observed_token, None);
        assert_eq!(
            tokenless.kind,
            GdbMiAsyncStopCorrelation::TokenlessSingleContinue
        );

        let matching = correlate_async_stop_to_single_continue(
            Some(WATCHPOINT_HIT_CONTINUE_TOKEN),
            "unit test watchpoint hit",
        )
        .unwrap();
        assert_eq!(matching.observed_token, Some(8));
        assert_eq!(
            matching.kind,
            GdbMiAsyncStopCorrelation::MatchingContinueToken
        );

        let unrelated =
            correlate_async_stop_to_single_continue(Some(77), "unit test watchpoint hit")
                .unwrap_err();
        assert_eq!(unrelated.code, ErrorCode::ProtocolError);
        assert_eq!(unrelated.details["expected_token_when_present"], 8);
        assert_eq!(unrelated.details["observed_token"], 77);
        assert_eq!(unrelated.details["single_continue_outstanding"], true);

        let competing =
            correlate_only_async_stop_to_single_continue(true, None, "unit test watchpoint hit")
                .unwrap_err();
        assert_eq!(competing.code, ErrorCode::ProtocolError);
        assert_eq!(competing.details["competing_stop"], true);
        assert_eq!(competing.details["continue_token"], 8);
    }

    #[test]
    fn cleanup_interrupt_stop_requires_sigint_and_all_stop_scope() {
        let valid = parse_record(concat!(
            "*stopped,reason=\"signal-received\",signal-name=\"SIGINT\",",
            "signal-meaning=\"Interrupt\",frame={addr=\"0x420128cd\",args=[]},",
            "thread-id=\"1\",stopped-threads=\"all\",core=\"0\""
        ))
        .unwrap();
        let ParsedRecord::ExecAsync { variables, .. } = valid else {
            panic!("expected exec async record");
        };
        validate_watchpoint_hit_interrupt_stop(&variables).unwrap();

        let wrong_signal = parse_record(
            "*stopped,reason=\"signal-received\",signal-name=\"SIGTRAP\",stopped-threads=\"all\"",
        )
        .unwrap();
        let ParsedRecord::ExecAsync { variables, .. } = wrong_signal else {
            panic!("expected exec async record");
        };
        assert!(validate_watchpoint_hit_interrupt_stop(&variables).is_err());

        let wrong_scope = parse_record(
            "*stopped,reason=\"signal-received\",signal-name=\"SIGINT\",stopped-threads=\"1\"",
        )
        .unwrap();
        let ParsedRecord::ExecAsync { variables, .. } = wrong_scope else {
            panic!("expected exec async record");
        };
        assert!(validate_watchpoint_hit_interrupt_stop(&variables).is_err());
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
    fn hardware_breakpoint_result_accepts_the_bounded_official_shape() {
        let record = parse_record(
            "3^done,bkpt={number=\"1\",type=\"hw breakpoint\",disp=\"keep\",enabled=\"y\",addr=\"0x420129e4\",thread-groups=[\"i1\"],times=\"0\",original-location=\"*0x420129e4\"}",
        )
        .unwrap();
        let ParsedRecord::Result { variables, .. } = record else {
            panic!("expected result record");
        };
        let breakpoint = parse_hardware_breakpoint(&variables, Address(0x4201_29e4)).unwrap();

        assert_eq!(breakpoint.number, 1);
        assert_eq!(breakpoint.breakpoint_type, "hw breakpoint");
        assert_eq!(breakpoint.address, Address(0x4201_29e4));
        assert_eq!(breakpoint.hit_count, 0);
        assert_eq!(breakpoint.thread_groups, ["i1"]);
        assert_eq!(breakpoint.original_location.as_deref(), Some("*0x420129e4"));
    }

    #[test]
    fn hardware_breakpoint_result_rejects_unsafe_type_address_and_fields() {
        let invalid = [
            "3^done,bkpt={number=\"1\",type=\"breakpoint\",disp=\"keep\",enabled=\"y\",addr=\"0x420129e4\",times=\"0\"}",
            "3^done,bkpt={number=\"1\",type=\"hw breakpoint\",disp=\"keep\",enabled=\"y\",addr=\"0x420129e8\",times=\"0\"}",
            "3^done,bkpt={number=\"1\",type=\"hw breakpoint\",disp=\"keep\",enabled=\"y\",addr=\"0x420129e4\",times=\"0\",cond=\"x == 1\"}",
        ];
        for line in invalid {
            let record = parse_record(line).unwrap();
            let ParsedRecord::Result { variables, .. } = record else {
                panic!("expected result record");
            };
            assert!(
                parse_hardware_breakpoint(&variables, Address(0x4201_29e4)).is_err(),
                "{line}"
            );
        }
    }

    #[test]
    fn hardware_watchpoint_results_accept_read_and_access_hardware_shapes() {
        const HEADER: &str = concat!(
            "hdr=[",
            "{width=\"3\",alignment=\"-1\",col_name=\"number\",colhdr=\"Num\"},",
            "{width=\"14\",alignment=\"-1\",col_name=\"type\",colhdr=\"Type\"},",
            "{width=\"4\",alignment=\"-1\",col_name=\"disp\",colhdr=\"Disp\"},",
            "{width=\"3\",alignment=\"-1\",col_name=\"enabled\",colhdr=\"Enb\"},",
            "{width=\"18\",alignment=\"-1\",col_name=\"addr\",colhdr=\"Address\"},",
            "{width=\"40\",alignment=\"2\",col_name=\"what\",colhdr=\"What\"}]",
        );
        let expression = "*((char*)0x3fcdb550)@4";
        for (mode, result_field, breakpoint_type) in [
            (
                OpenOcdHardwareWatchpointMode::Read,
                "hw-rwpt",
                "read watchpoint",
            ),
            (
                OpenOcdHardwareWatchpointMode::Access,
                "hw-awpt",
                "acc watchpoint",
            ),
        ] {
            let insert_line =
                format!("4^done,{result_field}={{number=\"1\",exp=\"{expression}\"}}");
            let record = parse_record(&insert_line).unwrap();
            let ParsedRecord::Result { variables, .. } = record else {
                panic!("expected result record");
            };
            let inserted =
                parse_hardware_watchpoint_insertion(&variables, expression, mode).unwrap();
            assert_eq!(inserted.result_field, result_field);
            assert_eq!(inserted.number, 1);
            assert_eq!(inserted.expression, expression);

            let table_line = format!(
                "5^done,BreakpointTable={{nr_rows=\"1\",nr_cols=\"6\",{HEADER},body=[bkpt={{number=\"1\",type=\"{breakpoint_type}\",disp=\"keep\",enabled=\"y\",what=\"{expression}\",thread-groups=[\"i1\"],times=\"0\",original-location=\"{expression}\"}}]}}"
            );
            let record = parse_record(&table_line).unwrap();
            let ParsedRecord::Result { variables, .. } = record else {
                panic!("expected result record");
            };
            let table = parse_hardware_watchpoint_table(&variables, expression, mode).unwrap();
            assert_eq!(table.reported_rows, 1);
            assert_eq!(table.body_entries, 1);
            assert_eq!(table.watchpoint.mode, mode);
            assert_eq!(table.watchpoint.breakpoint_type, breakpoint_type);
            assert_eq!(table.watchpoint.expression, expression);
            assert_eq!(table.watchpoint.thread_groups, ["i1"]);
            assert_eq!(table.watchpoint.hit_count, 0);
        }
    }

    #[test]
    fn hardware_watchpoint_results_reject_write_fallback_and_unsafe_shapes() {
        let expression = "*((char*)0x3fcdb550)@4";
        let wrong_insert =
            parse_record(&format!("4^done,wpt={{number=\"1\",exp=\"{expression}\"}}")).unwrap();
        let ParsedRecord::Result { variables, .. } = wrong_insert else {
            panic!("expected result record");
        };
        assert!(
            parse_hardware_watchpoint_insertion(
                &variables,
                expression,
                OpenOcdHardwareWatchpointMode::Read,
            )
            .is_err()
        );

        const HEADER: &str = concat!(
            "hdr=[",
            "{width=\"3\",alignment=\"-1\",col_name=\"number\",colhdr=\"Num\"},",
            "{width=\"14\",alignment=\"-1\",col_name=\"type\",colhdr=\"Type\"},",
            "{width=\"4\",alignment=\"-1\",col_name=\"disp\",colhdr=\"Disp\"},",
            "{width=\"3\",alignment=\"-1\",col_name=\"enabled\",colhdr=\"Enb\"},",
            "{width=\"18\",alignment=\"-1\",col_name=\"addr\",colhdr=\"Address\"},",
            "{width=\"40\",alignment=\"2\",col_name=\"what\",colhdr=\"What\"}]",
        );
        for entry in [
            format!(
                "number=\"1\",type=\"watchpoint\",disp=\"keep\",enabled=\"y\",what=\"{expression}\",times=\"0\",original-location=\"{expression}\""
            ),
            format!(
                "number=\"1\",type=\"read watchpoint\",disp=\"keep\",enabled=\"y\",addr=\"0x3fcdb550\",what=\"{expression}\",times=\"0\",original-location=\"{expression}\""
            ),
            format!(
                "number=\"1\",type=\"read watchpoint\",disp=\"keep\",enabled=\"y\",what=\"*((char*)0x3fcdb554)@4\",times=\"0\",original-location=\"{expression}\""
            ),
        ] {
            let line = format!(
                "5^done,BreakpointTable={{nr_rows=\"1\",nr_cols=\"6\",{HEADER},body=[bkpt={{{entry}}}]}}"
            );
            let record = parse_record(&line).unwrap();
            let ParsedRecord::Result { variables, .. } = record else {
                panic!("expected result record");
            };
            assert!(
                parse_hardware_watchpoint_table(
                    &variables,
                    expression,
                    OpenOcdHardwareWatchpointMode::Read,
                )
                .is_err(),
                "{line}"
            );
        }
    }

    #[test]
    fn breakpoint_delete_requires_the_exact_empty_table_shape() {
        let record = parse_record(
            "5^done,BreakpointTable={nr_rows=\"0\",nr_cols=\"6\",hdr=[{width=\"3\",alignment=\"-1\",col_name=\"number\",colhdr=\"Num\"},{width=\"14\",alignment=\"-1\",col_name=\"type\",colhdr=\"Type\"},{width=\"4\",alignment=\"-1\",col_name=\"disp\",colhdr=\"Disp\"},{width=\"3\",alignment=\"-1\",col_name=\"enabled\",colhdr=\"Enb\"},{width=\"18\",alignment=\"-1\",col_name=\"addr\",colhdr=\"Address\"},{width=\"40\",alignment=\"2\",col_name=\"what\",colhdr=\"What\"}],body=[]}",
        )
        .unwrap();
        let ParsedRecord::Result { variables, .. } = record else {
            panic!("expected result record");
        };
        let table = parse_empty_breakpoint_table(&variables).unwrap();

        assert_eq!(table.reported_rows, 0);
        assert_eq!(table.reported_columns, 6);
        assert_eq!(
            table.header_columns,
            ["number", "type", "disp", "enabled", "addr", "what"]
        );
        assert!(table.empty);
    }

    #[test]
    fn breakpoint_delete_rejects_a_nonempty_or_extended_table() {
        let invalid = [
            "5^done,BreakpointTable={nr_rows=\"1\",nr_cols=\"6\",hdr=[],body=[bkpt={number=\"1\"}]}",
            "5^done,BreakpointTable={nr_rows=\"0\",nr_cols=\"6\",hdr=[],body=[],extra=\"x\"}",
        ];
        for line in invalid {
            let record = parse_record(line).unwrap();
            let ParsedRecord::Result { variables, .. } = record else {
                panic!("expected result record");
            };
            assert!(parse_empty_breakpoint_table(&variables).is_err(), "{line}");
        }
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

    #[test]
    fn breakpoint_protocol_contract_binds_one_temporary_hardware_roundtrip() {
        let contract = breakpoint_protocol_contract(Address(0x4201_29e4));
        assert_eq!(contract.commands.len(), 7);
        assert_eq!(contract.commands[0].command, VERSION_COMMAND);
        assert_eq!(
            contract.commands[1].command,
            REMOTE_SELECT_COMMAND_PLACEHOLDER
        );
        assert_eq!(contract.commands[2].command, "-break-insert -h *0x420129e4");
        assert_eq!(contract.commands[3].command, BREAKPOINT_DELETE_COMMAND);
        assert_eq!(contract.commands[4].command, BREAKPOINT_LIST_COMMAND);
        assert_eq!(contract.commands[5].command, REMOTE_DETACH_COMMAND);
        assert_eq!(contract.commands[6].command, EXIT_COMMAND);

        let cleanup = breakpoint_failure_cleanup_contract();
        assert_eq!(cleanup.len(), 3);
        assert_eq!(cleanup[0].token, BREAKPOINT_CLEANUP_DELETE_TOKEN);
        assert_eq!(cleanup[1].token, BREAKPOINT_CLEANUP_LIST_TOKEN);
        assert_eq!(cleanup[2].token, BREAKPOINT_CLEANUP_DETACH_TOKEN);
    }

    #[test]
    fn watchpoint_protocol_contract_binds_one_classified_hardware_roundtrip() {
        let contract = watchpoint_protocol_contract(
            Address(0x3fcd_b550),
            4,
            OpenOcdHardwareWatchpointMode::Access,
        );
        assert_eq!(contract.commands.len(), 9);
        assert_eq!(contract.commands[0].command, VERSION_COMMAND);
        assert_eq!(
            contract.commands[1].command,
            REMOTE_SELECT_COMMAND_PLACEHOLDER
        );
        assert_eq!(contract.commands[2].command, WATCHPOINT_LANGUAGE_COMMAND);
        assert_eq!(
            contract.commands[3].command,
            "-break-watch -a *((char*)0x3fcdb550)@4"
        );
        assert_eq!(contract.commands[4].command, BREAKPOINT_LIST_COMMAND);
        assert_eq!(contract.commands[5].command, BREAKPOINT_DELETE_COMMAND);
        assert_eq!(contract.commands[6].command, BREAKPOINT_LIST_COMMAND);
        assert_eq!(contract.commands[7].command, REMOTE_DETACH_COMMAND);
        assert_eq!(contract.commands[8].command, EXIT_COMMAND);

        let cleanup = watchpoint_failure_cleanup_contract();
        assert_eq!(cleanup.len(), 3);
        assert_eq!(cleanup[0].token, WATCHPOINT_CLEANUP_DELETE_TOKEN);
        assert_eq!(cleanup[1].token, WATCHPOINT_CLEANUP_LIST_TOKEN);
        assert_eq!(cleanup[2].token, WATCHPOINT_CLEANUP_DETACH_TOKEN);
    }

    #[test]
    fn watchpoint_hit_protocol_binds_one_continue_and_fixed_interrupt_cleanup() {
        let contract = watchpoint_hit_protocol_contract(
            Address(0x3fcd_b550),
            4,
            OpenOcdHardwareWatchpointMode::Access,
        );
        assert_eq!(contract.commands.len(), 13);
        assert_eq!(contract.commands[1].command, WATCHPOINT_HIT_ASYNC_COMMAND);
        assert_eq!(
            contract.commands[2].command,
            WATCHPOINT_HIT_ALL_STOP_COMMAND
        );
        assert_eq!(contract.commands[3].token, WATCHPOINT_HIT_SELECT_TOKEN);
        assert_eq!(
            contract.commands[5].command,
            "-break-watch -a *((char*)0x3fcdb550)@4"
        );
        assert_eq!(
            contract.commands[7].command,
            WATCHPOINT_HIT_CONTINUE_COMMAND
        );
        assert_eq!(contract.commands[11].command, REMOTE_DETACH_COMMAND);
        assert_eq!(contract.commands[12].command, EXIT_COMMAND);
        assert_eq!(
            contract
                .commands
                .iter()
                .filter(|command| command.command == WATCHPOINT_HIT_CONTINUE_COMMAND)
                .count(),
            1
        );

        let cleanup = watchpoint_hit_failure_cleanup_contract();
        assert_eq!(cleanup.len(), 4);
        assert_eq!(cleanup[0].token, WATCHPOINT_HIT_CLEANUP_INTERRUPT_TOKEN);
        assert_eq!(cleanup[0].command, WATCHPOINT_HIT_INTERRUPT_COMMAND);
        assert_eq!(
            cleanup[0].expected_result_class,
            "done_then_tokenless_or_matching_continue_token_sigint_stop_when_running"
        );
        assert_eq!(cleanup[1].token, WATCHPOINT_HIT_CLEANUP_DELETE_TOKEN);
        assert_eq!(cleanup[2].token, WATCHPOINT_HIT_CLEANUP_LIST_TOKEN);
        assert_eq!(cleanup[3].token, WATCHPOINT_HIT_CLEANUP_DETACH_TOKEN);
    }
}
