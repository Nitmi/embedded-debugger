use std::{
    fs::{self, File},
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
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
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{
    OpenOcdConfigurationInspection, OpenOcdExecutableInspection, OpenOcdInspectOptions,
    process_tree_is_absent,
};
use crate::{
    SCHEMA_VERSION,
    error::{DebugError, ErrorCode, Result, SuggestedAction},
};

pub const DEFAULT_OPENOCD_SERVER_STARTUP_TIMEOUT_MS: u64 = 10_000;
pub const MIN_OPENOCD_SERVER_STARTUP_TIMEOUT_MS: u64 = 100;
pub const MAX_OPENOCD_SERVER_STARTUP_TIMEOUT_MS: u64 = 60_000;
pub const DEFAULT_OPENOCD_SERVER_SHUTDOWN_TIMEOUT_MS: u64 = 3_000;
pub const MIN_OPENOCD_SERVER_SHUTDOWN_TIMEOUT_MS: u64 = 100;
pub const MAX_OPENOCD_SERVER_SHUTDOWN_TIMEOUT_MS: u64 = 30_000;

const OPENOCD_BIND_ADDRESS: &str = "127.0.0.1";
const TCL_MESSAGE_TERMINATOR: u8 = 0x1a;
const MAX_OPENOCD_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_TCL_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_SERVER_OUTPUT_BYTES_PER_STREAM: usize = 256 * 1024;
const MAX_SERVER_LOG_LINE_BYTES: usize = 16 * 1024;
const SERVER_LOG_EVENT_QUEUE_CAPACITY: usize = 256;
const SERVER_LOG_SNIPPET_CHARS: usize = 4 * 1024;
const SERVER_POLL_INTERVAL: Duration = Duration::from_millis(10);
const TCL_RETRY_INTERVAL: Duration = Duration::from_millis(25);
const TCL_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(250);
const SERVER_STREAM_DRAIN_GRACE: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenOcdServerOptions {
    pub executable: PathBuf,
    pub config_files: Vec<PathBuf>,
    pub search_dirs: Vec<PathBuf>,
    pub version_timeout_ms: u64,
    pub startup_timeout_ms: u64,
    pub shutdown_timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdServerPlan {
    pub backend: String,
    pub operation: String,
    pub risk: String,
    pub complete: bool,
    pub executable: OpenOcdExecutableInspection,
    pub executable_file: OpenOcdExecutableFileIdentity,
    pub configuration: OpenOcdConfigurationInspection,
    pub lifecycle: OpenOcdServerLifecyclePlan,
    pub effects: OpenOcdServerEffects,
    pub confirmation_boundary: OpenOcdServerConfirmationBoundary,
    pub confirm_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdExecutableFileIdentity {
    pub bytes: u64,
    pub sha256: String,
    pub maximum_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdServerLifecyclePlan {
    pub bind_address: String,
    pub gdb_port_allocation: String,
    pub tcl_port_allocation: String,
    pub telnet_server: String,
    pub readiness_probe: String,
    pub tcl_message_terminator: String,
    pub graceful_shutdown: String,
    pub process_isolation: String,
    pub version_timeout_ms: u64,
    pub startup_timeout_ms: u64,
    pub shutdown_timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdServerEffects {
    pub configuration_tcl_execution_required: bool,
    pub configuration_semantics_statically_verified: bool,
    pub transitive_sources_resolved: bool,
    pub adapter_or_target_access_possible: bool,
    pub reset_possible_from_configuration: bool,
    pub device_write_possible_from_configuration: bool,
    pub arbitrary_host_command_execution_possible_from_configuration: bool,
    pub explicit_target_control_command_requested_by_tool: bool,
    pub explicit_flash_command_requested_by_tool: bool,
    pub target_state_restoration_verified: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdServerConfirmationBoundary {
    pub executable_file_hash_bound: bool,
    pub executable_version_bound: bool,
    pub top_level_configuration_hashes_bound: bool,
    pub search_directory_paths_bound: bool,
    pub search_directory_contents_bound: bool,
    pub transitive_sources_bound: bool,
    pub configuration_semantics_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdServerTestReport {
    pub backend: String,
    pub scope: String,
    pub risk: String,
    pub complete: bool,
    pub confirm_digest: String,
    pub executable: OpenOcdExecutableInspection,
    pub executable_file: OpenOcdExecutableFileIdentity,
    pub configuration: OpenOcdConfigurationInspection,
    pub lifecycle: OpenOcdServerLifecyclePlan,
    pub readiness: OpenOcdServerReadiness,
    pub shutdown: OpenOcdServerShutdown,
    pub effects: OpenOcdServerEffects,
    pub confirmation_boundary: OpenOcdServerConfirmationBoundary,
    pub capabilities: OpenOcdServerCapabilities,
    pub logs: OpenOcdServerLogs,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdServerReadiness {
    pub probe: String,
    pub bind_address: String,
    pub tcl_port: u16,
    pub gdb_port: u16,
    pub telnet_enabled: bool,
    pub tcl_version_response: String,
    pub elapsed_ms: u64,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdServerShutdown {
    pub command: String,
    pub requested: bool,
    pub command_sent: bool,
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
pub struct OpenOcdServerCapabilities {
    pub server_launch: bool,
    pub tcl_rpc: bool,
    pub dynamic_gdb_endpoint: bool,
    pub telnet_server: bool,
    pub gdb_mi: bool,
    pub target_operations: bool,
    pub flash: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdServerLogs {
    pub output_limit_bytes_per_stream: u64,
    pub line_limit_bytes: u64,
    pub event_queue_capacity: u64,
    pub stdout: OpenOcdServerLogSummary,
    pub stderr: OpenOcdServerLogSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdServerLogSummary {
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

pub(super) struct ManagedServerSession {
    server: ManagedOpenOcd,
    readiness: OpenOcdServerReadiness,
    shutdown_timeout_ms: u64,
}

pub(super) struct ManagedServerCompletion {
    pub readiness: OpenOcdServerReadiness,
    pub shutdown: OpenOcdServerShutdown,
    pub logs: OpenOcdServerLogs,
}

impl ManagedServerCompletion {
    pub fn lifecycle_error(&self) -> Option<&'static str> {
        if !self.shutdown.command_sent
            || !self.shutdown.graceful
            || !self.shutdown.exit_success
            || !self.shutdown.process_tree_cleanup_complete
        {
            return Some("managed OpenOCD server did not complete a graceful shutdown");
        }
        validate_complete_logs(&self.logs).err()
    }
}

#[derive(Debug, Serialize)]
struct ServerConfirmationInput<'a> {
    schema_version: &'static str,
    operation: &'static str,
    backend: &'static str,
    executable_path: &'a str,
    executable_version: &'a str,
    executable_file: &'a OpenOcdExecutableFileIdentity,
    configuration: &'a OpenOcdConfigurationInspection,
    lifecycle: &'a OpenOcdServerLifecyclePlan,
    effects: &'a OpenOcdServerEffects,
    confirmation_boundary: &'a OpenOcdServerConfirmationBoundary,
}

pub fn plan_server(options: &OpenOcdServerOptions) -> Result<OpenOcdServerPlan> {
    validate_server_options(options)?;

    let inspect_options = OpenOcdInspectOptions {
        executable: options.executable.clone(),
        config_files: options.config_files.clone(),
        search_dirs: options.search_dirs.clone(),
        timeout_ms: options.version_timeout_ms,
    };
    let configuration =
        super::inspect_configuration(&inspect_options.config_files, &inspect_options.search_dirs)?;
    let executable =
        super::inspect_executable(&inspect_options.executable, inspect_options.timeout_ms)?;
    let executable_file = inspect_executable_file(Path::new(&executable.resolved))?;
    let lifecycle = lifecycle_plan(options);
    let effects = server_effects();
    let confirmation_boundary = confirmation_boundary();
    let confirmation = ServerConfirmationInput {
        schema_version: SCHEMA_VERSION,
        operation: "openocd.server.test",
        backend: "openocd",
        executable_path: &executable.resolved,
        executable_version: &executable.version_line,
        executable_file: &executable_file,
        configuration: &configuration,
        lifecycle: &lifecycle,
        effects: &effects,
        confirmation_boundary: &confirmation_boundary,
    };
    let confirm_digest = hex::encode(Sha256::digest(
        serde_json::to_vec(&confirmation).expect("OpenOCD confirmation input always serializes"),
    ));

    Ok(OpenOcdServerPlan {
        backend: "openocd".to_string(),
        operation: "openocd.server.test".to_string(),
        risk: "R2_DEVICE_WRITE".to_string(),
        complete: true,
        executable,
        executable_file,
        configuration,
        lifecycle,
        effects,
        confirmation_boundary,
        confirm_digest,
    })
}

pub fn test_server(
    options: &OpenOcdServerOptions,
    confirm_digest: &str,
) -> Result<OpenOcdServerTestReport> {
    let plan = plan_server(options)?;
    if plan.confirm_digest != confirm_digest {
        return Err(server_confirmation_error(
            &plan.confirm_digest,
            confirm_digest,
        ));
    }
    execute_server_plan(plan)
}

pub(super) fn validate_server_options(options: &OpenOcdServerOptions) -> Result<()> {
    super::validate_options(&OpenOcdInspectOptions {
        executable: options.executable.clone(),
        config_files: options.config_files.clone(),
        search_dirs: options.search_dirs.clone(),
        timeout_ms: options.version_timeout_ms,
    })?;
    validate_server_timeout(
        "startup",
        options.startup_timeout_ms,
        MIN_OPENOCD_SERVER_STARTUP_TIMEOUT_MS,
        MAX_OPENOCD_SERVER_STARTUP_TIMEOUT_MS,
    )?;
    validate_server_timeout(
        "shutdown",
        options.shutdown_timeout_ms,
        MIN_OPENOCD_SERVER_SHUTDOWN_TIMEOUT_MS,
        MAX_OPENOCD_SERVER_SHUTDOWN_TIMEOUT_MS,
    )?;
    if options.config_files.is_empty() {
        return Err(DebugError::config(
            "managed OpenOCD server requires at least one top-level configuration file",
            json!({"required_argument": "--config <FILE>"}),
        ));
    }
    Ok(())
}

fn validate_server_timeout(label: &str, value: u64, minimum: u64, maximum: u64) -> Result<()> {
    if !(minimum..=maximum).contains(&value) {
        return Err(DebugError::config(
            format!("OpenOCD server {label} timeout is outside the supported range"),
            json!({
                "timeout_kind": label,
                "timeout_ms": value,
                "minimum": minimum,
                "maximum": maximum,
            }),
        ));
    }
    Ok(())
}

fn lifecycle_plan(options: &OpenOcdServerOptions) -> OpenOcdServerLifecyclePlan {
    OpenOcdServerLifecyclePlan {
        bind_address: OPENOCD_BIND_ADDRESS.to_string(),
        gdb_port_allocation: "operating_system_selected".to_string(),
        tcl_port_allocation: "operating_system_selected".to_string(),
        telnet_server: "disabled".to_string(),
        readiness_probe: "tcl_rpc.version".to_string(),
        tcl_message_terminator: "0x1a".to_string(),
        graceful_shutdown: "tcl_rpc.shutdown".to_string(),
        process_isolation: process_isolation().to_string(),
        version_timeout_ms: options.version_timeout_ms,
        startup_timeout_ms: options.startup_timeout_ms,
        shutdown_timeout_ms: options.shutdown_timeout_ms,
    }
}

fn server_effects() -> OpenOcdServerEffects {
    OpenOcdServerEffects {
        configuration_tcl_execution_required: true,
        configuration_semantics_statically_verified: false,
        transitive_sources_resolved: false,
        adapter_or_target_access_possible: true,
        reset_possible_from_configuration: true,
        device_write_possible_from_configuration: true,
        arbitrary_host_command_execution_possible_from_configuration: true,
        explicit_target_control_command_requested_by_tool: false,
        explicit_flash_command_requested_by_tool: false,
        target_state_restoration_verified: false,
        notes: vec![
            "OpenOCD configuration is executable Tcl; only explicitly listed top-level files are hashed.".to_string(),
            "Search directory contents, transitive sources, Tcl side effects, and target state preservation are not statically proven.".to_string(),
            "The tool adds only loopback server policy, dynamic ports, a Tcl version query, and Tcl shutdown; configuration code may do more.".to_string(),
        ],
    }
}

fn confirmation_boundary() -> OpenOcdServerConfirmationBoundary {
    OpenOcdServerConfirmationBoundary {
        executable_file_hash_bound: true,
        executable_version_bound: true,
        top_level_configuration_hashes_bound: true,
        search_directory_paths_bound: true,
        search_directory_contents_bound: false,
        transitive_sources_bound: false,
        configuration_semantics_verified: false,
    }
}

fn process_isolation() -> &'static str {
    #[cfg(windows)]
    {
        "windows_job_object"
    }
    #[cfg(unix)]
    {
        "unix_process_group"
    }
}

fn inspect_executable_file(path: &Path) -> Result<OpenOcdExecutableFileIdentity> {
    let metadata = fs::metadata(path).map_err(|source| {
        DebugError::io(
            "read selected OpenOCD executable metadata",
            path.to_str(),
            &source,
        )
    })?;
    if metadata.len() > MAX_OPENOCD_EXECUTABLE_BYTES {
        return Err(DebugError::config(
            "selected OpenOCD executable exceeds the identity hashing limit",
            json!({
                "path": path.to_string_lossy(),
                "bytes": metadata.len(),
                "maximum": MAX_OPENOCD_EXECUTABLE_BYTES,
            }),
        ));
    }

    let mut file = File::open(path).map_err(|source| {
        DebugError::io("open selected OpenOCD executable", path.to_str(), &source)
    })?;
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|source| {
            DebugError::io("hash selected OpenOCD executable", path.to_str(), &source)
        })?;
        if count == 0 {
            break;
        }
        total = total.saturating_add(count as u64);
        if total > MAX_OPENOCD_EXECUTABLE_BYTES {
            return Err(DebugError::config(
                "selected OpenOCD executable grew beyond the identity hashing limit",
                json!({
                    "path": path.to_string_lossy(),
                    "maximum": MAX_OPENOCD_EXECUTABLE_BYTES,
                }),
            ));
        }
        hasher.update(&buffer[..count]);
    }
    if total != metadata.len() {
        return Err(DebugError::config(
            "selected OpenOCD executable changed while its identity was being captured",
            json!({
                "path": path.to_string_lossy(),
                "metadata_bytes": metadata.len(),
                "read_bytes": total,
            }),
        ));
    }

    Ok(OpenOcdExecutableFileIdentity {
        bytes: total,
        sha256: hex::encode(hasher.finalize()),
        maximum_bytes: MAX_OPENOCD_EXECUTABLE_BYTES,
    })
}

fn server_confirmation_error(expected: &str, received: &str) -> DebugError {
    let mut error = DebugError::new(
        ErrorCode::ConfirmationMismatch,
        "OpenOCD server confirmation digest does not match the current launch plan",
        2,
        json!({
            "expected_confirm_digest": expected,
            "received_confirm_digest": received,
        }),
    );
    error.suggested_actions.push(SuggestedAction::new(
        "review_openocd_server_plan",
        json!({"command": "openocd server plan"}),
    ));
    error
}

fn execute_server_plan(plan: OpenOcdServerPlan) -> Result<OpenOcdServerTestReport> {
    let server = start_managed_server(&plan)?;
    let completion = server.finish();
    if let Some(message) = completion.lifecycle_error() {
        return Err(protocol_error_with_lifecycle(
            message,
            json!({}),
            &completion.shutdown,
            &completion.logs,
        ));
    }

    Ok(OpenOcdServerTestReport {
        backend: plan.backend,
        scope: "managed_server_lifecycle".to_string(),
        risk: plan.risk,
        complete: true,
        confirm_digest: plan.confirm_digest,
        executable: plan.executable,
        executable_file: plan.executable_file,
        configuration: plan.configuration,
        lifecycle: plan.lifecycle,
        readiness: completion.readiness,
        shutdown: completion.shutdown,
        effects: plan.effects,
        confirmation_boundary: plan.confirmation_boundary,
        capabilities: OpenOcdServerCapabilities {
            server_launch: true,
            tcl_rpc: true,
            dynamic_gdb_endpoint: true,
            telnet_server: false,
            gdb_mi: false,
            target_operations: false,
            flash: false,
        },
        logs: completion.logs,
    })
}

pub(super) fn start_managed_server(plan: &OpenOcdServerPlan) -> Result<ManagedServerSession> {
    let mut command = Command::new(&plan.executable.resolved);
    for search_dir in &plan.configuration.search_dirs {
        command.arg("-s").arg(search_dir);
    }
    command
        .arg("-c")
        .arg(format!("bindto {}", plan.lifecycle.bind_address))
        .arg("-c")
        .arg("gdb port 0")
        .arg("-c")
        .arg("tcl port 0")
        .arg("-c")
        .arg("telnet port disabled");
    for config in &plan.configuration.top_level_files {
        command.arg("-f").arg(&config.path);
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut server = ManagedOpenOcd::spawn(command, &plan.executable.resolved)?;
    let readiness =
        match server.wait_until_ready(Duration::from_millis(plan.lifecycle.startup_timeout_ms)) {
            Ok(readiness) => readiness,
            Err(failure) => {
                return Err(finalize_failure(
                    server,
                    failure,
                    plan.lifecycle.shutdown_timeout_ms,
                ));
            }
        };

    Ok(ManagedServerSession {
        server,
        readiness: OpenOcdServerReadiness {
            probe: "tcl_rpc.version".to_string(),
            bind_address: OPENOCD_BIND_ADDRESS.to_string(),
            tcl_port: readiness.tcl_port,
            gdb_port: readiness.gdb_port,
            telnet_enabled: false,
            tcl_version_response: readiness.version_response,
            elapsed_ms: duration_ms(readiness.elapsed),
            timeout_ms: plan.lifecycle.startup_timeout_ms,
        },
        shutdown_timeout_ms: plan.lifecycle.shutdown_timeout_ms,
    })
}

impl ManagedServerSession {
    pub fn readiness(&self) -> &OpenOcdServerReadiness {
        &self.readiness
    }

    pub fn tcl_request(
        &self,
        command: &str,
        timeout: Duration,
    ) -> std::result::Result<String, String> {
        tcl_request(self.readiness.tcl_port, command.as_bytes(), timeout, true)
    }

    pub fn finish(mut self) -> ManagedServerCompletion {
        let mut shutdown = self.server.cleanup(
            Some(self.readiness.tcl_port),
            true,
            Duration::from_millis(self.shutdown_timeout_ms),
        );
        let logs = self.server.finish_logs();
        shutdown.process_tree_cleanup_complete &= output_streams_closed(&logs);
        ManagedServerCompletion {
            readiness: self.readiness,
            shutdown,
            logs,
        }
    }
}

fn validate_complete_logs(logs: &OpenOcdServerLogs) -> std::result::Result<(), &'static str> {
    for stream in [&logs.stdout, &logs.stderr] {
        if !stream.drain_complete || stream.read_error.is_some() {
            return Err("managed OpenOCD output stream did not drain completely");
        }
        if stream.truncated {
            return Err("managed OpenOCD output exceeded the bounded capture limit");
        }
        if stream.line_limit_exceeded {
            return Err("managed OpenOCD emitted a log line beyond the bounded line limit");
        }
        if stream.events_dropped != 0 {
            return Err("managed OpenOCD log event queue overflowed");
        }
    }
    Ok(())
}

fn output_streams_closed(logs: &OpenOcdServerLogs) -> bool {
    [&logs.stdout, &logs.stderr]
        .into_iter()
        .all(|stream| stream.drain_complete && stream.read_error.is_none())
}

fn protocol_error_with_lifecycle(
    message: impl Into<String>,
    details: Value,
    shutdown: &OpenOcdServerShutdown,
    logs: &OpenOcdServerLogs,
) -> DebugError {
    let mut object = details.as_object().cloned().unwrap_or_default();
    object.insert(
        "shutdown".to_string(),
        serde_json::to_value(shutdown).expect("OpenOCD shutdown always serializes"),
    );
    object.insert(
        "logs".to_string(),
        serde_json::to_value(logs).expect("OpenOCD logs always serialize"),
    );
    DebugError::new(ErrorCode::ProtocolError, message, 6, Value::Object(object))
}

#[derive(Debug)]
struct LifecycleFailure {
    code: ErrorCode,
    message: String,
    exit_code: i32,
    retryable: bool,
    details: Value,
}

fn finalize_failure(
    mut server: ManagedOpenOcd,
    failure: LifecycleFailure,
    shutdown_timeout_ms: u64,
) -> DebugError {
    let tcl_port = server.tcl_port;
    let mut shutdown = server.cleanup(
        tcl_port,
        tcl_port.is_some(),
        Duration::from_millis(shutdown_timeout_ms),
    );
    let logs = server.finish_logs();
    shutdown.process_tree_cleanup_complete &= output_streams_closed(&logs);
    let mut object = failure.details.as_object().cloned().unwrap_or_default();
    object.insert(
        "shutdown".to_string(),
        serde_json::to_value(shutdown).expect("OpenOCD shutdown always serializes"),
    );
    object.insert(
        "logs".to_string(),
        serde_json::to_value(logs).expect("OpenOCD logs always serialize"),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerLogStream {
    Stdout,
    Stderr,
}

impl ServerLogStream {
    fn name(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}

#[derive(Debug)]
struct ServerLogEvent {
    stream: ServerLogStream,
    line: String,
}

#[derive(Debug)]
struct ServerStreamCapture {
    retained: Vec<u8>,
    total_bytes: u64,
    sha256: String,
    truncated: bool,
    line_limit_exceeded: bool,
    events_dropped: u64,
    drain_complete: bool,
    read_error: Option<String>,
}

impl ServerStreamCapture {
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

    fn summary(self) -> OpenOcdServerLogSummary {
        OpenOcdServerLogSummary {
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
                .take(SERVER_LOG_SNIPPET_CHARS)
                .collect(),
        }
    }
}

struct ManagedOpenOcd {
    child: Option<Box<dyn ChildWrapper>>,
    events: Receiver<ServerLogEvent>,
    stdout_reader: Option<JoinHandle<ServerStreamCapture>>,
    stderr_reader: Option<JoinHandle<ServerStreamCapture>>,
    started: Instant,
    tcl_port: Option<u16>,
    gdb_port: Option<u16>,
    port_error: Option<String>,
    observed_status: Option<ExitStatus>,
}

impl ManagedOpenOcd {
    fn spawn(mut command: Command, executable: &str) -> Result<Self> {
        command
            .stdin(Stdio::null())
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
                "managed OpenOCD server could not be started",
                json!({
                    "backend": "openocd",
                    "capability": "server_launch",
                    "executable": executable,
                    "cause": source.to_string(),
                    "process_isolation": process_isolation(),
                }),
            )
        })?;
        let stdout = child.stdout().take();
        let stderr = child.stderr().take();
        let (Some(stdout), Some(stderr)) = (stdout, stderr) else {
            let _ = child.start_kill();
            let _ = child.wait();
            return Err(DebugError::new(
                ErrorCode::Internal,
                "managed OpenOCD server did not provide its requested output pipes",
                10,
                json!({"executable": executable}),
            ));
        };

        let (sender, events) = mpsc::sync_channel(SERVER_LOG_EVENT_QUEUE_CAPACITY);
        let stdout_reader = capture_server_stream(stdout, ServerLogStream::Stdout, sender.clone());
        let stderr_reader = capture_server_stream(stderr, ServerLogStream::Stderr, sender);

        Ok(Self {
            child: Some(child),
            events,
            stdout_reader: Some(stdout_reader),
            stderr_reader: Some(stderr_reader),
            started: Instant::now(),
            tcl_port: None,
            gdb_port: None,
            port_error: None,
            observed_status: None,
        })
    }

    fn wait_until_ready(
        &mut self,
        timeout: Duration,
    ) -> std::result::Result<ReadinessInternal, LifecycleFailure> {
        let deadline = self.started + timeout;
        let mut next_tcl_attempt = Instant::now();
        let mut last_tcl_error = None;

        loop {
            self.drain_events();
            if let Some(port_error) = self.port_error.take() {
                return Err(LifecycleFailure {
                    code: ErrorCode::ProtocolError,
                    message: "managed OpenOCD server emitted conflicting endpoint ports"
                        .to_string(),
                    exit_code: 6,
                    retryable: false,
                    details: json!({"cause": port_error}),
                });
            }
            if let Some(status) = self.poll_status().map_err(|source| LifecycleFailure {
                code: ErrorCode::Internal,
                message: "poll managed OpenOCD server failed".to_string(),
                exit_code: 10,
                retryable: false,
                details: json!({"cause": source.to_string()}),
            })? {
                return Err(LifecycleFailure {
                    code: ErrorCode::CapabilityUnavailable,
                    message: "managed OpenOCD server exited before Tcl readiness was proven"
                        .to_string(),
                    exit_code: 4,
                    retryable: false,
                    details: json!({
                        "exit_code": status.code(),
                        "tcl_port": self.tcl_port,
                        "gdb_port": self.gdb_port,
                        "last_tcl_error": last_tcl_error,
                    }),
                });
            }

            let now = Instant::now();
            if let (Some(tcl_port), Some(gdb_port)) = (self.tcl_port, self.gdb_port)
                && now >= next_tcl_attempt
            {
                let remaining = deadline.saturating_duration_since(now);
                let attempt_timeout = TCL_ATTEMPT_TIMEOUT.min(remaining);
                if !attempt_timeout.is_zero() {
                    match tcl_version(tcl_port, attempt_timeout) {
                        Ok(version_response) => {
                            return Ok(ReadinessInternal {
                                tcl_port,
                                gdb_port,
                                version_response,
                                elapsed: self.started.elapsed(),
                            });
                        }
                        Err(error) => {
                            last_tcl_error = Some(error);
                            next_tcl_attempt = Instant::now() + TCL_RETRY_INTERVAL;
                        }
                    }
                }
            }

            if Instant::now() >= deadline {
                return Err(LifecycleFailure {
                    code: ErrorCode::Timeout,
                    message: "managed OpenOCD server did not become ready before its deadline"
                        .to_string(),
                    exit_code: 5,
                    retryable: true,
                    details: json!({
                        "timeout_ms": duration_ms(timeout),
                        "elapsed_ms": duration_ms(self.started.elapsed()),
                        "tcl_port": self.tcl_port,
                        "gdb_port": self.gdb_port,
                        "last_tcl_error": last_tcl_error,
                    }),
                });
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            match self
                .events
                .recv_timeout(SERVER_POLL_INTERVAL.min(remaining))
            {
                Ok(event) => self.observe_event(event),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {}
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
            .expect("managed OpenOCD child exists until cleanup")
            .try_wait()?;
        if let Some(status) = status {
            self.observed_status = Some(status);
        }
        Ok(status)
    }

    fn drain_events(&mut self) {
        loop {
            match self.events.try_recv() {
                Ok(event) => self.observe_event(event),
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => return,
            }
        }
    }

    fn observe_event(&mut self, event: ServerLogEvent) {
        eprintln!("[openocd:{}] {}", event.stream.name(), event.line);
        if let Some(port) = parse_listening_port(&event.line, "tcl") {
            record_port(&mut self.tcl_port, port, "tcl", &mut self.port_error);
        }
        if let Some(port) = parse_listening_port(&event.line, "gdb") {
            record_port(&mut self.gdb_port, port, "gdb", &mut self.port_error);
        }
    }

    fn cleanup(
        &mut self,
        tcl_port: Option<u16>,
        request_shutdown: bool,
        timeout: Duration,
    ) -> OpenOcdServerShutdown {
        let started = Instant::now();
        let mut command_sent = false;
        let mut command_error = None;
        if request_shutdown {
            if let Some(port) = tcl_port {
                match send_tcl_shutdown(port, TCL_ATTEMPT_TIMEOUT.min(timeout)) {
                    Ok(()) => command_sent = true,
                    Err(error) => command_error = Some(error),
                }
            } else {
                command_error = Some("Tcl endpoint was not discovered".to_string());
            }
        }

        let deadline = started + timeout;
        while self.observed_status.is_none() && Instant::now() < deadline {
            self.drain_events();
            match self.poll_status() {
                Ok(Some(_)) => break,
                Ok(None) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    thread::sleep(SERVER_POLL_INTERVAL.min(remaining));
                }
                Err(error) => {
                    command_error.get_or_insert_with(|| format!("poll server exit: {error}"));
                    break;
                }
            }
        }

        let forced_process_tree_kill = self.observed_status.is_none();
        let mut termination_error = None;
        let mut wait_error = None;
        let mut final_status = self.observed_status;
        if let Some(mut child) = self.child.take() {
            if let Err(error) = child.start_kill()
                && !process_tree_is_absent(&error)
            {
                termination_error = Some(error.to_string());
            }
            // A Windows JobObject try_wait may consume the job-empty completion event.
            // Once the parent status is known, terminating the job and closing its handle
            // is sufficient; pipe closure below verifies that descendants are gone.
            if final_status.is_none() {
                match child.wait() {
                    Ok(status) => final_status = Some(status),
                    Err(error) => wait_error = Some(error.to_string()),
                }
            }
        }
        self.observed_status = final_status;
        self.drain_events();

        let exit_success = final_status.is_some_and(|status| status.success());
        let graceful = request_shutdown
            && command_sent
            && !forced_process_tree_kill
            && exit_success
            && wait_error.is_none();
        let process_tree_cleanup_complete = termination_error.is_none() && wait_error.is_none();
        OpenOcdServerShutdown {
            command: "shutdown".to_string(),
            requested: request_shutdown,
            command_sent,
            graceful,
            exit_code: final_status.and_then(|status| status.code()),
            exit_success,
            elapsed_ms: duration_ms(started.elapsed()),
            timeout_ms: duration_ms(timeout),
            forced_process_tree_kill,
            process_tree_termination_enforced: true,
            process_tree_cleanup_complete,
            command_error,
            termination_error,
            wait_error,
        }
    }

    fn finish_logs(&mut self) -> OpenOcdServerLogs {
        self.drain_events();
        let deadline = Instant::now() + SERVER_STREAM_DRAIN_GRACE;
        let stdout = finish_server_stream(self.stdout_reader.take(), deadline).summary();
        let stderr = finish_server_stream(self.stderr_reader.take(), deadline).summary();
        OpenOcdServerLogs {
            output_limit_bytes_per_stream: MAX_SERVER_OUTPUT_BYTES_PER_STREAM as u64,
            line_limit_bytes: MAX_SERVER_LOG_LINE_BYTES as u64,
            event_queue_capacity: SERVER_LOG_EVENT_QUEUE_CAPACITY as u64,
            stdout,
            stderr,
        }
    }
}

impl Drop for ManagedOpenOcd {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
            let _ = child.wait();
        }
    }
}

#[derive(Debug)]
struct ReadinessInternal {
    tcl_port: u16,
    gdb_port: u16,
    version_response: String,
    elapsed: Duration,
}

fn capture_server_stream<R: Read + Send + 'static>(
    mut stream: R,
    stream_name: ServerLogStream,
    sender: SyncSender<ServerLogEvent>,
) -> JoinHandle<ServerStreamCapture> {
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
                        send_log_event(&sender, stream_name, &line, &mut events_dropped);
                    }
                    return ServerStreamCapture {
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
                    let remaining =
                        MAX_SERVER_OUTPUT_BYTES_PER_STREAM.saturating_sub(retained.len());
                    retained.extend_from_slice(&bytes[..bytes.len().min(remaining)]);
                    truncated = total_bytes > MAX_SERVER_OUTPUT_BYTES_PER_STREAM as u64;

                    for byte in bytes {
                        if *byte == b'\n' {
                            send_log_event(&sender, stream_name, &line, &mut events_dropped);
                            line.clear();
                            line_overflow = false;
                        } else if line.len() < MAX_SERVER_LOG_LINE_BYTES {
                            line.push(*byte);
                        } else {
                            line_overflow = true;
                            line_limit_exceeded = true;
                        }
                    }
                }
                Err(error) => {
                    return ServerStreamCapture {
                        retained,
                        total_bytes,
                        sha256: hex::encode(hasher.finalize()),
                        truncated,
                        line_limit_exceeded,
                        events_dropped,
                        drain_complete: false,
                        read_error: Some(error.to_string()),
                    };
                }
            }
        }
    })
}

fn send_log_event(
    sender: &SyncSender<ServerLogEvent>,
    stream: ServerLogStream,
    bytes: &[u8],
    events_dropped: &mut u64,
) {
    let line = String::from_utf8_lossy(bytes)
        .trim_end_matches('\r')
        .to_string();
    match sender.try_send(ServerLogEvent { stream, line }) {
        Ok(()) => {}
        Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
            *events_dropped = events_dropped.saturating_add(1);
        }
    }
}

fn finish_server_stream(
    handle: Option<JoinHandle<ServerStreamCapture>>,
    deadline: Instant,
) -> ServerStreamCapture {
    let Some(handle) = handle else {
        return ServerStreamCapture::incomplete("server output reader was not available");
    };
    while !handle.is_finished() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(1));
    }
    if !handle.is_finished() {
        return ServerStreamCapture::incomplete(
            "server output stream did not close after process-tree cleanup",
        );
    }
    handle
        .join()
        .unwrap_or_else(|_| ServerStreamCapture::incomplete("server output reader thread panicked"))
}

fn parse_listening_port(line: &str, service: &str) -> Option<u16> {
    let marker = "Listening on port ";
    let suffix = format!("for {service} connections");
    let after_marker = line.split_once(marker)?.1.trim();
    let (port, after_port) = after_marker.split_once(char::is_whitespace)?;
    let port = port.parse::<u16>().ok().filter(|port| *port != 0)?;
    (after_port.trim() == suffix).then_some(port)
}

fn record_port(slot: &mut Option<u16>, port: u16, service: &str, error: &mut Option<String>) {
    match *slot {
        None => *slot = Some(port),
        Some(existing) if existing == port => {}
        Some(existing) => {
            *error = Some(format!(
                "OpenOCD reported conflicting {service} ports {existing} and {port}"
            ));
        }
    }
}

fn tcl_version(port: u16, timeout: Duration) -> std::result::Result<String, String> {
    let response = tcl_request(port, b"version", timeout, true)?;
    if !response.lines().map(str::trim).any(|line| {
        line.starts_with("Open On-Chip Debugger")
            || line.to_ascii_lowercase().starts_with("openocd ")
    }) {
        return Err("Tcl version response did not identify itself as OpenOCD".to_string());
    }
    Ok(response)
}

fn send_tcl_shutdown(port: u16, timeout: Duration) -> std::result::Result<(), String> {
    tcl_request(port, b"shutdown", timeout, false).map(|_| ())
}

fn tcl_request(
    port: u16,
    command: &[u8],
    timeout: Duration,
    read_response: bool,
) -> std::result::Result<String, String> {
    if timeout.is_zero() {
        return Err("Tcl request timeout was exhausted".to_string());
    }
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let mut stream = TcpStream::connect_timeout(&address, timeout)
        .map_err(|error| format!("connect Tcl endpoint {address}: {error}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| format!("set Tcl read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|error| format!("set Tcl write timeout: {error}"))?;
    stream
        .write_all(command)
        .and_then(|_| stream.write_all(&[TCL_MESSAGE_TERMINATOR]))
        .and_then(|_| stream.flush())
        .map_err(|error| format!("write framed Tcl request: {error}"))?;
    if !read_response {
        let _ = stream.shutdown(Shutdown::Write);
        return Ok(String::new());
    }

    let mut response = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let count = stream
            .read(&mut buffer)
            .map_err(|error| format!("read framed Tcl response: {error}"))?;
        if count == 0 {
            return Err("Tcl endpoint closed before the response terminator".to_string());
        }
        if let Some(position) = buffer[..count]
            .iter()
            .position(|byte| *byte == TCL_MESSAGE_TERMINATOR)
        {
            if response.len().saturating_add(position) > MAX_TCL_RESPONSE_BYTES {
                return Err("Tcl response exceeded the bounded response limit".to_string());
            }
            response.extend_from_slice(&buffer[..position]);
            return String::from_utf8(response)
                .map(|response| response.trim().to_string())
                .map_err(|_| "Tcl response was not valid UTF-8".to_string());
        }
        if response.len().saturating_add(count) > MAX_TCL_RESPONSE_BYTES {
            return Err("Tcl response exceeded the bounded response limit".to_string());
        }
        response.extend_from_slice(&buffer[..count]);
    }
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        process::{Command, Stdio},
        thread,
        time::Duration,
    };

    use super::*;

    const HELPER_ROLE: &str = "EMBEDDED_DEBUGGER_OPENOCD_SERVER_HELPER_ROLE";

    #[test]
    fn listening_port_parser_accepts_only_exact_nonzero_service_lines() {
        assert_eq!(
            parse_listening_port("Info : Listening on port 10017 for tcl connections", "tcl"),
            Some(10017)
        );
        assert_eq!(
            parse_listening_port("Info : Listening on port 10018 for gdb connections", "gdb"),
            Some(10018)
        );
        assert_eq!(
            parse_listening_port("Info : Listening on port 0 for tcl connections", "tcl"),
            None
        );
        assert_eq!(
            parse_listening_port(
                "Info : Listening on port 10017 for telnet connections",
                "tcl"
            ),
            None
        );
    }

    #[test]
    fn tcl_client_requires_framing_and_a_recognizable_version() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            loop {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
                if byte[0] == TCL_MESSAGE_TERMINATOR {
                    break;
                }
            }
            assert_eq!(request, b"version\x1a");
            stream
                .write_all(b"Open On-Chip Debugger 0.12.0-test\x1a")
                .unwrap();
        });

        assert_eq!(
            tcl_version(port, Duration::from_secs(1)).unwrap(),
            "Open On-Chip Debugger 0.12.0-test"
        );
        server.join().unwrap();
    }

    #[test]
    fn server_options_reject_missing_config_and_bad_scalar_bounds() {
        let mut options = OpenOcdServerOptions {
            executable: PathBuf::from("openocd"),
            config_files: Vec::new(),
            search_dirs: Vec::new(),
            version_timeout_ms: super::super::DEFAULT_OPENOCD_VERSION_TIMEOUT_MS,
            startup_timeout_ms: DEFAULT_OPENOCD_SERVER_STARTUP_TIMEOUT_MS,
            shutdown_timeout_ms: DEFAULT_OPENOCD_SERVER_SHUTDOWN_TIMEOUT_MS,
        };
        let error = validate_server_options(&options).unwrap_err();
        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert!(error.message.contains("at least one"));

        options.startup_timeout_ms = 99;
        let error = validate_server_options(&options).unwrap_err();
        assert_eq!(error.details["timeout_kind"], "startup");
    }

    #[test]
    fn managed_server_helper() {
        let Some(role) = std::env::var_os(HELPER_ROLE) else {
            return;
        };
        if role == "descendant" {
            thread::sleep(Duration::from_secs(30));
            return;
        }

        let helper = "backend::openocd::server::tests::managed_server_helper";
        let mut descendant = if role == "server" {
            Some(
                Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", helper, "--nocapture"])
                    .env(HELPER_ROLE, "descendant")
                    .spawn()
                    .unwrap(),
            )
        } else {
            None
        };
        let tcl = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let gdb = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        eprintln!(
            "Info : Listening on port {} for tcl connections",
            tcl.local_addr().unwrap().port()
        );
        eprintln!(
            "Info : Listening on port {} for gdb connections",
            gdb.local_addr().unwrap().port()
        );

        'connections: loop {
            let (mut stream, _) = tcl.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            loop {
                match stream.read(&mut byte) {
                    Ok(0) => continue 'connections,
                    Ok(_) if byte[0] == TCL_MESSAGE_TERMINATOR => break,
                    Ok(_) => request.push(byte[0]),
                    Err(_) => continue 'connections,
                }
            }
            match request.as_slice() {
                b"version" => stream
                    .write_all(b"Open On-Chip Debugger 0.12.0-test\x1a")
                    .unwrap(),
                b"shutdown" => break,
                _ => {}
            }
        }
        if let Some(descendant) = &mut descendant {
            let _ = descendant.try_wait();
        }
    }

    #[test]
    fn managed_lifecycle_proves_readiness_shutdown_and_descendant_cleanup() {
        let helper = "backend::openocd::server::tests::managed_server_helper";
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", helper, "--nocapture"])
            .env(HELPER_ROLE, "server")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut server = ManagedOpenOcd::spawn(command, "test-helper").unwrap();
        let readiness = server.wait_until_ready(Duration::from_secs(5)).unwrap();
        assert!(readiness.tcl_port > 0);
        assert!(readiness.gdb_port > 0);
        assert!(readiness.version_response.contains("0.12.0-test"));

        let shutdown = server.cleanup(Some(readiness.tcl_port), true, Duration::from_secs(5));
        let logs = server.finish_logs();
        assert!(shutdown.command_sent);
        assert!(shutdown.graceful);
        assert!(shutdown.process_tree_termination_enforced);
        assert!(shutdown.process_tree_cleanup_complete);
        assert!(!shutdown.forced_process_tree_kill);
        assert!(logs.stdout.drain_complete);
        assert!(logs.stderr.drain_complete);
        assert_eq!(logs.stdout.events_dropped, 0);
        assert_eq!(logs.stderr.events_dropped, 0);
    }

    #[test]
    fn managed_lifecycle_does_not_block_after_a_job_without_descendants_exits() {
        let helper = "backend::openocd::server::tests::managed_server_helper";
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", helper, "--nocapture"])
            .env(HELPER_ROLE, "server_without_descendant")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut server = ManagedOpenOcd::spawn(command, "test-helper").unwrap();
        let readiness = server.wait_until_ready(Duration::from_secs(5)).unwrap();
        let shutdown = server.cleanup(Some(readiness.tcl_port), true, Duration::from_secs(5));
        let logs = server.finish_logs();

        assert!(shutdown.graceful);
        assert!(!shutdown.forced_process_tree_kill);
        assert!(shutdown.process_tree_cleanup_complete);
        assert!(output_streams_closed(&logs));
    }
}
