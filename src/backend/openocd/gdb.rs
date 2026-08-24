use std::{
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
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::error::{DebugError, ErrorCode, Result, SuggestedAction};

pub const DEFAULT_GDB_VERSION_TIMEOUT_MS: u64 = 10_000;
pub const MIN_GDB_VERSION_TIMEOUT_MS: u64 = 100;
pub const MAX_GDB_VERSION_TIMEOUT_MS: u64 = 30_000;
pub const DEFAULT_GDB_MI_STARTUP_TIMEOUT_MS: u64 = 10_000;
pub const MIN_GDB_MI_STARTUP_TIMEOUT_MS: u64 = 100;
pub const MAX_GDB_MI_STARTUP_TIMEOUT_MS: u64 = 60_000;
pub const DEFAULT_GDB_MI_SHUTDOWN_TIMEOUT_MS: u64 = 3_000;
pub const MIN_GDB_MI_SHUTDOWN_TIMEOUT_MS: u64 = 100;
pub const MAX_GDB_MI_SHUTDOWN_TIMEOUT_MS: u64 = 30_000;

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
const MI_LAUNCH_ARGUMENTS: [&str; 4] = ["--nx", "--nh", "--quiet", "--interpreter=mi2"];

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
    command.args(MI_LAUNCH_ARGUMENTS);
    let mut gdb = ManagedGdb::spawn(command, &inspection.executable.resolved)?;
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
    exit_command_sent: bool,
    exit_command_started: Option<Instant>,
    exit_result_class: Option<String>,
}

impl ManagedGdb {
    fn spawn(mut command: Command, executable: &str) -> Result<Self> {
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

    fn wait_for_prompt(&mut self, deadline: Instant) -> std::result::Result<(), LifecycleFailure> {
        loop {
            match self.next_record(deadline, "startup prompt")? {
                ParsedRecord::Prompt => return Ok(()),
                ParsedRecord::Result { token, class } => {
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
        loop {
            if let ParsedRecord::Result { token, class } = self.next_record(deadline, "result")? {
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
                return Ok(class);
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
        if let ParsedRecord::Result { token, class } = &record
            && *token == Some(EXIT_TOKEN)
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
        if token == EXIT_TOKEN {
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
            && let Err(failure) = self.send_command(EXIT_TOKEN, EXIT_COMMAND)
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
            token: EXIT_TOKEN,
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
    Result { token: Option<u64>, class: String },
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
        b'^' => Ok(ParsedRecord::Result {
            token,
            class: parse_class(payload, "result")?,
        }),
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
            }
        );
        assert_eq!(
            parse_record("2^exit").unwrap(),
            ParsedRecord::Result {
                token: Some(2),
                class: "exit".to_string(),
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
}
