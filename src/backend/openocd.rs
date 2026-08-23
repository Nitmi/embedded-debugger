use std::{
    collections::HashSet,
    env,
    ffi::OsString,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::error::{DebugError, ErrorCode, Result, SuggestedAction};

pub const DEFAULT_OPENOCD_VERSION_TIMEOUT_MS: u64 = 2_000;
pub const MIN_OPENOCD_VERSION_TIMEOUT_MS: u64 = 100;
pub const MAX_OPENOCD_VERSION_TIMEOUT_MS: u64 = 30_000;
pub const MAX_OPENOCD_CONFIG_FILES: usize = 64;
pub const MAX_OPENOCD_SEARCH_DIRS: usize = 64;
pub const MAX_OPENOCD_CONFIG_FILE_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_CAPTURED_VERSION_OUTPUT_BYTES: usize = 64 * 1024;

const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(10);
const STREAM_DRAIN_GRACE: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenOcdInspectOptions {
    pub executable: PathBuf,
    pub config_files: Vec<PathBuf>,
    pub search_dirs: Vec<PathBuf>,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdInspection {
    pub backend: String,
    pub scope: String,
    pub risk: String,
    pub complete: bool,
    pub executable: OpenOcdExecutableInspection,
    pub configuration: OpenOcdConfigurationInspection,
    pub server_enablement_requirements: OpenOcdServerEnablementRequirements,
    pub capabilities: OpenOcdInspectionCapabilities,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdExecutableInspection {
    pub requested: String,
    pub resolved: String,
    pub version_line: String,
    pub version_source: OpenOcdVersionSource,
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
pub enum OpenOcdVersionSource {
    Stdout,
    Stderr,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdConfigurationInspection {
    pub top_level_files: Vec<OpenOcdConfigFileInspection>,
    pub search_dirs: Vec<String>,
    pub semantic_validation: bool,
    pub sourced_files_resolved: bool,
    pub argument_order_preserved: bool,
    pub maximum_top_level_file_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdConfigFileInspection {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdServerEnablementRequirements {
    pub implemented: bool,
    pub bind_address: String,
    pub gdb_port_allocation: String,
    pub tcl_port_allocation: String,
    pub telnet_server: String,
    pub readiness_probe: String,
    pub tcl_message_terminator: String,
    pub graceful_shutdown: String,
    pub process_tree_cleanup_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdInspectionCapabilities {
    pub executable_discovery: bool,
    pub bounded_version_probe: bool,
    pub top_level_config_validation: bool,
    pub config_semantic_validation: bool,
    pub server_launch: bool,
    pub tcl_rpc: bool,
    pub gdb_mi: bool,
    pub target_operations: bool,
    pub flash: bool,
}

pub fn inspect(options: &OpenOcdInspectOptions) -> Result<OpenOcdInspection> {
    validate_options(options)?;
    let configuration = inspect_configuration(&options.config_files, &options.search_dirs)?;
    let executable = inspect_executable(&options.executable, options.timeout_ms)?;

    Ok(complete_host_inspection(executable, configuration))
}

fn complete_host_inspection(
    executable: OpenOcdExecutableInspection,
    configuration: OpenOcdConfigurationInspection,
) -> OpenOcdInspection {
    OpenOcdInspection {
        backend: "openocd".to_string(),
        scope: "host_only".to_string(),
        risk: "R0_READ_ONLY".to_string(),
        complete: true,
        executable,
        configuration,
        server_enablement_requirements: OpenOcdServerEnablementRequirements {
            implemented: false,
            bind_address: "127.0.0.1".to_string(),
            gdb_port_allocation: "dynamic".to_string(),
            tcl_port_allocation: "dynamic".to_string(),
            telnet_server: "disabled".to_string(),
            readiness_probe: "tcl_rpc".to_string(),
            tcl_message_terminator: "0x1a".to_string(),
            graceful_shutdown: "shutdown".to_string(),
            process_tree_cleanup_required: true,
        },
        capabilities: OpenOcdInspectionCapabilities {
            executable_discovery: true,
            bounded_version_probe: true,
            top_level_config_validation: true,
            config_semantic_validation: false,
            server_launch: false,
            tcl_rpc: false,
            gdb_mi: false,
            target_operations: false,
            flash: false,
        },
    }
}

pub fn inspect_executable(
    requested: &Path,
    timeout_ms: u64,
) -> Result<OpenOcdExecutableInspection> {
    validate_timeout(timeout_ms)?;
    let requested_display = stable_path(requested, "OpenOCD executable")?;
    let resolved = resolve_executable(requested)?;
    let resolved_display = stable_path(&resolved, "resolved OpenOCD executable")?;

    let mut command = Command::new(&resolved);
    command
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = run_bounded_command(
        command,
        &resolved_display,
        Duration::from_millis(timeout_ms),
    )?;

    executable_inspection_from_output(requested_display, resolved_display, timeout_ms, output)
}

fn validate_options(options: &OpenOcdInspectOptions) -> Result<()> {
    validate_timeout(options.timeout_ms)?;
    validate_executable_request(&options.executable)?;
    if options.config_files.len() > MAX_OPENOCD_CONFIG_FILES {
        return Err(DebugError::config(
            "too many top-level OpenOCD configuration files",
            json!({
                "count": options.config_files.len(),
                "maximum": MAX_OPENOCD_CONFIG_FILES,
            }),
        ));
    }
    if options.search_dirs.len() > MAX_OPENOCD_SEARCH_DIRS {
        return Err(DebugError::config(
            "too many OpenOCD configuration search directories",
            json!({
                "count": options.search_dirs.len(),
                "maximum": MAX_OPENOCD_SEARCH_DIRS,
            }),
        ));
    }
    Ok(())
}

fn validate_executable_request(requested: &Path) -> Result<()> {
    if requested.as_os_str().is_empty() {
        return Err(DebugError::config(
            "OpenOCD executable name must not be empty",
            json!({"requested_executable": ""}),
        ));
    }
    stable_path(requested, "OpenOCD executable")?;
    Ok(())
}

fn validate_timeout(timeout_ms: u64) -> Result<()> {
    if !(MIN_OPENOCD_VERSION_TIMEOUT_MS..=MAX_OPENOCD_VERSION_TIMEOUT_MS).contains(&timeout_ms) {
        return Err(DebugError::config(
            "OpenOCD version timeout is outside the supported range",
            json!({
                "timeout_ms": timeout_ms,
                "minimum": MIN_OPENOCD_VERSION_TIMEOUT_MS,
                "maximum": MAX_OPENOCD_VERSION_TIMEOUT_MS,
            }),
        ));
    }
    Ok(())
}

fn inspect_configuration(
    config_files: &[PathBuf],
    search_dirs: &[PathBuf],
) -> Result<OpenOcdConfigurationInspection> {
    let mut seen_files = HashSet::new();
    let mut normalized_files = Vec::with_capacity(config_files.len());
    for config_file in config_files {
        reject_tcl_comment_marker(config_file, "configuration file")?;
        let canonical = canonicalize_path(config_file, PathKind::File, "configuration file")?;
        reject_tcl_comment_marker(&canonical, "resolved configuration file")?;
        if !seen_files.insert(canonical.clone()) {
            return Err(DebugError::config(
                "duplicate OpenOCD configuration file",
                json!({"path": stable_path(&canonical, "configuration file")?}),
            ));
        }
        normalized_files.push(inspect_config_file(&canonical)?);
    }

    let mut seen_dirs = HashSet::new();
    let mut normalized_dirs = Vec::with_capacity(search_dirs.len());
    for search_dir in search_dirs {
        reject_tcl_comment_marker(search_dir, "configuration search directory")?;
        let canonical = canonicalize_path(
            search_dir,
            PathKind::Directory,
            "configuration search directory",
        )?;
        reject_tcl_comment_marker(&canonical, "resolved configuration search directory")?;
        if !seen_dirs.insert(canonical.clone()) {
            return Err(DebugError::config(
                "duplicate OpenOCD configuration search directory",
                json!({"path": stable_path(&canonical, "configuration search directory")?}),
            ));
        }
        normalized_dirs.push(stable_path(&canonical, "configuration search directory")?);
    }

    Ok(OpenOcdConfigurationInspection {
        top_level_files: normalized_files,
        search_dirs: normalized_dirs,
        semantic_validation: false,
        sourced_files_resolved: false,
        argument_order_preserved: true,
        maximum_top_level_file_bytes: MAX_OPENOCD_CONFIG_FILE_BYTES,
    })
}

fn inspect_config_file(path: &Path) -> Result<OpenOcdConfigFileInspection> {
    let display = stable_path(path, "configuration file")?;
    let metadata = fs::metadata(path)
        .map_err(|error| path_io_error("read OpenOCD configuration metadata", path, &error))?;
    if metadata.len() > MAX_OPENOCD_CONFIG_FILE_BYTES {
        return Err(DebugError::config(
            "OpenOCD configuration file exceeds the inspection size limit",
            json!({
                "path": display,
                "bytes": metadata.len(),
                "maximum": MAX_OPENOCD_CONFIG_FILE_BYTES,
            }),
        ));
    }

    let file = File::open(path)
        .map_err(|error| path_io_error("open OpenOCD configuration file", path, &error))?;
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.take(MAX_OPENOCD_CONFIG_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| path_io_error("read OpenOCD configuration file", path, &error))?;
    if bytes.len() as u64 > MAX_OPENOCD_CONFIG_FILE_BYTES {
        return Err(DebugError::config(
            "OpenOCD configuration file grew beyond the inspection size limit",
            json!({
                "path": display,
                "maximum": MAX_OPENOCD_CONFIG_FILE_BYTES,
            }),
        ));
    }

    Ok(OpenOcdConfigFileInspection {
        path: display,
        bytes: bytes.len() as u64,
        sha256: hex::encode(Sha256::digest(&bytes)),
    })
}

#[derive(Debug, Clone, Copy)]
enum PathKind {
    File,
    Directory,
}

fn canonicalize_path(path: &Path, kind: PathKind, label: &str) -> Result<PathBuf> {
    stable_path(path, label)?;
    let canonical = fs::canonicalize(path)
        .map_err(|error| path_io_error(&format!("resolve OpenOCD {label}"), path, &error))?;
    let metadata = fs::metadata(&canonical)
        .map_err(|error| path_io_error(&format!("inspect OpenOCD {label}"), path, &error))?;
    let matches_kind = match kind {
        PathKind::File => metadata.is_file(),
        PathKind::Directory => metadata.is_dir(),
    };
    if !matches_kind {
        return Err(DebugError::config(
            format!("OpenOCD {label} has the wrong filesystem type"),
            json!({
                "path": stable_path(path, label)?,
                "expected": match kind {
                    PathKind::File => "regular_file",
                    PathKind::Directory => "directory",
                },
            }),
        ));
    }
    Ok(canonical)
}

fn reject_tcl_comment_marker(path: &Path, label: &str) -> Result<()> {
    let display = stable_path(path, label)?;
    if display.contains('#') {
        return Err(DebugError::config(
            "OpenOCD configuration paths must not contain '#'",
            json!({"path": display, "path_kind": label}),
        ));
    }
    Ok(())
}

fn resolve_executable(requested: &Path) -> Result<PathBuf> {
    validate_executable_request(requested)?;
    if is_explicit_path(requested) {
        return canonicalize_path(requested, PathKind::File, "executable");
    }

    let path_value = env::var_os("PATH").unwrap_or_default();
    let extensions = executable_extensions(requested);
    for directory in env::split_paths(&path_value) {
        let candidate = directory.join(requested);
        if let Some(found) = executable_candidate(&candidate) {
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

    let requested_display = stable_path(requested, "OpenOCD executable")?;
    let mut error = DebugError::unavailable(
        ErrorCode::CapabilityUnavailable,
        "OpenOCD executable was not found on PATH",
        json!({
            "backend": "openocd",
            "capability": "host_tool_discovery",
            "requested_executable": requested_display,
        }),
    );
    error.suggested_actions.push(SuggestedAction::new(
        "install_or_select_openocd",
        json!({"argument": "--executable <PATH>"}),
    ));
    Err(error)
}

fn executable_candidate(path: &Path) -> Option<PathBuf> {
    if !path.is_file() {
        return None;
    }
    fs::canonicalize(path).ok()
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
            format!("OpenOCD {label} is not valid Unicode"),
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

fn path_io_error(operation: &str, path: &Path, source: &std::io::Error) -> DebugError {
    let display = path.to_string_lossy();
    if source.kind() == std::io::ErrorKind::PermissionDenied {
        DebugError::io(operation, Some(&display), source)
    } else {
        DebugError::config(
            format!("{operation} failed"),
            json!({"path": display, "cause": source.to_string()}),
        )
    }
}

#[derive(Debug)]
struct BoundedProcessOutput {
    success: bool,
    exit_code: Option<i32>,
    elapsed: Duration,
    stdout: CapturedStream,
    stderr: CapturedStream,
}

#[derive(Debug, Default)]
struct CapturedStream {
    retained: Vec<u8>,
    total_bytes: u64,
    truncated: bool,
    read_error: Option<String>,
    drain_complete: bool,
}

fn run_bounded_command(
    mut command: Command,
    executable: &str,
    timeout: Duration,
) -> Result<BoundedProcessOutput> {
    let started = Instant::now();
    let mut child = command.spawn().map_err(|source| {
        if source.kind() == std::io::ErrorKind::PermissionDenied {
            DebugError::io("start OpenOCD version probe", Some(executable), &source)
        } else {
            DebugError::unavailable(
                ErrorCode::CapabilityUnavailable,
                "OpenOCD executable could not be started",
                json!({
                    "backend": "openocd",
                    "capability": "version_probe",
                    "executable": executable,
                    "cause": source.to_string(),
                }),
            )
        }
    })?;
    let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(DebugError::new(
            ErrorCode::Internal,
            "OpenOCD version probe did not provide its requested output pipes",
            10,
            json!({"executable": executable}),
        ));
    };
    let stdout_reader = capture_stream(stdout);
    let stderr_reader = capture_stream(stderr);

    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < timeout => {
                let remaining = timeout.saturating_sub(started.elapsed());
                thread::sleep(PROCESS_POLL_INTERVAL.min(remaining));
            }
            Ok(None) => {
                let kill_error = child.kill().err().map(|error| error.to_string());
                let wait_error = child.wait().err().map(|error| error.to_string());
                let (stdout, stderr) = finish_streams(stdout_reader, stderr_reader);
                let mut error = DebugError::new(
                    ErrorCode::Timeout,
                    "OpenOCD version probe exceeded its deadline",
                    5,
                    json!({
                        "backend": "openocd",
                        "capability": "version_probe",
                        "executable": executable,
                        "timeout_ms": duration_ms(timeout),
                        "elapsed_ms": duration_ms(started.elapsed()),
                        "kill_error": kill_error,
                        "wait_error": wait_error,
                        "stdout": output_snippet(&stdout),
                        "stderr": output_snippet(&stderr),
                        "stdout_bytes": stdout.total_bytes,
                        "stderr_bytes": stderr.total_bytes,
                        "stdout_drain_complete": stdout.drain_complete,
                        "stderr_drain_complete": stderr.drain_complete,
                    }),
                );
                error.retryable = true;
                return Err(error);
            }
            Err(source) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = finish_streams(stdout_reader, stderr_reader);
                return Err(DebugError::io(
                    "poll OpenOCD version probe",
                    Some(executable),
                    &source,
                ));
            }
        }
    };

    let (stdout, stderr) = finish_streams(stdout_reader, stderr_reader);
    Ok(BoundedProcessOutput {
        success: status.success(),
        exit_code: status.code(),
        elapsed: started.elapsed(),
        stdout,
        stderr,
    })
}

fn capture_stream<R: Read + Send + 'static>(mut stream: R) -> JoinHandle<CapturedStream> {
    thread::spawn(move || {
        let mut capture = CapturedStream::default();
        let mut buffer = [0_u8; 4096];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => {
                    capture.drain_complete = true;
                    return capture;
                }
                Ok(count) => {
                    capture.total_bytes = capture.total_bytes.saturating_add(count as u64);
                    let remaining =
                        MAX_CAPTURED_VERSION_OUTPUT_BYTES.saturating_sub(capture.retained.len());
                    capture
                        .retained
                        .extend_from_slice(&buffer[..count.min(remaining)]);
                    capture.truncated =
                        capture.total_bytes > MAX_CAPTURED_VERSION_OUTPUT_BYTES as u64;
                }
                Err(source) => {
                    capture.read_error = Some(source.to_string());
                    return capture;
                }
            }
        }
    })
}

fn finish_streams(
    stdout: JoinHandle<CapturedStream>,
    stderr: JoinHandle<CapturedStream>,
) -> (CapturedStream, CapturedStream) {
    let deadline = Instant::now() + STREAM_DRAIN_GRACE;
    (
        finish_stream(stdout, deadline),
        finish_stream(stderr, deadline),
    )
}

fn finish_stream(handle: JoinHandle<CapturedStream>, deadline: Instant) -> CapturedStream {
    while !handle.is_finished() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(1));
    }
    if !handle.is_finished() {
        return CapturedStream {
            truncated: true,
            read_error: Some("output stream did not close after the child exited".to_string()),
            ..CapturedStream::default()
        };
    }
    handle.join().unwrap_or_else(|_| CapturedStream {
        read_error: Some("output reader thread panicked".to_string()),
        ..CapturedStream::default()
    })
}

fn executable_inspection_from_output(
    requested: String,
    resolved: String,
    timeout_ms: u64,
    output: BoundedProcessOutput,
) -> Result<OpenOcdExecutableInspection> {
    for (stream_name, stream) in [("stdout", &output.stdout), ("stderr", &output.stderr)] {
        if let Some(read_error) = &stream.read_error {
            return Err(DebugError::new(
                ErrorCode::ProtocolError,
                "OpenOCD version output could not be drained completely",
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
                "OpenOCD version output exceeded the bounded capture limit",
                6,
                json!({
                    "executable": resolved,
                    "stream": stream_name,
                    "bytes": stream.total_bytes,
                    "maximum": MAX_CAPTURED_VERSION_OUTPUT_BYTES,
                }),
            ));
        }
    }

    if !output.success {
        return Err(DebugError::unavailable(
            ErrorCode::CapabilityUnavailable,
            "OpenOCD version probe exited unsuccessfully",
            json!({
                "backend": "openocd",
                "capability": "version_probe",
                "executable": resolved,
                "exit_code": output.exit_code,
                "stdout": output_snippet(&output.stdout),
                "stderr": output_snippet(&output.stderr),
            }),
        ));
    }

    let (version_source, version_line) = find_openocd_version_line(&output.stdout, &output.stderr)
        .ok_or_else(|| {
            DebugError::config(
                "selected executable did not identify itself as OpenOCD",
                json!({
                    "requested_executable": requested,
                    "resolved_executable": resolved,
                    "stdout": output_snippet(&output.stdout),
                    "stderr": output_snippet(&output.stderr),
                }),
            )
        })?;

    Ok(OpenOcdExecutableInspection {
        requested,
        resolved,
        version_line,
        version_source,
        timeout_ms,
        elapsed_ms: duration_ms(output.elapsed),
        exit_code: output.exit_code.unwrap_or(0),
        stdout_bytes: output.stdout.total_bytes,
        stderr_bytes: output.stderr.total_bytes,
        output_limit_bytes_per_stream: MAX_CAPTURED_VERSION_OUTPUT_BYTES as u64,
        stdout_truncated: output.stdout.truncated,
        stderr_truncated: output.stderr.truncated,
    })
}

fn find_openocd_version_line(
    stdout: &CapturedStream,
    stderr: &CapturedStream,
) -> Option<(OpenOcdVersionSource, String)> {
    [
        (OpenOcdVersionSource::Stdout, &stdout.retained),
        (OpenOcdVersionSource::Stderr, &stderr.retained),
    ]
    .into_iter()
    .find_map(|(source, bytes)| {
        String::from_utf8_lossy(bytes)
            .lines()
            .map(str::trim)
            .find(|line| {
                line.starts_with("Open On-Chip Debugger")
                    || line.to_ascii_lowercase().starts_with("openocd ")
            })
            .map(|line| (source, line.to_string()))
    })
}

fn output_snippet(stream: &CapturedStream) -> String {
    String::from_utf8_lossy(&stream.retained)
        .chars()
        .take(2_048)
        .collect()
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::{fs, io::Cursor, process::Command, thread, time::Duration};

    use tempfile::tempdir;

    use super::*;

    fn captured(bytes: &[u8]) -> CapturedStream {
        CapturedStream {
            retained: bytes.to_vec(),
            total_bytes: bytes.len() as u64,
            drain_complete: true,
            ..CapturedStream::default()
        }
    }

    #[test]
    fn inspect_configuration_normalizes_and_hashes_top_level_files() {
        let directory = tempdir().unwrap();
        let config = directory.path().join("board.cfg");
        fs::write(&config, b"source [find interface/cmsis-dap.cfg]\n").unwrap();

        let inspection = inspect_configuration(
            std::slice::from_ref(&config),
            &[directory.path().to_path_buf()],
        )
        .unwrap();

        assert_eq!(inspection.top_level_files.len(), 1);
        assert_eq!(inspection.top_level_files[0].bytes, 38);
        assert_eq!(
            inspection.top_level_files[0].sha256,
            hex::encode(Sha256::digest(b"source [find interface/cmsis-dap.cfg]\n"))
        );
        assert_eq!(inspection.search_dirs.len(), 1);
        assert!(!inspection.semantic_validation);
        assert!(!inspection.sourced_files_resolved);
    }

    #[test]
    fn inspect_configuration_rejects_duplicates_and_tcl_comment_markers() {
        let directory = tempdir().unwrap();
        let config = directory.path().join("board.cfg");
        fs::write(&config, b"adapter speed 1000\n").unwrap();

        let duplicate = inspect_configuration(&[config.clone(), config], &[]).unwrap_err();
        assert_eq!(duplicate.code, ErrorCode::ConfigInvalid);
        assert!(duplicate.message.contains("duplicate"));

        let marked = directory.path().join("bad#board.cfg");
        fs::write(&marked, b"adapter speed 1000\n").unwrap();
        let marker = inspect_configuration(&[marked], &[]).unwrap_err();
        assert_eq!(marker.code, ErrorCode::ConfigInvalid);
        assert!(marker.message.contains("must not contain"));
    }

    #[test]
    fn inspect_configuration_rejects_oversized_top_level_files() {
        let directory = tempdir().unwrap();
        let config = directory.path().join("oversized.cfg");
        let file = File::create(&config).unwrap();
        file.set_len(MAX_OPENOCD_CONFIG_FILE_BYTES + 1).unwrap();

        let error = inspect_configuration(&[config], &[]).unwrap_err();
        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert_eq!(error.details["maximum"], MAX_OPENOCD_CONFIG_FILE_BYTES);
    }

    #[test]
    fn version_line_accepts_official_and_vendor_shapes_from_either_stream() {
        let stdout = captured(b"Open On-Chip Debugger 0.12.0\n");
        let stderr = captured(b"");
        assert_eq!(
            find_openocd_version_line(&stdout, &stderr),
            Some((
                OpenOcdVersionSource::Stdout,
                "Open On-Chip Debugger 0.12.0".to_string()
            ))
        );

        let stdout = captured(b"wrapper diagnostic\n");
        let stderr = captured(b"OpenOCD 0.11.0-vendor\n");
        assert_eq!(
            find_openocd_version_line(&stdout, &stderr),
            Some((
                OpenOcdVersionSource::Stderr,
                "OpenOCD 0.11.0-vendor".to_string()
            ))
        );
    }

    #[test]
    fn synthetic_success_keeps_target_capabilities_disabled() {
        let output = BoundedProcessOutput {
            success: true,
            exit_code: Some(0),
            elapsed: Duration::from_millis(12),
            stdout: captured(b"Open On-Chip Debugger 0.12.0\n"),
            stderr: captured(b""),
        };
        let executable = executable_inspection_from_output(
            "openocd".to_string(),
            "C:\\OpenOCD\\bin\\openocd.exe".to_string(),
            2_000,
            output,
        )
        .unwrap();
        let report = complete_host_inspection(
            executable,
            OpenOcdConfigurationInspection {
                top_level_files: vec![],
                search_dirs: vec![],
                semantic_validation: false,
                sourced_files_resolved: false,
                argument_order_preserved: true,
                maximum_top_level_file_bytes: MAX_OPENOCD_CONFIG_FILE_BYTES,
            },
        );

        assert_eq!(
            report.executable.version_source,
            OpenOcdVersionSource::Stdout
        );
        assert_eq!(report.executable.elapsed_ms, 12);
        assert!(!report.capabilities.server_launch);
        assert!(!report.capabilities.target_operations);
        assert!(!report.capabilities.flash);
    }

    #[test]
    fn bounded_process_helper() {
        if std::env::var_os("EMBEDDED_DEBUGGER_OPENOCD_TEST_OUTPUT").is_some() {
            println!("Open On-Chip Debugger 0.12.0-test");
        }
        if std::env::var_os("EMBEDDED_DEBUGGER_OPENOCD_TEST_SLEEP").is_some() {
            thread::sleep(Duration::from_secs(2));
        }
    }

    #[test]
    fn bounded_runner_collects_output_and_enforces_timeout() {
        let current_exe = std::env::current_exe().unwrap();
        let helper = "backend::openocd::tests::bounded_process_helper";

        let mut success = Command::new(&current_exe);
        success
            .args(["--exact", helper, "--nocapture"])
            .env("EMBEDDED_DEBUGGER_OPENOCD_TEST_OUTPUT", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = run_bounded_command(success, "test-helper", Duration::from_secs(5)).unwrap();
        assert!(output.success);
        assert!(output.stdout.drain_complete);
        assert!(
            String::from_utf8_lossy(&output.stdout.retained)
                .contains("Open On-Chip Debugger 0.12.0-test")
        );

        let mut timeout = Command::new(current_exe);
        timeout
            .args(["--exact", helper, "--nocapture"])
            .env("EMBEDDED_DEBUGGER_OPENOCD_TEST_SLEEP", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let error =
            run_bounded_command(timeout, "test-helper", Duration::from_millis(100)).unwrap_err();
        assert_eq!(error.code, ErrorCode::Timeout);
        assert!(error.retryable);
    }

    #[test]
    fn stream_capture_drains_all_bytes_but_retains_only_the_bounded_prefix() {
        let bytes = vec![b'x'; MAX_CAPTURED_VERSION_OUTPUT_BYTES + 17];
        let capture = capture_stream(Cursor::new(bytes)).join().unwrap();

        assert!(capture.drain_complete);
        assert!(capture.truncated);
        assert_eq!(
            capture.total_bytes,
            (MAX_CAPTURED_VERSION_OUTPUT_BYTES + 17) as u64
        );
        assert_eq!(capture.retained.len(), MAX_CAPTURED_VERSION_OUTPUT_BYTES);
    }

    #[test]
    fn empty_executable_name_is_a_configuration_error() {
        let error = resolve_executable(Path::new("")).unwrap_err();
        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert!(error.message.contains("must not be empty"));
    }

    #[test]
    fn empty_executable_is_rejected_before_configuration_filesystem_access() {
        let options = OpenOcdInspectOptions {
            executable: PathBuf::new(),
            config_files: vec![PathBuf::from("missing.cfg")],
            search_dirs: vec![],
            timeout_ms: DEFAULT_OPENOCD_VERSION_TIMEOUT_MS,
        };

        let error = inspect(&options).unwrap_err();
        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert!(error.message.contains("must not be empty"));
    }

    #[test]
    fn timeout_is_validated_before_filesystem_inputs() {
        let options = OpenOcdInspectOptions {
            executable: PathBuf::from("missing-openocd"),
            config_files: vec![PathBuf::from("missing.cfg")],
            search_dirs: vec![],
            timeout_ms: 99,
        };

        let error = inspect(&options).unwrap_err();
        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert_eq!(error.details["timeout_ms"], 99);
    }
}
