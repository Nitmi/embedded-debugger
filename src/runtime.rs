use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use chrono::{SecondsFormat, Utc};
#[cfg(windows)]
use process_wrap::std::JobObject;
#[cfg(unix)]
use process_wrap::std::ProcessGroup;
use process_wrap::std::{ChildWrapper, CommandWrap};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    SCHEMA_VERSION,
    backend::DebugBackend,
    error::{DebugError, ErrorCode, Result},
    model::{ArtifactReference, OperationRecord, ProbeInfo, ResetCaptureReport},
    service::DebugService,
};

pub const DEFAULT_RUNTIME_DURATION_SECONDS: u64 = 15;
pub const DEFAULT_RUNTIME_MONITOR_STARTUP_DELAY_MS: u64 = 400;
pub const DEFAULT_MINIMUM_HEARTBEATS: u32 = 3;
const MAX_RUNTIME_DURATION_SECONDS: u64 = 120;
const MAX_MONITOR_STARTUP_DELAY_MS: u64 = 5_000;
const MAX_EXPECTED_LINE_BYTES: usize = 512;
const MAX_BAUD_CONTROL_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_BAUD_EVENT_BYTES: u64 = 8 * 1024 * 1024;
const MONITOR_EXIT_GRACE: Duration = Duration::from_secs(10);
const MONITOR_POLL_INTERVAL: Duration = Duration::from_millis(25);

#[derive(Debug, Clone)]
pub struct RuntimeAcceptanceOptions {
    pub probe: String,
    pub target: String,
    pub port: String,
    pub vendor_id: u16,
    pub product_id: u16,
    pub serial_number: String,
    pub baudrate: u32,
    pub dtr: bool,
    pub rts: bool,
    pub duration_seconds: u64,
    pub monitor_startup_delay_ms: u64,
    pub ready_line: String,
    pub build_id_line: Option<String>,
    pub heartbeat_line: String,
    pub minimum_heartbeats: u32,
    pub evidence: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaudPortInfo {
    pub device: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub hardware_id: Option<String>,
    #[serde(default)]
    pub vid: Option<u16>,
    #[serde(default)]
    pub pid: Option<u16>,
    #[serde(default)]
    pub serial_number: Option<String>,
    #[serde(default)]
    pub manufacturer: Option<String>,
    #[serde(default)]
    pub product: Option<String>,
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default)]
    pub location: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SerialPreflight {
    pub tool: String,
    pub executable: String,
    pub version: String,
    pub port: BaudPortInfo,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeSerialSelection {
    pub port: String,
    pub vendor_id: String,
    pub product_id: String,
    pub serial_number: String,
    pub baudrate: u32,
    pub dtr: bool,
    pub rts: bool,
    pub transmit_bytes: u64,
    pub duration_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExactLineAssertion {
    pub line: String,
    pub expected_minimum: u32,
    pub observed: u32,
    pub passed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OptionalLineAssertion {
    pub required: bool,
    pub line: Option<String>,
    pub observed: u32,
    pub passed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeAssertions {
    pub monitor_completed: bool,
    pub reset_capture_completed: bool,
    pub ready: ExactLineAssertion,
    pub build_identity: OptionalLineAssertion,
    pub heartbeat: ExactLineAssertion,
    pub complete_line_count: u32,
    pub partial_tail_present: bool,
    pub passed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SerialMonitorObservation {
    pub process_exit_code: Option<i32>,
    pub result_ok: bool,
    pub result_exit_code: i64,
    pub reported_port: String,
    pub reported_baudrate: u32,
    pub duration_ms: u64,
    pub event_count: u32,
    pub receive_event_count: u32,
    pub bytes_received: u64,
    pub artifacts: Vec<ArtifactReference>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RuntimeFailureEvidence {
    pub code: ErrorCode,
    pub message: String,
    pub retryable: bool,
    pub details: Value,
}

impl From<&DebugError> for RuntimeFailureEvidence {
    fn from(error: &DebugError) -> Self {
        Self {
            code: error.code,
            message: error.message.clone(),
            retryable: error.retryable,
            details: error.details.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RuntimeAcceptanceReport {
    pub schema_version: &'static str,
    pub acceptance_id: String,
    pub captured_at: String,
    pub risk: String,
    pub accepted: bool,
    pub complete: bool,
    pub automatic_retries: u32,
    pub probe: ProbeInfo,
    pub target: String,
    pub serial_selection: RuntimeSerialSelection,
    pub serial_preflight: SerialPreflight,
    pub artifact_directory: String,
    pub serial_observation: Option<SerialMonitorObservation>,
    pub serial_error: Option<RuntimeFailureEvidence>,
    pub reset_capture: Option<ResetCaptureReport>,
    pub reset_capture_error: Option<RuntimeFailureEvidence>,
    pub assertions: RuntimeAssertions,
    pub effects: RuntimeAcceptanceEffects,
    pub operations: Vec<OperationRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeAcceptanceEffects {
    pub reset_requested: bool,
    pub serial_transmit_requested: bool,
    pub flash_operation_requested: bool,
    pub erase_requested: bool,
    pub recover_requested: bool,
    pub non_boot_nvm_access_requested: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RuntimeAcceptanceExecution {
    pub report: RuntimeAcceptanceReport,
    pub evidence: ArtifactReference,
}

pub struct SerialCapture {
    pub observation: SerialMonitorObservation,
    pub received_text: String,
}

pub trait SerialMonitorSession {
    fn is_running(&mut self) -> Result<bool>;
    fn finish(self: Box<Self>, timeout: Duration) -> Result<SerialCapture>;
}

pub trait SerialMonitorDriver {
    fn preflight(&self, selection: &RuntimeSerialSelection) -> Result<SerialPreflight>;
    fn start(
        &self,
        selection: &RuntimeSerialSelection,
        artifact_directory: &Path,
    ) -> Result<Box<dyn SerialMonitorSession>>;
}

pub struct BaudCliDriver {
    executable: PathBuf,
}

impl BaudCliDriver {
    pub fn new(executable: PathBuf) -> Self {
        Self { executable }
    }
}

#[derive(Debug, Deserialize)]
struct BaudListResult {
    ok: bool,
    ports: Vec<BaudPortInfo>,
}

impl SerialMonitorDriver for BaudCliDriver {
    fn preflight(&self, selection: &RuntimeSerialSelection) -> Result<SerialPreflight> {
        let version_output = Command::new(&self.executable)
            .arg("--version")
            .output()
            .map_err(|error| {
                DebugError::io("start baud version check", self.executable.to_str(), &error)
            })?;
        let version = first_nonempty_line(&version_output.stdout, &version_output.stderr)
            .ok_or_else(|| {
                DebugError::new(
                    ErrorCode::ProtocolError,
                    "baud version check returned no identity",
                    6,
                    json!({"executable": self.executable}),
                )
            })?;
        if !version_output.status.success() || !version.starts_with("baud ") {
            return Err(DebugError::new(
                ErrorCode::ConfigInvalid,
                "configured serial executable did not identify itself as baud",
                7,
                json!({
                    "executable": self.executable,
                    "version": version,
                    "exit_code": version_output.status.code(),
                }),
            ));
        }

        let list_output = Command::new(&self.executable)
            .args(["list", "--json"])
            .output()
            .map_err(|error| {
                DebugError::io(
                    "start baud port discovery",
                    self.executable.to_str(),
                    &error,
                )
            })?;
        ensure_bounded_control_output(&list_output.stdout, "baud list stdout")?;
        ensure_bounded_control_output(&list_output.stderr, "baud list stderr")?;
        if !list_output.status.success() {
            return Err(DebugError::unavailable(
                ErrorCode::CapabilityUnavailable,
                "baud port discovery failed",
                json!({
                    "executable": self.executable,
                    "exit_code": list_output.status.code(),
                    "stderr": String::from_utf8_lossy(&list_output.stderr),
                }),
            ));
        }
        let list: BaudListResult =
            serde_json::from_slice(&list_output.stdout).map_err(|error| {
                DebugError::new(
                    ErrorCode::ProtocolError,
                    "baud list did not return its structured JSON contract",
                    6,
                    json!({"cause": error.to_string()}),
                )
            })?;
        if !list.ok {
            return Err(DebugError::unavailable(
                ErrorCode::CapabilityUnavailable,
                "baud reported unsuccessful port discovery",
                json!({"ports": list.ports}),
            ));
        }
        let matches = list
            .ports
            .iter()
            .filter(|port| {
                port.device == selection.port
                    && port.vid == Some(parse_usb_id(&selection.vendor_id).expect("validated VID"))
                    && port.pid == Some(parse_usb_id(&selection.product_id).expect("validated PID"))
                    && port.serial_number.as_deref() == Some(selection.serial_number.as_str())
            })
            .cloned()
            .collect::<Vec<_>>();
        let port = match matches.as_slice() {
            [port] => port.clone(),
            [] => {
                return Err(DebugError::unavailable(
                    ErrorCode::CapabilityUnavailable,
                    "the exact serial port identity is not available",
                    json!({"requested": selection, "available": list.ports}),
                ));
            }
            many => {
                return Err(DebugError::unavailable(
                    ErrorCode::CapabilityUnavailable,
                    "the exact serial port identity is ambiguous",
                    json!({"requested": selection, "matches": many}),
                ));
            }
        };

        Ok(SerialPreflight {
            tool: "baud".to_string(),
            executable: self.executable.display().to_string(),
            version,
            port,
        })
    }

    fn start(
        &self,
        selection: &RuntimeSerialSelection,
        artifact_directory: &Path,
    ) -> Result<Box<dyn SerialMonitorSession>> {
        Ok(Box::new(ManagedBaudMonitor::spawn(
            &self.executable,
            selection,
            artifact_directory,
        )?))
    }
}

struct ManagedBaudMonitor {
    child: Option<Box<dyn ChildWrapper>>,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
    artifact_directory: PathBuf,
    selection: RuntimeSerialSelection,
}

impl ManagedBaudMonitor {
    fn spawn(
        executable: &Path,
        selection: &RuntimeSerialSelection,
        artifact_directory: &Path,
    ) -> Result<Self> {
        let stdout_path = artifact_directory.join("baud-monitor.stdout.json");
        let stderr_path = artifact_directory.join("baud-monitor.stderr.log");
        let stdout = create_new_file(&stdout_path, "reserve baud monitor stdout")?;
        let stderr = create_new_file(&stderr_path, "reserve baud monitor stderr")?;
        let mut command = Command::new(executable);
        command
            .arg("monitor")
            .args(["--port", &selection.port])
            .args(["--baud", &selection.baudrate.to_string()])
            .args(["--duration", &selection.duration_seconds.to_string()])
            .args(["--dtr", if selection.dtr { "true" } else { "false" }])
            .args(["--rts", if selection.rts { "true" } else { "false" }])
            .args(["--expected-vid", &selection.vendor_id])
            .args(["--expected-pid", &selection.product_id])
            .args(["--expected-serial-number", &selection.serial_number])
            .arg("--json")
            .arg("--log-dir")
            .arg(artifact_directory)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        let mut wrapped = CommandWrap::from(command);
        #[cfg(windows)]
        wrapped.wrap(JobObject);
        #[cfg(unix)]
        wrapped.wrap(ProcessGroup::leader());
        let child = wrapped.spawn().map_err(|error| {
            let _ = fs::remove_file(&stdout_path);
            let _ = fs::remove_file(&stderr_path);
            DebugError::unavailable(
                ErrorCode::CapabilityUnavailable,
                "baud monitor could not be started",
                json!({
                    "executable": executable,
                    "cause": error.to_string(),
                    "port": selection.port,
                }),
            )
        })?;
        Ok(Self {
            child: Some(child),
            stdout_path,
            stderr_path,
            artifact_directory: artifact_directory.to_path_buf(),
            selection: selection.clone(),
        })
    }

    fn wait_for_exit(&mut self, timeout: Duration) -> Result<ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            let child = self
                .child
                .as_mut()
                .expect("baud monitor child exists until finish");
            match child.try_wait() {
                Ok(Some(status)) => return Ok(status),
                Ok(None) if Instant::now() < deadline => {
                    thread::sleep(
                        MONITOR_POLL_INTERVAL
                            .min(deadline.saturating_duration_since(Instant::now())),
                    );
                }
                Ok(None) => {
                    let _ = child.start_kill();
                    let _ = child.wait();
                    self.child.take();
                    return Err(DebugError::new(
                        ErrorCode::Timeout,
                        "baud monitor did not exit after its bounded observation window",
                        5,
                        json!({
                            "port": self.selection.port,
                            "timeout_ms": timeout.as_millis(),
                            "process_tree_termination_requested": true,
                        }),
                    ));
                }
                Err(error) => {
                    return Err(DebugError::io(
                        "poll baud monitor",
                        self.stdout_path.to_str(),
                        &error,
                    ));
                }
            }
        }
    }
}

impl SerialMonitorSession for ManagedBaudMonitor {
    fn is_running(&mut self) -> Result<bool> {
        let child = self
            .child
            .as_mut()
            .expect("baud monitor child exists until finish");
        child
            .try_wait()
            .map(|status| status.is_none())
            .map_err(|error| DebugError::io("poll baud monitor", self.stdout_path.to_str(), &error))
    }

    fn finish(mut self: Box<Self>, timeout: Duration) -> Result<SerialCapture> {
        let status = self.wait_for_exit(timeout)?;
        if let Some(mut child) = self.child.take() {
            let _ = child.wait();
        }
        let stdout = read_bounded_file(
            &self.stdout_path,
            MAX_BAUD_CONTROL_OUTPUT_BYTES as u64,
            "read baud monitor result",
        )?;
        let result: Value = serde_json::from_slice(&stdout).map_err(|error| {
            DebugError::new(
                ErrorCode::ProtocolError,
                "baud monitor did not return its structured JSON contract",
                6,
                json!({
                    "cause": error.to_string(),
                    "stdout_artifact": self.stdout_path,
                    "process_exit_code": status.code(),
                }),
            )
        })?;
        let result_ok = required_bool(&result, "ok", "baud monitor result")?;
        let result_exit_code = required_i64(&result, "exit_code", "baud monitor result")?;
        let reported_port = required_string(&result, "port", "baud monitor result")?;
        let reported_baudrate = required_u64(&result, "baudrate", "baud monitor result")?;
        let duration_ms = required_u64(&result, "duration_ms", "baud monitor result")?;
        if reported_port != self.selection.port
            || reported_baudrate != u64::from(self.selection.baudrate)
        {
            return Err(DebugError::new(
                ErrorCode::ProtocolError,
                "baud monitor result does not match the selected serial endpoint",
                6,
                json!({
                    "selected_port": self.selection.port,
                    "reported_port": reported_port,
                    "selected_baudrate": self.selection.baudrate,
                    "reported_baudrate": reported_baudrate,
                }),
            ));
        }
        let events_path = resolve_baud_artifact(
            &result,
            "events_file",
            &self.artifact_directory,
            "baud monitor events",
        )?;
        let log_path = resolve_baud_artifact(
            &result,
            "log_file",
            &self.artifact_directory,
            "baud monitor log",
        )?;
        let event_bytes = read_bounded_file(
            &events_path,
            MAX_BAUD_EVENT_BYTES,
            "read baud monitor events",
        )?;
        let event_text = std::str::from_utf8(&event_bytes).map_err(|error| {
            DebugError::new(
                ErrorCode::ProtocolError,
                "baud monitor events are not UTF-8 JSONL",
                6,
                json!({"path": events_path, "cause": error.to_string()}),
            )
        })?;
        let mut received_text = String::new();
        let mut event_count = 0_u32;
        let mut receive_event_count = 0_u32;
        let mut bytes_received = 0_u64;
        for (index, line) in event_text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let event: Value = serde_json::from_str(line).map_err(|error| {
                DebugError::new(
                    ErrorCode::ProtocolError,
                    "baud monitor events contain invalid JSONL",
                    6,
                    json!({
                        "path": events_path,
                        "line": index + 1,
                        "cause": error.to_string(),
                    }),
                )
            })?;
            event_count = event_count.saturating_add(1);
            if event.get("type").and_then(Value::as_str) == Some("recv") {
                receive_event_count = receive_event_count.saturating_add(1);
                let text = event.get("text").and_then(Value::as_str).ok_or_else(|| {
                    DebugError::new(
                        ErrorCode::ProtocolError,
                        "baud receive event is missing text",
                        6,
                        json!({"path": events_path, "line": index + 1}),
                    )
                })?;
                let bytes = event.get("bytes").and_then(Value::as_u64).ok_or_else(|| {
                    DebugError::new(
                        ErrorCode::ProtocolError,
                        "baud receive event is missing its byte count",
                        6,
                        json!({"path": events_path, "line": index + 1}),
                    )
                })?;
                bytes_received = bytes_received.saturating_add(bytes);
                received_text.push_str(text);
            }
        }
        let artifacts = vec![
            artifact_reference("baud_monitor_result", &self.stdout_path)?,
            artifact_reference("baud_monitor_stderr", &self.stderr_path)?,
            artifact_reference("baud_monitor_events", &events_path)?,
            artifact_reference("baud_monitor_log", &log_path)?,
        ];
        Ok(SerialCapture {
            observation: SerialMonitorObservation {
                process_exit_code: status.code(),
                result_ok,
                result_exit_code,
                reported_port,
                reported_baudrate: u32::try_from(reported_baudrate).map_err(|_| {
                    DebugError::new(
                        ErrorCode::ProtocolError,
                        "baud monitor reported an invalid baud rate",
                        6,
                        json!({"baudrate": reported_baudrate}),
                    )
                })?,
                duration_ms,
                event_count,
                receive_event_count,
                bytes_received,
                artifacts,
            },
            received_text,
        })
    }
}

impl Drop for ManagedBaudMonitor {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
            let _ = child.wait();
        }
    }
}

pub fn run_runtime_acceptance<B: DebugBackend, D: SerialMonitorDriver>(
    backend: B,
    driver: &D,
    options: &RuntimeAcceptanceOptions,
) -> Result<RuntimeAcceptanceExecution> {
    validate_options(options)?;
    let mut publisher = RuntimeEvidencePublisher::new(&options.evidence)?;
    let artifact_directory = publisher.artifact_directory().to_path_buf();
    let serial_selection = serial_selection(options);
    let mut service = DebugService::new(backend);
    let probes = service.probes()?;
    let probe = select_exact_probe(&probes, &options.probe)?;
    let serial_preflight = driver.preflight(&serial_selection)?;
    let mut monitor = driver.start(&serial_selection, &artifact_directory)?;

    thread::sleep(Duration::from_millis(options.monitor_startup_delay_ms));
    let monitor_running = monitor.is_running()?;
    let reset_result = if monitor_running {
        Some(service.capture_reset_snapshot(&options.probe, &options.target))
    } else {
        None
    };
    let monitor_timeout = Duration::from_secs(options.duration_seconds) + MONITOR_EXIT_GRACE;
    let serial_result = monitor.finish(monitor_timeout);

    let (serial_observation, serial_text, serial_error) = match serial_result {
        Ok(capture) => (Some(capture.observation), capture.received_text, None),
        Err(error) => (
            None,
            String::new(),
            Some(RuntimeFailureEvidence::from(&error)),
        ),
    };
    let (reset_capture, reset_capture_error) = match reset_result {
        Some(Ok(report)) => (Some(report), None),
        Some(Err(error)) => (None, Some(RuntimeFailureEvidence::from(&error))),
        None => (
            None,
            Some(RuntimeFailureEvidence {
                code: ErrorCode::ProtocolError,
                message: "baud monitor exited before reset-capture".to_string(),
                retryable: false,
                details: json!({"target_control_attempted": false}),
            }),
        ),
    };
    let assertions = evaluate_assertions(
        options,
        serial_observation.as_ref(),
        reset_capture.as_ref(),
        &serial_text,
    );
    let operations = vec![
        operation(1, "debug_probe.select_exact"),
        operation(2, "serial_port.select_exact"),
        operation(3, "serial.monitor_start_zero_transmit"),
        OperationRecord {
            sequence: 4,
            operation: "snapshot.reset_capture".to_string(),
            ok: reset_capture.is_some(),
        },
        OperationRecord {
            sequence: 5,
            operation: "serial.monitor_finish".to_string(),
            ok: serial_observation.is_some(),
        },
        OperationRecord {
            sequence: 6,
            operation: "runtime.assertions_evaluate".to_string(),
            ok: assertions.passed,
        },
    ];
    let report = RuntimeAcceptanceReport {
        schema_version: SCHEMA_VERSION,
        acceptance_id: format!("runtime_acc_{}", Uuid::new_v4().simple()),
        captured_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        risk: "R1_REVERSIBLE_CONTROL".to_string(),
        accepted: assertions.passed,
        complete: true,
        automatic_retries: 0,
        probe,
        target: options.target.clone(),
        serial_selection,
        serial_preflight,
        artifact_directory: artifact_directory.display().to_string(),
        serial_observation,
        serial_error,
        reset_capture,
        reset_capture_error,
        assertions,
        effects: RuntimeAcceptanceEffects {
            reset_requested: monitor_running,
            serial_transmit_requested: false,
            flash_operation_requested: false,
            erase_requested: false,
            recover_requested: false,
            non_boot_nvm_access_requested: false,
        },
        operations,
    };
    let evidence = publisher.publish(&report)?;
    Ok(RuntimeAcceptanceExecution { report, evidence })
}

fn serial_selection(options: &RuntimeAcceptanceOptions) -> RuntimeSerialSelection {
    RuntimeSerialSelection {
        port: options.port.clone(),
        vendor_id: format!("{:04X}", options.vendor_id),
        product_id: format!("{:04X}", options.product_id),
        serial_number: options.serial_number.clone(),
        baudrate: options.baudrate,
        dtr: options.dtr,
        rts: options.rts,
        transmit_bytes: 0,
        duration_seconds: options.duration_seconds,
    }
}

fn validate_options(options: &RuntimeAcceptanceOptions) -> Result<()> {
    validate_visible_value("probe", &options.probe, 256)?;
    validate_visible_value("target", &options.target, 256)?;
    validate_visible_value("port", &options.port, 256)?;
    validate_visible_value("serial_number", &options.serial_number, 256)?;
    validate_expected_line("ready_line", &options.ready_line)?;
    validate_expected_line("heartbeat_line", &options.heartbeat_line)?;
    if let Some(line) = &options.build_id_line {
        validate_expected_line("build_id_line", line)?;
    }
    if options.baudrate == 0 {
        return Err(DebugError::config(
            "runtime acceptance baud rate must be non-zero",
            json!({"baudrate": options.baudrate}),
        ));
    }
    if !(1..=MAX_RUNTIME_DURATION_SECONDS).contains(&options.duration_seconds) {
        return Err(DebugError::config(
            "runtime acceptance duration is outside the bounded range",
            json!({
                "duration_seconds": options.duration_seconds,
                "minimum": 1,
                "maximum": MAX_RUNTIME_DURATION_SECONDS,
            }),
        ));
    }
    if options.monitor_startup_delay_ms > MAX_MONITOR_STARTUP_DELAY_MS {
        return Err(DebugError::config(
            "runtime monitor startup delay is outside the bounded range",
            json!({
                "monitor_startup_delay_ms": options.monitor_startup_delay_ms,
                "maximum": MAX_MONITOR_STARTUP_DELAY_MS,
            }),
        ));
    }
    if options.minimum_heartbeats == 0 {
        return Err(DebugError::config(
            "runtime acceptance requires at least one heartbeat",
            json!({"minimum_heartbeats": options.minimum_heartbeats}),
        ));
    }
    Ok(())
}

fn validate_visible_value(name: &str, value: &str, maximum: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > maximum
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(DebugError::config(
            format!("{name} must be a bounded visible value without surrounding whitespace"),
            json!({"field": name, "maximum_bytes": maximum}),
        ));
    }
    Ok(())
}

fn validate_expected_line(name: &str, value: &str) -> Result<()> {
    validate_visible_value(name, value, MAX_EXPECTED_LINE_BYTES)
}

fn select_exact_probe(probes: &[ProbeInfo], requested: &str) -> Result<ProbeInfo> {
    let matches = probes
        .iter()
        .filter(|probe| probe.id == requested)
        .cloned()
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [probe] if probe.accessible => Ok(probe.clone()),
        [probe] => Err(DebugError::new(
            ErrorCode::PermissionDenied,
            "the exact debug probe is visible but not accessible",
            8,
            json!({"probe": probe}),
        )),
        [] => Err(DebugError::unavailable(
            ErrorCode::ProbeUnavailable,
            "the exact debug probe is not available",
            json!({"requested": requested, "available": probes}),
        )),
        many => Err(DebugError::unavailable(
            ErrorCode::ProbeAmbiguous,
            "the exact debug probe selector is ambiguous",
            json!({"requested": requested, "matches": many}),
        )),
    }
}

fn evaluate_assertions(
    options: &RuntimeAcceptanceOptions,
    serial: Option<&SerialMonitorObservation>,
    reset: Option<&ResetCaptureReport>,
    text: &str,
) -> RuntimeAssertions {
    let (lines, partial_tail_present) = complete_lines(text);
    let count = |expected: &str| -> u32 {
        u32::try_from(
            lines
                .iter()
                .filter(|line| line.as_str() == expected)
                .count(),
        )
        .unwrap_or(u32::MAX)
    };
    let ready_count = count(&options.ready_line);
    let build_count = options.build_id_line.as_deref().map_or(0, count);
    let heartbeat_count = count(&options.heartbeat_line);
    let monitor_completed = serial.is_some_and(|observation| {
        observation.process_exit_code == Some(0)
            && observation.result_ok
            && observation.result_exit_code == 0
    });
    let reset_capture_completed = reset.is_some_and(|report| report.complete);
    let ready = ExactLineAssertion {
        line: options.ready_line.clone(),
        expected_minimum: 1,
        observed: ready_count,
        passed: ready_count >= 1,
    };
    let build_identity = OptionalLineAssertion {
        required: options.build_id_line.is_some(),
        line: options.build_id_line.clone(),
        observed: build_count,
        passed: options.build_id_line.is_none() || build_count >= 1,
    };
    let heartbeat = ExactLineAssertion {
        line: options.heartbeat_line.clone(),
        expected_minimum: options.minimum_heartbeats,
        observed: heartbeat_count,
        passed: heartbeat_count >= options.minimum_heartbeats,
    };
    let passed = monitor_completed
        && reset_capture_completed
        && ready.passed
        && build_identity.passed
        && heartbeat.passed;
    RuntimeAssertions {
        monitor_completed,
        reset_capture_completed,
        ready,
        build_identity,
        heartbeat,
        complete_line_count: u32::try_from(lines.len()).unwrap_or(u32::MAX),
        partial_tail_present,
        passed,
    }
}

fn complete_lines(text: &str) -> (Vec<String>, bool) {
    let mut lines = Vec::new();
    let mut consumed = 0_usize;
    for part in text.split_inclusive('\n') {
        if !part.ends_with('\n') {
            break;
        }
        consumed += part.len();
        lines.push(part.trim_end_matches(['\r', '\n']).to_string());
    }
    (lines, consumed < text.len())
}

pub fn parse_usb_id(value: &str) -> std::result::Result<u16, String> {
    let value = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    if value.len() != 4 || !value.chars().all(|character| character.is_ascii_hexdigit()) {
        return Err("USB VID/PID must be exactly four hexadecimal digits".to_string());
    }
    u16::from_str_radix(value, 16)
        .map_err(|_| "USB VID/PID must be exactly four hexadecimal digits".to_string())
}

fn first_nonempty_line(stdout: &[u8], stderr: &[u8]) -> Option<String> {
    String::from_utf8_lossy(stdout)
        .lines()
        .chain(String::from_utf8_lossy(stderr).lines())
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_string)
}

fn ensure_bounded_control_output(bytes: &[u8], name: &str) -> Result<()> {
    if bytes.len() > MAX_BAUD_CONTROL_OUTPUT_BYTES {
        return Err(DebugError::new(
            ErrorCode::ProtocolError,
            format!("{name} exceeded the bounded output limit"),
            6,
            json!({
                "bytes": bytes.len(),
                "maximum": MAX_BAUD_CONTROL_OUTPUT_BYTES,
            }),
        ));
    }
    Ok(())
}

fn required_bool(value: &Value, field: &str, context: &str) -> Result<bool> {
    value.get(field).and_then(Value::as_bool).ok_or_else(|| {
        DebugError::new(
            ErrorCode::ProtocolError,
            format!("{context} is missing boolean field {field}"),
            6,
            json!({"field": field}),
        )
    })
}

fn required_i64(value: &Value, field: &str, context: &str) -> Result<i64> {
    value.get(field).and_then(Value::as_i64).ok_or_else(|| {
        DebugError::new(
            ErrorCode::ProtocolError,
            format!("{context} is missing integer field {field}"),
            6,
            json!({"field": field}),
        )
    })
}

fn required_u64(value: &Value, field: &str, context: &str) -> Result<u64> {
    value.get(field).and_then(Value::as_u64).ok_or_else(|| {
        DebugError::new(
            ErrorCode::ProtocolError,
            format!("{context} is missing unsigned integer field {field}"),
            6,
            json!({"field": field}),
        )
    })
}

fn required_string(value: &Value, field: &str, context: &str) -> Result<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            DebugError::new(
                ErrorCode::ProtocolError,
                format!("{context} is missing string field {field}"),
                6,
                json!({"field": field}),
            )
        })
}

fn resolve_baud_artifact(
    result: &Value,
    field: &str,
    artifact_directory: &Path,
    context: &str,
) -> Result<PathBuf> {
    let reported = required_string(result, field, "baud monitor result")?;
    let path = PathBuf::from(&reported);
    let path = if path.is_absolute() {
        path
    } else {
        artifact_directory.join(path)
    };
    let canonical_directory = artifact_directory.canonicalize().map_err(|error| {
        DebugError::io(
            "resolve runtime artifact directory",
            artifact_directory.to_str(),
            &error,
        )
    })?;
    let canonical_path = path
        .canonicalize()
        .map_err(|error| DebugError::io(&format!("resolve {context}"), path.to_str(), &error))?;
    if !canonical_path.starts_with(&canonical_directory) {
        return Err(DebugError::new(
            ErrorCode::ProtocolError,
            format!("{context} was written outside the reserved artifact directory"),
            6,
            json!({
                "path": canonical_path,
                "artifact_directory": canonical_directory,
            }),
        ));
    }
    Ok(canonical_path)
}

fn create_new_file(path: &Path, operation_name: &str) -> Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| DebugError::io(operation_name, path.to_str(), &error))
}

fn read_bounded_file(path: &Path, maximum: u64, operation_name: &str) -> Result<Vec<u8>> {
    let metadata = fs::metadata(path)
        .map_err(|error| DebugError::io(operation_name, path.to_str(), &error))?;
    if metadata.len() > maximum {
        return Err(DebugError::new(
            ErrorCode::ProtocolError,
            format!("{operation_name} exceeded the bounded file limit"),
            6,
            json!({"path": path, "bytes": metadata.len(), "maximum": maximum}),
        ));
    }
    fs::read(path).map_err(|error| DebugError::io(operation_name, path.to_str(), &error))
}

fn artifact_reference(kind: &str, path: &Path) -> Result<ArtifactReference> {
    let mut file = File::open(path)
        .map_err(|error| DebugError::io("open runtime artifact", path.to_str(), &error))?;
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 8192];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| DebugError::io("hash runtime artifact", path.to_str(), &error))?;
        if read == 0 {
            break;
        }
        size = size.saturating_add(read as u64);
        hasher.update(&buffer[..read]);
    }
    Ok(ArtifactReference {
        kind: kind.to_string(),
        path: path.display().to_string(),
        size,
        sha256: hex::encode(hasher.finalize()),
    })
}

struct RuntimeEvidencePublisher {
    target_path: PathBuf,
    artifact_directory: PathBuf,
    published: bool,
}

impl RuntimeEvidencePublisher {
    fn new(target_path: &Path) -> Result<Self> {
        if target_path.exists() {
            return Err(DebugError::output_exists(
                &target_path.display().to_string(),
            ));
        }
        let parent = target_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).map_err(|error| {
            DebugError::io("create runtime evidence parent", parent.to_str(), &error)
        })?;
        let mut directory_name = target_path
            .file_name()
            .map(|name| name.to_os_string())
            .unwrap_or_else(|| "runtime.evidence.json".into());
        directory_name.push(".artifacts");
        let artifact_directory = target_path.with_file_name(directory_name);
        fs::create_dir(&artifact_directory).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                DebugError::output_exists(&artifact_directory.display().to_string())
            } else {
                DebugError::io(
                    "reserve runtime artifact directory",
                    artifact_directory.to_str(),
                    &error,
                )
            }
        })?;
        Ok(Self {
            target_path: target_path.to_path_buf(),
            artifact_directory,
            published: false,
        })
    }

    fn artifact_directory(&self) -> &Path {
        &self.artifact_directory
    }

    fn publish(&mut self, report: &RuntimeAcceptanceReport) -> Result<ArtifactReference> {
        let bytes = serde_json::to_vec_pretty(report).expect("runtime evidence always serializes");
        let recovery_path = self
            .artifact_directory
            .join("runtime-acceptance.complete.json");
        let mut recovery = create_new_file(&recovery_path, "reserve runtime recovery evidence")?;
        recovery
            .write_all(&bytes)
            .and_then(|()| recovery.write_all(b"\n"))
            .and_then(|()| recovery.sync_all())
            .map_err(|error| {
                DebugError::io(
                    "write runtime recovery evidence",
                    recovery_path.to_str(),
                    &error,
                )
            })?;
        drop(recovery);
        fs::hard_link(&recovery_path, &self.target_path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                DebugError::new(
                    ErrorCode::OutputExists,
                    "refusing to overwrite runtime evidence created during execution",
                    2,
                    json!({
                        "path": self.target_path,
                        "recovery_path": recovery_path,
                    }),
                )
            } else {
                DebugError::new(
                    ErrorCode::Internal,
                    format!(
                        "publish runtime evidence failed: {error}; complete evidence remains at the recovery path"
                    ),
                    10,
                    json!({
                        "path": self.target_path,
                        "recovery_path": recovery_path,
                    }),
                )
            }
        })?;
        self.published = true;
        artifact_reference("runtime_acceptance", &self.target_path)
    }
}

impl Drop for RuntimeEvidencePublisher {
    fn drop(&mut self) {
        if self.published {
            return;
        }
        let is_empty = fs::read_dir(&self.artifact_directory)
            .map(|mut entries| entries.next().is_none())
            .unwrap_or(false);
        if is_empty {
            let _ = fs::remove_dir(&self.artifact_directory);
        }
    }
}

fn operation(sequence: u32, name: &str) -> OperationRecord {
    OperationRecord {
        sequence,
        operation: name.to_string(),
        ok: true,
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;
    use crate::backend::replay::{ReplayBackend, ReplayFixture};

    struct FakeSerialDriver {
        preflight: SerialPreflight,
        text: String,
        running: bool,
        result_ok: bool,
    }

    struct FakeSerialMonitor {
        text: String,
        running: bool,
        result_ok: bool,
    }

    impl SerialMonitorDriver for FakeSerialDriver {
        fn preflight(&self, _selection: &RuntimeSerialSelection) -> Result<SerialPreflight> {
            Ok(self.preflight.clone())
        }

        fn start(
            &self,
            _selection: &RuntimeSerialSelection,
            _artifact_directory: &Path,
        ) -> Result<Box<dyn SerialMonitorSession>> {
            Ok(Box::new(FakeSerialMonitor {
                text: self.text.clone(),
                running: self.running,
                result_ok: self.result_ok,
            }))
        }
    }

    impl SerialMonitorSession for FakeSerialMonitor {
        fn is_running(&mut self) -> Result<bool> {
            Ok(self.running)
        }

        fn finish(self: Box<Self>, _timeout: Duration) -> Result<SerialCapture> {
            Ok(SerialCapture {
                observation: SerialMonitorObservation {
                    process_exit_code: Some(if self.result_ok { 0 } else { 1 }),
                    result_ok: self.result_ok,
                    result_exit_code: if self.result_ok { 0 } else { 1 },
                    reported_port: "COM11".to_string(),
                    reported_baudrate: 115_200,
                    duration_ms: 15_000,
                    event_count: 4,
                    receive_event_count: 2,
                    bytes_received: self.text.len() as u64,
                    artifacts: Vec::new(),
                },
                received_text: self.text,
            })
        }
    }

    fn fixture() -> ReplayFixture {
        serde_json::from_str(include_str!("../examples/replay/stm32g4.json")).unwrap()
    }

    fn options(evidence: PathBuf) -> RuntimeAcceptanceOptions {
        RuntimeAcceptanceOptions {
            probe: "replay:stlink-v3:0039002A3432510433343034".to_string(),
            target: "STM32G431CBTx".to_string(),
            port: "COM11".to_string(),
            vendor_id: 0x1366,
            product_id: 0x1061,
            serial_number: "001050275757".to_string(),
            baudrate: 115_200,
            dtr: true,
            rts: false,
            duration_seconds: 15,
            monitor_startup_delay_ms: 0,
            ready_line: "READY v1".to_string(),
            build_id_line: Some("BUILD v1 abc123".to_string()),
            heartbeat_line: "HEARTBEAT".to_string(),
            minimum_heartbeats: 3,
            evidence,
        }
    }

    fn driver(text: &str) -> FakeSerialDriver {
        FakeSerialDriver {
            preflight: SerialPreflight {
                tool: "baud".to_string(),
                executable: "fake-baud".to_string(),
                version: "baud 0.1.0".to_string(),
                port: BaudPortInfo {
                    device: "COM11".to_string(),
                    name: Some("COM11".to_string()),
                    description: Some("fixture".to_string()),
                    hardware_id: Some("fixture".to_string()),
                    vid: Some(0x1366),
                    pid: Some(0x1061),
                    serial_number: Some("001050275757".to_string()),
                    manufacturer: None,
                    product: None,
                    interface: None,
                    location: None,
                },
            },
            text: text.to_string(),
            running: true,
            result_ok: true,
        }
    }

    #[test]
    fn usb_ids_are_explicit_four_digit_hex() {
        assert_eq!(parse_usb_id("1366").unwrap(), 0x1366);
        assert_eq!(parse_usb_id("0x1061").unwrap(), 0x1061);
        assert!(parse_usb_id("136").is_err());
        assert!(parse_usb_id("zzzz").is_err());
    }

    #[test]
    fn partial_lines_do_not_satisfy_runtime_assertions() {
        let directory = tempdir().unwrap();
        let options = options(directory.path().join("runtime.evidence.json"));
        let observation = SerialMonitorObservation {
            process_exit_code: Some(0),
            result_ok: true,
            result_exit_code: 0,
            reported_port: "COM11".to_string(),
            reported_baudrate: 115_200,
            duration_ms: 15_000,
            event_count: 1,
            receive_event_count: 1,
            bytes_received: 5,
            artifacts: Vec::new(),
        };
        let assertions =
            evaluate_assertions(&options, Some(&observation), None, "READY v1\r\nHEARTBEAT");
        assert_eq!(assertions.ready.observed, 1);
        assert_eq!(assertions.heartbeat.observed, 0);
        assert!(assertions.partial_tail_present);
        assert!(!assertions.passed);
    }

    #[test]
    fn replay_and_fake_serial_complete_joint_runtime_acceptance() {
        let directory = tempdir().unwrap();
        let evidence = directory.path().join("runtime.evidence.json");
        let execution = run_runtime_acceptance(
            ReplayBackend::new(fixture()),
            &driver("READY v1\r\nBUILD v1 abc123\r\nHEARTBEAT\r\nHEARTBEAT\r\nHEARTBEAT\r\n"),
            &options(evidence.clone()),
        )
        .unwrap();

        assert!(execution.report.accepted);
        assert!(execution.report.complete);
        assert_eq!(execution.report.automatic_retries, 0);
        assert!(execution.report.effects.reset_requested);
        assert!(!execution.report.effects.flash_operation_requested);
        assert_eq!(execution.report.assertions.heartbeat.observed, 3);
        assert!(evidence.exists());
        assert!(Path::new(&execution.evidence.path).exists());
    }

    #[test]
    fn failed_assertions_still_publish_complete_evidence() {
        let directory = tempdir().unwrap();
        let evidence = directory.path().join("runtime.evidence.json");
        let execution = run_runtime_acceptance(
            ReplayBackend::new(fixture()),
            &driver("HEARTBEAT\r\nHEARTBEAT\r\nHEARTBEAT\r\n"),
            &options(evidence.clone()),
        )
        .unwrap();

        assert!(!execution.report.accepted);
        assert!(execution.report.complete);
        assert_eq!(execution.report.assertions.ready.observed, 0);
        assert_eq!(execution.report.assertions.build_identity.observed, 0);
        assert!(evidence.exists());
    }

    #[test]
    fn evidence_is_never_overwritten() {
        let directory = tempdir().unwrap();
        let evidence = directory.path().join("runtime.evidence.json");
        fs::write(&evidence, b"keep me").unwrap();
        let error = run_runtime_acceptance(
            ReplayBackend::new(fixture()),
            &driver(""),
            &options(evidence.clone()),
        )
        .unwrap_err();

        assert_eq!(error.code, ErrorCode::OutputExists);
        assert_eq!(fs::read(&evidence).unwrap(), b"keep me");
    }
}
