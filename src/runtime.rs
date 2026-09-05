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
const MAX_FORBIDDEN_LINES: usize = 64;
const MAX_RUNTIME_CONTRACT_BYTES: u64 = 1024 * 1024;
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
    pub interface: Option<String>,
    pub baudrate: u32,
    pub dtr: bool,
    pub rts: bool,
    pub duration_seconds: u64,
    pub monitor_startup_delay_ms: u64,
    pub ready_line: String,
    pub build_id_line: Option<String>,
    pub heartbeat_line: String,
    pub minimum_heartbeats: u32,
    pub forbidden_lines: Vec<String>,
    pub evidence: PathBuf,
    pub contract: Option<LoadedRuntimeContract>,
}

#[derive(Debug, Clone)]
pub struct LoadedRuntimeContract {
    source_path: PathBuf,
    bytes: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeContractDocument {
    schema_version: String,
    name: String,
    board: String,
    target: String,
    debug: RuntimeContractDebug,
    firmware: Value,
    flash: RuntimeContractFlash,
    serial: RuntimeContractSerial,
    visual: Option<Value>,
    abort_conditions: Vec<String>,
    cleanup: RuntimeContractCleanup,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeContractDebug {
    probe: String,
    operation: String,
    automatic_retries: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeContractFlash {
    exact_probe_selector_required: bool,
    exact_confirmation_digest_required: bool,
    automatic_retries: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeContractSerial {
    exact_port_identity_required: bool,
    port: String,
    usb_vendor_id: String,
    usb_product_id: String,
    usb_serial_number: String,
    usb_interface: Option<String>,
    baud: u32,
    data_bits: u8,
    parity: String,
    stop_bits: u8,
    flow_control: String,
    dtr: bool,
    rts: bool,
    transmit_bytes: u64,
    observe_duration_seconds: u64,
    monitor_startup_delay_ms: u64,
    ready_line: String,
    build_id_line: Option<String>,
    heartbeat_line: String,
    minimum_complete_heartbeats: u32,
    #[serde(default)]
    forbidden_complete_lines: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeContractCleanup {
    close_serial_session: bool,
    disconnect_debug_session: bool,
    do_not_retry_state_changing_failures: bool,
}

#[derive(Debug, Serialize)]
pub struct RuntimeContractInspection {
    pub scope: &'static str,
    pub valid: bool,
    pub hardware_identity_verified: bool,
    pub runtime_firmware_identity_verified: bool,
    pub flash_authorized: bool,
    pub artifact: ArtifactReference,
    pub contract: Value,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
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
pub struct ForbiddenLineAssertion {
    pub line: String,
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
    pub forbidden_lines: Vec<ForbiddenLineAssertion>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract: Option<RuntimeContractEvidence>,
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
pub struct RuntimeContractEvidence {
    pub source_path: String,
    pub captured: ArtifactReference,
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
                    && selection
                        .interface
                        .as_deref()
                        .is_none_or(|interface| port.interface.as_deref() == Some(interface))
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

pub fn load_runtime_acceptance_contract(
    path: &Path,
    evidence: PathBuf,
) -> Result<RuntimeAcceptanceOptions> {
    let canonical_path = path.canonicalize().map_err(|error| {
        DebugError::io("resolve runtime acceptance contract", path.to_str(), &error)
    })?;
    let bytes = read_bounded_file(
        &canonical_path,
        MAX_RUNTIME_CONTRACT_BYTES,
        "read runtime acceptance contract",
    )?;
    parse_runtime_acceptance_contract(canonical_path, bytes, evidence)
}

fn parse_runtime_acceptance_contract(
    canonical_path: PathBuf,
    bytes: Vec<u8>,
    evidence: PathBuf,
) -> Result<RuntimeAcceptanceOptions> {
    let contract: RuntimeContractDocument = serde_json::from_slice(&bytes).map_err(|error| {
        DebugError::config(
            "runtime acceptance contract is not valid strict JSON",
            json!({"path": canonical_path, "cause": error.to_string()}),
        )
    })?;
    validate_contract(&contract, &canonical_path)?;
    let vendor_id = parse_usb_id(&contract.serial.usb_vendor_id).map_err(|message| {
        DebugError::config(
            message,
            json!({"path": canonical_path, "field": "serial.usb_vendor_id"}),
        )
    })?;
    let product_id = parse_usb_id(&contract.serial.usb_product_id).map_err(|message| {
        DebugError::config(
            message,
            json!({"path": canonical_path, "field": "serial.usb_product_id"}),
        )
    })?;
    let options = RuntimeAcceptanceOptions {
        probe: contract.debug.probe,
        target: contract.target,
        port: contract.serial.port,
        vendor_id,
        product_id,
        serial_number: contract.serial.usb_serial_number,
        interface: contract.serial.usb_interface,
        baudrate: contract.serial.baud,
        dtr: contract.serial.dtr,
        rts: contract.serial.rts,
        duration_seconds: contract.serial.observe_duration_seconds,
        monitor_startup_delay_ms: contract.serial.monitor_startup_delay_ms,
        ready_line: contract.serial.ready_line,
        build_id_line: contract.serial.build_id_line,
        heartbeat_line: contract.serial.heartbeat_line,
        minimum_heartbeats: contract.serial.minimum_complete_heartbeats,
        forbidden_lines: contract.serial.forbidden_complete_lines,
        evidence,
        contract: Some(LoadedRuntimeContract {
            source_path: canonical_path,
            bytes,
        }),
    };
    validate_options(&options)?;
    Ok(options)
}

pub fn init_runtime_acceptance_contract(
    name: &str,
    board: &str,
    options: &RuntimeAcceptanceOptions,
    output: &Path,
) -> Result<RuntimeContractInspection> {
    validate_visible_value("contract.name", name, 256)?;
    validate_visible_value("contract.board", board, 256)?;
    validate_options(options)?;
    let document = RuntimeContractDocument {
        schema_version: SCHEMA_VERSION.to_string(),
        name: name.to_string(),
        board: board.to_string(),
        target: options.target.clone(),
        debug: RuntimeContractDebug {
            probe: options.probe.clone(),
            operation: "snapshot.reset-capture".to_string(),
            automatic_retries: 0,
        },
        firmware: json!({}),
        flash: RuntimeContractFlash {
            exact_probe_selector_required: true,
            exact_confirmation_digest_required: true,
            automatic_retries: 0,
        },
        serial: RuntimeContractSerial {
            exact_port_identity_required: true,
            port: options.port.clone(),
            usb_vendor_id: format!("{:04X}", options.vendor_id),
            usb_product_id: format!("{:04X}", options.product_id),
            usb_serial_number: options.serial_number.clone(),
            usb_interface: options.interface.clone(),
            baud: options.baudrate,
            data_bits: 8,
            parity: "none".to_string(),
            stop_bits: 1,
            flow_control: "none".to_string(),
            dtr: options.dtr,
            rts: options.rts,
            transmit_bytes: 0,
            observe_duration_seconds: options.duration_seconds,
            monitor_startup_delay_ms: options.monitor_startup_delay_ms,
            ready_line: options.ready_line.clone(),
            build_id_line: options.build_id_line.clone(),
            heartbeat_line: options.heartbeat_line.clone(),
            minimum_complete_heartbeats: options.minimum_heartbeats,
            forbidden_complete_lines: options.forbidden_lines.clone(),
        },
        visual: None,
        abort_conditions: vec![
            "probe or serial identity differs".to_string(),
            "any state-changing stage returns an indeterminate result".to_string(),
        ],
        cleanup: RuntimeContractCleanup {
            close_serial_session: true,
            disconnect_debug_session: true,
            do_not_retry_state_changing_failures: true,
        },
    };
    let mut bytes = serde_json::to_vec_pretty(&document).expect("contract always serializes");
    bytes.push(b'\n');
    parse_runtime_acceptance_contract(output.to_path_buf(), bytes.clone(), PathBuf::new())?;
    if let Some(parent) = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|error| {
            DebugError::io("create runtime contract parent", parent.to_str(), &error)
        })?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                DebugError::new(
                    ErrorCode::OutputExists,
                    "refusing to overwrite an existing runtime contract",
                    2,
                    json!({"path": output}),
                )
            } else {
                DebugError::io("create runtime contract", output.to_str(), &error)
            }
        })?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| DebugError::io("write runtime contract", output.to_str(), &error))?;
    let canonical_path = output
        .canonicalize()
        .map_err(|error| DebugError::io("resolve new runtime contract", output.to_str(), &error))?;
    Ok(runtime_contract_inspection(&canonical_path, &bytes))
}

pub fn inspect_runtime_acceptance_contract(path: &Path) -> Result<RuntimeContractInspection> {
    let options = load_runtime_acceptance_contract(path, PathBuf::new())?;
    let loaded = options
        .contract
        .expect("loaded contract contains source bytes");
    Ok(runtime_contract_inspection(
        &loaded.source_path,
        &loaded.bytes,
    ))
}

fn runtime_contract_inspection(path: &Path, bytes: &[u8]) -> RuntimeContractInspection {
    RuntimeContractInspection {
        scope: "host_only_no_hardware_access",
        valid: true,
        hardware_identity_verified: false,
        runtime_firmware_identity_verified: false,
        flash_authorized: false,
        artifact: ArtifactReference {
            kind: "runtime_acceptance_contract".to_string(),
            path: path.display().to_string(),
            size: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(bytes)),
        },
        contract: serde_json::from_slice(bytes).expect("contract bytes were already validated"),
    }
}

fn validate_contract(contract: &RuntimeContractDocument, path: &Path) -> Result<()> {
    validate_visible_value("contract.name", &contract.name, 256)?;
    validate_visible_value("contract.board", &contract.board, 256)?;
    if contract.schema_version != SCHEMA_VERSION {
        return Err(DebugError::config(
            "runtime acceptance contract schema version is unsupported",
            json!({
                "path": path,
                "schema_version": contract.schema_version,
                "supported": SCHEMA_VERSION,
            }),
        ));
    }
    if contract.debug.operation != "snapshot.reset-capture" || contract.debug.automatic_retries != 0
    {
        return Err(DebugError::config(
            "runtime acceptance contract must select one non-retried snapshot.reset-capture",
            json!({
                "path": path,
                "operation": contract.debug.operation,
                "automatic_retries": contract.debug.automatic_retries,
            }),
        ));
    }
    if !contract.flash.exact_probe_selector_required
        || !contract.flash.exact_confirmation_digest_required
        || contract.flash.automatic_retries != 0
    {
        return Err(DebugError::config(
            "runtime acceptance contract must preserve guarded zero-retry flash policy",
            json!({"path": path, "flash": contract.flash}),
        ));
    }
    let serial = &contract.serial;
    if !serial.exact_port_identity_required
        || serial.data_bits != 8
        || serial.parity != "none"
        || serial.stop_bits != 1
        || serial.flow_control != "none"
        || serial.transmit_bytes != 0
    {
        return Err(DebugError::config(
            "runtime acceptance contract requires exact zero-transmit 8N1 serial observation",
            json!({
                "path": path,
                "exact_port_identity_required": serial.exact_port_identity_required,
                "data_bits": serial.data_bits,
                "parity": serial.parity,
                "stop_bits": serial.stop_bits,
                "flow_control": serial.flow_control,
                "transmit_bytes": serial.transmit_bytes,
            }),
        ));
    }
    if !contract.cleanup.close_serial_session
        || !contract.cleanup.disconnect_debug_session
        || !contract.cleanup.do_not_retry_state_changing_failures
    {
        return Err(DebugError::config(
            "runtime acceptance contract must require complete cleanup and no retry",
            json!({"path": path, "cleanup": contract.cleanup}),
        ));
    }
    if !contract.firmware.is_object()
        || contract
            .visual
            .as_ref()
            .is_some_and(|visual| !visual.is_object())
        || contract.abort_conditions.is_empty()
        || contract
            .abort_conditions
            .iter()
            .any(|condition| validate_visible_value("abort_condition", condition, 512).is_err())
    {
        return Err(DebugError::config(
            "runtime acceptance contract metadata is incomplete",
            json!({"path": path}),
        ));
    }
    Ok(())
}

pub fn run_runtime_acceptance<B: DebugBackend, D: SerialMonitorDriver>(
    backend: B,
    driver: &D,
    options: &RuntimeAcceptanceOptions,
) -> Result<RuntimeAcceptanceExecution> {
    validate_options(options)?;
    let mut publisher = RuntimeEvidencePublisher::new(&options.evidence)?;
    let artifact_directory = publisher.artifact_directory().to_path_buf();
    let contract = options
        .contract
        .as_ref()
        .map(|contract| capture_runtime_contract(contract, &artifact_directory))
        .transpose()?;
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
        contract,
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
        interface: options.interface.clone(),
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
    if let Some(interface) = &options.interface {
        validate_visible_value("interface", interface, 256)?;
    }
    validate_expected_line("ready_line", &options.ready_line)?;
    validate_expected_line("heartbeat_line", &options.heartbeat_line)?;
    if let Some(line) = &options.build_id_line {
        validate_expected_line("build_id_line", line)?;
    }
    if options.forbidden_lines.len() > MAX_FORBIDDEN_LINES {
        return Err(DebugError::config(
            "runtime acceptance has too many forbidden complete lines",
            json!({
                "count": options.forbidden_lines.len(),
                "maximum": MAX_FORBIDDEN_LINES,
            }),
        ));
    }
    for line in &options.forbidden_lines {
        validate_expected_line("forbidden_line", line)?;
        if line == &options.ready_line
            || line == &options.heartbeat_line
            || options.build_id_line.as_ref() == Some(line)
        {
            return Err(DebugError::config(
                "runtime acceptance cannot both require and forbid the same complete line",
                json!({"line": line}),
            ));
        }
    }
    let mut unique_forbidden_lines = options.forbidden_lines.clone();
    unique_forbidden_lines.sort();
    unique_forbidden_lines.dedup();
    if unique_forbidden_lines.len() != options.forbidden_lines.len() {
        return Err(DebugError::config(
            "runtime acceptance forbidden complete lines must be unique",
            json!({"forbidden_lines": options.forbidden_lines}),
        ));
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
    let forbidden_lines = options
        .forbidden_lines
        .iter()
        .map(|line| {
            let observed = count(line);
            ForbiddenLineAssertion {
                line: line.clone(),
                observed,
                passed: observed == 0,
            }
        })
        .collect::<Vec<_>>();
    let passed = monitor_completed
        && reset_capture_completed
        && ready.passed
        && build_identity.passed
        && heartbeat.passed
        && forbidden_lines.iter().all(|assertion| assertion.passed);
    RuntimeAssertions {
        monitor_completed,
        reset_capture_completed,
        ready,
        build_identity,
        heartbeat,
        forbidden_lines,
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
    let canonical_directory = artifact_directory.canonicalize().map_err(|error| {
        DebugError::io(
            "resolve runtime artifact directory",
            artifact_directory.to_str(),
            &error,
        )
    })?;
    let reported_path = PathBuf::from(&reported);
    let path = if reported_path.is_absolute() {
        reported_path
    } else if let Ok(canonical_reported) = reported_path.canonicalize() {
        if !canonical_reported.starts_with(&canonical_directory) {
            return Err(runtime_artifact_outside_directory(
                context,
                &canonical_reported,
                &canonical_directory,
            ));
        }
        return Ok(canonical_reported);
    } else {
        artifact_directory.join(reported_path)
    };
    let canonical_path = path
        .canonicalize()
        .map_err(|error| DebugError::io(&format!("resolve {context}"), path.to_str(), &error))?;
    if !canonical_path.starts_with(&canonical_directory) {
        return Err(runtime_artifact_outside_directory(
            context,
            &canonical_path,
            &canonical_directory,
        ));
    }
    Ok(canonical_path)
}

fn runtime_artifact_outside_directory(
    context: &str,
    path: &Path,
    artifact_directory: &Path,
) -> DebugError {
    DebugError::new(
        ErrorCode::ProtocolError,
        format!("{context} was written outside the reserved artifact directory"),
        6,
        json!({
            "path": path,
            "artifact_directory": artifact_directory,
        }),
    )
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
    if !metadata.is_file() {
        return Err(DebugError::config(
            format!("{operation_name} requires a regular file"),
            json!({"path": path}),
        ));
    }
    if metadata.len() > maximum {
        return Err(DebugError::new(
            ErrorCode::ProtocolError,
            format!("{operation_name} exceeded the bounded file limit"),
            6,
            json!({"path": path, "bytes": metadata.len(), "maximum": maximum}),
        ));
    }
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| file.take(maximum.saturating_add(1)).read_to_end(&mut bytes))
        .map_err(|error| DebugError::io(operation_name, path.to_str(), &error))?;
    if bytes.len() as u64 > maximum {
        return Err(DebugError::new(
            ErrorCode::ProtocolError,
            format!("{operation_name} exceeded the bounded file limit"),
            6,
            json!({"path": path, "bytes": bytes.len(), "maximum": maximum}),
        ));
    }
    Ok(bytes)
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

fn capture_runtime_contract(
    contract: &LoadedRuntimeContract,
    artifact_directory: &Path,
) -> Result<RuntimeContractEvidence> {
    let captured_path = artifact_directory.join("runtime-contract.json");
    let mut captured = create_new_file(&captured_path, "reserve runtime contract artifact")?;
    captured
        .write_all(&contract.bytes)
        .and_then(|()| captured.sync_all())
        .map_err(|error| {
            DebugError::io(
                "capture runtime acceptance contract",
                captured_path.to_str(),
                &error,
            )
        })?;
    drop(captured);
    Ok(RuntimeContractEvidence {
        source_path: contract.source_path.display().to_string(),
        captured: artifact_reference("runtime_acceptance_contract", &captured_path)?,
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
            interface: None,
            baudrate: 115_200,
            dtr: true,
            rts: false,
            duration_seconds: 15,
            monitor_startup_delay_ms: 0,
            ready_line: "READY v1".to_string(),
            build_id_line: Some("BUILD v1 abc123".to_string()),
            heartbeat_line: "HEARTBEAT".to_string(),
            minimum_heartbeats: 3,
            forbidden_lines: vec!["FAULT".to_string(), "PANIC".to_string()],
            evidence,
            contract: None,
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
    fn baud_artifact_accepts_a_working_directory_relative_reported_path() {
        let current_directory = std::env::current_dir().unwrap();
        let directory = tempfile::tempdir_in(&current_directory).unwrap();
        let artifact_directory = directory.path().join("artifacts");
        fs::create_dir(&artifact_directory).unwrap();
        let artifact = artifact_directory.join("events.jsonl");
        fs::write(&artifact, b"{}\n").unwrap();
        let relative_directory = artifact_directory
            .strip_prefix(&current_directory)
            .unwrap()
            .to_path_buf();
        let result = json!({
            "events_file": relative_directory.join("events.jsonl").display().to_string(),
        });

        let resolved = resolve_baud_artifact(
            &result,
            "events_file",
            &relative_directory,
            "baud monitor events",
        )
        .unwrap();

        assert_eq!(resolved, artifact.canonicalize().unwrap());
    }

    #[test]
    fn baud_artifact_rejects_a_reported_path_outside_the_reserved_directory() {
        let directory = tempdir().unwrap();
        let artifact_directory = directory.path().join("artifacts");
        fs::create_dir(&artifact_directory).unwrap();
        let outside = directory.path().join("outside.jsonl");
        fs::write(&outside, b"{}\n").unwrap();
        let result = json!({"events_file": outside});

        let error = resolve_baud_artifact(
            &result,
            "events_file",
            &artifact_directory,
            "baud monitor events",
        )
        .unwrap_err();

        assert_eq!(error.code, ErrorCode::ProtocolError);
        assert!(
            error
                .message
                .contains("outside the reserved artifact directory")
        );
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
        assert!(
            execution
                .report
                .assertions
                .forbidden_lines
                .iter()
                .all(|assertion| assertion.passed)
        );
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
    fn forbidden_complete_line_fails_runtime_acceptance() {
        let directory = tempdir().unwrap();
        let evidence = directory.path().join("runtime.evidence.json");
        let execution = run_runtime_acceptance(
            ReplayBackend::new(fixture()),
            &driver(
                "READY v1\r\nBUILD v1 abc123\r\nHEARTBEAT\r\nHEARTBEAT\r\nHEARTBEAT\r\nFAULT\r\n",
            ),
            &options(evidence.clone()),
        )
        .unwrap();

        assert!(!execution.report.accepted);
        assert_eq!(
            execution.report.assertions.forbidden_lines[0],
            ForbiddenLineAssertion {
                line: "FAULT".to_string(),
                observed: 1,
                passed: false,
            }
        );
        assert!(evidence.exists());
    }

    #[test]
    fn checked_in_runtime_contract_loads_exact_selection() {
        let directory = tempdir().unwrap();
        let contract = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("examples/nrf52840-dk-smoke/test-contract.json");
        let loaded = load_runtime_acceptance_contract(
            &contract,
            directory.path().join("runtime.evidence.json"),
        )
        .unwrap();

        assert_eq!(loaded.probe, "1366:1061:001050275757");
        assert_eq!(loaded.target, "nRF52840_xxAA");
        assert_eq!(loaded.port, "COM11");
        assert_eq!(loaded.vendor_id, 0x1366);
        assert_eq!(loaded.product_id, 0x1061);
        assert_eq!(loaded.duration_seconds, 15);
        assert_eq!(loaded.forbidden_lines.len(), 2);
        assert!(loaded.contract.is_some());
    }

    #[test]
    fn loaded_contract_is_captured_with_the_runtime_evidence() {
        let directory = tempdir().unwrap();
        let contract_path = directory.path().join("contract.json");
        let mut contract: Value = serde_json::from_str(include_str!(
            "../examples/nrf52840-dk-smoke/test-contract.json"
        ))
        .unwrap();
        contract["target"] = json!("STM32G431CBTx");
        contract["debug"]["probe"] = json!("replay:stlink-v3:0039002A3432510433343034");
        contract["serial"]["ready_line"] = json!("READY v1");
        contract["serial"]["build_id_line"] = json!("BUILD v1 abc123");
        contract["serial"]["heartbeat_line"] = json!("HEARTBEAT");
        contract["serial"]["forbidden_complete_lines"] = json!(["FAULT"]);
        contract["serial"]["monitor_startup_delay_ms"] = json!(0);
        let contract_bytes = serde_json::to_vec_pretty(&contract).unwrap();
        fs::write(&contract_path, &contract_bytes).unwrap();
        let evidence = directory.path().join("runtime.evidence.json");
        let options = load_runtime_acceptance_contract(&contract_path, evidence.clone()).unwrap();

        let execution = run_runtime_acceptance(
            ReplayBackend::new(fixture()),
            &driver("READY v1\r\nBUILD v1 abc123\r\nHEARTBEAT\r\nHEARTBEAT\r\nHEARTBEAT\r\n"),
            &options,
        )
        .unwrap();

        let captured = &execution.report.contract.as_ref().unwrap().captured;
        assert_eq!(captured.kind, "runtime_acceptance_contract");
        assert_eq!(captured.size, contract_bytes.len() as u64);
        assert_eq!(fs::read(&captured.path).unwrap(), contract_bytes);
        assert!(evidence.exists());
    }

    #[test]
    fn runtime_contract_rejects_unknown_fields() {
        let directory = tempdir().unwrap();
        let contract_path = directory.path().join("contract.json");
        let mut contract: Value = serde_json::from_str(include_str!(
            "../examples/nrf52840-dk-smoke/test-contract.json"
        ))
        .unwrap();
        contract
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_string(), json!(true));
        fs::write(&contract_path, serde_json::to_vec(&contract).unwrap()).unwrap();

        let error = load_runtime_acceptance_contract(
            &contract_path,
            directory.path().join("runtime.evidence.json"),
        )
        .unwrap_err();

        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert!(
            error.details["cause"]
                .as_str()
                .unwrap()
                .contains("unknown field")
        );
    }

    #[test]
    fn initialized_contract_round_trips_and_runs_through_existing_acceptance() {
        let directory = tempdir().unwrap();
        let contract_path = directory.path().join("project/runtime.json");
        let expected = options(directory.path().join("unused.evidence.json"));
        let created = init_runtime_acceptance_contract(
            "project-smoke",
            "Project development board",
            &expected,
            &contract_path,
        )
        .unwrap();
        assert_eq!(created.scope, "host_only_no_hardware_access");
        assert!(created.valid);
        assert!(!created.hardware_identity_verified);
        assert!(!created.runtime_firmware_identity_verified);
        assert!(!created.flash_authorized);
        assert_eq!(created.contract["firmware"], json!({}));
        assert_eq!(created.contract["visual"], Value::Null);
        assert_eq!(created.contract["serial"]["transmit_bytes"], 0);
        assert_eq!(created.contract["debug"]["automatic_retries"], 0);
        assert_eq!(
            created.contract["flash"]["exact_confirmation_digest_required"],
            true
        );
        let bytes = fs::read(&contract_path).unwrap();
        assert_eq!(created.artifact.size, bytes.len() as u64);
        assert_eq!(created.artifact.sha256, hex::encode(Sha256::digest(&bytes)));
        let inspected = inspect_runtime_acceptance_contract(&contract_path).unwrap();
        assert_eq!(inspected.artifact, created.artifact);
        assert_eq!(inspected.contract, created.contract);

        let evidence = directory.path().join("runtime.evidence.json");
        let loaded = load_runtime_acceptance_contract(&contract_path, evidence).unwrap();
        assert_eq!(serial_selection(&loaded), serial_selection(&expected));
        assert_eq!(loaded.build_id_line, expected.build_id_line);
        assert_eq!(loaded.forbidden_lines, expected.forbidden_lines);
        let execution = run_runtime_acceptance(
            ReplayBackend::new(fixture()),
            &driver("READY v1\r\nBUILD v1 abc123\r\nHEARTBEAT\r\nHEARTBEAT\r\nHEARTBEAT\r\n"),
            &loaded,
        )
        .unwrap();
        assert!(execution.report.accepted);
        assert_eq!(
            execution.report.contract.unwrap().captured.sha256,
            created.artifact.sha256
        );
    }

    #[test]
    fn initialized_contract_is_deterministic_and_never_overwritten() {
        let directory = tempdir().unwrap();
        let first = directory.path().join("first.json");
        let second = directory.path().join("second.json");
        let expected = options(PathBuf::new());
        init_runtime_acceptance_contract("smoke", "Board", &expected, &first).unwrap();
        init_runtime_acceptance_contract("smoke", "Board", &expected, &second).unwrap();
        let bytes = fs::read(&first).unwrap();
        assert_eq!(bytes, fs::read(&second).unwrap());
        let error =
            init_runtime_acceptance_contract("other", "Board", &expected, &first).unwrap_err();
        assert_eq!(error.code, ErrorCode::OutputExists);
        assert_eq!(bytes, fs::read(&first).unwrap());
    }

    #[test]
    fn invalid_initialization_does_not_create_parent_or_contract() {
        let directory = tempdir().unwrap();
        let output = directory.path().join("not-created/runtime.json");
        let mut invalid = options(PathBuf::new());
        invalid.duration_seconds = 121;
        let error =
            init_runtime_acceptance_contract("smoke", "Board", &invalid, &output).unwrap_err();
        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert!(!output.parent().unwrap().exists());
        let error =
            init_runtime_acceptance_contract(" ", "Board", &options(PathBuf::new()), &output)
                .unwrap_err();
        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert!(!output.parent().unwrap().exists());
    }

    #[test]
    fn contract_inspection_rejects_invalid_shapes_and_unsafe_policies() {
        let directory = tempdir().unwrap();
        let output = directory.path().join("runtime.json");
        let original =
            init_runtime_acceptance_contract("smoke", "Board", &options(PathBuf::new()), &output)
                .unwrap()
                .contract;
        for (pointer, invalid) in [
            ("/schema_version", json!("2.0")),
            ("/serial/unexpected", json!(true)),
            ("/debug/automatic_retries", json!(1)),
            ("/flash/exact_confirmation_digest_required", json!(false)),
            ("/serial/transmit_bytes", json!(1)),
            ("/serial/usb_vendor_id", json!("136")),
            ("/serial/observe_duration_seconds", json!(121)),
            ("/serial/minimum_complete_heartbeats", json!(0)),
            (
                "/serial/forbidden_complete_lines",
                json!(["FAULT", "FAULT"]),
            ),
            ("/serial/forbidden_complete_lines", json!(["READY v1"])),
            (
                "/serial/forbidden_complete_lines",
                json!(["BUILD v1 abc123"]),
            ),
            ("/serial/forbidden_complete_lines", json!(["HEARTBEAT"])),
            ("/serial/ready_line", json!("READY\nINJECTED")),
            ("/cleanup/close_serial_session", json!(false)),
        ] {
            let mut changed = original.clone();
            if pointer == "/serial/unexpected" {
                changed["serial"]["unexpected"] = invalid;
            } else {
                *changed.pointer_mut(pointer).unwrap() = invalid;
            }
            let bytes = serde_json::to_vec(&changed).unwrap();
            fs::write(&output, &bytes).unwrap();
            let error = inspect_runtime_acceptance_contract(&output).unwrap_err();
            assert_eq!(error.code, ErrorCode::ConfigInvalid, "{pointer}");
            assert_eq!(fs::read(&output).unwrap(), bytes);
        }
    }

    #[test]
    fn contract_inspection_preserves_optional_identity_and_metadata() {
        let directory = tempdir().unwrap();
        let output = directory.path().join("runtime.json");
        let mut expected = options(PathBuf::new());
        expected.interface = Some("Port 0".to_string());
        expected.build_id_line = None;
        let created =
            init_runtime_acceptance_contract("smoke", "Board", &expected, &output).unwrap();
        assert_eq!(created.contract["serial"]["usb_interface"], "Port 0");
        assert_eq!(created.contract["serial"]["build_id_line"], Value::Null);

        let mut document = created.contract;
        document["firmware"] = json!({"build_script": "never-execute.ps1"});
        fs::write(&output, serde_json::to_vec(&document).unwrap()).unwrap();
        let inspected = inspect_runtime_acceptance_contract(&output).unwrap();
        assert_eq!(
            inspected.contract["firmware"]["build_script"],
            "never-execute.ps1"
        );
        assert!(!inspected.runtime_firmware_identity_verified);
    }

    #[test]
    fn contract_inspection_rejects_non_files_oversize_and_malformed_json() {
        let directory = tempdir().unwrap();
        assert_eq!(
            inspect_runtime_acceptance_contract(directory.path())
                .unwrap_err()
                .code,
            ErrorCode::ConfigInvalid
        );
        let output = directory.path().join("runtime.json");
        File::create(&output)
            .unwrap()
            .set_len(MAX_RUNTIME_CONTRACT_BYTES + 1)
            .unwrap();
        assert_eq!(
            inspect_runtime_acceptance_contract(&output)
                .unwrap_err()
                .code,
            ErrorCode::ProtocolError
        );
        for bytes in [
            &b""[..],
            &b"{\"schema_version\":\"1.0\",\"schema_version\":\"1.0\"}"[..],
        ] {
            fs::write(&output, bytes).unwrap();
            assert_eq!(
                inspect_runtime_acceptance_contract(&output)
                    .unwrap_err()
                    .code,
                ErrorCode::ConfigInvalid
            );
        }
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
