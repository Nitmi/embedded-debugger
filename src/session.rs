use std::{
    collections::BTreeSet,
    io::{BufRead, Write},
};

use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    SCHEMA_VERSION,
    backend::DebugBackend,
    error::{DebugError, ErrorCode, Result},
    model::{
        CoreExecutionAction, CoreExecutionObservation, SessionInfo,
        validate_core_execution_observation,
    },
    service::select_probe,
};

const MAX_REQUEST_LINE_BYTES: usize = 64 * 1024;
const MAX_REQUEST_ID_BYTES: usize = 128;
const CLOSE_POLICY: &str = "run_observed_cores_before_disconnect";
const SESSION_STATE_WARNING: &str = "Core state is guaranteed only while this debug session remains open; closing the session or terminating the process may change target state.";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionOpenReport {
    pub transport: &'static str,
    pub state: &'static str,
    pub opened_at: String,
    pub session: SessionInfo,
    pub close_policy: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionStatusReport {
    pub state: &'static str,
    pub opened_at: String,
    pub session: SessionInfo,
    pub observed_core_indexes: Vec<u32>,
    pub close_policy: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionCoreControlReport {
    pub observed_at: String,
    pub state_scope: &'static str,
    pub session_id: String,
    pub core: CoreExecutionObservation,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionCloseReport {
    pub state: &'static str,
    pub session_id: String,
    pub close_policy: &'static str,
    pub final_core_observations: Vec<CoreExecutionObservation>,
    pub disconnected: bool,
    pub complete: bool,
}

struct ActiveSession {
    info: SessionInfo,
    opened_at: String,
    observed_cores: BTreeSet<u32>,
}

pub struct SessionService<B: DebugBackend> {
    backend: B,
    active: Option<ActiveSession>,
}

impl<B: DebugBackend> SessionService<B> {
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            active: None,
        }
    }

    pub fn open(&mut self, probe_id: &str, target: &str) -> Result<SessionOpenReport> {
        if let Some(active) = &self.active {
            return Err(DebugError::new(
                ErrorCode::ProtocolError,
                "the session service already owns an active debug session",
                6,
                json!({"active_session_id": active.info.session_id}),
            ));
        }

        let target_info = self.backend.target().clone();
        if target != target_info.name {
            return Err(DebugError::unavailable(
                ErrorCode::TargetUnavailable,
                "requested target does not exactly match the session server target",
                json!({"requested": target, "available": target_info.name}),
            ));
        }

        let capabilities = self.backend.capabilities();
        let missing = [
            ("core_status", capabilities.core_status),
            ("run", capabilities.run),
        ]
        .into_iter()
        .filter_map(|(name, enabled)| (!enabled).then_some(name))
        .collect::<Vec<_>>();
        if !missing.is_empty() {
            return Err(DebugError::new(
                ErrorCode::CapabilityUnavailable,
                "selected backend cannot safely own a persistent core-control session",
                6,
                json!({"backend": self.backend.name(), "missing": missing}),
            ));
        }

        let probe = select_probe(&self.backend.list_probes()?, Some(probe_id))?;
        let session = self.backend.attach(&probe.id, &target_info.name)?;
        if session.probe.id != probe.id || session.target != target_info {
            let mismatch = DebugError::new(
                ErrorCode::ProtocolError,
                "backend attached a different probe or target than requested",
                6,
                json!({
                    "requested_probe": probe.id,
                    "received_probe": session.probe.id,
                    "requested_target": target_info,
                    "received_target": session.target,
                }),
            );
            return match self.backend.disconnect(&session) {
                Ok(()) => Err(mismatch),
                Err(cleanup) => Err(with_cleanup_failure(mismatch, cleanup)),
            };
        }

        let opened_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        let report = SessionOpenReport {
            transport: "stdio_jsonl",
            state: "open",
            opened_at: opened_at.clone(),
            session: session.clone(),
            close_policy: CLOSE_POLICY,
        };
        self.active = Some(ActiveSession {
            info: session,
            opened_at,
            observed_cores: BTreeSet::new(),
        });
        Ok(report)
    }

    pub fn status(&self, session_id: &str) -> Result<SessionStatusReport> {
        let active = self.require_session(session_id)?;
        Ok(SessionStatusReport {
            state: "open",
            opened_at: active.opened_at.clone(),
            session: active.info.clone(),
            observed_core_indexes: active.observed_cores.iter().copied().collect(),
            close_policy: CLOSE_POLICY,
        })
    }

    pub fn control_core(
        &mut self,
        session_id: &str,
        core_index: u32,
        action: CoreExecutionAction,
    ) -> Result<SessionCoreControlReport> {
        let session = self.require_session(session_id)?.info.clone();
        if core_index >= session.target.core_count {
            return Err(DebugError::config(
                "requested core index is outside the target core inventory",
                json!({
                    "core_index": core_index,
                    "core_count": session.target.core_count,
                    "target": session.target.name,
                }),
            ));
        }
        require_core_action_capability(self.backend.capabilities(), self.backend.name(), action)?;

        let core = self
            .backend
            .control_core_in_session(&session, core_index, action)?;
        validate_control_observation(&session, core_index, action, &core)?;
        self.active
            .as_mut()
            .expect("active session was validated")
            .observed_cores
            .insert(core_index);

        Ok(SessionCoreControlReport {
            observed_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            state_scope: "active_session",
            session_id: session.session_id,
            core,
            complete: true,
        })
    }

    pub fn close(&mut self, session_id: &str) -> Result<SessionCloseReport> {
        let active = self.require_session(session_id)?;
        let session = active.info.clone();
        let observed_cores = active.observed_cores.iter().copied().collect::<Vec<_>>();

        let mut final_core_observations = Vec::with_capacity(observed_cores.len());
        let mut resume_failures = Vec::new();
        for core_index in observed_cores {
            match self.backend.control_core_in_session(
                &session,
                core_index,
                CoreExecutionAction::Run,
            ) {
                Ok(core) => match validate_control_observation(
                    &session,
                    core_index,
                    CoreExecutionAction::Run,
                    &core,
                ) {
                    Ok(()) => final_core_observations.push(core),
                    Err(error) => resume_failures.push(error_summary(&error)),
                },
                Err(error) => resume_failures.push(error_summary(&error)),
            }
        }

        let disconnect_result = self.backend.disconnect(&session);
        if disconnect_result.is_ok() {
            self.active = None;
        }

        match (resume_failures.is_empty(), disconnect_result) {
            (true, Ok(())) => Ok(SessionCloseReport {
                state: "closed",
                session_id: session.session_id,
                close_policy: CLOSE_POLICY,
                final_core_observations,
                disconnected: true,
                complete: true,
            }),
            (false, Ok(())) => Err(DebugError::new(
                ErrorCode::ProtocolError,
                "session disconnected, but one or more observed cores could not be explicitly resumed",
                6,
                json!({
                    "session_id": session.session_id,
                    "session_closed": true,
                    "resume_failures": resume_failures,
                }),
            )),
            (true, Err(error)) => Err(error),
            (false, Err(cleanup)) => Err(DebugError::new(
                ErrorCode::ProtocolError,
                "failed to resume observed cores and disconnect the active session",
                6,
                json!({
                    "session_id": session.session_id,
                    "session_closed": false,
                    "resume_failures": resume_failures,
                    "disconnect_failure": error_summary(&cleanup),
                }),
            )),
        }
    }

    pub fn close_active(&mut self) -> Result<Option<SessionCloseReport>> {
        let Some(session_id) = self
            .active
            .as_ref()
            .map(|active| active.info.session_id.clone())
        else {
            return Ok(None);
        };
        self.close(&session_id).map(Some)
    }

    pub fn has_active_session(&self) -> bool {
        self.active.is_some()
    }

    fn require_session(&self, session_id: &str) -> Result<&ActiveSession> {
        let Some(active) = &self.active else {
            return Err(DebugError::new(
                ErrorCode::ProtocolError,
                "the session service does not own an active debug session",
                6,
                json!({"requested_session_id": session_id}),
            ));
        };
        if active.info.session_id != session_id {
            return Err(DebugError::new(
                ErrorCode::ProtocolError,
                "request refers to a stale or foreign debug session",
                6,
                json!({
                    "requested_session_id": session_id,
                    "active_session_id": active.info.session_id,
                }),
            ));
        }
        Ok(active)
    }
}

#[derive(Debug, Deserialize)]
struct SessionRequest {
    schema_version: String,
    request_id: String,
    #[serde(flatten)]
    operation: SessionOperation,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "operation")]
enum SessionOperation {
    #[serde(rename = "session.open")]
    Open { probe: String, target: String },
    #[serde(rename = "session.status")]
    Status { session_id: String },
    #[serde(rename = "core.status")]
    CoreStatus {
        session_id: String,
        #[serde(default)]
        core: u32,
    },
    #[serde(rename = "core.halt")]
    CoreHalt {
        session_id: String,
        #[serde(default)]
        core: u32,
    },
    #[serde(rename = "core.run")]
    CoreRun {
        session_id: String,
        #[serde(default)]
        core: u32,
    },
    #[serde(rename = "session.close")]
    Close { session_id: String },
    #[serde(rename = "server.shutdown")]
    Shutdown,
}

impl SessionOperation {
    fn name(&self) -> &'static str {
        match self {
            Self::Open { .. } => "session.open",
            Self::Status { .. } => "session.status",
            Self::CoreStatus { .. } => "core.status",
            Self::CoreHalt { .. } => "core.halt",
            Self::CoreRun { .. } => "core.run",
            Self::Close { .. } => "session.close",
            Self::Shutdown => "server.shutdown",
        }
    }
}

struct HandledResponse {
    operation: &'static str,
    data: Value,
    warnings: Vec<String>,
    shutdown: bool,
}

#[derive(Debug, Serialize)]
struct SessionSuccessEnvelope<'a> {
    schema_version: &'static str,
    ok: bool,
    request_id: &'a str,
    operation: &'a str,
    operation_id: String,
    data: Value,
    warnings: Vec<String>,
    artifacts: Vec<Value>,
}

#[derive(Debug, Serialize)]
struct SessionErrorEnvelope<'a> {
    schema_version: &'static str,
    ok: bool,
    request_id: Option<&'a str>,
    operation: &'a str,
    operation_id: String,
    error: SessionErrorPayload<'a>,
}

#[derive(Debug, Serialize)]
struct SessionErrorPayload<'a> {
    code: ErrorCode,
    message: &'a str,
    retryable: bool,
    details: &'a Value,
    suggested_actions: &'a [crate::error::SuggestedAction],
}

pub fn serve_jsonl<B, R, W, D>(
    backend: B,
    mut input: R,
    mut output: W,
    mut diagnostics: D,
) -> Result<()>
where
    B: DebugBackend,
    R: BufRead,
    W: Write,
    D: Write,
{
    let mut service = SessionService::new(backend);
    let result = serve_jsonl_loop(&mut service, &mut input, &mut output);
    let cleanup = cleanup_after_transport_end(&mut service, &mut diagnostics);
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(()), Err(cleanup)) => Err(cleanup),
        (Err(primary), Err(cleanup)) => Err(with_cleanup_failure(primary, cleanup)),
    }
}

fn serve_jsonl_loop<B: DebugBackend>(
    service: &mut SessionService<B>,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<()> {
    let mut line = String::new();

    loop {
        line.clear();
        let bytes = input
            .read_line(&mut line)
            .map_err(|error| DebugError::io("read session JSONL request", None, &error))?;
        if bytes == 0 {
            return Ok(());
        }
        if line.trim().is_empty() {
            continue;
        }

        let (request_id, operation) = request_context(&line);
        if line.len() > MAX_REQUEST_LINE_BYTES {
            let error = protocol_error(
                "session request exceeds the JSONL line limit",
                json!({"maximum_bytes": MAX_REQUEST_LINE_BYTES, "received_bytes": line.len()}),
            );
            write_error(output, request_id.as_deref(), &operation, &error)?;
            continue;
        }

        let request = match parse_request(&line) {
            Ok(request) => request,
            Err(error) => {
                write_error(output, request_id.as_deref(), &operation, &error)?;
                continue;
            }
        };

        match handle_request(service, &request) {
            Ok(response) => {
                let shutdown = response.shutdown;
                write_success(output, &request.request_id, response)?;
                if shutdown {
                    return Ok(());
                }
            }
            Err(error) => {
                write_error(
                    output,
                    Some(&request.request_id),
                    request.operation.name(),
                    &error,
                )?;
            }
        }
    }
}

fn parse_request(line: &str) -> Result<SessionRequest> {
    let request: SessionRequest = serde_json::from_str(line).map_err(|error| {
        protocol_error(
            "invalid session JSONL request",
            json!({"cause": error.to_string()}),
        )
    })?;
    if request.schema_version != SCHEMA_VERSION {
        return Err(protocol_error(
            "unsupported session protocol schema version",
            json!({
                "expected": SCHEMA_VERSION,
                "received": request.schema_version,
            }),
        ));
    }
    if request.request_id.trim().is_empty() || request.request_id.len() > MAX_REQUEST_ID_BYTES {
        return Err(protocol_error(
            "request_id must be non-empty and bounded",
            json!({
                "maximum_bytes": MAX_REQUEST_ID_BYTES,
                "received_bytes": request.request_id.len(),
            }),
        ));
    }
    Ok(request)
}

fn handle_request<B: DebugBackend>(
    service: &mut SessionService<B>,
    request: &SessionRequest,
) -> Result<HandledResponse> {
    let operation = request.operation.name();
    let (data, warnings, shutdown) = match &request.operation {
        SessionOperation::Open { probe, target } => (
            serde_json::to_value(service.open(probe, target)?)
                .expect("session open report always serializes"),
            vec![SESSION_STATE_WARNING.to_string()],
            false,
        ),
        SessionOperation::Status { session_id } => (
            serde_json::to_value(service.status(session_id)?)
                .expect("session status report always serializes"),
            Vec::new(),
            false,
        ),
        SessionOperation::CoreStatus { session_id, core } => (
            serde_json::to_value(service.control_core(
                session_id,
                *core,
                CoreExecutionAction::Status,
            )?)
            .expect("session core report always serializes"),
            vec![SESSION_STATE_WARNING.to_string()],
            false,
        ),
        SessionOperation::CoreHalt { session_id, core } => (
            serde_json::to_value(service.control_core(
                session_id,
                *core,
                CoreExecutionAction::Halt,
            )?)
            .expect("session core report always serializes"),
            vec![SESSION_STATE_WARNING.to_string()],
            false,
        ),
        SessionOperation::CoreRun { session_id, core } => (
            serde_json::to_value(service.control_core(
                session_id,
                *core,
                CoreExecutionAction::Run,
            )?)
            .expect("session core report always serializes"),
            vec![SESSION_STATE_WARNING.to_string()],
            false,
        ),
        SessionOperation::Close { session_id } => (
            serde_json::to_value(service.close(session_id)?)
                .expect("session close report always serializes"),
            Vec::new(),
            false,
        ),
        SessionOperation::Shutdown => {
            if service.has_active_session() {
                return Err(protocol_error(
                    "close the active debug session before shutting down the server",
                    json!({"required_operation": "session.close"}),
                ));
            }
            (json!({"shutdown": true}), Vec::new(), true)
        }
    };
    Ok(HandledResponse {
        operation,
        data,
        warnings,
        shutdown,
    })
}

fn write_success(
    output: &mut impl Write,
    request_id: &str,
    response: HandledResponse,
) -> Result<()> {
    let envelope = SessionSuccessEnvelope {
        schema_version: SCHEMA_VERSION,
        ok: true,
        request_id,
        operation: response.operation,
        operation_id: format!("op_{}", Uuid::new_v4().simple()),
        data: response.data,
        warnings: response.warnings,
        artifacts: Vec::new(),
    };
    write_envelope(output, &envelope)
}

fn write_error(
    output: &mut impl Write,
    request_id: Option<&str>,
    operation: &str,
    error: &DebugError,
) -> Result<()> {
    let envelope = SessionErrorEnvelope {
        schema_version: SCHEMA_VERSION,
        ok: false,
        request_id,
        operation,
        operation_id: format!("op_{}", Uuid::new_v4().simple()),
        error: SessionErrorPayload {
            code: error.code,
            message: &error.message,
            retryable: error.retryable,
            details: &error.details,
            suggested_actions: &error.suggested_actions,
        },
    };
    write_envelope(output, &envelope)
}

fn write_envelope(output: &mut impl Write, envelope: &impl Serialize) -> Result<()> {
    serde_json::to_writer(&mut *output, envelope).map_err(|error| {
        DebugError::new(
            ErrorCode::Internal,
            "failed to serialize session JSONL response",
            10,
            json!({"cause": error.to_string()}),
        )
    })?;
    output
        .write_all(b"\n")
        .and_then(|_| output.flush())
        .map_err(|error| DebugError::io("write session JSONL response", None, &error))
}

fn cleanup_after_transport_end<B: DebugBackend>(
    service: &mut SessionService<B>,
    diagnostics: &mut impl Write,
) -> Result<()> {
    match service.close_active() {
        Ok(Some(report)) => {
            let _ = writeln!(
                diagnostics,
                "session transport ended; safely closed {} using {}",
                report.session_id, report.close_policy
            );
            Ok(())
        }
        Ok(None) => Ok(()),
        Err(error) => {
            let _ = writeln!(
                diagnostics,
                "session transport ended; cleanup failed [{}]: {}",
                serialize_error_code(error.code),
                error.message
            );
            Err(error)
        }
    }
}

fn request_context(line: &str) -> (Option<String>, String) {
    let Ok(value) = serde_json::from_str::<Value>(line) else {
        return (None, "session.request".to_string());
    };
    let request_id = value
        .get("request_id")
        .and_then(Value::as_str)
        .filter(|request_id| {
            !request_id.trim().is_empty() && request_id.len() <= MAX_REQUEST_ID_BYTES
        })
        .map(ToString::to_string);
    let operation = value
        .get("operation")
        .and_then(Value::as_str)
        .unwrap_or("session.request")
        .to_string();
    (request_id, operation)
}

fn require_core_action_capability(
    capabilities: &crate::model::Capabilities,
    backend: &str,
    action: CoreExecutionAction,
) -> Result<()> {
    let missing = match action {
        CoreExecutionAction::Status if !capabilities.core_status => Some("core_status"),
        CoreExecutionAction::Halt if !capabilities.core_status => Some("core_status"),
        CoreExecutionAction::Halt if !capabilities.halt => Some("halt"),
        CoreExecutionAction::Run if !capabilities.core_status => Some("core_status"),
        CoreExecutionAction::Run if !capabilities.run => Some("run"),
        _ => None,
    };
    if let Some(capability) = missing {
        return Err(DebugError::new(
            ErrorCode::CapabilityUnavailable,
            "selected backend cannot perform the requested in-session core action",
            6,
            json!({"backend": backend, "action": action, "capability": capability}),
        ));
    }
    Ok(())
}

fn validate_control_observation(
    session: &SessionInfo,
    core_index: u32,
    action: CoreExecutionAction,
    core: &CoreExecutionObservation,
) -> Result<()> {
    if core.index != core_index || core.action != action {
        return Err(protocol_error(
            "backend returned a different core control observation than requested",
            json!({
                "requested_core": core_index,
                "received_core": core.index,
                "requested_action": action,
                "received_action": core.action,
            }),
        ));
    }
    validate_core_execution_observation(&session.target, core).map_err(|problem| {
        protocol_error(
            "backend returned an invalid in-session core control observation",
            json!({"problem": problem, "core": core}),
        )
    })
}

fn protocol_error(message: impl Into<String>, details: Value) -> DebugError {
    DebugError::new(ErrorCode::ProtocolError, message, 6, details)
}

fn error_summary(error: &DebugError) -> Value {
    json!({
        "code": error.code,
        "message": error.message,
        "details": error.details,
    })
}

fn with_cleanup_failure(primary: DebugError, cleanup: DebugError) -> DebugError {
    DebugError::new(
        primary.code,
        primary.message,
        primary.exit_code,
        json!({
            "primary": primary.details,
            "cleanup_failure": error_summary(&cleanup),
        }),
    )
}

fn serialize_error_code(code: ErrorCode) -> String {
    serde_json::to_value(code)
        .expect("error code always serializes")
        .as_str()
        .expect("error code serializes as a string")
        .to_string()
}

#[cfg(test)]
mod tests {
    use std::{io::Cursor, path::Path};

    use serde_json::Value;

    use super::*;
    use crate::{
        backend::replay::{ReplayBackend, ReplayFixture},
        model::CoreState,
    };

    fn service() -> SessionService<ReplayBackend> {
        SessionService::new(
            ReplayBackend::from_path(Path::new("examples/replay/stm32g4.json")).unwrap(),
        )
    }

    #[test]
    fn persistent_replay_session_keeps_state_until_safe_close() {
        let mut service = service();
        let opened = service
            .open("replay:stlink-v3:0039002A3432510433343034", "STM32G431CBTx")
            .unwrap();
        let session_id = opened.session.session_id.clone();

        let running = service
            .control_core(&session_id, 0, CoreExecutionAction::Run)
            .unwrap();
        let halted = service
            .control_core(&session_id, 0, CoreExecutionAction::Halt)
            .unwrap();
        let status = service
            .control_core(&session_id, 0, CoreExecutionAction::Status)
            .unwrap();
        let open_status = service.status(&session_id).unwrap();
        let closed = service.close(&session_id).unwrap();

        assert_eq!(running.core.state, CoreState::Running);
        assert_eq!(halted.core.state, CoreState::Halted);
        assert_eq!(status.core.state, CoreState::Halted);
        assert_eq!(open_status.observed_core_indexes, vec![0]);
        assert_eq!(closed.final_core_observations.len(), 1);
        assert_eq!(closed.final_core_observations[0].state, CoreState::Running);
        assert!(!service.has_active_session());
    }

    #[test]
    fn stale_session_id_is_rejected_without_mutating_the_active_session() {
        let mut service = service();
        let opened = service
            .open("replay:stlink-v3:0039002A3432510433343034", "STM32G431CBTx")
            .unwrap();

        let error = service
            .control_core("ses_stale", 0, CoreExecutionAction::Halt)
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::ProtocolError);
        assert_eq!(
            error.details["active_session_id"],
            opened.session.session_id
        );
        assert!(service.status(&opened.session.session_id).is_ok());
        service.close(&opened.session.session_id).unwrap();
    }

    #[test]
    fn in_session_control_does_not_require_a_post_disconnect_guarantee() {
        let mut fixture = ReplayFixture::load(Path::new("examples/replay/stm32g4.json")).unwrap();
        fixture.capabilities.post_disconnect_core_state = false;
        let mut service = SessionService::new(ReplayBackend::new(fixture));
        let opened = service
            .open("replay:stlink-v3:0039002A3432510433343034", "STM32G431CBTx")
            .unwrap();

        let halted = service
            .control_core(&opened.session.session_id, 0, CoreExecutionAction::Halt)
            .unwrap();

        assert_eq!(halted.core.state, CoreState::Halted);
        service.close(&opened.session.session_id).unwrap();
    }

    #[test]
    fn jsonl_protocol_returns_errors_per_line_and_keeps_serving() {
        let backend = ReplayBackend::from_path(Path::new("examples/replay/stm32g4.json")).unwrap();
        let input = concat!(
            "not-json\n",
            "{\"schema_version\":\"0.9\",\"request_id\":\"old\",\"operation\":\"server.shutdown\"}\n",
            "{\"schema_version\":\"1.0\",\"request_id\":\"done\",\"operation\":\"server.shutdown\"}\n"
        );
        let mut output = Vec::new();
        serve_jsonl(
            backend,
            Cursor::new(input.as_bytes()),
            &mut output,
            Vec::new(),
        )
        .unwrap();

        let responses = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(responses.len(), 3);
        assert_eq!(responses[0]["error"]["code"], "PROTOCOL_ERROR");
        assert_eq!(responses[1]["request_id"], "old");
        assert_eq!(responses[1]["error"]["details"]["expected"], "1.0");
        assert_eq!(responses[2]["ok"], true);
        assert_eq!(responses[2]["operation"], "server.shutdown");
    }
}
