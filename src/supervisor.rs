use std::{
    collections::HashMap,
    ffi::OsString,
    io::{self, BufRead, BufReader, Write},
    path::Path,
    process::{Command, ExitStatus, Stdio},
    sync::mpsc::{self, Receiver, SyncSender},
    thread,
    time::Duration,
};

use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    SCHEMA_VERSION,
    error::{DebugError, Result},
    session::MAX_REQUEST_LINE_BYTES,
};

const SUPERVISOR_ERROR_CHILD_EXITED: i64 = -32001;
const SUPERVISOR_ERROR_NOT_READY: i64 = -32002;
const SUPERVISOR_ERROR_DUPLICATE_ID: i64 = -32003;
const DEFAULT_MAX_RESTARTS: u32 = 3;
const MAX_MAX_RESTARTS: u32 = 32;
const DEFAULT_RESTART_DELAY_MS: u64 = 250;
const MAX_RESTART_DELAY_MS: u64 = 60_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupervisorOptions {
    max_restarts: u32,
    restart_delay_ms: u64,
}

impl SupervisorOptions {
    pub fn from_values(max_restarts: u32, restart_delay_ms: u64) -> Result<Self> {
        if max_restarts > MAX_MAX_RESTARTS {
            return Err(DebugError::config(
                "supervisor max restarts exceeds the supported bound",
                json!({
                    "max_restarts": max_restarts,
                    "maximum": MAX_MAX_RESTARTS,
                }),
            ));
        }
        if restart_delay_ms > MAX_RESTART_DELAY_MS {
            return Err(DebugError::config(
                "supervisor restart delay exceeds the supported bound",
                json!({
                    "restart_delay_ms": restart_delay_ms,
                    "maximum_ms": MAX_RESTART_DELAY_MS,
                }),
            ));
        }
        Ok(Self {
            max_restarts,
            restart_delay_ms,
        })
    }

    pub const fn max_restarts(self) -> u32 {
        self.max_restarts
    }

    pub const fn restart_delay_ms(self) -> u64 {
        self.restart_delay_ms
    }
}

impl Default for SupervisorOptions {
    fn default() -> Self {
        Self {
            max_restarts: DEFAULT_MAX_RESTARTS,
            restart_delay_ms: DEFAULT_RESTART_DELAY_MS,
        }
    }
}

pub const fn default_max_restarts() -> u32 {
    DEFAULT_MAX_RESTARTS
}

pub const fn default_restart_delay_ms() -> u64 {
    DEFAULT_RESTART_DELAY_MS
}

pub const fn max_max_restarts() -> u32 {
    MAX_MAX_RESTARTS
}

pub const fn max_restart_delay_ms() -> u64 {
    MAX_RESTART_DELAY_MS
}

#[derive(Debug)]
enum ChildInput {
    Line(String),
    Close,
}

#[derive(Debug)]
enum SupervisorEvent {
    ParentLine(String),
    ParentEnd,
    ParentReadError(io::Error),
    ChildOutput {
        generation: u64,
        line: String,
    },
    ChildStdoutEnd {
        generation: u64,
    },
    ChildStdoutError {
        generation: u64,
        error: io::Error,
    },
    ChildStdinError {
        generation: u64,
        error: io::Error,
    },
    ChildExit {
        generation: u64,
        status: std::result::Result<ExitStatus, io::Error>,
    },
}

struct ChildHandle {
    generation: u64,
    stdin: SyncSender<ChildInput>,
}

#[derive(Debug, Default)]
struct RequestMetadata {
    method: Option<String>,
    id: Option<Value>,
}

#[derive(Debug)]
struct PendingRequest {
    id: Value,
    method: Option<String>,
    initialize_request: Option<Value>,
}

#[derive(Debug, Default)]
struct HandshakeCache {
    initialize_request: Option<Value>,
    initialized_notification: Option<String>,
}

pub fn serve_mcp(
    executable: &Path,
    child_args: &[OsString],
    options: SupervisorOptions,
) -> Result<()> {
    let (sender, receiver) = mpsc::sync_channel(128);
    spawn_parent_reader(sender.clone())?;

    let mut generation = 1_u64;
    let mut child = spawn_child(executable, child_args, generation, &sender)?;
    let mut restart_count = 0_u32;
    let mut awaiting_initialize = false;
    let mut internal_initialize_id = None::<String>;
    let mut expected_exit = false;
    let mut parent_ended = false;
    let mut child_exit_status = None;
    let mut child_stdout_ended = false;
    let mut pending = HashMap::<String, PendingRequest>::new();
    let mut handshake = HandshakeCache::default();
    let stdout = io::stdout();
    let stderr = io::stderr();
    let mut output = stdout.lock();
    let mut diagnostics = stderr.lock();

    loop {
        let event = receiver.recv().map_err(|error| {
            DebugError::new(
                crate::error::ErrorCode::Internal,
                "supervisor event channel closed unexpectedly",
                10,
                json!({"cause": error.to_string()}),
            )
        })?;
        match event {
            SupervisorEvent::ParentLine(line) => {
                if line.len() > MAX_REQUEST_LINE_BYTES {
                    write_error(
                        &mut output,
                        None,
                        -32600,
                        "supervisor rejected an oversized MCP request",
                        json!({"maximum_bytes": MAX_REQUEST_LINE_BYTES}),
                    )?;
                    continue;
                }
                let metadata = request_metadata(&line);
                let initialized_notification = metadata.method.as_deref()
                    == Some("notifications/initialized")
                    && metadata.id.is_none();
                if initialized_notification && handshake.initialize_request.is_some() {
                    handshake.initialized_notification = Some(line.clone());
                }
                if initialized_notification && internal_initialize_id.is_some() {
                    continue;
                }
                let permits_external_initialize = internal_initialize_id.is_none()
                    && metadata.method.as_deref() == Some("initialize")
                    && metadata.id.is_some();
                if awaiting_initialize && metadata.method.is_some() && !permits_external_initialize
                {
                    if let Some(id) = metadata.id {
                        let (message, data) = if internal_initialize_id.is_some() {
                            (
                                "supervised MCP child is reinitializing; retry the request",
                                json!({"retry": true}),
                            )
                        } else {
                            (
                                "supervised MCP child is awaiting the connection's first initialize request",
                                json!({"required_method": "initialize"}),
                            )
                        };
                        write_error(
                            &mut output,
                            Some(&id),
                            SUPERVISOR_ERROR_NOT_READY,
                            message,
                            data,
                        )?;
                    }
                    continue;
                }

                let pending_key = metadata.id.as_ref().map(request_id_key);
                if let Some(key) = pending_key.as_ref()
                    && pending.contains_key(key)
                {
                    write_error(
                        &mut output,
                        metadata.id.as_ref(),
                        SUPERVISOR_ERROR_DUPLICATE_ID,
                        "supervisor rejected a duplicate in-flight JSON-RPC id",
                        json!({"id": metadata.id}),
                    )?;
                    continue;
                }
                if let (Some(key), Some(id)) = (pending_key, metadata.id) {
                    let initialize_request = (metadata.method.as_deref() == Some("initialize"))
                        .then(|| serde_json::from_str(&line).ok())
                        .flatten();
                    pending.insert(
                        key,
                        PendingRequest {
                            id,
                            method: metadata.method.clone(),
                            initialize_request,
                        },
                    );
                }
                if metadata.method.as_deref() == Some("shutdown") {
                    expected_exit = true;
                }
                child.stdin.send(ChildInput::Line(line)).map_err(|error| {
                    DebugError::new(
                        crate::error::ErrorCode::Internal,
                        "failed to forward an MCP request to the supervised child",
                        10,
                        json!({"cause": error.to_string()}),
                    )
                })?;
            }
            SupervisorEvent::ParentEnd => {
                parent_ended = true;
                expected_exit = true;
                let _ = child.stdin.send(ChildInput::Close);
            }
            SupervisorEvent::ParentReadError(error) => {
                return Err(DebugError::io("read supervisor stdin", None, &error));
            }
            SupervisorEvent::ChildOutput {
                generation: event_generation,
                line,
            } => {
                if event_generation != child.generation {
                    continue;
                }
                if let Some(id) = response_id(&line) {
                    if internal_initialize_id
                        .as_deref()
                        .is_some_and(|internal_id| id.as_str() == Some(internal_id))
                    {
                        if !response_is_success(&line) {
                            return Err(DebugError::new(
                                crate::error::ErrorCode::Internal,
                                "supervised MCP child rejected the restored initialize handshake",
                                10,
                                json!({
                                    "generation": child.generation,
                                    "response": serde_json::from_str::<Value>(&line).ok(),
                                }),
                            ));
                        }
                        internal_initialize_id = None;
                        awaiting_initialize = false;
                        if let Some(notification) = &handshake.initialized_notification {
                            child
                                .stdin
                                .send(ChildInput::Line(notification.clone()))
                                .map_err(|error| {
                                    DebugError::new(
                                        crate::error::ErrorCode::Internal,
                                        "failed to restore the MCP initialized notification",
                                        10,
                                        json!({"cause": error.to_string()}),
                                    )
                                })?;
                        }
                        write_event(
                            &mut diagnostics,
                            "supervisor.child_ready",
                            json!({
                                "generation": child.generation,
                                "restart_count": restart_count,
                                "initialize_replayed": true,
                                "initialized_notification_replayed": handshake
                                    .initialized_notification
                                    .is_some(),
                            }),
                        )?;
                        continue;
                    }

                    if let Some(request) = pending.remove(&request_id_key(&id))
                        && request.method.as_deref() == Some("initialize")
                        && response_is_success(&line)
                    {
                        if let Some(initialize_request) = request.initialize_request {
                            handshake.initialize_request = Some(initialize_request);
                        }
                        awaiting_initialize = false;
                    }
                }
                output
                    .write_all(line.as_bytes())
                    .and_then(|_| output.flush())
                    .map_err(|error| DebugError::io("write supervised MCP stdout", None, &error))?;
            }
            SupervisorEvent::ChildStdoutEnd {
                generation: event_generation,
            } => {
                if event_generation == child.generation {
                    child_stdout_ended = true;
                }
            }
            SupervisorEvent::ChildStdoutError {
                generation: event_generation,
                error,
            } => {
                if event_generation == child.generation {
                    child_stdout_ended = true;
                    write_event(
                        &mut diagnostics,
                        "supervisor.child_stdout_error",
                        json!({
                            "generation": event_generation,
                            "message": error.to_string(),
                        }),
                    )?;
                }
            }
            SupervisorEvent::ChildStdinError {
                generation: event_generation,
                error,
            } => {
                if event_generation == child.generation {
                    write_event(
                        &mut diagnostics,
                        "supervisor.child_stdin_error",
                        json!({
                            "generation": event_generation,
                            "message": error.to_string(),
                        }),
                    )?;
                }
            }
            SupervisorEvent::ChildExit {
                generation: event_generation,
                status,
            } => {
                if event_generation != child.generation {
                    continue;
                }
                let status = status.map_err(|error| {
                    DebugError::io("wait for supervised MCP child", None, &error)
                })?;
                child_exit_status = Some(status);
            }
        }

        if child_stdout_ended && let Some(status) = child_exit_status.take() {
            if expected_exit || parent_ended {
                if !parent_ended {
                    fail_pending(&mut output, &mut pending, child.generation, &status)?;
                }
                if !status.success() {
                    return Err(DebugError::new(
                        crate::error::ErrorCode::Internal,
                        "supervised MCP child exited during an expected shutdown",
                        10,
                        exit_details(status),
                    ));
                }
                return Ok(());
            }

            fail_pending(&mut output, &mut pending, child.generation, &status)?;
            if restart_count >= options.max_restarts() {
                write_event(
                    &mut diagnostics,
                    "supervisor.child_exited",
                    json!({
                        "generation": child.generation,
                        "restart": false,
                        "restart_count": restart_count,
                        "max_restarts": options.max_restarts(),
                        "exit": exit_details(status),
                    }),
                )?;
                return Err(DebugError::new(
                    crate::error::ErrorCode::Internal,
                    "supervisor restart limit was reached",
                    10,
                    json!({
                        "restart_count": restart_count,
                        "max_restarts": options.max_restarts(),
                        "exit": exit_details(status),
                    }),
                ));
            }

            restart_count += 1;
            write_event(
                &mut diagnostics,
                "supervisor.child_exited",
                json!({
                    "generation": child.generation,
                    "restart": true,
                    "restart_count": restart_count,
                    "max_restarts": options.max_restarts(),
                    "exit": exit_details(status),
                }),
            )?;
            if options.restart_delay_ms() != 0 {
                thread::sleep(Duration::from_millis(options.restart_delay_ms()));
            }
            generation += 1;
            child = spawn_child(executable, child_args, generation, &sender)?;
            awaiting_initialize = true;
            internal_initialize_id = None;
            expected_exit = false;
            child_stdout_ended = false;
            let recovery_state = if let Some(initialize_request) = &handshake.initialize_request {
                let (initialize_id, initialize_line) =
                    restored_initialize_request(initialize_request, generation)?;
                child
                    .stdin
                    .send(ChildInput::Line(initialize_line))
                    .map_err(|error| {
                        DebugError::new(
                            crate::error::ErrorCode::Internal,
                            "failed to restore the MCP initialize handshake",
                            10,
                            json!({"cause": error.to_string()}),
                        )
                    })?;
                internal_initialize_id = Some(initialize_id);
                "reinitializing"
            } else {
                "awaiting_client_initialize"
            };
            write_event(
                &mut diagnostics,
                "supervisor.child_restarted",
                json!({
                    "generation": generation,
                    "restart_count": restart_count,
                    "max_restarts": options.max_restarts(),
                    "state": recovery_state,
                }),
            )?;
        }
    }
}

fn spawn_parent_reader(sender: SyncSender<SupervisorEvent>) -> Result<()> {
    thread::Builder::new()
        .name("embedded-debugger-supervisor-stdin".to_string())
        .spawn(move || {
            let stdin = io::stdin();
            let mut input = stdin.lock();
            loop {
                let mut line = String::new();
                match input.read_line(&mut line) {
                    Ok(0) => {
                        let _ = sender.send(SupervisorEvent::ParentEnd);
                        return;
                    }
                    Ok(_) => {
                        if sender.send(SupervisorEvent::ParentLine(line)).is_err() {
                            return;
                        }
                    }
                    Err(error) => {
                        let _ = sender.send(SupervisorEvent::ParentReadError(error));
                        return;
                    }
                }
            }
        })
        .map(|_| ())
        .map_err(|error| DebugError::io("start supervisor stdin reader", None, &error))
}

fn spawn_child(
    executable: &Path,
    child_args: &[OsString],
    generation: u64,
    sender: &SyncSender<SupervisorEvent>,
) -> Result<ChildHandle> {
    let mut command = Command::new(executable);
    command
        .args(child_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let mut child = command.spawn().map_err(|error| {
        DebugError::io("spawn supervised MCP child", executable.to_str(), &error)
    })?;
    let child_stdin = child.stdin.take().ok_or_else(|| {
        DebugError::new(
            crate::error::ErrorCode::Internal,
            "supervised MCP child did not expose stdin",
            10,
            json!({"generation": generation}),
        )
    })?;
    let child_stdout = child.stdout.take().ok_or_else(|| {
        DebugError::new(
            crate::error::ErrorCode::Internal,
            "supervised MCP child did not expose stdout",
            10,
            json!({"generation": generation}),
        )
    })?;

    let (stdin_sender, stdin_receiver) = mpsc::sync_channel(64);
    let stdin_events = sender.clone();
    thread::spawn(move || {
        child_stdin_writer(child_stdin, stdin_receiver, generation, stdin_events)
    });

    let stdout_events = sender.clone();
    thread::spawn(move || child_stdout_reader(child_stdout, generation, stdout_events));

    let wait_events = sender.clone();
    thread::spawn(move || {
        let status = child.wait();
        let _ = wait_events.send(SupervisorEvent::ChildExit { generation, status });
    });

    Ok(ChildHandle {
        generation,
        stdin: stdin_sender,
    })
}

fn child_stdin_writer(
    mut stdin: impl Write,
    receiver: Receiver<ChildInput>,
    generation: u64,
    sender: SyncSender<SupervisorEvent>,
) {
    for input in receiver {
        match input {
            ChildInput::Line(line) => {
                if let Err(error) = stdin.write_all(line.as_bytes()).and_then(|_| stdin.flush()) {
                    let _ = sender.send(SupervisorEvent::ChildStdinError { generation, error });
                    return;
                }
            }
            ChildInput::Close => return,
        }
    }
}

fn child_stdout_reader(
    stdout: impl std::io::Read,
    generation: u64,
    sender: SyncSender<SupervisorEvent>,
) {
    let mut reader = BufReader::new(stdout);
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => {
                let _ = sender.send(SupervisorEvent::ChildStdoutEnd { generation });
                return;
            }
            Ok(_) => {
                if sender
                    .send(SupervisorEvent::ChildOutput { generation, line })
                    .is_err()
                {
                    return;
                }
            }
            Err(error) => {
                let _ = sender.send(SupervisorEvent::ChildStdoutError { generation, error });
                return;
            }
        }
    }
}

fn request_metadata(line: &str) -> RequestMetadata {
    let Ok(value) = serde_json::from_str::<Value>(line) else {
        return RequestMetadata::default();
    };
    let Some(object) = value.as_object() else {
        return RequestMetadata::default();
    };
    let is_json_rpc = object.get("jsonrpc").and_then(Value::as_str) == Some("2.0");
    let method = is_json_rpc
        .then(|| {
            object
                .get("method")
                .and_then(Value::as_str)
                .filter(|method| !method.trim().is_empty())
                .map(str::to_string)
        })
        .flatten();
    RequestMetadata {
        id: method
            .is_some()
            .then(|| object.get("id").filter(|value| !value.is_null()).cloned())
            .flatten(),
        method,
    }
}

fn response_id(line: &str) -> Option<Value> {
    let value = serde_json::from_str::<Value>(line).ok()?;
    let object = value.as_object()?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || object.contains_key("method")
        || (!object.contains_key("result") && !object.contains_key("error"))
    {
        return None;
    }
    object.get("id").filter(|value| !value.is_null()).cloned()
}

fn response_is_success(line: &str) -> bool {
    serde_json::from_str::<Value>(line)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .is_some_and(|object| object.contains_key("result") && !object.contains_key("error"))
}

fn restored_initialize_request(request: &Value, generation: u64) -> Result<(String, String)> {
    let mut restored = request.clone();
    let object = restored.as_object_mut().ok_or_else(|| {
        DebugError::new(
            crate::error::ErrorCode::Internal,
            "cached MCP initialize handshake is not a JSON object",
            10,
            json!({"generation": generation}),
        )
    })?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || object.get("method").and_then(Value::as_str) != Some("initialize")
    {
        return Err(DebugError::new(
            crate::error::ErrorCode::Internal,
            "cached MCP initialize handshake is invalid",
            10,
            json!({"generation": generation}),
        ));
    }

    let id = format!("supervisor.initialize.{generation}.{}", Uuid::new_v4());
    object.insert("id".to_string(), Value::String(id.clone()));
    let mut line = serde_json::to_string(&restored).map_err(|error| {
        DebugError::new(
            crate::error::ErrorCode::Internal,
            "failed to serialize the restored MCP initialize handshake",
            10,
            json!({"generation": generation, "cause": error.to_string()}),
        )
    })?;
    line.push('\n');
    Ok((id, line))
}

fn request_id_key(id: &Value) -> String {
    serde_json::to_string(id).expect("JSON-RPC id always serializes")
}

fn fail_pending(
    output: &mut impl Write,
    pending: &mut HashMap<String, PendingRequest>,
    generation: u64,
    status: &ExitStatus,
) -> Result<()> {
    let requests = pending
        .drain()
        .map(|(_, request)| request.id)
        .collect::<Vec<_>>();
    for id in requests {
        write_error(
            output,
            Some(&id),
            SUPERVISOR_ERROR_CHILD_EXITED,
            "supervised MCP child exited before a response; target state is indeterminate",
            json!({
                "generation": generation,
                "restart_required": true,
                "exit": exit_details(*status),
            }),
        )?;
    }
    Ok(())
}

fn exit_details(status: ExitStatus) -> Value {
    json!({
        "success": status.success(),
        "code": status.code(),
    })
}

fn write_error(
    output: &mut impl Write,
    id: Option<&Value>,
    code: i64,
    message: &str,
    data: Value,
) -> Result<()> {
    serde_json::to_writer(
        &mut *output,
        &json!({
            "jsonrpc": "2.0",
            "id": id.cloned().unwrap_or(Value::Null),
            "error": {"code": code, "message": message, "data": data},
        }),
    )
    .map_err(|error| {
        DebugError::new(
            crate::error::ErrorCode::Internal,
            "failed to serialize supervisor JSON-RPC error",
            10,
            json!({"cause": error.to_string()}),
        )
    })?;
    output
        .write_all(b"\n")
        .and_then(|_| output.flush())
        .map_err(|error| DebugError::io("write supervisor JSON-RPC error", None, &error))
}

fn write_event(output: &mut impl Write, event: &str, details: Value) -> Result<()> {
    let mut object = serde_json::Map::new();
    object.insert("schema_version".to_string(), json!(SCHEMA_VERSION));
    object.insert("event".to_string(), json!(event));
    if let Value::Object(details) = details {
        object.extend(details);
    }
    serde_json::to_writer(&mut *output, &Value::Object(object)).map_err(|error| {
        DebugError::new(
            crate::error::ErrorCode::Internal,
            "failed to serialize supervisor lifecycle event",
            10,
            json!({"cause": error.to_string()}),
        )
    })?;
    output
        .write_all(b"\n")
        .and_then(|_| output.flush())
        .map_err(|error| DebugError::io("write supervisor lifecycle event", None, &error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supervisor_options_are_bounded() {
        assert_eq!(
            SupervisorOptions::default().max_restarts(),
            DEFAULT_MAX_RESTARTS
        );
        assert_eq!(
            SupervisorOptions::default().restart_delay_ms(),
            DEFAULT_RESTART_DELAY_MS
        );
        assert!(SupervisorOptions::from_values(MAX_MAX_RESTARTS, MAX_RESTART_DELAY_MS).is_ok());
        assert_eq!(
            SupervisorOptions::from_values(MAX_MAX_RESTARTS + 1, 0)
                .unwrap_err()
                .code,
            crate::error::ErrorCode::ConfigInvalid
        );
        assert_eq!(
            SupervisorOptions::from_values(0, MAX_RESTART_DELAY_MS + 1)
                .unwrap_err()
                .code,
            crate::error::ErrorCode::ConfigInvalid
        );
    }

    #[test]
    fn request_metadata_tracks_only_real_json_rpc_ids() {
        let metadata = request_metadata(r#"{"jsonrpc":"2.0","id":7,"method":"ping"}"#);
        assert_eq!(metadata.method.as_deref(), Some("ping"));
        assert_eq!(metadata.id, Some(json!(7)));
        assert!(
            request_metadata(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
                .id
                .is_none()
        );
        let wrong_version = request_metadata(r#"{"jsonrpc":"1.0","id":8,"method":"shutdown"}"#);
        assert!(wrong_version.method.is_none());
        assert!(wrong_version.id.is_none());
        let client_response = request_metadata(r#"{"jsonrpc":"2.0","id":9,"result":{}}"#);
        assert!(client_response.method.is_none());
        assert!(client_response.id.is_none());
        assert!(request_metadata("not json").method.is_none());
    }

    #[test]
    fn response_ids_do_not_consume_server_requests() {
        assert_eq!(
            response_id(r#"{"jsonrpc":"2.0","id":7,"result":{}}"#),
            Some(json!(7))
        );
        assert!(response_id(r#"{"jsonrpc":"2.0","id":7,"method":"roots/list"}"#).is_none());
        assert!(response_id(r#"{"jsonrpc":"2.0","id":7}"#).is_none());
    }

    #[test]
    fn pending_requests_fail_as_indeterminate_without_replay() {
        let status = Command::new(std::env::current_exe().unwrap())
            .arg("--help")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        let mut pending = HashMap::from([(
            request_id_key(&json!(7)),
            PendingRequest {
                id: json!(7),
                method: Some("tools/call".to_string()),
                initialize_request: None,
            },
        )]);
        let mut output = Vec::new();

        fail_pending(&mut output, &mut pending, 3, &status).unwrap();

        assert!(pending.is_empty());
        let response: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(response["id"], 7);
        assert_eq!(response["error"]["code"], SUPERVISOR_ERROR_CHILD_EXITED);
        assert_eq!(response["error"]["data"]["generation"], 3);
        assert_eq!(response["error"]["data"]["restart_required"], true);
        assert!(
            response["error"]["message"]
                .as_str()
                .unwrap()
                .contains("target state is indeterminate")
        );
    }

    #[test]
    fn restored_initialize_preserves_params_and_uses_a_private_id() {
        let original = json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "clientInfo": {"name": "test-client", "version": "1.0.0"}
            }
        });

        let (id, line) = restored_initialize_request(&original, 4).unwrap();
        let restored: Value = serde_json::from_str(&line).unwrap();

        assert!(id.starts_with("supervisor.initialize.4."));
        assert_eq!(restored["id"], id);
        assert_eq!(restored["params"], original["params"]);
        assert_eq!(original["id"], 7);
    }
}
