use std::{
    fs::{self, File},
    io::Read,
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{
    GdbExecutableFileIdentity, GdbExecutableInspection, GdbInspectOptions, GdbMiCommandResult,
    GdbMiHandshake, GdbMiOutput, GdbMiProtocol, GdbMiShutdown, OpenOcdConfigurationInspection,
    OpenOcdExecutableFileIdentity, OpenOcdExecutableInspection, OpenOcdServerConfirmationBoundary,
    OpenOcdServerEffects, OpenOcdServerLifecyclePlan, OpenOcdServerLogs, OpenOcdServerOptions,
    OpenOcdServerPlan, OpenOcdServerReadiness, OpenOcdServerShutdown,
    gdb::{
        MAX_GDB_MI_COMMAND_TIMEOUT_MS, MAX_GDB_MI_SHUTDOWN_TIMEOUT_MS,
        MAX_GDB_MI_STARTUP_TIMEOUT_MS, MAX_GDB_VERSION_TIMEOUT_MS, MIN_GDB_MI_COMMAND_TIMEOUT_MS,
        MIN_GDB_MI_SHUTDOWN_TIMEOUT_MS, MIN_GDB_MI_STARTUP_TIMEOUT_MS, MIN_GDB_VERSION_TIMEOUT_MS,
        XTENSA_GNU_CONFIG_ENV, execute_remote_gdb, remote_protocol_contract,
    },
    server::{ManagedServerCompletion, ManagedServerSession, start_managed_server},
};
use crate::{
    SCHEMA_VERSION,
    error::{DebugError, ErrorCode, Result, SuggestedAction},
};

pub const DEFAULT_OPENOCD_TARGET_STATE_TIMEOUT_MS: u64 = 3_000;
pub const MIN_OPENOCD_TARGET_STATE_TIMEOUT_MS: u64 = 100;
pub const MAX_OPENOCD_TARGET_STATE_TIMEOUT_MS: u64 = 30_000;
pub const MAX_GDB_XTENSA_CONFIG_BYTES: u64 = 16 * 1024 * 1024;

pub(super) const TARGET_STATE_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(250);
const TARGET_STATE_POLL_INTERVAL: Duration = Duration::from_millis(25);
const MAX_TARGET_NAME_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenOcdGdbSessionOptions {
    pub openocd: OpenOcdServerOptions,
    pub gdb_executable: PathBuf,
    pub gdb_xtensa_config: Option<PathBuf>,
    pub expected_target: String,
    pub gdb_version_timeout_ms: u64,
    pub gdb_startup_timeout_ms: u64,
    pub gdb_command_timeout_ms: u64,
    pub gdb_shutdown_timeout_ms: u64,
    pub target_state_timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdGdbSessionPlan {
    pub backend: String,
    pub operation: String,
    pub risk: String,
    pub complete: bool,
    pub openocd: OpenOcdSessionServerPlan,
    pub gdb: OpenOcdSessionGdbPlan,
    pub protocol: GdbMiProtocol,
    pub target_state_policy: OpenOcdTargetStatePolicy,
    pub effects: OpenOcdGdbSessionEffects,
    pub confirmation_boundary: OpenOcdGdbSessionConfirmationBoundary,
    pub confirm_digest: String,
    #[serde(skip)]
    pub(super) openocd_execution_plan: OpenOcdServerPlan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdSessionServerPlan {
    pub executable: OpenOcdExecutableInspection,
    pub executable_file: OpenOcdExecutableFileIdentity,
    pub configuration: OpenOcdConfigurationInspection,
    pub lifecycle: OpenOcdServerLifecyclePlan,
    pub configuration_effects: OpenOcdServerEffects,
    pub confirmation_boundary: OpenOcdServerConfirmationBoundary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdSessionGdbPlan {
    pub executable: GdbExecutableInspection,
    pub executable_file: GdbExecutableFileIdentity,
    pub xtensa_config: Option<GdbXtensaConfigInspection>,
    pub ambient_xtensa_config_inherited: bool,
    pub version_timeout_ms: u64,
    pub startup_timeout_ms: u64,
    pub command_timeout_ms: u64,
    pub shutdown_timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GdbXtensaConfigInspection {
    pub environment_variable: String,
    pub requested: String,
    pub resolved: String,
    pub bytes: u64,
    pub sha256: String,
    pub maximum_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdTargetStatePolicy {
    pub target_selection: String,
    pub expected_current_target: String,
    pub state_query: String,
    pub initial_state_required: String,
    pub attach_behavior: String,
    pub normal_restoration_command: String,
    pub normal_restoration_expected_effect: String,
    pub fallback_condition: String,
    pub fallback_command_template: String,
    pub final_state_required: String,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdGdbSessionEffects {
    pub configuration_tcl_execution_required: bool,
    pub adapter_or_target_access_possible_from_configuration: bool,
    pub reset_or_device_write_possible_from_configuration: bool,
    pub arbitrary_host_command_execution_possible_from_configuration: bool,
    pub remote_gdb_attach_requested: bool,
    pub target_halt_possible_on_attach: bool,
    pub openocd_attach_handler_flash_probe_possible: bool,
    pub openocd_attach_handler_reset_possible: bool,
    pub remote_negotiation_target_description_or_memory_map_possible: bool,
    pub remote_negotiation_register_or_stop_state_access_possible: bool,
    pub detach_resume_requested: bool,
    pub fixed_resume_fallback_possible: bool,
    pub target_state_restoration_verification_required: bool,
    pub symbol_or_executable_loading_requested: bool,
    pub explicit_register_or_memory_command_requested: bool,
    pub breakpoint_or_watchpoint_requested: bool,
    pub flash_command_requested: bool,
    pub arbitrary_gdb_or_monitor_command_requested: bool,
    pub gdb_xtensa_target_configuration_requested: bool,
    pub gdb_xtensa_target_configuration_native_code_execution_possible: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdGdbSessionConfirmationBoundary {
    pub openocd_executable_file_hash_bound: bool,
    pub openocd_version_bound: bool,
    pub top_level_configuration_hashes_bound: bool,
    pub search_directory_paths_bound: bool,
    pub search_directory_contents_bound: bool,
    pub transitive_sources_bound: bool,
    pub gdb_executable_file_hash_bound: bool,
    pub gdb_version_bound: bool,
    pub gdb_xtensa_config_selection_bound: bool,
    pub gdb_xtensa_config_file_hash_bound: bool,
    pub fixed_mi_protocol_bound: bool,
    pub lifecycle_deadlines_bound: bool,
    pub loopback_dynamic_endpoint_policy_bound: bool,
    pub runtime_port_number_bound: bool,
    pub expected_target_name_bound: bool,
    pub runtime_adapter_identity_bound: bool,
    pub target_state_policy_bound: bool,
    pub symbol_or_firmware_identity_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdGdbSessionTestReport {
    pub backend: String,
    pub scope: String,
    pub risk: String,
    pub complete: bool,
    pub confirm_digest: String,
    pub openocd: OpenOcdSessionServerPlan,
    pub gdb: OpenOcdSessionGdbPlan,
    pub protocol: GdbMiProtocol,
    pub target_state_policy: OpenOcdTargetStatePolicy,
    pub readiness: OpenOcdServerReadiness,
    pub target_restoration: OpenOcdTargetRestoration,
    pub exchange: OpenOcdGdbExchange,
    pub openocd_shutdown: OpenOcdServerShutdown,
    pub openocd_logs: OpenOcdServerLogs,
    pub effects: OpenOcdGdbSessionEffects,
    pub confirmation_boundary: OpenOcdGdbSessionConfirmationBoundary,
    pub capabilities: OpenOcdGdbSessionCapabilities,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdTargetStateObservation {
    pub target_name: String,
    pub state: String,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdTargetRestoration {
    pub initial: OpenOcdTargetStateObservation,
    pub after_gdb: Option<OpenOcdTargetStateObservation>,
    pub after_gdb_error: Option<String>,
    pub fallback_resume_requested: bool,
    pub fallback_resume_response: Option<String>,
    pub fallback_resume_error: Option<String>,
    pub final_observation: Option<OpenOcdTargetStateObservation>,
    pub final_observation_error: Option<String>,
    pub required_final_state: String,
    pub timeout_ms: u64,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdGdbExchange {
    pub endpoint: String,
    pub handshake: GdbMiHandshake,
    pub connection: GdbMiCommandResult,
    pub detach: GdbMiCommandResult,
    pub shutdown: GdbMiShutdown,
    pub output: GdbMiOutput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdGdbSessionCapabilities {
    pub server_launch: bool,
    pub tcl_rpc: bool,
    pub gdb_mi: bool,
    pub remote_target_connection: bool,
    pub target_state_observation: bool,
    pub attach_detach: bool,
    pub restoration_resume: bool,
    pub symbol_loading: bool,
    pub register_read: bool,
    pub memory_read: bool,
    pub stack_read: bool,
    pub breakpoints: bool,
    pub watchpoints: bool,
    pub general_execution_control: bool,
    pub flash: bool,
    pub arbitrary_commands: bool,
}

#[derive(Debug, Serialize)]
struct SessionConfirmationInput<'a> {
    schema_version: &'static str,
    operation: &'static str,
    backend: &'static str,
    openocd_executable_path: &'a str,
    openocd_executable_version: &'a str,
    openocd_executable_file: &'a super::OpenOcdExecutableFileIdentity,
    openocd_configuration: &'a super::OpenOcdConfigurationInspection,
    openocd_lifecycle: &'a super::OpenOcdServerLifecyclePlan,
    openocd_effects: &'a OpenOcdServerEffects,
    openocd_confirmation_boundary: &'a OpenOcdServerConfirmationBoundary,
    gdb_executable_path: &'a str,
    gdb_executable_version: &'a str,
    gdb_executable_file: &'a GdbExecutableFileIdentity,
    gdb_xtensa_config: Option<&'a GdbXtensaConfigInspection>,
    gdb_lifecycle: GdbLifecycleConfirmation,
    protocol: &'a GdbMiProtocol,
    target_state_policy: &'a OpenOcdTargetStatePolicy,
    effects: &'a OpenOcdGdbSessionEffects,
    confirmation_boundary: &'a OpenOcdGdbSessionConfirmationBoundary,
}

#[derive(Debug, Serialize)]
struct GdbLifecycleConfirmation {
    version_timeout_ms: u64,
    startup_timeout_ms: u64,
    command_timeout_ms: u64,
    shutdown_timeout_ms: u64,
}

pub fn plan_session(options: &OpenOcdGdbSessionOptions) -> Result<OpenOcdGdbSessionPlan> {
    validate_session_options(options)?;
    let openocd_server = super::plan_server(&options.openocd)?;
    let openocd = OpenOcdSessionServerPlan {
        executable: openocd_server.executable.clone(),
        executable_file: openocd_server.executable_file.clone(),
        configuration: openocd_server.configuration.clone(),
        lifecycle: openocd_server.lifecycle.clone(),
        configuration_effects: openocd_server.effects.clone(),
        confirmation_boundary: openocd_server.confirmation_boundary.clone(),
    };
    let gdb_inspection = super::inspect_gdb(&GdbInspectOptions {
        executable: options.gdb_executable.clone(),
        timeout_ms: options.gdb_version_timeout_ms,
    })?;
    let gdb_xtensa_config = options
        .gdb_xtensa_config
        .as_deref()
        .map(inspect_gdb_xtensa_config)
        .transpose()?;
    if gdb_xtensa_config.is_some() && gdb_inspection.executable.vendor != "espressif" {
        return Err(DebugError::config(
            "Xtensa target configuration requires an Espressif GDB executable",
            json!({
                "gdb_vendor": gdb_inspection.executable.vendor,
                "environment_variable": XTENSA_GNU_CONFIG_ENV,
            }),
        ));
    }
    let gdb = OpenOcdSessionGdbPlan {
        executable: gdb_inspection.executable,
        executable_file: gdb_inspection.executable_file,
        xtensa_config: gdb_xtensa_config,
        ambient_xtensa_config_inherited: false,
        version_timeout_ms: options.gdb_version_timeout_ms,
        startup_timeout_ms: options.gdb_startup_timeout_ms,
        command_timeout_ms: options.gdb_command_timeout_ms,
        shutdown_timeout_ms: options.gdb_shutdown_timeout_ms,
    };
    let protocol = remote_protocol_contract();
    let target_state_policy = target_state_policy(
        options.expected_target.clone(),
        options.target_state_timeout_ms,
    );
    let effects = session_effects(gdb.xtensa_config.is_some());
    let confirmation_boundary = session_confirmation_boundary();
    let confirmation = SessionConfirmationInput {
        schema_version: SCHEMA_VERSION,
        operation: "openocd.session.test",
        backend: "openocd",
        openocd_executable_path: &openocd.executable.resolved,
        openocd_executable_version: &openocd.executable.version_line,
        openocd_executable_file: &openocd.executable_file,
        openocd_configuration: &openocd.configuration,
        openocd_lifecycle: &openocd.lifecycle,
        openocd_effects: &openocd.configuration_effects,
        openocd_confirmation_boundary: &openocd.confirmation_boundary,
        gdb_executable_path: &gdb.executable.resolved,
        gdb_executable_version: &gdb.executable.version_line,
        gdb_executable_file: &gdb.executable_file,
        gdb_xtensa_config: gdb.xtensa_config.as_ref(),
        gdb_lifecycle: GdbLifecycleConfirmation {
            version_timeout_ms: gdb.version_timeout_ms,
            startup_timeout_ms: gdb.startup_timeout_ms,
            command_timeout_ms: gdb.command_timeout_ms,
            shutdown_timeout_ms: gdb.shutdown_timeout_ms,
        },
        protocol: &protocol,
        target_state_policy: &target_state_policy,
        effects: &effects,
        confirmation_boundary: &confirmation_boundary,
    };
    let confirm_digest = hex::encode(Sha256::digest(
        serde_json::to_vec(&confirmation).expect("session confirmation input always serializes"),
    ));

    Ok(OpenOcdGdbSessionPlan {
        backend: "openocd".to_string(),
        operation: "openocd.session.test".to_string(),
        risk: "R2_DEVICE_WRITE".to_string(),
        complete: true,
        openocd,
        gdb,
        protocol,
        target_state_policy,
        effects,
        confirmation_boundary,
        confirm_digest,
        openocd_execution_plan: openocd_server,
    })
}

pub fn test_session(
    options: &OpenOcdGdbSessionOptions,
    confirm_digest: &str,
) -> Result<OpenOcdGdbSessionTestReport> {
    let plan = plan_session(options)?;
    if plan.confirm_digest != confirm_digest {
        return Err(session_confirmation_error(
            &plan.confirm_digest,
            confirm_digest,
        ));
    }
    execute_session_plan(plan)
}

fn execute_session_plan(plan: OpenOcdGdbSessionPlan) -> Result<OpenOcdGdbSessionTestReport> {
    let server = start_managed_server(&plan.openocd_execution_plan)?;
    let initial = match observe_initial_target(&server, plan.target_state_policy.timeout_ms) {
        Ok(observation) => observation,
        Err(error) => {
            return Err(with_server_context(error, server.finish(), None));
        }
    };
    if initial.target_name != plan.target_state_policy.expected_current_target {
        let error = DebugError::new(
            ErrorCode::VerificationFailed,
            "OpenOCD current target did not match the confirmed target name",
            3,
            json!({
                "expected_current_target": plan.target_state_policy.expected_current_target,
                "observed_current_target": initial.target_name,
                "observed_state": initial.state,
                "remote_gdb_started": false,
            }),
        );
        return Err(with_server_context(error, server.finish(), None));
    }
    if initial.state != plan.target_state_policy.initial_state_required {
        let error = DebugError::new(
            ErrorCode::VerificationFailed,
            "OpenOCD current target was not running before remote GDB attachment",
            3,
            json!({
                "initial_observation": initial,
                "required_initial_state": plan.target_state_policy.initial_state_required,
                "remote_gdb_started": false,
            }),
        );
        return Err(with_server_context(error, server.finish(), None));
    }

    let gdb_result = execute_remote_gdb(
        &plan.gdb.executable.resolved,
        plan.gdb
            .xtensa_config
            .as_ref()
            .map(|config| config.resolved.as_str()),
        server.readiness().gdb_port,
        plan.gdb.startup_timeout_ms,
        plan.gdb.command_timeout_ms,
        plan.gdb.shutdown_timeout_ms,
    );
    let restoration = restore_running_target(&server, initial, plan.target_state_policy.timeout_ms);
    let completion = server.finish();

    let exchange = match gdb_result {
        Ok(execution) => OpenOcdGdbExchange {
            endpoint: execution.endpoint.clone(),
            handshake: GdbMiHandshake {
                startup_prompt_observed: true,
                startup_elapsed_ms: duration_ms(execution.startup_elapsed),
                startup_timeout_ms: plan.gdb.startup_timeout_ms,
                version_command: GdbMiCommandResult {
                    token: 1,
                    command: "-gdb-version".to_string(),
                    result_class: execution.version_result_class,
                    elapsed_ms: duration_ms(execution.version_elapsed),
                },
                version_stream_records: execution.version_stream_records,
                record_counts: execution.record_counts,
            },
            connection: GdbMiCommandResult {
                token: 2,
                command: format!("-target-select remote {}", execution.endpoint),
                result_class: execution.connect_result_class,
                elapsed_ms: duration_ms(execution.connect_elapsed),
            },
            detach: GdbMiCommandResult {
                token: 3,
                command: "-target-detach".to_string(),
                result_class: execution.detach_result_class,
                elapsed_ms: duration_ms(execution.detach_elapsed),
            },
            shutdown: execution.shutdown,
            output: execution.output,
        },
        Err(gdb_error) => {
            if !restoration.complete {
                let error = restoration_error(&restoration, Some(&gdb_error));
                return Err(with_server_context(error, completion, Some(&restoration)));
            }
            return Err(with_server_context(
                gdb_error,
                completion,
                Some(&restoration),
            ));
        }
    };

    if !restoration.complete {
        let error = restoration_error(&restoration, None);
        return Err(with_server_context(error, completion, Some(&restoration)));
    }
    if let Some(message) = completion.lifecycle_error() {
        let error = DebugError::new(
            ErrorCode::ProtocolError,
            message,
            6,
            json!({
                "target_restoration": restoration,
                "gdb_exchange": exchange,
            }),
        );
        return Err(with_server_context(error, completion, None));
    }

    Ok(OpenOcdGdbSessionTestReport {
        backend: plan.backend,
        scope: "confirmed_remote_attach_detach_lifecycle".to_string(),
        risk: plan.risk,
        complete: true,
        confirm_digest: plan.confirm_digest,
        openocd: plan.openocd,
        gdb: plan.gdb,
        protocol: plan.protocol,
        target_state_policy: plan.target_state_policy,
        readiness: completion.readiness,
        target_restoration: restoration,
        exchange,
        openocd_shutdown: completion.shutdown,
        openocd_logs: completion.logs,
        effects: plan.effects,
        confirmation_boundary: plan.confirmation_boundary,
        capabilities: session_capabilities(),
    })
}

pub(super) fn observe_initial_target(
    server: &ManagedServerSession,
    timeout_ms: u64,
) -> Result<OpenOcdTargetStateObservation> {
    let started = Instant::now();
    let deadline = started + Duration::from_millis(timeout_ms);
    let target_name = server
        .tcl_request("target current", remaining_timeout(deadline)?)
        .map_err(|cause| target_state_error("query OpenOCD current target", cause))?;
    let target_name = validate_target_name(&target_name)?;
    let state = query_target_state(server, &target_name, deadline)
        .map_err(|cause| target_state_error("query initial OpenOCD target state", cause))?;
    Ok(OpenOcdTargetStateObservation {
        target_name,
        state,
        elapsed_ms: duration_ms(started.elapsed()),
    })
}

pub(super) fn restore_running_target(
    server: &ManagedServerSession,
    initial: OpenOcdTargetStateObservation,
    timeout_ms: u64,
) -> OpenOcdTargetRestoration {
    let started = Instant::now();
    let deadline = started + Duration::from_millis(timeout_ms);
    let mut after_gdb = None;
    let mut after_gdb_error = None;
    match query_target_state(server, &initial.target_name, deadline) {
        Ok(state) => {
            after_gdb = Some(OpenOcdTargetStateObservation {
                target_name: initial.target_name.clone(),
                state,
                elapsed_ms: duration_ms(started.elapsed()),
            });
        }
        Err(error) => after_gdb_error = Some(error),
    }

    if after_gdb
        .as_ref()
        .is_some_and(|observed| observed.state == "running")
    {
        return OpenOcdTargetRestoration {
            initial,
            after_gdb: after_gdb.clone(),
            after_gdb_error,
            fallback_resume_requested: false,
            fallback_resume_response: None,
            fallback_resume_error: None,
            final_observation: after_gdb,
            final_observation_error: None,
            required_final_state: "running".to_string(),
            timeout_ms,
            complete: true,
        };
    }

    let resume_command = format!("targets {}; resume", initial.target_name);
    let (fallback_resume_response, fallback_resume_error) = match remaining_timeout(deadline)
        .and_then(|timeout| {
            server
                .tcl_request(&resume_command, timeout)
                .map_err(|cause| target_state_error("send fixed OpenOCD resume fallback", cause))
        }) {
        Ok(response) => (Some(response), None),
        Err(error) => (None, Some(error.message)),
    };

    let mut final_observation = None;
    let mut final_observation_error = None;
    loop {
        match query_target_state(server, &initial.target_name, deadline) {
            Ok(state) => {
                let observation = OpenOcdTargetStateObservation {
                    target_name: initial.target_name.clone(),
                    state,
                    elapsed_ms: duration_ms(started.elapsed()),
                };
                let running = observation.state == "running";
                final_observation = Some(observation);
                if running {
                    break;
                }
            }
            Err(error) => final_observation_error = Some(error),
        }
        if Instant::now() >= deadline {
            break;
        }
        thread::sleep(
            TARGET_STATE_POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
        );
    }
    let complete = final_observation
        .as_ref()
        .is_some_and(|observation| observation.state == "running");
    if !complete && final_observation_error.is_none() {
        final_observation_error = Some("target did not reach running before deadline".to_string());
    }
    OpenOcdTargetRestoration {
        initial,
        after_gdb,
        after_gdb_error,
        fallback_resume_requested: true,
        fallback_resume_response,
        fallback_resume_error,
        final_observation,
        final_observation_error,
        required_final_state: "running".to_string(),
        timeout_ms,
        complete,
    }
}

pub(super) fn query_target_state(
    server: &ManagedServerSession,
    target_name: &str,
    deadline: Instant,
) -> std::result::Result<String, String> {
    let timeout = remaining_timeout_string(deadline)?.min(TARGET_STATE_ATTEMPT_TIMEOUT);
    let response = server.tcl_request(&format!("{target_name} curstate"), timeout)?;
    let state = response.trim();
    if !matches!(
        state,
        "debug-running" | "halted" | "reset" | "running" | "unavailable" | "unknown"
    ) {
        return Err(format!(
            "OpenOCD returned an unrecognized target state: {}",
            bounded_text(state)
        ));
    }
    Ok(state.to_string())
}

pub(super) fn validate_target_name(response: &str) -> Result<String> {
    let name = response.trim();
    if name.is_empty()
        || name.len() > MAX_TARGET_NAME_BYTES
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
    {
        return Err(DebugError::new(
            ErrorCode::ProtocolError,
            "OpenOCD returned an unsafe current target name",
            6,
            json!({
                "response": bounded_text(name),
                "maximum_bytes": MAX_TARGET_NAME_BYTES,
            }),
        ));
    }
    Ok(name.to_string())
}

fn remaining_timeout(deadline: Instant) -> Result<Duration> {
    remaining_timeout_string(deadline).map_err(|cause| {
        let mut error = DebugError::new(ErrorCode::Timeout, cause, 5, json!({}));
        error.retryable = true;
        error
    })
}

fn remaining_timeout_string(deadline: Instant) -> std::result::Result<Duration, String> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err("target-state deadline was exhausted".to_string());
    }
    Ok(remaining)
}

fn target_state_error(operation: &str, cause: impl Into<String>) -> DebugError {
    DebugError::new(
        ErrorCode::ProtocolError,
        operation,
        6,
        json!({"cause": cause.into()}),
    )
}

fn restoration_error(
    restoration: &OpenOcdTargetRestoration,
    gdb_error: Option<&DebugError>,
) -> DebugError {
    DebugError::verification(
        "remote GDB session did not prove restoration of the initial running target state",
        json!({
            "target_restoration": restoration,
            "gdb_error": gdb_error.map(error_value),
        }),
    )
}

pub(super) fn with_server_context(
    mut error: DebugError,
    completion: ManagedServerCompletion,
    restoration: Option<&OpenOcdTargetRestoration>,
) -> DebugError {
    let mut details = error.details.as_object().cloned().unwrap_or_default();
    if let Some(restoration) = restoration {
        details.insert(
            "target_restoration".to_string(),
            serde_json::to_value(restoration).expect("target restoration always serializes"),
        );
    }
    details.insert(
        "openocd_readiness".to_string(),
        serde_json::to_value(&completion.readiness).expect("readiness always serializes"),
    );
    details.insert(
        "openocd_shutdown".to_string(),
        serde_json::to_value(&completion.shutdown).expect("shutdown always serializes"),
    );
    details.insert(
        "openocd_logs".to_string(),
        serde_json::to_value(&completion.logs).expect("logs always serialize"),
    );
    if let Some(message) = completion.lifecycle_error() {
        details.insert(
            "openocd_lifecycle_error".to_string(),
            Value::String(message.to_string()),
        );
    }
    error.details = Value::Object(details);
    error
}

fn error_value(error: &DebugError) -> Value {
    json!({
        "code": error.code,
        "message": error.message,
        "retryable": error.retryable,
        "exit_code": error.exit_code,
        "details": error.details,
        "suggested_actions": error.suggested_actions,
    })
}

pub(super) fn validate_session_options(options: &OpenOcdGdbSessionOptions) -> Result<()> {
    validate_expected_target_name(&options.expected_target)?;
    validate_timeout(
        "gdb_version",
        options.gdb_version_timeout_ms,
        MIN_GDB_VERSION_TIMEOUT_MS,
        MAX_GDB_VERSION_TIMEOUT_MS,
    )?;
    validate_timeout(
        "gdb_startup",
        options.gdb_startup_timeout_ms,
        MIN_GDB_MI_STARTUP_TIMEOUT_MS,
        MAX_GDB_MI_STARTUP_TIMEOUT_MS,
    )?;
    validate_timeout(
        "gdb_command",
        options.gdb_command_timeout_ms,
        MIN_GDB_MI_COMMAND_TIMEOUT_MS,
        MAX_GDB_MI_COMMAND_TIMEOUT_MS,
    )?;
    validate_timeout(
        "gdb_shutdown",
        options.gdb_shutdown_timeout_ms,
        MIN_GDB_MI_SHUTDOWN_TIMEOUT_MS,
        MAX_GDB_MI_SHUTDOWN_TIMEOUT_MS,
    )?;
    validate_timeout(
        "target_state",
        options.target_state_timeout_ms,
        MIN_OPENOCD_TARGET_STATE_TIMEOUT_MS,
        MAX_OPENOCD_TARGET_STATE_TIMEOUT_MS,
    )?;
    super::server::validate_server_options(&options.openocd)
}

fn validate_expected_target_name(name: &str) -> Result<()> {
    if name != name.trim() {
        return Err(DebugError::config(
            "expected OpenOCD target name must not contain surrounding whitespace",
            json!({"expected_target": bounded_text(name)}),
        ));
    }
    validate_target_name(name).map(|_| ()).map_err(|error| {
        DebugError::config(
            "expected OpenOCD target name is outside the supported syntax",
            error.details,
        )
    })
}

fn validate_timeout(label: &str, value: u64, minimum: u64, maximum: u64) -> Result<()> {
    if !(minimum..=maximum).contains(&value) {
        return Err(DebugError::config(
            "OpenOCD GDB session timeout is outside the supported range",
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

fn target_state_policy(
    expected_current_target: String,
    timeout_ms: u64,
) -> OpenOcdTargetStatePolicy {
    OpenOcdTargetStatePolicy {
        target_selection: "OpenOCD target current must exactly match the confirmed target name"
            .to_string(),
        expected_current_target,
        state_query: "<validated_initial_current_target> curstate".to_string(),
        initial_state_required: "running".to_string(),
        attach_behavior: "default OpenOCD gdb-attach event may halt the target".to_string(),
        normal_restoration_command: "3-target-detach".to_string(),
        normal_restoration_expected_effect:
            "resume target according to GDB remote detach semantics".to_string(),
        fallback_condition: "running state is not proven after GDB cleanup".to_string(),
        fallback_command_template: "targets <validated_initial_current_target>; resume".to_string(),
        final_state_required: "running".to_string(),
        timeout_ms,
    }
}

fn session_effects(xtensa_config_selected: bool) -> OpenOcdGdbSessionEffects {
    OpenOcdGdbSessionEffects {
        configuration_tcl_execution_required: true,
        adapter_or_target_access_possible_from_configuration: true,
        reset_or_device_write_possible_from_configuration: true,
        arbitrary_host_command_execution_possible_from_configuration: true,
        remote_gdb_attach_requested: true,
        target_halt_possible_on_attach: true,
        openocd_attach_handler_flash_probe_possible: true,
        openocd_attach_handler_reset_possible: true,
        remote_negotiation_target_description_or_memory_map_possible: true,
        remote_negotiation_register_or_stop_state_access_possible: true,
        detach_resume_requested: true,
        fixed_resume_fallback_possible: true,
        target_state_restoration_verification_required: true,
        symbol_or_executable_loading_requested: false,
        explicit_register_or_memory_command_requested: false,
        breakpoint_or_watchpoint_requested: false,
        flash_command_requested: false,
        arbitrary_gdb_or_monitor_command_requested: false,
        gdb_xtensa_target_configuration_requested: xtensa_config_selected,
        gdb_xtensa_target_configuration_native_code_execution_possible: xtensa_config_selected,
        notes: vec![
            "OpenOCD configuration remains executable Tcl; only top-level files are hashed."
                .to_string(),
            "The tool sends no explicit target-data MI command, but normal remote negotiation may exchange stop state, target descriptions, memory-map metadata, or register state."
                .to_string(),
            "Confirmed OpenOCD configuration may run an attach handler that probes flash or resets and halts a protected target."
                .to_string(),
            "The session refuses attachment unless the current target is running and fails unless running is proven again before server shutdown."
                .to_string(),
            "Ambient XTENSA_GNU_CONFIG is never inherited; an explicitly selected configuration is canonicalized, hashed, and loaded as native host code."
                .to_string(),
        ],
    }
}

fn session_confirmation_boundary() -> OpenOcdGdbSessionConfirmationBoundary {
    OpenOcdGdbSessionConfirmationBoundary {
        openocd_executable_file_hash_bound: true,
        openocd_version_bound: true,
        top_level_configuration_hashes_bound: true,
        search_directory_paths_bound: true,
        search_directory_contents_bound: false,
        transitive_sources_bound: false,
        gdb_executable_file_hash_bound: true,
        gdb_version_bound: true,
        gdb_xtensa_config_selection_bound: true,
        gdb_xtensa_config_file_hash_bound: true,
        fixed_mi_protocol_bound: true,
        lifecycle_deadlines_bound: true,
        loopback_dynamic_endpoint_policy_bound: true,
        runtime_port_number_bound: false,
        expected_target_name_bound: true,
        runtime_adapter_identity_bound: false,
        target_state_policy_bound: true,
        symbol_or_firmware_identity_required: false,
    }
}

fn inspect_gdb_xtensa_config(requested: &std::path::Path) -> Result<GdbXtensaConfigInspection> {
    if requested.as_os_str().is_empty() {
        return Err(DebugError::config(
            "GDB Xtensa target configuration path must not be empty",
            json!({"environment_variable": XTENSA_GNU_CONFIG_ENV}),
        ));
    }
    let requested_display = stable_config_path(requested, "requested target configuration")?;
    let resolved = fs::canonicalize(requested).map_err(|source| {
        DebugError::config(
            "resolve GDB Xtensa target configuration failed",
            json!({"path": requested_display, "cause": source.to_string()}),
        )
    })?;
    let resolved_display = stable_config_path(&resolved, "resolved target configuration")?;
    let metadata = fs::metadata(&resolved).map_err(|source| {
        DebugError::config(
            "inspect GDB Xtensa target configuration failed",
            json!({"path": resolved_display, "cause": source.to_string()}),
        )
    })?;
    if !metadata.is_file() {
        return Err(DebugError::config(
            "GDB Xtensa target configuration is not a regular file",
            json!({"path": resolved_display}),
        ));
    }
    if metadata.len() > MAX_GDB_XTENSA_CONFIG_BYTES {
        return Err(DebugError::config(
            "GDB Xtensa target configuration exceeds the hashing size limit",
            json!({
                "path": resolved_display,
                "bytes": metadata.len(),
                "maximum": MAX_GDB_XTENSA_CONFIG_BYTES,
            }),
        ));
    }

    let mut file = File::open(&resolved).map_err(|source| {
        DebugError::config(
            "open GDB Xtensa target configuration for hashing failed",
            json!({"path": resolved_display, "cause": source.to_string()}),
        )
    })?;
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|source| {
            DebugError::config(
                "read GDB Xtensa target configuration for hashing failed",
                json!({"path": resolved_display, "cause": source.to_string()}),
            )
        })?;
        if count == 0 {
            break;
        }
        total = total.saturating_add(count as u64);
        if total > MAX_GDB_XTENSA_CONFIG_BYTES {
            return Err(DebugError::config(
                "GDB Xtensa target configuration grew beyond the hashing size limit",
                json!({"path": resolved_display, "maximum": MAX_GDB_XTENSA_CONFIG_BYTES}),
            ));
        }
        hasher.update(&buffer[..count]);
    }

    Ok(GdbXtensaConfigInspection {
        environment_variable: XTENSA_GNU_CONFIG_ENV.to_string(),
        requested: requested_display,
        resolved: resolved_display,
        bytes: total,
        sha256: hex::encode(hasher.finalize()),
        maximum_bytes: MAX_GDB_XTENSA_CONFIG_BYTES,
    })
}

fn stable_config_path(path: &std::path::Path, label: &str) -> Result<String> {
    let path = path.to_str().ok_or_else(|| {
        DebugError::config(
            format!("GDB Xtensa {label} is not valid Unicode"),
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

fn session_capabilities() -> OpenOcdGdbSessionCapabilities {
    OpenOcdGdbSessionCapabilities {
        server_launch: true,
        tcl_rpc: true,
        gdb_mi: true,
        remote_target_connection: true,
        target_state_observation: true,
        attach_detach: true,
        restoration_resume: true,
        symbol_loading: false,
        register_read: false,
        memory_read: false,
        stack_read: false,
        breakpoints: false,
        watchpoints: false,
        general_execution_control: false,
        flash: false,
        arbitrary_commands: false,
    }
}

fn session_confirmation_error(expected: &str, received: &str) -> DebugError {
    let mut error = DebugError::new(
        ErrorCode::ConfirmationMismatch,
        "OpenOCD GDB session confirmation digest does not match the current plan",
        2,
        json!({
            "expected_confirm_digest": expected,
            "received_confirm_digest": received,
        }),
    );
    error.suggested_actions.push(SuggestedAction::new(
        "review_openocd_session_plan",
        json!({"command": "openocd session plan"}),
    ));
    error
}

fn bounded_text(value: &str) -> String {
    value.chars().take(512).collect()
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::{Read, Write},
        net::{Ipv4Addr, TcpListener},
        path::Path,
    };

    use tempfile::tempdir;

    use super::*;

    const HELPER_ROLE: &str = "EMBEDDED_DEBUGGER_OPENOCD_SESSION_HELPER_ROLE";

    #[test]
    fn target_names_are_strictly_bounded_before_becoming_tcl_commands() {
        assert_eq!(
            validate_target_name("esp32s3.cpu0\n").unwrap(),
            "esp32s3.cpu0"
        );
        assert!(validate_target_name("esp32s3.cpu0; reset").is_err());
        assert!(validate_target_name("target with spaces").is_err());
    }

    #[test]
    fn session_specific_timeouts_fail_before_any_executable_lookup() {
        let options = OpenOcdGdbSessionOptions {
            openocd: OpenOcdServerOptions {
                executable: PathBuf::from("missing-openocd"),
                config_files: vec![PathBuf::from("missing.cfg")],
                search_dirs: Vec::new(),
                version_timeout_ms: super::super::DEFAULT_OPENOCD_VERSION_TIMEOUT_MS,
                startup_timeout_ms: super::super::DEFAULT_OPENOCD_SERVER_STARTUP_TIMEOUT_MS,
                shutdown_timeout_ms: super::super::DEFAULT_OPENOCD_SERVER_SHUTDOWN_TIMEOUT_MS,
            },
            gdb_executable: PathBuf::from("missing-gdb"),
            gdb_xtensa_config: None,
            expected_target: "fake.cpu0".to_string(),
            gdb_version_timeout_ms: super::super::DEFAULT_GDB_VERSION_TIMEOUT_MS,
            gdb_startup_timeout_ms: super::super::DEFAULT_GDB_MI_STARTUP_TIMEOUT_MS,
            gdb_command_timeout_ms: MIN_GDB_MI_COMMAND_TIMEOUT_MS - 1,
            gdb_shutdown_timeout_ms: super::super::DEFAULT_GDB_MI_SHUTDOWN_TIMEOUT_MS,
            target_state_timeout_ms: DEFAULT_OPENOCD_TARGET_STATE_TIMEOUT_MS,
        };
        let error = plan_session(&options).unwrap_err();
        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert_eq!(error.details["timeout_kind"], "gdb_command");
    }

    #[test]
    fn protocol_and_policy_expose_only_the_fixed_attach_detach_exchange() {
        let protocol = remote_protocol_contract();
        assert_eq!(protocol.commands.len(), 4);
        assert_eq!(protocol.commands[1].expected_result_class, "connected");
        assert_eq!(protocol.commands[2].command, "-target-detach");
        let policy = target_state_policy(
            "esp32s3.cpu0".to_string(),
            DEFAULT_OPENOCD_TARGET_STATE_TIMEOUT_MS,
        );
        assert_eq!(policy.expected_current_target, "esp32s3.cpu0");
        assert_eq!(policy.initial_state_required, "running");
        assert_eq!(policy.final_state_required, "running");
        assert!(policy.fallback_command_template.contains("resume"));
    }

    #[test]
    fn combined_session_restores_running_after_a_simulated_attach_halt() {
        let directory = tempdir().unwrap();
        let openocd = write_fake_openocd(directory.path());
        let gdb = write_fake_remote_gdb(directory.path());
        let config = directory.path().join("board.cfg");
        fs::write(&config, b"adapter speed 1000\n").unwrap();
        let options = OpenOcdGdbSessionOptions {
            openocd: OpenOcdServerOptions {
                executable: openocd,
                config_files: vec![config],
                search_dirs: vec![directory.path().to_path_buf()],
                version_timeout_ms: super::super::DEFAULT_OPENOCD_VERSION_TIMEOUT_MS,
                startup_timeout_ms: 5_000,
                shutdown_timeout_ms: 5_000,
            },
            gdb_executable: gdb,
            gdb_xtensa_config: None,
            expected_target: "fake.cpu0".to_string(),
            gdb_version_timeout_ms: 5_000,
            gdb_startup_timeout_ms: 5_000,
            gdb_command_timeout_ms: 5_000,
            gdb_shutdown_timeout_ms: 5_000,
            target_state_timeout_ms: 5_000,
        };

        let plan = plan_session(&options).unwrap();
        let report = test_session(&options, &plan.confirm_digest).unwrap();
        assert!(report.complete);
        assert_eq!(report.exchange.connection.result_class, "connected");
        assert_eq!(report.exchange.detach.result_class, "done");
        assert_eq!(report.target_restoration.initial.state, "running");
        assert_eq!(
            report.target_restoration.after_gdb.as_ref().unwrap().state,
            "halted"
        );
        assert!(report.target_restoration.fallback_resume_requested);
        assert_eq!(
            report
                .target_restoration
                .final_observation
                .as_ref()
                .unwrap()
                .state,
            "running"
        );
        assert!(report.exchange.shutdown.graceful);
        assert!(report.openocd_shutdown.graceful);
    }

    #[test]
    fn xtensa_config_is_hash_bound_and_passed_only_to_remote_gdb() {
        let directory = tempdir().unwrap();
        let openocd = write_fake_openocd(directory.path());
        let gdb = write_fake_remote_gdb_requiring_xtensa_config(directory.path());
        let config = directory.path().join("board.cfg");
        let xtensa_config = directory.path().join("xtensa_fake.so");
        fs::write(&config, b"adapter speed 1000\n").unwrap();
        fs::write(&xtensa_config, b"target-profile-a").unwrap();
        let options = OpenOcdGdbSessionOptions {
            openocd: OpenOcdServerOptions {
                executable: openocd,
                config_files: vec![config],
                search_dirs: vec![directory.path().to_path_buf()],
                version_timeout_ms: super::super::DEFAULT_OPENOCD_VERSION_TIMEOUT_MS,
                startup_timeout_ms: 5_000,
                shutdown_timeout_ms: 5_000,
            },
            gdb_executable: gdb,
            gdb_xtensa_config: Some(xtensa_config.clone()),
            expected_target: "fake.cpu0".to_string(),
            gdb_version_timeout_ms: 5_000,
            gdb_startup_timeout_ms: 5_000,
            gdb_command_timeout_ms: 5_000,
            gdb_shutdown_timeout_ms: 5_000,
            target_state_timeout_ms: 5_000,
        };

        let first_plan = plan_session(&options).unwrap();
        let target_config = first_plan.gdb.xtensa_config.as_ref().unwrap();
        assert_eq!(target_config.environment_variable, XTENSA_GNU_CONFIG_ENV);
        assert!(!first_plan.gdb.ambient_xtensa_config_inherited);
        assert!(first_plan.effects.gdb_xtensa_target_configuration_requested);
        let report = test_session(&options, &first_plan.confirm_digest).unwrap();
        assert!(report.complete);

        fs::write(&xtensa_config, b"target-profile-b").unwrap();
        let changed_plan = plan_session(&options).unwrap();
        assert_ne!(first_plan.confirm_digest, changed_plan.confirm_digest);
        assert_ne!(
            first_plan.gdb.xtensa_config.unwrap().sha256,
            changed_plan.gdb.xtensa_config.unwrap().sha256
        );
        let error = test_session(&options, &first_plan.confirm_digest).unwrap_err();
        assert_eq!(error.code, ErrorCode::ConfirmationMismatch);
    }

    #[test]
    fn remote_protocol_failure_still_restores_target_and_closes_openocd() {
        let directory = tempdir().unwrap();
        let openocd = write_fake_openocd(directory.path());
        let gdb = write_fake_remote_gdb_with_wrong_connect_token(directory.path());
        let config = directory.path().join("board.cfg");
        fs::write(&config, b"adapter speed 1000\n").unwrap();
        let options = OpenOcdGdbSessionOptions {
            openocd: OpenOcdServerOptions {
                executable: openocd,
                config_files: vec![config],
                search_dirs: vec![directory.path().to_path_buf()],
                version_timeout_ms: super::super::DEFAULT_OPENOCD_VERSION_TIMEOUT_MS,
                startup_timeout_ms: 5_000,
                shutdown_timeout_ms: 5_000,
            },
            gdb_executable: gdb,
            gdb_xtensa_config: None,
            expected_target: "fake.cpu0".to_string(),
            gdb_version_timeout_ms: 5_000,
            gdb_startup_timeout_ms: 5_000,
            gdb_command_timeout_ms: 5_000,
            gdb_shutdown_timeout_ms: 5_000,
            target_state_timeout_ms: 5_000,
        };

        let plan = plan_session(&options).unwrap();
        let error = test_session(&options, &plan.confirm_digest).unwrap_err();
        assert_eq!(error.code, ErrorCode::ProtocolError);
        assert_eq!(error.details["expected_token"], 2);
        assert_eq!(error.details["observed_token"], 9);
        assert_eq!(error.details["target_restoration"]["complete"], true);
        assert_eq!(
            error.details["target_restoration"]["fallback_resume_requested"],
            true
        );
        assert_eq!(
            error.details["target_restoration"]["final_observation"]["state"],
            "running"
        );
        assert_eq!(error.details["openocd_shutdown"]["graceful"], true);
    }

    #[test]
    fn confirmed_target_mismatch_stops_before_remote_gdb_start() {
        let directory = tempdir().unwrap();
        let openocd = write_fake_openocd(directory.path());
        let gdb = write_fake_remote_gdb(directory.path());
        let config = directory.path().join("board.cfg");
        fs::write(&config, b"adapter speed 1000\n").unwrap();
        let options = OpenOcdGdbSessionOptions {
            openocd: OpenOcdServerOptions {
                executable: openocd,
                config_files: vec![config],
                search_dirs: vec![directory.path().to_path_buf()],
                version_timeout_ms: super::super::DEFAULT_OPENOCD_VERSION_TIMEOUT_MS,
                startup_timeout_ms: 5_000,
                shutdown_timeout_ms: 5_000,
            },
            gdb_executable: gdb,
            gdb_xtensa_config: None,
            expected_target: "other.cpu0".to_string(),
            gdb_version_timeout_ms: 5_000,
            gdb_startup_timeout_ms: 5_000,
            gdb_command_timeout_ms: 5_000,
            gdb_shutdown_timeout_ms: 5_000,
            target_state_timeout_ms: 5_000,
        };

        let plan = plan_session(&options).unwrap();
        let error = test_session(&options, &plan.confirm_digest).unwrap_err();
        assert_eq!(error.code, ErrorCode::VerificationFailed);
        assert_eq!(error.details["expected_current_target"], "other.cpu0");
        assert_eq!(error.details["observed_current_target"], "fake.cpu0");
        assert_eq!(error.details["remote_gdb_started"], false);
        assert_eq!(error.details["openocd_shutdown"]["graceful"], true);
    }

    #[test]
    fn managed_session_openocd_helper() {
        if std::env::var_os(HELPER_ROLE).is_none() {
            return;
        }
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

        let mut state_queries = 0_u32;
        'connections: loop {
            let (mut stream, _) = tcl.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            loop {
                match stream.read(&mut byte) {
                    Ok(0) => continue 'connections,
                    Ok(_) if byte[0] == 0x1a => break,
                    Ok(_) => request.push(byte[0]),
                    Err(_) => continue 'connections,
                }
            }
            match request.as_slice() {
                b"version" => stream
                    .write_all(b"Open On-Chip Debugger 0.12.0-test\x1a")
                    .unwrap(),
                b"target current" => stream.write_all(b"fake.cpu0\x1a").unwrap(),
                b"fake.cpu0 curstate" => {
                    state_queries += 1;
                    let state = match state_queries {
                        1 => b"running\x1a".as_slice(),
                        2 => b"halted\x1a".as_slice(),
                        _ => b"running\x1a".as_slice(),
                    };
                    stream.write_all(state).unwrap();
                }
                b"targets fake.cpu0; resume" => stream.write_all(b"\x1a").unwrap(),
                b"shutdown" => break,
                _ => stream.write_all(b"unknown command\x1a").unwrap(),
            }
        }
        drop(gdb);
    }

    fn write_fake_openocd(directory: &Path) -> PathBuf {
        let current_exe = std::env::current_exe().unwrap();
        let helper = "backend::openocd::session::tests::managed_session_openocd_helper";
        #[cfg(windows)]
        {
            let executable = directory.join("fake-session-openocd.cmd");
            fs::write(
                &executable,
                format!(
                    "@echo off\r\nif \"%1\"==\"--version\" goto version\r\nset {HELPER_ROLE}=server\r\n\"{}\" --exact {helper} --nocapture\r\nexit /b %errorlevel%\r\n:version\r\necho Open On-Chip Debugger 0.12.0-test\r\nexit /b 0\r\n",
                    current_exe.display()
                ),
            )
            .unwrap();
            executable
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let executable = directory.join("fake-session-openocd");
            let escaped_exe = current_exe.to_string_lossy().replace('\'', "'\\''");
            fs::write(
                &executable,
                format!(
                    "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  printf '%s\\n' 'Open On-Chip Debugger 0.12.0-test'\n  exit 0\nfi\n{HELPER_ROLE}=server exec '{escaped_exe}' --exact {helper} --nocapture\n"
                ),
            )
            .unwrap();
            let mut permissions = fs::metadata(&executable).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&executable, permissions).unwrap();
            executable
        }
    }

    fn write_fake_remote_gdb(directory: &Path) -> PathBuf {
        #[cfg(windows)]
        {
            let executable = directory.join("fake-remote-gdb.cmd");
            fs::write(
                &executable,
                "@echo off\r\nif \"%1\"==\"--version\" goto version\r\nif defined XTENSA_GNU_CONFIG exit /b 8\r\necho ^(gdb^)\r\nset /p first=\r\nif not \"%first%\"==\"1-gdb-version\" exit /b 3\r\necho ~\"GNU gdb 17.1-test\\n\"\r\necho 1^^done\r\necho ^(gdb^)\r\nset /p second=\r\nif not \"%second:~0,23%\"==\"2-target-select remote \" exit /b 4\r\necho =thread-group-started,id=\"i1\",pid=\"42000\"\r\necho 2^^connected\r\necho ^(gdb^)\r\nset /p third=\r\nif not \"%third%\"==\"3-target-detach\" exit /b 5\r\necho 3^^done\r\necho ^(gdb^)\r\nset /p fourth=\r\nif not \"%fourth%\"==\"4-gdb-exit\" exit /b 6\r\necho 4^^exit\r\nexit /b 0\r\n:version\r\necho GNU gdb 17.1-test\r\nexit /b 0\r\n",
            )
            .unwrap();
            executable
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let executable = directory.join("fake-remote-gdb");
            fs::write(
                &executable,
                "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  printf '%s\\n' 'GNU gdb 17.1-test'\n  exit 0\nfi\n[ -z \"${XTENSA_GNU_CONFIG+x}\" ] || exit 8\nprintf '%s\\n' '(gdb)'\nIFS= read -r first\n[ \"$first\" = '1-gdb-version' ] || exit 3\nprintf '%s\\n' '~\"GNU gdb 17.1-test\\n\"' '1^done' '(gdb)'\nIFS= read -r second\ncase \"$second\" in '2-target-select remote 127.0.0.1:'*) ;; *) exit 4 ;; esac\nprintf '%s\\n' '=thread-group-started,id=\"i1\",pid=\"42000\"' '2^connected' '(gdb)'\nIFS= read -r third\n[ \"$third\" = '3-target-detach' ] || exit 5\nprintf '%s\\n' '3^done' '(gdb)'\nIFS= read -r fourth\n[ \"$fourth\" = '4-gdb-exit' ] || exit 6\nprintf '%s\\n' '4^exit'\n",
            )
            .unwrap();
            let mut permissions = fs::metadata(&executable).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&executable, permissions).unwrap();
            executable
        }
    }

    fn write_fake_remote_gdb_requiring_xtensa_config(directory: &Path) -> PathBuf {
        let executable = write_fake_remote_gdb(directory);
        let script = fs::read_to_string(&executable).unwrap();
        let script = if cfg!(windows) {
            script.replace(
                "if defined XTENSA_GNU_CONFIG exit /b 8",
                "if not defined XTENSA_GNU_CONFIG exit /b 8",
            )
        } else {
            script.replace(
                "[ -z \"${XTENSA_GNU_CONFIG+x}\" ] || exit 8",
                "[ -n \"${XTENSA_GNU_CONFIG:-}\" ] || exit 8",
            )
        };
        fs::write(
            &executable,
            script.replace("GNU gdb 17.1-test", "GNU gdb (esp-gdb) 17.1-test"),
        )
        .unwrap();
        executable
    }

    fn write_fake_remote_gdb_with_wrong_connect_token(directory: &Path) -> PathBuf {
        let executable = write_fake_remote_gdb(directory);
        let script = fs::read_to_string(&executable).unwrap();
        let script = if cfg!(windows) {
            script.replace("echo 2^^connected", "echo 9^^connected")
        } else {
            script.replace("'2^connected'", "'9^connected'")
        };
        fs::write(&executable, script).unwrap();
        executable
    }
}
