use std::time::Duration;

use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{
    GdbExecutableFileIdentity, GdbMiCommandResult, GdbMiHandshake, GdbMiOutput, GdbMiProtocol,
    GdbMiRegisterInventory, GdbMiRegisterValue, GdbMiShutdown, GdbXtensaConfigInspection,
    OpenOcdGdbSessionOptions, OpenOcdServerConfirmationBoundary, OpenOcdServerEffects,
    OpenOcdServerLogs, OpenOcdServerPlan, OpenOcdServerReadiness, OpenOcdServerShutdown,
    OpenOcdSessionGdbPlan, OpenOcdSessionServerPlan, OpenOcdTargetRestoration,
    OpenOcdTargetStatePolicy,
    gdb::{execute_remote_register_snapshot, register_protocol_contract},
    server::start_managed_server,
    session::{observe_initial_target, restore_running_target, with_server_context},
};
use crate::{
    SCHEMA_VERSION,
    error::{DebugError, ErrorCode, Result, SuggestedAction},
};

pub const MAX_OPENOCD_REGISTER_SNAPSHOT_REGISTERS: usize = 64;
const MAX_REGISTER_NAME_BYTES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenOcdRegisterSnapshotOptions {
    pub session: OpenOcdGdbSessionOptions,
    pub registers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdRegisterSnapshotPlan {
    pub backend: String,
    pub operation: String,
    pub risk: String,
    pub complete: bool,
    pub openocd: OpenOcdSessionServerPlan,
    pub gdb: OpenOcdSessionGdbPlan,
    pub protocol: GdbMiProtocol,
    pub register_policy: OpenOcdRegisterSnapshotPolicy,
    pub target_state_policy: OpenOcdTargetStatePolicy,
    pub effects: OpenOcdRegisterSnapshotEffects,
    pub confirmation_boundary: OpenOcdRegisterSnapshotConfirmationBoundary,
    pub confirm_digest: String,
    #[serde(skip)]
    openocd_execution_plan: OpenOcdServerPlan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdRegisterSnapshotPolicy {
    pub requested_names: Vec<String>,
    pub minimum_registers: u64,
    pub maximum_registers: u64,
    pub name_syntax: String,
    pub matching: String,
    pub duplicate_policy: String,
    pub inventory_command: String,
    pub values_command_template: String,
    pub value_format: String,
    pub unavailable_policy: String,
    pub result_order: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdRegisterSnapshotEffects {
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
    pub explicit_register_inventory_requested: bool,
    pub explicit_selected_register_read_requested: bool,
    pub memory_read_requested: bool,
    pub symbol_or_executable_loading_requested: bool,
    pub breakpoint_or_watchpoint_requested: bool,
    pub flash_command_requested: bool,
    pub arbitrary_gdb_or_monitor_command_requested: bool,
    pub detach_resume_requested: bool,
    pub fixed_resume_fallback_possible: bool,
    pub target_state_restoration_verification_required: bool,
    pub gdb_xtensa_target_configuration_requested: bool,
    pub gdb_xtensa_target_configuration_native_code_execution_possible: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdRegisterSnapshotConfirmationBoundary {
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
    pub requested_register_names_bound: bool,
    pub register_order_bound: bool,
    pub lifecycle_deadlines_bound: bool,
    pub loopback_dynamic_endpoint_policy_bound: bool,
    pub runtime_port_number_bound: bool,
    pub expected_target_name_bound: bool,
    pub runtime_adapter_identity_bound: bool,
    pub target_state_policy_bound: bool,
    pub symbol_or_firmware_identity_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdRegisterSnapshotTestReport {
    pub backend: String,
    pub scope: String,
    pub risk: String,
    pub complete: bool,
    pub confirm_digest: String,
    pub openocd: OpenOcdSessionServerPlan,
    pub gdb: OpenOcdSessionGdbPlan,
    pub protocol: GdbMiProtocol,
    pub register_policy: OpenOcdRegisterSnapshotPolicy,
    pub target_state_policy: OpenOcdTargetStatePolicy,
    pub readiness: OpenOcdServerReadiness,
    pub target_restoration: OpenOcdTargetRestoration,
    pub exchange: OpenOcdRegisterSnapshotExchange,
    pub openocd_shutdown: OpenOcdServerShutdown,
    pub openocd_logs: OpenOcdServerLogs,
    pub effects: OpenOcdRegisterSnapshotEffects,
    pub confirmation_boundary: OpenOcdRegisterSnapshotConfirmationBoundary,
    pub capabilities: OpenOcdRegisterSnapshotCapabilities,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdRegisterSnapshotExchange {
    pub endpoint: String,
    pub handshake: GdbMiHandshake,
    pub connection: GdbMiCommandResult,
    pub register_names: GdbMiCommandResult,
    pub register_values: GdbMiCommandResult,
    pub inventory: GdbMiRegisterInventory,
    pub values: Vec<GdbMiRegisterValue>,
    pub detach: GdbMiCommandResult,
    pub shutdown: GdbMiShutdown,
    pub output: GdbMiOutput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdRegisterSnapshotCapabilities {
    pub server_launch: bool,
    pub tcl_rpc: bool,
    pub gdb_mi: bool,
    pub remote_target_connection: bool,
    pub target_state_observation: bool,
    pub attach_detach: bool,
    pub restoration_resume: bool,
    pub register_inventory: bool,
    pub selected_register_read: bool,
    pub memory_read: bool,
    pub symbol_loading: bool,
    pub breakpoints: bool,
    pub watchpoints: bool,
    pub general_execution_control: bool,
    pub flash: bool,
    pub arbitrary_commands: bool,
}

#[derive(Debug, Serialize)]
struct RegisterConfirmationInput<'a> {
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
    register_policy: &'a OpenOcdRegisterSnapshotPolicy,
    target_state_policy: &'a OpenOcdTargetStatePolicy,
    effects: &'a OpenOcdRegisterSnapshotEffects,
    confirmation_boundary: &'a OpenOcdRegisterSnapshotConfirmationBoundary,
}

#[derive(Debug, Serialize)]
struct GdbLifecycleConfirmation {
    version_timeout_ms: u64,
    startup_timeout_ms: u64,
    command_timeout_ms: u64,
    shutdown_timeout_ms: u64,
}

pub fn plan_register_snapshot(
    options: &OpenOcdRegisterSnapshotOptions,
) -> Result<OpenOcdRegisterSnapshotPlan> {
    let requested_names = normalize_register_names(&options.registers)?;
    let session = super::plan_session(&options.session)?;
    let protocol = register_protocol_contract();
    let register_policy = register_policy(requested_names);
    let mut target_state_policy = session.target_state_policy.clone();
    target_state_policy.normal_restoration_command = "5-target-detach".to_string();
    let effects = register_effects(session.gdb.xtensa_config.is_some());
    let confirmation_boundary = register_confirmation_boundary();
    let confirmation = RegisterConfirmationInput {
        schema_version: SCHEMA_VERSION,
        operation: "openocd.registers.test",
        backend: "openocd",
        openocd_executable_path: &session.openocd.executable.resolved,
        openocd_executable_version: &session.openocd.executable.version_line,
        openocd_executable_file: &session.openocd.executable_file,
        openocd_configuration: &session.openocd.configuration,
        openocd_lifecycle: &session.openocd.lifecycle,
        openocd_effects: &session.openocd.configuration_effects,
        openocd_confirmation_boundary: &session.openocd.confirmation_boundary,
        gdb_executable_path: &session.gdb.executable.resolved,
        gdb_executable_version: &session.gdb.executable.version_line,
        gdb_executable_file: &session.gdb.executable_file,
        gdb_xtensa_config: session.gdb.xtensa_config.as_ref(),
        gdb_lifecycle: GdbLifecycleConfirmation {
            version_timeout_ms: session.gdb.version_timeout_ms,
            startup_timeout_ms: session.gdb.startup_timeout_ms,
            command_timeout_ms: session.gdb.command_timeout_ms,
            shutdown_timeout_ms: session.gdb.shutdown_timeout_ms,
        },
        protocol: &protocol,
        register_policy: &register_policy,
        target_state_policy: &target_state_policy,
        effects: &effects,
        confirmation_boundary: &confirmation_boundary,
    };
    let confirm_digest = hex::encode(Sha256::digest(
        serde_json::to_vec(&confirmation)
            .expect("register-snapshot confirmation input always serializes"),
    ));

    Ok(OpenOcdRegisterSnapshotPlan {
        backend: "openocd".to_string(),
        operation: "openocd.registers.test".to_string(),
        risk: "R2_DEVICE_WRITE".to_string(),
        complete: true,
        openocd: session.openocd,
        gdb: session.gdb,
        protocol,
        register_policy,
        target_state_policy,
        effects,
        confirmation_boundary,
        confirm_digest,
        openocd_execution_plan: session.openocd_execution_plan,
    })
}

pub fn test_register_snapshot(
    options: &OpenOcdRegisterSnapshotOptions,
    confirm_digest: &str,
) -> Result<OpenOcdRegisterSnapshotTestReport> {
    let plan = plan_register_snapshot(options)?;
    if plan.confirm_digest != confirm_digest {
        return Err(register_confirmation_error(
            &plan.confirm_digest,
            confirm_digest,
        ));
    }
    execute_register_plan(plan)
}

fn execute_register_plan(
    plan: OpenOcdRegisterSnapshotPlan,
) -> Result<OpenOcdRegisterSnapshotTestReport> {
    let server = start_managed_server(&plan.openocd_execution_plan)?;
    let initial = match observe_initial_target(&server, plan.target_state_policy.timeout_ms) {
        Ok(observation) => observation,
        Err(error) => return Err(with_server_context(error, server.finish(), None)),
    };
    if initial.target_name != plan.target_state_policy.expected_current_target {
        let error = DebugError::verification(
            "OpenOCD current target did not match the confirmed register-snapshot target",
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
        let error = DebugError::verification(
            "OpenOCD current target was not running before register-snapshot attachment",
            json!({
                "initial_observation": initial,
                "required_initial_state": plan.target_state_policy.initial_state_required,
                "remote_gdb_started": false,
            }),
        );
        return Err(with_server_context(error, server.finish(), None));
    }

    let gdb_result = execute_remote_register_snapshot(
        &plan.gdb.executable.resolved,
        plan.gdb
            .xtensa_config
            .as_ref()
            .map(|config| config.resolved.as_str()),
        server.readiness().gdb_port,
        &plan.register_policy.requested_names,
        plan.gdb.startup_timeout_ms,
        plan.gdb.command_timeout_ms,
        plan.gdb.shutdown_timeout_ms,
    );
    let restoration = restore_running_target(&server, initial, plan.target_state_policy.timeout_ms);
    let completion = server.finish();

    let exchange = match gdb_result {
        Ok(execution) => OpenOcdRegisterSnapshotExchange {
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
            register_names: GdbMiCommandResult {
                token: 3,
                command: "-data-list-register-names".to_string(),
                result_class: execution.names_result_class,
                elapsed_ms: duration_ms(execution.names_elapsed),
            },
            register_values: GdbMiCommandResult {
                token: 4,
                command: execution.values_command,
                result_class: execution.values_result_class,
                elapsed_ms: duration_ms(execution.values_elapsed),
            },
            inventory: execution.inventory,
            values: execution.values,
            detach: GdbMiCommandResult {
                token: 5,
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

    Ok(OpenOcdRegisterSnapshotTestReport {
        backend: plan.backend,
        scope: "confirmed_selected_register_snapshot".to_string(),
        risk: plan.risk,
        complete: true,
        confirm_digest: plan.confirm_digest,
        openocd: plan.openocd,
        gdb: plan.gdb,
        protocol: plan.protocol,
        register_policy: plan.register_policy,
        target_state_policy: plan.target_state_policy,
        readiness: completion.readiness,
        target_restoration: restoration,
        exchange,
        openocd_shutdown: completion.shutdown,
        openocd_logs: completion.logs,
        effects: plan.effects,
        confirmation_boundary: plan.confirmation_boundary,
        capabilities: register_capabilities(),
    })
}

fn normalize_register_names(registers: &[String]) -> Result<Vec<String>> {
    if registers.is_empty() || registers.len() > MAX_OPENOCD_REGISTER_SNAPSHOT_REGISTERS {
        return Err(DebugError::config(
            "OpenOCD register snapshot requires a bounded non-empty register selection",
            json!({
                "count": registers.len(),
                "minimum": 1,
                "maximum": MAX_OPENOCD_REGISTER_SNAPSHOT_REGISTERS,
            }),
        ));
    }
    let mut normalized = Vec::with_capacity(registers.len());
    for register in registers {
        if register != register.trim()
            || register.is_empty()
            || register.len() > MAX_REGISTER_NAME_BYTES
            || !register.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':')
            })
        {
            return Err(DebugError::config(
                "requested GDB register name is outside the supported safe syntax",
                json!({
                    "register": register.chars().take(128).collect::<String>(),
                    "maximum_bytes": MAX_REGISTER_NAME_BYTES,
                }),
            ));
        }
        let register = register.to_ascii_lowercase();
        if normalized.contains(&register) {
            return Err(DebugError::config(
                "duplicate requested GDB register name",
                json!({
                    "register": register,
                    "matching": "ascii_case_insensitive",
                }),
            ));
        }
        normalized.push(register);
    }
    Ok(normalized)
}

fn register_policy(requested_names: Vec<String>) -> OpenOcdRegisterSnapshotPolicy {
    OpenOcdRegisterSnapshotPolicy {
        requested_names,
        minimum_registers: 1,
        maximum_registers: MAX_OPENOCD_REGISTER_SNAPSHOT_REGISTERS as u64,
        name_syntax: "ASCII alphanumeric plus '_', '-', '.', or ':'; maximum 64 bytes".to_string(),
        matching: "ASCII case-insensitive against the complete GDB register-name inventory"
            .to_string(),
        duplicate_policy: "reject requested duplicates and ambiguous inventory names".to_string(),
        inventory_command: "3-data-list-register-names".to_string(),
        values_command_template:
            "4-data-list-register-values --skip-unavailable x <resolved_register_numbers>"
                .to_string(),
        value_format: "normalized lowercase hexadecimal with 0x prefix".to_string(),
        unavailable_policy: "fail unless every selected register number is returned".to_string(),
        result_order: "requested_names order".to_string(),
    }
}

fn register_effects(xtensa_config_selected: bool) -> OpenOcdRegisterSnapshotEffects {
    OpenOcdRegisterSnapshotEffects {
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
        explicit_register_inventory_requested: true,
        explicit_selected_register_read_requested: true,
        memory_read_requested: false,
        symbol_or_executable_loading_requested: false,
        breakpoint_or_watchpoint_requested: false,
        flash_command_requested: false,
        arbitrary_gdb_or_monitor_command_requested: false,
        detach_resume_requested: true,
        fixed_resume_fallback_possible: true,
        target_state_restoration_verification_required: true,
        gdb_xtensa_target_configuration_requested: xtensa_config_selected,
        gdb_xtensa_target_configuration_native_code_execution_possible: xtensa_config_selected,
        notes: vec![
            "OpenOCD configuration remains executable Tcl; only top-level files are hashed."
                .to_string(),
            "The fixed GDB/MI exchange enumerates register names and reads only the confirmed selected register numbers."
                .to_string(),
            "Normal remote negotiation may exchange target descriptions, memory-map metadata, stop state, or register state before the explicit selected-register command."
                .to_string(),
            "Confirmed OpenOCD attach handlers may probe flash or reset/halt a protected target."
                .to_string(),
            "No executable, symbols, memory command, breakpoint, monitor command, or flash command is accepted."
                .to_string(),
            "The command refuses attachment unless the selected target is running and fails unless running is proven again before OpenOCD shutdown."
                .to_string(),
        ],
    }
}

fn register_confirmation_boundary() -> OpenOcdRegisterSnapshotConfirmationBoundary {
    OpenOcdRegisterSnapshotConfirmationBoundary {
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
        requested_register_names_bound: true,
        register_order_bound: true,
        lifecycle_deadlines_bound: true,
        loopback_dynamic_endpoint_policy_bound: true,
        runtime_port_number_bound: false,
        expected_target_name_bound: true,
        runtime_adapter_identity_bound: false,
        target_state_policy_bound: true,
        symbol_or_firmware_identity_required: false,
    }
}

fn register_capabilities() -> OpenOcdRegisterSnapshotCapabilities {
    OpenOcdRegisterSnapshotCapabilities {
        server_launch: true,
        tcl_rpc: true,
        gdb_mi: true,
        remote_target_connection: true,
        target_state_observation: true,
        attach_detach: true,
        restoration_resume: true,
        register_inventory: true,
        selected_register_read: true,
        memory_read: false,
        symbol_loading: false,
        breakpoints: false,
        watchpoints: false,
        general_execution_control: false,
        flash: false,
        arbitrary_commands: false,
    }
}

fn restoration_error(
    restoration: &OpenOcdTargetRestoration,
    gdb_error: Option<&DebugError>,
) -> DebugError {
    DebugError::verification(
        "register snapshot did not prove restoration of the initial running target state",
        json!({
            "target_restoration": restoration,
            "gdb_error": gdb_error.map(error_value),
        }),
    )
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

fn register_confirmation_error(expected: &str, received: &str) -> DebugError {
    let mut error = DebugError::new(
        ErrorCode::ConfirmationMismatch,
        "OpenOCD register-snapshot confirmation digest does not match the current plan",
        2,
        json!({
            "expected_confirm_digest": expected,
            "received_confirm_digest": received,
        }),
    );
    error.suggested_actions.push(SuggestedAction::new(
        "review_openocd_register_snapshot_plan",
        json!({"command": "openocd registers plan"}),
    ));
    error
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
        path::{Path, PathBuf},
    };

    use tempfile::tempdir;

    use super::*;

    const HELPER_ROLE: &str = "EMBEDDED_DEBUGGER_OPENOCD_REGISTERS_HELPER_ROLE";

    #[test]
    fn register_names_are_normalized_and_duplicates_are_rejected() {
        assert_eq!(
            normalize_register_names(&["PC".to_string(), "a0".to_string()]).unwrap(),
            ["pc", "a0"]
        );
        let error = normalize_register_names(&["pc".to_string(), "PC".to_string()]).unwrap_err();
        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert_eq!(error.details["matching"], "ascii_case_insensitive");
        assert!(normalize_register_names(&["pc; reset".to_string()]).is_err());
    }

    #[test]
    fn register_selection_bounds_fail_before_session_inputs_are_inspected() {
        let options = OpenOcdRegisterSnapshotOptions {
            session: OpenOcdGdbSessionOptions {
                openocd: super::super::OpenOcdServerOptions {
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
                gdb_command_timeout_ms: super::super::DEFAULT_GDB_MI_COMMAND_TIMEOUT_MS,
                gdb_shutdown_timeout_ms: super::super::DEFAULT_GDB_MI_SHUTDOWN_TIMEOUT_MS,
                target_state_timeout_ms: super::super::DEFAULT_OPENOCD_TARGET_STATE_TIMEOUT_MS,
            },
            registers: Vec::new(),
        };
        let error = plan_register_snapshot(&options).unwrap_err();
        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert_eq!(error.details["count"], 0);
    }

    #[test]
    fn register_plan_is_deterministic_and_binds_requested_order() {
        let directory = tempdir().unwrap();
        let options = test_options(directory.path(), vec!["pc", "ps"]);
        let first = plan_register_snapshot(&options).unwrap();
        let second = plan_register_snapshot(&options).unwrap();
        assert_eq!(first.confirm_digest, second.confirm_digest);
        assert_eq!(first.protocol.commands.len(), 6);
        assert_eq!(first.protocol.commands[4].token, 5);
        assert_eq!(
            first.target_state_policy.normal_restoration_command,
            "5-target-detach"
        );
        assert!(first.effects.explicit_selected_register_read_requested);
        assert!(first.confirmation_boundary.requested_register_names_bound);

        let reversed = test_options(directory.path(), vec!["ps", "pc"]);
        let reversed = plan_register_snapshot(&reversed).unwrap();
        assert_ne!(first.confirm_digest, reversed.confirm_digest);
    }

    #[test]
    fn controlled_register_snapshot_restores_running_and_preserves_requested_order() {
        let directory = tempdir().unwrap();
        let options = test_options(directory.path(), vec!["ps", "pc"]);
        let plan = plan_register_snapshot(&options).unwrap();
        let report = test_register_snapshot(&options, &plan.confirm_digest).unwrap();

        assert!(report.complete);
        assert_eq!(report.exchange.inventory.total_entries, 4);
        assert_eq!(report.exchange.inventory.named_entries, 3);
        assert_eq!(report.exchange.values[0].requested_name, "ps");
        assert_eq!(report.exchange.values[0].number, 3);
        assert_eq!(report.exchange.values[0].value, "0x20");
        assert_eq!(report.exchange.values[1].requested_name, "pc");
        assert_eq!(report.exchange.values[1].value, "0x4200abcd");
        assert_eq!(
            report.exchange.register_values.command,
            "-data-list-register-values --skip-unavailable x 3 0"
        );
        assert_eq!(report.target_restoration.initial.state, "running");
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
    fn unknown_register_still_detaches_exits_restores_and_closes_openocd() {
        let directory = tempdir().unwrap();
        let options = test_options(directory.path(), vec!["missing"]);
        let plan = plan_register_snapshot(&options).unwrap();
        let error = test_register_snapshot(&options, &plan.confirm_digest).unwrap_err();

        assert_eq!(error.code, ErrorCode::ProtocolError);
        assert_eq!(error.details["requested_register"], "missing");
        assert_eq!(error.details["cleanup_detach"]["complete"], true);
        assert_eq!(error.details["shutdown"]["graceful"], true);
        assert_eq!(error.details["target_restoration"]["complete"], true);
        assert_eq!(
            error.details["target_restoration"]["final_observation"]["state"],
            "running"
        );
        assert_eq!(error.details["openocd_shutdown"]["graceful"], true);
    }

    #[test]
    fn invalid_value_payload_still_detaches_exits_restores_and_closes_openocd() {
        let directory = tempdir().unwrap();
        let options = test_options(directory.path(), vec!["ps", "pc"]);
        let gdb = &options.session.gdb_executable;
        let script = fs::read_to_string(gdb).unwrap();
        fs::write(
            gdb,
            script.replace("value=\"0x20\"", "value=\"unavailable\""),
        )
        .unwrap();
        let plan = plan_register_snapshot(&options).unwrap();
        let error = test_register_snapshot(&options, &plan.confirm_digest).unwrap_err();

        assert_eq!(error.code, ErrorCode::ProtocolError);
        assert_eq!(error.details["cleanup_detach"]["complete"], true);
        assert_eq!(error.details["shutdown"]["graceful"], true);
        assert_eq!(error.details["target_restoration"]["complete"], true);
        assert_eq!(error.details["openocd_shutdown"]["graceful"], true);
    }

    #[test]
    fn managed_register_openocd_helper() {
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

    fn test_options(directory: &Path, registers: Vec<&str>) -> OpenOcdRegisterSnapshotOptions {
        let openocd = write_fake_openocd(directory);
        let gdb = write_fake_register_gdb(directory);
        let config = directory.join("board.cfg");
        fs::write(&config, b"adapter speed 1000\n").unwrap();
        OpenOcdRegisterSnapshotOptions {
            session: OpenOcdGdbSessionOptions {
                openocd: super::super::OpenOcdServerOptions {
                    executable: openocd,
                    config_files: vec![config],
                    search_dirs: vec![directory.to_path_buf()],
                    version_timeout_ms: 5_000,
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
            },
            registers: registers.into_iter().map(str::to_string).collect(),
        }
    }

    fn write_fake_openocd(directory: &Path) -> PathBuf {
        let current_exe = std::env::current_exe().unwrap();
        let helper = "backend::openocd::registers::tests::managed_register_openocd_helper";
        #[cfg(windows)]
        {
            let executable = directory.join("fake-register-openocd.cmd");
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

            let executable = directory.join("fake-register-openocd");
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

    fn write_fake_register_gdb(directory: &Path) -> PathBuf {
        #[cfg(windows)]
        {
            let executable = directory.join("fake-register-gdb.cmd");
            fs::write(
                &executable,
                "@echo off\r\nif \"%1\"==\"--version\" goto version\r\nif defined XTENSA_GNU_CONFIG exit /b 8\r\necho ^(gdb^)\r\nset /p first=\r\nif not \"%first%\"==\"1-gdb-version\" exit /b 3\r\necho ~\"GNU gdb 17.1-test\\n\"\r\necho 1^^done\r\necho ^(gdb^)\r\nset /p second=\r\nif not \"%second:~0,23%\"==\"2-target-select remote \" exit /b 4\r\necho *stopped,reason=\"signal-received\"\r\necho 2^^connected\r\necho ^(gdb^)\r\nset /p third=\r\nif not \"%third%\"==\"3-data-list-register-names\" exit /b 5\r\necho 3^^done,register-names=[\"pc\",\"a0\",\"\",\"ps\"]\r\necho ^(gdb^)\r\nset /p fourth=\r\nif \"%fourth%\"==\"5-target-detach\" goto detach\r\nif not \"%fourth%\"==\"4-data-list-register-values --skip-unavailable x 3 0\" exit /b 6\r\necho 4^^done,register-values=[{number=\"0\",value=\"0X4200ABCD\"},{number=\"3\",value=\"0x20\"}]\r\necho ^(gdb^)\r\nset /p fifth=\r\nif not \"%fifth%\"==\"5-target-detach\" exit /b 7\r\n:detach\r\necho 5^^done\r\necho ^(gdb^)\r\nset /p sixth=\r\nif not \"%sixth%\"==\"6-gdb-exit\" exit /b 9\r\necho 6^^exit\r\nexit /b 0\r\n:version\r\necho GNU gdb 17.1-test\r\nexit /b 0\r\n",
            )
            .unwrap();
            executable
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let executable = directory.join("fake-register-gdb");
            fs::write(
                &executable,
                "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  printf '%s\\n' 'GNU gdb 17.1-test'\n  exit 0\nfi\n[ -z \"${XTENSA_GNU_CONFIG+x}\" ] || exit 8\nprintf '%s\\n' '(gdb)'\nIFS= read -r first\n[ \"$first\" = '1-gdb-version' ] || exit 3\nprintf '%s\\n' '~\"GNU gdb 17.1-test\\n\"' '1^done' '(gdb)'\nIFS= read -r second\ncase \"$second\" in '2-target-select remote 127.0.0.1:'*) ;; *) exit 4 ;; esac\nprintf '%s\\n' '*stopped,reason=\"signal-received\"' '2^connected' '(gdb)'\nIFS= read -r third\n[ \"$third\" = '3-data-list-register-names' ] || exit 5\nprintf '%s\\n' '3^done,register-names=[\"pc\",\"a0\",\"\",\"ps\"]' '(gdb)'\nIFS= read -r fourth\nif [ \"$fourth\" = '4-data-list-register-values --skip-unavailable x 3 0' ]; then\n  printf '%s\\n' '4^done,register-values=[{number=\"0\",value=\"0X4200ABCD\"},{number=\"3\",value=\"0x20\"}]' '(gdb)'\n  IFS= read -r fifth\n  [ \"$fifth\" = '5-target-detach' ] || exit 7\nelif [ \"$fourth\" != '5-target-detach' ]; then\n  exit 6\nfi\nprintf '%s\\n' '5^done' '(gdb)'\nIFS= read -r sixth\n[ \"$sixth\" = '6-gdb-exit' ] || exit 9\nprintf '%s\\n' '6^exit'\n",
            )
            .unwrap();
            let mut permissions = fs::metadata(&executable).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&executable, permissions).unwrap();
            executable
        }
    }
}
