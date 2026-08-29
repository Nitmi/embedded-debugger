use std::time::Duration;

use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{
    GdbExecutableFileIdentity, GdbMiCommandResult, GdbMiHandshake,
    GdbMiHardwareBreakpointRoundtrip, GdbMiOutput, GdbMiPlannedCommand, GdbMiProtocol,
    GdbMiShutdown, GdbXtensaConfigInspection, OpenOcdGdbSessionOptions,
    OpenOcdServerConfirmationBoundary, OpenOcdServerEffects, OpenOcdServerLogs, OpenOcdServerPlan,
    OpenOcdServerReadiness, OpenOcdServerShutdown, OpenOcdSessionGdbPlan, OpenOcdSessionServerPlan,
    OpenOcdTargetRestoration, OpenOcdTargetStatePolicy,
    gdb::{
        breakpoint_failure_cleanup_contract, breakpoint_protocol_contract,
        execute_remote_breakpoint_roundtrip,
    },
    server::start_managed_server,
    session::{observe_initial_target, restore_running_target, with_server_context},
};
use crate::{
    SCHEMA_VERSION,
    error::{DebugError, ErrorCode, Result, SuggestedAction},
    model::Address,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenOcdHardwareBreakpointOptions {
    pub session: OpenOcdGdbSessionOptions,
    pub address: Address,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdHardwareBreakpointPlan {
    pub backend: String,
    pub operation: String,
    pub risk: String,
    pub complete: bool,
    pub openocd: OpenOcdSessionServerPlan,
    pub gdb: OpenOcdSessionGdbPlan,
    pub protocol: GdbMiProtocol,
    pub breakpoint_policy: OpenOcdHardwareBreakpointPolicy,
    pub target_state_policy: OpenOcdTargetStatePolicy,
    pub effects: OpenOcdHardwareBreakpointEffects,
    pub confirmation_boundary: OpenOcdHardwareBreakpointConfirmationBoundary,
    pub confirm_digest: String,
    #[serde(skip)]
    openocd_execution_plan: OpenOcdServerPlan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdHardwareBreakpointPolicy {
    pub requested_address: Address,
    pub address_input: String,
    pub address_zero_allowed: bool,
    pub symbols_or_expressions_allowed: bool,
    pub breakpoint_kind: String,
    pub expected_gdb_breakpoint_number: u64,
    pub insert_command: String,
    pub delete_command: String,
    pub list_command: String,
    pub insertion_requirements: Vec<String>,
    pub deletion_verification: String,
    pub failure_cleanup_commands: Vec<GdbMiPlannedCommand>,
    pub breakpoint_hit_requested: bool,
    pub target_execution_while_installed_requested: bool,
    pub success_resume_requires_empty_gdb_table: bool,
    pub failure_cleanup_scope: String,
    pub failure_cleanup_gdb_detach_requested: bool,
    pub target_resume_possible_during_failure_cleanup: bool,
    pub explicit_openocd_resume_after_gdb_failure: bool,
    pub physical_comparator_state_independently_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdHardwareBreakpointEffects {
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
    pub hardware_breakpoint_insert_requested: bool,
    pub hardware_breakpoint_delete_requested: bool,
    pub breakpoint_table_read_requested: bool,
    pub breakpoint_hit_or_continue_requested: bool,
    pub software_breakpoint_requested: bool,
    pub symbolic_or_conditional_breakpoint_requested: bool,
    pub watchpoint_requested: bool,
    pub symbol_or_executable_loading_requested: bool,
    pub explicit_register_or_memory_command_requested: bool,
    pub flash_command_requested: bool,
    pub arbitrary_gdb_or_monitor_command_requested: bool,
    pub detach_resume_requested_on_verified_success: bool,
    pub fixed_resume_fallback_possible_on_verified_success: bool,
    pub failure_cleanup_gdb_detach_requested: bool,
    pub target_resume_possible_during_failure_cleanup: bool,
    pub explicit_openocd_resume_after_gdb_failure: bool,
    pub target_state_restoration_verification_required_on_success: bool,
    pub gdb_xtensa_target_configuration_requested: bool,
    pub gdb_xtensa_target_configuration_native_code_execution_possible: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdHardwareBreakpointConfirmationBoundary {
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
    pub exact_numeric_address_bound: bool,
    pub hardware_only_policy_bound: bool,
    pub insert_response_policy_bound: bool,
    pub empty_table_cleanup_policy_bound: bool,
    pub failure_detach_resume_effect_bound: bool,
    pub failure_no_additional_tcl_resume_policy_bound: bool,
    pub lifecycle_deadlines_bound: bool,
    pub loopback_dynamic_endpoint_policy_bound: bool,
    pub runtime_port_number_bound: bool,
    pub expected_target_name_bound: bool,
    pub runtime_adapter_identity_bound: bool,
    pub hardware_breakpoint_capacity_bound: bool,
    pub physical_comparator_cleanup_bound: bool,
    pub target_state_policy_bound: bool,
    pub symbol_or_firmware_identity_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdHardwareBreakpointTestReport {
    pub backend: String,
    pub scope: String,
    pub risk: String,
    pub complete: bool,
    pub confirm_digest: String,
    pub openocd: OpenOcdSessionServerPlan,
    pub gdb: OpenOcdSessionGdbPlan,
    pub protocol: GdbMiProtocol,
    pub breakpoint_policy: OpenOcdHardwareBreakpointPolicy,
    pub target_state_policy: OpenOcdTargetStatePolicy,
    pub readiness: OpenOcdServerReadiness,
    pub target_restoration: OpenOcdTargetRestoration,
    pub exchange: OpenOcdHardwareBreakpointExchange,
    pub openocd_shutdown: OpenOcdServerShutdown,
    pub openocd_logs: OpenOcdServerLogs,
    pub effects: OpenOcdHardwareBreakpointEffects,
    pub confirmation_boundary: OpenOcdHardwareBreakpointConfirmationBoundary,
    pub capabilities: OpenOcdHardwareBreakpointCapabilities,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdHardwareBreakpointExchange {
    pub endpoint: String,
    pub handshake: GdbMiHandshake,
    pub connection: GdbMiCommandResult,
    pub insert: GdbMiCommandResult,
    pub delete: GdbMiCommandResult,
    pub list_after_delete: GdbMiCommandResult,
    pub roundtrip: GdbMiHardwareBreakpointRoundtrip,
    pub detach: GdbMiCommandResult,
    pub shutdown: GdbMiShutdown,
    pub output: GdbMiOutput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdHardwareBreakpointCapabilities {
    pub server_launch: bool,
    pub tcl_rpc: bool,
    pub gdb_mi: bool,
    pub remote_target_connection: bool,
    pub target_state_observation: bool,
    pub attach_detach: bool,
    pub restoration_resume: bool,
    pub temporary_hardware_breakpoint_roundtrip: bool,
    pub persistent_breakpoints: bool,
    pub software_breakpoints: bool,
    pub symbolic_breakpoints: bool,
    pub conditional_breakpoints: bool,
    pub watchpoints: bool,
    pub breakpoint_hit_execution: bool,
    pub register_read: bool,
    pub memory_read: bool,
    pub stack_read: bool,
    pub symbol_loading: bool,
    pub general_execution_control: bool,
    pub flash: bool,
    pub arbitrary_commands: bool,
}

#[derive(Debug, Serialize)]
struct BreakpointConfirmationInput<'a> {
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
    breakpoint_policy: &'a OpenOcdHardwareBreakpointPolicy,
    target_state_policy: &'a OpenOcdTargetStatePolicy,
    effects: &'a OpenOcdHardwareBreakpointEffects,
    confirmation_boundary: &'a OpenOcdHardwareBreakpointConfirmationBoundary,
}

#[derive(Debug, Serialize)]
struct GdbLifecycleConfirmation {
    version_timeout_ms: u64,
    startup_timeout_ms: u64,
    command_timeout_ms: u64,
    shutdown_timeout_ms: u64,
}

pub fn plan_hardware_breakpoint(
    options: &OpenOcdHardwareBreakpointOptions,
) -> Result<OpenOcdHardwareBreakpointPlan> {
    let breakpoint_policy = validate_breakpoint_policy(options.address)?;
    let session = super::plan_session(&options.session)?;
    let protocol = breakpoint_protocol_contract(options.address);
    let mut target_state_policy = session.target_state_policy.clone();
    target_state_policy.normal_restoration_command = "6-target-detach".to_string();
    target_state_policy.normal_restoration_expected_effect =
        "resume only after GDB reports the fixed breakpoint deleted and its table empty"
            .to_string();
    target_state_policy.fallback_condition =
        "only on an otherwise successful, cleanup-verified roundtrip when running is not proven after GDB cleanup"
            .to_string();
    let effects = breakpoint_effects(session.gdb.xtensa_config.is_some());
    let confirmation_boundary = breakpoint_confirmation_boundary();
    let confirmation = BreakpointConfirmationInput {
        schema_version: SCHEMA_VERSION,
        operation: "openocd.breakpoint.test",
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
        breakpoint_policy: &breakpoint_policy,
        target_state_policy: &target_state_policy,
        effects: &effects,
        confirmation_boundary: &confirmation_boundary,
    };
    let confirm_digest = hex::encode(Sha256::digest(
        serde_json::to_vec(&confirmation)
            .expect("hardware-breakpoint confirmation input always serializes"),
    ));

    Ok(OpenOcdHardwareBreakpointPlan {
        backend: "openocd".to_string(),
        operation: "openocd.breakpoint.test".to_string(),
        risk: "R2_DEVICE_WRITE".to_string(),
        complete: true,
        openocd: session.openocd,
        gdb: session.gdb,
        protocol,
        breakpoint_policy,
        target_state_policy,
        effects,
        confirmation_boundary,
        confirm_digest,
        openocd_execution_plan: session.openocd_execution_plan,
    })
}

pub fn test_hardware_breakpoint(
    options: &OpenOcdHardwareBreakpointOptions,
    confirm_digest: &str,
) -> Result<OpenOcdHardwareBreakpointTestReport> {
    let plan = plan_hardware_breakpoint(options)?;
    if plan.confirm_digest != confirm_digest {
        return Err(breakpoint_confirmation_error(
            &plan.confirm_digest,
            confirm_digest,
        ));
    }
    execute_breakpoint_plan(plan)
}

fn execute_breakpoint_plan(
    plan: OpenOcdHardwareBreakpointPlan,
) -> Result<OpenOcdHardwareBreakpointTestReport> {
    let server = start_managed_server(&plan.openocd_execution_plan)?;
    let initial = match observe_initial_target(&server, plan.target_state_policy.timeout_ms) {
        Ok(observation) => observation,
        Err(error) => return Err(with_server_context(error, server.finish(), None)),
    };
    if initial.target_name != plan.target_state_policy.expected_current_target {
        let error = DebugError::verification(
            "OpenOCD current target did not match the confirmed hardware-breakpoint target",
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
            "OpenOCD current target was not running before hardware-breakpoint attachment",
            json!({
                "initial_observation": initial,
                "required_initial_state": plan.target_state_policy.initial_state_required,
                "remote_gdb_started": false,
            }),
        );
        return Err(with_server_context(error, server.finish(), None));
    }

    let gdb_result = execute_remote_breakpoint_roundtrip(
        &plan.gdb.executable.resolved,
        plan.gdb
            .xtensa_config
            .as_ref()
            .map(|config| config.resolved.as_str()),
        server.readiness().gdb_port,
        plan.breakpoint_policy.requested_address,
        plan.gdb.startup_timeout_ms,
        plan.gdb.command_timeout_ms,
        plan.gdb.shutdown_timeout_ms,
    );
    let execution = match gdb_result {
        Ok(execution) => execution,
        Err(mut gdb_error) => {
            let observation = observe_initial_target(&server, plan.target_state_policy.timeout_ms);
            let mut details = gdb_error.details.as_object().cloned().unwrap_or_default();
            details.insert(
                "initial_target_observation".to_string(),
                serde_json::to_value(&initial).expect("target observation always serializes"),
            );
            match observation {
                Ok(observation) => {
                    details.insert(
                        "target_observation_after_gdb_failure".to_string(),
                        serde_json::to_value(observation)
                            .expect("target observation always serializes"),
                    );
                }
                Err(observation_error) => {
                    details.insert(
                        "target_observation_after_gdb_failure_error".to_string(),
                        error_value(&observation_error),
                    );
                }
            }
            details.insert(
                "target_restoration".to_string(),
                json!({
                    "attempted": false,
                    "explicit_openocd_resume_attempted": false,
                    "gdb_cleanup_detach_or_exit_may_resume_target": true,
                    "observed_state_is_point_in_time_only": true,
                    "reason": "hardware-breakpoint cleanup or protocol success was not fully proven",
                    "manual_recovery_may_be_required": true,
                }),
            );
            gdb_error.details = Value::Object(details);
            return Err(with_server_context(gdb_error, server.finish(), None));
        }
    };

    let restoration = restore_running_target(&server, initial, plan.target_state_policy.timeout_ms);
    let completion = server.finish();
    let exchange = OpenOcdHardwareBreakpointExchange {
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
        insert: GdbMiCommandResult {
            token: 3,
            command: execution.insert_command,
            result_class: execution.insert_result_class,
            elapsed_ms: duration_ms(execution.insert_elapsed),
        },
        delete: GdbMiCommandResult {
            token: 4,
            command: "-break-delete 1".to_string(),
            result_class: execution.delete_result_class,
            elapsed_ms: duration_ms(execution.delete_elapsed),
        },
        list_after_delete: GdbMiCommandResult {
            token: 5,
            command: "-break-list".to_string(),
            result_class: execution.list_result_class,
            elapsed_ms: duration_ms(execution.list_elapsed),
        },
        roundtrip: execution.roundtrip,
        detach: GdbMiCommandResult {
            token: 6,
            command: "-target-detach".to_string(),
            result_class: execution.detach_result_class,
            elapsed_ms: duration_ms(execution.detach_elapsed),
        },
        shutdown: execution.shutdown,
        output: execution.output,
    };

    if !restoration.complete {
        let error = restoration_error(&restoration);
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

    Ok(OpenOcdHardwareBreakpointTestReport {
        backend: plan.backend,
        scope: "confirmed_temporary_hardware_breakpoint_roundtrip".to_string(),
        risk: plan.risk,
        complete: true,
        confirm_digest: plan.confirm_digest,
        openocd: plan.openocd,
        gdb: plan.gdb,
        protocol: plan.protocol,
        breakpoint_policy: plan.breakpoint_policy,
        target_state_policy: plan.target_state_policy,
        readiness: completion.readiness,
        target_restoration: restoration,
        exchange,
        openocd_shutdown: completion.shutdown,
        openocd_logs: completion.logs,
        effects: plan.effects,
        confirmation_boundary: plan.confirmation_boundary,
        capabilities: breakpoint_capabilities(),
    })
}

fn validate_breakpoint_policy(address: Address) -> Result<OpenOcdHardwareBreakpointPolicy> {
    if address.0 == 0 {
        return Err(DebugError::config(
            "OpenOCD hardware-breakpoint address must be non-zero",
            json!({"address": address, "minimum": "0x1"}),
        ));
    }
    Ok(OpenOcdHardwareBreakpointPolicy {
        requested_address: address,
        address_input: "exact non-zero numeric address".to_string(),
        address_zero_allowed: false,
        symbols_or_expressions_allowed: false,
        breakpoint_kind: "hardware".to_string(),
        expected_gdb_breakpoint_number: 1,
        insert_command: format!("3-break-insert -h *0x{:x}", address.0),
        delete_command: "4-break-delete 1".to_string(),
        list_command: "5-break-list".to_string(),
        insertion_requirements: vec![
            "exactly one bkpt tuple".to_string(),
            "number=1".to_string(),
            "type=hw breakpoint".to_string(),
            "disp=keep".to_string(),
            "enabled=y".to_string(),
            "addr equals the requested numeric address".to_string(),
            "times=0".to_string(),
            "no pending, multiple-location, condition, command, or script fields".to_string(),
        ],
        deletion_verification:
            "require an exact zero-row six-column BreakpointTable with an empty body".to_string(),
        failure_cleanup_commands: breakpoint_failure_cleanup_contract(),
        breakpoint_hit_requested: false,
        target_execution_while_installed_requested: false,
        success_resume_requires_empty_gdb_table: true,
        failure_cleanup_scope:
            "after remote connection when the breakpoint exchange fails before normal detach"
                .to_string(),
        failure_cleanup_gdb_detach_requested: true,
        target_resume_possible_during_failure_cleanup: true,
        explicit_openocd_resume_after_gdb_failure: false,
        physical_comparator_state_independently_verified: false,
    })
}

fn breakpoint_effects(xtensa_config_selected: bool) -> OpenOcdHardwareBreakpointEffects {
    OpenOcdHardwareBreakpointEffects {
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
        hardware_breakpoint_insert_requested: true,
        hardware_breakpoint_delete_requested: true,
        breakpoint_table_read_requested: true,
        breakpoint_hit_or_continue_requested: false,
        software_breakpoint_requested: false,
        symbolic_or_conditional_breakpoint_requested: false,
        watchpoint_requested: false,
        symbol_or_executable_loading_requested: false,
        explicit_register_or_memory_command_requested: false,
        flash_command_requested: false,
        arbitrary_gdb_or_monitor_command_requested: false,
        detach_resume_requested_on_verified_success: true,
        fixed_resume_fallback_possible_on_verified_success: true,
        failure_cleanup_gdb_detach_requested: true,
        target_resume_possible_during_failure_cleanup: true,
        explicit_openocd_resume_after_gdb_failure: false,
        target_state_restoration_verification_required_on_success: true,
        gdb_xtensa_target_configuration_requested: xtensa_config_selected,
        gdb_xtensa_target_configuration_native_code_execution_possible: xtensa_config_selected,
        notes: vec![
            "OpenOCD configuration remains executable Tcl; only top-level files are hashed."
                .to_string(),
            "The exact numeric address is user-confirmed; no ELF, symbol, executable, expression, or source location is loaded or evaluated."
                .to_string(),
            "The target is never intentionally continued while the hardware breakpoint is installed, so this workflow does not request or verify a breakpoint hit."
                .to_string(),
            "A successful delete plus empty GDB breakpoint table proves GDB bookkeeping cleanup, not an independent read of the physical comparator."
                .to_string(),
            "After a breakpoint-exchange failure following remote connection and before normal detach, the tool attempts fixed delete/list/detach cleanup. No GDB failure path sends an additional OpenOCD Tcl resume; GDB detach, GDB exit, or configuration-defined detach handlers may still resume the target."
                .to_string(),
            "Normal remote negotiation may exchange target descriptions, memory-map metadata, stop state, or register state."
                .to_string(),
            "Confirmed OpenOCD attach handlers may probe flash or reset/halt a protected target."
                .to_string(),
        ],
    }
}

fn breakpoint_confirmation_boundary() -> OpenOcdHardwareBreakpointConfirmationBoundary {
    OpenOcdHardwareBreakpointConfirmationBoundary {
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
        exact_numeric_address_bound: true,
        hardware_only_policy_bound: true,
        insert_response_policy_bound: true,
        empty_table_cleanup_policy_bound: true,
        failure_detach_resume_effect_bound: true,
        failure_no_additional_tcl_resume_policy_bound: true,
        lifecycle_deadlines_bound: true,
        loopback_dynamic_endpoint_policy_bound: true,
        runtime_port_number_bound: false,
        expected_target_name_bound: true,
        runtime_adapter_identity_bound: false,
        hardware_breakpoint_capacity_bound: false,
        physical_comparator_cleanup_bound: false,
        target_state_policy_bound: true,
        symbol_or_firmware_identity_required: false,
    }
}

fn breakpoint_capabilities() -> OpenOcdHardwareBreakpointCapabilities {
    OpenOcdHardwareBreakpointCapabilities {
        server_launch: true,
        tcl_rpc: true,
        gdb_mi: true,
        remote_target_connection: true,
        target_state_observation: true,
        attach_detach: true,
        restoration_resume: true,
        temporary_hardware_breakpoint_roundtrip: true,
        persistent_breakpoints: false,
        software_breakpoints: false,
        symbolic_breakpoints: false,
        conditional_breakpoints: false,
        watchpoints: false,
        breakpoint_hit_execution: false,
        register_read: false,
        memory_read: false,
        stack_read: false,
        symbol_loading: false,
        general_execution_control: false,
        flash: false,
        arbitrary_commands: false,
    }
}

fn restoration_error(restoration: &OpenOcdTargetRestoration) -> DebugError {
    DebugError::verification(
        "hardware-breakpoint roundtrip did not prove restoration of the initial running target state",
        json!({"target_restoration": restoration}),
    )
}

fn breakpoint_confirmation_error(expected: &str, received: &str) -> DebugError {
    let mut error = DebugError::new(
        ErrorCode::ConfirmationMismatch,
        "OpenOCD hardware-breakpoint confirmation digest does not match the current plan",
        2,
        json!({
            "expected_confirm_digest": expected,
            "received_confirm_digest": received,
            "hardware_access_started": false,
        }),
    );
    error.suggested_actions.push(SuggestedAction::new(
        "review_openocd_hardware_breakpoint_plan",
        json!({"command": "openocd breakpoint plan"}),
    ));
    error
}

fn error_value(error: &DebugError) -> Value {
    json!({
        "code": error.code,
        "message": error.message,
        "retryable": error.retryable,
        "exit_code": error.exit_code,
        "details": error.details,
    })
}

fn duration_ms(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
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

    const OPENOCD_HELPER_ROLE: &str = "EMBEDDED_DEBUGGER_BREAKPOINT_OPENOCD_HELPER_ROLE";
    const ADDRESS: Address = Address(0x4201_29e4);
    const EMPTY_BREAKPOINT_TABLE: &str = concat!(
        "BreakpointTable={nr_rows=\"0\",nr_cols=\"6\",hdr=[",
        "{width=\"3\",alignment=\"-1\",col_name=\"number\",colhdr=\"Num\"},",
        "{width=\"14\",alignment=\"-1\",col_name=\"type\",colhdr=\"Type\"},",
        "{width=\"4\",alignment=\"-1\",col_name=\"disp\",colhdr=\"Disp\"},",
        "{width=\"3\",alignment=\"-1\",col_name=\"enabled\",colhdr=\"Enb\"},",
        "{width=\"18\",alignment=\"-1\",col_name=\"addr\",colhdr=\"Address\"},",
        "{width=\"40\",alignment=\"2\",col_name=\"what\",colhdr=\"What\"}],body=[]}",
    );

    #[test]
    fn zero_address_fails_before_session_inputs_are_inspected() {
        let error = plan_hardware_breakpoint(&missing_options(Address(0))).unwrap_err();
        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert_eq!(error.details["address"], "0x00000000");
    }

    #[test]
    fn breakpoint_plan_is_deterministic_and_binds_the_exact_address() {
        let directory = tempdir().unwrap();
        let first =
            plan_hardware_breakpoint(&test_options(directory.path(), "success", ADDRESS)).unwrap();
        let second =
            plan_hardware_breakpoint(&test_options(directory.path(), "success", ADDRESS)).unwrap();

        assert_eq!(first.confirm_digest, second.confirm_digest);
        assert_eq!(first.risk, "R2_DEVICE_WRITE");
        assert_eq!(first.protocol.commands.len(), 7);
        assert_eq!(
            first.protocol.commands[2].command,
            "-break-insert -h *0x420129e4"
        );
        assert_eq!(first.breakpoint_policy.requested_address, ADDRESS);
        assert!(!first.breakpoint_policy.breakpoint_hit_requested);
        assert!(
            !first
                .breakpoint_policy
                .target_execution_while_installed_requested
        );
        assert!(first.breakpoint_policy.failure_cleanup_gdb_detach_requested);
        assert!(
            first
                .breakpoint_policy
                .target_resume_possible_during_failure_cleanup
        );
        assert!(
            !first
                .breakpoint_policy
                .explicit_openocd_resume_after_gdb_failure
        );
        assert!(
            first
                .breakpoint_policy
                .success_resume_requires_empty_gdb_table
        );
        assert_eq!(
            first.breakpoint_policy.failure_cleanup_scope,
            "after remote connection when the breakpoint exchange fails before normal detach"
        );
        assert!(first.confirmation_boundary.exact_numeric_address_bound);
        assert!(!first.confirmation_boundary.runtime_adapter_identity_bound);
        assert!(
            !first
                .confirmation_boundary
                .hardware_breakpoint_capacity_bound
        );

        let changed = plan_hardware_breakpoint(&test_options(
            directory.path(),
            "success",
            Address(ADDRESS.0 + 4),
        ))
        .unwrap();
        assert_ne!(first.confirm_digest, changed.confirm_digest);
    }

    #[test]
    fn controlled_breakpoint_roundtrip_proves_empty_table_and_running_restoration() {
        let directory = tempdir().unwrap();
        let options = test_options(directory.path(), "success", ADDRESS);
        let plan = plan_hardware_breakpoint(&options).unwrap();
        let report = test_hardware_breakpoint(&options, &plan.confirm_digest).unwrap();

        assert!(report.complete);
        assert_eq!(report.exchange.roundtrip.inserted.address, ADDRESS);
        assert_eq!(
            report.exchange.roundtrip.inserted.breakpoint_type,
            "hw breakpoint"
        );
        assert!(report.exchange.roundtrip.gdb_breakpoint_table_empty);
        assert!(report.exchange.roundtrip.table_after_delete.empty);
        assert_eq!(
            report.exchange.roundtrip.table_after_delete.reported_rows,
            0
        );
        assert!(
            !report
                .exchange
                .roundtrip
                .physical_comparator_state_independently_verified
        );
        assert_eq!(report.target_restoration.initial.state, "running");
        assert!(!report.target_restoration.fallback_resume_requested);
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
    fn malformed_insert_runs_fixed_cleanup_without_an_additional_tcl_resume() {
        let directory = tempdir().unwrap();
        let options = test_options(directory.path(), "malformed_insert", ADDRESS);
        let plan = plan_hardware_breakpoint(&options).unwrap();
        let error = test_hardware_breakpoint(&options, &plan.confirm_digest).unwrap_err();

        assert_eq!(error.code, ErrorCode::ProtocolError);
        assert_eq!(error.details["breakpoint_cleanup"]["attempted"], true);
        assert_eq!(
            error.details["breakpoint_cleanup"]["gdb_breakpoint_table_empty"],
            true
        );
        assert_eq!(error.details["breakpoint_cleanup"]["complete"], true);
        assert_eq!(error.details["cleanup_detach"]["complete"], true);
        assert_eq!(error.details["shutdown"]["graceful"], true);
        assert_eq!(
            error.details["target_observation_after_gdb_failure"]["state"],
            "halted"
        );
        assert_eq!(error.details["target_restoration"]["attempted"], false);
        assert_eq!(
            error.details["target_restoration"]["explicit_openocd_resume_attempted"],
            false
        );
        assert_eq!(
            error.details["target_restoration"]["gdb_cleanup_detach_or_exit_may_resume_target"],
            true
        );
        assert_eq!(error.details["openocd_shutdown"]["graceful"], true);
    }

    #[test]
    fn managed_breakpoint_openocd_helper() {
        let Some(mode) = std::env::var_os(OPENOCD_HELPER_ROLE) else {
            return;
        };
        let mode = mode.to_string_lossy();
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
                    let state = if mode == "malformed_insert" && state_queries > 1 {
                        b"halted\x1a".as_slice()
                    } else {
                        b"running\x1a".as_slice()
                    };
                    stream.write_all(state).unwrap();
                }
                b"targets fake.cpu0; resume" if mode == "malformed_insert" => {
                    panic!("failure path sent a forbidden Tcl resume")
                }
                b"targets fake.cpu0; resume" => stream.write_all(b"\x1a").unwrap(),
                b"shutdown" => break,
                _ => stream.write_all(b"unknown command\x1a").unwrap(),
            }
        }
        drop(gdb);
    }

    fn missing_options(address: Address) -> OpenOcdHardwareBreakpointOptions {
        OpenOcdHardwareBreakpointOptions {
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
            address,
        }
    }

    fn test_options(
        directory: &Path,
        mode: &str,
        address: Address,
    ) -> OpenOcdHardwareBreakpointOptions {
        let openocd = write_fake_openocd(directory, mode);
        let gdb = write_fake_gdb(directory, mode);
        let config = directory.join(format!("board-{mode}.cfg"));
        fs::write(&config, b"adapter speed 1000\n").unwrap();
        OpenOcdHardwareBreakpointOptions {
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
            address,
        }
    }

    fn write_fake_openocd(directory: &Path, mode: &str) -> PathBuf {
        let current_exe = std::env::current_exe().unwrap();
        let helper = "backend::openocd::breakpoint::tests::managed_breakpoint_openocd_helper";
        write_helper_wrapper(
            directory,
            &format!("fake-breakpoint-openocd-{mode}"),
            OPENOCD_HELPER_ROLE,
            mode,
            &current_exe,
            helper,
            "Open On-Chip Debugger 0.12.0-test",
        )
    }

    fn write_fake_gdb(directory: &Path, mode: &str) -> PathBuf {
        let breakpoint_type = if mode == "malformed_insert" {
            "breakpoint"
        } else {
            "hw breakpoint"
        };
        #[cfg(windows)]
        {
            let executable = directory.join(format!("fake-breakpoint-gdb-{mode}.cmd"));
            let insert = format!(
                "3^^done,bkpt={{number=\"1\",type=\"{breakpoint_type}\",disp=\"keep\",enabled=\"y\",addr=\"0x420129e4\",thread-groups=[\"i1\"],times=\"0\",original-location=\"*0x420129e4\"}}"
            );
            let lifecycle = if mode == "malformed_insert" {
                format!(
                    "set /p cleanup_delete=\r\nif not \"%cleanup_delete%\"==\"8-break-delete 1\" exit /b 8\r\necho 8^^done\r\necho ^(gdb^)\r\nset /p cleanup_list=\r\nif not \"%cleanup_list%\"==\"9-break-list\" exit /b 9\r\necho 9^^done,{EMPTY_BREAKPOINT_TABLE}\r\necho ^(gdb^)\r\nset /p cleanup_detach=\r\nif not \"%cleanup_detach%\"==\"10-target-detach\" exit /b 10\r\necho 10^^done\r\necho ^(gdb^)\r\n"
                )
            } else {
                format!(
                    "set /p delete=\r\nif not \"%delete%\"==\"4-break-delete 1\" exit /b 8\r\necho 4^^done\r\necho ^(gdb^)\r\nset /p list=\r\nif not \"%list%\"==\"5-break-list\" exit /b 9\r\necho 5^^done,{EMPTY_BREAKPOINT_TABLE}\r\necho ^(gdb^)\r\nset /p detach=\r\nif not \"%detach%\"==\"6-target-detach\" exit /b 10\r\necho 6^^done\r\necho ^(gdb^)\r\n"
                )
            };
            fs::write(
                &executable,
                format!(
                    "@echo off\r\nif \"%1\"==\"--version\" goto version\r\nif defined XTENSA_GNU_CONFIG exit /b 2\r\necho ^(gdb^)\r\nset /p first=\r\nif not \"%first%\"==\"1-gdb-version\" exit /b 3\r\necho ~\"GNU gdb 17.1-test\\n\"\r\necho 1^^done\r\necho ^(gdb^)\r\nset /p second=\r\nif not \"%second:~0,23%\"==\"2-target-select remote \" exit /b 4\r\necho *stopped,reason=\"signal-received\"\r\necho 2^^connected\r\necho ^(gdb^)\r\nset /p insert=\r\nif not \"%insert%\"==\"3-break-insert -h *0x420129e4\" exit /b 5\r\necho {insert}\r\necho ^(gdb^)\r\n{lifecycle}set /p exit_command=\r\nif not \"%exit_command%\"==\"7-gdb-exit\" exit /b 11\r\necho 7^^exit\r\nexit /b 0\r\n:version\r\necho GNU gdb 17.1-test\r\nexit /b 0\r\n"
                ),
            )
            .unwrap();
            executable
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let executable = directory.join(format!("fake-breakpoint-gdb-{mode}"));
            let insert = format!(
                "3^done,bkpt={{number=\"1\",type=\"{breakpoint_type}\",disp=\"keep\",enabled=\"y\",addr=\"0x420129e4\",thread-groups=[\"i1\"],times=\"0\",original-location=\"*0x420129e4\"}}"
            );
            let lifecycle = if mode == "malformed_insert" {
                format!(
                    "IFS= read -r cleanup_delete\n[ \"$cleanup_delete\" = '8-break-delete 1' ] || exit 8\nprintf '%s\\n' '8^done' '(gdb)'\nIFS= read -r cleanup_list\n[ \"$cleanup_list\" = '9-break-list' ] || exit 9\nprintf '%s\\n' '9^done,{EMPTY_BREAKPOINT_TABLE}' '(gdb)'\nIFS= read -r cleanup_detach\n[ \"$cleanup_detach\" = '10-target-detach' ] || exit 10\nprintf '%s\\n' '10^done' '(gdb)'\n"
                )
            } else {
                format!(
                    "IFS= read -r delete\n[ \"$delete\" = '4-break-delete 1' ] || exit 8\nprintf '%s\\n' '4^done' '(gdb)'\nIFS= read -r list\n[ \"$list\" = '5-break-list' ] || exit 9\nprintf '%s\\n' '5^done,{EMPTY_BREAKPOINT_TABLE}' '(gdb)'\nIFS= read -r detach\n[ \"$detach\" = '6-target-detach' ] || exit 10\nprintf '%s\\n' '6^done' '(gdb)'\n"
                )
            };
            fs::write(
                &executable,
                format!(
                    "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  printf '%s\\n' 'GNU gdb 17.1-test'\n  exit 0\nfi\n[ -z \"${{XTENSA_GNU_CONFIG+x}}\" ] || exit 2\nprintf '%s\\n' '(gdb)'\nIFS= read -r first\n[ \"$first\" = '1-gdb-version' ] || exit 3\nprintf '%s\\n' '~\"GNU gdb 17.1-test\\n\"' '1^done' '(gdb)'\nIFS= read -r second\ncase \"$second\" in '2-target-select remote 127.0.0.1:'*) ;; *) exit 4 ;; esac\nprintf '%s\\n' '*stopped,reason=\"signal-received\"' '2^connected' '(gdb)'\nIFS= read -r insert\n[ \"$insert\" = '3-break-insert -h *0x420129e4' ] || exit 5\nprintf '%s\\n' '{insert}' '(gdb)'\n{lifecycle}IFS= read -r exit_command\n[ \"$exit_command\" = '7-gdb-exit' ] || exit 11\nprintf '%s\\n' '7^exit'\n"
                ),
            )
            .unwrap();
            let mut permissions = fs::metadata(&executable).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&executable, permissions).unwrap();
            executable
        }
    }

    fn write_helper_wrapper(
        directory: &Path,
        name: &str,
        role: &str,
        mode: &str,
        current_exe: &Path,
        helper: &str,
        version: &str,
    ) -> PathBuf {
        #[cfg(windows)]
        {
            let executable = directory.join(format!("{name}.cmd"));
            fs::write(
                &executable,
                format!(
                    "@echo off\r\nif \"%1\"==\"--version\" goto version\r\nset {role}={mode}\r\n\"{}\" --exact {helper} --nocapture\r\nexit /b %errorlevel%\r\n:version\r\necho {version}\r\nexit /b 0\r\n",
                    current_exe.display()
                ),
            )
            .unwrap();
            executable
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let executable = directory.join(name);
            let escaped_exe = current_exe.to_string_lossy().replace('\'', "'\\''");
            fs::write(
                &executable,
                format!(
                    "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  printf '%s\\n' '{version}'\n  exit 0\nfi\n{role}='{mode}' exec '{escaped_exe}' --exact {helper} --nocapture\n"
                ),
            )
            .unwrap();
            let mut permissions = fs::metadata(&executable).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&executable, permissions).unwrap();
            executable
        }
    }
}
