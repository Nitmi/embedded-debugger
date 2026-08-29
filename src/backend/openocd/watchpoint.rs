use std::time::Duration;

use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{
    GdbExecutableFileIdentity, GdbMiCommandResult, GdbMiHandshake,
    GdbMiHardwareWatchpointRoundtrip, GdbMiOutput, GdbMiPlannedCommand, GdbMiProtocol,
    GdbMiShutdown, GdbXtensaConfigInspection, OpenOcdDeclaredMemoryRegion,
    OpenOcdGdbSessionOptions, OpenOcdHardwareWatchpointMode, OpenOcdServerConfirmationBoundary,
    OpenOcdServerEffects, OpenOcdServerLogs, OpenOcdServerPlan, OpenOcdServerReadiness,
    OpenOcdServerShutdown, OpenOcdSessionGdbPlan, OpenOcdSessionServerPlan,
    OpenOcdTargetRestoration, OpenOcdTargetStatePolicy,
    gdb::{
        RemoteWatchpointRequest, execute_remote_watchpoint_roundtrip, watchpoint_expression,
        watchpoint_failure_cleanup_contract, watchpoint_protocol_contract,
    },
    server::start_managed_server,
    session::{observe_initial_target, restore_running_target, with_server_context},
};
use crate::{
    SCHEMA_VERSION,
    error::{DebugError, ErrorCode, Result, SuggestedAction},
    model::{Address, MemoryRegionKind},
};

pub const OPENOCD_HARDWARE_WATCHPOINT_LENGTHS: [u64; 4] = [1, 2, 4, 8];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenOcdHardwareWatchpointOptions {
    pub session: OpenOcdGdbSessionOptions,
    pub address: Address,
    pub length_bytes: u64,
    pub region_start: Address,
    pub region_length_bytes: u64,
    pub region_kind: MemoryRegionKind,
    pub mode: OpenOcdHardwareWatchpointMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdHardwareWatchpointPlan {
    pub backend: String,
    pub operation: String,
    pub risk: String,
    pub complete: bool,
    pub openocd: OpenOcdSessionServerPlan,
    pub gdb: OpenOcdSessionGdbPlan,
    pub protocol: GdbMiProtocol,
    pub watchpoint_policy: OpenOcdHardwareWatchpointPolicy,
    pub target_state_policy: OpenOcdTargetStatePolicy,
    pub effects: OpenOcdHardwareWatchpointEffects,
    pub confirmation_boundary: OpenOcdHardwareWatchpointConfirmationBoundary,
    pub confirm_digest: String,
    #[serde(skip)]
    openocd_execution_plan: OpenOcdServerPlan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdHardwareWatchpointPolicy {
    pub requested_address: Address,
    pub requested_length_bytes: u64,
    pub requested_end_exclusive: Address,
    pub allowed_lengths_bytes: Vec<u64>,
    pub natural_alignment_required: bool,
    pub natural_alignment_verified: bool,
    pub declared_region: OpenOcdDeclaredMemoryRegion,
    pub allowed_region_kinds: Vec<String>,
    pub declared_region_containment_verified: bool,
    pub declared_region_semantics_verified: bool,
    pub declared_region_source: String,
    pub mode: OpenOcdHardwareWatchpointMode,
    pub supported_modes: Vec<String>,
    pub write_only_mode_supported: bool,
    pub hardware_only_by_gdb_semantics: bool,
    pub language_command: String,
    pub expression: String,
    pub expression_source: String,
    pub expression_evaluation_may_read_declared_ram: bool,
    pub expected_gdb_breakpoint_number: u64,
    pub expected_insert_result_field: String,
    pub expected_breakpoint_table_type: String,
    pub insert_command: String,
    pub list_before_delete_command: String,
    pub delete_command: String,
    pub list_after_delete_command: String,
    pub insertion_requirements: Vec<String>,
    pub classification_requirements: Vec<String>,
    pub deletion_verification: String,
    pub failure_cleanup_commands: Vec<GdbMiPlannedCommand>,
    pub watchpoint_hit_requested: bool,
    pub target_execution_while_installed_requested: bool,
    pub success_resume_requires_empty_gdb_table: bool,
    pub failure_cleanup_scope: String,
    pub failure_cleanup_gdb_detach_requested: bool,
    pub target_resume_possible_during_failure_cleanup: bool,
    pub explicit_openocd_resume_after_gdb_failure: bool,
    pub physical_comparator_allocation_independently_verified: bool,
    pub physical_comparator_state_independently_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdHardwareWatchpointEffects {
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
    pub gdb_language_change_requested: bool,
    pub hardware_watchpoint_insert_requested: bool,
    pub hardware_watchpoint_delete_requested: bool,
    pub breakpoint_table_read_requested: bool,
    pub expression_evaluation_memory_read_possible: bool,
    pub side_effectful_read_possible_if_region_declaration_is_wrong: bool,
    pub watchpoint_hit_or_continue_requested: bool,
    pub write_only_or_software_watchpoint_requested: bool,
    pub persistent_watchpoint_requested: bool,
    pub breakpoint_requested: bool,
    pub symbol_or_executable_loading_requested: bool,
    pub explicit_register_or_general_memory_command_requested: bool,
    pub memory_write_requested: bool,
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
pub struct OpenOcdHardwareWatchpointConfirmationBoundary {
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
    pub exact_numeric_range_bound: bool,
    pub declared_ram_region_bound: bool,
    pub watchpoint_mode_bound: bool,
    pub hardware_only_policy_bound: bool,
    pub insertion_response_policy_bound: bool,
    pub hardware_classification_policy_bound: bool,
    pub empty_table_cleanup_policy_bound: bool,
    pub expression_evaluation_read_effect_bound: bool,
    pub failure_detach_resume_effect_bound: bool,
    pub failure_no_additional_tcl_resume_policy_bound: bool,
    pub lifecycle_deadlines_bound: bool,
    pub loopback_dynamic_endpoint_policy_bound: bool,
    pub runtime_port_number_bound: bool,
    pub expected_target_name_bound: bool,
    pub runtime_adapter_identity_bound: bool,
    pub target_ram_semantics_bound: bool,
    pub hardware_watchpoint_width_support_bound: bool,
    pub hardware_watchpoint_capacity_bound: bool,
    pub physical_comparator_allocation_bound: bool,
    pub physical_comparator_cleanup_bound: bool,
    pub target_state_policy_bound: bool,
    pub symbol_or_firmware_identity_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdHardwareWatchpointTestReport {
    pub backend: String,
    pub scope: String,
    pub risk: String,
    pub complete: bool,
    pub confirm_digest: String,
    pub openocd: OpenOcdSessionServerPlan,
    pub gdb: OpenOcdSessionGdbPlan,
    pub protocol: GdbMiProtocol,
    pub watchpoint_policy: OpenOcdHardwareWatchpointPolicy,
    pub target_state_policy: OpenOcdTargetStatePolicy,
    pub readiness: OpenOcdServerReadiness,
    pub target_restoration: OpenOcdTargetRestoration,
    pub exchange: OpenOcdHardwareWatchpointExchange,
    pub openocd_shutdown: OpenOcdServerShutdown,
    pub openocd_logs: OpenOcdServerLogs,
    pub effects: OpenOcdHardwareWatchpointEffects,
    pub confirmation_boundary: OpenOcdHardwareWatchpointConfirmationBoundary,
    pub capabilities: OpenOcdHardwareWatchpointCapabilities,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdHardwareWatchpointExchange {
    pub endpoint: String,
    pub handshake: GdbMiHandshake,
    pub connection: GdbMiCommandResult,
    pub language: GdbMiCommandResult,
    pub insert: GdbMiCommandResult,
    pub list_before_delete: GdbMiCommandResult,
    pub delete: GdbMiCommandResult,
    pub list_after_delete: GdbMiCommandResult,
    pub roundtrip: GdbMiHardwareWatchpointRoundtrip,
    pub detach: GdbMiCommandResult,
    pub shutdown: GdbMiShutdown,
    pub output: GdbMiOutput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdHardwareWatchpointCapabilities {
    pub server_launch: bool,
    pub tcl_rpc: bool,
    pub gdb_mi: bool,
    pub remote_target_connection: bool,
    pub target_state_observation: bool,
    pub attach_detach: bool,
    pub restoration_resume: bool,
    pub temporary_hardware_read_watchpoint_roundtrip: bool,
    pub temporary_hardware_access_watchpoint_roundtrip: bool,
    pub write_only_watchpoints: bool,
    pub persistent_watchpoints: bool,
    pub watchpoint_hit_execution: bool,
    pub breakpoints: bool,
    pub register_read: bool,
    pub general_memory_read: bool,
    pub memory_write: bool,
    pub stack_read: bool,
    pub symbol_loading: bool,
    pub general_execution_control: bool,
    pub flash: bool,
    pub arbitrary_commands: bool,
}

#[derive(Debug, Serialize)]
struct WatchpointConfirmationInput<'a> {
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
    watchpoint_policy: &'a OpenOcdHardwareWatchpointPolicy,
    target_state_policy: &'a OpenOcdTargetStatePolicy,
    effects: &'a OpenOcdHardwareWatchpointEffects,
    confirmation_boundary: &'a OpenOcdHardwareWatchpointConfirmationBoundary,
}

#[derive(Debug, Serialize)]
struct GdbLifecycleConfirmation {
    version_timeout_ms: u64,
    startup_timeout_ms: u64,
    command_timeout_ms: u64,
    shutdown_timeout_ms: u64,
}

pub fn plan_hardware_watchpoint(
    options: &OpenOcdHardwareWatchpointOptions,
) -> Result<OpenOcdHardwareWatchpointPlan> {
    let watchpoint_policy = validate_watchpoint_policy(options)?;
    let session = super::plan_session(&options.session)?;
    let protocol =
        watchpoint_protocol_contract(options.address, options.length_bytes, options.mode);
    let mut target_state_policy = session.target_state_policy.clone();
    target_state_policy.normal_restoration_command = "8-target-detach".to_string();
    target_state_policy.normal_restoration_expected_effect =
        "resume only after GDB classifies the fixed watchpoint as hardware, deletes it, and reports its table empty"
            .to_string();
    target_state_policy.fallback_condition =
        "only on an otherwise successful, cleanup-verified roundtrip when running is not proven after GDB cleanup"
            .to_string();
    let effects = watchpoint_effects(session.gdb.xtensa_config.is_some());
    let confirmation_boundary = watchpoint_confirmation_boundary();
    let confirmation = WatchpointConfirmationInput {
        schema_version: SCHEMA_VERSION,
        operation: "openocd.watchpoint.test",
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
        watchpoint_policy: &watchpoint_policy,
        target_state_policy: &target_state_policy,
        effects: &effects,
        confirmation_boundary: &confirmation_boundary,
    };
    let confirm_digest = hex::encode(Sha256::digest(
        serde_json::to_vec(&confirmation)
            .expect("hardware-watchpoint confirmation input always serializes"),
    ));

    Ok(OpenOcdHardwareWatchpointPlan {
        backend: "openocd".to_string(),
        operation: "openocd.watchpoint.test".to_string(),
        risk: "R2_DEVICE_WRITE".to_string(),
        complete: true,
        openocd: session.openocd,
        gdb: session.gdb,
        protocol,
        watchpoint_policy,
        target_state_policy,
        effects,
        confirmation_boundary,
        confirm_digest,
        openocd_execution_plan: session.openocd_execution_plan,
    })
}

pub fn test_hardware_watchpoint(
    options: &OpenOcdHardwareWatchpointOptions,
    confirm_digest: &str,
) -> Result<OpenOcdHardwareWatchpointTestReport> {
    let plan = plan_hardware_watchpoint(options)?;
    if plan.confirm_digest != confirm_digest {
        return Err(watchpoint_confirmation_error(
            &plan.confirm_digest,
            confirm_digest,
        ));
    }
    execute_watchpoint_plan(plan)
}

fn execute_watchpoint_plan(
    plan: OpenOcdHardwareWatchpointPlan,
) -> Result<OpenOcdHardwareWatchpointTestReport> {
    let server = start_managed_server(&plan.openocd_execution_plan)?;
    let initial = match observe_initial_target(&server, plan.target_state_policy.timeout_ms) {
        Ok(observation) => observation,
        Err(error) => return Err(with_server_context(error, server.finish(), None)),
    };
    if initial.target_name != plan.target_state_policy.expected_current_target {
        let error = DebugError::verification(
            "OpenOCD current target did not match the confirmed hardware-watchpoint target",
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
            "OpenOCD current target was not running before hardware-watchpoint attachment",
            json!({
                "initial_observation": initial,
                "required_initial_state": plan.target_state_policy.initial_state_required,
                "remote_gdb_started": false,
            }),
        );
        return Err(with_server_context(error, server.finish(), None));
    }

    let gdb_result = execute_remote_watchpoint_roundtrip(
        &plan.gdb.executable.resolved,
        plan.gdb
            .xtensa_config
            .as_ref()
            .map(|config| config.resolved.as_str()),
        server.readiness().gdb_port,
        RemoteWatchpointRequest {
            address: plan.watchpoint_policy.requested_address,
            length_bytes: plan.watchpoint_policy.requested_length_bytes,
            mode: plan.watchpoint_policy.mode,
        },
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
                    "reason": "hardware-watchpoint cleanup or protocol success was not fully proven",
                    "manual_recovery_may_be_required": true,
                }),
            );
            gdb_error.details = Value::Object(details);
            return Err(with_server_context(gdb_error, server.finish(), None));
        }
    };

    let restoration = restore_running_target(&server, initial, plan.target_state_policy.timeout_ms);
    let completion = server.finish();
    let exchange = OpenOcdHardwareWatchpointExchange {
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
        language: GdbMiCommandResult {
            token: 3,
            command: "-gdb-set language c".to_string(),
            result_class: execution.language_result_class,
            elapsed_ms: duration_ms(execution.language_elapsed),
        },
        insert: GdbMiCommandResult {
            token: 4,
            command: execution.insert_command,
            result_class: execution.insert_result_class,
            elapsed_ms: duration_ms(execution.insert_elapsed),
        },
        list_before_delete: GdbMiCommandResult {
            token: 5,
            command: "-break-list".to_string(),
            result_class: execution.list_before_delete_result_class,
            elapsed_ms: duration_ms(execution.list_before_delete_elapsed),
        },
        delete: GdbMiCommandResult {
            token: 6,
            command: "-break-delete 1".to_string(),
            result_class: execution.delete_result_class,
            elapsed_ms: duration_ms(execution.delete_elapsed),
        },
        list_after_delete: GdbMiCommandResult {
            token: 7,
            command: "-break-list".to_string(),
            result_class: execution.list_after_delete_result_class,
            elapsed_ms: duration_ms(execution.list_after_delete_elapsed),
        },
        roundtrip: execution.roundtrip,
        detach: GdbMiCommandResult {
            token: 8,
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

    Ok(OpenOcdHardwareWatchpointTestReport {
        backend: plan.backend,
        scope: "confirmed_temporary_hardware_watchpoint_roundtrip".to_string(),
        risk: plan.risk,
        complete: true,
        confirm_digest: plan.confirm_digest,
        openocd: plan.openocd,
        gdb: plan.gdb,
        protocol: plan.protocol,
        watchpoint_policy: plan.watchpoint_policy,
        target_state_policy: plan.target_state_policy,
        readiness: completion.readiness,
        target_restoration: restoration,
        exchange,
        openocd_shutdown: completion.shutdown,
        openocd_logs: completion.logs,
        effects: plan.effects,
        confirmation_boundary: plan.confirmation_boundary,
        capabilities: watchpoint_capabilities(),
    })
}

fn validate_watchpoint_policy(
    options: &OpenOcdHardwareWatchpointOptions,
) -> Result<OpenOcdHardwareWatchpointPolicy> {
    if options.region_kind != MemoryRegionKind::Ram {
        return Err(DebugError::config(
            "OpenOCD hardware watchpoints require a declared RAM region",
            json!({
                "region_kind": options.region_kind,
                "allowed_region_kinds": ["ram"],
            }),
        ));
    }
    if options.address.0 == 0 {
        return Err(DebugError::config(
            "OpenOCD hardware-watchpoint address must be non-zero",
            json!({"address": options.address, "minimum": "0x1"}),
        ));
    }
    if !OPENOCD_HARDWARE_WATCHPOINT_LENGTHS.contains(&options.length_bytes) {
        return Err(DebugError::config(
            "OpenOCD hardware-watchpoint length is not supported",
            json!({
                "length_bytes": options.length_bytes,
                "allowed_lengths_bytes": OPENOCD_HARDWARE_WATCHPOINT_LENGTHS,
            }),
        ));
    }
    if !options.address.0.is_multiple_of(options.length_bytes) {
        return Err(DebugError::config(
            "OpenOCD hardware-watchpoint address is not naturally aligned",
            json!({
                "address": options.address,
                "length_bytes": options.length_bytes,
                "required_alignment_bytes": options.length_bytes,
            }),
        ));
    }
    if options.region_length_bytes == 0 {
        return Err(DebugError::config(
            "declared OpenOCD watchpoint RAM region must be non-empty",
            json!({"region_length_bytes": options.region_length_bytes}),
        ));
    }
    let request_end = options
        .address
        .0
        .checked_add(options.length_bytes)
        .ok_or_else(|| {
            DebugError::config(
                "OpenOCD hardware-watchpoint range overflows the address space",
                json!({
                    "address": options.address,
                    "length_bytes": options.length_bytes,
                }),
            )
        })?;
    let region_end = options
        .region_start
        .0
        .checked_add(options.region_length_bytes)
        .ok_or_else(|| {
            DebugError::config(
                "declared OpenOCD watchpoint RAM region overflows the address space",
                json!({
                    "region_start": options.region_start,
                    "region_length_bytes": options.region_length_bytes,
                }),
            )
        })?;
    if options.address.0 < options.region_start.0 || request_end > region_end {
        return Err(DebugError::config(
            "OpenOCD hardware-watchpoint range is not contained in the declared RAM region",
            json!({
                "requested_address": options.address,
                "requested_length_bytes": options.length_bytes,
                "requested_end_exclusive": Address(request_end),
                "region_start": options.region_start,
                "region_length_bytes": options.region_length_bytes,
                "region_end_exclusive": Address(region_end),
            }),
        ));
    }

    let expression = watchpoint_expression(options.address, options.length_bytes);
    let mode_flag = mode_command_flag(options.mode);
    Ok(OpenOcdHardwareWatchpointPolicy {
        requested_address: options.address,
        requested_length_bytes: options.length_bytes,
        requested_end_exclusive: Address(request_end),
        allowed_lengths_bytes: OPENOCD_HARDWARE_WATCHPOINT_LENGTHS.to_vec(),
        natural_alignment_required: true,
        natural_alignment_verified: true,
        declared_region: OpenOcdDeclaredMemoryRegion {
            kind: options.region_kind,
            start: options.region_start,
            length_bytes: options.region_length_bytes,
            end_exclusive: Address(region_end),
        },
        allowed_region_kinds: vec!["ram".to_string()],
        declared_region_containment_verified: true,
        declared_region_semantics_verified: false,
        declared_region_source: "user_confirmed_cli_input".to_string(),
        mode: options.mode,
        supported_modes: vec!["read".to_string(), "access".to_string()],
        write_only_mode_supported: false,
        hardware_only_by_gdb_semantics: true,
        language_command: "3-gdb-set language c".to_string(),
        expression: expression.clone(),
        expression_source: "fixed_exact_numeric_artificial_char_array".to_string(),
        expression_evaluation_may_read_declared_ram: true,
        expected_gdb_breakpoint_number: 1,
        expected_insert_result_field: mode_insert_result_field(options.mode).to_string(),
        expected_breakpoint_table_type: mode_breakpoint_type(options.mode).to_string(),
        insert_command: format!("4-break-watch {mode_flag} {expression}"),
        list_before_delete_command: "5-break-list".to_string(),
        delete_command: "6-break-delete 1".to_string(),
        list_after_delete_command: "7-break-list".to_string(),
        insertion_requirements: vec![
            format!(
                "exactly one {} tuple",
                mode_insert_result_field(options.mode)
            ),
            "number=1".to_string(),
            "exp equals the generated fixed numeric expression".to_string(),
            "no additional insertion fields".to_string(),
        ],
        classification_requirements: vec![
            "exactly one bkpt row in the canonical six-column BreakpointTable".to_string(),
            "number=1".to_string(),
            format!("type={}", mode_breakpoint_type(options.mode)),
            "disp=keep".to_string(),
            "enabled=y".to_string(),
            "what and original-location equal the generated expression".to_string(),
            "times=0".to_string(),
            "no address, pending, condition, command, script, or location fields".to_string(),
        ],
        deletion_verification:
            "require an exact zero-row six-column BreakpointTable with an empty body".to_string(),
        failure_cleanup_commands: watchpoint_failure_cleanup_contract(),
        watchpoint_hit_requested: false,
        target_execution_while_installed_requested: false,
        success_resume_requires_empty_gdb_table: true,
        failure_cleanup_scope:
            "after the watchpoint insertion command is attempted and before normal detach"
                .to_string(),
        failure_cleanup_gdb_detach_requested: true,
        target_resume_possible_during_failure_cleanup: true,
        explicit_openocd_resume_after_gdb_failure: false,
        physical_comparator_allocation_independently_verified: false,
        physical_comparator_state_independently_verified: false,
    })
}

fn watchpoint_effects(xtensa_config_selected: bool) -> OpenOcdHardwareWatchpointEffects {
    OpenOcdHardwareWatchpointEffects {
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
        gdb_language_change_requested: true,
        hardware_watchpoint_insert_requested: true,
        hardware_watchpoint_delete_requested: true,
        breakpoint_table_read_requested: true,
        expression_evaluation_memory_read_possible: true,
        side_effectful_read_possible_if_region_declaration_is_wrong: true,
        watchpoint_hit_or_continue_requested: false,
        write_only_or_software_watchpoint_requested: false,
        persistent_watchpoint_requested: false,
        breakpoint_requested: false,
        symbol_or_executable_loading_requested: false,
        explicit_register_or_general_memory_command_requested: false,
        memory_write_requested: false,
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
            "GDB evaluates a fixed artificial char-array expression while creating the watchpoint and may read the confirmed RAM range before deletion."
                .to_string(),
            "The declared RAM region and containment are confirmed inputs; target memory-map semantics are not independently verified. A wrong declaration can make expression evaluation side-effectful."
                .to_string(),
            "Only GDB rwatch and awatch are exposed because GDB defines them as hardware-only; ordinary write watchpoints can fall back to software stepping and are rejected by omission."
                .to_string(),
            "The target is never intentionally continued while the hardware watchpoint is installed, so this workflow does not request or verify a watchpoint hit."
                .to_string(),
            "A classified table row proves GDB hardware classification, not physical comparator allocation or target width/capacity support, which may only fail when execution resumes."
                .to_string(),
            "A successful delete plus empty GDB breakpoint table proves GDB bookkeeping cleanup, not an independent read of the physical comparator."
                .to_string(),
            "After a watchpoint-exchange failure following insertion and before normal detach, the tool attempts fixed delete/list/detach cleanup. No GDB failure path sends an additional OpenOCD Tcl resume; GDB detach, GDB exit, or configuration-defined detach handlers may still resume the target."
                .to_string(),
            "Normal remote negotiation may exchange target descriptions, memory-map metadata, stop state, or register state."
                .to_string(),
            "Confirmed OpenOCD attach handlers may probe flash or reset/halt a protected target."
                .to_string(),
        ],
    }
}

fn watchpoint_confirmation_boundary() -> OpenOcdHardwareWatchpointConfirmationBoundary {
    OpenOcdHardwareWatchpointConfirmationBoundary {
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
        exact_numeric_range_bound: true,
        declared_ram_region_bound: true,
        watchpoint_mode_bound: true,
        hardware_only_policy_bound: true,
        insertion_response_policy_bound: true,
        hardware_classification_policy_bound: true,
        empty_table_cleanup_policy_bound: true,
        expression_evaluation_read_effect_bound: true,
        failure_detach_resume_effect_bound: true,
        failure_no_additional_tcl_resume_policy_bound: true,
        lifecycle_deadlines_bound: true,
        loopback_dynamic_endpoint_policy_bound: true,
        runtime_port_number_bound: false,
        expected_target_name_bound: true,
        runtime_adapter_identity_bound: false,
        target_ram_semantics_bound: false,
        hardware_watchpoint_width_support_bound: false,
        hardware_watchpoint_capacity_bound: false,
        physical_comparator_allocation_bound: false,
        physical_comparator_cleanup_bound: false,
        target_state_policy_bound: true,
        symbol_or_firmware_identity_required: false,
    }
}

fn watchpoint_capabilities() -> OpenOcdHardwareWatchpointCapabilities {
    OpenOcdHardwareWatchpointCapabilities {
        server_launch: true,
        tcl_rpc: true,
        gdb_mi: true,
        remote_target_connection: true,
        target_state_observation: true,
        attach_detach: true,
        restoration_resume: true,
        temporary_hardware_read_watchpoint_roundtrip: true,
        temporary_hardware_access_watchpoint_roundtrip: true,
        write_only_watchpoints: false,
        persistent_watchpoints: false,
        watchpoint_hit_execution: false,
        breakpoints: false,
        register_read: false,
        general_memory_read: false,
        memory_write: false,
        stack_read: false,
        symbol_loading: false,
        general_execution_control: false,
        flash: false,
        arbitrary_commands: false,
    }
}

fn mode_command_flag(mode: OpenOcdHardwareWatchpointMode) -> &'static str {
    match mode {
        OpenOcdHardwareWatchpointMode::Read => "-r",
        OpenOcdHardwareWatchpointMode::Access => "-a",
    }
}

fn mode_insert_result_field(mode: OpenOcdHardwareWatchpointMode) -> &'static str {
    match mode {
        OpenOcdHardwareWatchpointMode::Read => "hw-rwpt",
        OpenOcdHardwareWatchpointMode::Access => "hw-awpt",
    }
}

fn mode_breakpoint_type(mode: OpenOcdHardwareWatchpointMode) -> &'static str {
    match mode {
        OpenOcdHardwareWatchpointMode::Read => "read watchpoint",
        OpenOcdHardwareWatchpointMode::Access => "acc watchpoint",
    }
}

fn restoration_error(restoration: &OpenOcdTargetRestoration) -> DebugError {
    DebugError::verification(
        "hardware-watchpoint roundtrip did not prove restoration of the initial running target state",
        json!({"target_restoration": restoration}),
    )
}

fn watchpoint_confirmation_error(expected: &str, received: &str) -> DebugError {
    let mut error = DebugError::new(
        ErrorCode::ConfirmationMismatch,
        "OpenOCD hardware-watchpoint confirmation digest does not match the current plan",
        2,
        json!({
            "expected_confirm_digest": expected,
            "received_confirm_digest": received,
            "hardware_access_started": false,
        }),
    );
    error.suggested_actions.push(SuggestedAction::new(
        "review_openocd_hardware_watchpoint_plan",
        json!({"command": "openocd watchpoint plan"}),
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

    const OPENOCD_HELPER_ROLE: &str = "EMBEDDED_DEBUGGER_WATCHPOINT_OPENOCD_HELPER_ROLE";
    const ADDRESS: Address = Address(0x3fcd_b550);
    const EMPTY_BREAKPOINT_TABLE: &str = concat!(
        "BreakpointTable={nr_rows=\"0\",nr_cols=\"6\",hdr=[",
        "{width=\"3\",alignment=\"-1\",col_name=\"number\",colhdr=\"Num\"},",
        "{width=\"14\",alignment=\"-1\",col_name=\"type\",colhdr=\"Type\"},",
        "{width=\"4\",alignment=\"-1\",col_name=\"disp\",colhdr=\"Disp\"},",
        "{width=\"3\",alignment=\"-1\",col_name=\"enabled\",colhdr=\"Enb\"},",
        "{width=\"18\",alignment=\"-1\",col_name=\"addr\",colhdr=\"Address\"},",
        "{width=\"40\",alignment=\"2\",col_name=\"what\",colhdr=\"What\"}],body=[]}",
    );
    const ACCESS_WATCHPOINT_TABLE: &str = concat!(
        "BreakpointTable={nr_rows=\"1\",nr_cols=\"6\",hdr=[",
        "{width=\"3\",alignment=\"-1\",col_name=\"number\",colhdr=\"Num\"},",
        "{width=\"14\",alignment=\"-1\",col_name=\"type\",colhdr=\"Type\"},",
        "{width=\"4\",alignment=\"-1\",col_name=\"disp\",colhdr=\"Disp\"},",
        "{width=\"3\",alignment=\"-1\",col_name=\"enabled\",colhdr=\"Enb\"},",
        "{width=\"18\",alignment=\"-1\",col_name=\"addr\",colhdr=\"Address\"},",
        "{width=\"40\",alignment=\"2\",col_name=\"what\",colhdr=\"What\"}],",
        "body=[bkpt={number=\"1\",type=\"acc watchpoint\",disp=\"keep\",enabled=\"y\",",
        "what=\"*((char*)0x3fcdb550)@4\",thread-groups=[\"i1\"],times=\"0\",",
        "original-location=\"*((char*)0x3fcdb550)@4\"}]}",
    );
    const MALFORMED_WATCHPOINT_TABLE: &str = concat!(
        "BreakpointTable={nr_rows=\"1\",nr_cols=\"6\",hdr=[",
        "{width=\"3\",alignment=\"-1\",col_name=\"number\",colhdr=\"Num\"},",
        "{width=\"14\",alignment=\"-1\",col_name=\"type\",colhdr=\"Type\"},",
        "{width=\"4\",alignment=\"-1\",col_name=\"disp\",colhdr=\"Disp\"},",
        "{width=\"3\",alignment=\"-1\",col_name=\"enabled\",colhdr=\"Enb\"},",
        "{width=\"18\",alignment=\"-1\",col_name=\"addr\",colhdr=\"Address\"},",
        "{width=\"40\",alignment=\"2\",col_name=\"what\",colhdr=\"What\"}],",
        "body=[bkpt={number=\"1\",type=\"watchpoint\",disp=\"keep\",enabled=\"y\",",
        "what=\"*((char*)0x3fcdb550)@4\",times=\"0\",",
        "original-location=\"*((char*)0x3fcdb550)@4\"}]}",
    );

    #[test]
    fn invalid_watchpoint_ranges_fail_before_session_inputs_are_inspected() {
        let mut options = missing_options();
        options.region_kind = MemoryRegionKind::Nvm;
        let error = plan_hardware_watchpoint(&options).unwrap_err();
        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert_eq!(error.details["region_kind"], "nvm");

        options = missing_options();
        options.address = Address(0);
        let error = plan_hardware_watchpoint(&options).unwrap_err();
        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert_eq!(error.details["address"], "0x00000000");

        options = missing_options();
        options.length_bytes = 3;
        let error = plan_hardware_watchpoint(&options).unwrap_err();
        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert_eq!(error.details["length_bytes"], 3);

        options = missing_options();
        options.address = Address(ADDRESS.0 + 2);
        let error = plan_hardware_watchpoint(&options).unwrap_err();
        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert_eq!(error.details["required_alignment_bytes"], 4);

        options = missing_options();
        options.region_length_bytes = 0;
        let error = plan_hardware_watchpoint(&options).unwrap_err();
        assert_eq!(error.code, ErrorCode::ConfigInvalid);

        options = missing_options();
        options.region_start = Address(ADDRESS.0 + 4);
        let error = plan_hardware_watchpoint(&options).unwrap_err();
        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert_eq!(error.details["requested_address"], "0x3FCDB550");
    }

    #[test]
    fn watchpoint_plan_is_deterministic_and_binds_range_mode_and_read_effect() {
        let directory = tempdir().unwrap();
        let first = plan_hardware_watchpoint(&test_options(directory.path(), "success")).unwrap();
        let second = plan_hardware_watchpoint(&test_options(directory.path(), "success")).unwrap();

        assert_eq!(first.confirm_digest, second.confirm_digest);
        assert_eq!(first.risk, "R2_DEVICE_WRITE");
        assert_eq!(first.protocol.commands.len(), 9);
        assert_eq!(first.protocol.commands[2].command, "-gdb-set language c");
        assert_eq!(
            first.protocol.commands[3].command,
            "-break-watch -a *((char*)0x3fcdb550)@4"
        );
        assert_eq!(first.watchpoint_policy.requested_address, ADDRESS);
        assert_eq!(first.watchpoint_policy.requested_length_bytes, 4);
        assert_eq!(
            first.watchpoint_policy.mode,
            OpenOcdHardwareWatchpointMode::Access
        );
        assert!(
            first
                .watchpoint_policy
                .expression_evaluation_may_read_declared_ram
        );
        assert!(!first.watchpoint_policy.write_only_mode_supported);
        assert!(first.watchpoint_policy.hardware_only_by_gdb_semantics);
        assert!(!first.watchpoint_policy.watchpoint_hit_requested);
        assert!(first.effects.expression_evaluation_memory_read_possible);
        assert!(!first.confirmation_boundary.target_ram_semantics_bound);
        assert!(
            !first
                .confirmation_boundary
                .physical_comparator_allocation_bound
        );

        let mut changed_options = test_options(directory.path(), "success");
        changed_options.mode = OpenOcdHardwareWatchpointMode::Read;
        let changed = plan_hardware_watchpoint(&changed_options).unwrap();
        assert_ne!(first.confirm_digest, changed.confirm_digest);
    }

    #[test]
    fn controlled_watchpoint_roundtrip_proves_classification_empty_table_and_restoration() {
        let directory = tempdir().unwrap();
        let options = test_options(directory.path(), "success");
        let plan = plan_hardware_watchpoint(&options).unwrap();
        let report = test_hardware_watchpoint(&options, &plan.confirm_digest).unwrap();

        assert!(report.complete);
        assert_eq!(report.exchange.roundtrip.inserted.result_field, "hw-awpt");
        assert_eq!(
            report
                .exchange
                .roundtrip
                .table_before_delete
                .watchpoint
                .breakpoint_type,
            "acc watchpoint"
        );
        assert!(
            report
                .exchange
                .roundtrip
                .gdb_hardware_classification_verified
        );
        assert!(report.exchange.roundtrip.gdb_breakpoint_table_empty);
        assert!(report.exchange.roundtrip.table_after_delete.empty);
        assert!(
            !report
                .exchange
                .roundtrip
                .physical_comparator_allocation_independently_verified
        );
        assert_eq!(report.target_restoration.initial.state, "running");
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
    fn malformed_classification_runs_fixed_cleanup_without_additional_tcl_resume() {
        let directory = tempdir().unwrap();
        let options = test_options(directory.path(), "malformed_classification");
        let plan = plan_hardware_watchpoint(&options).unwrap();
        let error = test_hardware_watchpoint(&options, &plan.confirm_digest).unwrap_err();

        assert_eq!(error.code, ErrorCode::ProtocolError);
        assert_eq!(error.details["watchpoint_cleanup"]["attempted"], true);
        assert_eq!(
            error.details["watchpoint_cleanup"]["gdb_breakpoint_table_empty"],
            true
        );
        assert_eq!(error.details["watchpoint_cleanup"]["complete"], true);
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
        assert_eq!(error.details["openocd_shutdown"]["graceful"], true);
    }

    #[test]
    fn managed_watchpoint_openocd_helper() {
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
                    let state = if mode == "malformed_classification" && state_queries > 1 {
                        b"halted\x1a".as_slice()
                    } else {
                        b"running\x1a".as_slice()
                    };
                    stream.write_all(state).unwrap();
                }
                b"targets fake.cpu0; resume" if mode == "malformed_classification" => {
                    panic!("failure path sent a forbidden Tcl resume")
                }
                b"targets fake.cpu0; resume" => stream.write_all(b"\x1a").unwrap(),
                b"shutdown" => break,
                _ => stream.write_all(b"unknown command\x1a").unwrap(),
            }
        }
        drop(gdb);
    }

    fn missing_options() -> OpenOcdHardwareWatchpointOptions {
        OpenOcdHardwareWatchpointOptions {
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
            address: ADDRESS,
            length_bytes: 4,
            region_start: Address(0x3fcd_0000),
            region_length_bytes: 0x1_0000,
            region_kind: MemoryRegionKind::Ram,
            mode: OpenOcdHardwareWatchpointMode::Access,
        }
    }

    fn test_options(directory: &Path, mode: &str) -> OpenOcdHardwareWatchpointOptions {
        let openocd = write_fake_openocd(directory, mode);
        let gdb = write_fake_gdb(directory, mode);
        let config = directory.join(format!("board-{mode}.cfg"));
        fs::write(&config, b"adapter speed 1000\n").unwrap();
        let mut options = missing_options();
        options.session.openocd.executable = openocd;
        options.session.openocd.config_files = vec![config];
        options.session.openocd.search_dirs = vec![directory.to_path_buf()];
        options.session.openocd.version_timeout_ms = 5_000;
        options.session.openocd.startup_timeout_ms = 5_000;
        options.session.openocd.shutdown_timeout_ms = 5_000;
        options.session.gdb_executable = gdb;
        options.session.gdb_version_timeout_ms = 5_000;
        options.session.gdb_startup_timeout_ms = 5_000;
        options.session.gdb_command_timeout_ms = 5_000;
        options.session.gdb_shutdown_timeout_ms = 5_000;
        options.session.target_state_timeout_ms = 5_000;
        options
    }

    fn write_fake_openocd(directory: &Path, mode: &str) -> PathBuf {
        let current_exe = std::env::current_exe().unwrap();
        let helper = "backend::openocd::watchpoint::tests::managed_watchpoint_openocd_helper";
        write_helper_wrapper(
            directory,
            &format!("fake-watchpoint-openocd-{mode}"),
            OPENOCD_HELPER_ROLE,
            mode,
            &current_exe,
            helper,
            "Open On-Chip Debugger 0.12.0-test",
        )
    }

    fn write_fake_gdb(directory: &Path, mode: &str) -> PathBuf {
        let table = if mode == "malformed_classification" {
            MALFORMED_WATCHPOINT_TABLE
        } else {
            ACCESS_WATCHPOINT_TABLE
        };
        let expression = "*((char*)0x3fcdb550)@4";
        #[cfg(windows)]
        {
            let executable = directory.join(format!("fake-watchpoint-gdb-{mode}.cmd"));
            let prompt = batch_escape("(gdb)");
            let insert_result = batch_escape_mi(&format!(
                "4^done,hw-awpt={{number=\"1\",exp=\"{expression}\"}}"
            ));
            let list_result = batch_escape_mi(&format!("5^done,{table}"));
            let empty_after_delete = batch_escape_mi(&format!("7^done,{EMPTY_BREAKPOINT_TABLE}"));
            let empty_after_cleanup = batch_escape_mi(&format!("11^done,{EMPTY_BREAKPOINT_TABLE}"));
            let lifecycle = if mode == "malformed_classification" {
                format!(
                    "set /p cleanup_delete=\r\nif not \"%cleanup_delete%\"==\"10-break-delete 1\" exit /b 10\r\necho 10^^done\r\necho {prompt}\r\nset /p cleanup_list=\r\nif not \"%cleanup_list%\"==\"11-break-list\" exit /b 11\r\necho {empty_after_cleanup}\r\necho {prompt}\r\nset /p cleanup_detach=\r\nif not \"%cleanup_detach%\"==\"12-target-detach\" exit /b 12\r\necho 12^^done\r\necho {prompt}\r\n"
                )
            } else {
                format!(
                    "set /p delete=\r\nif not \"%delete%\"==\"6-break-delete 1\" exit /b 10\r\necho 6^^done\r\necho {prompt}\r\nset /p list_after=\r\nif not \"%list_after%\"==\"7-break-list\" exit /b 11\r\necho {empty_after_delete}\r\necho {prompt}\r\nset /p detach=\r\nif not \"%detach%\"==\"8-target-detach\" exit /b 12\r\necho 8^^done\r\necho {prompt}\r\n"
                )
            };
            fs::write(
                &executable,
                format!(
                    "@echo off\r\nif \"%1\"==\"--version\" goto version\r\nif defined XTENSA_GNU_CONFIG exit /b 2\r\necho {prompt}\r\nset /p first=\r\nif not \"%first%\"==\"1-gdb-version\" exit /b 3\r\necho ~\"GNU gdb 17.1-test\\n\"\r\necho 1^^done\r\necho {prompt}\r\nset /p second=\r\nif not \"%second:~0,23%\"==\"2-target-select remote \" exit /b 4\r\necho *stopped,reason=\"signal-received\"\r\necho 2^^connected\r\necho {prompt}\r\nset /p language=\r\nif not \"%language%\"==\"3-gdb-set language c\" exit /b 5\r\necho 3^^done\r\necho {prompt}\r\nset /p insert=\r\nif not \"%insert:~0,17%\"==\"4-break-watch -a \" exit /b 6\r\necho {insert_result}\r\necho {prompt}\r\nset /p list_before=\r\nif not \"%list_before%\"==\"5-break-list\" exit /b 7\r\necho {list_result}\r\necho {prompt}\r\n{lifecycle}set /p exit_command=\r\nif not \"%exit_command%\"==\"9-gdb-exit\" exit /b 13\r\necho 9^^exit\r\nexit /b 0\r\n:version\r\necho GNU gdb 17.1-test\r\nexit /b 0\r\n"
                ),
            )
            .unwrap();
            executable
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let executable = directory.join(format!("fake-watchpoint-gdb-{mode}"));
            let lifecycle = if mode == "malformed_classification" {
                format!(
                    "IFS= read -r cleanup_delete\n[ \"$cleanup_delete\" = '10-break-delete 1' ] || exit 10\nprintf '%s\\n' '10^done' '(gdb)'\nIFS= read -r cleanup_list\n[ \"$cleanup_list\" = '11-break-list' ] || exit 11\nprintf '%s\\n' '11^done,{EMPTY_BREAKPOINT_TABLE}' '(gdb)'\nIFS= read -r cleanup_detach\n[ \"$cleanup_detach\" = '12-target-detach' ] || exit 12\nprintf '%s\\n' '12^done' '(gdb)'\n"
                )
            } else {
                format!(
                    "IFS= read -r delete\n[ \"$delete\" = '6-break-delete 1' ] || exit 10\nprintf '%s\\n' '6^done' '(gdb)'\nIFS= read -r list_after\n[ \"$list_after\" = '7-break-list' ] || exit 11\nprintf '%s\\n' '7^done,{EMPTY_BREAKPOINT_TABLE}' '(gdb)'\nIFS= read -r detach\n[ \"$detach\" = '8-target-detach' ] || exit 12\nprintf '%s\\n' '8^done' '(gdb)'\n"
                )
            };
            fs::write(
                &executable,
                format!(
                    "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  printf '%s\\n' 'GNU gdb 17.1-test'\n  exit 0\nfi\n[ -z \"${{XTENSA_GNU_CONFIG+x}}\" ] || exit 2\nprintf '%s\\n' '(gdb)'\nIFS= read -r first\n[ \"$first\" = '1-gdb-version' ] || exit 3\nprintf '%s\\n' '~\"GNU gdb 17.1-test\\n\"' '1^done' '(gdb)'\nIFS= read -r second\ncase \"$second\" in '2-target-select remote 127.0.0.1:'*) ;; *) exit 4 ;; esac\nprintf '%s\\n' '*stopped,reason=\"signal-received\"' '2^connected' '(gdb)'\nIFS= read -r language\n[ \"$language\" = '3-gdb-set language c' ] || exit 5\nprintf '%s\\n' '3^done' '(gdb)'\nIFS= read -r insert\n[ \"$insert\" = '4-break-watch -a {expression}' ] || exit 6\nprintf '%s\\n' '4^done,hw-awpt={{number=\"1\",exp=\"{expression}\"}}' '(gdb)'\nIFS= read -r list_before\n[ \"$list_before\" = '5-break-list' ] || exit 7\nprintf '%s\\n' '5^done,{table}' '(gdb)'\n{lifecycle}IFS= read -r exit_command\n[ \"$exit_command\" = '9-gdb-exit' ] || exit 13\nprintf '%s\\n' '9^exit'\n"
                ),
            )
            .unwrap();
            let mut permissions = fs::metadata(&executable).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&executable, permissions).unwrap();
            executable
        }
    }

    #[cfg(windows)]
    fn batch_escape(value: &str) -> String {
        value
            .replace('^', "^^")
            .replace('(', "^(")
            .replace(')', "^)")
    }

    #[cfg(windows)]
    fn batch_escape_mi(value: &str) -> String {
        value.replace('^', "^^")
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
