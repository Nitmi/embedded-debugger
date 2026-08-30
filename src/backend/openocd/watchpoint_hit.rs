use std::time::Duration;

use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{
    GdbMiCommandResult, GdbMiHandshake, GdbMiHardwareWatchpointHitRoundtrip, GdbMiOutput,
    GdbMiPlannedCommand, GdbMiProtocol, GdbMiShutdown, OpenOcdHardwareWatchpointOptions,
    OpenOcdHardwareWatchpointPolicy, OpenOcdServerLogs, OpenOcdServerPlan, OpenOcdServerReadiness,
    OpenOcdServerShutdown, OpenOcdSessionGdbPlan, OpenOcdSessionServerPlan,
    OpenOcdTargetRestoration, OpenOcdTargetStatePolicy,
    gdb::{
        RemoteWatchpointHitRequest, execute_remote_watchpoint_hit,
        watchpoint_hit_failure_cleanup_contract, watchpoint_hit_protocol_contract,
    },
    plan_hardware_watchpoint,
    server::start_managed_server,
    session::{observe_initial_target, restore_running_target, with_server_context},
};
use crate::{
    SCHEMA_VERSION,
    error::{DebugError, ErrorCode, Result, SuggestedAction},
    model::Address,
};

pub const DEFAULT_OPENOCD_WATCHPOINT_HIT_TIMEOUT_MS: u64 = 10_000;
pub const MIN_OPENOCD_WATCHPOINT_HIT_TIMEOUT_MS: u64 = 100;
pub const MAX_OPENOCD_WATCHPOINT_HIT_TIMEOUT_MS: u64 = 60_000;
pub const MAX_OPENOCD_WATCHPOINT_EXPECTED_PC_LENGTH_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenOcdHardwareWatchpointHitOptions {
    pub watchpoint: OpenOcdHardwareWatchpointOptions,
    pub expected_pc_start: Address,
    pub expected_pc_length_bytes: u64,
    pub hit_timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdHardwareWatchpointHitPlan {
    pub backend: String,
    pub operation: String,
    pub risk: String,
    pub complete: bool,
    pub openocd: OpenOcdSessionServerPlan,
    pub gdb: OpenOcdSessionGdbPlan,
    pub protocol: GdbMiProtocol,
    pub watchpoint_policy: OpenOcdHardwareWatchpointPolicy,
    pub hit_policy: OpenOcdHardwareWatchpointHitPolicy,
    pub target_state_policy: OpenOcdTargetStatePolicy,
    pub effects: OpenOcdHardwareWatchpointHitEffects,
    pub confirmation_boundary: OpenOcdHardwareWatchpointHitConfirmationBoundary,
    pub confirm_digest: String,
    #[serde(skip)]
    openocd_execution_plan: OpenOcdServerPlan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdHardwareWatchpointHitPolicy {
    pub expected_pc_start: Address,
    pub expected_pc_length_bytes: u64,
    pub expected_pc_end_exclusive: Address,
    pub maximum_expected_pc_length_bytes: u64,
    pub expected_pc_semantics_verified: bool,
    pub runtime_firmware_identity_verified: bool,
    pub hit_timeout_ms: u64,
    pub minimum_hit_timeout_ms: u64,
    pub maximum_hit_timeout_ms: u64,
    pub asynchronous_execution_required: bool,
    pub all_stop_required: bool,
    pub exactly_one_continue_requested: bool,
    pub automatic_retry_allowed: bool,
    pub continue_command: String,
    pub expected_continue_result_class: String,
    pub expected_continue_token: u64,
    pub expected_stop_reason: String,
    pub expected_stop_tuple: String,
    pub expected_watchpoint_number: u64,
    pub expected_expression: String,
    pub accepted_value_tuple_shapes: Vec<Vec<String>>,
    pub stop_requirements: Vec<String>,
    pub post_hit_table_command: String,
    pub expected_post_hit_count: u64,
    pub deletion_command: String,
    pub deletion_verification_command: String,
    pub failure_cleanup_commands: Vec<GdbMiPlannedCommand>,
    pub failure_interrupt_condition: String,
    pub cleanup_retry_allowed: bool,
    pub physical_comparator_hit_verified_by_success: bool,
    pub physical_comparator_state_independently_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdHardwareWatchpointHitEffects {
    pub configuration_tcl_execution_required: bool,
    pub adapter_or_target_access_possible_from_configuration: bool,
    pub reset_or_device_write_possible_from_configuration: bool,
    pub arbitrary_host_command_execution_possible_from_configuration: bool,
    pub remote_gdb_attach_requested: bool,
    pub target_halt_possible_on_attach: bool,
    pub openocd_attach_handler_flash_probe_possible: bool,
    pub openocd_attach_handler_reset_possible: bool,
    pub expression_evaluation_memory_read_possible: bool,
    pub target_execution_while_watchpoint_installed_requested: bool,
    pub hardware_watchpoint_hit_requested: bool,
    pub exactly_one_continue_requested: bool,
    pub bounded_wait_requested: bool,
    pub timeout_interrupt_requested_when_execution_may_continue: bool,
    pub hardware_watchpoint_delete_requested: bool,
    pub breakpoint_table_read_requested: bool,
    pub detach_resume_requested_on_verified_success: bool,
    pub fixed_resume_fallback_possible_on_verified_success: bool,
    pub failure_cleanup_gdb_detach_requested: bool,
    pub target_resume_possible_during_failure_cleanup: bool,
    pub explicit_openocd_resume_after_gdb_failure: bool,
    pub memory_write_command_requested: bool,
    pub flash_command_requested: bool,
    pub arbitrary_gdb_or_monitor_command_requested: bool,
    pub symbol_or_executable_loading_requested: bool,
    pub gdb_xtensa_target_configuration_requested: bool,
    pub gdb_xtensa_target_configuration_native_code_execution_possible: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdHardwareWatchpointHitConfirmationBoundary {
    pub complete_session_plan_bound: bool,
    pub openocd_executable_file_hash_bound: bool,
    pub openocd_version_bound: bool,
    pub top_level_configuration_hashes_bound: bool,
    pub search_directory_paths_bound: bool,
    pub search_directory_contents_bound: bool,
    pub transitive_sources_bound: bool,
    pub gdb_executable_file_hash_bound: bool,
    pub gdb_version_bound: bool,
    pub gdb_xtensa_config_selection_and_hash_bound: bool,
    pub exact_watchpoint_range_and_mode_bound: bool,
    pub declared_ram_region_bound: bool,
    pub exact_expected_pc_interval_bound: bool,
    pub expected_pc_semantics_bound: bool,
    pub runtime_firmware_identity_bound: bool,
    pub fixed_success_protocol_bound: bool,
    pub fixed_failure_protocol_bound: bool,
    pub async_token_and_stop_parser_bound: bool,
    pub exact_hit_timeout_bound: bool,
    pub no_retry_policy_bound: bool,
    pub target_state_policy_bound: bool,
    pub expected_target_name_bound: bool,
    pub lifecycle_deadlines_bound: bool,
    pub loopback_dynamic_endpoint_policy_bound: bool,
    pub runtime_port_number_bound: bool,
    pub runtime_adapter_identity_bound: bool,
    pub target_ram_semantics_bound: bool,
    pub physical_comparator_state_bound: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdHardwareWatchpointHitTestReport {
    pub backend: String,
    pub scope: String,
    pub risk: String,
    pub complete: bool,
    pub confirm_digest: String,
    pub openocd: OpenOcdSessionServerPlan,
    pub gdb: OpenOcdSessionGdbPlan,
    pub protocol: GdbMiProtocol,
    pub watchpoint_policy: OpenOcdHardwareWatchpointPolicy,
    pub hit_policy: OpenOcdHardwareWatchpointHitPolicy,
    pub target_state_policy: OpenOcdTargetStatePolicy,
    pub readiness: OpenOcdServerReadiness,
    pub target_restoration: OpenOcdTargetRestoration,
    pub exchange: OpenOcdHardwareWatchpointHitExchange,
    pub openocd_shutdown: OpenOcdServerShutdown,
    pub openocd_logs: OpenOcdServerLogs,
    pub effects: OpenOcdHardwareWatchpointHitEffects,
    pub confirmation_boundary: OpenOcdHardwareWatchpointHitConfirmationBoundary,
    pub capabilities: OpenOcdHardwareWatchpointHitCapabilities,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdHardwareWatchpointHitExchange {
    pub endpoint: String,
    pub handshake: GdbMiHandshake,
    pub asynchronous_execution: GdbMiCommandResult,
    pub all_stop: GdbMiCommandResult,
    pub connection: GdbMiCommandResult,
    pub language: GdbMiCommandResult,
    pub insert: GdbMiCommandResult,
    pub list_before_continue: GdbMiCommandResult,
    pub continue_execution: GdbMiCommandResult,
    pub hit_wait_elapsed_ms: u64,
    pub list_after_hit: GdbMiCommandResult,
    pub delete: GdbMiCommandResult,
    pub list_after_delete: GdbMiCommandResult,
    pub roundtrip: GdbMiHardwareWatchpointHitRoundtrip,
    pub detach: GdbMiCommandResult,
    pub shutdown: GdbMiShutdown,
    pub output: GdbMiOutput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdHardwareWatchpointHitCapabilities {
    pub server_launch: bool,
    pub gdb_mi: bool,
    pub remote_target_connection: bool,
    pub asynchronous_execution: bool,
    pub all_stop_execution: bool,
    pub temporary_hardware_read_watchpoint_hit: bool,
    pub temporary_hardware_access_watchpoint_hit: bool,
    pub exact_pc_interval_verification: bool,
    pub bounded_timeout_interrupt: bool,
    pub verified_gdb_table_cleanup: bool,
    pub target_state_restoration: bool,
    pub automatic_retry: bool,
    pub persistent_watchpoints: bool,
    pub write_only_watchpoints: bool,
    pub arbitrary_commands: bool,
    pub flash: bool,
}

#[derive(Debug, Serialize)]
struct WatchpointHitConfirmationInput<'a> {
    schema_version: &'static str,
    operation: &'static str,
    backend: &'static str,
    base_watchpoint_confirm_digest: &'a str,
    protocol: &'a GdbMiProtocol,
    watchpoint_policy: &'a OpenOcdHardwareWatchpointPolicy,
    hit_policy: &'a OpenOcdHardwareWatchpointHitPolicy,
    target_state_policy: &'a OpenOcdTargetStatePolicy,
    effects: &'a OpenOcdHardwareWatchpointHitEffects,
    confirmation_boundary: &'a OpenOcdHardwareWatchpointHitConfirmationBoundary,
}

pub fn plan_hardware_watchpoint_hit(
    options: &OpenOcdHardwareWatchpointHitOptions,
) -> Result<OpenOcdHardwareWatchpointHitPlan> {
    let expected_pc_end_exclusive = validate_hit_options(options)?;
    let base = plan_hardware_watchpoint(&options.watchpoint)?;
    let protocol = watchpoint_hit_protocol_contract(
        options.watchpoint.address,
        options.watchpoint.length_bytes,
        options.watchpoint.mode,
    );
    let mut target_state_policy = base.target_state_policy;
    target_state_policy.normal_restoration_command = "12-target-detach".to_string();
    target_state_policy.normal_restoration_expected_effect =
        "resume only after one correlated watchpoint stop, times=1, fixed deletion, and an empty GDB table"
            .to_string();
    target_state_policy.fallback_condition =
        "only on an otherwise successful hit and cleanup when running is not proven after GDB detach"
            .to_string();

    let hit_policy = hit_policy(options, expected_pc_end_exclusive, &base.watchpoint_policy);
    let effects = hit_effects(base.gdb.xtensa_config.is_some());
    let confirmation_boundary = hit_confirmation_boundary();
    let confirmation = WatchpointHitConfirmationInput {
        schema_version: SCHEMA_VERSION,
        operation: "openocd.watchpoint.hit.test",
        backend: "openocd",
        base_watchpoint_confirm_digest: &base.confirm_digest,
        protocol: &protocol,
        watchpoint_policy: &base.watchpoint_policy,
        hit_policy: &hit_policy,
        target_state_policy: &target_state_policy,
        effects: &effects,
        confirmation_boundary: &confirmation_boundary,
    };
    let confirm_digest = hex::encode(Sha256::digest(
        serde_json::to_vec(&confirmation)
            .expect("hardware-watchpoint hit confirmation input always serializes"),
    ));

    Ok(OpenOcdHardwareWatchpointHitPlan {
        backend: "openocd".to_string(),
        operation: "openocd.watchpoint.hit.test".to_string(),
        risk: "R2_DEVICE_WRITE".to_string(),
        complete: true,
        openocd: base.openocd,
        gdb: base.gdb,
        protocol,
        watchpoint_policy: base.watchpoint_policy,
        hit_policy,
        target_state_policy,
        effects,
        confirmation_boundary,
        confirm_digest,
        openocd_execution_plan: base.openocd_execution_plan,
    })
}

pub fn test_hardware_watchpoint_hit(
    options: &OpenOcdHardwareWatchpointHitOptions,
    confirm_digest: &str,
) -> Result<OpenOcdHardwareWatchpointHitTestReport> {
    let plan = plan_hardware_watchpoint_hit(options)?;
    if plan.confirm_digest != confirm_digest {
        return Err(hit_confirmation_error(&plan.confirm_digest, confirm_digest));
    }
    execute_hit_plan(plan)
}

fn execute_hit_plan(
    plan: OpenOcdHardwareWatchpointHitPlan,
) -> Result<OpenOcdHardwareWatchpointHitTestReport> {
    let server = start_managed_server(&plan.openocd_execution_plan)?;
    let initial = match observe_initial_target(&server, plan.target_state_policy.timeout_ms) {
        Ok(observation) => observation,
        Err(error) => return Err(with_server_context(error, server.finish(), None)),
    };
    if initial.target_name != plan.target_state_policy.expected_current_target {
        let error = DebugError::verification(
            "OpenOCD current target did not match the confirmed watchpoint-hit target",
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
            "OpenOCD current target was not running before watchpoint-hit attachment",
            json!({
                "initial_observation": initial,
                "required_initial_state": plan.target_state_policy.initial_state_required,
                "remote_gdb_started": false,
            }),
        );
        return Err(with_server_context(error, server.finish(), None));
    }

    let result = execute_remote_watchpoint_hit(
        &plan.gdb.executable.resolved,
        plan.gdb
            .xtensa_config
            .as_ref()
            .map(|config| config.resolved.as_str()),
        server.readiness().gdb_port,
        RemoteWatchpointHitRequest {
            address: plan.watchpoint_policy.requested_address,
            length_bytes: plan.watchpoint_policy.requested_length_bytes,
            mode: plan.watchpoint_policy.mode,
            expected_pc_start: plan.hit_policy.expected_pc_start,
            expected_pc_end_exclusive: plan.hit_policy.expected_pc_end_exclusive,
            hit_timeout_ms: plan.hit_policy.hit_timeout_ms,
        },
        plan.gdb.startup_timeout_ms,
        plan.gdb.command_timeout_ms,
        plan.gdb.shutdown_timeout_ms,
    );
    let execution = match result {
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
                    "reason": "watchpoint-hit protocol or cleanup was not fully proven",
                    "manual_recovery_may_be_required": true,
                    "automatic_retry_allowed": false,
                }),
            );
            gdb_error.details = Value::Object(details);
            return Err(with_server_context(gdb_error, server.finish(), None));
        }
    };

    let restoration = restore_running_target(&server, initial, plan.target_state_policy.timeout_ms);
    let completion = server.finish();
    let exchange = OpenOcdHardwareWatchpointHitExchange {
        endpoint: execution.endpoint.clone(),
        handshake: GdbMiHandshake {
            startup_prompt_observed: true,
            startup_elapsed_ms: duration_ms(execution.startup_elapsed),
            startup_timeout_ms: plan.gdb.startup_timeout_ms,
            version_command: command_result(
                1,
                "-gdb-version",
                execution.version_result_class,
                execution.version_elapsed,
            ),
            version_stream_records: execution.version_stream_records,
            record_counts: execution.record_counts,
        },
        asynchronous_execution: command_result(
            2,
            "-gdb-set mi-async on",
            execution.async_result_class,
            execution.async_elapsed,
        ),
        all_stop: command_result(
            3,
            "-gdb-set non-stop off",
            execution.all_stop_result_class,
            execution.all_stop_elapsed,
        ),
        connection: command_result(
            4,
            &format!("-target-select remote {}", execution.endpoint),
            execution.connect_result_class,
            execution.connect_elapsed,
        ),
        language: command_result(
            5,
            "-gdb-set language c",
            execution.language_result_class,
            execution.language_elapsed,
        ),
        insert: command_result(
            6,
            &execution.insert_command,
            execution.insert_result_class,
            execution.insert_elapsed,
        ),
        list_before_continue: command_result(
            7,
            "-break-list",
            execution.list_before_continue_result_class,
            execution.list_before_continue_elapsed,
        ),
        continue_execution: command_result(
            8,
            "-exec-continue --all",
            execution.continue_result_class,
            execution.continue_elapsed,
        ),
        hit_wait_elapsed_ms: duration_ms(execution.hit_wait_elapsed),
        list_after_hit: command_result(
            9,
            "-break-list",
            execution.list_after_hit_result_class,
            execution.list_after_hit_elapsed,
        ),
        delete: command_result(
            10,
            "-break-delete 1",
            execution.delete_result_class,
            execution.delete_elapsed,
        ),
        list_after_delete: command_result(
            11,
            "-break-list",
            execution.list_after_delete_result_class,
            execution.list_after_delete_elapsed,
        ),
        roundtrip: execution.roundtrip,
        detach: command_result(
            12,
            "-target-detach",
            execution.detach_result_class,
            execution.detach_elapsed,
        ),
        shutdown: execution.shutdown,
        output: execution.output,
    };

    if !restoration.complete {
        let error = DebugError::verification(
            "hardware-watchpoint hit did not prove restoration of the initial running target state",
            json!({"target_restoration": restoration}),
        );
        return Err(with_server_context(error, completion, Some(&restoration)));
    }
    if let Some(message) = completion.lifecycle_error() {
        let error = DebugError::new(
            ErrorCode::ProtocolError,
            message,
            6,
            json!({"target_restoration": restoration, "gdb_exchange": exchange}),
        );
        return Err(with_server_context(error, completion, None));
    }

    Ok(OpenOcdHardwareWatchpointHitTestReport {
        backend: plan.backend,
        scope: "confirmed_bounded_hardware_watchpoint_hit".to_string(),
        risk: plan.risk,
        complete: true,
        confirm_digest: plan.confirm_digest,
        openocd: plan.openocd,
        gdb: plan.gdb,
        protocol: plan.protocol,
        watchpoint_policy: plan.watchpoint_policy,
        hit_policy: plan.hit_policy,
        target_state_policy: plan.target_state_policy,
        readiness: completion.readiness,
        target_restoration: restoration,
        exchange,
        openocd_shutdown: completion.shutdown,
        openocd_logs: completion.logs,
        effects: plan.effects,
        confirmation_boundary: plan.confirmation_boundary,
        capabilities: hit_capabilities(),
    })
}

fn validate_hit_options(options: &OpenOcdHardwareWatchpointHitOptions) -> Result<Address> {
    if options.expected_pc_start.0 == 0 {
        return Err(DebugError::config(
            "OpenOCD watchpoint-hit expected PC start must be non-zero",
            json!({"expected_pc_start": options.expected_pc_start, "minimum": "0x1"}),
        ));
    }
    if !(1..=MAX_OPENOCD_WATCHPOINT_EXPECTED_PC_LENGTH_BYTES)
        .contains(&options.expected_pc_length_bytes)
    {
        return Err(DebugError::config(
            "OpenOCD watchpoint-hit expected PC length is outside the supported range",
            json!({
                "expected_pc_length_bytes": options.expected_pc_length_bytes,
                "minimum": 1,
                "maximum": MAX_OPENOCD_WATCHPOINT_EXPECTED_PC_LENGTH_BYTES,
            }),
        ));
    }
    let end = options
        .expected_pc_start
        .0
        .checked_add(options.expected_pc_length_bytes)
        .ok_or_else(|| {
            DebugError::config(
                "OpenOCD watchpoint-hit expected PC interval overflows the address space",
                json!({
                    "expected_pc_start": options.expected_pc_start,
                    "expected_pc_length_bytes": options.expected_pc_length_bytes,
                }),
            )
        })?;
    if !(MIN_OPENOCD_WATCHPOINT_HIT_TIMEOUT_MS..=MAX_OPENOCD_WATCHPOINT_HIT_TIMEOUT_MS)
        .contains(&options.hit_timeout_ms)
    {
        return Err(DebugError::config(
            "OpenOCD watchpoint-hit timeout is outside the supported range",
            json!({
                "hit_timeout_ms": options.hit_timeout_ms,
                "minimum": MIN_OPENOCD_WATCHPOINT_HIT_TIMEOUT_MS,
                "maximum": MAX_OPENOCD_WATCHPOINT_HIT_TIMEOUT_MS,
            }),
        ));
    }
    Ok(Address(end))
}

fn hit_policy(
    options: &OpenOcdHardwareWatchpointHitOptions,
    expected_pc_end_exclusive: Address,
    watchpoint: &OpenOcdHardwareWatchpointPolicy,
) -> OpenOcdHardwareWatchpointHitPolicy {
    let (reason, tuple, value_shapes) = match watchpoint.mode {
        super::OpenOcdHardwareWatchpointMode::Read => (
            "read-watchpoint-trigger",
            "hw-rwpt",
            vec![vec!["value".to_string()]],
        ),
        super::OpenOcdHardwareWatchpointMode::Access => (
            "access-watchpoint-trigger",
            "hw-awpt",
            vec![
                vec!["new".to_string()],
                vec!["new".to_string(), "old".to_string()],
            ],
        ),
    };
    OpenOcdHardwareWatchpointHitPolicy {
        expected_pc_start: options.expected_pc_start,
        expected_pc_length_bytes: options.expected_pc_length_bytes,
        expected_pc_end_exclusive,
        maximum_expected_pc_length_bytes: MAX_OPENOCD_WATCHPOINT_EXPECTED_PC_LENGTH_BYTES,
        expected_pc_semantics_verified: false,
        runtime_firmware_identity_verified: false,
        hit_timeout_ms: options.hit_timeout_ms,
        minimum_hit_timeout_ms: MIN_OPENOCD_WATCHPOINT_HIT_TIMEOUT_MS,
        maximum_hit_timeout_ms: MAX_OPENOCD_WATCHPOINT_HIT_TIMEOUT_MS,
        asynchronous_execution_required: true,
        all_stop_required: true,
        exactly_one_continue_requested: true,
        automatic_retry_allowed: false,
        continue_command: "8-exec-continue --all".to_string(),
        expected_continue_result_class: "running".to_string(),
        expected_continue_token: 8,
        expected_stop_reason: reason.to_string(),
        expected_stop_tuple: tuple.to_string(),
        expected_watchpoint_number: 1,
        expected_expression: watchpoint.expression.clone(),
        accepted_value_tuple_shapes: value_shapes,
        stop_requirements: vec![
            "one *stopped record correlated while the single continue is outstanding".to_string(),
            "stop token absent, or exactly equal to the fixed continue token when present"
                .to_string(),
            "competing stops and nonmatching stop tokens rejected".to_string(),
            "exact mode-specific reason and hardware tuple".to_string(),
            "number=1 and exact generated expression".to_string(),
            "top frame address inside the confirmed half-open PC interval".to_string(),
            "stopped-threads=all when reported".to_string(),
            "no unsupported top-level, tuple, value, or frame fields".to_string(),
        ],
        post_hit_table_command: "9-break-list".to_string(),
        expected_post_hit_count: 1,
        deletion_command: "10-break-delete 1".to_string(),
        deletion_verification_command: "11-break-list".to_string(),
        failure_cleanup_commands: watchpoint_hit_failure_cleanup_contract(),
        failure_interrupt_condition: "continue was accepted or target execution state is unknown"
            .to_string(),
        cleanup_retry_allowed: false,
        physical_comparator_hit_verified_by_success: true,
        physical_comparator_state_independently_verified: false,
    }
}

fn hit_effects(xtensa_config_selected: bool) -> OpenOcdHardwareWatchpointHitEffects {
    OpenOcdHardwareWatchpointHitEffects {
        configuration_tcl_execution_required: true,
        adapter_or_target_access_possible_from_configuration: true,
        reset_or_device_write_possible_from_configuration: true,
        arbitrary_host_command_execution_possible_from_configuration: true,
        remote_gdb_attach_requested: true,
        target_halt_possible_on_attach: true,
        openocd_attach_handler_flash_probe_possible: true,
        openocd_attach_handler_reset_possible: true,
        expression_evaluation_memory_read_possible: true,
        target_execution_while_watchpoint_installed_requested: true,
        hardware_watchpoint_hit_requested: true,
        exactly_one_continue_requested: true,
        bounded_wait_requested: true,
        timeout_interrupt_requested_when_execution_may_continue: true,
        hardware_watchpoint_delete_requested: true,
        breakpoint_table_read_requested: true,
        detach_resume_requested_on_verified_success: true,
        fixed_resume_fallback_possible_on_verified_success: true,
        failure_cleanup_gdb_detach_requested: true,
        target_resume_possible_during_failure_cleanup: true,
        explicit_openocd_resume_after_gdb_failure: false,
        memory_write_command_requested: false,
        flash_command_requested: false,
        arbitrary_gdb_or_monitor_command_requested: false,
        symbol_or_executable_loading_requested: false,
        gdb_xtensa_target_configuration_requested: xtensa_config_selected,
        gdb_xtensa_target_configuration_native_code_execution_possible: xtensa_config_selected,
        notes: vec![
            "The fixed expression may read the user-declared RAM range during watchpoint creation."
                .to_string(),
            "The target executes while the hardware watchpoint is installed and may perform arbitrary firmware-defined I/O."
                .to_string(),
            "Only one fixed continue is sent; timeout causes one fixed interrupt attempt and never an automatic retry."
                .to_string(),
            "A matching PC interval is runtime provenance, not firmware identity or executable-memory attestation."
                .to_string(),
            "A hit and times=1 prove one GDB-attributed comparator event, not independent comparator-register readback."
                .to_string(),
            "No GDB failure path sends an additional OpenOCD Tcl resume; detach, exit, or configuration handlers may still resume the target."
                .to_string(),
        ],
    }
}

fn hit_confirmation_boundary() -> OpenOcdHardwareWatchpointHitConfirmationBoundary {
    OpenOcdHardwareWatchpointHitConfirmationBoundary {
        complete_session_plan_bound: true,
        openocd_executable_file_hash_bound: true,
        openocd_version_bound: true,
        top_level_configuration_hashes_bound: true,
        search_directory_paths_bound: true,
        search_directory_contents_bound: false,
        transitive_sources_bound: false,
        gdb_executable_file_hash_bound: true,
        gdb_version_bound: true,
        gdb_xtensa_config_selection_and_hash_bound: true,
        exact_watchpoint_range_and_mode_bound: true,
        declared_ram_region_bound: true,
        exact_expected_pc_interval_bound: true,
        expected_pc_semantics_bound: false,
        runtime_firmware_identity_bound: false,
        fixed_success_protocol_bound: true,
        fixed_failure_protocol_bound: true,
        async_token_and_stop_parser_bound: true,
        exact_hit_timeout_bound: true,
        no_retry_policy_bound: true,
        target_state_policy_bound: true,
        expected_target_name_bound: true,
        lifecycle_deadlines_bound: true,
        loopback_dynamic_endpoint_policy_bound: true,
        runtime_port_number_bound: false,
        runtime_adapter_identity_bound: false,
        target_ram_semantics_bound: false,
        physical_comparator_state_bound: false,
    }
}

fn hit_capabilities() -> OpenOcdHardwareWatchpointHitCapabilities {
    OpenOcdHardwareWatchpointHitCapabilities {
        server_launch: true,
        gdb_mi: true,
        remote_target_connection: true,
        asynchronous_execution: true,
        all_stop_execution: true,
        temporary_hardware_read_watchpoint_hit: true,
        temporary_hardware_access_watchpoint_hit: true,
        exact_pc_interval_verification: true,
        bounded_timeout_interrupt: true,
        verified_gdb_table_cleanup: true,
        target_state_restoration: true,
        automatic_retry: false,
        persistent_watchpoints: false,
        write_only_watchpoints: false,
        arbitrary_commands: false,
        flash: false,
    }
}

fn command_result(
    token: u64,
    command: &str,
    result_class: String,
    elapsed: Duration,
) -> GdbMiCommandResult {
    GdbMiCommandResult {
        token,
        command: command.to_string(),
        result_class,
        elapsed_ms: duration_ms(elapsed),
    }
}

fn hit_confirmation_error(expected: &str, received: &str) -> DebugError {
    let mut error = DebugError::new(
        ErrorCode::ConfirmationMismatch,
        "OpenOCD hardware-watchpoint hit confirmation digest does not match the current plan",
        2,
        json!({
            "expected_confirm_digest": expected,
            "received_confirm_digest": received,
            "hardware_access_started": false,
        }),
    );
    error.suggested_actions.push(SuggestedAction::new(
        "review_openocd_hardware_watchpoint_hit_plan",
        json!({"command": "openocd watchpoint hit plan"}),
    ));
    error
}

fn error_value(error: &DebugError) -> Value {
    json!({
        "code": error.code,
        "message": error.message,
        "retryable": error.retryable,
        "details": error.details,
    })
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
    use crate::model::MemoryRegionKind;

    const OPENOCD_HELPER_ROLE: &str = "EMBEDDED_DEBUGGER_WATCHPOINT_HIT_OPENOCD_HELPER_ROLE";
    const ADDRESS: Address = Address(0x3fcd_b550);
    const PC_START: Address = Address(0x4201_28c5);
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
    fn invalid_hit_bounds_fail_before_session_files_are_inspected() {
        let mut options = missing_options();
        options.expected_pc_start = Address(0);
        let error = plan_hardware_watchpoint_hit(&options).unwrap_err();
        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert_eq!(error.details["expected_pc_start"], "0x00000000");

        options = missing_options();
        options.expected_pc_length_bytes = 0;
        let error = plan_hardware_watchpoint_hit(&options).unwrap_err();
        assert_eq!(error.code, ErrorCode::ConfigInvalid);

        options = missing_options();
        options.expected_pc_length_bytes = MAX_OPENOCD_WATCHPOINT_EXPECTED_PC_LENGTH_BYTES + 1;
        let error = plan_hardware_watchpoint_hit(&options).unwrap_err();
        assert_eq!(error.code, ErrorCode::ConfigInvalid);

        options = missing_options();
        options.hit_timeout_ms = MIN_OPENOCD_WATCHPOINT_HIT_TIMEOUT_MS - 1;
        let error = plan_hardware_watchpoint_hit(&options).unwrap_err();
        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert_eq!(error.details["hit_timeout_ms"], 99);
    }

    #[test]
    fn hit_plan_is_deterministic_and_binds_pc_timeout_and_one_continue() {
        let directory = tempdir().unwrap();
        let first =
            plan_hardware_watchpoint_hit(&test_options(directory.path(), "success")).unwrap();
        let second =
            plan_hardware_watchpoint_hit(&test_options(directory.path(), "success")).unwrap();
        assert_eq!(first.confirm_digest, second.confirm_digest);
        assert_eq!(first.operation, "openocd.watchpoint.hit.test");
        assert_eq!(first.protocol.commands.len(), 13);
        assert_eq!(first.protocol.commands[7].command, "-exec-continue --all");
        assert_eq!(
            first
                .protocol
                .commands
                .iter()
                .filter(|command| command.command == "-exec-continue --all")
                .count(),
            1
        );
        assert_eq!(first.hit_policy.expected_pc_start, PC_START);
        assert_eq!(
            first.hit_policy.expected_pc_end_exclusive,
            Address(0x4201_28d0)
        );
        assert_eq!(
            first.hit_policy.expected_stop_reason,
            "access-watchpoint-trigger"
        );
        assert_eq!(first.hit_policy.expected_stop_tuple, "hw-awpt");
        assert!(
            first
                .hit_policy
                .stop_requirements
                .iter()
                .any(|requirement| requirement.contains("stop token absent"))
        );
        assert!(
            first
                .hit_policy
                .stop_requirements
                .iter()
                .any(|requirement| requirement.contains("competing stops"))
        );
        assert!(!first.hit_policy.automatic_retry_allowed);
        assert!(
            first
                .effects
                .target_execution_while_watchpoint_installed_requested
        );
        assert!(!first.confirmation_boundary.runtime_firmware_identity_bound);

        let mut changed = test_options(directory.path(), "success");
        changed.hit_timeout_ms += 1;
        assert_ne!(
            first.confirm_digest,
            plan_hardware_watchpoint_hit(&changed)
                .unwrap()
                .confirm_digest
        );
        changed.hit_timeout_ms -= 1;
        changed.expected_pc_start = Address(PC_START.0 + 1);
        assert_ne!(
            first.confirm_digest,
            plan_hardware_watchpoint_hit(&changed)
                .unwrap()
                .confirm_digest
        );
    }

    #[test]
    fn controlled_immediate_hit_proves_token_pc_count_cleanup_and_restoration() {
        let directory = tempdir().unwrap();
        let options = test_options(directory.path(), "success");
        let plan = plan_hardware_watchpoint_hit(&options).unwrap();
        let report = test_hardware_watchpoint_hit(&options, &plan.confirm_digest).unwrap();

        assert!(report.complete);
        assert_eq!(report.exchange.continue_execution.result_class, "running");
        assert_eq!(report.exchange.roundtrip.hit.continue_token, 8);
        assert_eq!(report.exchange.roundtrip.hit.observed_stop_token, None);
        assert_eq!(
            report.exchange.roundtrip.hit.stop_correlation,
            super::super::GdbMiAsyncStopCorrelation::TokenlessSingleContinue
        );
        assert_eq!(report.exchange.roundtrip.hit.running_notifications, 2);
        assert_eq!(
            report.exchange.roundtrip.hit.stop_reason,
            "access-watchpoint-trigger"
        );
        assert_eq!(report.exchange.roundtrip.hit.result_field, "hw-awpt");
        assert_eq!(
            report.exchange.roundtrip.hit.frame_address,
            Address(0x4201_28cd)
        );
        assert_eq!(
            report
                .exchange
                .roundtrip
                .table_after_hit
                .watchpoint
                .hit_count,
            1
        );
        assert!(report.exchange.roundtrip.table_after_delete.empty);
        assert!(report.exchange.roundtrip.one_correlated_hit_verified);
        assert!(report.exchange.roundtrip.gdb_breakpoint_table_empty);
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
    fn timeout_interrupts_once_then_cleans_without_tcl_resume_or_retry() {
        let directory = tempdir().unwrap();
        let mut options = test_options(directory.path(), "timeout");
        options.hit_timeout_ms = MIN_OPENOCD_WATCHPOINT_HIT_TIMEOUT_MS;
        let plan = plan_hardware_watchpoint_hit(&options).unwrap();
        let error = test_hardware_watchpoint_hit(&options, &plan.confirm_digest).unwrap_err();

        assert_eq!(error.code, ErrorCode::Timeout);
        assert!(!error.retryable);
        assert_eq!(error.details["watchpoint_hit_cleanup"]["attempted"], true);
        assert_eq!(
            error.details["watchpoint_hit_cleanup"]["initial_execution_state"],
            "running_or_unknown"
        );
        assert_eq!(
            error.details["watchpoint_hit_cleanup"]["interrupt"]["complete"],
            true
        );
        assert_eq!(
            error.details["watchpoint_hit_cleanup"]["interrupt"]["token"],
            19
        );
        assert_eq!(
            error.details["watchpoint_hit_cleanup"]["interrupt"]["observed_stop_token"],
            Value::Null
        );
        assert_eq!(
            error.details["watchpoint_hit_cleanup"]["interrupt"]["stop_correlation"],
            "tokenless_single_continue"
        );
        assert_eq!(
            error.details["watchpoint_hit_cleanup"]["gdb_breakpoint_table_empty"],
            true
        );
        assert_eq!(error.details["watchpoint_hit_cleanup"]["complete"], true);
        assert_eq!(error.details["cleanup_detach"]["complete"], true);
        assert_eq!(
            error.details["target_observation_after_gdb_failure"]["state"],
            "halted"
        );
        assert_eq!(
            error.details["target_restoration"]["explicit_openocd_resume_attempted"],
            false
        );
        assert_eq!(
            error.details["target_restoration"]["automatic_retry_allowed"],
            false
        );
        assert_eq!(error.details["shutdown"]["graceful"], true);
        assert_eq!(error.details["openocd_shutdown"]["graceful"], true);
    }

    #[test]
    fn managed_watchpoint_hit_openocd_helper() {
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
                    let state = if mode == "timeout" && state_queries > 1 {
                        b"halted\x1a".as_slice()
                    } else {
                        b"running\x1a".as_slice()
                    };
                    stream.write_all(state).unwrap();
                }
                b"targets fake.cpu0; resume" if mode == "timeout" => {
                    panic!("failure path sent a forbidden Tcl resume")
                }
                b"targets fake.cpu0; resume" => stream.write_all(b"\x1a").unwrap(),
                b"shutdown" => break,
                _ => stream.write_all(b"unknown command\x1a").unwrap(),
            }
        }
        drop(gdb);
    }

    fn missing_options() -> OpenOcdHardwareWatchpointHitOptions {
        OpenOcdHardwareWatchpointHitOptions {
            watchpoint: OpenOcdHardwareWatchpointOptions {
                session: super::super::OpenOcdGdbSessionOptions {
                    openocd: super::super::OpenOcdServerOptions {
                        executable: PathBuf::from("missing-openocd"),
                        config_files: vec![PathBuf::from("missing.cfg")],
                        search_dirs: Vec::new(),
                        version_timeout_ms: super::super::DEFAULT_OPENOCD_VERSION_TIMEOUT_MS,
                        startup_timeout_ms: super::super::DEFAULT_OPENOCD_SERVER_STARTUP_TIMEOUT_MS,
                        shutdown_timeout_ms:
                            super::super::DEFAULT_OPENOCD_SERVER_SHUTDOWN_TIMEOUT_MS,
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
                mode: super::super::OpenOcdHardwareWatchpointMode::Access,
            },
            expected_pc_start: PC_START,
            expected_pc_length_bytes: 11,
            hit_timeout_ms: 500,
        }
    }

    fn test_options(directory: &Path, mode: &str) -> OpenOcdHardwareWatchpointHitOptions {
        let openocd = write_fake_openocd(directory, mode);
        let gdb = write_fake_gdb(directory, mode);
        let config = directory.join(format!("board-{mode}.cfg"));
        fs::write(&config, b"adapter speed 1000\n").unwrap();
        let mut options = missing_options();
        options.watchpoint.session.openocd.executable = openocd;
        options.watchpoint.session.openocd.config_files = vec![config];
        options.watchpoint.session.openocd.search_dirs = vec![directory.to_path_buf()];
        options.watchpoint.session.openocd.version_timeout_ms = 5_000;
        options.watchpoint.session.openocd.startup_timeout_ms = 5_000;
        options.watchpoint.session.openocd.shutdown_timeout_ms = 5_000;
        options.watchpoint.session.gdb_executable = gdb;
        options.watchpoint.session.gdb_version_timeout_ms = 5_000;
        options.watchpoint.session.gdb_startup_timeout_ms = 5_000;
        options.watchpoint.session.gdb_command_timeout_ms = 5_000;
        options.watchpoint.session.gdb_shutdown_timeout_ms = 5_000;
        options.watchpoint.session.target_state_timeout_ms = 5_000;
        options
    }

    fn access_watchpoint_table(hit_count: u64) -> String {
        format!(
            concat!(
                "BreakpointTable={{nr_rows=\"1\",nr_cols=\"6\",hdr=[",
                "{{width=\"3\",alignment=\"-1\",col_name=\"number\",colhdr=\"Num\"}},",
                "{{width=\"14\",alignment=\"-1\",col_name=\"type\",colhdr=\"Type\"}},",
                "{{width=\"4\",alignment=\"-1\",col_name=\"disp\",colhdr=\"Disp\"}},",
                "{{width=\"3\",alignment=\"-1\",col_name=\"enabled\",colhdr=\"Enb\"}},",
                "{{width=\"18\",alignment=\"-1\",col_name=\"addr\",colhdr=\"Address\"}},",
                "{{width=\"40\",alignment=\"2\",col_name=\"what\",colhdr=\"What\"}}],",
                "body=[bkpt={{number=\"1\",type=\"acc watchpoint\",disp=\"keep\",enabled=\"y\",",
                "what=\"*((char*)0x3fcdb550)@4\",thread-groups=[\"i1\"],times=\"{}\",",
                "original-location=\"*((char*)0x3fcdb550)@4\"}}]}}"
            ),
            hit_count
        )
    }

    fn write_fake_openocd(directory: &Path, mode: &str) -> PathBuf {
        let current_exe = std::env::current_exe().unwrap();
        let helper =
            "backend::openocd::watchpoint_hit::tests::managed_watchpoint_hit_openocd_helper";
        write_helper_wrapper(
            directory,
            &format!("fake-watchpoint-hit-openocd-{mode}"),
            OPENOCD_HELPER_ROLE,
            mode,
            &current_exe,
            helper,
            "Open On-Chip Debugger 0.12.0-test",
        )
    }

    fn write_fake_gdb(directory: &Path, mode: &str) -> PathBuf {
        let expression = "*((char*)0x3fcdb550)@4";
        let before = access_watchpoint_table(0);
        let after = access_watchpoint_table(1);
        #[cfg(windows)]
        {
            let executable = directory.join(format!("fake-watchpoint-hit-gdb-{mode}.cmd"));
            let prompt = batch_escape("(gdb)");
            let insert = batch_escape_mi(&format!(
                "6^done,hw-awpt={{number=\"1\",exp=\"{expression}\"}}"
            ));
            let before = batch_escape_mi(&format!("7^done,{before}"));
            let after = batch_escape_mi(&format!("9^done,{after}"));
            let empty_success = batch_escape_mi(&format!("11^done,{EMPTY_BREAKPOINT_TABLE}"));
            let empty_cleanup = batch_escape_mi(&format!("21^done,{EMPTY_BREAKPOINT_TABLE}"));
            let lifecycle = if mode == "timeout" {
                format!(
                    "echo *running,thread-id=\"all\"\r\necho 8^^running\r\necho {prompt}\r\nset /p interrupt=\r\nif not \"%interrupt%\"==\"19-exec-interrupt --all\" exit /b 19\r\necho 19^^done\r\necho {prompt}\r\necho *stopped,reason=\"signal-received\",signal-name=\"SIGINT\",signal-meaning=\"Interrupt\",frame={{addr=\"0x420128cd\",args=[]}},thread-id=\"1\",stopped-threads=\"all\",core=\"0\"\r\necho {prompt}\r\nset /p cleanup_delete=\r\nif not \"%cleanup_delete%\"==\"20-break-delete 1\" exit /b 20\r\necho 20^^done\r\necho {prompt}\r\nset /p cleanup_list=\r\nif not \"%cleanup_list%\"==\"21-break-list\" exit /b 21\r\necho {empty_cleanup}\r\necho {prompt}\r\nset /p cleanup_detach=\r\nif not \"%cleanup_detach%\"==\"22-target-detach\" exit /b 22\r\necho 22^^done\r\necho {prompt}\r\n"
                )
            } else {
                format!(
                    "echo *running,thread-id=\"all\"\r\necho *running,thread-id=\"all\"\r\necho *stopped,reason=\"access-watchpoint-trigger\",hw-awpt={{number=\"1\",exp=\"{expression}\"}},value={{old=\"6\",new=\"7\"}},frame={{addr=\"0x420128cd\",func=\"main\",args=[],file=\"src/bin/main.rs\",line=\"85\",arch=\"xtensa\"}},thread-id=\"1\",stopped-threads=\"all\",core=\"0\"\r\necho 8^^running\r\necho {prompt}\r\nset /p list_after_hit=\r\nif not \"%list_after_hit%\"==\"9-break-list\" exit /b 9\r\necho {after}\r\necho {prompt}\r\nset /p delete=\r\nif not \"%delete%\"==\"10-break-delete 1\" exit /b 10\r\necho 10^^done\r\necho {prompt}\r\nset /p list_empty=\r\nif not \"%list_empty%\"==\"11-break-list\" exit /b 11\r\necho {empty_success}\r\necho {prompt}\r\nset /p detach=\r\nif not \"%detach%\"==\"12-target-detach\" exit /b 12\r\necho 12^^done\r\necho {prompt}\r\n"
                )
            };
            fs::write(
                &executable,
                format!(
                    "@echo off\r\nif \"%1\"==\"--version\" goto version\r\nif defined XTENSA_GNU_CONFIG exit /b 2\r\necho {prompt}\r\nset /p version=\r\nif not \"%version%\"==\"1-gdb-version\" exit /b 1\r\necho ~\"GNU gdb 17.1-test\\n\"\r\necho 1^^done\r\necho {prompt}\r\nset /p async=\r\nif not \"%async%\"==\"2-gdb-set mi-async on\" exit /b 2\r\necho 2^^done\r\necho {prompt}\r\nset /p all_stop=\r\nif not \"%all_stop%\"==\"3-gdb-set non-stop off\" exit /b 3\r\necho 3^^done\r\necho {prompt}\r\nset /p connect=\r\nif not \"%connect:~0,23%\"==\"4-target-select remote \" exit /b 4\r\necho *stopped,reason=\"signal-received\"\r\necho 4^^connected\r\necho {prompt}\r\nset /p language=\r\nif not \"%language%\"==\"5-gdb-set language c\" exit /b 5\r\necho 5^^done\r\necho {prompt}\r\nset /p insert=\r\nif not \"%insert%\"==\"6-break-watch -a {expression}\" exit /b 6\r\necho {insert}\r\necho {prompt}\r\nset /p list_before=\r\nif not \"%list_before%\"==\"7-break-list\" exit /b 7\r\necho {before}\r\necho {prompt}\r\nset /p continue_command=\r\nif not \"%continue_command%\"==\"8-exec-continue --all\" exit /b 8\r\n{lifecycle}set /p exit_command=\r\nif not \"%exit_command%\"==\"13-gdb-exit\" exit /b 13\r\necho 13^^exit\r\nexit /b 0\r\n:version\r\necho GNU gdb 17.1-test\r\nexit /b 0\r\n"
                ),
            )
            .unwrap();
            executable
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let executable = directory.join(format!("fake-watchpoint-hit-gdb-{mode}"));
            let lifecycle = if mode == "timeout" {
                format!(
                    "printf '%s\\n' '*running,thread-id=\"all\"' '8^running' '(gdb)'\nIFS= read -r interrupt\n[ \"$interrupt\" = '19-exec-interrupt --all' ] || exit 19\nprintf '%s\\n' '19^done' '(gdb)' '*stopped,reason=\"signal-received\",signal-name=\"SIGINT\",signal-meaning=\"Interrupt\",frame={{addr=\"0x420128cd\",args=[]}},thread-id=\"1\",stopped-threads=\"all\",core=\"0\"' '(gdb)'\nIFS= read -r cleanup_delete\n[ \"$cleanup_delete\" = '20-break-delete 1' ] || exit 20\nprintf '%s\\n' '20^done' '(gdb)'\nIFS= read -r cleanup_list\n[ \"$cleanup_list\" = '21-break-list' ] || exit 21\nprintf '%s\\n' '21^done,{EMPTY_BREAKPOINT_TABLE}' '(gdb)'\nIFS= read -r cleanup_detach\n[ \"$cleanup_detach\" = '22-target-detach' ] || exit 22\nprintf '%s\\n' '22^done' '(gdb)'\n"
                )
            } else {
                format!(
                    "printf '%s\\n' '*running,thread-id=\"all\"' '*running,thread-id=\"all\"' '*stopped,reason=\"access-watchpoint-trigger\",hw-awpt={{number=\"1\",exp=\"{expression}\"}},value={{old=\"6\",new=\"7\"}},frame={{addr=\"0x420128cd\",func=\"main\",args=[],file=\"src/bin/main.rs\",line=\"85\",arch=\"xtensa\"}},thread-id=\"1\",stopped-threads=\"all\",core=\"0\"' '8^running' '(gdb)'\nIFS= read -r list_after_hit\n[ \"$list_after_hit\" = '9-break-list' ] || exit 9\nprintf '%s\\n' '9^done,{after}' '(gdb)'\nIFS= read -r delete\n[ \"$delete\" = '10-break-delete 1' ] || exit 10\nprintf '%s\\n' '10^done' '(gdb)'\nIFS= read -r list_empty\n[ \"$list_empty\" = '11-break-list' ] || exit 11\nprintf '%s\\n' '11^done,{EMPTY_BREAKPOINT_TABLE}' '(gdb)'\nIFS= read -r detach\n[ \"$detach\" = '12-target-detach' ] || exit 12\nprintf '%s\\n' '12^done' '(gdb)'\n"
                )
            };
            fs::write(
                &executable,
                format!(
                    "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf '%s\\n' 'GNU gdb 17.1-test'; exit 0; fi\n[ -z \"${{XTENSA_GNU_CONFIG+x}}\" ] || exit 2\nprintf '%s\\n' '(gdb)'\nIFS= read -r version\n[ \"$version\" = '1-gdb-version' ] || exit 1\nprintf '%s\\n' '~\"GNU gdb 17.1-test\\n\"' '1^done' '(gdb)'\nIFS= read -r async\n[ \"$async\" = '2-gdb-set mi-async on' ] || exit 2\nprintf '%s\\n' '2^done' '(gdb)'\nIFS= read -r all_stop\n[ \"$all_stop\" = '3-gdb-set non-stop off' ] || exit 3\nprintf '%s\\n' '3^done' '(gdb)'\nIFS= read -r connect\ncase \"$connect\" in '4-target-select remote 127.0.0.1:'*) ;; *) exit 4 ;; esac\nprintf '%s\\n' '*stopped,reason=\"signal-received\"' '4^connected' '(gdb)'\nIFS= read -r language\n[ \"$language\" = '5-gdb-set language c' ] || exit 5\nprintf '%s\\n' '5^done' '(gdb)'\nIFS= read -r insert\n[ \"$insert\" = '6-break-watch -a {expression}' ] || exit 6\nprintf '%s\\n' '6^done,hw-awpt={{number=\"1\",exp=\"{expression}\"}}' '(gdb)'\nIFS= read -r list_before\n[ \"$list_before\" = '7-break-list' ] || exit 7\nprintf '%s\\n' '7^done,{before}' '(gdb)'\nIFS= read -r continue_command\n[ \"$continue_command\" = '8-exec-continue --all' ] || exit 8\n{lifecycle}IFS= read -r exit_command\n[ \"$exit_command\" = '13-gdb-exit' ] || exit 13\nprintf '%s\\n' '13^exit'\n"
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
                    "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf '%s\\n' '{version}'; exit 0; fi\n{role}='{mode}' exec '{escaped_exe}' --exact {helper} --nocapture\n"
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
