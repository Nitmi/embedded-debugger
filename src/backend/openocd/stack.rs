use std::time::Duration;

use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{
    GdbExecutableFileIdentity, GdbMiCommandResult, GdbMiHandshake, GdbMiOutput, GdbMiProtocol,
    GdbMiShutdown, GdbMiStackSnapshot, GdbXtensaConfigInspection, OpenOcdGdbSessionOptions,
    OpenOcdServerConfirmationBoundary, OpenOcdServerEffects, OpenOcdServerLogs, OpenOcdServerPlan,
    OpenOcdServerReadiness, OpenOcdServerShutdown, OpenOcdSessionGdbPlan, OpenOcdSessionServerPlan,
    OpenOcdTargetRestoration, OpenOcdTargetStatePolicy,
    gdb::{execute_remote_stack_snapshot, stack_protocol_contract},
    server::start_managed_server,
    session::{observe_initial_target, restore_running_target, with_server_context},
};
use crate::{
    SCHEMA_VERSION,
    error::{DebugError, ErrorCode, Result, SuggestedAction},
};

pub const MAX_OPENOCD_STACK_SNAPSHOT_FRAMES: u64 = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenOcdStackSnapshotOptions {
    pub session: OpenOcdGdbSessionOptions,
    pub maximum_frames: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdStackSnapshotPlan {
    pub backend: String,
    pub operation: String,
    pub risk: String,
    pub complete: bool,
    pub openocd: OpenOcdSessionServerPlan,
    pub gdb: OpenOcdSessionGdbPlan,
    pub protocol: GdbMiProtocol,
    pub stack_policy: OpenOcdStackSnapshotPolicy,
    pub target_state_policy: OpenOcdTargetStatePolicy,
    pub effects: OpenOcdStackSnapshotEffects,
    pub confirmation_boundary: OpenOcdStackSnapshotConfirmationBoundary,
    pub confirm_digest: String,
    #[serde(skip)]
    openocd_execution_plan: OpenOcdServerPlan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdStackSnapshotPolicy {
    pub minimum_frames: u64,
    pub maximum_frames_supported: u64,
    pub maximum_frames_requested: u64,
    pub low_frame: u64,
    pub high_frame_inclusive: u64,
    pub list_command: String,
    pub frame_filters_disabled: bool,
    pub result_field: String,
    pub required_frame_fields: Vec<String>,
    pub optional_frame_fields: Vec<String>,
    pub level_policy: String,
    pub address_policy: String,
    pub optional_text_maximum_bytes: u64,
    pub limit_reporting_policy: String,
    pub physical_call_stack_completeness_claimed: bool,
    pub symbol_or_firmware_identity_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdStackSnapshotEffects {
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
    pub explicit_bounded_stack_unwind_requested: bool,
    pub returned_frame_count_bounded: bool,
    pub unwinder_register_access_possible: bool,
    pub unwinder_target_memory_read_possible: bool,
    pub unwinder_target_memory_addresses_bound: bool,
    pub side_effectful_target_read_possible_from_invalid_unwind_state: bool,
    pub explicit_memory_command_requested: bool,
    pub explicit_register_command_requested: bool,
    pub symbol_or_executable_loading_requested: bool,
    pub frame_filter_execution_requested: bool,
    pub argument_local_or_value_read_requested: bool,
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
pub struct OpenOcdStackSnapshotConfirmationBoundary {
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
    pub maximum_frame_count_bound: bool,
    pub exact_frame_range_bound: bool,
    pub frame_filter_policy_bound: bool,
    pub result_validation_policy_bound: bool,
    pub implicit_unwinder_target_access_addresses_bound: bool,
    pub lifecycle_deadlines_bound: bool,
    pub loopback_dynamic_endpoint_policy_bound: bool,
    pub runtime_port_number_bound: bool,
    pub expected_target_name_bound: bool,
    pub runtime_adapter_identity_bound: bool,
    pub target_state_policy_bound: bool,
    pub symbol_or_firmware_identity_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdStackSnapshotTestReport {
    pub backend: String,
    pub scope: String,
    pub risk: String,
    pub complete: bool,
    pub confirm_digest: String,
    pub openocd: OpenOcdSessionServerPlan,
    pub gdb: OpenOcdSessionGdbPlan,
    pub protocol: GdbMiProtocol,
    pub stack_policy: OpenOcdStackSnapshotPolicy,
    pub target_state_policy: OpenOcdTargetStatePolicy,
    pub readiness: OpenOcdServerReadiness,
    pub target_restoration: OpenOcdTargetRestoration,
    pub exchange: OpenOcdStackSnapshotExchange,
    pub openocd_shutdown: OpenOcdServerShutdown,
    pub openocd_logs: OpenOcdServerLogs,
    pub effects: OpenOcdStackSnapshotEffects,
    pub confirmation_boundary: OpenOcdStackSnapshotConfirmationBoundary,
    pub capabilities: OpenOcdStackSnapshotCapabilities,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdStackSnapshotExchange {
    pub endpoint: String,
    pub handshake: GdbMiHandshake,
    pub connection: GdbMiCommandResult,
    pub stack_list: GdbMiCommandResult,
    pub snapshot: GdbMiStackSnapshot,
    pub detach: GdbMiCommandResult,
    pub shutdown: GdbMiShutdown,
    pub output: GdbMiOutput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdStackSnapshotCapabilities {
    pub server_launch: bool,
    pub tcl_rpc: bool,
    pub gdb_mi: bool,
    pub remote_target_connection: bool,
    pub target_state_observation: bool,
    pub attach_detach: bool,
    pub restoration_resume: bool,
    pub bounded_stack_snapshot: bool,
    pub symbol_loading: bool,
    pub argument_local_or_value_read: bool,
    pub explicit_memory_commands: bool,
    pub explicit_register_commands: bool,
    pub breakpoints: bool,
    pub watchpoints: bool,
    pub general_execution_control: bool,
    pub flash: bool,
    pub arbitrary_commands: bool,
}

#[derive(Debug, Serialize)]
struct StackConfirmationInput<'a> {
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
    stack_policy: &'a OpenOcdStackSnapshotPolicy,
    target_state_policy: &'a OpenOcdTargetStatePolicy,
    effects: &'a OpenOcdStackSnapshotEffects,
    confirmation_boundary: &'a OpenOcdStackSnapshotConfirmationBoundary,
}

#[derive(Debug, Serialize)]
struct GdbLifecycleConfirmation {
    version_timeout_ms: u64,
    startup_timeout_ms: u64,
    command_timeout_ms: u64,
    shutdown_timeout_ms: u64,
}

pub fn plan_stack_snapshot(
    options: &OpenOcdStackSnapshotOptions,
) -> Result<OpenOcdStackSnapshotPlan> {
    let stack_policy = validate_stack_policy(options.maximum_frames)?;
    let session = super::plan_session(&options.session)?;
    let protocol = stack_protocol_contract(options.maximum_frames);
    let mut target_state_policy = session.target_state_policy.clone();
    target_state_policy.normal_restoration_command = "4-target-detach".to_string();
    let effects = stack_effects(session.gdb.xtensa_config.is_some());
    let confirmation_boundary = stack_confirmation_boundary();
    let confirmation = StackConfirmationInput {
        schema_version: SCHEMA_VERSION,
        operation: "openocd.stack.test",
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
        stack_policy: &stack_policy,
        target_state_policy: &target_state_policy,
        effects: &effects,
        confirmation_boundary: &confirmation_boundary,
    };
    let confirm_digest = hex::encode(Sha256::digest(
        serde_json::to_vec(&confirmation).expect("stack-snapshot confirmation input serializes"),
    ));

    Ok(OpenOcdStackSnapshotPlan {
        backend: "openocd".to_string(),
        operation: "openocd.stack.test".to_string(),
        risk: "R2_DEVICE_WRITE".to_string(),
        complete: true,
        openocd: session.openocd,
        gdb: session.gdb,
        protocol,
        stack_policy,
        target_state_policy,
        effects,
        confirmation_boundary,
        confirm_digest,
        openocd_execution_plan: session.openocd_execution_plan,
    })
}

pub fn test_stack_snapshot(
    options: &OpenOcdStackSnapshotOptions,
    confirm_digest: &str,
) -> Result<OpenOcdStackSnapshotTestReport> {
    let plan = plan_stack_snapshot(options)?;
    if plan.confirm_digest != confirm_digest {
        return Err(stack_confirmation_error(
            &plan.confirm_digest,
            confirm_digest,
        ));
    }
    execute_stack_plan(plan)
}

fn execute_stack_plan(plan: OpenOcdStackSnapshotPlan) -> Result<OpenOcdStackSnapshotTestReport> {
    let server = start_managed_server(&plan.openocd_execution_plan)?;
    let initial = match observe_initial_target(&server, plan.target_state_policy.timeout_ms) {
        Ok(observation) => observation,
        Err(error) => return Err(with_server_context(error, server.finish(), None)),
    };
    if initial.target_name != plan.target_state_policy.expected_current_target {
        let error = DebugError::verification(
            "OpenOCD current target did not match the confirmed stack-snapshot target",
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
            "OpenOCD current target was not running before stack-snapshot attachment",
            json!({
                "initial_observation": initial,
                "required_initial_state": plan.target_state_policy.initial_state_required,
                "remote_gdb_started": false,
            }),
        );
        return Err(with_server_context(error, server.finish(), None));
    }

    let gdb_result = execute_remote_stack_snapshot(
        &plan.gdb.executable.resolved,
        plan.gdb
            .xtensa_config
            .as_ref()
            .map(|config| config.resolved.as_str()),
        server.readiness().gdb_port,
        plan.stack_policy.maximum_frames_requested,
        plan.gdb.startup_timeout_ms,
        plan.gdb.command_timeout_ms,
        plan.gdb.shutdown_timeout_ms,
    );
    let restoration = restore_running_target(&server, initial, plan.target_state_policy.timeout_ms);
    let completion = server.finish();

    let exchange = match gdb_result {
        Ok(execution) => OpenOcdStackSnapshotExchange {
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
            stack_list: GdbMiCommandResult {
                token: 3,
                command: execution.list_command,
                result_class: execution.list_result_class,
                elapsed_ms: duration_ms(execution.list_elapsed),
            },
            snapshot: execution.snapshot,
            detach: GdbMiCommandResult {
                token: 4,
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

    Ok(OpenOcdStackSnapshotTestReport {
        backend: plan.backend,
        scope: "confirmed_bounded_stack_snapshot".to_string(),
        risk: plan.risk,
        complete: true,
        confirm_digest: plan.confirm_digest,
        openocd: plan.openocd,
        gdb: plan.gdb,
        protocol: plan.protocol,
        stack_policy: plan.stack_policy,
        target_state_policy: plan.target_state_policy,
        readiness: completion.readiness,
        target_restoration: restoration,
        exchange,
        openocd_shutdown: completion.shutdown,
        openocd_logs: completion.logs,
        effects: plan.effects,
        confirmation_boundary: plan.confirmation_boundary,
        capabilities: stack_capabilities(),
    })
}

fn validate_stack_policy(maximum_frames: u64) -> Result<OpenOcdStackSnapshotPolicy> {
    if !(1..=MAX_OPENOCD_STACK_SNAPSHOT_FRAMES).contains(&maximum_frames) {
        return Err(DebugError::config(
            "OpenOCD stack snapshot frame limit is outside the supported range",
            json!({
                "maximum_frames": maximum_frames,
                "minimum": 1,
                "maximum": MAX_OPENOCD_STACK_SNAPSHOT_FRAMES,
            }),
        ));
    }
    let high_frame_inclusive = maximum_frames - 1;
    Ok(OpenOcdStackSnapshotPolicy {
        minimum_frames: 1,
        maximum_frames_supported: MAX_OPENOCD_STACK_SNAPSHOT_FRAMES,
        maximum_frames_requested: maximum_frames,
        low_frame: 0,
        high_frame_inclusive,
        list_command: format!("3-stack-list-frames --no-frame-filters 0 {high_frame_inclusive}"),
        frame_filters_disabled: true,
        result_field: "stack".to_string(),
        required_frame_fields: vec!["level".to_string(), "addr".to_string()],
        optional_frame_fields: vec![
            "func".to_string(),
            "file".to_string(),
            "fullname".to_string(),
            "line".to_string(),
            "from".to_string(),
            "arch".to_string(),
            "addr_flags".to_string(),
        ],
        level_policy: "strict contiguous decimal levels beginning at zero".to_string(),
        address_policy: "required 0x-prefixed hexadecimal address, maximum 64 bits".to_string(),
        optional_text_maximum_bytes: 4 * 1024,
        limit_reporting_policy:
            "when returned_frames equals the limit, report that additional GDB frames are possible"
                .to_string(),
        physical_call_stack_completeness_claimed: false,
        symbol_or_firmware_identity_required: false,
    })
}

fn stack_effects(xtensa_config_selected: bool) -> OpenOcdStackSnapshotEffects {
    OpenOcdStackSnapshotEffects {
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
        explicit_bounded_stack_unwind_requested: true,
        returned_frame_count_bounded: true,
        unwinder_register_access_possible: true,
        unwinder_target_memory_read_possible: true,
        unwinder_target_memory_addresses_bound: false,
        side_effectful_target_read_possible_from_invalid_unwind_state: true,
        explicit_memory_command_requested: false,
        explicit_register_command_requested: false,
        symbol_or_executable_loading_requested: false,
        frame_filter_execution_requested: false,
        argument_local_or_value_read_requested: false,
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
            "The returned frame range is bounded, but GDB unwinding may read target registers and memory at addresses derived from live target state."
                .to_string(),
            "The confirmation cannot bind those implicit unwind-read addresses; invalid unwind state could reach an unexpected or side-effectful target address."
                .to_string(),
            "Python frame filters are explicitly disabled and no argument, local, or value data is requested."
                .to_string(),
            "No executable or symbol file is loaded, so function and source metadata are accepted only as optional GDB-reported text and no firmware identity claim is made."
                .to_string(),
            "Normal remote negotiation may exchange target descriptions, memory-map metadata, stop state, or register state before the explicit stack command."
                .to_string(),
            "Confirmed OpenOCD attach handlers may probe flash or reset/halt a protected target."
                .to_string(),
            "The command refuses attachment unless the selected target is running and fails unless running is proven again before OpenOCD shutdown."
                .to_string(),
        ],
    }
}

fn stack_confirmation_boundary() -> OpenOcdStackSnapshotConfirmationBoundary {
    OpenOcdStackSnapshotConfirmationBoundary {
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
        maximum_frame_count_bound: true,
        exact_frame_range_bound: true,
        frame_filter_policy_bound: true,
        result_validation_policy_bound: true,
        implicit_unwinder_target_access_addresses_bound: false,
        lifecycle_deadlines_bound: true,
        loopback_dynamic_endpoint_policy_bound: true,
        runtime_port_number_bound: false,
        expected_target_name_bound: true,
        runtime_adapter_identity_bound: false,
        target_state_policy_bound: true,
        symbol_or_firmware_identity_required: false,
    }
}

fn stack_capabilities() -> OpenOcdStackSnapshotCapabilities {
    OpenOcdStackSnapshotCapabilities {
        server_launch: true,
        tcl_rpc: true,
        gdb_mi: true,
        remote_target_connection: true,
        target_state_observation: true,
        attach_detach: true,
        restoration_resume: true,
        bounded_stack_snapshot: true,
        symbol_loading: false,
        argument_local_or_value_read: false,
        explicit_memory_commands: false,
        explicit_register_commands: false,
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
        "stack snapshot did not prove restoration of the initial running target state",
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

fn stack_confirmation_error(expected: &str, received: &str) -> DebugError {
    let mut error = DebugError::new(
        ErrorCode::ConfirmationMismatch,
        "OpenOCD stack-snapshot confirmation digest does not match the current plan",
        2,
        json!({
            "expected_confirm_digest": expected,
            "received_confirm_digest": received,
        }),
    );
    error.suggested_actions.push(SuggestedAction::new(
        "review_openocd_stack_snapshot_plan",
        json!({"command": "openocd stack plan"}),
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

    const HELPER_ROLE: &str = "EMBEDDED_DEBUGGER_OPENOCD_STACK_HELPER_ROLE";

    #[test]
    fn frame_limit_fails_before_session_inputs_are_inspected() {
        let mut options = missing_options(0);
        let error = plan_stack_snapshot(&options).unwrap_err();
        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert_eq!(error.details["maximum_frames"], 0);

        options.maximum_frames = MAX_OPENOCD_STACK_SNAPSHOT_FRAMES + 1;
        let error = plan_stack_snapshot(&options).unwrap_err();
        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert_eq!(error.details["maximum"], MAX_OPENOCD_STACK_SNAPSHOT_FRAMES);
    }

    #[test]
    fn stack_plan_is_deterministic_and_binds_the_limit() {
        let directory = tempdir().unwrap();
        let first = plan_stack_snapshot(&test_options(directory.path(), 4)).unwrap();
        let second = plan_stack_snapshot(&test_options(directory.path(), 4)).unwrap();
        assert_eq!(first.confirm_digest, second.confirm_digest);
        assert_eq!(first.protocol.commands.len(), 5);
        assert_eq!(
            first.protocol.commands[2].command,
            "-stack-list-frames --no-frame-filters 0 3"
        );
        assert_eq!(
            first.target_state_policy.normal_restoration_command,
            "4-target-detach"
        );
        assert!(!first.effects.unwinder_target_memory_addresses_bound);
        assert!(
            !first
                .confirmation_boundary
                .implicit_unwinder_target_access_addresses_bound
        );

        let changed = plan_stack_snapshot(&test_options(directory.path(), 5)).unwrap();
        assert_ne!(first.confirm_digest, changed.confirm_digest);
    }

    #[test]
    fn controlled_stack_snapshot_restores_running_and_returns_structured_frames() {
        let directory = tempdir().unwrap();
        let options = test_options(directory.path(), 4);
        let plan = plan_stack_snapshot(&options).unwrap();
        let report = test_stack_snapshot(&options, &plan.confirm_digest).unwrap();

        assert!(report.complete);
        assert_eq!(report.exchange.snapshot.returned_frames, 2);
        assert_eq!(report.exchange.snapshot.frames[0].level, 0);
        assert_eq!(
            report.exchange.snapshot.frames[0].function.as_deref(),
            Some("app_main")
        );
        assert!(!report.exchange.snapshot.frame_limit_reached);
        assert!(
            !report
                .exchange
                .snapshot
                .physical_call_stack_completeness_proven
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
    fn controlled_stack_snapshot_is_annotated_only_after_target_cleanup() {
        let directory = tempdir().unwrap();
        let elf = directory.path().join("fixture.elf");
        fs::write(&elf, super::super::stack_elf::test_executable_elf(false)).unwrap();
        let options = super::super::stack_elf::OpenOcdStackElfOptions {
            stack: test_options(directory.path(), 4),
            elf,
        };
        let plan = super::super::stack_elf::plan_stack_elf(&options).unwrap();
        let report =
            super::super::stack_elf::test_stack_elf(&options, &plan.confirm_digest).unwrap();

        assert!(report.complete);
        assert_eq!(report.annotations.resolved_frames, 2);
        assert_eq!(
            report.annotations.frames[0].inline_annotations[0]
                .function
                .as_deref(),
            Some("fixture_dwarf_app_main")
        );
        assert!(report.stack.target_restoration.complete);
        assert!(report.stack.exchange.shutdown.graceful);
        assert!(report.stack.openocd_shutdown.graceful);
        assert!(!report.annotations.runtime_firmware_identity_verified);
        assert!(!report.capabilities.gdb_symbol_loading);
    }

    #[test]
    fn malformed_stack_still_detaches_exits_restores_and_closes_openocd() {
        let directory = tempdir().unwrap();
        let options = test_options(directory.path(), 4);
        let gdb = &options.session.gdb_executable;
        let script = fs::read_to_string(gdb).unwrap();
        fs::write(gdb, script.replace("level=\"1\"", "level=\"3\"")).unwrap();
        let plan = plan_stack_snapshot(&options).unwrap();
        let error = test_stack_snapshot(&options, &plan.confirm_digest).unwrap_err();

        assert_eq!(error.code, ErrorCode::ProtocolError);
        assert_eq!(error.details["cleanup_detach"]["complete"], true);
        assert_eq!(error.details["shutdown"]["graceful"], true);
        assert_eq!(error.details["target_restoration"]["complete"], true);
        assert_eq!(error.details["openocd_shutdown"]["graceful"], true);
    }

    #[test]
    fn managed_stack_openocd_helper() {
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

    fn missing_options(maximum_frames: u64) -> OpenOcdStackSnapshotOptions {
        OpenOcdStackSnapshotOptions {
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
            maximum_frames,
        }
    }

    fn test_options(directory: &Path, maximum_frames: u64) -> OpenOcdStackSnapshotOptions {
        let openocd = write_fake_openocd(directory);
        let gdb = write_fake_stack_gdb(directory);
        let config = directory.join("board.cfg");
        fs::write(&config, b"adapter speed 1000\n").unwrap();
        OpenOcdStackSnapshotOptions {
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
            maximum_frames,
        }
    }

    fn write_fake_openocd(directory: &Path) -> PathBuf {
        let current_exe = std::env::current_exe().unwrap();
        let helper = "backend::openocd::stack::tests::managed_stack_openocd_helper";
        #[cfg(windows)]
        {
            let executable = directory.join("fake-stack-openocd.cmd");
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

            let executable = directory.join("fake-stack-openocd");
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

    fn write_fake_stack_gdb(directory: &Path) -> PathBuf {
        #[cfg(windows)]
        {
            let executable = directory.join("fake-stack-gdb.cmd");
            fs::write(
                &executable,
                "@echo off\r\nif \"%1\"==\"--version\" goto version\r\nif defined XTENSA_GNU_CONFIG exit /b 8\r\necho ^(gdb^)\r\nset /p first=\r\nif not \"%first%\"==\"1-gdb-version\" exit /b 3\r\necho ~\"GNU gdb 17.1-test\\n\"\r\necho 1^^done\r\necho ^(gdb^)\r\nset /p second=\r\nif not \"%second:~0,23%\"==\"2-target-select remote \" exit /b 4\r\necho *stopped,reason=\"signal-received\"\r\necho 2^^connected\r\necho ^(gdb^)\r\nset /p third=\r\nif not \"%third%\"==\"3-stack-list-frames --no-frame-filters 0 3\" exit /b 5\r\necho 3^^done,stack=[frame={level=\"0\",addr=\"0x40370010\",func=\"app_main\",arch=\"xtensa\"},frame={level=\"1\",addr=\"0x40370020\",from=\"rom\",arch=\"xtensa\"}]\r\necho ^(gdb^)\r\nset /p fourth=\r\nif not \"%fourth%\"==\"4-target-detach\" exit /b 6\r\necho 4^^done\r\necho ^(gdb^)\r\nset /p fifth=\r\nif not \"%fifth%\"==\"5-gdb-exit\" exit /b 7\r\necho 5^^exit\r\nexit /b 0\r\n:version\r\necho GNU gdb 17.1-test\r\nexit /b 0\r\n",
            )
            .unwrap();
            executable
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let executable = directory.join("fake-stack-gdb");
            fs::write(
                &executable,
                "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  printf '%s\\n' 'GNU gdb 17.1-test'\n  exit 0\nfi\n[ -z \"${XTENSA_GNU_CONFIG+x}\" ] || exit 8\nprintf '%s\\n' '(gdb)'\nIFS= read -r first\n[ \"$first\" = '1-gdb-version' ] || exit 3\nprintf '%s\\n' '~\"GNU gdb 17.1-test\\n\"' '1^done' '(gdb)'\nIFS= read -r second\ncase \"$second\" in '2-target-select remote 127.0.0.1:'*) ;; *) exit 4 ;; esac\nprintf '%s\\n' '*stopped,reason=\"signal-received\"' '2^connected' '(gdb)'\nIFS= read -r third\n[ \"$third\" = '3-stack-list-frames --no-frame-filters 0 3' ] || exit 5\nprintf '%s\\n' '3^done,stack=[frame={level=\"0\",addr=\"0x40370010\",func=\"app_main\",arch=\"xtensa\"},frame={level=\"1\",addr=\"0x40370020\",from=\"rom\",arch=\"xtensa\"}]' '(gdb)'\nIFS= read -r fourth\n[ \"$fourth\" = '4-target-detach' ] || exit 6\nprintf '%s\\n' '4^done' '(gdb)'\nIFS= read -r fifth\n[ \"$fifth\" = '5-gdb-exit' ] || exit 7\nprintf '%s\\n' '5^exit'\n",
            )
            .unwrap();
            let mut permissions = fs::metadata(&executable).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&executable, permissions).unwrap();
            executable
        }
    }
}
