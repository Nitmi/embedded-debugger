use std::time::Duration;

use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{
    GdbExecutableFileIdentity, GdbMiCommandResult, GdbMiHandshake, GdbMiMemorySnapshot,
    GdbMiOutput, GdbMiProtocol, GdbMiShutdown, GdbXtensaConfigInspection, OpenOcdGdbSessionOptions,
    OpenOcdServerConfirmationBoundary, OpenOcdServerEffects, OpenOcdServerLogs, OpenOcdServerPlan,
    OpenOcdServerReadiness, OpenOcdServerShutdown, OpenOcdSessionGdbPlan, OpenOcdSessionServerPlan,
    OpenOcdTargetRestoration, OpenOcdTargetStatePolicy,
    gdb::{RemoteMemoryRequest, execute_remote_memory_snapshot, memory_protocol_contract},
    server::start_managed_server,
    session::{observe_initial_target, restore_running_target, with_server_context},
};
use crate::{
    SCHEMA_VERSION,
    error::{DebugError, ErrorCode, Result, SuggestedAction},
    model::{Address, MAX_INLINE_MEMORY_READ_BYTES, MemoryRegionKind},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenOcdMemorySnapshotOptions {
    pub session: OpenOcdGdbSessionOptions,
    pub address: Address,
    pub length_bytes: u64,
    pub region_start: Address,
    pub region_length_bytes: u64,
    pub region_kind: MemoryRegionKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdMemorySnapshotPlan {
    pub backend: String,
    pub operation: String,
    pub risk: String,
    pub complete: bool,
    pub openocd: OpenOcdSessionServerPlan,
    pub gdb: OpenOcdSessionGdbPlan,
    pub protocol: GdbMiProtocol,
    pub memory_policy: OpenOcdMemorySnapshotPolicy,
    pub target_state_policy: OpenOcdTargetStatePolicy,
    pub effects: OpenOcdMemorySnapshotEffects,
    pub confirmation_boundary: OpenOcdMemorySnapshotConfirmationBoundary,
    pub confirm_digest: String,
    #[serde(skip)]
    openocd_execution_plan: OpenOcdServerPlan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdMemorySnapshotPolicy {
    pub requested_address: Address,
    pub requested_length_bytes: u64,
    pub requested_end_exclusive: Address,
    pub maximum_length_bytes: u64,
    pub declared_region: OpenOcdDeclaredMemoryRegion,
    pub allowed_region_kinds: Vec<String>,
    pub declared_region_containment_verified: bool,
    pub declared_region_semantics_verified: bool,
    pub declared_region_source: String,
    pub read_command: String,
    pub response_field: String,
    pub coverage_policy: String,
    pub block_order_policy: String,
    pub addressable_unit_policy: String,
    pub result_encoding: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdDeclaredMemoryRegion {
    pub kind: MemoryRegionKind,
    pub start: Address,
    pub length_bytes: u64,
    pub end_exclusive: Address,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdMemorySnapshotEffects {
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
    pub explicit_bounded_memory_read_requested: bool,
    pub target_memory_map_semantics_verified: bool,
    pub side_effectful_read_possible_if_region_declaration_is_wrong: bool,
    pub memory_write_requested: bool,
    pub register_inventory_requested: bool,
    pub explicit_register_read_requested: bool,
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
pub struct OpenOcdMemorySnapshotConfirmationBoundary {
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
    pub requested_address_bound: bool,
    pub requested_length_bound: bool,
    pub declared_region_bounds_bound: bool,
    pub declared_region_kind_bound: bool,
    pub complete_coverage_policy_bound: bool,
    pub target_memory_map_semantics_bound: bool,
    pub lifecycle_deadlines_bound: bool,
    pub loopback_dynamic_endpoint_policy_bound: bool,
    pub runtime_port_number_bound: bool,
    pub expected_target_name_bound: bool,
    pub runtime_adapter_identity_bound: bool,
    pub target_state_policy_bound: bool,
    pub symbol_or_firmware_identity_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdMemorySnapshotTestReport {
    pub backend: String,
    pub scope: String,
    pub risk: String,
    pub complete: bool,
    pub confirm_digest: String,
    pub openocd: OpenOcdSessionServerPlan,
    pub gdb: OpenOcdSessionGdbPlan,
    pub protocol: GdbMiProtocol,
    pub memory_policy: OpenOcdMemorySnapshotPolicy,
    pub target_state_policy: OpenOcdTargetStatePolicy,
    pub readiness: OpenOcdServerReadiness,
    pub target_restoration: OpenOcdTargetRestoration,
    pub exchange: OpenOcdMemorySnapshotExchange,
    pub openocd_shutdown: OpenOcdServerShutdown,
    pub openocd_logs: OpenOcdServerLogs,
    pub effects: OpenOcdMemorySnapshotEffects,
    pub confirmation_boundary: OpenOcdMemorySnapshotConfirmationBoundary,
    pub capabilities: OpenOcdMemorySnapshotCapabilities,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdMemorySnapshotExchange {
    pub endpoint: String,
    pub handshake: GdbMiHandshake,
    pub connection: GdbMiCommandResult,
    pub memory_read: GdbMiCommandResult,
    pub snapshot: GdbMiMemorySnapshot,
    pub detach: GdbMiCommandResult,
    pub shutdown: GdbMiShutdown,
    pub output: GdbMiOutput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdMemorySnapshotCapabilities {
    pub server_launch: bool,
    pub tcl_rpc: bool,
    pub gdb_mi: bool,
    pub remote_target_connection: bool,
    pub target_state_observation: bool,
    pub attach_detach: bool,
    pub restoration_resume: bool,
    pub register_inventory: bool,
    pub selected_register_read: bool,
    pub bounded_memory_read: bool,
    pub memory_write: bool,
    pub symbol_loading: bool,
    pub breakpoints: bool,
    pub watchpoints: bool,
    pub general_execution_control: bool,
    pub flash: bool,
    pub arbitrary_commands: bool,
}

#[derive(Debug, Serialize)]
struct MemoryConfirmationInput<'a> {
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
    memory_policy: &'a OpenOcdMemorySnapshotPolicy,
    target_state_policy: &'a OpenOcdTargetStatePolicy,
    effects: &'a OpenOcdMemorySnapshotEffects,
    confirmation_boundary: &'a OpenOcdMemorySnapshotConfirmationBoundary,
}

#[derive(Debug, Serialize)]
struct GdbLifecycleConfirmation {
    version_timeout_ms: u64,
    startup_timeout_ms: u64,
    command_timeout_ms: u64,
    shutdown_timeout_ms: u64,
}

pub fn plan_memory_snapshot(
    options: &OpenOcdMemorySnapshotOptions,
) -> Result<OpenOcdMemorySnapshotPlan> {
    let memory_policy = validate_memory_policy(options)?;
    let session = super::plan_session(&options.session)?;
    let protocol = memory_protocol_contract(options.address, options.length_bytes);
    let mut target_state_policy = session.target_state_policy.clone();
    target_state_policy.normal_restoration_command = "4-target-detach".to_string();
    let effects = memory_effects(session.gdb.xtensa_config.is_some());
    let confirmation_boundary = memory_confirmation_boundary();
    let confirmation = MemoryConfirmationInput {
        schema_version: SCHEMA_VERSION,
        operation: "openocd.memory.test",
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
        memory_policy: &memory_policy,
        target_state_policy: &target_state_policy,
        effects: &effects,
        confirmation_boundary: &confirmation_boundary,
    };
    let confirm_digest = hex::encode(Sha256::digest(
        serde_json::to_vec(&confirmation)
            .expect("memory-snapshot confirmation input always serializes"),
    ));

    Ok(OpenOcdMemorySnapshotPlan {
        backend: "openocd".to_string(),
        operation: "openocd.memory.test".to_string(),
        risk: "R2_DEVICE_WRITE".to_string(),
        complete: true,
        openocd: session.openocd,
        gdb: session.gdb,
        protocol,
        memory_policy,
        target_state_policy,
        effects,
        confirmation_boundary,
        confirm_digest,
        openocd_execution_plan: session.openocd_execution_plan,
    })
}

pub fn test_memory_snapshot(
    options: &OpenOcdMemorySnapshotOptions,
    confirm_digest: &str,
) -> Result<OpenOcdMemorySnapshotTestReport> {
    let plan = plan_memory_snapshot(options)?;
    if plan.confirm_digest != confirm_digest {
        return Err(memory_confirmation_error(
            &plan.confirm_digest,
            confirm_digest,
        ));
    }
    execute_memory_plan(plan)
}

fn execute_memory_plan(plan: OpenOcdMemorySnapshotPlan) -> Result<OpenOcdMemorySnapshotTestReport> {
    let server = start_managed_server(&plan.openocd_execution_plan)?;
    let initial = match observe_initial_target(&server, plan.target_state_policy.timeout_ms) {
        Ok(observation) => observation,
        Err(error) => return Err(with_server_context(error, server.finish(), None)),
    };
    if initial.target_name != plan.target_state_policy.expected_current_target {
        let error = DebugError::verification(
            "OpenOCD current target did not match the confirmed memory-snapshot target",
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
            "OpenOCD current target was not running before memory-snapshot attachment",
            json!({
                "initial_observation": initial,
                "required_initial_state": plan.target_state_policy.initial_state_required,
                "remote_gdb_started": false,
            }),
        );
        return Err(with_server_context(error, server.finish(), None));
    }

    let gdb_result = execute_remote_memory_snapshot(
        &plan.gdb.executable.resolved,
        plan.gdb
            .xtensa_config
            .as_ref()
            .map(|config| config.resolved.as_str()),
        server.readiness().gdb_port,
        RemoteMemoryRequest {
            address: plan.memory_policy.requested_address,
            length_bytes: plan.memory_policy.requested_length_bytes,
        },
        plan.gdb.startup_timeout_ms,
        plan.gdb.command_timeout_ms,
        plan.gdb.shutdown_timeout_ms,
    );
    let restoration = restore_running_target(&server, initial, plan.target_state_policy.timeout_ms);
    let completion = server.finish();

    let exchange = match gdb_result {
        Ok(execution) => OpenOcdMemorySnapshotExchange {
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
            memory_read: GdbMiCommandResult {
                token: 3,
                command: execution.read_command,
                result_class: execution.read_result_class,
                elapsed_ms: duration_ms(execution.read_elapsed),
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

    Ok(OpenOcdMemorySnapshotTestReport {
        backend: plan.backend,
        scope: "confirmed_bounded_memory_snapshot".to_string(),
        risk: plan.risk,
        complete: true,
        confirm_digest: plan.confirm_digest,
        openocd: plan.openocd,
        gdb: plan.gdb,
        protocol: plan.protocol,
        memory_policy: plan.memory_policy,
        target_state_policy: plan.target_state_policy,
        readiness: completion.readiness,
        target_restoration: restoration,
        exchange,
        openocd_shutdown: completion.shutdown,
        openocd_logs: completion.logs,
        effects: plan.effects,
        confirmation_boundary: plan.confirmation_boundary,
        capabilities: memory_capabilities(),
    })
}

fn validate_memory_policy(
    options: &OpenOcdMemorySnapshotOptions,
) -> Result<OpenOcdMemorySnapshotPolicy> {
    if options.length_bytes == 0 || options.length_bytes > MAX_INLINE_MEMORY_READ_BYTES {
        return Err(DebugError::config(
            "OpenOCD memory snapshot length is outside the supported range",
            json!({
                "length_bytes": options.length_bytes,
                "minimum": 1,
                "maximum": MAX_INLINE_MEMORY_READ_BYTES,
            }),
        ));
    }
    if options.region_length_bytes == 0 {
        return Err(DebugError::config(
            "declared OpenOCD memory region must be non-empty",
            json!({"region_length_bytes": options.region_length_bytes}),
        ));
    }
    let request_end = options
        .address
        .0
        .checked_add(options.length_bytes)
        .ok_or_else(|| {
            DebugError::config(
                "OpenOCD memory snapshot range overflows the address space",
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
                "declared OpenOCD memory region overflows the address space",
                json!({
                    "region_start": options.region_start,
                    "region_length_bytes": options.region_length_bytes,
                }),
            )
        })?;
    if options.address.0 < options.region_start.0 || request_end > region_end {
        return Err(DebugError::config(
            "OpenOCD memory snapshot range is not contained in the declared region",
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

    Ok(OpenOcdMemorySnapshotPolicy {
        requested_address: options.address,
        requested_length_bytes: options.length_bytes,
        requested_end_exclusive: Address(request_end),
        maximum_length_bytes: MAX_INLINE_MEMORY_READ_BYTES,
        declared_region: OpenOcdDeclaredMemoryRegion {
            kind: options.region_kind,
            start: options.region_start,
            length_bytes: options.region_length_bytes,
            end_exclusive: Address(region_end),
        },
        allowed_region_kinds: vec!["ram".to_string(), "nvm".to_string()],
        declared_region_containment_verified: true,
        declared_region_semantics_verified: false,
        declared_region_source: "user_confirmed_cli_input".to_string(),
        read_command: format!(
            "3-data-read-memory-bytes 0x{:x} {}",
            options.address.0, options.length_bytes
        ),
        response_field: "memory".to_string(),
        coverage_policy:
            "fail unless returned blocks cover every requested addressable unit without gaps"
                .to_string(),
        block_order_policy:
            "strict ascending offsets starting at zero; reject overlaps, gaps, reordering, and extras"
                .to_string(),
        addressable_unit_policy:
            "require one decoded hex byte for each increment in the returned begin/end span"
                .to_string(),
        result_encoding: "lowercase hexadecimal plus SHA-256".to_string(),
    })
}

fn memory_effects(xtensa_config_selected: bool) -> OpenOcdMemorySnapshotEffects {
    OpenOcdMemorySnapshotEffects {
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
        explicit_bounded_memory_read_requested: true,
        target_memory_map_semantics_verified: false,
        side_effectful_read_possible_if_region_declaration_is_wrong: true,
        memory_write_requested: false,
        register_inventory_requested: false,
        explicit_register_read_requested: false,
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
            "The declared RAM/NVM region and containment are confirmed inputs; target memory-map semantics are not independently verified."
                .to_string(),
            "A wrong region declaration can turn an apparent read into MMIO or another side-effectful target access."
                .to_string(),
            "GDB may split accessible memory into multiple blocks; the tool accepts only complete ordered gap-free coverage."
                .to_string(),
            "Normal remote negotiation may exchange target descriptions, memory-map metadata, stop state, or register state before the explicit memory command."
                .to_string(),
            "Confirmed OpenOCD attach handlers may probe flash or reset/halt a protected target."
                .to_string(),
            "No executable, symbols, register command, breakpoint, monitor command, memory write, or flash command is accepted."
                .to_string(),
            "The command refuses attachment unless the selected target is running and fails unless running is proven again before OpenOCD shutdown."
                .to_string(),
        ],
    }
}

fn memory_confirmation_boundary() -> OpenOcdMemorySnapshotConfirmationBoundary {
    OpenOcdMemorySnapshotConfirmationBoundary {
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
        requested_address_bound: true,
        requested_length_bound: true,
        declared_region_bounds_bound: true,
        declared_region_kind_bound: true,
        complete_coverage_policy_bound: true,
        target_memory_map_semantics_bound: false,
        lifecycle_deadlines_bound: true,
        loopback_dynamic_endpoint_policy_bound: true,
        runtime_port_number_bound: false,
        expected_target_name_bound: true,
        runtime_adapter_identity_bound: false,
        target_state_policy_bound: true,
        symbol_or_firmware_identity_required: false,
    }
}

fn memory_capabilities() -> OpenOcdMemorySnapshotCapabilities {
    OpenOcdMemorySnapshotCapabilities {
        server_launch: true,
        tcl_rpc: true,
        gdb_mi: true,
        remote_target_connection: true,
        target_state_observation: true,
        attach_detach: true,
        restoration_resume: true,
        register_inventory: false,
        selected_register_read: false,
        bounded_memory_read: true,
        memory_write: false,
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
        "memory snapshot did not prove restoration of the initial running target state",
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

fn memory_confirmation_error(expected: &str, received: &str) -> DebugError {
    let mut error = DebugError::new(
        ErrorCode::ConfirmationMismatch,
        "OpenOCD memory-snapshot confirmation digest does not match the current plan",
        2,
        json!({
            "expected_confirm_digest": expected,
            "received_confirm_digest": received,
        }),
    );
    error.suggested_actions.push(SuggestedAction::new(
        "review_openocd_memory_snapshot_plan",
        json!({"command": "openocd memory plan"}),
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

    const HELPER_ROLE: &str = "EMBEDDED_DEBUGGER_OPENOCD_MEMORY_HELPER_ROLE";

    #[test]
    fn memory_range_validation_runs_before_session_inputs_are_inspected() {
        let mut options = missing_options();
        options.length_bytes = 0;
        let error = plan_memory_snapshot(&options).unwrap_err();
        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert_eq!(error.details["length_bytes"], 0);

        options.length_bytes = MAX_INLINE_MEMORY_READ_BYTES + 1;
        assert!(plan_memory_snapshot(&options).is_err());

        options.length_bytes = 8;
        options.address = Address(0x3000_0000);
        let error = plan_memory_snapshot(&options).unwrap_err();
        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert!(error.message.contains("not contained"));

        options.address = Address(u64::MAX - 3);
        options.region_start = Address(u64::MAX - 7);
        options.region_length_bytes = 7;
        assert!(plan_memory_snapshot(&options).is_err());
    }

    #[test]
    fn memory_plan_is_deterministic_and_binds_range_and_region() {
        let directory = tempdir().unwrap();
        let options = test_options(directory.path());
        let first = plan_memory_snapshot(&options).unwrap();
        let second = plan_memory_snapshot(&options).unwrap();
        assert_eq!(first.confirm_digest, second.confirm_digest);
        assert_eq!(first.protocol.commands.len(), 5);
        assert_eq!(
            first.protocol.commands[2].command,
            "-data-read-memory-bytes 0x20000004 8"
        );
        assert_eq!(
            first.target_state_policy.normal_restoration_command,
            "4-target-detach"
        );
        assert!(first.effects.explicit_bounded_memory_read_requested);
        assert!(!first.effects.target_memory_map_semantics_verified);
        assert!(first.confirmation_boundary.requested_address_bound);
        assert!(first.confirmation_boundary.declared_region_kind_bound);

        let mut changed = options.clone();
        changed.address = Address(0x2000_0008);
        assert_ne!(
            first.confirm_digest,
            plan_memory_snapshot(&changed).unwrap().confirm_digest
        );
        changed = options.clone();
        changed.region_kind = MemoryRegionKind::Nvm;
        assert_ne!(
            first.confirm_digest,
            plan_memory_snapshot(&changed).unwrap().confirm_digest
        );
    }

    #[test]
    fn controlled_memory_snapshot_restores_running_and_hashes_exact_bytes() {
        let directory = tempdir().unwrap();
        let options = test_options(directory.path());
        let plan = plan_memory_snapshot(&options).unwrap();
        let report = test_memory_snapshot(&options, &plan.confirm_digest).unwrap();

        assert!(report.complete);
        assert_eq!(report.exchange.snapshot.address, Address(0x2000_0004));
        assert_eq!(report.exchange.snapshot.length_bytes, 8);
        assert_eq!(report.exchange.snapshot.data, "00010203aabbccdd");
        assert_eq!(report.exchange.snapshot.blocks.len(), 2);
        assert_eq!(
            report.exchange.memory_read.command,
            "-data-read-memory-bytes 0x20000004 8"
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
        assert!(report.capabilities.bounded_memory_read);
        assert!(!report.capabilities.memory_write);
    }

    #[test]
    fn incomplete_memory_result_still_detaches_exits_restores_and_closes_openocd() {
        let directory = tempdir().unwrap();
        let options = test_options(directory.path());
        let gdb = &options.session.gdb_executable;
        let script = fs::read_to_string(gdb).unwrap();
        fs::write(gdb, script.replace("offset=\"0x4\"", "offset=\"0x5\"")).unwrap();
        let plan = plan_memory_snapshot(&options).unwrap();
        let error = test_memory_snapshot(&options, &plan.confirm_digest).unwrap_err();

        assert_eq!(error.code, ErrorCode::ProtocolError);
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
    fn managed_memory_openocd_helper() {
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

    fn missing_options() -> OpenOcdMemorySnapshotOptions {
        OpenOcdMemorySnapshotOptions {
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
            address: Address(0x2000_0004),
            length_bytes: 8,
            region_start: Address(0x2000_0000),
            region_length_bytes: 0x1000,
            region_kind: MemoryRegionKind::Ram,
        }
    }

    fn test_options(directory: &Path) -> OpenOcdMemorySnapshotOptions {
        let openocd = write_fake_openocd(directory);
        let gdb = write_fake_memory_gdb(directory);
        let config = directory.join("board.cfg");
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

    fn write_fake_openocd(directory: &Path) -> PathBuf {
        let current_exe = std::env::current_exe().unwrap();
        let helper = "backend::openocd::memory::tests::managed_memory_openocd_helper";
        #[cfg(windows)]
        {
            let executable = directory.join("fake-memory-openocd.cmd");
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

            let executable = directory.join("fake-memory-openocd");
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

    fn write_fake_memory_gdb(directory: &Path) -> PathBuf {
        #[cfg(windows)]
        {
            let executable = directory.join("fake-memory-gdb.cmd");
            fs::write(
                &executable,
                "@echo off\r\nif \"%1\"==\"--version\" goto version\r\nif defined XTENSA_GNU_CONFIG exit /b 8\r\necho ^(gdb^)\r\nset /p first=\r\nif not \"%first%\"==\"1-gdb-version\" exit /b 3\r\necho ~\"GNU gdb 17.1-test\\n\"\r\necho 1^^done\r\necho ^(gdb^)\r\nset /p second=\r\nif not \"%second:~0,23%\"==\"2-target-select remote \" exit /b 4\r\necho *stopped,reason=\"signal-received\"\r\necho 2^^connected\r\necho ^(gdb^)\r\nset /p third=\r\nif not \"%third%\"==\"3-data-read-memory-bytes 0x20000004 8\" exit /b 5\r\necho 3^^done,memory=[{begin=\"0x20000004\",offset=\"0x0\",end=\"0x20000008\",contents=\"00010203\"},{begin=\"0x20000008\",offset=\"0x4\",end=\"0x2000000c\",contents=\"AABBCCDD\"}]\r\necho ^(gdb^)\r\nset /p fourth=\r\nif not \"%fourth%\"==\"4-target-detach\" exit /b 6\r\necho 4^^done\r\necho ^(gdb^)\r\nset /p fifth=\r\nif not \"%fifth%\"==\"5-gdb-exit\" exit /b 7\r\necho 5^^exit\r\nexit /b 0\r\n:version\r\necho GNU gdb 17.1-test\r\nexit /b 0\r\n",
            )
            .unwrap();
            executable
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let executable = directory.join("fake-memory-gdb");
            fs::write(
                &executable,
                "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  printf '%s\\n' 'GNU gdb 17.1-test'\n  exit 0\nfi\n[ -z \"${XTENSA_GNU_CONFIG+x}\" ] || exit 8\nprintf '%s\\n' '(gdb)'\nIFS= read -r first\n[ \"$first\" = '1-gdb-version' ] || exit 3\nprintf '%s\\n' '~\"GNU gdb 17.1-test\\n\"' '1^done' '(gdb)'\nIFS= read -r second\ncase \"$second\" in '2-target-select remote 127.0.0.1:'*) ;; *) exit 4 ;; esac\nprintf '%s\\n' '*stopped,reason=\"signal-received\"' '2^connected' '(gdb)'\nIFS= read -r third\n[ \"$third\" = '3-data-read-memory-bytes 0x20000004 8' ] || exit 5\nprintf '%s\\n' '3^done,memory=[{begin=\"0x20000004\",offset=\"0x0\",end=\"0x20000008\",contents=\"00010203\"},{begin=\"0x20000008\",offset=\"0x4\",end=\"0x2000000c\",contents=\"AABBCCDD\"}]' '(gdb)'\nIFS= read -r fourth\n[ \"$fourth\" = '4-target-detach' ] || exit 6\nprintf '%s\\n' '4^done' '(gdb)'\nIFS= read -r fifth\n[ \"$fifth\" = '5-gdb-exit' ] || exit 7\nprintf '%s\\n' '5^exit'\n",
            )
            .unwrap();
            let mut permissions = fs::metadata(&executable).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&executable, permissions).unwrap();
            executable
        }
    }
}
