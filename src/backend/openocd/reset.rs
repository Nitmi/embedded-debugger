use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{
    OpenOcdServerConfirmationBoundary, OpenOcdServerEffects, OpenOcdServerLogs,
    OpenOcdServerOptions, OpenOcdServerPlan, OpenOcdServerReadiness, OpenOcdServerShutdown,
    OpenOcdSessionServerPlan, OpenOcdTargetStateObservation,
    server::{ManagedServerCompletion, start_managed_server},
    session::observe_initial_target,
    target::{
        OpenOcdTargetTransition, transition_reached_state, transition_target_with_checked_command,
        validate_expected_target_and_timeout,
    },
};
use crate::{
    SCHEMA_VERSION,
    error::{DebugError, ErrorCode, Result, SuggestedAction},
};

const RESET_HALT_ENVELOPE_PREFIX: &str = "__EMBEDDED_DEBUGGER_RESET_V1__";
const RESET_HALT_ENVELOPE_COMMAND: &str =
    "format {__EMBEDDED_DEBUGGER_RESET_V1__%d} [catch {reset halt}]";
const RESET_RECOVERY_ENVELOPE_PREFIX: &str = "__EMBEDDED_DEBUGGER_RECOVERY_V1__";
const RESET_RECOVERY_COMMAND_TEMPLATE: &str = "format {__EMBEDDED_DEBUGGER_RECOVERY_V1__%d} [catch {targets <validated_current_target>; resume}]";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenOcdResetOptions {
    pub openocd: OpenOcdServerOptions,
    pub expected_target: String,
    pub target_state_timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdResetPlan {
    pub backend: String,
    pub operation: String,
    pub risk: String,
    pub complete: bool,
    pub openocd: OpenOcdSessionServerPlan,
    pub protocol: OpenOcdResetProtocol,
    pub reset_policy: OpenOcdResetPolicy,
    pub effects: OpenOcdResetEffects,
    pub confirmation_boundary: OpenOcdResetConfirmationBoundary,
    pub confirm_digest: String,
    #[serde(skip)]
    openocd_execution_plan: OpenOcdServerPlan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdResetProtocol {
    pub transport: String,
    pub message_terminator: String,
    pub commands: Vec<OpenOcdResetProtocolCommand>,
    pub target_name_interpolation: String,
    pub arbitrary_commands: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdResetProtocolCommand {
    pub phase: String,
    pub command: String,
    pub required_result: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdResetPolicy {
    pub expected_current_target: String,
    pub initial_state_required: String,
    pub reset_command: String,
    pub reset_scope: String,
    pub selected_target_post_reset_state_required: String,
    pub recovery_command_template: String,
    pub selected_target_final_state_required: String,
    pub transition_timeout_ms: u64,
    pub recovery_attempted_after_every_reset_result: bool,
    pub non_selected_target_final_state_policy: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdResetEffects {
    pub configuration_tcl_execution_required: bool,
    pub adapter_or_target_access_possible_from_configuration: bool,
    pub reset_or_device_write_possible_from_configuration: bool,
    pub arbitrary_host_command_execution_possible_from_configuration: bool,
    pub explicit_reset_requested: bool,
    pub explicit_reset_halt_requested: bool,
    pub reset_scope_all_defined_targets: bool,
    pub reset_event_handlers_execute: bool,
    pub reset_init_requested: bool,
    pub selected_target_resume_requested: bool,
    pub selected_target_final_running_verification_required: bool,
    pub non_selected_target_final_states_verified: bool,
    pub volatile_register_or_memory_state_change_expected: bool,
    pub peripheral_state_change_expected: bool,
    pub external_io_disruption_expected: bool,
    pub flash_command_requested: bool,
    pub explicit_register_or_memory_command_requested: bool,
    pub gdb_or_monitor_command_requested: bool,
    pub arbitrary_tcl_command_requested: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdResetConfirmationBoundary {
    pub openocd_executable_file_hash_bound: bool,
    pub openocd_version_bound: bool,
    pub top_level_configuration_hashes_bound: bool,
    pub search_directory_paths_bound: bool,
    pub search_directory_contents_bound: bool,
    pub transitive_sources_bound: bool,
    pub fixed_tcl_protocol_bound: bool,
    pub fixed_reset_mode_bound: bool,
    pub global_reset_scope_bound: bool,
    pub lifecycle_deadlines_bound: bool,
    pub target_transition_deadline_bound: bool,
    pub expected_target_name_bound: bool,
    pub selected_target_state_policy_bound: bool,
    pub loopback_dynamic_endpoint_policy_bound: bool,
    pub runtime_port_number_bound: bool,
    pub runtime_adapter_identity_bound: bool,
    pub non_selected_target_inventory_bound: bool,
    pub non_selected_target_initial_states_bound: bool,
    pub non_selected_target_final_states_bound: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdResetTestReport {
    pub backend: String,
    pub scope: String,
    pub risk: String,
    pub complete: bool,
    pub confirm_digest: String,
    pub openocd: OpenOcdSessionServerPlan,
    pub protocol: OpenOcdResetProtocol,
    pub reset_policy: OpenOcdResetPolicy,
    pub readiness: OpenOcdServerReadiness,
    pub initial: OpenOcdTargetStateObservation,
    pub reset: OpenOcdTargetTransition,
    pub recovery: OpenOcdTargetTransition,
    pub shutdown: OpenOcdServerShutdown,
    pub logs: OpenOcdServerLogs,
    pub effects: OpenOcdResetEffects,
    pub confirmation_boundary: OpenOcdResetConfirmationBoundary,
    pub capabilities: OpenOcdResetCapabilities,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdResetCapabilities {
    pub server_launch: bool,
    pub tcl_rpc: bool,
    pub selected_target_state_observation: bool,
    pub target_control: bool,
    pub reset: bool,
    pub fixed_reset_halt: bool,
    pub fixed_selected_target_resume: bool,
    pub final_selected_target_running_verification: bool,
    pub non_selected_target_state_verification: bool,
    pub gdb_mi: bool,
    pub register_read: bool,
    pub memory_read: bool,
    pub stack_read: bool,
    pub breakpoints: bool,
    pub watchpoints: bool,
    pub flash: bool,
    pub arbitrary_commands: bool,
}

#[derive(Debug, Serialize)]
struct ResetConfirmationInput<'a> {
    schema_version: &'static str,
    operation: &'static str,
    backend: &'static str,
    openocd_executable_path: &'a str,
    openocd_executable_version: &'a str,
    openocd_executable_file: &'a super::OpenOcdExecutableFileIdentity,
    openocd_configuration: &'a super::OpenOcdConfigurationInspection,
    openocd_lifecycle: &'a super::OpenOcdServerLifecyclePlan,
    openocd_configuration_effects: &'a OpenOcdServerEffects,
    openocd_confirmation_boundary: &'a OpenOcdServerConfirmationBoundary,
    protocol: &'a OpenOcdResetProtocol,
    reset_policy: &'a OpenOcdResetPolicy,
    effects: &'a OpenOcdResetEffects,
    confirmation_boundary: &'a OpenOcdResetConfirmationBoundary,
}

pub fn plan_reset(options: &OpenOcdResetOptions) -> Result<OpenOcdResetPlan> {
    validate_expected_target_and_timeout(
        &options.expected_target,
        options.target_state_timeout_ms,
    )?;
    let openocd_server = super::plan_server(&options.openocd)?;
    let openocd = OpenOcdSessionServerPlan {
        executable: openocd_server.executable.clone(),
        executable_file: openocd_server.executable_file.clone(),
        configuration: openocd_server.configuration.clone(),
        lifecycle: openocd_server.lifecycle.clone(),
        configuration_effects: openocd_server.effects.clone(),
        confirmation_boundary: openocd_server.confirmation_boundary.clone(),
    };
    let protocol = reset_protocol();
    let reset_policy = reset_policy(
        options.expected_target.clone(),
        options.target_state_timeout_ms,
    );
    let effects = reset_effects();
    let confirmation_boundary = reset_confirmation_boundary();
    let confirmation = ResetConfirmationInput {
        schema_version: SCHEMA_VERSION,
        operation: "openocd.reset.test",
        backend: "openocd",
        openocd_executable_path: &openocd.executable.resolved,
        openocd_executable_version: &openocd.executable.version_line,
        openocd_executable_file: &openocd.executable_file,
        openocd_configuration: &openocd.configuration,
        openocd_lifecycle: &openocd.lifecycle,
        openocd_configuration_effects: &openocd.configuration_effects,
        openocd_confirmation_boundary: &openocd.confirmation_boundary,
        protocol: &protocol,
        reset_policy: &reset_policy,
        effects: &effects,
        confirmation_boundary: &confirmation_boundary,
    };
    let confirm_digest = hex::encode(Sha256::digest(
        serde_json::to_vec(&confirmation).expect("reset confirmation input always serializes"),
    ));

    Ok(OpenOcdResetPlan {
        backend: "openocd".to_string(),
        operation: "openocd.reset.test".to_string(),
        risk: "R2_DEVICE_WRITE".to_string(),
        complete: true,
        openocd,
        protocol,
        reset_policy,
        effects,
        confirmation_boundary,
        confirm_digest,
        openocd_execution_plan: openocd_server,
    })
}

pub fn test_reset(
    options: &OpenOcdResetOptions,
    confirm_digest: &str,
) -> Result<OpenOcdResetTestReport> {
    let plan = plan_reset(options)?;
    if plan.confirm_digest != confirm_digest {
        return Err(reset_confirmation_error(
            &plan.confirm_digest,
            confirm_digest,
        ));
    }
    execute_reset_plan(plan)
}

fn execute_reset_plan(plan: OpenOcdResetPlan) -> Result<OpenOcdResetTestReport> {
    let server = start_managed_server(&plan.openocd_execution_plan)?;
    let initial = match observe_initial_target(&server, plan.reset_policy.transition_timeout_ms) {
        Ok(observation) => observation,
        Err(error) => {
            return Err(with_server_context(
                error,
                server.finish(),
                None,
                None,
                None,
            ));
        }
    };
    if initial.target_name != plan.reset_policy.expected_current_target {
        let error = DebugError::verification(
            "OpenOCD current target did not match the confirmed reset target name",
            json!({
                "expected_current_target": plan.reset_policy.expected_current_target,
                "observed_current_target": initial.target_name,
                "observed_state": initial.state,
                "reset_started": false,
            }),
        );
        return Err(with_server_context(
            error,
            server.finish(),
            Some(&initial),
            None,
            None,
        ));
    }
    if initial.state != plan.reset_policy.initial_state_required {
        let error = DebugError::verification(
            "OpenOCD target was not running before the confirmed reset roundtrip",
            json!({
                "initial_observation": initial,
                "required_initial_state": plan.reset_policy.initial_state_required,
                "reset_started": false,
            }),
        );
        return Err(with_server_context(
            error,
            server.finish(),
            Some(&initial),
            None,
            None,
        ));
    }

    let reset = transition_target_with_checked_command(
        &server,
        &initial.target_name,
        "reset_halt",
        RESET_HALT_ENVELOPE_COMMAND,
        "halted",
        plan.reset_policy.transition_timeout_ms,
        classify_reset_response,
    );
    let recovery_command = format!(
        "format {{__EMBEDDED_DEBUGGER_RECOVERY_V1__%d}} [catch {{targets {}; resume}}]",
        initial.target_name
    );
    let recovery = transition_target_with_checked_command(
        &server,
        &initial.target_name,
        "resume_after_reset",
        &recovery_command,
        "running",
        plan.reset_policy.transition_timeout_ms,
        classify_recovery_response,
    );
    let completion = server.finish();

    if !transition_reached_state(&recovery, "running") {
        let error = DebugError::verification(
            "confirmed OpenOCD reset roundtrip did not recover the selected target to running",
            json!({"reset": reset, "recovery": recovery}),
        );
        return Err(with_server_context(
            error,
            completion,
            Some(&initial),
            Some(&reset),
            Some(&recovery),
        ));
    }
    if !reset.complete {
        let error = DebugError::verification(
            "confirmed OpenOCD reset roundtrip did not prove reset halt on the selected target",
            json!({"reset": reset, "recovery": recovery}),
        );
        return Err(with_server_context(
            error,
            completion,
            Some(&initial),
            Some(&reset),
            Some(&recovery),
        ));
    }
    if !recovery.complete {
        let error = DebugError::new(
            ErrorCode::ProtocolError,
            "OpenOCD recovery command did not complete cleanly even though running was observed",
            6,
            json!({"reset": reset, "recovery": recovery}),
        );
        return Err(with_server_context(
            error,
            completion,
            Some(&initial),
            Some(&reset),
            Some(&recovery),
        ));
    }
    if let Some(message) = completion.lifecycle_error() {
        let error = DebugError::new(
            ErrorCode::ProtocolError,
            message,
            6,
            json!({"initial": initial, "reset": reset, "recovery": recovery}),
        );
        return Err(with_server_context(
            error,
            completion,
            Some(&initial),
            Some(&reset),
            Some(&recovery),
        ));
    }

    Ok(OpenOcdResetTestReport {
        backend: plan.backend,
        scope: "confirmed_global_reset_selected_target_recovery".to_string(),
        risk: plan.risk,
        complete: true,
        confirm_digest: plan.confirm_digest,
        openocd: plan.openocd,
        protocol: plan.protocol,
        reset_policy: plan.reset_policy,
        readiness: completion.readiness,
        initial,
        reset,
        recovery,
        shutdown: completion.shutdown,
        logs: completion.logs,
        effects: plan.effects,
        confirmation_boundary: plan.confirmation_boundary,
        capabilities: reset_capabilities(),
    })
}

fn reset_protocol() -> OpenOcdResetProtocol {
    OpenOcdResetProtocol {
        transport: "bounded_tcl_rpc".to_string(),
        message_terminator: "0x1a".to_string(),
        commands: vec![
            protocol_command("select", "target current", "exact confirmed target name"),
            protocol_command(
                "observe_initial",
                "<validated_current_target> curstate",
                "running",
            ),
            protocol_command(
                "reset",
                RESET_HALT_ENVELOPE_COMMAND,
                "Tcl catch code 0 and selected target halted state proven by bounded polling",
            ),
            protocol_command(
                "recover",
                RESET_RECOVERY_COMMAND_TEMPLATE,
                "Tcl catch code 0 and selected target running state proven by bounded polling",
            ),
            protocol_command("shutdown", "shutdown", "graceful OpenOCD exit"),
        ],
        target_name_interpolation:
            "only the validated runtime target that exactly matches the confirmed name".to_string(),
        arbitrary_commands: false,
    }
}

fn protocol_command(
    phase: &str,
    command: &str,
    required_result: &str,
) -> OpenOcdResetProtocolCommand {
    OpenOcdResetProtocolCommand {
        phase: phase.to_string(),
        command: command.to_string(),
        required_result: required_result.to_string(),
    }
}

fn reset_policy(expected_target: String, timeout_ms: u64) -> OpenOcdResetPolicy {
    OpenOcdResetPolicy {
        expected_current_target: expected_target,
        initial_state_required: "running".to_string(),
        reset_command: RESET_HALT_ENVELOPE_COMMAND.to_string(),
        reset_scope: "all_defined_targets_per_openocd_reset_semantics".to_string(),
        selected_target_post_reset_state_required: "halted".to_string(),
        recovery_command_template: RESET_RECOVERY_COMMAND_TEMPLATE.to_string(),
        selected_target_final_state_required: "running".to_string(),
        transition_timeout_ms: timeout_ms,
        recovery_attempted_after_every_reset_result: true,
        non_selected_target_final_state_policy:
            "not observed or restored; configuration and reset event handlers define their outcome"
                .to_string(),
    }
}

fn classify_reset_response(response: &str) -> std::result::Result<String, String> {
    classify_catch_response(response, RESET_HALT_ENVELOPE_PREFIX, "OpenOCD reset halt")
}

fn classify_recovery_response(response: &str) -> std::result::Result<String, String> {
    classify_catch_response(
        response,
        RESET_RECOVERY_ENVELOPE_PREFIX,
        "OpenOCD selected-target recovery",
    )
}

fn classify_catch_response(
    response: &str,
    prefix: &str,
    label: &str,
) -> std::result::Result<String, String> {
    let Some(code) = response.strip_prefix(prefix) else {
        return Err(format!("{label} returned a malformed Tcl catch envelope"));
    };
    if code == "0" {
        return Ok(response.to_string());
    }
    if code.is_empty() || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("{label} returned a malformed Tcl catch code"));
    }
    Err(format!("{label} Tcl command returned catch code {code}"))
}

fn reset_effects() -> OpenOcdResetEffects {
    OpenOcdResetEffects {
        configuration_tcl_execution_required: true,
        adapter_or_target_access_possible_from_configuration: true,
        reset_or_device_write_possible_from_configuration: true,
        arbitrary_host_command_execution_possible_from_configuration: true,
        explicit_reset_requested: true,
        explicit_reset_halt_requested: true,
        reset_scope_all_defined_targets: true,
        reset_event_handlers_execute: true,
        reset_init_requested: false,
        selected_target_resume_requested: true,
        selected_target_final_running_verification_required: true,
        non_selected_target_final_states_verified: false,
        volatile_register_or_memory_state_change_expected: true,
        peripheral_state_change_expected: true,
        external_io_disruption_expected: true,
        flash_command_requested: false,
        explicit_register_or_memory_command_requested: false,
        gdb_or_monitor_command_requested: false,
        arbitrary_tcl_command_requested: false,
        notes: vec![
            "OpenOCD reset acts on all defined targets and fires configured reset events."
                .to_string(),
            "Configuration and reset event handlers are executable Tcl; only top-level configuration files are hashed."
                .to_string(),
            "The reset mechanism is target and adapter dependent and may be hard, soft, or partly implemented by target event handlers."
                .to_string(),
            "The tool verifies and recovers only the exact selected target; non-selected target final states remain unverified."
                .to_string(),
            "The tool always attempts the one fixed catch-wrapped selected-target resume after the reset result and requires catch code zero plus final running."
                .to_string(),
            "The tool sends no reset init, second reset, flash, target-data, GDB, monitor, or arbitrary Tcl command."
                .to_string(),
        ],
    }
}

fn reset_confirmation_boundary() -> OpenOcdResetConfirmationBoundary {
    OpenOcdResetConfirmationBoundary {
        openocd_executable_file_hash_bound: true,
        openocd_version_bound: true,
        top_level_configuration_hashes_bound: true,
        search_directory_paths_bound: true,
        search_directory_contents_bound: false,
        transitive_sources_bound: false,
        fixed_tcl_protocol_bound: true,
        fixed_reset_mode_bound: true,
        global_reset_scope_bound: true,
        lifecycle_deadlines_bound: true,
        target_transition_deadline_bound: true,
        expected_target_name_bound: true,
        selected_target_state_policy_bound: true,
        loopback_dynamic_endpoint_policy_bound: true,
        runtime_port_number_bound: false,
        runtime_adapter_identity_bound: false,
        non_selected_target_inventory_bound: false,
        non_selected_target_initial_states_bound: false,
        non_selected_target_final_states_bound: false,
    }
}

fn reset_capabilities() -> OpenOcdResetCapabilities {
    OpenOcdResetCapabilities {
        server_launch: true,
        tcl_rpc: true,
        selected_target_state_observation: true,
        target_control: true,
        reset: true,
        fixed_reset_halt: true,
        fixed_selected_target_resume: true,
        final_selected_target_running_verification: true,
        non_selected_target_state_verification: false,
        gdb_mi: false,
        register_read: false,
        memory_read: false,
        stack_read: false,
        breakpoints: false,
        watchpoints: false,
        flash: false,
        arbitrary_commands: false,
    }
}

fn reset_confirmation_error(expected: &str, received: &str) -> DebugError {
    let mut error = DebugError::new(
        ErrorCode::ConfirmationMismatch,
        "OpenOCD reset confirmation digest does not match the current reset plan",
        2,
        json!({
            "expected_confirm_digest": expected,
            "received_confirm_digest": received,
        }),
    );
    error.suggested_actions.push(SuggestedAction::new(
        "review_openocd_reset_plan",
        json!({"command": "openocd reset plan"}),
    ));
    error
}

fn with_server_context(
    mut error: DebugError,
    completion: ManagedServerCompletion,
    initial: Option<&OpenOcdTargetStateObservation>,
    reset: Option<&OpenOcdTargetTransition>,
    recovery: Option<&OpenOcdTargetTransition>,
) -> DebugError {
    let mut details = error.details.as_object().cloned().unwrap_or_default();
    if let Some(initial) = initial {
        details.insert(
            "initial".to_string(),
            serde_json::to_value(initial).expect("target observation always serializes"),
        );
    }
    if let Some(reset) = reset {
        details.insert(
            "reset".to_string(),
            serde_json::to_value(reset).expect("reset transition always serializes"),
        );
    }
    if let Some(recovery) = recovery {
        details.insert(
            "recovery".to_string(),
            serde_json::to_value(recovery).expect("recovery transition always serializes"),
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

    const HELPER_ROLE: &str = "EMBEDDED_DEBUGGER_OPENOCD_RESET_HELPER_ROLE";
    const HELPER_MODE: &str = "EMBEDDED_DEBUGGER_OPENOCD_RESET_HELPER_MODE";

    #[test]
    fn reset_catch_envelope_accepts_only_an_exact_zero_code() {
        assert!(classify_reset_response("__EMBEDDED_DEBUGGER_RESET_V1__0").is_ok());
        assert_eq!(
            classify_reset_response("__EMBEDDED_DEBUGGER_RESET_V1__1").unwrap_err(),
            "OpenOCD reset halt Tcl command returned catch code 1"
        );
        assert!(classify_reset_response("reset halt failed").is_err());
        assert!(classify_reset_response("__EMBEDDED_DEBUGGER_RESET_V1__ok").is_err());
        assert!(classify_recovery_response("__EMBEDDED_DEBUGGER_RECOVERY_V1__0").is_ok());
        assert_eq!(
            classify_recovery_response("__EMBEDDED_DEBUGGER_RECOVERY_V1__2").unwrap_err(),
            "OpenOCD selected-target recovery Tcl command returned catch code 2"
        );
    }

    #[test]
    fn reset_plan_binds_the_fixed_global_reset_and_selected_target_recovery() {
        let directory = tempdir().unwrap();
        let openocd = write_fake_openocd(directory.path(), "normal");
        let config = directory.path().join("board.cfg");
        fs::write(&config, b"adapter speed 1000\n").unwrap();
        let options = reset_options(openocd, config, directory.path(), 5_000);

        let first = plan_reset(&options).unwrap();
        let second = plan_reset(&options).unwrap();

        assert_eq!(first.operation, "openocd.reset.test");
        assert_eq!(first.risk, "R2_DEVICE_WRITE");
        assert_eq!(first.protocol.commands.len(), 5);
        assert_eq!(
            first.protocol.commands[2].command,
            RESET_HALT_ENVELOPE_COMMAND
        );
        assert_eq!(
            first.protocol.commands[3].command,
            RESET_RECOVERY_COMMAND_TEMPLATE
        );
        assert!(first.effects.explicit_reset_requested);
        assert!(first.effects.reset_scope_all_defined_targets);
        assert!(first.effects.reset_event_handlers_execute);
        assert!(first.effects.selected_target_resume_requested);
        assert!(!first.effects.reset_init_requested);
        assert!(!first.effects.non_selected_target_final_states_verified);
        assert!(first.confirmation_boundary.fixed_reset_mode_bound);
        assert!(first.confirmation_boundary.global_reset_scope_bound);
        assert!(!first.confirmation_boundary.runtime_adapter_identity_bound);
        assert_eq!(first.confirm_digest, second.confirm_digest);

        let mut changed_target = options.clone();
        changed_target.expected_target = "fake.cpu1".to_string();
        assert_ne!(
            first.confirm_digest,
            plan_reset(&changed_target).unwrap().confirm_digest
        );
        let mut changed_timeout = options;
        changed_timeout.target_state_timeout_ms = 4_999;
        assert_ne!(
            first.confirm_digest,
            plan_reset(&changed_timeout).unwrap().confirm_digest
        );
    }

    #[test]
    fn confirmed_reset_proves_halted_then_selected_target_running_and_cleans_up() {
        let directory = tempdir().unwrap();
        let openocd = write_fake_openocd(directory.path(), "normal");
        let config = directory.path().join("board.cfg");
        fs::write(&config, b"adapter speed 1000\n").unwrap();
        let options = reset_options(openocd, config, directory.path(), 5_000);

        let plan = plan_reset(&options).unwrap();
        let report = test_reset(&options, &plan.confirm_digest).unwrap();

        assert!(report.complete);
        assert_eq!(report.initial.state, "running");
        assert!(report.reset.complete);
        assert_eq!(report.reset.observation.as_ref().unwrap().state, "halted");
        assert!(report.recovery.complete);
        assert_eq!(
            report.recovery.observation.as_ref().unwrap().state,
            "running"
        );
        assert!(report.shutdown.graceful);
        assert!(report.shutdown.process_tree_cleanup_complete);
        assert!(report.capabilities.reset);
        assert!(report.capabilities.fixed_reset_halt);
        assert!(report.capabilities.fixed_selected_target_resume);
        assert!(!report.capabilities.non_selected_target_state_verification);
        assert!(!report.capabilities.gdb_mi);
        assert!(!report.capabilities.flash);
    }

    #[test]
    fn ineffective_reset_still_runs_recovery_and_reports_failure() {
        let directory = tempdir().unwrap();
        let openocd = write_fake_openocd(directory.path(), "ignore_reset");
        let config = directory.path().join("board.cfg");
        fs::write(&config, b"adapter speed 1000\n").unwrap();
        let options = reset_options(openocd, config, directory.path(), 150);

        let plan = plan_reset(&options).unwrap();
        let error = test_reset(&options, &plan.confirm_digest).unwrap_err();

        assert_eq!(error.code, ErrorCode::VerificationFailed);
        assert_eq!(error.details["reset"]["complete"], false);
        assert_eq!(error.details["reset"]["observation"]["state"], "running");
        assert_eq!(error.details["recovery"]["complete"], true);
        assert_eq!(error.details["recovery"]["observation"]["state"], "running");
        assert_eq!(error.details["openocd_shutdown"]["graceful"], true);
    }

    #[test]
    fn caught_reset_error_is_failure_even_when_halted_was_observed() {
        let directory = tempdir().unwrap();
        let openocd = write_fake_openocd(directory.path(), "reset_error");
        let config = directory.path().join("board.cfg");
        fs::write(&config, b"adapter speed 1000\n").unwrap();
        let options = reset_options(openocd, config, directory.path(), 5_000);

        let plan = plan_reset(&options).unwrap();
        let error = test_reset(&options, &plan.confirm_digest).unwrap_err();

        assert_eq!(error.code, ErrorCode::VerificationFailed);
        assert_eq!(error.details["reset"]["complete"], false);
        assert_eq!(error.details["reset"]["observation"]["state"], "halted");
        assert_eq!(
            error.details["reset"]["command_error"],
            "OpenOCD reset halt Tcl command returned catch code 1"
        );
        assert_eq!(error.details["recovery"]["complete"], true);
        assert_eq!(error.details["recovery"]["observation"]["state"], "running");
        assert_eq!(error.details["openocd_shutdown"]["graceful"], true);
    }

    #[test]
    fn failed_recovery_preserves_indeterminate_final_state_evidence() {
        let directory = tempdir().unwrap();
        let openocd = write_fake_openocd(directory.path(), "ignore_recovery");
        let config = directory.path().join("board.cfg");
        fs::write(&config, b"adapter speed 1000\n").unwrap();
        let options = reset_options(openocd, config, directory.path(), 150);

        let plan = plan_reset(&options).unwrap();
        let error = test_reset(&options, &plan.confirm_digest).unwrap_err();

        assert_eq!(error.code, ErrorCode::VerificationFailed);
        assert_eq!(error.details["reset"]["complete"], true);
        assert_eq!(error.details["reset"]["observation"]["state"], "halted");
        assert_eq!(error.details["recovery"]["complete"], false);
        assert_eq!(error.details["recovery"]["observation"]["state"], "halted");
        assert_eq!(error.details["openocd_shutdown"]["graceful"], true);
    }

    #[test]
    fn caught_recovery_error_is_failure_even_when_running_was_observed() {
        let directory = tempdir().unwrap();
        let openocd = write_fake_openocd(directory.path(), "recovery_error");
        let config = directory.path().join("board.cfg");
        fs::write(&config, b"adapter speed 1000\n").unwrap();
        let options = reset_options(openocd, config, directory.path(), 5_000);

        let plan = plan_reset(&options).unwrap();
        let error = test_reset(&options, &plan.confirm_digest).unwrap_err();

        assert_eq!(error.code, ErrorCode::ProtocolError);
        assert_eq!(error.details["reset"]["complete"], true);
        assert_eq!(error.details["recovery"]["complete"], false);
        assert_eq!(error.details["recovery"]["observation"]["state"], "running");
        assert_eq!(
            error.details["recovery"]["command_error"],
            "OpenOCD selected-target recovery Tcl command returned catch code 1"
        );
        assert_eq!(error.details["openocd_shutdown"]["graceful"], true);
    }

    #[test]
    fn confirmed_target_mismatch_stops_before_reset() {
        let directory = tempdir().unwrap();
        let openocd = write_fake_openocd(directory.path(), "mismatch");
        let config = directory.path().join("board.cfg");
        fs::write(&config, b"adapter speed 1000\n").unwrap();
        let options = reset_options(openocd, config, directory.path(), 5_000);

        let plan = plan_reset(&options).unwrap();
        let error = test_reset(&options, &plan.confirm_digest).unwrap_err();

        assert_eq!(error.code, ErrorCode::VerificationFailed);
        assert_eq!(error.details["expected_current_target"], "fake.cpu0");
        assert_eq!(error.details["observed_current_target"], "other.cpu0");
        assert_eq!(error.details["reset_started"], false);
        assert_eq!(error.details["openocd_shutdown"]["graceful"], true);
        assert!(error.details.get("reset").is_none());
    }

    #[test]
    fn non_running_origin_stops_before_reset() {
        let directory = tempdir().unwrap();
        let openocd = write_fake_openocd(directory.path(), "initial_halted");
        let config = directory.path().join("board.cfg");
        fs::write(&config, b"adapter speed 1000\n").unwrap();
        let options = reset_options(openocd, config, directory.path(), 5_000);

        let plan = plan_reset(&options).unwrap();
        let error = test_reset(&options, &plan.confirm_digest).unwrap_err();

        assert_eq!(error.code, ErrorCode::VerificationFailed);
        assert_eq!(error.details["initial_observation"]["state"], "halted");
        assert_eq!(error.details["required_initial_state"], "running");
        assert_eq!(error.details["reset_started"], false);
        assert_eq!(error.details["openocd_shutdown"]["graceful"], true);
        assert!(error.details.get("reset").is_none());
    }

    #[test]
    fn reset_timeout_is_validated_before_executable_lookup() {
        let options = OpenOcdResetOptions {
            openocd: OpenOcdServerOptions {
                executable: PathBuf::from("missing-openocd"),
                config_files: vec![PathBuf::from("missing.cfg")],
                search_dirs: Vec::new(),
                version_timeout_ms: super::super::DEFAULT_OPENOCD_VERSION_TIMEOUT_MS,
                startup_timeout_ms: super::super::DEFAULT_OPENOCD_SERVER_STARTUP_TIMEOUT_MS,
                shutdown_timeout_ms: super::super::DEFAULT_OPENOCD_SERVER_SHUTDOWN_TIMEOUT_MS,
            },
            expected_target: "fake.cpu0".to_string(),
            target_state_timeout_ms: super::super::MIN_OPENOCD_TARGET_STATE_TIMEOUT_MS - 1,
        };

        let error = plan_reset(&options).unwrap_err();

        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert_eq!(error.details["timeout_kind"], "target_state");
    }

    #[test]
    fn managed_reset_openocd_helper() {
        if std::env::var_os(HELPER_ROLE).is_none() {
            return;
        }
        let mode = std::env::var(HELPER_MODE).unwrap();
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

        let mut state = if mode == "initial_halted" {
            "halted"
        } else {
            "running"
        };
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
                b"target current" if mode == "mismatch" => {
                    stream.write_all(b"other.cpu0\x1a").unwrap()
                }
                b"target current" => stream.write_all(b"fake.cpu0\x1a").unwrap(),
                b"fake.cpu0 curstate" | b"other.cpu0 curstate" => {
                    stream.write_all(state.as_bytes()).unwrap();
                    stream.write_all(b"\x1a").unwrap();
                }
                request if request == RESET_HALT_ENVELOPE_COMMAND.as_bytes() => {
                    if mode != "ignore_reset" {
                        state = "halted";
                    }
                    if mode == "reset_error" {
                        stream
                            .write_all(b"__EMBEDDED_DEBUGGER_RESET_V1__1\x1a")
                            .unwrap();
                    } else {
                        stream
                            .write_all(b"__EMBEDDED_DEBUGGER_RESET_V1__0\x1a")
                            .unwrap();
                    }
                }
                b"format {__EMBEDDED_DEBUGGER_RECOVERY_V1__%d} [catch {targets fake.cpu0; resume}]" => {
                    if mode != "ignore_recovery" {
                        state = "running";
                    }
                    if mode == "recovery_error" {
                        stream
                            .write_all(b"__EMBEDDED_DEBUGGER_RECOVERY_V1__1\x1a")
                            .unwrap();
                    } else {
                        stream
                            .write_all(b"__EMBEDDED_DEBUGGER_RECOVERY_V1__0\x1a")
                            .unwrap();
                    }
                }
                b"shutdown" => break,
                _ => stream.write_all(b"unknown command\x1a").unwrap(),
            }
        }
        drop(gdb);
    }

    fn reset_options(
        openocd: PathBuf,
        config: PathBuf,
        search: &Path,
        timeout_ms: u64,
    ) -> OpenOcdResetOptions {
        OpenOcdResetOptions {
            openocd: OpenOcdServerOptions {
                executable: openocd,
                config_files: vec![config],
                search_dirs: vec![search.to_path_buf()],
                version_timeout_ms: super::super::DEFAULT_OPENOCD_VERSION_TIMEOUT_MS,
                startup_timeout_ms: 5_000,
                shutdown_timeout_ms: 5_000,
            },
            expected_target: "fake.cpu0".to_string(),
            target_state_timeout_ms: timeout_ms,
        }
    }

    fn write_fake_openocd(directory: &Path, mode: &str) -> PathBuf {
        let current_exe = std::env::current_exe().unwrap();
        let helper = "backend::openocd::reset::tests::managed_reset_openocd_helper";
        #[cfg(windows)]
        {
            let executable = directory.join(format!("fake-reset-openocd-{mode}.cmd"));
            fs::write(
                &executable,
                format!(
                    "@echo off\r\nif \"%1\"==\"--version\" goto version\r\nset {HELPER_ROLE}=server\r\nset {HELPER_MODE}={mode}\r\n\"{}\" --exact {helper} --nocapture\r\nexit /b %errorlevel%\r\n:version\r\necho Open On-Chip Debugger 0.12.0-test\r\nexit /b 0\r\n",
                    current_exe.display()
                ),
            )
            .unwrap();
            executable
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let executable = directory.join(format!("fake-reset-openocd-{mode}"));
            let escaped_exe = current_exe.to_string_lossy().replace('\'', "'\\''");
            fs::write(
                &executable,
                format!(
                    "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  printf '%s\\n' 'Open On-Chip Debugger 0.12.0-test'\n  exit 0\nfi\n{HELPER_ROLE}=server {HELPER_MODE}={mode} exec '{escaped_exe}' --exact {helper} --nocapture\n"
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
