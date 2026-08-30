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
        OpenOcdTargetTransition, transition_target_with_checked_command,
        validate_expected_target_and_timeout,
    },
};
use crate::{
    SCHEMA_VERSION,
    error::{DebugError, ErrorCode, Result, SuggestedAction},
};

const RESUME_ENVELOPE_PREFIX: &str = "__EMBEDDED_DEBUGGER_RESUME_ONLY_V1__";
const RESUME_COMMAND_TEMPLATE: &str = "format {__EMBEDDED_DEBUGGER_RESUME_ONLY_V1__%d} [catch {targets <validated_current_target>; resume}]";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenOcdResumeOptions {
    pub openocd: OpenOcdServerOptions,
    pub expected_target: String,
    pub target_state_timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdResumePlan {
    pub backend: String,
    pub operation: String,
    pub risk: String,
    pub complete: bool,
    pub openocd: OpenOcdSessionServerPlan,
    pub protocol: OpenOcdResumeProtocol,
    pub resume_policy: OpenOcdResumePolicy,
    pub effects: OpenOcdResumeEffects,
    pub confirmation_boundary: OpenOcdResumeConfirmationBoundary,
    pub confirm_digest: String,
    #[serde(skip)]
    openocd_execution_plan: OpenOcdServerPlan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdResumeProtocol {
    pub transport: String,
    pub message_terminator: String,
    pub commands: Vec<OpenOcdResumeProtocolCommand>,
    pub target_name_interpolation: String,
    pub arbitrary_commands: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdResumeProtocolCommand {
    pub phase: String,
    pub command: String,
    pub required_result: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdResumePolicy {
    pub expected_current_target: String,
    pub accepted_initial_states: Vec<String>,
    pub resume_origin_required: String,
    pub running_origin_behavior: String,
    pub resume_command_template: String,
    pub final_state_required: String,
    pub transition_timeout_ms: u64,
    pub maximum_resume_command_count: u8,
    pub automatic_retry_allowed: bool,
    pub resume_after_error_allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdResumeEffects {
    pub configuration_tcl_execution_required: bool,
    pub adapter_or_target_access_possible_from_configuration: bool,
    pub reset_or_device_write_possible_from_configuration: bool,
    pub arbitrary_host_command_execution_possible_from_configuration: bool,
    pub explicit_selected_target_resume_possible: bool,
    pub explicit_selected_target_halt_requested: bool,
    pub reset_requested_by_tool: bool,
    pub flash_command_requested: bool,
    pub register_or_memory_command_requested: bool,
    pub gdb_or_monitor_command_requested: bool,
    pub breakpoint_or_watchpoint_command_requested: bool,
    pub arbitrary_tcl_command_requested: bool,
    pub target_firmware_execution_possible: bool,
    pub firmware_defined_external_io_possible: bool,
    pub selected_target_final_running_verification_required: bool,
    pub non_selected_target_states_verified: bool,
    pub automatic_retry_allowed: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdResumeConfirmationBoundary {
    pub openocd_executable_file_hash_bound: bool,
    pub openocd_version_bound: bool,
    pub top_level_configuration_hashes_bound: bool,
    pub search_directory_paths_bound: bool,
    pub search_directory_contents_bound: bool,
    pub transitive_sources_bound: bool,
    pub fixed_tcl_protocol_bound: bool,
    pub lifecycle_deadlines_bound: bool,
    pub target_transition_deadline_bound: bool,
    pub expected_target_name_bound: bool,
    pub accepted_initial_state_policy_bound: bool,
    pub maximum_resume_command_count_bound: bool,
    pub automatic_retry_policy_bound: bool,
    pub loopback_dynamic_endpoint_policy_bound: bool,
    pub runtime_port_number_bound: bool,
    pub runtime_adapter_identity_bound: bool,
    pub non_selected_target_inventory_bound: bool,
    pub non_selected_target_states_bound: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdResumeTestReport {
    pub backend: String,
    pub scope: String,
    pub risk: String,
    pub complete: bool,
    pub confirm_digest: String,
    pub openocd: OpenOcdSessionServerPlan,
    pub protocol: OpenOcdResumeProtocol,
    pub resume_policy: OpenOcdResumePolicy,
    pub readiness: OpenOcdServerReadiness,
    pub initial: OpenOcdTargetStateObservation,
    pub resume: Option<OpenOcdTargetTransition>,
    pub final_observation: OpenOcdTargetStateObservation,
    pub resume_command_count: u8,
    pub automatic_retry_count: u8,
    pub shutdown: OpenOcdServerShutdown,
    pub logs: OpenOcdServerLogs,
    pub effects: OpenOcdResumeEffects,
    pub confirmation_boundary: OpenOcdResumeConfirmationBoundary,
    pub capabilities: OpenOcdResumeCapabilities,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdResumeCapabilities {
    pub server_launch: bool,
    pub tcl_rpc: bool,
    pub selected_target_state_observation: bool,
    pub selected_target_resume: bool,
    pub idempotent_running_origin: bool,
    pub final_selected_target_running_verification: bool,
    pub halt: bool,
    pub reset: bool,
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
struct ResumeConfirmationInput<'a> {
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
    protocol: &'a OpenOcdResumeProtocol,
    resume_policy: &'a OpenOcdResumePolicy,
    effects: &'a OpenOcdResumeEffects,
    confirmation_boundary: &'a OpenOcdResumeConfirmationBoundary,
}

pub fn plan_resume(options: &OpenOcdResumeOptions) -> Result<OpenOcdResumePlan> {
    validate_resume_options(options)?;
    let openocd_server = super::plan_server(&options.openocd)?;
    let openocd = OpenOcdSessionServerPlan {
        executable: openocd_server.executable.clone(),
        executable_file: openocd_server.executable_file.clone(),
        configuration: openocd_server.configuration.clone(),
        lifecycle: openocd_server.lifecycle.clone(),
        configuration_effects: openocd_server.effects.clone(),
        confirmation_boundary: openocd_server.confirmation_boundary.clone(),
    };
    let protocol = resume_protocol();
    let resume_policy = resume_policy(
        options.expected_target.clone(),
        options.target_state_timeout_ms,
    );
    let effects = resume_effects();
    let confirmation_boundary = resume_confirmation_boundary();
    let confirmation = ResumeConfirmationInput {
        schema_version: SCHEMA_VERSION,
        operation: "openocd.resume.test",
        backend: "openocd",
        openocd_executable_path: &openocd.executable.resolved,
        openocd_executable_version: &openocd.executable.version_line,
        openocd_executable_file: &openocd.executable_file,
        openocd_configuration: &openocd.configuration,
        openocd_lifecycle: &openocd.lifecycle,
        openocd_configuration_effects: &openocd.configuration_effects,
        openocd_confirmation_boundary: &openocd.confirmation_boundary,
        protocol: &protocol,
        resume_policy: &resume_policy,
        effects: &effects,
        confirmation_boundary: &confirmation_boundary,
    };
    let confirm_digest = hex::encode(Sha256::digest(
        serde_json::to_vec(&confirmation).expect("resume confirmation input always serializes"),
    ));

    Ok(OpenOcdResumePlan {
        backend: "openocd".to_string(),
        operation: "openocd.resume.test".to_string(),
        risk: "R2_DEVICE_WRITE".to_string(),
        complete: true,
        openocd,
        protocol,
        resume_policy,
        effects,
        confirmation_boundary,
        confirm_digest,
        openocd_execution_plan: openocd_server,
    })
}

pub fn test_resume(
    options: &OpenOcdResumeOptions,
    confirm_digest: &str,
) -> Result<OpenOcdResumeTestReport> {
    let plan = plan_resume(options)?;
    if plan.confirm_digest != confirm_digest {
        return Err(resume_confirmation_error(
            &plan.confirm_digest,
            confirm_digest,
        ));
    }
    execute_resume_plan(plan)
}

fn execute_resume_plan(plan: OpenOcdResumePlan) -> Result<OpenOcdResumeTestReport> {
    let server = start_managed_server(&plan.openocd_execution_plan)?;
    let initial = match observe_initial_target(&server, plan.resume_policy.transition_timeout_ms) {
        Ok(observation) => observation,
        Err(error) => {
            return Err(with_server_context(
                error,
                server.finish(),
                None,
                None,
                None,
                0,
            ));
        }
    };
    if initial.target_name != plan.resume_policy.expected_current_target {
        let error = DebugError::verification(
            "OpenOCD current target did not match the confirmed resume-only target name",
            json!({
                "expected_current_target": plan.resume_policy.expected_current_target,
                "observed_current_target": initial.target_name,
                "observed_state": initial.state,
                "resume_started": false,
            }),
        );
        return Err(with_server_context(
            error,
            server.finish(),
            Some(&initial),
            None,
            Some(&initial),
            0,
        ));
    }

    let (resume, final_observation, resume_command_count) = match initial.state.as_str() {
        "running" => (None, Some(initial.clone()), 0),
        "halted" => {
            let command = format!(
                "format {{__EMBEDDED_DEBUGGER_RESUME_ONLY_V1__%d}} [catch {{targets {}; resume}}]",
                initial.target_name
            );
            let transition = transition_target_with_checked_command(
                &server,
                &initial.target_name,
                "resume_only",
                &command,
                "running",
                plan.resume_policy.transition_timeout_ms,
                classify_resume_response,
            );
            let final_observation = transition.observation.clone();
            (Some(transition), final_observation, 1)
        }
        _ => {
            let error = DebugError::verification(
                "OpenOCD target was neither halted nor running before confirmed resume-only recovery",
                json!({
                    "initial_observation": initial,
                    "accepted_initial_states": plan.resume_policy.accepted_initial_states,
                    "resume_started": false,
                }),
            );
            return Err(with_server_context(
                error,
                server.finish(),
                Some(&initial),
                None,
                Some(&initial),
                0,
            ));
        }
    };
    let completion = server.finish();

    let Some(final_observation) = final_observation else {
        let error = DebugError::verification(
            "confirmed OpenOCD resume-only recovery did not produce a final target observation",
            json!({"resume": resume}),
        );
        return Err(with_server_context(
            error,
            completion,
            Some(&initial),
            resume.as_ref(),
            None,
            resume_command_count,
        ));
    };
    if final_observation.state != plan.resume_policy.final_state_required {
        let error = DebugError::verification(
            "confirmed OpenOCD resume-only recovery did not prove the selected target running",
            json!({"resume": resume, "final_observation": final_observation}),
        );
        return Err(with_server_context(
            error,
            completion,
            Some(&initial),
            resume.as_ref(),
            Some(&final_observation),
            resume_command_count,
        ));
    }
    if let Some(resume) = resume.as_ref()
        && !resume.complete
    {
        let error = DebugError::new(
            ErrorCode::ProtocolError,
            "OpenOCD resume-only command did not complete cleanly even though running was observed",
            6,
            json!({"resume": resume, "final_observation": final_observation}),
        );
        return Err(with_server_context(
            error,
            completion,
            Some(&initial),
            Some(resume),
            Some(&final_observation),
            resume_command_count,
        ));
    }
    if let Some(message) = completion.lifecycle_error() {
        let error = DebugError::new(
            ErrorCode::ProtocolError,
            message,
            6,
            json!({
                "initial": initial,
                "resume": resume,
                "final_observation": final_observation,
            }),
        );
        return Err(with_server_context(
            error,
            completion,
            Some(&initial),
            resume.as_ref(),
            Some(&final_observation),
            resume_command_count,
        ));
    }

    Ok(OpenOcdResumeTestReport {
        backend: plan.backend,
        scope: "confirmed_selected_target_resume_only".to_string(),
        risk: plan.risk,
        complete: true,
        confirm_digest: plan.confirm_digest,
        openocd: plan.openocd,
        protocol: plan.protocol,
        resume_policy: plan.resume_policy,
        readiness: completion.readiness,
        initial,
        resume,
        final_observation,
        resume_command_count,
        automatic_retry_count: 0,
        shutdown: completion.shutdown,
        logs: completion.logs,
        effects: plan.effects,
        confirmation_boundary: plan.confirmation_boundary,
        capabilities: resume_capabilities(),
    })
}

fn validate_resume_options(options: &OpenOcdResumeOptions) -> Result<()> {
    validate_expected_target_and_timeout(&options.expected_target, options.target_state_timeout_ms)
}

fn resume_protocol() -> OpenOcdResumeProtocol {
    OpenOcdResumeProtocol {
        transport: "bounded_tcl_rpc".to_string(),
        message_terminator: "0x1a".to_string(),
        commands: vec![
            protocol_command("select", "target current", "exact confirmed target name"),
            protocol_command(
                "observe_initial",
                "<validated_current_target> curstate",
                "halted or running; every other state fails before resume",
            ),
            protocol_command(
                "resume_if_halted",
                RESUME_COMMAND_TEMPLATE,
                "issued at most once only from halted; exact Tcl catch code 0",
            ),
            protocol_command(
                "observe_final",
                "<validated_current_target> curstate",
                "after halted-origin resume, running proven within the bounded transition deadline; running origin reuses the initial observation",
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
) -> OpenOcdResumeProtocolCommand {
    OpenOcdResumeProtocolCommand {
        phase: phase.to_string(),
        command: command.to_string(),
        required_result: required_result.to_string(),
    }
}

fn resume_policy(expected_target: String, timeout_ms: u64) -> OpenOcdResumePolicy {
    OpenOcdResumePolicy {
        expected_current_target: expected_target,
        accepted_initial_states: vec!["halted".to_string(), "running".to_string()],
        resume_origin_required: "halted".to_string(),
        running_origin_behavior: "skip_resume_and_verify_running".to_string(),
        resume_command_template: RESUME_COMMAND_TEMPLATE.to_string(),
        final_state_required: "running".to_string(),
        transition_timeout_ms: timeout_ms,
        maximum_resume_command_count: 1,
        automatic_retry_allowed: false,
        resume_after_error_allowed: false,
    }
}

fn classify_resume_response(response: &str) -> std::result::Result<String, String> {
    let Some(code) = response.strip_prefix(RESUME_ENVELOPE_PREFIX) else {
        return Err(
            "OpenOCD resume-only command returned a malformed Tcl catch envelope".to_string(),
        );
    };
    if code == "0" {
        return Ok(response.to_string());
    }
    if code.is_empty() || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("OpenOCD resume-only command returned a malformed Tcl catch code".to_string());
    }
    Err(format!(
        "OpenOCD resume-only Tcl command returned catch code {code}"
    ))
}

fn resume_effects() -> OpenOcdResumeEffects {
    OpenOcdResumeEffects {
        configuration_tcl_execution_required: true,
        adapter_or_target_access_possible_from_configuration: true,
        reset_or_device_write_possible_from_configuration: true,
        arbitrary_host_command_execution_possible_from_configuration: true,
        explicit_selected_target_resume_possible: true,
        explicit_selected_target_halt_requested: false,
        reset_requested_by_tool: false,
        flash_command_requested: false,
        register_or_memory_command_requested: false,
        gdb_or_monitor_command_requested: false,
        breakpoint_or_watchpoint_command_requested: false,
        arbitrary_tcl_command_requested: false,
        target_firmware_execution_possible: true,
        firmware_defined_external_io_possible: true,
        selected_target_final_running_verification_required: true,
        non_selected_target_states_verified: false,
        automatic_retry_allowed: false,
        notes: vec![
            "OpenOCD configuration remains executable Tcl; only top-level files are hashed."
                .to_string(),
            "A halted selected target receives at most one fixed catch-wrapped resume command; a running selected target receives no control command."
                .to_string(),
            "Resumed firmware may perform arbitrary firmware-defined peripheral activity or external I/O."
                .to_string(),
            "The tool observes only the exact selected target and does not prove or restore non-selected target states."
                .to_string(),
            "The tool sends no halt, reset, flash, target-data, GDB, monitor, breakpoint, watchpoint, or arbitrary Tcl command."
                .to_string(),
            "No failure path retries or sends a second resume command.".to_string(),
        ],
    }
}

fn resume_confirmation_boundary() -> OpenOcdResumeConfirmationBoundary {
    OpenOcdResumeConfirmationBoundary {
        openocd_executable_file_hash_bound: true,
        openocd_version_bound: true,
        top_level_configuration_hashes_bound: true,
        search_directory_paths_bound: true,
        search_directory_contents_bound: false,
        transitive_sources_bound: false,
        fixed_tcl_protocol_bound: true,
        lifecycle_deadlines_bound: true,
        target_transition_deadline_bound: true,
        expected_target_name_bound: true,
        accepted_initial_state_policy_bound: true,
        maximum_resume_command_count_bound: true,
        automatic_retry_policy_bound: true,
        loopback_dynamic_endpoint_policy_bound: true,
        runtime_port_number_bound: false,
        runtime_adapter_identity_bound: false,
        non_selected_target_inventory_bound: false,
        non_selected_target_states_bound: false,
    }
}

fn resume_capabilities() -> OpenOcdResumeCapabilities {
    OpenOcdResumeCapabilities {
        server_launch: true,
        tcl_rpc: true,
        selected_target_state_observation: true,
        selected_target_resume: true,
        idempotent_running_origin: true,
        final_selected_target_running_verification: true,
        halt: false,
        reset: false,
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

fn resume_confirmation_error(expected: &str, received: &str) -> DebugError {
    let mut error = DebugError::new(
        ErrorCode::ConfirmationMismatch,
        "OpenOCD resume confirmation digest does not match the current resume-only plan",
        2,
        json!({
            "expected_confirm_digest": expected,
            "received_confirm_digest": received,
        }),
    );
    error.suggested_actions.push(SuggestedAction::new(
        "review_openocd_resume_plan",
        json!({"command": "openocd resume plan"}),
    ));
    error
}

fn with_server_context(
    mut error: DebugError,
    completion: ManagedServerCompletion,
    initial: Option<&OpenOcdTargetStateObservation>,
    resume: Option<&OpenOcdTargetTransition>,
    final_observation: Option<&OpenOcdTargetStateObservation>,
    resume_command_count: u8,
) -> DebugError {
    let mut details = error.details.as_object().cloned().unwrap_or_default();
    if let Some(initial) = initial {
        details.insert(
            "initial".to_string(),
            serde_json::to_value(initial).expect("target observation always serializes"),
        );
    }
    if let Some(resume) = resume {
        details.insert(
            "resume".to_string(),
            serde_json::to_value(resume).expect("resume transition always serializes"),
        );
    }
    if let Some(final_observation) = final_observation {
        details.insert(
            "final_observation".to_string(),
            serde_json::to_value(final_observation).expect("target observation always serializes"),
        );
    }
    details.insert(
        "resume_command_count".to_string(),
        Value::from(resume_command_count),
    );
    details.insert("automatic_retry_count".to_string(), Value::from(0));
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

    const HELPER_ROLE: &str = "EMBEDDED_DEBUGGER_OPENOCD_RESUME_HELPER_ROLE";
    const HELPER_MODE: &str = "EMBEDDED_DEBUGGER_OPENOCD_RESUME_HELPER_MODE";

    #[test]
    fn resume_plan_binds_one_conditional_resume_and_no_other_control() {
        let directory = tempdir().unwrap();
        let openocd = write_fake_openocd(directory.path(), "halted");
        let config = directory.path().join("board.cfg");
        fs::write(&config, b"adapter speed 1000\n").unwrap();
        let options = resume_options(openocd, config, directory.path(), 5_000);

        let first = plan_resume(&options).unwrap();
        let second = plan_resume(&options).unwrap();

        assert_eq!(first.operation, "openocd.resume.test");
        assert_eq!(first.risk, "R2_DEVICE_WRITE");
        assert_eq!(first.protocol.commands.len(), 5);
        assert_eq!(first.protocol.commands[2].command, RESUME_COMMAND_TEMPLATE);
        assert_eq!(
            first.resume_policy.accepted_initial_states,
            ["halted", "running"]
        );
        assert_eq!(first.resume_policy.maximum_resume_command_count, 1);
        assert!(!first.resume_policy.automatic_retry_allowed);
        assert!(!first.effects.explicit_selected_target_halt_requested);
        assert!(!first.effects.reset_requested_by_tool);
        assert!(!first.effects.flash_command_requested);
        assert!(!first.effects.breakpoint_or_watchpoint_command_requested);
        assert!(first.confirmation_boundary.fixed_tcl_protocol_bound);
        assert!(!first.confirmation_boundary.runtime_adapter_identity_bound);
        assert_eq!(first.confirm_digest, second.confirm_digest);

        let mut changed_target = options.clone();
        changed_target.expected_target = "fake.cpu1".to_string();
        assert_ne!(
            first.confirm_digest,
            plan_resume(&changed_target).unwrap().confirm_digest
        );
        let mut changed_timeout = options;
        changed_timeout.target_state_timeout_ms = 4_999;
        assert_ne!(
            first.confirm_digest,
            plan_resume(&changed_timeout).unwrap().confirm_digest
        );
    }

    #[test]
    fn halted_origin_resumes_once_and_proves_running() {
        let directory = tempdir().unwrap();
        let openocd = write_fake_openocd(directory.path(), "halted");
        let config = directory.path().join("board.cfg");
        fs::write(&config, b"adapter speed 1000\n").unwrap();
        let options = resume_options(openocd, config, directory.path(), 5_000);
        let plan = plan_resume(&options).unwrap();

        let report = test_resume(&options, &plan.confirm_digest).unwrap();

        assert!(report.complete);
        assert_eq!(report.initial.state, "halted");
        assert_eq!(report.resume_command_count, 1);
        assert_eq!(report.automatic_retry_count, 0);
        assert!(report.resume.as_ref().unwrap().complete);
        assert_eq!(report.final_observation.state, "running");
        assert!(report.shutdown.graceful);
        assert!(report.shutdown.process_tree_cleanup_complete);
        assert!(report.capabilities.selected_target_resume);
        assert!(!report.capabilities.halt);
        assert!(!report.capabilities.reset);
        assert!(!report.capabilities.watchpoints);
    }

    #[test]
    fn running_origin_is_idempotent_and_sends_no_resume() {
        let directory = tempdir().unwrap();
        let openocd = write_fake_openocd(directory.path(), "running");
        let config = directory.path().join("board.cfg");
        fs::write(&config, b"adapter speed 1000\n").unwrap();
        let options = resume_options(openocd, config, directory.path(), 5_000);
        let plan = plan_resume(&options).unwrap();

        let report = test_resume(&options, &plan.confirm_digest).unwrap();

        assert_eq!(report.initial.state, "running");
        assert!(report.resume.is_none());
        assert_eq!(report.resume_command_count, 0);
        assert_eq!(report.automatic_retry_count, 0);
        assert_eq!(report.final_observation.state, "running");
        assert!(report.shutdown.graceful);
    }

    #[test]
    fn mismatch_and_unsupported_state_stop_before_resume() {
        for mode in ["mismatch", "reset_state"] {
            let directory = tempdir().unwrap();
            let openocd = write_fake_openocd(directory.path(), mode);
            let config = directory.path().join("board.cfg");
            fs::write(&config, b"adapter speed 1000\n").unwrap();
            let options = resume_options(openocd, config, directory.path(), 5_000);
            let plan = plan_resume(&options).unwrap();

            let error = test_resume(&options, &plan.confirm_digest).unwrap_err();

            assert_eq!(error.code, ErrorCode::VerificationFailed);
            assert_eq!(error.details["resume_command_count"], 0);
            assert_eq!(error.details["automatic_retry_count"], 0);
            assert_eq!(error.details["openocd_shutdown"]["graceful"], true);
            assert!(error.details.get("resume").is_none());
        }
    }

    #[test]
    fn failed_resume_is_not_retried_and_preserves_cleanup_evidence() {
        for mode in ["resume_error", "ignore_resume"] {
            let directory = tempdir().unwrap();
            let openocd = write_fake_openocd(directory.path(), mode);
            let config = directory.path().join("board.cfg");
            fs::write(&config, b"adapter speed 1000\n").unwrap();
            let options = resume_options(openocd, config, directory.path(), 150);
            let plan = plan_resume(&options).unwrap();

            let error = test_resume(&options, &plan.confirm_digest).unwrap_err();

            assert_eq!(error.code, ErrorCode::VerificationFailed);
            assert_eq!(error.details["resume_command_count"], 1);
            assert_eq!(error.details["automatic_retry_count"], 0);
            assert_eq!(error.details["resume"]["complete"], false);
            assert_eq!(error.details["openocd_shutdown"]["graceful"], true);
        }
    }

    #[test]
    fn malformed_envelope_fails_even_if_target_reached_running() {
        let directory = tempdir().unwrap();
        let openocd = write_fake_openocd(directory.path(), "malformed_resume");
        let config = directory.path().join("board.cfg");
        fs::write(&config, b"adapter speed 1000\n").unwrap();
        let options = resume_options(openocd, config, directory.path(), 5_000);
        let plan = plan_resume(&options).unwrap();

        let error = test_resume(&options, &plan.confirm_digest).unwrap_err();

        assert_eq!(error.code, ErrorCode::ProtocolError);
        assert_eq!(error.details["resume_command_count"], 1);
        assert_eq!(error.details["automatic_retry_count"], 0);
        assert_eq!(error.details["final_observation"]["state"], "running");
        assert_eq!(error.details["openocd_shutdown"]["graceful"], true);
    }

    #[test]
    fn invalid_timeout_is_rejected_before_executable_lookup() {
        let options = OpenOcdResumeOptions {
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

        let error = plan_resume(&options).unwrap_err();

        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert_eq!(error.details["timeout_kind"], "target_state");
    }

    #[test]
    fn managed_resume_openocd_helper() {
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

        let mut state = match mode.as_str() {
            "running" => "running",
            "reset_state" => "reset",
            _ => "halted",
        };
        let mut resume_count = 0_u8;
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
                b"format {__EMBEDDED_DEBUGGER_RESUME_ONLY_V1__%d} [catch {targets fake.cpu0; resume}]" => {
                    resume_count += 1;
                    assert_eq!(resume_count, 1, "resume-only command was retried");
                    assert!(
                        !matches!(mode.as_str(), "running" | "mismatch" | "reset_state"),
                        "resume-only command ran from an unsupported origin"
                    );
                    match mode.as_str() {
                        "resume_error" => stream
                            .write_all(b"__EMBEDDED_DEBUGGER_RESUME_ONLY_V1__1\x1a")
                            .unwrap(),
                        "ignore_resume" => stream
                            .write_all(b"__EMBEDDED_DEBUGGER_RESUME_ONLY_V1__0\x1a")
                            .unwrap(),
                        "malformed_resume" => {
                            state = "running";
                            stream.write_all(b"malformed\x1a").unwrap();
                        }
                        _ => {
                            state = "running";
                            stream
                                .write_all(b"__EMBEDDED_DEBUGGER_RESUME_ONLY_V1__0\x1a")
                                .unwrap();
                        }
                    }
                }
                b"shutdown" => break,
                _ => stream.write_all(b"unknown command\x1a").unwrap(),
            }
        }
        drop(gdb);
    }

    fn resume_options(
        openocd: PathBuf,
        config: PathBuf,
        search: &Path,
        timeout_ms: u64,
    ) -> OpenOcdResumeOptions {
        OpenOcdResumeOptions {
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
        let helper = "backend::openocd::resume::tests::managed_resume_openocd_helper";
        #[cfg(windows)]
        {
            let executable = directory.join(format!("fake-resume-openocd-{mode}.cmd"));
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

            let executable = directory.join(format!("fake-resume-openocd-{mode}"));
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
