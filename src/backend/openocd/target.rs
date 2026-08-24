use std::{
    thread,
    time::{Duration, Instant},
};

use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{
    OpenOcdServerConfirmationBoundary, OpenOcdServerEffects, OpenOcdServerLogs,
    OpenOcdServerOptions, OpenOcdServerPlan, OpenOcdServerReadiness, OpenOcdServerShutdown,
    OpenOcdSessionServerPlan, OpenOcdTargetStateObservation,
    server::{ManagedServerCompletion, ManagedServerSession, start_managed_server},
    session::{observe_initial_target, query_target_state, validate_target_name},
};
use crate::{
    SCHEMA_VERSION,
    error::{DebugError, ErrorCode, Result, SuggestedAction},
};

const TARGET_STATE_POLL_INTERVAL: Duration = Duration::from_millis(25);
const TARGET_RESPONSE_SNIPPET_CHARS: usize = 4 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenOcdTargetOptions {
    pub openocd: OpenOcdServerOptions,
    pub expected_target: String,
    pub target_state_timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdTargetPlan {
    pub backend: String,
    pub operation: String,
    pub risk: String,
    pub complete: bool,
    pub openocd: OpenOcdSessionServerPlan,
    pub protocol: OpenOcdTargetProtocol,
    pub target_policy: OpenOcdTargetPolicy,
    pub effects: OpenOcdTargetEffects,
    pub confirmation_boundary: OpenOcdTargetConfirmationBoundary,
    pub confirm_digest: String,
    #[serde(skip)]
    openocd_execution_plan: OpenOcdServerPlan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdTargetProtocol {
    pub transport: String,
    pub message_terminator: String,
    pub commands: Vec<OpenOcdTargetProtocolCommand>,
    pub target_name_interpolation: String,
    pub arbitrary_commands: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdTargetProtocolCommand {
    pub phase: String,
    pub command: String,
    pub required_result: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdTargetPolicy {
    pub expected_current_target: String,
    pub initial_state_required: String,
    pub halt_command_template: String,
    pub halted_state_required: String,
    pub resume_command_template: String,
    pub final_state_required: String,
    pub transition_timeout_ms: u64,
    pub resume_attempted_after_halt_result: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdTargetEffects {
    pub configuration_tcl_execution_required: bool,
    pub adapter_or_target_access_possible_from_configuration: bool,
    pub reset_or_device_write_possible_from_configuration: bool,
    pub arbitrary_host_command_execution_possible_from_configuration: bool,
    pub explicit_target_halt_requested: bool,
    pub explicit_target_resume_requested: bool,
    pub target_execution_interruption_requested: bool,
    pub partial_external_io_possible: bool,
    pub reset_requested_by_tool: bool,
    pub flash_command_requested: bool,
    pub register_or_memory_command_requested: bool,
    pub gdb_or_monitor_command_requested: bool,
    pub final_running_state_verification_required: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdTargetConfirmationBoundary {
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
    pub target_state_policy_bound: bool,
    pub loopback_dynamic_endpoint_policy_bound: bool,
    pub runtime_port_number_bound: bool,
    pub runtime_adapter_identity_bound: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdTargetTransition {
    pub action: String,
    pub command: String,
    pub command_response: Option<String>,
    pub command_error: Option<String>,
    pub required_state: String,
    pub observation: Option<OpenOcdTargetStateObservation>,
    pub observation_error: Option<String>,
    pub elapsed_ms: u64,
    pub timeout_ms: u64,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdTargetTestReport {
    pub backend: String,
    pub scope: String,
    pub risk: String,
    pub complete: bool,
    pub confirm_digest: String,
    pub openocd: OpenOcdSessionServerPlan,
    pub protocol: OpenOcdTargetProtocol,
    pub target_policy: OpenOcdTargetPolicy,
    pub readiness: OpenOcdServerReadiness,
    pub initial: OpenOcdTargetStateObservation,
    pub halt: OpenOcdTargetTransition,
    pub resume: OpenOcdTargetTransition,
    pub shutdown: OpenOcdServerShutdown,
    pub logs: OpenOcdServerLogs,
    pub effects: OpenOcdTargetEffects,
    pub confirmation_boundary: OpenOcdTargetConfirmationBoundary,
    pub capabilities: OpenOcdTargetCapabilities,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdTargetCapabilities {
    pub server_launch: bool,
    pub tcl_rpc: bool,
    pub target_state_observation: bool,
    pub target_control: bool,
    pub halt: bool,
    pub run: bool,
    pub final_state_restoration: bool,
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
struct TargetConfirmationInput<'a> {
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
    protocol: &'a OpenOcdTargetProtocol,
    target_policy: &'a OpenOcdTargetPolicy,
    effects: &'a OpenOcdTargetEffects,
    confirmation_boundary: &'a OpenOcdTargetConfirmationBoundary,
}

pub fn plan_target(options: &OpenOcdTargetOptions) -> Result<OpenOcdTargetPlan> {
    validate_target_options(options)?;
    let openocd_server = super::plan_server(&options.openocd)?;
    let openocd = OpenOcdSessionServerPlan {
        executable: openocd_server.executable.clone(),
        executable_file: openocd_server.executable_file.clone(),
        configuration: openocd_server.configuration.clone(),
        lifecycle: openocd_server.lifecycle.clone(),
        configuration_effects: openocd_server.effects.clone(),
        confirmation_boundary: openocd_server.confirmation_boundary.clone(),
    };
    let protocol = target_protocol();
    let target_policy = target_policy(
        options.expected_target.clone(),
        options.target_state_timeout_ms,
    );
    let effects = target_effects();
    let confirmation_boundary = target_confirmation_boundary();
    let confirmation = TargetConfirmationInput {
        schema_version: SCHEMA_VERSION,
        operation: "openocd.target.test",
        backend: "openocd",
        openocd_executable_path: &openocd.executable.resolved,
        openocd_executable_version: &openocd.executable.version_line,
        openocd_executable_file: &openocd.executable_file,
        openocd_configuration: &openocd.configuration,
        openocd_lifecycle: &openocd.lifecycle,
        openocd_configuration_effects: &openocd.configuration_effects,
        openocd_confirmation_boundary: &openocd.confirmation_boundary,
        protocol: &protocol,
        target_policy: &target_policy,
        effects: &effects,
        confirmation_boundary: &confirmation_boundary,
    };
    let confirm_digest = hex::encode(Sha256::digest(
        serde_json::to_vec(&confirmation).expect("target confirmation input always serializes"),
    ));

    Ok(OpenOcdTargetPlan {
        backend: "openocd".to_string(),
        operation: "openocd.target.test".to_string(),
        risk: "R2_DEVICE_WRITE".to_string(),
        complete: true,
        openocd,
        protocol,
        target_policy,
        effects,
        confirmation_boundary,
        confirm_digest,
        openocd_execution_plan: openocd_server,
    })
}

pub fn test_target(
    options: &OpenOcdTargetOptions,
    confirm_digest: &str,
) -> Result<OpenOcdTargetTestReport> {
    let plan = plan_target(options)?;
    if plan.confirm_digest != confirm_digest {
        return Err(target_confirmation_error(
            &plan.confirm_digest,
            confirm_digest,
        ));
    }
    execute_target_plan(plan)
}

fn execute_target_plan(plan: OpenOcdTargetPlan) -> Result<OpenOcdTargetTestReport> {
    let server = start_managed_server(&plan.openocd_execution_plan)?;
    let initial = match observe_initial_target(&server, plan.target_policy.transition_timeout_ms) {
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
    if initial.target_name != plan.target_policy.expected_current_target {
        let error = DebugError::verification(
            "OpenOCD current target did not match the confirmed target name",
            json!({
                "expected_current_target": plan.target_policy.expected_current_target,
                "observed_current_target": initial.target_name,
                "observed_state": initial.state,
                "target_control_started": false,
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
    if initial.state != plan.target_policy.initial_state_required {
        let error = DebugError::verification(
            "OpenOCD target was not running before the confirmed state roundtrip",
            json!({
                "initial_observation": initial,
                "required_initial_state": plan.target_policy.initial_state_required,
                "target_control_started": false,
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

    let halt = transition_target(
        &server,
        &initial.target_name,
        "halt",
        "halted",
        plan.target_policy.transition_timeout_ms,
    );
    let resume = transition_target(
        &server,
        &initial.target_name,
        "resume",
        "running",
        plan.target_policy.transition_timeout_ms,
    );
    let completion = server.finish();

    if !transition_reached_state(&resume, "running") {
        let error = DebugError::verification(
            "confirmed OpenOCD target roundtrip did not restore the target to running",
            json!({"halt": halt, "resume": resume}),
        );
        return Err(with_server_context(
            error,
            completion,
            Some(&initial),
            Some(&halt),
            Some(&resume),
        ));
    }
    if !halt.complete {
        let error = DebugError::verification(
            "confirmed OpenOCD target roundtrip did not prove the fixed halt transition",
            json!({"halt": halt, "resume": resume}),
        );
        return Err(with_server_context(
            error,
            completion,
            Some(&initial),
            Some(&halt),
            Some(&resume),
        ));
    }
    if !resume.complete {
        let error = DebugError::new(
            ErrorCode::ProtocolError,
            "OpenOCD resume command did not complete cleanly even though running was observed",
            6,
            json!({"halt": halt, "resume": resume}),
        );
        return Err(with_server_context(
            error,
            completion,
            Some(&initial),
            Some(&halt),
            Some(&resume),
        ));
    }
    if let Some(message) = completion.lifecycle_error() {
        let error = DebugError::new(
            ErrorCode::ProtocolError,
            message,
            6,
            json!({"initial": initial, "halt": halt, "resume": resume}),
        );
        return Err(with_server_context(
            error,
            completion,
            Some(&initial),
            Some(&halt),
            Some(&resume),
        ));
    }

    Ok(OpenOcdTargetTestReport {
        backend: plan.backend,
        scope: "confirmed_target_state_roundtrip".to_string(),
        risk: plan.risk,
        complete: true,
        confirm_digest: plan.confirm_digest,
        openocd: plan.openocd,
        protocol: plan.protocol,
        target_policy: plan.target_policy,
        readiness: completion.readiness,
        initial,
        halt,
        resume,
        shutdown: completion.shutdown,
        logs: completion.logs,
        effects: plan.effects,
        confirmation_boundary: plan.confirmation_boundary,
        capabilities: target_capabilities(),
    })
}

fn transition_target(
    server: &ManagedServerSession,
    target_name: &str,
    action: &str,
    required_state: &str,
    timeout_ms: u64,
) -> OpenOcdTargetTransition {
    let started = Instant::now();
    let deadline = started + Duration::from_millis(timeout_ms);
    let command = format!("targets {target_name}; {action}");
    let (command_response, command_error) =
        match server.tcl_request(&command, deadline.saturating_duration_since(Instant::now())) {
            Ok(response) => (Some(bounded_text(response.trim())), None),
            Err(error) => (None, Some(error)),
        };

    let mut observation = None;
    let mut observation_error = None;
    loop {
        match query_target_state(server, target_name, deadline) {
            Ok(state) => {
                let reached = state == required_state;
                observation = Some(OpenOcdTargetStateObservation {
                    target_name: target_name.to_string(),
                    state,
                    elapsed_ms: duration_ms(started.elapsed()),
                });
                if reached {
                    break;
                }
            }
            Err(error) => observation_error = Some(error),
        }
        if Instant::now() >= deadline {
            break;
        }
        thread::sleep(
            TARGET_STATE_POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
        );
    }
    let state_reached = observation
        .as_ref()
        .is_some_and(|observed| observed.state == required_state);
    if !state_reached && observation_error.is_none() {
        observation_error = Some(format!(
            "target did not reach {required_state} before deadline"
        ));
    }
    let complete = command_error.is_none() && state_reached;

    OpenOcdTargetTransition {
        action: action.to_string(),
        command,
        command_response,
        command_error,
        required_state: required_state.to_string(),
        observation,
        observation_error,
        elapsed_ms: duration_ms(started.elapsed()),
        timeout_ms,
        complete,
    }
}

fn transition_reached_state(transition: &OpenOcdTargetTransition, state: &str) -> bool {
    transition
        .observation
        .as_ref()
        .is_some_and(|observation| observation.state == state)
}

fn validate_target_options(options: &OpenOcdTargetOptions) -> Result<()> {
    if options.expected_target != options.expected_target.trim() {
        return Err(DebugError::config(
            "expected OpenOCD target name must not contain surrounding whitespace",
            json!({"expected_target": bounded_text(&options.expected_target)}),
        ));
    }
    validate_target_name(&options.expected_target)
        .map(|_| ())
        .map_err(|error| {
            DebugError::config(
                "expected OpenOCD target name is outside the supported syntax",
                error.details,
            )
        })?;
    if !(super::MIN_OPENOCD_TARGET_STATE_TIMEOUT_MS..=super::MAX_OPENOCD_TARGET_STATE_TIMEOUT_MS)
        .contains(&options.target_state_timeout_ms)
    {
        return Err(DebugError::config(
            "OpenOCD target transition timeout is outside the supported range",
            json!({
                "timeout_kind": "target_state",
                "timeout_ms": options.target_state_timeout_ms,
                "minimum": super::MIN_OPENOCD_TARGET_STATE_TIMEOUT_MS,
                "maximum": super::MAX_OPENOCD_TARGET_STATE_TIMEOUT_MS,
            }),
        ));
    }
    Ok(())
}

fn target_protocol() -> OpenOcdTargetProtocol {
    OpenOcdTargetProtocol {
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
                "halt",
                "targets <validated_current_target>; halt",
                "halted state proven by bounded polling",
            ),
            protocol_command(
                "resume",
                "targets <validated_current_target>; resume",
                "running state proven by bounded polling",
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
) -> OpenOcdTargetProtocolCommand {
    OpenOcdTargetProtocolCommand {
        phase: phase.to_string(),
        command: command.to_string(),
        required_result: required_result.to_string(),
    }
}

fn target_policy(expected_target: String, timeout_ms: u64) -> OpenOcdTargetPolicy {
    OpenOcdTargetPolicy {
        expected_current_target: expected_target,
        initial_state_required: "running".to_string(),
        halt_command_template: "targets <validated_current_target>; halt".to_string(),
        halted_state_required: "halted".to_string(),
        resume_command_template: "targets <validated_current_target>; resume".to_string(),
        final_state_required: "running".to_string(),
        transition_timeout_ms: timeout_ms,
        resume_attempted_after_halt_result: true,
    }
}

fn target_effects() -> OpenOcdTargetEffects {
    OpenOcdTargetEffects {
        configuration_tcl_execution_required: true,
        adapter_or_target_access_possible_from_configuration: true,
        reset_or_device_write_possible_from_configuration: true,
        arbitrary_host_command_execution_possible_from_configuration: true,
        explicit_target_halt_requested: true,
        explicit_target_resume_requested: true,
        target_execution_interruption_requested: true,
        partial_external_io_possible: true,
        reset_requested_by_tool: false,
        flash_command_requested: false,
        register_or_memory_command_requested: false,
        gdb_or_monitor_command_requested: false,
        final_running_state_verification_required: true,
        notes: vec![
            "OpenOCD configuration remains executable Tcl; only top-level files are hashed."
                .to_string(),
            "Halting a running CPU can interrupt peripheral activity and external I/O at a partial record boundary."
                .to_string(),
            "The tool always attempts the fixed resume transition after the halt result and requires a final running observation."
                .to_string(),
            "The tool sends no reset, flash, register, memory, GDB, monitor, or arbitrary Tcl command."
                .to_string(),
        ],
    }
}

fn target_confirmation_boundary() -> OpenOcdTargetConfirmationBoundary {
    OpenOcdTargetConfirmationBoundary {
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
        target_state_policy_bound: true,
        loopback_dynamic_endpoint_policy_bound: true,
        runtime_port_number_bound: false,
        runtime_adapter_identity_bound: false,
    }
}

fn target_capabilities() -> OpenOcdTargetCapabilities {
    OpenOcdTargetCapabilities {
        server_launch: true,
        tcl_rpc: true,
        target_state_observation: true,
        target_control: true,
        halt: true,
        run: true,
        final_state_restoration: true,
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

fn target_confirmation_error(expected: &str, received: &str) -> DebugError {
    let mut error = DebugError::new(
        ErrorCode::ConfirmationMismatch,
        "OpenOCD target confirmation digest does not match the current state-roundtrip plan",
        2,
        json!({
            "expected_confirm_digest": expected,
            "received_confirm_digest": received,
        }),
    );
    error.suggested_actions.push(SuggestedAction::new(
        "review_openocd_target_plan",
        json!({"command": "openocd target plan"}),
    ));
    error
}

fn with_server_context(
    mut error: DebugError,
    completion: ManagedServerCompletion,
    initial: Option<&OpenOcdTargetStateObservation>,
    halt: Option<&OpenOcdTargetTransition>,
    resume: Option<&OpenOcdTargetTransition>,
) -> DebugError {
    let mut details = error.details.as_object().cloned().unwrap_or_default();
    if let Some(initial) = initial {
        details.insert(
            "initial".to_string(),
            serde_json::to_value(initial).expect("target observation always serializes"),
        );
    }
    if let Some(halt) = halt {
        details.insert(
            "halt".to_string(),
            serde_json::to_value(halt).expect("halt transition always serializes"),
        );
    }
    if let Some(resume) = resume {
        details.insert(
            "resume".to_string(),
            serde_json::to_value(resume).expect("resume transition always serializes"),
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

fn bounded_text(value: &str) -> String {
    value.chars().take(TARGET_RESPONSE_SNIPPET_CHARS).collect()
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

    const HELPER_ROLE: &str = "EMBEDDED_DEBUGGER_OPENOCD_TARGET_HELPER_ROLE";
    const HELPER_MODE: &str = "EMBEDDED_DEBUGGER_OPENOCD_TARGET_HELPER_MODE";

    #[test]
    fn target_plan_binds_only_the_fixed_state_roundtrip() {
        let directory = tempdir().unwrap();
        let openocd = write_fake_openocd(directory.path(), "normal");
        let config = directory.path().join("board.cfg");
        fs::write(&config, b"adapter speed 1000\n").unwrap();
        let options = target_options(openocd, config, directory.path(), 5_000);

        let first = plan_target(&options).unwrap();
        let second = plan_target(&options).unwrap();

        assert_eq!(first.operation, "openocd.target.test");
        assert_eq!(first.risk, "R2_DEVICE_WRITE");
        assert_eq!(first.protocol.commands.len(), 5);
        assert_eq!(
            first.protocol.commands[2].command,
            "targets <validated_current_target>; halt"
        );
        assert_eq!(
            first.protocol.commands[3].command,
            "targets <validated_current_target>; resume"
        );
        assert!(first.effects.explicit_target_halt_requested);
        assert!(first.effects.explicit_target_resume_requested);
        assert!(!first.effects.reset_requested_by_tool);
        assert!(!first.effects.flash_command_requested);
        assert!(first.confirmation_boundary.fixed_tcl_protocol_bound);
        assert!(!first.confirmation_boundary.runtime_adapter_identity_bound);
        assert_eq!(first.confirm_digest, second.confirm_digest);

        let mut changed_target = options.clone();
        changed_target.expected_target = "fake.cpu1".to_string();
        assert_ne!(
            first.confirm_digest,
            plan_target(&changed_target).unwrap().confirm_digest
        );
        let mut changed_timeout = options;
        changed_timeout.target_state_timeout_ms = 4_999;
        assert_ne!(
            first.confirm_digest,
            plan_target(&changed_timeout).unwrap().confirm_digest
        );
    }

    #[test]
    fn confirmed_target_roundtrip_proves_halted_then_running_and_cleans_up() {
        let directory = tempdir().unwrap();
        let openocd = write_fake_openocd(directory.path(), "normal");
        let config = directory.path().join("board.cfg");
        fs::write(&config, b"adapter speed 1000\n").unwrap();
        let options = target_options(openocd, config, directory.path(), 5_000);

        let plan = plan_target(&options).unwrap();
        let report = test_target(&options, &plan.confirm_digest).unwrap();

        assert!(report.complete);
        assert_eq!(report.initial.state, "running");
        assert!(report.halt.complete);
        assert_eq!(report.halt.observation.as_ref().unwrap().state, "halted");
        assert!(report.resume.complete);
        assert_eq!(report.resume.observation.as_ref().unwrap().state, "running");
        assert!(report.shutdown.graceful);
        assert!(report.shutdown.process_tree_cleanup_complete);
        assert!(report.capabilities.halt);
        assert!(report.capabilities.run);
        assert!(!report.capabilities.reset);
        assert!(!report.capabilities.gdb_mi);
        assert!(!report.capabilities.flash);
    }

    #[test]
    fn failed_halt_still_runs_the_fixed_resume_and_proves_final_running() {
        let directory = tempdir().unwrap();
        let openocd = write_fake_openocd(directory.path(), "ignore_halt");
        let config = directory.path().join("board.cfg");
        fs::write(&config, b"adapter speed 1000\n").unwrap();
        let options = target_options(openocd, config, directory.path(), 150);

        let plan = plan_target(&options).unwrap();
        let error = test_target(&options, &plan.confirm_digest).unwrap_err();

        assert_eq!(error.code, ErrorCode::VerificationFailed);
        assert_eq!(error.details["halt"]["complete"], false);
        assert_eq!(error.details["halt"]["observation"]["state"], "running");
        assert_eq!(error.details["resume"]["complete"], true);
        assert_eq!(error.details["resume"]["observation"]["state"], "running");
        assert_eq!(error.details["openocd_shutdown"]["graceful"], true);
    }

    #[test]
    fn confirmed_target_mismatch_stops_before_control() {
        let directory = tempdir().unwrap();
        let openocd = write_fake_openocd(directory.path(), "mismatch");
        let config = directory.path().join("board.cfg");
        fs::write(&config, b"adapter speed 1000\n").unwrap();
        let options = target_options(openocd, config, directory.path(), 5_000);

        let plan = plan_target(&options).unwrap();
        let error = test_target(&options, &plan.confirm_digest).unwrap_err();

        assert_eq!(error.code, ErrorCode::VerificationFailed);
        assert_eq!(error.details["expected_current_target"], "fake.cpu0");
        assert_eq!(error.details["observed_current_target"], "other.cpu0");
        assert_eq!(error.details["target_control_started"], false);
        assert_eq!(error.details["openocd_shutdown"]["graceful"], true);
        assert!(error.details.get("halt").is_none());
    }

    #[test]
    fn non_running_origin_stops_before_control() {
        let directory = tempdir().unwrap();
        let openocd = write_fake_openocd(directory.path(), "initial_halted");
        let config = directory.path().join("board.cfg");
        fs::write(&config, b"adapter speed 1000\n").unwrap();
        let options = target_options(openocd, config, directory.path(), 5_000);

        let plan = plan_target(&options).unwrap();
        let error = test_target(&options, &plan.confirm_digest).unwrap_err();

        assert_eq!(error.code, ErrorCode::VerificationFailed);
        assert_eq!(error.details["initial_observation"]["state"], "halted");
        assert_eq!(error.details["required_initial_state"], "running");
        assert_eq!(error.details["target_control_started"], false);
        assert_eq!(error.details["openocd_shutdown"]["graceful"], true);
        assert!(error.details.get("halt").is_none());
    }

    #[test]
    fn target_timeout_is_validated_before_executable_lookup() {
        let options = OpenOcdTargetOptions {
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

        let error = plan_target(&options).unwrap_err();

        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert_eq!(error.details["timeout_kind"], "target_state");
    }

    #[test]
    fn managed_target_openocd_helper() {
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
                b"targets fake.cpu0; halt" => {
                    if mode != "ignore_halt" {
                        state = "halted";
                    }
                    stream.write_all(b"\x1a").unwrap();
                }
                b"targets fake.cpu0; resume" => {
                    state = "running";
                    stream.write_all(b"\x1a").unwrap();
                }
                b"shutdown" => break,
                _ => stream.write_all(b"unknown command\x1a").unwrap(),
            }
        }
        drop(gdb);
    }

    fn target_options(
        openocd: PathBuf,
        config: PathBuf,
        search: &Path,
        timeout_ms: u64,
    ) -> OpenOcdTargetOptions {
        OpenOcdTargetOptions {
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
        let helper = "backend::openocd::target::tests::managed_target_openocd_helper";
        #[cfg(windows)]
        {
            let executable = directory.join(format!("fake-target-openocd-{mode}.cmd"));
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

            let executable = directory.join(format!("fake-target-openocd-{mode}"));
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
