use std::{
    collections::BTreeSet,
    io::{BufRead, Write},
};

use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    SCHEMA_VERSION,
    backend::{DebugBackend, validate_hardware_breakpoint_request},
    error::{DebugError, ErrorCode, Result},
    model::{
        Address, ContinueUntilHaltObservation, ContinueUntilHaltOptions, CoreExecutionAction,
        CoreExecutionObservation, DEFAULT_CONTINUE_UNTIL_HALT_POLL_INTERVAL_MS,
        DEFAULT_CONTINUE_UNTIL_HALT_TIMEOUT_MS, DebugControlEffects, HardwareBreakpointAction,
        HardwareBreakpointObservation, MemoryCoreObservation, MemoryReadRange, OperationRecord,
        RegisterCoreObservation, SessionInfo, validate_continue_until_halt_observation,
        validate_continue_until_halt_options, validate_core_execution_observation,
        validate_hardware_breakpoint_observation, validate_memory_core_observation,
        validate_memory_read_range, validate_register_core_observation,
    },
    service::{
        DebugControlEffectRequest, debug_control_effects, select_probe, sha256_bytes,
        validate_register_request,
    },
};

const MAX_REQUEST_LINE_BYTES: usize = 64 * 1024;
const MAX_REQUEST_ID_BYTES: usize = 128;
const CLOSE_POLICY: &str = "halt_clear_hardware_breakpoints_run_observed_cores_before_disconnect";
const SESSION_STATE_WARNING: &str = "Core state is guaranteed only while this debug session remains open; closing the session or terminating the process may change target state.";
const HALT_SIDE_EFFECT_WARNING: &str = "Halting a running core may interrupt in-flight peripheral or external I/O; resuming later cannot roll back effects already emitted.";
const STEP_SIDE_EFFECT_WARNING: &str = "Stepping executes one target instruction while halted; it may mutate registers, memory, peripherals, and external I/O.";
const BREAKPOINT_SIDE_EFFECT_WARNING: &str = "Hardware breakpoint changes write volatile debug comparator state. Once resumed, a matching instruction address will halt the core; session close clears managed breakpoint slots before resuming observed cores.";
const READ_SIDE_EFFECT_WARNING: &str = "The read may briefly halt a running core; external I/O, peripherals, other cores, and DMA are not rolled back or made atomic.";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionOpenReport {
    pub transport: &'static str,
    pub state: &'static str,
    pub opened_at: String,
    pub risk: String,
    pub session: SessionInfo,
    pub effects: DebugControlEffects,
    pub close_policy: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionStatusReport {
    pub state: &'static str,
    pub opened_at: String,
    pub session: SessionInfo,
    pub observed_core_indexes: Vec<u32>,
    pub hardware_breakpoint_core_indexes: Vec<u32>,
    pub close_policy: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionCoreControlReport {
    pub observed_at: String,
    pub state_scope: &'static str,
    pub session_id: String,
    pub risk: String,
    pub effects: DebugControlEffects,
    pub core: CoreExecutionObservation,
    pub operations: Vec<OperationRecord>,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionContinueUntilHaltReport {
    pub observed_at: String,
    pub state_scope: &'static str,
    pub session_id: String,
    pub risk: String,
    pub effects: DebugControlEffects,
    pub wait: ContinueUntilHaltObservation,
    pub operations: Vec<OperationRecord>,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionHardwareBreakpointReport {
    pub observed_at: String,
    pub state_scope: &'static str,
    pub session_id: String,
    pub risk: String,
    pub effects: DebugControlEffects,
    pub core: HardwareBreakpointObservation,
    pub operations: Vec<OperationRecord>,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionRegisterReadReport {
    pub read_id: String,
    pub captured_at: String,
    pub state_scope: &'static str,
    pub session_id: String,
    pub risk: String,
    pub effects: DebugControlEffects,
    pub core: RegisterCoreObservation,
    pub operations: Vec<OperationRecord>,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionMemoryReadReport {
    pub read_id: String,
    pub captured_at: String,
    pub state_scope: &'static str,
    pub session_id: String,
    pub risk: String,
    pub effects: DebugControlEffects,
    pub core: MemoryCoreObservation,
    pub range: MemoryReadRange,
    pub encoding: String,
    pub data: String,
    pub sha256: String,
    pub operations: Vec<OperationRecord>,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionCloseReport {
    pub state: &'static str,
    pub session_id: String,
    pub close_policy: &'static str,
    pub risk: String,
    pub effects: DebugControlEffects,
    pub hardware_breakpoint_cleanup: Vec<HardwareBreakpointObservation>,
    pub final_core_observations: Vec<CoreExecutionObservation>,
    pub operations: Vec<OperationRecord>,
    pub disconnected: bool,
    pub complete: bool,
}

struct ActiveSession {
    info: SessionInfo,
    opened_at: String,
    observed_cores: BTreeSet<u32>,
    hardware_breakpoint_cores: BTreeSet<u32>,
}

pub struct SessionService<B: DebugBackend> {
    backend: B,
    active: Option<ActiveSession>,
}

impl<B: DebugBackend> SessionService<B> {
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            active: None,
        }
    }

    pub fn open(&mut self, probe_id: &str, target: &str) -> Result<SessionOpenReport> {
        if let Some(active) = &self.active {
            return Err(DebugError::new(
                ErrorCode::ProtocolError,
                "the session service already owns an active debug session",
                6,
                json!({"active_session_id": active.info.session_id}),
            ));
        }

        let target_info = self.backend.target().clone();
        if target != target_info.name {
            return Err(DebugError::unavailable(
                ErrorCode::TargetUnavailable,
                "requested target does not exactly match the session server target",
                json!({"requested": target, "available": target_info.name}),
            ));
        }

        let capabilities = self.backend.capabilities();
        let missing = [
            ("core_status", capabilities.core_status),
            ("run", capabilities.run),
        ]
        .into_iter()
        .filter_map(|(name, enabled)| (!enabled).then_some(name))
        .collect::<Vec<_>>();
        if !missing.is_empty() {
            return Err(DebugError::new(
                ErrorCode::CapabilityUnavailable,
                "selected backend cannot safely own a persistent core-control session",
                6,
                json!({"backend": self.backend.name(), "missing": missing}),
            ));
        }

        let probe = select_probe(&self.backend.list_probes()?, Some(probe_id))?;
        let session = self.backend.attach(&probe.id, &target_info.name)?;
        if session.probe.id != probe.id || session.target != target_info {
            let mismatch = DebugError::new(
                ErrorCode::ProtocolError,
                "backend attached a different probe or target than requested",
                6,
                json!({
                    "requested_probe": probe.id,
                    "received_probe": session.probe.id,
                    "requested_target": target_info,
                    "received_target": session.target,
                }),
            );
            return match self.backend.disconnect(&session) {
                Ok(()) => Err(mismatch),
                Err(cleanup) => Err(with_cleanup_failure(mismatch, cleanup)),
            };
        }

        let opened_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        let report = SessionOpenReport {
            transport: "stdio_jsonl",
            state: "open",
            opened_at: opened_at.clone(),
            risk: "R1_REVERSIBLE_CONTROL".to_string(),
            session: session.clone(),
            effects: debug_control_effects(&self.backend, DebugControlEffectRequest::default()),
            close_policy: CLOSE_POLICY,
        };
        self.active = Some(ActiveSession {
            info: session,
            opened_at,
            observed_cores: BTreeSet::new(),
            hardware_breakpoint_cores: BTreeSet::new(),
        });
        Ok(report)
    }

    pub fn status(&self, session_id: &str) -> Result<SessionStatusReport> {
        let active = self.require_session(session_id)?;
        Ok(SessionStatusReport {
            state: "open",
            opened_at: active.opened_at.clone(),
            session: active.info.clone(),
            observed_core_indexes: active.observed_cores.iter().copied().collect(),
            hardware_breakpoint_core_indexes: active
                .hardware_breakpoint_cores
                .iter()
                .copied()
                .collect(),
            close_policy: CLOSE_POLICY,
        })
    }

    pub fn control_core(
        &mut self,
        session_id: &str,
        core_index: u32,
        action: CoreExecutionAction,
    ) -> Result<SessionCoreControlReport> {
        let session = self.require_session(session_id)?.info.clone();
        validate_session_core_index(&session, core_index)?;
        require_core_action_capability(self.backend.capabilities(), self.backend.name(), action)?;

        let core = self
            .backend
            .control_core_in_session(&session, core_index, action)?;
        validate_control_observation(&session, core_index, action, &core)?;
        self.track_observed_core(core_index);

        Ok(SessionCoreControlReport {
            observed_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            state_scope: "active_session",
            session_id: session.session_id,
            risk: "R1_REVERSIBLE_CONTROL".to_string(),
            effects: debug_control_effects(
                &self.backend,
                DebugControlEffectRequest {
                    instruction_step_requested: action == CoreExecutionAction::Step,
                    execution_continue_requested: action == CoreExecutionAction::Continue,
                    intentional_final_core_state_change_requested: matches!(
                        action,
                        CoreExecutionAction::Halt | CoreExecutionAction::Run
                    ),
                    ..DebugControlEffectRequest::default()
                },
            ),
            core,
            operations: in_session_core_operations(action),
            complete: true,
        })
    }

    pub fn continue_until_halt(
        &mut self,
        session_id: &str,
        core_index: u32,
        options: ContinueUntilHaltOptions,
    ) -> Result<SessionContinueUntilHaltReport> {
        let session = self.require_session(session_id)?.info.clone();
        validate_session_core_index(&session, core_index)?;
        validate_continue_until_halt_options(options).map_err(|problem| {
            DebugError::config(
                "invalid continue-until-halt timing options",
                json!({"problem": problem, "options": options}),
            )
        })?;
        require_capabilities(
            self.backend.name(),
            "core.continue_until_halt",
            &[
                ("core_status", session.capabilities.core_status),
                (
                    "continue_execution",
                    session.capabilities.continue_execution,
                ),
                (
                    "continue_until_halt",
                    session.capabilities.continue_until_halt,
                ),
            ],
        )?;

        let wait = self
            .backend
            .continue_until_halt_in_session(&session, core_index, options)?;
        if wait.continuation.index != core_index {
            return Err(protocol_error(
                "backend returned a different continue-until-halt core than requested",
                json!({
                    "requested_core": core_index,
                    "received_core": wait.continuation.index,
                }),
            ));
        }
        validate_continue_until_halt_observation(&session.target, &wait).map_err(|problem| {
            protocol_error(
                "backend returned an invalid in-session continue-until-halt observation",
                json!({"problem": problem, "wait": wait}),
            )
        })?;
        self.track_observed_core(core_index);

        let mut operations = vec![
            session_operation(1, "core.verify_halted"),
            session_operation(2, "core.continue_execution"),
        ];
        if wait.poll_count > 0 {
            operations.push(session_operation(3, "core.poll_until_halted_or_timeout"));
        }
        operations.push(session_operation(
            operations.len() as u32 + 1,
            "core.observe_halt_or_timeout",
        ));

        Ok(SessionContinueUntilHaltReport {
            observed_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            state_scope: "active_session",
            session_id: session.session_id,
            risk: "R1_REVERSIBLE_CONTROL".to_string(),
            effects: debug_control_effects(
                &self.backend,
                DebugControlEffectRequest {
                    execution_continue_requested: true,
                    ..DebugControlEffectRequest::default()
                },
            ),
            wait,
            operations,
            complete: true,
        })
    }

    pub fn control_hardware_breakpoints(
        &mut self,
        session_id: &str,
        core_index: u32,
        action: HardwareBreakpointAction,
        address: Option<Address>,
        slot: Option<u32>,
    ) -> Result<SessionHardwareBreakpointReport> {
        let session = self.require_session(session_id)?.info.clone();
        validate_session_core_index(&session, core_index)?;
        validate_hardware_breakpoint_request(
            action,
            address,
            slot,
            session.capabilities.hardware_breakpoints,
        )?;
        let mut required = vec![("core_status", session.capabilities.core_status)];
        if action != HardwareBreakpointAction::List {
            required.extend([
                ("halt", session.capabilities.halt),
                ("run", session.capabilities.run),
            ]);
        }
        require_capabilities(
            self.backend.name(),
            match action {
                HardwareBreakpointAction::List => "breakpoints.list",
                HardwareBreakpointAction::Set => "breakpoints.set",
                HardwareBreakpointAction::Clear => "breakpoints.clear",
                HardwareBreakpointAction::ClearAll => "breakpoints.clear_all",
            },
            &required,
        )?;

        if action != HardwareBreakpointAction::List {
            let status = self.backend.control_core_in_session(
                &session,
                core_index,
                CoreExecutionAction::Status,
            )?;
            validate_control_observation(
                &session,
                core_index,
                CoreExecutionAction::Status,
                &status,
            )?;
            if status.state != crate::model::CoreState::Halted {
                return Err(DebugError::config(
                    "hardware breakpoint mutations require the selected core to be halted",
                    json!({
                        "core_index": core_index,
                        "action": action,
                        "original_state": status.state,
                    }),
                ));
            }
            self.track_observed_core(core_index);
            self.active
                .as_mut()
                .expect("active session was validated")
                .hardware_breakpoint_cores
                .insert(core_index);
        }

        let core = self
            .backend
            .control_hardware_breakpoints_in_session(&session, core_index, action, address, slot)?;
        if core.index != core_index || core.action != action {
            return Err(protocol_error(
                "backend returned a different hardware-breakpoint observation than requested",
                json!({
                    "requested_core": core_index,
                    "received_core": core.index,
                    "requested_action": action,
                    "received_action": core.action,
                }),
            ));
        }
        if core.capacity != session.capabilities.hardware_breakpoints {
            return Err(protocol_error(
                "backend hardware-breakpoint capacity does not match the active session",
                json!({
                    "session_capacity": session.capabilities.hardware_breakpoints,
                    "received_capacity": core.capacity,
                }),
            ));
        }
        validate_hardware_breakpoint_observation(&session.target, &core).map_err(|problem| {
            protocol_error(
                "backend returned an invalid in-session hardware-breakpoint observation",
                json!({"problem": problem, "core": core}),
            )
        })?;
        self.track_observed_core(core_index);

        Ok(SessionHardwareBreakpointReport {
            observed_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            state_scope: "active_session",
            session_id: session.session_id,
            risk: "R1_REVERSIBLE_CONTROL".to_string(),
            effects: debug_control_effects(
                &self.backend,
                DebugControlEffectRequest {
                    core_execution_state_restoration_verified: true,
                    hardware_breakpoint_configuration_requested: action
                        != HardwareBreakpointAction::List,
                    hardware_breakpoint_state_verified: true,
                    ..DebugControlEffectRequest::default()
                },
            ),
            core,
            operations: in_session_hardware_breakpoint_operations(action),
            complete: true,
        })
    }

    pub fn read_registers(
        &mut self,
        session_id: &str,
        core_index: u32,
        names: &[String],
    ) -> Result<SessionRegisterReadReport> {
        let session = self.require_session(session_id)?.info.clone();
        validate_session_core_index(&session, core_index)?;
        validate_register_request(names)?;
        require_capabilities(
            self.backend.name(),
            "registers.read",
            &[
                ("halt", self.backend.capabilities().halt),
                ("run", self.backend.capabilities().run),
                ("register_read", self.backend.capabilities().register_read),
            ],
        )?;

        let core = self.backend.read_registers(&session, core_index, names)?;
        if core.index != core_index {
            return Err(protocol_error(
                "backend returned register data for a different core",
                json!({"requested_core": core_index, "received_core": core.index}),
            ));
        }
        validate_register_core_observation(&session.target, &core).map_err(|problem| {
            protocol_error(
                "backend returned an invalid in-session register observation",
                json!({"problem": problem, "core": core}),
            )
        })?;
        self.track_observed_core(core_index);

        Ok(SessionRegisterReadReport {
            read_id: format!("reg_{}", Uuid::new_v4().simple()),
            captured_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            state_scope: "active_session",
            session_id: session.session_id,
            risk: "R1_REVERSIBLE_CONTROL".to_string(),
            effects: debug_control_effects(
                &self.backend,
                DebugControlEffectRequest {
                    core_execution_state_restoration_verified: true,
                    ..DebugControlEffectRequest::default()
                },
            ),
            core,
            operations: vec![
                session_operation(1, "target.capture_original_core_state"),
                session_operation(2, "target.halt_core_if_running"),
                session_operation(3, "registers.read"),
                session_operation(4, "target.restore_original_core_state"),
            ],
            complete: true,
        })
    }

    pub fn read_memory(
        &mut self,
        session_id: &str,
        core_index: u32,
        start: Address,
        length: u64,
    ) -> Result<SessionMemoryReadReport> {
        let session = self.require_session(session_id)?.info.clone();
        validate_session_core_index(&session, core_index)?;
        let range = self.backend.plan_memory_read(core_index, start, length)?;
        validate_memory_read_range(&range).map_err(|problem| {
            protocol_error(
                "backend returned an invalid in-session memory read plan",
                json!({"problem": problem, "range": range}),
            )
        })?;
        require_capabilities(
            self.backend.name(),
            "memory.read",
            &[
                ("halt", self.backend.capabilities().halt),
                ("run", self.backend.capabilities().run),
                ("memory_read", self.backend.capabilities().memory_read),
            ],
        )?;

        let result = self.backend.read_memory(&session, core_index, &range)?;
        if result.core.index != core_index {
            return Err(protocol_error(
                "backend returned memory data for a different core",
                json!({
                    "requested_core": core_index,
                    "received_core": result.core.index,
                }),
            ));
        }
        if result.range != range {
            return Err(protocol_error(
                "backend returned bytes for a different memory range",
                json!({"planned": range, "received": result.range}),
            ));
        }
        if result.bytes.len() as u64 != range.length {
            return Err(protocol_error(
                "backend returned an unexpected number of memory bytes",
                json!({
                    "expected": range.length,
                    "received": result.bytes.len(),
                }),
            ));
        }
        validate_memory_core_observation(&session.target, &result.core).map_err(|problem| {
            protocol_error(
                "backend returned an invalid in-session memory core observation",
                json!({"problem": problem, "core": result.core}),
            )
        })?;
        self.track_observed_core(core_index);

        Ok(SessionMemoryReadReport {
            read_id: format!("mem_{}", Uuid::new_v4().simple()),
            captured_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            state_scope: "active_session",
            session_id: session.session_id,
            risk: "R1_REVERSIBLE_CONTROL".to_string(),
            effects: debug_control_effects(
                &self.backend,
                DebugControlEffectRequest {
                    core_execution_state_restoration_verified: true,
                    memory_read_requested: true,
                    ..DebugControlEffectRequest::default()
                },
            ),
            core: result.core,
            range: result.range,
            encoding: "hex".to_string(),
            data: hex::encode(&result.bytes),
            sha256: sha256_bytes(&result.bytes),
            operations: vec![
                session_operation(1, "memory.plan_read_range"),
                session_operation(2, "target.capture_original_core_state"),
                session_operation(3, "target.halt_core_if_running"),
                session_operation(4, "memory.read_exact"),
                session_operation(5, "target.restore_original_core_state"),
            ],
            complete: true,
        })
    }

    pub fn close(&mut self, session_id: &str) -> Result<SessionCloseReport> {
        let active = self.require_session(session_id)?;
        let session = active.info.clone();
        let observed_cores = active.observed_cores.iter().copied().collect::<Vec<_>>();
        let hardware_breakpoint_cores = active
            .hardware_breakpoint_cores
            .iter()
            .copied()
            .collect::<Vec<_>>();
        let observed_core_count = observed_cores.len();

        let mut hardware_breakpoint_cleanup = Vec::with_capacity(hardware_breakpoint_cores.len());
        let mut breakpoint_cleanup_failures = Vec::new();
        let mut breakpoint_cleanup_halt_count = 0_u32;
        for core_index in hardware_breakpoint_cores.iter().copied() {
            match self.backend.control_core_in_session(
                &session,
                core_index,
                CoreExecutionAction::Halt,
            ) {
                Ok(core) => {
                    if let Err(error) = validate_control_observation(
                        &session,
                        core_index,
                        CoreExecutionAction::Halt,
                        &core,
                    ) {
                        breakpoint_cleanup_failures.push(error_summary(&error));
                        continue;
                    }
                    breakpoint_cleanup_halt_count += 1;
                }
                Err(error) => {
                    breakpoint_cleanup_failures.push(error_summary(&error));
                    continue;
                }
            }
            match self.backend.control_hardware_breakpoints_in_session(
                &session,
                core_index,
                HardwareBreakpointAction::ClearAll,
                None,
                None,
            ) {
                Ok(core) => {
                    if core.index != core_index || core.action != HardwareBreakpointAction::ClearAll
                    {
                        breakpoint_cleanup_failures.push(json!({
                            "code": ErrorCode::ProtocolError,
                            "message": "backend returned a different breakpoint cleanup observation than requested",
                            "details": {
                                "requested_core": core_index,
                                "received_core": core.index,
                                "received_action": core.action,
                            }
                        }));
                    } else if let Err(problem) =
                        validate_hardware_breakpoint_observation(&session.target, &core)
                    {
                        breakpoint_cleanup_failures.push(json!({
                            "code": ErrorCode::ProtocolError,
                            "message": "backend returned invalid breakpoint cleanup evidence",
                            "details": {"core_index": core_index, "problem": problem}
                        }));
                    } else {
                        hardware_breakpoint_cleanup.push(core);
                    }
                }
                Err(error) => breakpoint_cleanup_failures.push(error_summary(&error)),
            }
        }

        let mut final_core_observations = Vec::with_capacity(observed_cores.len());
        let mut resume_failures = Vec::new();
        if breakpoint_cleanup_failures.is_empty() {
            for core_index in observed_cores.iter().copied() {
                match self.backend.control_core_in_session(
                    &session,
                    core_index,
                    CoreExecutionAction::Run,
                ) {
                    Ok(core) => match validate_control_observation(
                        &session,
                        core_index,
                        CoreExecutionAction::Run,
                        &core,
                    ) {
                        Ok(()) => final_core_observations.push(core),
                        Err(error) => resume_failures.push(error_summary(&error)),
                    },
                    Err(error) => resume_failures.push(error_summary(&error)),
                }
            }
        }

        let disconnect_result = self.backend.disconnect(&session);
        if disconnect_result.is_ok() {
            self.active = None;
        }

        let effects = debug_control_effects(
            &self.backend,
            DebugControlEffectRequest {
                intentional_final_core_state_change_requested: observed_core_count != 0,
                hardware_breakpoint_configuration_requested: !hardware_breakpoint_cores.is_empty(),
                hardware_breakpoint_state_verified: !hardware_breakpoint_cores.is_empty()
                    && breakpoint_cleanup_failures.is_empty(),
                ..DebugControlEffectRequest::default()
            },
        );
        let mut operations = (0..breakpoint_cleanup_halt_count)
            .map(|index| {
                session_operation(index + 1, "core.halt_for_breakpoint_cleanup_and_verify")
            })
            .collect::<Vec<_>>();
        let cleanup_operation_start = operations.len() as u32 + 1;
        operations.extend(
            hardware_breakpoint_cleanup
                .iter()
                .enumerate()
                .map(|(index, _)| {
                    session_operation(
                        cleanup_operation_start + index as u32,
                        "breakpoints.clear_all_and_verify",
                    )
                }),
        );
        let resume_operation_start = operations.len() as u32 + 1;
        operations.extend(
            final_core_observations
                .iter()
                .enumerate()
                .map(|(index, _)| {
                    session_operation(
                        resume_operation_start + index as u32,
                        "core.run_observed_and_verify",
                    )
                }),
        );
        operations.push(session_operation(
            operations.len() as u32 + 1,
            "session.disconnect",
        ));

        match (
            breakpoint_cleanup_failures.is_empty(),
            resume_failures.is_empty(),
            disconnect_result,
        ) {
            (true, true, Ok(())) => Ok(SessionCloseReport {
                state: "closed",
                session_id: session.session_id,
                close_policy: CLOSE_POLICY,
                risk: "R1_REVERSIBLE_CONTROL".to_string(),
                effects,
                hardware_breakpoint_cleanup,
                final_core_observations,
                operations,
                disconnected: true,
                complete: true,
            }),
            (false, _, Ok(())) => Err(DebugError::new(
                ErrorCode::ProtocolError,
                "session disconnected, but hardware breakpoints could not be explicitly cleared",
                6,
                json!({
                    "session_id": session.session_id,
                    "session_closed": true,
                    "breakpoint_cleanup_failures": breakpoint_cleanup_failures,
                    "resume_skipped": true,
                }),
            )),
            (true, false, Ok(())) => Err(DebugError::new(
                ErrorCode::ProtocolError,
                "session disconnected, but one or more observed cores could not be explicitly resumed",
                6,
                json!({
                    "session_id": session.session_id,
                    "session_closed": true,
                    "resume_failures": resume_failures,
                }),
            )),
            (true, true, Err(error)) => Err(error),
            (_, _, Err(cleanup)) => Err(DebugError::new(
                ErrorCode::ProtocolError,
                "failed to clean up the active debug session before disconnect",
                6,
                json!({
                    "session_id": session.session_id,
                    "session_closed": false,
                    "breakpoint_cleanup_failures": breakpoint_cleanup_failures,
                    "resume_failures": resume_failures,
                    "disconnect_failure": error_summary(&cleanup),
                }),
            )),
        }
    }

    pub fn close_active(&mut self) -> Result<Option<SessionCloseReport>> {
        let Some(session_id) = self
            .active
            .as_ref()
            .map(|active| active.info.session_id.clone())
        else {
            return Ok(None);
        };
        self.close(&session_id).map(Some)
    }

    pub fn has_active_session(&self) -> bool {
        self.active.is_some()
    }

    fn track_observed_core(&mut self, core_index: u32) {
        self.active
            .as_mut()
            .expect("active session was validated")
            .observed_cores
            .insert(core_index);
    }

    fn require_session(&self, session_id: &str) -> Result<&ActiveSession> {
        let Some(active) = &self.active else {
            return Err(DebugError::new(
                ErrorCode::ProtocolError,
                "the session service does not own an active debug session",
                6,
                json!({"requested_session_id": session_id}),
            ));
        };
        if active.info.session_id != session_id {
            return Err(DebugError::new(
                ErrorCode::ProtocolError,
                "request refers to a stale or foreign debug session",
                6,
                json!({
                    "requested_session_id": session_id,
                    "active_session_id": active.info.session_id,
                }),
            ));
        }
        Ok(active)
    }
}

#[derive(Debug, Deserialize)]
struct SessionRequest {
    schema_version: String,
    request_id: String,
    #[serde(flatten)]
    operation: SessionOperation,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "operation")]
enum SessionOperation {
    #[serde(rename = "session.open")]
    Open { probe: String, target: String },
    #[serde(rename = "session.status")]
    Status { session_id: String },
    #[serde(rename = "core.status")]
    CoreStatus {
        session_id: String,
        #[serde(default)]
        core: u32,
    },
    #[serde(rename = "core.halt")]
    CoreHalt {
        session_id: String,
        #[serde(default)]
        core: u32,
    },
    #[serde(rename = "core.run")]
    CoreRun {
        session_id: String,
        #[serde(default)]
        core: u32,
    },
    #[serde(rename = "core.continue")]
    CoreContinue {
        session_id: String,
        #[serde(default)]
        core: u32,
    },
    #[serde(rename = "core.continue_until_halt")]
    CoreContinueUntilHalt {
        session_id: String,
        #[serde(default)]
        core: u32,
        #[serde(default)]
        timeout_ms: Option<u64>,
        #[serde(default)]
        poll_interval_ms: Option<u64>,
    },
    #[serde(rename = "core.step")]
    CoreStep {
        session_id: String,
        #[serde(default)]
        core: u32,
    },
    #[serde(rename = "breakpoints.list")]
    BreakpointsList {
        session_id: String,
        #[serde(default)]
        core: u32,
    },
    #[serde(rename = "breakpoints.set")]
    BreakpointsSet {
        session_id: String,
        #[serde(default)]
        core: u32,
        address: Address,
        #[serde(default)]
        slot: Option<u32>,
    },
    #[serde(rename = "breakpoints.clear")]
    BreakpointsClear {
        session_id: String,
        #[serde(default)]
        core: u32,
        slot: u32,
    },
    #[serde(rename = "breakpoints.clear_all")]
    BreakpointsClearAll {
        session_id: String,
        #[serde(default)]
        core: u32,
    },
    #[serde(rename = "registers.read")]
    RegistersRead {
        session_id: String,
        #[serde(default)]
        core: u32,
        #[serde(default)]
        names: Vec<String>,
    },
    #[serde(rename = "memory.read")]
    MemoryRead {
        session_id: String,
        #[serde(default)]
        core: u32,
        address: Address,
        length: u64,
    },
    #[serde(rename = "session.close")]
    Close { session_id: String },
    #[serde(rename = "server.shutdown")]
    Shutdown,
}

impl SessionOperation {
    fn name(&self) -> &'static str {
        match self {
            Self::Open { .. } => "session.open",
            Self::Status { .. } => "session.status",
            Self::CoreStatus { .. } => "core.status",
            Self::CoreHalt { .. } => "core.halt",
            Self::CoreRun { .. } => "core.run",
            Self::CoreContinue { .. } => "core.continue",
            Self::CoreContinueUntilHalt { .. } => "core.continue_until_halt",
            Self::CoreStep { .. } => "core.step",
            Self::BreakpointsList { .. } => "breakpoints.list",
            Self::BreakpointsSet { .. } => "breakpoints.set",
            Self::BreakpointsClear { .. } => "breakpoints.clear",
            Self::BreakpointsClearAll { .. } => "breakpoints.clear_all",
            Self::RegistersRead { .. } => "registers.read",
            Self::MemoryRead { .. } => "memory.read",
            Self::Close { .. } => "session.close",
            Self::Shutdown => "server.shutdown",
        }
    }
}

struct HandledResponse {
    operation: &'static str,
    data: Value,
    warnings: Vec<String>,
    shutdown: bool,
}

#[derive(Debug, Serialize)]
struct SessionSuccessEnvelope<'a> {
    schema_version: &'static str,
    ok: bool,
    request_id: &'a str,
    operation: &'a str,
    operation_id: String,
    data: Value,
    warnings: Vec<String>,
    artifacts: Vec<Value>,
}

#[derive(Debug, Serialize)]
struct SessionErrorEnvelope<'a> {
    schema_version: &'static str,
    ok: bool,
    request_id: Option<&'a str>,
    operation: &'a str,
    operation_id: String,
    error: SessionErrorPayload<'a>,
}

#[derive(Debug, Serialize)]
struct SessionErrorPayload<'a> {
    code: ErrorCode,
    message: &'a str,
    retryable: bool,
    details: &'a Value,
    suggested_actions: &'a [crate::error::SuggestedAction],
}

pub fn serve_jsonl<B, R, W, D>(
    backend: B,
    mut input: R,
    mut output: W,
    mut diagnostics: D,
) -> Result<()>
where
    B: DebugBackend,
    R: BufRead,
    W: Write,
    D: Write,
{
    let mut service = SessionService::new(backend);
    let result = serve_jsonl_loop(&mut service, &mut input, &mut output);
    let cleanup = cleanup_after_transport_end(&mut service, &mut diagnostics);
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(()), Err(cleanup)) => Err(cleanup),
        (Err(primary), Err(cleanup)) => Err(with_cleanup_failure(primary, cleanup)),
    }
}

fn serve_jsonl_loop<B: DebugBackend>(
    service: &mut SessionService<B>,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<()> {
    let mut line = String::new();

    loop {
        line.clear();
        let bytes = input
            .read_line(&mut line)
            .map_err(|error| DebugError::io("read session JSONL request", None, &error))?;
        if bytes == 0 {
            return Ok(());
        }
        if line.trim().is_empty() {
            continue;
        }

        let (request_id, operation) = request_context(&line);
        if line.len() > MAX_REQUEST_LINE_BYTES {
            let error = protocol_error(
                "session request exceeds the JSONL line limit",
                json!({"maximum_bytes": MAX_REQUEST_LINE_BYTES, "received_bytes": line.len()}),
            );
            write_error(output, request_id.as_deref(), &operation, &error)?;
            continue;
        }

        let request = match parse_request(&line) {
            Ok(request) => request,
            Err(error) => {
                write_error(output, request_id.as_deref(), &operation, &error)?;
                continue;
            }
        };

        match handle_request(service, &request) {
            Ok(response) => {
                let shutdown = response.shutdown;
                write_success(output, &request.request_id, response)?;
                if shutdown {
                    return Ok(());
                }
            }
            Err(error) => {
                write_error(
                    output,
                    Some(&request.request_id),
                    request.operation.name(),
                    &error,
                )?;
            }
        }
    }
}

fn parse_request(line: &str) -> Result<SessionRequest> {
    let request: SessionRequest = serde_json::from_str(line).map_err(|error| {
        protocol_error(
            "invalid session JSONL request",
            json!({"cause": error.to_string()}),
        )
    })?;
    if request.schema_version != SCHEMA_VERSION {
        return Err(protocol_error(
            "unsupported session protocol schema version",
            json!({
                "expected": SCHEMA_VERSION,
                "received": request.schema_version,
            }),
        ));
    }
    if request.request_id.trim().is_empty() || request.request_id.len() > MAX_REQUEST_ID_BYTES {
        return Err(protocol_error(
            "request_id must be non-empty and bounded",
            json!({
                "maximum_bytes": MAX_REQUEST_ID_BYTES,
                "received_bytes": request.request_id.len(),
            }),
        ));
    }
    Ok(request)
}

fn handle_request<B: DebugBackend>(
    service: &mut SessionService<B>,
    request: &SessionRequest,
) -> Result<HandledResponse> {
    let operation = request.operation.name();
    let (data, warnings, shutdown) = match &request.operation {
        SessionOperation::Open { probe, target } => (
            serde_json::to_value(service.open(probe, target)?)
                .expect("session open report always serializes"),
            vec![SESSION_STATE_WARNING.to_string()],
            false,
        ),
        SessionOperation::Status { session_id } => (
            serde_json::to_value(service.status(session_id)?)
                .expect("session status report always serializes"),
            Vec::new(),
            false,
        ),
        SessionOperation::CoreStatus { session_id, core } => (
            serde_json::to_value(service.control_core(
                session_id,
                *core,
                CoreExecutionAction::Status,
            )?)
            .expect("session core report always serializes"),
            vec![SESSION_STATE_WARNING.to_string()],
            false,
        ),
        SessionOperation::CoreHalt { session_id, core } => (
            serde_json::to_value(service.control_core(
                session_id,
                *core,
                CoreExecutionAction::Halt,
            )?)
            .expect("session core report always serializes"),
            vec![
                SESSION_STATE_WARNING.to_string(),
                HALT_SIDE_EFFECT_WARNING.to_string(),
            ],
            false,
        ),
        SessionOperation::CoreRun { session_id, core } => (
            serde_json::to_value(service.control_core(
                session_id,
                *core,
                CoreExecutionAction::Run,
            )?)
            .expect("session core report always serializes"),
            vec![SESSION_STATE_WARNING.to_string()],
            false,
        ),
        SessionOperation::CoreContinue { session_id, core } => (
            serde_json::to_value(service.control_core(
                session_id,
                *core,
                CoreExecutionAction::Continue,
            )?)
            .expect("session core report always serializes"),
            vec![
                SESSION_STATE_WARNING.to_string(),
                "Continuing a halted core may immediately hit a breakpoint and return halted; the response reports the observed result rather than promising a durable running state.".to_string(),
            ],
            false,
        ),
        SessionOperation::CoreContinueUntilHalt {
            session_id,
            core,
            timeout_ms,
            poll_interval_ms,
        } => (
            serde_json::to_value(service.continue_until_halt(
                session_id,
                *core,
                ContinueUntilHaltOptions {
                    timeout_ms: timeout_ms
                        .unwrap_or(DEFAULT_CONTINUE_UNTIL_HALT_TIMEOUT_MS),
                    poll_interval_ms: poll_interval_ms
                        .unwrap_or(DEFAULT_CONTINUE_UNTIL_HALT_POLL_INTERVAL_MS),
                },
            )?)
            .expect("session continue-until-halt report always serializes"),
            vec![
                SESSION_STATE_WARNING.to_string(),
                "This bounded request occupies the single-request JSONL server until a halt event or timeout. A timed_out outcome leaves the core running and the same lease available for a later halt, breakpoint change, or close.".to_string(),
            ],
            false,
        ),
        SessionOperation::CoreStep { session_id, core } => (
            serde_json::to_value(service.control_core(
                session_id,
                *core,
                CoreExecutionAction::Step,
            )?)
            .expect("session core report always serializes"),
            vec![
                SESSION_STATE_WARNING.to_string(),
                STEP_SIDE_EFFECT_WARNING.to_string(),
            ],
            false,
        ),
        SessionOperation::BreakpointsList { session_id, core } => (
            serde_json::to_value(service.control_hardware_breakpoints(
                session_id,
                *core,
                HardwareBreakpointAction::List,
                None,
                None,
            )?)
            .expect("session hardware-breakpoint report always serializes"),
            vec![
                SESSION_STATE_WARNING.to_string(),
                READ_SIDE_EFFECT_WARNING.to_string(),
            ],
            false,
        ),
        SessionOperation::BreakpointsSet {
            session_id,
            core,
            address,
            slot,
        } => (
            serde_json::to_value(service.control_hardware_breakpoints(
                session_id,
                *core,
                HardwareBreakpointAction::Set,
                Some(*address),
                *slot,
            )?)
            .expect("session hardware-breakpoint report always serializes"),
            vec![
                SESSION_STATE_WARNING.to_string(),
                BREAKPOINT_SIDE_EFFECT_WARNING.to_string(),
            ],
            false,
        ),
        SessionOperation::BreakpointsClear {
            session_id,
            core,
            slot,
        } => (
            serde_json::to_value(service.control_hardware_breakpoints(
                session_id,
                *core,
                HardwareBreakpointAction::Clear,
                None,
                Some(*slot),
            )?)
            .expect("session hardware-breakpoint report always serializes"),
            vec![
                SESSION_STATE_WARNING.to_string(),
                BREAKPOINT_SIDE_EFFECT_WARNING.to_string(),
            ],
            false,
        ),
        SessionOperation::BreakpointsClearAll { session_id, core } => (
            serde_json::to_value(service.control_hardware_breakpoints(
                session_id,
                *core,
                HardwareBreakpointAction::ClearAll,
                None,
                None,
            )?)
            .expect("session hardware-breakpoint report always serializes"),
            vec![
                SESSION_STATE_WARNING.to_string(),
                BREAKPOINT_SIDE_EFFECT_WARNING.to_string(),
            ],
            false,
        ),
        SessionOperation::RegistersRead {
            session_id,
            core,
            names,
        } => (
            serde_json::to_value(service.read_registers(session_id, *core, names)?)
                .expect("session register report always serializes"),
            vec![
                SESSION_STATE_WARNING.to_string(),
                READ_SIDE_EFFECT_WARNING.to_string(),
            ],
            false,
        ),
        SessionOperation::MemoryRead {
            session_id,
            core,
            address,
            length,
        } => (
            serde_json::to_value(service.read_memory(session_id, *core, *address, *length)?)
                .expect("session memory report always serializes"),
            vec![
                SESSION_STATE_WARNING.to_string(),
                READ_SIDE_EFFECT_WARNING.to_string(),
            ],
            false,
        ),
        SessionOperation::Close { session_id } => (
            serde_json::to_value(service.close(session_id)?)
                .expect("session close report always serializes"),
            Vec::new(),
            false,
        ),
        SessionOperation::Shutdown => {
            if service.has_active_session() {
                return Err(protocol_error(
                    "close the active debug session before shutting down the server",
                    json!({"required_operation": "session.close"}),
                ));
            }
            (json!({"shutdown": true}), Vec::new(), true)
        }
    };
    Ok(HandledResponse {
        operation,
        data,
        warnings,
        shutdown,
    })
}

fn write_success(
    output: &mut impl Write,
    request_id: &str,
    response: HandledResponse,
) -> Result<()> {
    let envelope = SessionSuccessEnvelope {
        schema_version: SCHEMA_VERSION,
        ok: true,
        request_id,
        operation: response.operation,
        operation_id: format!("op_{}", Uuid::new_v4().simple()),
        data: response.data,
        warnings: response.warnings,
        artifacts: Vec::new(),
    };
    write_envelope(output, &envelope)
}

fn write_error(
    output: &mut impl Write,
    request_id: Option<&str>,
    operation: &str,
    error: &DebugError,
) -> Result<()> {
    let envelope = SessionErrorEnvelope {
        schema_version: SCHEMA_VERSION,
        ok: false,
        request_id,
        operation,
        operation_id: format!("op_{}", Uuid::new_v4().simple()),
        error: SessionErrorPayload {
            code: error.code,
            message: &error.message,
            retryable: error.retryable,
            details: &error.details,
            suggested_actions: &error.suggested_actions,
        },
    };
    write_envelope(output, &envelope)
}

fn write_envelope(output: &mut impl Write, envelope: &impl Serialize) -> Result<()> {
    serde_json::to_writer(&mut *output, envelope).map_err(|error| {
        DebugError::new(
            ErrorCode::Internal,
            "failed to serialize session JSONL response",
            10,
            json!({"cause": error.to_string()}),
        )
    })?;
    output
        .write_all(b"\n")
        .and_then(|_| output.flush())
        .map_err(|error| DebugError::io("write session JSONL response", None, &error))
}

fn cleanup_after_transport_end<B: DebugBackend>(
    service: &mut SessionService<B>,
    diagnostics: &mut impl Write,
) -> Result<()> {
    match service.close_active() {
        Ok(Some(report)) => {
            let _ = writeln!(
                diagnostics,
                "session transport ended; safely closed {} using {}",
                report.session_id, report.close_policy
            );
            Ok(())
        }
        Ok(None) => Ok(()),
        Err(error) => {
            let _ = writeln!(
                diagnostics,
                "session transport ended; cleanup failed [{}]: {}",
                serialize_error_code(error.code),
                error.message
            );
            Err(error)
        }
    }
}

fn request_context(line: &str) -> (Option<String>, String) {
    let Ok(value) = serde_json::from_str::<Value>(line) else {
        return (None, "session.request".to_string());
    };
    let request_id = value
        .get("request_id")
        .and_then(Value::as_str)
        .filter(|request_id| {
            !request_id.trim().is_empty() && request_id.len() <= MAX_REQUEST_ID_BYTES
        })
        .map(ToString::to_string);
    let operation = value
        .get("operation")
        .and_then(Value::as_str)
        .unwrap_or("session.request")
        .to_string();
    (request_id, operation)
}

fn require_core_action_capability(
    capabilities: &crate::model::Capabilities,
    backend: &str,
    action: CoreExecutionAction,
) -> Result<()> {
    let missing = match action {
        CoreExecutionAction::Status if !capabilities.core_status => Some("core_status"),
        CoreExecutionAction::Halt if !capabilities.core_status => Some("core_status"),
        CoreExecutionAction::Halt if !capabilities.halt => Some("halt"),
        CoreExecutionAction::Run if !capabilities.core_status => Some("core_status"),
        CoreExecutionAction::Run if !capabilities.run => Some("run"),
        CoreExecutionAction::Continue if !capabilities.core_status => Some("core_status"),
        CoreExecutionAction::Continue if !capabilities.continue_execution => {
            Some("continue_execution")
        }
        CoreExecutionAction::Step if !capabilities.core_status => Some("core_status"),
        CoreExecutionAction::Step if !capabilities.step => Some("step"),
        _ => None,
    };
    if let Some(capability) = missing {
        return Err(DebugError::new(
            ErrorCode::CapabilityUnavailable,
            "selected backend cannot perform the requested in-session core action",
            6,
            json!({"backend": backend, "action": action, "capability": capability}),
        ));
    }
    Ok(())
}

fn require_capabilities(backend: &str, operation: &str, required: &[(&str, bool)]) -> Result<()> {
    if let Some((capability, _)) = required.iter().find(|(_, available)| !available) {
        return Err(DebugError::new(
            ErrorCode::CapabilityUnavailable,
            "selected backend cannot perform the requested in-session operation",
            6,
            json!({
                "backend": backend,
                "operation": operation,
                "capability": capability,
            }),
        ));
    }
    Ok(())
}

fn validate_session_core_index(session: &SessionInfo, core_index: u32) -> Result<()> {
    if core_index >= session.target.core_count {
        return Err(DebugError::config(
            "requested core index is outside the target core inventory",
            json!({
                "core_index": core_index,
                "core_count": session.target.core_count,
                "target": session.target.name,
            }),
        ));
    }
    Ok(())
}

fn in_session_core_operations(action: CoreExecutionAction) -> Vec<OperationRecord> {
    match action {
        CoreExecutionAction::Status => {
            vec![session_operation(1, "core.read_execution_state")]
        }
        CoreExecutionAction::Halt => vec![
            session_operation(1, "core.read_original_execution_state"),
            session_operation(2, "core.halt_if_running"),
            session_operation(3, "core.verify_halted"),
        ],
        CoreExecutionAction::Run => vec![
            session_operation(1, "core.read_original_execution_state"),
            session_operation(2, "core.run_if_halted"),
            session_operation(3, "core.verify_running"),
        ],
        CoreExecutionAction::Continue => vec![
            session_operation(1, "core.verify_halted"),
            session_operation(2, "core.continue_execution"),
            session_operation(3, "core.observe_immediate_result"),
        ],
        CoreExecutionAction::Step => vec![
            session_operation(1, "core.read_original_execution_state"),
            session_operation(2, "core.step_one_instruction"),
            session_operation(3, "core.verify_halted"),
        ],
    }
}

fn in_session_hardware_breakpoint_operations(
    action: HardwareBreakpointAction,
) -> Vec<OperationRecord> {
    match action {
        HardwareBreakpointAction::List => vec![session_operation(
            1,
            "breakpoints.read_and_verify_all_slots",
        )],
        HardwareBreakpointAction::Set => vec![
            session_operation(1, "core.verify_halted"),
            session_operation(2, "breakpoints.read_before"),
            session_operation(3, "breakpoints.set_slot"),
            session_operation(4, "breakpoints.read_after_and_verify"),
        ],
        HardwareBreakpointAction::Clear => vec![
            session_operation(1, "core.verify_halted"),
            session_operation(2, "breakpoints.read_before"),
            session_operation(3, "breakpoints.clear_slot"),
            session_operation(4, "breakpoints.read_after_and_verify"),
        ],
        HardwareBreakpointAction::ClearAll => vec![
            session_operation(1, "core.verify_halted"),
            session_operation(2, "breakpoints.read_before"),
            session_operation(3, "breakpoints.clear_all"),
            session_operation(4, "breakpoints.read_after_and_verify"),
        ],
    }
}

fn session_operation(sequence: u32, operation: &str) -> OperationRecord {
    OperationRecord {
        sequence,
        operation: operation.to_string(),
        ok: true,
    }
}

fn validate_control_observation(
    session: &SessionInfo,
    core_index: u32,
    action: CoreExecutionAction,
    core: &CoreExecutionObservation,
) -> Result<()> {
    if core.index != core_index || core.action != action {
        return Err(protocol_error(
            "backend returned a different core control observation than requested",
            json!({
                "requested_core": core_index,
                "received_core": core.index,
                "requested_action": action,
                "received_action": core.action,
            }),
        ));
    }
    validate_core_execution_observation(&session.target, core).map_err(|problem| {
        protocol_error(
            "backend returned an invalid in-session core control observation",
            json!({"problem": problem, "core": core}),
        )
    })
}

fn protocol_error(message: impl Into<String>, details: Value) -> DebugError {
    DebugError::new(ErrorCode::ProtocolError, message, 6, details)
}

fn error_summary(error: &DebugError) -> Value {
    json!({
        "code": error.code,
        "message": error.message,
        "details": error.details,
    })
}

fn with_cleanup_failure(primary: DebugError, cleanup: DebugError) -> DebugError {
    DebugError::new(
        primary.code,
        primary.message,
        primary.exit_code,
        json!({
            "primary": primary.details,
            "cleanup_failure": error_summary(&cleanup),
        }),
    )
}

fn serialize_error_code(code: ErrorCode) -> String {
    serde_json::to_value(code)
        .expect("error code always serializes")
        .as_str()
        .expect("error code serializes as a string")
        .to_string()
}

#[cfg(test)]
mod tests {
    use std::{io::Cursor, path::Path};

    use serde_json::Value;

    use super::*;
    use crate::{
        backend::replay::{ReplayBackend, ReplayFixture},
        model::CoreState,
    };

    fn service() -> SessionService<ReplayBackend> {
        SessionService::new(
            ReplayBackend::from_path(Path::new("examples/replay/stm32g4.json")).unwrap(),
        )
    }

    #[test]
    fn persistent_replay_session_keeps_state_until_safe_close() {
        let mut service = service();
        let opened = service
            .open("replay:stlink-v3:0039002A3432510433343034", "STM32G431CBTx")
            .unwrap();
        let session_id = opened.session.session_id.clone();

        let running = service
            .control_core(&session_id, 0, CoreExecutionAction::Run)
            .unwrap();
        let halted = service
            .control_core(&session_id, 0, CoreExecutionAction::Halt)
            .unwrap();
        let status = service
            .control_core(&session_id, 0, CoreExecutionAction::Status)
            .unwrap();
        let open_status = service.status(&session_id).unwrap();
        let closed = service.close(&session_id).unwrap();

        assert_eq!(running.core.state, CoreState::Running);
        assert_eq!(halted.core.state, CoreState::Halted);
        assert_eq!(status.core.state, CoreState::Halted);
        assert_eq!(open_status.observed_core_indexes, vec![0]);
        assert_eq!(closed.final_core_observations.len(), 1);
        assert_eq!(closed.final_core_observations[0].state, CoreState::Running);
        assert!(!service.has_active_session());
    }

    #[test]
    fn stale_session_id_is_rejected_without_mutating_the_active_session() {
        let mut service = service();
        let opened = service
            .open("replay:stlink-v3:0039002A3432510433343034", "STM32G431CBTx")
            .unwrap();

        let error = service
            .control_core("ses_stale", 0, CoreExecutionAction::Halt)
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::ProtocolError);
        assert_eq!(
            error.details["active_session_id"],
            opened.session.session_id
        );
        assert!(service.status(&opened.session.session_id).is_ok());
        service.close(&opened.session.session_id).unwrap();
    }

    #[test]
    fn in_session_control_does_not_require_a_post_disconnect_guarantee() {
        let mut fixture = ReplayFixture::load(Path::new("examples/replay/stm32g4.json")).unwrap();
        fixture.capabilities.post_disconnect_core_state = false;
        let mut service = SessionService::new(ReplayBackend::new(fixture));
        let opened = service
            .open("replay:stlink-v3:0039002A3432510433343034", "STM32G431CBTx")
            .unwrap();

        let halted = service
            .control_core(&opened.session.session_id, 0, CoreExecutionAction::Halt)
            .unwrap();

        assert_eq!(halted.core.state, CoreState::Halted);
        service.close(&opened.session.session_id).unwrap();
    }

    #[test]
    fn persistent_reads_preserve_running_and_halted_session_state() {
        let mut fixture = ReplayFixture::load(Path::new("examples/replay/stm32g4.json")).unwrap();
        fixture.capabilities.post_disconnect_core_state = false;
        let mut service = SessionService::new(ReplayBackend::new(fixture));
        let opened = service
            .open("replay:stlink-v3:0039002A3432510433343034", "STM32G431CBTx")
            .unwrap();
        let session_id = opened.session.session_id;

        service
            .control_core(&session_id, 0, CoreExecutionAction::Run)
            .unwrap();
        let running_registers = service
            .read_registers(&session_id, 0, &["pc".to_string(), "sp".to_string()])
            .unwrap();
        let running_memory = service
            .read_memory(&session_id, 0, Address(0x2000_7f04), 8)
            .unwrap();

        assert_eq!(running_registers.core.original_state, CoreState::Running);
        assert_eq!(running_registers.core.state, CoreState::Running);
        assert!(
            running_registers
                .effects
                .core_execution_state_restoration_verified
        );
        assert_eq!(running_memory.core.original_state, CoreState::Running);
        assert_eq!(running_memory.core.state, CoreState::Running);
        assert_eq!(running_memory.data, "0405060708090a0b");
        assert!(running_memory.effects.memory_read_requested);

        service
            .control_core(&session_id, 0, CoreExecutionAction::Halt)
            .unwrap();
        let stepped = service
            .control_core(&session_id, 0, CoreExecutionAction::Step)
            .unwrap();
        let halted_registers = service
            .read_registers(&session_id, 0, &["pc".to_string()])
            .unwrap();
        let halted_memory = service
            .read_memory(&session_id, 0, Address(0x2000_7f04), 8)
            .unwrap();
        let halted_status = service
            .control_core(&session_id, 0, CoreExecutionAction::Status)
            .unwrap();

        assert_eq!(halted_registers.core.original_state, CoreState::Halted);
        assert_eq!(halted_registers.core.state, CoreState::Halted);
        assert_eq!(halted_memory.core.original_state, CoreState::Halted);
        assert_eq!(halted_memory.core.state, CoreState::Halted);
        assert_eq!(halted_status.core.state, CoreState::Halted);
        assert_eq!(stepped.core.original_state, CoreState::Halted);
        assert_eq!(stepped.core.state, CoreState::Halted);
        assert_eq!(stepped.core.halt_reason.as_deref(), Some("step"));
        assert_eq!(stepped.core.pc_before, Some(Address(0x0800_1234)));
        assert_eq!(stepped.core.pc_after, Some(Address(0x0800_1236)));
        assert!(stepped.effects.instruction_step_requested);
        assert!(
            !stepped
                .effects
                .intentional_final_core_state_change_requested
        );

        let closed = service.close(&session_id).unwrap();
        assert_eq!(closed.final_core_observations[0].state, CoreState::Running);
        assert!(closed.effects.intentional_final_core_state_change_requested);
    }

    #[test]
    fn persistent_step_requires_halted_state_without_mutating_the_lease() {
        let mut service = service();
        let opened = service
            .open("replay:stlink-v3:0039002A3432510433343034", "STM32G431CBTx")
            .unwrap();
        let session_id = opened.session.session_id;

        service
            .control_core(&session_id, 0, CoreExecutionAction::Run)
            .unwrap();
        let error = service
            .control_core(&session_id, 0, CoreExecutionAction::Step)
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert_eq!(error.details["original_state"], "running");
        assert_eq!(
            service
                .control_core(&session_id, 0, CoreExecutionAction::Status)
                .unwrap()
                .core
                .state,
            CoreState::Running
        );
        service.close(&session_id).unwrap();
    }

    #[test]
    fn persistent_continue_reports_explicit_replay_result_and_effect() {
        let mut service = service();
        let opened = service
            .open("replay:stlink-v3:0039002A3432510433343034", "STM32G431CBTx")
            .unwrap();
        let session_id = opened.session.session_id;

        let continued = service
            .control_core(&session_id, 0, CoreExecutionAction::Continue)
            .unwrap();

        assert_eq!(continued.core.original_state, CoreState::Halted);
        assert_eq!(continued.core.state, CoreState::Running);
        assert!(continued.effects.execution_continue_requested);
        assert!(
            !continued
                .effects
                .intentional_final_core_state_change_requested
        );
        service.close(&session_id).unwrap();
    }

    #[test]
    fn persistent_continue_until_halt_reports_event_then_timeout_and_keeps_the_lease() {
        let mut fixture = ReplayFixture::load(Path::new("examples/replay/stm32g4.json")).unwrap();
        fixture.capabilities.post_disconnect_core_state = false;
        let mut service = SessionService::new(ReplayBackend::new(fixture));
        let opened = service
            .open("replay:stlink-v3:0039002A3432510433343034", "STM32G431CBTx")
            .unwrap();
        let session_id = opened.session.session_id;
        let options = ContinueUntilHaltOptions {
            timeout_ms: 100,
            poll_interval_ms: 25,
        };

        let halted = service
            .continue_until_halt(&session_id, 0, options)
            .unwrap();
        let timed_out = service
            .continue_until_halt(&session_id, 0, options)
            .unwrap();
        let halted_after_timeout = service
            .control_core(&session_id, 0, CoreExecutionAction::Halt)
            .unwrap();

        assert_eq!(
            halted.wait.outcome,
            crate::model::ContinueUntilHaltOutcome::Halted
        );
        assert_eq!(halted.wait.state, CoreState::Halted);
        assert_eq!(halted.wait.poll_count, 3);
        assert!(halted.effects.execution_continue_requested);
        assert_eq!(
            timed_out.wait.outcome,
            crate::model::ContinueUntilHaltOutcome::TimedOut
        );
        assert_eq!(timed_out.wait.state, CoreState::Running);
        assert_eq!(timed_out.wait.poll_count, 4);
        assert_eq!(halted_after_timeout.core.state, CoreState::Halted);
        assert_eq!(
            service.status(&session_id).unwrap().observed_core_indexes,
            vec![0]
        );
        service.close(&session_id).unwrap();
    }

    #[test]
    fn invalid_persistent_continue_until_halt_options_do_not_consume_event_evidence() {
        let mut service = service();
        let opened = service
            .open("replay:stlink-v3:0039002A3432510433343034", "STM32G431CBTx")
            .unwrap();
        let session_id = opened.session.session_id;

        let error = service
            .continue_until_halt(
                &session_id,
                0,
                ContinueUntilHaltOptions {
                    timeout_ms: 5,
                    poll_interval_ms: 10,
                },
            )
            .unwrap_err();
        let valid = service
            .continue_until_halt(
                &session_id,
                0,
                ContinueUntilHaltOptions {
                    timeout_ms: 100,
                    poll_interval_ms: 25,
                },
            )
            .unwrap();

        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert_eq!(
            valid.wait.outcome,
            crate::model::ContinueUntilHaltOutcome::Halted
        );
        service.close(&session_id).unwrap();
    }

    #[test]
    fn persistent_hardware_breakpoints_are_verified_and_cleaned_before_close() {
        let mut service = service();
        let opened = service
            .open("replay:stlink-v3:0039002A3432510433343034", "STM32G431CBTx")
            .unwrap();
        let session_id = opened.session.session_id;

        let listed = service
            .control_hardware_breakpoints(
                &session_id,
                0,
                HardwareBreakpointAction::List,
                None,
                None,
            )
            .unwrap();
        let set = service
            .control_hardware_breakpoints(
                &session_id,
                0,
                HardwareBreakpointAction::Set,
                Some(Address(0x0800_1234)),
                None,
            )
            .unwrap();
        service
            .control_core(&session_id, 0, CoreExecutionAction::Run)
            .unwrap();
        let closed = service.close(&session_id).unwrap();

        assert_eq!(listed.core.capacity, 6);
        assert_eq!(set.core.affected_slot, Some(0));
        assert!(set.effects.hardware_breakpoint_configuration_requested);
        assert!(set.effects.hardware_breakpoint_state_verified);
        assert_eq!(closed.hardware_breakpoint_cleanup.len(), 1);
        assert!(
            closed.hardware_breakpoint_cleanup[0]
                .after
                .iter()
                .all(|slot| slot.address.is_none())
        );
        assert!(closed.effects.hardware_breakpoint_configuration_requested);
        assert!(closed.effects.hardware_breakpoint_state_verified);
        assert_eq!(closed.final_core_observations[0].state, CoreState::Running);
        assert!(!service.has_active_session());
    }

    #[test]
    fn failed_breakpoint_mutation_is_still_tracked_for_close_cleanup() {
        let mut service = service();
        let opened = service
            .open("replay:stlink-v3:0039002A3432510433343034", "STM32G431CBTx")
            .unwrap();
        let session_id = opened.session.session_id;

        service
            .control_hardware_breakpoints(
                &session_id,
                0,
                HardwareBreakpointAction::Set,
                Some(Address(0x0800_1234)),
                Some(1),
            )
            .unwrap();
        let error = service
            .control_hardware_breakpoints(
                &session_id,
                0,
                HardwareBreakpointAction::Set,
                Some(Address(0x0800_2000)),
                Some(1),
            )
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert_eq!(
            service
                .status(&session_id)
                .unwrap()
                .hardware_breakpoint_core_indexes,
            vec![0]
        );
        let closed = service.close(&session_id).unwrap();
        assert!(
            closed.hardware_breakpoint_cleanup[0]
                .after
                .iter()
                .all(|slot| slot.address.is_none())
        );
    }

    #[test]
    fn invalid_persistent_read_requests_do_not_touch_core_state() {
        let mut service = service();
        let opened = service
            .open("replay:stlink-v3:0039002A3432510433343034", "STM32G431CBTx")
            .unwrap();
        let session_id = opened.session.session_id;

        let duplicate = service
            .read_registers(&session_id, 0, &["pc".to_string(), "PC".to_string()])
            .unwrap_err();
        let outside = service
            .read_memory(&session_id, 0, Address(0x2000_7f18), 16)
            .unwrap_err();

        assert_eq!(duplicate.code, ErrorCode::ConfigInvalid);
        assert_eq!(outside.code, ErrorCode::ConfigInvalid);
        assert!(
            service
                .status(&session_id)
                .unwrap()
                .observed_core_indexes
                .is_empty()
        );
        service.close(&session_id).unwrap();
    }

    #[test]
    fn jsonl_protocol_returns_errors_per_line_and_keeps_serving() {
        let backend = ReplayBackend::from_path(Path::new("examples/replay/stm32g4.json")).unwrap();
        let input = concat!(
            "not-json\n",
            "{\"schema_version\":\"0.9\",\"request_id\":\"old\",\"operation\":\"server.shutdown\"}\n",
            "{\"schema_version\":\"1.0\",\"request_id\":\"done\",\"operation\":\"server.shutdown\"}\n"
        );
        let mut output = Vec::new();
        serve_jsonl(
            backend,
            Cursor::new(input.as_bytes()),
            &mut output,
            Vec::new(),
        )
        .unwrap();

        let responses = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(responses.len(), 3);
        assert_eq!(responses[0]["error"]["code"], "PROTOCOL_ERROR");
        assert_eq!(responses[1]["request_id"], "old");
        assert_eq!(responses[1]["error"]["details"]["expected"], "1.0");
        assert_eq!(responses[2]["ok"], true);
        assert_eq!(responses[2]["operation"], "server.shutdown");
    }
}
