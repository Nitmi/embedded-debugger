use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use chrono::{SecondsFormat, Utc};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    SCHEMA_VERSION,
    backend::{
        DebugBackend, nrf52840_development_debug_authorized,
        validate_nrf52840_development_debug_erase_ranges,
    },
    error::{DebugError, ErrorCode, Result},
    firmware::{self, FirmwareFormat, FirmwareInputOptions},
    model::{
        Address, ArtifactReference, ContinueUntilHaltOptions, ContinueUntilHaltReport,
        CoreControlReport, CoreExecutionAction, DebugControlEffects, EvidenceBundle,
        FirmwareImageOptions, FirmwareSegmentInfo, FlashExecution, FlashExecutionBlocker,
        FlashExecutionReadiness, FlashPlan, FlashPolicy, FlashRange, MAX_REGISTER_READS,
        MemoryReadReport, OperationRecord, PlannedAction, ProbeInfo, ProbeTestReport,
        RegisterReadReport, ResetCaptureReport, SnapshotCaptureReport,
        validate_continue_until_halt_observation, validate_continue_until_halt_options,
        validate_core_execution_observation, validate_core_inventory,
        validate_memory_core_observation, validate_memory_read_range,
        validate_post_flash_core_inventory, validate_register_core_observation,
    },
};

#[derive(Debug, Serialize)]
struct ConfirmationInput<'a> {
    schema_version: &'a str,
    operation: &'a str,
    backend: &'a str,
    probe_id: &'a str,
    target: &'a str,
    firmware_format: &'a str,
    firmware_sha256: &'a str,
    firmware_size: u64,
    firmware_program_size: u64,
    firmware_segments: &'a [FirmwareSegmentInfo],
    firmware_image_options: &'a Option<FirmwareImageOptions>,
    ranges: &'a [FlashRange],
    erase_ranges: &'a [FlashRange],
    policy: &'a FlashPolicy,
    execution: &'a FlashExecutionReadiness,
}

pub struct DebugService<B: DebugBackend> {
    backend: B,
}

pub struct ConfirmedFlashOptions<'a> {
    pub firmware: &'a FirmwareInputOptions,
    pub policy: &'a FlashPolicy,
    pub confirm_digest: &'a str,
    pub evidence_path: &'a Path,
}

impl<B: DebugBackend> DebugService<B> {
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    pub fn probes(&self) -> Result<Vec<ProbeInfo>> {
        self.backend.list_probes()
    }

    pub fn test_probe_connection(
        &mut self,
        probe_id: &str,
        target: &str,
    ) -> Result<ProbeTestReport> {
        let target_info = self.backend.target().clone();
        if !self.backend.matches_target(target) {
            return Err(DebugError::unavailable(
                ErrorCode::TargetUnavailable,
                "requested target is not available from the selected backend",
                json!({"requested": target, "available": target_info.name}),
            ));
        }
        let probe = select_probe(&self.backend.list_probes()?, Some(probe_id))?;
        let session = self.backend.attach(&probe.id, &target_info.name)?;
        let mut operations = vec![OperationRecord {
            sequence: 1,
            operation: "session.attach".to_string(),
            ok: true,
        }];
        self.backend.disconnect(&session)?;
        operations.push(OperationRecord {
            sequence: 2,
            operation: "session.disconnect".to_string(),
            ok: true,
        });

        Ok(ProbeTestReport {
            risk: "R1_REVERSIBLE_CONTROL".to_string(),
            session,
            effects: debug_control_effects(&self.backend, DebugControlEffectRequest::default()),
            operations,
            complete: true,
        })
    }

    pub fn capture_snapshot(
        &mut self,
        probe_id: &str,
        target: &str,
    ) -> Result<SnapshotCaptureReport> {
        let target_info = self.backend.target().clone();
        if !self.backend.matches_target(target) {
            return Err(DebugError::unavailable(
                ErrorCode::TargetUnavailable,
                "requested target is not available from the selected backend",
                json!({"requested": target, "available": target_info.name}),
            ));
        }
        let capabilities = self.backend.capabilities();
        let required_capabilities = [
            ("halt", capabilities.halt),
            ("run", capabilities.run),
            ("register_read", capabilities.register_read),
            (
                "post_disconnect_core_state",
                capabilities.post_disconnect_core_state,
            ),
        ];
        if let Some((capability, _)) = required_capabilities
            .iter()
            .find(|(_, available)| !available)
        {
            return Err(DebugError::new(
                ErrorCode::CapabilityUnavailable,
                "selected backend cannot capture a state-preserving core snapshot",
                6,
                json!({"backend": self.backend.name(), "capability": capability}),
            ));
        }

        let probe = select_probe(&self.backend.list_probes()?, Some(probe_id))?;
        let session = self.backend.attach(&probe.id, &target_info.name)?;
        let capture_result = self.backend.capture_live_snapshot(&session);
        let captured_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        let disconnect_result = self.backend.disconnect(&session);
        let cores = match (capture_result, disconnect_result) {
            (Err(error), Err(cleanup_error)) => {
                return Err(with_cleanup_failure(error, cleanup_error));
            }
            (Err(error), Ok(())) => return Err(error),
            (Ok(_), Err(error)) => return Err(error),
            (Ok(cores), Ok(())) => cores,
        };
        if !cores.iter().any(|core| core.available) {
            return Err(DebugError::new(
                ErrorCode::CapabilityUnavailable,
                "no target core was enabled for snapshot capture",
                6,
                json!({"target": target_info.name, "cores": cores}),
            ));
        }
        if let Err(problem) = validate_core_inventory(&target_info, &cores) {
            return Err(DebugError::new(
                ErrorCode::ProtocolError,
                "backend returned an invalid core snapshot inventory",
                6,
                json!({
                    "problem": problem,
                    "cores": cores,
                }),
            ));
        }

        Ok(SnapshotCaptureReport {
            capture_id: format!("cap_{}", Uuid::new_v4().simple()),
            captured_at,
            risk: "R1_REVERSIBLE_CONTROL".to_string(),
            session,
            effects: debug_control_effects(
                &self.backend,
                DebugControlEffectRequest {
                    core_execution_state_restoration_verified: true,
                    ..DebugControlEffectRequest::default()
                },
            ),
            cores,
            operations: vec![
                operation(1, "session.attach"),
                operation(2, "target.capture_original_core_states"),
                operation(3, "target.halt_running_cores"),
                operation(4, "snapshot.capture_all_cores"),
                operation(5, "target.restore_original_core_states"),
                operation(6, "session.disconnect_preserving_core_state"),
            ],
            complete: true,
        })
    }

    pub fn capture_reset_snapshot(
        &mut self,
        probe_id: &str,
        target: &str,
    ) -> Result<ResetCaptureReport> {
        let target_info = self.backend.target().clone();
        if !self.backend.matches_target(target) {
            return Err(DebugError::unavailable(
                ErrorCode::TargetUnavailable,
                "requested target is not available from the selected backend",
                json!({"requested": target, "available": target_info.name}),
            ));
        }
        let capabilities = self.backend.capabilities();
        let required_capabilities = [
            ("reset", capabilities.reset),
            ("halt", capabilities.halt),
            ("run", capabilities.run),
            ("register_read", capabilities.register_read),
        ];
        if let Some((capability, _)) = required_capabilities
            .iter()
            .find(|(_, available)| !available)
        {
            return Err(DebugError::new(
                ErrorCode::CapabilityUnavailable,
                "selected backend cannot capture a post-reset core snapshot",
                6,
                json!({"backend": self.backend.name(), "capability": capability}),
            ));
        }
        if target_info.core_count > 1 && !capabilities.multi_core_post_flash {
            return Err(DebugError::new(
                ErrorCode::CapabilityUnavailable,
                "selected backend cannot capture a complete multi-core post-reset snapshot",
                6,
                json!({
                    "backend": self.backend.name(),
                    "capability": "multi_core_post_flash",
                }),
            ));
        }

        let probe = select_probe(&self.backend.list_probes()?, Some(probe_id))?;
        let session = self.backend.attach(&probe.id, &target_info.name)?;
        let capture_result = self
            .backend
            .reset(&session)
            .and_then(|()| self.backend.capture_post_flash_snapshot(&session));
        let captured_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        let disconnect_result = self.backend.disconnect(&session);
        let cores = match (capture_result, disconnect_result) {
            (Err(error), Err(cleanup_error)) => {
                return Err(with_cleanup_failure(error, cleanup_error));
            }
            (Err(error), Ok(())) => return Err(error),
            (Ok(_), Err(error)) => return Err(error),
            (Ok(cores), Ok(())) => cores,
        };
        if let Err(problem) = validate_post_flash_core_inventory(&target_info, &cores) {
            return Err(DebugError::new(
                ErrorCode::ProtocolError,
                "backend returned an invalid post-reset core inventory",
                6,
                json!({
                    "problem": problem,
                    "cores": cores,
                }),
            ));
        }

        Ok(ResetCaptureReport {
            capture_id: format!("reset_cap_{}", Uuid::new_v4().simple()),
            captured_at,
            risk: "R1_REVERSIBLE_CONTROL".to_string(),
            session,
            effects: debug_control_effects(
                &self.backend,
                DebugControlEffectRequest {
                    core_execution_state_restoration_verified: true,
                    reset_requested: true,
                    ..DebugControlEffectRequest::default()
                },
            ),
            cores,
            operations: vec![
                operation(1, "session.attach"),
                operation(2, "target.system_reset_and_halt"),
                operation(3, "snapshot.capture_post_reset_cores"),
                operation(4, "target.restore_expected_post_reset_states"),
                operation(5, "session.disconnect"),
            ],
            complete: true,
        })
    }

    pub fn control_core(
        &mut self,
        probe_id: &str,
        target: &str,
        core_index: u32,
        action: CoreExecutionAction,
    ) -> Result<CoreControlReport> {
        let target_info = self.backend.target().clone();
        if !self.backend.matches_target(target) {
            return Err(DebugError::unavailable(
                ErrorCode::TargetUnavailable,
                "requested target is not available from the selected backend",
                json!({"requested": target, "available": target_info.name}),
            ));
        }
        if core_index >= target_info.core_count {
            return Err(DebugError::config(
                "requested core index is outside the target core inventory",
                json!({
                    "core_index": core_index,
                    "core_count": target_info.core_count,
                    "target": target_info.name,
                }),
            ));
        }
        let capabilities = self.backend.capabilities();
        let required_capability = match action {
            CoreExecutionAction::Status => {
                if !capabilities.core_status {
                    Some("core_status")
                } else {
                    (!capabilities.post_disconnect_core_state)
                        .then_some("post_disconnect_core_state")
                }
            }
            CoreExecutionAction::Halt => {
                if !capabilities.core_status {
                    Some("core_status")
                } else if !capabilities.halt {
                    Some("halt")
                } else {
                    (!capabilities.post_disconnect_core_state)
                        .then_some("post_disconnect_core_state")
                }
            }
            CoreExecutionAction::Run => {
                if !capabilities.core_status {
                    Some("core_status")
                } else if !capabilities.run {
                    Some("run")
                } else {
                    (!capabilities.post_disconnect_core_state)
                        .then_some("post_disconnect_core_state")
                }
            }
            CoreExecutionAction::Continue => {
                if !capabilities.core_status {
                    Some("core_status")
                } else if !capabilities.continue_execution {
                    Some("continue_execution")
                } else {
                    (!capabilities.post_disconnect_core_state)
                        .then_some("post_disconnect_core_state")
                }
            }
            CoreExecutionAction::Step => {
                if !capabilities.core_status {
                    Some("core_status")
                } else if !capabilities.step {
                    Some("step")
                } else {
                    (!capabilities.post_disconnect_core_state)
                        .then_some("post_disconnect_core_state")
                }
            }
        };
        if let Some(capability) = required_capability {
            return Err(DebugError::new(
                ErrorCode::CapabilityUnavailable,
                "selected backend cannot perform the requested core control action",
                6,
                json!({
                    "backend": self.backend.name(),
                    "action": action,
                    "capability": capability,
                }),
            ));
        }

        let probe = select_probe(&self.backend.list_probes()?, Some(probe_id))?;
        let session = self.backend.attach(&probe.id, &target_info.name)?;
        let control_result = self
            .backend
            .control_core_in_session(&session, core_index, action);
        let disconnect_result = self.backend.disconnect(&session);
        let core = match (control_result, disconnect_result) {
            (Err(error), Err(cleanup_error)) => {
                return Err(with_cleanup_failure(error, cleanup_error));
            }
            (Err(error), Ok(())) => return Err(error),
            (Ok(_), Err(error)) => return Err(error),
            (Ok(core), Ok(())) => core,
        };
        let observed_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        if core.index != core_index || core.action != action {
            return Err(DebugError::new(
                ErrorCode::ProtocolError,
                "backend returned a different core control observation than requested",
                6,
                json!({
                    "requested_core": core_index,
                    "received_core": core.index,
                    "requested_action": action,
                    "received_action": core.action,
                }),
            ));
        }
        if let Err(problem) = validate_core_execution_observation(&target_info, &core) {
            return Err(DebugError::new(
                ErrorCode::ProtocolError,
                "backend returned an invalid core control observation",
                6,
                json!({"problem": problem, "core": core}),
            ));
        }
        let operations = match action {
            CoreExecutionAction::Status => vec![
                operation(1, "session.attach"),
                operation(2, "core.read_execution_state"),
                operation(3, "session.disconnect_preserving_core_state"),
            ],
            CoreExecutionAction::Halt => vec![
                operation(1, "session.attach"),
                operation(2, "core.read_original_execution_state"),
                operation(3, "core.halt_if_running"),
                operation(4, "core.verify_halted_before_disconnect"),
                operation(5, "session.disconnect_preserving_core_state"),
            ],
            CoreExecutionAction::Run => vec![
                operation(1, "session.attach"),
                operation(2, "core.read_original_execution_state"),
                operation(3, "core.run_if_halted"),
                operation(4, "core.verify_running_before_disconnect"),
                operation(5, "session.disconnect_preserving_core_state"),
            ],
            CoreExecutionAction::Continue => vec![
                operation(1, "session.attach"),
                operation(2, "core.verify_halted"),
                operation(3, "core.continue_execution"),
                operation(4, "core.observe_immediate_result"),
                operation(5, "session.disconnect_preserving_core_state"),
            ],
            CoreExecutionAction::Step => vec![
                operation(1, "session.attach"),
                operation(2, "core.read_original_execution_state"),
                operation(3, "core.step_one_instruction"),
                operation(4, "core.verify_halted_before_disconnect"),
                operation(5, "session.disconnect_preserving_core_state"),
            ],
        };

        Ok(CoreControlReport {
            control_id: format!("ctl_{}", Uuid::new_v4().simple()),
            observed_at,
            risk: "R1_REVERSIBLE_CONTROL".to_string(),
            session,
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
            operations,
            complete: true,
        })
    }

    pub fn continue_until_halt(
        &mut self,
        probe_id: &str,
        target: &str,
        core_index: u32,
        options: ContinueUntilHaltOptions,
    ) -> Result<ContinueUntilHaltReport> {
        let target_info = self.backend.target().clone();
        if !self.backend.matches_target(target) {
            return Err(DebugError::unavailable(
                ErrorCode::TargetUnavailable,
                "requested target is not available from the selected backend",
                json!({"requested": target, "available": target_info.name}),
            ));
        }
        if core_index >= target_info.core_count {
            return Err(DebugError::config(
                "requested core index is outside the target core inventory",
                json!({
                    "core_index": core_index,
                    "core_count": target_info.core_count,
                    "target": target_info.name,
                }),
            ));
        }
        validate_continue_until_halt_options(options).map_err(|problem| {
            DebugError::config(
                "invalid continue-until-halt timing options",
                json!({"problem": problem, "options": options}),
            )
        })?;
        let capabilities = self.backend.capabilities();
        let required_capability = if !capabilities.core_status {
            Some("core_status")
        } else if !capabilities.continue_execution {
            Some("continue_execution")
        } else if !capabilities.continue_until_halt {
            Some("continue_until_halt")
        } else {
            (!capabilities.post_disconnect_core_state).then_some("post_disconnect_core_state")
        };
        if let Some(capability) = required_capability {
            return Err(DebugError::new(
                ErrorCode::CapabilityUnavailable,
                "selected backend cannot continue and wait for a halt event",
                6,
                json!({
                    "backend": self.backend.name(),
                    "capability": capability,
                }),
            ));
        }

        let probe = select_probe(&self.backend.list_probes()?, Some(probe_id))?;
        let session = self.backend.attach(&probe.id, &target_info.name)?;
        let wait_result = self
            .backend
            .continue_until_halt_in_session(&session, core_index, options);
        let disconnect_result = self.backend.disconnect(&session);
        let wait = match (wait_result, disconnect_result) {
            (Err(error), Err(cleanup_error)) => {
                return Err(with_cleanup_failure(error, cleanup_error));
            }
            (Err(error), Ok(())) => return Err(error),
            (Ok(_), Err(error)) => return Err(error),
            (Ok(wait), Ok(())) => wait,
        };
        if wait.continuation.index != core_index {
            return Err(DebugError::new(
                ErrorCode::ProtocolError,
                "backend returned a different continue-until-halt core than requested",
                6,
                json!({
                    "requested_core": core_index,
                    "received_core": wait.continuation.index,
                }),
            ));
        }
        validate_continue_until_halt_observation(&target_info, &wait).map_err(|problem| {
            DebugError::new(
                ErrorCode::ProtocolError,
                "backend returned an invalid continue-until-halt observation",
                6,
                json!({"problem": problem, "wait": wait}),
            )
        })?;

        let mut operations = vec![
            operation(1, "session.attach"),
            operation(2, "core.verify_halted"),
            operation(3, "core.continue_execution"),
        ];
        if wait.poll_count > 0 {
            operations.push(operation(4, "core.poll_until_halted_or_timeout"));
        }
        operations.push(operation(
            operations.len() as u32 + 1,
            "core.observe_halt_or_timeout",
        ));
        operations.push(operation(
            operations.len() as u32 + 1,
            "session.disconnect_preserving_core_state",
        ));

        Ok(ContinueUntilHaltReport {
            wait_id: format!("wait_{}", Uuid::new_v4().simple()),
            observed_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            risk: "R1_REVERSIBLE_CONTROL".to_string(),
            session,
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

    pub fn read_registers(
        &mut self,
        probe_id: &str,
        target: &str,
        core_index: u32,
        names: &[String],
    ) -> Result<RegisterReadReport> {
        let target_info = self.backend.target().clone();
        if !self.backend.matches_target(target) {
            return Err(DebugError::unavailable(
                ErrorCode::TargetUnavailable,
                "requested target is not available from the selected backend",
                json!({"requested": target, "available": target_info.name}),
            ));
        }
        if core_index >= target_info.core_count {
            return Err(DebugError::config(
                "requested core index is outside the target core inventory",
                json!({
                    "core_index": core_index,
                    "core_count": target_info.core_count,
                    "target": target_info.name,
                }),
            ));
        }
        validate_register_request(names)?;

        let capabilities = self.backend.capabilities();
        let required_capabilities = [
            ("halt", capabilities.halt),
            ("run", capabilities.run),
            ("register_read", capabilities.register_read),
            (
                "post_disconnect_core_state",
                capabilities.post_disconnect_core_state,
            ),
        ];
        if let Some((capability, _)) = required_capabilities
            .iter()
            .find(|(_, available)| !available)
        {
            return Err(DebugError::new(
                ErrorCode::CapabilityUnavailable,
                "selected backend cannot perform a state-preserving register read",
                6,
                json!({"backend": self.backend.name(), "capability": capability}),
            ));
        }

        let probe = select_probe(&self.backend.list_probes()?, Some(probe_id))?;
        let session = self.backend.attach(&probe.id, &target_info.name)?;
        let read_result = self.backend.read_registers(&session, core_index, names);
        let captured_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        let disconnect_result = self.backend.disconnect(&session);
        let core = match (read_result, disconnect_result) {
            (Err(error), Err(cleanup_error)) => {
                return Err(with_cleanup_failure(error, cleanup_error));
            }
            (Err(error), Ok(())) => return Err(error),
            (Ok(_), Err(error)) => return Err(error),
            (Ok(core), Ok(())) => core,
        };
        if core.index != core_index {
            return Err(DebugError::new(
                ErrorCode::ProtocolError,
                "backend returned register data for a different core",
                6,
                json!({"requested_core": core_index, "received_core": core.index}),
            ));
        }
        if let Err(problem) = validate_register_core_observation(&target_info, &core) {
            return Err(DebugError::new(
                ErrorCode::ProtocolError,
                "backend returned an invalid register observation",
                6,
                json!({"problem": problem, "core": core}),
            ));
        }

        Ok(RegisterReadReport {
            read_id: format!("reg_{}", Uuid::new_v4().simple()),
            captured_at,
            risk: "R1_REVERSIBLE_CONTROL".to_string(),
            session,
            effects: debug_control_effects(
                &self.backend,
                DebugControlEffectRequest {
                    core_execution_state_restoration_verified: true,
                    ..DebugControlEffectRequest::default()
                },
            ),
            core,
            operations: vec![
                operation(1, "session.attach"),
                operation(2, "target.capture_original_core_state"),
                operation(3, "target.halt_core_if_running"),
                operation(4, "registers.read"),
                operation(5, "target.restore_original_core_state"),
                operation(6, "session.disconnect_preserving_core_state"),
            ],
            complete: true,
        })
    }

    pub fn read_memory(
        &mut self,
        probe_id: &str,
        target: &str,
        core_index: u32,
        start: Address,
        length: u64,
    ) -> Result<MemoryReadReport> {
        let target_info = self.backend.target().clone();
        if !self.backend.matches_target(target) {
            return Err(DebugError::unavailable(
                ErrorCode::TargetUnavailable,
                "requested target is not available from the selected backend",
                json!({"requested": target, "available": target_info.name}),
            ));
        }
        if core_index >= target_info.core_count {
            return Err(DebugError::config(
                "requested core index is outside the target core inventory",
                json!({
                    "core_index": core_index,
                    "core_count": target_info.core_count,
                    "target": target_info.name,
                }),
            ));
        }
        let range = self.backend.plan_memory_read(core_index, start, length)?;
        if let Err(problem) = validate_memory_read_range(&range) {
            return Err(DebugError::new(
                ErrorCode::ProtocolError,
                "backend returned an invalid memory read plan",
                6,
                json!({"problem": problem, "range": range}),
            ));
        }

        let capabilities = self.backend.capabilities();
        let required_capabilities = [
            ("halt", capabilities.halt),
            ("run", capabilities.run),
            ("memory_read", capabilities.memory_read),
            (
                "post_disconnect_core_state",
                capabilities.post_disconnect_core_state,
            ),
        ];
        if let Some((capability, _)) = required_capabilities
            .iter()
            .find(|(_, available)| !available)
        {
            return Err(DebugError::new(
                ErrorCode::CapabilityUnavailable,
                "selected backend cannot perform a state-preserving memory read",
                6,
                json!({"backend": self.backend.name(), "capability": capability}),
            ));
        }

        let probe = select_probe(&self.backend.list_probes()?, Some(probe_id))?;
        let session = self.backend.attach(&probe.id, &target_info.name)?;
        let read_result = self.backend.read_memory(&session, core_index, &range);
        let captured_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        let disconnect_result = self.backend.disconnect(&session);
        let result = match (read_result, disconnect_result) {
            (Err(error), Err(cleanup_error)) => {
                return Err(with_cleanup_failure(error, cleanup_error));
            }
            (Err(error), Ok(())) => return Err(error),
            (Ok(_), Err(error)) => return Err(error),
            (Ok(result), Ok(())) => result,
        };
        if result.core.index != core_index {
            return Err(DebugError::new(
                ErrorCode::ProtocolError,
                "backend returned memory data for a different core",
                6,
                json!({
                    "requested_core": core_index,
                    "received_core": result.core.index,
                }),
            ));
        }
        if result.range != range {
            return Err(DebugError::new(
                ErrorCode::ProtocolError,
                "backend returned bytes for a different memory range",
                6,
                json!({"planned": range, "received": result.range}),
            ));
        }
        if result.bytes.len() as u64 != range.length {
            return Err(DebugError::new(
                ErrorCode::ProtocolError,
                "backend returned an unexpected number of memory bytes",
                6,
                json!({
                    "expected": range.length,
                    "received": result.bytes.len(),
                }),
            ));
        }
        if let Err(problem) = validate_memory_core_observation(&target_info, &result.core) {
            return Err(DebugError::new(
                ErrorCode::ProtocolError,
                "backend returned an invalid memory core observation",
                6,
                json!({"problem": problem, "core": result.core}),
            ));
        }

        Ok(MemoryReadReport {
            read_id: format!("mem_{}", Uuid::new_v4().simple()),
            captured_at,
            risk: "R1_REVERSIBLE_CONTROL".to_string(),
            session,
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
                operation(1, "memory.plan_read_range"),
                operation(2, "session.attach"),
                operation(3, "target.capture_original_core_state"),
                operation(4, "target.halt_core_if_running"),
                operation(5, "memory.read_exact"),
                operation(6, "target.restore_original_core_state"),
                operation(7, "session.disconnect_preserving_core_state"),
            ],
            complete: true,
        })
    }

    pub fn plan_flash(
        &self,
        firmware_path: &Path,
        probe_id: Option<&str>,
        target: Option<&str>,
        base_address: Option<Address>,
    ) -> Result<FlashPlan> {
        self.plan_flash_with_options(
            firmware_path,
            probe_id,
            target,
            &FirmwareInputOptions {
                base_address,
                ..FirmwareInputOptions::default()
            },
        )
    }

    pub fn plan_flash_with_options(
        &self,
        firmware_path: &Path,
        probe_id: Option<&str>,
        target: Option<&str>,
        firmware_options: &FirmwareInputOptions,
    ) -> Result<FlashPlan> {
        self.plan_flash_with_policy(
            firmware_path,
            probe_id,
            target,
            firmware_options,
            &FlashPolicy::default(),
        )
    }

    pub fn plan_flash_with_policy(
        &self,
        firmware_path: &Path,
        probe_id: Option<&str>,
        target: Option<&str>,
        firmware_options: &FirmwareInputOptions,
        policy: &FlashPolicy,
    ) -> Result<FlashPlan> {
        let target_info = self.backend.target().clone();
        if let Some(requested) = target
            && !self.backend.matches_target(requested)
        {
            return Err(DebugError::unavailable(
                ErrorCode::TargetUnavailable,
                "requested target is not available from the selected backend",
                json!({"requested": requested, "available": target_info.name}),
            ));
        }
        let mut firmware = firmware::load(firmware_path, &target_info.name, firmware_options)?;
        if let Some(image_options) = &firmware.info.image_options {
            self.backend
                .validate_firmware_image_options(image_options)?;
        }
        let development_debug_authorized =
            nrf52840_development_debug_authorized(&target_info.name, &firmware.segments, policy)?;
        let capabilities = self.backend.capabilities();
        let execution = execution_readiness(
            &firmware.info,
            &target_info,
            capabilities,
            development_debug_authorized,
        );
        if firmware.info.format == FirmwareFormat::Bin.name() {
            require_guarded_flash_capabilities(self.backend.name(), &target_info, capabilities)?;
        } else {
            require_image_planning_capabilities(self.backend.name(), capabilities)?;
        }

        let layout = if firmware.info.format == FirmwareFormat::Bin.name() {
            let layout = self
                .backend
                .plan_flash_ranges(firmware.info.size, firmware_options.base_address)?;
            let start = layout.write_ranges.first().map(|range| range.start);
            if let Some(start) = start {
                firmware.bind_raw_segment(start)?;
            }
            layout
        } else {
            self.backend
                .plan_segmented_flash_ranges(&firmware.write_ranges())?
        };
        if development_debug_authorized {
            validate_nrf52840_development_debug_erase_ranges(&layout.erase_ranges, policy)?;
        }
        if firmware.info.base_address.is_none() || layout.write_ranges.is_empty() {
            return Err(DebugError::new(
                ErrorCode::Internal,
                "backend returned an empty flash write layout",
                10,
                json!({"backend": self.backend.name()}),
            ));
        }
        let probes = self.backend.list_probes()?;
        let probe = select_probe(&probes, probe_id)?;
        if !self.backend.probe_identity_is_stable(&probe) {
            return Err(DebugError::unavailable(
                ErrorCode::ProbeAmbiguous,
                "selected probe does not expose a stable identity for a device write",
                json!({
                    "probe": probe,
                    "requirement": "non-empty hardware serial number",
                }),
            ));
        }
        let confirmation = ConfirmationInput {
            schema_version: SCHEMA_VERSION,
            operation: "flash.execute",
            backend: self.backend.name(),
            probe_id: &probe.id,
            target: &target_info.name,
            firmware_format: &firmware.info.format,
            firmware_sha256: &firmware.info.sha256,
            firmware_size: firmware.info.size,
            firmware_program_size: firmware.info.program_size,
            firmware_segments: &firmware.info.segments,
            firmware_image_options: &firmware.info.image_options,
            ranges: &layout.write_ranges,
            erase_ranges: &layout.erase_ranges,
            policy,
            execution: &execution,
        };
        let confirm_digest = sha256_bytes(
            &serde_json::to_vec(&confirmation).expect("confirmation input always serializes"),
        );
        let mut actions = vec![
            PlannedAction {
                action: "attach_probe".to_string(),
                risk: "R1_REVERSIBLE_CONTROL".to_string(),
            },
            PlannedAction {
                action: "erase_affected_sectors".to_string(),
                risk: "R2_DEVICE_WRITE".to_string(),
            },
        ];
        if development_debug_authorized {
            actions.push(PlannedAction {
                action: "program_nrf52840_uicr_approtect_hw_disabled".to_string(),
                risk: "R2_PERSISTENT_SECURITY_CONFIGURATION".to_string(),
            });
        }
        actions.extend([
            PlannedAction {
                action: "program_firmware".to_string(),
                risk: "R2_DEVICE_WRITE".to_string(),
            },
            PlannedAction {
                action: "verify_firmware".to_string(),
                risk: "R0_READ_ONLY".to_string(),
            },
            PlannedAction {
                action: "reset_and_halt_target".to_string(),
                risk: "R1_REVERSIBLE_CONTROL".to_string(),
            },
            PlannedAction {
                action: "capture_core_snapshot".to_string(),
                risk: "R0_READ_ONLY".to_string(),
            },
            PlannedAction {
                action: "resume_target".to_string(),
                risk: "R1_REVERSIBLE_CONTROL".to_string(),
            },
            PlannedAction {
                action: "disconnect_probe".to_string(),
                risk: "R0_READ_ONLY".to_string(),
            },
        ]);
        Ok(FlashPlan {
            plan_id: format!("plan_{}", &confirm_digest[..16]),
            risk: "R2_DEVICE_WRITE".to_string(),
            backend: self.backend.name().to_string(),
            probe,
            target: target_info,
            firmware: firmware.info,
            ranges: layout.write_ranges,
            erase_ranges: layout.erase_ranges,
            policy: policy.clone(),
            execution,
            actions,
            confirm_digest,
        })
    }

    pub fn execute_flash(
        &mut self,
        firmware_path: &Path,
        probe_id: Option<&str>,
        target: Option<&str>,
        base_address: Option<Address>,
        confirm_digest: &str,
        evidence_path: &Path,
    ) -> Result<FlashExecution> {
        self.execute_flash_with_options(
            firmware_path,
            probe_id,
            target,
            &FirmwareInputOptions {
                base_address,
                ..FirmwareInputOptions::default()
            },
            confirm_digest,
            evidence_path,
        )
    }

    pub fn execute_flash_with_options(
        &mut self,
        firmware_path: &Path,
        probe_id: Option<&str>,
        target: Option<&str>,
        firmware_options: &FirmwareInputOptions,
        confirm_digest: &str,
        evidence_path: &Path,
    ) -> Result<FlashExecution> {
        let policy = FlashPolicy::default();
        self.execute_flash_with_policy(
            firmware_path,
            probe_id,
            target,
            ConfirmedFlashOptions {
                firmware: firmware_options,
                policy: &policy,
                confirm_digest,
                evidence_path,
            },
        )
    }

    pub fn execute_flash_with_policy(
        &mut self,
        firmware_path: &Path,
        probe_id: Option<&str>,
        target: Option<&str>,
        options: ConfirmedFlashOptions<'_>,
    ) -> Result<FlashExecution> {
        let plan = self.plan_flash_with_policy(
            firmware_path,
            probe_id,
            target,
            options.firmware,
            options.policy,
        )?;
        if plan.confirm_digest != options.confirm_digest {
            return Err(DebugError::confirmation(
                &plan.confirm_digest,
                options.confirm_digest,
            ));
        }
        if !plan.execution.supported {
            return Err(DebugError::new(
                ErrorCode::CapabilityUnavailable,
                "this firmware plan is not executable by the selected backend yet",
                6,
                json!({
                    "plan_id": plan.plan_id,
                    "format": plan.firmware.format,
                    "blockers": plan.execution.blockers,
                    "probe_enumeration_performed": true,
                    "target_session_attached": false,
                    "flash_operation_requested": false,
                    "reset_requested": false,
                }),
            ));
        }
        let mut evidence_reservation = EvidenceReservation::new(options.evidence_path)?;

        let mut current = firmware::load(firmware_path, &plan.target.name, options.firmware)?;
        if current.info.format == FirmwareFormat::Bin.name() {
            current.bind_raw_segment(plan.ranges[0].start)?;
        }
        if current.info != plan.firmware {
            return Err(DebugError::new(
                ErrorCode::PlanStale,
                "firmware changed after the flash plan was created",
                2,
                json!({
                    "planned_sha256": plan.firmware.sha256,
                    "current_sha256": current.info.sha256,
                    "planned_segments": plan.firmware.segments,
                    "current_segments": current.info.segments,
                }),
            ));
        }

        let session = self.backend.attach(&plan.probe.id, &plan.target.name)?;
        let result = (|| {
            let staged = self.backend.program(
                &session,
                &current.segments,
                &current.info.sha256,
                &plan.policy,
            )?;
            validate_flash_report(&staged, &current.info)?;
            let flash = self
                .backend
                .verify(&session, &current.segments, &current.info.sha256)?;
            validate_flash_report(&flash, &current.info)?;
            if !flash.verified {
                return Err(DebugError::verification(
                    "firmware verification failed",
                    json!({
                        "firmware_sha256": current.info.sha256,
                        "segments": flash.segments,
                    }),
                ));
            }
            self.backend.reset(&session)?;
            let post_flash_cores = self.backend.capture_post_flash_snapshot(&session)?;
            validate_post_flash_core_inventory(&plan.target, &post_flash_cores).map_err(
                |problem| {
                    DebugError::new(
                        ErrorCode::ProtocolError,
                        "backend returned an invalid post-flash core inventory",
                        6,
                        json!({"target": plan.target, "problem": problem}),
                    )
                },
            )?;
            let snapshot = post_flash_cores
                .iter()
                .filter(|core| core.available)
                .min_by_key(|core| core.index)
                .and_then(|core| core.snapshot.clone())
                .expect("validated post-flash inventory contains an available core");
            let evidence = EvidenceBundle {
                schema_version: SCHEMA_VERSION.to_string(),
                capture_id: format!("cap_{}", Uuid::new_v4().simple()),
                captured_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                backend: self.backend.name().to_string(),
                probe: session.probe.clone(),
                target: session.target.clone(),
                firmware: current.info.clone(),
                plan_id: Some(plan.plan_id.clone()),
                confirm_digest: Some(plan.confirm_digest.clone()),
                ranges: plan.ranges.clone(),
                erase_ranges: plan.erase_ranges.clone(),
                policy: Some(plan.policy.clone()),
                flash: Some(flash.clone()),
                core: snapshot.clone(),
                post_flash_cores: post_flash_cores.clone(),
                operations: vec![
                    operation(1, "session.attach"),
                    operation(2, "flash.erase_affected_sectors"),
                    operation(3, "flash.program"),
                    operation(4, "flash.verify"),
                    operation(5, "core.reset_and_halt"),
                    operation(6, "snapshot.capture"),
                    operation(7, "core.resume"),
                ],
                complete: false,
            };
            Ok((flash, snapshot, post_flash_cores, evidence))
        })();

        let disconnect_result = self.backend.disconnect(&session);
        match (result, disconnect_result) {
            (Err(error), Err(cleanup_error)) => Err(with_cleanup_failure(error, cleanup_error)),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Ok((flash, snapshot, post_flash_cores, mut evidence)), Ok(())) => {
                evidence.operations.push(operation(8, "session.disconnect"));
                evidence.complete = true;
                let artifact = evidence_reservation.publish(&evidence)?;
                Ok(FlashExecution {
                    plan,
                    session,
                    flash,
                    snapshot,
                    post_flash_cores,
                    evidence: artifact,
                })
            }
        }
    }
}

pub(crate) fn validate_register_request(names: &[String]) -> Result<()> {
    if names.len() > MAX_REGISTER_READS {
        return Err(DebugError::config(
            "too many register names were requested",
            json!({"requested_count": names.len(), "maximum": MAX_REGISTER_READS}),
        ));
    }

    let mut normalized_names = std::collections::BTreeSet::new();
    for name in names {
        if name.is_empty()
            || name.len() > 64
            || name.trim() != name
            || name.chars().any(char::is_control)
        {
            return Err(DebugError::config(
                "register names must be 1 to 64 visible characters without surrounding whitespace",
                json!({"name": name}),
            ));
        }
        if !normalized_names.insert(name.to_ascii_lowercase()) {
            return Err(DebugError::config(
                "duplicate register names are not allowed",
                json!({"name": name}),
            ));
        }
    }
    Ok(())
}

#[derive(Default)]
pub(crate) struct DebugControlEffectRequest {
    pub core_execution_state_restoration_verified: bool,
    pub reset_requested: bool,
    pub memory_read_requested: bool,
    pub instruction_step_requested: bool,
    pub execution_continue_requested: bool,
    pub hardware_breakpoint_configuration_requested: bool,
    pub hardware_breakpoint_state_verified: bool,
    pub intentional_final_core_state_change_requested: bool,
}

pub(crate) fn debug_control_effects<B: DebugBackend>(
    backend: &B,
    request: DebugControlEffectRequest,
) -> DebugControlEffects {
    let volatile_target_state_notes = backend.volatile_target_state_notes();
    DebugControlEffects {
        reset_requested: request.reset_requested,
        flash_operation_requested: false,
        memory_read_requested: request.memory_read_requested,
        instruction_step_requested: request.instruction_step_requested,
        execution_continue_requested: request.execution_continue_requested,
        hardware_breakpoint_configuration_requested: request
            .hardware_breakpoint_configuration_requested,
        hardware_breakpoint_state_verified: request.hardware_breakpoint_state_verified,
        intentional_final_core_state_change_requested: request
            .intentional_final_core_state_change_requested,
        arbitrary_memory_write_requested: false,
        core_execution_state_restoration_verified: request
            .core_execution_state_restoration_verified,
        backend_may_modify_volatile_target_state: !volatile_target_state_notes.is_empty(),
        volatile_target_state_notes,
    }
}

fn require_guarded_flash_capabilities(
    backend: &str,
    target: &crate::model::TargetInfo,
    capabilities: &crate::model::Capabilities,
) -> Result<()> {
    let required = [
        ("flash", capabilities.flash),
        ("verify", capabilities.verify),
        ("halt", capabilities.halt),
        ("run", capabilities.run),
        ("reset", capabilities.reset),
        ("register_read", capabilities.register_read),
    ];
    if let Some((capability, _)) = required.iter().find(|(_, available)| !available) {
        return Err(DebugError::new(
            ErrorCode::CapabilityUnavailable,
            "selected backend cannot complete the guarded flash workflow",
            6,
            json!({"backend": backend, "capability": capability}),
        ));
    }
    if target.core_count > 1 && !capabilities.multi_core_post_flash {
        return Err(DebugError::new(
            ErrorCode::CapabilityUnavailable,
            "selected backend cannot complete the guarded multi-core post-flash workflow",
            6,
            json!({"backend": backend, "capability": "multi_core_post_flash"}),
        ));
    }
    Ok(())
}

fn validate_flash_report(
    report: &crate::model::FlashReport,
    firmware: &crate::model::FirmwareInfo,
) -> Result<()> {
    let manifests_match = report.segments.len() == firmware.segments.len()
        && report
            .segments
            .iter()
            .zip(&firmware.segments)
            .all(|(actual, planned)| {
                actual.kind == planned.kind
                    && actual.start == planned.start
                    && actual.length == planned.length
                    && actual.sha256 == planned.sha256
            });
    let verification_consistent = !report.segments.is_empty()
        && report.verified == report.segments.iter().all(|segment| segment.verified);
    if report.bytes_programmed != firmware.program_size
        || report.firmware_sha256 != firmware.sha256
        || !manifests_match
        || !verification_consistent
    {
        return Err(DebugError::new(
            ErrorCode::ProtocolError,
            "backend flash report does not match the confirmed firmware manifest",
            6,
            json!({
                "firmware": firmware,
                "flash_report": report,
            }),
        ));
    }
    Ok(())
}

fn require_image_planning_capabilities(
    backend: &str,
    capabilities: &crate::model::Capabilities,
) -> Result<()> {
    if !capabilities.flash {
        return Err(DebugError::new(
            ErrorCode::CapabilityUnavailable,
            "selected backend cannot plan a physical flash image",
            6,
            json!({"backend": backend, "capability": "flash"}),
        ));
    }
    Ok(())
}

fn execution_readiness(
    firmware: &crate::model::FirmwareInfo,
    target: &crate::model::TargetInfo,
    capabilities: &crate::model::Capabilities,
    development_debug_authorized: bool,
) -> FlashExecutionReadiness {
    let is_idf = firmware.format == FirmwareFormat::EspIdf.name();
    let is_intel_hex = firmware.format == FirmwareFormat::IntelHex.name();
    if !(is_idf || is_intel_hex) {
        return FlashExecutionReadiness::default();
    }

    let mut blockers = Vec::new();
    if is_intel_hex && !capabilities.intel_hex_flash {
        blockers.push(FlashExecutionBlocker {
            code: "INTEL_HEX_EXECUTION_ACCEPTANCE_REQUIRED".to_string(),
            message: "Intel HEX execution remains disabled until target-specific code-flash acceptance is completed"
                .to_string(),
        });
    }
    if firmware.segments.len() > 1 && !capabilities.segmented_flash {
        blockers.push(FlashExecutionBlocker {
            code: "SEGMENTED_FLASH_ACCEPTANCE_REQUIRED".to_string(),
            message: "the selected backend and target have not passed segmented flash execution acceptance"
                .to_string(),
        });
    }
    if is_intel_hex
        && firmware
            .segments
            .iter()
            .any(|segment| segment.kind == "uicr")
        && !capabilities.non_boot_nvm_flash
        && !development_debug_authorized
    {
        blockers.push(FlashExecutionBlocker {
            code: "NON_BOOT_NVM_EXECUTION_ACCEPTANCE_REQUIRED".to_string(),
            message: "non-boot NVM execution remains disabled until target-specific UICR or other non-boot NVM acceptance is completed"
                .to_string(),
        });
    }
    if target.core_count > 1 && !capabilities.multi_core_post_flash {
        blockers.push(FlashExecutionBlocker {
            code: "MULTI_CORE_POST_FLASH_POLICY_UNVERIFIED".to_string(),
            message: "the multi-core target lacks a complete post-flash reset/snapshot/resume evidence policy"
                .to_string(),
        });
    } else if !(capabilities.verify
        && capabilities.reset
        && capabilities.halt
        && capabilities.run
        && capabilities.register_read)
    {
        blockers.push(FlashExecutionBlocker {
            code: "POST_FLASH_WORKFLOW_UNAVAILABLE".to_string(),
            message:
                "the selected target lacks the guarded verify/reset/snapshot/resume capability set"
                    .to_string(),
        });
    }
    FlashExecutionReadiness {
        supported: blockers.is_empty(),
        blockers,
    }
}

pub fn inspect_evidence(path: &Path) -> Result<EvidenceBundle> {
    let bytes =
        fs::read(path).map_err(|error| DebugError::io("read evidence", path.to_str(), &error))?;
    let bundle: EvidenceBundle = serde_json::from_slice(&bytes).map_err(|error| {
        DebugError::evidence(
            "evidence is not valid JSON",
            json!({"path": path, "parser_message": error.to_string()}),
        )
    })?;
    if bundle.schema_version != SCHEMA_VERSION || !bundle.complete {
        return Err(DebugError::evidence(
            "evidence is incomplete or uses an unsupported schema",
            json!({
                "path": path,
                "schema_version": bundle.schema_version,
                "complete": bundle.complete,
            }),
        ));
    }
    if !bundle.post_flash_cores.is_empty() {
        validate_post_flash_core_inventory(&bundle.target, &bundle.post_flash_cores).map_err(
            |problem| {
                DebugError::evidence(
                    "evidence contains an invalid post-flash core inventory",
                    json!({"path": path, "problem": problem}),
                )
            },
        )?;
        let compatibility_core = bundle
            .post_flash_cores
            .iter()
            .filter(|core| core.available)
            .min_by_key(|core| core.index)
            .and_then(|core| core.snapshot.as_ref())
            .expect("validated post-flash inventory contains an available core");
        if &bundle.core != compatibility_core {
            return Err(DebugError::evidence(
                "evidence compatibility core does not match the first available post-flash core",
                json!({"path": path}),
            ));
        }
    }
    Ok(bundle)
}

pub(crate) fn select_probe(probes: &[ProbeInfo], requested: Option<&str>) -> Result<ProbeInfo> {
    if let Some(id) = requested {
        let matches = probes
            .iter()
            .filter(|probe| probe.id == id)
            .cloned()
            .collect::<Vec<_>>();
        return match matches.as_slice() {
            [probe] => ensure_probe_accessible(probe.clone()),
            [] => Err(DebugError::unavailable(
                ErrorCode::ProbeUnavailable,
                "requested probe is not available",
                json!({"requested": id, "available": probes}),
            )),
            many => Err(DebugError::unavailable(
                ErrorCode::ProbeAmbiguous,
                "requested selector matches multiple probes; a unique serial or interface is required",
                json!({"requested": id, "matches": many}),
            )),
        };
    }
    match probes {
        [only] => ensure_probe_accessible(only.clone()),
        [] => Err(DebugError::unavailable(
            ErrorCode::ProbeUnavailable,
            "no debug probe is available",
            json!({}),
        )),
        many => Err(DebugError::unavailable(
            ErrorCode::ProbeAmbiguous,
            "multiple debug probes are available; select one explicitly",
            json!({"available": many}),
        )),
    }
}

fn ensure_probe_accessible(probe: ProbeInfo) -> Result<ProbeInfo> {
    if probe.accessible {
        Ok(probe)
    } else {
        Err(DebugError::new(
            ErrorCode::PermissionDenied,
            "the selected debug probe is visible but not accessible",
            8,
            json!({"probe": probe}),
        ))
    }
}

struct EvidenceReservation {
    target_path: PathBuf,
    temp_path: PathBuf,
    file: Option<fs::File>,
    preserve_temp: bool,
}

impl EvidenceReservation {
    fn new(path: &Path) -> Result<Self> {
        if path.exists() {
            return Err(DebugError::output_exists(&path.display().to_string()));
        }
        let parent = output_parent(path);
        fs::create_dir_all(parent).map_err(|error| {
            DebugError::io("create evidence directory", parent.to_str(), &error)
        })?;
        let temp_path = temporary_sibling(path);
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .map_err(|error| {
                DebugError::io("reserve temporary evidence", temp_path.to_str(), &error)
            })?;
        Ok(Self {
            target_path: path.to_path_buf(),
            temp_path,
            file: Some(file),
            preserve_temp: false,
        })
    }

    fn publish(&mut self, bundle: &EvidenceBundle) -> Result<ArtifactReference> {
        let serialized = serde_json::to_vec_pretty(bundle).expect("evidence always serializes");
        let mut file = self
            .file
            .take()
            .expect("evidence reservation is unpublished");
        if let Err(error) = (|| -> std::io::Result<()> {
            file.write_all(&serialized)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            Ok(())
        })() {
            return Err(DebugError::io(
                "write temporary evidence",
                self.temp_path.to_str(),
                &error,
            ));
        }
        drop(file);

        if let Err(error) = fs::hard_link(&self.temp_path, &self.target_path) {
            self.preserve_temp = true;
            return if error.kind() == std::io::ErrorKind::AlreadyExists {
                Err(DebugError::new(
                    ErrorCode::OutputExists,
                    "refusing to overwrite an evidence file created during execution; complete evidence remains at the recovery path",
                    2,
                    json!({
                        "path": self.target_path,
                        "recovery_path": self.temp_path,
                    }),
                ))
            } else {
                Err(DebugError::new(
                    if error.kind() == std::io::ErrorKind::PermissionDenied {
                        ErrorCode::PermissionDenied
                    } else {
                        ErrorCode::Internal
                    },
                    format!(
                        "commit evidence failed: {error}; complete evidence remains at the recovery path"
                    ),
                    if error.kind() == std::io::ErrorKind::PermissionDenied {
                        8
                    } else {
                        10
                    },
                    json!({
                        "path": self.target_path,
                        "recovery_path": self.temp_path,
                    }),
                ))
            };
        }
        let _ = fs::remove_file(&self.temp_path);
        let size = (serialized.len() + 1) as u64;
        let mut persisted = serialized;
        persisted.push(b'\n');
        Ok(ArtifactReference {
            kind: "debug_snapshot".to_string(),
            path: self.target_path.display().to_string(),
            size,
            sha256: sha256_bytes(&persisted),
        })
    }
}

impl Drop for EvidenceReservation {
    fn drop(&mut self) {
        self.file.take();
        if !self.preserve_temp && self.temp_path.exists() {
            let _ = fs::remove_file(&self.temp_path);
        }
    }
}

fn output_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn temporary_sibling(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|value| value.to_os_string())
        .unwrap_or_else(|| "evidence".into());
    name.push(format!(".{}.tmp", Uuid::new_v4().simple()));
    path.with_file_name(name)
}

fn operation(sequence: u32, name: &str) -> OperationRecord {
    OperationRecord {
        sequence,
        operation: name.to_string(),
        ok: true,
    }
}

fn with_cleanup_failure(mut primary: DebugError, cleanup: DebugError) -> DebugError {
    primary.message = format!("{}; session cleanup also failed", primary.message);
    primary.details = json!({
        "primary": primary.details,
        "cleanup": {
            "code": cleanup.code,
            "message": cleanup.message,
            "details": cleanup.details,
        },
    });
    primary
}

pub(crate) fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;
    use crate::backend::replay::{ReplayBackend, ReplayFixture};
    use crate::model::{
        CoreObservation, CoreSnapshot, CoreState, FirmwareInfo, FlashReport, FlashSegmentReport,
        PostFlashCoreObservation,
    };

    fn fixture() -> ReplayFixture {
        serde_json::from_str(include_str!("../examples/replay/stm32g4.json")).unwrap()
    }

    fn esp32s3_post_flash_fixture() -> ReplayFixture {
        let mut replay = fixture();
        replay.target.name = "esp32s3".to_string();
        replay.target.architecture = "xtensa".to_string();
        replay.target.core_count = 2;
        replay.capabilities.segmented_flash = true;
        replay.capabilities.multi_core_post_flash = true;
        replay.capabilities.reset = true;
        replay.flash.base_address = Address(0);
        replay.flash.erase_ranges = vec![FlashRange {
            start: Address(0),
            length: 0x2_0000,
        }];
        let cpu0_snapshot = CoreSnapshot {
            captured_state: CoreState::Halted,
            state: CoreState::Running,
            pc: Address(0x4200_0000),
            sp: Address(0x3fcf_0000),
            registers: std::collections::BTreeMap::from([("lr".to_string(), Address(0x4200_0004))]),
            halt_reason: Some("request".to_string()),
        };
        let cpu1_snapshot = CoreSnapshot {
            captured_state: CoreState::Halted,
            state: CoreState::Halted,
            pc: Address(0x4000_03c0),
            sp: Address(0),
            registers: std::collections::BTreeMap::from([("lr".to_string(), Address(0))]),
            halt_reason: Some("breakpoint".to_string()),
        };
        replay.live_cores = vec![
            CoreObservation {
                index: 0,
                name: "cpu0".to_string(),
                architecture: "xtensa".to_string(),
                available: true,
                original_state: Some(CoreState::Running),
                snapshot: Some(cpu0_snapshot.clone()),
                unavailable_reason: None,
            },
            CoreObservation {
                index: 1,
                name: "cpu1".to_string(),
                architecture: "xtensa".to_string(),
                available: false,
                original_state: None,
                snapshot: None,
                unavailable_reason: Some("core is not enabled".to_string()),
            },
        ];
        replay.post_flash_cores = vec![
            PostFlashCoreObservation {
                index: 0,
                name: "cpu0".to_string(),
                architecture: "xtensa".to_string(),
                available: true,
                expected_final_state: Some(CoreState::Running),
                snapshot: Some(cpu0_snapshot),
                unavailable_reason: None,
            },
            PostFlashCoreObservation {
                index: 1,
                name: "cpu1".to_string(),
                architecture: "xtensa".to_string(),
                available: true,
                expected_final_state: Some(CoreState::Halted),
                snapshot: Some(cpu1_snapshot),
                unavailable_reason: None,
            },
        ];
        replay
    }

    #[test]
    fn changing_firmware_changes_confirmation_digest() {
        let directory = tempdir().unwrap();
        let first = directory.path().join("first.bin");
        let second = directory.path().join("second.bin");
        fs::write(&first, b"firmware-a").unwrap();
        fs::write(&second, b"firmware-b").unwrap();
        let service = DebugService::new(ReplayBackend::new(fixture()));

        let first_plan = service.plan_flash(&first, None, None, None).unwrap();
        let second_plan = service.plan_flash(&second, None, None, None).unwrap();

        assert_ne!(first_plan.confirm_digest, second_plan.confirm_digest);
    }

    #[test]
    fn flash_report_must_match_the_confirmed_segment_manifest() {
        let firmware = FirmwareInfo {
            path: "firmware.bin".to_string(),
            format: "bin".to_string(),
            base_address: Some(Address(0x0800_0000)),
            size: 4,
            sha256: "11".repeat(32),
            program_size: 4,
            segments: vec![FirmwareSegmentInfo {
                kind: "application".to_string(),
                start: Address(0x0800_0000),
                length: 4,
                sha256: "22".repeat(32),
            }],
            image_options: None,
        };
        let mut report = FlashReport {
            bytes_programmed: 4,
            firmware_sha256: firmware.sha256.clone(),
            segments: vec![FlashSegmentReport {
                kind: "application".to_string(),
                start: Address(0x0800_0000),
                length: 4,
                sha256: "22".repeat(32),
                verified: true,
            }],
            verified: true,
        };

        validate_flash_report(&report, &firmware).unwrap();
        report.segments[0].start = Address(0x0800_0004);

        let error = validate_flash_report(&report, &firmware).unwrap_err();
        assert_eq!(error.code, ErrorCode::ProtocolError);
    }

    #[test]
    fn flash_report_rejects_inconsistent_aggregate_verification() {
        let firmware = FirmwareInfo {
            path: "firmware.bin".to_string(),
            format: "bin".to_string(),
            base_address: Some(Address(0x0800_0000)),
            size: 1,
            sha256: "11".repeat(32),
            program_size: 1,
            segments: vec![FirmwareSegmentInfo {
                kind: "application".to_string(),
                start: Address(0x0800_0000),
                length: 1,
                sha256: "22".repeat(32),
            }],
            image_options: None,
        };
        let report = FlashReport {
            bytes_programmed: 1,
            firmware_sha256: firmware.sha256.clone(),
            segments: vec![FlashSegmentReport {
                kind: "application".to_string(),
                start: Address(0x0800_0000),
                length: 1,
                sha256: "22".repeat(32),
                verified: false,
            }],
            verified: true,
        };

        let error = validate_flash_report(&report, &firmware).unwrap_err();
        assert_eq!(error.code, ErrorCode::ProtocolError);
    }

    #[test]
    fn probe_test_disconnects_and_can_be_repeated() {
        let replay = fixture();
        let probe_id = replay.probe.id.clone();
        let target = replay.target.name.clone();
        let mut service = DebugService::new(ReplayBackend::new(replay));

        let first = service.test_probe_connection(&probe_id, &target).unwrap();
        let second = service.test_probe_connection(&probe_id, &target).unwrap();

        assert!(first.complete);
        assert!(second.complete);
        assert_eq!(first.operations[1].operation, "session.disconnect");
    }

    #[test]
    fn live_snapshot_restores_state_and_can_be_repeated() {
        let mut replay = fixture();
        replay.initial_core.captured_state = crate::model::CoreState::Running;
        replay.initial_core.state = crate::model::CoreState::Running;
        replay.control_cores[0].state = crate::model::CoreState::Running;
        replay.control_cores[0].halt_reason = None;
        let probe_id = replay.probe.id.clone();
        let target = replay.target.name.clone();
        let mut service = DebugService::new(ReplayBackend::new(replay));

        let first = service.capture_snapshot(&probe_id, &target).unwrap();
        let second = service.capture_snapshot(&probe_id, &target).unwrap();

        assert!(first.complete);
        assert!(second.complete);
        assert_eq!(first.cores.len(), 1);
        assert_eq!(first.cores[0].index, 0);
        assert_eq!(first.cores[0].name, "core0");
        assert_eq!(
            first.cores[0].original_state,
            Some(crate::model::CoreState::Running)
        );
        assert_eq!(
            first.cores[0].snapshot.as_ref().unwrap().captured_state,
            crate::model::CoreState::Halted
        );
        assert_eq!(
            first.cores[0].snapshot.as_ref().unwrap().halt_reason,
            Some("request".to_string())
        );
        assert_eq!(
            first.cores[0].snapshot.as_ref().unwrap().state,
            crate::model::CoreState::Running
        );
        assert_eq!(
            first.operations.last().unwrap().operation,
            "session.disconnect_preserving_core_state"
        );
    }

    #[test]
    fn live_snapshot_requires_state_restoration_capabilities() {
        let replay = fixture();
        let probe_id = replay.probe.id.clone();
        let target = replay.target.name.clone();
        let mut without_run = replay;
        without_run.capabilities.run = false;
        let mut service = DebugService::new(ReplayBackend::new(without_run));

        let error = service.capture_snapshot(&probe_id, &target).unwrap_err();

        assert_eq!(error.code, ErrorCode::CapabilityUnavailable);
        assert_eq!(error.details["capability"], "run");
    }

    #[test]
    fn register_read_is_bounded_state_preserving_and_repeatable() {
        let replay = fixture();
        let probe_id = replay.probe.id.clone();
        let target = replay.target.name.clone();
        let mut service = DebugService::new(ReplayBackend::new(replay));
        let names = ["r14".to_string(), "pc".to_string()];

        let first = service
            .read_registers(&probe_id, &target, 0, &names)
            .unwrap();
        let second = service
            .read_registers(&probe_id, &target, 0, &names)
            .unwrap();

        assert!(first.complete);
        assert!(second.complete);
        assert_eq!(first.core.original_state, CoreState::Halted);
        assert_eq!(first.core.captured_state, CoreState::Halted);
        assert_eq!(first.core.state, CoreState::Halted);
        assert_eq!(first.core.registers[0].name, "lr");
        assert_eq!(first.core.registers[1].name, "pc");
        assert!(first.effects.core_execution_state_restoration_verified);
        assert!(!first.effects.reset_requested);
        assert_eq!(first.operations[3].operation, "registers.read");
        assert_eq!(
            first.operations.last().unwrap().operation,
            "session.disconnect_preserving_core_state"
        );
    }

    #[test]
    fn invalid_register_core_is_rejected_before_a_session_is_opened() {
        let replay = fixture();
        let probe_id = replay.probe.id.clone();
        let target = replay.target.name.clone();
        let mut service = DebugService::new(ReplayBackend::new(replay));

        let error = service
            .read_registers(&probe_id, &target, 1, &[])
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert_eq!(error.details["core_count"], 1);

        assert!(
            service
                .read_registers(&probe_id, &target, 0, &["pc".to_string()])
                .is_ok()
        );
    }

    #[test]
    fn memory_read_is_exact_state_preserving_hashed_and_repeatable() {
        let replay = fixture();
        let probe_id = replay.probe.id.clone();
        let target = replay.target.name.clone();
        let mut service = DebugService::new(ReplayBackend::new(replay));

        let first = service
            .read_memory(&probe_id, &target, 0, Address(0x2000_7f04), 8)
            .unwrap();
        let second = service
            .read_memory(&probe_id, &target, 0, Address(0x2000_7f04), 8)
            .unwrap();

        assert!(first.complete);
        assert!(second.complete);
        assert_eq!(first.range.start, Address(0x2000_7f04));
        assert_eq!(first.range.length, 8);
        assert_eq!(first.range.region.kind, crate::model::MemoryRegionKind::Ram);
        assert_eq!(first.core.original_state, CoreState::Halted);
        assert_eq!(first.core.captured_state, CoreState::Halted);
        assert_eq!(first.core.state, CoreState::Halted);
        assert_eq!(first.encoding, "hex");
        assert_eq!(first.data, "0405060708090a0b");
        assert_eq!(first.sha256, sha256_bytes(&(4_u8..12).collect::<Vec<_>>()));
        assert!(first.effects.memory_read_requested);
        assert!(first.effects.core_execution_state_restoration_verified);
        assert!(!first.effects.arbitrary_memory_write_requested);
        assert_eq!(first.operations[4].operation, "memory.read_exact");
        assert_eq!(
            first.operations.last().unwrap().operation,
            "session.disconnect_preserving_core_state"
        );
    }

    #[test]
    fn invalid_memory_range_is_rejected_before_a_session_is_opened() {
        let replay = fixture();
        let probe_id = replay.probe.id.clone();
        let target = replay.target.name.clone();
        let mut service = DebugService::new(ReplayBackend::new(replay));

        let error = service
            .read_memory(&probe_id, &target, 0, Address(0x2000_7f18), 16)
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::ConfigInvalid);

        assert!(
            service
                .read_memory(&probe_id, &target, 0, Address(0x2000_7f00), 4)
                .is_ok()
        );
    }

    #[test]
    fn core_control_persists_verified_state_across_one_shot_sessions() {
        let replay = fixture();
        let probe_id = replay.probe.id.clone();
        let target = replay.target.name.clone();
        let mut service = DebugService::new(ReplayBackend::new(replay));

        let initial = service
            .control_core(&probe_id, &target, 0, CoreExecutionAction::Status)
            .unwrap();
        let run = service
            .control_core(&probe_id, &target, 0, CoreExecutionAction::Run)
            .unwrap();
        let running = service
            .control_core(&probe_id, &target, 0, CoreExecutionAction::Status)
            .unwrap();
        let snapshot_while_running = service.capture_snapshot(&probe_id, &target).unwrap();
        let registers_while_running = service
            .read_registers(&probe_id, &target, 0, &["pc".to_string()])
            .unwrap();
        let memory_while_running = service
            .read_memory(&probe_id, &target, 0, Address(0x2000_7f00), 4)
            .unwrap();
        let halt = service
            .control_core(&probe_id, &target, 0, CoreExecutionAction::Halt)
            .unwrap();
        let halted = service
            .control_core(&probe_id, &target, 0, CoreExecutionAction::Status)
            .unwrap();

        assert_eq!(initial.core.state, CoreState::Halted);
        assert!(!initial.core.state_changed);
        assert_eq!(initial.operations.len(), 3);
        assert!(
            !initial
                .effects
                .intentional_final_core_state_change_requested
        );
        assert_eq!(run.core.original_state, CoreState::Halted);
        assert_eq!(run.core.state, CoreState::Running);
        assert!(run.core.state_changed);
        assert_eq!(
            run.operations[3].operation,
            "core.verify_running_before_disconnect"
        );
        assert!(run.effects.intentional_final_core_state_change_requested);
        assert!(!run.effects.core_execution_state_restoration_verified);
        assert_eq!(running.core.state, CoreState::Running);
        assert_eq!(
            snapshot_while_running.cores[0].original_state,
            Some(CoreState::Running)
        );
        assert_eq!(
            snapshot_while_running.cores[0]
                .snapshot
                .as_ref()
                .unwrap()
                .state,
            CoreState::Running
        );
        assert_eq!(
            registers_while_running.core.original_state,
            CoreState::Running
        );
        assert_eq!(registers_while_running.core.state, CoreState::Running);
        assert_eq!(memory_while_running.core.original_state, CoreState::Running);
        assert_eq!(memory_while_running.core.state, CoreState::Running);
        assert_eq!(halt.core.original_state, CoreState::Running);
        assert_eq!(halt.core.state, CoreState::Halted);
        assert!(halt.core.state_changed);
        assert_eq!(
            halt.operations[3].operation,
            "core.verify_halted_before_disconnect"
        );
        assert!(halt.effects.intentional_final_core_state_change_requested);
        assert_eq!(
            halt.operations.last().unwrap().operation,
            "session.disconnect_preserving_core_state"
        );
        assert_eq!(halted.core.state, CoreState::Halted);
        assert_eq!(
            halted.operations.last().unwrap().operation,
            "session.disconnect_preserving_core_state"
        );
    }

    #[test]
    fn continue_until_halt_reports_a_bounded_replay_event() {
        let replay = fixture();
        let probe_id = replay.probe.id.clone();
        let target = replay.target.name.clone();
        let mut service = DebugService::new(ReplayBackend::new(replay));

        let report = service
            .continue_until_halt(
                &probe_id,
                &target,
                0,
                ContinueUntilHaltOptions {
                    timeout_ms: 100,
                    poll_interval_ms: 25,
                },
            )
            .unwrap();

        assert_eq!(
            report.wait.outcome,
            crate::model::ContinueUntilHaltOutcome::Halted
        );
        assert_eq!(report.wait.state, CoreState::Halted);
        assert_eq!(report.wait.halt_reason.as_deref(), Some("breakpoint"));
        assert_eq!(report.wait.poll_count, 3);
        assert!(report.effects.execution_continue_requested);
        assert!(!report.effects.intentional_final_core_state_change_requested);
        assert_eq!(
            report.operations.last().unwrap().operation,
            "session.disconnect_preserving_core_state"
        );
    }

    #[test]
    fn invalid_continue_until_halt_options_are_rejected_before_probe_selection() {
        let replay = fixture();
        let target = replay.target.name.clone();
        let mut service = DebugService::new(ReplayBackend::new(replay));

        let error = service
            .continue_until_halt(
                "deliberately-invalid",
                &target,
                0,
                ContinueUntilHaltOptions {
                    timeout_ms: 5,
                    poll_interval_ms: 10,
                },
            )
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::ConfigInvalid);
    }

    #[test]
    fn missing_post_disconnect_core_state_is_rejected_before_probe_selection() {
        let mut replay = fixture();
        replay.capabilities.post_disconnect_core_state = false;
        let target = replay.target.name.clone();
        let mut service = DebugService::new(ReplayBackend::new(replay));

        let error = service
            .control_core(
                "deliberately-invalid",
                &target,
                0,
                CoreExecutionAction::Halt,
            )
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::CapabilityUnavailable);
        assert_eq!(error.details["capability"], "post_disconnect_core_state");
        assert_eq!(error.details["action"], "halt");

        let status_error = service
            .control_core(
                "deliberately-invalid",
                &target,
                0,
                CoreExecutionAction::Status,
            )
            .unwrap_err();
        assert_eq!(status_error.code, ErrorCode::CapabilityUnavailable);
        assert_eq!(
            status_error.details["capability"],
            "post_disconnect_core_state"
        );

        let wait_error = service
            .continue_until_halt(
                "deliberately-invalid",
                &target,
                0,
                ContinueUntilHaltOptions {
                    timeout_ms: 100,
                    poll_interval_ms: 25,
                },
            )
            .unwrap_err();
        assert_eq!(wait_error.code, ErrorCode::CapabilityUnavailable);
        assert_eq!(
            wait_error.details["capability"],
            "post_disconnect_core_state"
        );

        let snapshot_error = service
            .capture_snapshot("deliberately-invalid", &target)
            .unwrap_err();
        assert_eq!(snapshot_error.code, ErrorCode::CapabilityUnavailable);
        assert_eq!(
            snapshot_error.details["capability"],
            "post_disconnect_core_state"
        );

        let register_error = service
            .read_registers("deliberately-invalid", &target, 0, &["pc".to_string()])
            .unwrap_err();
        assert_eq!(register_error.code, ErrorCode::CapabilityUnavailable);
        assert_eq!(
            register_error.details["capability"],
            "post_disconnect_core_state"
        );

        let memory_error = service
            .read_memory("deliberately-invalid", &target, 0, Address(0x2000_7f00), 4)
            .unwrap_err();
        assert_eq!(memory_error.code, ErrorCode::CapabilityUnavailable);
        assert_eq!(
            memory_error.details["capability"],
            "post_disconnect_core_state"
        );

        let invalid_memory_error = service
            .read_memory("deliberately-invalid", &target, 0, Address(0x2000_7f18), 16)
            .unwrap_err();
        assert_eq!(invalid_memory_error.code, ErrorCode::ConfigInvalid);
    }

    #[test]
    fn invalid_core_control_index_is_rejected_before_a_session_is_opened() {
        let replay = fixture();
        let probe_id = replay.probe.id.clone();
        let target = replay.target.name.clone();
        let mut service = DebugService::new(ReplayBackend::new(replay));

        let error = service
            .control_core(&probe_id, &target, 1, CoreExecutionAction::Status)
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert_eq!(error.details["core_count"], 1);
        assert!(
            service
                .control_core(&probe_id, &target, 0, CoreExecutionAction::Status)
                .is_ok()
        );
    }

    #[test]
    fn reset_capture_reports_and_preserves_per_core_expected_states() {
        let replay = esp32s3_post_flash_fixture();
        let probe_id = replay.probe.id.clone();
        let target = replay.target.name.clone();
        let mut service = DebugService::new(ReplayBackend::new(replay));

        let report = service.capture_reset_snapshot(&probe_id, &target).unwrap();

        assert!(report.complete);
        assert!(report.effects.reset_requested);
        assert!(!report.effects.flash_operation_requested);
        assert!(report.effects.core_execution_state_restoration_verified);
        assert_eq!(report.cores.len(), 2);
        assert_eq!(
            report.cores[0].expected_final_state,
            Some(CoreState::Running)
        );
        assert_eq!(
            report.cores[0].snapshot.as_ref().unwrap().state,
            CoreState::Running
        );
        assert_eq!(
            report.cores[1].expected_final_state,
            Some(CoreState::Halted)
        );
        assert_eq!(
            report.cores[1].snapshot.as_ref().unwrap().state,
            CoreState::Halted
        );
        assert_eq!(
            report.operations.last().unwrap().operation,
            "session.disconnect"
        );
    }

    #[test]
    fn changing_flash_address_changes_confirmation_digest() {
        let directory = tempdir().unwrap();
        let firmware = directory.path().join("demo.bin");
        fs::write(&firmware, b"same firmware").unwrap();
        let first_fixture = fixture();
        let mut second_fixture = fixture();
        second_fixture.flash.base_address = crate::model::Address(0x0801_0000);
        second_fixture.flash.erase_ranges[0].start = crate::model::Address(0x0801_0000);

        let first = DebugService::new(ReplayBackend::new(first_fixture))
            .plan_flash(&firmware, None, None, None)
            .unwrap();
        let second = DebugService::new(ReplayBackend::new(second_fixture))
            .plan_flash(&firmware, None, None, None)
            .unwrap();

        assert_eq!(first.ranges[0].start, crate::model::Address(0x0800_0000));
        assert_eq!(first.ranges[0].length, 13);
        assert_ne!(first.confirm_digest, second.confirm_digest);
    }

    #[test]
    fn idf_flash_size_changes_confirmation_and_execution_stays_blocked() {
        let directory = tempdir().unwrap();
        let firmware = directory.path().join("demo.elf");
        fs::write(&firmware, crate::firmware::tests::minimal_esp32s3_idf_elf()).unwrap();
        let mut replay = fixture();
        replay.target.name = "esp32s3".to_string();
        replay.target.architecture = "xtensa".to_string();
        replay.target.core_count = 2;
        replay.capabilities.reset = true;
        replay.flash.base_address = Address(0);
        replay.flash.erase_ranges = vec![FlashRange {
            start: Address(0),
            length: 0x2_0000,
        }];
        let service = DebugService::new(ReplayBackend::new(replay));
        let options = |flash_size| FirmwareInputOptions {
            format: Some(FirmwareFormat::EspIdf),
            flash_size: Some(flash_size),
            ..FirmwareInputOptions::default()
        };

        let first = service
            .plan_flash_with_options(&firmware, None, None, &options(4 * 1024 * 1024))
            .unwrap();
        let second = service
            .plan_flash_with_options(&firmware, None, None, &options(8 * 1024 * 1024))
            .unwrap();

        assert_eq!(first.firmware.segments.len(), 3);
        assert_eq!(first.ranges.len(), 3);
        assert!(!first.execution.supported);
        assert_eq!(first.execution.blockers.len(), 2);
        assert_eq!(
            first.execution.blockers[0].code,
            "SEGMENTED_FLASH_ACCEPTANCE_REQUIRED"
        );
        assert_eq!(
            first.execution.blockers[1].code,
            "MULTI_CORE_POST_FLASH_POLICY_UNVERIFIED"
        );
        assert_ne!(first.confirm_digest, second.confirm_digest);
    }

    #[test]
    fn accepted_hex_segmented_code_flash_can_execute_without_uicr_capability() {
        let directory = tempdir().unwrap();
        let firmware = directory.path().join("dk-acceptance.hex");
        let evidence = directory.path().join("run.evidence.json");
        fs::write(
            &firmware,
            ":020000040000FA\n:100000000000042009000000FEE7000000000000DE\n:10100000A55AC33C9669F00F11224488DEADBEEFAD\n:00000001FF\n",
        )
        .unwrap();

        let mut replay = fixture();
        replay.target.name = "nRF52840_xxAA".to_string();
        replay.target.architecture = "armv7em".to_string();
        replay.capabilities.intel_hex_flash = true;
        replay.capabilities.segmented_flash = true;
        replay.capabilities.non_boot_nvm_flash = false;
        replay.flash.base_address = Address(0);
        replay.flash.erase_ranges = vec![FlashRange {
            start: Address(0),
            length: 0x2000,
        }];

        let mut service = DebugService::new(ReplayBackend::new(replay));
        let plan = service
            .plan_flash_with_options(
                &firmware,
                Some("replay:stlink-v3:0039002A3432510433343034"),
                Some("nRF52840_xxAA"),
                &FirmwareInputOptions::default(),
            )
            .unwrap();

        assert!(plan.execution.supported);
        assert_eq!(plan.firmware.segments.len(), 2);
        assert!(
            plan.firmware
                .segments
                .iter()
                .all(|segment| segment.kind == "data")
        );

        let result = service
            .execute_flash_with_options(
                &firmware,
                Some("replay:stlink-v3:0039002A3432510433343034"),
                Some("nRF52840_xxAA"),
                &FirmwareInputOptions::default(),
                &plan.confirm_digest,
                &evidence,
            )
            .unwrap();

        assert!(result.flash.verified);
        assert_eq!(result.flash.segments.len(), 2);
        assert!(result.flash.segments.iter().all(|segment| segment.verified));
        assert!(evidence.exists());
    }

    #[test]
    fn uicr_hex_execution_stays_blocked_without_non_boot_nvm_acceptance() {
        let directory = tempdir().unwrap();
        let firmware = directory.path().join("uicr.hex");
        fs::write(
            &firmware,
            ":020000041000EA\n:041000001122334442\n:00000001FF\n",
        )
        .unwrap();

        let mut replay = fixture();
        replay.target.name = "nRF52840_xxAA".to_string();
        replay.target.architecture = "armv7em".to_string();
        replay.capabilities.intel_hex_flash = true;
        replay.capabilities.segmented_flash = true;
        replay.capabilities.non_boot_nvm_flash = false;
        replay.flash.base_address = Address(0x1000_1000);
        replay.flash.erase_ranges = vec![FlashRange {
            start: Address(0x1000_1000),
            length: 0x1000,
        }];

        let service = DebugService::new(ReplayBackend::new(replay));
        let plan = service
            .plan_flash_with_options(
                &firmware,
                Some("replay:stlink-v3:0039002A3432510433343034"),
                Some("nRF52840_xxAA"),
                &FirmwareInputOptions::default(),
            )
            .unwrap();

        assert!(!plan.execution.supported);
        assert_eq!(plan.execution.blockers.len(), 1);
        assert_eq!(
            plan.execution.blockers[0].code,
            "NON_BOOT_NVM_EXECUTION_ACCEPTANCE_REQUIRED"
        );
    }

    #[test]
    fn exact_nrf52840_development_debug_policy_is_digest_bound_and_executable() {
        let directory = tempdir().unwrap();
        let firmware = directory.path().join("development-debug.hex");
        let evidence = directory.path().join("run.evidence.json");
        fs::write(
            &firmware,
            ":020000040000FA\n:0400000001020304F2\n:020000041000EA\n:041208005A00000088\n:00000001FF\n",
        )
        .unwrap();

        let mut replay = fixture();
        replay.target.name = "nRF52840_xxAA".to_string();
        replay.target.architecture = "armv7em".to_string();
        replay.capabilities.intel_hex_flash = true;
        replay.capabilities.segmented_flash = true;
        replay.capabilities.non_boot_nvm_flash = false;
        replay.flash.base_address = Address(0);
        replay.flash.erase_ranges = vec![
            FlashRange {
                start: Address(0),
                length: 0x1000,
            },
            FlashRange {
                start: Address(0x1000_1000),
                length: 0x1000,
            },
        ];

        let mut service = DebugService::new(ReplayBackend::new(replay));
        let default_plan = service
            .plan_flash_with_options(
                &firmware,
                Some("replay:stlink-v3:0039002A3432510433343034"),
                Some("nRF52840_xxAA"),
                &FirmwareInputOptions::default(),
            )
            .unwrap();
        let policy = FlashPolicy::with_nrf52840_development_debug();
        let accepted_plan = service
            .plan_flash_with_policy(
                &firmware,
                Some("replay:stlink-v3:0039002A3432510433343034"),
                Some("nRF52840_xxAA"),
                &FirmwareInputOptions::default(),
                &policy,
            )
            .unwrap();

        assert!(!default_plan.execution.supported);
        assert!(accepted_plan.execution.supported);
        assert_ne!(default_plan.confirm_digest, accepted_plan.confirm_digest);
        assert_eq!(
            accepted_plan
                .policy
                .nrf52840_development_debug
                .as_ref()
                .unwrap()
                .uicr_address,
            Address(0x1000_1208)
        );
        assert!(accepted_plan.actions.iter().any(|action| {
            action.action == "program_nrf52840_uicr_approtect_hw_disabled"
                && action.risk == "R2_PERSISTENT_SECURITY_CONFIGURATION"
        }));

        let stale = service
            .execute_flash_with_policy(
                &firmware,
                Some("replay:stlink-v3:0039002A3432510433343034"),
                Some("nRF52840_xxAA"),
                ConfirmedFlashOptions {
                    firmware: &FirmwareInputOptions::default(),
                    policy: &policy,
                    confirm_digest: &default_plan.confirm_digest,
                    evidence_path: &evidence,
                },
            )
            .unwrap_err();
        assert_eq!(stale.code, ErrorCode::ConfirmationMismatch);
        assert!(!evidence.exists());

        let result = service
            .execute_flash_with_policy(
                &firmware,
                Some("replay:stlink-v3:0039002A3432510433343034"),
                Some("nRF52840_xxAA"),
                ConfirmedFlashOptions {
                    firmware: &FirmwareInputOptions::default(),
                    policy: &policy,
                    confirm_digest: &accepted_plan.confirm_digest,
                    evidence_path: &evidence,
                },
            )
            .unwrap();

        assert!(result.flash.verified);
        assert_eq!(result.flash.segments.len(), 2);
        assert_eq!(result.plan.policy, policy);
        assert_eq!(result.evidence.path, evidence.display().to_string());
    }

    #[test]
    fn nrf52840_development_debug_policy_rejects_any_other_uicr_value() {
        let directory = tempdir().unwrap();
        let firmware = directory.path().join("wrong-uicr.hex");
        fs::write(
            &firmware,
            ":020000040000FA\n:0400000001020304F2\n:020000041000EA\n:041208005B00000087\n:00000001FF\n",
        )
        .unwrap();

        let mut replay = fixture();
        replay.target.name = "nRF52840_xxAA".to_string();
        replay.target.architecture = "armv7em".to_string();
        replay.capabilities.intel_hex_flash = true;
        replay.capabilities.segmented_flash = true;
        replay.flash.base_address = Address(0);
        let service = DebugService::new(ReplayBackend::new(replay));

        let error = service
            .plan_flash_with_policy(
                &firmware,
                None,
                Some("nRF52840_xxAA"),
                &FirmwareInputOptions::default(),
                &FlashPolicy::with_nrf52840_development_debug(),
            )
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert_eq!(error.details["required_uicr_address"], "0x10001208");
        assert_eq!(error.details["required_little_endian_bytes"], "5a000000");
    }

    #[test]
    fn nrf52840_development_debug_policy_rejects_a_broader_uicr_erase_layout() {
        let directory = tempdir().unwrap();
        let firmware = directory.path().join("development-debug.hex");
        fs::write(
            &firmware,
            ":020000040000FA\n:0400000001020304F2\n:020000041000EA\n:041208005A00000088\n:00000001FF\n",
        )
        .unwrap();

        let mut replay = fixture();
        replay.target.name = "nRF52840_xxAA".to_string();
        replay.target.architecture = "armv7em".to_string();
        replay.capabilities.intel_hex_flash = true;
        replay.capabilities.segmented_flash = true;
        replay.flash.base_address = Address(0);
        replay.flash.erase_ranges = vec![
            FlashRange {
                start: Address(0),
                length: 0x1000,
            },
            FlashRange {
                start: Address(0x1000_1000),
                length: 0x2000,
            },
        ];
        let service = DebugService::new(ReplayBackend::new(replay));

        let error = service
            .plan_flash_with_policy(
                &firmware,
                None,
                Some("nRF52840_xxAA"),
                &FirmwareInputOptions::default(),
                &FlashPolicy::with_nrf52840_development_debug(),
            )
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::CapabilityUnavailable);
        assert_eq!(
            error.details["required_uicr_erase_range"]["start"],
            "0x10001000"
        );
    }

    #[test]
    fn nrf52840_development_debug_policy_rejects_extra_non_boot_nvm() {
        let directory = tempdir().unwrap();
        let firmware = directory.path().join("extra-nvm.hex");
        fs::write(
            &firmware,
            ":020000040000FA\n:0400000001020304F2\n:020000041000EA\n:041208005A00000088\n:040000001122334452\n:00000001FF\n",
        )
        .unwrap();

        let mut replay = fixture();
        replay.target.name = "nRF52840_xxAA".to_string();
        replay.target.architecture = "armv7em".to_string();
        replay.capabilities.intel_hex_flash = true;
        replay.capabilities.segmented_flash = true;
        replay.flash.base_address = Address(0);
        let service = DebugService::new(ReplayBackend::new(replay));

        let error = service
            .plan_flash_with_policy(
                &firmware,
                None,
                Some("nRF52840_xxAA"),
                &FirmwareInputOptions::default(),
                &FlashPolicy::with_nrf52840_development_debug(),
            )
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert_eq!(
            error.details["required_code_flash_range"]["length"],
            0x10_0000
        );
    }

    #[test]
    fn idf_execute_is_rejected_before_evidence_reservation_or_attach() {
        let directory = tempdir().unwrap();
        let firmware = directory.path().join("demo.elf");
        let evidence = directory.path().join("run.evidence.json");
        fs::write(&firmware, crate::firmware::tests::minimal_esp32s3_idf_elf()).unwrap();
        let mut replay = fixture();
        replay.target.name = "esp32s3".to_string();
        replay.target.architecture = "xtensa".to_string();
        replay.target.core_count = 2;
        replay.capabilities.reset = true;
        replay.flash.base_address = Address(0);
        replay.flash.erase_ranges = vec![FlashRange {
            start: Address(0),
            length: 0x2_0000,
        }];
        let mut service = DebugService::new(ReplayBackend::new(replay));
        let options = FirmwareInputOptions {
            format: Some(FirmwareFormat::EspIdf),
            flash_size: Some(8 * 1024 * 1024),
            ..FirmwareInputOptions::default()
        };
        let plan = service
            .plan_flash_with_options(&firmware, None, None, &options)
            .unwrap();

        let error = service
            .execute_flash_with_options(
                &firmware,
                None,
                None,
                &options,
                &plan.confirm_digest,
                &evidence,
            )
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::CapabilityUnavailable);
        assert_eq!(error.details["probe_enumeration_performed"], true);
        assert_eq!(error.details["target_session_attached"], false);
        assert_eq!(error.details["flash_operation_requested"], false);
        assert_eq!(error.details["reset_requested"], false);
        assert!(!evidence.exists());
    }

    #[test]
    fn idf_segmented_execution_publishes_per_segment_evidence_when_capabilities_are_verified() {
        let directory = tempdir().unwrap();
        let firmware = directory.path().join("demo.elf");
        let evidence = directory.path().join("run.evidence.json");
        fs::write(&firmware, crate::firmware::tests::minimal_esp32c3_idf_elf()).unwrap();
        let mut replay = fixture();
        replay.target.name = "esp32c3".to_string();
        replay.target.architecture = "riscv".to_string();
        replay.target.core_count = 1;
        replay.capabilities.segmented_flash = true;
        replay.flash.base_address = Address(0);
        replay.flash.erase_ranges = vec![FlashRange {
            start: Address(0),
            length: 0x2_0000,
        }];
        let mut service = DebugService::new(ReplayBackend::new(replay));
        let options = FirmwareInputOptions {
            format: Some(FirmwareFormat::EspIdf),
            flash_size: Some(8 * 1024 * 1024),
            ..FirmwareInputOptions::default()
        };
        let plan = service
            .plan_flash_with_options(&firmware, None, None, &options)
            .unwrap();

        assert!(plan.execution.supported);
        let result = service
            .execute_flash_with_options(
                &firmware,
                None,
                None,
                &options,
                &plan.confirm_digest,
                &evidence,
            )
            .unwrap();

        assert!(result.flash.verified);
        assert_eq!(result.flash.segments.len(), 3);
        assert_eq!(result.flash.bytes_programmed, plan.firmware.program_size);
        assert!(result.flash.segments.iter().all(|segment| segment.verified));
        assert!(evidence.exists());
        let bundle = inspect_evidence(&evidence).unwrap();
        assert!(bundle.complete);
        assert_eq!(bundle.flash.as_ref().unwrap(), &result.flash);
        assert_eq!(result.post_flash_cores.len(), 1);
        assert_eq!(bundle.post_flash_cores, result.post_flash_cores);
        assert_eq!(bundle.core, result.snapshot);
    }

    #[test]
    fn idf_multi_core_execution_publishes_complete_post_flash_inventory() {
        let directory = tempdir().unwrap();
        let firmware = directory.path().join("demo.elf");
        let evidence = directory.path().join("run.evidence.json");
        fs::write(&firmware, crate::firmware::tests::minimal_esp32s3_idf_elf()).unwrap();
        let mut service = DebugService::new(ReplayBackend::new(esp32s3_post_flash_fixture()));
        let options = FirmwareInputOptions {
            format: Some(FirmwareFormat::EspIdf),
            flash_size: Some(8 * 1024 * 1024),
            ..FirmwareInputOptions::default()
        };
        let plan = service
            .plan_flash_with_options(&firmware, None, None, &options)
            .unwrap();

        assert!(plan.execution.supported);
        let result = service
            .execute_flash_with_options(
                &firmware,
                None,
                None,
                &options,
                &plan.confirm_digest,
                &evidence,
            )
            .unwrap();

        assert_eq!(result.post_flash_cores.len(), 2);
        assert!(result.post_flash_cores[0].available);
        assert!(result.post_flash_cores[1].available);
        assert_eq!(
            result.post_flash_cores[1].expected_final_state,
            Some(CoreState::Halted)
        );
        assert_eq!(
            result.post_flash_cores[1].snapshot.as_ref().unwrap().state,
            CoreState::Halted
        );
        assert_eq!(
            result.snapshot,
            result.post_flash_cores[0].snapshot.clone().unwrap()
        );
        let bundle = inspect_evidence(&evidence).unwrap();
        assert_eq!(bundle.post_flash_cores, result.post_flash_cores);
        assert_eq!(bundle.core, result.snapshot);
    }

    #[test]
    fn invalid_post_flash_restoration_does_not_publish_evidence() {
        let directory = tempdir().unwrap();
        let firmware = directory.path().join("demo.elf");
        let evidence = directory.path().join("run.evidence.json");
        fs::write(&firmware, crate::firmware::tests::minimal_esp32s3_idf_elf()).unwrap();
        let mut replay = esp32s3_post_flash_fixture();
        replay.post_flash_cores[0].snapshot.as_mut().unwrap().state = CoreState::Halted;
        let mut service = DebugService::new(ReplayBackend::new(replay));
        let options = FirmwareInputOptions {
            format: Some(FirmwareFormat::EspIdf),
            flash_size: Some(8 * 1024 * 1024),
            ..FirmwareInputOptions::default()
        };
        let plan = service
            .plan_flash_with_options(&firmware, None, None, &options)
            .unwrap();

        let error = service
            .execute_flash_with_options(
                &firmware,
                None,
                None,
                &options,
                &plan.confirm_digest,
                &evidence,
            )
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::ProtocolError);
        assert!(error.message.contains("post-flash core inventory"));
        assert!(!evidence.exists());
    }

    #[test]
    fn plan_rejects_incomplete_guarded_workflow_before_writing() {
        let directory = tempdir().unwrap();
        let firmware = directory.path().join("demo.bin");
        fs::write(&firmware, b"firmware").unwrap();
        let mut replay = fixture();
        replay.capabilities.verify = false;
        let service = DebugService::new(ReplayBackend::new(replay));

        let error = service.plan_flash(&firmware, None, None, None).unwrap_err();

        assert_eq!(error.code, ErrorCode::CapabilityUnavailable);
        assert_eq!(error.details["capability"], "verify");
    }

    #[test]
    fn relative_evidence_path_uses_current_directory() {
        assert_eq!(
            output_parent(Path::new("run.evidence.json")),
            Path::new(".")
        );
    }

    #[test]
    fn duplicate_probe_identity_is_rejected() {
        let first = fixture().probe;
        let mut second = first.clone();
        second.product = Some("second physical probe".to_string());

        let error = select_probe(&[first.clone(), second], Some(&first.id)).unwrap_err();

        assert_eq!(error.code, ErrorCode::ProbeAmbiguous);
    }

    #[test]
    fn failed_execution_does_not_leave_evidence_or_reservation() {
        let directory = tempdir().unwrap();
        let firmware = directory.path().join("demo.bin");
        let evidence = directory.path().join("run.evidence.json");
        fs::write(&firmware, b"replay demo firmware\n").unwrap();
        let mut replay = fixture();
        replay.flash.verify_success = false;
        let mut service = DebugService::new(ReplayBackend::new(replay));
        let plan = service.plan_flash(&firmware, None, None, None).unwrap();

        let error = service
            .execute_flash(&firmware, None, None, None, &plan.confirm_digest, &evidence)
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::VerificationFailed);
        assert!(!evidence.exists());
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn execution_requires_exact_confirmation_and_writes_evidence() {
        let directory = tempdir().unwrap();
        let firmware = directory.path().join("demo.bin");
        let evidence = directory.path().join("run.evidence.json");
        fs::write(&firmware, b"replay demo firmware\n").unwrap();
        let mut service = DebugService::new(ReplayBackend::new(fixture()));
        let plan = service.plan_flash(&firmware, None, None, None).unwrap();

        let rejected = service
            .execute_flash(&firmware, None, None, None, "wrong", &evidence)
            .unwrap_err();
        assert_eq!(rejected.code, ErrorCode::ConfirmationMismatch);
        assert!(!evidence.exists());

        let result = service
            .execute_flash(&firmware, None, None, None, &plan.confirm_digest, &evidence)
            .unwrap();
        assert!(result.flash.verified);
        assert_eq!(result.flash.segments.len(), 1);
        assert!(result.flash.segments[0].verified);
        assert_eq!(
            result.snapshot.captured_state,
            crate::model::CoreState::Halted
        );
        assert_eq!(result.snapshot.state, crate::model::CoreState::Running);
        assert!(evidence.exists());
        assert!(inspect_evidence(&evidence).unwrap().complete);
    }

    #[test]
    fn evidence_is_never_overwritten() {
        let directory = tempdir().unwrap();
        let firmware = directory.path().join("demo.bin");
        let evidence = directory.path().join("run.evidence.json");
        fs::write(&firmware, b"replay demo firmware\n").unwrap();
        fs::write(&evidence, b"keep me").unwrap();
        let mut service = DebugService::new(ReplayBackend::new(fixture()));
        let plan = service.plan_flash(&firmware, None, None, None).unwrap();

        let error = service
            .execute_flash(&firmware, None, None, None, &plan.confirm_digest, &evidence)
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::OutputExists);
        assert_eq!(fs::read(&evidence).unwrap(), b"keep me");
    }

    #[test]
    fn publish_race_preserves_complete_recovery_evidence() {
        let directory = tempdir().unwrap();
        let target = directory.path().join("run.evidence.json");
        let mut reservation = EvidenceReservation::new(&target).unwrap();
        fs::write(&target, b"other writer").unwrap();
        let mut fixture = fixture();
        let bundle = EvidenceBundle {
            schema_version: SCHEMA_VERSION.to_string(),
            capture_id: "cap_test".to_string(),
            captured_at: "2026-08-13T00:00:00.000Z".to_string(),
            backend: "replay".to_string(),
            probe: fixture.probe,
            target: fixture.target,
            firmware: FirmwareInfo {
                path: "firmware.bin".to_string(),
                format: "bin".to_string(),
                base_address: Some(fixture.flash.base_address),
                size: 1,
                sha256: "00".repeat(32),
                program_size: 1,
                segments: vec![FirmwareSegmentInfo {
                    kind: "application".to_string(),
                    start: fixture.flash.base_address,
                    length: 1,
                    sha256: "00".repeat(32),
                }],
                image_options: None,
            },
            plan_id: Some("plan_test".to_string()),
            confirm_digest: Some("11".repeat(32)),
            ranges: vec![FlashRange {
                start: fixture.flash.base_address,
                length: 1,
            }],
            erase_ranges: std::mem::take(&mut fixture.flash.erase_ranges),
            policy: Some(FlashPolicy::default()),
            flash: Some(crate::model::FlashReport {
                bytes_programmed: 1,
                firmware_sha256: "00".repeat(32),
                segments: Vec::new(),
                verified: true,
            }),
            core: fixture.after_reset_core,
            post_flash_cores: Vec::new(),
            operations: vec![operation(1, "session.disconnect")],
            complete: true,
        };

        let error = reservation.publish(&bundle).unwrap_err();
        let recovery = PathBuf::from(error.details["recovery_path"].as_str().unwrap());

        assert_eq!(error.code, ErrorCode::OutputExists);
        assert_eq!(fs::read(&target).unwrap(), b"other writer");
        assert!(inspect_evidence(&recovery).unwrap().complete);
        fs::remove_file(recovery).unwrap();
    }
}
