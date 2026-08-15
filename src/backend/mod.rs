pub mod probe_rs;
pub mod replay;

use sha2::Digest;

use crate::{
    error::{DebugError, ErrorCode, Result},
    firmware::FirmwareSegment,
    model::{
        Address, Capabilities, CoreExecutionAction, CoreExecutionObservation, CoreObservation,
        CoreSnapshot, FirmwareImageOptions, FlashLayout, FlashReport, FlashSegmentReport,
        HardwareBreakpointAction, HardwareBreakpointObservation, MAX_INLINE_MEMORY_READ_BYTES,
        MemoryReadRange, MemoryReadResult, PostFlashCoreObservation, ProbeInfo,
        RegisterCoreObservation, SessionInfo, TargetInfo,
    },
};

pub trait DebugBackend {
    fn name(&self) -> &'static str;
    fn list_probes(&self) -> Result<Vec<ProbeInfo>>;
    fn target(&self) -> &TargetInfo;
    fn matches_target(&self, requested: &str) -> bool {
        requested.eq_ignore_ascii_case(&self.target().name)
    }
    fn probe_identity_is_stable(&self, _probe: &ProbeInfo) -> bool {
        true
    }
    fn volatile_target_state_notes(&self) -> Vec<String>;
    fn capabilities(&self) -> &Capabilities;
    fn plan_flash_ranges(
        &self,
        firmware_size: u64,
        requested_base_address: Option<Address>,
    ) -> Result<FlashLayout>;
    fn validate_firmware_image_options(&self, _options: &FirmwareImageOptions) -> Result<()> {
        Ok(())
    }
    fn plan_segmented_flash_ranges(
        &self,
        write_ranges: &[crate::model::FlashRange],
    ) -> Result<FlashLayout> {
        let [range] = write_ranges else {
            return Err(crate::error::DebugError::new(
                crate::error::ErrorCode::CapabilityUnavailable,
                "selected backend cannot plan a segmented firmware image",
                6,
                serde_json::json!({
                    "backend": self.name(),
                    "segment_count": write_ranges.len(),
                }),
            ));
        };
        self.plan_flash_ranges(range.length, Some(range.start))
    }
    fn attach(&mut self, probe_id: &str, target: &str) -> Result<SessionInfo>;
    fn program(
        &mut self,
        session: &SessionInfo,
        segments: &[FirmwareSegment],
        firmware_sha256: &str,
    ) -> Result<FlashReport>;
    fn verify(
        &mut self,
        session: &SessionInfo,
        segments: &[FirmwareSegment],
        firmware_sha256: &str,
    ) -> Result<FlashReport>;
    fn reset(&mut self, session: &SessionInfo) -> Result<()>;
    fn snapshot(&mut self, session: &SessionInfo) -> Result<CoreSnapshot>;
    fn capture_post_flash_snapshot(
        &mut self,
        session: &SessionInfo,
    ) -> Result<Vec<PostFlashCoreObservation>>;
    fn capture_live_snapshot(&mut self, session: &SessionInfo) -> Result<Vec<CoreObservation>>;
    /// Observe or change execution state while `session` remains active.
    ///
    /// Callers that disconnect immediately must separately require an explicit
    /// post-disconnect state guarantee from the backend capability matrix.
    fn control_core_in_session(
        &mut self,
        session: &SessionInfo,
        core_index: u32,
        action: CoreExecutionAction,
    ) -> Result<CoreExecutionObservation>;
    /// Inspect or mutate hardware breakpoint comparators while `session` remains active.
    ///
    /// User-requested mutations must be rejected unless the selected core is already halted.
    fn control_hardware_breakpoints_in_session(
        &mut self,
        session: &SessionInfo,
        core_index: u32,
        action: HardwareBreakpointAction,
        address: Option<Address>,
        slot: Option<u32>,
    ) -> Result<HardwareBreakpointObservation>;
    fn read_registers(
        &mut self,
        session: &SessionInfo,
        core_index: u32,
        names: &[String],
    ) -> Result<RegisterCoreObservation>;
    fn plan_memory_read(
        &self,
        core_index: u32,
        start: Address,
        length: u64,
    ) -> Result<MemoryReadRange>;
    fn read_memory(
        &mut self,
        session: &SessionInfo,
        core_index: u32,
        range: &MemoryReadRange,
    ) -> Result<MemoryReadResult>;
    fn disconnect(&mut self, session: &SessionInfo) -> Result<()>;
}

pub(crate) fn checked_memory_read_end(start: Address, length: u64) -> Result<u64> {
    if length == 0 {
        return Err(DebugError::config(
            "memory read length must be greater than zero",
            serde_json::json!({"start": start, "length": length}),
        ));
    }
    if length > MAX_INLINE_MEMORY_READ_BYTES {
        return Err(DebugError::config(
            "memory read exceeds the bounded inline result limit",
            serde_json::json!({
                "start": start,
                "length": length,
                "maximum": MAX_INLINE_MEMORY_READ_BYTES,
            }),
        ));
    }
    start.0.checked_add(length).ok_or_else(|| {
        DebugError::config(
            "memory read range overflows the target address space",
            serde_json::json!({"start": start, "length": length}),
        )
    })
}

pub(crate) fn validate_hardware_breakpoint_request(
    action: HardwareBreakpointAction,
    address: Option<Address>,
    slot: Option<u32>,
    capacity: u32,
) -> Result<()> {
    let valid = match action {
        HardwareBreakpointAction::List | HardwareBreakpointAction::ClearAll => {
            address.is_none() && slot.is_none()
        }
        HardwareBreakpointAction::Set => address.is_some(),
        HardwareBreakpointAction::Clear => address.is_none() && slot.is_some(),
    };
    if !valid {
        return Err(DebugError::config(
            "hardware breakpoint request fields do not match the selected action",
            serde_json::json!({"action": action, "address": address, "slot": slot}),
        ));
    }
    if capacity == 0 {
        return Err(DebugError::new(
            ErrorCode::CapabilityUnavailable,
            "selected backend does not expose any hardware breakpoint comparators",
            6,
            serde_json::json!({"capability": "hardware_breakpoints"}),
        ));
    }
    if slot.is_some_and(|slot| slot >= capacity) {
        return Err(DebugError::config(
            "hardware breakpoint slot is outside the available comparator range",
            serde_json::json!({"slot": slot, "capacity": capacity}),
        ));
    }
    Ok(())
}

pub(crate) fn validate_firmware_segments(segments: &[FirmwareSegment]) -> Result<u64> {
    if segments.is_empty() {
        return Err(DebugError::new(
            ErrorCode::PlanStale,
            "firmware image contains no payload segments",
            2,
            serde_json::json!({}),
        ));
    }

    let mut previous_end = None;
    let mut program_size = 0_u64;
    for segment in segments {
        if segment.data.is_empty() || segment.info.length != segment.data.len() as u64 {
            return Err(DebugError::new(
                ErrorCode::PlanStale,
                "firmware segment length does not match its payload",
                2,
                serde_json::json!({
                    "segment": segment.info,
                    "payload_length": segment.data.len(),
                }),
            ));
        }
        let actual_sha256 = hex::encode(sha2::Sha256::digest(&segment.data));
        if actual_sha256 != segment.info.sha256 {
            return Err(DebugError::new(
                ErrorCode::PlanStale,
                "firmware segment payload does not match its planned SHA-256",
                2,
                serde_json::json!({
                    "segment": segment.info,
                    "actual_sha256": actual_sha256,
                }),
            ));
        }
        let end = segment
            .info
            .start
            .0
            .checked_add(segment.info.length)
            .ok_or_else(|| {
                DebugError::new(
                    ErrorCode::PlanStale,
                    "firmware segment overflows the target address space",
                    2,
                    serde_json::json!({"segment": segment.info}),
                )
            })?;
        if previous_end.is_some_and(|previous| segment.info.start.0 < previous) {
            return Err(DebugError::new(
                ErrorCode::PlanStale,
                "firmware payload segments are not ordered or overlap",
                2,
                serde_json::json!({"segment": segment.info}),
            ));
        }
        previous_end = Some(end);
        program_size = program_size
            .checked_add(segment.info.length)
            .ok_or_else(|| {
                DebugError::new(
                    ErrorCode::PlanStale,
                    "firmware program size overflowed",
                    2,
                    serde_json::json!({}),
                )
            })?;
    }
    Ok(program_size)
}

pub(crate) fn firmware_flash_report(
    segments: &[FirmwareSegment],
    firmware_sha256: &str,
    verified: bool,
) -> Result<FlashReport> {
    let bytes_programmed = validate_firmware_segments(segments)?;
    Ok(FlashReport {
        bytes_programmed,
        firmware_sha256: firmware_sha256.to_string(),
        segments: segments
            .iter()
            .map(|segment| FlashSegmentReport {
                kind: segment.info.kind.clone(),
                start: segment.info.start,
                length: segment.info.length,
                sha256: segment.info.sha256.clone(),
                verified,
            })
            .collect(),
        verified,
    })
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::model::FirmwareSegmentInfo;

    fn segment(start: u64, data: &[u8]) -> FirmwareSegment {
        FirmwareSegment {
            info: FirmwareSegmentInfo {
                kind: "application".to_string(),
                start: Address(start),
                length: data.len() as u64,
                sha256: hex::encode(Sha256::digest(data)),
            },
            data: data.to_vec(),
        }
    }

    #[test]
    fn segment_validation_sums_ordered_payloads() {
        let segments = [segment(0x1000, b"first"), segment(0x2000, b"second")];

        assert_eq!(validate_firmware_segments(&segments).unwrap(), 11);
    }

    #[test]
    fn segment_validation_rejects_changed_payloads() {
        let mut segments = [segment(0x1000, b"planned")];
        segments[0].data[0] ^= 0xff;

        let error = validate_firmware_segments(&segments).unwrap_err();

        assert_eq!(error.code, ErrorCode::PlanStale);
        assert!(error.message.contains("SHA-256"));
    }

    #[test]
    fn segment_validation_rejects_overlaps() {
        let segments = [segment(0x1000, b"first"), segment(0x1004, b"second")];

        let error = validate_firmware_segments(&segments).unwrap_err();

        assert_eq!(error.code, ErrorCode::PlanStale);
        assert!(error.message.contains("overlap"));
    }
}
