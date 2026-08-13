use std::{fs, path::Path};

use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::{
    SCHEMA_VERSION,
    backend::{DebugBackend, firmware_flash_report, validate_firmware_segments},
    error::{DebugError, ErrorCode, Result},
    firmware::FirmwareSegment,
    model::{
        Address, Capabilities, CoreObservation, CoreSnapshot, FirmwareSegmentInfo, FlashLayout,
        FlashRange, FlashReport, PostFlashCoreObservation, ProbeInfo, SessionInfo, TargetInfo,
        validate_core_inventory, validate_post_flash_core_inventory,
    },
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayFlashBehavior {
    pub base_address: Address,
    #[serde(default)]
    pub erase_ranges: Vec<FlashRange>,
    #[serde(default)]
    pub expected_firmware_sha256: Option<String>,
    #[serde(default = "default_true")]
    pub verify_success: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayFixture {
    pub schema_version: String,
    pub probe: ProbeInfo,
    pub target: TargetInfo,
    pub capabilities: Capabilities,
    pub initial_core: CoreSnapshot,
    pub after_reset_core: CoreSnapshot,
    #[serde(default)]
    pub live_cores: Vec<CoreObservation>,
    #[serde(default)]
    pub post_flash_cores: Vec<PostFlashCoreObservation>,
    pub flash: ReplayFlashBehavior,
}

impl Default for ReplayFlashBehavior {
    fn default() -> Self {
        Self {
            base_address: Address(0),
            erase_ranges: Vec::new(),
            expected_firmware_sha256: None,
            verify_success: true,
        }
    }
}

impl ReplayFixture {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = fs::read(path)
            .map_err(|error| DebugError::io("read replay fixture", path.to_str(), &error))?;
        let fixture: Self = serde_json::from_slice(&bytes).map_err(|error| {
            DebugError::fixture(
                "replay fixture is not valid JSON",
                json!({"path": path, "parser_message": error.to_string()}),
            )
        })?;
        fixture.validate()?;
        Ok(fixture)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(DebugError::fixture(
                "unsupported replay fixture schema version",
                json!({
                    "expected": SCHEMA_VERSION,
                    "received": self.schema_version,
                }),
            ));
        }
        if self.probe.id.trim().is_empty() {
            return Err(DebugError::fixture(
                "replay probe id must not be empty",
                json!({}),
            ));
        }
        if self.target.name.trim().is_empty() || self.target.core_count == 0 {
            return Err(DebugError::fixture(
                "replay target requires a name and at least one core",
                json!({"target": self.target}),
            ));
        }
        if let Some(expected) = &self.flash.expected_firmware_sha256
            && (expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            return Err(DebugError::fixture(
                "expected firmware SHA-256 must contain 64 hexadecimal characters",
                json!({"expected_firmware_sha256": expected}),
            ));
        }
        if self.capabilities.segmented_flash && !self.capabilities.flash {
            return Err(DebugError::fixture(
                "segmented flash capability requires base flash capability",
                json!({"capability": "segmented_flash"}),
            ));
        }
        if !self.live_cores.is_empty()
            && let Err(problem) = validate_core_inventory(&self.target, &self.live_cores)
        {
            return Err(DebugError::fixture(
                "replay live core inventory is invalid",
                json!({"problem": problem}),
            ));
        }
        if self.live_cores.is_empty()
            && self.target.core_count > 1
            && self.capabilities.halt
            && self.capabilities.run
            && self.capabilities.register_read
        {
            return Err(DebugError::fixture(
                "multi-core replay snapshot capability requires live_cores evidence",
                json!({"core_count": self.target.core_count}),
            ));
        }
        if !self.post_flash_cores.is_empty()
            && let Err(problem) =
                validate_post_flash_core_inventory(&self.target, &self.post_flash_cores)
        {
            return Err(DebugError::fixture(
                "replay post-flash core inventory is invalid",
                json!({"problem": problem}),
            ));
        }
        if self.capabilities.multi_core_post_flash {
            if self.target.core_count < 2 {
                return Err(DebugError::fixture(
                    "multi-core post-flash capability requires a multi-core target",
                    json!({"core_count": self.target.core_count}),
                ));
            }
            if self.post_flash_cores.is_empty() {
                return Err(DebugError::fixture(
                    "multi-core post-flash capability requires post_flash_cores evidence",
                    json!({"core_count": self.target.core_count}),
                ));
            }
            let required = [
                ("reset", self.capabilities.reset),
                ("halt", self.capabilities.halt),
                ("run", self.capabilities.run),
                ("register_read", self.capabilities.register_read),
            ];
            if let Some((capability, _)) = required.iter().find(|(_, enabled)| !enabled) {
                return Err(DebugError::fixture(
                    "multi-core post-flash capability requires reset, halt, run, and register access",
                    json!({"capability": capability}),
                ));
            }
        }
        Ok(())
    }
}

pub struct ReplayBackend {
    fixture: ReplayFixture,
    active_session_id: Option<String>,
    programmed: Option<(String, Vec<FirmwareSegmentInfo>)>,
    reset_performed: bool,
}

impl ReplayBackend {
    pub fn from_path(path: &Path) -> Result<Self> {
        Ok(Self::new(ReplayFixture::load(path)?))
    }

    pub fn new(fixture: ReplayFixture) -> Self {
        Self {
            fixture,
            active_session_id: None,
            programmed: None,
            reset_performed: false,
        }
    }

    fn ensure_session(&self, session: &SessionInfo) -> Result<()> {
        if self.active_session_id.as_deref() == Some(&session.session_id) {
            Ok(())
        } else {
            Err(DebugError::unavailable(
                ErrorCode::ProbeUnavailable,
                "replay session is not active",
                json!({"session_id": session.session_id}),
            ))
        }
    }
}

impl DebugBackend for ReplayBackend {
    fn name(&self) -> &'static str {
        "replay"
    }

    fn list_probes(&self) -> Result<Vec<ProbeInfo>> {
        Ok(vec![self.fixture.probe.clone()])
    }

    fn target(&self) -> &TargetInfo {
        &self.fixture.target
    }

    fn volatile_target_state_notes(&self) -> Vec<String> {
        Vec::new()
    }

    fn capabilities(&self) -> &Capabilities {
        &self.fixture.capabilities
    }

    fn plan_flash_ranges(
        &self,
        firmware_size: u64,
        requested_base_address: Option<Address>,
    ) -> Result<FlashLayout> {
        let base_address = requested_base_address.unwrap_or(self.fixture.flash.base_address);
        if base_address != self.fixture.flash.base_address {
            return Err(DebugError::fixture(
                "requested base address does not match replay evidence",
                json!({
                    "requested": base_address,
                    "available": self.fixture.flash.base_address,
                }),
            ));
        }
        self.fixture
            .flash
            .base_address
            .0
            .checked_add(firmware_size)
            .ok_or_else(|| {
                DebugError::fixture(
                    "flash range overflows the target address space",
                    json!({
                        "base_address": self.fixture.flash.base_address,
                        "firmware_size": firmware_size,
                    }),
                )
            })?;
        let range = FlashRange {
            start: base_address,
            length: firmware_size,
        };
        let erase_ranges = if self.fixture.flash.erase_ranges.is_empty() {
            vec![range.clone()]
        } else {
            self.fixture.flash.erase_ranges.clone()
        };
        if !ranges_cover(&erase_ranges, &range)? {
            return Err(DebugError::fixture(
                "replay erase ranges do not contain the planned write range",
                json!({"write_range": range, "erase_ranges": erase_ranges}),
            ));
        }
        Ok(FlashLayout {
            write_ranges: vec![range.clone()],
            erase_ranges,
        })
    }

    fn plan_segmented_flash_ranges(&self, write_ranges: &[FlashRange]) -> Result<FlashLayout> {
        if write_ranges.is_empty() {
            return Err(DebugError::fixture(
                "replay firmware image does not contain any write ranges",
                json!({}),
            ));
        }
        let mut sorted = write_ranges.to_vec();
        sorted.sort_by_key(|range| range.start.0);
        if sorted[0].start != self.fixture.flash.base_address {
            return Err(DebugError::fixture(
                "first segmented write address does not match replay evidence",
                json!({
                    "requested": sorted[0].start,
                    "available": self.fixture.flash.base_address,
                }),
            ));
        }

        let erase_ranges = if self.fixture.flash.erase_ranges.is_empty() {
            sorted.clone()
        } else {
            self.fixture.flash.erase_ranges.clone()
        };
        let mut previous_end = None;
        for range in &sorted {
            if range.length == 0 {
                return Err(DebugError::fixture(
                    "replay firmware image contains an empty write range",
                    json!({"range": range}),
                ));
            }
            let end = range.start.0.checked_add(range.length).ok_or_else(|| {
                DebugError::fixture(
                    "segmented flash range overflows the target address space",
                    json!({"range": range}),
                )
            })?;
            if previous_end.is_some_and(|previous| range.start.0 < previous) {
                return Err(DebugError::fixture(
                    "replay firmware image contains overlapping write ranges",
                    json!({"ranges": sorted}),
                ));
            }
            if !ranges_cover(&erase_ranges, range)? {
                return Err(DebugError::fixture(
                    "replay erase ranges do not contain a segmented write range",
                    json!({"write_range": range, "erase_ranges": erase_ranges}),
                ));
            }
            previous_end = Some(end);
        }

        Ok(FlashLayout {
            write_ranges: sorted,
            erase_ranges,
        })
    }

    fn attach(&mut self, probe_id: &str, target: &str) -> Result<SessionInfo> {
        if probe_id != self.fixture.probe.id {
            return Err(DebugError::unavailable(
                ErrorCode::ProbeUnavailable,
                "requested probe is absent from replay evidence",
                json!({"requested": probe_id, "available": self.fixture.probe.id}),
            ));
        }
        if !target.eq_ignore_ascii_case(&self.fixture.target.name) {
            return Err(DebugError::unavailable(
                ErrorCode::TargetUnavailable,
                "requested target is absent from replay evidence",
                json!({"requested": target, "available": self.fixture.target.name}),
            ));
        }
        let session_id = format!("ses_{}", Uuid::new_v4().simple());
        self.active_session_id = Some(session_id.clone());
        self.programmed = None;
        self.reset_performed = false;
        Ok(SessionInfo {
            session_id,
            backend: self.name().to_string(),
            probe: self.fixture.probe.clone(),
            target: self.fixture.target.clone(),
            capabilities: self.fixture.capabilities.clone(),
        })
    }

    fn program(
        &mut self,
        session: &SessionInfo,
        segments: &[FirmwareSegment],
        firmware_sha256: &str,
    ) -> Result<FlashReport> {
        self.ensure_session(session)?;
        validate_firmware_segments(segments)?;
        if segments.len() > 1 && !self.fixture.capabilities.segmented_flash {
            return Err(DebugError::new(
                ErrorCode::CapabilityUnavailable,
                "replay fixture does not advertise segmented flash capability",
                6,
                json!({"capability": "segmented_flash"}),
            ));
        }
        self.plan_segmented_flash_ranges(
            &segments
                .iter()
                .map(|segment| FlashRange {
                    start: segment.info.start,
                    length: segment.info.length,
                })
                .collect::<Vec<_>>(),
        )?;
        if segments[0].info.start != self.fixture.flash.base_address {
            return Err(DebugError::new(
                ErrorCode::PlanStale,
                "flash address changed after replay planning",
                2,
                json!({
                    "requested": segments[0].info.start,
                    "available": self.fixture.flash.base_address,
                }),
            ));
        }
        if !self.fixture.capabilities.flash {
            return Err(DebugError::new(
                ErrorCode::CapabilityUnavailable,
                "replay fixture does not advertise flash capability",
                6,
                json!({"capability": "flash"}),
            ));
        }
        if let Some(expected) = &self.fixture.flash.expected_firmware_sha256
            && !expected.eq_ignore_ascii_case(firmware_sha256)
        {
            return Err(DebugError::new(
                ErrorCode::PlanStale,
                "firmware does not match the replay fixture expectation",
                3,
                json!({"expected": expected, "received": firmware_sha256}),
            ));
        }
        self.programmed = Some((
            firmware_sha256.to_string(),
            segments
                .iter()
                .map(|segment| segment.info.clone())
                .collect(),
        ));
        firmware_flash_report(segments, firmware_sha256, false)
    }

    fn verify(
        &mut self,
        session: &SessionInfo,
        segments: &[FirmwareSegment],
        firmware_sha256: &str,
    ) -> Result<FlashReport> {
        self.ensure_session(session)?;
        validate_firmware_segments(segments)?;
        let (programmed_sha256, programmed_segments) =
            self.programmed.as_ref().ok_or_else(|| {
                DebugError::new(
                    ErrorCode::ProtocolError,
                    "cannot verify before firmware has been programmed",
                    6,
                    json!({"session_id": session.session_id}),
                )
            })?;
        if programmed_sha256 != firmware_sha256 {
            return Err(DebugError::new(
                ErrorCode::PlanStale,
                "verification digest differs from the programmed firmware",
                2,
                json!({
                    "programmed": programmed_sha256,
                    "received": firmware_sha256,
                }),
            ));
        }
        if !programmed_segments
            .iter()
            .eq(segments.iter().map(|segment| &segment.info))
        {
            return Err(DebugError::new(
                ErrorCode::PlanStale,
                "verification segments differ from the programmed firmware manifest",
                2,
                json!({
                    "programmed_segments": programmed_segments,
                    "received_segments": segments.iter().map(|segment| &segment.info).collect::<Vec<_>>(),
                }),
            ));
        }
        let verified = self.fixture.capabilities.verify
            && self.fixture.flash.verify_success
            && programmed_sha256 == firmware_sha256;
        firmware_flash_report(segments, firmware_sha256, verified)
    }

    fn reset(&mut self, session: &SessionInfo) -> Result<()> {
        self.ensure_session(session)?;
        if !self.fixture.capabilities.reset {
            return Err(DebugError::new(
                ErrorCode::CapabilityUnavailable,
                "replay fixture does not advertise reset capability",
                6,
                json!({"capability": "reset"}),
            ));
        }
        self.reset_performed = true;
        Ok(())
    }

    fn snapshot(&mut self, session: &SessionInfo) -> Result<CoreSnapshot> {
        self.ensure_session(session)?;
        Ok(if self.reset_performed {
            self.fixture.after_reset_core.clone()
        } else {
            self.fixture.initial_core.clone()
        })
    }

    fn capture_post_flash_snapshot(
        &mut self,
        session: &SessionInfo,
    ) -> Result<Vec<PostFlashCoreObservation>> {
        self.ensure_session(session)?;
        if !self.reset_performed {
            return Err(DebugError::new(
                ErrorCode::ProtocolError,
                "post-flash snapshot requires a successful reset",
                6,
                json!({"session_id": session.session_id}),
            ));
        }
        if self.fixture.target.core_count > 1 && !self.fixture.capabilities.multi_core_post_flash {
            return Err(DebugError::new(
                ErrorCode::CapabilityUnavailable,
                "replay fixture does not advertise multi-core post-flash capability",
                6,
                json!({"capability": "multi_core_post_flash"}),
            ));
        }
        if !self.fixture.post_flash_cores.is_empty() {
            return Ok(self.fixture.post_flash_cores.clone());
        }
        if self.fixture.target.core_count != 1 {
            return Err(DebugError::fixture(
                "multi-core replay post-flash snapshots require explicit evidence",
                json!({"core_count": self.fixture.target.core_count}),
            ));
        }
        Ok(vec![PostFlashCoreObservation {
            index: 0,
            name: "core0".to_string(),
            architecture: self.fixture.target.architecture.clone(),
            available: true,
            snapshot: Some(self.fixture.after_reset_core.clone()),
            unavailable_reason: None,
        }])
    }

    fn capture_live_snapshot(&mut self, session: &SessionInfo) -> Result<Vec<CoreObservation>> {
        self.ensure_session(session)?;
        if !self.fixture.capabilities.halt
            || !self.fixture.capabilities.run
            || !self.fixture.capabilities.register_read
        {
            return Err(DebugError::new(
                ErrorCode::CapabilityUnavailable,
                "replay fixture cannot capture a state-preserving core snapshot",
                6,
                json!({"required": ["halt", "run", "register_read"]}),
            ));
        }
        if !self.fixture.live_cores.is_empty() {
            return Ok(self.fixture.live_cores.clone());
        }
        if self.fixture.target.core_count != 1 {
            return Err(DebugError::fixture(
                "multi-core replay snapshots require explicit live_cores evidence",
                json!({"core_count": self.fixture.target.core_count}),
            ));
        }
        let original_state = self.fixture.initial_core.state;
        let mut snapshot = self.fixture.initial_core.clone();
        snapshot.captured_state = crate::model::CoreState::Halted;
        snapshot.state = original_state;
        if original_state == crate::model::CoreState::Running {
            snapshot.halt_reason = Some("request".to_string());
        }
        Ok(vec![CoreObservation {
            index: 0,
            name: "core0".to_string(),
            architecture: self.fixture.target.architecture.clone(),
            available: true,
            original_state: Some(original_state),
            snapshot: Some(snapshot),
            unavailable_reason: None,
        }])
    }

    fn disconnect(&mut self, session: &SessionInfo) -> Result<()> {
        self.ensure_session(session)?;
        self.active_session_id = None;
        self.programmed = None;
        self.reset_performed = false;
        Ok(())
    }
}

fn ranges_cover(ranges: &[FlashRange], required: &FlashRange) -> Result<bool> {
    let required_end = required
        .start
        .0
        .checked_add(required.length)
        .ok_or_else(|| {
            DebugError::fixture(
                "replay write range overflows the address space",
                json!({"write_range": required}),
            )
        })?;
    let mut spans = ranges
        .iter()
        .map(|range| {
            range
                .start
                .0
                .checked_add(range.length)
                .map(|end| (range.start.0, end))
                .ok_or_else(|| {
                    DebugError::fixture(
                        "replay erase range overflows the address space",
                        json!({"erase_range": range}),
                    )
                })
        })
        .collect::<Result<Vec<_>>>()?;
    spans.sort_unstable_by_key(|(start, _)| *start);

    let mut cursor = required.start.0;
    for (start, end) in spans {
        if end <= cursor {
            continue;
        }
        if start > cursor {
            return Ok(false);
        }
        cursor = cursor.max(end);
        if cursor >= required_end {
            return Ok(true);
        }
    }
    Ok(cursor >= required_end)
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::model::FirmwareSegmentInfo;

    fn fixture() -> ReplayFixture {
        serde_json::from_str(include_str!("../../examples/replay/stm32g4.json")).unwrap()
    }

    fn segment(kind: &str, start: u64, data: &[u8]) -> FirmwareSegment {
        FirmwareSegment {
            info: FirmwareSegmentInfo {
                kind: kind.to_string(),
                start: Address(start),
                length: data.len() as u64,
                sha256: hex::encode(Sha256::digest(data)),
            },
            data: data.to_vec(),
        }
    }

    #[test]
    fn adjacent_erase_ranges_cover_a_cross_sector_write() {
        let erase_ranges = [
            FlashRange {
                start: Address(0x0800_0000),
                length: 0x800,
            },
            FlashRange {
                start: Address(0x0800_0800),
                length: 0x800,
            },
        ];
        let write_range = FlashRange {
            start: Address(0x0800_0700),
            length: 0x200,
        };

        assert!(ranges_cover(&erase_ranges, &write_range).unwrap());
    }

    #[test]
    fn a_gap_in_erase_ranges_does_not_cover_a_write() {
        let erase_ranges = [
            FlashRange {
                start: Address(0x0800_0000),
                length: 0x800,
            },
            FlashRange {
                start: Address(0x0800_0900),
                length: 0x700,
            },
        ];
        let write_range = FlashRange {
            start: Address(0x0800_0700),
            length: 0x300,
        };

        assert!(!ranges_cover(&erase_ranges, &write_range).unwrap());
    }

    #[test]
    fn segmented_program_and_verify_report_every_segment() {
        let mut fixture = fixture();
        fixture.capabilities.segmented_flash = true;
        let probe_id = fixture.probe.id.clone();
        let target = fixture.target.name.clone();
        let base = fixture.flash.base_address.0;
        let mut backend = ReplayBackend::new(fixture);
        let session = backend.attach(&probe_id, &target).unwrap();
        let segments = [
            segment("bootloader", base, b"boot"),
            segment("application", base + 0x400, b"application"),
        ];

        let staged = backend
            .program(&session, &segments, &"11".repeat(32))
            .unwrap();
        assert_eq!(staged.bytes_programmed, 15);
        assert_eq!(staged.segments.len(), 2);
        assert!(!staged.verified);
        assert!(staged.segments.iter().all(|segment| !segment.verified));

        let verified = backend
            .verify(&session, &segments, &"11".repeat(32))
            .unwrap();
        assert!(verified.verified);
        assert!(verified.segments.iter().all(|segment| segment.verified));
    }

    #[test]
    fn segmented_program_requires_an_explicit_capability() {
        let mut fixture = fixture();
        fixture.capabilities.segmented_flash = false;
        let probe_id = fixture.probe.id.clone();
        let target = fixture.target.name.clone();
        let base = fixture.flash.base_address.0;
        let mut backend = ReplayBackend::new(fixture);
        let session = backend.attach(&probe_id, &target).unwrap();
        let segments = [
            segment("bootloader", base, b"boot"),
            segment("application", base + 0x400, b"application"),
        ];

        let error = backend
            .program(&session, &segments, &"11".repeat(32))
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::CapabilityUnavailable);
        assert_eq!(error.details["capability"], "segmented_flash");
    }

    #[test]
    fn segmented_capability_requires_base_flash_capability() {
        let mut fixture = fixture();
        fixture.capabilities.flash = false;
        fixture.capabilities.segmented_flash = true;

        let error = fixture.validate().unwrap_err();

        assert_eq!(error.code, ErrorCode::FixtureInvalid);
        assert_eq!(error.details["capability"], "segmented_flash");
    }

    #[test]
    fn multi_core_post_flash_capability_requires_restoration_capabilities() {
        let mut fixture = fixture();
        fixture.target.core_count = 2;
        fixture.capabilities.multi_core_post_flash = true;
        fixture.capabilities.run = false;
        fixture.live_cores = vec![
            CoreObservation {
                index: 0,
                name: "cpu0".to_string(),
                architecture: "test".to_string(),
                available: true,
                original_state: Some(crate::model::CoreState::Running),
                snapshot: Some(fixture.after_reset_core.clone()),
                unavailable_reason: None,
            },
            CoreObservation {
                index: 1,
                name: "cpu1".to_string(),
                architecture: "test".to_string(),
                available: false,
                original_state: None,
                snapshot: None,
                unavailable_reason: Some("disabled".to_string()),
            },
        ];
        fixture.post_flash_cores = vec![
            PostFlashCoreObservation {
                index: 0,
                name: "cpu0".to_string(),
                architecture: "test".to_string(),
                available: true,
                snapshot: Some(fixture.after_reset_core.clone()),
                unavailable_reason: None,
            },
            PostFlashCoreObservation {
                index: 1,
                name: "cpu1".to_string(),
                architecture: "test".to_string(),
                available: false,
                snapshot: None,
                unavailable_reason: Some("disabled".to_string()),
            },
        ];

        let error = fixture.validate().unwrap_err();

        assert_eq!(error.code, ErrorCode::FixtureInvalid);
        assert_eq!(error.details["capability"], "run");
    }

    #[test]
    fn verification_rejects_a_manifest_changed_after_programming() {
        let mut fixture = fixture();
        fixture.capabilities.segmented_flash = true;
        let probe_id = fixture.probe.id.clone();
        let target = fixture.target.name.clone();
        let base = fixture.flash.base_address.0;
        let mut backend = ReplayBackend::new(fixture);
        let session = backend.attach(&probe_id, &target).unwrap();
        let segments = [
            segment("bootloader", base, b"boot"),
            segment("application", base + 0x400, b"application"),
        ];
        backend
            .program(&session, &segments, &"11".repeat(32))
            .unwrap();
        let changed = [
            segment("bootloader", base, b"boot"),
            segment("application", base + 0x500, b"application"),
        ];

        let error = backend
            .verify(&session, &changed, &"11".repeat(32))
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::PlanStale);
        assert!(error.message.contains("manifest"));
    }
}
