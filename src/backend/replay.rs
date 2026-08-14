use std::{fs, path::Path};

use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::{
    SCHEMA_VERSION,
    backend::{
        DebugBackend, checked_memory_read_end, firmware_flash_report, validate_firmware_segments,
    },
    error::{DebugError, ErrorCode, Result},
    firmware::FirmwareSegment,
    model::{
        Address, Capabilities, CoreExecutionAction, CoreExecutionObservation, CoreObservation,
        CoreSnapshot, CoreState, FirmwareSegmentInfo, FlashLayout, FlashRange, FlashReport,
        MAX_INLINE_MEMORY_READ_BYTES, MAX_REGISTER_READS, MemoryCoreObservation, MemoryReadRange,
        MemoryReadResult, MemoryRegionInfo, MemoryRegionKind, PostFlashCoreObservation, ProbeInfo,
        RegisterCoreObservation, RegisterReading, SessionInfo, TargetInfo,
        validate_core_execution_observation, validate_core_inventory,
        validate_memory_core_observation, validate_memory_read_range,
        validate_post_flash_core_inventory, validate_register_core_observation,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayMemoryBlock {
    pub core_index: u32,
    pub name: Option<String>,
    pub kind: MemoryRegionKind,
    pub start: Address,
    pub data: String,
    #[serde(default)]
    pub is_alias: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayCoreState {
    pub index: u32,
    pub name: String,
    pub architecture: String,
    pub state: CoreState,
    pub halt_reason: Option<String>,
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
    #[serde(default)]
    pub register_cores: Vec<RegisterCoreObservation>,
    #[serde(default)]
    pub memory_cores: Vec<MemoryCoreObservation>,
    #[serde(default)]
    pub memory_blocks: Vec<ReplayMemoryBlock>,
    #[serde(default)]
    pub control_cores: Vec<ReplayCoreState>,
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
        let mut register_core_indexes = std::collections::BTreeSet::new();
        for core in &self.register_cores {
            if !register_core_indexes.insert(core.index) {
                return Err(DebugError::fixture(
                    "replay register evidence contains a duplicate core index",
                    json!({"core_index": core.index}),
                ));
            }
            if let Err(problem) = validate_register_core_observation(&self.target, core) {
                return Err(DebugError::fixture(
                    "replay register evidence is invalid",
                    json!({"core_index": core.index, "problem": problem}),
                ));
            }
        }
        let mut control_core_indexes = std::collections::BTreeSet::new();
        for core in &self.control_cores {
            if !control_core_indexes.insert(core.index) {
                return Err(DebugError::fixture(
                    "replay execution-control evidence contains a duplicate core index",
                    json!({"core_index": core.index}),
                ));
            }
            let observation = CoreExecutionObservation {
                index: core.index,
                name: core.name.clone(),
                architecture: core.architecture.clone(),
                action: CoreExecutionAction::Status,
                original_state: core.state,
                state: core.state,
                state_changed: false,
                halt_reason: core.halt_reason.clone(),
            };
            if let Err(problem) = validate_core_execution_observation(&self.target, &observation) {
                return Err(DebugError::fixture(
                    "replay execution-control evidence is invalid",
                    json!({"core_index": core.index, "problem": problem}),
                ));
            }
        }
        if self.capabilities.core_status && self.control_cores.is_empty() {
            return Err(DebugError::fixture(
                "core status capability requires explicit execution-control evidence",
                json!({"control_core_count": 0}),
            ));
        }
        if self.capabilities.post_disconnect_core_state && !self.capabilities.core_status {
            return Err(DebugError::fixture(
                "post-disconnect core-state guarantees require core status support",
                json!({"capability": "core_status"}),
            ));
        }
        let mut memory_core_indexes = std::collections::BTreeSet::new();
        for core in &self.memory_cores {
            if !memory_core_indexes.insert(core.index) {
                return Err(DebugError::fixture(
                    "replay memory evidence contains a duplicate core index",
                    json!({"core_index": core.index}),
                ));
            }
            if let Err(problem) = validate_memory_core_observation(&self.target, core) {
                return Err(DebugError::fixture(
                    "replay memory core evidence is invalid",
                    json!({"core_index": core.index, "problem": problem}),
                ));
            }
        }
        let mut memory_spans = Vec::with_capacity(self.memory_blocks.len());
        for block in &self.memory_blocks {
            if block.core_index >= self.target.core_count {
                return Err(DebugError::fixture(
                    "replay memory block core is outside the target inventory",
                    json!({
                        "core_index": block.core_index,
                        "core_count": self.target.core_count,
                    }),
                ));
            }
            if !memory_core_indexes.contains(&block.core_index) {
                return Err(DebugError::fixture(
                    "replay memory block has no matching core state evidence",
                    json!({"core_index": block.core_index, "start": block.start}),
                ));
            }
            let bytes = decode_memory_block(block)?;
            let length = bytes.len() as u64;
            let end = block.start.0.checked_add(length).ok_or_else(|| {
                DebugError::fixture(
                    "replay memory block overflows the target address space",
                    json!({"core_index": block.core_index, "start": block.start, "length": length}),
                )
            })?;
            memory_spans.push((block.core_index, block.start.0, end));
        }
        memory_spans.sort_unstable();
        for pair in memory_spans.windows(2) {
            let (left_core, _, left_end) = pair[0];
            let (right_core, right_start, _) = pair[1];
            if left_core == right_core && right_start < left_end {
                return Err(DebugError::fixture(
                    "replay memory blocks overlap on the same core",
                    json!({"core_index": left_core, "overlap_start": Address(right_start)}),
                ));
            }
        }
        if self.capabilities.memory_read {
            let required = [
                ("halt", self.capabilities.halt),
                ("run", self.capabilities.run),
            ];
            if let Some((capability, _)) = required.iter().find(|(_, enabled)| !enabled) {
                return Err(DebugError::fixture(
                    "memory read capability requires halt and run support",
                    json!({"capability": capability}),
                ));
            }
            if self.memory_cores.is_empty() || self.memory_blocks.is_empty() {
                return Err(DebugError::fixture(
                    "memory read capability requires explicit core state and byte evidence",
                    json!({
                        "memory_core_count": self.memory_cores.len(),
                        "memory_block_count": self.memory_blocks.len(),
                    }),
                ));
            }
        }
        Ok(())
    }
}

pub struct ReplayBackend {
    fixture: ReplayFixture,
    control_cores: Vec<ReplayCoreState>,
    active_session_id: Option<String>,
    programmed: Option<(String, Vec<FirmwareSegmentInfo>)>,
    reset_performed: bool,
}

impl ReplayBackend {
    pub fn from_path(path: &Path) -> Result<Self> {
        Ok(Self::new(ReplayFixture::load(path)?))
    }

    pub fn new(fixture: ReplayFixture) -> Self {
        let control_cores = fixture.control_cores.clone();
        Self {
            fixture,
            control_cores,
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
        let mut snapshot = if self.reset_performed {
            self.fixture.after_reset_core.clone()
        } else {
            self.fixture.initial_core.clone()
        };
        if let Some(control) = self.control_cores.iter().find(|control| control.index == 0) {
            snapshot.captured_state = CoreState::Halted;
            snapshot.state = control.state;
            snapshot.halt_reason = if control.state == CoreState::Running {
                Some("request".to_string())
            } else {
                control.halt_reason.clone()
            };
        }
        Ok(snapshot)
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
        let observations = if !self.fixture.post_flash_cores.is_empty() {
            self.fixture.post_flash_cores.clone()
        } else {
            if self.fixture.target.core_count != 1 {
                return Err(DebugError::fixture(
                    "multi-core replay post-flash snapshots require explicit evidence",
                    json!({"core_count": self.fixture.target.core_count}),
                ));
            }
            vec![PostFlashCoreObservation {
                index: 0,
                name: "core0".to_string(),
                architecture: self.fixture.target.architecture.clone(),
                available: true,
                expected_final_state: Some(CoreState::Running),
                snapshot: Some(self.fixture.after_reset_core.clone()),
                unavailable_reason: None,
            }]
        };
        for observation in observations.iter().filter(|core| core.available) {
            let Some(control) = self
                .control_cores
                .iter_mut()
                .find(|control| control.index == observation.index)
            else {
                continue;
            };
            let snapshot = observation
                .snapshot
                .as_ref()
                .expect("available replay post-flash cores contain snapshots");
            control.state = snapshot.state;
            control.halt_reason = if snapshot.state == CoreState::Halted {
                snapshot.halt_reason.clone()
            } else {
                None
            };
        }
        Ok(observations)
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
        let mut observations = if !self.fixture.live_cores.is_empty() {
            self.fixture.live_cores.clone()
        } else {
            if self.fixture.target.core_count != 1 {
                return Err(DebugError::fixture(
                    "multi-core replay snapshots require explicit live_cores evidence",
                    json!({"core_count": self.fixture.target.core_count}),
                ));
            }
            vec![CoreObservation {
                index: 0,
                name: "core0".to_string(),
                architecture: self.fixture.target.architecture.clone(),
                available: true,
                original_state: Some(self.fixture.initial_core.state),
                snapshot: Some(self.fixture.initial_core.clone()),
                unavailable_reason: None,
            }]
        };
        for observation in observations.iter_mut().filter(|core| core.available) {
            let Some(control) = self
                .control_cores
                .iter()
                .find(|control| control.index == observation.index)
            else {
                continue;
            };
            observation.original_state = Some(control.state);
            let snapshot = observation
                .snapshot
                .as_mut()
                .expect("available replay cores contain snapshots");
            snapshot.captured_state = CoreState::Halted;
            snapshot.state = control.state;
            snapshot.halt_reason = if control.state == CoreState::Running {
                Some("request".to_string())
            } else {
                control.halt_reason.clone()
            };
        }
        Ok(observations)
    }

    fn control_core(
        &mut self,
        session: &SessionInfo,
        core_index: u32,
        action: CoreExecutionAction,
    ) -> Result<CoreExecutionObservation> {
        self.ensure_session(session)?;
        let capability = match action {
            CoreExecutionAction::Status if !self.fixture.capabilities.core_status => {
                Some("core_status")
            }
            CoreExecutionAction::Halt if !self.fixture.capabilities.halt => Some("halt"),
            CoreExecutionAction::Run if !self.fixture.capabilities.run => Some("run"),
            _ if !self.fixture.capabilities.post_disconnect_core_state => {
                Some("post_disconnect_core_state")
            }
            _ if !self.fixture.capabilities.core_status => Some("core_status"),
            _ => None,
        };
        if let Some(capability) = capability {
            return Err(DebugError::new(
                ErrorCode::CapabilityUnavailable,
                "replay fixture cannot perform the requested core control action",
                6,
                json!({"action": action, "capability": capability}),
            ));
        }
        let position = self
            .control_cores
            .iter()
            .position(|core| core.index == core_index)
            .ok_or_else(|| {
                DebugError::fixture(
                    "replay fixture has no explicit execution-control evidence for the requested core",
                    json!({"core_index": core_index}),
                )
            })?;
        let core = &self.control_cores[position];
        let original_state = core.state;
        let (state, halt_reason) = match action {
            CoreExecutionAction::Status => (core.state, core.halt_reason.clone()),
            CoreExecutionAction::Halt => (
                CoreState::Halted,
                if original_state == CoreState::Running {
                    Some("request".to_string())
                } else {
                    core.halt_reason.clone()
                },
            ),
            CoreExecutionAction::Run => (CoreState::Running, None),
        };
        let observation = CoreExecutionObservation {
            index: core.index,
            name: core.name.clone(),
            architecture: core.architecture.clone(),
            action,
            original_state,
            state,
            state_changed: original_state != state,
            halt_reason: halt_reason.clone(),
        };
        validate_core_execution_observation(&self.fixture.target, &observation).map_err(
            |problem| {
                DebugError::fixture(
                    "replay execution-control evidence is invalid",
                    json!({"core_index": core_index, "problem": problem}),
                )
            },
        )?;
        self.control_cores[position].state = state;
        self.control_cores[position].halt_reason = halt_reason;
        Ok(observation)
    }

    fn read_registers(
        &mut self,
        session: &SessionInfo,
        core_index: u32,
        names: &[String],
    ) -> Result<RegisterCoreObservation> {
        self.ensure_session(session)?;
        if !self.fixture.capabilities.halt
            || !self.fixture.capabilities.run
            || !self.fixture.capabilities.register_read
        {
            return Err(DebugError::new(
                ErrorCode::CapabilityUnavailable,
                "replay fixture cannot perform a state-preserving register read",
                6,
                json!({"required": ["halt", "run", "register_read"]}),
            ));
        }

        let mut core = self
            .fixture
            .register_cores
            .iter()
            .find(|core| core.index == core_index)
            .cloned()
            .ok_or_else(|| {
                DebugError::fixture(
                    "replay fixture has no explicit register evidence for the requested core",
                    json!({"core_index": core_index}),
                )
            })?;
        if let Some(control) = self
            .control_cores
            .iter()
            .find(|control| control.index == core_index)
        {
            core.original_state = control.state;
            core.captured_state = CoreState::Halted;
            core.state = control.state;
            core.halt_reason = if control.state == CoreState::Running {
                Some("request".to_string())
            } else {
                control.halt_reason.clone()
            };
        }
        core.registers = select_replay_registers(&core.registers, names, core_index)?;
        validate_register_core_observation(&self.fixture.target, &core).map_err(|problem| {
            DebugError::fixture(
                "replay register evidence is invalid",
                json!({"core_index": core_index, "problem": problem}),
            )
        })?;
        Ok(core)
    }

    fn plan_memory_read(
        &self,
        core_index: u32,
        start: Address,
        length: u64,
    ) -> Result<MemoryReadRange> {
        if core_index >= self.fixture.target.core_count {
            return Err(DebugError::config(
                "requested core index is outside the target core inventory",
                json!({
                    "core_index": core_index,
                    "core_count": self.fixture.target.core_count,
                }),
            ));
        }
        let end = checked_memory_read_end(start, length)?;
        let mut matches = Vec::new();
        for block in &self.fixture.memory_blocks {
            if block.core_index != core_index {
                continue;
            }
            let bytes = decode_memory_block(block)?;
            let block_end = block
                .start
                .0
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| {
                    DebugError::fixture(
                        "replay memory block overflows the target address space",
                        json!({"core_index": core_index, "start": block.start}),
                    )
                })?;
            if block.start.0 <= start.0 && end <= block_end {
                matches.push((block, bytes.len() as u64));
            }
        }
        let (block, block_length) = match matches.as_slice() {
            [(block, block_length)] => (*block, *block_length),
            [] => {
                let available = self
                    .fixture
                    .memory_blocks
                    .iter()
                    .filter(|block| block.core_index == core_index)
                    .filter_map(|block| {
                        hex::decode(&block.data).ok().map(|bytes| {
                            json!({
                                "start": block.start,
                                "length": bytes.len(),
                                "kind": block.kind,
                            })
                        })
                    })
                    .collect::<Vec<_>>();
                return Err(DebugError::config(
                    "requested range is not covered by one replay memory evidence block",
                    json!({
                        "core_index": core_index,
                        "start": start,
                        "length": length,
                        "available": available,
                    }),
                ));
            }
            _ => {
                return Err(DebugError::fixture(
                    "multiple replay memory blocks cover the requested range",
                    json!({"core_index": core_index, "start": start, "length": length}),
                ));
            }
        };
        let range = MemoryReadRange {
            start,
            length,
            region: MemoryRegionInfo {
                name: block.name.clone(),
                kind: block.kind,
                start: block.start,
                length: block_length,
                is_alias: block.is_alias,
            },
        };
        validate_memory_read_range(&range).map_err(|problem| {
            DebugError::fixture(
                "replay memory range evidence is invalid",
                json!({"core_index": core_index, "problem": problem}),
            )
        })?;
        Ok(range)
    }

    fn read_memory(
        &mut self,
        session: &SessionInfo,
        core_index: u32,
        range: &MemoryReadRange,
    ) -> Result<MemoryReadResult> {
        self.ensure_session(session)?;
        if !self.fixture.capabilities.halt
            || !self.fixture.capabilities.run
            || !self.fixture.capabilities.memory_read
        {
            return Err(DebugError::new(
                ErrorCode::CapabilityUnavailable,
                "replay fixture cannot perform a state-preserving memory read",
                6,
                json!({"required": ["halt", "run", "memory_read"]}),
            ));
        }
        let planned = self.plan_memory_read(core_index, range.start, range.length)?;
        if &planned != range {
            return Err(DebugError::new(
                ErrorCode::ProtocolError,
                "memory read range changed after planning",
                6,
                json!({"planned": planned, "received": range}),
            ));
        }
        let mut core = self
            .fixture
            .memory_cores
            .iter()
            .find(|core| core.index == core_index)
            .cloned()
            .ok_or_else(|| {
                DebugError::fixture(
                    "replay fixture has no explicit memory core evidence for the requested core",
                    json!({"core_index": core_index}),
                )
            })?;
        if let Some(control) = self
            .control_cores
            .iter()
            .find(|control| control.index == core_index)
        {
            core.original_state = control.state;
            core.captured_state = CoreState::Halted;
            core.state = control.state;
            core.halt_reason = if control.state == CoreState::Running {
                Some("request".to_string())
            } else {
                control.halt_reason.clone()
            };
        }
        validate_memory_core_observation(&self.fixture.target, &core).map_err(|problem| {
            DebugError::fixture(
                "replay memory core evidence is invalid",
                json!({"core_index": core_index, "problem": problem}),
            )
        })?;
        let block = self
            .fixture
            .memory_blocks
            .iter()
            .find(|block| {
                block.core_index == core_index
                    && block.start == range.region.start
                    && block.kind == range.region.kind
            })
            .ok_or_else(|| {
                DebugError::fixture(
                    "planned replay memory block is no longer available",
                    json!({"core_index": core_index, "range": range}),
                )
            })?;
        let block_bytes = decode_memory_block(block)?;
        let offset = usize::try_from(range.start.0 - block.start.0).map_err(|_| {
            DebugError::fixture(
                "replay memory block offset does not fit the host address space",
                json!({"core_index": core_index, "range": range}),
            )
        })?;
        let length = usize::try_from(range.length).expect("bounded memory length fits usize");
        let bytes = block_bytes[offset..offset + length].to_vec();
        Ok(MemoryReadResult {
            core,
            range: range.clone(),
            bytes,
        })
    }

    fn disconnect(&mut self, session: &SessionInfo) -> Result<()> {
        self.ensure_session(session)?;
        self.active_session_id = None;
        self.programmed = None;
        self.reset_performed = false;
        Ok(())
    }
}

fn decode_memory_block(block: &ReplayMemoryBlock) -> Result<Vec<u8>> {
    if block
        .name
        .as_ref()
        .is_some_and(|name| name.trim().is_empty())
    {
        return Err(DebugError::fixture(
            "replay memory block name must not be empty",
            json!({"core_index": block.core_index, "start": block.start}),
        ));
    }
    if block.data.is_empty() || !block.data.len().is_multiple_of(2) {
        return Err(DebugError::fixture(
            "replay memory block data must contain a non-empty even-length hexadecimal string",
            json!({
                "core_index": block.core_index,
                "start": block.start,
                "encoded_length": block.data.len(),
            }),
        ));
    }
    if block.data.len() as u64 > MAX_INLINE_MEMORY_READ_BYTES * 2 {
        return Err(DebugError::fixture(
            "replay memory block exceeds the bounded byte evidence limit",
            json!({
                "core_index": block.core_index,
                "start": block.start,
                "encoded_length": block.data.len(),
                "maximum_bytes": MAX_INLINE_MEMORY_READ_BYTES,
            }),
        ));
    }
    hex::decode(&block.data).map_err(|error| {
        DebugError::fixture(
            "replay memory block data is not valid hexadecimal",
            json!({
                "core_index": block.core_index,
                "start": block.start,
                "parser_message": error.to_string(),
            }),
        )
    })
}

fn select_replay_registers(
    available: &[RegisterReading],
    names: &[String],
    core_index: u32,
) -> Result<Vec<RegisterReading>> {
    if names.len() > MAX_REGISTER_READS {
        return Err(DebugError::config(
            "too many register names were requested",
            json!({"requested_count": names.len(), "maximum": MAX_REGISTER_READS}),
        ));
    }
    if names.is_empty() {
        if available.len() > MAX_REGISTER_READS {
            return Err(DebugError::config(
                "the replay register inventory exceeds the bounded read limit; select register names explicitly",
                json!({
                    "core_index": core_index,
                    "available_count": available.len(),
                    "maximum": MAX_REGISTER_READS,
                }),
            ));
        }
        return Ok(available.to_vec());
    }

    let available_names = available
        .iter()
        .map(|register| register.name.as_str())
        .collect::<Vec<_>>();
    let mut selected = Vec::with_capacity(names.len());
    let mut selected_ids = std::collections::BTreeSet::new();
    for requested in names {
        let matches = available
            .iter()
            .filter(|register| {
                register.name.eq_ignore_ascii_case(requested)
                    || register
                        .aliases
                        .iter()
                        .any(|alias| alias.eq_ignore_ascii_case(requested))
            })
            .collect::<Vec<_>>();
        let register = match matches.as_slice() {
            [register] => *register,
            [] => {
                return Err(DebugError::config(
                    "requested register name is not present in replay evidence",
                    json!({
                        "core_index": core_index,
                        "requested": requested,
                        "available": available_names,
                    }),
                ));
            }
            _ => {
                return Err(DebugError::config(
                    "requested register name is ambiguous in replay evidence",
                    json!({
                        "core_index": core_index,
                        "requested": requested,
                        "matches": matches.iter().map(|item| &item.name).collect::<Vec<_>>(),
                    }),
                ));
            }
        };
        if !selected_ids.insert(register.id.to_ascii_lowercase()) {
            return Err(DebugError::config(
                "multiple requested names resolve to the same register",
                json!({
                    "core_index": core_index,
                    "requested": requested,
                    "register": register.name,
                }),
            ));
        }
        selected.push(register.clone());
    }
    Ok(selected)
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
                expected_final_state: Some(crate::model::CoreState::Running),
                snapshot: Some(fixture.after_reset_core.clone()),
                unavailable_reason: None,
            },
            PostFlashCoreObservation {
                index: 1,
                name: "cpu1".to_string(),
                architecture: "test".to_string(),
                available: false,
                expected_final_state: None,
                snapshot: None,
                unavailable_reason: Some("disabled".to_string()),
            },
        ];

        let error = fixture.validate().unwrap_err();

        assert_eq!(error.code, ErrorCode::FixtureInvalid);
        assert_eq!(error.details["capability"], "run");
    }

    #[test]
    fn register_read_resolves_aliases_and_preserves_requested_order() {
        let fixture = fixture();
        let probe_id = fixture.probe.id.clone();
        let target = fixture.target.name.clone();
        let mut backend = ReplayBackend::new(fixture);
        let session = backend.attach(&probe_id, &target).unwrap();

        let observation = backend
            .read_registers(&session, 0, &["r15".to_string(), "xpsr".to_string()])
            .unwrap();

        assert_eq!(observation.original_state, crate::model::CoreState::Halted);
        assert_eq!(observation.state, crate::model::CoreState::Halted);
        assert_eq!(observation.registers.len(), 2);
        assert_eq!(observation.registers[0].name, "pc");
        assert_eq!(observation.registers[0].value, "0x08001234");
        assert_eq!(observation.registers[1].name, "xpsr");
        backend.disconnect(&session).unwrap();
    }

    #[test]
    fn register_read_rejects_names_absent_from_replay_evidence() {
        let fixture = fixture();
        let probe_id = fixture.probe.id.clone();
        let target = fixture.target.name.clone();
        let mut backend = ReplayBackend::new(fixture);
        let session = backend.attach(&probe_id, &target).unwrap();

        let error = backend
            .read_registers(&session, 0, &["missing".to_string()])
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert_eq!(error.details["requested"], "missing");
        backend.disconnect(&session).unwrap();
    }

    #[test]
    fn register_read_never_synthesizes_missing_replay_evidence() {
        let mut fixture = fixture();
        fixture.register_cores.clear();
        let probe_id = fixture.probe.id.clone();
        let target = fixture.target.name.clone();
        let mut backend = ReplayBackend::new(fixture);
        let session = backend.attach(&probe_id, &target).unwrap();

        let error = backend.read_registers(&session, 0, &[]).unwrap_err();

        assert_eq!(error.code, ErrorCode::FixtureInvalid);
        assert_eq!(error.details["core_index"], 0);
        backend.disconnect(&session).unwrap();
    }

    #[test]
    fn core_control_is_stateful_and_idempotent() {
        let fixture = fixture();
        let probe_id = fixture.probe.id.clone();
        let target = fixture.target.name.clone();
        let mut backend = ReplayBackend::new(fixture);
        let session = backend.attach(&probe_id, &target).unwrap();

        let initial = backend
            .control_core(&session, 0, CoreExecutionAction::Status)
            .unwrap();
        let running = backend
            .control_core(&session, 0, CoreExecutionAction::Run)
            .unwrap();
        let running_again = backend
            .control_core(&session, 0, CoreExecutionAction::Run)
            .unwrap();
        let halted = backend
            .control_core(&session, 0, CoreExecutionAction::Halt)
            .unwrap();

        assert_eq!(initial.state, CoreState::Halted);
        assert!(!initial.state_changed);
        assert_eq!(running.original_state, CoreState::Halted);
        assert_eq!(running.state, CoreState::Running);
        assert!(running.state_changed);
        assert_eq!(running.halt_reason, None);
        assert_eq!(running_again.original_state, CoreState::Running);
        assert!(!running_again.state_changed);
        assert_eq!(halted.original_state, CoreState::Running);
        assert_eq!(halted.state, CoreState::Halted);
        assert!(halted.state_changed);
        assert_eq!(halted.halt_reason.as_deref(), Some("request"));
        backend.disconnect(&session).unwrap();
    }

    #[test]
    fn invalid_core_control_evidence_does_not_mutate_replay_state() {
        let mut fixture = fixture();
        fixture.control_cores[0].name.clear();
        let probe_id = fixture.probe.id.clone();
        let target = fixture.target.name.clone();
        let mut backend = ReplayBackend::new(fixture);
        let session = backend.attach(&probe_id, &target).unwrap();

        let error = backend
            .control_core(&session, 0, CoreExecutionAction::Run)
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::FixtureInvalid);
        assert_eq!(backend.control_cores[0].state, CoreState::Halted);
        backend.disconnect(&session).unwrap();
    }

    #[test]
    fn core_status_capability_requires_explicit_replay_evidence() {
        let mut fixture = fixture();
        fixture.control_cores.clear();

        let error = fixture.validate().unwrap_err();

        assert_eq!(error.code, ErrorCode::FixtureInvalid);
        assert_eq!(error.details["control_core_count"], 0);
    }

    #[test]
    fn post_disconnect_core_state_requires_status_support() {
        let mut fixture = fixture();
        fixture.capabilities.core_status = false;

        let error = fixture.validate().unwrap_err();

        assert_eq!(error.code, ErrorCode::FixtureInvalid);
        assert_eq!(error.details["capability"], "core_status");
    }

    #[test]
    fn legacy_fixture_defaults_new_core_state_capabilities_to_false() {
        let mut value = serde_json::to_value(fixture()).unwrap();
        let capabilities = value["capabilities"].as_object_mut().unwrap();
        capabilities.remove("core_status");
        capabilities.remove("post_disconnect_core_state");
        value.as_object_mut().unwrap().remove("control_cores");

        let fixture: ReplayFixture = serde_json::from_value(value).unwrap();

        assert!(!fixture.capabilities.core_status);
        assert!(!fixture.capabilities.post_disconnect_core_state);
        fixture.validate().unwrap();
    }

    #[test]
    fn memory_read_returns_an_exact_replay_subset_and_explicit_core_state() {
        let fixture = fixture();
        let probe_id = fixture.probe.id.clone();
        let target = fixture.target.name.clone();
        let mut backend = ReplayBackend::new(fixture);
        let range = backend
            .plan_memory_read(0, Address(0x2000_7f04), 8)
            .unwrap();
        let session = backend.attach(&probe_id, &target).unwrap();

        let result = backend.read_memory(&session, 0, &range).unwrap();

        assert_eq!(result.range, range);
        assert_eq!(result.range.region.kind, MemoryRegionKind::Ram);
        assert_eq!(result.bytes, (4_u8..12).collect::<Vec<_>>());
        assert_eq!(result.core.original_state, crate::model::CoreState::Halted);
        assert_eq!(result.core.captured_state, crate::model::CoreState::Halted);
        assert_eq!(result.core.state, crate::model::CoreState::Halted);
        backend.disconnect(&session).unwrap();
    }

    #[test]
    fn memory_plan_rejects_ranges_crossing_replay_evidence_boundaries() {
        let backend = ReplayBackend::new(fixture());

        let error = backend
            .plan_memory_read(0, Address(0x2000_7f18), 16)
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert_eq!(error.details["start"], "0x20007F18");
    }

    #[test]
    fn memory_capability_never_synthesizes_missing_replay_evidence() {
        let mut fixture = fixture();
        fixture.memory_cores.clear();
        fixture.memory_blocks.clear();

        let error = fixture.validate().unwrap_err();

        assert_eq!(error.code, ErrorCode::FixtureInvalid);
        assert_eq!(error.details["memory_core_count"], 0);
        assert_eq!(error.details["memory_block_count"], 0);
    }

    #[test]
    fn memory_fixture_rejects_oversized_blocks_before_hex_decoding() {
        let mut fixture = fixture();
        fixture.memory_blocks[0].data =
            "00".repeat(crate::model::MAX_INLINE_MEMORY_READ_BYTES as usize + 1);

        let error = fixture.validate().unwrap_err();

        assert_eq!(error.code, ErrorCode::FixtureInvalid);
        assert_eq!(
            error.details["maximum_bytes"],
            crate::model::MAX_INLINE_MEMORY_READ_BYTES
        );
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
