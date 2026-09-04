use std::{
    collections::BTreeMap,
    sync::Once,
    time::{Duration, Instant},
};

use probe_rs::{
    CoreInterface, CoreRegister, CoreStatus, CoreType, HaltReason, MemoryInterface, Permissions,
    RegisterDataType, RegisterValue, Session, Target,
    config::{NvmRegion, RawFlashAlgorithm, Registry, RegistryError},
    flashing::{DownloadOptions, FlashError, FlashProgress},
    probe::{
        DebugProbeError, DebugProbeSelector, ProbeCreationError,
        list::{Accessibility, Lister},
    },
};
use serde_json::json;
use uuid::Uuid;

use crate::{
    backend::{
        DebugBackend, checked_memory_read_end, firmware_flash_report,
        nrf52840_development_debug_authorized, validate_firmware_segments,
        validate_hardware_breakpoint_request, validate_nrf52840_development_debug_erase_ranges,
    },
    error::{DebugError, ErrorCode, Result},
    firmware::FirmwareSegment,
    model::{
        Address, Capabilities, ContinueUntilHaltObservation, ContinueUntilHaltOptions,
        ContinueUntilHaltOutcome, CoreExecutionAction, CoreExecutionObservation, CoreObservation,
        CoreSnapshot, CoreState, FirmwareImageOptions, FirmwareSegmentInfo, FlashLayout,
        FlashPolicy, FlashRange, FlashReport, HardwareBreakpointAction,
        HardwareBreakpointObservation, HardwareBreakpointSlot, MAX_REGISTER_READS,
        MemoryCoreObservation, MemoryReadRange, MemoryReadResult, MemoryRegionInfo,
        MemoryRegionKind, PostFlashCoreObservation, ProbeInfo, RegisterCoreObservation,
        RegisterKind, RegisterReading, SessionInfo, TargetInfo,
        validate_continue_until_halt_observation, validate_continue_until_halt_options,
        validate_hardware_breakpoint_observation, validate_memory_read_range,
    },
};

const CORE_OPERATION_TIMEOUT: Duration = Duration::from_secs(2);
static REGISTER_PROBE_RS_PLUGINS: Once = Once::new();

fn register_probe_rs_plugins() {
    REGISTER_PROBE_RS_PLUGINS.call_once(probe_rs_espressif::register_plugin);
}

struct ProgrammedImage {
    segments: Vec<FirmwareSegmentInfo>,
    firmware_sha256: String,
}

struct NativeSession {
    id: String,
    probe: ProbeInfo,
    session: Session,
    programmed: Option<ProgrammedImage>,
    reset_halted: bool,
    restore_before_disconnect: BTreeMap<usize, CoreState>,
}

struct StatePreservingCapture<T> {
    original_state: CoreState,
    captured_status: CoreStatus,
    restored_state: CoreState,
    value: T,
}

pub struct ProbeRsBackend {
    target: Target,
    target_info: TargetInfo,
    capabilities: Capabilities,
    active: Option<NativeSession>,
}

impl ProbeRsBackend {
    pub fn new(target_name: &str) -> Result<Self> {
        register_probe_rs_plugins();
        let target = Registry::from_builtin_families()
            .get_target_by_name(target_name)
            .map_err(map_registry_error)?;
        if target.cores.is_empty() {
            return Err(DebugError::new(
                ErrorCode::CapabilityUnavailable,
                "target description does not contain a debuggable core",
                6,
                json!({"backend": "probe-rs", "target": target.name}),
            ));
        }

        let single_core = target.cores.len() == 1;
        let accepted_esp32s3_post_reset = target.name.eq_ignore_ascii_case("esp32s3");
        let accepted_esp32s3_segmented_flash = target.name.eq_ignore_ascii_case("esp32s3");
        let nrf52840_code_hex_candidate = target.name.eq_ignore_ascii_case("nRF52840_xxAA");
        let accepted_esp32s3_memory_read = target.name.eq_ignore_ascii_case("esp32s3");
        let accepted_esp32s3_core_control = target.name.eq_ignore_ascii_case("esp32s3");
        let flash = !target.flash_algorithms.is_empty();
        let target_info = TargetInfo {
            name: target.name.clone(),
            architecture: format!("{:?}", target.cores[0].core_type).to_ascii_lowercase(),
            core_count: target.cores.len() as u32,
        };
        let capabilities = Capabilities {
            flash,
            // ESP32-S3 segmented programming passed target-specific acceptance.
            // nRF52840 enables a code-flash-only candidate so its sparse HEX
            // path can undergo the same physical acceptance workflow.
            segmented_flash: accepted_esp32s3_segmented_flash || nrf52840_code_hex_candidate,
            // nRF52840 candidate execution is limited below to ordinary code
            // flash; UICR remains under its independent non-boot NVM gate.
            intel_hex_flash: nrf52840_code_hex_candidate,
            // Non-boot NVM (for example nRF52 UICR) remains disabled even when
            // ordinary code-flash acceptance is later enabled.
            non_boot_nvm_flash: false,
            // ESP32-S3 reset and per-core restoration passed target-specific acceptance.
            multi_core_post_flash: accepted_esp32s3_post_reset,
            verify: flash,
            halt: true,
            run: true,
            continue_execution: single_core || accepted_esp32s3_core_control,
            continue_until_halt: single_core || accepted_esp32s3_core_control,
            reset: single_core || accepted_esp32s3_post_reset,
            // probe-rs implements Xtensa single-instruction stepping; this is
            // accepted for CPU0 on ESP32-S3 and for single-core targets.
            step: single_core || accepted_esp32s3_core_control,
            core_status: true,
            // A probe-rs Session may alter execution state while it is dropped. In
            // particular, Xtensa leave_debug_mode resumes a halted core.
            post_disconnect_core_state: false,
            register_read: true,
            memory_read: single_core || accepted_esp32s3_memory_read,
            memory_write: false,
            hardware_breakpoints: 0,
            rtt: false,
            trace: false,
        };

        Ok(Self {
            target,
            target_info,
            capabilities,
            active: None,
        })
    }

    fn ensure_session(&self, session: &SessionInfo) -> Result<&NativeSession> {
        let active = self
            .active
            .as_ref()
            .ok_or_else(|| inactive_session(session))?;
        if active.id == session.session_id
            && active.probe.id == session.probe.id
            && self.target_info.name == session.target.name
        {
            Ok(active)
        } else {
            Err(inactive_session(session))
        }
    }

    fn ensure_session_mut(&mut self, session: &SessionInfo) -> Result<&mut NativeSession> {
        let target_name = self.target_info.name.clone();
        let active = self
            .active
            .as_mut()
            .ok_or_else(|| inactive_session(session))?;
        if active.id == session.session_id
            && active.probe.id == session.probe.id
            && target_name == session.target.name
        {
            Ok(active)
        } else {
            Err(inactive_session(session))
        }
    }
}

/// Discover probes through probe-rs without opening or mutating them.
pub fn list_probes() -> Vec<ProbeInfo> {
    register_probe_rs_plugins();
    let mut probes = Lister::new()
        .list_all_with_access()
        .into_iter()
        .map(|item| {
            let info = item.info;
            ProbeInfo {
                id: DebugProbeSelector::from(&info).to_string(),
                vendor_id: info.vendor_id,
                product_id: info.product_id,
                serial: info.serial_number.clone(),
                product: Some(info.identifier.clone()),
                interface: info.interface,
                probe_type: Some(info.probe_type()),
                accessible: item.accessibility == Accessibility::Accessible,
            }
        })
        .collect::<Vec<_>>();
    probes.sort_by(|left, right| left.id.cmp(&right.id));
    probes
}

impl DebugBackend for ProbeRsBackend {
    fn name(&self) -> &'static str {
        "probe-rs"
    }

    fn list_probes(&self) -> Result<Vec<ProbeInfo>> {
        Ok(list_probes())
    }

    fn target(&self) -> &TargetInfo {
        &self.target_info
    }

    fn matches_target(&self, requested: &str) -> bool {
        Registry::from_builtin_families()
            .get_target_by_name(requested)
            .is_ok_and(|target| target.name.eq_ignore_ascii_case(&self.target.name))
    }

    fn probe_identity_is_stable(&self, probe: &ProbeInfo) -> bool {
        probe
            .serial
            .as_deref()
            .is_some_and(|serial| !serial.is_empty())
    }

    fn volatile_target_state_notes(&self) -> Vec<String> {
        let mut notes = vec![
            "probe-rs session attach clears hardware breakpoints".to_string(),
            "probe-rs target attach/halt sequences may modify volatile target control state"
                .to_string(),
            "halting a running core can interrupt in-flight peripheral activity and produce partial external I/O"
                .to_string(),
            "probe-rs session teardown can resume a core that was halted before attach"
                .to_string(),
        ];
        if self.target_info.name.eq_ignore_ascii_case("esp32s3") {
            notes.push(
                "probe-rs ESP32-S3 attach/halt sequence disables super, timer-group 0/1, and RTC watchdogs"
                    .to_string(),
            );
        }
        notes
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    fn plan_flash_ranges(
        &self,
        firmware_size: u64,
        requested_base_address: Option<Address>,
    ) -> Result<FlashLayout> {
        let base_address = requested_base_address.ok_or_else(|| {
            DebugError::config(
                "raw BIN firmware requires --base-address with the probe-rs backend",
                json!({"backend": self.name(), "target": self.target_info.name}),
            )
        })?;
        let end = base_address.0.checked_add(firmware_size).ok_or_else(|| {
            DebugError::config(
                "flash write range overflows the target address space",
                json!({"base_address": base_address, "firmware_size": firmware_size}),
            )
        })?;
        if firmware_size == 0 {
            return Err(DebugError::config(
                "firmware must contain at least one byte",
                json!({"firmware_size": firmware_size}),
            ));
        }

        let region = self
            .target
            .memory_map
            .iter()
            .filter_map(|region| region.as_nvm_region())
            .find(|region| {
                region.is_readable()
                    && region.is_boot_memory()
                    && region.range.start <= base_address.0
                    && end <= region.range.end
            })
            .ok_or_else(|| {
                DebugError::config(
                    "raw BIN range is not fully contained in readable boot flash",
                    json!({
                        "target": self.target_info.name,
                        "start": base_address,
                        "length": firmware_size,
                    }),
                )
            })?;
        let algorithm = select_flash_algorithm(&self.target, region)?;
        let erase_ranges = affected_erase_ranges(algorithm, base_address.0, end)?;

        Ok(FlashLayout {
            write_ranges: vec![FlashRange {
                start: base_address,
                length: firmware_size,
            }],
            erase_ranges,
        })
    }

    fn validate_firmware_image_options(&self, options: &FirmwareImageOptions) -> Result<()> {
        let boot_window = self
            .target
            .memory_map
            .iter()
            .filter_map(|region| region.as_nvm_region())
            .find(|region| {
                region.is_readable() && region.is_boot_memory() && region.range.start == 0
            })
            .ok_or_else(|| {
                DebugError::new(
                    ErrorCode::CapabilityUnavailable,
                    "target does not describe a readable physical boot flash window",
                    6,
                    json!({"target": self.target_info.name}),
                )
            })?;
        let maximum = boot_window.range.end - boot_window.range.start;
        if options.flash_size > maximum {
            return Err(DebugError::config(
                "declared firmware flash size exceeds the target physical boot flash window",
                json!({
                    "target": self.target_info.name,
                    "declared_flash_size": options.flash_size,
                    "maximum_flash_size": maximum,
                    "boot_flash_start": Address(boot_window.range.start),
                    "boot_flash_end": Address(boot_window.range.end),
                }),
            ));
        }
        Ok(())
    }

    fn plan_segmented_flash_ranges(&self, write_ranges: &[FlashRange]) -> Result<FlashLayout> {
        if write_ranges.is_empty() {
            return Err(DebugError::config(
                "firmware image must contain at least one flash segment",
                json!({"target": self.target_info.name}),
            ));
        }

        let mut sorted = write_ranges.to_vec();
        sorted.sort_by_key(|range| range.start.0);
        let mut erase_ranges = Vec::new();
        let mut previous_end = None;

        for range in &sorted {
            if range.length == 0 {
                return Err(DebugError::config(
                    "firmware image contains an empty flash segment",
                    json!({"target": self.target_info.name, "range": range}),
                ));
            }
            let end = range.start.0.checked_add(range.length).ok_or_else(|| {
                DebugError::config(
                    "flash write range overflows the target address space",
                    json!({"target": self.target_info.name, "range": range}),
                )
            })?;
            if previous_end.is_some_and(|previous| range.start.0 < previous) {
                return Err(DebugError::config(
                    "firmware image contains overlapping flash segments",
                    json!({"target": self.target_info.name, "ranges": sorted}),
                ));
            }

            let region = self
                .target
                .memory_map
                .iter()
                .filter_map(|region| region.as_nvm_region())
                .find(|region| {
                    region.is_readable()
                        && region.range.start <= range.start.0
                        && end <= region.range.end
                })
                .ok_or_else(|| {
                    DebugError::config(
                        "firmware segment is not fully contained in readable nonvolatile memory",
                        json!({
                            "target": self.target_info.name,
                            "range": range,
                        }),
                    )
                })?;
            let algorithm = select_flash_algorithm(&self.target, region)?;
            erase_ranges.extend(affected_erase_ranges(algorithm, range.start.0, end)?);
            previous_end = Some(end);
        }

        Ok(FlashLayout {
            write_ranges: sorted,
            erase_ranges: merge_flash_ranges(erase_ranges)?,
        })
    }

    fn attach(&mut self, probe_id: &str, target: &str) -> Result<SessionInfo> {
        if self.active.is_some() {
            return Err(DebugError::new(
                ErrorCode::ProtocolError,
                "probe-rs backend already has an active session",
                6,
                json!({"backend": self.name()}),
            ));
        }
        if target != self.target_info.name {
            return Err(DebugError::new(
                ErrorCode::PlanStale,
                "target identity changed after planning",
                2,
                json!({"planned": self.target_info.name, "received": target}),
            ));
        }
        let matches = list_probes()
            .into_iter()
            .filter(|probe| probe.id == probe_id)
            .collect::<Vec<_>>();
        let probe_info = match matches.as_slice() {
            [probe] if probe.accessible => probe.clone(),
            [probe] => {
                return Err(DebugError::new(
                    ErrorCode::PermissionDenied,
                    "the planned debug probe is no longer accessible",
                    8,
                    json!({"probe": probe}),
                ));
            }
            [] => {
                return Err(DebugError::unavailable(
                    ErrorCode::ProbeUnavailable,
                    "the planned debug probe is no longer connected",
                    json!({"probe_id": probe_id}),
                ));
            }
            _ => {
                return Err(DebugError::unavailable(
                    ErrorCode::ProbeAmbiguous,
                    "multiple connected probes share the planned selector",
                    json!({"probe_id": probe_id, "matches": matches}),
                ));
            }
        };
        let selector = probe_id.parse::<DebugProbeSelector>().map_err(|error| {
            DebugError::config(
                "planned probe id is not a valid probe-rs selector",
                json!({"probe_id": probe_id, "cause": error.to_string()}),
            )
        })?;
        let probe = Lister::new()
            .open(selector)
            .map_err(|error| map_probe_error("open probe", error))?;
        // Default permissions deliberately exclude full-chip erase/unlock operations.
        let mut native_session = probe
            .attach(self.target.clone(), Permissions::default())
            .map_err(|error| map_core_error("attach target", error))?;
        let breakpoint_capacity = if supports_native_hardware_breakpoints(&self.target) {
            native_session
                .core(0)
                .and_then(|mut core| core.available_breakpoint_units())
                .map_err(|error| map_core_error("query hardware breakpoint capacity", error))?
        } else {
            0
        };
        self.capabilities.hardware_breakpoints = breakpoint_capacity;
        let id = format!("ses_{}", Uuid::new_v4().simple());
        let info = SessionInfo {
            session_id: id.clone(),
            backend: self.name().to_string(),
            probe: probe_info.clone(),
            target: self.target_info.clone(),
            capabilities: self.capabilities.clone(),
        };
        self.active = Some(NativeSession {
            id,
            probe: probe_info,
            session: native_session,
            programmed: None,
            reset_halted: false,
            restore_before_disconnect: BTreeMap::new(),
        });
        Ok(info)
    }

    fn program(
        &mut self,
        session: &SessionInfo,
        segments: &[FirmwareSegment],
        firmware_sha256: &str,
        policy: &FlashPolicy,
    ) -> Result<FlashReport> {
        validate_firmware_segments(segments)?;
        let development_debug_authorized =
            nrf52840_development_debug_authorized(&self.target_info.name, segments, policy)?;
        if segments.iter().any(|segment| segment.info.kind == "uicr")
            && !self.capabilities.non_boot_nvm_flash
            && !development_debug_authorized
        {
            return Err(DebugError::new(
                ErrorCode::CapabilityUnavailable,
                "non-boot NVM execution has not passed target-specific acceptance",
                6,
                json!({
                    "backend": self.name(),
                    "target": self.target_info.name,
                    "capability": "non_boot_nvm_flash",
                }),
            ));
        }
        if segments.len() > 1 && !self.capabilities.segmented_flash {
            return Err(DebugError::new(
                ErrorCode::CapabilityUnavailable,
                "segmented flash execution has not passed target-specific acceptance",
                6,
                json!({
                    "backend": self.name(),
                    "target": self.target_info.name,
                    "segment_count": segments.len(),
                }),
            ));
        }
        let layout = self.plan_segmented_flash_ranges(
            &segments
                .iter()
                .map(|segment| FlashRange {
                    start: segment.info.start,
                    length: segment.info.length,
                })
                .collect::<Vec<_>>(),
        )?;
        if development_debug_authorized {
            validate_nrf52840_development_debug_erase_ranges(&layout.erase_ranges, policy)?;
        }

        let active = self.ensure_session_mut(session)?;
        let mut loader = active.session.target().flash_loader();
        for segment in segments {
            loader
                .add_data(segment.info.start.0, &segment.data)
                .map_err(|error| map_flash_error("stage firmware segment", error))?;
        }
        let mut options = DownloadOptions::default();
        options.keep_unwritten_bytes = true;
        options.do_chip_erase = false;
        options.skip_erase = false;
        options.preverify = false;
        options.verify = false;
        loader
            .commit(&mut active.session, options)
            .map_err(|error| map_flash_error("program firmware", error))?;
        active.programmed = Some(ProgrammedImage {
            segments: segments
                .iter()
                .map(|segment| segment.info.clone())
                .collect(),
            firmware_sha256: firmware_sha256.to_string(),
        });

        firmware_flash_report(segments, firmware_sha256, false)
    }

    fn verify(
        &mut self,
        session: &SessionInfo,
        segments: &[FirmwareSegment],
        firmware_sha256: &str,
    ) -> Result<FlashReport> {
        validate_firmware_segments(segments)?;
        let active = self.ensure_session_mut(session)?;
        let image = active.programmed.as_ref().ok_or_else(|| {
            DebugError::new(
                ErrorCode::ProtocolError,
                "cannot verify before firmware has been programmed",
                6,
                json!({"session_id": session.session_id}),
            )
        })?;
        if image.firmware_sha256 != firmware_sha256 {
            return Err(DebugError::new(
                ErrorCode::PlanStale,
                "verification digest differs from the programmed firmware",
                2,
                json!({
                    "programmed": image.firmware_sha256,
                    "received": firmware_sha256,
                }),
            ));
        }
        let received_manifest = segments
            .iter()
            .map(|segment| &segment.info)
            .collect::<Vec<_>>();
        if !image.segments.iter().eq(received_manifest.iter().copied()) {
            return Err(DebugError::new(
                ErrorCode::PlanStale,
                "verification segments differ from the programmed firmware manifest",
                2,
                json!({
                    "programmed_segments": image.segments,
                    "received_segments": received_manifest,
                }),
            ));
        }
        let mut report = firmware_flash_report(segments, firmware_sha256, false)?;
        for (segment, segment_report) in segments.iter().zip(&mut report.segments) {
            let mut loader = active.session.target().flash_loader();
            loader
                .add_data(segment.info.start.0, &segment.data)
                .map_err(|error| map_flash_error("stage segment verification", error))?;
            segment_report.verified =
                match loader.verify(&mut active.session, &mut FlashProgress::empty()) {
                    Ok(()) => true,
                    Err(FlashError::Verify) => false,
                    Err(error) => return Err(map_flash_error("verify firmware segment", error)),
                };
        }
        report.verified = report.segments.iter().all(|segment| segment.verified);
        Ok(report)
    }

    fn reset(&mut self, session: &SessionInfo) -> Result<()> {
        if !self.capabilities.reset {
            return Err(DebugError::new(
                ErrorCode::CapabilityUnavailable,
                "target reset has not passed target-specific acceptance",
                6,
                json!({
                    "backend": self.name(),
                    "target": self.target_info.name,
                    "core_count": self.target_info.core_count,
                    "capability": "reset",
                }),
            ));
        }
        let active = self.ensure_session_mut(session)?;
        active
            .session
            .core(0)
            .and_then(|mut core| core.reset_and_halt(CORE_OPERATION_TIMEOUT))
            .map_err(|error| map_core_error("reset and halt core", error))?;
        active.reset_halted = true;
        Ok(())
    }

    fn snapshot(&mut self, session: &SessionInfo) -> Result<CoreSnapshot> {
        let active = self.ensure_session_mut(session)?;
        if !active.reset_halted {
            return Err(DebugError::new(
                ErrorCode::ProtocolError,
                "post-flash snapshot requires a successful reset-and-halt",
                6,
                json!({"session_id": session.session_id}),
            ));
        }

        let mut core = active
            .session
            .core(0)
            .map_err(|error| map_core_error("attach core for snapshot", error))?;
        let mut captured_status = core
            .status()
            .map_err(|error| map_core_error("read core status", error))?;
        if !captured_status.is_halted() {
            core.halt(CORE_OPERATION_TIMEOUT)
                .map_err(|error| map_core_error("halt core for snapshot", error))?;
            captured_status = core
                .status()
                .map_err(|error| map_core_error("read halted core status", error))?;
        }
        let pc_id = core.program_counter().id();
        let sp_id = core.stack_pointer().id();
        let lr_id = core.return_address().id();
        let pc = core
            .read_core_reg::<u64>(pc_id)
            .map_err(|error| map_core_error("read program counter", error))?;
        let sp = core
            .read_core_reg::<u64>(sp_id)
            .map_err(|error| map_core_error("read stack pointer", error))?;
        let lr = core
            .read_core_reg::<u64>(lr_id)
            .map_err(|error| map_core_error("read return address", error))?;
        core.run()
            .map_err(|error| map_core_error("resume core after snapshot", error))?;
        let final_status = core
            .status()
            .map_err(|error| map_core_error("read resumed core status", error))?;
        let final_state = live_core_state(0, final_status)
            .map_err(|error| map_core_error("validate resumed core state", error))?;
        if final_state == CoreState::Running {
            active.reset_halted = false;
        }

        Ok(CoreSnapshot {
            captured_state: map_core_state(captured_status),
            state: final_state,
            pc: Address(pc),
            sp: Address(sp),
            registers: BTreeMap::from([("lr".to_string(), Address(lr))]),
            halt_reason: halt_reason(captured_status),
        })
    }

    fn capture_post_flash_snapshot(
        &mut self,
        session: &SessionInfo,
    ) -> Result<Vec<PostFlashCoreObservation>> {
        if self.target.cores.len() > 1 && !self.capabilities.multi_core_post_flash {
            return Err(DebugError::new(
                ErrorCode::CapabilityUnavailable,
                "multi-core post-flash observation has not passed target-specific acceptance",
                6,
                json!({
                    "backend": self.name(),
                    "target": self.target_info.name,
                    "core_count": self.target_info.core_count,
                    "capability": "multi_core_post_flash",
                }),
            ));
        }
        let core_specs = self
            .target
            .cores
            .iter()
            .enumerate()
            .map(|(index, core)| {
                (
                    index,
                    core.name.clone(),
                    format!("{:?}", core.core_type).to_ascii_lowercase(),
                )
            })
            .collect::<Vec<_>>();
        let active = self.ensure_session_mut(session)?;
        if !active.reset_halted || !active.restore_before_disconnect.is_empty() {
            return Err(DebugError::new(
                ErrorCode::ProtocolError,
                "post-reset snapshot requires a successful reset-and-halt with no pending restoration",
                6,
                json!({"session_id": session.session_id}),
            ));
        }

        let mut disabled = BTreeMap::<usize, String>::new();
        let mut observed_states = BTreeMap::<usize, CoreState>::new();
        let mut expected_states = BTreeMap::<usize, CoreState>::new();

        // Core 0 is deliberately held by reset_and_halt and must resume. Other
        // cores retain the state in which the target's reset sequence left them.
        for (index, _, _) in &core_specs {
            let state_result = match active.session.core(*index) {
                Ok(mut core) => core.status(),
                Err(error @ probe_rs::Error::CoreDisabled(_)) => {
                    disabled.insert(*index, error.to_string());
                    continue;
                }
                Err(error) => Err(error),
            };
            let observed_status = match state_result {
                Ok(status) => status,
                Err(error) => {
                    return Err(restore_after_capture_error(
                        active,
                        "read post-reset core states",
                        error,
                    ));
                }
            };
            let observed_state = match live_core_state(*index, observed_status) {
                Ok(state) => state,
                Err(error) => {
                    return Err(restore_after_capture_error(
                        active,
                        "determine post-reset core states",
                        error,
                    ));
                }
            };
            let expected_state = if *index == 0 {
                CoreState::Running
            } else {
                observed_state
            };
            observed_states.insert(*index, observed_state);
            expected_states.insert(*index, expected_state);
            active
                .restore_before_disconnect
                .insert(*index, expected_state);
        }

        for (index, _, _) in &core_specs {
            if disabled.contains_key(index)
                || observed_states.get(index) == Some(&CoreState::Halted)
            {
                continue;
            }
            if let Err(error) = active
                .session
                .core(*index)
                .and_then(|mut core| core.halt(CORE_OPERATION_TIMEOUT))
            {
                return Err(restore_after_capture_error(
                    active,
                    "halt running cores for post-reset snapshot",
                    error,
                ));
            }
        }

        let captured =
            (|| -> std::result::Result<Vec<PostFlashCoreObservation>, probe_rs::Error> {
                let mut observations = Vec::with_capacity(core_specs.len());
                for (index, name, architecture) in &core_specs {
                    if let Some(reason) = disabled.get(index) {
                        observations.push(PostFlashCoreObservation {
                            index: *index as u32,
                            name: name.clone(),
                            architecture: architecture.clone(),
                            available: false,
                            expected_final_state: None,
                            snapshot: None,
                            unavailable_reason: Some(reason.clone()),
                        });
                        continue;
                    }

                    let mut core = active.session.core(*index)?;
                    let captured_status = core.status()?;
                    if live_core_state(*index, captured_status)? != CoreState::Halted {
                        return Err(probe_rs::Error::GenericCoreError(format!(
                            "core {index} was not halted when post-reset registers were captured"
                        )));
                    }
                    let pc_id = core.program_counter().id();
                    let sp_id = core.stack_pointer().id();
                    let lr_id = core.return_address().id();
                    let pc = core.read_core_reg::<u64>(pc_id)?;
                    let sp = core.read_core_reg::<u64>(sp_id)?;
                    let lr = core.read_core_reg::<u64>(lr_id)?;
                    observations.push(PostFlashCoreObservation {
                        index: *index as u32,
                        name: name.clone(),
                        architecture: architecture.clone(),
                        available: true,
                        expected_final_state: expected_states.get(index).copied(),
                        snapshot: Some(CoreSnapshot {
                            captured_state: CoreState::Halted,
                            state: CoreState::Unknown,
                            pc: Address(pc),
                            sp: Address(sp),
                            registers: BTreeMap::from([("lr".to_string(), Address(lr))]),
                            halt_reason: halt_reason(captured_status),
                        }),
                        unavailable_reason: None,
                    });
                }
                Ok(observations)
            })();
        let mut observations = match captured {
            Ok(observations) => observations,
            Err(error) => {
                return Err(restore_after_capture_error(
                    active,
                    "read all cores for post-reset snapshot",
                    error,
                ));
            }
        };

        let restored_states = restore_pending_core_states(active)
            .map_err(|error| map_core_error("restore cores after post-reset snapshot", error))?;
        if restored_states.get(&0) == Some(&CoreState::Running) {
            active.reset_halted = false;
        }
        for observation in observations.iter_mut().filter(|core| core.available) {
            observation
                .snapshot
                .as_mut()
                .expect("available cores always contain a snapshot")
                .state = restored_states
                .get(&(observation.index as usize))
                .copied()
                .expect("every available core has a restored state");
        }
        Ok(observations)
    }

    fn capture_live_snapshot(&mut self, session: &SessionInfo) -> Result<Vec<CoreObservation>> {
        let core_specs = self
            .target
            .cores
            .iter()
            .enumerate()
            .map(|(index, core)| {
                (
                    index,
                    core.name.clone(),
                    format!("{:?}", core.core_type).to_ascii_lowercase(),
                )
            })
            .collect::<Vec<_>>();
        let active = self.ensure_session_mut(session)?;
        if active.reset_halted || !active.restore_before_disconnect.is_empty() {
            return Err(DebugError::new(
                ErrorCode::ProtocolError,
                "cannot start a live snapshot while core restoration is pending",
                6,
                json!({"session_id": session.session_id}),
            ));
        }

        let mut disabled = BTreeMap::<usize, String>::new();
        let mut original_states = BTreeMap::<usize, CoreState>::new();

        // Observe every core before changing any core state. On coordinated
        // multi-core firmware, halting one core can affect how another appears.
        for (index, _, _) in &core_specs {
            let state_result = match active.session.core(*index) {
                Ok(mut core) => core.status(),
                Err(error @ probe_rs::Error::CoreDisabled(_)) => {
                    disabled.insert(*index, error.to_string());
                    continue;
                }
                Err(error) => Err(error),
            };
            let original_status = match state_result {
                Ok(state) => state,
                Err(error) => {
                    return Err(restore_after_capture_error(
                        active,
                        "read original core states for live snapshot",
                        error,
                    ));
                }
            };
            let original_state = match live_core_state(*index, original_status) {
                Ok(state) => state,
                Err(error) => {
                    return Err(restore_after_capture_error(
                        active,
                        "determine original core state for live snapshot",
                        error,
                    ));
                }
            };
            original_states.insert(*index, original_state);
            active
                .restore_before_disconnect
                .insert(*index, original_state);
        }

        for (index, _, _) in &core_specs {
            if disabled.contains_key(index)
                || original_states.get(index) == Some(&CoreState::Halted)
            {
                continue;
            }

            if let Err(error) = active
                .session
                .core(*index)
                .and_then(|mut core| core.halt(CORE_OPERATION_TIMEOUT))
            {
                return Err(restore_after_capture_error(
                    active,
                    "halt running cores for live snapshot",
                    error,
                ));
            }
        }

        let captured = (|| -> std::result::Result<Vec<CoreObservation>, probe_rs::Error> {
            let mut observations = Vec::with_capacity(core_specs.len());
            for (index, name, architecture) in &core_specs {
                if let Some(reason) = disabled.get(index) {
                    observations.push(CoreObservation {
                        index: *index as u32,
                        name: name.clone(),
                        architecture: architecture.clone(),
                        available: false,
                        original_state: None,
                        snapshot: None,
                        unavailable_reason: Some(reason.clone()),
                    });
                    continue;
                }

                let mut core = active.session.core(*index)?;
                let captured_status = core.status()?;
                if live_core_state(*index, captured_status)? != CoreState::Halted {
                    return Err(probe_rs::Error::GenericCoreError(format!(
                        "core {index} was not halted when registers were captured"
                    )));
                }
                let pc_id = core.program_counter().id();
                let sp_id = core.stack_pointer().id();
                let lr_id = core.return_address().id();
                let pc = core.read_core_reg::<u64>(pc_id)?;
                let sp = core.read_core_reg::<u64>(sp_id)?;
                let lr = core.read_core_reg::<u64>(lr_id)?;
                observations.push(CoreObservation {
                    index: *index as u32,
                    name: name.clone(),
                    architecture: architecture.clone(),
                    available: true,
                    original_state: original_states.get(index).copied(),
                    snapshot: Some(CoreSnapshot {
                        captured_state: CoreState::Halted,
                        state: CoreState::Unknown,
                        pc: Address(pc),
                        sp: Address(sp),
                        registers: BTreeMap::from([("lr".to_string(), Address(lr))]),
                        halt_reason: halt_reason(captured_status),
                    }),
                    unavailable_reason: None,
                });
            }
            Ok(observations)
        })();
        let mut observations = match captured {
            Ok(observations) => observations,
            Err(error) => {
                return Err(restore_after_capture_error(
                    active,
                    "read all cores for live snapshot",
                    error,
                ));
            }
        };

        let restored_states = restore_pending_core_states(active)
            .map_err(|error| map_core_error("restore core states after live snapshot", error))?;
        for observation in observations.iter_mut().filter(|core| core.available) {
            observation
                .snapshot
                .as_mut()
                .expect("available cores always contain a snapshot")
                .state = restored_states
                .get(&(observation.index as usize))
                .copied()
                .expect("every available core has a restored state");
        }
        Ok(observations)
    }

    fn control_core_in_session(
        &mut self,
        session: &SessionInfo,
        core_index: u32,
        action: CoreExecutionAction,
    ) -> Result<CoreExecutionObservation> {
        if !self.capabilities.core_status {
            return Err(DebugError::new(
                ErrorCode::CapabilityUnavailable,
                "probe-rs cannot observe execution state for the selected target",
                6,
                json!({
                    "action": action,
                    "capability": "core_status",
                    "target": self.target_info.name,
                }),
            ));
        }
        if action == CoreExecutionAction::Step
            && self.target_info.name.eq_ignore_ascii_case("esp32s3")
            && core_index != 0
        {
            return Err(DebugError::new(
                ErrorCode::CapabilityUnavailable,
                "single-step is not physically accepted for the selected target core",
                6,
                json!({
                    "action": action,
                    "capability": "step",
                    "core_index": core_index,
                    "accepted_core_indexes": [0],
                    "target": self.target_info.name,
                }),
            ));
        }
        let index = core_index as usize;
        let (core_name, architecture) = self
            .target
            .cores
            .get(index)
            .map(|core| {
                (
                    core.name.clone(),
                    format!("{:?}", core.core_type).to_ascii_lowercase(),
                )
            })
            .ok_or_else(|| {
                DebugError::config(
                    "requested core index is outside the target core inventory",
                    json!({
                        "core_index": core_index,
                        "core_count": self.target.cores.len(),
                    }),
                )
            })?;
        let active = self.ensure_session_mut(session)?;
        if active.reset_halted || !active.restore_before_disconnect.is_empty() {
            return Err(DebugError::new(
                ErrorCode::ProtocolError,
                "cannot control a core while restoration is pending",
                6,
                json!({"session_id": session.session_id, "core_index": core_index}),
            ));
        }
        let mut core = active.session.core(index).map_err(|error| match error {
            probe_rs::Error::CoreDisabled(_) => DebugError::new(
                ErrorCode::CapabilityUnavailable,
                "requested target core is disabled",
                6,
                json!({"core_index": core_index}),
            ),
            other => map_core_error("attach core for execution control", other),
        })?;
        let original_status = core
            .status()
            .map_err(|error| map_core_error("read original core state", error))?;
        let original_state = live_core_state(index, original_status)
            .map_err(|error| map_core_error("determine original core state", error))?;
        let mut step_pc_before = None;
        let mut step_pc_after = None;
        match (action, original_state) {
            (CoreExecutionAction::Halt, CoreState::Running) => core
                .halt(CORE_OPERATION_TIMEOUT)
                .map(|_| ())
                .map_err(|error| map_core_error("halt selected core", error))?,
            (CoreExecutionAction::Run, CoreState::Halted) => core
                .run()
                .map_err(|error| map_core_error("run selected core", error))?,
            (CoreExecutionAction::Continue, CoreState::Halted) => core
                .run()
                .map_err(|error| map_core_error("continue selected core", error))?,
            (CoreExecutionAction::Continue, CoreState::Running) => {
                return Err(DebugError::config(
                    "core.continue requires the selected core to be halted",
                    json!({
                        "core_index": core_index,
                        "action": action,
                        "original_state": original_state,
                    }),
                ));
            }
            (CoreExecutionAction::Step, CoreState::Halted) => {
                step_pc_before = Some(Address(
                    core.read_core_reg::<u64>(core.program_counter().id())
                        .map_err(|error| map_core_error("read PC before step", error))?,
                ));
                step_pc_after = Some(Address(
                    core.step()
                        .map_err(|error| map_core_error("step selected core", error))?
                        .pc,
                ));
            }
            (CoreExecutionAction::Step, CoreState::Running) => {
                return Err(DebugError::config(
                    "core.step requires the selected core to be halted",
                    json!({
                        "core_index": core_index,
                        "action": action,
                        "original_state": original_state,
                    }),
                ));
            }
            _ => {}
        }
        let final_status = core
            .status()
            .map_err(|error| map_core_error("verify final core state", error))?;
        let state = live_core_state(index, final_status)
            .map_err(|error| map_core_error("determine final core state", error))?;
        let expected = match action {
            CoreExecutionAction::Status => original_state,
            CoreExecutionAction::Halt => CoreState::Halted,
            CoreExecutionAction::Run => CoreState::Running,
            CoreExecutionAction::Continue => state,
            CoreExecutionAction::Step => CoreState::Halted,
        };
        if state != expected {
            return Err(DebugError::new(
                ErrorCode::ProtocolError,
                "selected core did not reach the requested execution state",
                6,
                json!({
                    "core_index": core_index,
                    "action": action,
                    "expected": expected,
                    "observed": state,
                }),
            ));
        }
        Ok(CoreExecutionObservation {
            index: core_index,
            name: core_name,
            architecture,
            action,
            original_state,
            state,
            state_changed: original_state != state,
            halt_reason: halt_reason(final_status),
            pc_before: step_pc_before,
            pc_after: step_pc_after,
        })
    }

    fn continue_until_halt_in_session(
        &mut self,
        session: &SessionInfo,
        core_index: u32,
        options: ContinueUntilHaltOptions,
    ) -> Result<ContinueUntilHaltObservation> {
        validate_continue_until_halt_options(options).map_err(|problem| {
            DebugError::config(
                "invalid continue-until-halt timing options",
                json!({"problem": problem, "options": options}),
            )
        })?;
        if !session.capabilities.continue_until_halt
            || !session.capabilities.continue_execution
            || !session.capabilities.core_status
        {
            return Err(DebugError::new(
                ErrorCode::CapabilityUnavailable,
                "selected target cannot continue and wait for a halt event",
                6,
                json!({
                    "capability": "continue_until_halt",
                    "core_index": core_index,
                }),
            ));
        }

        let started = Instant::now();
        let continuation =
            self.control_core_in_session(session, core_index, CoreExecutionAction::Continue)?;
        if continuation.state == CoreState::Halted {
            return validated_continue_until_halt_observation(
                &self.target_info,
                continuation.clone(),
                ContinueUntilHaltOutcome::Halted,
                CoreState::Halted,
                continuation.halt_reason.clone(),
                options,
                started,
                0,
            );
        }

        let timeout = Duration::from_millis(options.timeout_ms);
        let poll_interval = Duration::from_millis(options.poll_interval_ms);
        let mut poll_count = 0_u32;
        loop {
            let remaining = timeout.saturating_sub(started.elapsed());
            if !remaining.is_zero() {
                std::thread::sleep(poll_interval.min(remaining));
            }
            let status =
                self.control_core_in_session(session, core_index, CoreExecutionAction::Status)?;
            poll_count += 1;
            if status.state == CoreState::Halted {
                return validated_continue_until_halt_observation(
                    &self.target_info,
                    continuation,
                    ContinueUntilHaltOutcome::Halted,
                    CoreState::Halted,
                    status.halt_reason,
                    options,
                    started,
                    poll_count,
                );
            }
            if started.elapsed() >= timeout {
                return validated_continue_until_halt_observation(
                    &self.target_info,
                    continuation,
                    ContinueUntilHaltOutcome::TimedOut,
                    CoreState::Running,
                    None,
                    options,
                    started,
                    poll_count,
                );
            }
        }
    }

    fn control_hardware_breakpoints_in_session(
        &mut self,
        session: &SessionInfo,
        core_index: u32,
        action: HardwareBreakpointAction,
        address: Option<Address>,
        slot: Option<u32>,
    ) -> Result<HardwareBreakpointObservation> {
        let capacity = session.capabilities.hardware_breakpoints;
        validate_hardware_breakpoint_request(action, address, slot, capacity)?;
        if !supports_native_hardware_breakpoints(&self.target) || core_index != 0 {
            return Err(DebugError::new(
                ErrorCode::CapabilityUnavailable,
                "hardware breakpoints are not physically accepted for the selected target core",
                6,
                json!({
                    "capability": "hardware_breakpoints",
                    "core_index": core_index,
                    "accepted_core_indexes": if supports_native_hardware_breakpoints(&self.target) {
                        vec![0]
                    } else {
                        Vec::<u32>::new()
                    },
                    "target": self.target_info.name,
                }),
            ));
        }
        if address.is_some_and(|address| address.0 > u32::MAX as u64) {
            return Err(DebugError::config(
                "hardware breakpoint address exceeds the selected core address width",
                json!({"address": address, "maximum": Address(u32::MAX as u64)}),
            ));
        }
        let index = core_index as usize;
        let (core_name, architecture) = self
            .target
            .cores
            .get(index)
            .map(|core| {
                (
                    core.name.clone(),
                    format!("{:?}", core.core_type).to_ascii_lowercase(),
                )
            })
            .ok_or_else(|| {
                DebugError::config(
                    "requested core index is outside the target core inventory",
                    json!({
                        "core_index": core_index,
                        "core_count": self.target.cores.len(),
                    }),
                )
            })?;
        let target_info = self.target_info.clone();
        let active = self.ensure_session_mut(session)?;
        if active.reset_halted || !active.restore_before_disconnect.is_empty() {
            return Err(DebugError::new(
                ErrorCode::ProtocolError,
                "cannot control hardware breakpoints while restoration is pending",
                6,
                json!({"session_id": session.session_id, "core_index": core_index}),
            ));
        }
        let mut core = active.session.core(index).map_err(|error| match error {
            probe_rs::Error::CoreDisabled(_) => DebugError::new(
                ErrorCode::CapabilityUnavailable,
                "requested target core is disabled",
                6,
                json!({"core_index": core_index}),
            ),
            other => map_core_error("attach core for hardware breakpoint control", other),
        })?;
        let original_status = core.status().map_err(|error| {
            map_core_error("read core state before breakpoint operation", error)
        })?;
        let original_state = live_core_state(index, original_status).map_err(|error| {
            map_core_error("determine core state before breakpoint operation", error)
        })?;
        if action != HardwareBreakpointAction::List && original_state != CoreState::Halted {
            return Err(DebugError::config(
                "hardware breakpoint mutations require the selected core to be halted",
                json!({
                    "core_index": core_index,
                    "action": action,
                    "original_state": original_state,
                }),
            ));
        }

        let before = native_hardware_breakpoint_slots(&mut core, capacity)?;
        let affected_slot = match action {
            HardwareBreakpointAction::List | HardwareBreakpointAction::ClearAll => None,
            HardwareBreakpointAction::Set => {
                let address = address.expect("set request was validated");
                let selected = if let Some(existing) = before
                    .iter()
                    .position(|entry| entry.address == Some(address))
                {
                    if slot.is_some_and(|requested| requested as usize != existing) {
                        return Err(DebugError::config(
                            "requested hardware breakpoint address already occupies a different slot",
                            json!({
                                "core_index": core_index,
                                "address": address,
                                "existing_slot": existing,
                                "requested_slot": slot,
                            }),
                        ));
                    }
                    existing
                } else if let Some(requested) = slot {
                    let selected = requested as usize;
                    if let Some(occupied) = before[selected].address {
                        return Err(DebugError::config(
                            "requested hardware breakpoint slot is already occupied",
                            json!({
                                "core_index": core_index,
                                "slot": requested,
                                "address": occupied,
                            }),
                        ));
                    }
                    selected
                } else {
                    before
                        .iter()
                        .position(|entry| entry.address.is_none())
                        .ok_or_else(|| {
                            DebugError::new(
                                ErrorCode::CapabilityUnavailable,
                                "no hardware breakpoint slot is available",
                                6,
                                json!({"core_index": core_index, "capacity": capacity}),
                            )
                        })?
                };
                core.set_hw_breakpoint_unit(selected, address.0)
                    .map_err(|error| map_core_error("set hardware breakpoint", error))?;
                Some(selected as u32)
            }
            HardwareBreakpointAction::Clear => {
                let selected = slot.expect("clear request was validated") as usize;
                if before[selected].address.is_some() {
                    CoreInterface::clear_hw_breakpoint(&mut core, selected)
                        .map_err(|error| map_core_error("clear hardware breakpoint", error))?;
                }
                Some(selected as u32)
            }
        };
        if action == HardwareBreakpointAction::ClearAll {
            for active_slot in before.iter().filter(|entry| entry.address.is_some()) {
                CoreInterface::clear_hw_breakpoint(&mut core, active_slot.index as usize)
                    .map_err(|error| map_core_error("clear all hardware breakpoints", error))?;
            }
        }
        let after = native_hardware_breakpoint_slots(&mut core, capacity)?;
        let final_status = core
            .status()
            .map_err(|error| map_core_error("read core state after breakpoint operation", error))?;
        let state = live_core_state(index, final_status).map_err(|error| {
            map_core_error("determine core state after breakpoint operation", error)
        })?;
        let observation = HardwareBreakpointObservation {
            index: core_index,
            name: core_name,
            architecture,
            action,
            original_state,
            state,
            capacity,
            requested_address: address,
            requested_slot: slot,
            affected_slot,
            changed: before != after,
            before,
            after,
        };
        validate_hardware_breakpoint_observation(&target_info, &observation).map_err(
            |problem| {
                DebugError::new(
                    ErrorCode::ProtocolError,
                    "probe-rs returned an invalid hardware-breakpoint observation",
                    6,
                    json!({"problem": problem, "core": observation}),
                )
            },
        )?;
        Ok(observation)
    }

    fn read_registers(
        &mut self,
        session: &SessionInfo,
        core_index: u32,
        names: &[String],
    ) -> Result<RegisterCoreObservation> {
        let index = core_index as usize;
        let (core_name, architecture) = self
            .target
            .cores
            .get(index)
            .map(|core| {
                (
                    core.name.clone(),
                    format!("{:?}", core.core_type).to_ascii_lowercase(),
                )
            })
            .ok_or_else(|| {
                DebugError::config(
                    "requested core index is outside the target core inventory",
                    json!({
                        "core_index": core_index,
                        "core_count": self.target.cores.len(),
                    }),
                )
            })?;
        let active = self.ensure_session_mut(session)?;
        if active.reset_halted || !active.restore_before_disconnect.is_empty() {
            return Err(DebugError::new(
                ErrorCode::ProtocolError,
                "cannot read registers while core restoration is pending",
                6,
                json!({"session_id": session.session_id}),
            ));
        }

        let selected = {
            let core = active.session.core(index).map_err(|error| match error {
                probe_rs::Error::CoreDisabled(_) => DebugError::new(
                    ErrorCode::CapabilityUnavailable,
                    "requested target core is disabled",
                    6,
                    json!({"core_index": core_index}),
                ),
                other => map_core_error("attach core for register read", other),
            })?;
            let available = core
                .registers()
                .all_registers()
                .copied()
                .collect::<Vec<_>>();
            select_probe_registers(&available, names, core_index)?
        };
        let capture = state_preserving_core_capture(active, index, "register read", |core| {
            let mut readings = Vec::with_capacity(selected.len());
            for register in &selected {
                let value = core.read_core_reg::<RegisterValue>(register.id())?;
                readings.push(probe_register_reading(register, value));
            }
            Ok(readings)
        })?;
        Ok(RegisterCoreObservation {
            index: core_index,
            name: core_name,
            architecture,
            original_state: capture.original_state,
            captured_state: CoreState::Halted,
            state: capture.restored_state,
            halt_reason: halt_reason(capture.captured_status),
            registers: capture.value,
        })
    }

    fn plan_memory_read(
        &self,
        core_index: u32,
        start: Address,
        length: u64,
    ) -> Result<MemoryReadRange> {
        plan_probe_memory_read(&self.target, core_index, start, length)
    }

    fn read_memory(
        &mut self,
        session: &SessionInfo,
        core_index: u32,
        range: &MemoryReadRange,
    ) -> Result<MemoryReadResult> {
        let planned = self.plan_memory_read(core_index, range.start, range.length)?;
        if &planned != range {
            return Err(DebugError::new(
                ErrorCode::ProtocolError,
                "memory read range changed after planning",
                6,
                json!({"planned": planned, "received": range}),
            ));
        }
        let index = core_index as usize;
        let (core_name, architecture) = self
            .target
            .cores
            .get(index)
            .map(|core| {
                (
                    core.name.clone(),
                    format!("{:?}", core.core_type).to_ascii_lowercase(),
                )
            })
            .ok_or_else(|| {
                DebugError::config(
                    "requested core index is outside the target core inventory",
                    json!({
                        "core_index": core_index,
                        "core_count": self.target.cores.len(),
                    }),
                )
            })?;
        let byte_count = usize::try_from(range.length).expect("bounded memory length fits usize");
        let active = self.ensure_session_mut(session)?;
        let capture = state_preserving_core_capture(active, index, "memory read", |core| {
            let mut bytes = vec![0_u8; byte_count];
            core.read_8(range.start.0, &mut bytes)?;
            Ok(bytes)
        })?;
        Ok(MemoryReadResult {
            core: MemoryCoreObservation {
                index: core_index,
                name: core_name,
                architecture,
                original_state: capture.original_state,
                captured_state: CoreState::Halted,
                state: capture.restored_state,
                halt_reason: halt_reason(capture.captured_status),
            },
            range: range.clone(),
            bytes: capture.value,
        })
    }

    fn disconnect(&mut self, session: &SessionInfo) -> Result<()> {
        self.ensure_session(session)?;
        let active = self.active.as_mut().expect("active session was validated");
        if active.reset_halted {
            active
                .session
                .core(0)
                .and_then(|mut core| {
                    core.run()?;
                    let state = live_core_state(0, core.status()?)?;
                    if state != CoreState::Running {
                        return Err(probe_rs::Error::GenericCoreError(format!(
                            "core 0 resumed as {state:?}, expected Running"
                        )));
                    }
                    Ok(())
                })
                .map_err(|error| map_core_error("resume core before disconnect", error))?;
            active.reset_halted = false;
        }
        restore_pending_core_states(active)
            .map_err(|error| map_core_error("restore core states before disconnect", error))?;
        self.active.take();
        Ok(())
    }
}

fn state_preserving_core_capture<T>(
    active: &mut NativeSession,
    index: usize,
    operation: &str,
    capture: impl FnOnce(&mut probe_rs::Core<'_>) -> std::result::Result<T, probe_rs::Error>,
) -> Result<StatePreservingCapture<T>> {
    if active.reset_halted || !active.restore_before_disconnect.is_empty() {
        return Err(DebugError::new(
            ErrorCode::ProtocolError,
            format!("cannot perform {operation} while core restoration is pending"),
            6,
            json!({"session_id": active.id, "core_index": index}),
        ));
    }

    let original_state = {
        let mut core = active.session.core(index).map_err(|error| match error {
            probe_rs::Error::CoreDisabled(_) => DebugError::new(
                ErrorCode::CapabilityUnavailable,
                "requested target core is disabled",
                6,
                json!({"core_index": index}),
            ),
            other => map_core_error(&format!("attach core for {operation}"), other),
        })?;
        let status = core
            .status()
            .map_err(|error| map_core_error("read original core state", error))?;
        live_core_state(index, status)
            .map_err(|error| map_core_error("determine original core state", error))?
    };
    active
        .restore_before_disconnect
        .insert(index, original_state);

    if original_state == CoreState::Running
        && let Err(error) = active
            .session
            .core(index)
            .and_then(|mut core| core.halt(CORE_OPERATION_TIMEOUT))
    {
        return Err(restore_after_capture_error(
            active,
            &format!("halt core for {operation}"),
            error,
        ));
    }

    let captured = (|| -> std::result::Result<(CoreStatus, T), probe_rs::Error> {
        let mut core = active.session.core(index)?;
        let captured_status = core.status()?;
        if live_core_state(index, captured_status)? != CoreState::Halted {
            return Err(probe_rs::Error::GenericCoreError(format!(
                "core {index} was not halted during {operation}"
            )));
        }
        let value = capture(&mut core)?;
        Ok((captured_status, value))
    })();
    let (captured_status, value) = match captured {
        Ok(captured) => captured,
        Err(error) => {
            return Err(restore_after_capture_error(active, operation, error));
        }
    };

    let restored_states = restore_pending_core_states(active)
        .map_err(|error| map_core_error(&format!("restore core after {operation}"), error))?;
    let restored_state = restored_states.get(&index).copied().ok_or_else(|| {
        DebugError::new(
            ErrorCode::Internal,
            "core restoration result is missing the selected core",
            10,
            json!({"core_index": index}),
        )
    })?;
    Ok(StatePreservingCapture {
        original_state,
        captured_status,
        restored_state,
        value,
    })
}

fn plan_probe_memory_read(
    target: &Target,
    core_index: u32,
    start: Address,
    length: u64,
) -> Result<MemoryReadRange> {
    let core = target.cores.get(core_index as usize).ok_or_else(|| {
        DebugError::config(
            "requested core index is outside the target core inventory",
            json!({
                "core_index": core_index,
                "core_count": target.cores.len(),
                "target": target.name,
            }),
        )
    })?;
    let end = checked_memory_read_end(start, length)?;
    let mut candidates = Vec::new();
    for memory in &target.memory_map {
        let region = if let Some(region) = memory.as_ram_region() {
            if !region.is_readable() || !region.accessible_by(&core.name) {
                continue;
            }
            Some((
                MemoryRegionKind::Ram,
                region.name.clone(),
                region.range.clone(),
                region.is_alias,
            ))
        } else if let Some(region) = memory.as_nvm_region() {
            if !region.is_readable() || !region.accessible_by(&core.name) {
                continue;
            }
            Some((
                MemoryRegionKind::Nvm,
                region.name.clone(),
                region.range.clone(),
                region.is_alias,
            ))
        } else {
            None
        };
        let Some((kind, name, region_range, is_alias)) = region else {
            continue;
        };
        if region_range.start <= start.0 && end <= region_range.end {
            let Some(region_length) = region_range.end.checked_sub(region_range.start) else {
                continue;
            };
            candidates.push(MemoryReadRange {
                start,
                length,
                region: MemoryRegionInfo {
                    name,
                    kind,
                    start: Address(region_range.start),
                    length: region_length,
                    is_alias,
                },
            });
        }
    }
    let range = match candidates.as_slice() {
        [range] => range.clone(),
        [] => {
            return Err(DebugError::config(
                "memory reads must remain within one readable RAM or NVM region assigned to the selected core",
                json!({
                    "target": target.name,
                    "core_index": core_index,
                    "core_name": core.name,
                    "start": start,
                    "length": length,
                    "generic_or_mmio_regions_allowed": false,
                }),
            ));
        }
        _ => {
            return Err(DebugError::config(
                "memory read range resolves to multiple target regions",
                json!({
                    "target": target.name,
                    "core_index": core_index,
                    "start": start,
                    "length": length,
                    "regions": candidates.iter().map(|range| &range.region).collect::<Vec<_>>(),
                }),
            ));
        }
    };
    validate_memory_read_range(&range).map_err(|problem| {
        DebugError::new(
            ErrorCode::ProtocolError,
            "probe-rs target returned an invalid memory region",
            6,
            json!({"target": target.name, "problem": problem, "range": range}),
        )
    })?;
    Ok(range)
}

fn select_probe_registers(
    available: &[CoreRegister],
    names: &[String],
    core_index: u32,
) -> Result<Vec<CoreRegister>> {
    if names.len() > MAX_REGISTER_READS {
        return Err(DebugError::config(
            "too many register names were requested",
            json!({"requested_count": names.len(), "maximum": MAX_REGISTER_READS}),
        ));
    }
    if names.is_empty() {
        if available.len() > MAX_REGISTER_READS {
            return Err(DebugError::config(
                "the target register inventory exceeds the bounded read limit; select register names explicitly",
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
        .map(|register| register.name())
        .collect::<Vec<_>>();
    let mut selected = Vec::with_capacity(names.len());
    let mut selected_ids = std::collections::BTreeSet::new();
    for requested in names {
        let matches = available
            .iter()
            .filter(|register| register_matches_name(register, requested))
            .collect::<Vec<_>>();
        let register = match matches.as_slice() {
            [register] => **register,
            [] => {
                return Err(DebugError::config(
                    "requested register name is not available on the selected core",
                    json!({
                        "core_index": core_index,
                        "requested": requested,
                        "available": available_names,
                    }),
                ));
            }
            _ => {
                return Err(DebugError::config(
                    "requested register name is ambiguous on the selected core",
                    json!({
                        "core_index": core_index,
                        "requested": requested,
                        "matches": matches.iter().map(|item| item.name()).collect::<Vec<_>>(),
                    }),
                ));
            }
        };
        if !selected_ids.insert(register.id()) {
            return Err(DebugError::config(
                "multiple requested names resolve to the same register",
                json!({
                    "core_index": core_index,
                    "requested": requested,
                    "register": register.name(),
                }),
            ));
        }
        selected.push(register);
    }
    Ok(selected)
}

fn register_matches_name(register: &CoreRegister, requested: &str) -> bool {
    register.name().eq_ignore_ascii_case(requested)
        || register
            .roles
            .iter()
            .any(|role| role.to_string().eq_ignore_ascii_case(requested))
}

fn probe_register_reading(register: &CoreRegister, value: RegisterValue) -> RegisterReading {
    let name = register.name().to_string();
    let mut aliases = Vec::new();
    for role in register.roles {
        let alias = role.to_string();
        if !alias.eq_ignore_ascii_case(&name)
            && !aliases
                .iter()
                .any(|existing: &String| existing.eq_ignore_ascii_case(&alias))
        {
            aliases.push(alias);
        }
    }
    let kind = match register.data_type() {
        RegisterDataType::UnsignedInteger(_) => RegisterKind::UnsignedInteger,
        RegisterDataType::FloatingPoint(_) => RegisterKind::FloatingPoint,
    };
    let numeric = match value {
        RegisterValue::U32(value) => value as u128,
        RegisterValue::U64(value) => value as u128,
        RegisterValue::U128(value) => value,
    };
    let bits = register.size_in_bits() as u32;
    let width = bits.div_ceil(4) as usize;
    RegisterReading {
        name,
        aliases,
        id: format!("0x{:04X}", register.id().0),
        bits,
        kind,
        value: format!("0x{numeric:0width$X}"),
    }
}

impl Drop for ProbeRsBackend {
    fn drop(&mut self) {
        let Some(active) = self.active.as_mut() else {
            return;
        };
        if active.reset_halted {
            let resumed = active.session.core(0).and_then(|mut core| {
                core.run()?;
                let state = live_core_state(0, core.status()?)?;
                if state != CoreState::Running {
                    return Err(probe_rs::Error::GenericCoreError(format!(
                        "core 0 resumed as {state:?}, expected Running"
                    )));
                }
                Ok(())
            });
            if resumed.is_ok() {
                active.reset_halted = false;
            }
        }
        let _ = restore_pending_core_states(active);
    }
}

fn restore_pending_core_states(
    active: &mut NativeSession,
) -> std::result::Result<BTreeMap<usize, CoreState>, probe_rs::Error> {
    let pending = std::mem::take(&mut active.restore_before_disconnect);
    let mut restored = BTreeMap::new();
    let mut failed = BTreeMap::new();
    let mut first_error = None;
    for (index, desired_state) in pending {
        let result = (|| {
            let mut core = active.session.core(index)?;
            let current_state = live_core_state(index, core.status()?)?;
            if current_state != desired_state {
                match desired_state {
                    CoreState::Running => core.run()?,
                    CoreState::Halted => {
                        core.halt(CORE_OPERATION_TIMEOUT)?;
                    }
                    CoreState::Unknown => {
                        return Err(probe_rs::Error::GenericCoreError(format!(
                            "cannot restore core {index} to an unknown state"
                        )));
                    }
                }
            }
            let final_state = live_core_state(index, core.status()?)?;
            if final_state != desired_state {
                return Err(probe_rs::Error::GenericCoreError(format!(
                    "core {index} restored as {final_state:?}, expected {desired_state:?}"
                )));
            }
            Ok(final_state)
        })();
        match result {
            Ok(final_state) => {
                restored.insert(index, final_state);
            }
            Err(error) => {
                failed.insert(index, desired_state);
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
    }
    active.restore_before_disconnect = failed;
    match first_error {
        Some(error) => Err(error),
        None => Ok(restored),
    }
}

fn supports_native_hardware_breakpoints(target: &Target) -> bool {
    target.name.eq_ignore_ascii_case("esp32s3")
        && target
            .cores
            .first()
            .is_some_and(|core| core.core_type == CoreType::Xtensa)
}

fn native_hardware_breakpoint_slots(
    core: &mut probe_rs::Core<'_>,
    expected_capacity: u32,
) -> Result<Vec<HardwareBreakpointSlot>> {
    let addresses = CoreInterface::hw_breakpoints(core)
        .map_err(|error| map_core_error("read hardware breakpoint slots", error))?;
    if addresses.len() != expected_capacity as usize {
        return Err(DebugError::new(
            ErrorCode::ProtocolError,
            "hardware breakpoint capacity changed within the active session",
            6,
            json!({
                "expected_capacity": expected_capacity,
                "received_capacity": addresses.len(),
            }),
        ));
    }
    Ok(addresses
        .into_iter()
        .enumerate()
        .map(|(index, address)| HardwareBreakpointSlot {
            index: index as u32,
            address: address.map(Address),
        })
        .collect())
}

#[allow(clippy::too_many_arguments)]
fn validated_continue_until_halt_observation(
    target: &TargetInfo,
    continuation: CoreExecutionObservation,
    outcome: ContinueUntilHaltOutcome,
    state: CoreState,
    halt_reason: Option<String>,
    options: ContinueUntilHaltOptions,
    started: Instant,
    poll_count: u32,
) -> Result<ContinueUntilHaltObservation> {
    let observation = ContinueUntilHaltObservation {
        continuation,
        outcome,
        state,
        halt_reason,
        timeout_ms: options.timeout_ms,
        poll_interval_ms: options.poll_interval_ms,
        elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        poll_count,
    };
    validate_continue_until_halt_observation(target, &observation).map_err(|problem| {
        DebugError::new(
            ErrorCode::ProtocolError,
            "probe-rs returned an invalid continue-until-halt observation",
            6,
            json!({"problem": problem, "observation": observation}),
        )
    })?;
    Ok(observation)
}

fn restore_after_capture_error(
    active: &mut NativeSession,
    operation: &str,
    error: probe_rs::Error,
) -> DebugError {
    let primary = map_core_error(operation, error);
    // A failed first restoration remains pending. `disconnect` retries it and
    // reports a cleanup error only if that final attempt also fails.
    if let Ok(restored_states) = restore_pending_core_states(active)
        && restored_states.get(&0) == Some(&CoreState::Running)
    {
        active.reset_halted = false;
    }
    primary
}

fn select_flash_algorithm<'a>(
    target: &'a Target,
    region: &NvmRegion,
) -> Result<&'a RawFlashAlgorithm> {
    let core_name = region.cores.first().ok_or_else(|| {
        DebugError::new(
            ErrorCode::CapabilityUnavailable,
            "flash region is not assigned to a target core",
            6,
            json!({"target": target.name, "region": region.range}),
        )
    })?;
    let algorithms = target
        .flash_algorithms
        .iter()
        .filter(|algorithm| {
            algorithm.flash_properties.address_range.start <= region.range.start
                && region.range.end <= algorithm.flash_properties.address_range.end
                && (algorithm.cores.is_empty() || algorithm.cores.contains(core_name))
        })
        .collect::<Vec<_>>();
    match algorithms.as_slice() {
        [algorithm] => Ok(*algorithm),
        [] => Err(DebugError::new(
            ErrorCode::CapabilityUnavailable,
            "target has no flash algorithm for the selected memory region",
            6,
            json!({"target": target.name, "region": region.range}),
        )),
        many => {
            let defaults = many
                .iter()
                .copied()
                .filter(|algorithm| algorithm.default)
                .collect::<Vec<_>>();
            match defaults.as_slice() {
                [algorithm] => Ok(*algorithm),
                _ => Err(DebugError::new(
                    ErrorCode::CapabilityUnavailable,
                    "target flash algorithm selection is ambiguous",
                    6,
                    json!({
                        "target": target.name,
                        "region": region.range,
                        "algorithms": many.iter().map(|item| &item.name).collect::<Vec<_>>(),
                    }),
                )),
            }
        }
    }
}

fn affected_erase_ranges(
    algorithm: &RawFlashAlgorithm,
    write_start: u64,
    write_end: u64,
) -> Result<Vec<FlashRange>> {
    let properties = &algorithm.flash_properties;
    if properties.sectors.is_empty() {
        return Err(DebugError::new(
            ErrorCode::CapabilityUnavailable,
            "flash algorithm does not describe erase sectors",
            6,
            json!({"algorithm": algorithm.name}),
        ));
    }

    let mut sectors = Vec::<(u64, u64)>::new();
    let mut cursor = write_start;
    while cursor < write_end {
        let offset = cursor
            .checked_sub(properties.address_range.start)
            .ok_or_else(|| invalid_sector_layout(algorithm, cursor))?;
        let description = properties
            .sectors
            .iter()
            .rfind(|sector| sector.address <= offset)
            .ok_or_else(|| invalid_sector_layout(algorithm, cursor))?;
        if description.size == 0 {
            return Err(invalid_sector_layout(algorithm, cursor));
        }
        let sector_index = (offset - description.address) / description.size;
        let sector_start = properties
            .address_range
            .start
            .checked_add(description.address)
            .and_then(|value| {
                sector_index
                    .checked_mul(description.size)
                    .and_then(|offset| value.checked_add(offset))
            })
            .ok_or_else(|| invalid_sector_layout(algorithm, cursor))?;
        let sector_end = sector_start
            .checked_add(description.size)
            .ok_or_else(|| invalid_sector_layout(algorithm, cursor))?;
        if sector_end > properties.address_range.end || sector_end <= cursor {
            return Err(invalid_sector_layout(algorithm, cursor));
        }
        sectors.push((sector_start, sector_end));
        cursor = sector_end;
    }

    let mut merged = Vec::<FlashRange>::new();
    for (start, end) in sectors {
        if let Some(previous) = merged.last_mut()
            && previous.start.0.checked_add(previous.length) == Some(start)
        {
            previous.length += end - start;
        } else {
            merged.push(FlashRange {
                start: Address(start),
                length: end - start,
            });
        }
    }
    Ok(merged)
}

fn merge_flash_ranges(mut ranges: Vec<FlashRange>) -> Result<Vec<FlashRange>> {
    ranges.sort_by_key(|range| range.start.0);
    let mut merged = Vec::<FlashRange>::new();
    for range in ranges {
        let end = range.start.0.checked_add(range.length).ok_or_else(|| {
            DebugError::new(
                ErrorCode::Internal,
                "erase range overflows the target address space",
                10,
                json!({"range": range}),
            )
        })?;
        if let Some(previous) = merged.last_mut() {
            let previous_end = previous
                .start
                .0
                .checked_add(previous.length)
                .ok_or_else(|| {
                    DebugError::new(
                        ErrorCode::Internal,
                        "erase range overflows the target address space",
                        10,
                        json!({"range": previous}),
                    )
                })?;
            if range.start.0 <= previous_end {
                previous.length = previous_end.max(end) - previous.start.0;
                continue;
            }
        }
        merged.push(range);
    }
    Ok(merged)
}

fn invalid_sector_layout(algorithm: &RawFlashAlgorithm, address: u64) -> DebugError {
    DebugError::new(
        ErrorCode::CapabilityUnavailable,
        "flash algorithm contains an invalid sector layout",
        6,
        json!({"algorithm": algorithm.name, "address": Address(address)}),
    )
}

fn inactive_session(session: &SessionInfo) -> DebugError {
    DebugError::unavailable(
        ErrorCode::ProbeUnavailable,
        "probe-rs session is not active or its identity does not match",
        json!({"session_id": session.session_id}),
    )
}

fn map_registry_error(error: RegistryError) -> DebugError {
    match error {
        RegistryError::ChipNotFound(requested) => DebugError::unavailable(
            ErrorCode::TargetUnavailable,
            "requested target is not present in the probe-rs registry",
            json!({"requested": requested}),
        ),
        RegistryError::ChipNotUnique(requested, suggestions) => DebugError::unavailable(
            ErrorCode::TargetAmbiguous,
            "requested target name is ambiguous",
            json!({"requested": requested, "suggestions": suggestions}),
        ),
        other => protocol_error("load target registry", other.to_string()),
    }
}

fn map_probe_error(operation: &str, error: DebugProbeError) -> DebugError {
    let cause = error.to_string();
    match &error {
        DebugProbeError::Timeout => timeout_error(operation, cause),
        DebugProbeError::Usb(source) if source.kind() == std::io::ErrorKind::PermissionDenied => {
            DebugError::new(
                ErrorCode::PermissionDenied,
                "operating system denied access to the planned probe",
                8,
                json!({"cause": cause}),
            )
        }
        DebugProbeError::TargetNotFound => DebugError::unavailable(
            ErrorCode::TargetUnavailable,
            "probe could not find the planned target",
            json!({"cause": cause}),
        ),
        DebugProbeError::ProbeCouldNotBeCreated(ProbeCreationError::NotFound) => {
            DebugError::unavailable(
                ErrorCode::ProbeUnavailable,
                "planned probe could not be opened because it disappeared",
                json!({"cause": cause}),
            )
        }
        DebugProbeError::ProbeCouldNotBeCreated(ProbeCreationError::CouldNotOpen) => {
            DebugError::new(
                ErrorCode::PermissionDenied,
                "planned probe is present but could not be opened",
                8,
                json!({"cause": cause}),
            )
        }
        DebugProbeError::ProbeCouldNotBeCreated(ProbeCreationError::Usb(source))
            if source.kind() == std::io::ErrorKind::PermissionDenied =>
        {
            DebugError::new(
                ErrorCode::PermissionDenied,
                "operating system denied access to the planned probe",
                8,
                json!({"cause": cause}),
            )
        }
        _ => protocol_error(operation, cause),
    }
}

fn map_core_error(operation: &str, error: probe_rs::Error) -> DebugError {
    let cause = error.to_string();
    match error {
        probe_rs::Error::Timeout => timeout_error(operation, cause),
        probe_rs::Error::Probe(error) => map_probe_error(operation, error),
        probe_rs::Error::MissingPermissions(_) => DebugError::new(
            ErrorCode::PermissionDenied,
            format!("{operation} requires a permission this workflow does not grant"),
            8,
            json!({"operation": operation, "cause": cause}),
        ),
        probe_rs::Error::ChipNotFound(error) => map_registry_error(error),
        _ => protocol_error(operation, cause),
    }
}

fn map_flash_error(operation: &str, error: FlashError) -> DebugError {
    match error {
        FlashError::Verify => DebugError::verification(
            "firmware read-back did not match the planned image",
            json!({"operation": operation}),
        ),
        FlashError::Core(error) | FlashError::ResetAndHalt(error) | FlashError::Run(error) => {
            map_core_error(operation, error)
        }
        error => protocol_error(operation, error.to_string()),
    }
}

fn protocol_error(operation: &str, cause: String) -> DebugError {
    DebugError::new(
        ErrorCode::ProtocolError,
        format!("probe-rs failed to {operation}"),
        6,
        json!({"backend": "probe-rs", "operation": operation, "cause": cause}),
    )
}

fn timeout_error(operation: &str, cause: String) -> DebugError {
    let mut error = DebugError::new(
        ErrorCode::Timeout,
        format!("probe-rs timed out while attempting to {operation}"),
        5,
        json!({"backend": "probe-rs", "operation": operation, "cause": cause}),
    );
    error.retryable = true;
    error
}

fn map_core_state(status: CoreStatus) -> CoreState {
    match status {
        CoreStatus::Running | CoreStatus::Sleeping => CoreState::Running,
        CoreStatus::Halted(_) | CoreStatus::LockedUp => CoreState::Halted,
        CoreStatus::Unknown => CoreState::Unknown,
    }
}

fn live_core_state(
    index: usize,
    status: CoreStatus,
) -> std::result::Result<CoreState, probe_rs::Error> {
    match status {
        CoreStatus::Running | CoreStatus::Sleeping => Ok(CoreState::Running),
        CoreStatus::Halted(_) => Ok(CoreState::Halted),
        CoreStatus::LockedUp => Err(probe_rs::Error::GenericCoreError(format!(
            "core {index} is locked up"
        ))),
        CoreStatus::Unknown => Err(probe_rs::Error::GenericCoreError(format!(
            "core {index} reported an unknown state"
        ))),
    }
}

fn halt_reason(status: CoreStatus) -> Option<String> {
    let CoreStatus::Halted(reason) = status else {
        return None;
    };
    let reason = match reason {
        HaltReason::Multiple => "multiple",
        HaltReason::Breakpoint(_) => "breakpoint",
        HaltReason::Exception => "exception",
        HaltReason::Watchpoint => "watchpoint",
        HaltReason::Step => "step",
        HaltReason::Request => "request",
        HaltReason::External => "external",
        HaltReason::Unknown => "unknown",
    };
    Some(reason.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn esp32s3_advertises_accepted_session_controls_before_attach() {
        let backend = ProbeRsBackend::new("esp32s3").unwrap();

        assert!(backend.capabilities().step);
        assert!(backend.capabilities().continue_execution);
        assert!(backend.capabilities().continue_until_halt);
        assert_eq!(backend.capabilities().hardware_breakpoints, 0);
        assert!(supports_native_hardware_breakpoints(&backend.target));
        assert_eq!(backend.target().core_count, 2);
    }

    #[test]
    fn known_target_resolves_write_and_sector_erase_ranges() {
        let backend = ProbeRsBackend::new("STM32G431CB").unwrap();
        let layout = backend
            .plan_flash_ranges(43, Some(Address(0x0800_0101)))
            .unwrap();

        assert_eq!(layout.write_ranges[0].start, Address(0x0800_0101));
        assert_eq!(layout.write_ranges[0].length, 43);
        assert_eq!(layout.erase_ranges[0].start, Address(0x0800_0000));
        assert!(layout.erase_ranges[0].length >= 43);
    }

    #[test]
    fn raw_bin_requires_an_explicit_native_base_address() {
        let backend = ProbeRsBackend::new("STM32G431CB").unwrap();
        let error = backend.plan_flash_ranges(16, None).unwrap_err();

        assert_eq!(error.code, ErrorCode::ConfigInvalid);
    }

    #[test]
    fn native_plan_rejects_a_range_outside_flash() {
        let backend = ProbeRsBackend::new("STM32G431CB").unwrap();
        let error = backend
            .plan_flash_ranges(16, Some(Address(0x2000_0000)))
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::ConfigInvalid);
    }

    #[test]
    fn native_plan_rejects_option_bytes() {
        let backend = ProbeRsBackend::new("STM32G431CB").unwrap();
        let error = backend
            .plan_flash_ranges(16, Some(Address(0x1fff_7800)))
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::ConfigInvalid);
    }

    #[test]
    fn segmented_plan_sorts_ranges_and_merges_erase_impact() {
        let backend = ProbeRsBackend::new("esp32s3").unwrap();
        let layout = backend
            .plan_segmented_flash_ranges(&[
                FlashRange {
                    start: Address(0x1_0000),
                    length: 0x200,
                },
                FlashRange {
                    start: Address(0),
                    length: 0x100,
                },
                FlashRange {
                    start: Address(0x8000),
                    length: 0xC00,
                },
            ])
            .unwrap();

        assert_eq!(layout.write_ranges[0].start, Address(0));
        assert_eq!(layout.write_ranges[1].start, Address(0x8000));
        assert_eq!(layout.write_ranges[2].start, Address(0x1_0000));
        assert_eq!(layout.erase_ranges.len(), 1);
        assert_eq!(layout.erase_ranges[0].start, Address(0));
        assert_eq!(layout.erase_ranges[0].length, 0x2_0000);
    }

    #[test]
    fn segmented_plan_accepts_nrf52840_uicr_non_boot_nvm() {
        let backend = ProbeRsBackend::new("nRF52840_xxAA").unwrap();
        let layout = backend
            .plan_segmented_flash_ranges(&[
                FlashRange {
                    start: Address(0),
                    length: 0x20,
                },
                FlashRange {
                    start: Address(0x1000_1014),
                    length: 8,
                },
            ])
            .unwrap();

        assert_eq!(layout.write_ranges.len(), 2);
        assert_eq!(layout.erase_ranges.len(), 2);
        assert_eq!(layout.erase_ranges[0].start, Address(0));
        assert_eq!(layout.erase_ranges[0].length, 0x1000);
        assert_eq!(layout.erase_ranges[1].start, Address(0x1000_1000));
        assert_eq!(layout.erase_ranges[1].length, 0x1000);
    }

    #[test]
    fn nrf52840_candidate_accepts_code_hex_but_keeps_uicr_disabled() {
        let backend = ProbeRsBackend::new("nRF52840_xxAA").unwrap();

        assert!(backend.capabilities().flash);
        assert!(backend.capabilities().segmented_flash);
        assert!(backend.capabilities().intel_hex_flash);
        assert!(!backend.capabilities().non_boot_nvm_flash);
        assert_eq!(backend.target().core_count, 1);
    }

    #[test]
    fn segmented_plan_rejects_overlapping_ranges() {
        let backend = ProbeRsBackend::new("esp32s3").unwrap();
        let error = backend
            .plan_segmented_flash_ranges(&[
                FlashRange {
                    start: Address(0x1_0000),
                    length: 0x200,
                },
                FlashRange {
                    start: Address(0x1_0100),
                    length: 0x200,
                },
            ])
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::ConfigInvalid);
    }

    #[test]
    fn idf_options_reject_capacity_beyond_the_physical_boot_window() {
        let backend = ProbeRsBackend::new("esp32s3").unwrap();
        let error = backend
            .validate_firmware_image_options(&FirmwareImageOptions {
                generator: "espflash-4.5.0".to_string(),
                target_chip: "esp32s3".to_string(),
                flash_size: 128 * 1024 * 1024,
                chip_revision: 0,
            })
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert_eq!(error.details["maximum_flash_size"], 64 * 1024 * 1024);
    }

    #[test]
    fn target_errors_are_structured() {
        let error = match ProbeRsBackend::new("definitely-not-a-real-target") {
            Ok(_) => panic!("unknown target unexpectedly resolved"),
            Err(error) => error,
        };

        assert_eq!(error.code, ErrorCode::TargetUnavailable);
    }

    #[test]
    fn espressif_plugin_registers_targets() {
        let backend = ProbeRsBackend::new("esp32s3").unwrap();

        assert_eq!(backend.target().name, "esp32s3");
        assert_eq!(backend.target().core_count, 2);
        assert!(backend.capabilities().segmented_flash);
        assert!(backend.capabilities().multi_core_post_flash);
        assert!(backend.capabilities().reset);
        assert!(backend.capabilities().memory_read);
        assert!(backend.capabilities().core_status);
        assert!(!backend.capabilities().post_disconnect_core_state);
        assert!(
            backend
                .volatile_target_state_notes()
                .iter()
                .any(|note| note.contains("halted before attach"))
        );
        assert!(
            backend
                .volatile_target_state_notes()
                .iter()
                .any(|note| note.contains("watchdogs"))
        );
    }

    #[test]
    fn esp32s3_memory_plan_accepts_ram_and_nvm_but_rejects_generic_regions() {
        let backend = ProbeRsBackend::new("esp32s3").unwrap();

        let ram = backend
            .plan_memory_read(0, Address(0x3fc8_8000), 16)
            .unwrap();
        let nvm = backend
            .plan_memory_read(0, Address(0x4200_0000), 16)
            .unwrap();
        let generic = backend
            .plan_memory_read(0, Address(0x3ff0_0000), 16)
            .unwrap_err();

        assert_eq!(ram.region.kind, MemoryRegionKind::Ram);
        assert_eq!(nvm.region.kind, MemoryRegionKind::Nvm);
        assert_eq!(generic.code, ErrorCode::ConfigInvalid);
        assert_eq!(generic.details["generic_or_mmio_regions_allowed"], false);
    }

    #[test]
    fn esp32s3_memory_plan_rejects_cross_region_unbounded_and_overflowing_reads() {
        let backend = ProbeRsBackend::new("esp32s3").unwrap();

        let crossing = backend
            .plan_memory_read(0, Address(0x3fce_fff8), 16)
            .unwrap_err();
        let empty = backend
            .plan_memory_read(0, Address(0x3fc8_8000), 0)
            .unwrap_err();
        let oversized = backend
            .plan_memory_read(
                0,
                Address(0x3fc8_8000),
                crate::model::MAX_INLINE_MEMORY_READ_BYTES + 1,
            )
            .unwrap_err();
        let overflowing = backend
            .plan_memory_read(0, Address(u64::MAX), 1)
            .unwrap_err();

        assert_eq!(crossing.code, ErrorCode::ConfigInvalid);
        assert_eq!(empty.code, ErrorCode::ConfigInvalid);
        assert_eq!(oversized.code, ErrorCode::ConfigInvalid);
        assert_eq!(
            oversized.details["maximum"],
            crate::model::MAX_INLINE_MEMORY_READ_BYTES
        );
        assert_eq!(overflowing.code, ErrorCode::ConfigInvalid);
    }

    #[test]
    fn esp32s3_post_flash_controls_require_an_active_session() {
        let mut backend = ProbeRsBackend::new("esp32s3").unwrap();
        let session = SessionInfo {
            session_id: "not-attached".to_string(),
            backend: backend.name().to_string(),
            probe: ProbeInfo {
                id: "not-attached".to_string(),
                vendor_id: 0,
                product_id: 0,
                serial: Some("not-attached".to_string()),
                product: None,
                interface: None,
                probe_type: None,
                accessible: true,
            },
            target: backend.target().clone(),
            capabilities: backend.capabilities().clone(),
        };

        let reset_error = backend.reset(&session).unwrap_err();
        assert_eq!(reset_error.code, ErrorCode::ProbeUnavailable);

        let snapshot_error = backend.capture_post_flash_snapshot(&session).unwrap_err();
        assert_eq!(snapshot_error.code, ErrorCode::ProbeUnavailable);
    }

    #[test]
    fn live_snapshot_rejects_locked_up_and_unknown_states() {
        assert!(live_core_state(0, CoreStatus::LockedUp).is_err());
        assert!(live_core_state(1, CoreStatus::Unknown).is_err());
        assert_eq!(
            live_core_state(0, CoreStatus::Running).unwrap(),
            CoreState::Running
        );
        assert_eq!(
            live_core_state(0, CoreStatus::Halted(HaltReason::Request)).unwrap(),
            CoreState::Halted
        );
    }

    #[test]
    fn native_register_selection_resolves_architecture_roles() {
        use probe_rs::architecture::xtensa::registers::{PC, RA, SP};

        let selected =
            select_probe_registers(&[RA, SP, PC], &["lr".to_string(), "pc".to_string()], 0)
                .unwrap();

        assert_eq!(selected, vec![RA, PC]);
        let reading = probe_register_reading(&RA, RegisterValue::U32(0x4037_8695));
        assert_eq!(reading.name, "a0");
        assert_eq!(reading.aliases, vec!["LR"]);
        assert_eq!(reading.id, "0x0000");
        assert_eq!(reading.bits, 32);
        assert_eq!(reading.value, "0x40378695");
    }

    #[test]
    fn native_register_selection_rejects_duplicate_aliases() {
        use probe_rs::architecture::xtensa::registers::RA;

        let error =
            select_probe_registers(&[RA], &["a0".to_string(), "lr".to_string()], 0).unwrap_err();

        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert_eq!(error.details["register"], "a0");
    }

    #[test]
    fn package_variant_matches_its_canonical_target() {
        let backend = ProbeRsBackend::new("STM32G431CBTx").unwrap();

        assert_eq!(backend.target().name, "STM32G431CBTx");
        assert!(backend.matches_target("STM32G431CBTx"));
    }

    #[test]
    fn native_flash_requires_a_probe_serial_number() {
        let backend = ProbeRsBackend::new("STM32G431CB").unwrap();
        let probe = ProbeInfo {
            id: "0483:374f".to_string(),
            vendor_id: 0x0483,
            product_id: 0x374f,
            serial: None,
            product: Some("ST-Link".to_string()),
            interface: None,
            probe_type: Some("ST-Link".to_string()),
            accessible: true,
        };

        assert!(!backend.probe_identity_is_stable(&probe));
    }
}
