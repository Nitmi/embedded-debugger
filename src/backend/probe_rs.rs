use std::{collections::BTreeMap, sync::Once, time::Duration};

use probe_rs::{
    CoreStatus, HaltReason, Permissions, Session, Target,
    config::{NvmRegion, RawFlashAlgorithm, Registry, RegistryError},
    flashing::{DownloadOptions, FlashError, FlashProgress},
    probe::{
        DebugProbeError, DebugProbeSelector, ProbeCreationError,
        list::{Accessibility, Lister},
    },
};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    backend::DebugBackend,
    error::{DebugError, ErrorCode, Result},
    model::{
        Address, Capabilities, CoreObservation, CoreSnapshot, CoreState, FlashLayout, FlashRange,
        FlashReport, ProbeInfo, SessionInfo, TargetInfo,
    },
};

const CORE_OPERATION_TIMEOUT: Duration = Duration::from_secs(2);
static REGISTER_PROBE_RS_PLUGINS: Once = Once::new();

fn register_probe_rs_plugins() {
    REGISTER_PROBE_RS_PLUGINS.call_once(probe_rs_espressif::register_plugin);
}

struct ProgrammedImage {
    base_address: Address,
    bytes: Vec<u8>,
    sha256: String,
}

struct NativeSession {
    id: String,
    probe: ProbeInfo,
    session: Session,
    programmed: Option<ProgrammedImage>,
    reset_halted: bool,
    restore_before_disconnect: BTreeMap<usize, CoreState>,
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
        let flash = !target.flash_algorithms.is_empty();
        let target_info = TargetInfo {
            name: target.name.clone(),
            architecture: format!("{:?}", target.cores[0].core_type).to_ascii_lowercase(),
            core_count: target.cores.len() as u32,
        };
        let capabilities = Capabilities {
            flash,
            verify: flash,
            halt: true,
            run: true,
            reset: single_core,
            step: single_core,
            register_read: true,
            memory_read: single_core,
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
        let native_session = probe
            .attach(self.target.clone(), Permissions::default())
            .map_err(|error| map_core_error("attach target", error))?;
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
        firmware: &[u8],
        base_address: Address,
        firmware_sha256: &str,
    ) -> Result<FlashReport> {
        self.plan_flash_ranges(firmware.len() as u64, Some(base_address))?;
        let actual_sha256 = hex::encode(Sha256::digest(firmware));
        if actual_sha256 != firmware_sha256 {
            return Err(DebugError::new(
                ErrorCode::PlanStale,
                "firmware bytes do not match the planned SHA-256",
                2,
                json!({"planned": firmware_sha256, "actual": actual_sha256}),
            ));
        }

        let active = self.ensure_session_mut(session)?;
        let mut loader = active.session.target().flash_loader();
        loader
            .add_data(base_address.0, firmware)
            .map_err(|error| map_flash_error("stage firmware", error))?;
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
            base_address,
            bytes: firmware.to_vec(),
            sha256: firmware_sha256.to_string(),
        });

        Ok(FlashReport {
            bytes_programmed: firmware.len() as u64,
            firmware_sha256: firmware_sha256.to_string(),
            verified: false,
        })
    }

    fn verify(&mut self, session: &SessionInfo, firmware_sha256: &str) -> Result<bool> {
        let active = self.ensure_session_mut(session)?;
        let image = active.programmed.as_ref().ok_or_else(|| {
            DebugError::new(
                ErrorCode::ProtocolError,
                "cannot verify before firmware has been programmed",
                6,
                json!({"session_id": session.session_id}),
            )
        })?;
        if image.sha256 != firmware_sha256 {
            return Err(DebugError::new(
                ErrorCode::PlanStale,
                "verification digest differs from the programmed firmware",
                2,
                json!({"programmed": image.sha256, "received": firmware_sha256}),
            ));
        }
        let mut loader = active.session.target().flash_loader();
        loader
            .add_data(image.base_address.0, &image.bytes)
            .map_err(|error| map_flash_error("stage verification", error))?;
        match loader.verify(&mut active.session, &mut FlashProgress::empty()) {
            Ok(()) => Ok(true),
            Err(FlashError::Verify) => Ok(false),
            Err(error) => Err(map_flash_error("verify firmware", error)),
        }
    }

    fn reset(&mut self, session: &SessionInfo) -> Result<()> {
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
        active.reset_halted = false;
        let final_status = core
            .status()
            .map_err(|error| map_core_error("read resumed core status", error))?;

        Ok(CoreSnapshot {
            captured_state: map_core_state(captured_status),
            state: map_core_state(final_status),
            pc: Address(pc),
            sp: Address(sp),
            registers: BTreeMap::from([("lr".to_string(), Address(lr))]),
            halt_reason: halt_reason(captured_status),
        })
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

    fn disconnect(&mut self, session: &SessionInfo) -> Result<()> {
        self.ensure_session(session)?;
        let active = self.active.as_mut().expect("active session was validated");
        if active.reset_halted {
            active
                .session
                .core(0)
                .and_then(|mut core| core.run())
                .map_err(|error| map_core_error("resume core before disconnect", error))?;
            active.reset_halted = false;
        }
        restore_pending_core_states(active)
            .map_err(|error| map_core_error("restore core states before disconnect", error))?;
        self.active.take();
        Ok(())
    }
}

impl Drop for ProbeRsBackend {
    fn drop(&mut self) {
        let Some(active) = self.active.as_mut() else {
            return;
        };
        if active.reset_halted
            && active
                .session
                .core(0)
                .and_then(|mut core| core.run())
                .is_ok()
        {
            active.reset_halted = false;
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

fn restore_after_capture_error(
    active: &mut NativeSession,
    operation: &str,
    error: probe_rs::Error,
) -> DebugError {
    let primary = map_core_error(operation, error);
    // A failed first restoration remains pending. `disconnect` retries it and
    // reports a cleanup error only if that final attempt also fails.
    let _ = restore_pending_core_states(active);
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
        assert!(
            backend
                .volatile_target_state_notes()
                .iter()
                .any(|note| note.contains("watchdogs"))
        );
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
