use std::{collections::BTreeMap, fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::error::{DebugError, Result};

pub const MAX_REGISTER_READS: usize = 64;
pub const MAX_INLINE_MEMORY_READ_BYTES: u64 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address(pub u64);

impl Address {
    pub fn parse(value: &str) -> Result<Self> {
        let normalized = value.trim().replace('_', "");
        let parsed = if let Some(hex) = normalized
            .strip_prefix("0x")
            .or_else(|| normalized.strip_prefix("0X"))
        {
            u64::from_str_radix(hex, 16)
        } else {
            u64::from_str(&normalized)
        };
        parsed.map(Self).map_err(|_| {
            DebugError::config(
                "address must be a decimal integer or a 0x-prefixed hexadecimal string",
                serde_json::json!({"value": value}),
            )
        })
    }
}

impl fmt::Display for Address {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "0x{:08X}", self.0)
    }
}

impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AddressVisitor;

        impl<'de> de::Visitor<'de> for AddressVisitor {
            type Value = Address;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an address string or unsigned integer")
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                Address::parse(value).map_err(E::custom)
            }

            fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Address(value))
            }
        }

        deserializer.deserialize_any(AddressVisitor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeInfo {
    pub id: String,
    pub vendor_id: u16,
    pub product_id: u16,
    pub serial: Option<String>,
    pub product: Option<String>,
    #[serde(default)]
    pub interface: Option<u8>,
    #[serde(default)]
    pub probe_type: Option<String>,
    #[serde(default = "default_accessible")]
    pub accessible: bool,
}

fn default_accessible() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetInfo {
    pub name: String,
    pub architecture: String,
    pub core_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    pub flash: bool,
    #[serde(default)]
    pub segmented_flash: bool,
    /// Whether the backend has passed target-specific Intel HEX execution
    /// acceptance. Planning can still parse HEX when this is false, but the
    /// guarded execution path must remain blocked.
    #[serde(default)]
    pub intel_hex_flash: bool,
    /// Whether non-boot NVM regions such as nRF52 UICR may be mutated by the
    /// guarded flash workflow. This is deliberately independent from ordinary
    /// code-flash and segmented-image acceptance.
    #[serde(default)]
    pub non_boot_nvm_flash: bool,
    #[serde(default)]
    pub multi_core_post_flash: bool,
    pub verify: bool,
    pub halt: bool,
    pub run: bool,
    #[serde(default)]
    pub continue_execution: bool,
    #[serde(default)]
    pub continue_until_halt: bool,
    pub reset: bool,
    pub step: bool,
    #[serde(default)]
    pub core_status: bool,
    #[serde(default)]
    pub post_disconnect_core_state: bool,
    pub register_read: bool,
    pub memory_read: bool,
    pub memory_write: bool,
    pub hardware_breakpoints: u32,
    pub rtt: bool,
    pub trace: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreState {
    Running,
    Halted,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreExecutionAction {
    Status,
    Halt,
    Run,
    Continue,
    Step,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegisterKind {
    UnsignedInteger,
    FloatingPoint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterReading {
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    pub id: String,
    pub bits: u32,
    pub kind: RegisterKind,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterCoreObservation {
    pub index: u32,
    pub name: String,
    pub architecture: String,
    pub original_state: CoreState,
    pub captured_state: CoreState,
    pub state: CoreState,
    pub halt_reason: Option<String>,
    pub registers: Vec<RegisterReading>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryRegionKind {
    Ram,
    Nvm,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryRegionInfo {
    pub name: Option<String>,
    pub kind: MemoryRegionKind,
    pub start: Address,
    pub length: u64,
    pub is_alias: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryReadRange {
    pub start: Address,
    pub length: u64,
    pub region: MemoryRegionInfo,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryCoreObservation {
    pub index: u32,
    pub name: String,
    pub architecture: String,
    pub original_state: CoreState,
    pub captured_state: CoreState,
    pub state: CoreState,
    pub halt_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryReadResult {
    pub core: MemoryCoreObservation,
    pub range: MemoryReadRange,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreExecutionObservation {
    pub index: u32,
    pub name: String,
    pub architecture: String,
    pub action: CoreExecutionAction,
    pub original_state: CoreState,
    pub state: CoreState,
    pub state_changed: bool,
    pub halt_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pc_before: Option<Address>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pc_after: Option<Address>,
}

pub const DEFAULT_CONTINUE_UNTIL_HALT_TIMEOUT_MS: u64 = 5_000;
pub const DEFAULT_CONTINUE_UNTIL_HALT_POLL_INTERVAL_MS: u64 = 25;
pub const MIN_CONTINUE_UNTIL_HALT_TIMEOUT_MS: u64 = 10;
pub const MAX_CONTINUE_UNTIL_HALT_TIMEOUT_MS: u64 = 60_000;
pub const MIN_CONTINUE_UNTIL_HALT_POLL_INTERVAL_MS: u64 = 10;
pub const MAX_CONTINUE_UNTIL_HALT_POLL_INTERVAL_MS: u64 = 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContinueUntilHaltOptions {
    pub timeout_ms: u64,
    pub poll_interval_ms: u64,
}

impl Default for ContinueUntilHaltOptions {
    fn default() -> Self {
        Self {
            timeout_ms: DEFAULT_CONTINUE_UNTIL_HALT_TIMEOUT_MS,
            poll_interval_ms: DEFAULT_CONTINUE_UNTIL_HALT_POLL_INTERVAL_MS,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContinueUntilHaltOutcome {
    Halted,
    TimedOut,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContinueUntilHaltObservation {
    pub continuation: CoreExecutionObservation,
    pub outcome: ContinueUntilHaltOutcome,
    pub state: CoreState,
    pub halt_reason: Option<String>,
    pub timeout_ms: u64,
    pub poll_interval_ms: u64,
    pub elapsed_ms: u64,
    pub poll_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HardwareBreakpointAction {
    List,
    Set,
    Clear,
    ClearAll,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareBreakpointSlot {
    pub index: u32,
    pub address: Option<Address>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareBreakpointObservation {
    pub index: u32,
    pub name: String,
    pub architecture: String,
    pub action: HardwareBreakpointAction,
    pub original_state: CoreState,
    pub state: CoreState,
    pub capacity: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_address: Option<Address>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_slot: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub affected_slot: Option<u32>,
    pub before: Vec<HardwareBreakpointSlot>,
    pub after: Vec<HardwareBreakpointSlot>,
    pub changed: bool,
}

fn unknown_core_state() -> CoreState {
    CoreState::Unknown
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreSnapshot {
    #[serde(default = "unknown_core_state")]
    pub captured_state: CoreState,
    pub state: CoreState,
    pub pc: Address,
    pub sp: Address,
    #[serde(default)]
    pub registers: BTreeMap<String, Address>,
    pub halt_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreObservation {
    pub index: u32,
    pub name: String,
    pub architecture: String,
    pub available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_state: Option<CoreState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<CoreSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostFlashCoreObservation {
    pub index: u32,
    pub name: String,
    pub architecture: String,
    pub available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_final_state: Option<CoreState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<CoreSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
}

pub fn validate_core_inventory(
    target: &TargetInfo,
    cores: &[CoreObservation],
) -> std::result::Result<(), String> {
    if cores.len() != target.core_count as usize {
        return Err(format!(
            "expected {} core entries, received {}",
            target.core_count,
            cores.len()
        ));
    }
    let indexes = cores
        .iter()
        .map(|core| core.index)
        .collect::<std::collections::BTreeSet<_>>();
    let expected_indexes = (0..target.core_count).collect::<std::collections::BTreeSet<_>>();
    if indexes != expected_indexes {
        return Err(format!(
            "core indexes must be exactly 0..{}, received {indexes:?}",
            target.core_count
        ));
    }

    for core in cores {
        if core.available {
            let original = core
                .original_state
                .ok_or_else(|| format!("available core {} has no original state", core.index))?;
            let snapshot = core
                .snapshot
                .as_ref()
                .ok_or_else(|| format!("available core {} has no snapshot", core.index))?;
            if original == CoreState::Unknown {
                return Err(format!(
                    "available core {} has an unknown original state",
                    core.index
                ));
            }
            if snapshot.captured_state != CoreState::Halted {
                return Err(format!(
                    "core {} registers were not captured while halted",
                    core.index
                ));
            }
            if snapshot.state != original {
                return Err(format!(
                    "core {} was restored as {:?}, expected {:?}",
                    core.index, snapshot.state, original
                ));
            }
            if core.unavailable_reason.is_some() {
                return Err(format!(
                    "available core {} has an unavailable reason",
                    core.index
                ));
            }
        } else {
            if core.original_state.is_some() || core.snapshot.is_some() {
                return Err(format!(
                    "unavailable core {} contains captured state",
                    core.index
                ));
            }
            if core
                .unavailable_reason
                .as_deref()
                .is_none_or(|reason| reason.trim().is_empty())
            {
                return Err(format!("unavailable core {} has no reason", core.index));
            }
        }
    }
    if !cores.iter().any(|core| core.available) {
        return Err("no target core is available".to_string());
    }
    Ok(())
}

pub fn validate_post_flash_core_inventory(
    target: &TargetInfo,
    cores: &[PostFlashCoreObservation],
) -> std::result::Result<(), String> {
    if cores.len() != target.core_count as usize {
        return Err(format!(
            "expected {} post-flash core entries, received {}",
            target.core_count,
            cores.len()
        ));
    }
    let indexes = cores
        .iter()
        .map(|core| core.index)
        .collect::<std::collections::BTreeSet<_>>();
    let expected_indexes = (0..target.core_count).collect::<std::collections::BTreeSet<_>>();
    if indexes != expected_indexes {
        return Err(format!(
            "post-flash core indexes must be exactly 0..{}, received {indexes:?}",
            target.core_count
        ));
    }

    for core in cores {
        if core.name.trim().is_empty() || core.architecture.trim().is_empty() {
            return Err(format!(
                "post-flash core {} requires a name and architecture",
                core.index
            ));
        }
        if core.available {
            let expected_final_state = core.expected_final_state.unwrap_or(CoreState::Running);
            if expected_final_state == CoreState::Unknown {
                return Err(format!(
                    "available post-flash core {} has an unknown expected final state",
                    core.index
                ));
            }
            let snapshot = core.snapshot.as_ref().ok_or_else(|| {
                format!("available post-flash core {} has no snapshot", core.index)
            })?;
            if snapshot.captured_state != CoreState::Halted {
                return Err(format!(
                    "post-flash core {} registers were not captured while halted",
                    core.index
                ));
            }
            if snapshot.state != expected_final_state {
                return Err(format!(
                    "post-flash core {} finished as {:?}, expected {:?}",
                    core.index, snapshot.state, expected_final_state
                ));
            }
            if core.unavailable_reason.is_some() {
                return Err(format!(
                    "available post-flash core {} has an unavailable reason",
                    core.index
                ));
            }
        } else {
            if core.expected_final_state.is_some() || core.snapshot.is_some() {
                return Err(format!(
                    "unavailable post-flash core {} contains an expected state or snapshot",
                    core.index
                ));
            }
            if core
                .unavailable_reason
                .as_deref()
                .is_none_or(|reason| reason.trim().is_empty())
            {
                return Err(format!(
                    "unavailable post-flash core {} has no reason",
                    core.index
                ));
            }
        }
    }
    if !cores.iter().any(|core| {
        core.available
            && core.expected_final_state.unwrap_or(CoreState::Running) == CoreState::Running
    }) {
        return Err("no post-flash target core is expected to run".to_string());
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInfo {
    pub session_id: String,
    pub backend: String,
    pub probe: ProbeInfo,
    pub target: TargetInfo,
    pub capabilities: Capabilities,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugControlEffects {
    pub reset_requested: bool,
    pub flash_operation_requested: bool,
    #[serde(default)]
    pub memory_read_requested: bool,
    #[serde(default)]
    pub instruction_step_requested: bool,
    #[serde(default)]
    pub execution_continue_requested: bool,
    #[serde(default)]
    pub hardware_breakpoint_configuration_requested: bool,
    #[serde(default)]
    pub hardware_breakpoint_state_verified: bool,
    #[serde(default)]
    pub intentional_final_core_state_change_requested: bool,
    pub arbitrary_memory_write_requested: bool,
    pub core_execution_state_restoration_verified: bool,
    pub backend_may_modify_volatile_target_state: bool,
    pub volatile_target_state_notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeTestReport {
    pub risk: String,
    pub session: SessionInfo,
    pub effects: DebugControlEffects,
    pub operations: Vec<OperationRecord>,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotCaptureReport {
    pub capture_id: String,
    pub captured_at: String,
    pub risk: String,
    pub session: SessionInfo,
    pub effects: DebugControlEffects,
    pub cores: Vec<CoreObservation>,
    pub operations: Vec<OperationRecord>,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResetCaptureReport {
    pub capture_id: String,
    pub captured_at: String,
    pub risk: String,
    pub session: SessionInfo,
    pub effects: DebugControlEffects,
    pub cores: Vec<PostFlashCoreObservation>,
    pub operations: Vec<OperationRecord>,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterReadReport {
    pub read_id: String,
    pub captured_at: String,
    pub risk: String,
    pub session: SessionInfo,
    pub effects: DebugControlEffects,
    pub core: RegisterCoreObservation,
    pub operations: Vec<OperationRecord>,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryReadReport {
    pub read_id: String,
    pub captured_at: String,
    pub risk: String,
    pub session: SessionInfo,
    pub effects: DebugControlEffects,
    pub core: MemoryCoreObservation,
    pub range: MemoryReadRange,
    pub encoding: String,
    pub data: String,
    pub sha256: String,
    pub operations: Vec<OperationRecord>,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreControlReport {
    pub control_id: String,
    pub observed_at: String,
    pub risk: String,
    pub session: SessionInfo,
    pub effects: DebugControlEffects,
    pub core: CoreExecutionObservation,
    pub operations: Vec<OperationRecord>,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContinueUntilHaltReport {
    pub wait_id: String,
    pub observed_at: String,
    pub risk: String,
    pub session: SessionInfo,
    pub effects: DebugControlEffects,
    pub wait: ContinueUntilHaltObservation,
    pub operations: Vec<OperationRecord>,
    pub complete: bool,
}

pub fn validate_core_execution_observation(
    target: &TargetInfo,
    core: &CoreExecutionObservation,
) -> std::result::Result<(), String> {
    if core.index >= target.core_count {
        return Err(format!(
            "core index {} is outside target core count {}",
            core.index, target.core_count
        ));
    }
    if core.name.trim().is_empty() || core.architecture.trim().is_empty() {
        return Err(format!(
            "core {} requires a name and architecture",
            core.index
        ));
    }
    if core.original_state == CoreState::Unknown || core.state == CoreState::Unknown {
        return Err(format!("core {} contains an unknown state", core.index));
    }
    if core.state_changed != (core.original_state != core.state) {
        return Err(format!(
            "core {} state_changed does not match its state transition",
            core.index
        ));
    }
    match core.action {
        CoreExecutionAction::Status if core.state != core.original_state => {
            return Err(format!(
                "core {} status observation changed execution state",
                core.index
            ));
        }
        CoreExecutionAction::Halt if core.state != CoreState::Halted => {
            return Err(format!("core {} did not finish halted", core.index));
        }
        CoreExecutionAction::Run if core.state != CoreState::Running => {
            return Err(format!("core {} did not finish running", core.index));
        }
        CoreExecutionAction::Continue if core.original_state != CoreState::Halted => {
            return Err(format!(
                "core {} continue must start from a halted state",
                core.index
            ));
        }
        CoreExecutionAction::Continue
            if core.state == CoreState::Halted
                && core
                    .halt_reason
                    .as_deref()
                    .is_none_or(|reason| reason.trim().is_empty()) =>
        {
            return Err(format!(
                "core {} halted continue result requires a halt reason",
                core.index
            ));
        }
        CoreExecutionAction::Step if core.original_state != CoreState::Halted => {
            return Err(format!(
                "core {} step must start from a halted state",
                core.index
            ));
        }
        CoreExecutionAction::Step if core.state != CoreState::Halted => {
            return Err(format!("core {} step did not finish halted", core.index));
        }
        CoreExecutionAction::Step if core.halt_reason.as_deref() != Some("step") => {
            return Err(format!(
                "core {} step requires the normalized step halt reason",
                core.index
            ));
        }
        _ => {}
    }
    if core.action == CoreExecutionAction::Step {
        let (Some(_pc_before), Some(_pc_after)) = (core.pc_before, core.pc_after) else {
            return Err(format!(
                "core {} step requires before/after PCs",
                core.index
            ));
        };
    } else if core.pc_before.is_some() || core.pc_after.is_some() {
        return Err(format!(
            "core {} non-step observation contains step PC evidence",
            core.index
        ));
    }
    if core.state == CoreState::Running && core.halt_reason.is_some() {
        return Err(format!(
            "core {} is running but still contains a halt reason",
            core.index
        ));
    }
    Ok(())
}

pub fn validate_continue_until_halt_options(
    options: ContinueUntilHaltOptions,
) -> std::result::Result<(), String> {
    if !(MIN_CONTINUE_UNTIL_HALT_TIMEOUT_MS..=MAX_CONTINUE_UNTIL_HALT_TIMEOUT_MS)
        .contains(&options.timeout_ms)
    {
        return Err(format!(
            "continue-until-halt timeout must be {MIN_CONTINUE_UNTIL_HALT_TIMEOUT_MS}..={MAX_CONTINUE_UNTIL_HALT_TIMEOUT_MS} ms"
        ));
    }
    if !(MIN_CONTINUE_UNTIL_HALT_POLL_INTERVAL_MS..=MAX_CONTINUE_UNTIL_HALT_POLL_INTERVAL_MS)
        .contains(&options.poll_interval_ms)
    {
        return Err(format!(
            "continue-until-halt poll interval must be {MIN_CONTINUE_UNTIL_HALT_POLL_INTERVAL_MS}..={MAX_CONTINUE_UNTIL_HALT_POLL_INTERVAL_MS} ms"
        ));
    }
    if options.poll_interval_ms > options.timeout_ms {
        return Err("continue-until-halt poll interval must not exceed its timeout".to_string());
    }
    Ok(())
}

pub fn validate_continue_until_halt_observation(
    target: &TargetInfo,
    observation: &ContinueUntilHaltObservation,
) -> std::result::Result<(), String> {
    validate_continue_until_halt_options(ContinueUntilHaltOptions {
        timeout_ms: observation.timeout_ms,
        poll_interval_ms: observation.poll_interval_ms,
    })?;
    validate_core_execution_observation(target, &observation.continuation)?;
    if observation.continuation.action != CoreExecutionAction::Continue {
        return Err(format!(
            "core {} continue-until-halt result does not contain a continue observation",
            observation.continuation.index
        ));
    }
    if observation.state == CoreState::Unknown {
        return Err(format!(
            "core {} continue-until-halt result contains an unknown final state",
            observation.continuation.index
        ));
    }
    match observation.outcome {
        ContinueUntilHaltOutcome::Halted => {
            if observation.state != CoreState::Halted {
                return Err(format!(
                    "core {} halted wait outcome did not finish halted",
                    observation.continuation.index
                ));
            }
            if observation
                .halt_reason
                .as_deref()
                .is_none_or(|reason| reason.trim().is_empty())
            {
                return Err(format!(
                    "core {} halted wait outcome requires a halt reason",
                    observation.continuation.index
                ));
            }
        }
        ContinueUntilHaltOutcome::TimedOut => {
            if observation.state != CoreState::Running || observation.halt_reason.is_some() {
                return Err(format!(
                    "core {} timed-out wait must report a running core without a halt reason",
                    observation.continuation.index
                ));
            }
            if observation.elapsed_ms < observation.timeout_ms {
                return Err(format!(
                    "core {} timed-out wait returned before its deadline",
                    observation.continuation.index
                ));
            }
        }
    }
    if observation.continuation.state == CoreState::Halted {
        if observation.outcome != ContinueUntilHaltOutcome::Halted
            || observation.state != CoreState::Halted
            || observation.halt_reason != observation.continuation.halt_reason
            || observation.poll_count != 0
        {
            return Err(format!(
                "core {} immediate continue halt has inconsistent wait evidence",
                observation.continuation.index
            ));
        }
    } else if observation.poll_count == 0 {
        return Err(format!(
            "core {} non-immediate wait result requires at least one status poll",
            observation.continuation.index
        ));
    }
    Ok(())
}

pub fn validate_hardware_breakpoint_observation(
    target: &TargetInfo,
    observation: &HardwareBreakpointObservation,
) -> std::result::Result<(), String> {
    if observation.index >= target.core_count {
        return Err(format!(
            "core index {} is outside target core count {}",
            observation.index, target.core_count
        ));
    }
    if observation.name.trim().is_empty() || observation.architecture.trim().is_empty() {
        return Err(format!(
            "core {} requires a name and architecture",
            observation.index
        ));
    }
    if observation.original_state == CoreState::Unknown || observation.state == CoreState::Unknown {
        return Err(format!(
            "core {} hardware-breakpoint observation contains an unknown state",
            observation.index
        ));
    }
    if observation.original_state != observation.state {
        return Err(format!(
            "core {} hardware-breakpoint operation changed execution state",
            observation.index
        ));
    }
    if observation.capacity == 0 {
        return Err(format!(
            "core {} reports zero hardware-breakpoint capacity",
            observation.index
        ));
    }
    validate_hardware_breakpoint_slots(
        observation.index,
        observation.capacity,
        "before",
        &observation.before,
    )?;
    validate_hardware_breakpoint_slots(
        observation.index,
        observation.capacity,
        "after",
        &observation.after,
    )?;
    if observation.changed != (observation.before != observation.after) {
        return Err(format!(
            "core {} hardware-breakpoint changed flag does not match the slot transition",
            observation.index
        ));
    }

    match observation.action {
        HardwareBreakpointAction::List => {
            if observation.requested_address.is_some()
                || observation.requested_slot.is_some()
                || observation.affected_slot.is_some()
                || observation.changed
            {
                return Err(format!(
                    "core {} hardware-breakpoint list contains mutation fields",
                    observation.index
                ));
            }
        }
        HardwareBreakpointAction::Set => {
            require_halted_breakpoint_mutation(observation)?;
            let address = observation.requested_address.ok_or_else(|| {
                format!(
                    "core {} hardware-breakpoint set has no requested address",
                    observation.index
                )
            })?;
            let affected_slot = observation.affected_slot.ok_or_else(|| {
                format!(
                    "core {} hardware-breakpoint set has no affected slot",
                    observation.index
                )
            })?;
            if observation
                .requested_slot
                .is_some_and(|requested| requested != affected_slot)
            {
                return Err(format!(
                    "core {} hardware-breakpoint set affected a different slot than requested",
                    observation.index
                ));
            }
            require_only_affected_breakpoint_slot_changed(observation, affected_slot)?;
            if observation.after[affected_slot as usize].address != Some(address) {
                return Err(format!(
                    "core {} hardware-breakpoint set did not verify the requested address",
                    observation.index
                ));
            }
        }
        HardwareBreakpointAction::Clear => {
            require_halted_breakpoint_mutation(observation)?;
            if observation.requested_address.is_some() {
                return Err(format!(
                    "core {} hardware-breakpoint clear contains an address",
                    observation.index
                ));
            }
            let requested_slot = observation.requested_slot.ok_or_else(|| {
                format!(
                    "core {} hardware-breakpoint clear has no requested slot",
                    observation.index
                )
            })?;
            if observation.affected_slot != Some(requested_slot) {
                return Err(format!(
                    "core {} hardware-breakpoint clear affected a different slot than requested",
                    observation.index
                ));
            }
            require_only_affected_breakpoint_slot_changed(observation, requested_slot)?;
            if observation.after[requested_slot as usize].address.is_some() {
                return Err(format!(
                    "core {} hardware-breakpoint clear did not empty the requested slot",
                    observation.index
                ));
            }
        }
        HardwareBreakpointAction::ClearAll => {
            require_halted_breakpoint_mutation(observation)?;
            if observation.requested_address.is_some()
                || observation.requested_slot.is_some()
                || observation.affected_slot.is_some()
                || observation.after.iter().any(|slot| slot.address.is_some())
            {
                return Err(format!(
                    "core {} hardware-breakpoint clear-all did not leave every slot empty",
                    observation.index
                ));
            }
        }
    }
    Ok(())
}

fn validate_hardware_breakpoint_slots(
    core_index: u32,
    capacity: u32,
    phase: &str,
    slots: &[HardwareBreakpointSlot],
) -> std::result::Result<(), String> {
    if slots.len() != capacity as usize {
        return Err(format!(
            "core {core_index} hardware-breakpoint {phase} snapshot has {} slots, expected {capacity}",
            slots.len()
        ));
    }
    for (expected, slot) in slots.iter().enumerate() {
        if slot.index != expected as u32 {
            return Err(format!(
                "core {core_index} hardware-breakpoint {phase} slot indexes are not contiguous"
            ));
        }
    }
    let active = slots
        .iter()
        .filter_map(|slot| slot.address)
        .collect::<std::collections::BTreeSet<_>>();
    if active.len() != slots.iter().filter(|slot| slot.address.is_some()).count() {
        return Err(format!(
            "core {core_index} hardware-breakpoint {phase} snapshot contains duplicate addresses"
        ));
    }
    Ok(())
}

fn require_halted_breakpoint_mutation(
    observation: &HardwareBreakpointObservation,
) -> std::result::Result<(), String> {
    if observation.original_state != CoreState::Halted {
        return Err(format!(
            "core {} hardware-breakpoint mutation must start halted",
            observation.index
        ));
    }
    Ok(())
}

fn require_only_affected_breakpoint_slot_changed(
    observation: &HardwareBreakpointObservation,
    affected_slot: u32,
) -> std::result::Result<(), String> {
    if affected_slot >= observation.capacity {
        return Err(format!(
            "core {} hardware-breakpoint affected slot {} exceeds capacity {}",
            observation.index, affected_slot, observation.capacity
        ));
    }
    if observation
        .before
        .iter()
        .zip(&observation.after)
        .any(|(before, after)| before.index != affected_slot && before != after)
    {
        return Err(format!(
            "core {} hardware-breakpoint operation changed an unrequested slot",
            observation.index
        ));
    }
    Ok(())
}

pub fn validate_memory_read_range(range: &MemoryReadRange) -> std::result::Result<(), String> {
    if range.length == 0 {
        return Err("memory read length must be greater than zero".to_string());
    }
    if range.length > MAX_INLINE_MEMORY_READ_BYTES {
        return Err(format!(
            "memory read length {} exceeds the inline limit {MAX_INLINE_MEMORY_READ_BYTES}",
            range.length
        ));
    }
    let end = range
        .start
        .0
        .checked_add(range.length)
        .ok_or_else(|| "memory read range overflows the target address space".to_string())?;
    if range.region.length == 0 {
        return Err("memory region length must be greater than zero".to_string());
    }
    let region_end = range
        .region
        .start
        .0
        .checked_add(range.region.length)
        .ok_or_else(|| "memory region overflows the target address space".to_string())?;
    if range
        .region
        .name
        .as_ref()
        .is_some_and(|name| name.trim().is_empty())
    {
        return Err("memory region name must not be empty".to_string());
    }
    if range.start.0 < range.region.start.0 || end > region_end {
        return Err("memory read range is not fully contained in its described region".to_string());
    }
    Ok(())
}

pub fn validate_memory_core_observation(
    target: &TargetInfo,
    core: &MemoryCoreObservation,
) -> std::result::Result<(), String> {
    if core.index >= target.core_count {
        return Err(format!(
            "core index {} is outside target core count {}",
            core.index, target.core_count
        ));
    }
    if core.name.trim().is_empty() || core.architecture.trim().is_empty() {
        return Err(format!(
            "core {} requires a name and architecture",
            core.index
        ));
    }
    if core.original_state == CoreState::Unknown {
        return Err(format!("core {} has an unknown original state", core.index));
    }
    if core.captured_state != CoreState::Halted {
        return Err(format!(
            "core {} memory was not captured while halted",
            core.index
        ));
    }
    if core.state != core.original_state {
        return Err(format!(
            "core {} was restored as {:?}, expected {:?}",
            core.index, core.state, core.original_state
        ));
    }
    Ok(())
}

pub fn validate_register_core_observation(
    target: &TargetInfo,
    core: &RegisterCoreObservation,
) -> std::result::Result<(), String> {
    if core.index >= target.core_count {
        return Err(format!(
            "core index {} is outside target core count {}",
            core.index, target.core_count
        ));
    }
    if core.name.trim().is_empty() || core.architecture.trim().is_empty() {
        return Err(format!(
            "core {} requires a name and architecture",
            core.index
        ));
    }
    if core.original_state == CoreState::Unknown {
        return Err(format!("core {} has an unknown original state", core.index));
    }
    if core.captured_state != CoreState::Halted {
        return Err(format!(
            "core {} registers were not captured while halted",
            core.index
        ));
    }
    if core.state != core.original_state {
        return Err(format!(
            "core {} was restored as {:?}, expected {:?}",
            core.index, core.state, core.original_state
        ));
    }
    if core.registers.is_empty() {
        return Err(format!("core {} contains no register readings", core.index));
    }
    if core.registers.len() > MAX_REGISTER_READS {
        return Err(format!(
            "core {} contains {} register readings, maximum is {MAX_REGISTER_READS}",
            core.index,
            core.registers.len()
        ));
    }

    let mut ids = std::collections::BTreeSet::new();
    let mut names = std::collections::BTreeMap::<String, String>::new();
    for register in &core.registers {
        if register.name.trim().is_empty() || register.id.trim().is_empty() {
            return Err(format!(
                "core {} contains a register without a name or id",
                core.index
            ));
        }
        if !(1..=128).contains(&register.bits) {
            return Err(format!(
                "register {} has unsupported width {}",
                register.name, register.bits
            ));
        }
        if !ids.insert(register.id.to_ascii_lowercase()) {
            return Err(format!(
                "core {} contains duplicate register id {}",
                core.index, register.id
            ));
        }

        let mut labels = Vec::with_capacity(register.aliases.len() + 1);
        labels.push(register.name.as_str());
        labels.extend(register.aliases.iter().map(String::as_str));
        for label in labels {
            if label.trim().is_empty() {
                return Err(format!(
                    "register {} contains an empty alias",
                    register.name
                ));
            }
            let normalized = label.to_ascii_lowercase();
            if let Some(previous) = names.insert(normalized, register.id.clone())
                && !previous.eq_ignore_ascii_case(&register.id)
            {
                return Err(format!(
                    "register label {label} resolves to multiple ids on core {}",
                    core.index
                ));
            }
        }

        let digits = register
            .value
            .strip_prefix("0x")
            .or_else(|| register.value.strip_prefix("0X"))
            .ok_or_else(|| format!("register {} value is not hexadecimal", register.name))?;
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(format!(
                "register {} value is not hexadecimal",
                register.name
            ));
        }
        let maximum_digits = register.bits.div_ceil(4) as usize;
        let numeric = u128::from_str_radix(digits, 16).map_err(|_| {
            format!(
                "register {} value does not fit its {}-bit width",
                register.name, register.bits
            )
        })?;
        if digits.len() > maximum_digits
            || (register.bits < 128 && numeric >= (1_u128 << register.bits))
        {
            return Err(format!(
                "register {} value does not fit its {}-bit width",
                register.name, register.bits
            ));
        }
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirmwareInfo {
    pub path: String,
    pub format: String,
    #[serde(default)]
    pub base_address: Option<Address>,
    pub size: u64,
    pub sha256: String,
    #[serde(default)]
    pub program_size: u64,
    #[serde(default)]
    pub segments: Vec<FirmwareSegmentInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_options: Option<FirmwareImageOptions>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirmwareSegmentInfo {
    pub kind: String,
    pub start: Address,
    pub length: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirmwareImageOptions {
    pub generator: String,
    pub target_chip: String,
    pub flash_size: u64,
    pub chip_revision: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlashRange {
    pub start: Address,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlashLayout {
    pub write_ranges: Vec<FlashRange>,
    pub erase_ranges: Vec<FlashRange>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedAction {
    pub action: String,
    pub risk: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlashPolicy {
    pub erase_mode: String,
    pub preserve_unwritten_bytes: bool,
    pub verify: bool,
    pub post_flash: String,
    #[serde(default)]
    pub nrf52840_development_debug: Option<Nrf52840DevelopmentDebugPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nrf52840DevelopmentDebugPolicy {
    pub operation: String,
    pub target: String,
    pub allowed_code_flash_range: FlashRange,
    pub uicr_register: String,
    pub uicr_address: Address,
    pub uicr_value: String,
    pub little_endian_bytes: String,
    pub affected_erase_range: FlashRange,
    pub unwritten_uicr_bytes_preserved: bool,
    pub persistent_until_uicr_erase_or_rewrite: bool,
    pub security_effect: String,
}

impl Default for FlashPolicy {
    fn default() -> Self {
        Self {
            erase_mode: "affected_sectors_only".to_string(),
            preserve_unwritten_bytes: true,
            verify: true,
            post_flash: "reset_halt_snapshot_resume".to_string(),
            nrf52840_development_debug: None,
        }
    }
}

impl FlashPolicy {
    pub fn with_nrf52840_development_debug() -> Self {
        Self {
            nrf52840_development_debug: Some(Nrf52840DevelopmentDebugPolicy {
                operation: "program_exact_approtect_hw_disabled".to_string(),
                target: "nRF52840_xxAA".to_string(),
                allowed_code_flash_range: FlashRange {
                    start: Address(0),
                    length: 0x10_0000,
                },
                uicr_register: "UICR.APPROTECT".to_string(),
                uicr_address: Address(0x1000_1208),
                uicr_value: "0x0000005A".to_string(),
                little_endian_bytes: "5a000000".to_string(),
                affected_erase_range: FlashRange {
                    start: Address(0x1000_1000),
                    length: 0x1000,
                },
                unwritten_uicr_bytes_preserved: true,
                persistent_until_uicr_erase_or_rewrite: true,
                security_effect:
                    "keeps invasive debug access enabled across reset for development use"
                        .to_string(),
            }),
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlashPlan {
    pub plan_id: String,
    pub risk: String,
    pub backend: String,
    pub probe: ProbeInfo,
    pub target: TargetInfo,
    pub firmware: FirmwareInfo,
    pub ranges: Vec<FlashRange>,
    #[serde(default)]
    pub erase_ranges: Vec<FlashRange>,
    #[serde(default)]
    pub policy: FlashPolicy,
    #[serde(default)]
    pub execution: FlashExecutionReadiness,
    pub actions: Vec<PlannedAction>,
    pub confirm_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlashExecutionReadiness {
    pub supported: bool,
    #[serde(default)]
    pub blockers: Vec<FlashExecutionBlocker>,
}

impl Default for FlashExecutionReadiness {
    fn default() -> Self {
        Self {
            supported: true,
            blockers: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlashExecutionBlocker {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlashReport {
    pub bytes_programmed: u64,
    pub firmware_sha256: String,
    #[serde(default)]
    pub segments: Vec<FlashSegmentReport>,
    pub verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlashSegmentReport {
    pub kind: String,
    pub start: Address,
    pub length: u64,
    pub sha256: String,
    pub verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationRecord {
    pub sequence: u32,
    pub operation: String,
    pub ok: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceBundle {
    pub schema_version: String,
    pub capture_id: String,
    pub captured_at: String,
    pub backend: String,
    pub probe: ProbeInfo,
    pub target: TargetInfo,
    pub firmware: FirmwareInfo,
    #[serde(default)]
    pub plan_id: Option<String>,
    #[serde(default)]
    pub confirm_digest: Option<String>,
    #[serde(default)]
    pub ranges: Vec<FlashRange>,
    #[serde(default)]
    pub erase_ranges: Vec<FlashRange>,
    #[serde(default)]
    pub policy: Option<FlashPolicy>,
    #[serde(default)]
    pub flash: Option<FlashReport>,
    pub core: CoreSnapshot,
    #[serde(default)]
    pub post_flash_cores: Vec<PostFlashCoreObservation>,
    pub operations: Vec<OperationRecord>,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactReference {
    pub kind: String,
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlashExecution {
    pub plan: FlashPlan,
    pub session: SessionInfo,
    pub flash: FlashReport,
    pub snapshot: CoreSnapshot,
    #[serde(default)]
    pub post_flash_cores: Vec<PostFlashCoreObservation>,
    pub evidence: ArtifactReference,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_round_trips_as_hex_string() {
        let address: Address = serde_json::from_str("\"0x0800_1234\"").unwrap();
        assert_eq!(address, Address(0x0800_1234));
        assert_eq!(serde_json::to_string(&address).unwrap(), "\"0x08001234\"");
    }

    #[test]
    fn address_accepts_integer_fixture_values() {
        let address: Address = serde_json::from_str("536870912").unwrap();
        assert_eq!(address.to_string(), "0x20000000");
    }

    #[test]
    fn core_inventory_requires_state_restoration() {
        let target = TargetInfo {
            name: "dual".to_string(),
            architecture: "test".to_string(),
            core_count: 2,
        };
        let mut cores = vec![
            CoreObservation {
                index: 0,
                name: "cpu0".to_string(),
                architecture: "test".to_string(),
                available: true,
                original_state: Some(CoreState::Running),
                snapshot: Some(CoreSnapshot {
                    captured_state: CoreState::Halted,
                    state: CoreState::Running,
                    pc: Address(1),
                    sp: Address(2),
                    registers: BTreeMap::new(),
                    halt_reason: Some("request".to_string()),
                }),
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

        assert!(validate_core_inventory(&target, &cores).is_ok());
        cores[0].snapshot.as_mut().unwrap().state = CoreState::Halted;
        assert!(
            validate_core_inventory(&target, &cores)
                .unwrap_err()
                .contains("restored")
        );
    }

    #[test]
    fn post_flash_inventory_preserves_each_expected_final_state() {
        let target = TargetInfo {
            name: "dual".to_string(),
            architecture: "test".to_string(),
            core_count: 2,
        };
        let mut cores = vec![
            PostFlashCoreObservation {
                index: 0,
                name: "cpu0".to_string(),
                architecture: "test".to_string(),
                available: true,
                expected_final_state: Some(CoreState::Running),
                snapshot: Some(CoreSnapshot {
                    captured_state: CoreState::Halted,
                    state: CoreState::Running,
                    pc: Address(1),
                    sp: Address(2),
                    registers: BTreeMap::new(),
                    halt_reason: Some("request".to_string()),
                }),
                unavailable_reason: None,
            },
            PostFlashCoreObservation {
                index: 1,
                name: "cpu1".to_string(),
                architecture: "test".to_string(),
                available: true,
                expected_final_state: Some(CoreState::Halted),
                snapshot: Some(CoreSnapshot {
                    captured_state: CoreState::Halted,
                    state: CoreState::Halted,
                    pc: Address(3),
                    sp: Address(4),
                    registers: BTreeMap::new(),
                    halt_reason: Some("breakpoint".to_string()),
                }),
                unavailable_reason: None,
            },
        ];

        assert!(validate_post_flash_core_inventory(&target, &cores).is_ok());
        cores[1].snapshot.as_mut().unwrap().state = CoreState::Running;
        assert!(
            validate_post_flash_core_inventory(&target, &cores)
                .unwrap_err()
                .contains("expected Halted")
        );
    }

    #[test]
    fn post_flash_inventory_defaults_legacy_expected_state_to_running() {
        let target = TargetInfo {
            name: "single".to_string(),
            architecture: "test".to_string(),
            core_count: 1,
        };
        let json = r#"{
            "index": 0,
            "name": "cpu0",
            "architecture": "test",
            "available": true,
            "snapshot": {
                "captured_state": "halted",
                "state": "running",
                "pc": "0x00000001",
                "sp": "0x00000002",
                "registers": {},
                "halt_reason": "request"
            }
        }"#;
        let core: PostFlashCoreObservation = serde_json::from_str(json).unwrap();

        assert_eq!(core.expected_final_state, None);
        assert!(validate_post_flash_core_inventory(&target, &[core]).is_ok());
    }

    #[test]
    fn register_observation_requires_unique_bounded_values_and_state_restoration() {
        let target = TargetInfo {
            name: "single".to_string(),
            architecture: "armv7em".to_string(),
            core_count: 1,
        };
        let mut core = RegisterCoreObservation {
            index: 0,
            name: "core0".to_string(),
            architecture: "armv7em".to_string(),
            original_state: CoreState::Running,
            captured_state: CoreState::Halted,
            state: CoreState::Running,
            halt_reason: Some("request".to_string()),
            registers: vec![RegisterReading {
                name: "pc".to_string(),
                aliases: vec!["r15".to_string()],
                id: "0x000F".to_string(),
                bits: 32,
                kind: RegisterKind::UnsignedInteger,
                value: "0x08001234".to_string(),
            }],
        };

        assert!(validate_register_core_observation(&target, &core).is_ok());

        core.state = CoreState::Halted;
        assert!(
            validate_register_core_observation(&target, &core)
                .unwrap_err()
                .contains("restored")
        );
        core.state = CoreState::Running;
        core.registers[0].value = "0x100000000".to_string();
        assert!(
            validate_register_core_observation(&target, &core)
                .unwrap_err()
                .contains("does not fit")
        );
    }

    #[test]
    fn memory_observation_requires_a_bounded_contained_range_and_state_restoration() {
        let target = TargetInfo {
            name: "single".to_string(),
            architecture: "armv7em".to_string(),
            core_count: 1,
        };
        let mut range = MemoryReadRange {
            start: Address(0x2000_0004),
            length: 8,
            region: MemoryRegionInfo {
                name: Some("sram".to_string()),
                kind: MemoryRegionKind::Ram,
                start: Address(0x2000_0000),
                length: 16,
                is_alias: false,
            },
        };
        let mut core = MemoryCoreObservation {
            index: 0,
            name: "core0".to_string(),
            architecture: "armv7em".to_string(),
            original_state: CoreState::Running,
            captured_state: CoreState::Halted,
            state: CoreState::Running,
            halt_reason: Some("request".to_string()),
        };

        assert!(validate_memory_read_range(&range).is_ok());
        assert!(validate_memory_core_observation(&target, &core).is_ok());

        range.length = 13;
        assert!(
            validate_memory_read_range(&range)
                .unwrap_err()
                .contains("contained")
        );
        range.length = MAX_INLINE_MEMORY_READ_BYTES + 1;
        assert!(
            validate_memory_read_range(&range)
                .unwrap_err()
                .contains("inline limit")
        );
        core.state = CoreState::Halted;
        assert!(
            validate_memory_core_observation(&target, &core)
                .unwrap_err()
                .contains("restored")
        );
    }

    #[test]
    fn core_execution_observation_enforces_action_state_and_change_semantics() {
        let target = TargetInfo {
            name: "single".to_string(),
            architecture: "armv7em".to_string(),
            core_count: 1,
        };
        let mut observation = CoreExecutionObservation {
            index: 0,
            name: "core0".to_string(),
            architecture: "armv7em".to_string(),
            action: CoreExecutionAction::Status,
            original_state: CoreState::Halted,
            state: CoreState::Halted,
            state_changed: false,
            halt_reason: Some("breakpoint".to_string()),
            pc_before: None,
            pc_after: None,
        };

        assert!(validate_core_execution_observation(&target, &observation).is_ok());

        observation.state_changed = true;
        assert!(
            validate_core_execution_observation(&target, &observation)
                .unwrap_err()
                .contains("state_changed")
        );
        observation.action = CoreExecutionAction::Run;
        observation.state = CoreState::Running;
        observation.halt_reason = Some("stale".to_string());
        assert!(
            validate_core_execution_observation(&target, &observation)
                .unwrap_err()
                .contains("halt reason")
        );

        observation.action = CoreExecutionAction::Step;
        observation.original_state = CoreState::Halted;
        observation.state = CoreState::Halted;
        observation.state_changed = false;
        observation.halt_reason = Some("step".to_string());
        observation.pc_before = Some(Address(0x0800_1234));
        observation.pc_after = Some(Address(0x0800_1236));
        assert!(validate_core_execution_observation(&target, &observation).is_ok());

        observation.halt_reason = Some("request".to_string());
        assert!(
            validate_core_execution_observation(&target, &observation)
                .unwrap_err()
                .contains("normalized step halt reason")
        );
        observation.halt_reason = Some("step".to_string());

        observation.pc_after = None;
        assert!(
            validate_core_execution_observation(&target, &observation)
                .unwrap_err()
                .contains("before/after PCs")
        );

        observation.action = CoreExecutionAction::Status;
        observation.pc_after = Some(Address(0x0800_1236));
        assert!(
            validate_core_execution_observation(&target, &observation)
                .unwrap_err()
                .contains("non-step observation")
        );

        observation.action = CoreExecutionAction::Continue;
        observation.original_state = CoreState::Halted;
        observation.state = CoreState::Running;
        observation.state_changed = true;
        observation.halt_reason = None;
        observation.pc_before = None;
        observation.pc_after = None;
        assert!(validate_core_execution_observation(&target, &observation).is_ok());

        observation.state = CoreState::Halted;
        observation.state_changed = false;
        observation.halt_reason = Some("breakpoint".to_string());
        assert!(validate_core_execution_observation(&target, &observation).is_ok());

        observation.halt_reason = None;
        assert!(
            validate_core_execution_observation(&target, &observation)
                .unwrap_err()
                .contains("requires a halt reason")
        );
    }

    #[test]
    fn continue_until_halt_observation_distinguishes_halt_and_timeout() {
        let target = TargetInfo {
            name: "single".to_string(),
            architecture: "armv7em".to_string(),
            core_count: 1,
        };
        let continuation = CoreExecutionObservation {
            index: 0,
            name: "core0".to_string(),
            architecture: "armv7em".to_string(),
            action: CoreExecutionAction::Continue,
            original_state: CoreState::Halted,
            state: CoreState::Running,
            state_changed: true,
            halt_reason: None,
            pc_before: None,
            pc_after: None,
        };
        let mut observation = ContinueUntilHaltObservation {
            continuation: continuation.clone(),
            outcome: ContinueUntilHaltOutcome::Halted,
            state: CoreState::Halted,
            halt_reason: Some("breakpoint".to_string()),
            timeout_ms: 100,
            poll_interval_ms: 25,
            elapsed_ms: 75,
            poll_count: 3,
        };

        assert!(validate_continue_until_halt_observation(&target, &observation).is_ok());

        observation.outcome = ContinueUntilHaltOutcome::TimedOut;
        observation.state = CoreState::Running;
        observation.halt_reason = None;
        observation.elapsed_ms = 100;
        observation.poll_count = 4;
        assert!(validate_continue_until_halt_observation(&target, &observation).is_ok());

        observation.elapsed_ms = 99;
        assert!(
            validate_continue_until_halt_observation(&target, &observation)
                .unwrap_err()
                .contains("before its deadline")
        );
        observation.elapsed_ms = 100;

        observation.poll_count = 0;
        assert!(
            validate_continue_until_halt_observation(&target, &observation)
                .unwrap_err()
                .contains("at least one status poll")
        );

        observation.continuation = CoreExecutionObservation {
            state: CoreState::Halted,
            state_changed: false,
            halt_reason: Some("breakpoint".to_string()),
            ..continuation
        };
        observation.outcome = ContinueUntilHaltOutcome::Halted;
        observation.state = CoreState::Halted;
        observation.halt_reason = Some("breakpoint".to_string());
        observation.elapsed_ms = 0;
        observation.poll_count = 0;
        assert!(validate_continue_until_halt_observation(&target, &observation).is_ok());

        assert!(
            validate_continue_until_halt_options(ContinueUntilHaltOptions {
                timeout_ms: 5,
                poll_interval_ms: 10,
            })
            .unwrap_err()
            .contains("timeout")
        );
        assert!(
            validate_continue_until_halt_options(ContinueUntilHaltOptions {
                timeout_ms: 100,
                poll_interval_ms: 101,
            })
            .unwrap_err()
            .contains("must not exceed")
        );
    }

    #[test]
    fn hardware_breakpoint_observation_enforces_slot_and_state_semantics() {
        let target = TargetInfo {
            name: "single".to_string(),
            architecture: "armv7em".to_string(),
            core_count: 1,
        };
        let empty_slots = (0..2)
            .map(|index| HardwareBreakpointSlot {
                index,
                address: None,
            })
            .collect::<Vec<_>>();
        let mut set_slots = empty_slots.clone();
        set_slots[0].address = Some(Address(0x0800_1234));
        let mut observation = HardwareBreakpointObservation {
            index: 0,
            name: "core0".to_string(),
            architecture: "armv7em".to_string(),
            action: HardwareBreakpointAction::Set,
            original_state: CoreState::Halted,
            state: CoreState::Halted,
            capacity: 2,
            requested_address: Some(Address(0x0800_1234)),
            requested_slot: None,
            affected_slot: Some(0),
            before: empty_slots,
            after: set_slots,
            changed: true,
        };

        assert!(validate_hardware_breakpoint_observation(&target, &observation).is_ok());

        observation.state = CoreState::Running;
        assert!(
            validate_hardware_breakpoint_observation(&target, &observation)
                .unwrap_err()
                .contains("changed execution state")
        );
        observation.state = CoreState::Halted;
        observation.after[1].address = Some(Address(0x0800_2000));
        assert!(
            validate_hardware_breakpoint_observation(&target, &observation)
                .unwrap_err()
                .contains("unrequested slot")
        );
        observation.after[1].address = None;
        observation.changed = false;
        assert!(
            validate_hardware_breakpoint_observation(&target, &observation)
                .unwrap_err()
                .contains("changed flag")
        );
    }
}
