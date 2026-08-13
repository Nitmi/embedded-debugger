use std::{collections::BTreeMap, fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::error::{DebugError, Result};

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
    pub verify: bool,
    pub halt: bool,
    pub run: bool,
    pub reset: bool,
    pub step: bool,
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
            if !core
                .unavailable_reason
                .as_deref()
                .is_some_and(|reason| !reason.trim().is_empty())
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
}

impl Default for FlashPolicy {
    fn default() -> Self {
        Self {
            erase_mode: "affected_sectors_only".to_string(),
            preserve_unwritten_bytes: true,
            verify: true,
            post_flash: "reset_halt_snapshot_resume".to_string(),
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
}
