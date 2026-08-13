use std::{fs, path::Path};

use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::{
    SCHEMA_VERSION,
    backend::DebugBackend,
    error::{DebugError, ErrorCode, Result},
    model::{
        Address, Capabilities, CoreSnapshot, FlashRange, FlashReport, ProbeInfo, SessionInfo,
        TargetInfo,
    },
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayFlashBehavior {
    pub base_address: Address,
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
    pub flash: ReplayFlashBehavior,
}

impl Default for ReplayFlashBehavior {
    fn default() -> Self {
        Self {
            base_address: Address(0),
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
        Ok(())
    }
}

pub struct ReplayBackend {
    fixture: ReplayFixture,
    active_session_id: Option<String>,
    programmed_sha256: Option<String>,
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
            programmed_sha256: None,
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

    fn capabilities(&self) -> &Capabilities {
        &self.fixture.capabilities
    }

    fn plan_flash_ranges(&self, firmware_size: u64) -> Result<Vec<FlashRange>> {
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
        Ok(vec![FlashRange {
            start: self.fixture.flash.base_address,
            length: firmware_size,
        }])
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
        firmware: &[u8],
        firmware_sha256: &str,
    ) -> Result<FlashReport> {
        self.ensure_session(session)?;
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
        self.programmed_sha256 = Some(firmware_sha256.to_string());
        Ok(FlashReport {
            bytes_programmed: firmware.len() as u64,
            firmware_sha256: firmware_sha256.to_string(),
            verified: false,
        })
    }

    fn verify(&mut self, session: &SessionInfo, firmware_sha256: &str) -> Result<bool> {
        self.ensure_session(session)?;
        Ok(self.fixture.capabilities.verify
            && self.fixture.flash.verify_success
            && self.programmed_sha256.as_deref() == Some(firmware_sha256))
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

    fn disconnect(&mut self, session: &SessionInfo) -> Result<()> {
        self.ensure_session(session)?;
        self.active_session_id = None;
        Ok(())
    }
}
