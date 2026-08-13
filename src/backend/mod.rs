pub mod probe_rs;
pub mod replay;

use crate::{
    error::Result,
    model::{
        Address, Capabilities, CoreObservation, CoreSnapshot, FirmwareImageOptions, FlashLayout,
        FlashReport, ProbeInfo, SessionInfo, TargetInfo,
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
        firmware: &[u8],
        base_address: Address,
        firmware_sha256: &str,
    ) -> Result<FlashReport>;
    fn verify(&mut self, session: &SessionInfo, firmware_sha256: &str) -> Result<bool>;
    fn reset(&mut self, session: &SessionInfo) -> Result<()>;
    fn snapshot(&mut self, session: &SessionInfo) -> Result<CoreSnapshot>;
    fn capture_live_snapshot(&mut self, session: &SessionInfo) -> Result<Vec<CoreObservation>>;
    fn disconnect(&mut self, session: &SessionInfo) -> Result<()>;
}
