pub mod probe_rs;
pub mod replay;

use crate::{
    error::Result,
    model::{
        Address, Capabilities, CoreObservation, CoreSnapshot, FlashLayout, FlashReport, ProbeInfo,
        SessionInfo, TargetInfo,
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
