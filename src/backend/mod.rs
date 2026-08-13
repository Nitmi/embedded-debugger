pub mod probe_rs;
pub mod replay;

use crate::{
    error::Result,
    model::{
        Capabilities, CoreSnapshot, FlashRange, FlashReport, ProbeInfo, SessionInfo, TargetInfo,
    },
};

pub trait DebugBackend {
    fn name(&self) -> &'static str;
    fn list_probes(&self) -> Result<Vec<ProbeInfo>>;
    fn target(&self) -> &TargetInfo;
    fn capabilities(&self) -> &Capabilities;
    fn plan_flash_ranges(&self, firmware_size: u64) -> Result<Vec<FlashRange>>;
    fn attach(&mut self, probe_id: &str, target: &str) -> Result<SessionInfo>;
    fn program(
        &mut self,
        session: &SessionInfo,
        firmware: &[u8],
        firmware_sha256: &str,
    ) -> Result<FlashReport>;
    fn verify(&mut self, session: &SessionInfo, firmware_sha256: &str) -> Result<bool>;
    fn reset(&mut self, session: &SessionInfo) -> Result<()>;
    fn snapshot(&mut self, session: &SessionInfo) -> Result<CoreSnapshot>;
    fn disconnect(&mut self, session: &SessionInfo) -> Result<()>;
}
