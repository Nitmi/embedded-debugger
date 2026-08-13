use probe_rs::probe::{
    DebugProbeSelector,
    list::{Accessibility, Lister},
};

use crate::model::ProbeInfo;

/// Discover probes through probe-rs without opening or mutating them.
pub fn list_probes() -> Vec<ProbeInfo> {
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
