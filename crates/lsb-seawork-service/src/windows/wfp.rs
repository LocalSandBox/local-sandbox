#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WfpCapability {
    pub available: bool,
    pub reason: &'static str,
}

pub fn capability() -> WfpCapability {
    WfpCapability {
        available: false,
        reason: "WFP logon-SID loopback isolation has not passed the Phase 0 real-machine gate",
    }
}
