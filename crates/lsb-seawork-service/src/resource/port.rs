use anyhow::{bail, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortIsolationCapability {
    pub available: bool,
    pub reason: String,
}

impl PortIsolationCapability {
    pub fn detect() -> Self {
        let wfp = crate::windows::wfp::capability();
        Self {
            available: wfp.available,
            reason: wfp.reason.to_string(),
        }
    }

    pub fn require_available(&self) -> Result<()> {
        if !self.available {
            bail!("PORT_ISOLATION_UNAVAILABLE: {}", self.reason);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_ports_fail_closed_without_wfp_evidence() {
        let capability = PortIsolationCapability::detect();
        assert!(!capability.available);
        assert!(capability.require_available().is_err());
    }
}
