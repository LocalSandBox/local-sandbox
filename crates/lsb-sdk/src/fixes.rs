use anyhow::Result;

/// Result of an automatic host configuration fix applied during initialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxFixResult {
    /// Stable name of the fix.
    pub name: String,
    /// True when the fix changed host configuration.
    pub changed: bool,
}

/// Apply every automatic host configuration fix supported by this SDK build.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub fn apply_sandbox_fixes() -> Result<Vec<SandboxFixResult>> {
    let report = lsb_platform::windows_x86_64::fs::smb::fix_windows_smb_policy()?;
    Ok(vec![SandboxFixResult {
        name: "windows-smb-policy".to_string(),
        changed: report.changed,
    }])
}

/// Return no fixes on hosts without automatic host configuration repairs.
#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub fn apply_sandbox_fixes() -> Result<Vec<SandboxFixResult>> {
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    #[test]
    fn automatic_fixes_are_a_noop_on_unsupported_hosts() {
        assert!(apply_sandbox_fixes()
            .expect("fixes should succeed")
            .is_empty());
    }
}
