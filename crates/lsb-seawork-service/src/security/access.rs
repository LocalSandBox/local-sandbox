use anyhow::{bail, Result};
use windows_sys::Win32::System::SystemServices::SECURITY_MANDATORY_MEDIUM_RID;

use super::token::TokenSnapshot;

pub fn authorize_interactive_client(token: &TokenSnapshot) -> Result<()> {
    if token.session_id == 0
        || token.user_sid.is_empty()
        || matches!(
            token.user_sid.to_ascii_uppercase().as_str(),
            "S-1-5-7" | "S-1-5-18" | "S-1-5-19" | "S-1-5-20"
        )
    {
        bail!("anonymous and service identities are not accepted");
    }
    if token.is_app_container {
        bail!("AppContainer clients are not accepted");
    }
    if token.integrity_rid < SECURITY_MANDATORY_MEDIUM_RID as u32 {
        bail!("low-integrity clients are not accepted");
    }
    if token.logon_sid.is_empty() {
        bail!("client token has no interactive logon SID");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> TokenSnapshot {
        TokenSnapshot {
            user_sid: "S-1-5-21-test".to_string(),
            logon_sid: "S-1-5-5-test".to_string(),
            authentication_luid: 1,
            session_id: 1,
            integrity_rid: SECURITY_MANDATORY_MEDIUM_RID as u32,
            is_app_container: false,
            elevated: false,
            administrator: false,
        }
    }

    #[test]
    fn rejects_low_integrity_and_appcontainer() {
        let mut token = snapshot();
        assert!(authorize_interactive_client(&token).is_ok());
        token.integrity_rid = 0x1000;
        assert!(authorize_interactive_client(&token).is_err());
        token.integrity_rid = SECURITY_MANDATORY_MEDIUM_RID as u32;
        token.is_app_container = true;
        assert!(authorize_interactive_client(&token).is_err());
        token.is_app_container = false;
        token.user_sid = "S-1-5-18".to_string();
        assert!(authorize_interactive_client(&token).is_err());
    }
}
