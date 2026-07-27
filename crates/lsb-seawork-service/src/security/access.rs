use anyhow::{bail, Result};
use windows_sys::Win32::System::SystemServices::{
    SECURITY_MANDATORY_MEDIUM_RID, SECURITY_MANDATORY_SYSTEM_RID,
};

use super::token::TokenSnapshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientTokenClass {
    Interactive,
    LocalSystemMaintenance,
}

pub fn classify_client_token(token: &TokenSnapshot) -> Result<ClientTokenClass> {
    if token.user_sid.eq_ignore_ascii_case("S-1-5-18") {
        if token.session_id != 0
            || token.is_app_container
            || token.integrity_rid < SECURITY_MANDATORY_SYSTEM_RID as u32
        {
            bail!("LocalSystem maintenance client token is inconsistent");
        }
        return Ok(ClientTokenClass::LocalSystemMaintenance);
    }
    if token.session_id == 0
        || token.user_sid.is_empty()
        || matches!(
            token.user_sid.to_ascii_uppercase().as_str(),
            "S-1-5-7" | "S-1-5-19" | "S-1-5-20"
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
    Ok(ClientTokenClass::Interactive)
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
    fn classifies_interactive_clients_and_rejects_untrusted_token_classes() {
        let mut token = snapshot();
        assert_eq!(
            classify_client_token(&token).unwrap(),
            ClientTokenClass::Interactive
        );
        token.integrity_rid = 0x1000;
        assert!(classify_client_token(&token).is_err());
        token.integrity_rid = SECURITY_MANDATORY_MEDIUM_RID as u32;
        token.is_app_container = true;
        assert!(classify_client_token(&token).is_err());
        token.is_app_container = false;
        token.user_sid = "S-1-5-19".to_string();
        assert!(classify_client_token(&token).is_err());
    }

    #[test]
    fn admits_only_session_zero_local_system_as_maintenance() {
        let mut token = snapshot();
        token.user_sid = "S-1-5-18".to_string();
        token.session_id = 0;
        token.logon_sid.clear();
        token.integrity_rid = SECURITY_MANDATORY_SYSTEM_RID as u32;
        assert_eq!(
            classify_client_token(&token).unwrap(),
            ClientTokenClass::LocalSystemMaintenance
        );

        token.session_id = 1;
        assert!(classify_client_token(&token).is_err());
        token.session_id = 0;
        token.is_app_container = true;
        assert!(classify_client_token(&token).is_err());
        token.is_app_container = false;
        token.integrity_rid = SECURITY_MANDATORY_MEDIUM_RID as u32;
        assert!(classify_client_token(&token).is_err());
    }
}
