use std::error::Error;
use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::password::WindowsSmbPasswordGenerator;
use super::share::WindowsSmbShareName;
use super::user::WindowsSmbUserName;

pub const WINDOWS_SMB_GATEWAY_SERVER: &str = "10.0.0.1";
pub const WINDOWS_SMB_USER_PREFIX: &str = "lsb_";
pub const WINDOWS_SMB_USER_HEX_LEN: usize = 12;
pub const WINDOWS_SMB_MAX_USER_NAME_LEN: usize = 20;
pub const WINDOWS_SMB_SHARE_PREFIX: &str = "lsb-";
pub const WINDOWS_SMB_MAX_SHARE_NAME_LEN: usize = 80;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WindowsSmbAccess {
    ReadOnly,
    ReadWrite,
}

impl WindowsSmbAccess {
    pub fn read_only(self) -> bool {
        matches!(self, Self::ReadOnly)
    }

    pub fn file_mode(self) -> u32 {
        match self {
            Self::ReadOnly => 0o644,
            Self::ReadWrite => 0o666,
        }
    }

    pub fn dir_mode(self) -> u32 {
        match self {
            Self::ReadOnly => 0o755,
            Self::ReadWrite => 0o777,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsSmbMount {
    pub source: PathBuf,
    pub target: String,
    pub access: WindowsSmbAccess,
}

impl WindowsSmbMount {
    pub fn read_only(source: impl Into<PathBuf>, target: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            target: target.into(),
            access: WindowsSmbAccess::ReadOnly,
        }
    }

    pub fn read_write(source: impl Into<PathBuf>, target: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            target: target.into(),
            access: WindowsSmbAccess::ReadWrite,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsSmbLifecycleConfig {
    pub instance_id: String,
    pub mounts: Vec<WindowsSmbMount>,
}

impl WindowsSmbLifecycleConfig {
    pub fn new(instance_id: impl Into<String>, mounts: Vec<WindowsSmbMount>) -> Self {
        Self {
            instance_id: instance_id.into(),
            mounts,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsSmbLifecyclePhase {
    AdminPreflight,
    PasswordGeneration,
    UserNameGeneration,
    ShareNameGeneration,
    UserCreate,
    UserDelete,
    AclGrant,
    AclRevoke,
    ShareCreate,
    ShareRemove,
    ComputerName,
    CleanupManifest,
    SmbLoopbackPreflight,
}

impl WindowsSmbLifecyclePhase {
    pub fn label(self) -> &'static str {
        match self {
            Self::AdminPreflight => "admin preflight",
            Self::PasswordGeneration => "password generation",
            Self::UserNameGeneration => "user name generation",
            Self::ShareNameGeneration => "share name generation",
            Self::UserCreate => "user creation",
            Self::UserDelete => "user deletion",
            Self::AclGrant => "NTFS ACL grant",
            Self::AclRevoke => "NTFS ACL revoke",
            Self::ShareCreate => "SMB share creation",
            Self::ShareRemove => "SMB share removal",
            Self::ComputerName => "computer name lookup",
            Self::CleanupManifest => "cleanup manifest",
            Self::SmbLoopbackPreflight => "SMB loopback preflight",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsSmbCleanupFailure {
    pub phase: WindowsSmbLifecyclePhase,
    pub detail: String,
}

impl WindowsSmbCleanupFailure {
    pub fn new(phase: WindowsSmbLifecyclePhase, detail: impl Into<String>) -> Self {
        Self {
            phase,
            detail: sanitize_error_detail(detail),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WindowsSmbLifecycleError {
    NotElevated,
    OperationFailed {
        phase: WindowsSmbLifecyclePhase,
        detail: String,
    },
    SetupFailed {
        phase: WindowsSmbLifecyclePhase,
        detail: String,
        cleanup_failures: Vec<WindowsSmbCleanupFailure>,
    },
    CleanupFailed {
        failures: Vec<WindowsSmbCleanupFailure>,
    },
    InvalidUserName {
        reason: String,
    },
    InvalidShareName {
        reason: String,
    },
}

impl WindowsSmbLifecycleError {
    pub fn operation_failed(phase: WindowsSmbLifecyclePhase, detail: impl Into<String>) -> Self {
        Self::OperationFailed {
            phase,
            detail: sanitize_error_detail(detail),
        }
    }

    pub fn with_cleanup_failures(self, cleanup_failures: Vec<WindowsSmbCleanupFailure>) -> Self {
        if cleanup_failures.is_empty() {
            return self;
        }

        match self {
            Self::OperationFailed { phase, detail } => Self::SetupFailed {
                phase,
                detail,
                cleanup_failures,
            },
            Self::InvalidUserName { reason } => Self::SetupFailed {
                phase: WindowsSmbLifecyclePhase::UserNameGeneration,
                detail: reason,
                cleanup_failures,
            },
            Self::InvalidShareName { reason } => Self::SetupFailed {
                phase: WindowsSmbLifecyclePhase::ShareNameGeneration,
                detail: reason,
                cleanup_failures,
            },
            other => other,
        }
    }

    pub fn cleanup_failures(&self) -> &[WindowsSmbCleanupFailure] {
        match self {
            Self::SetupFailed {
                cleanup_failures, ..
            } => cleanup_failures,
            Self::CleanupFailed { failures } => failures,
            _ => &[],
        }
    }
}

impl fmt::Display for WindowsSmbLifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotElevated => {
                f.write_str("Windows direct mounts require an elevated Administrator shell")
            }
            Self::OperationFailed { phase, detail } => {
                write!(f, "Windows SMB {} failed: {detail}", phase.label())
            }
            Self::SetupFailed {
                phase,
                detail,
                cleanup_failures,
            } => write!(
                f,
                "Windows SMB {} failed: {detail}; best-effort cleanup had {} failure(s)",
                phase.label(),
                cleanup_failures.len()
            ),
            Self::CleanupFailed { failures } => write!(
                f,
                "Windows SMB cleanup failed for {} resource operation(s)",
                failures.len()
            ),
            Self::InvalidUserName { reason } => {
                write!(f, "generated Windows SMB user name is invalid: {reason}")
            }
            Self::InvalidShareName { reason } => {
                write!(f, "generated Windows SMB share name is invalid: {reason}")
            }
        }
    }
}

impl Error for WindowsSmbLifecycleError {}

pub fn generate_smb_user_name(
    generator: &mut impl WindowsSmbPasswordGenerator,
) -> Result<WindowsSmbUserName, WindowsSmbLifecycleError> {
    let mut bytes = [0u8; WINDOWS_SMB_USER_HEX_LEN / 2];
    generator.fill_random_bytes(&mut bytes)?;
    let name = format!("{WINDOWS_SMB_USER_PREFIX}{}", lower_hex(&bytes));
    validate_smb_user_name(&name)?;
    Ok(WindowsSmbUserName::new_unchecked(name))
}

pub fn generate_smb_share_name(
    instance_id: &str,
    mount_index: usize,
    generator: &mut impl WindowsSmbPasswordGenerator,
) -> Result<WindowsSmbShareName, WindowsSmbLifecycleError> {
    let mut bytes = [0u8; 4];
    generator.fill_random_bytes(&mut bytes)?;
    let instance = share_instance_component(instance_id);
    let name = format!(
        "{WINDOWS_SMB_SHARE_PREFIX}{instance}-m{mount_index}-{}",
        lower_hex(&bytes)
    );
    validate_smb_share_name(&name)?;
    Ok(WindowsSmbShareName::new_unchecked(name))
}

pub fn validate_smb_user_name(name: &str) -> Result<(), WindowsSmbLifecycleError> {
    if name.is_empty() {
        return Err(WindowsSmbLifecycleError::InvalidUserName {
            reason: "name is empty".to_string(),
        });
    }
    if name.len() > WINDOWS_SMB_MAX_USER_NAME_LEN {
        return Err(WindowsSmbLifecycleError::InvalidUserName {
            reason: format!(
                "name exceeds Windows {} character limit",
                WINDOWS_SMB_MAX_USER_NAME_LEN
            ),
        });
    }
    if !name.starts_with(WINDOWS_SMB_USER_PREFIX) {
        return Err(WindowsSmbLifecycleError::InvalidUserName {
            reason: "name must use the LocalSandbox lsb_ prefix".to_string(),
        });
    }
    if name
        .chars()
        .any(|ch| !(ch.is_ascii_alphanumeric() || ch == '_'))
    {
        return Err(WindowsSmbLifecycleError::InvalidUserName {
            reason: "name contains characters disallowed for generated SMB users".to_string(),
        });
    }
    Ok(())
}

pub fn validate_smb_share_name(name: &str) -> Result<(), WindowsSmbLifecycleError> {
    if name.is_empty() {
        return Err(WindowsSmbLifecycleError::InvalidShareName {
            reason: "name is empty".to_string(),
        });
    }
    if name.len() > WINDOWS_SMB_MAX_SHARE_NAME_LEN {
        return Err(WindowsSmbLifecycleError::InvalidShareName {
            reason: format!(
                "name exceeds Windows {} character limit",
                WINDOWS_SMB_MAX_SHARE_NAME_LEN
            ),
        });
    }
    if !name.starts_with(WINDOWS_SMB_SHARE_PREFIX) {
        return Err(WindowsSmbLifecycleError::InvalidShareName {
            reason: "name must use the LocalSandbox lsb- prefix".to_string(),
        });
    }
    let lower = name.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "ipc$" | "admin$" | "pipe" | "mailslot" | "print$"
    ) || (lower.len() == 2 && lower.ends_with('$') && lower.as_bytes()[0].is_ascii_alphabetic())
    {
        return Err(WindowsSmbLifecycleError::InvalidShareName {
            reason: "name collides with a reserved Windows share name".to_string(),
        });
    }
    if name.chars().any(is_invalid_share_char) {
        return Err(WindowsSmbLifecycleError::InvalidShareName {
            reason: "name contains characters disallowed for generated SMB shares".to_string(),
        });
    }
    Ok(())
}

pub fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub fn sanitize_error_detail(detail: impl Into<String>) -> String {
    let detail = detail.into();
    if detail.is_empty() {
        return "unknown error".to_string();
    }
    detail.replace('\0', "<nul>")
}

fn share_instance_component(instance_id: &str) -> String {
    let component: String = instance_id
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_lowercase())
        .take(16)
        .collect();
    if component.is_empty() {
        "inst".to_string()
    } else {
        component
    }
}

fn is_invalid_share_char(ch: char) -> bool {
    ch.is_control()
        || matches!(
            ch,
            '"' | '/'
                | '\\'
                | '['
                | ']'
                | ':'
                | '|'
                | '<'
                | '>'
                | '+'
                | '='
                | ';'
                | ','
                | '?'
                | '*'
        )
}
