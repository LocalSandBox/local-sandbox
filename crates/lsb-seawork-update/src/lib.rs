mod archive;
mod committed;
mod discovery;
mod journal;

pub use archive::{extract_zip_archive, ArchiveExtraction};
pub use committed::{CommittedState, CommittedStateEnvelope, FailedTargetState};
pub use discovery::{ReleaseCandidate, ReleaseChannel, ReleaseSelector};
pub use journal::{HelperProtocol, TransactionEnvelope, TransactionPhase, UpdateTransaction};

pub const UPDATE_STATE_SCHEMA_VERSION: u32 = 1;

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_id(value: &str) -> anyhow::Result<()> {
    if !is_lower_hex(value, 32) {
        anyhow::bail!("identifier must be 32 lowercase hexadecimal characters");
    }
    Ok(())
}

fn validate_utc(value: &str) -> anyhow::Result<()> {
    if value.len() < 20
        || value.len() > 40
        || !value.ends_with('Z')
        || value.as_bytes().get(4) != Some(&b'-')
        || value.as_bytes().get(7) != Some(&b'-')
        || value.as_bytes().get(10) != Some(&b'T')
        || value.as_bytes().get(13) != Some(&b':')
        || value.as_bytes().get(16) != Some(&b':')
        || value.chars().any(char::is_whitespace)
    {
        anyhow::bail!("UTC timestamp is not bounded canonical RFC 3339 form");
    }
    Ok(())
}

fn validate_windows_absolute_path(value: &str) -> anyhow::Result<()> {
    if value.len() < 3
        || value.len() > 1024
        || value.contains('\0')
        || !value.as_bytes()[0].is_ascii_alphabetic()
        || value.as_bytes()[1] != b':'
        || value.as_bytes()[2] != b'\\'
        || value.contains('/')
        || value
            .split('\\')
            .skip(1)
            .any(|part| part.is_empty() || part == "." || part == ".." || part.contains(':'))
    {
        anyhow::bail!("transaction path is not a bounded absolute Windows path");
    }
    Ok(())
}

fn sha256_json<T: serde::Serialize>(value: &T) -> anyhow::Result<String> {
    use sha2::{Digest, Sha256};

    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}
