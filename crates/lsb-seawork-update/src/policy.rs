use std::io::{Read, Write};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use semver::Version;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use time::format_description::well_known::{Rfc2822, Rfc3339};
use time::OffsetDateTime;

use crate::{FailedTargetState, ReleaseCandidate, ReleaseChannel};

const FAILED_TARGET_COOLDOWN_SECONDS: i64 = 24 * 60 * 60;
const MAX_HELPER_VERSION_OUTPUT_BYTES: usize = 4 * 1024;
const MAX_RELEASE_PAGES: usize = 10;
const RELEASES_PER_PAGE: usize = 50;
const MAX_ETAG_BYTES: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseResponseStatus {
    Success,
    NotModified { etag: String },
    RateLimited,
    HttpFailure { status: u16 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleasePageProgress {
    pub etag: Option<String>,
    pub complete: bool,
}

pub fn classify_release_response(
    page: usize,
    status: u16,
    conditional_etag: Option<&str>,
) -> Result<ReleaseResponseStatus> {
    if !(1..=MAX_RELEASE_PAGES).contains(&page) {
        bail!("GitHub release page is outside the compiled limit");
    }
    match status {
        200 => Ok(ReleaseResponseStatus::Success),
        304 if page == 1 => {
            let etag = conditional_etag.context("unconditional GitHub response returned 304")?;
            validate_etag(etag)?;
            Ok(ReleaseResponseStatus::NotModified {
                etag: etag.to_string(),
            })
        }
        403 | 429 => Ok(ReleaseResponseStatus::RateLimited),
        _ => Ok(ReleaseResponseStatus::HttpFailure { status }),
    }
}

pub fn validate_release_page(
    page: usize,
    release_count: usize,
    response_etag: Option<&str>,
) -> Result<ReleasePageProgress> {
    if !(1..=MAX_RELEASE_PAGES).contains(&page) || release_count > RELEASES_PER_PAGE {
        bail!("GitHub release pagination exceeds the compiled limit");
    }
    let etag = if page == 1 {
        response_etag
            .map(validate_etag)
            .transpose()?
            .map(str::to_string)
    } else {
        None
    };
    let complete = release_count < RELEASES_PER_PAGE;
    if page == MAX_RELEASE_PAGES && !complete {
        bail!("GitHub release pagination exceeds the compiled limit");
    }
    Ok(ReleasePageProgress { etag, complete })
}

fn validate_etag(value: &str) -> Result<&str> {
    if value.is_empty()
        || value.len() > MAX_ETAG_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        bail!("GitHub release ETag is invalid");
    }
    Ok(value)
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperVersionOutput {
    pub service_name: String,
    pub helper_version: String,
    pub helper_protocol_major: u16,
    pub helper_protocol_minor: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperInstallOutput {
    pub valid: bool,
    pub service_name: String,
    pub helper_version: String,
    pub helper_protocol_major: u16,
    pub helper_protocol_minor: u16,
    pub error: Option<String>,
}

pub fn validate_helper_version_output(
    bytes: &[u8],
    expected_service_name: &str,
    required_protocol: crate::HelperProtocol,
) -> Result<HelperVersionOutput> {
    if bytes.is_empty() || bytes.len() > MAX_HELPER_VERSION_OUTPUT_BYTES {
        bail!("helper protocol version output is outside bounds");
    }
    let output: HelperVersionOutput =
        serde_json::from_slice(bytes).context("parse helper protocol version output")?;
    validate_helper_identity(&output, expected_service_name, required_protocol)?;
    Ok(output)
}

pub fn validate_helper_install_output(
    bytes: &[u8],
    expected_service_name: &str,
    required_protocol: crate::HelperProtocol,
) -> Result<HelperInstallOutput> {
    if bytes.is_empty() || bytes.len() > MAX_HELPER_VERSION_OUTPUT_BYTES {
        bail!("helper protocol install output is outside bounds");
    }
    let output: HelperInstallOutput =
        serde_json::from_slice(bytes).context("parse helper protocol install output")?;
    let version = HelperVersionOutput {
        service_name: output.service_name.clone(),
        helper_version: output.helper_version.clone(),
        helper_protocol_major: output.helper_protocol_major,
        helper_protocol_minor: output.helper_protocol_minor,
    };
    validate_helper_identity(&version, expected_service_name, required_protocol)?;
    if !output.valid || output.error.is_some() {
        bail!("helper protocol installation is not valid");
    }
    Ok(output)
}

fn validate_helper_identity(
    output: &HelperVersionOutput,
    expected_service_name: &str,
    required_protocol: crate::HelperProtocol,
) -> Result<()> {
    required_protocol.validate()?;
    if output.service_name != expected_service_name
        || Version::parse(&output.helper_version).is_err()
        || output.helper_protocol_major != required_protocol.major
        || output.helper_protocol_minor < required_protocol.minor
    {
        bail!("helper protocol is incompatible with compiled product policy");
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailedTargetDecision {
    Allowed,
    Cooldown { retry_after_utc: String },
    Suppressed,
}

pub fn retry_delay(attempt: u8) -> Duration {
    let exponent = attempt.saturating_sub(1).min(6);
    Duration::from_secs(5 * 60 * (1u64 << exponent))
}

pub fn bounded_retry_delay(deadline: OffsetDateTime, now: OffsetDateTime) -> Duration {
    let seconds = (deadline - now).whole_seconds().clamp(60, 24 * 60 * 60);
    Duration::from_secs(seconds as u64)
}

pub fn validate_download_url(value: &str, initial: bool) -> Result<()> {
    let url = url::Url::parse(value)?;
    let allowed = [
        "github.com",
        "objects.githubusercontent.com",
        "github-releases.githubusercontent.com",
        "release-assets.githubusercontent.com",
    ];
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none_or(|host| !allowed.contains(&host))
        || (initial && url.host_str() != Some("github.com"))
    {
        bail!("release asset URL violates compiled redirect policy");
    }
    Ok(())
}

pub fn parse_retry_after_utc(
    retry_after: Option<&str>,
    rate_limit_reset: Option<&str>,
    now: OffsetDateTime,
) -> Option<String> {
    let retry = retry_after.and_then(|value| {
        value
            .parse::<u64>()
            .ok()
            .and_then(|seconds| i64::try_from(seconds.min(24 * 60 * 60)).ok())
            .map(|seconds| now + time::Duration::seconds(seconds))
            .or_else(|| OffsetDateTime::parse(value, &Rfc2822).ok())
    });
    let reset = rate_limit_reset
        .and_then(|value| value.parse::<i64>().ok())
        .and_then(|seconds| OffsetDateTime::from_unix_timestamp(seconds).ok());
    retry
        .or(reset)
        .filter(|deadline| *deadline > now)
        .and_then(|deadline| deadline.format(&Rfc3339).ok())
}

pub fn cached_candidate(
    candidate: Option<&ReleaseCandidate>,
    channel: ReleaseChannel,
    current_version: &str,
    highest_committed_version: &str,
) -> Result<Option<ReleaseCandidate>> {
    let Some(candidate) = candidate else {
        return Ok(None);
    };
    candidate.validate()?;
    let version = Version::parse(&candidate.version)?;
    let baseline = Version::parse(current_version)?.max(Version::parse(highest_committed_version)?);
    if version <= baseline || (channel == ReleaseChannel::Stable && candidate.prerelease) {
        return Ok(None);
    }
    Ok(Some(candidate.clone()))
}

pub fn failed_target_decision(
    candidate: &ReleaseCandidate,
    failed: &FailedTargetState,
    now: OffsetDateTime,
) -> Result<FailedTargetDecision> {
    candidate.validate()?;
    failed.validate()?;
    if Version::parse(&candidate.version)? > Version::parse(&failed.target_version)?
        || candidate.archive_sha256 != failed.archive_sha256
    {
        return Ok(FailedTargetDecision::Allowed);
    }
    if failed.suppressed {
        return Ok(FailedTargetDecision::Suppressed);
    }
    let rollback = OffsetDateTime::parse(&failed.last_rollback_utc, &Rfc3339)?;
    let retry_after = rollback + time::Duration::seconds(FAILED_TARGET_COOLDOWN_SECONDS);
    if retry_after > now {
        return Ok(FailedTargetDecision::Cooldown {
            retry_after_utc: retry_after.format(&Rfc3339)?,
        });
    }
    Ok(FailedTargetDecision::Allowed)
}

pub fn stream_exact_asset(
    reader: &mut impl Read,
    writer: &mut impl Write,
    expected_size: u64,
    expected_sha256: &str,
    mut cancelled: impl FnMut() -> bool,
) -> Result<()> {
    if expected_size == 0
        || expected_sha256.len() != 64
        || !expected_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("immutable asset identity is invalid");
    }
    let mut hasher = Sha256::new();
    let mut count = 0u64;
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        if cancelled() {
            bail!("service shutdown cancelled update download");
        }
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        count = count
            .checked_add(read as u64)
            .context("download size overflow")?;
        if count > expected_size {
            bail!("download exceeds immutable declared asset size");
        }
        writer.write_all(&buffer[..read])?;
        hasher.update(&buffer[..read]);
    }
    if count != expected_size || format!("{:x}", hasher.finalize()) != expected_sha256 {
        bail!("download size or digest differs from immutable release metadata");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HELPER_SERVICE: &str = "LocalSandboxSeaWorkUpdater";

    fn candidate(version: &str, prerelease: bool, digest: char) -> ReleaseCandidate {
        let name = format!("lsb-seawork-service-v{version}-windows-x86_64.zip");
        ReleaseCandidate {
            release_id: 7,
            version: version.to_string(),
            prerelease,
            asset_name: name.clone(),
            asset_url: format!(
                "https://github.com/LocalSandBox/local-sandbox/releases/download/v{version}/{name}"
            ),
            asset_size: 7,
            archive_sha256: digest.to_string().repeat(64),
        }
    }

    #[test]
    fn redirect_policy_is_fixed_https_and_host_bounded() {
        assert!(validate_download_url(
            "https://github.com/LocalSandBox/local-sandbox/releases/download/v1/a.zip",
            true
        )
        .is_ok());
        assert!(validate_download_url(
            "https://release-assets.githubusercontent.com/github-production-release-asset/x",
            false
        )
        .is_ok());
        for url in [
            "http://github.com/a",
            "https://evil.example/a",
            "https://user@github.com/a",
        ] {
            assert!(validate_download_url(url, false).is_err());
        }
    }

    #[test]
    fn conditional_etag_and_pagination_responses_are_deterministic() {
        assert_eq!(
            classify_release_response(1, 304, Some("\"immutable-etag\"")).unwrap(),
            ReleaseResponseStatus::NotModified {
                etag: "\"immutable-etag\"".to_string()
            }
        );
        assert!(classify_release_response(1, 304, None).is_err());
        assert_eq!(
            classify_release_response(1, 429, None).unwrap(),
            ReleaseResponseStatus::RateLimited
        );
        assert_eq!(
            classify_release_response(2, 503, None).unwrap(),
            ReleaseResponseStatus::HttpFailure { status: 503 }
        );

        let first = validate_release_page(1, 50, Some("W/\"page-one\"")).unwrap();
        assert_eq!(first.etag.as_deref(), Some("W/\"page-one\""));
        assert!(!first.complete);
        assert!(
            validate_release_page(2, 49, Some("ignored-on-later-pages"))
                .unwrap()
                .complete
        );
        assert!(validate_release_page(10, 50, None).is_err());
        assert!(validate_release_page(1, 0, Some(&"x".repeat(513))).is_err());
        assert!(classify_release_response(0, 200, None).is_err());
    }

    #[test]
    fn helper_version_requires_exact_identity_and_compatible_protocol() {
        let required = crate::HelperProtocol { major: 1, minor: 1 };
        let compatible = br#"{
            "service_name":"LocalSandboxSeaWorkUpdater",
            "helper_version":"0.5.0-rc.1",
            "helper_protocol_major":1,
            "helper_protocol_minor":2
        }"#;
        assert_eq!(
            validate_helper_version_output(compatible, HELPER_SERVICE, required)
                .unwrap()
                .helper_protocol_minor,
            2
        );
        for incompatible in [
            br#"{"service_name":"wrong","helper_version":"0.5.0","helper_protocol_major":1,"helper_protocol_minor":1}"#.as_slice(),
            br#"{"service_name":"LocalSandboxSeaWorkUpdater","helper_version":"invalid","helper_protocol_major":1,"helper_protocol_minor":1}"#.as_slice(),
            br#"{"service_name":"LocalSandboxSeaWorkUpdater","helper_version":"0.5.0","helper_protocol_major":2,"helper_protocol_minor":1}"#.as_slice(),
            br#"{"service_name":"LocalSandboxSeaWorkUpdater","helper_version":"0.5.0","helper_protocol_major":1,"helper_protocol_minor":0}"#.as_slice(),
            br#"{"service_name":"LocalSandboxSeaWorkUpdater","helper_version":"0.5.0","helper_protocol_major":1,"helper_protocol_minor":1,"extra":true}"#.as_slice(),
        ] {
            assert!(validate_helper_version_output(incompatible, HELPER_SERVICE, required).is_err());
        }
        assert!(validate_helper_version_output(
            &vec![b'x'; MAX_HELPER_VERSION_OUTPUT_BYTES + 1],
            HELPER_SERVICE,
            required
        )
        .is_err());
    }

    #[test]
    fn helper_install_requires_a_strict_successful_self_check() {
        let required = crate::HelperProtocol { major: 1, minor: 1 };
        let valid = br#"{
            "valid":true,
            "service_name":"LocalSandboxSeaWorkUpdater",
            "helper_version":"0.5.0",
            "helper_protocol_major":1,
            "helper_protocol_minor":1,
            "error":null
        }"#;
        assert!(validate_helper_install_output(valid, HELPER_SERVICE, required).is_ok());
        for invalid in [
            br#"{"valid":false,"service_name":"LocalSandboxSeaWorkUpdater","helper_version":"0.5.0","helper_protocol_major":1,"helper_protocol_minor":1,"error":"SCM mismatch"}"#.as_slice(),
            br#"{"valid":true,"service_name":"LocalSandboxSeaWorkUpdater","helper_version":"0.5.0","helper_protocol_major":1,"helper_protocol_minor":1,"error":"contradictory"}"#.as_slice(),
            br#"{"valid":true,"service_name":"LocalSandboxSeaWorkUpdater","helper_version":"0.5.0","helper_protocol_major":1,"helper_protocol_minor":1,"error":null,"extra":true}"#.as_slice(),
        ] {
            assert!(validate_helper_install_output(invalid, HELPER_SERVICE, required).is_err());
        }
    }

    #[test]
    fn retry_is_exponential_bounded_and_honors_server_deadlines() {
        assert_eq!(retry_delay(1), Duration::from_secs(5 * 60));
        assert_eq!(retry_delay(2), Duration::from_secs(10 * 60));
        assert_eq!(retry_delay(10), Duration::from_secs(320 * 60));
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        assert_eq!(
            parse_retry_after_utc(Some("120"), None, now).unwrap(),
            (now + time::Duration::seconds(120))
                .format(&Rfc3339)
                .unwrap()
        );
        assert!(parse_retry_after_utc(None, Some("1"), now).is_none());
        assert_eq!(
            bounded_retry_delay(now + time::Duration::seconds(120), now),
            Duration::from_secs(120)
        );
        assert_eq!(
            bounded_retry_delay(now - time::Duration::hours(1), now),
            Duration::from_secs(60),
            "an expired deadline or a wall-clock rollback must not create a tight loop"
        );
        assert_eq!(
            bounded_retry_delay(now + time::Duration::days(2), now),
            Duration::from_secs(24 * 60 * 60)
        );
    }

    #[test]
    fn cached_candidates_remain_channel_and_high_water_bound() {
        let prerelease = candidate("0.5.1-rc.1", true, 'a');
        assert!(
            cached_candidate(Some(&prerelease), ReleaseChannel::Stable, "0.5.0", "0.5.0")
                .unwrap()
                .is_none()
        );
        assert!(cached_candidate(
            Some(&prerelease),
            ReleaseChannel::Prerelease,
            "0.5.0",
            "0.5.0"
        )
        .unwrap()
        .is_some());
        assert!(cached_candidate(
            Some(&prerelease),
            ReleaseChannel::Prerelease,
            "0.5.0",
            "0.5.1"
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn failed_digest_cooldown_and_suppression_survive_restart_state() {
        let release = candidate("0.5.1", false, 'b');
        let now = OffsetDateTime::parse("2026-07-23T11:00:00Z", &Rfc3339).unwrap();
        let mut failed = FailedTargetState {
            target_version: release.version.clone(),
            archive_sha256: release.archive_sha256.clone(),
            rollback_count: 1,
            last_rollback_utc: "2026-07-22T12:00:00Z".to_string(),
            suppressed: false,
        };
        assert!(matches!(
            failed_target_decision(&release, &failed, now).unwrap(),
            FailedTargetDecision::Cooldown { .. }
        ));
        failed.rollback_count = 3;
        failed.suppressed = true;
        assert_eq!(
            failed_target_decision(&release, &failed, now).unwrap(),
            FailedTargetDecision::Suppressed
        );
        assert_eq!(
            failed_target_decision(&candidate("0.5.2", false, 'c'), &failed, now).unwrap(),
            FailedTargetDecision::Allowed
        );
    }

    #[test]
    fn exact_stream_rejects_partial_oversized_digest_and_cancellation() {
        let bytes = b"payload";
        let digest = format!("{:x}", Sha256::digest(bytes));
        let bad_digest = "a".repeat(64);
        let mut output = Vec::new();
        stream_exact_asset(&mut bytes.as_slice(), &mut output, 7, &digest, || false).unwrap();
        assert_eq!(output, bytes);
        for (mut input, size, hash) in [
            (b"short".as_slice(), 7, digest.as_str()),
            (b"too-long".as_slice(), 7, digest.as_str()),
            (bytes.as_slice(), 7, bad_digest.as_str()),
        ] {
            assert!(stream_exact_asset(&mut input, &mut Vec::new(), size, hash, || false).is_err());
        }
        assert!(
            stream_exact_asset(&mut bytes.as_slice(), &mut Vec::new(), 7, &digest, || true)
                .is_err()
        );
    }
}
