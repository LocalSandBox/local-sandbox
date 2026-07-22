use std::collections::BTreeMap;

use anyhow::{bail, Context, Result};
use semver::Version;
use serde::{Deserialize, Serialize};

const MAX_RELEASE_JSON_BYTES: usize = 2 * 1024 * 1024;
const MAX_RELEASE_PAGES: usize = 10;
const MAX_RELEASES: usize = 500;
const MAX_ARCHIVE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_JSON_DEPTH: usize = 16;
const MAX_JSON_STRING_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseChannel {
    #[default]
    Stable,
    Prerelease,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseCandidate {
    pub release_id: u64,
    pub version: String,
    pub prerelease: bool,
    pub asset_name: String,
    pub asset_url: String,
    pub asset_size: u64,
    pub archive_sha256: String,
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    id: u64,
    tag_name: String,
    draft: bool,
    prerelease: bool,
    immutable: bool,
    assets: Vec<GithubAsset>,
}

#[derive(Debug, Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
    state: String,
    size: u64,
    digest: Option<String>,
}

#[derive(Debug, Default)]
pub struct ReleaseSelector {
    pages: usize,
    inspected: usize,
    candidates: BTreeMap<Version, ReleaseCandidate>,
    ambiguous: bool,
}

impl ReleaseSelector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_page(&mut self, bytes: &[u8]) -> Result<()> {
        if self.pages >= MAX_RELEASE_PAGES {
            bail!("GitHub release pagination exceeds the compiled limit");
        }
        if bytes.len() > MAX_RELEASE_JSON_BYTES {
            bail!("GitHub release page exceeds the compiled byte limit");
        }
        let value: serde_json::Value = serde_json::from_slice(bytes)?;
        validate_json_value(&value, 0)?;
        let releases: Vec<GithubRelease> = serde_json::from_value(value)?;
        self.pages += 1;
        self.inspected = self
            .inspected
            .checked_add(releases.len())
            .context("release count overflow")?;
        if self.inspected > MAX_RELEASES {
            bail!("GitHub releases exceed the compiled count limit");
        }
        for release in releases {
            let Some((version, candidate)) = candidate_from_release(release)? else {
                continue;
            };
            if self.candidates.insert(version, candidate).is_some() {
                self.ambiguous = true;
            }
        }
        Ok(())
    }

    pub fn select(
        &self,
        channel: ReleaseChannel,
        current_version: &str,
        highest_committed_version: &str,
    ) -> Result<Option<ReleaseCandidate>> {
        if self.ambiguous {
            bail!("GitHub release selection has ambiguous SemVer precedence");
        }
        let current = parse_canonical_version(current_version)?;
        let highest = parse_canonical_version(highest_committed_version)?;
        let baseline = current.max(highest);
        Ok(self
            .candidates
            .iter()
            .rev()
            .find(|(version, candidate)| {
                **version > baseline
                    && match channel {
                        ReleaseChannel::Stable => !candidate.prerelease,
                        ReleaseChannel::Prerelease => true,
                    }
            })
            .map(|(_, candidate)| candidate.clone()))
    }
}

fn candidate_from_release(release: GithubRelease) -> Result<Option<(Version, ReleaseCandidate)>> {
    if release.draft || !release.immutable {
        return Ok(None);
    }
    if release.id == 0 || release.tag_name.len() > 128 {
        bail!("GitHub release identity is invalid");
    }
    let Some(raw_version) = release.tag_name.strip_prefix('v') else {
        return Ok(None);
    };
    let version = match parse_canonical_version(raw_version) {
        Ok(version) => version,
        Err(_) => return Ok(None),
    };
    if release.tag_name != format!("v{version}") || release.prerelease != !version.pre.is_empty() {
        return Ok(None);
    }
    let expected_name = format!("lsb-seawork-service-v{version}-windows-x86_64.zip");
    let mut matching = release
        .assets
        .into_iter()
        .filter(|asset| asset.name == expected_name);
    let Some(asset) = matching.next() else {
        return Ok(None);
    };
    if matching.next().is_some()
        || asset.state != "uploaded"
        || asset.size == 0
        || asset.size > MAX_ARCHIVE_BYTES
        || !valid_asset_url(
            &asset.browser_download_url,
            &release.tag_name,
            &expected_name,
        )
    {
        return Ok(None);
    }
    let Some(digest) = asset.digest.as_deref() else {
        return Ok(None);
    };
    let Some(sha256) = digest.strip_prefix("sha256:") else {
        return Ok(None);
    };
    if sha256.len() != 64 || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok(None);
    }
    Ok(Some((
        version.clone(),
        ReleaseCandidate {
            release_id: release.id,
            version: version.to_string(),
            prerelease: release.prerelease,
            asset_name: expected_name,
            asset_url: asset.browser_download_url,
            asset_size: asset.size,
            archive_sha256: sha256.to_ascii_lowercase(),
        },
    )))
}

fn parse_canonical_version(value: &str) -> Result<Version> {
    let version = Version::parse(value)?;
    if version.to_string() != value || !version.build.is_empty() {
        bail!("release version is not canonical automatic-update SemVer");
    }
    Ok(version)
}

fn valid_asset_url(url: &str, tag: &str, name: &str) -> bool {
    url == format!("https://github.com/LocalSandBox/local-sandbox/releases/download/{tag}/{name}")
}

fn validate_json_value(value: &serde_json::Value, depth: usize) -> Result<()> {
    if depth > MAX_JSON_DEPTH {
        bail!("GitHub release JSON nesting exceeds the compiled limit");
    }
    match value {
        serde_json::Value::String(value) => {
            if value.len() > MAX_JSON_STRING_BYTES {
                bail!("GitHub release JSON string exceeds the compiled limit");
            }
        }
        serde_json::Value::Array(values) => {
            if values.len() > MAX_RELEASES {
                bail!("GitHub release JSON array exceeds the compiled limit");
            }
            for value in values {
                validate_json_value(value, depth + 1)?;
            }
        }
        serde_json::Value::Object(values) => {
            if values.len() > 256 {
                bail!("GitHub release JSON object exceeds the compiled limit");
            }
            for (key, value) in values {
                if key.len() > 128 {
                    bail!("GitHub release JSON key exceeds the compiled limit");
                }
                validate_json_value(value, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_and_prerelease_channels_choose_greatest_eligible_semver() {
        let mut selector = ReleaseSelector::new();
        selector
            .push_page(include_bytes!("../fixtures/github-releases-valid.json"))
            .unwrap();
        assert_eq!(
            selector
                .select(ReleaseChannel::Stable, "0.5.0", "0.5.0")
                .unwrap()
                .unwrap()
                .version,
            "0.5.1"
        );
        assert_eq!(
            selector
                .select(ReleaseChannel::Prerelease, "0.5.0", "0.5.0")
                .unwrap()
                .unwrap()
                .version,
            "0.6.0-rc.1"
        );
    }

    #[test]
    fn malformed_and_nonimmutable_releases_are_ignored() {
        let mut selector = ReleaseSelector::new();
        selector
            .push_page(include_bytes!("../fixtures/github-releases-hostile.json"))
            .unwrap();
        assert!(selector
            .select(ReleaseChannel::Prerelease, "0.5.0", "0.5.0")
            .unwrap()
            .is_none());
    }

    #[test]
    fn duplicate_precedence_is_rejected_even_when_one_record_looks_valid() {
        let page = include_bytes!("../fixtures/github-releases-valid.json");
        let mut selector = ReleaseSelector::new();
        selector.push_page(page).unwrap();
        selector.push_page(page).unwrap();
        assert!(selector
            .select(ReleaseChannel::Prerelease, "0.5.0", "0.5.0")
            .is_err());
    }

    #[test]
    fn committed_high_water_mark_forbids_automatic_downgrade() {
        let mut selector = ReleaseSelector::new();
        selector
            .push_page(include_bytes!("../fixtures/github-releases-valid.json"))
            .unwrap();
        assert!(selector
            .select(ReleaseChannel::Prerelease, "0.5.0", "0.6.0")
            .unwrap()
            .is_none());
    }

    #[test]
    fn response_and_pagination_limits_fail_closed() {
        let mut selector = ReleaseSelector::new();
        let oversized = vec![b' '; MAX_RELEASE_JSON_BYTES + 1];
        assert!(selector.push_page(&oversized).is_err());
        for _ in 0..MAX_RELEASE_PAGES {
            selector.push_page(b"[]").unwrap();
        }
        assert!(selector.push_page(b"[]").is_err());
    }
}
