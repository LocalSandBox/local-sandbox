use std::fmt;

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use crate::error::ProtocolError;

pub const CURRENT: ProtocolVersion = ProtocolVersion { major: 1, minor: 5 };
pub const SUPPORTED: ProtocolRange = ProtocolRange {
    major: 1,
    min_minor: 0,
    max_minor: 5,
};

pub const FEATURE_NETWORK_EGRESS: u64 = 1 << 0;
pub const FEATURE_NETWORK_SECRETS: u64 = 1 << 1;
pub const FEATURE_HTTPS_INTERCEPTION: u64 = 1 << 2;
pub const START_REPLAY_MIN_MINOR: u16 = 4;
pub const CANCELLATION_COMMIT_MIN_MINOR: u16 = 5;
pub const CLIENT_FEATURE_BITS: u64 =
    FEATURE_NETWORK_EGRESS | FEATURE_NETWORK_SECRETS | FEATURE_HTTPS_INTERCEPTION;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolRange {
    pub major: u16,
    pub min_minor: u16,
    pub max_minor: u16,
}

impl ProtocolRange {
    pub fn validate(self) -> Result<Self, ProtocolError> {
        if self.min_minor > self.max_minor {
            return Err(ProtocolError::InvalidVersionRange);
        }
        Ok(self)
    }
}

pub fn negotiate(
    service: ProtocolRange,
    client: ProtocolRange,
) -> Result<ProtocolVersion, ProtocolError> {
    service.validate()?;
    client.validate()?;
    if service.major != client.major {
        return Err(ProtocolError::IncompatibleProtocol);
    }
    let min = service.min_minor.max(client.min_minor);
    let max = service.max_minor.min(client.max_minor);
    if min > max {
        return Err(ProtocolError::IncompatibleProtocol);
    }
    Ok(ProtocolVersion {
        major: service.major,
        minor: max,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HexU64(pub u64);

impl fmt::Display for HexU64 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:016x}", self.0)
    }
}

impl Serialize for HexU64 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for HexU64 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value.len() != 16
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(de::Error::custom(
                "expected exactly 16 lowercase hexadecimal characters",
            ));
        }
        u64::from_str_radix(&value, 16)
            .map(HexU64)
            .map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chooses_highest_mutual_minor() {
        let selected = negotiate(
            ProtocolRange {
                major: 1,
                min_minor: 0,
                max_minor: 3,
            },
            ProtocolRange {
                major: 1,
                min_minor: 1,
                max_minor: 2,
            },
        )
        .unwrap();
        assert_eq!(selected.minor, 2);
    }

    #[test]
    fn current_protocol_supports_connection_bound_start_replay() {
        let selected = negotiate(
            SUPPORTED,
            ProtocolRange {
                major: CURRENT.major,
                min_minor: START_REPLAY_MIN_MINOR,
                max_minor: START_REPLAY_MIN_MINOR,
            },
        )
        .unwrap();
        assert_eq!(selected.minor, START_REPLAY_MIN_MINOR);
    }

    #[test]
    fn current_protocol_supports_commit_aware_cancellation() {
        let selected = negotiate(
            SUPPORTED,
            ProtocolRange {
                major: CURRENT.major,
                min_minor: CANCELLATION_COMMIT_MIN_MINOR,
                max_minor: CANCELLATION_COMMIT_MIN_MINOR,
            },
        )
        .unwrap();
        assert_eq!(selected.minor, CANCELLATION_COMMIT_MIN_MINOR);
    }

    #[test]
    fn rejects_major_or_range_mismatch() {
        let wrong_major = ProtocolRange {
            major: 2,
            min_minor: 0,
            max_minor: 1,
        };
        assert_eq!(
            negotiate(SUPPORTED, wrong_major),
            Err(ProtocolError::IncompatibleProtocol)
        );
        let backwards = ProtocolRange {
            major: 1,
            min_minor: 2,
            max_minor: 1,
        };
        assert_eq!(
            negotiate(SUPPORTED, backwards),
            Err(ProtocolError::InvalidVersionRange)
        );
    }

    #[test]
    fn strict_hex_round_trips() {
        let encoded = serde_json::to_string(&HexU64(0xabc)).unwrap();
        assert_eq!(encoded, "\"0000000000000abc\"");
        assert_eq!(serde_json::from_str::<HexU64>(&encoded).unwrap().0, 0xabc);
        assert!(serde_json::from_str::<HexU64>("\"0000000000000ABC\"").is_err());
        assert!(serde_json::from_str::<HexU64>("\"abc\"").is_err());
    }
}
