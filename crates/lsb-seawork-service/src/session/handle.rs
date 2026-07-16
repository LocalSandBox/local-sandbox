use std::fmt;

use anyhow::{bail, Result};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ResourceHandle([u8; 16]);

impl ResourceHandle {
    pub fn random() -> Result<Self> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes)
            .map_err(|error| anyhow::anyhow!("generate resource handle: {error}"))?;
        if bytes == [0; 16] {
            bail!("random resource handle was zero");
        }
        Ok(Self(bytes))
    }

    pub fn parse(value: &str) -> Result<Self> {
        if value.len() != 32
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            bail!("resource handle must be 32 lowercase hexadecimal characters");
        }
        let mut bytes = [0u8; 16];
        for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
            let text = std::str::from_utf8(chunk)?;
            bytes[index] = u8::from_str_radix(text, 16)?;
        }
        if bytes == [0; 16] {
            bail!("zero is not a valid resource handle");
        }
        Ok(Self(bytes))
    }
}

impl fmt::Display for ResourceHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for ResourceHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ResourceHandle")
            .field(&self.to_string())
            .finish()
    }
}

impl Serialize for ResourceHandle {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ResourceHandle {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_are_fixed_lowercase_hex_strings() {
        let handle = ResourceHandle::random().unwrap();
        let encoded = serde_json::to_string(&handle).unwrap();
        assert_eq!(encoded.len(), 34);
        assert_eq!(
            serde_json::from_str::<ResourceHandle>(&encoded).unwrap(),
            handle
        );
        assert!(ResourceHandle::parse("ABCDEF0123456789ABCDEF0123456789").is_err());
        assert!(ResourceHandle::parse("00000000000000000000000000000000").is_err());
    }
}
