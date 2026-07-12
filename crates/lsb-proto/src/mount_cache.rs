use std::fmt;

const KEY_DOMAIN: &[u8] = b"lsb.mount-snapshot-key\0";
const DIRECTORY_RECORD: u8 = 1;
const FILE_RECORD: u8 = 2;

pub const MOUNT_CACHE_KEY_ABI_VERSION: u16 = 1;
pub const MOUNT_IMPORT_SEMANTICS_VERSION: u16 = 1;
pub const MOUNT_IMPORT_DIRECTORY_MODE: u32 = 0o755;
pub const MOUNT_IMPORT_FILE_MODE: u32 = 0o644;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MountSnapshotKey([u8; 32]);

impl MountSnapshotKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        self.0.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

impl fmt::Display for MountSnapshotKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountSnapshotEncodingError {
    InvalidRelativePath(String),
    FileRecordAlreadyOpen,
    NoFileRecordOpen,
    FileContentTooLong { remaining: u64, supplied: usize },
    FileContentIncomplete { remaining: u64 },
}

impl fmt::Display for MountSnapshotEncodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRelativePath(reason) => {
                write!(f, "invalid mount snapshot relative path: {reason}")
            }
            Self::FileRecordAlreadyOpen => {
                f.write_str("cannot start a snapshot record while file content is pending")
            }
            Self::NoFileRecordOpen => f.write_str("no snapshot file record is open"),
            Self::FileContentTooLong {
                remaining,
                supplied,
            } => write!(
                f,
                "snapshot file content exceeds its declared length: {remaining} bytes remain, {supplied} supplied"
            ),
            Self::FileContentIncomplete { remaining } => write!(
                f,
                "snapshot file content is incomplete: {remaining} declared bytes remain"
            ),
        }
    }
}

impl std::error::Error for MountSnapshotEncodingError {}

#[derive(Debug, Clone)]
pub struct MountSnapshotKeyEncoder {
    hasher: blake3::Hasher,
    remaining_file_bytes: Option<u64>,
}

impl Default for MountSnapshotKeyEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl MountSnapshotKeyEncoder {
    pub fn new() -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(KEY_DOMAIN);
        hasher.update(&MOUNT_CACHE_KEY_ABI_VERSION.to_be_bytes());
        hasher.update(&MOUNT_IMPORT_SEMANTICS_VERSION.to_be_bytes());
        Self {
            hasher,
            remaining_file_bytes: None,
        }
    }

    pub fn add_directory(&mut self, relative_path: &str) -> Result<(), MountSnapshotEncodingError> {
        self.ensure_record_boundary()?;
        encode_record_prefix(
            &mut self.hasher,
            DIRECTORY_RECORD,
            relative_path,
            MOUNT_IMPORT_DIRECTORY_MODE,
        )
    }

    pub fn begin_file(
        &mut self,
        relative_path: &str,
        length: u64,
    ) -> Result<(), MountSnapshotEncodingError> {
        self.ensure_record_boundary()?;
        encode_record_prefix(
            &mut self.hasher,
            FILE_RECORD,
            relative_path,
            MOUNT_IMPORT_FILE_MODE,
        )?;
        self.hasher.update(&length.to_be_bytes());
        self.remaining_file_bytes = Some(length);
        Ok(())
    }

    pub fn write_file_bytes(&mut self, bytes: &[u8]) -> Result<(), MountSnapshotEncodingError> {
        let Some(remaining) = self.remaining_file_bytes else {
            return Err(MountSnapshotEncodingError::NoFileRecordOpen);
        };
        if bytes.len() as u64 > remaining {
            return Err(MountSnapshotEncodingError::FileContentTooLong {
                remaining,
                supplied: bytes.len(),
            });
        }
        self.hasher.update(bytes);
        self.remaining_file_bytes = Some(remaining - bytes.len() as u64);
        Ok(())
    }

    pub fn finish_file(&mut self) -> Result<(), MountSnapshotEncodingError> {
        match self.remaining_file_bytes {
            Some(0) => {
                self.remaining_file_bytes = None;
                Ok(())
            }
            Some(remaining) => Err(MountSnapshotEncodingError::FileContentIncomplete { remaining }),
            None => Err(MountSnapshotEncodingError::NoFileRecordOpen),
        }
    }

    pub fn finish(self) -> Result<MountSnapshotKey, MountSnapshotEncodingError> {
        if let Some(remaining) = self.remaining_file_bytes {
            return Err(MountSnapshotEncodingError::FileContentIncomplete { remaining });
        }
        Ok(MountSnapshotKey::from_bytes(
            *self.hasher.finalize().as_bytes(),
        ))
    }

    fn ensure_record_boundary(&self) -> Result<(), MountSnapshotEncodingError> {
        if self.remaining_file_bytes.is_some() {
            Err(MountSnapshotEncodingError::FileRecordAlreadyOpen)
        } else {
            Ok(())
        }
    }
}

fn encode_record_prefix(
    hasher: &mut blake3::Hasher,
    record_type: u8,
    relative_path: &str,
    mode: u32,
) -> Result<(), MountSnapshotEncodingError> {
    validate_relative_path(relative_path)?;
    let path = relative_path.as_bytes();
    let path_len = u32::try_from(path.len()).map_err(|_| {
        MountSnapshotEncodingError::InvalidRelativePath("path exceeds u32 length".to_string())
    })?;
    hasher.update(&[record_type]);
    hasher.update(&path_len.to_be_bytes());
    hasher.update(path);
    hasher.update(&mode.to_be_bytes());
    Ok(())
}

fn validate_relative_path(path: &str) -> Result<(), MountSnapshotEncodingError> {
    if path.contains('\0') {
        return Err(MountSnapshotEncodingError::InvalidRelativePath(
            "path contains NUL".to_string(),
        ));
    }
    if path.starts_with('/') || path.ends_with('/') || path.contains("//") {
        return Err(MountSnapshotEncodingError::InvalidRelativePath(
            "path must use canonical relative '/' separators".to_string(),
        ));
    }
    if path
        .split('/')
        .any(|component| component == "." || component == ".." || component.contains('\\'))
    {
        return Err(MountSnapshotEncodingError::InvalidRelativePath(
            "path contains an unsafe component".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_key() -> MountSnapshotKey {
        let mut encoder = MountSnapshotKeyEncoder::new();
        encoder.add_directory("").expect("root directory");
        encoder.add_directory("empty").expect("empty directory");
        encoder.begin_file("nested/file.txt", 5).expect("file");
        encoder.write_file_bytes(b"he").expect("first chunk");
        encoder.write_file_bytes(b"llo").expect("second chunk");
        encoder.finish_file().expect("complete file");
        encoder.finish().expect("snapshot key")
    }

    #[test]
    fn snapshot_key_is_deterministic_across_file_chunking() {
        let expected = sample_key();
        let mut encoder = MountSnapshotKeyEncoder::new();
        encoder.add_directory("").unwrap();
        encoder.add_directory("empty").unwrap();
        encoder.begin_file("nested/file.txt", 5).unwrap();
        encoder.write_file_bytes(b"hello").unwrap();
        encoder.finish_file().unwrap();

        assert_eq!(encoder.finish().unwrap(), expected);
        assert_eq!(expected.to_hex().len(), 64);
        assert_eq!(
            expected.to_hex(),
            "19afec5f1737c16f1e6ff690b8ebb7ece2756f51859f697faf49c66c9dc35378"
        );
    }

    #[test]
    fn snapshot_key_includes_paths_types_modes_lengths_and_content() {
        let expected = sample_key();
        for changed_path in ["other/file.txt", "nested/FILE.txt"] {
            let mut encoder = MountSnapshotKeyEncoder::new();
            encoder.add_directory("").unwrap();
            encoder.add_directory("empty").unwrap();
            encoder.begin_file(changed_path, 5).unwrap();
            encoder.write_file_bytes(b"hello").unwrap();
            encoder.finish_file().unwrap();
            assert_ne!(encoder.finish().unwrap(), expected);
        }

        let mut changed_content = MountSnapshotKeyEncoder::new();
        changed_content.add_directory("").unwrap();
        changed_content.add_directory("empty").unwrap();
        changed_content.begin_file("nested/file.txt", 5).unwrap();
        changed_content.write_file_bytes(b"HELLO").unwrap();
        changed_content.finish_file().unwrap();
        assert_ne!(changed_content.finish().unwrap(), expected);
    }

    #[test]
    fn snapshot_encoder_rejects_invalid_paths_and_length_mismatches() {
        let mut encoder = MountSnapshotKeyEncoder::new();
        assert!(encoder.add_directory("../escape").is_err());
        encoder.begin_file("file", 2).unwrap();
        assert!(encoder.write_file_bytes(b"abc").is_err());
        assert!(encoder.finish_file().is_err());
    }
}
