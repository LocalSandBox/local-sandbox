use std::io::{self, Read, Write};

use crate::error::ProtocolError;
use crate::limits::{HEADER_LEN, MAX_CONTROL_PAYLOAD, MAX_STREAM_PAYLOAD};
use crate::version::ProtocolVersion;

pub const MAGIC: [u8; 4] = *b"LSBS";
pub const HEADER_VERSION: u8 = 1;

pub fn encode_stream_payload(sequence: u64, bytes: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    if bytes.len() + crate::limits::STREAM_SEQUENCE_LEN > MAX_STREAM_PAYLOAD {
        return Err(ProtocolError::MessageTooLarge);
    }
    let mut payload = Vec::with_capacity(crate::limits::STREAM_SEQUENCE_LEN + bytes.len());
    payload.extend_from_slice(&sequence.to_le_bytes());
    payload.extend_from_slice(bytes);
    Ok(payload)
}

pub fn decode_stream_payload(payload: &[u8]) -> Result<(u64, &[u8]), ProtocolError> {
    if payload.len() < crate::limits::STREAM_SEQUENCE_LEN || payload.len() > MAX_STREAM_PAYLOAD {
        return Err(ProtocolError::TruncatedFrame);
    }
    let sequence = u64::from_le_bytes(
        payload[..crate::limits::STREAM_SEQUENCE_LEN]
            .try_into()
            .map_err(|_| ProtocolError::TruncatedFrame)?,
    );
    Ok((sequence, &payload[crate::limits::STREAM_SEQUENCE_LEN..]))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameKind {
    Hello = 1,
    Request = 2,
    Response = 3,
    Event = 4,
    StreamData = 5,
    WindowUpdate = 6,
    Cancel = 7,
    Close = 8,
}

impl TryFrom<u8> for FrameKind {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Hello),
            2 => Ok(Self::Request),
            3 => Ok(Self::Response),
            4 => Ok(Self::Event),
            5 => Ok(Self::StreamData),
            6 => Ok(Self::WindowUpdate),
            7 => Ok(Self::Cancel),
            8 => Ok(Self::Close),
            _ => Err(ProtocolError::InvalidKind),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Correlation {
    pub high: u64,
    pub low: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub kind: FrameKind,
    pub flags: u16,
    pub protocol: ProtocolVersion,
    pub payload_len: u32,
    pub correlation: Correlation,
}

impl FrameHeader {
    pub fn encode(self) -> Result<[u8; HEADER_LEN], ProtocolError> {
        self.validate()?;
        let mut bytes = [0u8; HEADER_LEN];
        bytes[0..4].copy_from_slice(&MAGIC);
        bytes[4] = HEADER_VERSION;
        bytes[5] = self.kind as u8;
        bytes[6..8].copy_from_slice(&self.flags.to_le_bytes());
        bytes[8..10].copy_from_slice(&self.protocol.major.to_le_bytes());
        bytes[10..12].copy_from_slice(&self.protocol.minor.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.payload_len.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.correlation.high.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.correlation.low.to_le_bytes());
        Ok(bytes)
    }

    pub fn decode(bytes: [u8; HEADER_LEN]) -> Result<Self, ProtocolError> {
        if bytes[0..4] != MAGIC {
            return Err(ProtocolError::InvalidMagic);
        }
        if bytes[4] != HEADER_VERSION {
            return Err(ProtocolError::InvalidHeaderVersion);
        }
        let header = Self {
            kind: FrameKind::try_from(bytes[5])?,
            flags: u16::from_le_bytes([bytes[6], bytes[7]]),
            protocol: ProtocolVersion {
                major: u16::from_le_bytes([bytes[8], bytes[9]]),
                minor: u16::from_le_bytes([bytes[10], bytes[11]]),
            },
            payload_len: u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
            correlation: Correlation {
                high: u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
                low: u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
            },
        };
        header.validate()?;
        Ok(header)
    }

    fn validate(self) -> Result<(), ProtocolError> {
        if self.flags != 0 {
            return Err(ProtocolError::InvalidFlags);
        }
        let maximum = if self.kind == FrameKind::StreamData {
            MAX_STREAM_PAYLOAD
        } else {
            MAX_CONTROL_PAYLOAD
        };
        if self.payload_len as usize > maximum {
            return Err(ProtocolError::MessageTooLarge);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub header: FrameHeader,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn write_to(&self, writer: &mut impl Write) -> io::Result<()> {
        if self.payload.len() != self.header.payload_len as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "frame payload length does not match header",
            ));
        }
        let header = self
            .header
            .encode()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        writer.write_all(&header)?;
        writer.write_all(&self.payload)
    }

    pub fn read_from(reader: &mut impl Read) -> Result<Self, ProtocolError> {
        let mut header_bytes = [0u8; HEADER_LEN];
        reader
            .read_exact(&mut header_bytes)
            .map_err(|_| ProtocolError::TruncatedFrame)?;
        let header = FrameHeader::decode(header_bytes)?;
        let mut payload = vec![0u8; header.payload_len as usize];
        reader
            .read_exact(&mut payload)
            .map_err(|_| ProtocolError::TruncatedFrame)?;
        Ok(Self { header, payload })
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn header() -> FrameHeader {
        FrameHeader {
            kind: FrameKind::Request,
            flags: 0,
            protocol: ProtocolVersion { major: 1, minor: 1 },
            payload_len: 3,
            correlation: Correlation { high: 7, low: 9 },
        }
    }

    #[test]
    fn header_matches_golden_little_endian_vector() {
        let encoded = header().encode().unwrap();
        assert_eq!(
            encoded,
            [
                0x4c, 0x53, 0x42, 0x53, 0x01, 0x02, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x03, 0x00,
                0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ]
        );
        assert_eq!(FrameHeader::decode(encoded).unwrap(), header());
    }

    #[test]
    fn validates_before_allocating_payload() {
        let mut bytes = header().encode().unwrap();
        bytes[12..16].copy_from_slice(&((MAX_CONTROL_PAYLOAD + 1) as u32).to_le_bytes());
        assert_eq!(
            FrameHeader::decode(bytes),
            Err(ProtocolError::MessageTooLarge)
        );
        let mut stream = Cursor::new(bytes);
        assert_eq!(
            Frame::read_from(&mut stream),
            Err(ProtocolError::MessageTooLarge)
        );
    }

    #[test]
    fn rejects_magic_kind_flags_and_truncation() {
        let mut bytes = header().encode().unwrap();
        bytes[0] = b'X';
        assert_eq!(FrameHeader::decode(bytes), Err(ProtocolError::InvalidMagic));
        let mut bytes = header().encode().unwrap();
        bytes[5] = 99;
        assert_eq!(FrameHeader::decode(bytes), Err(ProtocolError::InvalidKind));
        let mut bytes = header().encode().unwrap();
        bytes[6] = 1;
        assert_eq!(FrameHeader::decode(bytes), Err(ProtocolError::InvalidFlags));
        assert_eq!(
            Frame::read_from(&mut Cursor::new([0u8; 8])),
            Err(ProtocolError::TruncatedFrame)
        );
    }

    #[test]
    fn stream_payload_sequence_is_bounded_and_little_endian() {
        let payload = encode_stream_payload(0x0102_0304_0506_0708, b"data").unwrap();
        assert_eq!(&payload[..8], &[8, 7, 6, 5, 4, 3, 2, 1]);
        assert_eq!(
            decode_stream_payload(&payload).unwrap(),
            (0x0102_0304_0506_0708, b"data".as_slice())
        );
        assert_eq!(
            decode_stream_payload(&[0; 7]),
            Err(ProtocolError::TruncatedFrame)
        );
        assert_eq!(
            encode_stream_payload(1, &vec![0; MAX_STREAM_PAYLOAD]),
            Err(ProtocolError::MessageTooLarge)
        );
    }
}
