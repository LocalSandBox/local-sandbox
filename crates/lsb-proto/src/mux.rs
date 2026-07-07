//! Transport-internal session mux frames.
//!
//! These envelopes are carried by the existing `frame` header after a transport
//! has negotiated mux mode. `MuxFrame::Data` bytes are ordinary `lsb-proto`
//! operation frames, including their existing `[len][type][payload]` header.

use std::fmt;

use crate::frame::MAX_FRAME_PAYLOAD;

pub const MUX_OPEN: u8 = 0x70;
pub const MUX_OPEN_OK: u8 = 0x71;
pub const MUX_OPEN_ERR: u8 = 0x72;
pub const MUX_DATA: u8 = 0x73;
pub const MUX_WINDOW: u8 = 0x74;
pub const MUX_FIN: u8 = 0x75;
pub const MUX_RST: u8 = 0x76;

pub const SESSION_ID_LEN: usize = 8;
pub const WINDOW_CREDIT_LEN: usize = 4;
pub const MAX_DATA_LEN: usize = 64 * 1024;
pub const MAX_OPEN_METADATA_LEN: usize = 4 * 1024;
pub const MAX_REASON_LEN: usize = 4 * 1024;

const WINDOW_PAYLOAD_LEN: usize = SESSION_ID_LEN + WINDOW_CREDIT_LEN;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MuxFrame {
    Open {
        session_id: u64,
        metadata: Vec<u8>,
    },
    OpenOk {
        session_id: u64,
        initial_credit: u32,
    },
    OpenErr {
        session_id: u64,
        reason: String,
    },
    Data {
        session_id: u64,
        bytes: Vec<u8>,
    },
    Window {
        session_id: u64,
        credit: u32,
    },
    Fin {
        session_id: u64,
    },
    Rst {
        session_id: u64,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MuxFrameError {
    UnknownType(u8),
    PayloadTooShort {
        frame_type: u8,
        min: usize,
        actual: usize,
    },
    InvalidPayloadLen {
        frame_type: u8,
        expected: usize,
        actual: usize,
    },
    ReservedSessionId,
    InvalidHostSessionId(u64),
    InvalidGuestSessionId(u64),
    EmptyData,
    DataTooLarge {
        len: usize,
        max: usize,
    },
    MetadataTooLarge {
        len: usize,
        max: usize,
    },
    ReasonTooLarge {
        len: usize,
        max: usize,
    },
    ZeroWindowCredit,
    ReasonNotUtf8,
}

impl fmt::Display for MuxFrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownType(frame_type) => {
                write!(f, "unknown mux frame type 0x{frame_type:02x}")
            }
            Self::PayloadTooShort {
                frame_type,
                min,
                actual,
            } => write!(
                f,
                "mux frame type 0x{frame_type:02x} payload too short: expected at least {min} bytes, got {actual}"
            ),
            Self::InvalidPayloadLen {
                frame_type,
                expected,
                actual,
            } => write!(
                f,
                "mux frame type 0x{frame_type:02x} payload length mismatch: expected {expected} bytes, got {actual}"
            ),
            Self::ReservedSessionId => f.write_str("mux session id 0 is reserved"),
            Self::InvalidHostSessionId(session_id) => write!(
                f,
                "invalid host-opened mux session id {session_id}: expected a non-zero odd id"
            ),
            Self::InvalidGuestSessionId(session_id) => write!(
                f,
                "invalid guest-opened mux session id {session_id}: expected a non-zero even id"
            ),
            Self::EmptyData => f.write_str("mux data frame payload is empty"),
            Self::DataTooLarge { len, max } => {
                write!(f, "mux data payload too large: {len} bytes exceeds {max}")
            }
            Self::MetadataTooLarge { len, max } => {
                write!(f, "mux open metadata too large: {len} bytes exceeds {max}")
            }
            Self::ReasonTooLarge { len, max } => {
                write!(f, "mux reason too large: {len} bytes exceeds {max}")
            }
            Self::ZeroWindowCredit => f.write_str("mux window credit must be non-zero"),
            Self::ReasonNotUtf8 => f.write_str("mux reason is not valid UTF-8"),
        }
    }
}

impl std::error::Error for MuxFrameError {}

pub fn is_host_session_id(session_id: u64) -> bool {
    session_id != 0 && session_id % 2 == 1
}

pub fn is_guest_session_id(session_id: u64) -> bool {
    session_id != 0 && session_id % 2 == 0
}

pub fn validate_session_id(session_id: u64) -> Result<(), MuxFrameError> {
    if session_id == 0 {
        return Err(MuxFrameError::ReservedSessionId);
    }
    Ok(())
}

pub fn validate_host_session_id(session_id: u64) -> Result<(), MuxFrameError> {
    if is_host_session_id(session_id) {
        Ok(())
    } else if session_id == 0 {
        Err(MuxFrameError::ReservedSessionId)
    } else {
        Err(MuxFrameError::InvalidHostSessionId(session_id))
    }
}

pub fn validate_guest_session_id(session_id: u64) -> Result<(), MuxFrameError> {
    if is_guest_session_id(session_id) {
        Ok(())
    } else if session_id == 0 {
        Err(MuxFrameError::ReservedSessionId)
    } else {
        Err(MuxFrameError::InvalidGuestSessionId(session_id))
    }
}

pub fn encode_frame(frame: &MuxFrame) -> Result<(u8, Vec<u8>), MuxFrameError> {
    match frame {
        MuxFrame::Open {
            session_id,
            metadata,
        } => {
            let mut payload = encode_session_id(*session_id)?;
            validate_payload_len(MUX_OPEN, metadata, MAX_OPEN_METADATA_LEN)?;
            payload.extend_from_slice(metadata);
            Ok((MUX_OPEN, payload))
        }
        MuxFrame::OpenOk {
            session_id,
            initial_credit,
        } => {
            let mut payload = encode_session_id(*session_id)?;
            validate_credit(*initial_credit)?;
            payload.extend_from_slice(&initial_credit.to_be_bytes());
            Ok((MUX_OPEN_OK, payload))
        }
        MuxFrame::OpenErr { session_id, reason } => {
            let mut payload = encode_session_id(*session_id)?;
            validate_reason(reason)?;
            payload.extend_from_slice(reason.as_bytes());
            Ok((MUX_OPEN_ERR, payload))
        }
        MuxFrame::Data { session_id, bytes } => {
            let mut payload = encode_session_id(*session_id)?;
            validate_data(bytes)?;
            payload.extend_from_slice(bytes);
            Ok((MUX_DATA, payload))
        }
        MuxFrame::Window { session_id, credit } => {
            let mut payload = encode_session_id(*session_id)?;
            validate_credit(*credit)?;
            payload.extend_from_slice(&credit.to_be_bytes());
            Ok((MUX_WINDOW, payload))
        }
        MuxFrame::Fin { session_id } => Ok((MUX_FIN, encode_session_id(*session_id)?)),
        MuxFrame::Rst { session_id, reason } => {
            let mut payload = encode_session_id(*session_id)?;
            validate_reason(reason)?;
            payload.extend_from_slice(reason.as_bytes());
            Ok((MUX_RST, payload))
        }
    }
}

pub fn decode_frame(frame_type: u8, payload: &[u8]) -> Result<MuxFrame, MuxFrameError> {
    match frame_type {
        MUX_OPEN => {
            let (session_id, metadata) = decode_session_prefixed(frame_type, payload)?;
            validate_payload_len(frame_type, metadata, MAX_OPEN_METADATA_LEN)?;
            Ok(MuxFrame::Open {
                session_id,
                metadata: metadata.to_vec(),
            })
        }
        MUX_OPEN_OK => {
            let (session_id, initial_credit) = decode_window_payload(frame_type, payload)?;
            Ok(MuxFrame::OpenOk {
                session_id,
                initial_credit,
            })
        }
        MUX_OPEN_ERR => {
            let (session_id, reason) = decode_reason_payload(frame_type, payload)?;
            Ok(MuxFrame::OpenErr { session_id, reason })
        }
        MUX_DATA => {
            let (session_id, bytes) = decode_session_prefixed(frame_type, payload)?;
            validate_data(bytes)?;
            Ok(MuxFrame::Data {
                session_id,
                bytes: bytes.to_vec(),
            })
        }
        MUX_WINDOW => {
            let (session_id, credit) = decode_window_payload(frame_type, payload)?;
            Ok(MuxFrame::Window { session_id, credit })
        }
        MUX_FIN => {
            if payload.len() != SESSION_ID_LEN {
                return Err(MuxFrameError::InvalidPayloadLen {
                    frame_type,
                    expected: SESSION_ID_LEN,
                    actual: payload.len(),
                });
            }
            Ok(MuxFrame::Fin {
                session_id: decode_session_id(&payload[..SESSION_ID_LEN])?,
            })
        }
        MUX_RST => {
            let (session_id, reason) = decode_reason_payload(frame_type, payload)?;
            Ok(MuxFrame::Rst { session_id, reason })
        }
        _ => Err(MuxFrameError::UnknownType(frame_type)),
    }
}

fn encode_session_id(session_id: u64) -> Result<Vec<u8>, MuxFrameError> {
    validate_session_id(session_id)?;
    Ok(session_id.to_be_bytes().to_vec())
}

fn decode_session_id(payload: &[u8]) -> Result<u64, MuxFrameError> {
    let mut bytes = [0u8; SESSION_ID_LEN];
    bytes.copy_from_slice(payload);
    let session_id = u64::from_be_bytes(bytes);
    validate_session_id(session_id)?;
    Ok(session_id)
}

fn decode_session_prefixed(frame_type: u8, payload: &[u8]) -> Result<(u64, &[u8]), MuxFrameError> {
    if payload.len() < SESSION_ID_LEN {
        return Err(MuxFrameError::PayloadTooShort {
            frame_type,
            min: SESSION_ID_LEN,
            actual: payload.len(),
        });
    }
    let session_id = decode_session_id(&payload[..SESSION_ID_LEN])?;
    Ok((session_id, &payload[SESSION_ID_LEN..]))
}

fn decode_window_payload(frame_type: u8, payload: &[u8]) -> Result<(u64, u32), MuxFrameError> {
    if payload.len() != WINDOW_PAYLOAD_LEN {
        return Err(MuxFrameError::InvalidPayloadLen {
            frame_type,
            expected: WINDOW_PAYLOAD_LEN,
            actual: payload.len(),
        });
    }
    let session_id = decode_session_id(&payload[..SESSION_ID_LEN])?;
    let mut credit = [0u8; WINDOW_CREDIT_LEN];
    credit.copy_from_slice(&payload[SESSION_ID_LEN..WINDOW_PAYLOAD_LEN]);
    let credit = u32::from_be_bytes(credit);
    validate_credit(credit)?;
    Ok((session_id, credit))
}

fn decode_reason_payload(frame_type: u8, payload: &[u8]) -> Result<(u64, String), MuxFrameError> {
    let (session_id, reason) = decode_session_prefixed(frame_type, payload)?;
    if reason.len() > MAX_REASON_LEN {
        return Err(MuxFrameError::ReasonTooLarge {
            len: reason.len(),
            max: MAX_REASON_LEN,
        });
    }
    let reason = std::str::from_utf8(reason)
        .map_err(|_| MuxFrameError::ReasonNotUtf8)?
        .to_string();
    Ok((session_id, reason))
}

fn validate_credit(credit: u32) -> Result<(), MuxFrameError> {
    if credit == 0 {
        return Err(MuxFrameError::ZeroWindowCredit);
    }
    Ok(())
}

fn validate_data(data: &[u8]) -> Result<(), MuxFrameError> {
    if data.is_empty() {
        return Err(MuxFrameError::EmptyData);
    }
    validate_payload_len(MUX_DATA, data, MAX_DATA_LEN)
}

fn validate_reason(reason: &str) -> Result<(), MuxFrameError> {
    if reason.len() > MAX_REASON_LEN {
        return Err(MuxFrameError::ReasonTooLarge {
            len: reason.len(),
            max: MAX_REASON_LEN,
        });
    }
    Ok(())
}

fn validate_payload_len(frame_type: u8, payload: &[u8], max: usize) -> Result<(), MuxFrameError> {
    if payload.len() > max {
        let error = if frame_type == MUX_DATA {
            MuxFrameError::DataTooLarge {
                len: payload.len(),
                max,
            }
        } else {
            MuxFrameError::MetadataTooLarge {
                len: payload.len(),
                max,
            }
        };
        return Err(error);
    }
    debug_assert!(SESSION_ID_LEN + max <= MAX_FRAME_PAYLOAD);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mux_frames_round_trip() {
        let frames = [
            MuxFrame::Open {
                session_id: 1,
                metadata: b"exec".to_vec(),
            },
            MuxFrame::OpenOk {
                session_id: 1,
                initial_credit: 1024,
            },
            MuxFrame::OpenErr {
                session_id: 3,
                reason: "unsupported session".to_string(),
            },
            MuxFrame::Data {
                session_id: 5,
                bytes: b"\0\0\0\x02\x02x".to_vec(),
            },
            MuxFrame::Window {
                session_id: 5,
                credit: 4096,
            },
            MuxFrame::Fin { session_id: 5 },
            MuxFrame::Rst {
                session_id: 5,
                reason: "cancelled".to_string(),
            },
        ];

        for frame in frames {
            let (frame_type, payload) = encode_frame(&frame).expect("frame should encode");
            let decoded = decode_frame(frame_type, &payload).expect("frame should decode");
            assert_eq!(decoded, frame);
        }
    }

    #[test]
    fn session_id_helpers_enforce_reserved_and_parity_rules() {
        assert!(is_host_session_id(1));
        assert!(!is_host_session_id(2));
        assert!(is_guest_session_id(2));
        assert!(!is_guest_session_id(1));

        assert_eq!(
            validate_session_id(0),
            Err(MuxFrameError::ReservedSessionId)
        );
        assert_eq!(
            validate_host_session_id(0),
            Err(MuxFrameError::ReservedSessionId)
        );
        assert_eq!(
            validate_host_session_id(2),
            Err(MuxFrameError::InvalidHostSessionId(2))
        );
        assert_eq!(
            validate_guest_session_id(1),
            Err(MuxFrameError::InvalidGuestSessionId(1))
        );

        assert_eq!(
            encode_frame(&MuxFrame::Fin { session_id: 0 }),
            Err(MuxFrameError::ReservedSessionId)
        );
    }

    #[test]
    fn decode_rejects_reserved_session_id() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0u64.to_be_bytes());
        payload.extend_from_slice(b"data");

        assert_eq!(
            decode_frame(MUX_DATA, &payload),
            Err(MuxFrameError::ReservedSessionId)
        );
    }

    #[test]
    fn decode_rejects_malformed_payloads() {
        assert_eq!(
            decode_frame(MUX_OPEN, &[1, 2, 3]),
            Err(MuxFrameError::PayloadTooShort {
                frame_type: MUX_OPEN,
                min: SESSION_ID_LEN,
                actual: 3,
            })
        );

        let mut fin_with_trailing = 1u64.to_be_bytes().to_vec();
        fin_with_trailing.push(0);
        assert_eq!(
            decode_frame(MUX_FIN, &fin_with_trailing),
            Err(MuxFrameError::InvalidPayloadLen {
                frame_type: MUX_FIN,
                expected: SESSION_ID_LEN,
                actual: SESSION_ID_LEN + 1,
            })
        );

        assert_eq!(
            decode_frame(MUX_OPEN_OK, &1u64.to_be_bytes()),
            Err(MuxFrameError::InvalidPayloadLen {
                frame_type: MUX_OPEN_OK,
                expected: WINDOW_PAYLOAD_LEN,
                actual: SESSION_ID_LEN,
            })
        );

        let mut invalid_utf8 = 1u64.to_be_bytes().to_vec();
        invalid_utf8.push(0xff);
        assert_eq!(
            decode_frame(MUX_RST, &invalid_utf8),
            Err(MuxFrameError::ReasonNotUtf8)
        );

        assert_eq!(
            decode_frame(0xff, &1u64.to_be_bytes()),
            Err(MuxFrameError::UnknownType(0xff))
        );
    }

    #[test]
    fn decode_rejects_empty_data_and_zero_credit() {
        assert_eq!(
            decode_frame(MUX_DATA, &1u64.to_be_bytes()),
            Err(MuxFrameError::EmptyData)
        );

        let mut payload = 1u64.to_be_bytes().to_vec();
        payload.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(
            decode_frame(MUX_WINDOW, &payload),
            Err(MuxFrameError::ZeroWindowCredit)
        );
    }

    #[test]
    fn data_payload_size_limit_is_enforced() {
        let max = vec![b'x'; MAX_DATA_LEN];
        let frame = MuxFrame::Data {
            session_id: 1,
            bytes: max.clone(),
        };
        let (frame_type, payload) = encode_frame(&frame).expect("max data should encode");
        assert_eq!(
            decode_frame(frame_type, &payload).expect("max data should decode"),
            frame
        );

        let too_large = vec![b'x'; MAX_DATA_LEN + 1];
        let frame = MuxFrame::Data {
            session_id: 1,
            bytes: too_large.clone(),
        };
        assert_eq!(
            encode_frame(&frame),
            Err(MuxFrameError::DataTooLarge {
                len: too_large.len(),
                max: MAX_DATA_LEN,
            })
        );

        let mut payload = 1u64.to_be_bytes().to_vec();
        payload.extend_from_slice(&too_large);
        assert_eq!(
            decode_frame(MUX_DATA, &payload),
            Err(MuxFrameError::DataTooLarge {
                len: too_large.len(),
                max: MAX_DATA_LEN,
            })
        );
    }

    #[test]
    fn control_payload_size_limits_are_enforced() {
        let metadata = vec![b'x'; MAX_OPEN_METADATA_LEN + 1];
        let frame = MuxFrame::Open {
            session_id: 1,
            metadata: metadata.clone(),
        };
        assert_eq!(
            encode_frame(&frame),
            Err(MuxFrameError::MetadataTooLarge {
                len: metadata.len(),
                max: MAX_OPEN_METADATA_LEN,
            })
        );

        let mut payload = 1u64.to_be_bytes().to_vec();
        payload.extend_from_slice(&metadata);
        assert_eq!(
            decode_frame(MUX_OPEN, &payload),
            Err(MuxFrameError::MetadataTooLarge {
                len: metadata.len(),
                max: MAX_OPEN_METADATA_LEN,
            })
        );

        let reason = "x".repeat(MAX_REASON_LEN + 1);
        let frame = MuxFrame::Rst {
            session_id: 1,
            reason: reason.clone(),
        };
        assert_eq!(
            encode_frame(&frame),
            Err(MuxFrameError::ReasonTooLarge {
                len: reason.len(),
                max: MAX_REASON_LEN,
            })
        );

        let mut payload = 1u64.to_be_bytes().to_vec();
        payload.extend_from_slice(reason.as_bytes());
        assert_eq!(
            decode_frame(MUX_RST, &payload),
            Err(MuxFrameError::ReasonTooLarge {
                len: reason.len(),
                max: MAX_REASON_LEN,
            })
        );
    }
}
