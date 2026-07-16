use crate::ClientError;

pub const INITIAL_STREAM_CREDIT: u32 = 256 * 1024;
pub const MAX_STREAM_BUFFER: u32 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreditWindow {
    available: u32,
}

impl Default for CreditWindow {
    fn default() -> Self {
        Self {
            available: INITIAL_STREAM_CREDIT,
        }
    }
}

impl CreditWindow {
    pub fn available(&self) -> u32 {
        self.available
    }

    pub fn consume(&mut self, bytes: u32) -> Result<(), ClientError> {
        self.available = self
            .available
            .checked_sub(bytes)
            .ok_or_else(|| ClientError::Protocol("stream exceeded granted credit".to_string()))?;
        Ok(())
    }

    pub fn grant(&mut self, bytes: u32) -> Result<(), ClientError> {
        let next = self
            .available
            .checked_add(bytes)
            .ok_or_else(|| ClientError::Protocol("stream credit overflow".to_string()))?;
        if next > MAX_STREAM_BUFFER {
            return Err(ClientError::Protocol(
                "stream credit exceeds buffer cap".to_string(),
            ));
        }
        self.available = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credit_is_checked_and_bounded() {
        let mut window = CreditWindow::default();
        window.consume(INITIAL_STREAM_CREDIT).unwrap();
        assert!(window.consume(1).is_err());
        assert!(window.grant(MAX_STREAM_BUFFER + 1).is_err());
    }
}
