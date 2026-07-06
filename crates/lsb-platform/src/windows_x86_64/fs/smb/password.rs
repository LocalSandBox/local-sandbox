use std::fmt;

use super::types::{WindowsSmbLifecycleError, WindowsSmbLifecyclePhase};

const PASSWORD_LEN: usize = 32;
const UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
const LOWER: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
const DIGITS: &[u8] = b"23456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{}:?.";
const ALL: &[u8] =
    b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()-_=+[]{}:?.";

pub trait WindowsSmbPasswordGenerator {
    fn generate_password(&mut self) -> Result<WindowsSmbPassword, WindowsSmbLifecycleError>;
    fn fill_random_bytes(&mut self, dest: &mut [u8]) -> Result<(), WindowsSmbLifecycleError>;
}

#[derive(Default)]
pub struct NativeWindowsSmbPasswordGenerator;

impl WindowsSmbPasswordGenerator for NativeWindowsSmbPasswordGenerator {
    fn generate_password(&mut self) -> Result<WindowsSmbPassword, WindowsSmbLifecycleError> {
        let mut random = [0u8; PASSWORD_LEN];
        self.fill_random_bytes(&mut random)?;

        let mut password = Vec::with_capacity(PASSWORD_LEN);
        password.push(pick(UPPER, random[0]));
        password.push(pick(LOWER, random[1]));
        password.push(pick(DIGITS, random[2]));
        password.push(pick(SYMBOLS, random[3]));
        for byte in &random[4..] {
            password.push(pick(ALL, *byte));
        }

        Ok(WindowsSmbPassword::from_ascii(password))
    }

    fn fill_random_bytes(&mut self, dest: &mut [u8]) -> Result<(), WindowsSmbLifecycleError> {
        getrandom::fill(dest).map_err(|error| {
            WindowsSmbLifecycleError::operation_failed(
                WindowsSmbLifecyclePhase::PasswordGeneration,
                format!("OS random generator failed: {error}"),
            )
        })
    }
}

pub struct WindowsSmbPassword {
    bytes: Vec<u8>,
}

impl WindowsSmbPassword {
    pub fn from_ascii(bytes: Vec<u8>) -> Self {
        debug_assert!(bytes.is_ascii());
        Self { bytes }
    }

    pub(crate) fn expose_secret(&self) -> &str {
        std::str::from_utf8(&self.bytes).expect("generated SMB password is ASCII")
    }

    #[cfg(test)]
    pub(crate) fn expose_secret_for_tests(&self) -> &str {
        self.expose_secret()
    }
}

impl Drop for WindowsSmbPassword {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

impl fmt::Debug for WindowsSmbPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WindowsSmbPassword(<redacted>)")
    }
}

impl fmt::Display for WindowsSmbPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

fn pick(charset: &[u8], byte: u8) -> u8 {
    charset[byte as usize % charset.len()]
}
