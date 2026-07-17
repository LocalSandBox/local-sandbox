use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};

use crate::session::CancellationToken;

use super::pipe::MAX_REQUESTS_PER_CONNECTION;

const NANOS_PER_SECOND: u128 = 1_000_000_000;

pub const DEFAULT_UNARY_DEADLINE: Duration = Duration::from_secs(30);
pub const DEFAULT_BOOT_DEADLINE: Duration = Duration::from_secs(120);
pub const DEFAULT_TRANSFER_DEADLINE: Duration = Duration::from_secs(5 * 60);
pub const MAX_REQUEST_DEADLINE: Duration = Duration::from_secs(10 * 60);

#[derive(Debug)]
pub struct RateLimiter {
    rate_per_second: u32,
    capacity: u32,
    tokens: u32,
    fractional_tokens: u128,
    last_refill: Instant,
}

impl RateLimiter {
    pub fn new(rate_per_second: u32, capacity: u32, now: Instant) -> Self {
        assert!(rate_per_second > 0 && capacity > 0);
        Self {
            rate_per_second,
            capacity,
            tokens: capacity,
            fractional_tokens: 0,
            last_refill: now,
        }
    }

    pub fn try_acquire(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last_refill).as_nanos();
        let generated = elapsed
            .saturating_mul(u128::from(self.rate_per_second))
            .saturating_add(self.fractional_tokens);
        let whole_tokens = generated / NANOS_PER_SECOND;
        self.fractional_tokens = generated % NANOS_PER_SECOND;
        self.last_refill = now;
        if whole_tokens > 0 {
            let refill = u32::try_from(whole_tokens).unwrap_or(u32::MAX);
            self.tokens = self.tokens.saturating_add(refill).min(self.capacity);
        }
        if self.tokens == self.capacity {
            self.fractional_tokens = 0;
        }
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RequestDeadline(Instant);

impl RequestDeadline {
    pub fn from_client(now: Instant, client_ms: Option<u32>, operation_maximum: Duration) -> Self {
        let maximum = operation_maximum.min(MAX_REQUEST_DEADLINE);
        let requested = client_ms
            .map(|milliseconds| Duration::from_millis(milliseconds.max(1) as u64))
            .unwrap_or(maximum)
            .min(maximum);
        Self(now + requested)
    }

    pub fn expired(self, now: Instant) -> bool {
        now >= self.0
    }

    pub fn remaining(self, now: Instant) -> Duration {
        self.0.saturating_duration_since(now)
    }
}

#[derive(Debug)]
struct ActiveRequest {
    deadline: RequestDeadline,
    cancellation: CancellationToken,
}

#[derive(Debug)]
pub struct ConnectionState {
    epoch: u64,
    last_sequence: u64,
    active: HashMap<u64, ActiveRequest>,
    request_rate: RateLimiter,
}

impl ConnectionState {
    pub fn new(epoch: u64) -> Result<Self> {
        if epoch == 0 {
            bail!("connection epoch cannot be zero");
        }
        Ok(Self {
            epoch,
            last_sequence: 0,
            active: HashMap::new(),
            request_rate: RateLimiter::new(
                super::pipe::REQUESTS_PER_SECOND,
                super::pipe::REQUEST_BURST,
                Instant::now(),
            ),
        })
    }

    pub fn admit_request(&mut self, now: Instant) -> Result<()> {
        if !self.request_rate.try_acquire(now) {
            bail!("per-connection request rate exceeded");
        }
        Ok(())
    }

    pub fn accept_sequence(&mut self, epoch: u64, sequence: u64) -> Result<()> {
        if epoch != self.epoch {
            bail!("invalid connection epoch");
        }
        let expected = self
            .last_sequence
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("control sequence exhausted"))?;
        if sequence != expected {
            bail!("invalid, duplicate, or out-of-order control sequence");
        }
        self.last_sequence = sequence;
        Ok(())
    }

    pub fn begin_request(
        &mut self,
        request_id: u64,
        deadline: RequestDeadline,
    ) -> Result<CancellationToken> {
        if self.active.len() >= MAX_REQUESTS_PER_CONNECTION {
            bail!("per-connection active request quota exceeded");
        }
        if self.active.contains_key(&request_id) {
            bail!("request is already active");
        }
        let cancellation = CancellationToken::default();
        self.active.insert(
            request_id,
            ActiveRequest {
                deadline,
                cancellation: cancellation.clone(),
            },
        );
        Ok(cancellation)
    }

    pub fn cancel(&self, request_id: u64) -> bool {
        if let Some(request) = self.active.get(&request_id) {
            request.cancellation.cancel();
            true
        } else {
            false
        }
    }

    pub fn finish(&mut self, request_id: u64) -> bool {
        self.active.remove(&request_id).is_some()
    }

    pub fn cancel_expired(&self, now: Instant) -> usize {
        let mut count = 0;
        for request in self.active.values() {
            if request.deadline.expired(now) {
                request.cancellation.cancel();
                count += 1;
            }
        }
        count
    }

    pub fn cancel_all(&self) {
        for request in self.active.values() {
            request.cancellation.cancel();
        }
    }

    pub fn active_len(&self) -> usize {
        self.active.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_state_is_constant_space_and_strict() {
        let mut state = ConnectionState::new(7).unwrap();
        state.accept_sequence(7, 1).unwrap();
        assert!(state.accept_sequence(7, 1).is_err());
        assert!(state.accept_sequence(7, 3).is_err());
        assert!(state.accept_sequence(8, 2).is_err());
        state.accept_sequence(7, 2).unwrap();
    }

    #[test]
    fn active_requests_are_bounded_and_cancelled() {
        let mut state = ConnectionState::new(1).unwrap();
        let now = Instant::now();
        let mut first = None;
        for request in 0..MAX_REQUESTS_PER_CONNECTION as u64 {
            let cancellation = state
                .begin_request(
                    request,
                    RequestDeadline::from_client(now, Some(1), DEFAULT_UNARY_DEADLINE),
                )
                .unwrap();
            first.get_or_insert(cancellation);
        }
        assert!(state
            .begin_request(
                100,
                RequestDeadline::from_client(now, None, DEFAULT_UNARY_DEADLINE),
            )
            .is_err());
        assert_eq!(state.cancel_expired(now + Duration::from_millis(2)), 16);
        assert!(first.unwrap().is_cancelled());
        for request in 0..MAX_REQUESTS_PER_CONNECTION as u64 {
            assert!(state.finish(request));
        }
        assert_eq!(state.active_len(), 0);
    }

    #[test]
    fn client_deadline_only_shortens_server_maximum() {
        let now = Instant::now();
        assert!(!RequestDeadline::from_client(now, Some(0), DEFAULT_UNARY_DEADLINE).expired(now));
        assert!(
            RequestDeadline::from_client(now, Some(u32::MAX), DEFAULT_UNARY_DEADLINE)
                .expired(now + DEFAULT_UNARY_DEADLINE)
        );
    }

    #[test]
    fn token_bucket_enforces_burst_and_integer_refill() {
        let now = Instant::now();
        let mut limiter = RateLimiter::new(100, 200, now);
        for _ in 0..200 {
            assert!(limiter.try_acquire(now));
        }
        assert!(!limiter.try_acquire(now));
        assert!(!limiter.try_acquire(now + Duration::from_millis(5)));
        assert!(limiter.try_acquire(now + Duration::from_millis(10)));
        assert!(!limiter.try_acquire(now + Duration::from_millis(10)));
        assert!(limiter.try_acquire(now + Duration::from_millis(20)));

        let mut full = RateLimiter::new(100, 2, now);
        assert!(full.try_acquire(now + Duration::from_millis(5)));
        assert!(full.try_acquire(now + Duration::from_millis(5)));
        assert!(!full.try_acquire(now + Duration::from_millis(10)));
        assert!(full.try_acquire(now + Duration::from_millis(15)));
    }
}
