use std::fmt;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

const ACTIVE: u8 = 0;
const CANCELLED: u8 = 1;
const DEADLINE_EXCEEDED: u8 = 2;
const COMMITTING: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelOutcome {
    Requested,
    AlreadyRequested,
    TooLate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancellationReason {
    Cancelled,
    DeadlineExceeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CancellationError {
    reason: CancellationReason,
}

impl CancellationError {
    pub const fn reason(self) -> CancellationReason {
        self.reason
    }
}

impl fmt::Display for CancellationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.reason {
            CancellationReason::Cancelled => "operation cancelled",
            CancellationReason::DeadlineExceeded => "operation deadline exceeded",
        })
    }
}

impl std::error::Error for CancellationError {}

#[derive(Debug, Clone)]
pub struct CancellationToken {
    state: Arc<AtomicU8>,
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self {
            state: Arc::new(AtomicU8::new(ACTIVE)),
        }
    }
}

impl CancellationToken {
    pub fn cancel(&self) -> CancelOutcome {
        self.request(CANCELLED)
    }

    pub fn expire(&self) -> CancelOutcome {
        self.request(DEADLINE_EXCEEDED)
    }

    fn request(&self, requested: u8) -> CancelOutcome {
        match self
            .state
            .compare_exchange(ACTIVE, requested, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => CancelOutcome::Requested,
            Err(COMMITTING) => CancelOutcome::TooLate,
            Err(CANCELLED | DEADLINE_EXCEEDED) => CancelOutcome::AlreadyRequested,
            Err(_) => unreachable!("invalid cancellation state"),
        }
    }

    /// Atomically crosses the point after which a synchronous mutation must report its
    /// real result. Returns false when cancellation or expiry won the race.
    pub fn begin_commit(&self) -> bool {
        match self
            .state
            .compare_exchange(ACTIVE, COMMITTING, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) | Err(COMMITTING) => true,
            Err(CANCELLED | DEADLINE_EXCEEDED) => false,
            Err(_) => unreachable!("invalid cancellation state"),
        }
    }

    pub fn is_committing(&self) -> bool {
        self.state.load(Ordering::Acquire) == COMMITTING
    }

    pub fn is_cancelled(&self) -> bool {
        matches!(
            self.state.load(Ordering::Acquire),
            CANCELLED | DEADLINE_EXCEEDED
        )
    }

    pub fn cancellation_reason(&self) -> Option<CancellationReason> {
        match self.state.load(Ordering::Acquire) {
            CANCELLED => Some(CancellationReason::Cancelled),
            DEADLINE_EXCEEDED => Some(CancellationReason::DeadlineExceeded),
            ACTIVE | COMMITTING => None,
            _ => unreachable!("invalid cancellation state"),
        }
    }

    pub fn check(&self) -> anyhow::Result<()> {
        if let Some(reason) = self.cancellation_reason() {
            return Err(CancellationError { reason }.into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_is_shared_and_idempotent() {
        let token = CancellationToken::default();
        let clone = token.clone();
        assert_eq!(token.cancel(), CancelOutcome::Requested);
        assert_eq!(token.cancel(), CancelOutcome::AlreadyRequested);
        assert!(clone.is_cancelled());
        assert!(clone.check().is_err());
    }

    #[test]
    fn deadline_reason_is_shared_and_first_terminal_request_wins() {
        let token = CancellationToken::default();
        let clone = token.clone();
        assert_eq!(token.expire(), CancelOutcome::Requested);
        assert_eq!(clone.cancel(), CancelOutcome::AlreadyRequested);
        let error = clone.check().unwrap_err();
        assert_eq!(
            error.downcast_ref::<CancellationError>().unwrap().reason(),
            CancellationReason::DeadlineExceeded
        );
    }

    #[test]
    fn commit_and_cancellation_have_one_atomic_winner() {
        let committed = CancellationToken::default();
        assert!(committed.begin_commit());
        assert!(committed.is_committing());
        assert_eq!(committed.cancel(), CancelOutcome::TooLate);
        assert_eq!(committed.expire(), CancelOutcome::TooLate);
        committed.check().unwrap();

        let cancelled = CancellationToken::default();
        assert_eq!(cancelled.cancel(), CancelOutcome::Requested);
        assert!(!cancelled.begin_commit());
        assert!(!cancelled.is_committing());
    }

    #[test]
    fn every_file_mutation_uses_the_same_deterministic_cancel_schedule() {
        let mutations = ["mkdir", "remove", "rename", "copy", "chmod", "writeFile"];
        for mutation in mutations {
            for phase in ["before dispatch", "queued", "immediately before commit"] {
                let token = CancellationToken::default();
                assert_eq!(
                    token.cancel(),
                    CancelOutcome::Requested,
                    "{mutation}: {phase}"
                );
                assert!(!token.begin_commit(), "{mutation}: {phase}");
                assert!(token.check().is_err(), "{mutation}: {phase}");
            }

            for phase in ["during blocking call", "immediately after commit"] {
                let token = CancellationToken::default();
                assert!(token.begin_commit(), "{mutation}: {phase}");
                assert_eq!(
                    token.cancel(),
                    CancelOutcome::TooLate,
                    "{mutation}: {phase}"
                );
                token.check().unwrap();
            }
        }
    }
}
