use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Debug, Clone, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    pub fn check(&self) -> anyhow::Result<()> {
        if self.is_cancelled() {
            anyhow::bail!("operation cancelled");
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
        token.cancel();
        token.cancel();
        assert!(clone.is_cancelled());
        assert!(clone.check().is_err());
    }
}
