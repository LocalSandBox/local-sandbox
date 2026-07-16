use std::time::{Duration, Instant};

use anyhow::{bail, Result};

use crate::session::{CancellationToken, ClientIdentityKey, ResourceHandle};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxState {
    Reserved,
    Preparing,
    Running,
    Draining,
    Cleaning,
    Removed,
    FailedSetup,
    Quarantined,
}

#[derive(Debug)]
pub struct SandboxResource {
    pub id: ResourceHandle,
    pub connection_id: ResourceHandle,
    pub owner: ClientIdentityKey,
    pub cancellation: CancellationToken,
    pub deadline: Instant,
    state: SandboxState,
}

impl SandboxResource {
    pub fn reserve(
        connection_id: ResourceHandle,
        owner: ClientIdentityKey,
        cancellation: CancellationToken,
        maximum_duration: Duration,
    ) -> Result<Self> {
        if maximum_duration.is_zero() {
            bail!("sandbox duration must be nonzero");
        }
        Ok(Self {
            id: ResourceHandle::random()?,
            connection_id,
            owner,
            cancellation,
            deadline: Instant::now() + maximum_duration,
            state: SandboxState::Reserved,
        })
    }

    pub fn state(&self) -> SandboxState {
        self.state
    }

    pub fn transition(&mut self, next: SandboxState) -> Result<()> {
        let allowed = matches!(
            (self.state, next),
            (SandboxState::Reserved, SandboxState::Preparing)
                | (SandboxState::Preparing, SandboxState::Running)
                | (SandboxState::Preparing, SandboxState::FailedSetup)
                | (SandboxState::Running, SandboxState::Draining)
                | (SandboxState::FailedSetup, SandboxState::Cleaning)
                | (SandboxState::Draining, SandboxState::Cleaning)
                | (SandboxState::Cleaning, SandboxState::Removed)
                | (SandboxState::Cleaning, SandboxState::Quarantined)
        );
        if !allowed {
            bail!(
                "invalid sandbox lifecycle transition {:?} -> {next:?}",
                self.state
            );
        }
        self.state = next;
        Ok(())
    }

    pub fn begin_drain(&mut self) -> Result<()> {
        self.cancellation.cancel();
        match self.state {
            SandboxState::Running => self.transition(SandboxState::Draining),
            SandboxState::Preparing => self.transition(SandboxState::FailedSetup),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_cannot_skip_cleanup() {
        let mut sandbox = SandboxResource::reserve(
            ResourceHandle::random().unwrap(),
            ClientIdentityKey::for_test("user", "logon", 1),
            CancellationToken::default(),
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(sandbox.transition(SandboxState::Running).is_err());
        sandbox.transition(SandboxState::Preparing).unwrap();
        sandbox.transition(SandboxState::Running).unwrap();
        sandbox.begin_drain().unwrap();
        assert!(sandbox.cancellation.is_cancelled());
        sandbox.transition(SandboxState::Cleaning).unwrap();
        sandbox.transition(SandboxState::Removed).unwrap();
    }
}
