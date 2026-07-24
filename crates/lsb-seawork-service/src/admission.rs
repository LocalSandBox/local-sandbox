use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use anyhow::{bail, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionState {
    Open,
    UpdateWaitingForIdle,
    UpdateSealed,
    ActivationPending,
    Uninstalling,
    Quarantined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionSnapshot {
    pub state: AdmissionState,
    pub active_use_count: u32,
}

#[derive(Debug)]
struct Inner {
    state: AdmissionState,
    active_use_count: u32,
}

#[derive(Debug)]
struct Shared {
    inner: Mutex<Inner>,
    changed: Condvar,
}

#[derive(Debug, Clone)]
pub struct AdmissionController {
    shared: Arc<Shared>,
}

#[derive(Debug)]
pub struct ActiveUseLease {
    shared: Arc<Shared>,
    released: bool,
}

impl AdmissionController {
    pub fn new(initially_open: bool) -> Self {
        Self {
            shared: Arc::new(Shared {
                inner: Mutex::new(Inner {
                    state: if initially_open {
                        AdmissionState::Open
                    } else {
                        AdmissionState::Quarantined
                    },
                    active_use_count: 0,
                }),
                changed: Condvar::new(),
            }),
        }
    }

    pub fn snapshot(&self) -> AdmissionSnapshot {
        self.shared
            .inner
            .lock()
            .map(|inner| AdmissionSnapshot {
                state: inner.state,
                active_use_count: inner.active_use_count,
            })
            .unwrap_or(AdmissionSnapshot {
                state: AdmissionState::Quarantined,
                active_use_count: u32::MAX,
            })
    }

    pub fn is_same_controller(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.shared, &other.shared)
    }

    pub fn accepts_work(&self) -> bool {
        matches!(
            self.snapshot().state,
            AdmissionState::Open | AdmissionState::UpdateWaitingForIdle
        )
    }

    pub fn reserve_active_use(&self) -> Result<ActiveUseLease> {
        let mut inner = self
            .shared
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("admission controller poisoned"))?;
        if !matches!(
            inner.state,
            AdmissionState::Open | AdmissionState::UpdateWaitingForIdle
        ) {
            bail!("new workload admissions are sealed");
        }
        inner.active_use_count = inner
            .active_use_count
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("active-use count overflow"))?;
        Ok(ActiveUseLease {
            shared: self.shared.clone(),
            released: false,
        })
    }

    pub fn begin_update_waiting(&self) -> Result<AdmissionState> {
        let mut inner = self
            .shared
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("admission controller poisoned"))?;
        match inner.state {
            AdmissionState::Open | AdmissionState::UpdateWaitingForIdle => {
                inner.state = if inner.active_use_count == 0 {
                    AdmissionState::UpdateSealed
                } else {
                    AdmissionState::UpdateWaitingForIdle
                };
            }
            AdmissionState::UpdateSealed => {}
            _ => bail!("service is not available for update preparation"),
        }
        let state = inner.state;
        self.shared.changed.notify_all();
        Ok(state)
    }

    pub fn try_seal_if_idle(&self) -> Result<bool> {
        let mut inner = self
            .shared
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("admission controller poisoned"))?;
        match inner.state {
            AdmissionState::Open if inner.active_use_count == 0 => {
                inner.state = AdmissionState::UpdateSealed;
                self.shared.changed.notify_all();
                Ok(true)
            }
            AdmissionState::Open => Ok(false),
            AdmissionState::UpdateSealed if inner.active_use_count == 0 => Ok(true),
            _ => bail!("service is not available for atomic update sealing"),
        }
    }

    pub fn mark_activation_pending(&self) -> Result<()> {
        let mut inner = self
            .shared
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("admission controller poisoned"))?;
        if inner.state != AdmissionState::UpdateSealed || inner.active_use_count != 0 {
            bail!("activation requires sealed zero-use admissions");
        }
        inner.state = AdmissionState::ActivationPending;
        self.shared.changed.notify_all();
        Ok(())
    }

    pub fn reopen(&self, allowed: bool) -> Result<()> {
        let mut inner = self
            .shared
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("admission controller poisoned"))?;
        inner.state = if allowed {
            AdmissionState::Open
        } else {
            AdmissionState::Quarantined
        };
        self.shared.changed.notify_all();
        Ok(())
    }

    pub fn begin_uninstall(&self) -> Result<()> {
        let mut inner = self
            .shared
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("admission controller poisoned"))?;
        if !matches!(
            inner.state,
            AdmissionState::Open | AdmissionState::Uninstalling
        ) {
            bail!("service is not available for uninstall preparation");
        }
        inner.state = AdmissionState::Uninstalling;
        self.shared.changed.notify_all();
        Ok(())
    }

    pub fn restore_uninstalling(&self) -> Result<()> {
        let mut inner = self
            .shared
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("admission controller poisoned"))?;
        if inner.active_use_count != 0 {
            bail!("cannot restore uninstall state with active use");
        }
        inner.state = AdmissionState::Uninstalling;
        self.shared.changed.notify_all();
        Ok(())
    }

    pub fn quarantine(&self) {
        if let Ok(mut inner) = self.shared.inner.lock() {
            inner.state = AdmissionState::Quarantined;
            self.shared.changed.notify_all();
        }
    }

    pub fn wait_until_update_sealed(&self, cancelled: &AtomicBool) -> Result<()> {
        let mut inner = self
            .shared
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("admission controller poisoned"))?;
        loop {
            match inner.state {
                AdmissionState::UpdateSealed if inner.active_use_count == 0 => return Ok(()),
                AdmissionState::UpdateWaitingForIdle => {}
                _ => bail!("service left update waiting state before helper handoff"),
            }
            if cancelled.load(Ordering::Acquire) {
                bail!("update wait cancelled by service shutdown");
            }
            let waited = self
                .shared
                .changed
                .wait_timeout(inner, Duration::from_secs(1))
                .map_err(|_| anyhow::anyhow!("admission controller poisoned"))?;
            inner = waited.0;
        }
    }
}

impl ActiveUseLease {
    fn release(&mut self) {
        if self.released {
            return;
        }
        self.released = true;
        let Ok(mut inner) = self.shared.inner.lock() else {
            return;
        };
        inner.active_use_count = inner.active_use_count.saturating_sub(1);
        if inner.active_use_count == 0 && inner.state == AdmissionState::UpdateWaitingForIdle {
            inner.state = AdmissionState::UpdateSealed;
        }
        self.shared.changed.notify_all();
    }
}

impl Drop for ActiveUseLease {
    fn drop(&mut self) {
        self.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    use std::thread;

    #[test]
    fn waiting_accepts_work_and_zero_transition_seals() {
        let controller = AdmissionController::new(true);
        let first = controller.reserve_active_use().unwrap();
        assert_eq!(
            controller.begin_update_waiting().unwrap(),
            AdmissionState::UpdateWaitingForIdle
        );
        let second = controller.reserve_active_use().unwrap();
        assert_eq!(controller.snapshot().active_use_count, 2);
        drop(first);
        assert_eq!(
            controller.snapshot().state,
            AdmissionState::UpdateWaitingForIdle
        );
        drop(second);
        assert_eq!(
            controller.snapshot(),
            AdmissionSnapshot {
                state: AdmissionState::UpdateSealed,
                active_use_count: 0,
            }
        );
        assert!(controller.reserve_active_use().is_err());
    }

    #[test]
    fn atomic_idle_seal_never_enters_a_waiting_blackout() {
        let controller = AdmissionController::new(true);
        let active = controller.reserve_active_use().unwrap();
        assert!(!controller.try_seal_if_idle().unwrap());
        assert_eq!(controller.snapshot().state, AdmissionState::Open);
        assert!(controller.accepts_work());
        drop(active);
        assert!(controller.try_seal_if_idle().unwrap());
        assert_eq!(controller.snapshot().state, AdmissionState::UpdateSealed);
        assert!(!controller.accepts_work());
    }

    #[test]
    fn a_racing_start_is_either_reserved_or_rejected_after_seal() {
        for _ in 0..256 {
            let controller = AdmissionController::new(true);
            let active = controller.reserve_active_use().unwrap();
            controller.begin_update_waiting().unwrap();
            let barrier = Arc::new(Barrier::new(2));
            let contender = controller.clone();
            let contender_barrier = barrier.clone();
            let thread = thread::spawn(move || {
                contender_barrier.wait();
                contender.reserve_active_use().ok()
            });
            barrier.wait();
            drop(active);
            let raced = thread.join().unwrap();
            let snapshot = controller.snapshot();
            match raced {
                Some(lease) => {
                    assert_eq!(snapshot.active_use_count, 1);
                    assert_eq!(snapshot.state, AdmissionState::UpdateWaitingForIdle);
                    drop(lease);
                    assert_eq!(controller.snapshot().state, AdmissionState::UpdateSealed);
                }
                None => {
                    assert_eq!(snapshot.active_use_count, 0);
                    assert_eq!(snapshot.state, AdmissionState::UpdateSealed);
                }
            }
        }
    }

    #[test]
    fn activation_requires_a_zero_use_seal() {
        let controller = AdmissionController::new(true);
        let active = controller.reserve_active_use().unwrap();
        controller.begin_update_waiting().unwrap();
        assert!(controller.mark_activation_pending().is_err());
        drop(active);
        controller.mark_activation_pending().unwrap();
        assert_eq!(
            controller.snapshot().state,
            AdmissionState::ActivationPending
        );
        controller.reopen(true).unwrap();
        assert!(controller.accepts_work());
    }
}
