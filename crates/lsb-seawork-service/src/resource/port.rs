use std::collections::HashMap;
use std::fmt;

use anyhow::{bail, Result};

use crate::session::ResourceHandle;

pub const MAPPINGS_PER_SANDBOX: usize = 32;
pub const MAPPINGS_PER_USER: usize = 64;
pub const MAPPINGS_GLOBAL: usize = 128;
pub const ACTIVE_TUNNELS_PER_SANDBOX: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkQuotaError {
    SandboxMappings,
    UserMappings,
    GlobalMappings,
    SandboxAlreadyReserved,
    SandboxNotReserved,
    SandboxActiveTunnels,
}

impl fmt::Display for NetworkQuotaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SandboxMappings => "per-sandbox network mapping quota exceeded",
            Self::UserMappings => "per-user network mapping quota exceeded",
            Self::GlobalMappings => "global network mapping quota exceeded",
            Self::SandboxAlreadyReserved => "sandbox network mappings are already reserved",
            Self::SandboxNotReserved => "sandbox network mappings are not reserved",
            Self::SandboxActiveTunnels => "per-sandbox active tunnel quota exceeded",
        })
    }
}

impl std::error::Error for NetworkQuotaError {}

#[derive(Debug, Clone)]
struct MappingReservation {
    user_sid: String,
    count: usize,
}

#[derive(Debug, Default)]
pub struct NetworkQuotaBook {
    mappings: usize,
    mappings_by_user: HashMap<String, usize>,
    mappings_by_sandbox: HashMap<ResourceHandle, MappingReservation>,
    active_tunnels_by_sandbox: HashMap<ResourceHandle, usize>,
}

impl NetworkQuotaBook {
    pub fn reserve_mappings(
        &mut self,
        sandbox: ResourceHandle,
        user_sid: &str,
        count: usize,
    ) -> std::result::Result<(), NetworkQuotaError> {
        if self.mappings_by_sandbox.contains_key(&sandbox) {
            return Err(NetworkQuotaError::SandboxAlreadyReserved);
        }
        if count > MAPPINGS_PER_SANDBOX {
            return Err(NetworkQuotaError::SandboxMappings);
        }
        let user = self.mappings_by_user.get(user_sid).copied().unwrap_or(0);
        let next_user = user
            .checked_add(count)
            .ok_or(NetworkQuotaError::UserMappings)?;
        if next_user > MAPPINGS_PER_USER {
            return Err(NetworkQuotaError::UserMappings);
        }
        let next_global = self
            .mappings
            .checked_add(count)
            .ok_or(NetworkQuotaError::GlobalMappings)?;
        if next_global > MAPPINGS_GLOBAL {
            return Err(NetworkQuotaError::GlobalMappings);
        }

        self.mappings = next_global;
        if count != 0 {
            self.mappings_by_user
                .insert(user_sid.to_string(), next_user);
        }
        self.mappings_by_sandbox.insert(
            sandbox,
            MappingReservation {
                user_sid: user_sid.to_string(),
                count,
            },
        );
        Ok(())
    }

    pub fn reserve_tunnel(
        &mut self,
        sandbox: ResourceHandle,
    ) -> std::result::Result<(), NetworkQuotaError> {
        if self
            .mappings_by_sandbox
            .get(&sandbox)
            .is_none_or(|reservation| reservation.count == 0)
        {
            return Err(NetworkQuotaError::SandboxNotReserved);
        }
        let count = self
            .active_tunnels_by_sandbox
            .get(&sandbox)
            .copied()
            .unwrap_or(0);
        if count >= ACTIVE_TUNNELS_PER_SANDBOX {
            return Err(NetworkQuotaError::SandboxActiveTunnels);
        }
        self.active_tunnels_by_sandbox.insert(sandbox, count + 1);
        Ok(())
    }

    pub fn release_tunnel(&mut self, sandbox: ResourceHandle) {
        let remove = if let Some(count) = self.active_tunnels_by_sandbox.get_mut(&sandbox) {
            *count = count.saturating_sub(1);
            *count == 0
        } else {
            false
        };
        if remove {
            self.active_tunnels_by_sandbox.remove(&sandbox);
        }
    }

    pub fn release_sandbox(&mut self, sandbox: ResourceHandle) {
        self.active_tunnels_by_sandbox.remove(&sandbox);
        let Some(reservation) = self.mappings_by_sandbox.remove(&sandbox) else {
            return;
        };
        self.mappings = self.mappings.saturating_sub(reservation.count);
        let remove_user = if let Some(count) = self.mappings_by_user.get_mut(&reservation.user_sid)
        {
            *count = count.saturating_sub(reservation.count);
            *count == 0
        } else {
            false
        };
        if remove_user {
            self.mappings_by_user.remove(&reservation.user_sid);
        }
    }

    pub fn totals(&self, sandbox: ResourceHandle) -> (usize, usize) {
        (
            self.mappings,
            self.active_tunnels_by_sandbox
                .get(&sandbox)
                .copied()
                .unwrap_or(0),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortIsolationCapability {
    pub available: bool,
    pub reason: String,
}

impl PortIsolationCapability {
    pub fn detect() -> Self {
        let wfp = crate::windows::wfp::capability();
        Self {
            available: wfp.available,
            reason: wfp.reason.to_string(),
        }
    }

    pub fn require_available(&self) -> Result<()> {
        if !self.available {
            bail!("PORT_ISOLATION_UNAVAILABLE: {}", self.reason);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_ports_fail_closed_without_wfp_evidence() {
        let capability = PortIsolationCapability::detect();
        assert!(!capability.available);
        assert!(capability.require_available().is_err());
    }

    #[test]
    fn mapping_quotas_are_atomic_and_release_exactly() {
        let mut quotas = NetworkQuotaBook::default();
        let a1 = ResourceHandle::random().unwrap();
        let a2 = ResourceHandle::random().unwrap();
        let a3 = ResourceHandle::random().unwrap();
        let b1 = ResourceHandle::random().unwrap();
        let b2 = ResourceHandle::random().unwrap();
        quotas.reserve_mappings(a1, "A", 32).unwrap();
        quotas.reserve_mappings(a2, "A", 32).unwrap();
        assert_eq!(
            quotas.reserve_mappings(a3, "A", 1),
            Err(NetworkQuotaError::UserMappings)
        );
        assert_eq!(quotas.totals(a1), (64, 0));
        quotas.reserve_mappings(b1, "B", 32).unwrap();
        quotas.reserve_mappings(b2, "B", 32).unwrap();
        assert_eq!(
            quotas.reserve_mappings(ResourceHandle::random().unwrap(), "C", 1),
            Err(NetworkQuotaError::GlobalMappings)
        );
        assert_eq!(quotas.totals(a1), (128, 0));
        quotas.release_sandbox(a1);
        quotas.reserve_mappings(a3, "A", 32).unwrap();
        assert_eq!(quotas.totals(a3), (128, 0));
        assert_eq!(
            quotas.reserve_mappings(a3, "A", 0),
            Err(NetworkQuotaError::SandboxAlreadyReserved)
        );
        assert_eq!(
            quotas.reserve_mappings(ResourceHandle::random().unwrap(), "C", 33),
            Err(NetworkQuotaError::SandboxMappings)
        );
        assert_eq!(quotas.totals(a3), (128, 0));
    }

    #[test]
    fn active_tunnel_quota_requires_a_sandbox_and_recovers_one_slot() {
        let mut quotas = NetworkQuotaBook::default();
        let sandbox = ResourceHandle::random().unwrap();
        assert_eq!(
            quotas.reserve_tunnel(sandbox),
            Err(NetworkQuotaError::SandboxNotReserved)
        );
        let empty = ResourceHandle::random().unwrap();
        quotas.reserve_mappings(empty, "A", 0).unwrap();
        assert_eq!(
            quotas.reserve_tunnel(empty),
            Err(NetworkQuotaError::SandboxNotReserved)
        );
        quotas.release_sandbox(empty);
        quotas.reserve_mappings(sandbox, "A", 1).unwrap();
        for _ in 0..ACTIVE_TUNNELS_PER_SANDBOX {
            quotas.reserve_tunnel(sandbox).unwrap();
        }
        assert_eq!(
            quotas.reserve_tunnel(sandbox),
            Err(NetworkQuotaError::SandboxActiveTunnels)
        );
        quotas.release_tunnel(sandbox);
        quotas.reserve_tunnel(sandbox).unwrap();
        assert_eq!(quotas.totals(sandbox), (1, ACTIVE_TUNNELS_PER_SANDBOX));
        quotas.release_sandbox(sandbox);
        assert_eq!(quotas.totals(sandbox), (0, 0));
        assert_eq!(
            quotas.reserve_tunnel(sandbox),
            Err(NetworkQuotaError::SandboxNotReserved)
        );
    }
}
