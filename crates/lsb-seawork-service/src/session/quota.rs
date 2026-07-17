use std::collections::HashMap;
use std::fmt;

use super::manager::ClientIdentityKey;
use super::ResourceHandle;

pub const SANDBOX_MEMORY_OVERHEAD_MIB: u32 = 2 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaLimits {
    pub connections_global: usize,
    pub connections_per_user: usize,
    pub sandboxes_global: usize,
    pub sandboxes_per_user: usize,
    pub sandboxes_per_connection: usize,
    pub cpus_per_user: u16,
    pub cpus_global: u16,
    pub memory_mib_per_user: u32,
    pub memory_mib_global: u32,
    pub disk_mib_per_user: u32,
    pub disk_mib_global: u32,
    pub processes_global: usize,
    pub processes_per_user: usize,
    pub processes_per_sandbox: usize,
    pub watches_global: usize,
    pub watches_per_user: usize,
    pub watches_per_sandbox: usize,
}

impl Default for QuotaLimits {
    fn default() -> Self {
        Self {
            connections_global: 32,
            connections_per_user: 4,
            sandboxes_global: 8,
            sandboxes_per_user: 4,
            sandboxes_per_connection: 2,
            cpus_per_user: 8,
            cpus_global: 16,
            memory_mib_per_user: 8 * 1024,
            memory_mib_global: 24 * 1024,
            disk_mib_per_user: 64 * 1024,
            disk_mib_global: 128 * 1024,
            processes_global: 256,
            processes_per_user: 128,
            processes_per_sandbox: 64,
            watches_global: 512,
            watches_per_user: 128,
            watches_per_sandbox: 64,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaError {
    GlobalConnections,
    UserConnections,
    GlobalSandboxes,
    UserSandboxes,
    ConnectionSandboxes,
    SandboxResources,
    UserCpus,
    GlobalCpus,
    UserMemory,
    GlobalMemory,
    UserDisk,
    GlobalDisk,
    GlobalProcesses,
    UserProcesses,
    SandboxProcesses,
    GlobalWatches,
    UserWatches,
    SandboxWatches,
}

impl fmt::Display for QuotaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::GlobalConnections => "global connection quota exceeded",
            Self::UserConnections => "per-user connection quota exceeded",
            Self::GlobalSandboxes => "global sandbox quota exceeded",
            Self::UserSandboxes => "per-user sandbox quota exceeded",
            Self::ConnectionSandboxes => "per-connection sandbox quota exceeded",
            Self::SandboxResources => "per-sandbox resource quota exceeded",
            Self::UserCpus => "per-user vCPU quota exceeded",
            Self::GlobalCpus => "global vCPU quota exceeded",
            Self::UserMemory => "per-user memory quota exceeded",
            Self::GlobalMemory => "global memory quota exceeded",
            Self::UserDisk => "per-user virtual disk quota exceeded",
            Self::GlobalDisk => "global virtual disk quota exceeded",
            Self::GlobalProcesses => "global guest process quota exceeded",
            Self::UserProcesses => "per-user guest process quota exceeded",
            Self::SandboxProcesses => "per-sandbox guest process quota exceeded",
            Self::GlobalWatches => "global watch quota exceeded",
            Self::UserWatches => "per-user watch quota exceeded",
            Self::SandboxWatches => "per-sandbox watch quota exceeded",
        })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SandboxResources {
    pub cpus: u16,
    pub memory_mib: u32,
    pub disk_mib: u32,
}

impl std::error::Error for QuotaError {}

#[derive(Debug)]
pub struct QuotaBook {
    limits: QuotaLimits,
    connections: usize,
    connections_by_user: HashMap<String, usize>,
    sandboxes: usize,
    sandboxes_by_user: HashMap<String, usize>,
    sandboxes_by_connection: HashMap<ResourceHandle, usize>,
    sandbox_resources: HashMap<ResourceHandle, SandboxResources>,
    cpus: u16,
    cpus_by_user: HashMap<String, u16>,
    memory_mib: u32,
    memory_mib_by_user: HashMap<String, u32>,
    disk_mib: u32,
    disk_mib_by_user: HashMap<String, u32>,
    processes: usize,
    processes_by_user: HashMap<String, usize>,
    processes_by_sandbox: HashMap<ResourceHandle, usize>,
    watches: usize,
    watches_by_user: HashMap<String, usize>,
    watches_by_sandbox: HashMap<ResourceHandle, usize>,
}

impl QuotaBook {
    pub fn new(limits: QuotaLimits) -> Self {
        Self {
            limits,
            connections: 0,
            connections_by_user: HashMap::new(),
            sandboxes: 0,
            sandboxes_by_user: HashMap::new(),
            sandboxes_by_connection: HashMap::new(),
            sandbox_resources: HashMap::new(),
            cpus: 0,
            cpus_by_user: HashMap::new(),
            memory_mib: 0,
            memory_mib_by_user: HashMap::new(),
            disk_mib: 0,
            disk_mib_by_user: HashMap::new(),
            processes: 0,
            processes_by_user: HashMap::new(),
            processes_by_sandbox: HashMap::new(),
            watches: 0,
            watches_by_user: HashMap::new(),
            watches_by_sandbox: HashMap::new(),
        }
    }

    pub fn reserve_connection(&mut self, identity: &ClientIdentityKey) -> Result<(), QuotaError> {
        if self.connections >= self.limits.connections_global {
            return Err(QuotaError::GlobalConnections);
        }
        let user = self
            .connections_by_user
            .get(&identity.user_sid)
            .copied()
            .unwrap_or(0);
        if user >= self.limits.connections_per_user {
            return Err(QuotaError::UserConnections);
        }
        self.connections += 1;
        *self
            .connections_by_user
            .entry(identity.user_sid.clone())
            .or_default() += 1;
        Ok(())
    }

    pub fn release_connection(&mut self, identity: &ClientIdentityKey) {
        self.connections = self.connections.saturating_sub(1);
        decrement(&mut self.connections_by_user, &identity.user_sid);
    }

    pub fn reserve_sandbox(
        &mut self,
        connection: ResourceHandle,
        sandbox: ResourceHandle,
        identity: &ClientIdentityKey,
        resources: SandboxResources,
    ) -> Result<(), QuotaError> {
        if self.sandboxes >= self.limits.sandboxes_global {
            return Err(QuotaError::GlobalSandboxes);
        }
        let user = self
            .sandboxes_by_user
            .get(&identity.user_sid)
            .copied()
            .unwrap_or(0);
        if user >= self.limits.sandboxes_per_user {
            return Err(QuotaError::UserSandboxes);
        }
        let connection_count = self
            .sandboxes_by_connection
            .get(&connection)
            .copied()
            .unwrap_or(0);
        if connection_count >= self.limits.sandboxes_per_connection {
            return Err(QuotaError::ConnectionSandboxes);
        }
        if self.sandbox_resources.contains_key(&sandbox)
            || resources.cpus > 8
            || resources.memory_mib > 8 * 1024
            || resources.disk_mib > 32 * 1024
            || (resources != SandboxResources::default()
                && (resources.cpus == 0 || resources.memory_mib < 512 || resources.disk_mib < 1024))
        {
            return Err(QuotaError::SandboxResources);
        }
        let user_cpus = self
            .cpus_by_user
            .get(&identity.user_sid)
            .copied()
            .unwrap_or(0);
        let next_user_cpus = user_cpus
            .checked_add(resources.cpus)
            .ok_or(QuotaError::UserCpus)?;
        let next_cpus = self
            .cpus
            .checked_add(resources.cpus)
            .ok_or(QuotaError::GlobalCpus)?;
        if next_user_cpus > self.limits.cpus_per_user {
            return Err(QuotaError::UserCpus);
        }
        if next_cpus > self.limits.cpus_global {
            return Err(QuotaError::GlobalCpus);
        }
        let user_memory = self
            .memory_mib_by_user
            .get(&identity.user_sid)
            .copied()
            .unwrap_or(0);
        let next_user_memory = user_memory
            .checked_add(resources.memory_mib)
            .ok_or(QuotaError::UserMemory)?;
        let accounted_memory = if resources == SandboxResources::default() {
            0
        } else {
            resources
                .memory_mib
                .checked_add(SANDBOX_MEMORY_OVERHEAD_MIB)
                .ok_or(QuotaError::GlobalMemory)?
        };
        let next_memory = self
            .memory_mib
            .checked_add(accounted_memory)
            .ok_or(QuotaError::GlobalMemory)?;
        if next_user_memory > self.limits.memory_mib_per_user {
            return Err(QuotaError::UserMemory);
        }
        if next_memory > self.limits.memory_mib_global {
            return Err(QuotaError::GlobalMemory);
        }
        let user_disk = self
            .disk_mib_by_user
            .get(&identity.user_sid)
            .copied()
            .unwrap_or(0);
        let next_user_disk = user_disk
            .checked_add(resources.disk_mib)
            .ok_or(QuotaError::UserDisk)?;
        let next_disk = self
            .disk_mib
            .checked_add(resources.disk_mib)
            .ok_or(QuotaError::GlobalDisk)?;
        if next_user_disk > self.limits.disk_mib_per_user {
            return Err(QuotaError::UserDisk);
        }
        if next_disk > self.limits.disk_mib_global {
            return Err(QuotaError::GlobalDisk);
        }
        self.sandboxes += 1;
        *self
            .sandboxes_by_user
            .entry(identity.user_sid.clone())
            .or_default() += 1;
        *self.sandboxes_by_connection.entry(connection).or_default() += 1;
        self.sandbox_resources.insert(sandbox, resources);
        self.cpus = next_cpus;
        *self
            .cpus_by_user
            .entry(identity.user_sid.clone())
            .or_default() = next_user_cpus;
        self.memory_mib = next_memory;
        *self
            .memory_mib_by_user
            .entry(identity.user_sid.clone())
            .or_default() = next_user_memory;
        self.disk_mib = next_disk;
        *self
            .disk_mib_by_user
            .entry(identity.user_sid.clone())
            .or_default() = next_user_disk;
        Ok(())
    }

    pub fn release_sandbox(
        &mut self,
        connection: ResourceHandle,
        sandbox: ResourceHandle,
        identity: &ClientIdentityKey,
    ) {
        let Some(resources) = self.sandbox_resources.remove(&sandbox) else {
            return;
        };
        self.sandboxes = self.sandboxes.saturating_sub(1);
        decrement(&mut self.sandboxes_by_user, &identity.user_sid);
        decrement(&mut self.sandboxes_by_connection, &connection);
        self.cpus = self.cpus.saturating_sub(resources.cpus);
        decrement_by(&mut self.cpus_by_user, &identity.user_sid, resources.cpus);
        let accounted_memory = if resources == SandboxResources::default() {
            0
        } else {
            resources
                .memory_mib
                .saturating_add(SANDBOX_MEMORY_OVERHEAD_MIB)
        };
        self.memory_mib = self.memory_mib.saturating_sub(accounted_memory);
        decrement_by(
            &mut self.memory_mib_by_user,
            &identity.user_sid,
            resources.memory_mib,
        );
        self.disk_mib = self.disk_mib.saturating_sub(resources.disk_mib);
        decrement_by(
            &mut self.disk_mib_by_user,
            &identity.user_sid,
            resources.disk_mib,
        );
    }

    pub fn reserve_process(
        &mut self,
        sandbox: ResourceHandle,
        identity: &ClientIdentityKey,
    ) -> Result<(), QuotaError> {
        if self.processes >= self.limits.processes_global {
            return Err(QuotaError::GlobalProcesses);
        }
        let user = self
            .processes_by_user
            .get(&identity.user_sid)
            .copied()
            .unwrap_or(0);
        if user >= self.limits.processes_per_user {
            return Err(QuotaError::UserProcesses);
        }
        let sandbox_count = self
            .processes_by_sandbox
            .get(&sandbox)
            .copied()
            .unwrap_or(0);
        if sandbox_count >= self.limits.processes_per_sandbox {
            return Err(QuotaError::SandboxProcesses);
        }
        self.processes += 1;
        *self
            .processes_by_user
            .entry(identity.user_sid.clone())
            .or_default() += 1;
        *self.processes_by_sandbox.entry(sandbox).or_default() += 1;
        Ok(())
    }

    pub fn release_process(&mut self, sandbox: ResourceHandle, identity: &ClientIdentityKey) {
        self.processes = self.processes.saturating_sub(1);
        decrement(&mut self.processes_by_user, &identity.user_sid);
        decrement(&mut self.processes_by_sandbox, &sandbox);
    }

    pub fn reserve_watch(
        &mut self,
        sandbox: ResourceHandle,
        identity: &ClientIdentityKey,
    ) -> Result<(), QuotaError> {
        if self.watches >= self.limits.watches_global {
            return Err(QuotaError::GlobalWatches);
        }
        let user = self
            .watches_by_user
            .get(&identity.user_sid)
            .copied()
            .unwrap_or(0);
        if user >= self.limits.watches_per_user {
            return Err(QuotaError::UserWatches);
        }
        let sandbox_count = self.watches_by_sandbox.get(&sandbox).copied().unwrap_or(0);
        if sandbox_count >= self.limits.watches_per_sandbox {
            return Err(QuotaError::SandboxWatches);
        }
        self.watches += 1;
        *self
            .watches_by_user
            .entry(identity.user_sid.clone())
            .or_default() += 1;
        *self.watches_by_sandbox.entry(sandbox).or_default() += 1;
        Ok(())
    }

    pub fn release_watch(&mut self, sandbox: ResourceHandle, identity: &ClientIdentityKey) {
        self.watches = self.watches.saturating_sub(1);
        decrement(&mut self.watches_by_user, &identity.user_sid);
        decrement(&mut self.watches_by_sandbox, &sandbox);
    }

    pub fn totals(&self) -> (usize, usize) {
        (self.connections, self.sandboxes)
    }
}

fn decrement<K: std::hash::Hash + Eq + Clone>(counts: &mut HashMap<K, usize>, key: &K) {
    let remove = if let Some(count) = counts.get_mut(key) {
        *count = count.saturating_sub(1);
        *count == 0
    } else {
        false
    };
    if remove {
        counts.remove(key);
    }
}

fn decrement_by<K, V>(counts: &mut HashMap<K, V>, key: &K, amount: V)
where
    K: std::hash::Hash + Eq + Clone,
    V: Copy + Default + PartialEq + std::ops::Sub<Output = V>,
{
    let remove = if let Some(count) = counts.get_mut(key) {
        *count = *count - amount;
        *count == V::default()
    } else {
        false
    };
    if remove {
        counts.remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(user: &str) -> ClientIdentityKey {
        ClientIdentityKey::for_test(user, "logon", 1)
    }

    #[test]
    fn quota_boundaries_release_exactly() {
        let limits = QuotaLimits {
            connections_global: 2,
            connections_per_user: 1,
            sandboxes_global: 2,
            sandboxes_per_user: 1,
            sandboxes_per_connection: 1,
            processes_global: 2,
            processes_per_user: 1,
            processes_per_sandbox: 1,
            watches_global: 2,
            watches_per_user: 1,
            watches_per_sandbox: 1,
            ..QuotaLimits::default()
        };
        let mut book = QuotaBook::new(limits);
        let a = identity("A");
        let b = identity("B");
        let connection_a = ResourceHandle::random().unwrap();
        let connection_b = ResourceHandle::random().unwrap();
        let sandbox_a = ResourceHandle::random().unwrap();
        let sandbox_b = ResourceHandle::random().unwrap();
        book.reserve_connection(&a).unwrap();
        assert_eq!(
            book.reserve_connection(&a),
            Err(QuotaError::UserConnections)
        );
        book.reserve_connection(&b).unwrap();
        assert_eq!(
            book.reserve_connection(&identity("C")),
            Err(QuotaError::GlobalConnections)
        );
        book.reserve_sandbox(connection_a, sandbox_a, &a, SandboxResources::default())
            .unwrap();
        assert_eq!(
            book.reserve_sandbox(
                connection_a,
                ResourceHandle::random().unwrap(),
                &a,
                SandboxResources::default(),
            ),
            Err(QuotaError::UserSandboxes)
        );
        book.reserve_sandbox(connection_b, sandbox_b, &b, SandboxResources::default())
            .unwrap();
        book.reserve_process(sandbox_a, &a).unwrap();
        assert_eq!(
            book.reserve_process(sandbox_a, &a),
            Err(QuotaError::UserProcesses)
        );
        book.reserve_process(sandbox_b, &b).unwrap();
        assert_eq!(
            book.reserve_process(ResourceHandle::random().unwrap(), &identity("C")),
            Err(QuotaError::GlobalProcesses)
        );
        book.reserve_watch(sandbox_a, &a).unwrap();
        assert_eq!(
            book.reserve_watch(sandbox_a, &a),
            Err(QuotaError::UserWatches)
        );
        book.reserve_watch(sandbox_b, &b).unwrap();
        assert_eq!(
            book.reserve_watch(ResourceHandle::random().unwrap(), &identity("C")),
            Err(QuotaError::GlobalWatches)
        );
        book.release_watch(sandbox_a, &a);
        book.release_process(sandbox_a, &a);
        assert_eq!(book.totals(), (2, 2));
        book.release_sandbox(connection_a, sandbox_a, &a);
        book.release_connection(&a);
        assert_eq!(book.totals(), (1, 1));
    }

    #[test]
    fn cpu_memory_and_disk_are_reserved_and_released_atomically() {
        let limits = QuotaLimits {
            sandboxes_per_user: 4,
            sandboxes_per_connection: 4,
            ..QuotaLimits::default()
        };
        let mut book = QuotaBook::new(limits);
        let a = identity("A");
        let b = identity("B");
        let connection_a = ResourceHandle::random().unwrap();
        let connection_b = ResourceHandle::random().unwrap();
        book.reserve_connection(&a).unwrap();
        book.reserve_connection(&b).unwrap();
        let sandbox_a = ResourceHandle::random().unwrap();
        let resources = SandboxResources {
            cpus: 8,
            memory_mib: 8 * 1024,
            disk_mib: 32 * 1024,
        };
        book.reserve_sandbox(connection_a, sandbox_a, &a, resources)
            .unwrap();
        assert_eq!(
            book.reserve_sandbox(
                connection_a,
                ResourceHandle::random().unwrap(),
                &a,
                SandboxResources {
                    cpus: 1,
                    memory_mib: 512,
                    disk_mib: 1024,
                },
            ),
            Err(QuotaError::UserCpus)
        );
        book.release_sandbox(connection_a, sandbox_a, &a);
        book.reserve_sandbox(
            connection_b,
            ResourceHandle::random().unwrap(),
            &b,
            resources,
        )
        .unwrap();
        let sandbox_b = book.sandbox_resources.keys().copied().next().unwrap();
        book.release_sandbox(connection_b, sandbox_b, &b);
        assert_eq!((book.cpus, book.memory_mib, book.disk_mib), (0, 0, 0));
        assert!(book.cpus_by_user.is_empty());
        assert!(book.memory_mib_by_user.is_empty());
        assert!(book.disk_mib_by_user.is_empty());

        let mut memory = QuotaBook::new(limits);
        memory.reserve_connection(&a).unwrap();
        let first = ResourceHandle::random().unwrap();
        memory
            .reserve_sandbox(
                connection_a,
                first,
                &a,
                SandboxResources {
                    cpus: 1,
                    memory_mib: 8 * 1024,
                    disk_mib: 1024,
                },
            )
            .unwrap();
        assert_eq!(
            memory.reserve_sandbox(
                connection_a,
                ResourceHandle::random().unwrap(),
                &a,
                SandboxResources {
                    cpus: 1,
                    memory_mib: 512,
                    disk_mib: 1024,
                },
            ),
            Err(QuotaError::UserMemory)
        );

        let mut disk = QuotaBook::new(limits);
        disk.reserve_connection(&a).unwrap();
        for _ in 0..2 {
            disk.reserve_sandbox(
                connection_a,
                ResourceHandle::random().unwrap(),
                &a,
                SandboxResources {
                    cpus: 1,
                    memory_mib: 512,
                    disk_mib: 32 * 1024,
                },
            )
            .unwrap();
        }
        assert_eq!(
            disk.reserve_sandbox(
                connection_a,
                ResourceHandle::random().unwrap(),
                &a,
                SandboxResources {
                    cpus: 1,
                    memory_mib: 512,
                    disk_mib: 1024,
                },
            ),
            Err(QuotaError::UserDisk)
        );
    }
}
