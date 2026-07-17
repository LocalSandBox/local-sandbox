use std::collections::HashMap;
use std::fmt;

use super::manager::ClientIdentityKey;
use super::ResourceHandle;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaLimits {
    pub connections_global: usize,
    pub connections_per_user: usize,
    pub sandboxes_global: usize,
    pub sandboxes_per_user: usize,
    pub sandboxes_per_connection: usize,
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
            Self::GlobalProcesses => "global guest process quota exceeded",
            Self::UserProcesses => "per-user guest process quota exceeded",
            Self::SandboxProcesses => "per-sandbox guest process quota exceeded",
            Self::GlobalWatches => "global watch quota exceeded",
            Self::UserWatches => "per-user watch quota exceeded",
            Self::SandboxWatches => "per-sandbox watch quota exceeded",
        })
    }
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
        identity: &ClientIdentityKey,
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
        self.sandboxes += 1;
        *self
            .sandboxes_by_user
            .entry(identity.user_sid.clone())
            .or_default() += 1;
        *self.sandboxes_by_connection.entry(connection).or_default() += 1;
        Ok(())
    }

    pub fn release_sandbox(&mut self, connection: ResourceHandle, identity: &ClientIdentityKey) {
        self.sandboxes = self.sandboxes.saturating_sub(1);
        decrement(&mut self.sandboxes_by_user, &identity.user_sid);
        decrement(&mut self.sandboxes_by_connection, &connection);
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
        };
        let mut book = QuotaBook::new(limits);
        let a = identity("A");
        let b = identity("B");
        let connection_a = ResourceHandle::random().unwrap();
        let connection_b = ResourceHandle::random().unwrap();
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
        book.reserve_sandbox(connection_a, &a).unwrap();
        assert_eq!(
            book.reserve_sandbox(connection_a, &a),
            Err(QuotaError::UserSandboxes)
        );
        book.reserve_sandbox(connection_b, &b).unwrap();
        book.reserve_process(connection_a, &a).unwrap();
        assert_eq!(
            book.reserve_process(connection_a, &a),
            Err(QuotaError::UserProcesses)
        );
        book.reserve_process(connection_b, &b).unwrap();
        assert_eq!(
            book.reserve_process(ResourceHandle::random().unwrap(), &identity("C")),
            Err(QuotaError::GlobalProcesses)
        );
        book.reserve_watch(connection_a, &a).unwrap();
        assert_eq!(
            book.reserve_watch(connection_a, &a),
            Err(QuotaError::UserWatches)
        );
        book.reserve_watch(connection_b, &b).unwrap();
        assert_eq!(
            book.reserve_watch(ResourceHandle::random().unwrap(), &identity("C")),
            Err(QuotaError::GlobalWatches)
        );
        book.release_watch(connection_a, &a);
        book.release_process(connection_a, &a);
        assert_eq!(book.totals(), (2, 2));
        book.release_sandbox(connection_a, &a);
        book.release_connection(&a);
        assert_eq!(book.totals(), (1, 1));
    }
}
