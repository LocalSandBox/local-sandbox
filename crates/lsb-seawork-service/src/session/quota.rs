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
}

impl Default for QuotaLimits {
    fn default() -> Self {
        Self {
            connections_global: 32,
            connections_per_user: 4,
            sandboxes_global: 8,
            sandboxes_per_user: 4,
            sandboxes_per_connection: 2,
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
}

impl fmt::Display for QuotaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::GlobalConnections => "global connection quota exceeded",
            Self::UserConnections => "per-user connection quota exceeded",
            Self::GlobalSandboxes => "global sandbox quota exceeded",
            Self::UserSandboxes => "per-user sandbox quota exceeded",
            Self::ConnectionSandboxes => "per-connection sandbox quota exceeded",
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
        assert_eq!(book.totals(), (2, 2));
        book.release_sandbox(connection_a, &a);
        book.release_connection(&a);
        assert_eq!(book.totals(), (1, 1));
    }
}
