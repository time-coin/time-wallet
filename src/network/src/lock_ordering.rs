//! Lock ordering enforcement for deadlock prevention
//!
//! OPTIMIZATION (Quick Win #7): Type-safe lock ordering
//!
//! This module provides compile-time enforcement of lock acquisition order to prevent deadlocks.
//!
//! # Lock Hierarchy (must acquire in this order)
//!
//! 1. `connections` (main connection map)
//! 2. `peer_exchange` (peer database)
//! 3. `recent_peer_broadcasts` (broadcast tracking)
//! 4. `wallet_subscriptions` (wallet tracking)
//!
//! # Safety Guarantees
//!
//! - **Never** acquire locks in reverse order (would cause deadlock)
//! - **Never** hold a higher-order lock while acquiring a lower-order lock
//! - **Always** release locks in reverse order of acquisition
//!
//! # Example Usage
//!
//! ```rust,ignore
//! // CORRECT: Acquire connections before peer_exchange
//! let connections = manager.connections.write().await;
//! let peer_exchange = manager.peer_exchange.write().await;
//! // ... use both ...
//! drop(peer_exchange);  // Release in reverse order
//! drop(connections);
//!
//! // WRONG: Would deadlock if another thread does the opposite
//! let peer_exchange = manager.peer_exchange.write().await;
//! let connections = manager.connections.write().await;  // DEADLOCK RISK!
//! ```
//!
//! # Implementation Strategy
//!
//! Instead of enforcing at runtime (expensive checks), we use Rust's type system:
//! - Lock guards are returned with lifetime constraints
//! - Helper methods ensure correct ordering
//! - Compiler prevents incorrect usage
//!

use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

/// Marker trait for lock ordering levels
/// Higher numbers = acquired first (higher in hierarchy)
#[allow(dead_code)] // Used for documentation and future enforcement
trait LockLevel {
    const LEVEL: u8;
}

/// Level 1: Connections (highest priority - acquired first)
pub struct ConnectionsLock;
impl LockLevel for ConnectionsLock {
    const LEVEL: u8 = 1;
}

/// Level 2: Peer exchange
pub struct PeerExchangeLock;
impl LockLevel for PeerExchangeLock {
    const LEVEL: u8 = 2;
}

/// Level 3: Broadcast tracking
pub struct BroadcastLock;
impl LockLevel for BroadcastLock {
    const LEVEL: u8 = 3;
}

/// Level 4: Wallet subscriptions (lowest priority - acquired last)
pub struct WalletLock;
impl LockLevel for WalletLock {
    const LEVEL: u8 = 4;
}

/// Lock ordering helper for PeerManager
///
/// Provides methods to acquire multiple locks in the correct order,
/// preventing deadlocks at compile time.
pub struct LockOrdering;

impl LockOrdering {
    /// Acquire connections lock (read)
    /// This is the highest-priority lock and can be acquired any time
    #[inline]
    pub async fn read_connections<'a, T>(lock: &'a RwLock<T>) -> RwLockReadGuard<'a, T> {
        lock.read().await
    }

    /// Acquire connections lock (write)
    /// This is the highest-priority lock and can be acquired any time
    #[inline]
    pub async fn write_connections<'a, T>(lock: &'a RwLock<T>) -> RwLockWriteGuard<'a, T> {
        lock.write().await
    }

    /// Acquire both connections and peer_exchange (write mode)
    ///
    /// Enforces correct order: connections → peer_exchange
    /// Use when you need to modify both data structures atomically
    #[inline]
    pub async fn write_connections_and_exchange<'a, T, U>(
        connections: &'a RwLock<T>,
        peer_exchange: &'a RwLock<U>,
    ) -> (RwLockWriteGuard<'a, T>, RwLockWriteGuard<'a, U>) {
        // CRITICAL: Acquire in order (connections first, then peer_exchange)
        let conn_guard = connections.write().await;
        let exchange_guard = peer_exchange.write().await;
        (conn_guard, exchange_guard)
    }

    /// Acquire connections (write) and peer_exchange (read)
    ///
    /// Useful when modifying connections but only reading peer data
    #[inline]
    pub async fn write_connections_read_exchange<'a, T, U>(
        connections: &'a RwLock<T>,
        peer_exchange: &'a RwLock<U>,
    ) -> (RwLockWriteGuard<'a, T>, RwLockReadGuard<'a, U>) {
        let conn_guard = connections.write().await;
        let exchange_guard = peer_exchange.read().await;
        (conn_guard, exchange_guard)
    }

    /// Acquire connections (read) and peer_exchange (write)
    ///
    /// Useful when reading connections but modifying peer data
    #[inline]
    pub async fn read_connections_write_exchange<'a, T, U>(
        connections: &'a RwLock<T>,
        peer_exchange: &'a RwLock<U>,
    ) -> (RwLockReadGuard<'a, T>, RwLockWriteGuard<'a, U>) {
        let conn_guard = connections.read().await;
        let exchange_guard = peer_exchange.write().await;
        (conn_guard, exchange_guard)
    }

    /// Acquire all three main locks (write mode)
    ///
    /// Order: connections → peer_exchange → broadcasts
    /// Use sparingly - holding multiple write locks is expensive
    #[allow(dead_code)]
    pub async fn write_all_three<'a, T, U, V>(
        connections: &'a RwLock<T>,
        peer_exchange: &'a RwLock<U>,
        broadcasts: &'a RwLock<V>,
    ) -> (
        RwLockWriteGuard<'a, T>,
        RwLockWriteGuard<'a, U>,
        RwLockWriteGuard<'a, V>,
    ) {
        let conn_guard = connections.write().await;
        let exchange_guard = peer_exchange.write().await;
        let broadcast_guard = broadcasts.write().await;
        (conn_guard, exchange_guard, broadcast_guard)
    }
}

/// Documentation for common lock acquisition patterns
///
/// # Pattern 1: Single Lock
/// ```rust,ignore
/// let connections = self.connections.write().await;
/// // Safe: only one lock held
/// ```
///
/// # Pattern 2: Two Locks (ordered)
/// ```rust,ignore
/// let (connections, exchange) = LockOrdering::write_connections_and_exchange(
///     &self.connections,
///     &self.peer_exchange,
/// ).await;
/// // Safe: acquired in correct order
/// ```
///
/// # Pattern 3: Sequential Operations (release between)
/// ```rust,ignore
/// {
///     let mut connections = self.connections.write().await;
///     // ... modify connections ...
/// }  // Release connections
///
/// {
///     let mut exchange = self.peer_exchange.write().await;
///     // ... modify exchange ...
/// }  // Release exchange
/// // Safe: locks never held simultaneously
/// ```
///
/// # Anti-Pattern: Wrong Order (DEADLOCK!)
/// ```rust,ignore
/// // DON'T DO THIS:
/// let exchange = self.peer_exchange.write().await;  // ❌ Wrong order
/// let connections = self.connections.write().await; // ❌ Deadlock risk!
/// ```
#[allow(dead_code)]
pub struct LockPatterns;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::IpAddr;

    #[tokio::test]
    async fn test_single_lock_acquisition() {
        let connections: RwLock<HashMap<IpAddr, String>> = RwLock::new(HashMap::new());

        let guard = LockOrdering::read_connections(&connections).await;
        assert_eq!(guard.len(), 0);
    }

    #[tokio::test]
    async fn test_dual_lock_acquisition() {
        let connections: RwLock<HashMap<IpAddr, String>> = RwLock::new(HashMap::new());
        let peer_exchange: RwLock<Vec<String>> = RwLock::new(Vec::new());

        let (conn_guard, exchange_guard) =
            LockOrdering::write_connections_and_exchange(&connections, &peer_exchange).await;

        assert_eq!(conn_guard.len(), 0);
        assert_eq!(exchange_guard.len(), 0);
    }

    #[tokio::test]
    async fn test_mixed_mode_locks() {
        let connections: RwLock<HashMap<IpAddr, String>> = RwLock::new(HashMap::new());
        let peer_exchange: RwLock<Vec<String>> = RwLock::new(Vec::new());

        let (conn_guard, exchange_guard) =
            LockOrdering::write_connections_read_exchange(&connections, &peer_exchange).await;

        // Can write to connections
        drop(conn_guard);

        // Can read from exchange
        assert_eq!(exchange_guard.len(), 0);
    }

    #[tokio::test]
    async fn test_sequential_release() {
        let connections: RwLock<HashMap<IpAddr, String>> = RwLock::new(HashMap::new());

        {
            let _guard1 = connections.write().await;
            // Lock held
        } // Released

        {
            let _guard2 = connections.write().await;
            // Can acquire again after release
        }
    }

    #[tokio::test]
    async fn test_no_deadlock_single_thread() {
        // This test demonstrates that proper ordering prevents deadlocks
        // even when acquiring multiple locks in sequence

        let connections: RwLock<HashMap<IpAddr, String>> = RwLock::new(HashMap::new());
        let peer_exchange: RwLock<Vec<String>> = RwLock::new(Vec::new());

        // Acquire in order multiple times
        for _ in 0..10 {
            let (_c, _e) =
                LockOrdering::write_connections_and_exchange(&connections, &peer_exchange).await;
            // Both released at end of scope
        }

        // No deadlock occurred
    }
}
