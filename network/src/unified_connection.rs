//! Unified connection pool structure
//!
//! This module consolidates the previously separate `peers`, `connections`, and `last_seen` maps
//! into a single unified structure, eliminating cascading lock contention and duplicate data storage.

use crate::connection::PeerConnection;
use crate::peer_info::PeerInfo;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

/// Unified peer connection that combines connection state, peer info, and health tracking
pub struct UnifiedPeerConnection {
    /// The actual TCP connection (wrapped for concurrent access)
    pub connection: Arc<Mutex<PeerConnection>>,

    /// Peer information (version, address, etc.)
    pub info: PeerInfo,

    /// Last time we received any message from this peer (for reaper)
    pub last_seen: Instant,

    /// Health score for peer quality tracking (0-100)
    pub health_score: u8,

    /// Connection established timestamp
    pub connected_at: Instant,
}

impl UnifiedPeerConnection {
    /// Create a new unified connection
    pub fn new(connection: PeerConnection, info: PeerInfo) -> Self {
        let now = Instant::now();
        Self {
            connection: Arc::new(Mutex::new(connection)),
            info,
            last_seen: now,
            health_score: 100,
            connected_at: now,
        }
    }

    /// Create from an existing Arc-wrapped connection
    pub fn from_arc(connection: Arc<Mutex<PeerConnection>>, info: PeerInfo) -> Self {
        let now = Instant::now();
        Self {
            connection,
            info,
            last_seen: now,
            health_score: 100,
            connected_at: now,
        }
    }

    /// Mark that we received a message from this peer
    #[inline]
    pub fn mark_seen(&mut self) {
        self.last_seen = Instant::now();
    }

    /// Check if this connection is stale (no activity for given duration)
    #[inline]
    pub fn is_stale(&self, stale_after: std::time::Duration) -> bool {
        self.last_seen.elapsed() > stale_after
    }

    /// Decrease health score (call on failures)
    pub fn penalize_health(&mut self, amount: u8) {
        self.health_score = self.health_score.saturating_sub(amount);
    }

    /// Increase health score (call on successes)
    pub fn reward_health(&mut self, amount: u8) {
        self.health_score = self.health_score.saturating_add(amount).min(100);
    }

    /// Check if connection is healthy enough to use
    #[inline]
    pub fn is_healthy(&self) -> bool {
        self.health_score > 30
    }

    /// Get connection uptime
    #[inline]
    pub fn uptime(&self) -> std::time::Duration {
        self.connected_at.elapsed()
    }
}

/// Statistics about the connection pool
#[derive(Debug, Clone, Default)]
pub struct PoolStats {
    pub total_connections: usize,
    pub healthy_connections: usize,
    pub stale_connections: usize,
    pub avg_health_score: u8,
    pub oldest_connection_secs: u64,
}

#[cfg(test)]
mod tests {

    // TODO: Re-enable these tests after implementing mock methods for PeerConnection and PeerInfo
    /*
    #[test]
    fn test_health_scoring() {
        let conn = PeerConnection::mock();
        let info = PeerInfo::mock();
        let mut unified = UnifiedPeerConnection::new(conn, info);

        assert_eq!(unified.health_score, 100);
        assert!(unified.is_healthy());

        // Penalize
        unified.penalize_health(20);
        assert_eq!(unified.health_score, 80);
        assert!(unified.is_healthy());

        // Heavy penalty
        unified.penalize_health(60);
        assert_eq!(unified.health_score, 20);
        assert!(!unified.is_healthy());

        // Reward
        unified.reward_health(50);
        assert_eq!(unified.health_score, 70);
        assert!(unified.is_healthy());

        // Can't exceed 100
        unified.reward_health(50);
        assert_eq!(unified.health_score, 100);
    }

    #[test]
    fn test_staleness_check() {
        let conn = PeerConnection::mock();
        let info = PeerInfo::mock();
        let unified = UnifiedPeerConnection::new(conn, info);

        // Not stale immediately
        assert!(!unified.is_stale(std::time::Duration::from_secs(300)));

        // Mock older connection (you'd need to expose last_seen for testing)
        // For now, this is a placeholder test structure
    }
    */
}
