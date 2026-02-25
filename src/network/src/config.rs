/// Network configuration with named constants
/// CRITICAL FIX (Issue #14): Extract magic numbers to config struct
use std::time::Duration;

/// Configuration for network manager behavior
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// How long before a peer is considered stale (default: 300 seconds / 5 minutes)
    pub stale_peer_timeout: Duration,

    /// How often to check for stale peers (default: 30 seconds)
    pub reaper_interval: Duration,

    /// Timeout for outgoing connections (default: 5 seconds)
    pub connection_timeout: Duration,

    /// Minimum number of peer connections to maintain (default: 5)
    pub min_connections: usize,

    /// Target number of peer connections (default: 8)
    pub target_connections: usize,

    /// Maximum concurrent connection attempts (default: 10)
    pub max_concurrent_connections: usize,

    /// How long to wait for peer discovery/connection batch (default: 10 seconds)
    pub batch_timeout: Duration,

    /// TCP keepalive: time before first probe (default: 60 seconds)
    pub tcp_keepalive_time: Duration,

    /// TCP keepalive: interval between probes (default: 30 seconds)
    pub tcp_keepalive_interval: Duration,

    /// How often to clean up broadcast tracking (default: 60 seconds)
    pub broadcast_cleanup_interval: Duration,

    /// How long to remember broadcast entries (default: 300 seconds / 5 minutes)
    pub broadcast_memory_duration: Duration,

    /// Maximum broadcasts per minute (default: 60)
    pub max_broadcasts_per_minute: u32,

    /// How often to clean up peer exchange (default: 3600 seconds / 1 hour)
    pub peer_exchange_cleanup_interval: Duration,

    /// Max age for peer exchange entries (default: 604800 seconds / 7 days)
    pub peer_exchange_max_age: Duration,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            stale_peer_timeout: Duration::from_secs(300), // 5 minutes
            reaper_interval: Duration::from_secs(30),     // 30 seconds
            connection_timeout: Duration::from_secs(5),   // 5 seconds
            min_connections: 5,
            target_connections: 8,
            max_concurrent_connections: 10,
            batch_timeout: Duration::from_secs(10), // 10 seconds
            tcp_keepalive_time: Duration::from_secs(60), // 60 seconds
            tcp_keepalive_interval: Duration::from_secs(30), // 30 seconds
            broadcast_cleanup_interval: Duration::from_secs(60), // 1 minute
            broadcast_memory_duration: Duration::from_secs(300), // 5 minutes
            max_broadcasts_per_minute: 60,
            peer_exchange_cleanup_interval: Duration::from_secs(3600), // 1 hour
            peer_exchange_max_age: Duration::from_secs(604800),        // 7 days
        }
    }
}

impl NetworkConfig {
    /// Create a new configuration with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a configuration suitable for testing (faster timeouts, shorter intervals)
    pub fn for_testing() -> Self {
        Self {
            stale_peer_timeout: Duration::from_secs(10),
            reaper_interval: Duration::from_secs(2),
            connection_timeout: Duration::from_secs(1),
            min_connections: 2,
            target_connections: 3,
            max_concurrent_connections: 5,
            batch_timeout: Duration::from_secs(2),
            tcp_keepalive_time: Duration::from_secs(5),
            tcp_keepalive_interval: Duration::from_secs(2),
            broadcast_cleanup_interval: Duration::from_secs(5),
            broadcast_memory_duration: Duration::from_secs(10),
            max_broadcasts_per_minute: 30,
            peer_exchange_cleanup_interval: Duration::from_secs(10),
            peer_exchange_max_age: Duration::from_secs(60),
        }
    }

    /// Create a configuration for high-traffic nodes (more aggressive cleanup)
    pub fn for_high_traffic() -> Self {
        Self {
            stale_peer_timeout: Duration::from_secs(180), // 3 minutes (more aggressive)
            reaper_interval: Duration::from_secs(15),     // 15 seconds (more frequent)
            connection_timeout: Duration::from_secs(3),   // 3 seconds (faster timeout)
            min_connections: 10,
            target_connections: 20,
            max_concurrent_connections: 20,
            batch_timeout: Duration::from_secs(5),
            tcp_keepalive_time: Duration::from_secs(30), // More aggressive
            tcp_keepalive_interval: Duration::from_secs(15),
            broadcast_cleanup_interval: Duration::from_secs(30), // More frequent
            broadcast_memory_duration: Duration::from_secs(180), // Shorter memory
            max_broadcasts_per_minute: 120,                      // Higher limit
            peer_exchange_cleanup_interval: Duration::from_secs(1800), // Every 30 minutes
            peer_exchange_max_age: Duration::from_secs(259200),  // 3 days
        }
    }

    /// Create config optimized for initial sync (Phase 1 optimization)
    pub fn for_fast_sync() -> Self {
        Self {
            stale_peer_timeout: Duration::from_secs(30), // More aggressive
            reaper_interval: Duration::from_secs(5),     // More frequent checks
            connection_timeout: Duration::from_secs(2),  // Fail fast
            min_connections: 8,
            target_connections: 20, // More peers for faster sync
            max_concurrent_connections: 25,
            batch_timeout: Duration::from_secs(5),
            tcp_keepalive_time: Duration::from_secs(30),
            tcp_keepalive_interval: Duration::from_secs(15),
            broadcast_cleanup_interval: Duration::from_secs(30),
            broadcast_memory_duration: Duration::from_secs(180),
            max_broadcasts_per_minute: 120,
            peer_exchange_cleanup_interval: Duration::from_secs(1800),
            peer_exchange_max_age: Duration::from_secs(259200),
        }
    }
}

/// Configuration for snapshot sync optimization (Phase 1)
#[derive(Debug, Clone)]
pub struct SnapshotSyncConfig {
    /// Enable state snapshot sync
    pub enabled: bool,

    /// How many recent blocks to sync after snapshot
    pub recent_blocks: u64,

    /// Timeout for snapshot download
    pub snapshot_timeout: Duration,

    /// Minimum gap to use snapshot sync (blocks)
    pub min_gap_for_snapshot: u64,

    /// Enable compression for snapshots
    pub compression_enabled: bool,

    /// Compression threshold in bytes
    pub compression_threshold: usize,
}

impl Default for SnapshotSyncConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            recent_blocks: 10,
            snapshot_timeout: Duration::from_secs(300), // 5 minutes
            min_gap_for_snapshot: 1000,
            compression_enabled: true,
            compression_threshold: 1024, // Only compress >1KB
        }
    }
}

impl SnapshotSyncConfig {
    pub fn new() -> Self {
        Self::default()
    }

    /// Disable snapshot sync (use traditional block sync)
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = NetworkConfig::default();
        assert_eq!(config.stale_peer_timeout, Duration::from_secs(300));
        assert_eq!(config.min_connections, 5);
        assert_eq!(config.target_connections, 8);
    }

    #[test]
    fn test_testing_config() {
        let config = NetworkConfig::for_testing();
        assert!(config.stale_peer_timeout < Duration::from_secs(30));
        assert!(config.reaper_interval < Duration::from_secs(5));
    }

    #[test]
    fn test_high_traffic_config() {
        let config = NetworkConfig::for_high_traffic();
        assert_eq!(config.min_connections, 10);
        assert_eq!(config.target_connections, 20);
        assert!(config.stale_peer_timeout < Duration::from_secs(300));
    }
}
