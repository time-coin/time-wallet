//! Synchronization gate to prevent fork creation
//!
//! This module provides a gating mechanism to ensure nodes don't create blocks
//! when they're significantly behind the network, preventing fork creation.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Gate system that prevents block creation when node is behind network
///
/// # Purpose
/// Prevents forks by ensuring nodes wait to sync before creating blocks
///
/// # Lock Hierarchy
/// This module uses its own locks and doesn't interact with PeerManager locks
pub struct SyncGate {
    /// Current local blockchain height
    local_height: Arc<RwLock<u64>>,

    /// Highest height observed from any peer
    network_height: Arc<RwLock<u64>>,

    /// Whether sync is currently in progress
    sync_in_progress: Arc<RwLock<bool>>,

    /// Maximum blocks we can be behind before blocking
    max_blocks_behind: u64,
}

impl SyncGate {
    /// Create a new sync gate with initial local height
    pub fn new(initial_height: u64) -> Self {
        Self {
            local_height: Arc::new(RwLock::new(initial_height)),
            network_height: Arc::new(RwLock::new(initial_height)),
            sync_in_progress: Arc::new(RwLock::new(false)),
            max_blocks_behind: 5, // Conservative: don't create if 5+ blocks behind
        }
    }

    /// Block until we're within acceptable range of network height
    ///
    /// Returns error if sync appears stalled
    pub async fn wait_for_sync(&self) -> Result<(), String> {
        const MAX_WAIT: Duration = Duration::from_secs(30);
        const CHECK_INTERVAL: Duration = Duration::from_millis(500);

        let start = tokio::time::Instant::now();

        loop {
            let local = *self.local_height.read().await;
            let network = *self.network_height.read().await;

            // Within 1 block is acceptable (might be creating next block)
            if local >= network.saturating_sub(1) {
                return Ok(());
            }

            // Check if we've been waiting too long
            if start.elapsed() > MAX_WAIT {
                return Err(format!(
                    "Sync timeout: local={}, network={}, waited {}s",
                    local,
                    network,
                    MAX_WAIT.as_secs()
                ));
            }

            // If sync is running, keep waiting
            if *self.sync_in_progress.read().await {
                tokio::time::sleep(CHECK_INTERVAL).await;
            } else {
                // Sync not running and we're behind - stalled
                return Err(format!(
                    "Sync stalled: local={}, network={}, sync not in progress",
                    local, network
                ));
            }
        }
    }

    /// Check if we can create a block at the given height
    ///
    /// This is the main gate that consensus MUST call before block creation
    pub async fn can_create_block(&self, desired_height: u64) -> Result<(), String> {
        let local = *self.local_height.read().await;
        let network = *self.network_height.read().await;

        // Rule 1: Can't create above local height + 1
        if desired_height > local + 1 {
            return Err(format!(
                "Cannot create block {}: local height is {} (can only create {})",
                desired_height,
                local,
                local + 1
            ));
        }

        // Rule 2: Can't create below local height (already exists)
        if desired_height <= local {
            return Err(format!(
                "Cannot create block {}: already at local height {}",
                desired_height, local
            ));
        }

        // Rule 3: If network is far ahead, we must sync first
        if network > local + self.max_blocks_behind {
            return Err(format!(
                "Cannot create block {}: too far behind network (local={}, network={}, max_behind={})",
                desired_height, local, network, self.max_blocks_behind
            ));
        }

        // All checks passed
        Ok(())
    }

    /// Update the known network height from a peer
    ///
    /// Always takes the maximum observed height
    pub async fn update_network_height(&self, height: u64) {
        let mut net_height = self.network_height.write().await;
        let old_height = *net_height;

        if height > old_height {
            *net_height = height;

            let local = *self.local_height.read().await;
            if height > local + 10 {
                warn!(
                    "Network significantly ahead: local={}, network={} (delta={})",
                    local,
                    height,
                    height - local
                );
            } else if height > local + 1 {
                info!(
                    "Network ahead: local={}, network={} (delta={})",
                    local,
                    height,
                    height - local
                );
            }
        }
    }

    /// Update our local blockchain height
    ///
    /// Call this after successfully adding a block to the chain
    pub async fn update_local_height(&self, height: u64) {
        let mut local = self.local_height.write().await;

        if height > *local {
            *local = height;

            let network = *self.network_height.read().await;
            if height >= network {
                info!("Local height {} caught up with network", height);
            }
        }
    }

    /// Get current local height
    pub async fn local_height(&self) -> u64 {
        *self.local_height.read().await
    }

    /// Get current network height
    pub async fn network_height(&self) -> u64 {
        *self.network_height.read().await
    }

    /// Check if we're significantly behind the network
    pub async fn is_behind(&self) -> bool {
        let local = *self.local_height.read().await;
        let network = *self.network_height.read().await;
        network > local + 1
    }

    /// Get the number of blocks we're behind
    pub async fn blocks_behind(&self) -> u64 {
        let local = *self.local_height.read().await;
        let network = *self.network_height.read().await;
        network.saturating_sub(local)
    }

    /// Mark sync as in progress
    pub async fn start_sync(&self) {
        *self.sync_in_progress.write().await = true;
    }

    /// Mark sync as complete
    pub async fn complete_sync(&self) {
        *self.sync_in_progress.write().await = false;
    }

    /// Check if sync is currently running
    pub async fn is_syncing(&self) -> bool {
        *self.sync_in_progress.read().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_can_create_next_block() {
        let gate = SyncGate::new(100);

        // Can create next block (100 + 1)
        assert!(gate.can_create_block(101).await.is_ok());
    }

    #[tokio::test]
    async fn test_cannot_create_past_block() {
        let gate = SyncGate::new(100);

        // Can't create already existing block
        assert!(gate.can_create_block(100).await.is_err());
        assert!(gate.can_create_block(99).await.is_err());
    }

    #[tokio::test]
    async fn test_cannot_create_skip_block() {
        let gate = SyncGate::new(100);

        // Can't skip ahead (100 -> 102)
        assert!(gate.can_create_block(102).await.is_err());
    }

    #[tokio::test]
    async fn test_blocked_when_far_behind() {
        let gate = SyncGate::new(100);

        // Update network to far ahead
        gate.update_network_height(110).await;

        // Should be blocked (10 blocks behind, max is 5)
        assert!(gate.can_create_block(101).await.is_err());
    }

    #[tokio::test]
    async fn test_allowed_when_close() {
        let gate = SyncGate::new(100);

        // Update network to slightly ahead
        gate.update_network_height(102).await;

        // Should be allowed (2 blocks behind, within max of 5)
        assert!(gate.can_create_block(101).await.is_ok());
    }

    #[tokio::test]
    async fn test_blocks_behind() {
        let gate = SyncGate::new(100);
        gate.update_network_height(110).await;

        assert_eq!(gate.blocks_behind().await, 10);
    }

    #[tokio::test]
    async fn test_update_local_height() {
        let gate = SyncGate::new(100);
        gate.update_network_height(105).await;

        assert!(gate.is_behind().await);

        gate.update_local_height(104).await;
        assert_eq!(gate.local_height().await, 104);
        assert_eq!(gate.blocks_behind().await, 1);
    }

    #[tokio::test]
    async fn test_sync_state_tracking() {
        let gate = SyncGate::new(100);

        assert!(!gate.is_syncing().await);

        gate.start_sync().await;
        assert!(gate.is_syncing().await);

        gate.complete_sync().await;
        assert!(!gate.is_syncing().await);
    }
}
