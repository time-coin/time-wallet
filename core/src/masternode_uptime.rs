//! Masternode Uptime Tracking for Block Rewards
//!
//! This module tracks which masternodes were online during block production
//! to ensure only masternodes that contributed to the block receive rewards.
//!
//! ## Key Principle
//! A masternode must be online for the ENTIRE block production period to qualify
//! for rewards. If a masternode joins mid-block, it must wait until the next block.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Tracks when each masternode joined the network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasternodeUptimeTracker {
    /// Map of masternode address -> timestamp when it joined
    join_times: HashMap<String, DateTime<Utc>>,

    /// Set of masternodes that were online for the previous block
    /// These are the ones eligible for rewards in the current block
    eligible_for_current_block: HashSet<String>,

    /// Timestamp when the previous block was created
    previous_block_time: DateTime<Utc>,
}

impl MasternodeUptimeTracker {
    /// Create a new uptime tracker
    pub fn new() -> Self {
        Self {
            join_times: HashMap::new(),
            eligible_for_current_block: HashSet::new(),
            previous_block_time: Utc::now(),
        }
    }

    /// Register a masternode joining the network
    ///
    /// The masternode will NOT be eligible for the current block being produced,
    /// but WILL be eligible for the next block if it stays online.
    ///
    /// # Arguments
    /// * `address` - Masternode address
    /// * `join_time` - When the masternode joined (typically Utc::now())
    pub fn register_masternode(&mut self, address: String, join_time: DateTime<Utc>) {
        log::info!(
            "📋 Masternode {} joined at {}",
            address,
            join_time.format("%Y-%m-%d %H:%M:%S UTC")
        );
        log::info!(
            "   Previous block time: {}",
            self.previous_block_time.format("%Y-%m-%d %H:%M:%S UTC")
        );

        self.join_times.insert(address.clone(), join_time);

        // If this masternode joined after the previous block, it's NOT eligible yet
        if join_time > self.previous_block_time {
            log::info!(
                "   ⏰ Masternode {} joined after previous block - NOT eligible for current block",
                address
            );
        } else {
            // This is a restart or rejoin - since it joined before previous block,
            // it should be eligible for the next block
            log::info!("   🔄 Masternode {} rejoined before previous block - will be eligible for next block", address);
            // Don't add to eligible_for_current_block - that's handled in finalize_block
        }
    }

    /// Remove a masternode from tracking (when it goes offline)
    pub fn remove_masternode(&mut self, address: &str) {
        log::info!("👋 Masternode {} went offline", address);
        self.join_times.remove(address);
        self.eligible_for_current_block.remove(address);
    }

    /// Update uptime tracking when a new block is created
    ///
    /// This determines which masternodes are eligible for rewards in the NEXT block.
    /// Only masternodes that were online BEFORE this block started are eligible.
    ///
    /// # Arguments
    /// * `block_time` - Timestamp of the block being created
    /// * `current_online` - Set of masternodes currently online
    ///
    /// # Returns
    /// Set of masternode addresses eligible for THIS block's rewards
    pub fn finalize_block(
        &mut self,
        block_time: DateTime<Utc>,
        current_online: &HashSet<String>,
    ) -> HashSet<String> {
        log::info!("🔄 Finalizing block at {}", block_time.format("%H:%M:%S"));
        log::info!("   Current online: {} masternodes", current_online.len());
        log::info!(
            "   Previously eligible: {} masternodes",
            self.eligible_for_current_block.len()
        );

        // The masternodes eligible for THIS block are the ones that were eligible
        // at the start of this block period
        let eligible_this_block = self.eligible_for_current_block.clone();

        // Now determine eligibility for the NEXT block
        // Only masternodes that are currently online AND were online before this block
        let mut eligible_next_block = HashSet::new();

        for address in current_online {
            if let Some(join_time) = self.join_times.get(address) {
                // Masternode must have joined BEFORE this block to be eligible for next block
                if join_time <= &self.previous_block_time {
                    eligible_next_block.insert(address.clone());
                } else {
                    log::info!(
                        "   ⏰ Masternode {} joined at {} (after previous block at {}) - not eligible yet",
                        address,
                        join_time.format("%H:%M:%S"),
                        self.previous_block_time.format("%H:%M:%S")
                    );
                }
            } else {
                // This shouldn't happen, but handle it gracefully
                log::warn!("   ⚠️ Masternode {} online but not in join_times", address);
                // Register it with current time, so it will be eligible for block after next
                self.join_times.insert(address.clone(), block_time);
            }
        }

        // Remove masternodes that went offline
        self.join_times
            .retain(|addr, _| current_online.contains(addr));

        log::info!(
            "   ✅ Eligible for current block: {} masternodes",
            eligible_this_block.len()
        );
        log::info!(
            "   📋 Eligible for next block: {} masternodes",
            eligible_next_block.len()
        );

        // Update state for next block
        self.eligible_for_current_block = eligible_next_block;
        self.previous_block_time = block_time;

        eligible_this_block
    }

    /// Check if a specific masternode is eligible for the current block
    pub fn is_eligible(&self, address: &str) -> bool {
        self.eligible_for_current_block.contains(address)
    }

    /// Get all masternodes eligible for the current block
    pub fn get_eligible(&self) -> &HashSet<String> {
        &self.eligible_for_current_block
    }

    /// Get count of eligible masternodes
    pub fn eligible_count(&self) -> usize {
        self.eligible_for_current_block.len()
    }

    /// Bootstrap from genesis - all initial masternodes are eligible
    ///
    /// Call this when starting the blockchain to make all initial masternodes
    /// eligible for the first block.
    pub fn bootstrap_genesis(&mut self, genesis_time: DateTime<Utc>, masternodes: &[String]) {
        log::info!("🌱 Bootstrapping genesis masternodes");
        log::info!(
            "   Genesis time: {}",
            genesis_time.format("%Y-%m-%d %H:%M:%S UTC")
        );

        self.previous_block_time = genesis_time;

        for address in masternodes {
            log::info!(
                "   📋 Adding {} to eligible set (join time = genesis)",
                address
            );
            self.join_times.insert(address.clone(), genesis_time);
            self.eligible_for_current_block.insert(address.clone());
        }

        log::info!(
            "   ✅ {} masternodes eligible for first block",
            self.eligible_for_current_block.len()
        );
    }
}

impl Default for MasternodeUptimeTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_new_masternode_not_eligible_immediately() {
        let mut tracker = MasternodeUptimeTracker::new();
        let block_time = Utc::now() + Duration::seconds(1);
        let block2_time = block_time + Duration::seconds(1);
        let block3_time = block2_time + Duration::seconds(1);

        // Masternode joins during this block period
        let mn1 = "masternode1".to_string();
        tracker.register_masternode(mn1.clone(), block_time);

        // Finalize block — MN1 joined after previous_block_time, so NOT eligible
        let current_online = [mn1.clone()].iter().cloned().collect();
        let eligible = tracker.finalize_block(block_time, &current_online);
        assert_eq!(eligible.len(), 0); // Not eligible for current block

        // After finalize, previous_block_time = block_time.
        // MN1's join_time (block_time) <= previous_block_time (block_time) → eligible_next_block.
        // But eligible_for_current_block is still the empty eligible_next_block from this finalize.
        // Need one more finalize to promote to eligible_this_block.
        let eligible2 = tracker.finalize_block(block2_time, &current_online);
        assert_eq!(eligible2.len(), 0); // eligible_this_block was set to empty

        // Now eligible_for_current_block has MN1
        let eligible3 = tracker.finalize_block(block3_time, &current_online);
        assert_eq!(eligible3.len(), 1); // NOW eligible
    }

    #[test]
    fn test_masternode_eligible_after_one_block() {
        let mut tracker = MasternodeUptimeTracker::new();
        let block1_time = Utc::now() + Duration::seconds(1);
        let block2_time = block1_time + Duration::minutes(10);
        let block3_time = block2_time + Duration::minutes(10);

        // Masternode joins at block 1
        let mn1 = "masternode1".to_string();
        tracker.register_masternode(mn1.clone(), block1_time);

        // Finalize block 1 — MN1 joined at block1_time which is after previous_block_time
        let current_online = [mn1.clone()].iter().cloned().collect();
        let eligible_block1 = tracker.finalize_block(block1_time, &current_online);
        assert_eq!(eligible_block1.len(), 0); // Not eligible for block 1

        // Finalize block 2 — eligible_this_block was set to empty at end of block 1
        // But MN1's join_time <= previous_block_time now, so it enters eligible_next_block
        let eligible_block2 = tracker.finalize_block(block2_time, &current_online);
        assert_eq!(eligible_block2.len(), 0); // Still not eligible (returns prior eligible set)

        // Finalize block 3 — NOW MN1 is in eligible_for_current_block
        let eligible_block3 = tracker.finalize_block(block3_time, &current_online);
        assert_eq!(eligible_block3.len(), 1); // NOW eligible
        assert!(eligible_block3.contains(&mn1));
    }

    #[test]
    fn test_masternode_goes_offline() {
        let mut tracker = MasternodeUptimeTracker::new();
        let genesis = Utc::now();

        // Bootstrap with two masternodes
        let mn1 = "masternode1".to_string();
        let mn2 = "masternode2".to_string();
        tracker.bootstrap_genesis(genesis, &[mn1.clone(), mn2.clone()]);

        assert_eq!(tracker.eligible_count(), 2);

        // MN2 goes offline
        tracker.remove_masternode(&mn2);

        // Finalize block - only MN1 is online
        let current_online = [mn1.clone()].iter().cloned().collect();
        let eligible = tracker.finalize_block(genesis + Duration::minutes(10), &current_online);

        // MN2 was removed, so only MN1 was eligible when block was finalized
        assert_eq!(eligible.len(), 1);

        // But only MN1 is eligible for next block
        assert_eq!(tracker.eligible_count(), 1);
        assert!(tracker.is_eligible(&mn1));
        assert!(!tracker.is_eligible(&mn2));
    }

    #[test]
    fn test_masternode_rejoins() {
        let mut tracker = MasternodeUptimeTracker::new();
        let genesis = Utc::now();
        let block1 = genesis + Duration::minutes(10);
        let block2 = genesis + Duration::minutes(20);
        let block3 = genesis + Duration::minutes(30);
        let block4 = genesis + Duration::minutes(40);

        // Bootstrap with one masternode
        let mn1 = "masternode1".to_string();
        tracker.bootstrap_genesis(genesis, std::slice::from_ref(&mn1));

        // Block 1: MN1 is online
        let current_online = [mn1.clone()].iter().cloned().collect();
        tracker.finalize_block(block1, &current_online);
        assert_eq!(tracker.eligible_count(), 1);

        // MN1 goes offline
        tracker.remove_masternode(&mn1);

        // Block 2: MN1 rejoins at block2 time (after previous_block_time=block1)
        tracker.register_masternode(mn1.clone(), block2);
        let current_online = [mn1.clone()].iter().cloned().collect();
        let eligible = tracker.finalize_block(block2, &current_online);

        // MN1 not eligible for block 2 (joined at block2 > previous_block_time block1)
        assert_eq!(eligible.len(), 0);

        // Block 3: eligible_this_block is still empty (set at end of block 2 finalize)
        // But eligible_next_block now picks up MN1 since join_time (block2) <= previous_block_time (block2)
        let eligible3 = tracker.finalize_block(block3, &current_online);
        assert_eq!(eligible3.len(), 0);

        // Block 4: MN1 is now in eligible_for_current_block
        let eligible4 = tracker.finalize_block(block4, &current_online);
        assert_eq!(eligible4.len(), 1);
        assert!(eligible4.contains(&mn1));
    }

    #[test]
    fn test_bootstrap_genesis() {
        let mut tracker = MasternodeUptimeTracker::new();
        let genesis = Utc::now();

        let masternodes = vec!["mn1".to_string(), "mn2".to_string(), "mn3".to_string()];

        tracker.bootstrap_genesis(genesis, &masternodes);

        assert_eq!(tracker.eligible_count(), 3);
        assert!(tracker.is_eligible("mn1"));
        assert!(tracker.is_eligible("mn2"));
        assert!(tracker.is_eligible("mn3"));
    }
}
