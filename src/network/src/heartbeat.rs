//! Heartbeat tracking for masternode uptime monitoring
//!
//! This module tracks heartbeats from masternodes to monitor their availability
//! and detect extended downtime violations.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

/// Configuration for heartbeat tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatConfig {
    /// Maximum heartbeat interval in seconds (5 minutes default)
    pub max_heartbeat_interval: u64,
    /// Maximum number of heartbeats to track per masternode
    pub max_heartbeat_history: usize,
    /// Downtime threshold in days before considering it extended
    pub extended_downtime_threshold_days: u64,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            max_heartbeat_interval: 300, // 5 minutes
            max_heartbeat_history: 1000,
            extended_downtime_threshold_days: 90,
        }
    }
}

/// A single heartbeat record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Heartbeat {
    pub masternode_id: String,
    pub timestamp: u64,
    pub block_height: u64,
}

/// Heartbeat tracker for all masternodes
#[derive(Debug)]
pub struct HeartbeatTracker {
    config: HeartbeatConfig,
    /// Heartbeat history for each masternode
    heartbeats: HashMap<String, VecDeque<Heartbeat>>,
    /// Last known heartbeat timestamp for each masternode
    last_heartbeat: HashMap<String, u64>,
}

impl HeartbeatTracker {
    /// Create a new heartbeat tracker with default configuration
    pub fn new() -> Self {
        Self::with_config(HeartbeatConfig::default())
    }

    /// Create a new heartbeat tracker with custom configuration
    pub fn with_config(config: HeartbeatConfig) -> Self {
        Self {
            config,
            heartbeats: HashMap::new(),
            last_heartbeat: HashMap::new(),
        }
    }

    /// Record a heartbeat for a masternode
    pub fn record_heartbeat(&mut self, masternode_id: String, timestamp: u64, block_height: u64) {
        let heartbeat = Heartbeat {
            masternode_id: masternode_id.clone(),
            timestamp,
            block_height,
        };

        // Update last heartbeat
        self.last_heartbeat.insert(masternode_id.clone(), timestamp);

        // Add to history
        let history = self.heartbeats.entry(masternode_id).or_default();
        history.push_back(heartbeat);

        // Maintain max history size
        while history.len() > self.config.max_heartbeat_history {
            history.pop_front();
        }
    }

    /// Get the last heartbeat timestamp for a masternode
    pub fn get_last_heartbeat(&self, masternode_id: &str) -> Option<u64> {
        self.last_heartbeat.get(masternode_id).copied()
    }

    /// Check if a masternode is online
    pub fn is_online(&self, masternode_id: &str, current_timestamp: u64) -> bool {
        if let Some(&last_seen) = self.last_heartbeat.get(masternode_id) {
            let elapsed = current_timestamp.saturating_sub(last_seen);
            elapsed < self.config.max_heartbeat_interval
        } else {
            false
        }
    }

    /// Get seconds since last heartbeat
    pub fn seconds_since_heartbeat(
        &self,
        masternode_id: &str,
        current_timestamp: u64,
    ) -> Option<u64> {
        self.last_heartbeat
            .get(masternode_id)
            .map(|&last| current_timestamp.saturating_sub(last))
    }

    /// Get days since last heartbeat
    pub fn days_since_heartbeat(&self, masternode_id: &str, current_timestamp: u64) -> Option<u64> {
        self.seconds_since_heartbeat(masternode_id, current_timestamp)
            .map(|seconds| seconds / 86400)
    }

    /// Check if a masternode has extended downtime
    pub fn has_extended_downtime(&self, masternode_id: &str, current_timestamp: u64) -> bool {
        if let Some(days) = self.days_since_heartbeat(masternode_id, current_timestamp) {
            days > self.config.extended_downtime_threshold_days
        } else {
            false
        }
    }

    /// Get heartbeat history for a masternode
    pub fn get_heartbeat_history(&self, masternode_id: &str) -> Vec<&Heartbeat> {
        self.heartbeats
            .get(masternode_id)
            .map(|history| history.iter().collect())
            .unwrap_or_default()
    }

    /// Calculate uptime percentage for a masternode over a given period
    /// Returns (uptime_percentage, total_expected_heartbeats, actual_heartbeats)
    pub fn calculate_uptime(
        &self,
        masternode_id: &str,
        period_seconds: u64,
        current_timestamp: u64,
    ) -> (f64, u64, u64) {
        let expected_heartbeats = period_seconds / self.config.max_heartbeat_interval;

        if let Some(history) = self.heartbeats.get(masternode_id) {
            let cutoff = current_timestamp.saturating_sub(period_seconds);
            let actual = history.iter().filter(|h| h.timestamp >= cutoff).count() as u64;

            let percentage = if expected_heartbeats > 0 {
                (actual as f64 / expected_heartbeats as f64) * 100.0
            } else {
                0.0
            };

            (percentage, expected_heartbeats, actual)
        } else {
            (0.0, expected_heartbeats, 0)
        }
    }

    /// Get all masternodes being tracked
    pub fn get_tracked_masternodes(&self) -> Vec<String> {
        self.last_heartbeat.keys().cloned().collect()
    }

    /// Get count of tracked masternodes
    pub fn count_tracked(&self) -> usize {
        self.last_heartbeat.len()
    }

    /// Remove tracking data for a masternode
    pub fn remove_masternode(&mut self, masternode_id: &str) {
        self.heartbeats.remove(masternode_id);
        self.last_heartbeat.remove(masternode_id);
    }

    /// Get configuration
    pub fn config(&self) -> &HeartbeatConfig {
        &self.config
    }
}

impl Default for HeartbeatTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_and_get_heartbeat() {
        let mut tracker = HeartbeatTracker::new();

        tracker.record_heartbeat("mn1".to_string(), 1000, 100);

        assert_eq!(tracker.get_last_heartbeat("mn1"), Some(1000));
        assert!(tracker.is_online("mn1", 1100));
    }

    #[test]
    fn test_is_online_detection() {
        let mut tracker = HeartbeatTracker::new();

        tracker.record_heartbeat("mn1".to_string(), 1000, 100);

        // Within 5 minutes - should be online
        assert!(tracker.is_online("mn1", 1000 + 299));

        // After 5 minutes - should be offline
        assert!(!tracker.is_online("mn1", 1000 + 301));
    }

    #[test]
    fn test_days_since_heartbeat() {
        let mut tracker = HeartbeatTracker::new();

        tracker.record_heartbeat("mn1".to_string(), 1000, 100);

        // After 50 days
        let current = 1000 + (50 * 86400);
        assert_eq!(tracker.days_since_heartbeat("mn1", current), Some(50));
    }

    #[test]
    fn test_extended_downtime_detection() {
        let mut tracker = HeartbeatTracker::new();

        tracker.record_heartbeat("mn1".to_string(), 1000, 100);

        // After 80 days - not extended yet
        let current_80 = 1000 + (80 * 86400);
        assert!(!tracker.has_extended_downtime("mn1", current_80));

        // After 100 days - extended downtime
        let current_100 = 1000 + (100 * 86400);
        assert!(tracker.has_extended_downtime("mn1", current_100));
    }

    #[test]
    fn test_uptime_calculation() {
        let mut tracker = HeartbeatTracker::with_config(HeartbeatConfig {
            max_heartbeat_interval: 300, // 5 minutes
            ..Default::default()
        });

        // Record 9 out of 10 expected heartbeats over 3000 seconds
        let base_time = 1000u64;
        for i in 0..9 {
            tracker.record_heartbeat("mn1".to_string(), base_time + (i * 300), 100 + i);
        }

        // Calculate uptime over the period
        let (uptime, expected, actual) = tracker.calculate_uptime("mn1", 3000, base_time + 3000);

        assert_eq!(expected, 10);
        assert_eq!(actual, 9);
        assert_eq!(uptime, 90.0);
    }

    #[test]
    fn test_history_size_limit() {
        let mut tracker = HeartbeatTracker::with_config(HeartbeatConfig {
            max_heartbeat_history: 10,
            ..Default::default()
        });

        // Record more heartbeats than the limit
        for i in 0..20 {
            tracker.record_heartbeat("mn1".to_string(), 1000 + i, 100 + i);
        }

        let history = tracker.get_heartbeat_history("mn1");
        assert_eq!(history.len(), 10);

        // Should keep the most recent ones
        assert_eq!(history.last().unwrap().timestamp, 1019);
    }

    #[test]
    fn test_remove_masternode() {
        let mut tracker = HeartbeatTracker::new();

        tracker.record_heartbeat("mn1".to_string(), 1000, 100);
        assert_eq!(tracker.count_tracked(), 1);

        tracker.remove_masternode("mn1");
        assert_eq!(tracker.count_tracked(), 0);
        assert_eq!(tracker.get_last_heartbeat("mn1"), None);
    }

    #[test]
    fn test_multiple_masternodes() {
        let mut tracker = HeartbeatTracker::new();

        tracker.record_heartbeat("mn1".to_string(), 1000, 100);
        tracker.record_heartbeat("mn2".to_string(), 1000, 100);
        tracker.record_heartbeat("mn3".to_string(), 1000, 100);

        assert_eq!(tracker.count_tracked(), 3);

        let tracked = tracker.get_tracked_masternodes();
        assert!(tracked.contains(&"mn1".to_string()));
        assert!(tracked.contains(&"mn2".to_string()));
        assert!(tracked.contains(&"mn3".to_string()));
    }
}
