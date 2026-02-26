//! Priority Queue Manager for Mempool
//!
//! Provides O(log n) transaction selection using binary heaps.
//! Three priority tiers for efficient transaction ordering.

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use time_core::Transaction;

/// Transaction with priority for heap ordering
#[derive(Clone, Debug)]
pub struct PriorityTransaction {
    pub transaction: Transaction,
    pub priority: u64, // fee/size ratio
    pub added_at: i64,
    pub finalized: bool,
}

impl Ord for PriorityTransaction {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher priority first
        self.priority
            .cmp(&other.priority)
            // Break ties by timestamp (older first)
            .then(other.added_at.cmp(&self.added_at))
    }
}

impl PartialOrd for PriorityTransaction {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for PriorityTransaction {
    fn eq(&self, other: &Self) -> bool {
        self.transaction.txid == other.transaction.txid
    }
}

impl Eq for PriorityTransaction {}

/// Three-tier priority queue system for efficient transaction selection
pub struct PriorityQueueManager {
    high_priority: BinaryHeap<PriorityTransaction>, // Fee/byte > 1000
    standard: BinaryHeap<PriorityTransaction>,      // Fee/byte 10-1000
    low_priority: BinaryHeap<PriorityTransaction>,  // Fee/byte < 10
}

impl Default for PriorityQueueManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PriorityQueueManager {
    /// Create new priority queue manager
    pub fn new() -> Self {
        Self {
            high_priority: BinaryHeap::new(),
            standard: BinaryHeap::new(),
            low_priority: BinaryHeap::new(),
        }
    }

    /// Add transaction to appropriate priority tier
    pub fn add(&mut self, tx: PriorityTransaction) {
        if tx.priority > 1000 {
            self.high_priority.push(tx);
        } else if tx.priority >= 10 {
            self.standard.push(tx);
        } else {
            self.low_priority.push(tx);
        }
    }

    /// Select transactions for block (fills from high to low priority)
    pub fn select_for_block(&mut self, max_count: usize) -> Vec<Transaction> {
        let mut selected = Vec::with_capacity(max_count);

        // Fill from high priority first
        while selected.len() < max_count {
            if let Some(tx) = self.high_priority.pop() {
                selected.push(tx.transaction);
            } else {
                break;
            }
        }

        // Then standard priority
        while selected.len() < max_count {
            if let Some(tx) = self.standard.pop() {
                selected.push(tx.transaction);
            } else {
                break;
            }
        }

        // Finally low priority if space available
        while selected.len() < max_count {
            if let Some(tx) = self.low_priority.pop() {
                selected.push(tx.transaction);
            } else {
                break;
            }
        }

        selected
    }

    /// Get total transaction count across all tiers
    pub fn len(&self) -> usize {
        self.high_priority.len() + self.standard.len() + self.low_priority.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear all queues
    pub fn clear(&mut self) {
        self.high_priority.clear();
        self.standard.clear();
        self.low_priority.clear();
    }

    /// Get stats about queue distribution
    pub fn stats(&self) -> PriorityStats {
        PriorityStats {
            high_priority_count: self.high_priority.len(),
            standard_count: self.standard.len(),
            low_priority_count: self.low_priority.len(),
            total: self.len(),
        }
    }
}

/// Statistics about priority queue distribution
#[derive(Debug, Clone)]
pub struct PriorityStats {
    pub high_priority_count: usize,
    pub standard_count: usize,
    pub low_priority_count: usize,
    pub total: usize,
}

impl PriorityStats {
    pub fn print(&self) {
        println!("📊 Mempool Priority Distribution:");
        println!("   🔥 High Priority: {} txs", self.high_priority_count);
        println!("   ⚡ Standard: {} txs", self.standard_count);
        println!("   💤 Low Priority: {} txs", self.low_priority_count);
        println!("   📝 Total: {} txs", self.total);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time_core::{Transaction, TxOutput};

    fn create_test_tx(txid: &str, priority: u64) -> PriorityTransaction {
        PriorityTransaction {
            transaction: Transaction {
                txid: txid.to_string(),
                version: 1,
                inputs: vec![],
                outputs: vec![TxOutput {
                    amount: 1000,
                    address: "test".to_string(),
                }],
                lock_time: 0,
                timestamp: 0,
            },
            priority,
            added_at: chrono::Utc::now().timestamp(),
            finalized: false,
        }
    }

    #[test]
    fn test_priority_ordering() {
        let mut manager = PriorityQueueManager::new();

        // Add transactions with different priorities
        manager.add(create_test_tx("low", 5));
        manager.add(create_test_tx("high", 2000));
        manager.add(create_test_tx("standard", 100));

        assert_eq!(manager.len(), 3);

        // Should select high priority first
        let selected = manager.select_for_block(3);
        assert_eq!(selected.len(), 3);
        assert_eq!(selected[0].txid, "high");
        assert_eq!(selected[1].txid, "standard");
        assert_eq!(selected[2].txid, "low");
    }

    #[test]
    fn test_tier_distribution() {
        let mut manager = PriorityQueueManager::new();

        manager.add(create_test_tx("high1", 1500));
        manager.add(create_test_tx("high2", 2000));
        manager.add(create_test_tx("standard1", 50));
        manager.add(create_test_tx("standard2", 100));
        manager.add(create_test_tx("low1", 5));

        let stats = manager.stats();
        assert_eq!(stats.high_priority_count, 2);
        assert_eq!(stats.standard_count, 2);
        assert_eq!(stats.low_priority_count, 1);
        assert_eq!(stats.total, 5);
    }

    #[test]
    fn test_max_count_limit() {
        let mut manager = PriorityQueueManager::new();

        for i in 0..10 {
            manager.add(create_test_tx(&format!("tx{}", i), 100));
        }

        let selected = manager.select_for_block(5);
        assert_eq!(selected.len(), 5);

        // 5 should remain
        assert_eq!(manager.len(), 5);
    }
}
