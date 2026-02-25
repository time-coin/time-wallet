//! Snapshot system for fast memory operations with disk backup

use crate::db::BlockchainDB;
use crate::state::StateError;
use crate::transaction::Transaction;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Hot state snapshot - current block period in memory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotStateSnapshot {
    pub current_height: u64,
    pub mempool: Vec<Transaction>,
    pub recent_tx_hashes: Vec<String>,
    pub snapshot_time: u64,
    pub last_block_hash: String,
}

/// Hot state manager - keeps current activity in memory
pub struct HotStateManager {
    hot_state: Arc<RwLock<HotState>>,
    db: Arc<BlockchainDB>,
    snapshot_interval: u64,
    last_snapshot: Arc<RwLock<SystemTime>>,
}

/// In-memory hot state (fast access)
#[derive(Debug, Clone)]
pub struct HotState {
    pub current_height: u64,
    pub mempool: VecDeque<Transaction>,
    pub tx_hash_set: std::collections::HashSet<String>,
    pub recent_txs: VecDeque<Transaction>,
    pub balance_cache: HashMap<String, u64>,
    pub last_block_hash: String,
}

impl HotStateManager {
    pub fn new(db: Arc<BlockchainDB>, snapshot_interval_secs: u64) -> Result<Self, StateError> {
        let hot_state = Arc::new(RwLock::new(HotState {
            current_height: 0,
            mempool: VecDeque::new(),
            tx_hash_set: std::collections::HashSet::new(),
            recent_txs: VecDeque::new(),
            balance_cache: HashMap::new(),
            last_block_hash: String::new(),
        }));

        Ok(HotStateManager {
            hot_state,
            db,
            snapshot_interval: snapshot_interval_secs,
            last_snapshot: Arc::new(RwLock::new(SystemTime::now())),
        })
    }

    /// Load from disk on startup
    pub fn load_from_disk(&self) -> Result<(), StateError> {
        println!("🔄 Loading hot state from disk...");

        // Try to load snapshot
        let snapshot = match self.db.load_snapshot()? {
            Some(s) => s,
            None => {
                println!("⚠️  No snapshot found, starting fresh");
                return Ok(());
            }
        };

        println!(
            "✅ Loaded snapshot from {} (height {})",
            format_timestamp(snapshot.snapshot_time),
            snapshot.current_height
        );

        // Restore hot state
        let mut state = self.hot_state.write().unwrap();
        state.current_height = snapshot.current_height;
        state.last_block_hash = snapshot.last_block_hash;

        // Restore mempool
        state.mempool.clear();
        state.tx_hash_set.clear();
        for tx in snapshot.mempool {
            state.tx_hash_set.insert(tx.txid.clone());
            state.mempool.push_back(tx.clone());
            state.recent_txs.push_back(tx);
        }

        // Restore tx hash set from recent hashes
        for hash in snapshot.recent_tx_hashes {
            state.tx_hash_set.insert(hash);
        }

        println!(
            "✅ Restored {} transactions in mempool",
            state.mempool.len()
        );

        Ok(())
    }

    pub fn add_transaction(&self, tx: Transaction) -> Result<(), StateError> {
        let mut state = self.hot_state.write().unwrap();

        // Check for duplicates (O(1) lookup)
        if state.tx_hash_set.contains(&tx.txid) {
            return Err(StateError::DuplicateTransaction);
        }

        // Add to mempool
        state.tx_hash_set.insert(tx.txid.clone());
        state.mempool.push_back(tx.clone());
        state.recent_txs.push_back(tx);

        // Keep recent_txs bounded
        while state.recent_txs.len() > 10_000 {
            if let Some(old_tx) = state.recent_txs.pop_front() {
                // Don't remove from tx_hash_set if still in mempool
                let in_mempool = state.mempool.iter().any(|t| t.txid == old_tx.txid);
                if !in_mempool {
                    state.tx_hash_set.remove(&old_tx.txid);
                }
            }
        }

        Ok(())
    }

    pub fn get_mempool_transactions(&self, max_count: usize) -> Vec<Transaction> {
        let state = self.hot_state.read().unwrap();
        state.mempool.iter().take(max_count).cloned().collect()
    }

    pub fn mempool_size(&self) -> usize {
        let state = self.hot_state.read().unwrap();
        state.mempool.len()
    }

    pub fn has_transaction(&self, tx_hash: &[u8; 32]) -> bool {
        let state = self.hot_state.read().unwrap();
        let hash_str = hex::encode(tx_hash);
        state.tx_hash_set.contains(&hash_str)
    }

    /// Save snapshot to disk (periodic backup)
    pub fn save_snapshot(&self) -> Result<(), StateError> {
        let now = SystemTime::now();
        let last = *self.last_snapshot.read().unwrap();

        // Check if enough time has passed
        if now.duration_since(last).unwrap().as_secs() < self.snapshot_interval {
            return Ok(());
        }

        let state = self.hot_state.read().unwrap();

        // Create snapshot
        let snapshot = HotStateSnapshot {
            current_height: state.current_height,
            mempool: state.mempool.iter().cloned().collect(),
            recent_tx_hashes: state.tx_hash_set.iter().cloned().collect(),
            snapshot_time: now.duration_since(UNIX_EPOCH).unwrap().as_secs(),
            last_block_hash: state.last_block_hash.clone(),
        };

        // Save to disk
        self.db.save_snapshot(&snapshot)?;

        // Update last snapshot time
        *self.last_snapshot.write().unwrap() = now;

        println!(
            "💾 Snapshot saved (height: {}, mempool: {} txs)",
            snapshot.current_height,
            snapshot.mempool.len()
        );

        Ok(())
    }

    /// Force save snapshot to disk (ignores time interval)
    pub fn force_save_snapshot(&self) -> Result<(), StateError> {
        let now = SystemTime::now();
        let state = self.hot_state.read().unwrap();

        // Create snapshot
        let snapshot = HotStateSnapshot {
            current_height: state.current_height,
            mempool: state.mempool.iter().cloned().collect(),
            recent_tx_hashes: state.tx_hash_set.iter().cloned().collect(),
            snapshot_time: now.duration_since(UNIX_EPOCH).unwrap().as_secs(),
            last_block_hash: state.last_block_hash.clone(),
        };

        // Save to disk
        self.db.save_snapshot(&snapshot)?;

        // Update last snapshot time
        *self.last_snapshot.write().unwrap() = now;

        println!(
            "💾 Snapshot force saved (height: {}, mempool: {} txs)",
            snapshot.current_height,
            snapshot.mempool.len()
        );

        Ok(())
    }

    pub fn get_stats(&self) -> HotStateStats {
        let state = self.hot_state.read().unwrap();
        HotStateStats {
            mempool_size: state.mempool.len(),
            recent_tx_count: state.recent_txs.len(),
            pending_utxo_count: 0,
            cached_addresses: state.balance_cache.len(),
            current_height: state.current_height,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotStateStats {
    pub mempool_size: usize,
    pub recent_tx_count: usize,
    pub pending_utxo_count: usize,
    pub cached_addresses: usize,
    pub current_height: u64,
}

// Helper function
fn format_timestamp(secs: u64) -> String {
    use std::time::Duration;
    let duration = Duration::from_secs(secs);
    let datetime = SystemTime::UNIX_EPOCH + duration;
    format!("{:?}", datetime)
}
