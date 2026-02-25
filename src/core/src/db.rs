//! Sled-based persistence for blockchain data
use crate::block::{Block, BlockHeader, MasternodeCounts};
use crate::state::StateError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Old BlockHeader format without masternode_counts (for migration)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BlockHeaderV1 {
    pub block_number: u64,
    pub timestamp: DateTime<Utc>,
    pub previous_hash: String,
    pub merkle_root: String,
    pub validator_signature: String,
    pub validator_address: String,
}

/// Old Block format (for migration)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BlockV1 {
    pub header: BlockHeaderV1,
    pub transactions: Vec<crate::transaction::Transaction>,
    pub hash: String,
}

// Type alias to simplify complex type
type BlockObserver = Arc<dyn Fn(&Block) + Send + Sync>;

pub struct BlockchainDB {
    db: sled::Db,
    path: String,
    block_observers: Arc<RwLock<Vec<BlockObserver>>>,
}

use std::sync::Arc;
use tokio::sync::RwLock;

impl std::fmt::Debug for BlockchainDB {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockchainDB")
            .field("path", &self.path)
            .field(
                "observers_count",
                &self
                    .block_observers
                    .try_read()
                    .map(|o| o.len())
                    .unwrap_or(0),
            )
            .finish()
    }
}

impl Clone for BlockchainDB {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
            path: self.path.clone(),
            block_observers: self.block_observers.clone(),
        }
    }
}

impl BlockchainDB {
    /// Open or create the database
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, StateError> {
        let path_str = path.as_ref().to_string_lossy().to_string();

        // Configure sled for maximum durability to ensure blocks persist across reboots
        let db = sled::Config::new()
            .path(&path)
            .mode(sled::Mode::LowSpace) // Prioritize durability over performance
            .flush_every_ms(Some(100)) // Flush to disk every 100ms for better persistence
            .open()
            .map_err(|e| StateError::IoError(format!("Failed to open database: {}", e)))?;

        Ok(BlockchainDB {
            db,
            path: path_str,
            block_observers: Arc::new(RwLock::new(Vec::new())),
        })
    }

    /// Get the database path
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Register a callback to be notified when blocks are saved
    pub async fn register_block_observer<F>(&self, observer: F)
    where
        F: Fn(&Block) + Send + Sync + 'static,
    {
        let mut observers = self.block_observers.write().await;
        observers.push(Arc::new(observer));
    }

    /// Save a block to disk
    pub fn save_block(&self, block: &Block) -> Result<(), StateError> {
        eprintln!(
            "   💾 Saving block {} with {} transactions to disk",
            block.header.block_number,
            block.transactions.len()
        );

        let key = format!("block:{}", block.header.block_number);
        let value = bincode::serialize(block)
            .map_err(|e| StateError::IoError(format!("Failed to serialize block: {}", e)))?;

        eprintln!("   💾 Serialized to {} bytes", value.len());

        self.db
            .insert(key.as_bytes(), value)
            .map_err(|e| StateError::IoError(format!("Failed to save block: {}", e)))?;

        // Flush to disk and fsync to ensure durability across reboots
        self.db
            .flush()
            .map_err(|e| StateError::IoError(format!("Failed to flush block to disk: {}", e)))?;

        // Debug: verify block was saved
        eprintln!(
            "   ✅ Block {} saved to disk (path: {})",
            block.header.block_number, self.path
        );

        // Notify all observers (async operations spawned as background tasks)
        let observers = self.block_observers.clone();
        let block_clone = block.clone();
        tokio::spawn(async move {
            let observers_guard = observers.read().await;
            for observer in observers_guard.iter() {
                observer(&block_clone);
            }
        });

        Ok(())
    }

    /// Delete a block from disk
    pub fn delete_block(&self, height: u64) -> Result<(), StateError> {
        let key = format!("block:{}", height);
        self.db
            .remove(key.as_bytes())
            .map_err(|e| StateError::IoError(format!("Failed to delete block: {}", e)))?;
        Ok(())
    }

    /// Load a block from disk by height
    pub fn load_block(&self, height: u64) -> Result<Option<Block>, StateError> {
        let key = format!("block:{}", height);

        match self.db.get(key.as_bytes()) {
            Ok(Some(data)) => {
                // Only log in debug mode
                if std::env::var("RUST_LOG")
                    .unwrap_or_default()
                    .contains("debug")
                {
                    eprintln!(
                        "   🔍 Loading block {} from disk ({} bytes)",
                        height,
                        data.len()
                    );
                }

                // Try to deserialize with new format first
                match bincode::deserialize::<Block>(&data) {
                    Ok(block) => {
                        if std::env::var("RUST_LOG")
                            .unwrap_or_default()
                            .contains("debug")
                        {
                            eprintln!(
                                "   ✅ Block {} loaded with {} transactions (new format)",
                                height,
                                block.transactions.len()
                            );
                        }
                        Ok(Some(block))
                    }
                    Err(e1) => {
                        // Fall back to old format and migrate
                        eprintln!(
                            "   ⚠️  Block {} uses old format (new format error: {:?}), migrating...",
                            height, e1
                        );
                        match bincode::deserialize::<BlockV1>(&data) {
                            Ok(old_block) => {
                                eprintln!(
                                    "   📦 Old block has {} transactions",
                                    old_block.transactions.len()
                                );
                                // Convert old format to new format
                                let new_block = Block {
                                    header: BlockHeader {
                                        block_number: old_block.header.block_number,
                                        timestamp: old_block.header.timestamp,
                                        previous_hash: old_block.header.previous_hash,
                                        merkle_root: old_block.header.merkle_root,
                                        validator_signature: old_block.header.validator_signature,
                                        validator_address: old_block.header.validator_address,
                                        masternode_counts: MasternodeCounts::default(),
                                        proof_of_time: None,
                                        checkpoints: Vec::new(),
                                    },
                                    transactions: old_block.transactions,
                                    hash: old_block.hash,
                                };

                                eprintln!(
                                    "   📦 New block has {} transactions",
                                    new_block.transactions.len()
                                );
                                // Save migrated block back to disk
                                self.save_block(&new_block)?;
                                eprintln!("   ✅ Block {} migrated to new format", height);

                                Ok(Some(new_block))
                            }
                            Err(e2) => {
                                eprintln!("   ❌ Block {} deserialization failed:", height);
                                eprintln!("      New format error: {}", e1);
                                eprintln!("      Old format error: {}", e2);
                                eprintln!("      Block data size: {} bytes", data.len());

                                // Delete the corrupted block so it can be re-synced
                                eprintln!(
                                    "   ⚠️  Deleting corrupted block {} - will re-sync from peers",
                                    height
                                );

                                if let Err(del_err) = self.db.remove(key.as_bytes()) {
                                    eprintln!(
                                        "   ⚠️  Failed to delete corrupted block {}: {}",
                                        height, del_err
                                    );
                                }

                                Ok(None)
                            }
                        }
                    }
                }
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StateError::IoError(format!("Failed to load block: {}", e))),
        }
    }

    /// Load all blocks from disk
    pub fn load_all_blocks(&self) -> Result<Vec<Block>, StateError> {
        let mut blocks = Vec::new();
        let mut height = 0u64;

        eprintln!("   🔍 Loading blocks from disk (path: {})...", self.path);

        // Show progress every 50 blocks or in debug mode
        let debug_mode = std::env::var("RUST_LOG")
            .unwrap_or_default()
            .contains("debug");

        while let Some(block) = self.load_block(height)? {
            blocks.push(block);
            height += 1;

            // Show progress indicator every 50 blocks (unless in debug mode)
            if !debug_mode && height.is_multiple_of(50) {
                eprint!("\r   📦 Loading... {} blocks", height);
            }
        }

        if !debug_mode && height > 0 {
            eprint!("\r");
        }

        eprintln!("   📦 Loaded {} blocks from disk", blocks.len());

        Ok(blocks)
    }

    /// Save hot state snapshot
    pub fn save_snapshot(
        &self,
        snapshot: &crate::snapshot::HotStateSnapshot,
    ) -> Result<(), StateError> {
        let data = bincode::serialize(snapshot)
            .map_err(|e| StateError::IoError(format!("Failed to serialize snapshot: {}", e)))?;

        self.db
            .insert(b"snapshot:hot_state", data)
            .map_err(|e| StateError::IoError(format!("Failed to save snapshot: {}", e)))?;

        // Flush to ensure it's on disk
        self.db
            .flush()
            .map_err(|e| StateError::IoError(format!("Failed to flush snapshot: {}", e)))?;

        Ok(())
    }

    /// Load latest hot state snapshot
    pub fn load_snapshot(&self) -> Result<Option<crate::snapshot::HotStateSnapshot>, StateError> {
        match self.db.get(b"snapshot:hot_state") {
            Ok(Some(data)) => {
                let snapshot = bincode::deserialize(&data).map_err(|e| {
                    StateError::IoError(format!("Failed to deserialize snapshot: {}", e))
                })?;
                Ok(Some(snapshot))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StateError::IoError(format!(
                "Failed to load snapshot: {}",
                e
            ))),
        }
    }

    /// Save UTXO state snapshot for persistence between blocks
    pub fn save_utxo_snapshot(
        &self,
        utxo_set: &crate::utxo_set::UTXOSet,
    ) -> Result<(), StateError> {
        let snapshot = utxo_set.snapshot();
        let data = bincode::serialize(&snapshot).map_err(|e| {
            StateError::IoError(format!("Failed to serialize UTXO snapshot: {}", e))
        })?;

        self.db
            .insert(b"snapshot:utxo_state", data)
            .map_err(|e| StateError::IoError(format!("Failed to save UTXO snapshot: {}", e)))?;

        // Flush to ensure it's on disk
        self.db
            .flush()
            .map_err(|e| StateError::IoError(format!("Failed to flush UTXO snapshot: {}", e)))?;

        Ok(())
    }

    /// Load UTXO state snapshot
    pub fn load_utxo_snapshot(
        &self,
    ) -> Result<Option<crate::utxo_set::UTXOSetSnapshot>, StateError> {
        match self.db.get(b"snapshot:utxo_state") {
            Ok(Some(data)) => {
                let snapshot = bincode::deserialize(&data).map_err(|e| {
                    StateError::IoError(format!("Failed to deserialize UTXO snapshot: {}", e))
                })?;
                Ok(Some(snapshot))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StateError::IoError(format!(
                "Failed to load UTXO snapshot: {}",
                e
            ))),
        }
    }

    /// Save a finalized transaction to database
    pub fn save_finalized_tx(
        &self,
        tx: &crate::Transaction,
        votes: usize,
        total: usize,
    ) -> Result<(), StateError> {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize)]
        struct FinalizedTx {
            transaction: crate::Transaction,
            finalized_at: i64,
            votes_received: usize,
            total_voters: usize,
        }

        let finalized = FinalizedTx {
            transaction: tx.clone(),
            finalized_at: chrono::Utc::now().timestamp(),
            votes_received: votes,
            total_voters: total,
        };

        let key = format!("finalized_tx:{}", tx.txid);
        let value = bincode::serialize(&finalized)
            .map_err(|e| StateError::IoError(format!("Failed to serialize finalized tx: {}", e)))?;

        self.db
            .insert(key.as_bytes(), value)
            .map_err(|e| StateError::IoError(format!("Failed to save finalized tx: {}", e)))?;

        self.db
            .flush()
            .map_err(|e| StateError::IoError(format!("Failed to flush finalized tx: {}", e)))?;

        Ok(())
    }

    /// Remove a finalized transaction (when it's been included in a block)
    pub fn remove_finalized_tx(&self, txid: &str) -> Result<(), StateError> {
        let key = format!("finalized_tx:{}", txid);
        self.db
            .remove(key.as_bytes())
            .map_err(|e| StateError::IoError(format!("Failed to remove finalized tx: {}", e)))?;
        Ok(())
    }

    /// Load all finalized transactions
    pub fn load_finalized_txs(&self) -> Result<Vec<crate::Transaction>, StateError> {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize)]
        struct FinalizedTx {
            transaction: crate::Transaction,
            finalized_at: i64,
            votes_received: usize,
            total_voters: usize,
        }

        let mut txs = Vec::new();
        let prefix = b"finalized_tx:";

        for item in self.db.scan_prefix(prefix) {
            match item {
                Ok((_key, value)) => {
                    let finalized: FinalizedTx = bincode::deserialize(&value).map_err(|e| {
                        StateError::IoError(format!("Failed to deserialize finalized tx: {}", e))
                    })?;
                    txs.push(finalized.transaction);
                }
                Err(e) => {
                    return Err(StateError::IoError(format!(
                        "Failed to scan finalized txs: {}",
                        e
                    )))
                }
            }
        }

        Ok(txs)
    }

    /// Clear all blocks from the database
    pub fn clear_all(&self) -> Result<(), StateError> {
        // Get all keys that start with "block:"
        let keys_to_delete: Vec<_> = self
            .db
            .scan_prefix(b"block:")
            .keys()
            .filter_map(|k| k.ok())
            .collect();

        // Delete all block entries
        for key in keys_to_delete {
            self.db
                .remove(key)
                .map_err(|e| StateError::IoError(format!("Failed to clear database: {}", e)))?;
        }

        // Clear wallet balance cache (stale after blockchain reset)
        let wallet_keys: Vec<_> = self
            .db
            .scan_prefix(b"wallet_balance:")
            .keys()
            .filter_map(|k| k.ok())
            .collect();

        for key in wallet_keys {
            let _ = self.db.remove(key);
        }

        // Also clear snapshots
        let _ = self.db.remove(b"snapshot:hot_state");

        // Flush to ensure changes are persisted
        self.db
            .flush()
            .map_err(|e| StateError::IoError(format!("Failed to flush database: {}", e)))?;

        Ok(())
    }

    /// Save wallet balance to database
    pub fn save_wallet_balance(&self, address: &str, balance: u64) -> Result<(), StateError> {
        let key = format!("wallet_balance:{}", address);
        let value = balance.to_le_bytes();

        self.db
            .insert(key.as_bytes(), &value)
            .map_err(|e| StateError::IoError(format!("Failed to save wallet balance: {}", e)))?;

        // Flush to ensure it's on disk
        self.db
            .flush()
            .map_err(|e| StateError::IoError(format!("Failed to flush wallet balance: {}", e)))?;

        Ok(())
    }

    /// Load wallet balance from database
    pub fn load_wallet_balance(&self, address: &str) -> Result<Option<u64>, StateError> {
        let key = format!("wallet_balance:{}", address);

        match self.db.get(key.as_bytes()) {
            Ok(Some(data)) => {
                if data.len() == 8 {
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(&data);
                    Ok(Some(u64::from_le_bytes(bytes)))
                } else {
                    Err(StateError::IoError(
                        "Invalid wallet balance data".to_string(),
                    ))
                }
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StateError::IoError(format!(
                "Failed to load wallet balance: {}",
                e
            ))),
        }
    }
}
