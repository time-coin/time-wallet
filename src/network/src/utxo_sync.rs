//! UTXO Instant Synchronization Implementation
//!
//! Handles instant UTXO locking, conflict resolution, and network-wide synchronization

use crate::protocol::NetworkMessage;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

const LOCK_TIMEOUT_MS: i64 = 5000; // 5 seconds
const SPENT_WINDOW_MS: i64 = 60000; // 1 minute

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoInput {
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoOutput {
    pub address: String,
    pub amount: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UtxoKey {
    pub txid: String,
    pub vout: u32,
}

#[derive(Debug, Clone)]
pub struct Utxo {
    pub address: String,
    pub amount: u64,
    pub block_height: Option<u64>,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct LockedUtxo {
    pub utxo: Utxo,
    pub locked_at: i64,
    pub locked_by_tx: String,
    pub locking_masternode: String,
}

#[derive(Debug, Clone)]
pub struct SpentUtxo {
    pub utxo: Utxo,
    pub spent_at: i64,
    pub spent_by_tx: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictInfo {
    pub existing_txid: String,
    pub existing_timestamp: i64,
    pub existing_locks: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockAcknowledgment {
    pub txid: String,
    pub masternode: String,
    pub tier: MasternodeTier,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum MasternodeTier {
    Free,
    Bronze,
    Silver,
    Gold,
}

impl MasternodeTier {
    pub fn weight(&self) -> f64 {
        match self {
            MasternodeTier::Gold => 3.0,
            MasternodeTier::Silver => 2.0,
            MasternodeTier::Bronze => 1.5,
            MasternodeTier::Free => 1.0,
        }
    }

    pub fn from_string(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "gold" => MasternodeTier::Gold,
            "silver" => MasternodeTier::Silver,
            "bronze" => MasternodeTier::Bronze,
            _ => MasternodeTier::Free,
        }
    }
}

/// UTXO Synchronization Manager
pub struct UtxoSyncManager {
    /// Active UTXOs available for spending
    active: Arc<RwLock<HashMap<UtxoKey, Utxo>>>,
    /// Locked UTXOs (pending transaction approval)
    locked: Arc<RwLock<HashMap<UtxoKey, LockedUtxo>>>,
    /// Recently spent (for conflict detection window)
    recently_spent: Arc<RwLock<HashMap<UtxoKey, SpentUtxo>>>,
    /// Track lock acknowledgments per transaction
    lock_acks: Arc<RwLock<HashMap<String, Vec<LockAcknowledgment>>>>,
    /// Our masternode info
    our_node_id: String,
    our_tier: MasternodeTier,
}

impl UtxoSyncManager {
    pub fn new(node_id: String, tier: MasternodeTier) -> Self {
        Self {
            active: Arc::new(RwLock::new(HashMap::new())),
            locked: Arc::new(RwLock::new(HashMap::new())),
            recently_spent: Arc::new(RwLock::new(HashMap::new())),
            lock_acks: Arc::new(RwLock::new(HashMap::new())),
            our_node_id: node_id,
            our_tier: tier,
        }
    }

    /// Lock a UTXO for a pending transaction
    pub async fn lock_utxo(
        &self,
        key: UtxoKey,
        txid: String,
        proposer: String,
    ) -> Result<(), String> {
        let mut locked = self.locked.write().await;
        let active = self.active.read().await;

        // Check if already locked
        if let Some(existing_lock) = locked.get(&key) {
            return Err(format!(
                "UTXO already locked by tx {}",
                existing_lock.locked_by_tx
            ));
        }

        // Get the UTXO from active set
        let utxo = active
            .get(&key)
            .ok_or_else(|| "UTXO not found".to_string())?
            .clone();

        // Create lock
        let lock = LockedUtxo {
            utxo,
            locked_at: current_timestamp_ms(),
            locked_by_tx: txid,
            locking_masternode: proposer,
        };

        locked.insert(key, lock);
        Ok(())
    }

    /// Unlock a UTXO (rollback)
    pub async fn unlock_utxo(&self, key: &UtxoKey) -> Result<(), String> {
        let mut locked = self.locked.write().await;
        locked
            .remove(key)
            .ok_or_else(|| "UTXO not locked".to_string())?;
        Ok(())
    }

    /// Commit a locked UTXO (mark as spent)
    pub async fn commit_lock(&self, key: &UtxoKey, txid: String) -> Result<(), String> {
        let mut locked = self.locked.write().await;
        let mut active = self.active.write().await;
        let mut spent = self.recently_spent.write().await;

        // Remove from locked
        let lock = locked
            .remove(key)
            .ok_or_else(|| "UTXO not locked".to_string())?;

        // Remove from active
        active.remove(key);

        // Add to recently spent
        spent.insert(
            key.clone(),
            SpentUtxo {
                utxo: lock.utxo,
                spent_at: current_timestamp_ms(),
                spent_by_tx: txid,
            },
        );

        Ok(())
    }

    /// Add a new UTXO to the active set
    pub async fn add_utxo(&self, key: UtxoKey, utxo: Utxo) {
        self.active.write().await.insert(key, utxo);
    }

    /// Record a lock acknowledgment
    pub async fn add_lock_ack(&self, ack: LockAcknowledgment) {
        self.lock_acks
            .write()
            .await
            .entry(ack.txid.clone())
            .or_insert_with(Vec::new)
            .push(ack);
    }

    /// Check if we have enough acknowledgments to commit
    pub async fn check_threshold(&self, txid: &str, total_masternodes: u32) -> bool {
        let acks = self.lock_acks.read().await;
        if let Some(ack_list) = acks.get(txid) {
            let threshold = (total_masternodes * 2 / 3) + 1;
            ack_list.len() as u32 >= threshold
        } else {
            false
        }
    }

    /// Calculate total weight of acknowledgments
    pub async fn calculate_ack_weight(&self, txid: &str) -> f64 {
        let acks = self.lock_acks.read().await;
        if let Some(ack_list) = acks.get(txid) {
            ack_list.iter().map(|ack| ack.tier.weight()).sum()
        } else {
            0.0
        }
    }

    /// Clean up expired locks
    pub async fn cleanup_expired_locks(&self) {
        let now = current_timestamp_ms();
        let mut locked = self.locked.write().await;

        locked.retain(|_key, lock| {
            let expired = now - lock.locked_at > LOCK_TIMEOUT_MS;
            if expired {
                warn!(
                    txid = %lock.locked_by_tx,
                    "Lock expired after timeout"
                );
            }
            !expired
        });
    }

    /// Clean up old spent UTXOs
    pub async fn cleanup_spent_window(&self) {
        let now = current_timestamp_ms();
        let mut spent = self.recently_spent.write().await;

        spent.retain(|_key, spent_utxo| now - spent_utxo.spent_at < SPENT_WINDOW_MS);
    }

    /// Handle incoming lock broadcast
    pub async fn handle_lock_broadcast(
        &self,
        txid: String,
        inputs: Vec<UtxoInput>,
        _outputs: Vec<UtxoOutput>,
        _timestamp: i64,
        proposer: String,
    ) -> Result<NetworkMessage, String> {
        debug!(txid = %txid, inputs = inputs.len(), "Processing lock broadcast");

        // Try to lock all inputs
        for input in &inputs {
            let key = UtxoKey {
                txid: input.txid.clone(),
                vout: input.vout,
            };

            match self
                .lock_utxo(key.clone(), txid.clone(), proposer.clone())
                .await
            {
                Ok(_) => {
                    info!(txid = %txid, input = ?input, "UTXO locked successfully");
                }
                Err(e) => {
                    warn!(txid = %txid, input = ?input, error = %e, "Failed to lock UTXO");

                    // Check for conflict
                    let locked = self.locked.read().await;
                    let conflict_info = if let Some(lock) = locked.get(&key) {
                        let acks = self.lock_acks.read().await;
                        let lock_count = acks
                            .get(&lock.locked_by_tx)
                            .map(|v| v.len() as u32)
                            .unwrap_or(0);

                        Some(ConflictInfo {
                            existing_txid: lock.locked_by_tx.clone(),
                            existing_timestamp: lock.locked_at,
                            existing_locks: lock_count,
                        })
                    } else {
                        None
                    };

                    return Ok(NetworkMessage::UtxoLockAcknowledge {
                        txid,
                        masternode: self.our_node_id.clone(),
                        tier: format!("{:?}", self.our_tier),
                        success: false,
                        conflict: conflict_info
                            .map(|c| serde_json::to_string(&c).unwrap_or_default()),
                        timestamp: current_timestamp_ms(),
                    });
                }
            }
        }

        // All locks successful
        Ok(NetworkMessage::UtxoLockAcknowledge {
            txid,
            masternode: self.our_node_id.clone(),
            tier: format!("{:?}", self.our_tier),
            success: true,
            conflict: None,
            timestamp: current_timestamp_ms(),
        })
    }

    /// Handle lock acknowledgment
    pub async fn handle_lock_ack(&self, ack: NetworkMessage) {
        if let NetworkMessage::UtxoLockAcknowledge {
            txid,
            masternode,
            tier,
            success,
            conflict: _,
            timestamp,
        } = ack
        {
            if success {
                let lock_ack = LockAcknowledgment {
                    txid: txid.clone(),
                    masternode,
                    tier: MasternodeTier::from_string(&tier),
                    timestamp,
                };
                self.add_lock_ack(lock_ack).await;
                debug!(txid = %txid, "Lock acknowledgment recorded");
            } else {
                warn!(txid = %txid, "Lock rejected by masternode");
            }
        }
    }

    /// Handle UTXO commit (finalize or reject)
    pub async fn handle_commit(
        &self,
        txid: String,
        status: String,
        inputs: Vec<UtxoInput>,
    ) -> Result<(), String> {
        if status == "Approved" {
            // Commit all locks
            for input in inputs {
                let key = UtxoKey {
                    txid: input.txid.clone(),
                    vout: input.vout,
                };
                self.commit_lock(&key, txid.clone()).await?;
            }
            info!(txid = %txid, "Transaction approved and committed");
        } else {
            // Rollback all locks
            for input in inputs {
                let key = UtxoKey {
                    txid: input.txid.clone(),
                    vout: input.vout,
                };
                let _ = self.unlock_utxo(&key).await;
            }
            info!(txid = %txid, "Transaction rejected and rolled back");
        }
        Ok(())
    }

    /// Get UTXO statistics
    pub async fn stats(&self) -> UtxoStats {
        UtxoStats {
            active_count: self.active.read().await.len(),
            locked_count: self.locked.read().await.len(),
            spent_count: self.recently_spent.read().await.len(),
        }
    }
}

#[derive(Debug)]
pub struct UtxoStats {
    pub active_count: usize,
    pub locked_count: usize,
    pub spent_count: usize,
}

fn current_timestamp_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_utxo_lock() {
        let manager = UtxoSyncManager::new("test-node".to_string(), MasternodeTier::Free);

        let key = UtxoKey {
            txid: "genesis".to_string(),
            vout: 0,
        };

        let utxo = Utxo {
            address: "test_addr".to_string(),
            amount: 100,
            block_height: Some(0),
            created_at: current_timestamp_ms(),
        };

        manager.add_utxo(key.clone(), utxo).await;

        // Lock should succeed
        assert!(manager
            .lock_utxo(key.clone(), "tx1".to_string(), "proposer1".to_string())
            .await
            .is_ok());

        // Second lock should fail
        assert!(manager
            .lock_utxo(key, "tx2".to_string(), "proposer2".to_string())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_lock_commit() {
        let manager = UtxoSyncManager::new("test-node".to_string(), MasternodeTier::Free);

        let key = UtxoKey {
            txid: "genesis".to_string(),
            vout: 0,
        };

        let utxo = Utxo {
            address: "test_addr".to_string(),
            amount: 100,
            block_height: Some(0),
            created_at: current_timestamp_ms(),
        };

        manager.add_utxo(key.clone(), utxo).await;
        manager
            .lock_utxo(key.clone(), "tx1".to_string(), "proposer1".to_string())
            .await
            .unwrap();

        // Commit should succeed
        assert!(manager.commit_lock(&key, "tx1".to_string()).await.is_ok());

        // UTXO should be in spent window
        let stats = manager.stats().await;
        assert_eq!(stats.active_count, 0);
        assert_eq!(stats.locked_count, 0);
        assert_eq!(stats.spent_count, 1);
    }
}
