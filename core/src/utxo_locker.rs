//! UTXO Locking and Coin Selection
//!
//! This module provides:
//! 1. Local UTXO locking to prevent double-spending during concurrent transactions
//! 2. Network-wide UTXO state synchronization for instant propagation
//! 3. Smart coin selection to optimize transaction creation

use crate::transaction::{OutPoint, TxOutput};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum UTXOLockerError {
    #[error("UTXO is already locked")]
    AlreadyLocked,

    #[error("UTXO not found")]
    NotFound,

    #[error("Insufficient funds: need {need}, available {available}")]
    InsufficientFunds { need: u64, available: u64 },

    #[error("Lock expired")]
    LockExpired,
}

/// Lock information for a UTXO
#[derive(Debug, Clone, Serialize, Deserialize)]
struct UTXOLock {
    /// When the lock was acquired
    locked_at: u64,
    /// Lock duration in seconds
    duration: u64,
    /// Transaction ID that locked it (for debugging)
    tx_id: Option<String>,
}

impl UTXOLock {
    fn new(duration_secs: u64, tx_id: Option<String>) -> Self {
        let locked_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            locked_at,
            duration: duration_secs,
            tx_id,
        }
    }

    /// Check if the lock has expired
    fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        now > self.locked_at + self.duration
    }
}

/// Network-wide UTXO state update
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UTXOStateUpdate {
    /// Timestamp of the update
    pub timestamp: u64,
    /// UTXOs being locked/consumed
    pub locked_utxos: Vec<OutPoint>,
    /// New UTXOs being created
    pub created_utxos: Vec<(OutPoint, TxOutput)>,
    /// Transaction ID causing this update
    pub tx_id: String,
    /// Node that initiated the update
    pub node_id: String,
}

/// UTXO Locker - manages local locks and network synchronization
pub struct UTXOLocker {
    /// Locally locked UTXOs
    locked: Arc<RwLock<HashMap<OutPoint, UTXOLock>>>,
    /// Default lock duration (30 seconds for pending transactions)
    default_lock_duration: Duration,
}

impl UTXOLocker {
    /// Create a new UTXO locker
    pub fn new() -> Self {
        Self {
            locked: Arc::new(RwLock::new(HashMap::new())),
            default_lock_duration: Duration::from_secs(30),
        }
    }

    /// Lock a UTXO locally (prevents concurrent transactions from using it)
    pub fn lock_utxo(
        &self,
        outpoint: OutPoint,
        tx_id: Option<String>,
    ) -> Result<(), UTXOLockerError> {
        let mut locked = self.locked.write().unwrap();

        // Check if already locked and not expired
        if let Some(existing_lock) = locked.get(&outpoint) {
            if !existing_lock.is_expired() {
                return Err(UTXOLockerError::AlreadyLocked);
            }
        }

        // Create new lock
        let lock = UTXOLock::new(self.default_lock_duration.as_secs(), tx_id);
        locked.insert(outpoint, lock);

        Ok(())
    }

    /// Unlock a UTXO (transaction completed or failed)
    pub fn unlock_utxo(&self, outpoint: &OutPoint) {
        let mut locked = self.locked.write().unwrap();
        locked.remove(outpoint);
    }

    /// Check if a UTXO is currently locked
    pub fn is_locked(&self, outpoint: &OutPoint) -> bool {
        let locked = self.locked.read().unwrap();

        if let Some(lock) = locked.get(outpoint) {
            !lock.is_expired()
        } else {
            false
        }
    }

    /// Cleanup expired locks
    pub fn cleanup_expired_locks(&self) {
        let mut locked = self.locked.write().unwrap();
        locked.retain(|_, lock| !lock.is_expired());
    }

    /// Get all currently locked UTXOs
    pub fn get_locked_utxos(&self) -> Vec<OutPoint> {
        let locked = self.locked.read().unwrap();
        locked.keys().cloned().collect()
    }
}

impl Default for UTXOLocker {
    fn default() -> Self {
        Self::new()
    }
}

/// Smart Coin Selection Algorithm
pub struct CoinSelector;

impl CoinSelector {
    /// Select UTXOs to meet a target amount
    ///
    /// Strategy:
    /// 1. Try to find a single UTXO that exactly matches
    /// 2. Try to find a single UTXO slightly larger (minimize change)
    /// 3. Use multiple UTXOs, preferring smaller ones first
    pub fn select_coins(
        available_utxos: &[(OutPoint, TxOutput)],
        target_amount: u64,
        locked_utxos: &HashSet<OutPoint>,
    ) -> Result<Vec<(OutPoint, TxOutput)>, UTXOLockerError> {
        // Filter out locked UTXOs
        let mut usable: Vec<_> = available_utxos
            .iter()
            .filter(|(outpoint, _)| !locked_utxos.contains(outpoint))
            .cloned()
            .collect();

        if usable.is_empty() {
            return Err(UTXOLockerError::InsufficientFunds {
                need: target_amount,
                available: 0,
            });
        }

        // Calculate total available
        let total_available: u64 = usable.iter().map(|(_, output)| output.amount).sum();

        if total_available < target_amount {
            return Err(UTXOLockerError::InsufficientFunds {
                need: target_amount,
                available: total_available,
            });
        }

        // Strategy 1: Find exact match
        if let Some(exact) = usable
            .iter()
            .find(|(_, output)| output.amount == target_amount)
        {
            return Ok(vec![exact.clone()]);
        }

        // Strategy 2: Find single UTXO slightly larger (within 20% overhead)
        let max_acceptable = target_amount + (target_amount / 5); // 20% overhead
        if let Some(single) = usable
            .iter()
            .filter(|(_, output)| output.amount >= target_amount && output.amount <= max_acceptable)
            .min_by_key(|(_, output)| output.amount)
        {
            return Ok(vec![single.clone()]);
        }

        // Strategy 3: Use multiple UTXOs - prefer smaller ones to reduce fragmentation
        usable.sort_by_key(|(_, output)| output.amount);

        let mut selected = Vec::new();
        let mut total = 0u64;

        for utxo in usable {
            selected.push(utxo.clone());
            total += utxo.1.amount;

            if total >= target_amount {
                return Ok(selected);
            }
        }

        // Should never reach here due to earlier total_available check
        Err(UTXOLockerError::InsufficientFunds {
            need: target_amount,
            available: total_available,
        })
    }

    /// Calculate optimal change output
    /// Returns None if change is too small to be worth creating
    pub fn calculate_change(selected_total: u64, target_amount: u64, fee: u64) -> Option<u64> {
        let spent = target_amount + fee;

        if selected_total <= spent {
            return None;
        }

        let change = selected_total - spent;

        // Don't create dust outputs (less than 1000 satoshis)
        if change < 1000 {
            None
        } else {
            Some(change)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::OutPoint;

    #[test]
    fn test_utxo_locking() {
        let locker = UTXOLocker::new();
        let outpoint = OutPoint::new(hex::encode([1u8; 32]), 0);

        // Lock should succeed
        assert!(locker
            .lock_utxo(outpoint.clone(), Some("tx1".to_string()))
            .is_ok());

        // Second lock should fail
        assert!(locker
            .lock_utxo(outpoint.clone(), Some("tx2".to_string()))
            .is_err());

        // Unlock
        locker.unlock_utxo(&outpoint);

        // Lock should succeed again
        assert!(locker
            .lock_utxo(outpoint.clone(), Some("tx3".to_string()))
            .is_ok());
    }

    #[test]
    fn test_coin_selection_exact_match() {
        let utxos = vec![
            (
                OutPoint::new(hex::encode([1u8; 32]), 0),
                TxOutput {
                    amount: 100,
                    address: "addr1".to_string(),
                },
            ),
            (
                OutPoint::new(hex::encode([2u8; 32]), 0),
                TxOutput {
                    amount: 500,
                    address: "addr1".to_string(),
                },
            ),
            (
                OutPoint::new(hex::encode([3u8; 32]), 0),
                TxOutput {
                    amount: 1000,
                    address: "addr1".to_string(),
                },
            ),
        ];

        let selected = CoinSelector::select_coins(&utxos, 500, &HashSet::new()).unwrap();

        // Should select exact match
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].1.amount, 500);
    }

    #[test]
    fn test_coin_selection_multiple() {
        let utxos = vec![
            (
                OutPoint::new(hex::encode([1u8; 32]), 0),
                TxOutput {
                    amount: 100,
                    address: "addr1".to_string(),
                },
            ),
            (
                OutPoint::new(hex::encode([2u8; 32]), 0),
                TxOutput {
                    amount: 200,
                    address: "addr1".to_string(),
                },
            ),
            (
                OutPoint::new(hex::encode([3u8; 32]), 0),
                TxOutput {
                    amount: 300,
                    address: "addr1".to_string(),
                },
            ),
        ];

        let selected = CoinSelector::select_coins(&utxos, 450, &HashSet::new()).unwrap();

        // Should select multiple UTXOs
        assert!(selected.len() >= 2);
        let total: u64 = selected.iter().map(|(_, output)| output.amount).sum();
        assert!(total >= 450);
    }

    #[test]
    fn test_insufficient_funds() {
        let utxos = vec![(
            OutPoint::new(hex::encode([1u8; 32]), 0),
            TxOutput {
                amount: 100,
                address: "addr1".to_string(),
            },
        )];

        let result = CoinSelector::select_coins(&utxos, 500, &HashSet::new());
        assert!(result.is_err());
    }
}
