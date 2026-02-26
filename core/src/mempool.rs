//! Transaction Pool (Mempool) for TIME Coin
//!
//! Manages pending transactions with UTXO validation

use crate::transaction::{Transaction, TransactionError};
use crate::utxo_set::UTXOSet;
use crate::utxo_state_manager::UTXOStateManager;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Maximum transactions in mempool
const MAX_MEMPOOL_SIZE: usize = 10_000;

#[derive(Debug, Clone)]
pub enum MempoolError {
    TransactionError(TransactionError),
    MempoolFull,
    DuplicateTransaction,
    InvalidTransaction,
    ConflictingTransaction,
    UTXOLocked(String), // UTXO is locked by another transaction
}

impl std::fmt::Display for MempoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            MempoolError::TransactionError(e) => write!(f, "Transaction error: {}", e),
            MempoolError::MempoolFull => write!(f, "Mempool is full"),
            MempoolError::DuplicateTransaction => write!(f, "Transaction already in mempool"),
            MempoolError::InvalidTransaction => write!(f, "Invalid transaction"),
            MempoolError::ConflictingTransaction => {
                write!(f, "Transaction conflicts with another in mempool")
            }
            MempoolError::UTXOLocked(msg) => write!(f, "UTXO locked: {}", msg),
        }
    }
}

impl std::error::Error for MempoolError {}

impl From<TransactionError> for MempoolError {
    fn from(err: TransactionError) -> Self {
        MempoolError::TransactionError(err)
    }
}

/// Transaction with priority for ordering
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MempoolTransaction {
    transaction: Transaction,
    fee_per_byte: u64,
    added_timestamp: i64,
}

/// Transaction pool for pending transactions
#[derive(Clone)]
pub struct Mempool {
    /// Pending transactions by txid
    transactions: HashMap<String, MempoolTransaction>,

    /// Track which UTXOs are being spent (to prevent double-spend in mempool)
    spent_outputs: HashSet<String>, // Format: "txid:vout"

    /// Maximum size
    max_size: usize,

    /// Optional UTXO state manager for instant finality
    utxo_state_manager: Option<Arc<UTXOStateManager>>,
}

// Manual Debug impl since UTXOStateManager doesn't derive Debug
impl std::fmt::Debug for Mempool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mempool")
            .field("transaction_count", &self.transactions.len())
            .field("spent_outputs_count", &self.spent_outputs.len())
            .field("max_size", &self.max_size)
            .field("has_utxo_manager", &self.utxo_state_manager.is_some())
            .finish()
    }
}

impl Mempool {
    /// Create a new mempool
    pub fn new() -> Self {
        Self {
            transactions: HashMap::new(),
            spent_outputs: HashSet::new(),
            max_size: MAX_MEMPOOL_SIZE,
            utxo_state_manager: None,
        }
    }

    /// Create a mempool with custom max size
    pub fn with_capacity(max_size: usize) -> Self {
        Self {
            transactions: HashMap::new(),
            spent_outputs: HashSet::new(),
            max_size,
            utxo_state_manager: None,
        }
    }

    /// Set the UTXO state manager (enables instant finality)
    pub fn set_utxo_state_manager(&mut self, manager: Arc<UTXOStateManager>) {
        self.utxo_state_manager = Some(manager);
    }

    /// Check if a UTXO is locked by another transaction
    #[allow(dead_code)]
    async fn check_utxo_locks(&self, tx: &Transaction) -> Result<(), MempoolError> {
        if let Some(manager) = &self.utxo_state_manager {
            for input in &tx.inputs {
                // Check if UTXO is locked
                if let Some(utxo_info) = manager.get_utxo_info(&input.previous_output).await {
                    use crate::utxo_state_manager::UTXOState;
                    match utxo_info.state {
                        UTXOState::Locked { txid, .. } if txid != tx.txid => {
                            return Err(MempoolError::UTXOLocked(format!(
                                "UTXO {}:{} is locked by transaction {}",
                                input.previous_output.txid, input.previous_output.vout, txid
                            )));
                        }
                        UTXOState::SpentPending { txid, .. } if txid != tx.txid => {
                            return Err(MempoolError::UTXOLocked(format!(
                                "UTXO {}:{} is being spent by transaction {}",
                                input.previous_output.txid, input.previous_output.vout, txid
                            )));
                        }
                        UTXOState::SpentFinalized { txid, .. } => {
                            return Err(MempoolError::UTXOLocked(format!(
                                "UTXO {}:{} already spent by finalized transaction {}",
                                input.previous_output.txid, input.previous_output.vout, txid
                            )));
                        }
                        UTXOState::Confirmed { .. } => {
                            return Err(MempoolError::UTXOLocked(format!(
                                "UTXO {}:{} already confirmed as spent",
                                input.previous_output.txid, input.previous_output.vout
                            )));
                        }
                        _ => {} // Unspent or locked by this tx - OK
                    }
                }
            }
        }
        Ok(())
    }

    /// Lock UTXOs for a transaction (if state manager available)
    #[allow(dead_code)]
    async fn lock_transaction_utxos(&self, tx: &Transaction) -> Result<(), MempoolError> {
        if let Some(manager) = &self.utxo_state_manager {
            for input in &tx.inputs {
                manager
                    .lock_utxo(&input.previous_output, tx.txid.clone())
                    .await
                    .map_err(MempoolError::UTXOLocked)?;
            }
        }
        Ok(())
    }

    /// Unlock UTXOs for a transaction (when removing from mempool)
    async fn unlock_transaction_utxos(&self, tx: &Transaction) {
        if let Some(manager) = &self.utxo_state_manager {
            for input in &tx.inputs {
                let _ = manager.unlock_utxo(&input.previous_output).await;
            }
        }
    }

    /// Add a transaction to the mempool (async version with UTXO locking)
    pub async fn add_transaction_async(
        &mut self,
        tx: Transaction,
        utxo_set: &UTXOSet,
    ) -> Result<(), MempoolError> {
        // Check if mempool is full
        if self.transactions.len() >= self.max_size {
            return Err(MempoolError::MempoolFull);
        }

        // Check if transaction already exists
        if self.transactions.contains_key(&tx.txid) {
            return Err(MempoolError::DuplicateTransaction);
        }

        // Validate transaction structure
        tx.validate_structure()?;

        // Don't allow coinbase transactions in mempool
        if tx.is_coinbase() {
            return Err(MempoolError::InvalidTransaction);
        }

        // Check for conflicts with other mempool transactions
        for input in &tx.inputs {
            let output_key = format!(
                "{}:{}",
                input.previous_output.txid, input.previous_output.vout
            );
            if self.spent_outputs.contains(&output_key) {
                return Err(MempoolError::ConflictingTransaction);
            }
        }

        // Validate against UTXO set
        for input in &tx.inputs {
            if !utxo_set.contains(&input.previous_output) {
                return Err(MempoolError::InvalidTransaction);
            }
        }

        // Calculate fee per byte for priority
        let fee = tx.fee(utxo_set.utxos())?;
        let tx_size = serde_json::to_string(&tx).map(|s| s.len()).unwrap_or(1000);
        let fee_per_byte = fee / tx_size.max(1) as u64;

        // Add to mempool
        let mempool_tx = MempoolTransaction {
            transaction: tx.clone(),
            fee_per_byte,
            added_timestamp: chrono::Utc::now().timestamp(),
        };

        // Mark outputs as spent
        for input in &tx.inputs {
            let output_key = format!(
                "{}:{}",
                input.previous_output.txid, input.previous_output.vout
            );
            self.spent_outputs.insert(output_key);
        }

        self.transactions.insert(tx.txid.clone(), mempool_tx);

        Ok(())
    }

    /// Remove a transaction from the mempool (async version - unlocks UTXOs)
    pub async fn remove_transaction_async(&mut self, txid: &str) -> Option<Transaction> {
        if let Some(mempool_tx) = self.transactions.remove(txid) {
            // **NEW: Unlock UTXOs**
            self.unlock_transaction_utxos(&mempool_tx.transaction).await;

            // Unmark spent outputs
            for input in &mempool_tx.transaction.inputs {
                let output_key = format!(
                    "{}:{}",
                    input.previous_output.txid, input.previous_output.vout
                );
                self.spent_outputs.remove(&output_key);
            }
            return Some(mempool_tx.transaction);
        }
        None
    }

    /// Remove a transaction from the mempool (legacy sync version)
    pub fn remove_transaction(&mut self, txid: &str) -> Option<Transaction> {
        if let Some(mempool_tx) = self.transactions.remove(txid) {
            // Unmark spent outputs
            for input in &mempool_tx.transaction.inputs {
                let output_key = format!(
                    "{}:{}",
                    input.previous_output.txid, input.previous_output.vout
                );
                self.spent_outputs.remove(&output_key);
            }
            Some(mempool_tx.transaction)
        } else {
            None
        }
    }

    /// Get a transaction from the mempool
    pub fn get_transaction(&self, txid: &str) -> Option<&Transaction> {
        self.transactions.get(txid).map(|mt| &mt.transaction)
    }

    /// Get transactions ordered by fee (highest first)
    pub fn get_transactions_by_fee(&self, limit: usize) -> Vec<Transaction> {
        let mut txs: Vec<_> = self.transactions.values().collect();
        txs.sort_by(|a, b| {
            // Sort by fee per byte (descending), then by timestamp (ascending)
            b.fee_per_byte
                .cmp(&a.fee_per_byte)
                .then(a.added_timestamp.cmp(&b.added_timestamp))
        });

        txs.into_iter()
            .take(limit)
            .map(|mt| mt.transaction.clone())
            .collect()
    }

    /// Get all transactions
    pub fn get_all_transactions(&self) -> Vec<Transaction> {
        self.transactions
            .values()
            .map(|mt| mt.transaction.clone())
            .collect()
    }

    /// Get transactions for a specific address (appears in inputs or outputs)
    pub fn get_transactions_for_address(&self, address: &str) -> Vec<Transaction> {
        self.transactions
            .values()
            .filter(|mt| {
                // Check if address appears in any output
                mt.transaction
                    .outputs
                    .iter()
                    .any(|out| out.address == address)
            })
            .map(|mt| mt.transaction.clone())
            .collect()
    }

    /// Clear all transactions
    pub fn clear(&mut self) {
        self.transactions.clear();
        self.spent_outputs.clear();
    }

    /// Get mempool size
    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    /// Check if mempool is empty
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    /// Remove transactions that are now invalid (UTXOs spent in blockchain)
    pub fn remove_invalid_transactions(&mut self, utxo_set: &UTXOSet) -> Vec<String> {
        let mut removed = Vec::new();

        // Find transactions with invalid inputs
        let invalid_txids: Vec<String> = self
            .transactions
            .iter()
            .filter(|(_, mt)| {
                // Check if any input no longer exists in UTXO set
                mt.transaction
                    .inputs
                    .iter()
                    .any(|input| !utxo_set.contains(&input.previous_output))
            })
            .map(|(txid, _)| txid.clone())
            .collect();

        // Remove invalid transactions
        for txid in invalid_txids {
            if self.remove_transaction(&txid).is_some() {
                removed.push(txid);
            }
        }

        removed
    }

    /// Get mempool statistics
    pub fn get_stats(&self) -> MempoolStats {
        let total_fees: u64 = self
            .transactions
            .values()
            .map(|mt| {
                // Estimate fee based on fee_per_byte
                let size = serde_json::to_string(&mt.transaction)
                    .map(|s| s.len())
                    .unwrap_or(1000);
                mt.fee_per_byte * size as u64
            })
            .sum();

        MempoolStats {
            transaction_count: self.transactions.len(),
            total_fees,
            max_fee_per_byte: self
                .transactions
                .values()
                .map(|mt| mt.fee_per_byte)
                .max()
                .unwrap_or(0),
            min_fee_per_byte: self
                .transactions
                .values()
                .map(|mt| mt.fee_per_byte)
                .min()
                .unwrap_or(0),
        }
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

/// Mempool statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolStats {
    pub transaction_count: usize,
    pub total_fees: u64,
    pub max_fee_per_byte: u64,
    pub min_fee_per_byte: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{OutPoint, TxInput, TxOutput};

    #[test]
    fn test_mempool_creation() {
        let mempool = Mempool::new();
        assert_eq!(mempool.len(), 0);
        assert!(mempool.is_empty());
    }

    #[tokio::test]
    async fn test_add_transaction() {
        let mut mempool = Mempool::new();
        let mut utxo_set = UTXOSet::new();

        // Add UTXO for the transaction to spend
        let prev_outpoint = OutPoint::new("prev_tx".to_string(), 0);
        let prev_output = TxOutput::new(2000, "addr1".to_string());
        utxo_set.add_utxo(prev_outpoint.clone(), prev_output);

        // Create transaction
        let input = TxInput::new("prev_tx".to_string(), 0, vec![1, 2, 3], vec![4, 5, 6]);
        let output = TxOutput::new(1900, "addr2".to_string());
        let tx = Transaction::new(vec![input], vec![output]);

        // Add to mempool
        let result = mempool.add_transaction_async(tx.clone(), &utxo_set).await;
        assert!(result.is_ok());
        assert_eq!(mempool.len(), 1);
        assert!(mempool.get_transaction(&tx.txid).is_some());
    }

    #[tokio::test]
    async fn test_duplicate_transaction() {
        let mut mempool = Mempool::new();
        let mut utxo_set = UTXOSet::new();

        let prev_outpoint = OutPoint::new("prev_tx".to_string(), 0);
        let prev_output = TxOutput::new(2000, "addr1".to_string());
        utxo_set.add_utxo(prev_outpoint, prev_output);

        let input = TxInput::new("prev_tx".to_string(), 0, vec![1, 2, 3], vec![4, 5, 6]);
        let output = TxOutput::new(1900, "addr2".to_string());
        let tx = Transaction::new(vec![input], vec![output]);

        mempool
            .add_transaction_async(tx.clone(), &utxo_set)
            .await
            .unwrap();

        // Try to add same transaction again
        let result = mempool.add_transaction_async(tx, &utxo_set).await;
        assert!(matches!(result, Err(MempoolError::DuplicateTransaction)));
    }
}
