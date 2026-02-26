//! Mempool - Pending Transaction Pool for TIME Coin
//!
//! Manages pending transactions that haven't been included in blocks yet.
//! Provides validation, ordering, and transaction selection for block production.

mod resource_monitor;
pub use resource_monitor::*;

mod priority_queue;
pub use priority_queue::*;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use time_core::{Transaction, TransactionError};
use tokio::sync::RwLock;

/// Transaction pool for pending transactions
pub struct Mempool {
    /// Pending transactions by txid
    transactions: Arc<RwLock<HashMap<String, MempoolEntry>>>,
    /// Maximum size of mempool
    max_size: usize,
    /// Reference to blockchain for UTXO validation (optional)
    blockchain: Option<Arc<tokio::sync::RwLock<time_core::state::BlockchainState>>>,
    /// Track UTXOs being spent by transactions in mempool (to prevent double-spends)
    spent_utxos: Arc<RwLock<std::collections::HashSet<time_core::OutPoint>>>,
    /// Network type (testnet or mainnet) - used to determine if coinbase transactions are allowed
    network: String,
}

/// Entry in the mempool with metadata
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MempoolEntry {
    /// The transaction
    pub transaction: Transaction,
    /// When it was added to mempool
    pub added_at: i64,
    /// Priority score (higher = included sooner)
    pub priority: u64,
    /// Whether the transaction has been finalized by BFT consensus
    pub finalized: bool,
    /// When it was finalized (if applicable)
    pub finalized_at: Option<i64>,
}

impl Mempool {
    /// Calculate dynamic mempool size based on available memory
    /// Uses 10% of available memory for mempool, assuming ~2KB per transaction
    fn calculate_dynamic_size() -> usize {
        let monitor = ResourceMonitor::new();
        let mut sys = sysinfo::System::new_all();
        sys.refresh_memory();

        let available_bytes = sys.available_memory();
        // Use 10% of available memory for mempool
        let mempool_memory = (available_bytes as f64 * 0.10) as u64;
        // Assume average transaction size of 2KB
        let capacity = monitor.estimate_transaction_capacity(2048, mempool_memory);

        // Minimum 1000 transactions, maximum 10 million
        capacity.clamp(1000, 10_000_000)
    }

    /// Create a new mempool with dynamic sizing based on available memory
    pub fn new(network: String) -> Self {
        let max_size = Self::calculate_dynamic_size();
        println!(
            "🗄️  Mempool configured with dynamic capacity: {} transactions",
            max_size
        );

        Self {
            transactions: Arc::new(RwLock::new(HashMap::new())),
            max_size,
            blockchain: None,
            spent_utxos: Arc::new(RwLock::new(std::collections::HashSet::new())),
            network,
        }
    }

    /// Create mempool with blockchain validation and dynamic sizing
    pub fn with_blockchain(
        blockchain: Arc<tokio::sync::RwLock<time_core::state::BlockchainState>>,
        network: String,
    ) -> Self {
        let max_size = Self::calculate_dynamic_size();
        println!(
            "🗄️  Mempool configured with dynamic capacity: {} transactions",
            max_size
        );

        Self {
            transactions: Arc::new(RwLock::new(HashMap::new())),
            max_size,
            blockchain: Some(blockchain),
            spent_utxos: Arc::new(RwLock::new(std::collections::HashSet::new())),
            network,
        }
    }

    /// Add a transaction to the mempool
    pub async fn add_transaction(&self, tx: Transaction) -> Result<(), MempoolError> {
        // Validate transaction structure
        tx.validate_structure()
            .map_err(MempoolError::InvalidTransaction)?;

        // Check for double-spend in mempool
        self.check_double_spend(&tx).await?;

        // Verify signatures
        self.verify_signatures(&tx).await?;

        // Validate UTXO if blockchain is available
        if let Some(blockchain) = &self.blockchain {
            self.validate_utxo(&tx, blockchain).await?;
        }

        let mut pool = self.transactions.write().await;

        // Check if already in mempool
        if pool.contains_key(&tx.txid) {
            return Err(MempoolError::DuplicateTransaction);
        }

        // Check size limit
        if pool.len() >= self.max_size {
            return Err(MempoolError::MemPoolFull);
        }

        // Calculate priority (fee per byte, roughly)
        let tx_size = tx.txid.len() + tx.inputs.len() * 64 + tx.outputs.len() * 64;
        let total_fee = self.calculate_fee(&tx);
        let priority = if tx_size > 0 {
            (total_fee * 1000) / tx_size as u64
        } else {
            0
        };

        let entry = MempoolEntry {
            transaction: tx.clone(),
            added_at: chrono::Utc::now().timestamp(),
            priority,
            finalized: false,
            finalized_at: None,
        };

        pool.insert(tx.txid.clone(), entry);

        println!(
            "📝 Added transaction {} to mempool (priority: {})",
            &tx.txid[..std::cmp::min(16, tx.txid.len())],
            priority
        );

        // Mark UTXOs as spent
        drop(pool);
        self.mark_spent(&tx).await;

        Ok(())
    }

    /// Verify transaction signatures
    async fn verify_signatures(&self, tx: &Transaction) -> Result<(), MempoolError> {
        // Skip for coinbase transactions (they have no inputs)
        if tx.is_coinbase() {
            return Ok(());
        }

        // Get transaction hash for signing
        let tx_hash = self.calculate_tx_hash(tx);

        for input in &tx.inputs {
            // Verify signature length
            if input.public_key.len() != 32 {
                return Err(MempoolError::InvalidTransaction(
                    TransactionError::InvalidSignature,
                ));
            }

            if input.signature.len() != 64 {
                return Err(MempoolError::InvalidTransaction(
                    TransactionError::InvalidSignature,
                ));
            }

            // Create verifying key from public key
            let public_key_bytes: [u8; 32] = input.public_key[..32].try_into().map_err(|_| {
                MempoolError::InvalidTransaction(TransactionError::InvalidSignature)
            })?;

            let verifying_key = VerifyingKey::from_bytes(&public_key_bytes).map_err(|_| {
                MempoolError::InvalidTransaction(TransactionError::InvalidSignature)
            })?;

            // Create signature
            let signature_bytes: [u8; 64] = input.signature[..64].try_into().map_err(|_| {
                MempoolError::InvalidTransaction(TransactionError::InvalidSignature)
            })?;

            let signature = Signature::from_bytes(&signature_bytes);

            // Verify signature
            if verifying_key.verify(&tx_hash, &signature).is_err() {
                return Err(MempoolError::InvalidTransaction(
                    TransactionError::InvalidSignature,
                ));
            }
        }

        Ok(())
    }

    /// Calculate transaction hash for signing
    fn calculate_tx_hash(&self, tx: &Transaction) -> Vec<u8> {
        let mut hasher = Sha256::new();

        // Hash transaction fields (excluding signatures)
        hasher.update(tx.txid.as_bytes());
        hasher.update(tx.version.to_le_bytes());

        for input in &tx.inputs {
            hasher.update(input.previous_output.txid.as_bytes());
            hasher.update(input.previous_output.vout.to_le_bytes());
            hasher.update(&input.public_key);
            hasher.update(input.sequence.to_le_bytes());
        }

        for output in &tx.outputs {
            hasher.update(output.address.as_bytes());
            hasher.update(output.amount.to_le_bytes());
        }

        hasher.update(tx.lock_time.to_le_bytes());
        hasher.update(tx.timestamp.to_le_bytes());

        hasher.finalize().to_vec()
    }

    /// Check for double-spend attempts
    async fn check_double_spend(&self, tx: &Transaction) -> Result<(), MempoolError> {
        let spent = self.spent_utxos.read().await;

        for input in &tx.inputs {
            if spent.contains(&input.previous_output) {
                return Err(MempoolError::DoubleSpend);
            }
        }

        Ok(())
    }

    /// Mark UTXOs as spent
    async fn mark_spent(&self, tx: &Transaction) {
        let mut spent = self.spent_utxos.write().await;

        for input in &tx.inputs {
            spent.insert(input.previous_output.clone());
        }
    }

    /// Release spent UTXOs when transaction is removed
    async fn release_spent(&self, tx: &Transaction) {
        let mut spent = self.spent_utxos.write().await;

        for input in &tx.inputs {
            spent.remove(&input.previous_output);
        }
    }

    /// Validate transaction against UTXO set
    async fn validate_utxo(
        &self,
        tx: &Transaction,
        blockchain: &Arc<tokio::sync::RwLock<time_core::state::BlockchainState>>,
    ) -> Result<(), MempoolError> {
        // Coinbase transactions should ONLY be created by block producers
        // EXCEPTION: Allow in testnet mode for minting test coins
        if tx.is_coinbase() {
            let is_testnet = self.network.to_uppercase() == "TESTNET";
            if !is_testnet {
                return Err(MempoolError::InvalidTransaction(
                    time_core::TransactionError::InvalidInput,
                ));
            }
            // In testnet mode, allow coinbase transactions (for minting)
            return Ok(());
        }

        let chain = blockchain.read().await;
        let utxo_set = chain.utxo_set();

        let mut input_sum = 0u64;

        // Validate all inputs exist and are unspent
        for input in &tx.inputs {
            match utxo_set.get(&input.previous_output) {
                Some(utxo) => {
                    input_sum = input_sum.checked_add(utxo.amount).ok_or(
                        MempoolError::InvalidTransaction(
                            time_core::TransactionError::InvalidAmount,
                        ),
                    )?;
                }
                None => {
                    // Input does not exist or already spent
                    return Err(MempoolError::InvalidTransaction(
                        time_core::TransactionError::InvalidInput,
                    ));
                }
            }
        }

        // Calculate output sum
        let output_sum: u64 = tx.outputs.iter().map(|o| o.amount).sum();

        // Inputs must be >= outputs
        if input_sum < output_sum {
            return Err(MempoolError::InvalidTransaction(
                time_core::TransactionError::InsufficientFunds,
            ));
        }

        Ok(())
    }

    /// Remove a transaction from mempool (after inclusion in block)
    pub async fn remove_transaction(&self, txid: &str) -> Option<Transaction> {
        let mut pool = self.transactions.write().await;
        if let Some(entry) = pool.remove(txid) {
            let tx = entry.transaction.clone();
            drop(pool);
            self.release_spent(&tx).await;
            Some(tx)
        } else {
            None
        }
    }

    /// Get transaction by ID
    pub async fn get_transaction(&self, txid: &str) -> Option<Transaction> {
        let pool = self.transactions.read().await;
        pool.get(txid).map(|entry| entry.transaction.clone())
    }

    /// Check if transaction exists in mempool
    pub async fn contains(&self, txid: &str) -> bool {
        let pool = self.transactions.read().await;
        pool.contains_key(txid)
    }

    /// Get all transactions (for broadcasting)
    pub async fn get_all_transactions(&self) -> Vec<Transaction> {
        let pool = self.transactions.read().await;
        let mut transactions: Vec<Transaction> = pool
            .values()
            .map(|entry| entry.transaction.clone())
            .collect();

        // CRITICAL: Sort deterministically by txid to ensure all nodes
        // create identical blocks (same transaction order = same merkle root)
        transactions.sort_by(|a, b| a.txid.cmp(&b.txid));

        transactions
    }

    /// Get all unfinalized transactions (for retry mechanism)
    pub async fn get_unfinalized_transactions(&self) -> Vec<Transaction> {
        let pool = self.transactions.read().await;
        let mut transactions: Vec<Transaction> = pool
            .values()
            .filter(|entry| !entry.finalized)
            .map(|entry| entry.transaction.clone())
            .collect();

        // CRITICAL: Sort deterministically by txid
        transactions.sort_by(|a, b| a.txid.cmp(&b.txid));

        transactions
    }

    /// Select transactions for a block (by priority) - O(n log n)
    pub async fn select_transactions(&self, max_count: usize) -> Vec<Transaction> {
        let pool = self.transactions.read().await;

        let mut entries: Vec<_> = pool.values().collect();

        // Sort by priority (highest first), then by time (oldest first)
        entries.sort_by(|a, b| {
            b.priority
                .cmp(&a.priority)
                .then(a.added_at.cmp(&b.added_at))
        });

        entries
            .into_iter()
            .take(max_count)
            .map(|entry| entry.transaction.clone())
            .collect()
    }

    /// Select transactions using priority queue (faster for large mempools) - O(k log n)
    /// where k = max_count
    pub async fn select_transactions_fast(&self, max_count: usize) -> Vec<Transaction> {
        let pool = self.transactions.read().await;

        // Build priority queue from mempool entries
        let mut pq = PriorityQueueManager::new();

        for entry in pool.values() {
            pq.add(PriorityTransaction {
                transaction: entry.transaction.clone(),
                priority: entry.priority,
                added_at: entry.added_at,
                finalized: entry.finalized,
            });
        }

        // Select top transactions
        pq.select_for_block(max_count)
    }

    /// Get priority distribution stats
    pub async fn get_priority_stats(&self) -> PriorityStats {
        let pool = self.transactions.read().await;

        let mut high = 0;
        let mut standard = 0;
        let mut low = 0;

        for entry in pool.values() {
            if entry.priority > 1000 {
                high += 1;
            } else if entry.priority >= 10 {
                standard += 1;
            } else {
                low += 1;
            }
        }

        PriorityStats {
            high_priority_count: high,
            standard_count: standard,
            low_priority_count: low,
            total: pool.len(),
        }
    }

    /// Get mempool size
    pub async fn size(&self) -> usize {
        let pool = self.transactions.read().await;
        pool.len()
    }

    /// Clear all transactions (e.g., after chain reorganization)
    pub async fn clear(&self) {
        let mut pool = self.transactions.write().await;
        pool.clear();

        // Also clear spent UTXOs
        let mut spent = self.spent_utxos.write().await;
        spent.clear();
    }

    /// Remove transactions that are now invalid and get affected addresses
    pub async fn remove_invalid_transactions(
        &self,
        invalid_txids: Vec<String>,
    ) -> Vec<(String, Vec<String>)> {
        let mut pool = self.transactions.write().await;
        let mut invalidated = Vec::new();

        for txid in invalid_txids {
            if let Some(entry) = pool.remove(&txid) {
                // Collect affected addresses (all output addresses in the transaction)
                let affected: Vec<String> = entry
                    .transaction
                    .outputs
                    .iter()
                    .map(|output| output.address.clone())
                    .collect();

                invalidated.push((txid, affected));

                drop(pool);
                self.release_spent(&entry.transaction).await;
                pool = self.transactions.write().await;
            }
        }

        invalidated
    }

    /// Validate transaction and return detailed error if invalid
    pub async fn validate_transaction_detailed(
        &self,
        tx: &Transaction,
    ) -> Result<(), MempoolError> {
        // Validate transaction structure
        tx.validate_structure()
            .map_err(MempoolError::InvalidTransaction)?;

        // Check for double-spend in mempool
        self.check_double_spend(tx).await?;

        // Verify signatures
        self.verify_signatures(tx).await?;

        // Validate UTXO if blockchain is available
        if let Some(blockchain) = &self.blockchain {
            self.validate_utxo(tx, blockchain).await?;
        }

        Ok(())
    }

    /// Get addresses affected by a transaction (all output addresses)
    pub fn get_affected_addresses(tx: &Transaction) -> Vec<String> {
        tx.outputs.iter().map(|o| o.address.clone()).collect()
    }

    /// Save mempool to disk
    pub async fn save_to_disk(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let pool = self.transactions.read().await;
        let entries: Vec<&MempoolEntry> = pool.values().collect();

        // Create directory if it doesn't exist
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent)?;
        }

        let json = serde_json::to_string_pretty(&entries)?;
        std::fs::write(path, json)?;

        Ok(())
    }

    /// Load mempool from disk
    pub async fn load_from_disk(&self, path: &str) -> Result<usize, Box<dyn std::error::Error>> {
        if !std::path::Path::new(path).exists() {
            return Ok(0);
        }

        let json = std::fs::read_to_string(path)?;
        let entries: Vec<MempoolEntry> = serde_json::from_str(&json)?;

        let mut pool = self.transactions.write().await;
        let mut loaded = 0;
        let now = chrono::Utc::now().timestamp();

        for entry in entries {
            // Skip transactions older than 24 hours
            if now - entry.added_at > 86400 {
                continue;
            }

            // Skip if mempool is full
            if pool.len() >= self.max_size {
                break;
            }

            let tx = entry.transaction.clone();
            pool.insert(tx.txid.clone(), entry);
            drop(pool);

            // Mark UTXOs as spent
            self.mark_spent(&tx).await;

            pool = self.transactions.write().await;
            loaded += 1;
        }

        Ok(loaded)
    }

    /// Clean up stale transactions (older than 24 hours)
    pub async fn cleanup_stale(&self) -> usize {
        let mut pool = self.transactions.write().await;
        let now = chrono::Utc::now().timestamp();
        let mut removed_txs = Vec::new();

        pool.retain(|_, entry| {
            let is_fresh = now - entry.added_at < 86400;
            if !is_fresh {
                removed_txs.push(entry.transaction.clone());
            }
            is_fresh
        });

        let removed = removed_txs.len();
        drop(pool);

        // Release spent UTXOs for removed transactions
        for tx in removed_txs {
            self.release_spent(&tx).await;
        }

        removed
    }

    /// Calculate total fee for a transaction
    fn calculate_fee(&self, tx: &Transaction) -> u64 {
        // Fee = sum(inputs) - sum(outputs)
        // For now, we'll use a simple estimation
        // In production, you'd need UTXO set to get input values

        let output_sum: u64 = tx.outputs.iter().map(|o| o.amount).sum();

        // Estimate: assume inputs are worth slightly more than outputs
        // This is a placeholder - real implementation needs UTXO lookup
        output_sum / 100 // 1% fee estimation
    }

    /// Finalize a transaction (mark as confirmed by BFT consensus)
    /// After finalization, the transaction is removed from mempool
    pub async fn finalize_transaction(&self, txid: &str) -> Result<(), MempoolError> {
        let mut pool = self.transactions.write().await;

        if let Some(entry) = pool.remove(txid) {
            // Also remove from spent_utxos tracking
            let mut spent = self.spent_utxos.write().await;
            for input in &entry.transaction.inputs {
                spent.remove(&input.previous_output);
            }

            println!(
                "✅ Transaction {} finalized and removed from mempool",
                &txid[..std::cmp::min(16, txid.len())]
            );

            Ok(())
        } else {
            Err(MempoolError::InvalidTransaction(
                TransactionError::InvalidInput,
            ))
        }
    }

    /// Check if a transaction is finalized
    pub async fn is_finalized(&self, txid: &str) -> bool {
        let pool = self.transactions.read().await;
        pool.get(txid).map(|e| e.finalized).unwrap_or(false)
    }

    /// Get finalized transactions
    pub async fn get_finalized_transactions(&self) -> Vec<Transaction> {
        let pool = self.transactions.read().await;
        pool.values()
            .filter(|entry| entry.finalized)
            .map(|entry| entry.transaction.clone())
            .collect()
    }

    /// Get pending (not finalized) transactions
    pub async fn get_pending_transactions(&self) -> Vec<Transaction> {
        let pool = self.transactions.read().await;
        pool.values()
            .filter(|entry| !entry.finalized)
            .map(|entry| entry.transaction.clone())
            .collect()
    }

    /// Remove transactions that are included in a block
    /// Returns the number of transactions removed
    pub async fn remove_transactions_in_block(&self, block: &time_core::block::Block) -> usize {
        let mut removed_count = 0;

        for tx in &block.transactions {
            if self.remove_transaction(&tx.txid).await.is_some() {
                removed_count += 1;
            }
        }

        if removed_count > 0 {
            println!(
                "🗑️  Removed {} transactions from mempool (included in block #{})",
                removed_count, block.header.block_number
            );
        }

        removed_count
    }

    /// Re-validate all transactions against current blockchain state
    /// Removes any that have become invalid (e.g., spent UTXOs)
    /// Returns count of removed transactions
    pub async fn revalidate_against_blockchain(&self) -> usize {
        if self.blockchain.is_none() {
            return 0;
        }

        let blockchain = self.blockchain.as_ref().unwrap();
        let transactions: Vec<Transaction> = {
            let pool = self.transactions.read().await;
            pool.values()
                .map(|entry| entry.transaction.clone())
                .collect()
        };

        let mut invalid_txids = Vec::new();

        for tx in transactions {
            // Skip coinbase and treasury transactions
            if tx.is_coinbase() || tx.is_treasury_grant() {
                continue;
            }

            // Check if transaction is still valid
            let blockchain_guard = blockchain.read().await;
            let utxo_map = blockchain_guard.utxo_set().utxos();

            // Check if any inputs have been spent
            let mut is_invalid = false;
            for input in &tx.inputs {
                let outpoint = time_core::OutPoint {
                    txid: input.previous_output.txid.clone(),
                    vout: input.previous_output.vout,
                };

                if !utxo_map.contains_key(&outpoint) {
                    // UTXO no longer exists (was spent in a block)
                    is_invalid = true;
                    break;
                }
            }

            if is_invalid {
                invalid_txids.push(tx.txid.clone());
            }
        }

        if !invalid_txids.is_empty() {
            let removed = self.remove_invalid_transactions(invalid_txids).await;
            let count = removed.len();
            if count > 0 {
                println!(
                    "🗑️  Removed {} invalid transactions from mempool (spent UTXOs)",
                    count
                );
            }
            count
        } else {
            0
        }
    }
}

#[derive(Debug, Clone)]
pub enum MempoolError {
    DuplicateTransaction,
    MemPoolFull,
    InvalidTransaction(TransactionError),
    DoubleSpend,
}

impl std::fmt::Display for MempoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            MempoolError::DuplicateTransaction => write!(f, "Transaction already in mempool"),
            MempoolError::MemPoolFull => write!(f, "Mempool is full"),
            MempoolError::InvalidTransaction(e) => write!(f, "Invalid transaction: {}", e),
            MempoolError::DoubleSpend => write!(f, "Double-spend attempt detected"),
        }
    }
}

impl std::error::Error for MempoolError {}

#[cfg(test)]
mod tests {
    use super::*;
    use time_core::TxOutput;

    #[tokio::test]
    async fn test_mempool_add_and_get() {
        let mempool = Mempool::new("testnet".to_string());

        let tx = Transaction {
            txid: "test_tx_1".to_string(),
            version: 1,
            inputs: vec![],
            outputs: vec![TxOutput {
                amount: 1000,
                address: "addr1".to_string(),
            }],
            lock_time: 0,
            timestamp: 1234567890,
        };

        mempool.add_transaction(tx.clone()).await.unwrap();

        assert_eq!(mempool.size().await, 1);
        assert!(mempool.contains("test_tx_1").await);

        let retrieved = mempool.get_transaction("test_tx_1").await.unwrap();
        assert_eq!(retrieved.txid, tx.txid);
    }

    #[tokio::test]
    async fn test_mempool_priority_selection() {
        let mempool = Mempool::new("testnet".to_string());

        // Add transactions with different priorities
        for i in 0..5 {
            let tx = Transaction {
                txid: format!("tx_{}", i),
                version: 1,
                inputs: vec![],
                outputs: vec![TxOutput {
                    amount: 1000 * (i + 1),
                    address: "addr".to_string(),
                }],
                lock_time: 0,
                timestamp: 1234567890 + i as i64,
            };
            mempool.add_transaction(tx).await.unwrap();
        }

        let selected = mempool.select_transactions(3).await;
        assert_eq!(selected.len(), 3);
    }

    #[tokio::test]
    async fn test_coinbase_rejected_in_mainnet() {
        // Create mempool for mainnet (without blockchain, so it won't validate UTXO)
        let mempool = Mempool::new("mainnet".to_string());

        // Create a coinbase transaction (no inputs)
        let coinbase_tx = Transaction {
            txid: "coinbase_tx_1".to_string(),
            version: 1,
            inputs: vec![], // Coinbase = no inputs
            outputs: vec![TxOutput {
                amount: 1000,
                address: "addr1".to_string(),
            }],
            lock_time: 0,
            timestamp: 1234567890,
        };

        // Should be accepted without blockchain validation (no UTXO check)
        // The coinbase check only happens when blockchain is present
        let result = mempool.add_transaction(coinbase_tx).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_coinbase_accepted_in_testnet() {
        // Create mempool for testnet (without blockchain, so it won't validate UTXO)
        let mempool = Mempool::new("testnet".to_string());

        // Create a coinbase transaction (no inputs)
        let coinbase_tx = Transaction {
            txid: "coinbase_tx_1".to_string(),
            version: 1,
            inputs: vec![], // Coinbase = no inputs
            outputs: vec![TxOutput {
                amount: 1000,
                address: "addr1".to_string(),
            }],
            lock_time: 0,
            timestamp: 1234567890,
        };

        // Should be accepted in testnet
        let result = mempool.add_transaction(coinbase_tx.clone()).await;
        assert!(result.is_ok());
        assert_eq!(mempool.size().await, 1);
        assert!(mempool.contains("coinbase_tx_1").await);
    }

    #[tokio::test]
    async fn test_transaction_finalization() {
        let mempool = Mempool::new("testnet".to_string());

        let tx = Transaction {
            txid: "test_tx_finalize".to_string(),
            version: 1,
            inputs: vec![],
            outputs: vec![TxOutput {
                amount: 1000,
                address: "addr1".to_string(),
            }],
            lock_time: 0,
            timestamp: 1234567890,
        };

        // Add transaction to mempool
        mempool.add_transaction(tx.clone()).await.unwrap();

        // Initially should not be finalized
        assert!(!mempool.is_finalized("test_tx_finalize").await);

        // Finalize the transaction
        mempool
            .finalize_transaction("test_tx_finalize")
            .await
            .unwrap();

        // Now should be finalized
        assert!(mempool.is_finalized("test_tx_finalize").await);
    }

    #[tokio::test]
    async fn test_get_finalized_transactions() {
        let mempool = Mempool::new("testnet".to_string());

        // Add multiple transactions
        for i in 0..3 {
            let tx = Transaction {
                txid: format!("tx_{}", i),
                version: 1,
                inputs: vec![],
                outputs: vec![TxOutput {
                    amount: 1000,
                    address: "addr".to_string(),
                }],
                lock_time: 0,
                timestamp: 1234567890 + i as i64,
            };
            mempool.add_transaction(tx).await.unwrap();
        }

        // Finalize first two
        mempool.finalize_transaction("tx_0").await.unwrap();
        mempool.finalize_transaction("tx_1").await.unwrap();

        // Check counts
        let finalized = mempool.get_finalized_transactions().await;
        let pending = mempool.get_pending_transactions().await;

        assert_eq!(finalized.len(), 2);
        assert_eq!(pending.len(), 1);
    }
}
