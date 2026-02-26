//! Transaction Synchronization for Block Proposals
//!
//! When a block is proposed and nodes have different mempools, this module
//! handles:
//! 1. Requesting missing transactions from peers
//! 2. Validating received transactions
//! 3. Rejecting invalid transactions (double spend, etc.)
//! 4. Notifying wallets of rejected transactions

use crate::protocol::NetworkMessage;
use crate::PeerManager;
use std::collections::HashSet;
use std::sync::Arc;
use time_core::transaction::Transaction;
use time_mempool::Mempool;
use tokio::sync::RwLock;

pub struct TransactionSyncManager {
    peer_manager: Arc<PeerManager>,
    mempool: Arc<Mempool>,
    blockchain: Arc<RwLock<time_core::state::BlockchainState>>,
}

impl TransactionSyncManager {
    pub fn new(
        peer_manager: Arc<PeerManager>,
        mempool: Arc<Mempool>,
        blockchain: Arc<RwLock<time_core::state::BlockchainState>>,
    ) -> Self {
        Self {
            peer_manager,
            mempool,
            blockchain,
        }
    }

    /// Request missing transactions from peers for block proposal
    pub async fn request_missing_transactions(
        &self,
        txids: Vec<String>,
        block_height: u64,
        requester: String,
    ) -> Result<Vec<Transaction>, String> {
        if txids.is_empty() {
            return Ok(Vec::new());
        }

        println!(
            "📡 Requesting {} missing transactions for block #{}",
            txids.len(),
            block_height
        );

        let message = NetworkMessage::RequestMissingTransactions {
            txids: txids.clone(),
            requester,
            block_height,
        };

        // Broadcast request to all peers
        self.peer_manager.broadcast_message(message).await;

        // Wait for responses (with timeout)
        let timeout = tokio::time::Duration::from_secs(5);
        let mut collected = Vec::new();
        let mut received_txids = HashSet::new();

        let start = tokio::time::Instant::now();
        while start.elapsed() < timeout && received_txids.len() < txids.len() {
            // Check mempool for newly added transactions
            for txid in &txids {
                if !received_txids.contains(txid) {
                    if let Some(tx) = self.mempool.get_transaction(txid).await {
                        collected.push(tx);
                        received_txids.insert(txid.clone());
                    }
                }
            }

            if received_txids.len() >= txids.len() {
                break;
            }

            // Small delay before next check
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }

        println!(
            "✅ Received {}/{} missing transactions",
            collected.len(),
            txids.len()
        );

        Ok(collected)
    }

    /// Handle incoming request for missing transactions
    pub async fn handle_missing_tx_request(
        &self,
        txids: Vec<String>,
        requester: String,
        block_height: u64,
    ) -> Result<(), String> {
        println!(
            "📨 Received request for {} transactions from {} (block #{})",
            txids.len(),
            requester,
            block_height
        );

        let mut transactions = Vec::new();

        // Collect requested transactions from mempool
        for txid in &txids {
            if let Some(tx) = self.mempool.get_transaction(txid).await {
                transactions.push(tx);
            } else {
                println!("⚠️  Transaction {} not found in mempool", &txid[..16]);
            }
        }

        if transactions.is_empty() {
            println!("❌ No matching transactions found");
            return Ok(());
        }

        println!(
            "📤 Sending {} transactions to {}",
            transactions.len(),
            requester
        );

        // Send response directly to requester
        let response = NetworkMessage::MissingTransactionsResponse {
            transactions,
            block_height,
        };

        // Parse requester IP and send message
        if let Ok(addr) = format!("{}:24100", requester).parse() {
            if let Err(e) = self.peer_manager.send_message_to_peer(addr, response).await {
                println!("⚠️  Failed to send transactions to {}: {}", requester, e);
            }
        }

        Ok(())
    }

    /// Handle incoming missing transactions response
    pub async fn handle_missing_tx_response(
        &self,
        transactions: Vec<Transaction>,
        block_height: u64,
    ) -> Result<(), String> {
        println!(
            "📨 Received {} transactions for block #{}",
            transactions.len(),
            block_height
        );

        let mut added = 0;
        let mut rejected = 0;

        for tx in transactions {
            // Validate transaction
            match self.validate_transaction(&tx).await {
                Ok(()) => {
                    // Add to mempool
                    match self.mempool.add_transaction(tx.clone()).await {
                        Ok(_) => {
                            println!("   ✅ Added transaction {}", &tx.txid[..16]);
                            added += 1;
                        }
                        Err(e) => {
                            println!("   ❌ Failed to add transaction {}: {}", &tx.txid[..16], e);
                            self.reject_transaction(tx, format!("Mempool add failed: {}", e))
                                .await;
                            rejected += 1;
                        }
                    }
                }
                Err(reason) => {
                    println!("   ❌ Invalid transaction {}: {}", &tx.txid[..16], reason);
                    self.reject_transaction(tx, reason).await;
                    rejected += 1;
                }
            }
        }

        println!(
            "✅ Transaction sync complete: {} added, {} rejected",
            added, rejected
        );

        Ok(())
    }

    /// Validate a transaction before adding to mempool
    async fn validate_transaction(&self, tx: &Transaction) -> Result<(), String> {
        let blockchain = self.blockchain.read().await;
        let utxo_set = blockchain.utxo_set();

        // Check for double spend
        for input in &tx.inputs {
            if !utxo_set.contains(&input.previous_output) {
                return Err(format!(
                    "double_spend:{}:{}",
                    &input.previous_output.txid[..16],
                    input.previous_output.vout
                ));
            }
        }

        // Build UTXO map for signature verification
        let mut utxo_map = std::collections::HashMap::new();
        for input in &tx.inputs {
            if let Some(output) = utxo_set.get(&input.previous_output) {
                utxo_map.insert(input.previous_output.clone(), output.clone());
            }
        }

        // Verify signatures
        if let Err(e) = tx.verify_signatures(&utxo_map) {
            return Err(format!("invalid_signature:{}", e));
        }

        // Check amounts
        let input_sum: u64 = tx
            .inputs
            .iter()
            .filter_map(|input| utxo_set.get(&input.previous_output).map(|utxo| utxo.amount))
            .sum();

        let output_sum: u64 = tx.outputs.iter().map(|o| o.amount).sum();

        if output_sum > input_sum {
            return Err("invalid_amount:outputs_exceed_inputs".to_string());
        }

        Ok(())
    }

    /// Reject a transaction and notify the sender's wallet
    async fn reject_transaction(&self, tx: Transaction, reason: String) {
        println!("🚫 Rejecting transaction {}: {}", &tx.txid[..16], reason);

        // Extract wallet address from first output (sender)
        if let Some(output) = tx.outputs.first() {
            let wallet_address = output.address.clone();

            let rejection = NetworkMessage::TransactionRejection {
                txid: tx.txid.clone(),
                reason: reason.clone(),
                wallet_address: wallet_address.clone(),
            };

            // Broadcast rejection to all peers (they'll notify connected wallets)
            self.peer_manager.broadcast_message(rejection).await;

            println!(
                "📨 Rejection notification sent for wallet: {}",
                wallet_address
            );
        }
    }

    /// Handle transaction rejection notification
    pub async fn handle_transaction_rejection(
        &self,
        txid: String,
        reason: String,
        wallet_address: String,
    ) {
        println!(
            "🚫 Transaction {} rejected: {} (wallet: {})",
            &txid[..16],
            reason,
            wallet_address
        );

        // Remove from mempool if present
        if self.mempool.remove_transaction(&txid).await.is_some() {
            println!("   ✅ Removed rejected transaction from mempool");
        }

        // Wallet notification happens automatically via the wallet_sync notification system
        // when the wallet queries for its transactions and sees the rejection
    }
}
