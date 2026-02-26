//! Hybrid masternode client - wraps MasternodeClient with JSON-RPC
//!
//! This client delegates all operations to the JSON-RPC MasternodeClient.
//! The "hybrid" name is kept for backward compatibility with the rest of the codebase.

use crate::masternode_client::{Balance, ClientError, MasternodeClient, TransactionRecord, Utxo};

pub struct HybridMasternodeClient {
    client: MasternodeClient,
}

impl HybridMasternodeClient {
    pub fn new(endpoint: String, _network: wallet::NetworkType) -> Self {
        Self {
            client: MasternodeClient::new(endpoint),
        }
    }

    /// Get balance for an address
    pub async fn get_balance(&self, address: &str) -> Result<Balance, ClientError> {
        self.client.get_balance(address).await
    }

    /// Get transactions
    pub async fn get_transactions(
        &self,
        address: &str,
        limit: u32,
    ) -> Result<Vec<TransactionRecord>, ClientError> {
        self.client.get_transactions(address, limit).await
    }

    /// Get UTXOs for an address
    pub async fn get_utxos(&self, address: &str) -> Result<Vec<Utxo>, ClientError> {
        self.client.get_utxos(address).await
    }

    /// Broadcast transaction
    pub async fn broadcast_transaction(&self, tx_hex: &str) -> Result<String, ClientError> {
        self.client.broadcast_transaction(tx_hex).await
    }

    /// Health check
    pub async fn health_check(
        &self,
    ) -> Result<crate::masternode_client::HealthStatus, ClientError> {
        self.client.health_check().await
    }
}
