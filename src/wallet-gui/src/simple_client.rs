//! Simple async client for TIME wallet GUI
//!
//! Wraps the JSON-RPC MasternodeClient for simple wallet operations.

use crate::masternode_client::MasternodeClient;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct SimpleClient {
    client: MasternodeClient,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TransactionRecord {
    pub tx_hash: String,
    pub from_address: String,
    pub to_address: String,
    pub amount: u64,
    pub timestamp: i64,
    pub block_height: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Balance {
    pub confirmed: u64,
    pub pending: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UtxoInfo {
    pub txid: String,
    pub vout: u32,
    pub address: String,
    pub amount: u64,
    pub block_height: Option<u64>,
    pub confirmations: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("Network error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Timeout")]
    Timeout,

    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    #[error("RPC error: {0}")]
    Rpc(String),
}

pub type Result<T> = std::result::Result<T, ClientError>;

impl SimpleClient {
    /// Create a new client pointing to a masternode RPC endpoint
    pub fn new(masternode_addr: String, _network: wallet::NetworkType) -> Self {
        Self {
            client: MasternodeClient::new(masternode_addr),
        }
    }

    /// Get transaction history for an address
    pub async fn get_transactions(&self, address: &str) -> Result<Vec<TransactionRecord>> {
        let txs = self
            .client
            .get_transactions(address, 100)
            .await
            .map_err(|e| ClientError::Rpc(e.to_string()))?;

        let records = txs
            .into_iter()
            .map(|tx| TransactionRecord {
                tx_hash: tx.txid,
                from_address: tx.from.first().cloned().unwrap_or_default(),
                to_address: tx.to.first().cloned().unwrap_or_default(),
                amount: tx.amount,
                timestamp: tx.timestamp,
                block_height: tx.confirmations as u64,
            })
            .collect();

        Ok(records)
    }

    /// Submit a transaction (hex-encoded bincode)
    pub async fn submit_transaction(&self, tx: time_core::Transaction) -> Result<String> {
        let tx_bytes =
            bincode::serialize(&tx).map_err(|e| ClientError::InvalidResponse(e.to_string()))?;
        let tx_hex = hex::encode(&tx_bytes);

        self.client
            .broadcast_transaction(&tx_hex)
            .await
            .map_err(|e| ClientError::Rpc(e.to_string()))
    }
}
