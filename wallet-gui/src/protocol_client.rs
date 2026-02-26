//! TIME Coin Protocol Client
//!
//! JSON-RPC based communication with masternode for peer discovery and transactions.

use serde::{Deserialize, Serialize};
use sha2::Digest;
use wallet::NetworkType;

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] bincode::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    #[error("RPC error: {0}")]
    RpcError(String),
}

pub type ProtocolResult<T> = Result<T, ProtocolError>;

/// Protocol client using JSON-RPC over HTTP
pub struct ProtocolClient {
    rpc_endpoint: String,
    _network: NetworkType,
    client: reqwest::Client,
}

impl ProtocolClient {
    pub fn new(peer_address: String, network: NetworkType) -> Self {
        let rpc_endpoint =
            if peer_address.starts_with("http://") || peer_address.starts_with("https://") {
                peer_address
            } else {
                format!("http://{}", peer_address)
            };

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .connect_timeout(std::time::Duration::from_secs(3))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            rpc_endpoint,
            _network: network,
            client,
        }
    }

    /// Send a JSON-RPC request (blocking wrapper for sync code)
    fn rpc_call_blocking(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> ProtocolResult<serde_json::Value> {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "1",
            "method": method,
            "params": params,
        });

        let rt = tokio::runtime::Handle::current();
        let client = self.client.clone();
        let endpoint = self.rpc_endpoint.clone();

        let result = rt.block_on(async {
            let response = client
                .post(&endpoint)
                .json(&request)
                .send()
                .await
                .map_err(|e| ProtocolError::ConnectionError(e.to_string()))?;

            let rpc_response: serde_json::Value = response
                .json()
                .await
                .map_err(|e| ProtocolError::InvalidResponse(e.to_string()))?;

            if let Some(error) = rpc_response.get("error") {
                if !error.is_null() {
                    let msg = error
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("Unknown RPC error");
                    return Err(ProtocolError::RpcError(msg.to_string()));
                }
            }

            rpc_response
                .get("result")
                .cloned()
                .ok_or_else(|| ProtocolError::InvalidResponse("No result field".into()))
        })?;

        Ok(result)
    }

    /// Get peer list from masternode
    pub fn get_peer_list(&self) -> ProtocolResult<Vec<String>> {
        let result = self.rpc_call_blocking("getpeerinfo", serde_json::json!([]))?;

        let peers: Vec<serde_json::Value> = serde_json::from_value(result).unwrap_or_default();

        let addresses: Vec<String> = peers
            .into_iter()
            .filter_map(|p| p.get("addr")?.as_str().map(|s| s.to_string()))
            .collect();

        Ok(addresses)
    }

    /// Submit transaction to masternode
    pub fn submit_transaction(&self, transaction: wallet::Transaction) -> ProtocolResult<String> {
        let tx_data =
            bincode::serialize(&transaction).map_err(ProtocolError::SerializationError)?;
        let tx_hex = hex::encode(&tx_data);

        let result = self.rpc_call_blocking("sendrawtransaction", serde_json::json!([tx_hex]))?;

        let txid = result
            .as_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| hex::encode(sha2::Sha256::digest(&tx_data)));

        Ok(txid)
    }

    /// Ping peer to check connectivity
    pub fn ping(&self) -> ProtocolResult<()> {
        let _result = self.rpc_call_blocking("getblockcount", serde_json::json!([]))?;
        Ok(())
    }
}

/// Wallet sync data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSyncData {
    pub transactions: Vec<wallet::Transaction>,
    pub current_height: u64,
    pub total_balance: u64,
}

/// Response containing wallet transactions from masternode
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletTransactionsResponse {
    pub transactions: Vec<time_network::protocol::WalletTransaction>,
    pub last_synced_height: u64,
}
