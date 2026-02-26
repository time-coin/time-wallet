//! Masternode JSON-RPC client
//!
//! Communicates with masternodes using JSON-RPC 2.0 over HTTP.
//! The masternode exposes an axum-based HTTP server on the RPC port
//! (24101 for testnet, 24001 for mainnet).

use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static REQUEST_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
pub struct MasternodeClient {
    rpc_endpoint: String,
    client: Client,
}

/// JSON-RPC 2.0 request
#[derive(Debug, Serialize)]
struct JsonRpcRequest {
    jsonrpc: &'static str,
    id: String,
    method: String,
    params: serde_json::Value,
}

/// JSON-RPC 2.0 response
#[derive(Debug, Deserialize)]
struct JsonRpcResponse {
    #[allow(dead_code)]
    jsonrpc: Option<String>,
    #[allow(dead_code)]
    id: Option<serde_json::Value>,
    result: Option<serde_json::Value>,
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

impl MasternodeClient {
    pub fn new(endpoint: String) -> Self {
        // Ensure endpoint is an HTTP URL pointing to the RPC port
        let rpc_endpoint = if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
            endpoint
        } else {
            format!("http://{}", endpoint)
        };

        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .build()
            .expect("Failed to create HTTP client");

        log::info!(
            "📡 Masternode JSON-RPC client initialized: {}",
            rpc_endpoint
        );

        Self {
            rpc_endpoint,
            client,
        }
    }

    pub fn endpoint(&self) -> &str {
        &self.rpc_endpoint
    }

    /// Send a JSON-RPC 2.0 request and return the result
    async fn rpc_call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, ClientError> {
        let id = REQUEST_ID.fetch_add(1, Ordering::Relaxed);
        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            id: id.to_string(),
            method: method.to_string(),
            params,
        };

        log::debug!("→ RPC {}: {:?}", method, request.params);

        let response = self
            .client
            .post(&self.rpc_endpoint)
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(ClientError::http(response.status().as_u16()));
        }

        let rpc_response: JsonRpcResponse = response.json().await.map_err(|e| {
            ClientError::InvalidResponse(format!("Failed to parse JSON-RPC response: {}", e))
        })?;

        if let Some(error) = rpc_response.error {
            return Err(ClientError::RpcError(error.code, error.message));
        }

        rpc_response
            .result
            .ok_or_else(|| ClientError::InvalidResponse("No result in JSON-RPC response".into()))
    }

    /// Get balance for an address
    pub async fn get_balance(&self, address: &str) -> Result<Balance, ClientError> {
        let result = self
            .rpc_call("getbalance", serde_json::json!([address]))
            .await?;

        // Masternode returns {balance, locked, available} in TIME (f64)
        let balance_time = result
            .get("balance")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let _locked_time = result.get("locked").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let available_time = result
            .get("available")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);

        // Convert TIME to satoshis (1 TIME = 100_000_000 satoshis)
        let confirmed = (available_time * 100_000_000.0) as u64;
        let pending = 0u64; // Masternode doesn't report pending separately
        let total = (balance_time * 100_000_000.0) as u64;
        let _locked = (_locked_time * 100_000_000.0) as u64;

        let balance = Balance {
            confirmed,
            pending,
            total,
        };
        log::info!(
            "✅ Balance: {} TIME (available: {} TIME)",
            balance_time,
            available_time
        );
        Ok(balance)
    }

    /// Get combined balance across multiple addresses (batch query for HD wallets)
    pub async fn get_balances(&self, addresses: &[String]) -> Result<Balance, ClientError> {
        let result = self
            .rpc_call("getbalances", serde_json::json!([addresses]))
            .await?;

        let balance_time = result
            .get("balance")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let _locked_time = result.get("locked").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let available_time = result
            .get("available")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);

        let confirmed = (available_time * 100_000_000.0) as u64;
        let total = (balance_time * 100_000_000.0) as u64;

        let balance = Balance {
            confirmed,
            pending: 0,
            total,
        };

        let addr_count = result
            .get("address_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        log::info!(
            "✅ Batch balance ({} addresses): {} TIME (available: {} TIME)",
            addr_count,
            balance_time,
            available_time
        );
        Ok(balance)
    }

    /// Get transaction history for a single address
    pub async fn get_transactions(
        &self,
        address: &str,
        limit: u32,
    ) -> Result<Vec<TransactionRecord>, ClientError> {
        let result = self
            .rpc_call("listtransactions", serde_json::json!([address, limit]))
            .await?;

        Self::parse_transaction_list(result)
    }

    /// Get transaction history across multiple addresses (batch query for HD wallets)
    pub async fn get_transactions_multi(
        &self,
        addresses: &[String],
        limit: u32,
    ) -> Result<Vec<TransactionRecord>, ClientError> {
        let result = self
            .rpc_call(
                "listtransactionsmulti",
                serde_json::json!([addresses, limit]),
            )
            .await?;

        Self::parse_transaction_list(result)
    }

    /// Parse a JSON array of transaction objects into TransactionRecords
    fn parse_transaction_list(
        result: serde_json::Value,
    ) -> Result<Vec<TransactionRecord>, ClientError> {
        let txs: Vec<serde_json::Value> = serde_json::from_value(result).unwrap_or_default();

        let records: Vec<TransactionRecord> = txs
            .into_iter()
            .filter_map(|tx| {
                let txid = tx.get("txid")?.as_str()?.to_string();
                let category = tx.get("category")?.as_str().unwrap_or("unknown");
                let amount_time = tx.get("amount")?.as_f64().unwrap_or(0.0);
                let amount = (amount_time.abs() * 100_000_000.0) as u64;
                let fee_time = tx.get("fee").and_then(|v| v.as_f64()).unwrap_or(0.0);
                let fee = (fee_time.abs() * 100_000_000.0) as u64;
                let confirmations = tx
                    .get("confirmations")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32;
                let timestamp = tx.get("time").and_then(|v| v.as_i64()).unwrap_or(0);

                let status = if confirmations >= 6 {
                    TransactionStatus::Confirmed
                } else {
                    TransactionStatus::Pending
                };

                let (from, to) = match category {
                    "send" => (vec!["self".to_string()], vec![txid.clone()]),
                    "receive" => (vec![txid.clone()], vec!["self".to_string()]),
                    _ => (vec![], vec![]),
                };

                Some(TransactionRecord {
                    txid,
                    from,
                    to,
                    amount,
                    fee,
                    timestamp,
                    confirmations,
                    status,
                })
            })
            .collect();

        log::info!("✅ Retrieved {} transactions", records.len());
        Ok(records)
    }

    /// Get UTXOs for an address
    pub async fn get_utxos(&self, address: &str) -> Result<Vec<Utxo>, ClientError> {
        // listunspent params: [min_conf, max_conf, [addresses], limit]
        let result = self
            .rpc_call(
                "listunspent",
                serde_json::json!([0, 9999999, [address], 100]),
            )
            .await?;

        let utxo_values: Vec<serde_json::Value> =
            serde_json::from_value(result).unwrap_or_default();

        let utxos: Vec<Utxo> = utxo_values
            .into_iter()
            .filter_map(|u| {
                let txid = u.get("txid")?.as_str()?.to_string();
                let vout = u.get("vout")?.as_u64()? as u32;
                let amount_time = u.get("amount")?.as_f64().unwrap_or(0.0);
                let amount = (amount_time * 100_000_000.0) as u64;
                let addr = u
                    .get("address")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let confirmations =
                    u.get("confirmations").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

                Some(Utxo {
                    txid,
                    vout,
                    amount,
                    address: addr,
                    confirmations,
                })
            })
            .collect();

        log::info!("✅ Retrieved {} UTXOs", utxos.len());
        Ok(utxos)
    }

    /// Broadcast a signed transaction (hex-encoded bincode)
    pub async fn broadcast_transaction(&self, tx_hex: &str) -> Result<String, ClientError> {
        let result = self
            .rpc_call("sendrawtransaction", serde_json::json!([tx_hex]))
            .await?;

        let txid = result
            .as_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| result.to_string().trim_matches('"').to_string());

        log::info!("✅ Transaction broadcast: {}", txid);
        Ok(txid)
    }

    /// Validate an address
    pub async fn validate_address(&self, address: &str) -> Result<bool, ClientError> {
        let result = self
            .rpc_call("validateaddress", serde_json::json!([address]))
            .await?;

        let valid = result
            .get("isvalid")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        Ok(valid)
    }

    /// Check if masternode is reachable via getblockchaininfo
    pub async fn health_check(&self) -> Result<HealthStatus, ClientError> {
        let result = self
            .rpc_call("getblockchaininfo", serde_json::json!([]))
            .await?;

        // Masternode returns "blocks", fall back to "height" for compat
        let height = result
            .get("blocks")
            .or_else(|| result.get("height"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        // Masternode returns "chain", fall back to "version" for compat
        let version = result
            .get("chain")
            .or_else(|| result.get("version"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let status = HealthStatus {
            status: "healthy".to_string(),
            version,
            block_height: height,
            peer_count: 0,
        };

        log::info!("✅ Masternode healthy: height={}", height);
        Ok(status)
    }

    /// Get current blockchain height
    pub async fn get_block_height(&self) -> Result<u64, ClientError> {
        let result = self
            .rpc_call("getblockcount", serde_json::json!([]))
            .await?;

        let height = result.as_u64().unwrap_or(0);
        Ok(height)
    }

    /// Query instant finality status for a transaction
    pub async fn get_transaction_finality(
        &self,
        txid: &str,
    ) -> Result<FinalityStatus, ClientError> {
        let result = self
            .rpc_call("gettransactionfinality", serde_json::json!([txid]))
            .await?;

        let finalized = result
            .get("finalized")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let confirmations = result
            .get("confirmations")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;

        Ok(FinalityStatus {
            txid: txid.to_string(),
            finalized,
            confirmations,
        })
    }

    /// Get peer info from masternode
    pub async fn get_peer_info(&self) -> Result<Vec<PeerInfoResult>, ClientError> {
        let result = self.rpc_call("getpeerinfo", serde_json::json!([])).await?;

        let peers: Vec<serde_json::Value> = serde_json::from_value(result).unwrap_or_default();

        let peer_info: Vec<PeerInfoResult> = peers
            .into_iter()
            .filter_map(|p| {
                let addr = p.get("addr")?.as_str()?.to_string();
                let active = p.get("active").and_then(|v| v.as_bool()).unwrap_or(false);
                Some(PeerInfoResult { addr, active })
            })
            .collect();

        Ok(peer_info)
    }
}

// ============================================================================
// Data Structures
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Balance {
    pub confirmed: u64,
    pub pending: u64,
    pub total: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionRecord {
    pub txid: String,
    pub from: Vec<String>,
    pub to: Vec<String>,
    pub amount: u64,
    pub fee: u64,
    pub timestamp: i64,
    pub confirmations: u32,
    pub status: TransactionStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransactionStatus {
    Pending,
    Finalized,
    Confirmed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    pub address: String,
    pub confirmations: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub status: String,
    pub version: String,
    pub block_height: u64,
    pub peer_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalityStatus {
    pub txid: String,
    pub finalized: bool,
    pub confirmations: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfoResult {
    pub addr: String,
    pub active: bool,
}

// ============================================================================
// Error Handling
// ============================================================================

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("HTTP error {0}: {1}")]
    Http(u16, String),

    #[error("RPC error {0}: {1}")]
    RpcError(i64, String),

    #[error("Request failed: {0}")]
    Request(#[from] reqwest::Error),

    #[error("Network timeout")]
    Timeout,

    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    #[error("Transaction broadcast failed: {0}")]
    BroadcastFailed(String),

    #[error("Masternode unavailable")]
    Unavailable,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

impl ClientError {
    pub fn http(status: u16) -> Self {
        let message = match status {
            400 => "Bad Request",
            404 => "Not Found",
            500 => "Internal Server Error",
            503 => "Service Unavailable",
            _ => "Unknown Error",
        };
        Self::Http(status, message.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_client_creation() {
        let client = MasternodeClient::new("http://127.0.0.1:24101".to_string());
        assert_eq!(client.endpoint(), "http://127.0.0.1:24101");
    }

    #[tokio::test]
    async fn test_client_creation_bare_endpoint() {
        let client = MasternodeClient::new("127.0.0.1:24101".to_string());
        assert_eq!(client.endpoint(), "http://127.0.0.1:24101");
    }

    #[test]
    fn test_balance_serialization() {
        let balance = Balance {
            confirmed: 1000,
            pending: 500,
            total: 1500,
        };

        let json = serde_json::to_string(&balance).unwrap();
        let deserialized: Balance = serde_json::from_str(&json).unwrap();

        assert_eq!(balance.total, deserialized.total);
    }

    #[test]
    fn test_transaction_status() {
        let status = TransactionStatus::Confirmed;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, r#""confirmed""#);
    }
}
