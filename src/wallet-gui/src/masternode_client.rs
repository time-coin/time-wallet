//! Masternode client with TCP primary and HTTP fallback
//!
//! This is a thin client that delegates all blockchain operations to masternodes.
//! The wallet only handles key management and transaction signing locally.
//!
//! Protocol priority:
//! 1. Try TCP (faster, lower overhead)
//! 2. Fallback to HTTP on TCP failure

use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Clone)]
pub struct MasternodeClient {
    tcp_endpoint: String,
    http_endpoint: String,
    client: Client,
    prefer_tcp: bool,
}

impl MasternodeClient {
    pub fn new(endpoint: String) -> Self {
        // Parse endpoint to create both TCP and HTTP versions
        let (tcp_endpoint, http_endpoint) = Self::parse_endpoint(&endpoint);

        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .build()
            .expect("Failed to create HTTP client");

        log::info!("📡 Masternode client initialized");
        log::info!("   TCP: {}", tcp_endpoint);
        log::info!("   HTTP: {}", http_endpoint);

        Self {
            tcp_endpoint,
            http_endpoint,
            client,
            prefer_tcp: true,
        }
    }

    fn parse_endpoint(endpoint: &str) -> (String, String) {
        // If it's http/https, derive TCP from it
        if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
            let http_endpoint = endpoint.to_string();
            // Extract host:port for TCP (remove scheme and path)
            let without_scheme = endpoint
                .trim_start_matches("http://")
                .trim_start_matches("https://");
            // Remove any path components
            let tcp_endpoint = without_scheme
                .split('/')
                .next()
                .unwrap_or(without_scheme)
                .to_string();
            (tcp_endpoint, http_endpoint)
        } else {
            // If it's just host:port, create both
            let tcp_endpoint = endpoint.to_string();
            let http_endpoint = format!("http://{}", endpoint);
            (tcp_endpoint, http_endpoint)
        }
    }

    pub fn endpoint(&self) -> &str {
        &self.http_endpoint
    }

    /// Try TCP request with automatic HTTP fallback
    async fn request_with_fallback<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<T, ClientError> {
        // Try TCP first
        if self.prefer_tcp {
            match self.tcp_request(method, path, body.clone()).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    log::warn!("⚠️ TCP request failed, falling back to HTTP: {}", e);
                }
            }
        }

        // Fallback to HTTP
        self.http_request(method, path, body).await
    }

    /// Make TCP request
    async fn tcp_request<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<T, ClientError> {
        let mut stream = TcpStream::connect(&self.tcp_endpoint).await?;

        // Build request
        let request = if let Some(body) = body {
            format!(
                "{} {} HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\n\r\n{}",
                method,
                path,
                self.tcp_endpoint,
                body.len(),
                String::from_utf8_lossy(&body)
            )
        } else {
            format!(
                "{} {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                method, path, self.tcp_endpoint
            )
        };

        // Send request
        stream.write_all(request.as_bytes()).await?;

        // Read response
        let mut buffer = Vec::new();
        stream.read_to_end(&mut buffer).await?;

        // Parse HTTP response
        let response_str = String::from_utf8_lossy(&buffer);
        let body_start = response_str
            .find("\r\n\r\n")
            .ok_or_else(|| ClientError::InvalidResponse("No response body found".to_string()))?
            + 4;

        let body = &response_str[body_start..];
        serde_json::from_str(body)
            .map_err(|e| ClientError::InvalidResponse(format!("JSON parse error: {}", e)))
    }

    /// Make HTTP request
    async fn http_request<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<T, ClientError> {
        let url = format!("{}{}", self.http_endpoint, path);

        let request = match method {
            "GET" => self.client.get(&url),
            "POST" => {
                let mut req = self.client.post(&url);
                if let Some(body) = body {
                    req = req.body(body);
                }
                req
            }
            _ => {
                return Err(ClientError::InvalidResponse(
                    "Unsupported method".to_string(),
                ))
            }
        };

        let response = request.send().await?;

        if !response.status().is_success() {
            return Err(ClientError::http(response.status().as_u16()));
        }

        response
            .json()
            .await
            .map_err(|e| ClientError::InvalidResponse(format!("JSON parse error: {}", e)))
    }

    /// Get balance for an xpub
    pub async fn get_balance(&self, xpub: &str) -> Result<Balance, ClientError> {
        let path = format!("/wallet/balance?xpub={}", xpub);
        log::debug!("→ GET {}", path);

        let balance: Balance = self.request_with_fallback("GET", &path, None).await?;
        log::info!("✅ Balance retrieved: {:?}", balance);
        Ok(balance)
    }

    /// Get transaction history for an xpub
    pub async fn get_transactions(
        &self,
        xpub: &str,
        limit: u32,
    ) -> Result<Vec<TransactionRecord>, ClientError> {
        let path = format!("/wallet/transactions?xpub={}&limit={}", xpub, limit);
        log::debug!("→ GET {} (limit: {})", path, limit);

        let transactions: Vec<TransactionRecord> =
            self.request_with_fallback("GET", &path, None).await?;
        log::info!("✅ Retrieved {} transactions", transactions.len());
        Ok(transactions)
    }

    /// Get UTXOs for an xpub
    pub async fn get_utxos(&self, xpub: &str) -> Result<Vec<Utxo>, ClientError> {
        let path = format!("/wallet/utxos?xpub={}", xpub);
        log::debug!("→ GET {}", path);

        let utxos: Vec<Utxo> = self.request_with_fallback("GET", &path, None).await?;
        log::info!("✅ Retrieved {} UTXOs", utxos.len());
        Ok(utxos)
    }

    /// Broadcast a signed transaction
    pub async fn broadcast_transaction(&self, tx_hex: &str) -> Result<String, ClientError> {
        let path = "/transaction/broadcast";
        log::debug!("→ POST {}", path);

        let body = serde_json::json!({ "tx": tx_hex });
        let body_bytes = serde_json::to_vec(&body)?;

        let result: BroadcastResponse = self
            .request_with_fallback("POST", path, Some(body_bytes))
            .await?;
        log::info!("✅ Transaction broadcast: {}", result.txid);
        Ok(result.txid)
    }

    /// Get address information
    pub async fn get_address_info(&self, address: &str) -> Result<AddressInfo, ClientError> {
        let path = format!("/address/{}", address);
        log::debug!("→ GET {}", path);

        let info: AddressInfo = self.request_with_fallback("GET", &path, None).await?;
        log::debug!("✅ Address info retrieved: {:?}", info);
        Ok(info)
    }

    /// Check if masternode is reachable
    pub async fn health_check(&self) -> Result<HealthStatus, ClientError> {
        let path = "/health";
        log::debug!("→ GET {}", path);

        let status: HealthStatus = self.request_with_fallback("GET", path, None).await?;
        log::info!("✅ Masternode healthy: {:?}", status);
        Ok(status)
    }

    /// Get current blockchain height
    pub async fn get_block_height(&self) -> Result<u64, ClientError> {
        let path = "/blockchain/height";
        log::debug!("→ GET {}", path);

        let result: BlockHeightResponse = self.request_with_fallback("GET", path, None).await?;
        Ok(result.height)
    }

    /// Validate an address
    pub async fn validate_address(&self, address: &str) -> Result<bool, ClientError> {
        let path = format!("/address/validate/{}", address);
        log::debug!("→ GET {}", path);

        let result: AddressValidation = self.request_with_fallback("GET", &path, None).await?;
        Ok(result.valid)
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
pub struct AddressInfo {
    pub address: String,
    pub has_transactions: bool,
    pub balance: u64,
    pub transaction_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub status: String,
    pub version: String,
    pub block_height: u64,
    pub peer_count: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct BroadcastResponse {
    txid: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct BlockHeightResponse {
    height: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct AddressValidation {
    valid: bool,
}

// ============================================================================
// Error Handling
// ============================================================================

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("HTTP error {0}: {1}")]
    Http(u16, String),

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

// Fix the HTTP error construction
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

// Update the usage in the impl block
impl MasternodeClient {
    // Helper method to handle HTTP errors consistently
    fn handle_error_response(status: u16) -> ClientError {
        ClientError::http(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_client_creation() {
        let client = MasternodeClient::new("https://testnet.time-coin.io".to_string());
        assert_eq!(client.endpoint(), "https://testnet.time-coin.io");
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
