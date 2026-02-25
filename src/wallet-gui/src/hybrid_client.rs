//! Hybrid masternode client - tries TCP first, falls back to HTTP
//!
//! This client attempts to use the faster TCP protocol for communication,
//! but falls back to HTTP if TCP is unavailable.

use crate::masternode_client::{
    Balance, ClientError, MasternodeClient, TransactionRecord, TransactionStatus, Utxo,
};
use time_network::protocol::{NetworkMessage, WalletTransaction};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use wallet::NetworkType;

pub struct HybridMasternodeClient {
    http_client: MasternodeClient,
    network: NetworkType,
    tcp_port: u16,
}

impl HybridMasternodeClient {
    pub fn new(endpoint: String, network: NetworkType) -> Self {
        let tcp_port = match network {
            NetworkType::Testnet => 24100,
            NetworkType::Mainnet => 24101,
        };

        Self {
            http_client: MasternodeClient::new(endpoint),
            network,
            tcp_port,
        }
    }

    /// Extract host from HTTP endpoint
    fn extract_host(&self) -> Option<String> {
        let endpoint = self.http_client.endpoint();
        endpoint
            .replace("http://", "")
            .replace("https://", "")
            .split(':')
            .next()
            .map(|s| s.to_string())
    }

    /// Try TCP connection with timeout
    async fn try_tcp_connect(&self) -> Option<TcpStream> {
        let host = self.extract_host()?;
        let addr = format!("{}:{}", host, self.tcp_port);

        log::debug!("🔌 Attempting TCP connection to {}...", addr);

        match tokio::time::timeout(std::time::Duration::from_secs(3), TcpStream::connect(&addr))
            .await
        {
            Ok(Ok(stream)) => {
                let _ = stream.set_nodelay(true);
                log::info!("✅ TCP connected to {}", addr);
                Some(stream)
            }
            Ok(Err(e)) => {
                log::warn!("⚠️ TCP connection failed: {}, falling back to HTTP", e);
                None
            }
            Err(_) => {
                log::warn!("⏱️ TCP connection timeout, falling back to HTTP");
                None
            }
        }
    }

    /// Send a message over TCP
    async fn send_tcp_message(stream: &mut TcpStream, msg: &NetworkMessage) -> Result<(), String> {
        let serialized =
            bincode::serialize(msg).map_err(|e| format!("Serialization error: {}", e))?;

        let len = serialized.len() as u32;
        stream
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|e| format!("Write error: {}", e))?;
        stream
            .write_all(&serialized)
            .await
            .map_err(|e| format!("Write error: {}", e))?;
        stream
            .flush()
            .await
            .map_err(|e| format!("Flush error: {}", e))?;

        Ok(())
    }

    /// Receive a message from TCP
    async fn receive_tcp_message(stream: &mut TcpStream) -> Result<NetworkMessage, String> {
        let mut len_bytes = [0u8; 4];
        stream
            .read_exact(&mut len_bytes)
            .await
            .map_err(|e| format!("Read length error: {}", e))?;

        let len = u32::from_be_bytes(len_bytes) as usize;
        if len > 10_000_000 {
            return Err("Message too large".to_string());
        }

        let mut buffer = vec![0u8; len];
        stream
            .read_exact(&mut buffer)
            .await
            .map_err(|e| format!("Read data error: {}", e))?;

        bincode::deserialize(&buffer).map_err(|e| format!("Deserialization error: {}", e))
    }

    /// Convert WalletTransaction to TransactionRecord
    fn convert_transaction(tx: WalletTransaction) -> TransactionRecord {
        TransactionRecord {
            txid: tx.tx_hash,
            from: vec![tx.from_address],
            to: vec![tx.to_address],
            amount: tx.amount,
            fee: 0, // Not available in WalletTransaction
            timestamp: tx.timestamp as i64,
            confirmations: tx.confirmations,
            status: if tx.confirmations >= 6 {
                TransactionStatus::Confirmed
            } else {
                TransactionStatus::Pending
            },
        }
    }

    /// Get balance - HTTP only (no TCP support yet)
    pub async fn get_balance(&self, xpub: &str) -> Result<Balance, ClientError> {
        self.http_client.get_balance(xpub).await
    }

    /// Get transactions using TCP or HTTP
    pub async fn get_transactions(
        &self,
        xpub: &str,
        _limit: u32,
    ) -> Result<Vec<TransactionRecord>, ClientError> {
        // Try TCP first
        if let Some(mut stream) = self.try_tcp_connect().await {
            log::debug!("→ TCP: RequestWalletTransactions");

            let request = NetworkMessage::RequestWalletTransactions {
                xpub: xpub.to_string(),
            };

            if let Err(e) = Self::send_tcp_message(&mut stream, &request).await {
                log::warn!("⚠️ TCP send failed: {}, trying HTTP", e);
            } else {
                // Wait for response
                match tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    Self::receive_tcp_message(&mut stream),
                )
                .await
                {
                    Ok(Ok(NetworkMessage::WalletTransactionsResponse {
                        transactions,
                        last_synced_height,
                    })) => {
                        log::info!(
                            "✅ {} transactions from TCP (synced to height {})",
                            transactions.len(),
                            last_synced_height
                        );

                        let records: Vec<TransactionRecord> = transactions
                            .into_iter()
                            .map(Self::convert_transaction)
                            .collect();

                        return Ok(records);
                    }
                    Ok(Ok(msg)) => {
                        log::warn!("⚠️ Unexpected TCP response: {:?}, trying HTTP", msg);
                    }
                    Ok(Err(e)) => {
                        log::warn!("⚠️ TCP receive error: {}, trying HTTP", e);
                    }
                    Err(_) => {
                        log::warn!("⏱️ TCP response timeout, trying HTTP");
                    }
                }
            }
        }

        // Fallback to HTTP
        log::debug!("↪️ Using HTTP fallback for transactions");
        self.http_client.get_transactions(xpub, _limit).await
    }

    /// Get UTXOs - HTTP only (no TCP support yet)
    pub async fn get_utxos(&self, xpub: &str) -> Result<Vec<Utxo>, ClientError> {
        self.http_client.get_utxos(xpub).await
    }

    /// Broadcast transaction - HTTP only for reliability
    pub async fn broadcast_transaction(&self, tx_hex: &str) -> Result<String, ClientError> {
        log::info!("📡 Broadcasting transaction via HTTP (reliable path)");
        self.http_client.broadcast_transaction(tx_hex).await
    }

    /// Health check
    pub async fn health_check(
        &self,
    ) -> Result<crate::masternode_client::HealthStatus, ClientError> {
        self.http_client.health_check().await
    }
}
