//! Simple async client for TIME wallet GUI
//!
//! This replaces the complex P2P networking with simple async TCP requests
//! to masternodes. No mutexes, no blocking, just clean async/await.

use serde::{Deserialize, Serialize};
use std::time::Duration;
use time_network::protocol::{HandshakeMessage, NetworkMessage};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use wallet::NetworkType;

#[derive(Debug, Clone)]
pub struct SimpleClient {
    masternode_addr: String,
    network: NetworkType,
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
}

pub type Result<T> = std::result::Result<T, ClientError>;

impl SimpleClient {
    /// Create a new client pointing to a masternode
    pub fn new(masternode_addr: String, network: NetworkType) -> Self {
        Self {
            masternode_addr,
            network,
        }
    }

    /// Connect and perform handshake with timeout
    async fn connect(&self) -> Result<TcpStream> {
        let stream = tokio::time::timeout(
            Duration::from_secs(3),
            TcpStream::connect(&self.masternode_addr),
        )
        .await
        .map_err(|_| ClientError::Timeout)??;

        Ok(stream)
    }

    /// Send a message and receive response
    async fn send_message(&self, message: NetworkMessage) -> Result<NetworkMessage> {
        let mut stream = self.connect().await?;

        // Perform handshake
        let network_type = match self.network {
            NetworkType::Mainnet => time_network::discovery::NetworkType::Mainnet,
            NetworkType::Testnet => time_network::discovery::NetworkType::Testnet,
        };

        let handshake = HandshakeMessage::new(network_type, "0.0.0.0:0".parse().unwrap());
        let magic = network_type.magic_bytes();

        // Send handshake
        let handshake_json = serde_json::to_vec(&handshake)?;
        let handshake_len = (handshake_json.len() as u32).to_be_bytes();

        stream.write_all(&magic).await?;
        stream.write_all(&handshake_len).await?;
        stream.write_all(&handshake_json).await?;
        stream.flush().await?;

        // Read their handshake
        let mut their_magic = [0u8; 4];
        let mut their_len = [0u8; 4];
        stream.read_exact(&mut their_magic).await?;
        stream.read_exact(&mut their_len).await?;

        let len = u32::from_be_bytes(their_len) as usize;
        if len > 10 * 1024 {
            return Err(ClientError::InvalidResponse("Handshake too large".into()));
        }

        let mut their_handshake = vec![0u8; len];
        stream.read_exact(&mut their_handshake).await?;

        // Now send our actual message
        let msg_json = serde_json::to_vec(&message)?;
        let msg_len = (msg_json.len() as u32).to_be_bytes();

        stream.write_all(&magic).await?;
        stream.write_all(&msg_len).await?;
        stream.write_all(&msg_json).await?;
        stream.flush().await?;

        // Read response with timeout
        let response = tokio::time::timeout(Duration::from_secs(10), async {
            let mut resp_magic = [0u8; 4];
            let mut resp_len = [0u8; 4];
            stream.read_exact(&mut resp_magic).await?;
            stream.read_exact(&mut resp_len).await?;

            let len = u32::from_be_bytes(resp_len) as usize;
            if len > 10 * 1024 * 1024 {
                return Err(ClientError::InvalidResponse("Response too large".into()));
            }

            let mut resp_data = vec![0u8; len];
            stream.read_exact(&mut resp_data).await?;

            let response: NetworkMessage = serde_json::from_slice(&resp_data)?;
            Ok(response)
        })
        .await
        .map_err(|_| ClientError::Timeout)??;

        Ok(response)
    }

    /// Get transaction history for xpub (uses existing protocol)
    pub async fn get_transactions(&self, xpub: &str) -> Result<Vec<TransactionRecord>> {
        let message = NetworkMessage::RequestWalletTransactions {
            xpub: xpub.to_string(),
        };

        let response = self.send_message(message).await?;

        match response {
            NetworkMessage::WalletTransactionsResponse { transactions, .. } => {
                let tx_records = transactions
                    .into_iter()
                    .map(|tx| TransactionRecord {
                        tx_hash: tx.tx_hash,
                        from_address: tx.from_address,
                        to_address: tx.to_address,
                        amount: tx.amount,
                        timestamp: tx.timestamp as i64,
                        block_height: tx.block_height,
                    })
                    .collect();
                Ok(tx_records)
            }
            _ => Err(ClientError::InvalidResponse(
                "Expected WalletTransactionsResponse".into(),
            )),
        }
    }

    /// Submit a transaction (uses Transaction message)
    pub async fn submit_transaction(&self, tx: time_core::Transaction) -> Result<String> {
        let txid = tx.txid.clone();
        let message = NetworkMessage::TransactionBroadcast(tx);

        // Just send it - no response expected for broadcast
        self.send_message(message).await?;

        Ok(txid)
    }

    /// Register xpub for notifications
    pub async fn register_xpub(&self, xpub: &str) -> Result<()> {
        let message = NetworkMessage::RegisterXpub {
            xpub: xpub.to_string(),
        };

        let response = self.send_message(message).await?;

        match response {
            NetworkMessage::XpubRegistered { success, .. } => {
                if success {
                    Ok(())
                } else {
                    Err(ClientError::InvalidResponse("Registration failed".into()))
                }
            }
            _ => Err(ClientError::InvalidResponse(
                "Expected XpubRegistered".into(),
            )),
        }
    }
}
