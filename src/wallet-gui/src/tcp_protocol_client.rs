//! TCP-based TIME Coin Protocol Client
//!
//! Simplified to use JSON-RPC via MasternodeClient.
//! The old raw TCP protocol is incompatible with the masternode's TLS+bincode transport.

use crate::masternode_client::MasternodeClient;
use wallet::NetworkType;

pub struct TcpProtocolClient {
    client: MasternodeClient,
}

impl TcpProtocolClient {
    pub fn new(network: NetworkType) -> Self {
        // Default RPC endpoint based on network
        let port = match network {
            NetworkType::Testnet => 24101,
            NetworkType::Mainnet => 24001,
        };
        let endpoint = format!("http://127.0.0.1:{}", port);

        Self {
            client: MasternodeClient::new(endpoint),
        }
    }

    pub async fn disconnect(&self) {
        // No persistent connection to close with JSON-RPC
    }
}

/// Transaction notification type
#[derive(Debug, Clone)]
pub enum TransactionNotification {
    Approved { txid: String, timestamp: i64 },
    Rejected { txid: String, reason: String },
}
