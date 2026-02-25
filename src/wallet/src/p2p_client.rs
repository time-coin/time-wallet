//! Wallet P2P Client
//!
//! Allows wallets to communicate directly with masternodes via P2P network
//! instead of using HTTP API. This is more efficient and aligns with
//! blockchain design principles.

use std::net::SocketAddr;
use std::sync::Arc;
use time_core::Transaction;
use time_network::protocol::NetworkMessage;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

/// P2P client for wallet-to-masternode communication
pub struct WalletP2PClient {
    /// TCP connection to masternode
    stream: Arc<Mutex<TcpStream>>,
    /// Masternode address
    masternode_addr: SocketAddr,
}

impl WalletP2PClient {
    /// Connect to a masternode via P2P network
    pub async fn connect(masternode_addr: SocketAddr) -> Result<Self, String> {
        let stream = TcpStream::connect(masternode_addr)
            .await
            .map_err(|e| format!("Failed to connect to masternode: {}", e))?;

        println!("✅ Connected to masternode at {}", masternode_addr);

        Ok(Self {
            stream: Arc::new(Mutex::new(stream)),
            masternode_addr,
        })
    }

    /// Send a transaction to the masternode
    ///
    /// The masternode will:
    /// 1. Validate the transaction
    /// 2. Add to mempool
    /// 3. Lock UTXOs
    /// 4. Broadcast to other masternodes
    /// 5. Initiate instant finality voting
    pub async fn send_transaction(&self, tx: Transaction) -> Result<(), String> {
        let message = NetworkMessage::TransactionBroadcast(tx.clone());
        self.send_message(message).await?;

        println!(
            "📤 Sent transaction {} to masternode {}",
            &tx.txid[..16],
            self.masternode_addr
        );

        Ok(())
    }

    /// Subscribe to address notifications
    ///
    /// Receive real-time UTXO state changes for specified addresses
    pub async fn subscribe_to_addresses(
        &self,
        addresses: Vec<String>,
        subscriber_id: String,
    ) -> Result<(), String> {
        let message = NetworkMessage::UTXOSubscribe {
            outpoints: vec![],
            addresses,
            subscriber_id,
        };

        self.send_message(message).await?;
        println!("✅ Subscribed to address notifications");

        Ok(())
    }

    /// Unsubscribe from notifications
    pub async fn unsubscribe(&self, subscriber_id: String) -> Result<(), String> {
        let message = NetworkMessage::UTXOUnsubscribe { subscriber_id };
        self.send_message(message).await?;

        println!("✅ Unsubscribed from notifications");
        Ok(())
    }

    /// Query UTXO states
    pub async fn query_utxo_states(
        &self,
        outpoints: Vec<String>,
    ) -> Result<NetworkMessage, String> {
        let message = NetworkMessage::UTXOStateQuery { outpoints };
        self.send_message(message).await?;

        // Read response
        self.receive_message().await
    }

    /// Send a network message
    async fn send_message(&self, message: NetworkMessage) -> Result<(), String> {
        let json =
            serde_json::to_vec(&message).map_err(|e| format!("Serialization error: {}", e))?;

        let len = json.len() as u32;
        let mut stream = self.stream.lock().await;

        // Write length prefix
        stream
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|e| format!("Write error: {}", e))?;

        // Write message
        stream
            .write_all(&json)
            .await
            .map_err(|e| format!("Write error: {}", e))?;

        stream
            .flush()
            .await
            .map_err(|e| format!("Flush error: {}", e))?;

        Ok(())
    }

    /// Receive a network message
    async fn receive_message(&self) -> Result<NetworkMessage, String> {
        let mut stream = self.stream.lock().await;

        // Read length prefix
        let mut len_bytes = [0u8; 4];
        stream
            .read_exact(&mut len_bytes)
            .await
            .map_err(|e| format!("Read error: {}", e))?;

        let len = u32::from_be_bytes(len_bytes) as usize;

        // Read message
        let mut buffer = vec![0u8; len];
        stream
            .read_exact(&mut buffer)
            .await
            .map_err(|e| format!("Read error: {}", e))?;

        // Deserialize
        serde_json::from_slice(&buffer).map_err(|e| format!("Deserialization error: {}", e))
    }

    /// Receive messages in a loop (for subscriptions)
    pub async fn receive_loop<F>(&self, handler: F) -> Result<(), String>
    where
        F: Fn(NetworkMessage) + Send + 'static,
    {
        loop {
            match self.receive_message().await {
                Ok(message) => {
                    handler(message);
                }
                Err(e) => {
                    println!("❌ Connection error: {}", e);
                    return Err(e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires running masternode
    async fn test_wallet_p2p_connection() {
        let addr: SocketAddr = "127.0.0.1:24000".parse().unwrap();
        let client = WalletP2PClient::connect(addr).await;
        assert!(client.is_ok());
    }
}
