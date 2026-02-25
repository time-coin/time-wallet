//! TCP-based TIME Coin Protocol Client
//!
//! Communicates with masternodes using raw TCP and NetworkMessage protocol

use std::sync::Arc;
use time_network::protocol::{NetworkMessage, WalletTransaction};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, RwLock};
use wallet::NetworkType;

pub struct TcpProtocolClient {
    network: NetworkType,
    xpub: Option<String>,
    connected_peers: Arc<RwLock<Vec<String>>>,
    active: Arc<RwLock<bool>>,
}

impl TcpProtocolClient {
    pub fn new(network: NetworkType) -> Self {
        Self {
            network,
            xpub: None,
            connected_peers: Arc::new(RwLock::new(Vec::new())),
            active: Arc::new(RwLock::new(false)),
        }
    }

    pub async fn set_xpub(&mut self, xpub: String) {
        self.xpub = Some(xpub);
    }

    /// Connect to a masternode and register xpub
    pub async fn connect_to_masternode(
        &self,
        masternode_url: &str,
        tx_sender: mpsc::UnboundedSender<WalletTransaction>,
    ) -> Result<(), String> {
        // Extract IP from URL
        let ip = masternode_url
            .replace("http://", "")
            .replace("https://", "")
            .split(':')
            .next()
            .ok_or("Invalid masternode URL")?
            .to_string();

        // Connect to TCP port (24100 for testnet, 24101 for mainnet)
        let port = if self.network == NetworkType::Testnet {
            24100
        } else {
            24101
        };
        let tcp_addr = format!("{}:{}", ip, port);

        log::info!("Connecting to masternode via TCP: {}", tcp_addr);

        let mut stream = TcpStream::connect(&tcp_addr)
            .await
            .map_err(|e| format!("TCP connection failed: {}", e))?;

        // Enable TCP_NODELAY for low latency
        stream
            .set_nodelay(true)
            .map_err(|e| format!("Failed to set TCP_NODELAY: {}", e))?;

        *self.active.write().await = true;

        // Register xpub if available
        if let Some(xpub) = &self.xpub {
            log::info!("Registering xpub with masternode...");
            let msg = NetworkMessage::RegisterXpub { xpub: xpub.clone() };
            self.send_message(&mut stream, &msg).await?;

            // Wait for response
            match self.receive_message(&mut stream).await? {
                NetworkMessage::XpubRegistered { success, message } => {
                    if success {
                        log::info!("✓ xPub registered successfully: {}", message);
                    } else {
                        return Err(format!("xPub registration failed: {}", message));
                    }
                }
                _ => {
                    return Err("Unexpected response to xPub registration".to_string());
                }
            }
        }

        // Spawn reader task
        let active = self.active.clone();
        tokio::spawn(async move {
            loop {
                if !*active.read().await {
                    break;
                }

                match Self::receive_message_static(&mut stream).await {
                    Ok(msg) => match msg {
                        NetworkMessage::NewTransactionNotification { transaction } => {
                            log::info!(
                                "Received transaction notification: {}",
                                transaction.tx_hash
                            );
                            if let Err(e) = tx_sender.send(transaction) {
                                log::error!("Failed to forward transaction: {}", e);
                            }
                        }
                        NetworkMessage::UtxoUpdate { xpub, utxos } => {
                            log::info!("Received UTXO update for {}: {} UTXOs", xpub, utxos.len());
                            // TODO: Process UTXO updates
                        }
                        NetworkMessage::Ping => {
                            // Respond to ping
                            let pong = NetworkMessage::Pong;
                            if let Err(e) = Self::send_message_static(&mut stream, &pong).await {
                                log::error!("Failed to send pong: {}", e);
                            }
                        }
                        _ => {
                            log::debug!("Received message: {:?}", msg);
                        }
                    },
                    Err(e) => {
                        log::error!("Connection error: {}", e);
                        break;
                    }
                }
            }
            log::info!("TCP protocol client disconnected");
        });

        Ok(())
    }

    /// Send a message over TCP
    async fn send_message(
        &self,
        stream: &mut TcpStream,
        msg: &NetworkMessage,
    ) -> Result<(), String> {
        Self::send_message_static(stream, msg).await
    }

    async fn send_message_static(
        stream: &mut TcpStream,
        msg: &NetworkMessage,
    ) -> Result<(), String> {
        let json =
            serde_json::to_vec(msg).map_err(|e| format!("Failed to serialize message: {}", e))?;

        // Send length prefix (4 bytes)
        let len = json.len() as u32;
        stream
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|e| format!("Failed to send length: {}", e))?;

        // Send message
        stream
            .write_all(&json)
            .await
            .map_err(|e| format!("Failed to send message: {}", e))?;

        stream
            .flush()
            .await
            .map_err(|e| format!("Failed to flush: {}", e))?;

        Ok(())
    }

    /// Receive a message from TCP
    async fn receive_message(&self, stream: &mut TcpStream) -> Result<NetworkMessage, String> {
        Self::receive_message_static(stream).await
    }

    async fn receive_message_static(stream: &mut TcpStream) -> Result<NetworkMessage, String> {
        // Read length prefix
        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| format!("Failed to read length: {}", e))?;
        let len = u32::from_be_bytes(len_buf) as usize;

        // Size limit check
        if len > 10 * 1024 * 1024 {
            return Err("Message too large (>10MB)".into());
        }

        // Read message
        let mut buf = vec![0u8; len];
        stream
            .read_exact(&mut buf)
            .await
            .map_err(|e| format!("Failed to read message: {}", e))?;

        // Deserialize from JSON
        serde_json::from_slice(&buf).map_err(|e| format!("Failed to deserialize message: {}", e))
    }

    pub async fn disconnect(&self) {
        *self.active.write().await = false;
    }
}

/// Transaction notification type
#[derive(Debug, Clone)]
pub enum TransactionNotification {
    Approved { txid: String, timestamp: i64 },
    Rejected { txid: String, reason: String },
}

/// TCP Protocol Listener - maintains persistent connection and listens for push notifications
pub struct TcpProtocolListener {
    peer_addr: String,
    xpub: String,
    utxo_tx: mpsc::UnboundedSender<time_network::protocol::UtxoInfo>,
    tx_notif_tx: mpsc::UnboundedSender<TransactionNotification>,
}

impl TcpProtocolListener {
    pub fn new(
        peer_addr: String,
        xpub: String,
        utxo_tx: mpsc::UnboundedSender<time_network::protocol::UtxoInfo>,
        tx_notif_tx: mpsc::UnboundedSender<TransactionNotification>,
    ) -> Self {
        Self {
            peer_addr,
            xpub,
            utxo_tx,
            tx_notif_tx,
        }
    }

    /// Start listening for incoming messages (persistent connection)
    pub async fn start(self) {
        log::debug!("Starting TCP listener for {}", self.peer_addr);

        loop {
            match self.connect_and_listen().await {
                Ok(_) => {
                    log::debug!("TCP connection closed");
                }
                Err(e) => {
                    log::error!("TCP listener error: {}", e);
                }
            }

            // Reconnect after 5 seconds
            log::debug!("Reconnecting in 5s");
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }
    }

    async fn connect_and_listen(&self) -> Result<(), Box<dyn std::error::Error>> {
        use time_network::protocol::HandshakeMessage;

        // Connect to masternode
        log::debug!("Connecting to {}", self.peer_addr);
        let mut stream = TcpStream::connect(&self.peer_addr).await?;

        // Enable TCP_NODELAY for low latency
        stream.set_nodelay(true)?;

        log::debug!("Connected to {}", self.peer_addr);

        // Perform handshake first (required by masternode protocol)
        let network_type = if self.peer_addr.contains("24100") {
            time_network::discovery::NetworkType::Testnet
        } else {
            time_network::discovery::NetworkType::Mainnet
        };

        let our_addr = "0.0.0.0:0".parse().unwrap();
        let handshake = HandshakeMessage::new(network_type, our_addr);
        let magic = network_type.magic_bytes();

        // Send magic bytes + handshake
        if let Ok(handshake_json) = serde_json::to_vec(&handshake) {
            let handshake_len = handshake_json.len() as u32;

            log::debug!("Sending handshake to {}", self.peer_addr);
            stream.write_all(&magic).await?;
            stream.write_all(&handshake_len.to_be_bytes()).await?;
            stream.write_all(&handshake_json).await?;
            stream.flush().await?;

            // Read their handshake response
            let mut their_magic = [0u8; 4];
            let mut their_len_bytes = [0u8; 4];

            stream.read_exact(&mut their_magic).await?;
            log::info!("📥 Got magic: {:?}", their_magic);

            if their_magic != magic {
                return Err(format!(
                    "Invalid magic bytes in handshake response: expected {:?}, got {:?}",
                    magic, their_magic
                )
                .into());
            }

            stream.read_exact(&mut their_len_bytes).await?;
            let their_len = u32::from_be_bytes(their_len_bytes) as usize;

            if their_len < 10 * 1024 {
                let mut their_handshake_bytes = vec![0u8; their_len];

                stream.read_exact(&mut their_handshake_bytes).await?;

                if let Ok(_their_handshake) =
                    serde_json::from_slice::<HandshakeMessage>(&their_handshake_bytes)
                {
                    log::debug!("Handshake completed with {}", self.peer_addr);
                } else {
                    log::error!("❌ Failed to parse handshake JSON");
                    return Err("Failed to parse handshake response".into());
                }
            } else {
                return Err(format!("Handshake response too large: {}", their_len).into());
            }
        } else {
            return Err("Failed to serialize our handshake".into());
        }

        // Now register xpub
        log::info!(
            "📤 Registering xpub: {}...",
            &self.xpub[..std::cmp::min(20, self.xpub.len())]
        );

        let register_msg = NetworkMessage::RegisterXpub {
            xpub: self.xpub.clone(),
        };

        self.send_message(&mut stream, register_msg).await?;

        // Wait for XpubRegistered response or UtxoUpdate with 10 second timeout
        let response_timeout = tokio::time::Duration::from_secs(10);
        match tokio::time::timeout(response_timeout, self.read_message(&mut stream)).await {
            Ok(Ok(NetworkMessage::XpubRegistered { success, message })) => {
                if success {
                    log::info!("✅ Connected to {} - xpub registered", self.peer_addr);
                } else {
                    log::error!("❌ Xpub registration failed: {}", message);
                    return Err(message.into());
                }
            }
            Ok(Ok(NetworkMessage::UtxoUpdate { xpub, utxos })) => {
                log::info!(
                    "📦 Initial UTXO update: {} UTXOs for xpub {}",
                    utxos.len(),
                    &xpub[..std::cmp::min(20, xpub.len())]
                );

                // Send each UTXO to channel
                for utxo in utxos {
                    log::info!(
                        "  📍 UTXO: {} - {} TIME",
                        utxo.txid,
                        utxo.amount as f64 / 1_000_000.0
                    );
                    let _ = self.utxo_tx.send(utxo);
                }
            }
            Ok(Ok(msg)) => {
                log::warn!("⚠️ Unexpected response to RegisterXpub: {:?}", msg);
            }
            Ok(Err(e)) => {
                log::error!("❌ Error reading RegisterXpub response: {}", e);
                return Err(e);
            }
            Err(_) => {
                log::error!("❌ Timeout waiting for RegisterXpub response - masternode may not be responding");
                return Err("Timeout waiting for xpub registration response".into());
            }
        }

        // Now listen for push notifications
        log::info!(
            "👂 Listening for push notifications from {}...",
            self.peer_addr
        );

        loop {
            match self.read_message(&mut stream).await {
                Ok(msg) => {
                    if let Err(e) = self.handle_message(msg) {
                        log::error!("Failed to handle message: {}", e);
                    }
                }
                Err(e) => {
                    log::info!("Connection closed: {}", e);
                    break;
                }
            }
        }

        Ok(())
    }

    async fn send_message(
        &self,
        stream: &mut TcpStream,
        message: NetworkMessage,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let data = serde_json::to_vec(&message)?;
        let len = data.len() as u32;
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(&data).await?;
        Ok(())
    }

    async fn read_message(
        &self,
        stream: &mut TcpStream,
    ) -> Result<NetworkMessage, Box<dyn std::error::Error>> {
        // Read message length (4 bytes)
        let mut len_bytes = [0u8; 4];
        stream.read_exact(&mut len_bytes).await?;
        let len = u32::from_be_bytes(len_bytes) as usize;

        // Read message data
        let mut data = vec![0u8; len];
        stream.read_exact(&mut data).await?;

        // Deserialize from JSON
        let message: NetworkMessage = serde_json::from_slice(&data)?;
        Ok(message)
    }

    fn handle_message(&self, msg: NetworkMessage) -> Result<(), Box<dyn std::error::Error>> {
        match msg {
            NetworkMessage::UtxoUpdate { xpub, utxos } => {
                log::info!(
                    "🔔 Received UTXO update: {} UTXOs for xpub {}",
                    utxos.len(),
                    &xpub[..std::cmp::min(20, xpub.len())]
                );

                // Send each UTXO to channel
                for utxo in utxos {
                    let _ = self.utxo_tx.send(utxo);
                }
                Ok(())
            }
            NetworkMessage::NewTransactionNotification { transaction } => {
                log::info!(
                    "🔔 New transaction notification: {} TIME to {}",
                    transaction.amount as f64 / 1_000_000.0,
                    &transaction.to_address[..std::cmp::min(20, transaction.to_address.len())]
                );

                // Convert to UTXO format and send
                let utxo = time_network::protocol::UtxoInfo {
                    txid: transaction.tx_hash,
                    vout: 0,
                    address: transaction.to_address,
                    amount: transaction.amount,
                    block_height: Some(transaction.block_height),
                    confirmations: transaction.confirmations as u64,
                };

                let _ = self.utxo_tx.send(utxo);
                Ok(())
            }
            NetworkMessage::TransactionApproved {
                txid,
                approver: _,
                timestamp,
            } => {
                log::info!(
                    "✅ Transaction APPROVED: {} at {}",
                    &txid[..std::cmp::min(16, txid.len())],
                    timestamp
                );
                // Send notification to UI
                let _ = self
                    .tx_notif_tx
                    .send(TransactionNotification::Approved { txid, timestamp });
                Ok(())
            }
            NetworkMessage::TransactionRejected {
                txid,
                reason,
                rejector: _,
                timestamp: _,
            } => {
                log::warn!(
                    "❌ Transaction REJECTED: {} - Reason: {}",
                    &txid[..std::cmp::min(16, txid.len())],
                    reason
                );
                // Send notification to UI
                let _ = self.tx_notif_tx.send(TransactionNotification::Rejected {
                    txid: txid.clone(),
                    reason: reason.clone(),
                });
                Ok(())
            }
            _ => Ok(()), // Ignore other messages
        }
    }
}
