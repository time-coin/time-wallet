//! WebSocket client for real-time transaction notifications from masternodes.
//!
//! Connects to the masternode's WebSocket server, subscribes to the wallet's
//! address, and receives instant notifications when transactions arrive.
//! Includes automatic reconnection with exponential backoff.

use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

/// Notification received from the masternode WebSocket server
#[derive(Clone, Debug, Deserialize)]
pub struct TxNotification {
    pub txid: String,
    pub address: String,
    pub amount: serde_json::Value,
    pub output_index: u32,
    pub timestamp: i64,
    pub confirmations: u32,
}

/// Notification that a UTXO has been finalized by masternode consensus
#[derive(Clone, Debug, Deserialize)]
pub struct UtxoFinalizedNotification {
    pub txid: String,
    pub output_index: u32,
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub amount: serde_json::Value,
}

/// Server message envelope
#[derive(Deserialize, Debug)]
struct ServerMessage {
    #[serde(rename = "type")]
    msg_type: String,
    #[serde(default)]
    data: Option<serde_json::Value>,
}

/// Client message to server
#[derive(Serialize)]
struct ClientMessage {
    method: String,
    params: serde_json::Value,
}

/// Notification that a transaction was rejected by the masternode
#[derive(Clone, Debug, Deserialize)]
pub struct TxRejectedNotification {
    pub txid: String,
    #[serde(default)]
    pub reason: String,
}

/// Events sent from the WebSocket client to the wallet UI
#[derive(Clone, Debug)]
pub enum WsEvent {
    /// A new transaction was detected for our address
    TransactionReceived(TxNotification),
    /// A UTXO has been finalized (locked by masternode consensus)
    UtxoFinalized(UtxoFinalizedNotification),
    /// A transaction was rejected by the masternode
    TransactionRejected(TxRejectedNotification),
    /// WebSocket connected successfully
    Connected(String),
    /// WebSocket disconnected
    Disconnected(String),
}

/// WebSocket client that maintains a persistent connection to a masternode
pub struct WsClient;

impl WsClient {
    /// Start the WebSocket client in a background task.
    ///
    /// Connects to the masternode's WebSocket server, subscribes to the given
    /// addresses, and sends notifications through the event channel.
    /// Automatically reconnects with exponential backoff on disconnect.
    pub fn start(
        ws_url: String,
        addresses: Vec<String>,
        event_tx: mpsc::UnboundedSender<WsEvent>,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut backoff_secs = 1u64;
            let max_backoff = 60u64;

            loop {
                // Check shutdown
                if *shutdown.borrow() {
                    log::info!("🛑 WebSocket client shutting down");
                    break;
                }

                log::info!("📡 Connecting to WebSocket at {}...", ws_url);

                match tokio_tungstenite::connect_async(&ws_url).await {
                    Ok((ws_stream, _response)) => {
                        log::info!("✅ WebSocket connected to {}", ws_url);
                        backoff_secs = 1; // Reset backoff on successful connect

                        let _ = event_tx.send(WsEvent::Connected(ws_url.clone()));

                        let result = Self::handle_connection(
                            ws_stream,
                            &addresses,
                            &event_tx,
                            shutdown.clone(),
                        )
                        .await;

                        match result {
                            Ok(()) => {
                                log::info!("WebSocket connection closed normally");
                            }
                            Err(e) => {
                                log::warn!("⚠️ WebSocket connection error: {}", e);
                            }
                        }

                        let _ = event_tx.send(WsEvent::Disconnected(ws_url.clone()));
                    }
                    Err(e) => {
                        log::warn!(
                            "⚠️ WebSocket connection failed: {} (retry in {}s)",
                            e,
                            backoff_secs
                        );
                    }
                }

                // Check shutdown before sleeping
                if *shutdown.borrow() {
                    break;
                }

                // Exponential backoff
                tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
                backoff_secs = (backoff_secs * 2).min(max_backoff);
            }
        })
    }

    async fn handle_connection(
        ws_stream: tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        addresses: &[String],
        event_tx: &mpsc::UnboundedSender<WsEvent>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (mut ws_sender, mut ws_receiver) = ws_stream.split();

        // Subscribe to all wallet addresses
        for address in addresses {
            let subscribe_msg = ClientMessage {
                method: "subscribe".to_string(),
                params: serde_json::json!({"address": address}),
            };
            let json = serde_json::to_string(&subscribe_msg)?;
            ws_sender.send(Message::Text(json)).await?;
        }
        log::info!("📡 Subscribed to {} addresses", addresses.len());

        // Heartbeat interval
        let mut heartbeat = tokio::time::interval(std::time::Duration::from_secs(25));

        loop {
            tokio::select! {
                msg = ws_receiver.next() => {
                    match msg {
                        Some(Ok(Message::Text(text))) => {
                            Self::handle_server_message(&text, event_tx);
                        }
                        Some(Ok(Message::Ping(data))) => {
                            ws_sender.send(Message::Pong(data)).await?;
                        }
                        Some(Ok(Message::Close(_))) | None => {
                            log::info!("WebSocket server closed connection");
                            break;
                        }
                        Some(Err(e)) => {
                            return Err(Box::new(e));
                        }
                        _ => {}
                    }
                }

                // Send periodic ping to keep connection alive
                _ = heartbeat.tick() => {
                    let ping_msg = ClientMessage {
                        method: "ping".to_string(),
                        params: serde_json::json!({}),
                    };
                    let json = serde_json::to_string(&ping_msg)?;
                    if ws_sender.send(Message::Text(json)).await.is_err() {
                        break;
                    }
                }

                // Shutdown signal
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        let _ = ws_sender.send(Message::Close(None)).await;
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    fn handle_server_message(text: &str, event_tx: &mpsc::UnboundedSender<WsEvent>) {
        match serde_json::from_str::<ServerMessage>(text) {
            Ok(msg) => match msg.msg_type.as_str() {
                "tx_notification" => {
                    if let Some(data) = msg.data {
                        match serde_json::from_value::<TxNotification>(data) {
                            Ok(notif) => {
                                log::info!(
                                    "💰 Transaction received! {} TIME (txid: {}...)",
                                    notif.amount,
                                    &notif.txid[..std::cmp::min(16, notif.txid.len())]
                                );
                                let _ = event_tx.send(WsEvent::TransactionReceived(notif));
                            }
                            Err(e) => {
                                log::warn!("Failed to parse tx_notification: {}", e);
                            }
                        }
                    }
                }
                "utxo_finalized" => {
                    if let Some(data) = msg.data {
                        match serde_json::from_value::<UtxoFinalizedNotification>(data) {
                            Ok(notif) => {
                                log::info!(
                                    "✅ UTXO finalized! txid: {}... vout: {}",
                                    &notif.txid[..std::cmp::min(16, notif.txid.len())],
                                    notif.output_index
                                );
                                let _ = event_tx.send(WsEvent::UtxoFinalized(notif));
                            }
                            Err(e) => {
                                log::warn!("Failed to parse utxo_finalized: {}", e);
                            }
                        }
                    }
                }
                "subscribed" => {
                    log::info!("✅ Subscription confirmed: {:?}", msg.data);
                }
                "tx_rejected" => {
                    if let Some(data) = msg.data {
                        match serde_json::from_value::<TxRejectedNotification>(data) {
                            Ok(notif) => {
                                log::warn!(
                                    "❌ Transaction rejected! txid: {}... reason: {}",
                                    &notif.txid[..std::cmp::min(16, notif.txid.len())],
                                    notif.reason
                                );
                                let _ = event_tx.send(WsEvent::TransactionRejected(notif));
                            }
                            Err(e) => {
                                log::warn!("Failed to parse tx_rejected: {}", e);
                            }
                        }
                    }
                }
                "pong" => {
                    // Heartbeat response, ignore
                }
                other => {
                    log::debug!("Unknown WebSocket message type: {}", other);
                }
            },
            Err(e) => {
                log::debug!("Failed to parse WebSocket message: {}", e);
            }
        }
    }
}
