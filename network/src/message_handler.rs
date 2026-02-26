//! Async message handler for multiplexed TCP connections
//! Allows concurrent send/receive without protocol collisions

use crate::protocol::NetworkMessage;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use tracing::{debug, warn};

type ResponseSender = oneshot::Sender<NetworkMessage>;
type RequestId = u64;

/// Async message handler with request-response multiplexing
pub struct MessageHandler {
    /// Channel for sending outgoing messages
    tx_sender: mpsc::UnboundedSender<(NetworkMessage, Option<RequestId>)>,
    /// Pending response channels
    pending_responses: Arc<RwLock<HashMap<RequestId, ResponseSender>>>,
    /// Next request ID
    next_request_id: Arc<Mutex<RequestId>>,
}

impl MessageHandler {
    /// Create a new async message handler
    pub fn new(
        stream: TcpStream,
        broadcast_handler: Arc<dyn Fn(NetworkMessage) + Send + Sync>,
    ) -> Self {
        let (tx_sender, tx_receiver) = mpsc::unbounded_channel();
        let pending_responses = Arc::new(RwLock::new(HashMap::new()));
        let stream = Arc::new(Mutex::new(stream));

        // Spawn sender task (write loop)
        Self::spawn_sender_task(stream.clone(), tx_receiver);

        // Spawn receiver task (read loop)
        Self::spawn_receiver_task(
            stream.clone(),
            pending_responses.clone(),
            broadcast_handler.clone(),
            tx_sender.clone(),
        );

        Self {
            tx_sender,
            pending_responses,
            next_request_id: Arc::new(Mutex::new(0)),
        }
    }

    /// Send a message asynchronously (fire-and-forget, non-blocking)
    pub fn send(&self, msg: NetworkMessage) -> Result<(), String> {
        self.tx_sender
            .send((msg, None))
            .map_err(|e| format!("Send channel closed: {}", e))
    }

    /// Send a message and wait for response (with timeout)
    pub async fn send_with_response(
        &self,
        msg: NetworkMessage,
        timeout: std::time::Duration,
    ) -> Result<NetworkMessage, String> {
        // Generate request ID
        let request_id = {
            let mut id = self.next_request_id.lock().await;
            *id += 1;
            *id
        };

        // Create response channel
        let (tx, rx) = oneshot::channel();
        self.pending_responses.write().await.insert(request_id, tx);

        // Send message with request ID
        self.tx_sender
            .send((msg, Some(request_id)))
            .map_err(|e| format!("Send channel closed: {}", e))?;

        // Wait for response with timeout
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => {
                // Clean up pending response
                self.pending_responses.write().await.remove(&request_id);
                Err("Response channel closed".to_string())
            }
            Err(_) => {
                // Clean up pending response
                self.pending_responses.write().await.remove(&request_id);
                Err("Response timeout".to_string())
            }
        }
    }

    /// Spawn background task to send messages
    fn spawn_sender_task(
        stream: Arc<Mutex<TcpStream>>,
        mut rx: mpsc::UnboundedReceiver<(NetworkMessage, Option<RequestId>)>,
    ) {
        tokio::spawn(async move {
            while let Some((msg, _request_id)) = rx.recv().await {
                let mut stream = stream.lock().await;

                // Serialize message
                let json = match serde_json::to_vec(&msg) {
                    Ok(j) => j,
                    Err(e) => {
                        warn!("Failed to serialize message: {}", e);
                        continue;
                    }
                };
                let len = json.len() as u32;

                // Send length + payload
                if let Err(e) = stream.write_all(&len.to_be_bytes()).await {
                    debug!("Failed to write length: {}", e);
                    break;
                }
                if let Err(e) = stream.write_all(&json).await {
                    debug!("Failed to write message: {}", e);
                    break;
                }
                if let Err(e) = stream.flush().await {
                    debug!("Failed to flush: {}", e);
                    break;
                }

                debug!("📤 Sent message");
            }
            debug!("Sender task exiting");
        });
    }

    /// Spawn background task to receive messages
    fn spawn_receiver_task(
        stream: Arc<Mutex<TcpStream>>,
        pending_responses: Arc<RwLock<HashMap<RequestId, ResponseSender>>>,
        handler: Arc<dyn Fn(NetworkMessage) + Send + Sync>,
        tx_sender: mpsc::UnboundedSender<(NetworkMessage, Option<RequestId>)>,
    ) {
        tokio::spawn(async move {
            loop {
                let mut stream = stream.lock().await;

                // Read length
                let mut len_bytes = [0u8; 4];
                if let Err(e) = stream.read_exact(&mut len_bytes).await {
                    debug!("Connection closed or error reading length: {}", e);
                    break;
                }
                let len = u32::from_be_bytes(len_bytes) as usize;

                if len > 10 * 1024 * 1024 {
                    warn!("Message too large: {} bytes", len);
                    break;
                }

                // Read payload
                let mut buf = vec![0u8; len];
                if let Err(e) = stream.read_exact(&mut buf).await {
                    debug!("Error reading message payload: {}", e);
                    break;
                }

                // Release lock before processing
                drop(stream);

                // Deserialize message
                let msg = match serde_json::from_slice::<NetworkMessage>(&buf) {
                    Ok(m) => m,
                    Err(e) => {
                        warn!("Failed to deserialize message: {}", e);
                        continue;
                    }
                };

                debug!("📥 Received message");

                // Route message based on type
                match &msg {
                    // Auto-respond to Ping with Pong
                    NetworkMessage::Ping => {
                        debug!("Received Ping, auto-responding with Pong");
                        // Send Pong response immediately
                        if let Err(e) = tx_sender.send((NetworkMessage::Pong, None)) {
                            warn!("Failed to send Pong response: {}", e);
                        }
                        // Also notify handler for logging/stats
                        handler(msg);
                    }
                    // Auto-respond to TimeRequest with TimeResponse
                    NetworkMessage::TimeRequest { request_time_ms } => {
                        debug!("Received TimeRequest, auto-responding with TimeResponse");
                        let peer_time_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_millis() as i64;
                        let response = NetworkMessage::TimeResponse {
                            request_time_ms: *request_time_ms,
                            peer_time_ms,
                        };
                        if let Err(e) = tx_sender.send((response, None)) {
                            warn!("Failed to send TimeResponse: {}", e);
                        }
                        // Also notify handler
                        handler(msg);
                    }
                    // Check if this is a response to a pending request
                    NetworkMessage::Pong
                    | NetworkMessage::BlockchainInfo { .. }
                    | NetworkMessage::Blocks { .. }
                    | NetworkMessage::TimeResponse { .. }
                    | NetworkMessage::InstantFinalityVote { .. } => {
                        // Try to match with pending response
                        let mut responses = pending_responses.write().await;
                        if let Some(id) = responses.keys().next().copied() {
                            // Simple approach: match first pending request
                            // TODO: Add proper request ID tracking in protocol
                            if let Some(sender) = responses.remove(&id) {
                                if sender.send(msg.clone()).is_err() {
                                    debug!("Failed to send response - receiver dropped");
                                }
                            }
                        } else {
                            // No pending request, treat as broadcast
                            handler(msg);
                        }
                    }
                    // All other messages are broadcasts
                    _ => {
                        handler(msg);
                    }
                }
            }
            debug!("Receiver task exiting");
        });
    }
}

/// Default message handler that logs received messages
pub fn default_message_handler() -> Arc<dyn Fn(NetworkMessage) + Send + Sync> {
    Arc::new(|msg: NetworkMessage| {
        debug!("Received broadcast message: {:?}", msg);
    })
}
