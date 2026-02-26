//! Protocol V2 Connection Wrapper
//!
//! Wraps a PeerConnection with protocol v2 message routing to prevent message crossing.

use crate::connection::PeerConnection;
use crate::protocol::NetworkMessage;
use crate::protocol_v2::{MessageEnvelope, MessageRouter, RequestId};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

/// Connection using Protocol V2 with request/response correlation
pub struct ConnectionV2 {
    connection: Arc<Mutex<PeerConnection>>,
    router: Arc<MessageRouter>,
}

impl ConnectionV2 {
    /// Wrap an existing connection with protocol v2
    pub fn new(connection: PeerConnection) -> Self {
        Self {
            connection: Arc::new(Mutex::new(connection)),
            router: Arc::new(MessageRouter::new()),
        }
    }

    /// Send a request and wait for correlated response
    pub async fn request(
        &self,
        message: NetworkMessage,
        timeout: Duration,
    ) -> Result<NetworkMessage, String> {
        // Create request envelope
        let (id, envelope, rx) = self.router.create_request(message).await;

        // Send the envelope
        let data = envelope.serialize()?;
        {
            let mut conn = self.connection.lock().await;
            conn.send_raw(&data).await?;
        }

        // Wait for response with timeout
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => {
                self.router.cancel_request(id).await;
                Err("Response channel closed".to_string())
            }
            Err(_) => {
                self.router.cancel_request(id).await;
                Err(format!("Request timeout after {:?}", timeout))
            }
        }
    }

    /// Send a response to a received request
    pub async fn respond(
        &self,
        request_id: RequestId,
        message: NetworkMessage,
    ) -> Result<(), String> {
        let envelope = MessageRouter::create_response(request_id, message);
        let data = envelope.serialize()?;

        let mut conn = self.connection.lock().await;
        conn.send_raw(&data).await
    }

    /// Send a notification (no response expected)
    pub async fn notify(&self, message: NetworkMessage) -> Result<(), String> {
        let envelope = MessageRouter::create_notification(message);
        let data = envelope.serialize()?;

        let mut conn = self.connection.lock().await;
        conn.send_raw(&data).await
    }

    /// Receive and route an incoming message
    /// Returns Some(message, request_id) for requests/notifications that need handling
    /// Returns None for responses (handled internally by router)
    pub async fn receive(&self) -> Result<Option<(NetworkMessage, Option<RequestId>)>, String> {
        // Receive raw data
        let data = {
            let mut conn = self.connection.lock().await;
            conn.receive_raw().await?
        };

        // Deserialize envelope
        let envelope = MessageEnvelope::deserialize(&data)?;

        // Extract request ID if this is a request
        let request_id = match &envelope {
            MessageEnvelope::Request { id, .. } => Some(*id),
            _ => None,
        };

        // Route the envelope
        match self.router.route_envelope(envelope).await {
            Some(message) => Ok(Some((message, request_id))),
            None => Ok(None), // Response was handled internally
        }
    }

    /// Check connection health
    pub async fn is_alive(&self) -> bool {
        let conn = self.connection.lock().await;
        conn.is_alive().await
    }

    /// Get diagnostics
    pub async fn diagnostics(&self) -> String {
        let pending = self.router.pending_count().await;
        format!("Pending requests: {}", pending)
    }
}

// Extension methods for PeerConnection to support raw send/receive
impl PeerConnection {
    /// Send raw bytes (for protocol v2 envelopes)
    pub(crate) async fn send_raw(&mut self, data: &[u8]) -> Result<(), String> {
        let len = data.len() as u32;
        let mut writer_guard = self.writer.lock().await;

        writer_guard
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|e| format!("Failed to write length: {}", e))?;

        writer_guard
            .write_all(data)
            .await
            .map_err(|e| format!("Failed to write data: {}", e))?;

        writer_guard
            .flush()
            .await
            .map_err(|e| format!("Failed to flush: {}", e))?;

        Ok(())
    }

    /// Receive raw bytes (for protocol v2 envelopes)
    pub(crate) async fn receive_raw(&mut self) -> Result<Vec<u8>, String> {
        let mut reader_guard = self.reader.lock().await;

        let mut len_bytes = [0u8; 4];
        reader_guard
            .read_exact(&mut len_bytes)
            .await
            .map_err(|e| format!("Failed to read length: {}", e))?;

        let len = u32::from_be_bytes(len_bytes) as usize;

        if len > 50 * 1024 * 1024 {
            return Err("Message too large (>50MB)".into());
        }

        let mut buf = vec![0u8; len];
        reader_guard
            .read_exact(&mut buf)
            .await
            .map_err(|e| format!("Failed to read data: {}", e))?;

        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    // Tests would require mock connections
    // For now, the protocol_v2 module has comprehensive unit tests
}
