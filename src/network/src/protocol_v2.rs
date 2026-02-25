//! Protocol V2 - Request/Response with correlation IDs
//!
//! This protocol wraps messages in envelopes that include:
//! - Request ID for correlating responses with requests
//! - Message type classification (Request/Response/Notification)
//! - Proper routing to prevent message crossing
//!
//! # Message Flow
//!
//! ```text
//! Node A                                    Node B
//!   |                                         |
//!   |-- Request(id=1, GetBlockchainInfo) --> |
//!   |                                         |
//!   |<-- Response(id=1, BlockchainInfo) ---- |
//!   |                                         |
//! ```
//!
//! # Message Crossing Prevention
//!
//! When both nodes make concurrent requests:
//!
//! ```text
//! Node A                                    Node B
//!   |                                         |
//!   |-- Request(id=1, GetMempool) ---------> |
//!   |<-- Request(id=2, GetBlockchainInfo) -- |
//!   |                                         |
//!   |-- Response(id=2, BlockchainInfo) ----> |
//!   |<-- Response(id=1, MempoolResponse) --- |
//!   |                                         |
//! ```
//!
//! Each side can correlate responses by matching request IDs.

use crate::protocol::NetworkMessage;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{oneshot, Mutex};

/// Unique identifier for request/response correlation
pub type RequestId = u64;

/// Message envelope for protocol v2
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageEnvelope {
    /// Request message with ID for correlation
    Request {
        id: RequestId,
        message: NetworkMessage,
    },

    /// Response message correlated to request
    Response {
        id: RequestId,
        message: NetworkMessage,
    },

    /// Unsolicited notification (no response expected)
    Notification { message: NetworkMessage },
}

impl MessageEnvelope {
    /// Serialize envelope to bytes
    pub fn serialize(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|e| format!("Serialization error: {}", e))
    }

    /// Deserialize envelope from bytes
    pub fn deserialize(data: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(data).map_err(|e| format!("Deserialization error: {}", e))
    }
}

/// Pending request waiting for response
struct PendingRequest {
    sender: oneshot::Sender<NetworkMessage>,
}

/// Request/Response router for protocol v2
pub struct MessageRouter {
    next_request_id: Arc<Mutex<RequestId>>,
    pending_requests: Arc<Mutex<HashMap<RequestId, PendingRequest>>>,
}

impl Default for MessageRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl MessageRouter {
    /// Create a new message router
    pub fn new() -> Self {
        Self {
            next_request_id: Arc::new(Mutex::new(1)),
            pending_requests: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Generate next request ID
    async fn next_id(&self) -> RequestId {
        let mut id = self.next_request_id.lock().await;
        let current = *id;
        *id = id.wrapping_add(1);
        current
    }

    /// Create a request envelope and register for response
    pub async fn create_request(
        &self,
        message: NetworkMessage,
    ) -> (
        RequestId,
        MessageEnvelope,
        oneshot::Receiver<NetworkMessage>,
    ) {
        let id = self.next_id().await;
        let (tx, rx) = oneshot::channel();

        let mut pending = self.pending_requests.lock().await;
        pending.insert(id, PendingRequest { sender: tx });

        let envelope = MessageEnvelope::Request { id, message };

        (id, envelope, rx)
    }

    /// Create a response envelope
    pub fn create_response(id: RequestId, message: NetworkMessage) -> MessageEnvelope {
        MessageEnvelope::Response { id, message }
    }

    /// Create a notification envelope (no response expected)
    pub fn create_notification(message: NetworkMessage) -> MessageEnvelope {
        MessageEnvelope::Notification { message }
    }

    /// Route an incoming envelope
    pub async fn route_envelope(&self, envelope: MessageEnvelope) -> Option<NetworkMessage> {
        match envelope {
            MessageEnvelope::Request { id: _, message } => {
                // This is a request from peer - return it for handling
                // The handler should send back a Response with the same id
                Some(message)
            }
            MessageEnvelope::Response { id, message } => {
                // This is a response to our request - deliver to waiting receiver
                let mut pending = self.pending_requests.lock().await;
                if let Some(request) = pending.remove(&id) {
                    let _ = request.sender.send(message);
                    None // Handled internally
                } else {
                    // Unexpected response (no pending request)
                    tracing::warn!(id, "Received response for unknown request");
                    None
                }
            }
            MessageEnvelope::Notification { message } => {
                // Unsolicited message - return for handling
                Some(message)
            }
        }
    }

    /// Cancel a pending request (e.g., on timeout)
    pub async fn cancel_request(&self, id: RequestId) {
        let mut pending = self.pending_requests.lock().await;
        pending.remove(&id);
    }

    /// Get count of pending requests (for diagnostics)
    pub async fn pending_count(&self) -> usize {
        self.pending_requests.lock().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_request_response_flow() {
        let router = MessageRouter::new();

        // Node A creates a request
        let (id, envelope, mut rx) = router
            .create_request(NetworkMessage::GetBlockchainInfo)
            .await;

        assert!(matches!(envelope, MessageEnvelope::Request { .. }));

        // Simulate response from Node B
        let response = MessageRouter::create_response(
            id,
            NetworkMessage::BlockchainInfo {
                height: Some(100),
                best_block_hash: "abc123".to_string(),
            },
        );

        // Route the response
        router.route_envelope(response).await;

        // Receiver should get the message
        let received = rx.await.unwrap();
        assert!(matches!(
            received,
            NetworkMessage::BlockchainInfo {
                height: Some(100),
                ..
            }
        ));
    }

    #[tokio::test]
    async fn test_notification() {
        let router = MessageRouter::new();

        let notification = MessageRouter::create_notification(NetworkMessage::Ping);

        let result = router.route_envelope(notification).await;
        assert!(result.is_some());
        assert!(matches!(result.unwrap(), NetworkMessage::Ping));
    }

    #[tokio::test]
    async fn test_concurrent_requests() {
        let router = Arc::new(MessageRouter::new());

        // Create two concurrent requests
        let (id1, _env1, mut rx1) = router.create_request(NetworkMessage::GetMempool).await;

        let (id2, _env2, mut rx2) = router
            .create_request(NetworkMessage::GetBlockchainInfo)
            .await;

        assert_ne!(id1, id2);

        // Responses arrive in reverse order
        let resp2 = MessageRouter::create_response(
            id2,
            NetworkMessage::BlockchainInfo {
                height: Some(50),
                best_block_hash: "xyz".to_string(),
            },
        );

        let resp1 = MessageRouter::create_response(id1, NetworkMessage::MempoolResponse(vec![]));

        // Route them
        router.route_envelope(resp2).await;
        router.route_envelope(resp1).await;

        // Each receiver should get the correct response
        let r2 = rx2.await.unwrap();
        assert!(matches!(r2, NetworkMessage::BlockchainInfo { .. }));

        let r1 = rx1.await.unwrap();
        assert!(matches!(r1, NetworkMessage::MempoolResponse(_)));
    }
}
