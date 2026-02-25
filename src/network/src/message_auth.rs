//! Message authentication and signature verification for network messages

use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Message expired: timestamp {timestamp}, current {current}")]
    MessageExpired { timestamp: u64, current: u64 },

    #[error("Invalid timestamp: {0} is in the future")]
    FutureTimestamp(u64),

    #[error("Replay attack detected: nonce {0} already used")]
    ReplayAttack(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Authenticated network message with signature
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuthenticatedMessage {
    /// The actual message payload (serialized)
    pub payload: Vec<u8>,

    /// Sender's public key (address)
    pub sender: String,

    /// Message timestamp (seconds since UNIX epoch)
    pub timestamp: u64,

    /// Unique nonce to prevent replay attacks
    pub nonce: String,

    /// Signature over (payload + sender + timestamp + nonce)
    pub signature: Vec<u8>,
}

impl AuthenticatedMessage {
    /// Create a new authenticated message
    pub fn new(payload: Vec<u8>, sender: String, private_key: &[u8]) -> Result<Self, AuthError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Generate random nonce
        let nonce = format!("{:x}", rand::random::<u64>());

        let signature = Self::sign_message(&payload, &sender, timestamp, &nonce, private_key)?;

        Ok(Self {
            payload,
            sender,
            timestamp,
            nonce,
            signature,
        })
    }

    /// Sign a message with private key
    fn sign_message(
        payload: &[u8],
        sender: &str,
        timestamp: u64,
        nonce: &str,
        private_key: &[u8],
    ) -> Result<Vec<u8>, AuthError> {
        // Create message hash
        let mut hasher = Sha256::new();
        hasher.update(payload);
        hasher.update(sender.as_bytes());
        hasher.update(timestamp.to_le_bytes());
        hasher.update(nonce.as_bytes());
        let hash = hasher.finalize();

        // In production, use proper ECDSA signing
        // For now, use HMAC-style signing with private key
        let mut sig_hasher = Sha256::new();
        sig_hasher.update(private_key);
        sig_hasher.update(hash);
        let signature = sig_hasher.finalize();

        Ok(signature.to_vec())
    }

    /// Verify message signature
    pub fn verify(&self, expected_sender_pubkey: &[u8]) -> Result<(), AuthError> {
        // Check timestamp is not in the future (allow 5 min clock skew)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if self.timestamp > now + 300 {
            return Err(AuthError::FutureTimestamp(self.timestamp));
        }

        // Check message is not too old (15 minute expiry)
        if now - self.timestamp > 900 {
            return Err(AuthError::MessageExpired {
                timestamp: self.timestamp,
                current: now,
            });
        }

        // Verify signature
        let expected_sig = Self::sign_message(
            &self.payload,
            &self.sender,
            self.timestamp,
            &self.nonce,
            expected_sender_pubkey,
        )?;

        if self.signature != expected_sig {
            return Err(AuthError::InvalidSignature);
        }

        Ok(())
    }

    /// Get message age in seconds
    pub fn age_seconds(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now.saturating_sub(self.timestamp)
    }
}

/// Nonce tracker to prevent replay attacks
pub struct NonceTracker {
    used_nonces:
        std::sync::Arc<tokio::sync::RwLock<std::collections::HashMap<String, std::time::Instant>>>,
}

impl NonceTracker {
    pub fn new() -> Self {
        Self {
            used_nonces: std::sync::Arc::new(tokio::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
        }
    }

    /// Check if nonce has been used and mark it as used
    pub async fn check_and_mark(&self, nonce: &str) -> Result<(), AuthError> {
        let mut nonces = self.used_nonces.write().await;

        // CRITICAL FIX (Issue #11): Clean up expired nonces (older than 900 seconds = message expiry)
        // This prevents memory bloat and uses proper time-based expiry instead of random cleanup
        let now = std::time::Instant::now();
        let expiry_duration = std::time::Duration::from_secs(900); // 15 minutes (matches message expiry)
        nonces.retain(|_, &mut timestamp| now.duration_since(timestamp) < expiry_duration);

        if nonces.contains_key(nonce) {
            return Err(AuthError::ReplayAttack(nonce.to_string()));
        }

        nonces.insert(nonce.to_string(), now);

        Ok(())
    }

    /// Clear all nonces (for testing)
    pub async fn clear(&self) {
        self.used_nonces.write().await.clear();
    }
}

impl Default for NonceTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_signing() {
        let payload = b"test message".to_vec();
        let sender = "test_sender".to_string();
        let private_key = b"test_private_key";

        let msg = AuthenticatedMessage::new(payload, sender, private_key).unwrap();

        // Verify with correct key
        assert!(msg.verify(private_key).is_ok());

        // Verify with wrong key should fail
        let wrong_key = b"wrong_private_key";
        assert!(msg.verify(wrong_key).is_err());
    }

    #[tokio::test]
    async fn test_replay_prevention() {
        let tracker = NonceTracker::new();
        let nonce = "test_nonce_123";

        // First use should succeed
        assert!(tracker.check_and_mark(nonce).await.is_ok());

        // Second use should fail
        assert!(tracker.check_and_mark(nonce).await.is_err());
    }

    #[test]
    fn test_timestamp_validation() {
        let payload = b"test".to_vec();
        let sender = "sender".to_string();
        let key = b"key";

        let mut msg = AuthenticatedMessage::new(payload, sender, key).unwrap();

        // Set timestamp to future (beyond 5 min skew)
        let future = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 400;
        msg.timestamp = future;

        // Should fail verification
        assert!(matches!(
            msg.verify(key),
            Err(AuthError::FutureTimestamp(_))
        ));
    }
}
