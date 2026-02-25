/// Network error types using thiserror for consistent error handling
/// CRITICAL FIX (Issue #13): Standardized error types across network module
use std::net::IpAddr;
use std::time::Duration;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("Connection failed to {peer}: {reason}")]
    ConnectionFailed { peer: String, reason: String },

    #[error("Connection timeout after {timeout:?}")]
    ConnectionTimeout { timeout: Duration },

    #[error("Handshake failed with {peer}: {reason}")]
    HandshakeFailed { peer: String, reason: String },

    #[error("Peer {0} is quarantined")]
    PeerQuarantined(IpAddr),

    #[error("No seed nodes discovered from any source")]
    NoSeedNodes,

    #[error("No TCP connection available for {0}")]
    NoConnection(IpAddr),

    #[error("Failed to send message to {peer}: {reason}")]
    SendFailed { peer: IpAddr, reason: String },

    #[error("Failed to receive message from {peer}: {reason}")]
    ReceiveFailed { peer: IpAddr, reason: String },

    #[error("Message timeout after {timeout:?}")]
    MessageTimeout { timeout: Duration },

    #[error("Invalid peer address: {0}")]
    InvalidAddress(String),

    #[error("Broadcast failed: {0}")]
    BroadcastFailed(String),

    #[error("Peer exchange error: {0}")]
    PeerExchangeError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("State error: {0}")]
    StateError(#[from] time_core::StateError),

    // Sync-related errors
    #[error("No peers available for synchronization")]
    NoPeersAvailable,

    #[error("No consensus reached among peers")]
    NoConsensusReached,

    #[error("Timeout waiting for response")]
    Timeout,

    #[error("Block not found")]
    BlockNotFound,

    #[error("Sync gap too large: {0} blocks")]
    SyncGapTooLarge(u64),

    #[error("Critical sync required - manual intervention needed")]
    CriticalSyncRequired,

    #[error("Invalid merkle root in snapshot")]
    InvalidMerkleRoot,

    #[error("Snapshot verification failed: {0}")]
    SnapshotVerificationFailed(String),

    #[error("Sync failed: {0}")]
    SyncFailed(String),

    #[error("Feature not yet implemented")]
    NotImplemented,
}

/// Convert NetworkError to String for backward compatibility
impl From<NetworkError> for String {
    fn from(err: NetworkError) -> Self {
        err.to_string()
    }
}

/// Result type alias for network operations
pub type NetworkResult<T> = Result<T, NetworkError>;
