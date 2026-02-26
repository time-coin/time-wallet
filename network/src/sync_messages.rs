//! Synchronization message handler
//!
//! Handles HeightRequest/Response, BlockRequest/Response, and ChainRequest/Response messages
//! for the three-tier network synchronization strategy.

use crate::error::NetworkError;
use crate::protocol::NetworkMessage;
use std::sync::Arc;
use time_core::state::BlockchainState;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Handler for synchronization-related network messages
pub struct SyncMessageHandler {
    blockchain: Arc<RwLock<BlockchainState>>,
}

impl SyncMessageHandler {
    /// Create a new sync message handler
    pub fn new(blockchain: Arc<RwLock<BlockchainState>>) -> Self {
        Self { blockchain }
    }

    /// Handle incoming sync message and generate response
    pub async fn handle_message(
        &self,
        message: NetworkMessage,
    ) -> Result<Option<NetworkMessage>, NetworkError> {
        match message {
            // Tier 1: Height queries
            NetworkMessage::HeightRequest => self.handle_height_request().await,

            // Tier 2: Block queries
            NetworkMessage::BlockRequest { height } => self.handle_block_request(height).await,

            // Tier 3: Chain queries
            NetworkMessage::ChainRequest { from_height } => {
                self.handle_chain_request(from_height).await
            }

            // State Snapshot queries
            NetworkMessage::StateSnapshotRequest { height } => {
                self.handle_state_snapshot_request(height).await
            }

            // Handle responses (for client side)
            NetworkMessage::HeightResponse { .. }
            | NetworkMessage::BlockResponse { .. }
            | NetworkMessage::ChainResponse { .. }
            | NetworkMessage::StateSnapshotResponse { .. } => {
                // Responses are handled by the requesting side
                Ok(None)
            }

            _ => Ok(None), // Not a sync message
        }
    }

    /// Handle height request - return current blockchain height
    async fn handle_height_request(&self) -> Result<Option<NetworkMessage>, NetworkError> {
        let blockchain = self.blockchain.read().await;
        let height = blockchain.chain_tip_height();
        let best_block_hash = blockchain.chain_tip_hash().to_string();

        debug!(height, hash = %best_block_hash, "responding to height request");

        Ok(Some(NetworkMessage::HeightResponse {
            height,
            best_block_hash,
        }))
    }

    /// Handle block request - return specific block by height
    async fn handle_block_request(
        &self,
        height: u64,
    ) -> Result<Option<NetworkMessage>, NetworkError> {
        let blockchain = self.blockchain.read().await;

        match blockchain.get_block_by_height(height) {
            Some(block) => {
                debug!(height, "sending block");
                Ok(Some(NetworkMessage::BlockResponse {
                    block: Some(block.clone()),
                }))
            }
            None => {
                warn!(height, "block not found");
                Ok(Some(NetworkMessage::BlockResponse { block: None }))
            }
        }
    }

    /// Handle chain request - return blocks starting from height
    async fn handle_chain_request(
        &self,
        from_height: u64,
    ) -> Result<Option<NetworkMessage>, NetworkError> {
        let blockchain = self.blockchain.read().await;
        let current_height = blockchain.chain_tip_height();

        // Limit batch size to prevent overwhelming the network
        const MAX_BATCH_SIZE: u64 = 100;

        let end_height = (from_height + MAX_BATCH_SIZE).min(current_height);
        let mut blocks = Vec::new();

        for height in from_height..=end_height {
            if let Some(block) = blockchain.get_block_by_height(height) {
                blocks.push(block.clone());
            } else {
                warn!(height, "block not found in chain request");
                break;
            }
        }

        let complete = end_height >= current_height;

        info!(
            from = from_height,
            to = end_height,
            count = blocks.len(),
            complete,
            "sending chain response"
        );

        Ok(Some(NetworkMessage::ChainResponse { blocks, complete }))
    }

    /// Handle state snapshot request - return compressed UTXO state
    async fn handle_state_snapshot_request(
        &self,
        height: u64,
    ) -> Result<Option<NetworkMessage>, NetworkError> {
        let blockchain = self.blockchain.read().await;

        // Check if height is valid
        let current_height = blockchain.chain_tip_height();
        if height > current_height {
            warn!(
                requested = height,
                current = current_height,
                "snapshot height too high"
            );
            return Ok(None);
        }

        info!(height, "creating state snapshot");

        // Get UTXO state at height
        let utxo_set = blockchain.utxo_set();

        // Calculate merkle root for verification
        let merkle_root = time_core::calculate_utxo_merkle_root(utxo_set);

        // Serialize UTXO state
        let serialized = bincode::serialize(utxo_set)
            .map_err(|e| NetworkError::SerializationError(e.to_string()))?;

        // Compress state data
        let compressed = compress_data(&serialized)?;
        let snapshot_size = compressed.len() as u64;

        info!(
            height,
            original_size = serialized.len(),
            compressed_size = snapshot_size,
            compression_ratio = format!("{:.1}x", serialized.len() as f64 / snapshot_size as f64),
            merkle_root = &merkle_root[..16],
            "sending state snapshot"
        );

        Ok(Some(NetworkMessage::StateSnapshotResponse {
            height,
            utxo_merkle_root: merkle_root,
            state_data: compressed,
            compressed: true,
            snapshot_size_bytes: snapshot_size,
        }))
    }
}

/// Compress data using flate2/gzip
fn compress_data(data: &[u8]) -> Result<Vec<u8>, NetworkError> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).map_err(NetworkError::IoError)?;
    encoder.finish().map_err(NetworkError::IoError)
}

/// Decompress data using flate2/gzip
#[allow(dead_code)]
fn decompress_data(data: &[u8]) -> Result<Vec<u8>, NetworkError> {
    use flate2::read::GzDecoder;
    use std::io::Read;

    let mut decoder = GzDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .map_err(NetworkError::IoError)?;
    Ok(decompressed)
}

// ═══════════════════════════════════════════════════════════════
// Helper functions for sending sync requests
// ═══════════════════════════════════════════════════════════════

/// Send height request to peer
pub async fn send_height_request(peer_address: &str) -> Result<(u64, String), NetworkError> {
    // TODO: Implement actual network send/receive
    // This is a placeholder that will be integrated with the existing connection infrastructure
    debug!(peer = peer_address, "sending height request");

    // For now, return an error indicating this needs integration
    Err(NetworkError::NotImplemented)
}

/// Send block request to peer
pub async fn send_block_request(
    peer_address: &str,
    height: u64,
) -> Result<Option<time_core::block::Block>, NetworkError> {
    debug!(peer = peer_address, height, "sending block request");

    // TODO: Implement actual network send/receive
    Err(NetworkError::NotImplemented)
}

/// Send chain request to peer
pub async fn send_chain_request(
    peer_address: &str,
    from_height: u64,
) -> Result<Vec<time_core::block::Block>, NetworkError> {
    debug!(peer = peer_address, from_height, "sending chain request");

    // TODO: Implement actual network send/receive
    Err(NetworkError::NotImplemented)
}
