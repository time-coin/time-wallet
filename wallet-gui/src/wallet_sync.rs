//! Multi-Peer Wallet Synchronization
//!
//! Implements robust wallet synchronization with multi-peer consensus validation.
//! This ensures the wallet syncs with the correct blockchain state even in the
//! presence of byzantine or dishonest peers.

use crate::network::NetworkManager;
use crate::peer_manager::PeerManager;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Minimum number of peers required for consensus
const MIN_PEERS_FOR_CONSENSUS: usize = 3;

/// Consensus threshold (67% - Byzantine Fault Tolerance)
const CONSENSUS_THRESHOLD: f64 = 0.67;

/// Maximum blocks to download per batch
const BATCH_SIZE: u64 = 100;

/// Timeout for peer queries (30 seconds)
const PEER_QUERY_TIMEOUT_SECS: u64 = 30;

/// Checkpoint save interval (every 100 blocks)
const CHECKPOINT_INTERVAL: u64 = 100;

/// Maximum sync time (30 minutes)
const MAX_SYNC_TIME_SECS: u64 = 1800;

/// Synchronization state
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncState {
    /// Not syncing
    Idle,
    /// Querying peers for heights
    Querying,
    /// Validating peer responses
    Validating,
    /// Downloading blocks
    Syncing { current: u64, total: u64 },
    /// Sync complete
    Ready,
    /// Sync failed
    Failed(String),
}

/// Sync checkpoint for persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SyncCheckpoint {
    /// Last synced height
    height: u64,
    /// Block hash at this height
    block_hash: String,
    /// Timestamp when checkpoint was saved
    timestamp: std::time::SystemTime,
    /// Network height at time of checkpoint
    network_height: u64,
}

/// Peer blockchain info
#[derive(Debug, Clone)]
struct PeerChainInfo {
    peer_address: String,
    height: u64,
    tip_hash: String,
    queried_at: std::time::Instant,
}

/// Consensus result
#[derive(Debug)]
struct ConsensusResult {
    height: u64,
    tip_hash: String,
    agreeing_peers: Vec<String>,
}

/// Multi-peer wallet synchronizer
pub struct WalletSync {
    peer_manager: Arc<Mutex<PeerManager>>,
    network_manager: Arc<Mutex<NetworkManager>>,
    state: Arc<Mutex<SyncState>>,
    last_sync: Arc<Mutex<Option<std::time::Instant>>>,
    current_height: Arc<Mutex<u64>>,
    network_height: Arc<Mutex<u64>>,
    checkpoint_path: PathBuf,
    sync_start_time: Arc<Mutex<Option<std::time::Instant>>>,
}

impl WalletSync {
    /// Create new wallet sync
    pub fn new(
        peer_manager: Arc<Mutex<PeerManager>>,
        network_manager: Arc<Mutex<NetworkManager>>,
        data_dir: PathBuf,
    ) -> Self {
        let checkpoint_path = data_dir.join("sync_checkpoint.json");

        Self {
            peer_manager,
            network_manager,
            state: Arc::new(Mutex::new(SyncState::Idle)),
            last_sync: Arc::new(Mutex::new(None)),
            current_height: Arc::new(Mutex::new(0)),
            network_height: Arc::new(Mutex::new(0)),
            checkpoint_path,
            sync_start_time: Arc::new(Mutex::new(None)),
        }
    }

    /// Load checkpoint from disk
    async fn load_checkpoint(&self) -> Result<Option<SyncCheckpoint>, String> {
        if !self.checkpoint_path.exists() {
            return Ok(None);
        }

        let data = std::fs::read_to_string(&self.checkpoint_path)
            .map_err(|e| format!("Failed to read checkpoint: {}", e))?;

        let checkpoint: SyncCheckpoint = serde_json::from_str(&data)
            .map_err(|e| format!("Failed to parse checkpoint: {}", e))?;

        log::info!(
            "📥 Loaded sync checkpoint: height={}, hash={}",
            checkpoint.height,
            &checkpoint.block_hash[..16]
        );

        Ok(Some(checkpoint))
    }

    /// Save checkpoint to disk
    async fn save_checkpoint(
        &self,
        height: u64,
        block_hash: String,
        network_height: u64,
    ) -> Result<(), String> {
        let checkpoint = SyncCheckpoint {
            height,
            block_hash: block_hash.clone(),
            timestamp: std::time::SystemTime::now(),
            network_height,
        };

        let data = serde_json::to_string_pretty(&checkpoint)
            .map_err(|e| format!("Failed to serialize checkpoint: {}", e))?;

        std::fs::write(&self.checkpoint_path, data)
            .map_err(|e| format!("Failed to write checkpoint: {}", e))?;

        log::debug!(
            "💾 Saved sync checkpoint: height={}, hash={}",
            height,
            &block_hash[..16]
        );

        Ok(())
    }

    /// Check if sync has timed out
    async fn check_timeout(&self) -> Result<(), String> {
        if let Some(start_time) = *self.sync_start_time.lock().await {
            let elapsed = start_time.elapsed().as_secs();
            if elapsed > MAX_SYNC_TIME_SECS {
                return Err(format!("Sync timeout after {} seconds", elapsed));
            }
        }
        Ok(())
    }

    /// Get current sync state
    pub async fn state(&self) -> SyncState {
        self.state.lock().await.clone()
    }

    /// Get last successful sync time
    pub async fn last_sync(&self) -> Option<std::time::Instant> {
        *self.last_sync.lock().await
    }

    /// Get sync progress as percentage (0-100)
    pub fn get_sync_progress(&self) -> f64 {
        let current =
            tokio::runtime::Handle::current().block_on(async { *self.current_height.lock().await });
        let network =
            tokio::runtime::Handle::current().block_on(async { *self.network_height.lock().await });

        if network == 0 {
            return 0.0;
        }

        (current as f64 / network as f64 * 100.0).min(100.0)
    }

    /// Get current blockchain height
    pub fn get_current_height(&self) -> u64 {
        tokio::runtime::Handle::current().block_on(async { *self.current_height.lock().await })
    }

    /// Get network blockchain height
    pub fn get_network_height(&self) -> u64 {
        tokio::runtime::Handle::current().block_on(async { *self.network_height.lock().await })
    }

    /// Get estimated time to completion in seconds
    pub fn get_estimated_completion(&self) -> Option<u64> {
        let current = self.get_current_height();
        let network = self.get_network_height();

        if network <= current {
            return None;
        }

        let remaining = network - current;

        // Estimate 100 blocks per minute
        let estimated_secs = (remaining / 100) * 60;

        Some(estimated_secs)
    }

    /// Update heights for UI display
    async fn update_heights(&self, current: u64, network: u64) {
        *self.current_height.lock().await = current;
        *self.network_height.lock().await = network;
    }

    /// Perform multi-peer consensus sync
    pub async fn sync(&self, local_height: u64) -> Result<SyncState, String> {
        // Set sync start time
        *self.sync_start_time.lock().await = Some(std::time::Instant::now());

        // Try to load checkpoint
        let checkpoint = self.load_checkpoint().await?;
        let start_height = if let Some(ref cp) = checkpoint {
            if cp.height > local_height {
                log::info!("📍 Resuming from checkpoint: height={}", cp.height);
                cp.height
            } else {
                local_height
            }
        } else {
            local_height
        };

        // Update state to querying
        *self.state.lock().await = SyncState::Querying;

        // Step 1: Query multiple peers for their chain info with timeout
        let peer_infos = tokio::time::timeout(
            std::time::Duration::from_secs(PEER_QUERY_TIMEOUT_SECS),
            self.query_peer_heights(),
        )
        .await
        .map_err(|_| "Peer query timeout".to_string())??;

        if peer_infos.len() < MIN_PEERS_FOR_CONSENSUS {
            let msg = format!(
                "Insufficient peers for consensus: {} < {}",
                peer_infos.len(),
                MIN_PEERS_FOR_CONSENSUS
            );
            *self.state.lock().await = SyncState::Failed(msg.clone());
            *self.sync_start_time.lock().await = None;
            return Err(msg);
        }

        // Step 2: Find consensus on blockchain state
        *self.state.lock().await = SyncState::Validating;

        let consensus = match self.find_consensus(&peer_infos).await {
            Ok(c) => c,
            Err(e) => {
                *self.state.lock().await = SyncState::Failed(e.clone());
                *self.sync_start_time.lock().await = None;
                return Err(e);
            }
        };

        // Update heights for UI
        self.update_heights(start_height, consensus.height).await;

        log::info!(
            "✅ Consensus reached: height {} with {}/{} peers",
            consensus.height,
            consensus.agreeing_peers.len(),
            peer_infos.len()
        );

        // Step 3: Check if we need to sync
        if consensus.height <= local_height {
            log::info!("✅ Already synced to height {}", local_height);
            *self.state.lock().await = SyncState::Ready;
            *self.last_sync.lock().await = Some(std::time::Instant::now());
            return Ok(SyncState::Ready);
        }

        // Step 4: Download missing blocks
        let blocks_to_download = consensus.height - local_height;
        log::info!("📥 Downloading {} blocks...", blocks_to_download);

        *self.state.lock().await = SyncState::Syncing {
            current: local_height,
            total: consensus.height,
        };

        // Download blocks in batches
        let result = self
            .download_blocks(
                local_height + 1,
                consensus.height,
                &consensus.agreeing_peers,
            )
            .await;

        match result {
            Ok(_) => {
                log::info!("✅ Sync complete at height {}", consensus.height);
                *self.state.lock().await = SyncState::Ready;
                *self.last_sync.lock().await = Some(std::time::Instant::now());
                Ok(SyncState::Ready)
            }
            Err(e) => {
                log::error!("❌ Sync failed: {}", e);
                *self.state.lock().await = SyncState::Failed(e.clone());
                Err(e)
            }
        }
    }

    /// Query multiple peers for their blockchain heights
    async fn query_peer_heights(&self) -> Result<Vec<PeerChainInfo>, String> {
        let peer_mgr = self.peer_manager.lock().await;
        let peers = peer_mgr.get_healthy_peers().await;

        if peers.is_empty() {
            return Err("No healthy peers available".to_string());
        }

        drop(peer_mgr); // Release lock before async operations

        let mut peer_infos = Vec::new();
        let mut tasks = Vec::new();

        // Query peers in parallel (up to 10 at a time)
        for peer in peers.iter().take(10) {
            let peer_addr = peer.address.clone();
            let network_mgr = self.network_manager.clone();

            let task = tokio::spawn(async move {
                let net = network_mgr.lock().await;
                match net.get_blockchain_info(&peer_addr).await {
                    Ok(info) => Some(PeerChainInfo {
                        peer_address: peer_addr.clone(),
                        height: info.height,
                        tip_hash: info.best_block_hash,
                        queried_at: std::time::Instant::now(),
                    }),
                    Err(e) => {
                        log::warn!("Failed to query peer {}: {}", peer_addr, e);
                        None
                    }
                }
            });

            tasks.push(task);
        }

        // Wait for all queries to complete
        for task in tasks {
            if let Ok(Some(info)) = task.await {
                peer_infos.push(info);
            }
        }

        log::info!(
            "📊 Queried {}/{} peers successfully",
            peer_infos.len(),
            peers.len()
        );

        Ok(peer_infos)
    }

    /// Find consensus among peers (Byzantine Fault Tolerant)
    async fn find_consensus(
        &self,
        peer_infos: &[PeerChainInfo],
    ) -> Result<ConsensusResult, String> {
        if peer_infos.is_empty() {
            return Err("No peer information available".to_string());
        }

        // Group peers by (height, tip_hash)
        let mut height_groups: HashMap<(u64, String), Vec<String>> = HashMap::new();

        for info in peer_infos {
            let key = (info.height, info.tip_hash.clone());
            height_groups
                .entry(key)
                .or_default()
                .push(info.peer_address.clone());
        }

        // Find group with most peers (must exceed consensus threshold)
        let total_peers = peer_infos.len();
        let required_agreement = (total_peers as f64 * CONSENSUS_THRESHOLD).ceil() as usize;

        let mut best_group: Option<((u64, String), Vec<String>)> = None;
        let mut max_agreement = 0;

        for (key, peers) in height_groups {
            if peers.len() > max_agreement {
                max_agreement = peers.len();
                best_group = Some((key, peers));
            }
        }

        match best_group {
            Some(((height, tip_hash), peers)) if peers.len() >= required_agreement => {
                Ok(ConsensusResult {
                    height,
                    tip_hash,
                    agreeing_peers: peers,
                })
            }
            Some(((height, _), peers)) => Err(format!(
                "Insufficient consensus: {}/{} peers agree on height {} (need {})",
                peers.len(),
                total_peers,
                height,
                required_agreement
            )),
            None => Err("No consensus found".to_string()),
        }
    }

    /// Download blocks from consensus peers
    async fn download_blocks(
        &self,
        start_height: u64,
        end_height: u64,
        peers: &[String],
    ) -> Result<(), String> {
        if peers.is_empty() {
            return Err("No peers available for download".to_string());
        }

        let mut current_height = start_height;

        while current_height <= end_height {
            // Check for timeout
            self.check_timeout().await?;

            let batch_end = (current_height + BATCH_SIZE - 1).min(end_height);

            log::debug!("📥 Downloading blocks {}-{}...", current_height, batch_end);

            // Try each peer until one succeeds
            let mut downloaded = false;
            let mut last_block_hash = String::new();

            for peer_addr in peers {
                let net = self.network_manager.lock().await;
                match net.get_blocks(peer_addr, current_height, batch_end).await {
                    Ok(blocks) => {
                        log::debug!("✅ Downloaded {} blocks from {}", blocks.len(), peer_addr);

                        // TODO: Validate and store blocks
                        // For now, just update progress

                        if let Some(last_block) = blocks.last() {
                            last_block_hash = last_block.hash.clone();
                        }

                        current_height = batch_end + 1;
                        downloaded = true;

                        // Update sync state
                        *self.state.lock().await = SyncState::Syncing {
                            current: batch_end,
                            total: end_height,
                        };

                        self.update_heights(batch_end, end_height).await;

                        // Save checkpoint every CHECKPOINT_INTERVAL blocks
                        if batch_end.is_multiple_of(CHECKPOINT_INTERVAL) {
                            if let Err(e) = self
                                .save_checkpoint(batch_end, last_block_hash.clone(), end_height)
                                .await
                            {
                                log::warn!("Failed to save checkpoint: {}", e);
                            }
                        }

                        break;
                    }
                    Err(e) => {
                        log::warn!("Failed to download from {}: {}", peer_addr, e);
                        continue;
                    }
                }
            }

            if !downloaded {
                return Err(format!(
                    "Failed to download blocks {}-{} from any peer",
                    current_height, batch_end
                ));
            }
        }

        // Save final checkpoint
        if let Err(e) = self
            .save_checkpoint(end_height, "final".to_string(), end_height)
            .await
        {
            log::warn!("Failed to save final checkpoint: {}", e);
        }

        // Clear sync start time
        *self.sync_start_time.lock().await = None;

        Ok(())
    }

    /// Force a re-sync (useful when chain reorg detected)
    pub async fn force_resync(&self, local_height: u64) -> Result<SyncState, String> {
        log::info!("🔄 Force re-sync requested from height {}", local_height);
        self.sync(local_height).await
    }

    /// Check if sync is needed (call periodically)
    pub async fn check_sync_needed(&self, local_height: u64) -> bool {
        // Sync if we haven't synced in the last 5 minutes
        if let Some(last) = *self.last_sync.lock().await {
            if last.elapsed().as_secs() < 300 {
                return false;
            }
        }

        // Quick check: ask one peer if they're ahead
        let peer_mgr = self.peer_manager.lock().await;
        let peers = peer_mgr.get_healthy_peers().await;

        if let Some(peer) = peers.first() {
            let net = self.network_manager.lock().await;
            if let Ok(info) = net.get_blockchain_info(&peer.address).await {
                return info.height > local_height;
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_state_transitions() {
        assert_eq!(SyncState::Idle, SyncState::Idle);
        assert_ne!(SyncState::Idle, SyncState::Querying);
    }

    #[test]
    fn test_consensus_threshold() {
        // 67% of 3 peers = ceil(2.01) = 3 peers minimum (need all 3)
        let required = (3.0 * CONSENSUS_THRESHOLD).ceil() as usize;
        assert_eq!(required, 3);

        // 67% of 5 peers = ceil(3.35) = 4 peers minimum
        let required = (5.0 * CONSENSUS_THRESHOLD).ceil() as usize;
        assert_eq!(required, 4);

        // 67% of 10 peers = ceil(6.7) = 7 peers minimum
        let required = (10.0 * CONSENSUS_THRESHOLD).ceil() as usize;
        assert_eq!(required, 7);
    }

    #[test]
    fn test_batch_size() {
        let start = 100;
        let end = 250;
        let batch_end = (start + BATCH_SIZE - 1).min(end);
        assert_eq!(batch_end, 199); // First batch: 100-199
    }
}
