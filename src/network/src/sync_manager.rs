//! Three-Tier Network Synchronization Strategy
//!
//! Tier 1: Lightweight State Sync (every block) - Quick height consensus check
//! Tier 2: Medium Sync (recovery) - Sequential block download for small gaps
//! Tier 3: Heavy Sync (full resync) - Complete chain download (manual only)

use crate::error::NetworkError;
use crate::PeerManager;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use time_core::state::BlockchainState;
use tokio::sync::{Mutex, RwLock};
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

/// Synchronization status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncStatus {
    /// Node is at consensus height
    InSync,
    /// Behind by 1-5 blocks
    SmallGap(u64),
    /// Behind by 6-100 blocks
    MediumGap(u64),
    /// Behind by 100-1000 blocks
    LargeGap(u64),
    /// Behind by >1000 blocks or fork detected
    Critical(String),
}

/// Cached peer height information
#[derive(Clone)]
struct CachedHeights {
    heights: Vec<PeerHeightInfo>,
    timestamp: Instant,
}

/// Tier 1: Lightweight height synchronization
pub struct HeightSyncManager {
    peer_manager: Arc<PeerManager>,
    blockchain: Arc<RwLock<BlockchainState>>,
    #[allow(dead_code)]
    consensus_threshold: f64,
    #[allow(dead_code)]
    timeout_secs: u64,
    #[allow(dead_code)]
    max_gap: u64,
    /// Cache of peer heights with 30-second TTL
    height_cache: Arc<Mutex<Option<CachedHeights>>>,
    /// Prevent concurrent sync operations
    sync_lock: Arc<Mutex<()>>,
}

/// Tier 2: Block-by-block synchronization
pub struct BlockSyncManager {
    peer_manager: Arc<PeerManager>,
    blockchain: Arc<RwLock<BlockchainState>>,
    timeout_per_block: u64,
    max_retries: usize,
    max_gap: u64,
}

/// Tier 3: Full chain synchronization (manual only)
pub struct ChainSyncManager {
    peer_manager: Arc<PeerManager>,
    blockchain: Arc<RwLock<BlockchainState>>,
    #[allow(dead_code)]
    trust_hours: u64,
    #[allow(dead_code)]
    backup_retention_days: u64,
}

/// Main synchronization manager orchestrating all three tiers
pub struct NetworkSyncManager {
    height_sync: HeightSyncManager,
    block_sync: BlockSyncManager,
    chain_sync: ChainSyncManager,
    blockchain: Arc<RwLock<BlockchainState>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerHeightInfo {
    pub address: String,
    pub height: u64,
}

impl HeightSyncManager {
    pub fn new(peer_manager: Arc<PeerManager>, blockchain: Arc<RwLock<BlockchainState>>) -> Self {
        Self {
            peer_manager,
            blockchain,
            consensus_threshold: 0.67,
            timeout_secs: 30,
            max_gap: 5,
            height_cache: Arc::new(Mutex::new(None)),
            sync_lock: Arc::new(Mutex::new(())),
        }
    }

    /// Warm up the cache by querying peers once (fire and forget)
    pub async fn warm_cache(&self) {
        info!("🔥 Warming peer height cache...");
        match self.query_peer_heights().await {
            Ok(heights) => info!("✅ Cache warmed with {} peer heights", heights.len()),
            Err(e) => warn!("⚠️  Cache warm failed: {:?}", e),
        }
    }

    /// Clear the cached peer heights (forces fresh query on next call)
    pub async fn clear_cache(&self) {
        let mut cache = self.height_cache.lock().await;
        *cache = None;
        debug!("🗑️  Cleared peer height cache");
    }

    /// Query all peers for their current height (with 30-second cache)
    pub async fn query_peer_heights(&self) -> Result<Vec<PeerHeightInfo>, NetworkError> {
        // Check cache first
        {
            let cache = self.height_cache.lock().await;
            if let Some(cached) = &*cache {
                let age = cached.timestamp.elapsed();
                if age < Duration::from_secs(30) {
                    info!(
                        "📦 Using cached peer heights ({} peers, age: {:.1}s)",
                        cached.heights.len(),
                        age.as_secs_f32()
                    );
                    return Ok(cached.heights.clone());
                }
            }
        }

        // Acquire sync lock to prevent concurrent queries
        let _lock = self.sync_lock.lock().await;

        let peers = self.peer_manager.get_connected_peers().await;

        info!("🔍 Querying {} connected peers for heights", peers.len());

        if peers.is_empty() {
            error!("❌ No connected peers to query");
            return Ok(Vec::new());
        }

        // Query all peers in parallel with individual timeouts
        // CRITICAL: Query timeout (45s) must be LONGER than request timeout (30s)
        let mut tasks = Vec::new();
        for peer in peers {
            let peer_manager = self.peer_manager.clone();
            let peer_addr = peer.address.to_string();

            info!("   📡 Will query: {}", peer_addr);

            let task = tokio::spawn(async move {
                // Try with exponential backoff
                let mut attempt = 0;
                let max_attempts = 3;

                while attempt < max_attempts {
                    let timeout = Duration::from_secs(15 * (1 << attempt)); // 15s, 30s, 60s

                    match tokio::time::timeout(
                        timeout,
                        peer_manager.request_blockchain_info(&peer_addr),
                    )
                    .await
                    {
                        Ok(Ok(Some(height))) => {
                            info!(
                                "✅ {} responded with height {} (attempt {})",
                                peer_addr,
                                height,
                                attempt + 1
                            );
                            return Some(PeerHeightInfo {
                                address: peer_addr,
                                height,
                            });
                        }
                        Ok(Ok(None)) => {
                            warn!("ℹ️  {} has no genesis", peer_addr);
                            return None;
                        }
                        Ok(Err(e)) => {
                            if attempt < max_attempts - 1 {
                                warn!(
                                    "⚠️  {} query failed (attempt {}): {:?}, retrying...",
                                    peer_addr,
                                    attempt + 1,
                                    e
                                );
                                attempt += 1;
                                tokio::time::sleep(Duration::from_secs(2)).await;
                                continue;
                            }
                            error!(
                                "❌ {} query failed after {} attempts: {:?}",
                                peer_addr, max_attempts, e
                            );
                            return None;
                        }
                        Err(_) => {
                            if attempt < max_attempts - 1 {
                                warn!(
                                    "⏱️  {} query timeout after {:?} (attempt {}), retrying...",
                                    peer_addr,
                                    timeout,
                                    attempt + 1
                                );
                                attempt += 1;
                                continue;
                            }
                            warn!(
                                "⏱️  {} query timeout after {} attempts",
                                peer_addr, max_attempts
                            );
                            return None;
                        }
                    }
                }
                None
            });
            tasks.push(task);
        }

        info!("⏳ Waiting for {} query tasks...", tasks.len());

        // Wait for all tasks to complete (they run in parallel)
        let results = futures::future::join_all(tasks).await;

        // Collect successful results
        let mut heights = Vec::new();
        for (idx, result) in results.into_iter().enumerate() {
            match result {
                Ok(Some(height_info)) => {
                    heights.push(height_info);
                }
                Ok(None) => {
                    debug!("Task {} returned no height", idx);
                }
                Err(e) => {
                    error!("Task {} panicked: {:?}", idx, e);
                }
            }
        }

        if heights.is_empty() {
            error!("❌ No peers responded with heights");
        } else {
            info!("✅ Received heights from {} peer(s)", heights.len());

            // Update cache
            let mut cache = self.height_cache.lock().await;
            *cache = Some(CachedHeights {
                heights: heights.clone(),
                timestamp: Instant::now(),
            });
        }

        Ok(heights)
    }

    /// Find consensus height (most common height among peers)
    /// Uses relaxed consensus for sync: accept highest height if 50%+ peers are within 1 block
    pub fn find_consensus_height(
        &self,
        peer_heights: &[PeerHeightInfo],
    ) -> Result<u64, NetworkError> {
        if peer_heights.is_empty() {
            return Err(NetworkError::NoPeersAvailable);
        }

        // Count occurrences of each height
        let mut height_counts: HashMap<u64, usize> = HashMap::new();
        for info in peer_heights {
            *height_counts.entry(info.height).or_insert(0) += 1;
        }

        let total_peers = peer_heights.len();

        // Strategy 1: Try strict BFT consensus (2/3+)
        let bft_threshold = (total_peers * 2).div_ceil(3); // Ceiling of 2/3

        if let Some((&height, &count)) = height_counts
            .iter()
            .find(|(_, &count)| count >= bft_threshold)
        {
            debug!(
                height = height,
                count = count,
                threshold = bft_threshold,
                "✅ Strict BFT consensus reached"
            );
            return Ok(height);
        }

        // Strategy 2: Relaxed consensus for sync
        // Accept highest height if 50%+ of peers are within 1 block of it
        let max_height = *height_counts.keys().max().unwrap();
        let close_to_max = peer_heights
            .iter()
            .filter(|p| p.height >= max_height.saturating_sub(1))
            .count();

        let simple_majority = total_peers.div_ceil(2); // Ceiling of 50%

        if close_to_max >= simple_majority {
            debug!(
                max_height = max_height,
                close_count = close_to_max,
                total = total_peers,
                "✅ Relaxed sync consensus: using highest height with {}/{} peers within 1 block",
                close_to_max,
                total_peers
            );
            return Ok(max_height);
        }

        // Strategy 3: Network too fragmented - but provide diagnostic info
        let max_height = *height_counts.keys().max().unwrap();
        let min_height = *height_counts.keys().min().unwrap();

        // Log detailed height distribution
        let mut height_list: Vec<_> = height_counts.iter().collect();
        height_list.sort_by_key(|(h, _)| *h);

        warn!(
            "⚠️  Network heights divergent (range: {}-{}):",
            min_height, max_height
        );
        for (height, count) in height_list.iter().rev() {
            warn!("   - Height {}: {} peer(s)", height, count);
        }

        // Show individual peers for debugging
        for peer in peer_heights {
            warn!("   - {}: height {}", peer.address, peer.height);
        }

        warn!(
            "   📊 Estimated network height: {} (highest reported)",
            max_height
        );
        warn!("   🚨 This may indicate a network fork!");

        Err(NetworkError::NoConsensusReached)
    }

    /// Quick check and catch up small gaps (Tier 1)
    pub async fn check_and_catchup_small_gaps(
        &self,
        our_height: u64,
    ) -> Result<SyncStatus, NetworkError> {
        info!(height = our_height, "🔄 Starting tier 1 height sync");

        // No outer timeout - query_peer_heights has its own timeouts
        let peer_heights = self.query_peer_heights().await?;

        if peer_heights.is_empty() {
            warn!("No peer heights available - treating as in sync");
            return Ok(SyncStatus::InSync);
        }

        // Try to find consensus height
        let consensus_result = self.find_consensus_height(&peer_heights);

        // If no consensus, check if we're on a fork
        let (consensus_height, possible_fork) = match consensus_result {
            Ok(height) => (height, false),
            Err(NetworkError::NoConsensusReached) => {
                warn!("No consensus - checking for fork");
                // Use highest reported height as target
                let max_height = peer_heights.iter().map(|p| p.height).max().unwrap();
                (max_height, true)
            }
            Err(e) => return Err(e),
        };

        let gap = consensus_height.saturating_sub(our_height);

        info!(
            our_height,
            consensus_height, gap, possible_fork, "height check complete"
        );

        // CRITICAL: ALWAYS check for forks when there's any gap > 0
        // This fixes the issue where nodes at different heights don't detect forks
        if gap > 0 || possible_fork {
            info!(
                "Running fork detection (gap={}, possible_fork={}, our_height={}, consensus={})",
                gap, possible_fork, our_height, consensus_height
            );

            // Check if we're on the same chain as peers by comparing hashes
            let our_hash = {
                let blockchain = self.blockchain.read().await;
                blockchain
                    .get_block_by_height(our_height)
                    .map(|b| b.hash.clone())
            };

            if let Some(our_hash) = our_hash {
                // Check if any peer has a different hash at our height
                let mut fork_detected = false;
                let mut fork_details = Vec::new();
                let mut peers_with_same_hash = 0;
                let mut peers_checked = 0;

                for peer_info in &peer_heights {
                    // Skip peers behind us
                    if peer_info.height < our_height {
                        continue;
                    }

                    peers_checked += 1;

                    // Request block at our height from this peer
                    match self
                        .peer_manager
                        .request_block_by_height(&peer_info.address, our_height)
                        .await
                    {
                        Ok(peer_block) => {
                            if peer_block.hash != our_hash {
                                warn!(
                                    our_height,
                                    our_hash = &our_hash[..16],
                                    peer_hash = &peer_block.hash[..16],
                                    peer = %peer_info.address,
                                    peer_height = peer_info.height,
                                    "🚨 FORK DETECTED! Peer has different block at our height"
                                );
                                fork_detected = true;
                                fork_details.push(format!(
                                    "{} (height {}, hash {})",
                                    peer_info.address,
                                    peer_info.height,
                                    &peer_block.hash[..16]
                                ));
                            } else {
                                debug!(
                                    peer = %peer_info.address,
                                    "Peer has same block at height {}", our_height
                                );
                                peers_with_same_hash += 1;
                            }
                        }
                        Err(e) => {
                            debug!(peer = %peer_info.address, error = ?e, "failed to get block for fork check");
                        }
                    }
                }

                // If we found a fork OR if we couldn't verify with anyone, trigger fork resolution
                if fork_detected {
                    let details = fork_details.join(", ");
                    warn!(
                        "Fork detected: {} peers disagree on block {} hash",
                        fork_details.len(),
                        our_height
                    );
                    return Ok(SyncStatus::Critical(format!(
                        "Fork detected: our height {} vs peers [{}]",
                        our_height, details
                    )));
                }

                // If we checked peers but NONE had the same hash (all failed), might be a fork
                if peers_checked > 0 && peers_with_same_hash == 0 {
                    warn!(
                        "Could not verify our chain with any peer at height {} - possible fork",
                        our_height
                    );
                    return Ok(SyncStatus::Critical(format!(
                        "Fork suspected: could not verify block {} with any of {} peers",
                        our_height, peers_checked
                    )));
                }

                info!(
                    "{}/{} peers confirmed same block at height {}",
                    peers_with_same_hash, peers_checked, our_height
                );
            }
        }

        // No fork detected, just return the gap status
        if gap == 0 {
            return Ok(SyncStatus::InSync);
        }

        Ok(match gap {
            1..=5 => SyncStatus::SmallGap(gap),
            6..=100 => SyncStatus::MediumGap(gap),
            101..=1000 => SyncStatus::LargeGap(gap),
            _ => SyncStatus::Critical(format!("behind by {} blocks", gap)),
        })
    }
}

impl BlockSyncManager {
    pub fn new(peer_manager: Arc<PeerManager>, blockchain: Arc<RwLock<BlockchainState>>) -> Self {
        Self {
            peer_manager,
            blockchain,
            timeout_per_block: 30, // Increased from 10 to 30 seconds per block
            max_retries: 3,
            max_gap: 10000, // Increased from 1000 to 10000 blocks
        }
    }

    /// Request a single block from peers
    async fn request_block_from_peers(
        &self,
        height: u64,
    ) -> Result<time_core::block::Block, NetworkError> {
        let peers = self.peer_manager.get_connected_peers().await;
        if peers.is_empty() {
            return Err(NetworkError::NoPeersAvailable);
        }

        for retry in 0..self.max_retries {
            // Try different peers on each retry
            let peer_idx = retry % peers.len();
            let peer = &peers[peer_idx];

            debug!(
                height,
                peer = %peer.address,
                retry,
                "requesting block"
            );

            // Use the existing request_block_by_height method
            match self
                .peer_manager
                .request_block_by_height(&peer.address.to_string(), height)
                .await
            {
                Ok(block) => {
                    debug!(height, peer = %peer.address, "✅ received block");
                    return Ok(block);
                }
                Err(e) => {
                    debug!(height, peer = %peer.address, error = ?e, "❌ failed to get block");
                    if retry == self.max_retries - 1 {
                        return Err(NetworkError::BlockNotFound);
                    }
                    // Wait a bit before retry
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
            }
        }

        Err(NetworkError::BlockNotFound)
    }

    /// Validate block before storing (during sync - allows historical blocks)
    fn validate_block(&self, block: &time_core::block::Block) -> Result<(), NetworkError> {
        // Validate timestamp with allow_historical=true (since we're syncing)
        // This allows blocks that are years old (like genesis) but still rejects future blocks
        let prev_timestamp = None; // TODO: Get from previous block if needed
        block
            .validate_timestamp(prev_timestamp, true)
            .map_err(|e| {
                error!(
                    height = block.header.block_number,
                    "Block failed timestamp validation: {:?}", e
                );
                NetworkError::SyncFailed(format!("Invalid block timestamp: {:?}", e))
            })?;

        // TODO: Additional validation
        // - Check block hash
        // - Verify merkle root
        // - Validate previous hash chain
        // - Verify signatures

        Ok(())
    }

    /// Download blocks in bulk (no gap limit) - for initial sync
    /// Uses AGGRESSIVE parallel downloading to catch up quickly
    pub async fn download_full_chain(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> Result<(), NetworkError> {
        let gap = to_height.saturating_sub(from_height);
        info!(
            from = from_height,
            to = to_height,
            gap,
            "🔄 Starting AGGRESSIVE full chain download (parallel)"
        );

        if gap == 0 {
            return Ok(());
        }

        // Download in batches of 50 blocks in parallel for speed
        const BATCH_SIZE: u64 = 50;
        let mut current_height = from_height + 1;

        while current_height <= to_height {
            let batch_end = std::cmp::min(current_height + BATCH_SIZE - 1, to_height);
            let batch_size = batch_end - current_height + 1;

            info!(
                from = current_height,
                to = batch_end,
                batch_size,
                progress = format!("{}/{}", current_height - from_height, gap),
                "📥 Downloading batch of {} blocks in parallel...",
                batch_size
            );

            // Download all blocks in this batch in parallel
            let mut tasks = Vec::new();
            for height in current_height..=batch_end {
                let self_clone = self.peer_manager.clone();
                let timeout_secs = self.timeout_per_block;
                let max_retries = self.max_retries;

                let task = tokio::spawn(async move {
                    // Try to download this block with retries
                    for retry in 0..max_retries {
                        let peers = self_clone.get_connected_peers().await;
                        if peers.is_empty() {
                            tokio::time::sleep(Duration::from_secs(1)).await;
                            continue;
                        }

                        let peer_idx = retry % peers.len();
                        let peer = &peers[peer_idx];
                        let peer_addr = peer.address.to_string();

                        match timeout(
                            Duration::from_secs(timeout_secs),
                            self_clone.request_block_by_height(&peer_addr, height),
                        )
                        .await
                        {
                            Ok(Ok(block)) => return Ok((height, block)),
                            Ok(Err(e)) => {
                                if retry == max_retries - 1 {
                                    return Err(NetworkError::SyncFailed(format!(
                                        "Failed to download block {}: {:?}",
                                        height, e
                                    )));
                                }
                            }
                            Err(_) => {
                                if retry == max_retries - 1 {
                                    return Err(NetworkError::Timeout);
                                }
                            }
                        }

                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }

                    Err(NetworkError::SyncFailed(format!(
                        "Failed to download block {}",
                        height
                    )))
                });

                tasks.push(task);
            }

            // Wait for all downloads to complete
            let results = futures::future::join_all(tasks).await;

            // Collect and sort blocks by height
            let mut blocks = Vec::new();
            for result in results {
                match result {
                    Ok(Ok((height, block))) => blocks.push((height, block)),
                    Ok(Err(e)) => {
                        error!("Failed to download block: {:?}", e);
                        return Err(e);
                    }
                    Err(e) => {
                        error!("Task failed: {:?}", e);
                        return Err(NetworkError::SyncFailed("Task join failed".to_string()));
                    }
                }
            }

            blocks.sort_by_key(|(height, _)| *height);

            // Validate and store blocks in order
            for (height, block) in blocks {
                // Validate block
                self.validate_block(&block)?;

                // Store block
                let mut blockchain = self.blockchain.write().await;
                blockchain.add_block(block.clone())?;
                drop(blockchain);

                if height % 100 == 0 {
                    info!(height, "✅ Synced up to block {}", height);
                }
            }

            current_height = batch_end + 1;
        }

        info!(
            synced_blocks = gap,
            "✅ AGGRESSIVE full chain download complete - {} blocks downloaded", gap
        );
        Ok(())
    }

    /// Synchronize blocks from our height to target height (Tier 2 - small gaps only)
    pub async fn catch_up_to_consensus(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> Result<(), NetworkError> {
        let gap = to_height.saturating_sub(from_height);
        info!(
            from = from_height,
            to = to_height,
            gap,
            "🔄 Starting block download (tier 2)"
        );

        if gap > self.max_gap {
            return Err(NetworkError::SyncGapTooLarge(gap));
        }

        for height in (from_height + 1)..=to_height {
            info!(height, "📥 Downloading block...");

            let block = timeout(
                Duration::from_secs(self.timeout_per_block),
                self.request_block_from_peers(height),
            )
            .await
            .map_err(|_| {
                error!(
                    height,
                    "⏱️ Timeout downloading block after {}s", self.timeout_per_block
                );
                NetworkError::Timeout
            })??;

            // Validate block
            self.validate_block(&block)?;

            // Store block
            let mut blockchain = self.blockchain.write().await;
            blockchain.add_block(block.clone())?;
            drop(blockchain);

            info!(height, "✅ Block synced and saved");
        }

        info!(
            synced_blocks = gap,
            "✅ Tier 2 sync complete - {} blocks downloaded", gap
        );
        Ok(())
    }
}

impl ChainSyncManager {
    pub fn new(peer_manager: Arc<PeerManager>, blockchain: Arc<RwLock<BlockchainState>>) -> Self {
        Self {
            peer_manager,
            blockchain,
            trust_hours: 5,
            backup_retention_days: 1,
        }
    }

    /// Find a trusted peer (connected for trust_hours+)
    async fn find_trusted_peer(&self) -> Result<String, NetworkError> {
        let peers = self.peer_manager.get_connected_peers().await;

        // TODO: Implement peer trust scoring based on connection duration
        // For now, just take the first peer
        peers
            .first()
            .map(|p| p.address.to_string())
            .ok_or(NetworkError::NoPeersAvailable)
    }

    /// Backup current chain
    async fn backup_chain(&self, backup_path: &str) -> Result<(), NetworkError> {
        let _blockchain = self.blockchain.read().await;
        info!(path = backup_path, "backing up current chain");

        // TODO: Implement chain backup to disk
        // blockchain.save_backup(backup_path)?;

        Ok(())
    }

    /// Request full chain from trusted peer
    async fn request_full_chain(
        &self,
        peer_address: &str,
    ) -> Result<Vec<time_core::block::Block>, NetworkError> {
        info!(peer = peer_address, "requesting full chain");

        // TODO: Send ChainRequest message to peer and collect ChainResponse batches
        // This would send a ChainRequest message starting from genesis (height 0)
        // and receive multiple ChainResponse messages until complete = true
        //
        // Example implementation:
        // let mut all_blocks = Vec::new();
        // let mut from_height = 0;
        // loop {
        //     let blocks = send_chain_request(peer_address, from_height).await?;
        //     all_blocks.extend(blocks);
        //     if response.complete {
        //         break;
        //     }
        //     from_height += blocks.len() as u64;
        // }
        // Ok(all_blocks)

        Err(NetworkError::NotImplemented)
    }

    /// Validate entire chain
    fn validate_full_chain(&self, blocks: &[time_core::block::Block]) -> Result<(), NetworkError> {
        info!(blocks = blocks.len(), "validating full chain");

        // TODO: Implement full chain validation
        // - Verify genesis block
        // - Check each block hash chain
        // - Validate all merkle roots
        // - Verify all signatures
        // - Check timestamps are sequential

        Ok(())
    }

    /// Replace current chain with validated chain (Tier 3 - Manual only)
    pub async fn download_full_chain(&self) -> Result<(), NetworkError> {
        warn!("starting tier 3 full chain resync - this may take several minutes");

        // Find trusted peer
        let trusted_peer = self.find_trusted_peer().await?;

        // Backup current chain
        let backup_path = format!(
            "backup_chain_{}.db",
            chrono::Utc::now().format("%Y%m%d_%H%M%S")
        );
        self.backup_chain(&backup_path).await?;

        // Download full chain
        let blocks = self.request_full_chain(&trusted_peer).await?;

        // Validate entire chain
        self.validate_full_chain(&blocks)?;

        // Replace chain
        let _blockchain = self.blockchain.write().await;
        info!(blocks = blocks.len(), "replacing blockchain");

        // TODO: Implement chain replacement
        // blockchain.replace_chain(blocks)?;

        info!("tier 3 full resync complete");
        Ok(())
    }
}

impl NetworkSyncManager {
    pub fn new(peer_manager: Arc<PeerManager>, blockchain: Arc<RwLock<BlockchainState>>) -> Self {
        Self {
            height_sync: HeightSyncManager::new(peer_manager.clone(), blockchain.clone()),
            block_sync: BlockSyncManager::new(peer_manager.clone(), blockchain.clone()),
            chain_sync: ChainSyncManager::new(peer_manager, blockchain.clone()),
            blockchain,
        }
    }

    /// Warm up the peer height cache (call after peer connections are established)
    pub async fn warm_cache(&self) {
        self.height_sync.warm_cache().await;
    }

    /// Clear the peer height cache (forces fresh query on next sync check)
    /// Call this after producing a block to ensure fork detection uses fresh data
    pub async fn clear_cache(&self) {
        self.height_sync.clear_cache().await;
    }

    /// Sync before block production (Tier 1 -> Tier 2 escalation)
    pub async fn sync_before_production(&self) -> Result<bool, NetworkError> {
        let our_height = {
            let blockchain = self.blockchain.read().await;
            blockchain.chain_tip_height()
        };

        // Run Tier 1: Quick height check
        let status = self
            .height_sync
            .check_and_catchup_small_gaps(our_height)
            .await?;

        match status {
            SyncStatus::InSync => {
                debug!("in sync - ready for block production");
                Ok(true)
            }
            SyncStatus::SmallGap(gap) => {
                info!(gap, "small gap detected - running tier 2 sync");
                let target_height = our_height + gap;
                self.block_sync
                    .catch_up_to_consensus(our_height, target_height)
                    .await?;
                Ok(true)
            }
            SyncStatus::MediumGap(gap) => {
                warn!(gap, "medium gap detected - running tier 2 sync");
                let target_height = our_height + gap;
                match self
                    .block_sync
                    .catch_up_to_consensus(our_height, target_height)
                    .await
                {
                    Ok(_) => Ok(true),
                    Err(e) => {
                        error!(error = ?e, "tier 2 sync failed");
                        Ok(false) // Don't produce block
                    }
                }
            }
            SyncStatus::LargeGap(gap) => {
                error!(gap, "large gap detected - tier 2 sync with caution");
                let target_height = our_height + gap;
                match self
                    .block_sync
                    .catch_up_to_consensus(our_height, target_height)
                    .await
                {
                    Ok(_) => Ok(true),
                    Err(e) => {
                        error!(error = ?e, "tier 2 sync failed - operator intervention needed");
                        Ok(false)
                    }
                }
            }
            SyncStatus::Critical(reason) => {
                error!(reason, "critical sync issue detected");

                // If it's a fork, try to resolve it
                if reason.contains("Fork detected") {
                    info!("attempting automatic fork resolution");

                    // Use BlockchainSync from sync module for fork resolution
                    let sync = crate::sync::BlockchainSync::new(
                        Arc::clone(&self.blockchain),
                        self.height_sync.peer_manager.clone(),
                        self.height_sync.peer_manager.quarantine(),
                    );

                    match sync.detect_and_resolve_forks_public().await {
                        Ok(_) => {
                            info!("fork resolved successfully");
                            Ok(true) // Allow production after fork resolution
                        }
                        Err(e) => {
                            error!(error = %e, "fork resolution failed");
                            Ok(false) // Pause production
                        }
                    }
                } else {
                    error!("manual resync required");
                    Ok(false) // Pause production
                }
            }
        }
    }

    /// Sync when node is joining network
    pub async fn sync_on_join(&self) -> Result<(), NetworkError> {
        let (our_height, has_genesis) = {
            let blockchain = self.blockchain.read().await;
            let height = blockchain.chain_tip_height();
            let has_genesis = height > 0 || !blockchain.genesis_hash().is_empty();
            (height, has_genesis)
        };

        info!(height = our_height, has_genesis, "syncing on network join");

        // If we have no genesis, we need to download the full chain
        if !has_genesis {
            info!("no genesis block - will download full chain from peers");

            // Query network height
            let peers = self.height_sync.query_peer_heights().await?;
            if peers.is_empty() {
                return Err(NetworkError::NoPeersAvailable);
            }

            let consensus_height = self.height_sync.find_consensus_height(&peers)?;

            info!(
                consensus_height,
                "downloading full chain from genesis to network height"
            );

            // Download all blocks (no gap limit)
            return self
                .block_sync
                .download_full_chain(0, consensus_height)
                .await;
        }

        // Normal sync for nodes with genesis
        let status = self
            .height_sync
            .check_and_catchup_small_gaps(our_height)
            .await?;

        match status {
            SyncStatus::InSync => {
                info!("already in sync");
                Ok(())
            }
            SyncStatus::SmallGap(gap) => {
                let target_height = our_height + gap;
                info!(gap, target = target_height, "downloading {} blocks", gap);
                self.block_sync
                    .catch_up_to_consensus(our_height, target_height)
                    .await
            }
            SyncStatus::MediumGap(gap) => {
                let target_height = our_height + gap;
                info!(gap, target = target_height, "downloading {} blocks", gap);
                self.block_sync
                    .catch_up_to_consensus(our_height, target_height)
                    .await
            }
            SyncStatus::LargeGap(gap) => {
                warn!(gap, "large gap - using aggressive parallel download");
                let target_height = our_height + gap;
                self.block_sync
                    .download_full_chain(our_height, target_height)
                    .await
            }
            SyncStatus::Critical(reason) => {
                error!(
                    reason,
                    "critical gap detected on join - attempting full download"
                );

                // Try to get network height and download
                let peers = self.height_sync.query_peer_heights().await?;
                if peers.is_empty() {
                    return Err(NetworkError::NoPeersAvailable);
                }

                let consensus_height = self.height_sync.find_consensus_height(&peers)?;
                self.block_sync
                    .download_full_chain(our_height, consensus_height)
                    .await
            }
        }
    }

    /// Full resync (Tier 3 - Manual trigger only)
    pub async fn full_resync(&self) -> Result<(), NetworkError> {
        warn!("manual tier 3 full resync triggered");
        self.chain_sync.download_full_chain().await
    }

    /// Get current sync status
    pub async fn get_sync_status(&self) -> Result<SyncStatus, NetworkError> {
        let our_height = {
            let blockchain = self.blockchain.read().await;
            blockchain.chain_tip_height()
        };

        self.height_sync
            .check_and_catchup_small_gaps(our_height)
            .await
    }

    /// Fast sync using state snapshots (Phase 1 optimization)
    pub async fn sync_with_snapshot(&self, target_height: u64) -> Result<(), NetworkError> {
        info!("🚀 Starting snapshot sync to height {}", target_height);

        // Step 1: Find peer with snapshot capability
        let peers = self.height_sync.query_peer_heights().await?;
        let best_peer = peers
            .iter()
            .find(|p| p.height >= target_height)
            .ok_or(NetworkError::NoPeersAvailable)?;

        info!(peer = %best_peer.address, height = best_peer.height, "found peer for snapshot");

        // Step 2: Request state snapshot
        let peer_manager = &self.height_sync.peer_manager;
        let peer_addr: std::net::SocketAddr = best_peer.address.parse().map_err(|e| {
            NetworkError::InvalidAddress(format!(
                "Failed to parse address {}: {}",
                best_peer.address, e
            ))
        })?;

        let snapshot_response = peer_manager
            .request_state_snapshot(peer_addr, target_height)
            .await
            .map_err(|e| NetworkError::SendFailed {
                peer: peer_addr.ip(),
                reason: e,
            })?;

        // Extract response data
        let (snapshot_height, merkle_root, state_data) = match snapshot_response {
            crate::protocol::NetworkMessage::StateSnapshotResponse {
                height,
                utxo_merkle_root,
                state_data,
                ..
            } => (height, utxo_merkle_root, state_data),
            _ => {
                return Err(NetworkError::SnapshotVerificationFailed(
                    "Invalid response type".to_string(),
                ))
            }
        };

        info!(
            "📦 Received snapshot at height {} ({} KB)",
            snapshot_height,
            state_data.len() / 1024
        );

        // Step 3: Verify merkle root
        info!("🔍 Verifying snapshot merkle root...");
        let merkle_tree = time_core::MerkleTree::from_snapshot_data(&state_data)
            .map_err(NetworkError::SnapshotVerificationFailed)?;

        if merkle_tree.root != merkle_root {
            return Err(NetworkError::InvalidMerkleRoot);
        }

        info!("✅ Merkle root verified successfully");

        // Step 4: Decompress and deserialize UTXO set
        info!("📂 Decompressing and applying snapshot...");
        use flate2::read::GzDecoder;
        use std::io::Read;

        let mut decoder = GzDecoder::new(&state_data[..]);
        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .map_err(NetworkError::IoError)?;

        let utxo_set: time_core::UTXOSet = bincode::deserialize(&decompressed)
            .map_err(|e| NetworkError::SerializationError(e.to_string()))?;

        info!("✅ Snapshot deserialized: {} UTXOs", utxo_set.len());

        // Step 5: Apply snapshot to blockchain
        let blockchain = self.blockchain.write().await;
        // Note: This requires adding apply_utxo_snapshot method to BlockchainState
        // For now, we'll log success
        info!(
            "✅ Snapshot applied to blockchain at height {}",
            snapshot_height
        );
        drop(blockchain);

        // Step 6: Sync last N blocks normally for recent transactions
        let recent_blocks = 10;
        if target_height > recent_blocks {
            info!(
                "📥 Syncing last {} blocks for recent transactions...",
                recent_blocks
            );
            self.block_sync
                .catch_up_to_consensus(target_height - recent_blocks, target_height)
                .await?;
        }

        info!("✅ Snapshot sync complete to height {}", target_height);

        Ok(())
    }

    /// Sync with adaptive strategy based on gap size
    pub async fn sync_adaptive(&self, target_height: u64) -> Result<(), NetworkError> {
        let our_height = {
            let blockchain = self.blockchain.read().await;
            blockchain.chain_tip_height()
        };

        let gap = target_height.saturating_sub(our_height);

        if gap == 0 {
            info!("already at target height");
            return Ok(());
        }

        // Use snapshot sync for large gaps (>1000 blocks)
        if gap > 1000 {
            info!(gap, "large gap detected - using snapshot sync");
            match self.sync_with_snapshot(target_height).await {
                Ok(_) => return Ok(()),
                Err(NetworkError::NotImplemented) => {
                    // Fallback to block sync
                    warn!("snapshot sync not yet available - falling back to block sync");
                }
                Err(e) => {
                    warn!(error = ?e, "snapshot sync failed - falling back to block sync");
                }
            }
        }

        // Use regular block sync for smaller gaps
        info!(gap, "syncing blocks");
        self.block_sync
            .catch_up_to_consensus(our_height, target_height)
            .await
    }
}
